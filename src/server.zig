const std = @import("std");
const dns = @import("dns.zig");
const net = std.net;
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const AtomicValue = std.atomic.Value;
const AutoHashMap = std.AutoHashMap;
const LRU = @import("util/lru.zig").LRU;
const CompletionPool = std.heap.MemoryPool(xev.Completion);
const StatePool = std.heap.MemoryPool(UDP.State);

// Logging setup
const level: std.log.Level = switch (@import("builtin").mode) {
    .Debug => .debug,
    else => .info,
};
pub const std_options = .{
    .log_level = level,
};
const log = std.log.scoped(.sever);

// Constants
pub const BUFFER_SIZE = 512;
const READ_TIMEOUT_MS = 6000;

// Global vars (for thread sync)
var dns_mutex = Mutex{};
var dns_condition = Thread.Condition{};
var running = AtomicValue(bool).init(false);

pub const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
};

const xev = @import("xev");
const UDP = xev.UDP;

pub const ServerXev = struct {
    options: Options,
    allocator: Allocator,
    dns_cache: LRU(dns.Message),
    dns_store: AutoHashMap(u64, []u8),
    bind_addr: net.Address,
    resolv: []const u8,
    udp: UDP,
    c_read: xev.Completion = undefined,
    c_write: xev.Completion = undefined,
    completion_pool: CompletionPool,
    state_pool: StatePool,

    pub fn init(allocator: Allocator, comptime options: Options) !ServerXev {
        const addr = try net.Address.parseIp(options.bind_addr, options.bind_port);
        const resolv = try getResolv(
            allocator,
            options.external_server,
        );
        errdefer allocator.free(resolv);

        var dns_store = AutoHashMap(u64, []u8).init(allocator);
        errdefer dns_store.deinit();

        // TODO: Populate store with a zone definition
        // This is just a placeholder for testing
        const put = "example.com.";
        var ip_heap = try allocator.alloc(u8, 4);
        errdefer allocator.free(ip_heap);
        @memcpy(ip_heap, &[_]u8{ 192, 168, 1, 1 });
        try dns_store.put(hashFn(put), ip_heap[0..]);

        return .{
            .allocator = allocator,
            .dns_cache = LRU(dns.Message).init(allocator, 100),
            .dns_store = dns_store,
            .bind_addr = addr,
            .options = options,
            .resolv = resolv,
            .udp = try UDP.init(addr),
            .completion_pool = CompletionPool.init(allocator),
            .state_pool = StatePool.init(allocator),
        };
    }

    pub fn deinit(self: *ServerXev) void {
        var cache_itr = self.dns_cache.map.iterator();
        var store_itr = self.dns_store.iterator();
        while (cache_itr.next()) |item| {
            item.value_ptr.*.value.deinit();
        }
        while (store_itr.next()) |item| {
            self.allocator.free(item.value_ptr.*);
        }
        self.allocator.free(self.resolv);
        self.completion_pool.deinit();
        self.state_pool.deinit();
        self.dns_cache.deinit();
        self.dns_store.deinit();
    }

    pub fn handle(self: *ServerXev) void {
        self.run() catch |err| {
            log.err("Error in server run: {}", .{err});
        };
    }

    pub fn run(self: *ServerXev) !void {
        // Send signal to main thread to show we are done
        defer dns_condition.signal();

        var thread_pool = xev.ThreadPool.init(.{});
        defer thread_pool.deinit();
        defer thread_pool.shutdown();
        var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
        defer loop.deinit();

        try self.udp.bind(self.bind_addr);
        log.info("Listen on {any}", .{self.bind_addr});

        while (running.load(.acquire)) {
            try self.read(&loop);
            try loop.run(.no_wait);
        }

        loop.stop();
        self.udp.close(&loop, &self.c_read, void, null, (struct {
            fn callback(
                _: ?*void,
                _: *xev.Loop,
                _: *xev.Completion,
                _: UDP,
                r: UDP.CloseError!void,
            ) xev.CallbackAction {
                _ = r catch unreachable;
                return .disarm;
            }
        }).callback);

        try loop.run(.until_done);
    }

    pub fn read(self: *ServerXev, loop: *xev.Loop) !void {
        var recv_buf: [BUFFER_SIZE]u8 = undefined;
        const c_read = try self.completion_pool.create();
        const s_read = try self.state_pool.create();
        self.udp.read(
            loop,
            c_read,
            s_read,
            .{ .slice = &recv_buf },
            ServerXev,
            self,
            readCallBack,
        );
    }

    pub fn write(self: *ServerXev, loop: *xev.Loop, addr: net.Address, c: *xev.Completion, s: *UDP.State, buf: []u8) !void {
        const response_buf = try self.allocator.alloc(u8, 512);
        const len = try handleDnsQuery(
            self,
            buf[0..],
            response_buf,
        );
        _ = len;

        //defer self.message_pool.destroy(buf);

        self.udp.write(
            loop,
            c,
            s,
            addr,
            .{ .slice = response_buf },
            ServerXev,
            self,
            (struct {
                fn callback(
                    user_data: ?*ServerXev,
                    _: *xev.Loop,
                    cw: *xev.Completion,
                    sw: *UDP.State,
                    _: UDP,
                    buff: xev.WriteBuffer,
                    r: UDP.WriteError!usize,
                ) xev.CallbackAction {
                    _ = r catch unreachable;
                    const server = user_data.?;
                    server.allocator.free(buff.slice);
                    server.completion_pool.destroy(cw);
                    server.state_pool.destroy(sw);
                    return .disarm;
                }
            }).callback,
        );
    }

    // Callback for after reading from socket
    fn readCallBack(
        ud: ?*ServerXev,
        loop: *xev.Loop,
        c: *xev.Completion,
        s: *xev.UDP.State,
        addr: net.Address,
        _: UDP,
        buf: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        const len = r catch |err| {
            log.err("Read error: {}\n", .{err});
            return .rearm;
        };
        if (ud) |user_data| {
            //const response_buf = user_data.message_pool.create() catch unreachable;
            //std.mem.copyForwards(u8, response_buf, buf.slice[0..]);
            user_data.write(loop, addr, c, s, buf.slice[0..len]) catch |err| {
                log.err("Error in write: {}\n", .{err});
                return .rearm;
            };
        }

        return xev.CallbackAction.disarm;
    }

    fn handleDnsQuery(
        user_data: *ServerXev,
        query: []const u8,
        response: []u8,
    ) !usize {
        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        var len: usize = 0;

        var packet = try dns.Message.fromBytes(user_data.allocator, query);
        var response_packet = dns.Message.init(user_data.allocator);
        defer response_packet.deinit();
        defer packet.deinit();
        createDnsResponse(&response_packet, packet);

        log.debug("Received DNS Packet: {any}", .{packet.header});

        for (packet.questions.items) |*question| {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            const qname = try question.qnameToString(&qname_buf);
            //std.debug.print("Qname: {s}\n", .{qname});
            const qname_hash = hashFn(qname);

            if (user_data.dns_cache.get(qname_hash)) |*cached_response| {
                // TODO: this only works if there is one question
                var non_const_response = cached_response.*;

                // Return cached response
                log.debug("Cache hit for {s}", .{qname});
                non_const_response.header.id = packet.header.id;

                const bytes = try non_const_response.bytes(response);

                len = bytes.len;
            } else if (user_data.dns_store.get(qname_hash)) |address| {
                // Return local response
                log.debug("Found in local store: {s} -> {any}", .{ qname, address });

                try updateDnsResponse(&response_packet, question.*, address);
                const bytes = try response_packet.bytes(response);
                len = bytes.len;
            } else {
                // TODO: This only works if theres one question
                // Query external server
                log.debug("Not found in local store, querying external server...", .{});
                const external_len = try queryExternalServer(
                    user_data.resolv,
                    query,
                    response,
                );
                const res = try dns.Message.fromBytes(
                    user_data.dns_cache.allocator,
                    response[0..external_len],
                );
                try user_data.dns_cache.put(qname_hash, res);
                len = external_len;
            }
        }
        return len;
    }
};

fn queryExternalServer(resolv: []const u8, query: []const u8, response: []u8) !usize {
    // TODO: Placeholder implementation
    const external_server_port = 53;

    const addr = try net.Address.parseIp(resolv, external_server_port);
    const sock = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );
    defer posix.close(sock);

    var from_addr: posix.sockaddr = undefined;
    var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
    _ = try posix.sendto(
        sock,
        query,
        0,
        &addr.any,
        addr.getOsSockLen(),
    );

    var buf: [512]u8 = undefined;
    const recv_bytes = try posix.recvfrom(
        sock,
        buf[0..],
        0,
        &from_addr,
        &from_addrlen,
    );
    std.mem.copyForwards(u8, response, buf[0..recv_bytes]);
    return recv_bytes;
}

inline fn createDnsResponse(message: *dns.Message, packet: dns.Message) void {
    message.header = dns.Header{
        .id = packet.header.id,
        .flags = dns.Header.Flags{
            .qr = true,
            .opcode = dns.Header.Opcode.query,
            .aa = false,
            .tc = false,
            .rd = packet.header.flags.rd,
            .ra = true,
            .rcode = dns.Header.ResponseCode.no_error,
        },
        .qcount = packet.header.qcount,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };
}

inline fn updateDnsResponse(message: *dns.Message, question: dns.Question, address: []u8) !void {
    // TODO: Something here is causing more memory to be allocated than we need
    var q = try message.addQuestion();
    q.qtype = question.qtype;
    q.qclass = question.qclass;
    try q.qnameCloneOther(question.qname);
    var ans = try message.addAnswer();
    try ans.nameCloneOther(question.qname);
    try ans.rdataAppendSlice(address);
    ans.type = dns.Record.Type.a;
    ans.class = dns.Record.Class.in;
    ans.ttl = 300;
    ans.rdlength = @as(u16, @intCast(address.len));
}

inline fn createDnsError(allocator: Allocator, err: dns.Header.ResponseCode) dns.Message {
    var message = dns.Message.init(allocator);
    message.header = dns.Header{
        .id = 0,
        .flags = dns.Header.Flags{
            .qr = true,
            .opcode = dns.Header.Opcode.query,
            .aa = false,
            .tc = false,
            .rd = false,
            .ra = true,
            .rcode = err,
        },
        .qcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
    return message;
}

fn getResolv(allocator: Allocator, external_server: ?[]const u8) ![]const u8 {
    if (external_server) |r| {
        const ret = try allocator.alloc(u8, r.len);
        std.mem.copyForwards(u8, ret, r);
        return ret;
    }
    const file = try std.fs.openFileAbsolute("/etc/resolv.conf", .{});
    defer file.close();

    const resolv_contents = try file.reader().readAllAlloc(
        allocator,
        (try file.stat()).size,
    );
    defer allocator.free(resolv_contents);

    if (std.mem.indexOf(u8, resolv_contents, "nameserver")) |i| {
        const start_index = i + 11;
        const end_index = std.mem.indexOf(
            u8,
            resolv_contents[start_index..],
            "\n",
        ).? + start_index;

        const ret = try allocator.alloc(u8, end_index - start_index);
        std.mem.copyForwards(u8, ret, resolv_contents[start_index..end_index]);
        return ret;
    } else {
        const ret = try allocator.alloc(u8, 7);
        std.mem.copyForwards(u8, ret, "8.8.8.8");
        return ret;
    }
}

fn hashFn(data: []const u8) u64 {
    const p: u64 = 31;
    const m: u64 = 1e9 + 9;
    var hash: u64 = 0;
    var p_pow: u64 = 1;
    for (data) |byte| {
        hash = (hash + byte * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    //const allocator = std.heap.raw_c_allocator;
    const stdin = std.io.getStdIn().reader();

    var server = try ServerXev.init(
        allocator,
        .{ .bind_port = 5553 },
    );
    defer server.deinit();

    var main_thread = try Thread.spawn(
        .{},
        ServerXev.handle,
        .{&server},
    );

    running.store(true, .monotonic);
    while (running.load(.acquire)) {
        const in = try stdin.readUntilDelimiterAlloc(
            allocator,
            '\n',
            100,
        );
        defer allocator.free(in);
        if (std.mem.eql(u8, in, "q")) {
            running.store(false, .release);
        }
    }

    dns_mutex.lock();
    dns_condition.wait(&dns_mutex);
    dns_mutex.unlock();
    main_thread.join();
}
