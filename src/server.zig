const std = @import("std");
const dns = @import("dns.zig");
const net = std.net;
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const AutoHashMap = std.AutoHashMap;
const LRU = @import("util/lru.zig").LRU;
const Loop = @import("poll.zig").Loop;

//pub const Server = @This();
pub const BUFFER_SIZE = 512;
var dns_mutex = Mutex{};
var condition = Thread.Condition{};
var running: bool = false;
const READ_TIMEOUT_MS = 60_000;

const ClientList = std.DoublyLinkedList(*Client);
const ClientNode = ClientList.Node;

pub const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
    n_jobs: ?u32 = null,
};

pub const Server = struct {
    allocator: Allocator,
    dns_cache: LRU(dns.Message),
    dns_store: AutoHashMap(u64, []const u8),
    pool: Thread.Pool,
    resolv: []const u8,
    sock: posix.socket_t,
    options: Options = Options{},

    pub fn init(allocator: Allocator, comptime options: Options) !Server {
        return .{
            .dns_cache = LRU(dns.Message).init(allocator, 100),
            .dns_store = AutoHashMap(u64, []const u8).init(allocator),
            .resolv = try getResolv(allocator, options.external_server),
            .allocator = allocator,
            //.arena = std.heap.ArenaAllocator.init(allocator),
            .pool = undefined,
            .sock = try posix.socket(
                posix.AF.INET,
                posix.SOCK.DGRAM | posix.SOCK.NONBLOCK,
                posix.IPPROTO.UDP,
            ),
            .options = options,
        };
    }

    pub fn deinit(self: *Server) void {
        self.allocator.free(self.resolv);
        posix.close(self.sock);
        var itr = self.dns_cache.map.iterator();
        while (itr.next()) |item| {
            item.value_ptr.*.value.deinit();
        }
        self.dns_cache.deinit();
        self.dns_store.deinit();
    }

    pub fn handle(self: *Server) void {
        self.run() catch |err| {
            std.debug.print("Error in server run: {}\n", .{err});
        };
    }

    pub fn run(self: *Server) !void {
        // TODO: Change this line with local dns info
        const put = "example.com.";
        try self.dns_store.put(hashFn(put), &[4]u8{ 192, 168, 1, 1 });

        const addr = try net.Address.parseIp(self.options.bind_addr, self.options.bind_port);

        try posix.bind(self.sock, &addr.any, addr.getOsSockLen());

        std.debug.print("Listen on {any}\n", .{addr});

        var thread_safe = std.heap.ThreadSafeAllocator{
            .child_allocator = self.allocator,
        };
        const alloc = thread_safe.allocator();

        try Thread.Pool.init(&self.pool, .{
            .allocator = alloc,
            .n_jobs = self.options.n_jobs orelse @intCast(try Thread.getCpuCount() - 1),
        });

        var buffer: [BUFFER_SIZE]u8 = undefined;

        //var count: usize = 0;
        while (running) {
            var from_addr: net.Address = undefined;
            var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
            const recv_len = posix.recvfrom(
                self.sock,
                buffer[0..],
                posix.SOCK.NONBLOCK,
                &from_addr.any,
                &from_addrlen,
            ) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => break,
            };
            std.debug.print("Received {d} bytes from {any};\n", .{ recv_len, from_addr });
            var client = Client{
                .socket = self.sock,
                .address = from_addr,
                .recv_len = recv_len,
                .allocator = &thread_safe,
                .store_ptr = &self.dns_store,
                .cache_ptr = &self.dns_cache,
                .resolv = self.resolv[0..],
            };
            std.mem.copyForwards(u8, client.buffer[0..], buffer[0..]);

            // Spawn thread to handle DNS query
            try self.pool.spawn(Client.handle, .{client});
        }

        dns_mutex.lock();
        defer dns_mutex.unlock();
        //condition.wait(&dns_mutex);
        self.pool.deinit();
    }
};

pub const Client = struct {
    socket: posix.fd_t,
    address: std.net.Address,
    buffer: [BUFFER_SIZE]u8 = undefined,
    recv_len: usize,
    allocator: *std.heap.ThreadSafeAllocator,
    store_ptr: *AutoHashMap(u64, []const u8),
    cache_ptr: *LRU(dns.Message),
    resolv: []const u8,

    fn handle(self: Client) void {
        self.handleDnsQuery() catch |err| {
            dns_mutex.lock();
            defer dns_mutex.unlock();
            std.io.getStdErr().writer().print(
                "[{any}] client handle error: {}\n",
                .{ self.address, err },
            ) catch {};
            var message = createDnsError(self.allocator.allocator(), .format_error);
            defer message.deinit();
            const bytes = message.bytesAlloc(self.allocator.allocator()) catch "  ";
            defer self.allocator.allocator().free(bytes);
            _ = posix.sendto(
                self.socket,
                bytes,
                0,
                &self.address.any,
                self.address.getOsSockLen(),
            ) catch |serr| {
                std.io.getStdErr().writer().print(
                    "[{any}] client handle error: {}\n",
                    .{ self.address, serr },
                ) catch {};
            };
        };
    }

    fn handleDnsQuery(self: Client) !void {
        const alloc = self.allocator.allocator();
        const query = self.buffer[0..self.recv_len];
        var response: [BUFFER_SIZE]u8 = undefined;

        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        defer condition.signal();
        var len: usize = 0;

        var packet = try dns.Message.fromBytes(alloc, query);
        defer packet.deinit();

        var response_packet = dns.Message.init(alloc);
        defer response_packet.deinit();
        createDnsResponse(&response_packet, packet);
        ////std.debug.print("Received DNS Packet: {any}\n", .{packet});

        for (packet.questions.items) |*question| {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            const qname = try question.qnameToString(&qname_buf);
            //std.debug.print("Qname: {s}\n", .{qname});
            const qname_hash = hashFn(qname);

            dns_mutex.lock();
            defer dns_mutex.unlock();
            if (self.cache_ptr.get(qname_hash)) |cached_response| {
                // TODO: this only works if there is one question
                const non_const_response: *dns.Message = @constCast(&cached_response);

                // Return cached response
                //std.debug.print("Cache hit for {s}\n", .{qname});
                non_const_response.header.id = packet.header.id;

                //try response_packet.copyFromOther(non_const_response.*);
                const bytes = try non_const_response.bytes(&response);

                len = bytes.len;
                break;
            } else if (self.store_ptr.get(qname_hash)) |address| {
                // Return local response
                //std.debug.print("Found in local store: {s} -> {any}\n", .{ qname, address });

                try updateDnsResponse(&response_packet, question.*, address[0..]);
                const bytes = try response_packet.bytes(&response);
                len = bytes.len;
                break;
            } else {
                // TODO: This only works if theres one question

                // Query external server
                //std.debug.print("Not found in local store, querying external server...\n", .{});

                const external_len = try self.queryExternalServer(query, &response);

                const res = try dns.Message.fromBytes(self.cache_ptr.allocator, response[0..external_len]);
                //try response_packet.copyFromOther(res);
                try self.cache_ptr.put(qname_hash, res);
                len = external_len;
                break;
            }
        }

        //const res = try response_packet.bytes(response[0..]);
        ////std.debug.print("Sending: {x}\n", .{response[0..len]});

        dns_mutex.lock();
        defer dns_mutex.unlock();
        _ = try posix.sendto(
            self.socket,
            response[0..len],
            0,
            &self.address.any,
            self.address.getOsSockLen(),
        );
    }

    inline fn queryExternalServer(self: Client, query: []const u8, response: []u8) !usize {
        // TODO: Placeholder implementation
        const external_server_port = 53;

        const addr = try net.Address.parseIp(self.resolv, external_server_port);
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
        const recv_bytes = try posix.recvfrom(sock, buf[0..], 0, &from_addr, &from_addrlen);

        std.mem.copyForwards(u8, response, buf[0..recv_bytes]);
        return recv_bytes;
    }
};

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

inline fn updateDnsResponse(message: *dns.Message, question: dns.Question, address: []const u8) !void {
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
        const end_index = std.mem.indexOf(u8, resolv_contents[start_index..], "\n").? + start_index;

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
    const stdin = std.io.getStdIn().reader();

    var server = try Server.init(allocator, .{ .bind_port = 5553, .n_jobs = 8 });
    defer server.deinit();

    running = true;

    var main_thread = try Thread.spawn(.{}, Server.handle, .{&server});

    while (running) {
        const in = try stdin.readUntilDelimiterAlloc(allocator, '\n', 100);
        defer allocator.free(in);
        if (std.mem.eql(u8, in, "q")) {
            dns_mutex.lock();
            defer dns_mutex.unlock();
            running = false;
        }
    }

    main_thread.join();
}
