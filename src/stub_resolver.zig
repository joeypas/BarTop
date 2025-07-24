const std = @import("std");
const Message = @import("message.zig");
const net = std.net;
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const AtomicValue = std.atomic.Value;
const AutoHashMap = std.AutoHashMap;
const LRU = @import("util/cache.zig").LRU;
const CompletionPool = std.heap.MemoryPoolExtra(xev.Completion, .{ .alignment = @alignOf(xev.Completion) });
const StatePool = std.heap.MemoryPoolExtra(UDP.State, .{ .alignment = @alignOf(UDP.State) });

// TODO: For the whole project
// 1. Implement Timeout/backup server to ask if timeout is too long
// 2. Validate Messages
// 3. Return correct errors when we encounter one
// 4. Async reads/writes when querying external server

// Logging setup
const level: std.log.Level = switch (@import("builtin").mode) {
    .Debug => .debug,
    else => .info,
};
const std_options = std.Options{
    .log_level = level,
};
const log = std.log.scoped(.server);

// Constants
const BUFFER_SIZE = 1024;
const READ_TIMEOUT_MS = 6000;

// Global vars (for thread sync)
var dns_mutex = Mutex{};
var dns_condition = std.Thread.Condition{};
var running = AtomicValue(bool).init(false);

pub const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
};

const xev = @import("xev");
const UDP = xev.UDP;

pub const StubResolver = struct {
    options: Options,
    allocator: Allocator,
    dns_cache: LRU(Message.Message),
    bind_addr: net.Address,
    resolv: []const u8,
    udp: UDP,
    loop: xev.Loop,
    timer: xev.Timer,
    c_read: xev.Completion = undefined,
    c_timer: xev.Completion = undefined,
    completion_pool: CompletionPool,
    state_pool: StatePool,
    arena: std.heap.ArenaAllocator,
    thread_pool: xev.ThreadPool,

    pub fn init(allocator: Allocator, comptime options: Options) !StubResolver {
        var thread_pool = xev.ThreadPool.init(.{});
        errdefer thread_pool.deinit();

        var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
        errdefer loop.deinit();

        var timer = try xev.Timer.init();
        errdefer timer.deinit();

        const addr = try net.Address.parseIp(options.bind_addr, options.bind_port);
        const resolv = try getResolv(
            allocator,
            options.external_server,
        );
        errdefer allocator.free(resolv);

        const udp = try UDP.init(addr);

        return .{
            .allocator = allocator,
            .dns_cache = LRU(Message.Message).init(allocator, 512),
            .bind_addr = addr,
            .options = options,
            .resolv = resolv,
            .udp = udp,
            .loop = loop,
            .timer = timer,
            .completion_pool = CompletionPool.init(allocator),
            .state_pool = StatePool.init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
            .thread_pool = thread_pool,
        };
    }

    pub fn deinit(self: *StubResolver) void {
        self.loop.deinit();
        self.thread_pool.deinit();
        self.arena.deinit();
        self.allocator.free(self.resolv);
        self.completion_pool.deinit();
        self.state_pool.deinit();
        self.dns_cache.deinit();
    }

    pub fn handle(self: *StubResolver) void {
        self.start() catch |err| {
            log.err("Error in server run: {}", .{err});
        };
    }

    pub fn start(self: *StubResolver) !void {
        // Send signal to main thread to show we are done
        defer dns_condition.signal();

        try self.udp.bind(self.bind_addr);
        log.info("Listen on {any}", .{self.bind_addr});

        try self.read(&self.loop);
        self.timer.run(&self.loop, &self.c_timer, 1000, StubResolver, self, timerCallback);
        try self.loop.run(.until_done);

        self.loop.stop();
        self.udp.close(&self.loop, &self.c_read, void, null, (struct {
            fn callback(
                _: ?*void,
                _: *xev.Loop,
                _: *xev.Completion,
                _: UDP,
                r: xev.CloseError!void,
            ) xev.CallbackAction {
                _ = r catch unreachable;
                return .disarm;
            }
        }).callback);

        try self.loop.run(.until_done);
        self.thread_pool.shutdown();
    }

    // We need this to run once every second to update ttl values, and remove
    // stale records
    //
    // Is this overkill? probably
    // I could just store the time the request was recieved
    // and update ttl/remove stale records when theres a cache hit
    // but thats also in the hot path so idk
    fn timerCallback(
        self_: ?*StubResolver,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        var self = self_.?;
        _ = result catch unreachable;

        var itr = self.dns_cache.map.valueIterator();

        while (itr.next()) |value| {
            for (0..value.*.value.answers.items.len) |i| {
                var item = &value.*.value.answers.items[i];
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                }
                item.ttl -= 1;
            }
            for (value.*.value.authorities.items) |*item| {
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                }
                item.ttl -= 1;
            }
            for (value.*.value.additionals.items) |*item| {
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                }
                item.ttl -= 1;
            }
        }

        if (running.load(.acquire)) {
            self.timer.run(loop, &self.c_timer, 1000, StubResolver, self, timerCallback);
        }

        return .disarm;
    }

    pub fn read(self: *StubResolver, loop: *xev.Loop) !void {
        var allocator = self.arena.allocator();
        var recv_buf = try allocator.alloc(u8, BUFFER_SIZE);
        const c_read = try self.completion_pool.create();
        const s_read = try self.state_pool.create();
        self.udp.read(
            loop,
            c_read,
            s_read,
            .{ .slice = recv_buf[0..] },
            StubResolver,
            self,
            readCallback,
        );
    }

    pub fn write(
        self: *StubResolver,
        loop: *xev.Loop,
        addr: net.Address,
        buf: []u8,
    ) !void {
        var allocator = self.arena.allocator();
        var response_buf = try allocator.alloc(u8, BUFFER_SIZE);
        const len = try handleDnsQuery(
            self,
            buf[0..],
            response_buf,
        );

        const c_write = try self.completion_pool.create();
        const s_write = try self.state_pool.create();
        response_buf = try allocator.realloc(response_buf, len);

        self.udp.write(
            loop,
            c_write,
            s_write,
            addr,
            .{ .slice = response_buf },
            StubResolver,
            self,
            (struct {
                fn callback(
                    user_data: ?*StubResolver,
                    _: *xev.Loop,
                    cw: *xev.Completion,
                    sw: *UDP.State,
                    _: UDP,
                    buff: xev.WriteBuffer,
                    r: xev.WriteError!usize,
                ) xev.CallbackAction {
                    _ = r catch unreachable;
                    const server = user_data.?;
                    server.arena.allocator().free(buff.slice);
                    server.completion_pool.destroy(cw);
                    server.state_pool.destroy(sw);
                    return .disarm;
                }
            }).callback,
        );
    }

    // Callback for after reading from socket
    fn readCallback(
        ud: ?*StubResolver,
        _: *xev.Loop,
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
            if (running.load(.acquire)) {
                user_data.read(&user_data.loop) catch |err| {
                    log.err("Error in read: {}\n", .{err});
                    return .rearm;
                };
            }
            user_data.completion_pool.destroy(c);
            user_data.state_pool.destroy(s);
            user_data.write(&user_data.loop, addr, buf.slice[0..len]) catch |err| {
                log.err("Error in write: {}\n", .{err});
                return .disarm;
            };
            user_data.arena.allocator().free(buf.slice);
        }

        return xev.CallbackAction.disarm;
    }

    fn handleDnsQuery(
        user_data: *StubResolver,
        query: []const u8,
        response: []u8,
    ) !usize {
        // TODO: Return error messages when error is encountered
        const allocator = user_data.arena.allocator();
        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        var fbr = std.io.fixedBufferStream(query);
        var fbw = std.io.fixedBufferStream(response);

        var packet = try Message.Message.decode(allocator, fbr.reader().any());
        var response_packet = Message.Message.init(allocator);
        // doing alot of copying but we dont want to have to clone allocations
        response_packet.ref = true;
        defer response_packet.deinit();
        defer packet.deinit();
        try createDnsResponse(&response_packet, &packet);

        log.debug("Received DNS Packet:\n{s}", .{packet});

        for (packet.questions.items) |*question| {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            // Add the question type so we don't accidentally get a cache entry for
            // another type of question
            const qname = try question.qname.print(&qname_buf, question.qtype);
            //std.debug.print("Qname: {s}\n", .{qname});
            const qname_hash = hashFn(qname);

            if (user_data.dns_cache.get(qname_hash)) |*cached_response| {
                log.debug("Cache hit for {s}", .{qname});

                // Add cached records to our response
                try glue(&response_packet, cached_response.*);
            } else {
                log.debug("Not found in local store, querying external server...", .{});
                var tmp_response: [BUFFER_SIZE]u8 = undefined;
                const external_len = try queryExternalServer(
                    user_data.resolv,
                    query,
                    &tmp_response,
                );

                var tmp_reader = std.io.fixedBufferStream(tmp_response[0..external_len]);
                const res = Message.Message.decode(
                    allocator,
                    tmp_reader.reader().any(),
                ) catch |err| {
                    log.err("in decode", .{});
                    return err;
                };

                // Add external records to our response
                try glue(&response_packet, res);

                try user_data.dns_cache.put(qname_hash, res);
            }
        }

        log.debug("Sending DNS Packet:\n{s}", .{response_packet});
        return response_packet.encode(fbw.writer().any());
    }
};

// Copy records from one message to another
// Update: only copy references
fn glue(message: *Message.Message, other: Message.Message) !void {
    try message.answers.appendSlice(other.answers.items);
    message.header.an_count += other.header.an_count;

    try message.authorities.appendSlice(other.authorities.items);
    message.header.ns_count += other.header.ns_count;

    try message.additionals.appendSlice(other.additionals.items);
    message.header.ar_count += other.header.ar_count;
}

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

    var buf: [BUFFER_SIZE]u8 = undefined;
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

inline fn createDnsResponse(message: *Message.Message, packet: *Message.Message) !void {
    message.header = Message.Header{
        .id = packet.header.id,
        .flags = Message.Flags{
            .response = true,
            .op_code = .query,
            .authoritative = false,
            .truncated = false,
            .recursion_desired = packet.header.flags.recursion_desired,
            .recursion_available = true,
            .response_code = .no_error,
        },
        .qd_count = packet.header.qd_count,
        .an_count = 0,
        .ns_count = 0,
        .ar_count = 0,
    };

    try message.questions.appendSlice(packet.questions.items);
}

inline fn createDnsError(allocator: Allocator, err: Message.ResponseCode) Message.Message {
    var message = Message.Message.init(allocator);
    message.header = Message.Header{
        .id = 0,
        .flags = Message.Flags{
            .response = true,
            .op_code = .query,
            .authoritative = false,
            .truncated = false,
            .recursion_desired = false,
            .recursion_available = true,
            .response_code = err,
        },
        .qd_count = 0,
        .an_count = 0,
        .ns_count = 0,
        .ar_count = 0,
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
        std.mem.copyForwards(u8, ret, "1.1.1.1");
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

pub fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stdin = std.io.getStdIn().reader();

    var server = try StubResolver.init(
        allocator,
        .{
            .bind_port = 5533,
            .external_server = "8.8.8.8",
        },
    );
    defer server.deinit();

    var main_thread = try std.Thread.spawn(
        .{},
        StubResolver.handle,
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
