const std = @import("std");
const Message = @import("message.zig");
const net = std.net;
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const AutoHashMap = std.AutoHashMap;
const LRU = @import("util/cache.zig").LRU;

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

var dns_mutex = Mutex{};
var dns_condition = std.Thread.Condition{};

pub const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
    thread_count: usize = 8,
};

const xev = @import("xev");
const UDP = xev.UDP;

const AsyncContext = struct {
    self: *Thread,
    question: Message.Message,
    message: Message.Message,
    addr: std.net.Address,
    recv_buf: [BUFFER_SIZE]u8 = undefined,
    send_buf: [BUFFER_SIZE]u8 = undefined,
    state: UDP.State = undefined,
    completion: xev.Completion = .{},
    wait_completion: xev.Completion = .{},
};

const ExternalContext = struct {
    self: *Thread,
    qname_hash: u64,
    message: *Message.Message,
    recv_buf: [BUFFER_SIZE]u8 = undefined,
    send_buf: [BUFFER_SIZE]u8 = undefined,
    state: UDP.State = undefined,
    completion: xev.Completion = .{},
};

const ContextPool = std.heap.MemoryPoolExtra(AsyncContext, .{ .alignment = @alignOf(AsyncContext) });

const ExtContextPool = std.heap.MemoryPoolExtra(ExternalContext, .{ .alignment = @alignOf(ExternalContext) });

pub const Thread = struct {
    dns_cache: LRU(Message.Message),
    bind_addr: net.Address,
    resolv: net.Address,
    udp: UDP,
    ext_udp: UDP,
    notifier: xev.Async,
    shutdown_notifier: xev.Async,
    c_shutdown: xev.Completion = undefined,
    loop: xev.Loop,
    timer: xev.Timer,
    c_read: xev.Completion = undefined,
    c_timer: xev.Completion = undefined,
    context_pool: ContextPool,
    ext_context_pool: ExtContextPool,
    arena: std.heap.ArenaAllocator,
    thread_pool: xev.ThreadPool,

    pub fn init(allocator: Allocator, options: Options) !Thread {
        var thread_pool = xev.ThreadPool.init(.{});
        errdefer thread_pool.deinit();

        var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
        errdefer loop.deinit();

        var timer = try xev.Timer.init();
        errdefer timer.deinit();

        const addr = try net.Address.parseIp(options.bind_addr, options.bind_port);

        const resolv = try net.Address.parseIp(options.external_server orelse "8.8.8.8", 53);
        var notifier = try xev.Async.init();
        errdefer notifier.deinit();

        var shutdown_notifier = try xev.Async.init();
        errdefer shutdown_notifier.deinit();

        const udp = try UDP.init(addr);
        const ext_udp = try UDP.init(addr);

        return .{
            .dns_cache = LRU(Message).init(allocator, 512),
            .bind_addr = addr,
            .resolv = resolv,
            .udp = udp,
            .ext_udp = ext_udp,
            .notifier = notifier,
            .shutdown_notifier = shutdown_notifier,
            .loop = loop,
            .timer = timer,
            .context_pool = ContextPool.init(allocator),
            .ext_context_pool = ExtContextPool.init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
            .thread_pool = thread_pool,
        };
    }

    pub fn deinit(self: *Thread) void {
        self.dns_cache.deinit();
        self.context_pool.deinit();
        self.ext_context_pool.deinit();
        self.notifier.deinit();
        self.shutdown_notifier.deinit();
        self.loop.deinit();
        self.thread_pool.deinit();
        self.arena.deinit();
    }

    pub fn handle(self: *Thread, id: usize) void {
        self.start() catch |err| {
            log.err("Error in Thread {d} run: {}", .{ id, err });
        };
    }

    pub fn start(self: *Thread) !void {
        try self.udp.bind(self.bind_addr);
        log.info("Listen on {any}", .{self.bind_addr});

        try self.read();
        self.timer.run(&self.loop, &self.c_timer, 1000, Thread, self, timerCallback);
        self.shutdown_notifier.wait(&self.loop, &self.c_shutdown, Thread, self, stopCallback);
        try self.loop.run(.until_done);
    }

    pub fn notifyShutdown(self: *Thread) !void {
        try self.shutdown_notifier.notify();
    }

    fn stop(self: *Thread) !void {
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

        self.ext_udp.close(&self.loop, &self.c_read, void, null, (struct {
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
        dns_condition.signal();
    }

    fn stopCallback(
        ud: ?*Thread,
        _: *xev.Loop,
        _: *xev.Completion,
        r: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = r catch undefined;
        if (ud) |user_data| {
            user_data.loop.stop();
            user_data.stop() catch unreachable;
        }
        return .disarm;
    }

    // We need this to run once every second to update ttl values, and remove
    // stale records
    //
    // Is this overkill? probably
    // I could just store the time the request was recieved
    // and update ttl/remove stale records when theres a cache hit
    // but thats also in the hot path so idk
    fn timerCallback(
        self_: ?*Thread,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        var self = self_.?;
        _ = result catch return .rearm;

        var itr = self.dns_cache.map.valueIterator();

        while (itr.next()) |value| {
            for (value.*.value.answers.items) |*item| {
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                    self.timer.run(loop, &self.c_timer, 1000, Thread, self, timerCallback);

                    return .disarm;
                }
                item.ttl -= 1;
            }
            for (value.*.value.authorities.items) |*item| {
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                    self.timer.run(loop, &self.c_timer, 1000, Thread, self, timerCallback);

                    return .disarm;
                }
                item.ttl -= 1;
            }
            for (value.*.value.additionals.items) |*item| {
                if (item.ttl == 0) {
                    value.*.value.deinit();
                    self.dns_cache.remove(value.*.key);
                    self.timer.run(loop, &self.c_timer, 1000, Thread, self, timerCallback);

                    return .disarm;
                }
                item.ttl -= 1;
            }
        }

        self.timer.run(loop, &self.c_timer, 1000, Thread, self, timerCallback);

        return .disarm;
    }

    fn read(self: *Thread) !void {
        var context = try self.context_pool.create();
        context.self = self;
        self.udp.read(
            &self.loop,
            &context.completion,
            &context.state,
            .{ .slice = context.recv_buf[0..] },
            AsyncContext,
            context,
            readCallback,
        );
    }

    fn asyncCallback(
        ud: ?*AsyncContext,
        _: *xev.Loop,
        _: *xev.Completion,
        r: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = r catch |err| {
            log.err("Error in async callback: {}", .{err});
            return .rearm;
        };
        if (ud) |context| {
            write(context) catch |err| {
                log.err("Error in write: {}", .{err});
                return .disarm;
            };
        }
        return .disarm;
    }

    fn write(context: *AsyncContext) !void {
        var self = context.self;
        var message = context.message;

        var fbw = std.io.fixedBufferStream(&context.send_buf);

        const len = try message.encode(fbw.writer().any());

        const addr = context.addr;

        self.udp.write(
            &self.loop,
            &context.completion,
            &context.state,
            addr,
            .{ .slice = context.send_buf[0..len] },
            AsyncContext,
            context,
            (struct {
                fn callback(
                    user_data: ?*AsyncContext,
                    _: *xev.Loop,
                    _: *xev.Completion,
                    _: *UDP.State,
                    _: UDP,
                    _: xev.WriteBuffer,
                    r: xev.WriteError!usize,
                ) xev.CallbackAction {
                    _ = r catch |err| {
                        log.err("Error writing to client: {}", .{err});
                        return .rearm;
                    };
                    const server = user_data.?;
                    server.self.context_pool.destroy(server);
                    return .disarm;
                }
            }).callback,
        );
    }

    fn handlePacket(
        self: *Thread,
        context: *AsyncContext,
        buf: []u8,
    ) !void {
        const allocator = self.arena.allocator();
        var fbr = std.io.fixedBufferStream(buf);

        context.question = try Message.Message.decode(allocator, fbr.reader().any());
        context.message = Message.Message.init(allocator);
        context.message.ref = true;

        errdefer context.question.deinit();
        errdefer context.message.deinit();
        errdefer self.context_pool.destroy(context);

        try createDnsResponse(&context.message, &context.question);
        self.notifier.wait(&self.loop, &context.wait_completion, AsyncContext, context, asyncCallback);

        try handleDnsQuery(
            self,
            buf[0..],
            &context.message,
            &context.question,
        );
    }

    // Callback for after reading from socket
    fn readCallback(
        ud: ?*AsyncContext,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
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
            user_data.self.read() catch |err| {
                log.err("Error in read: {}\n", .{err});
                return .rearm;
            };
            user_data.addr = addr;
            user_data.self.handlePacket(user_data, buf.slice[0..len]) catch |err| {
                log.err("Error in write: {}\n", .{err});
                return .disarm;
            };
        }

        return xev.CallbackAction.disarm;
    }

    fn handleDnsQuery(
        self: *Thread,
        query: []const u8,
        response: *Message.Message,
        packet: *Message.Message,
    ) !void {
        // TODO: Return error messages when error is encountered
        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        var did_ask = false;

        log.debug("Received DNS Packet:\n{s}", .{packet});

        for (packet.questions.items) |*question| {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            // Add the question type so we don't accidentally get a cache entry for
            // another type of question
            const qname = try question.qname.print(&qname_buf, question.qtype);
            //std.debug.print("Qname: {s}\n", .{qname});
            const qname_hash = hashFn(qname);

            if (self.dns_cache.get(qname_hash)) |*cached_response| {
                log.debug("Cache hit for {s}", .{qname});

                // Add cached records to our response
                try glue(response, cached_response.*);
            } else {
                log.debug("Not found in local store, querying external server...", .{});
                const ext_context = try self.ext_context_pool.create();
                ext_context.* = ExternalContext{
                    .self = self,
                    .message = response,
                    .qname_hash = qname_hash,
                };
                @memcpy(ext_context.send_buf[0..query.len], query);
                self.ext_udp.write(
                    &self.loop,
                    &ext_context.completion,
                    &ext_context.state,
                    self.resolv,
                    .{ .slice = ext_context.send_buf[0..query.len] },
                    ExternalContext,
                    ext_context,
                    externalWriteCallback,
                );
                did_ask = true;
            }
        }

        if (!did_ask) try self.notifier.notify();
    }

    fn externalWriteCallback(
        ud: ?*ExternalContext,
        loop: *xev.Loop,
        cw: *xev.Completion,
        sw: *UDP.State,
        _: UDP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        _ = r catch |err| {
            log.err("Error in External Write: {}", .{err});
            return .rearm;
        };

        if (ud) |user_data| {
            user_data.self.ext_udp.read(
                loop,
                cw,
                sw,
                .{ .slice = user_data.recv_buf[0..] },
                ExternalContext,
                user_data,
                externalReadCallback,
            );
        }

        return .disarm;
    }

    fn externalReadCallback(
        ud: ?*ExternalContext,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: net.Address,
        _: UDP,
        buf: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        const len = r catch |err| {
            log.err("Error reading from External Server: {}", .{err});
            return .rearm;
        };
        var tmp_reader = std.io.fixedBufferStream(buf.slice[0..len]);
        if (ud) |user_data| {
            defer user_data.self.ext_context_pool.destroy(user_data);
            const allocator = user_data.self.arena.allocator();
            const res = Message.Message.decode(
                allocator,
                tmp_reader.reader().any(),
            ) catch |err| {
                log.err("Error decoding external message: {}", .{err});
                return .disarm;
            };

            // Add external records to our response
            glue(user_data.message, res) catch |err| {
                log.err("Error preforming glue: {}", .{err});
                return .disarm;
            };

            user_data.self.dns_cache.put(user_data.qname_hash, res) catch |err| {
                log.err("Error storing message in cache: {}", .{err});
            };

            user_data.self.notifier.notify() catch |err| {
                log.err("Error notifying: {}", .{err});
                return .disarm;
            };
        }
        return .disarm;
    }
};

pub fn StubResolver(comptime options: Options) type {
    return struct {
        const Self = @This();
        allocator: Allocator,
        thread_pool: std.Thread.Pool,

        pub fn init(allocator: Allocator) !Self {
            var thread_pool: std.Thread.Pool = undefined;
            try std.Thread.Pool.init(&thread_pool, .{ .allocator = allocator });

            return .{
                .allocator = allocator,
                .thread_pool = thread_pool,
            };
        }

        pub fn deinit(self: *Self) void {
            self.thread_pool.deinit();
        }

        pub fn run(self: *Self) !void {
            var workers: [8]std.Thread = undefined;
            var threads: [8]Thread = undefined;

            for (0..8) |i| {
                threads[i] = try Thread.init(self.allocator, options);
                workers[i] = try std.Thread.spawn(.{}, Thread.handle, .{ &threads[i], i });
            }

            var running = true;
            const stdin = std.io.getStdIn().reader();
            while (running) {
                const in = try stdin.readUntilDelimiterAlloc(
                    self.allocator,
                    '\n',
                    100,
                );
                defer self.allocator.free(in);
                if (std.mem.eql(u8, in, "q")) {
                    for (0..8) |i| {
                        try threads[i].shutdown_notifier.notify();
                    }
                    running = false;
                }
            }

            for (&threads) |*thread| {
                thread.deinit();
            }
        }
    };
}

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

    var server = try Thread.init(
        allocator,
        .{
            .bind_port = 5533,
            .external_server = "8.8.8.8",
        },
    );
    defer server.deinit();

    var main_thread = try std.Thread.spawn(
        .{},
        Thread.handle,
        .{ &server, 1 },
    );

    var running = true;
    while (running) {
        const in = try stdin.readUntilDelimiterAlloc(
            allocator,
            '\n',
            100,
        );
        defer allocator.free(in);
        if (std.mem.eql(u8, in, "q")) {
            try server.notifyShutdown();
            running = false;
        }
    }

    dns_mutex.lock();
    dns_condition.wait(&dns_mutex);
    dns_mutex.unlock();
    main_thread.join();
}
