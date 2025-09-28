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
// 4. Any resolver implemetations will now be stale since zig will be adding async,
// so any implementations will need a rewrite once that is available
// 5. Decide on a common api and naming for functions

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
const READ_TIMEOUT_MS = 2000;

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
    canceled: bool = false,
    cancel_timer: xev.Timer = undefined,
    timer_completion: xev.Completion = .{},
    cancel_completion: xev.Completion = .{},
};

const ExternalContext = struct {
    self: *Thread,
    qname_hash: [BUFFER_SIZE]u8 = undefined,
    message: *Message.Message,
    recv_buf: [BUFFER_SIZE]u8 = undefined,
    send_buf: [BUFFER_SIZE]u8 = undefined,
    state: UDP.State = undefined,
    completion: xev.Completion = .{},
};

const ContextPool = std.heap.MemoryPool(AsyncContext);

const ExtContextPool = std.heap.MemoryPool(ExternalContext);

pub const Thread = struct {
    id: usize = 0,
    // TODO: Should this be a central cache all threads can use? Or should we cache per thread?
    dns_cache: LRU(Message.Message),
    bind_addr: net.Address,
    resolv: net.Address,
    udp: UDP,
    ext_udp: UDP,
    notifier: xev.Async,
    shutdown_notifier: xev.Async,
    c_shutdown: xev.Completion = .{},
    loop: xev.Loop,
    timer: xev.Timer,
    c_read: xev.Completion = .{},
    c_timer: xev.Completion = .{},
    context_pool: ContextPool,
    ext_context_pool: ExtContextPool,
    allocator: Allocator,

    pub fn init(allocator: Allocator, options: Options) !Thread {
        var loop = try xev.Loop.init(.{});
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
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Thread) void {
        var head = self.dns_cache.head();
        while (head) |entry| {
            entry.*.value.deinit();
            self.allocator.free(entry.*.key);
            head = entry.next();
        }
        self.dns_cache.deinit();
        self.context_pool.deinit();
        self.ext_context_pool.deinit();
        self.notifier.deinit();
        self.shutdown_notifier.deinit();
        log.debug("Thread {d}: destroyed", .{self.id});
    }

    pub fn handle(self: *Thread, id: usize) void {
        self.id = id;
        self.start() catch |err| {
            log.err("Error in Thread {d} run: {}", .{ id, err });
        };
    }

    pub fn start(self: *Thread) !void {
        try self.udp.bind(self.bind_addr);
        log.info("Thread {d}: Listen on {f}", .{ self.id, self.bind_addr });

        try self.read();
        self.timer.run(&self.loop, &self.c_timer, 1000, Thread, self, timerCallback);
        self.shutdown_notifier.wait(&self.loop, &self.c_shutdown, Thread, self, stopCallback);
        try self.loop.run(.until_done);
    }

    pub fn notifyShutdown(self: *Thread) !void {
        try self.shutdown_notifier.notify();
    }

    fn stop(self: *Thread) !void {
        posix.close(self.udp.fd);
        posix.close(self.ext_udp.fd);

        self.loop.deinit();
        log.debug("Thread {d}: shutdown", .{self.id});
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

        var head = self.dns_cache.head();
        var removed_any = false;

        while (head) |value| {
            for (value.*.value.answers.items) |*item| {
                if (item.ttl == 0) {
                    self.dns_cache.remove(value.*.key);
                    removed_any = true;
                    break;
                }
                item.ttl -= 1;
            }
            if (removed_any) {
                head = value.next();
                continue;
            }
            for (value.*.value.authorities.items) |*item| {
                if (item.ttl == 0) {
                    self.dns_cache.remove(value.*.key);
                    removed_any = true;
                    break;
                }
                item.ttl -= 1;
            }
            if (removed_any) {
                head = value.next();
                continue;
            }
            for (value.*.value.additionals.items) |*item| {
                if (item.ttl == 0) {
                    self.dns_cache.remove(value.*.key);
                    removed_any = true;
                    break;
                }
                item.ttl -= 1;
            }
            head = value.next();
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

    fn timeoutCallback(
        ud: ?*AsyncContext,
        _: *xev.Loop,
        _: *xev.Completion,
        r: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = r catch |err| switch (err) {
            xev.Timer.RunError.Canceled => return .disarm,
            else => {
                log.err("Timeout error: {}", .{err});
                return .disarm;
            },
        };

        if (ud) |user_data| {
            user_data.canceled = true;
            user_data.self.notifier.notify() catch unreachable;
        }

        return .disarm;
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
            if (!context.canceled) {
                write(context) catch |err| {
                    log.err("Error in write: {}", .{err});
                    return .disarm;
                };
            } else {
                log.debug("Cancelled", .{});
                context.message.deinit();
                context.question.deinit();
                context.cancel_timer.deinit();
                context.self.context_pool.destroy(context);
                return .disarm;
            }
        }
        return .disarm;
    }

    fn write(context: *AsyncContext) !void {
        var self = context.self;
        var message = context.message;

        var writer = std.Io.Writer.fixed(&context.send_buf);

        _ = try message.encode(&writer);
        const len = writer.end;
        try writer.flush();

        const addr = context.addr;

        context.cancel_timer.cancel(&context.self.loop, &context.timer_completion, &context.cancel_completion, void, null, (struct {
            fn callback(
                _: ?*void,
                _: *xev.Loop,
                _: *xev.Completion,
                r: xev.Timer.CancelError!void,
            ) xev.CallbackAction {
                _ = r catch unreachable;
                return .disarm;
            }
        }).callback);

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
                    log.debug("Wrote DNS Packet:\n{f}", .{server.message});
                    server.message.deinit();
                    server.question.deinit();
                    server.cancel_timer.deinit();
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
        var reader = std.Io.Reader.fixed(buf);

        context.question = try Message.Message.decode(self.allocator, &reader);
        context.message = Message.Message.init(self.allocator);
        context.message.ref = true;

        errdefer context.question.deinit();
        errdefer context.message.deinit();
        errdefer self.context_pool.destroy(context);

        try createDnsResponse(&context.message, &context.question);

        try handleDnsQuery(
            self,
            buf[0..],
            context,
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
            return .disarm;
        };
        if (ud) |user_data| {
            user_data.self.notifier.wait(&user_data.self.loop, &user_data.wait_completion, AsyncContext, user_data, asyncCallback);
            user_data.cancel_timer = xev.Timer.init() catch |err| {
                log.err("Error setting up Timeout: {}", .{err});
                return .disarm;
            };

            user_data.cancel_timer.run(&user_data.self.loop, &user_data.timer_completion, READ_TIMEOUT_MS, AsyncContext, user_data, timeoutCallback);
            user_data.self.read() catch |err| {
                log.err("Error in read: {}\n", .{err});
                return .disarm;
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
        context: *AsyncContext,
    ) !void {
        // TODO: Return error messages when error is encountered
        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        var did_ask = false;

        log.debug("Received DNS Packet:\n{f}", .{context.question});

        for (context.question.questions.items) |*question| {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            // Add the question type so we don't accidentally get a cache entry for
            // another type of question
            const qname = try question.qname.print(qname_buf[0..], question.qtype);

            if (self.dns_cache.get(&qname_buf)) |*cached_response| {
                log.debug("Cache hit for {s}", .{qname});

                // Add cached records to our response
                try glue(&context.message, cached_response.*);
            } else {
                if (!context.canceled) {
                    log.debug("Not found in local store, querying external server...", .{});
                    const ext_context: *ExternalContext = try self.ext_context_pool.create();
                    ext_context.* = ExternalContext{
                        .self = self,
                        .message = &context.message,
                    };
                    @memcpy(ext_context.send_buf[0..query.len], query);
                    @memcpy(ext_context.qname_hash[0..], qname_buf[0..]);
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
        var tmp_reader = std.Io.Reader.fixed(buf.slice[0..len]);
        if (ud) |user_data| {
            defer user_data.self.ext_context_pool.destroy(user_data);
            const res = Message.Message.decode(
                user_data.self.allocator,
                &tmp_reader,
            ) catch |err| {
                log.err("Error decoding external message: {}", .{err});
                return .disarm;
            };

            // Add external records to our response
            glue(user_data.message, res) catch |err| {
                log.err("Error preforming glue: {}", .{err});
                return .disarm;
            };

            user_data.self.dns_cache.put(&user_data.qname_hash, res) catch |err| {
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

// TODO: This is mostly an example and not fully featured, just shows how to manage threads
pub fn StubResolver(comptime options: Options) type {
    return struct {
        const Self = @This();
        allocator: Allocator,

        pub fn init(allocator: Allocator) !Self {
            return .{
                .allocator = allocator,
            };
        }

        pub fn deinit(_: *Self) void {}

        pub fn run(self: *Self) !void {
            var workers: [options.thread_count]std.Thread = undefined;
            var threads: [options.thread_count]Thread = undefined;

            for (0..options.thread_count) |i| {
                threads[i] = try Thread.init(self.allocator, options);
                workers[i] = try std.Thread.spawn(
                    .{ .allocator = self.allocator },
                    Thread.handle,
                    .{ &threads[i], i },
                );
            }

            var running = true;
            var buffer: [1024]u8 = undefined;
            var stdin_fd = std.fs.File.stdin();
            var stdin = stdin_fd.reader(&buffer);
            while (running) {
                var in: [1024]u8 = undefined;
                const len = try stdin.read(&in);
                if (std.mem.eql(u8, in[0..len], "q\n")) {
                    for (0..options.thread_count) |i| {
                        // Tell each thread to shutdown
                        try threads[i].shutdown_notifier.notify();
                    }
                    running = false;
                }
            }
            stdin_fd.close();
            for (workers) |worker| {
                worker.join();
                log.debug("Thread joined", .{});
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
    try message.answers.appendSlice(message.allocator, other.answers.items);
    message.header.an_count += other.header.an_count;

    try message.authorities.appendSlice(message.allocator, other.authorities.items);
    message.header.ns_count += other.header.ns_count;

    try message.additionals.appendSlice(message.allocator, other.additionals.items);
    message.header.ar_count += other.header.ar_count;
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

    try message.questions.appendSlice(message.allocator, packet.questions.items);
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

    var server = try StubResolver(.{ .bind_port = 5533, .external_server = "8.8.8.8" }).init(allocator);
    defer server.deinit();

    try server.run();
}
