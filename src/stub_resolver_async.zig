const std = @import("std");
const Message = @import("message.zig");
const LRU = @import("util/cache.zig").LRU;

const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const Mutex = Io.Mutex;

const log = std.log.scoped(.stub_async);

const BUFFER_SIZE = 2048;
const RECV_TIMEOUT_MS = 200;
const UPSTREAM_TIMEOUT_MS = 2000;
const MAX_INFLIGHT = 128;
const CACHE_CAPACITY = 512;

pub const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
};

const TaskResult = ?anyerror;

const CachedMessage = struct {
    message: Message.Message,
    stored_at: Io.Timestamp,

    pub fn deinit(self: *CachedMessage) void {
        self.message.deinit();
    }
};

const Task = struct {
    allocator: Allocator,
    from: net.IpAddress,
    data: []u8,

    pub fn init(allocator: Allocator, from: net.IpAddress, data: []const u8) !*Task {
        const task = try allocator.create(Task);
        errdefer allocator.destroy(task);
        task.allocator = allocator;
        task.from = from;
        task.data = try allocator.alloc(u8, data.len);
        @memcpy(task.data, data);
        return task;
    }

    pub fn deinit(self: *Task) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }
};

pub const Server = struct {
    allocator: Allocator,
    options: Options,
    io: Io,
    socket: net.Socket,
    upstream_addr: net.IpAddress,
    cache: LRU(CachedMessage),
    cache_mutex: Mutex = .init,
    shutdown: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: Allocator, io: Io, options: Options) !Server {
        var bind_addr = try net.IpAddress.parse(options.bind_addr, options.bind_port);
        const socket = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });

        const resolv_text = try getResolv(allocator, io, options.external_server);
        defer allocator.free(resolv_text);

        const upstream_addr = net.IpAddress.parse(resolv_text, 53) catch try net.IpAddress.resolve(io, resolv_text, 53);

        return .{
            .allocator = allocator,
            .options = options,
            .io = io,
            .socket = socket,
            .upstream_addr = upstream_addr,
            .cache = LRU(CachedMessage).init(allocator, CACHE_CAPACITY),
        };
    }

    pub fn deinit(self: *Server) void {
        self.cache_mutex.lockUncancelable(self.io);
        var head = self.cache.head;
        while (head) |entry| {
            entry.value.message.deinit();
            head = entry.next;
        }
        self.cache.deinit();
        self.cache_mutex.unlock(self.io);

        self.socket.close(self.io);
    }

    pub fn requestStop(self: *Server) void {
        self.shutdown.store(true, .release);
    }

    pub fn run(self: *Server) !void {
        log.info("Async stub resolver listening on {f}", .{self.socket.address});

        var recv_buf: [BUFFER_SIZE]u8 = undefined;
        const timeout = Io.Timeout{ .duration = .{ .raw = Io.Duration.fromMilliseconds(RECV_TIMEOUT_MS), .clock = .awake } };

        var futures: std.ArrayList(Io.Future(TaskResult)) = .empty;
        defer {
            for (futures.items) |*f| {
                const res = f.await(self.io);
                if (res) |err| log.err("Task failed during shutdown: {}", .{err});
            }
            futures.deinit(self.allocator);
        }

        while (!self.shutdown.load(.acquire)) {
            const incoming = self.socket.receiveTimeout(self.io, recv_buf[0..], timeout) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };

            const task = Task.init(self.allocator, incoming.from, incoming.data) catch |err| {
                log.err("Failed to allocate task: {}", .{err});
                continue;
            };

            const future = Io.async(self.io, Server.handleTask, .{ self, task });
            if (future.any_future == null) {
                const res = future.result;
                if (res) |err| log.err("Task failed: {}", .{err});
            } else {
                try futures.append(self.allocator, future);
                if (futures.items.len >= MAX_INFLIGHT) {
                    try self.drainCompleted(&futures);
                }
            }
        }
    }

    fn drainCompleted(self: *Server, futures: *std.ArrayList(Io.Future(TaskResult))) !void {
        if (futures.items.len == 0) return;

        var any_futures: [MAX_INFLIGHT]*Io.AnyFuture = undefined;
        var indices: [MAX_INFLIGHT]usize = undefined;
        var count: usize = 0;

        for (futures.items, 0..) |f, i| {
            if (f.any_future) |af| {
                any_futures[count] = af;
                indices[count] = i;
                count += 1;
            }
        }

        if (count == 0) return;

        const ready_index = try self.io.vtable.select(self.io.userdata, any_futures[0..count]);
        self.awaitOne(futures, indices[ready_index]);
    }

    fn awaitOne(self: *Server, futures: *std.ArrayList(Io.Future(TaskResult)), index: usize) void {
        var future = futures.items[index];
        const res = future.await(self.io);
        if (res) |err| log.err("Task failed: {}", .{err});
        _ = futures.swapRemove(index);
    }

    fn handleTask(self: *Server, task: *Task) TaskResult {
        defer task.deinit();
        self.processRequest(task) catch |err| return err;
        return null;
    }

    fn processRequest(self: *Server, task: *Task) !void {
        if (task.data.len < 12) return;

        var reader = std.Io.Reader.fixed(task.data);
        var request = Message.Message.decode(self.allocator, &reader) catch {
            const id = readIdFromWire(task.data);
            var err_msg = createDnsError(self.allocator, id, false, .format_error);
            defer err_msg.deinit();
            try self.sendMessage(task.from, &err_msg);
            return;
        };
        defer request.deinit();

        if (request.questions.items.len == 0) {
            var err_msg = createDnsError(self.allocator, request.header.id, request.header.flags.recursion_desired, .format_error);
            defer err_msg.deinit();
            try self.sendMessage(task.from, &err_msg);
            return;
        }

        var response = Message.Message.init(self.allocator);
        defer response.deinit();
        try createDnsResponse(&response, &request);

        if (request.questions.items.len == 1) {
            var qname_buf: [BUFFER_SIZE]u8 = undefined;
            const q = &request.questions.items[0];
            const qname = try q.qname.print(qname_buf[0..], q.qtype);
            const key = hashFn(qname);

            if (self.cacheGet(key)) |cached| {
                const elapsed = elapsedSeconds(self.io, cached.stored_at);
                try appendWithElapsed(&response, &cached.message, elapsed);
                try self.sendMessage(task.from, &response);
                return;
            }

            var upstream = self.queryUpstream(task.data) catch |err| {
                var err_msg = createDnsError(self.allocator, request.header.id, request.header.flags.recursion_desired, .server_failure);
                defer err_msg.deinit();
                try self.sendMessage(task.from, &err_msg);
                return err;
            };
            var upstream_owned = true;
            defer if (upstream_owned) upstream.deinit();

            if (upstream.header.flags.response_code == .no_error) {
                if (self.cachePut(key, upstream)) |_| {
                    upstream_owned = false;
                } else |err| {
                    log.err("Cache put failed: {}", .{err});
                }
            } else {
                var err_msg = createDnsError(self.allocator, request.header.id, request.header.flags.recursion_desired, upstream.header.flags.response_code);
                defer err_msg.deinit();
                try self.sendMessage(task.from, &err_msg);
                return;
            }

            try appendWithElapsed(&response, &upstream, 0);
            try self.sendMessage(task.from, &response);
            return;
        }

        // Fallback for multi-question requests: no cache, just forward.
        var upstream_multi = self.queryUpstream(task.data) catch |err| {
            var err_msg = createDnsError(self.allocator, request.header.id, request.header.flags.recursion_desired, .server_failure);
            defer err_msg.deinit();
            try self.sendMessage(task.from, &err_msg);
            return err;
        };
        defer upstream_multi.deinit();
        try appendWithElapsed(&response, &upstream_multi, 0);
        try self.sendMessage(task.from, &response);
    }

    fn queryUpstream(self: *Server, data: []const u8) !Message.Message {
        var upstream_socket = try self.openUpstreamSocket();
        defer upstream_socket.close(self.io);

        try upstream_socket.send(self.io, &self.upstream_addr, data);

        var upstream_buf: [BUFFER_SIZE]u8 = undefined;
        const upstream_timeout = Io.Timeout{ .duration = .{ .raw = Io.Duration.fromMilliseconds(UPSTREAM_TIMEOUT_MS), .clock = .awake } };
        const upstream_msg = try upstream_socket.receiveTimeout(self.io, upstream_buf[0..], upstream_timeout);

        var upstream_reader = std.Io.Reader.fixed(upstream_msg.data);
        return try Message.Message.decode(self.allocator, &upstream_reader);
    }

    fn sendMessage(self: *Server, to: net.IpAddress, message: *Message.Message) !void {
        var out_buf: [BUFFER_SIZE]u8 = undefined;
        var writer = std.Io.Writer.fixed(&out_buf);
        try message.encode(&writer);
        const len = writer.end;
        try self.socket.send(self.io, &to, out_buf[0..len]);
    }

    fn cacheGet(self: *Server, key: u64) ?CachedMessage {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.cache.get(key)) |cached| {
            const elapsed = elapsedSeconds(self.io, cached.stored_at);
            if (elapsed >= maxTtlSeconds(&cached.message)) {
                var tmp = cached;
                tmp.deinit();
                self.cache.remove(key);
                return null;
            }
            return cached;
        }
        return null;
    }

    fn cachePut(self: *Server, key: u64, value: Message.Message) !void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);

        if (self.cache.map.count() >= self.cache.capacity) {
            if (self.cache.tail) |tail| {
                tail.value.message.deinit();
                self.cache.remove(tail.key);
            }
        }

        if (self.cache.map.get(key)) |entry| {
            entry.value.message.deinit();
        }

        const cached = CachedMessage{
            .message = value,
            .stored_at = Io.Timestamp.now(self.io, .awake),
        };
        try self.cache.put(key, cached);
    }

    fn openUpstreamSocket(self: *Server) !net.Socket {
        var bind_addr = switch (self.upstream_addr) {
            .ip4 => try net.IpAddress.parse("0.0.0.0", 0),
            .ip6 => try net.IpAddress.parse("::", 0),
        };
        return net.IpAddress.bind(&bind_addr, self.io, .{ .mode = .dgram, .protocol = .udp });
    }
};

fn appendWithElapsed(message: *Message.Message, other: *const Message.Message, elapsed_secs: u64) !void {
    message.header.an_count += try appendRecordsWithTtl(message, &message.answers, other.answers.items, elapsed_secs);
    message.header.ns_count += try appendRecordsWithTtl(message, &message.authorities, other.authorities.items, elapsed_secs);
    message.header.ar_count += try appendRecordsWithTtl(message, &message.additionals, other.additionals.items, elapsed_secs);
}

fn appendRecordsWithTtl(
    message: *Message.Message,
    list: *std.ArrayList(Message.Record),
    records: []const Message.Record,
    elapsed_secs: u64,
) !u16 {
    var added: u16 = 0;
    for (records) |*record| {
        const remaining = ttlRemaining(record.ttl, elapsed_secs) orelse continue;
        var cloned = try record.clone();
        cloned.ttl = remaining;
        try list.append(message.allocator, cloned);
        added += 1;
    }
    return added;
}

fn ttlRemaining(ttl: u32, elapsed_secs: u64) ?u32 {
    if (elapsed_secs >= ttl) return null;
    return @intCast(ttl - elapsed_secs);
}

fn maxTtlSeconds(message: *const Message.Message) u64 {
    var max_ttl: u64 = 0;
    for (message.answers.items) |*record| max_ttl = @max(max_ttl, record.ttl);
    for (message.authorities.items) |*record| max_ttl = @max(max_ttl, record.ttl);
    for (message.additionals.items) |*record| max_ttl = @max(max_ttl, record.ttl);
    return max_ttl;
}

fn elapsedSeconds(io: Io, stored_at: Io.Timestamp) u64 {
    const now = Io.Timestamp.now(io, .awake);
    const dur = stored_at.durationTo(now);
    const secs = dur.toSeconds();
    return if (secs <= 0) 0 else @intCast(secs);
}

fn createDnsResponse(message: *Message.Message, packet: *Message.Message) !void {
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
        .qd_count = 0,
        .an_count = 0,
        .ns_count = 0,
        .ar_count = 0,
    };

    for (packet.questions.items) |*q| {
        const cloned = try q.clone();
        try message.questions.append(message.allocator, cloned);
        message.header.qd_count += 1;
    }
}

fn createDnsError(allocator: Allocator, id: u16, rd: bool, err: Message.ResponseCode) Message.Message {
    var message = Message.Message.init(allocator);
    message.header = Message.Header{
        .id = id,
        .flags = Message.Flags{
            .response = true,
            .op_code = .query,
            .authoritative = false,
            .truncated = false,
            .recursion_desired = rd,
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

fn readIdFromWire(data: []const u8) u16 {
    if (data.len < 2) return 0;
    return std.mem.readInt(u16, data[0..2], .big);
}

fn getResolv(allocator: Allocator, io: Io, external_server: ?[]const u8) ![]const u8 {
    if (external_server) |r| {
        const ret = try allocator.alloc(u8, r.len);
        std.mem.copyForwards(u8, ret, r);
        return ret;
    }

    const file = try Io.Dir.openFileAbsolute(io, "/etc/resolv.conf", .{});
    defer file.close(io);

    const stat = try file.stat(io);
    var buffer: [1024]u8 = undefined;
    var reader = Io.File.Reader.init(file, io, &buffer);
    var iface = &reader.interface;
    const contents = try iface.readAlloc(allocator, stat.size);
    defer allocator.free(contents);

    if (std.mem.indexOf(u8, contents, "nameserver")) |i| {
        const start_index = i + 11;
        const end_index = std.mem.indexOf(u8, contents[start_index..], "\n").? + start_index;

        const ret = try allocator.alloc(u8, end_index - start_index);
        std.mem.copyForwards(u8, ret, contents[start_index..end_index]);
        return ret;
    }

    const ret = try allocator.alloc(u8, 7);
    std.mem.copyForwards(u8, ret, "1.1.1.1");
    return ret;
}

fn hashFn(data: []const u8) u64 {
    const p: u64 = 31;
    const m: u64 = 1_000_000_009;
    var hash: u64 = 0;
    var p_pow: u64 = 1;
    for (data) |byte| {
        hash = (hash + byte * p_pow) % m;
        p_pow = (p_pow * p) % m;
    }
    return hash;
}

pub fn run(io: std.Io, allocator: Allocator) !void {
    //var threaded = Io.Threaded.init(allocator, .{});
    //defer threaded.deinit();

    var server = try Server.init(allocator, io, .{});
    defer server.deinit();

    try server.run();
}
