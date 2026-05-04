const std = @import("std");
const Message = @import("message.zig");
const MessageReader = @import("message_reader.zig").MessageReader;
const cache_hub = @import("cache_hub.zig");
const dns_server = @import("dns_server.zig");

const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.stub_async);

const BUFFER_SIZE = 2048;
const UPSTREAM_TIMEOUT_MS = 2000;

pub const Options = struct {
    external_server: ?[]const u8 = null,
};

const CacheKey = cache_hub.Key;
const CacheValue = cache_hub.Value;
const CacheHub = cache_hub.Hub;

pub const Server = struct {
    pub const Request = CacheHub.Request;

    allocator: Allocator,
    options: Options,
    upstream_addr: net.IpAddress,
    cache_hub: CacheHub,

    pub fn init(allocator: Allocator, io: Io, options: Options, request_buffer: []Request) !Server {
        const resolv_text = try getResolv(allocator, io, options.external_server);
        defer allocator.free(resolv_text);

        const upstream_addr = net.IpAddress.parse(resolv_text, 53) catch try net.IpAddress.resolve(io, resolv_text, 53);

        return .{
            .allocator = allocator,
            .options = options,
            .upstream_addr = upstream_addr,
            .cache_hub = CacheHub.init(allocator, request_buffer),
        };
    }

    pub fn deinit(self: *Server, io: Io) void {
        self.cache_hub.deinit(io);
    }

    pub fn start(self: *Server, io: Io) !void {
        try self.cache_hub.start(io);
    }

    pub fn handlePacket(
        self: *Server,
        io: Io,
        allocator: Allocator,
        responder: dns_server.Responder,
        from: net.IpAddress,
        data: []const u8,
    ) !void {
        if (data.len < 12) return;

        var request = MessageReader.parse(data) catch {
            const id = readIdFromWire(data);
            var err_msg = createDnsError(id, false, .format_error);
            defer err_msg.deinit(allocator);
            try responder.sendMessage(from, &err_msg);
            return;
        };

        if (request.header.qd_count == 0) {
            var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, .format_error);
            defer err_msg.deinit(allocator);
            try responder.sendMessage(from, &err_msg);
            return;
        }

        var response = Message.Message.init();
        defer response.deinit(allocator);
        try createDnsResponse(allocator, &response, &request);

        if (request.header.qd_count == 1) {
            var q = (try request.nextQuestion()) orelse return error.BadQuestion;
            defer q.deinit(allocator);

            var qname = try q.qname.toOwned(allocator);
            defer qname.deinit(allocator);
            const key = CacheKey{
                .qname = qname,
                .qtype = q.qtype,
            };

            if (try self.cache_hub.get(io, allocator, &key)) |cached| {
                var owned_cached = cached;
                defer self.cache_hub.freeValue(allocator, &owned_cached);
                try appendCachedAnswers(allocator, &response, &owned_cached);
                try responder.sendMessage(from, &response);
                return;
            }

            var upstream = self.queryUpstream(io, allocator, data) catch |err| {
                var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, .server_failure);
                defer err_msg.deinit(allocator);
                try responder.sendMessage(from, &err_msg);
                return err;
            };
            defer upstream.deinit(allocator);

            if (upstream.header.flags.response_code == .no_error) {
                self.cachePut(io, allocator, &qname, q.qtype, &upstream) catch |err| {
                    log.err("Cache put failed: {}", .{err});
                };
            } else {
                var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, upstream.header.flags.response_code);
                defer err_msg.deinit(allocator);
                try responder.sendMessage(from, &err_msg);
                return;
            }

            try appendWithElapsed(allocator, &response, &upstream, 0);
            try responder.sendMessage(from, &response);
            return;
        }

        // Fallback for multi-question requests: no cache, just forward.
        var upstream_multi = self.queryUpstream(io, allocator, data) catch |err| {
            var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, .server_failure);
            defer err_msg.deinit(allocator);
            try responder.sendMessage(from, &err_msg);
            return err;
        };
        defer upstream_multi.deinit(allocator);
        try appendWithElapsed(allocator, &response, &upstream_multi, 0);
        try responder.sendMessage(from, &response);
    }

    fn queryUpstream(self: *Server, io: Io, allocator: Allocator, data: []const u8) !Message.Message {
        var upstream_socket = try self.openUpstreamSocket(io);
        defer upstream_socket.close(io);

        try upstream_socket.send(io, &self.upstream_addr, data);

        var upstream_buf: [BUFFER_SIZE]u8 = undefined;
        const upstream_timeout = Io.Timeout{ .duration = .{ .raw = Io.Duration.fromMilliseconds(UPSTREAM_TIMEOUT_MS), .clock = .awake } };
        const upstream_msg = try upstream_socket.receiveTimeout(io, upstream_buf[0..], upstream_timeout);

        var upstream_reader = std.Io.Reader.fixed(upstream_msg.data);
        return try Message.Message.decode(allocator, &upstream_reader);
    }

    fn cachePut(
        self: *Server,
        io: Io,
        allocator: Allocator,
        qname: *const Message.Name,
        qtype: Message.Type,
        upstream: *const Message.Message,
    ) !void {
        var key = CacheKey{
            .qname = try qname.clone(allocator),
            .qtype = qtype,
        };
        var value = CacheValue{};
        var transferred = false;
        errdefer if (!transferred) {
            key.deinit(allocator);
            value.deinit(allocator);
        };

        for (upstream.answers.items) |*record| {
            if (record.type == qtype or record.type == .cname) {
                try value.appendRecord(allocator, record);
            }
        }

        if (value.records.items.len == 0) {
            key.deinit(allocator);
            value.deinit(allocator);
            return;
        }
        transferred = true;
        try self.cache_hub.putBlocking(io, allocator, key, value);
    }

    fn openUpstreamSocket(self: *Server, io: Io) !net.Socket {
        var bind_addr = switch (self.upstream_addr) {
            .ip4 => try net.IpAddress.parse("0.0.0.0", 0),
            .ip6 => try net.IpAddress.parse("::", 0),
        };
        return net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });
    }
};

fn appendCachedAnswers(
    allocator: Allocator,
    message: *Message.Message,
    cached: *const CacheValue,
) !void {
    for (cached.records.items) |*record| {
        var cloned = try record.clone(allocator);
        var transferred = false;
        errdefer if (!transferred) cloned.deinit(allocator);
        try message.answers.append(allocator, cloned);
        transferred = true;
        message.header.an_count += 1;
    }
}

fn appendWithElapsed(
    allocator: Allocator,
    message: *Message.Message,
    other: *const Message.Message,
    elapsed_secs: u64,
) !void {
    message.header.an_count += try appendRecordsWithTtl(allocator, &message.answers, other.answers.items, elapsed_secs);
    message.header.ns_count += try appendRecordsWithTtl(allocator, &message.authorities, other.authorities.items, elapsed_secs);
    message.header.ar_count += try appendRecordsWithTtl(allocator, &message.additionals, other.additionals.items, elapsed_secs);
}

fn appendRecordsWithTtl(
    allocator: Allocator,
    list: *std.ArrayList(Message.Record),
    records: []const Message.Record,
    elapsed_secs: u64,
) !u16 {
    var added: u16 = 0;
    for (records) |*record| {
        const remaining = ttlRemaining(record.ttl, elapsed_secs) orelse continue;
        var cloned = try record.clone(allocator);
        cloned.ttl = remaining;
        try list.append(allocator, cloned);
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

fn createDnsResponse(allocator: Allocator, message: *Message.Message, packet: *MessageReader) !void {
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

    if (packet.header.qd_count == 0) return;
    var decoded_questions = try packet.getAllQuestions(allocator);
    defer {
        for (decoded_questions.items) |*q| q.deinit(allocator);
        decoded_questions.deinit(allocator);
    }
    for (decoded_questions.items) |*q| {
        const cloned = try q.clone(allocator);
        try message.questions.append(allocator, cloned);
        message.header.qd_count += 1;
    }
}

fn createDnsError(id: u16, rd: bool, err: Message.ResponseCode) Message.Message {
    var message = Message.Message.init();
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
    var request_buffer: [1024]CacheHub.Request = undefined;
    var handler = try Server.init(allocator, io, .{}, &request_buffer);
    defer handler.deinit(io);

    const DnsServer = dns_server.Server(Server);
    var server = try DnsServer.init(allocator, io, .{ .bind_addr = "127.0.0.1", .bind_port = 53 }, &handler);
    defer server.deinit();

    try server.run();
}
