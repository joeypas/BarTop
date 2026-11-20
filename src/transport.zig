const std = @import("std");
const xev = @import("xev");

const Fetch = @import("fetch.zig");
const Message = @import("message.zig");
const resolver_types = @import("resolver_types.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Io = std.Io;
const net = Io.net;

const DEFAULT_DNS_PORT = 53;
var next_query_id = std.atomic.Value(u16).init(1);

pub const UdpTransport = struct {
    pub fn init() UdpTransport {
        return .{};
    }

    pub fn transport(self: *UdpTransport) Fetch.Transport {
        return .{
            .ptr = self,
            .query_any = queryAny,
        };
    }

    fn queryAny(
        ptr: *anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        allocator: Allocator,
        delegation: *const resolver_types.Delegation,
        question: *const Message.Question,
        policy: Fetch.QueryPolicy,
        userdata: ?*anyopaque,
        callback: Fetch.Transport.QueryCallback,
    ) !void {
        _ = ptr;

        const targets = try collectTargets(allocator, delegation);
        errdefer allocator.free(targets);
        if (targets.len == 0) return error.NoNameserverAddress;

        const query_wire = try encodeQuery(allocator, question, policy.udp_payload_size);
        errdefer allocator.free(query_wire);

        const ctx = try allocator.create(QueryContext);
        ctx.* = .{
            .allocator = allocator,
            .loop = loop,
            .completion = completion,
            .callback = callback,
            .userdata = userdata,
            .targets = targets,
            .query_wire = query_wire,
            .recv_size = @max(policy.udp_payload_size, 512),
            .timeout_ms = policy.timeout_ms,
        };
        errdefer allocator.destroy(ctx);

        ctx.startAll() catch |err| {
            ctx.deinit();
            return err;
        };
    }
};

pub const Transport = UdpTransport;

const QueryContext = struct {
    allocator: Allocator,
    loop: *xev.Loop,
    completion: *xev.Completion,
    callback: Fetch.Transport.QueryCallback,
    userdata: ?*anyopaque,
    targets: []net.IpAddress,
    query_wire: []u8,
    recv_size: usize,
    timeout_ms: u64,
    attempts: ArrayList(*Attempt) = .empty,
    pending_attempts: usize = 0,
    live_attempts: usize = 0,
    delivered: bool = false,
    last_err: anyerror = error.NoNameserverAddress,

    fn startAll(self: *QueryContext) !void {
        for (self.targets) |addr| {
            self.startAttempt(addr) catch |err| {
                self.last_err = err;
                continue;
            };
        }

        if (self.live_attempts == 0) return self.last_err;
    }

    fn startAttempt(self: *QueryContext, addr: net.IpAddress) !void {
        const attempt = try self.allocator.create(Attempt);
        errdefer self.allocator.destroy(attempt);

        const recv_buf = try self.allocator.alloc(u8, self.recv_size);
        errdefer self.allocator.free(recv_buf);

        const udp = try xev.UDP.init(addr);
        errdefer closeUdp(udp);

        try udp.bind(anyLocalAddress(addr));

        attempt.* = .{
            .query = self,
            .addr = addr,
            .udp = udp,
            .recv_buf = recv_buf,
            .timer = try xev.Timer.init(),
        };
        errdefer attempt.timer.deinit();

        try self.attempts.append(self.allocator, attempt);
        self.pending_attempts += 1;
        self.live_attempts += 1;

        attempt.start();
    }

    fn deliverSuccess(self: *QueryContext, winner: *Attempt, message: Message.Message, from: net.IpAddress) void {
        if (self.delivered) {
            var owned = message;
            owned.deinit(self.allocator);
            return;
        }

        self.delivered = true;
        for (self.attempts.items) |attempt| {
            if (attempt != winner) attempt.stop(error.QueryCanceled);
        }

        _ = self.callback(self.userdata, self.loop, self.completion, .{
            .message = message,
            .server = from,
            .via_tcp = false,
        });
    }

    fn attemptFinished(self: *QueryContext, err: anyerror) void {
        self.last_err = err;
        if (self.pending_attempts > 0) self.pending_attempts -= 1;
        if (!self.delivered and self.pending_attempts == 0) {
            self.delivered = true;
            _ = self.callback(self.userdata, self.loop, self.completion, self.last_err);
        }
    }

    fn attemptDestroyed(self: *QueryContext) void {
        self.live_attempts -= 1;
        if (self.delivered and self.live_attempts == 0) self.deinit();
    }

    fn deinit(self: *QueryContext) void {
        self.attempts.deinit(self.allocator);
        self.allocator.free(self.query_wire);
        self.allocator.free(self.targets);
        self.allocator.destroy(self);
    }
};

const Attempt = struct {
    query: *QueryContext,
    addr: net.IpAddress,
    udp: xev.UDP,
    recv_buf: []u8,
    timer: xev.Timer,
    write_completion: xev.Completion = undefined,
    read_completion: xev.Completion = undefined,
    timer_completion: xev.Completion = undefined,
    write_state: xev.UDP.State = undefined,
    read_state: xev.UDP.State = undefined,
    outstanding: usize = 0,
    read_started: bool = false,
    finished: bool = false,
    closed: bool = false,

    fn start(self: *Attempt) void {
        self.outstanding += 1;
        self.udp.write(
            self.query.loop,
            &self.write_completion,
            &self.write_state,
            self.addr,
            .{ .slice = self.query.query_wire },
            Attempt,
            self,
            Attempt.onWrite,
        );

        self.outstanding += 1;
        self.timer.run(
            self.query.loop,
            &self.timer_completion,
            self.query.timeout_ms,
            Attempt,
            self,
            Attempt.onTimer,
        );
    }

    fn close(self: *Attempt) void {
        if (!self.closed) {
            closeUdp(self.udp);
            self.closed = true;
        }
    }

    fn stop(self: *Attempt, err: anyerror) void {
        if (self.finished) return;
        self.finished = true;
        self.close();
        self.query.attemptFinished(err);
    }

    fn destroyIfDrained(self: *Attempt) void {
        if (!self.finished or self.outstanding != 0) return;
        const query = self.query;
        self.close();
        self.timer.deinit();
        self.query.allocator.free(self.recv_buf);
        self.query.allocator.destroy(self);
        query.attemptDestroyed();
    }

    fn onWrite(
        attempt_: ?*Attempt,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        const attempt = attempt_.?;
        const query = attempt.query;
        defer {
            attempt.outstanding -= 1;
            attempt.destroyIfDrained();
        }

        if (attempt.finished) return .disarm;

        _ = result catch |err| {
            attempt.stop(err);
            return .disarm;
        };

        attempt.read_started = true;
        attempt.outstanding += 1;
        attempt.udp.read(
            query.loop,
            &attempt.read_completion,
            &attempt.read_state,
            .{ .slice = attempt.recv_buf },
            Attempt,
            attempt,
            Attempt.onRead,
        );
        return .disarm;
    }

    fn onTimer(
        attempt_: ?*Attempt,
        _: *xev.Loop,
        _: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const attempt = attempt_.?;
        defer {
            attempt.outstanding -= 1;
            attempt.destroyIfDrained();
        }

        if (attempt.finished) return .disarm;
        _ = result catch |err| {
            attempt.stop(err);
            return .disarm;
        };
        attempt.stop(error.Timeout);
        return .disarm;
    }

    fn onRead(
        attempt_: ?*Attempt,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        from: net.IpAddress,
        _: xev.UDP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        const attempt = attempt_.?;
        const query = attempt.query;
        defer {
            attempt.outstanding -= 1;
            attempt.destroyIfDrained();
        }

        if (attempt.finished) return .disarm;

        const len = result catch |err| {
            attempt.stop(err);
            return .disarm;
        };

        var reader = Io.Reader.fixed(buffer.slice[0..len]);
        var message = Message.Message.decode(query.allocator, &reader) catch |err| {
            attempt.stop(err);
            return .disarm;
        };
        errdefer message.deinit(query.allocator);

        const expected_id = std.mem.readInt(u16, query.query_wire[0..2], .big);
        if (message.header.id != expected_id) {
            attempt.stop(error.UpstreamIdMismatch);
            return .disarm;
        }

        attempt.finished = true;
        attempt.close();
        if (query.pending_attempts > 0) query.pending_attempts -= 1;
        query.deliverSuccess(attempt, message, from);
        return .disarm;
    }
};

fn collectTargets(allocator: Allocator, delegation: *const resolver_types.Delegation) ![]net.IpAddress {
    var out: ArrayList(net.IpAddress) = .empty;
    errdefer out.deinit(allocator);

    for (delegation.servers.items) |*server| {
        for (server.addrs.items) |addr| {
            try out.append(allocator, withDefaultPort(addr));
        }
    }

    return out.toOwnedSlice(allocator);
}

fn encodeQuery(allocator: Allocator, question: *const Message.Question, udp_payload_size: usize) ![]u8 {
    const capacity = @max(udp_payload_size, 512);
    const out = try allocator.alloc(u8, capacity);
    errdefer allocator.free(out);

    var writer = Io.Writer.fixed(out);
    var header = Message.Header{
        .id = nextQueryId(),
        .flags = .{
            .op_code = .query,
            .recursion_desired = false,
        },
        .qd_count = 1,
    };
    _ = try header.encode(&writer);

    var owned_question = try question.clone(allocator);
    defer owned_question.deinit(allocator);
    _ = try owned_question.encode(&writer);

    return allocator.realloc(out, writer.end);
}

fn nextQueryId() u16 {
    const id = next_query_id.fetchAdd(1, .monotonic);
    return if (id == 0) next_query_id.fetchAdd(1, .monotonic) else id;
}

fn withDefaultPort(addr: net.IpAddress) net.IpAddress {
    return switch (addr) {
        .ip4 => |ip| .{ .ip4 = .{ .bytes = ip.bytes, .port = if (ip.port == 0) DEFAULT_DNS_PORT else ip.port } },
        .ip6 => |ip| .{ .ip6 = .{
            .bytes = ip.bytes,
            .port = if (ip.port == 0) DEFAULT_DNS_PORT else ip.port,
            .flow = ip.flow,
            .interface = ip.interface,
        } },
    };
}

fn anyLocalAddress(remote: net.IpAddress) net.IpAddress {
    return switch (remote) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = .{0} ** 16, .port = 0, .flow = 0, .interface = .none } },
    };
}

fn closeUdp(udp: xev.UDP) void {
    switch (@import("builtin").os.tag) {
        .windows => {},
        else => _ = std.posix.system.close(udp.fd),
    }
}

test "UDP transport exposes fetch transport adapter" {
    var udp = UdpTransport.init();
    const transport = udp.transport();
    try std.testing.expect(transport.ptr == @as(*anyopaque, @ptrCast(&udp)));
}
