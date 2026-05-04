const std = @import("std");
const Message = @import("message.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = Io.net;

const log = std.log.scoped(.dns_server);

pub const MAX_PACKET_SIZE = 4096;

pub const Options = struct {
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
    recv_timeout_ms: i64 = 200,
    max_inflight: usize = 128,
};

pub const Responder = struct {
    io: Io,
    socket: net.Socket,

    pub fn sendBytes(self: Responder, to: net.IpAddress, bytes: []const u8) !void {
        try self.socket.send(self.io, &to, bytes);
    }

    pub fn sendMessage(self: Responder, to: net.IpAddress, message: *Message.Message) !void {
        var out_buf: [MAX_PACKET_SIZE]u8 = undefined;
        var writer = Io.Writer.fixed(&out_buf);
        try message.encode(&writer);
        try self.sendBytes(to, out_buf[0..writer.end]);
    }
};

const Task = struct {
    allocator: Allocator,
    from: net.IpAddress,
    data: []u8,

    fn init(allocator: Allocator, from: net.IpAddress, data: []const u8) !*Task {
        const task = try allocator.create(Task);
        errdefer allocator.destroy(task);

        task.* = .{
            .allocator = allocator,
            .from = from,
            .data = try allocator.dupe(u8, data),
        };
        return task;
    }

    fn deinit(self: *Task) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }
};

const TaskResult = ?anyerror;
const SelectResult = union(enum) {
    task: TaskResult,
};

pub fn Server(comptime Handler: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        io: Io,
        options: Options,
        socket: net.Socket,
        handler: *Handler,
        shutdown: std.atomic.Value(bool) = .init(false),

        pub fn init(
            allocator: Allocator,
            io: Io,
            options: Options,
            handler: *Handler,
        ) !Self {
            var bind_addr = try net.IpAddress.parse(options.bind_addr, options.bind_port);
            const socket = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });

            return .{
                .allocator = allocator,
                .io = io,
                .options = options,
                .socket = socket,
                .handler = handler,
            };
        }

        pub fn deinit(self: *Self) void {
            self.socket.close(self.io);
        }

        pub fn requestStop(self: *Self) void {
            self.shutdown.store(true, .release);
        }

        pub fn run(self: *Self) !void {
            if (self.options.max_inflight == 0) return error.InvalidMaxInflight;

            try self.startHandlerIfPresent();
            defer self.stopHandlerIfPresent();

            const select_buf = try self.allocator.alloc(SelectResult, self.options.max_inflight);
            defer self.allocator.free(select_buf);

            var select: Io.Select(SelectResult) = .init(self.io, select_buf);
            var inflight: usize = 0;
            defer self.drainInFlight(&select, &inflight);

            var recv_buf: [MAX_PACKET_SIZE]u8 = undefined;
            const timeout = Io.Timeout{ .duration = .{ .raw = Io.Duration.fromMilliseconds(@intCast(self.options.recv_timeout_ms)), .clock = .awake } };

            log.info("DNS server listening on {f}", .{self.socket.address});

            while (!self.shutdown.load(.acquire)) {
                const incoming = self.socket.receiveTimeout(self.io, recv_buf[0..], timeout) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };

                const task = Task.init(self.allocator, incoming.from, incoming.data) catch |err| {
                    log.err("failed to allocate request task: {}", .{err});
                    continue;
                };

                select.async(.task, Self.handleTask, .{ self, task });
                inflight += 1;

                if (inflight >= self.options.max_inflight) {
                    try self.awaitOne(&select, &inflight);
                }
            }
        }

        fn awaitOne(self: *Self, select: *Io.Select(SelectResult), inflight: *usize) !void {
            const completed = try select.await();
            self.handleSelectResult(completed, false);
            inflight.* -= 1;
        }

        fn drainInFlight(self: *Self, select: *Io.Select(SelectResult), inflight: *usize) void {
            while (inflight.* > 0) {
                const completed = select.await() catch |err| {
                    log.err("task failed while draining server shutdown: {}", .{err});
                    break;
                };
                self.handleSelectResult(completed, true);
                inflight.* -= 1;
            }
            _ = select.cancel();
        }

        fn handleSelectResult(_: *Self, completed: SelectResult, during_shutdown: bool) void {
            switch (completed) {
                .task => |result| if (result) |err| {
                    if (during_shutdown) {
                        log.err("request task failed during shutdown: {}", .{err});
                    } else {
                        log.err("request task failed: {}", .{err});
                    }
                },
            }
        }

        fn handleTask(self: *Self, task: *Task) TaskResult {
            defer task.deinit();

            const responder = Responder{
                .io = self.io,
                .socket = self.socket,
            };

            self.handler.handlePacket(
                self.io,
                self.allocator,
                responder,
                task.from,
                task.data,
            ) catch |err| return err;

            return null;
        }

        fn startHandlerIfPresent(self: *Self) !void {
            if (@hasDecl(Handler, "start")) {
                try self.handler.start(self.io);
            }
        }

        fn stopHandlerIfPresent(self: *Self) void {
            if (@hasDecl(Handler, "stop")) {
                self.handler.stop(self.io);
            }
        }
    };
}

test "generic server type can be instantiated" {
    const Handler = struct {
        fn handlePacket(
            _: *@This(),
            _: Io,
            _: Allocator,
            _: Responder,
            _: net.IpAddress,
            _: []const u8,
        ) !void {}
    };

    const DnsServer = Server(Handler);
    try std.testing.expect(@hasDecl(DnsServer, "init"));
    try std.testing.expect(@hasDecl(DnsServer, "run"));
}
