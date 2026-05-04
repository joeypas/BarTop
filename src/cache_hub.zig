const std = @import("std");
const Message = @import("message.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const PutError = Allocator.Error || Io.QueueClosedError;
pub const GetError = Allocator.Error || Io.QueueClosedError;

pub const Key = struct {
    qname: Message.Name,
    qtype: Message.Type,

    pub const HashContext = struct {
        pub fn hash(_: HashContext, key: Key) u64 {
            var hasher = std.hash.Wyhash.init(0);

            var name = key.qname;
            var buf: [256]u8 = undefined;
            var writer = std.Io.Writer.fixed(&buf);
            const len = name.encode(&writer) catch 0;

            var cursor: usize = 0;
            while (cursor < len) {
                const label_len = buf[cursor];
                hasher.update(buf[cursor .. cursor + 1]);
                cursor += 1;
                if (label_len == 0) break;

                const label_end = cursor + label_len;
                while (cursor < label_end) : (cursor += 1) {
                    const lower = std.ascii.toLower(buf[cursor]);
                    hasher.update((&lower)[0..1]);
                }
            }

            const type_bytes: [2]u8 = @bitCast(@intFromEnum(key.qtype));
            hasher.update(&type_bytes);
            return hasher.final();
        }

        pub fn eql(_: HashContext, a: Key, b: Key) bool {
            return a.qtype == b.qtype and Message.Name.equalsIgnoreCase(&a.qname, &b.qname);
        }
    };

    pub fn deinit(self: *Key, allocator: Allocator) void {
        self.qname.deinit(allocator);
    }
};

pub const Value = struct {
    records: ArrayList(Message.Record) = .empty,

    pub fn clone(self: *const Value, allocator: Allocator) !Value {
        var out = Value{};
        errdefer out.deinit(allocator);

        try out.records.ensureTotalCapacity(allocator, self.records.items.len);
        for (self.records.items) |*record| {
            out.records.appendAssumeCapacity(try record.clone(allocator));
        }
        return out;
    }

    pub fn deinit(self: *Value, allocator: Allocator) void {
        for (self.records.items) |*record| record.deinit(allocator);
        self.records.deinit(allocator);
    }

    pub fn appendRecord(self: *Value, allocator: Allocator, record: *const Message.Record) !void {
        try self.records.append(allocator, try record.clone(allocator));
    }
};

pub const Hub = struct {
    const Self = @This();
    const StoredValue = struct {
        value: Value,
        key_alloc: Allocator,
        value_alloc: Allocator,
    };
    const Map = std.HashMap(Key, StoredValue, Key.HashContext, std.hash_map.default_max_load_percentage);

    pub const Request = struct {
        alloc: Allocator,
        completion: ?Completion,
        payload: Payload,

        pub const Completion = struct {
            done: *Io.Event,
            response: *Response,
        };

        pub const Payload = union(enum) {
            get: *const Key,
            put: struct {
                key: Key,
                value: Value,
            },
        };
    };

    pub const Response = union(enum) {
        ok,
        not_found,
        value: Value,
        oom,
    };

    gpa: Allocator,
    requests: Io.Queue(Request),
    workers: Io.Group,
    map: Map,

    pub fn init(gpa: Allocator, request_buffer: []Request) Self {
        return .{
            .gpa = gpa,
            .requests = .init(request_buffer),
            .workers = .init,
            .map = Map.init(gpa),
        };
    }

    pub fn start(h: *Self, io: Io) Io.ConcurrentError!void {
        try h.workers.concurrent(io, workerMain, .{ h, io });
    }

    pub fn deinit(h: *Self, io: Io) void {
        h.requests.close(io);
        h.workers.await(io) catch {};

        var it = h.map.iterator();
        while (it.next()) |entry| {
            entry.key_ptr.deinit(entry.value_ptr.key_alloc);
            entry.value_ptr.value.deinit(entry.value_ptr.value_alloc);
        }
        h.map.deinit();
    }

    pub fn freeKey(_: *Self, allocator: Allocator, key: *Key) void {
        key.deinit(allocator);
    }

    pub fn freeValue(_: *Self, allocator: Allocator, value: *Value) void {
        value.deinit(allocator);
    }

    pub fn put(
        h: *Self,
        io: Io,
        alloc: Allocator,
        key: Key,
        value: Value,
    ) PutError!void {
        var owned_key = key;
        var owned_value = value;

        const request: Request = .{
            .alloc = alloc,
            .completion = null,
            .payload = .{ .put = .{
                .key = owned_key,
                .value = owned_value,
            } },
        };
        h.requests.putOneUncancelable(io, request) catch |err| {
            owned_key.deinit(alloc);
            owned_value.deinit(alloc);
            return err;
        };
    }

    fn putWaitable(
        h: *Self,
        io: Io,
        alloc: Allocator,
        key: Key,
        value: Value,
    ) PutError!Request {
        var owned_key = key;
        var owned_value = value;

        const completion = makeCompletion(alloc) catch |err| {
            owned_key.deinit(alloc);
            owned_value.deinit(alloc);
            return err;
        };
        errdefer {
            destroyCompletion(alloc, completion);
            owned_key.deinit(alloc);
            owned_value.deinit(alloc);
        }

        const request: Request = .{
            .alloc = alloc,
            .completion = completion,
            .payload = .{ .put = .{
                .key = owned_key,
                .value = owned_value,
            } },
        };
        try h.requests.putOneUncancelable(io, request);
        return request;
    }

    pub fn get(
        h: *Self,
        io: Io,
        alloc: Allocator,
        key: *const Key,
    ) GetError!?Value {
        const completion = try makeCompletion(alloc);

        const request: Request = .{
            .alloc = alloc,
            .completion = completion,
            .payload = .{ .get = key },
        };
        h.requests.putOneUncancelable(io, request) catch |err| {
            destroyCompletion(alloc, completion);
            return err;
        };

        completion.done.waitUncancelable(io);
        const response = completion.response.*;
        destroyCompletion(alloc, completion);
        switch (response) {
            .not_found => return null,
            .value => |v| return v,
            .oom => return error.OutOfMemory,
            .ok => unreachable,
        }
    }

    fn wait(_: *Self, io: Io, req: Request) Response {
        const completion = req.completion orelse @panic("wait called on request without completion");
        completion.done.waitUncancelable(io);
        const response = completion.response.*;
        destroyCompletion(req.alloc, completion);
        return response;
    }

    pub fn putBlocking(
        h: *Self,
        io: Io,
        alloc: Allocator,
        key: Key,
        value: Value,
    ) PutError!void {
        const req = try h.putWaitable(io, alloc, key, value);
        switch (h.wait(io, req)) {
            .ok => {},
            .oom => return error.OutOfMemory,
            .not_found, .value => unreachable,
        }
    }

    fn makeCompletion(alloc: Allocator) Allocator.Error!Request.Completion {
        const done = try alloc.create(Io.Event);
        errdefer alloc.destroy(done);
        done.* = .unset;

        const response = try alloc.create(Response);
        return .{
            .done = done,
            .response = response,
        };
    }

    fn destroyCompletion(alloc: Allocator, completion: Request.Completion) void {
        alloc.destroy(completion.done);
        alloc.destroy(completion.response);
    }

    fn workerMain(h: *Self, io: Io) Io.Cancelable!void {
        while (true) {
            const req = h.requests.getOne(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => break,
            };
            h.processOne(io, &req);
        }
    }

    fn processOne(h: *Self, io: Io, req: *const Request) void {
        switch (req.payload) {
            .get => |key| {
                const completion = req.completion orelse return;
                if (h.map.get(key.*)) |stored| {
                    const copy = stored.value.clone(req.alloc) catch {
                        completion.response.* = .oom;
                        completion.done.set(io);
                        return;
                    };
                    completion.response.* = .{ .value = copy };
                } else {
                    completion.response.* = .not_found;
                }
            },
            .put => |payload_pair| {
                var pair = payload_pair;
                if (h.map.getEntry(pair.key)) |entry| {
                    pair.key.deinit(req.alloc);
                    entry.value_ptr.value.deinit(entry.value_ptr.value_alloc);
                    entry.value_ptr.value = pair.value;
                    entry.value_ptr.value_alloc = req.alloc;
                } else {
                    h.map.put(pair.key, .{
                        .value = pair.value,
                        .key_alloc = req.alloc,
                        .value_alloc = req.alloc,
                    }) catch {
                        pair.key.deinit(req.alloc);
                        pair.value.deinit(req.alloc);
                        if (req.completion) |completion| {
                            completion.response.* = .oom;
                            completion.done.set(io);
                        }
                        return;
                    };
                }
                if (req.completion) |completion| {
                    completion.response.* = .ok;
                }
            },
        }
        if (req.completion) |completion| completion.done.set(io);
    }
};

test "cache key hashes names case-insensitively" {
    const allocator = std.testing.allocator;
    var key = Key{
        .qname = try Message.Name.initString(allocator, "Example.COM"),
        .qtype = .a,
    };
    defer key.deinit(allocator);

    var same_key = Key{
        .qname = try Message.Name.initString(allocator, "example.com"),
        .qtype = .a,
    };
    defer same_key.deinit(allocator);

    const ctx = Key.HashContext{};
    try std.testing.expect(ctx.eql(key, same_key));
    try std.testing.expectEqual(ctx.hash(key), ctx.hash(same_key));
}

test "cache value clones records" {
    const allocator = std.testing.allocator;
    var record = Message.Record.init(.aaaa);
    defer record.deinit(allocator);
    try record.name.parse(allocator, "answer.example.com");
    var rdata = Message.RData.init(.aaaa);
    defer rdata.deinit(allocator);
    rdata.aaaa.addr = try Io.net.Ip6Address.parse("2001:db8::1", 0);
    try record.setRData(allocator, &rdata);

    var value = Value{};
    defer value.deinit(allocator);
    try value.appendRecord(allocator, &record);

    var copy = try value.clone(allocator);
    defer copy.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), copy.records.items.len);
}

test "hub can be initialized" {
    var request_buffer: [4]Hub.Request = undefined;
    var hub = Hub.init(std.testing.allocator, &request_buffer);
    _ = &hub;
}

test "put consumes ownership and get blocks with borrowed key" {
    const allocator = std.testing.allocator;

    var threaded = Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_buffer: [8]Hub.Request = undefined;
    var hub = Hub.init(allocator, &request_buffer);
    try hub.start(io);
    defer hub.deinit(io);

    var record = Message.Record.init(.a);
    defer record.deinit(allocator);
    try record.name.parse(allocator, "answer.example.com");
    var rdata = Message.RData.init(.a);
    defer rdata.deinit(allocator);
    rdata.a.addr = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 };
    try record.setRData(allocator, &rdata);

    const put_key = Key{
        .qname = try Message.Name.initString(allocator, "answer.example.com"),
        .qtype = .a,
    };
    var put_value = Value{};
    try put_value.appendRecord(allocator, &record);
    try hub.putBlocking(io, allocator, put_key, put_value);

    var lookup_key = Key{
        .qname = try Message.Name.initString(allocator, "ANSWER.example.com"),
        .qtype = .a,
    };
    defer lookup_key.deinit(allocator);

    var got = (try hub.get(io, allocator, &lookup_key)) orelse return error.ExpectedCacheValue;
    defer got.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), got.records.items.len);
}
