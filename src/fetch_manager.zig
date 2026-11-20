const std = @import("std");
const xev = @import("xev");

const Fetch = @import("fetch.zig");
const Message = @import("message.zig");
const resolver_types = @import("resolver_types.zig");

const Allocator = std.mem.Allocator;

const ActiveFetchMap = std.HashMap(
    Fetch.FetchKey,
    *ActiveFetch,
    Fetch.FetchKey.HashContext,
    std.hash_map.default_max_load_percentage,
);

pub const CompletionResult = union(enum) {
    success: Message.Message,
    failure: anyerror,
};

pub const CompletionCallback = *const fn (
    userdata: ?*anyopaque,
    manager: *FetchManager,
    active: *ActiveFetch,
    result: CompletionResult,
) void;

pub const FetchManager = @This();

allocator: Allocator,
cache: Fetch.Cache,
transport: *Fetch.Transport,
active: ActiveFetchMap,
policy: Fetch.ResolverPolicy = .{},
completion_userdata: ?*anyopaque = null,
completion_callback: ?CompletionCallback = null,

pub const ActiveFetch = struct {
    manager: *FetchManager,
    fetch: Fetch,
    completion: Fetch.Completion = .{},

    pub fn waiterCount(self: *const ActiveFetch) usize {
        return self.fetch.waiters.items.len;
    }
};

pub const Options = struct {
    policy: Fetch.ResolverPolicy = .{},
    completion_userdata: ?*anyopaque = null,
    completion_callback: ?CompletionCallback = null,
};

pub fn init(
    allocator: Allocator,
    cache: Fetch.Cache,
    transport: *Fetch.Transport,
    options: Options,
) FetchManager {
    return .{
        .allocator = allocator,
        .cache = cache,
        .transport = transport,
        .active = ActiveFetchMap.init(allocator),
        .policy = options.policy,
        .completion_userdata = options.completion_userdata,
        .completion_callback = options.completion_callback,
    };
}

pub fn deinit(self: *FetchManager) void {
    var it = self.active.iterator();
    while (it.next()) |entry| {
        entry.key_ptr.deinit(self.allocator);
        self.destroyActive(entry.value_ptr.*);
    }
    self.active.deinit();
}

pub fn activeCount(self: *const FetchManager) usize {
    return self.active.count();
}

pub fn attachOrStart(
    self: *FetchManager,
    loop: *xev.Loop,
    request: *const resolver_types.ClientRequest,
    initial_delegation: *const resolver_types.Delegation,
) !*ActiveFetch {
    if (self.active.count() >= self.policy.max_active_fetches) return error.TooManyActiveFetches;

    var lookup_key = try Fetch.FetchKey.fromQuestion(self.allocator, &request.question);
    defer lookup_key.deinit(self.allocator);

    if (self.active.get(lookup_key)) |active| {
        try active.fetch.attachWaiter(self.allocator, request);
        return active;
    }

    const active = try self.allocator.create(ActiveFetch);
    errdefer self.allocator.destroy(active);

    var map_key = try lookup_key.clone(self.allocator);
    errdefer map_key.deinit(self.allocator);

    active.* = .{
        .manager = self,
        .fetch = try Fetch.init(self.allocator, &lookup_key, initial_delegation, self.policy),
    };
    var fetch_initialized = true;
    errdefer if (fetch_initialized) active.fetch.deinit(self.allocator);

    try active.fetch.attachWaiter(self.allocator, request);

    try self.active.put(map_key, active);
    var inserted = true;
    errdefer if (inserted) {
        if (self.active.fetchRemove(lookup_key)) |removed| {
            var owned_key = removed.key;
            owned_key.deinit(self.allocator);
        }
    };

    map_key = undefined;
    fetch_initialized = false;

    active.fetch.start(
        loop,
        &active.completion,
        self.allocator,
        self.cache,
        self.transport,
        active,
        onFetchComplete,
    ) catch |err| {
        if (self.active.fetchRemove(active.fetch.key)) |removed| {
            var owned_key = removed.key;
            owned_key.deinit(self.allocator);
        }
        active.fetch.deinit(self.allocator);
        self.allocator.destroy(active);
        inserted = false;
        return err;
    };

    inserted = false;
    return active;
}

fn onFetchComplete(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    _: *Fetch.Completion,
    result: Fetch.FetchResult,
) xev.CallbackAction {
    _ = loop;

    const active: *ActiveFetch = @ptrCast(@alignCast(userdata.?));
    const manager = active.manager;

    if (result) |message| {
        manager.notify(active, .{ .success = message });
    } else |err| {
        manager.notify(active, .{ .failure = err });
    }

    if (manager.active.fetchRemove(active.fetch.key)) |removed| {
        var owned_key = removed.key;
        owned_key.deinit(manager.allocator);
    }
    manager.destroyActive(active);
    return .disarm;
}

fn notify(self: *FetchManager, active: *ActiveFetch, result: CompletionResult) void {
    if (self.completion_callback) |callback| {
        callback(self.completion_userdata, self, active, result);
        return;
    }

    switch (result) {
        .success => |message| {
            var owned = message;
            owned.deinit(self.allocator);
        },
        .failure => {},
    }
}

fn destroyActive(self: *FetchManager, active: *ActiveFetch) void {
    active.completion.deinit();
    active.fetch.deinit(self.allocator);
    self.allocator.destroy(active);
}

test "fetch manager deduplicates matching requests" {
    const allocator = std.testing.allocator;

    const NoopTransport = struct {
        fn queryAny(
            _: *anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            _: Allocator,
            _: *const resolver_types.Delegation,
            _: *const Message.Question,
            _: Fetch.QueryPolicy,
            _: ?*anyopaque,
            _: Fetch.Transport.QueryCallback,
        ) !void {}
    };

    var transport_context: u8 = 0;
    var transport = Fetch.Transport{
        .ptr = &transport_context,
        .query_any = NoopTransport.queryAny,
    };

    var manager = FetchManager.init(allocator, Fetch.Cache.none(), &transport, .{});
    defer manager.deinit();

    var question = Message.Question.init();
    defer question.deinit(allocator);
    try question.qname.parse(allocator, "example.com");
    question.qtype = .a;
    question.qclass = .in;

    const request = resolver_types.ClientRequest{
        .addr = try std.Io.net.IpAddress.parse("127.0.0.1", 12345),
        .header = .{},
        .question = question,
    };

    var root_delegation = resolver_types.Delegation{
        .zone = Message.Name.init(),
        .ns = .{
            .name = Message.Name.init(),
            .type = .ns,
            .class = .in,
            .records = .empty,
            .ttl = 0,
        },
        .servers = .empty,
    };
    defer root_delegation.deinit(allocator);

    var loop: xev.Loop = undefined;

    const first = try manager.attachOrStart(&loop, &request, &root_delegation);
    const second = try manager.attachOrStart(&loop, &request, &root_delegation);

    try std.testing.expect(first == second);
    try std.testing.expectEqual(@as(usize, 1), manager.activeCount());
    try std.testing.expectEqual(@as(usize, 2), first.waiterCount());
}
