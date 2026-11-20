const std = @import("std");
const xev = @import("xev");

const Message = @import("message.zig");
const resolver_types = @import("resolver_types.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const net = std.Io.net;

const Fetch = @This();

pub const ResolverPolicy = struct {
    max_depth: u8 = 16,
    max_queries_per_fetch: u16 = 50,
    max_inflight_upstreams: u8 = 2,
    max_waiters_per_fetch: usize = 128,
    max_active_fetches: usize = 4096,
    udp_payload_size: usize = 1232,
    upstream_timeout_ms: u64 = 2000,
    serve_stale: bool = false,
};

pub const FetchState = enum {
    init,
    cache_exact_answer,
    find_best_delegation,
    query_nameservers,
    process_response,
    complete_positive,
    complete_negative,
    failed,
    done,
};

pub const FetchKey = struct {
    name: Message.Name,
    type: Message.Type,
    class: Message.Class = .in,

    pub fn fromQuestion(allocator: Allocator, question: *const Message.Question) !FetchKey {
        return .{
            .name = try question.qname.clone(allocator),
            .type = question.qtype,
            .class = question.qclass,
        };
    }

    pub fn clone(self: *const FetchKey, allocator: Allocator) !FetchKey {
        return .{
            .name = try self.name.clone(allocator),
            .type = self.type,
            .class = self.class,
        };
    }

    pub fn deinit(self: *FetchKey, allocator: Allocator) void {
        self.name.deinit(allocator);
        self.* = undefined;
    }

    pub fn toQuestion(self: *const FetchKey, allocator: Allocator) !Message.Question {
        return .{
            .qname = try self.name.clone(allocator),
            .qtype = self.type,
            .qclass = self.class,
        };
    }

    pub const HashContext = struct {
        pub fn hash(_: HashContext, key: FetchKey) u64 {
            var hasher = std.hash.Wyhash.init(0);
            for (key.name.wire.items) |byte| {
                var lower = [1]u8{std.ascii.toLower(byte)};
                hasher.update(&lower);
            }
            const type_int: u16 = @intFromEnum(key.type);
            const class_int: u16 = @intFromEnum(key.class);
            hasher.update(std.mem.asBytes(&type_int));
            hasher.update(std.mem.asBytes(&class_int));
            return hasher.final();
        }

        pub fn eql(_: HashContext, a: FetchKey, b: FetchKey) bool {
            return a.type == b.type and
                a.class == b.class and
                Message.Name.equalsIgnoreCase(&a.name, &b.name);
        }
    };
};

pub const QueryPolicy = struct {
    max_inflight: u8,
    udp_payload_size: usize,
    timeout_ms: u64,
};

pub const UpstreamResponse = struct {
    message: Message.Message,
    server: ?net.IpAddress = null,
    rtt_ms: ?u32 = null,
    via_tcp: bool = false,

    pub fn deinit(self: *UpstreamResponse, allocator: Allocator) void {
        self.message.deinit(allocator);
    }
};

pub const QueryResult = anyerror!UpstreamResponse;

pub const Transport = struct {
    ptr: *anyopaque,
    query_any: QueryAnyFn,

    pub const QueryCallback = *const fn (
        userdata: ?*anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: QueryResult,
    ) xev.CallbackAction;

    pub const QueryAnyFn = *const fn (
        ptr: *anyopaque,
        loop: *xev.Loop,
        completion: *xev.Completion,
        allocator: Allocator,
        delegation: *const resolver_types.Delegation,
        question: *const Message.Question,
        policy: QueryPolicy,
        userdata: ?*anyopaque,
        callback: QueryCallback,
    ) anyerror!void;

    pub fn queryAny(
        self: *Transport,
        loop: *xev.Loop,
        completion: *xev.Completion,
        allocator: Allocator,
        delegation: *const resolver_types.Delegation,
        question: *const Message.Question,
        policy: QueryPolicy,
        userdata: ?*anyopaque,
        callback: QueryCallback,
    ) !void {
        return self.query_any(
            self.ptr,
            loop,
            completion,
            allocator,
            delegation,
            question,
            policy,
            userdata,
            callback,
        );
    }
};

pub const Cache = struct {
    vtable: *const VTable,
    pub const VTable = struct {
        get_exact_answer: ?*const fn (
            ptr: *Cache,
            allocator: Allocator,
            key: *const FetchKey,
        ) anyerror!?Message.Message = null,
        find_best_delegation: ?*const fn (
            ptr: *Cache,
            allocator: Allocator,
            name: *const Message.Name,
        ) anyerror!?resolver_types.Delegation = null,
        put_message: ?*const fn (
            ptr: *Cache,
            allocator: Allocator,
            message: *const Message.Message,
        ) anyerror!void = null,
        put_delegation: ?*const fn (
            ptr: *Cache,
            allocator: Allocator,
            delegation: *const resolver_types.Delegation,
        ) anyerror!void = null,
        put_negative: ?*const fn (
            ptr: *Cache,
            allocator: Allocator,
            key: *const FetchKey,
            message: *const Message.Message,
        ) anyerror!void = null,
    };

    const empty_vtable = VTable{};

    pub fn none() Cache {
        return .{ .vtable = &empty_vtable };
    }

    pub fn getExactAnswer(c: *Cache, allocator: Allocator, key: *const FetchKey) !?Message.Message {
        const func = c.vtable.get_exact_answer orelse return null;
        return func(c, allocator, key);
    }

    pub fn findBestDelegation(
        c: *Cache,
        allocator: Allocator,
        name: *const Message.Name,
    ) !?resolver_types.Delegation {
        const func = c.vtable.find_best_delegation orelse return null;
        return func(c, allocator, name);
    }

    pub fn putMessage(c: *Cache, allocator: Allocator, message: *const Message.Message) !void {
        const func = c.vtable.put_message orelse return;
        try func(c, allocator, message);
    }

    pub fn putDelegation(c: *Cache, allocator: Allocator, delegation: *const resolver_types.Delegation) !void {
        const func = c.vtable.put_delegation orelse return;
        try func(c, allocator, delegation);
    }

    pub fn putNegative(c: *Cache, allocator: Allocator, key: *const FetchKey, message: *const Message.Message) !void {
        const func = c.vtable.put_negative orelse return;
        try func(c, allocator, key, message);
    }
};

pub const UpstreamQuery = struct {
    completion: xev.Completion = undefined,
    timer: xev.Completion = undefined,
    packet_buffer: []u8 = &.{},
    server_addr: net.IpAddress,
    parent: *Fetch,
};

pub const FetchResult = anyerror!Message.Message;

pub const CompletionCallback = *const fn (
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    completion: *Completion,
    result: FetchResult,
) xev.CallbackAction;

pub const Completion = struct {
    fetch: *Fetch = undefined,
    allocator: Allocator = undefined,
    cache: Cache = undefined,
    transport: *Transport = undefined,
    question: ?Message.Question = null,
    transport_completion: xev.Completion = undefined,
    callback: CompletionCallback = undefined,
    userdata: ?*anyopaque = null,
    active: bool = false,

    pub fn deinit(self: *Completion) void {
        if (self.question) |*question| {
            question.deinit(self.allocator);
            self.question = null;
        }
        self.active = false;
    }
};

key: FetchKey,
waiters: ArrayList(resolver_types.ClientRequest) = .empty,
state: FetchState = .init,

current_delegation: resolver_types.Delegation,
depth: u8 = 0,
query_count: u16 = 0,
inflight: ArrayList(UpstreamQuery) = .empty,
tried: ArrayList(resolver_types.NameServer) = .empty,
policy: ResolverPolicy = .{},
cname_chain: ArrayList(Message.Record) = .empty,

pub fn init(
    allocator: Allocator,
    key: *const FetchKey,
    initial_delegation: *const resolver_types.Delegation,
    policy: ResolverPolicy,
) !Fetch {
    var owned_key = try key.clone(allocator);
    errdefer owned_key.deinit(allocator);
    var owned_delegation = try initial_delegation.clone(allocator);
    errdefer owned_delegation.deinit(allocator);

    return .{
        .key = owned_key,
        .current_delegation = owned_delegation,
        .policy = policy,
    };
}

pub fn deinit(self: *Fetch, allocator: Allocator) void {
    self.key.deinit(allocator);
    for (self.waiters.items) |*waiter| waiter.deinit(allocator);
    self.waiters.deinit(allocator);
    self.current_delegation.deinit(allocator);
    self.inflight.deinit(allocator);
    for (self.tried.items) |*server| server.deinit(allocator);
    self.tried.deinit(allocator);
    for (self.cname_chain.items) |*record| record.deinit(allocator);
    self.cname_chain.deinit(allocator);
    self.* = undefined;
}

pub fn attachWaiter(self: *Fetch, allocator: Allocator, request: *const resolver_types.ClientRequest) !void {
    if (self.waiters.items.len >= self.policy.max_waiters_per_fetch) return error.TooManyWaiters;
    var waiter = try request.clone(allocator);
    errdefer waiter.deinit(allocator);
    try self.waiters.append(allocator, waiter);
}

pub fn start(
    self: *Fetch,
    loop: *xev.Loop,
    completion: *Completion,
    allocator: Allocator,
    cache: Cache,
    transport: *Transport,
    userdata: ?*anyopaque,
    callback: CompletionCallback,
) !void {
    completion.* = .{
        .fetch = self,
        .allocator = allocator,
        .cache = cache,
        .transport = transport,
        .callback = callback,
        .userdata = userdata,
        .active = true,
    };
    errdefer completion.deinit();

    self.state = .cache_exact_answer;
    if (try completion.cache.getExactAnswer(allocator, &self.key)) |cached| {
        self.state = .complete_positive;
        self.state = .done;
        _ = finish(self, loop, completion, cached);
        return;
    }

    self.state = .find_best_delegation;
    if (try completion.cache.findBestDelegation(allocator, &self.key.name)) |best| {
        self.current_delegation.deinit(allocator);
        self.current_delegation = best;
    }

    completion.question = try self.key.toQuestion(allocator);
    _ = self.advance(loop, completion);
}

fn advance(self: *Fetch, loop: *xev.Loop, completion: *Completion) xev.CallbackAction {
    while (true) {
        if (self.depth >= self.policy.max_depth) {
            self.state = .failed;
            return finishError(self, loop, completion, error.FetchDepthExceeded);
        }
        if (self.query_count >= self.policy.max_queries_per_fetch) {
            self.state = .failed;
            return finishError(self, loop, completion, error.FetchQueryLimitExceeded);
        }

        self.state = .query_nameservers;
        self.query_count += 1;
        const question = if (completion.question) |*question| question else {
            return finishError(self, loop, completion, error.FetchNotStarted);
        };
        completion.transport.queryAny(loop, &completion.transport_completion, completion.allocator, &self.current_delegation, question, .{
            .max_inflight = self.policy.max_inflight_upstreams,
            .udp_payload_size = self.policy.udp_payload_size,
            .timeout_ms = self.policy.upstream_timeout_ms,
        }, completion, onTransportComplete) catch |err| {
            return finishError(self, loop, completion, err);
        };
        return .disarm;
    }
}

fn onTransportComplete(
    userdata: ?*anyopaque,
    loop: *xev.Loop,
    _: *xev.Completion,
    result: QueryResult,
) xev.CallbackAction {
    const completion: *Completion = @ptrCast(@alignCast(userdata.?));
    return completion.fetch.handleTransportResult(loop, completion, result);
}

fn handleTransportResult(
    self: *Fetch,
    loop: *xev.Loop,
    completion: *Completion,
    result: QueryResult,
) xev.CallbackAction {
    var upstream = result catch |err| {
        self.state = .failed;
        return finishError(self, loop, completion, err);
    };
    defer upstream.deinit(completion.allocator);

    self.state = .process_response;
    const question = if (completion.question) |*question| question else {
        return finishError(self, loop, completion, error.FetchNotStarted);
    };

    var action = classifyResponse(completion.allocator, &upstream.message, question) catch |err| {
        return finishError(self, loop, completion, err);
    };
    defer action.deinit(completion.allocator);

    switch (action) {
        .answer => {
            self.state = .complete_positive;
            completion.cache.putMessage(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.appendCnameChain(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.state = .done;
            return finish(self, loop, completion, takeUpstreamMessage(&upstream));
        },
        .cname => |*target| {
            self.rememberCnamesForQuestion(completion.allocator, &upstream.message, &question.qname) catch |err| {
                return finishError(self, loop, completion, err);
            };
            const next_name = target.clone(completion.allocator) catch |err| {
                return finishError(self, loop, completion, err);
            };
            question.qname.deinit(completion.allocator);
            question.qname = next_name;
            self.depth += 1;
            return self.advance(loop, completion);
        },
        .referral => |*delegation| {
            completion.cache.putMessage(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            completion.cache.putDelegation(completion.allocator, delegation) catch |err| {
                return finishError(self, loop, completion, err);
            };
            const next_delegation = delegation.clone(completion.allocator) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.current_delegation.deinit(completion.allocator);
            self.current_delegation = next_delegation;
            self.depth += 1;
            return self.advance(loop, completion);
        },
        .negative => {
            self.state = .complete_negative;
            completion.cache.putMessage(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            completion.cache.putNegative(completion.allocator, &self.key, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.appendCnameChain(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.state = .done;
            return finish(self, loop, completion, takeUpstreamMessage(&upstream));
        },
        .error_response => {
            self.state = .failed;
            completion.cache.putMessage(completion.allocator, &upstream.message) catch |err| {
                return finishError(self, loop, completion, err);
            };
            self.state = .done;
            return finish(self, loop, completion, takeUpstreamMessage(&upstream));
        },
    }
}

fn finish(self: *Fetch, loop: *xev.Loop, completion: *Completion, message: Message.Message) xev.CallbackAction {
    _ = self;
    completion.deinit();
    return completion.callback(completion.userdata, loop, completion, message);
}

fn finishError(self: *Fetch, loop: *xev.Loop, completion: *Completion, err: anyerror) xev.CallbackAction {
    self.state = .failed;
    completion.deinit();
    return completion.callback(completion.userdata, loop, completion, err);
}

fn takeUpstreamMessage(upstream: *UpstreamResponse) Message.Message {
    const out = upstream.message;
    upstream.message = Message.Message.init();
    return out;
}

const ProcessAction = union(enum) {
    answer,
    cname: Message.Name,
    referral: resolver_types.Delegation,
    negative,
    error_response,

    fn deinit(self: *ProcessAction, allocator: Allocator) void {
        switch (self.*) {
            .cname => |*name| name.deinit(allocator),
            .referral => |*delegation| delegation.deinit(allocator),
            else => {},
        }
    }
};

fn classifyResponse(
    allocator: Allocator,
    response: *const Message.Message,
    question: *const Message.Question,
) !ProcessAction {
    if (response.header.flags.response_code == .name_error) return .negative;
    if (response.header.flags.response_code != .no_error) return .error_response;
    if (hasAnswer(response, &question.qname, question.qtype)) return .answer;

    if (try findCnameTarget(allocator, response, &question.qname)) |target| {
        return .{ .cname = target };
    }

    if (try buildDelegationFromReferral(allocator, response)) |delegation| {
        return .{ .referral = delegation };
    }

    return .negative;
}

fn hasAnswer(response: *const Message.Message, qname: *const Message.Name, qtype: Message.Type) bool {
    for (response.answers.items) |*record| {
        if (record.type == qtype and
            record.class == .in and
            Message.Name.equalsIgnoreCase(&record.name, qname))
        {
            return true;
        }
    }
    return false;
}

fn findCnameTarget(
    allocator: Allocator,
    response: *const Message.Message,
    qname: *const Message.Name,
) !?Message.Name {
    for (response.answers.items) |*record| {
        if (record.type == .cname and Message.Name.equalsIgnoreCase(&record.name, qname)) {
            return try record.rdata.cname.name.clone(allocator);
        }
    }
    return null;
}

fn buildDelegationFromReferral(
    allocator: Allocator,
    response: *const Message.Message,
) !?resolver_types.Delegation {
    var ns_records: ArrayList(Message.Record) = .empty;
    defer {
        for (ns_records.items) |*record| record.deinit(allocator);
        ns_records.deinit(allocator);
    }

    var zone: ?Message.Name = null;
    errdefer if (zone) |*owned| owned.deinit(allocator);
    var min_ttl: u32 = std.math.maxInt(u32);

    for (response.authorities.items) |*record| {
        if (record.type != .ns) continue;
        if (zone == null) zone = try record.name.clone(allocator);
        if (!Message.Name.equalsIgnoreCase(&record.name, &zone.?)) continue;
        min_ttl = @min(min_ttl, record.ttl);
        try ns_records.append(allocator, try record.clone(allocator));
    }

    if (zone == null or ns_records.items.len == 0) return null;

    var delegation_zone = try zone.?.clone(allocator);
    var delegation_zone_transferred = false;
    errdefer if (!delegation_zone_transferred) delegation_zone.deinit(allocator);
    var ns_name = try zone.?.clone(allocator);
    var ns_name_transferred = false;
    errdefer if (!ns_name_transferred) ns_name.deinit(allocator);

    var delegation = resolver_types.Delegation{
        .zone = delegation_zone,
        .ns = .{
            .name = ns_name,
            .type = .ns,
            .class = .in,
            .records = .empty,
            .ttl = if (min_ttl == std.math.maxInt(u32)) 0 else min_ttl,
        },
        .servers = .empty,
    };
    delegation_zone_transferred = true;
    ns_name_transferred = true;
    errdefer delegation.deinit(allocator);

    try delegation.ns.records.ensureTotalCapacity(allocator, ns_records.items.len);
    for (ns_records.items) |*record| {
        delegation.ns.records.appendAssumeCapacity(try record.clone(allocator));

        var server = resolver_types.NameServer{
            .name = try record.rdata.ns.name.clone(allocator),
        };
        errdefer server.deinit(allocator);

        try appendGlueAddresses(allocator, response, &server);
        try delegation.servers.append(allocator, server);
    }

    zone.?.deinit(allocator);
    zone = null;
    return delegation;
}

fn appendGlueAddresses(
    allocator: Allocator,
    response: *const Message.Message,
    server: *resolver_types.NameServer,
) !void {
    for (response.additionals.items) |*additional| {
        if (!Message.Name.equalsIgnoreCase(&additional.name, &server.name)) continue;
        switch (additional.type) {
            .a => try server.addrs.append(allocator, withPort(.{ .ip4 = additional.rdata.a.addr }, 53)),
            .aaaa => try server.addrs.append(allocator, withPort(.{ .ip6 = additional.rdata.aaaa.addr }, 53)),
            else => {},
        }
    }
}

fn withPort(addr: net.IpAddress, port: u16) net.IpAddress {
    return switch (addr) {
        .ip4 => |ip| .{ .ip4 = .{ .bytes = ip.bytes, .port = port } },
        .ip6 => |ip| .{ .ip6 = .{ .bytes = ip.bytes, .port = port, .flow = ip.flow, .interface = ip.interface } },
    };
}

fn rememberCnamesForQuestion(
    self: *Fetch,
    allocator: Allocator,
    response: *const Message.Message,
    qname: *const Message.Name,
) !void {
    for (response.answers.items) |*record| {
        if (record.type != .cname or !Message.Name.equalsIgnoreCase(&record.name, qname)) continue;
        if (self.hasRememberedCname(&record.name)) continue;
        try self.cname_chain.append(allocator, try record.clone(allocator));
    }
}

fn hasRememberedCname(self: *const Fetch, name: *const Message.Name) bool {
    for (self.cname_chain.items) |*record| {
        if (Message.Name.equalsIgnoreCase(&record.name, name)) return true;
    }
    return false;
}

fn appendCnameChain(self: *Fetch, allocator: Allocator, message: *Message.Message) !void {
    for (self.cname_chain.items) |*record| {
        if (messageHasCnameFor(message, &record.name)) continue;
        try message.answers.append(allocator, try record.clone(allocator));
    }
    message.header.an_count = @intCast(message.answers.items.len);
}

fn messageHasCnameFor(message: *const Message.Message, name: *const Message.Name) bool {
    for (message.answers.items) |*record| {
        if (record.type == .cname and Message.Name.equalsIgnoreCase(&record.name, name)) return true;
    }
    return false;
}

test "fetch key hashes names case-insensitively" {
    const allocator = std.testing.allocator;

    var upper_name = try Message.Name.initString(allocator, "Example.COM");
    defer upper_name.deinit(allocator);
    var lower_name = try Message.Name.initString(allocator, "example.com");
    defer lower_name.deinit(allocator);

    const upper = FetchKey{ .name = upper_name, .type = .a, .class = .in };
    const lower = FetchKey{ .name = lower_name, .type = .a, .class = .in };
    const ctx = FetchKey.HashContext{};

    try std.testing.expect(ctx.eql(upper, lower));
    try std.testing.expectEqual(ctx.hash(upper), ctx.hash(lower));
}

test "referral response builds delegation with glue" {
    const allocator = std.testing.allocator;

    var response = Message.Message.init();
    defer response.deinit(allocator);

    const ns = try response.addAuthority(allocator, .ns);
    try ns.name.parse(allocator, "example.com");
    ns.ttl = 300;
    var ns_rdata = Message.RData.init(.ns);
    defer ns_rdata.deinit(allocator);
    try ns_rdata.ns.name.parse(allocator, "ns1.example.com");
    try ns.setRData(allocator, &ns_rdata);

    const glue = try response.addAdditional(allocator, .a);
    try glue.name.parse(allocator, "ns1.example.com");
    var a_rdata = Message.RData.init(.a);
    defer a_rdata.deinit(allocator);
    a_rdata.a.addr = try net.Ip4Address.parse("192.0.2.1", 0);
    try glue.setRData(allocator, &a_rdata);

    var delegation = (try buildDelegationFromReferral(allocator, &response)).?;
    defer delegation.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), delegation.ns.records.items.len);
    try std.testing.expectEqual(@as(usize, 1), delegation.servers.items.len);
    try std.testing.expectEqual(@as(usize, 1), delegation.servers.items[0].addrs.items.len);
}

test "fetch start completes on direct answer" {
    const allocator = std.testing.allocator;

    var question = Message.Question.init();
    defer question.deinit(allocator);
    try question.qname.parse(allocator, "example.com");
    question.qtype = .a;
    question.qclass = .in;

    var key = try FetchKey.fromQuestion(allocator, &question);
    defer key.deinit(allocator);

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

    var fetch = try Fetch.init(allocator, &key, &root_delegation, .{});
    defer fetch.deinit(allocator);

    const FakeTransport = struct {
        fn queryAny(
            ptr: *anyopaque,
            loop: *xev.Loop,
            completion: *xev.Completion,
            alloc: Allocator,
            _: *const resolver_types.Delegation,
            q: *const Message.Question,
            _: QueryPolicy,
            userdata: ?*anyopaque,
            callback: Transport.QueryCallback,
        ) !void {
            _ = ptr;

            var message = Message.Message.init();
            errdefer message.deinit(alloc);
            message.header.flags.response = true;
            message.header.flags.response_code = .no_error;

            const answer = try message.addAnswer(alloc, .a);
            answer.name = try q.qname.clone(alloc);
            answer.ttl = 60;
            var rdata = Message.RData.init(.a);
            defer rdata.deinit(alloc);
            rdata.a.addr = try net.Ip4Address.parse("192.0.2.10", 0);
            try answer.setRData(alloc, &rdata);
            message.header.an_count = 1;

            _ = callback(userdata, loop, completion, .{ .message = message });
        }
    };

    const ResultContext = struct {
        result: ?FetchResult = null,

        fn onComplete(
            userdata: ?*anyopaque,
            _: *xev.Loop,
            _: *Completion,
            result: FetchResult,
        ) xev.CallbackAction {
            const ctx: *@This() = @ptrCast(@alignCast(userdata.?));
            ctx.result = result;
            return .disarm;
        }
    };

    var loop: xev.Loop = undefined;
    var completion: Completion = .{};
    var ctx = ResultContext{};
    var fake_transport_context: u8 = 0;
    var transport = Transport{
        .ptr = &fake_transport_context,
        .query_any = FakeTransport.queryAny,
    };
    try fetch.start(&loop, &completion, allocator, Cache.none(), &transport, &ctx, ResultContext.onComplete);

    var result = try ctx.result.?;
    defer result.deinit(allocator);

    try std.testing.expectEqual(FetchState.done, fetch.state);
    try std.testing.expectEqual(@as(u16, 1), fetch.query_count);
    try std.testing.expectEqual(@as(usize, 1), result.answers.items.len);
}
