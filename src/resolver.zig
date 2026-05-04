const std = @import("std");
const Message = @import("message.zig");
const MessageReader = @import("message_reader.zig").MessageReader;
const cache_hub = @import("cache_hub.zig");
const dns_server = @import("dns_server.zig");
const Io = std.Io;
const net = Io.net;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const log = std.log.scoped(.recursive_resolver);

const DEFAULT_ROOT_HINTS_PATH = "resource/named.root";
const CACHE_UPDATE_BUFFER_CAPACITY = 256;
const MAX_NS = 16;
const MAX_UPSTREAM_INFLIGHT = 2;
const BUFFER_SIZE = 1232;
const MAX_REFERRAL_DEPTH = 16;
const UPSTREAM_TIMEOUT_MS = 2000;

const UpstreamPacket = struct {
    data: [BUFFER_SIZE]u8,
    len: usize,
};

const UpstreamSelectResult = union(enum) {
    response: anyerror!UpstreamPacket,
};

const QueryTarget = struct {
    server: *const NameServerEntry,
    addr: net.IpAddress,
};

const SList = struct {
    zone: Message.Name = .init(),
    match_count: i32 = 0,
    servers: ArrayList(NameServerEntry) = .empty,

    pub fn clone(self: *const SList, allocator: Allocator) !SList {
        var out = SList{
            .zone = try self.zone.clone(allocator),
            .match_count = self.match_count,
        };
        errdefer out.deinit(allocator);

        try out.servers.ensureTotalCapacity(allocator, self.servers.items.len);
        for (self.servers.items) |*server| {
            out.servers.appendAssumeCapacity(try server.clone(allocator));
        }
        return out;
    }

    pub fn deinit(self: *SList, allocator: Allocator) void {
        self.zone.deinit(allocator);
        for (self.servers.items) |*server| server.deinit(allocator);
        self.servers.deinit(allocator);
    }
};

const NameServerEntry = struct {
    name: Message.Name,
    addrs: ArrayList(net.IpAddress) = .empty,
    stats: ServerStats = .{},

    pub fn clone(self: *const NameServerEntry, allocator: Allocator) !NameServerEntry {
        return .{
            .name = try self.name.clone(allocator),
            .addrs = try self.addrs.clone(allocator),
            .stats = self.stats,
        };
    }

    pub fn deinit(self: *NameServerEntry, allocator: Allocator) void {
        self.name.deinit(allocator);
        self.addrs.deinit(allocator);
    }
};

const ServerStats = struct {
    rtt_ms: ?u32 = null,
    failed_attempts: u32 = 0,
    last_used: ?i64 = null,
    lame: bool = false,
};

const CacheKey = cache_hub.Key;
const CacheValue = cache_hub.Value;
const ResolverCacheHub = cache_hub.Hub;
const SListCache = std.HashMap(CacheKey, SList, CacheKey.HashContext, std.hash_map.default_max_load_percentage);

const PendingCacheEntry = struct {
    key: CacheKey,
    value: CacheValue,
    key_transferred: bool = false,

    fn deinit(self: *PendingCacheEntry, allocator: Allocator) void {
        if (!self.key_transferred) self.key.deinit(allocator);
        self.value.deinit(allocator);
    }
};

const ResolveResult = struct {
    message: Message,
    cacheable: bool,
};

const CacheJob = struct {
    message: Message,

    fn deinit(self: *CacheJob, allocator: Allocator) void {
        self.message.deinit(allocator);
    }
};

pub const Task = struct {
    allocator: Allocator,
    from: net.IpAddress,
    data: []u8,

    pub fn init(allocator: Allocator, from: net.IpAddress, data: []const u8) !*Task {
        const task = try allocator.create(Task);
        errdefer allocator.destroy(task);
        task.allocator = allocator;
        task.from = from;
        task.data = try allocator.dupe(u8, data);
        return task;
    }

    pub fn deinit(self: *Task) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }
};

pub const Resolver = struct {
    pub const Request = ResolverCacheHub.Request;

    allocator: Allocator,
    cache_hub: ResolverCacheHub,
    slist_cache: SListCache,
    slist_cache_mutex: Io.Mutex = .init,
    cache_update_buf: []CacheJob,
    cache_updates: Io.Queue(CacheJob),
    cache_update_workers: Io.Group = .init,
    s_belt: SList,

    pub fn init(
        allocator: Allocator,
        io: Io,
        request_buffer: []Request,
        root_hints_path: ?[]const u8,
    ) !Resolver {
        log.info("loading root hints from {s}", .{root_hints_path orelse DEFAULT_ROOT_HINTS_PATH});
        var s_belt = try loadSBeltFromRootHints(allocator, io, root_hints_path orelse DEFAULT_ROOT_HINTS_PATH);
        errdefer s_belt.deinit(allocator);
        log.info("loaded s_belt: servers={d}", .{s_belt.servers.items.len});

        const cache_update_buf = try allocator.alloc(CacheJob, CACHE_UPDATE_BUFFER_CAPACITY);
        errdefer allocator.free(cache_update_buf);

        return .{
            .allocator = allocator,
            .cache_hub = ResolverCacheHub.init(allocator, request_buffer),
            .slist_cache = SListCache.init(allocator),
            .cache_update_buf = cache_update_buf,
            .cache_updates = .init(cache_update_buf),
            .s_belt = s_belt,
        };
    }

    pub fn deinit(self: *Resolver, allocator: Allocator, io: Io) void {
        log.info("resolver deinit", .{});
        self.cache_updates.close(io);
        self.cache_update_workers.await(io) catch {};
        self.allocator.free(self.cache_update_buf);
        self.cache_hub.deinit(io);
        self.deinitSListCache(allocator, io);
        self.s_belt.deinit(allocator);
    }

    pub fn start(self: *Resolver, io: Io) !void {
        log.info("starting cache hub", .{});
        try self.cache_hub.start(io);
        try self.cache_update_workers.concurrent(io, cacheUpdateWorkerMain, .{ self, io });
    }

    fn deinitSListCache(self: *Resolver, allocator: Allocator, io: Io) void {
        self.slist_cache_mutex.lockUncancelable(io);
        defer self.slist_cache_mutex.unlock(io);

        var it = self.slist_cache.iterator();
        while (it.next()) |entry| {
            entry.key_ptr.deinit(allocator);
            entry.value_ptr.deinit(allocator);
        }
        self.slist_cache.deinit();
    }

    pub fn handlePacket(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        responder: dns_server.Responder,
        from: net.IpAddress,
        data: []const u8,
    ) !void {
        const gpa = allocator;
        log.debug("received packet from {f}: len={d}", .{ from, data.len });
        if (data.len < 12) {
            log.debug("dropping short packet from {f}: len={d}", .{ from, data.len });
            return;
        }

        var request = MessageReader.parse(data) catch {
            const id = readIdFromWire(data);
            log.debug("parse failed for packet from {f}: id={d}", .{ from, id });
            var err_msg = createDnsError(id, false, .format_error);
            try responder.sendMessage(from, &err_msg);
            return;
        };

        log.debug(
            "parsed request from {f}: id={d} qd={d} an={d} ns={d} ar={d}",
            .{ from, request.header.id, request.header.qd_count, request.header.an_count, request.header.ns_count, request.header.ar_count },
        );

        if (request.header.qd_count != 1) {
            log.debug("rejecting request id={d}: unsupported qd_count={d}", .{ request.header.id, request.header.qd_count });
            var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, .format_error);
            try responder.sendMessage(from, &err_msg);
            return;
        }

        var q = (try request.nextQuestion()) orelse return error.BadQuestion;
        logQuestionRef("request question", &q);

        var response = self.resolve(io, gpa, &request.header, &q) catch |err| {
            log.err("resolve failed for id={d}: {}", .{ request.header.id, err });
            var err_msg = createDnsError(request.header.id, request.header.flags.recursion_desired, .server_failure);
            try responder.sendMessage(from, &err_msg);
            return;
        };
        if (response.cacheable) {
            var cached_message = response.message;
            response.message = Message.Message.init();
            try responder.sendMessage(from, &cached_message);
            log.debug(
                "sent response to {f}: id={d} rcode={any} an={d} ns={d} ar={d}",
                .{ from, cached_message.header.id, cached_message.header.flags.response_code, cached_message.header.an_count, cached_message.header.ns_count, cached_message.header.ar_count },
            );
            self.enqueueCacheUpdate(io, gpa, cached_message) catch |err| {
                log.err("failed to queue cache update: {}", .{err});
                cached_message.deinit(gpa);
            };
            return;
        }
        defer response.message.deinit(gpa);
        try responder.sendMessage(from, &response.message);
        log.debug(
            "sent response to {f}: id={d} rcode={any} an={d} ns={d} ar={d}",
            .{ from, response.message.header.id, response.message.header.flags.response_code, response.message.header.an_count, response.message.header.ns_count, response.message.header.ar_count },
        );
    }

    pub fn resolve(
        self: *Resolver,
        io: Io,
        gpa: Allocator,
        header: *Message.Header,
        q: *Message.QuestionRef,
    ) !ResolveResult {
        var question = try q.toOwned(gpa);
        defer question.deinit(gpa);
        var qname = try q.qname.toOwned(gpa);
        defer qname.deinit(gpa);

        var slist = (try self.findClosestNs(io, gpa, &qname)) orelse try self.s_belt.clone(gpa);
        defer slist.deinit(gpa);
        logSList("initial slist", &slist);

        for (0..MAX_REFERRAL_DEPTH) |depth| {
            log.debug("resolve iteration depth={d} qtype={any}", .{ depth, q.qtype });
            const key = CacheKey{
                .qname = qname,
                .qtype = q.qtype,
            };

            if (try self.cache_hub.get(io, gpa, &key)) |cached| {
                var owned_cached = cached;
                defer self.cache_hub.freeValue(gpa, &owned_cached);
                log.debug("cache hit: qtype={any} records={d}", .{ q.qtype, owned_cached.records.items.len });
                return .{
                    .message = try responseFromCache(gpa, header, &question, &owned_cached),
                    .cacheable = false,
                };
            }
            log.debug("cache miss: qtype={any}", .{q.qtype});

            var upstream = try self.querySList(io, gpa, header, q, &slist);
            errdefer upstream.deinit(gpa);
            upstream.header.id = header.id;
            upstream.header.flags.recursion_available = true;
            log.debug(
                "upstream response: id={d} rcode={any} an={d} ns={d} ar={d}",
                .{ upstream.header.id, upstream.header.flags.response_code, upstream.header.an_count, upstream.header.ns_count, upstream.header.ar_count },
            );
            if (hasUsefulAnswer(&upstream, &qname, q.qtype)) {
                log.debug("returning useful answer", .{});
                return .{
                    .message = upstream,
                    .cacheable = true,
                };
            }
            if (upstream.header.flags.response_code != .no_error) {
                log.debug("returning upstream error rcode={any}", .{upstream.header.flags.response_code});
                return .{
                    .message = upstream,
                    .cacheable = true,
                };
            }

            var next_slist = (try self.buildSListFromReferralResponse(io, gpa, &upstream)) orelse {
                return .{
                    .message = upstream,
                    .cacheable = true,
                };
            };
            if (next_slist.match_count <= slist.match_count) {
                log.debug("referral did not improve slist: old_match={d} new_match={d}", .{ slist.match_count, next_slist.match_count });
                next_slist.deinit(gpa);
                return .{
                    .message = upstream,
                    .cacheable = true,
                };
            }

            slist.deinit(gpa);
            slist = next_slist;
            logSList("referral slist", &slist);
            const referral_key = CacheKey{ .qname = slist.zone, .qtype = .ns };
            self.putCachedSList(io, gpa, &referral_key, &slist) catch |err| {
                log.debug("failed to memoize referral slist: {}", .{err});
            };
            upstream.deinit(gpa);
        }

        return error.ReferralDepthExceeded;
    }

    fn readIdFromWire(data: []const u8) u16 {
        if (data.len < 2) return 0;
        return std.mem.readInt(u16, data[0..2], .big);
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

    fn createUpstreamQuery(
        id: u16,
        rd: bool,
        question: *Message.QuestionRef,
        writer: *Io.Writer,
    ) !usize {
        var header = Message.Header{
            .id = id,
            .flags = Message.Flags{
                .op_code = .query,
                .recursion_desired = rd,
            },
            .qd_count = 1,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        };

        var size: usize = 0;
        size += try header.encode(writer);
        size += try question.encode(writer);
        return size;
    }

    fn querySList(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        header: *const Message.Header,
        question: *Message.QuestionRef,
        slist: *const SList,
    ) !Message.Message {
        _ = self;
        var last_err: anyerror = error.NoNameserverAddress;
        var targets: [MAX_NS]QueryTarget = undefined;
        const target_count = collectQueryTargets(slist, targets[0..]);
        if (target_count == 0) return last_err;

        var select_buf: [MAX_UPSTREAM_INFLIGHT]UpstreamSelectResult = undefined;
        var select: Io.Select(UpstreamSelectResult) = .init(io, &select_buf);
        defer select.cancelDiscard();

        var next_target: usize = 0;
        var inflight: usize = 0;
        while (inflight < MAX_UPSTREAM_INFLIGHT and next_target < target_count) {
            const target = targets[next_target];
            next_target += 1;
            log.debug("querying upstream ns={f} addr={f}", .{ target.server.name, target.addr });
            select.async(.response, queryServerUdpPacket, .{ io, target.addr, header.id, false, question });
            inflight += 1;
        }
        log.debug("upstream fanout started: inflight={d} queued_targets={d}", .{ inflight, target_count });

        while (inflight > 0) {
            const completed = try select.await();
            inflight -= 1;

            switch (completed) {
                .response => |result| {
                    const packet = result catch |err| {
                        log.debug("upstream query failed: {}", .{err});
                        last_err = err;
                        continue;
                    };
                    log.debug("upstream packet received: len={d}", .{packet.len});

                    var reader = Io.Reader.fixed(packet.data[0..packet.len]);
                    var message = Message.Message.decode(allocator, &reader) catch |err| {
                        log.debug("upstream decode failed: {}", .{err});
                        last_err = err;
                        continue;
                    };
                    errdefer message.deinit(allocator);

                    if (message.header.id != header.id) {
                        log.debug("upstream id mismatch: expected={d} got={d}", .{ header.id, message.header.id });
                        last_err = error.UpstreamIdMismatch;
                        continue;
                    }

                    return message;
                },
            }

            while (inflight < MAX_UPSTREAM_INFLIGHT and next_target < target_count) {
                const target = targets[next_target];
                next_target += 1;
                log.debug("querying fallback upstream ns={f} addr={f}", .{ target.server.name, target.addr });
                select.async(.response, queryServerUdpPacket, .{ io, target.addr, header.id, false, question });
                inflight += 1;
            }
        }

        return last_err;
    }

    fn queryServerUdpPacket(
        io: Io,
        server: net.IpAddress,
        id: u16,
        rd: bool,
        question: *Message.QuestionRef,
    ) !UpstreamPacket {
        var bind_addr = switch (server) {
            .ip4 => try net.IpAddress.parse("0.0.0.0", 0),
            .ip6 => try net.IpAddress.parse("::", 0),
        };
        var socket = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });
        defer socket.close(io);

        var out_buf: [BUFFER_SIZE]u8 = undefined;
        var writer = Io.Writer.fixed(&out_buf);
        _ = try createUpstreamQuery(id, rd, question, &writer);
        log.debug("sending upstream UDP query: server={f} len={d}", .{ server, writer.end });
        try socket.send(io, &server, out_buf[0..writer.end]);

        var packet = UpstreamPacket{
            .data = undefined,
            .len = 0,
        };
        const timeout = Io.Timeout{ .duration = .{ .raw = Io.Duration.fromMilliseconds(UPSTREAM_TIMEOUT_MS), .clock = .awake } };
        const incoming = try socket.receiveTimeout(io, packet.data[0..], timeout);
        packet.len = incoming.data.len;
        log.debug("received upstream UDP response: server={f} len={d}", .{ server, packet.len });
        return packet;
    }

    fn cacheResponse(self: *Resolver, io: Io, allocator: Allocator, response: *const Message.Message) !void {
        log.debug("caching response records: an={d} ns={d} ar={d}", .{ response.answers.items.len, response.authorities.items.len, response.additionals.items.len });
        var groups: ArrayList(PendingCacheEntry) = .empty;
        defer {
            for (groups.items) |*group| group.deinit(allocator);
            groups.deinit(allocator);
        }

        for (response.answers.items) |*record| try addRecordToCacheGroups(allocator, &groups, record);
        for (response.authorities.items) |*record| try addRecordToCacheGroups(allocator, &groups, record);
        for (response.additionals.items) |*record| try addRecordToCacheGroups(allocator, &groups, record);

        for (groups.items) |*group| try self.commitCacheGroup(io, allocator, group);
    }

    fn cacheRecord(self: *Resolver, io: Io, allocator: Allocator, record: *const Message.Record) !void {
        var key = CacheKey{
            .qname = try record.name.clone(allocator),
            .qtype = record.type,
        };
        var value = if (try self.cache_hub.get(io, allocator, &key)) |existing| existing else CacheValue{};
        var transferred = false;
        errdefer if (!transferred) {
            key.deinit(allocator);
            value.deinit(allocator);
        };

        var cached_record = try normalizedRecordForCache(allocator, record);
        var record_transferred = false;
        errdefer if (!record_transferred) cached_record.deinit(allocator);
        try value.records.append(allocator, cached_record);
        record_transferred = true;

        transferred = true;
        try self.cache_hub.putBlocking(io, allocator, key, value);
        log.debug("cached record: name={f} type={any}", .{ record.name, record.type });
    }

    fn commitCacheGroup(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        group: *PendingCacheEntry,
    ) !void {
        var value = if (try self.cache_hub.get(io, allocator, &group.key)) |existing| existing else CacheValue{};
        var value_transferred = false;
        errdefer if (!value_transferred) value.deinit(allocator);

        for (group.value.records.items) |*record| {
            try value.appendRecord(allocator, record);
        }

        group.key_transferred = true;
        value_transferred = true;
        try self.cache_hub.putBlocking(io, allocator, group.key, value);
        log.debug("cached rrset: name={f} type={any} added={d}", .{ group.key.qname, group.key.qtype, group.value.records.items.len });
    }

    fn responseFromCache(
        allocator: Allocator,
        request_header: *const Message.Header,
        question: *const Message.Question,
        cached: *const CacheValue,
    ) !Message.Message {
        var response = Message.Message.init();
        errdefer response.deinit(allocator);

        response.header = .{
            .id = request_header.id,
            .flags = .{
                .response = true,
                .op_code = .query,
                .recursion_desired = request_header.flags.recursion_desired,
                .recursion_available = true,
                .response_code = .no_error,
            },
            .qd_count = 1,
            .an_count = @intCast(cached.records.items.len),
            .ns_count = 0,
            .ar_count = 0,
        };

        var question_copy = try question.clone(allocator);
        var question_transferred = false;
        errdefer if (!question_transferred) question_copy.deinit(allocator);
        try response.questions.append(allocator, question_copy);
        question_transferred = true;

        for (cached.records.items) |*record| {
            var record_copy = try record.clone(allocator);
            var record_transferred = false;
            errdefer if (!record_transferred) record_copy.deinit(allocator);
            try response.answers.append(allocator, record_copy);
            record_transferred = true;
        }
        return response;
    }

    fn hasUsefulAnswer(response: *const Message.Message, qname: *const Message.Name, qtype: Message.Type) bool {
        for (response.answers.items) |*record| {
            if (record.type == qtype and Message.Name.equalsIgnoreCase(&record.name, qname)) return true;
            if (record.type == .cname and Message.Name.equalsIgnoreCase(&record.name, qname)) return true;
        }
        return false;
    }

    fn findClosestNs(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        name: *const Message.Name,
    ) !?SList {
        var zone = try name.clone(allocator);
        defer zone.deinit(allocator);
        while (true) {
            log.debug("findClosestNs lookup: zone={f}", .{zone});
            const key = CacheKey{
                .qname = zone,
                .qtype = .ns,
            };

            if (try self.getCachedSList(io, allocator, &key)) |slist| {
                log.debug("findClosestNs slist cache hit: zone={f} servers={d}", .{ zone, slist.servers.items.len });
                return slist;
            }

            if (try self.cache_hub.get(io, allocator, &key)) |ns_value| {
                var owned_ns_value = ns_value;
                defer self.cache_hub.freeValue(allocator, &owned_ns_value);

                var slist = try self.buildSListFromNsCache(io, allocator, &zone, &owned_ns_value);
                log.debug("findClosestNs cache hit: zone={f} ns_records={d} usable_servers={d}", .{ zone, owned_ns_value.records.items.len, slist.servers.items.len });
                if (slist.servers.items.len > 0) {
                    try self.putCachedSList(io, allocator, &key, &slist);
                    return slist;
                }
                slist.deinit(allocator);
            }

            if (!zone.removeFirstLabel()) break;
        }

        return null;
    }

    fn getCachedSList(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        key: *const CacheKey,
    ) !?SList {
        self.slist_cache_mutex.lockUncancelable(io);
        defer self.slist_cache_mutex.unlock(io);

        const cached = self.slist_cache.getPtr(key.*) orelse return null;
        return try cached.clone(allocator);
    }

    fn putCachedSList(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        key: *const CacheKey,
        slist: *const SList,
    ) !void {
        var owned_key = CacheKey{
            .qname = try key.qname.clone(allocator),
            .qtype = key.qtype,
        };
        var owned_slist = try slist.clone(allocator);
        var transferred = false;
        errdefer if (!transferred) {
            owned_key.deinit(allocator);
            owned_slist.deinit(allocator);
        };

        self.slist_cache_mutex.lockUncancelable(io);
        defer self.slist_cache_mutex.unlock(io);

        if (self.slist_cache.getEntry(owned_key)) |entry| {
            owned_key.deinit(allocator);
            entry.value_ptr.deinit(allocator);
            entry.value_ptr.* = owned_slist;
            transferred = true;
            log.debug("updated slist cache: zone={f} servers={d}", .{ key.qname, slist.servers.items.len });
            return;
        }

        try self.slist_cache.put(owned_key, owned_slist);
        transferred = true;
        log.debug("stored slist cache: zone={f} servers={d}", .{ key.qname, slist.servers.items.len });
    }

    fn buildSListFromNsCache(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        zone: *const Message.Name,
        ns_value: *const CacheValue,
    ) !SList {
        var slist = SList{
            .zone = try zone.clone(allocator),
            .match_count = @intCast(zone.labelCount()),
        };
        errdefer slist.deinit(allocator);

        for (ns_value.records.items) |*record| {
            if (record.type != .ns) continue;
            var parsed = try record.parseRData(allocator);
            defer parsed.deinit(allocator);

            var entry = NameServerEntry{
                .name = try parsed.ns.name.clone(allocator),
            };
            errdefer entry.deinit(allocator);

            try self.appendCachedAddrs(io, allocator, &entry);
            log.debug("slist ns entry: name={f} addrs={d}", .{ entry.name, entry.addrs.items.len });
            if (entry.addrs.items.len == 0) {
                log.debug("skipping ns entry without cached address: name={f}", .{entry.name});
                entry.deinit(allocator);
                continue;
            }
            try slist.servers.append(allocator, entry);
        }

        return slist;
    }

    fn buildSListFromReferralResponse(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        response: *const Message.Message,
    ) !?SList {
        var slist = SList{
            .zone = .init(),
            .match_count = 0,
        };
        errdefer slist.deinit(allocator);

        var saw_ns = false;
        for (response.authorities.items) |*record| {
            if (record.type != .ns) continue;

            if (!saw_ns) {
                slist.zone = try record.name.clone(allocator);
                slist.match_count = @intCast(slist.zone.labelCount());
                saw_ns = true;
            }

            var parsed = try record.parseRData(allocator);
            defer parsed.deinit(allocator);

            var entry = NameServerEntry{
                .name = try parsed.ns.name.clone(allocator),
            };
            errdefer entry.deinit(allocator);

            for (response.additionals.items) |*additional| {
                if (!Message.Name.equalsIgnoreCase(&additional.name, &entry.name)) continue;
                switch (additional.type) {
                    .a => {
                        var parsed_a = try additional.parseRData(allocator);
                        defer parsed_a.deinit(allocator);
                        try entry.addrs.append(allocator, withPort(.{ .ip4 = parsed_a.a.addr }, 53));
                    },
                    .aaaa => {
                        var parsed_aaaa = try additional.parseRData(allocator);
                        defer parsed_aaaa.deinit(allocator);
                        try entry.addrs.append(allocator, withPort(.{ .ip6 = parsed_aaaa.aaaa.addr }, 53));
                    },
                    else => {},
                }
            }

            if (entry.addrs.items.len == 0) {
                try self.appendCachedAddrs(io, allocator, &entry);
            }

            if (entry.addrs.items.len == 0) {
                entry.deinit(allocator);
                continue;
            }

            try slist.servers.append(allocator, entry);
        }

        if (!saw_ns or slist.servers.items.len == 0) {
            slist.deinit(allocator);
            return null;
        }

        return slist;
    }

    fn appendCachedAddrs(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        entry: *NameServerEntry,
    ) !void {
        const before = entry.addrs.items.len;
        try self.appendCachedAddrsOfType(io, allocator, entry, .a);
        if (entry.addrs.items.len == before) {
            try self.appendCachedAddrsOfType(io, allocator, entry, .aaaa);
        }
    }

    fn enqueueCacheUpdate(self: *Resolver, io: Io, allocator: Allocator, message: Message.Message) !void {
        var job = CacheJob{ .message = message };
        errdefer job.deinit(allocator);
        try self.cache_updates.putOneUncancelable(io, job);
    }

    fn appendCachedAddrsOfType(
        self: *Resolver,
        io: Io,
        allocator: Allocator,
        entry: *NameServerEntry,
        qtype: Message.Type,
    ) !void {
        const key = CacheKey{
            .qname = entry.name,
            .qtype = qtype,
        };

        if (try self.cache_hub.get(io, allocator, &key)) |addr_value| {
            var owned_addr_value = addr_value;
            defer self.cache_hub.freeValue(allocator, &owned_addr_value);

            for (owned_addr_value.records.items) |*record| {
                if (!Message.Name.equalsIgnoreCase(&record.name, &entry.name)) continue;
                switch (record.type) {
                    .a => {
                        var parsed = try record.parseRData(allocator);
                        defer parsed.deinit(allocator);
                        try entry.addrs.append(allocator, withPort(.{ .ip4 = parsed.a.addr }, 53));
                        log.debug("found cached A glue: ns={f} addr={f}", .{ entry.name, entry.addrs.items[entry.addrs.items.len - 1] });
                    },
                    .aaaa => {
                        var parsed = try record.parseRData(allocator);
                        defer parsed.deinit(allocator);
                        try entry.addrs.append(allocator, withPort(.{ .ip6 = parsed.aaaa.addr }, 53));
                        log.debug("found cached AAAA glue: ns={f} addr={f}", .{ entry.name, entry.addrs.items[entry.addrs.items.len - 1] });
                    },
                    else => {},
                }
            }
        }
    }
};

fn loadSBeltFromRootHints(allocator: Allocator, io: Io, path: []const u8) !SList {
    var slist = SList{
        .zone = Message.Name.init(),
        .match_count = 0,
    };
    errdefer slist.deinit(allocator);

    var dir = Io.Dir.cwd();
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    var buffer: [1024]u8 = undefined;
    var reader = Io.File.Reader.init(file, io, &buffer);
    const contents = try reader.interface.readAlloc(allocator, stat.size);
    defer allocator.free(contents);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        var line = raw_line;
        if (std.mem.indexOfScalar(u8, line, ';')) |comment_start| {
            line = line[0..comment_start];
        }
        line = std.mem.trim(u8, line, " \t\r");
        if (line.len == 0 or line[0] == '$') continue;

        var token_it = std.mem.tokenizeAny(u8, line, " \t");
        var tokens_buf: [8][]const u8 = undefined;
        var tokens_len: usize = 0;
        while (token_it.next()) |token| {
            if (tokens_len == tokens_buf.len) break;
            tokens_buf[tokens_len] = token;
            tokens_len += 1;
        }
        if (tokens_len < 4) continue;

        const tokens = tokens_buf[0..tokens_len];
        const type_index, const record_type = findRootHintType(tokens) orelse continue;
        if (type_index + 1 >= tokens.len) continue;

        const owner = tokens[0];
        const rdata = tokens[type_index + 1];
        switch (record_type) {
            .ns => {
                _ = try getOrCreateServer(allocator, &slist, rdata);
            },
            .a, .aaaa => {
                const server = try getOrCreateServer(allocator, &slist, owner);
                try server.addrs.append(allocator, try net.IpAddress.parse(rdata, 53));
            },
            else => {},
        }
    }

    return slist;
}

fn cacheUpdateWorkerMain(self: *Resolver, io: Io) Io.Cancelable!void {
    while (true) {
        const job = self.cache_updates.getOne(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => break,
        };
        var owned_job = job;
        defer owned_job.deinit(self.allocator);

        self.cacheResponse(io, self.allocator, &owned_job.message) catch |err| {
            log.err("background cache update failed: {}", .{err});
        };
    }
}

fn findRootHintType(tokens: []const []const u8) ?struct { usize, Message.Type } {
    for (tokens, 0..) |token, index| {
        if (std.ascii.eqlIgnoreCase(token, "NS")) return .{ index, .ns };
        if (std.ascii.eqlIgnoreCase(token, "A")) return .{ index, .a };
        if (std.ascii.eqlIgnoreCase(token, "AAAA")) return .{ index, .aaaa };
    }
    return null;
}

fn getOrCreateServer(
    allocator: Allocator,
    slist: *SList,
    name_text: []const u8,
) !*NameServerEntry {
    var name = try Message.Name.initString(allocator, name_text);
    errdefer name.deinit(allocator);

    for (slist.servers.items) |*server| {
        if (Message.Name.equalsIgnoreCase(&server.name, &name)) {
            name.deinit(allocator);
            return server;
        }
    }

    try slist.servers.append(allocator, .{ .name = name });
    return &slist.servers.items[slist.servers.items.len - 1];
}

fn collectQueryTargets(slist: *const SList, out: []QueryTarget) usize {
    var count: usize = 0;

    for (slist.servers.items) |*server| {
        if (server.addrs.items.len == 0 or count == out.len) continue;
        const addr_index = preferredAddrIndex(server);
        out[count] = .{ .server = server, .addr = server.addrs.items[addr_index] };
        count += 1;
    }

    for (slist.servers.items) |*server| {
        if (server.addrs.items.len <= 1) continue;
        const preferred = preferredAddrIndex(server);
        for (server.addrs.items, 0..) |addr, index| {
            if (count == out.len) return count;
            if (index == preferred) continue;
            out[count] = .{ .server = server, .addr = addr };
            count += 1;
        }
    }

    return count;
}

fn preferredAddrIndex(server: *const NameServerEntry) usize {
    for (server.addrs.items, 0..) |addr, index| {
        switch (addr) {
            .ip4 => return index,
            .ip6 => {},
        }
    }
    return 0;
}

fn normalizedRecordForCache(allocator: Allocator, record: *const Message.Record) !Message.Record {
    var out = try record.clone(allocator);
    errdefer out.deinit(allocator);

    var parsed = record.parseRData(allocator) catch |err| {
        log.debug("leaving cached rdata raw: name={f} type={any} parse_err={}", .{ record.name, record.type, err });
        return out;
    };
    defer parsed.deinit(allocator);

    try out.setRData(allocator, &parsed);
    return out;
}

fn addRecordToCacheGroups(
    allocator: Allocator,
    groups: *ArrayList(PendingCacheEntry),
    record: *const Message.Record,
) !void {
    const lookup_key = CacheKey{
        .qname = record.name,
        .qtype = record.type,
    };
    const ctx = CacheKey.HashContext{};

    for (groups.items) |*group| {
        if (ctx.eql(group.key, lookup_key)) {
            var cached_record = try normalizedRecordForCache(allocator, record);
            var transferred = false;
            errdefer if (!transferred) cached_record.deinit(allocator);
            try group.value.records.append(allocator, cached_record);
            transferred = true;
            return;
        }
    }

    var entry = PendingCacheEntry{
        .key = .{
            .qname = try record.name.clone(allocator),
            .qtype = record.type,
        },
        .value = .{},
    };
    errdefer entry.deinit(allocator);

    var cached_record = try normalizedRecordForCache(allocator, record);
    var transferred = false;
    errdefer if (!transferred) cached_record.deinit(allocator);
    try entry.value.records.append(allocator, cached_record);
    transferred = true;

    try groups.append(allocator, entry);
}

fn withPort(addr: net.IpAddress, port: u16) net.IpAddress {
    return switch (addr) {
        .ip4 => |ip| .{ .ip4 = .{ .bytes = ip.bytes, .port = port } },
        .ip6 => |ip| .{ .ip6 = .{ .bytes = ip.bytes, .port = port, .flow = ip.flow, .interface = ip.interface } },
    };
}

fn logQuestionRef(prefix: []const u8, q: *const Message.QuestionRef) void {
    var buf: [512]u8 = undefined;
    const qname = q.qname.print(buf[0..], q.qtype) catch "<bad qname>";
    log.debug("{s}: qname={s} qtype={any} qclass={any}", .{ prefix, qname, q.qtype, q.qclass });
}

fn logSList(prefix: []const u8, slist: *const SList) void {
    var addr_count: usize = 0;
    for (slist.servers.items) |*server| {
        addr_count += server.addrs.items.len;
    }
    log.debug("{s}: zone={f} match={d} servers={d} addrs={d}", .{ prefix, slist.zone, slist.match_count, slist.servers.items.len, addr_count });
}

test "resolver cache key and value support CacheHub ownership" {
    const allocator = std.testing.allocator;

    var key = CacheKey{
        .qname = try Message.Name.initString(allocator, "Example.COM"),
        .qtype = .a,
    };
    defer key.deinit(allocator);

    var same_key = CacheKey{
        .qname = try Message.Name.initString(allocator, "example.com"),
        .qtype = .a,
    };
    defer same_key.deinit(allocator);

    const ctx = CacheKey.HashContext{};
    try std.testing.expect(ctx.eql(key, same_key));
    try std.testing.expectEqual(ctx.hash(key), ctx.hash(same_key));

    var record = Message.Record.init(.aaaa);
    defer record.deinit(allocator);
    try record.name.parse(allocator, "answer.example.com");
    var rdata = Message.RData.init(.aaaa);
    defer rdata.deinit(allocator);
    rdata.aaaa.addr = try net.Ip6Address.parse("2001:db8::1", 0);
    try record.setRData(allocator, &rdata);

    var value = CacheValue{};
    defer value.deinit(allocator);
    try value.appendRecord(allocator, &record);

    var value_copy = try value.clone(allocator);
    defer value_copy.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), value_copy.records.items.len);

    var request_buffer: [4]ResolverCacheHub.Request = undefined;
    var hub = ResolverCacheHub.init(allocator, &request_buffer);
    defer hub.map.deinit();
}

test "findClosestNs builds SLIST from cached NS and address records" {
    const allocator = std.testing.allocator;

    var threaded = Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_buffer: [32]ResolverCacheHub.Request = undefined;
    var resolver = Resolver{
        .allocator = allocator,
        .cache_hub = ResolverCacheHub.init(allocator, &request_buffer),
        .slist_cache = SListCache.init(allocator),
        .cache_update_buf = try allocator.alloc(CacheJob, CACHE_UPDATE_BUFFER_CAPACITY),
        .cache_updates = undefined,
        .s_belt = .{},
    };
    resolver.cache_updates = .init(resolver.cache_update_buf);
    try resolver.cache_hub.start(io);
    defer {
        resolver.cache_hub.deinit(io);
        resolver.deinitSListCache(allocator, io);
        resolver.cache_updates.close(io);
        resolver.cache_update_workers.await(io) catch {};
        allocator.free(resolver.cache_update_buf);
    }

    var zone = try Message.Name.initString(allocator, "example.com");
    defer zone.deinit(allocator);

    var ns_record = Message.Record.init(.ns);
    defer ns_record.deinit(allocator);
    try ns_record.name.copy(allocator, &zone);
    var ns_rdata = Message.RData.init(.ns);
    defer ns_rdata.deinit(allocator);
    try ns_rdata.ns.name.parse(allocator, "ns1.example.com");
    try ns_record.setRData(allocator, &ns_rdata);

    var ns_value = CacheValue{};
    try ns_value.appendRecord(allocator, &ns_record);

    const ns_key = CacheKey{
        .qname = try zone.clone(allocator),
        .qtype = .ns,
    };
    try resolver.cache_hub.putBlocking(io, allocator, ns_key, ns_value);

    var ns_name = try Message.Name.initString(allocator, "ns1.example.com");
    defer ns_name.deinit(allocator);

    var a_record = Message.Record.init(.a);
    defer a_record.deinit(allocator);
    try a_record.name.copy(allocator, &ns_name);
    var a_rdata = Message.RData.init(.a);
    defer a_rdata.deinit(allocator);
    a_rdata.a.addr = try net.Ip4Address.parse("192.0.2.53", 0);
    try a_record.setRData(allocator, &a_rdata);

    var a_value = CacheValue{};
    try a_value.appendRecord(allocator, &a_record);

    const a_key = CacheKey{
        .qname = try ns_name.clone(allocator),
        .qtype = .a,
    };
    try resolver.cache_hub.putBlocking(io, allocator, a_key, a_value);

    var qname = try Message.Name.initString(allocator, "www.api.example.com");
    defer qname.deinit(allocator);

    var slist = (try resolver.findClosestNs(io, allocator, &qname)) orelse return error.MissingSList;
    defer slist.deinit(allocator);

    try std.testing.expect(Message.Name.equalsIgnoreCase(&slist.zone, &zone));
    try std.testing.expectEqual(@as(i32, 2), slist.match_count);
    try std.testing.expectEqual(@as(usize, 1), slist.servers.items.len);
    try std.testing.expect(Message.Name.equalsIgnoreCase(&slist.servers.items[0].name, &ns_name));
    try std.testing.expectEqual(@as(usize, 1), slist.servers.items[0].addrs.items.len);

    const expected_addr = withPort(.{ .ip4 = try net.Ip4Address.parse("192.0.2.53", 0) }, 53);
    try std.testing.expect(slist.servers.items[0].addrs.items[0].eql(&expected_addr));
}

test "Resolver.init loads s_belt from root hints" {
    const allocator = std.testing.allocator;

    var threaded = Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_buffer: [4]ResolverCacheHub.Request = undefined;
    var resolver = try Resolver.init(allocator, io, &request_buffer, DEFAULT_ROOT_HINTS_PATH);
    defer resolver.deinit(allocator, io);

    try std.testing.expectEqual(@as(i32, 0), resolver.s_belt.match_count);
    try std.testing.expect(resolver.s_belt.servers.items.len >= 13);

    var addrs: usize = 0;
    for (resolver.s_belt.servers.items) |server| {
        addrs += server.addrs.items.len;
    }
    try std.testing.expect(addrs >= 13);
}

test "cached compressed NS rdata is normalized before reuse" {
    const allocator = std.testing.allocator;

    const packet =
        "\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x07example\x03com\x00\x00\x02\x00\x01" ++
        "\xc0\x0c\x00\x02\x00\x01\x00\x00\x00\x3c\x00\x06\x03ns1\xc0\x0c";

    var reader = Io.Reader.fixed(packet);
    var decoded = try Message.Message.decode(allocator, &reader);
    defer decoded.deinit(allocator);

    var normalized = try normalizedRecordForCache(allocator, &decoded.answers.items[0]);
    defer normalized.deinit(allocator);

    var parsed = try normalized.parseRData(allocator);
    defer parsed.deinit(allocator);

    var expected = try Message.Name.initString(allocator, "ns1.example.com");
    defer expected.deinit(allocator);
    try std.testing.expect(Message.Name.equalsIgnoreCase(&parsed.ns.name, &expected));
}

pub fn run(io: Io, allocator: Allocator) !void {
    var request_buffer: [1024]ResolverCacheHub.Request = undefined;
    var resolver = try Resolver.init(allocator, io, &request_buffer, DEFAULT_ROOT_HINTS_PATH);
    defer resolver.deinit(allocator, io);

    const DnsServer = dns_server.Server(Resolver);
    var server = try DnsServer.init(allocator, io, .{ .bind_addr = "0.0.0.0", .bind_port = 53 }, &resolver);
    defer server.deinit();

    try server.run();
}
