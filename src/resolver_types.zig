const std = @import("std");
const Message = @import("message.zig");
const Name = Message.Name;
const Header = Message.Header;
const Record = Message.Record;
const Question = Message.Question;
const Type = Message.Type;
const Class = Message.Class;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const net = std.Io.net;

pub const RRSet = struct {
    name: Name,
    type: Type,
    class: Class,
    records: ArrayList(Record),
    ttl: u32,

    pub fn init(allocator: Allocator, name: Name, @"type": Type, class: Class) RRSet {
        return .{
            .name = name.clone(allocator),
            .type = @"type",
            .class = class,
            .records = .empty,
            .ttl = 0,
        };
    }

    pub fn clone(self: *const RRSet, allocator: Allocator) !RRSet {
        var out = RRSet{
            .name = try self.name.clone(allocator),
            .type = self.type,
            .class = self.class,
            .records = .empty,
            .ttl = self.ttl,
        };
        errdefer out.deinit(allocator);

        try out.records.ensureTotalCapacity(allocator, self.records.items.len);
        for (self.records.items) |*record| {
            out.records.appendAssumeCapacity(try record.clone(allocator));
        }
        return out;
    }

    pub fn deinit(self: *RRSet, allocator: Allocator) void {
        self.name.deinit(allocator);
        for (self.records.items) |*record| record.deinit(allocator);
        self.records.deinit(allocator);
        self.* = undefined;
    }
};

pub const Delegation = struct {
    zone: Name,
    ns: RRSet,
    servers: ArrayList(NameServer),

    pub fn clone(self: *const Delegation, allocator: Allocator) !Delegation {
        var zone = try self.zone.clone(allocator);
        var zone_transferred = false;
        errdefer if (!zone_transferred) zone.deinit(allocator);
        var ns = try self.ns.clone(allocator);
        var ns_transferred = false;
        errdefer if (!ns_transferred) ns.deinit(allocator);

        var out = Delegation{
            .zone = zone,
            .ns = ns,
            .servers = .empty,
        };
        zone_transferred = true;
        ns_transferred = true;
        errdefer out.deinit(allocator);

        try out.servers.ensureTotalCapacity(allocator, self.servers.items.len);
        for (self.servers.items) |*server| {
            out.servers.appendAssumeCapacity(try server.clone(allocator));
        }
        return out;
    }

    pub fn deinit(self: *Delegation, allocator: Allocator) void {
        self.zone.deinit(allocator);
        self.ns.deinit(allocator);
        for (self.servers.items) |*server| server.deinit(allocator);
        self.servers.deinit(allocator);
        self.* = undefined;
    }
};

pub const NameServer = struct {
    name: Message.Name,
    addrs: ArrayList(net.IpAddress) = .empty,
    stats: ServerStats = .{},

    pub fn clone(self: *const NameServer, allocator: Allocator) !NameServer {
        var name = try self.name.clone(allocator);
        errdefer name.deinit(allocator);
        return .{
            .name = name,
            .addrs = try self.addrs.clone(allocator),
            .stats = self.stats,
        };
    }

    pub fn deinit(self: *NameServer, allocator: Allocator) void {
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

pub const ClientRequest = struct {
    addr: net.IpAddress,

    header: Header,
    question: Question,

    pub fn clone(self: *const ClientRequest, allocator: Allocator) !ClientRequest {
        return .{
            .addr = self.addr,
            .header = self.header,
            .question = try self.question.clone(allocator),
        };
    }

    pub fn deinit(self: *ClientRequest, allocator: Allocator) void {
        self.question.deinit(allocator);
    }
};
