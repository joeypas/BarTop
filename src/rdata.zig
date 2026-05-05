const std = @import("std");
const rr = @import("rr.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const Type = rr.Type;

pub const A = @import("rdata/a.zig");
pub const AAAA = @import("rdata/aaaa.zig");
pub const NS = @import("rdata/ns.zig");
pub const CNAME = @import("rdata/cname.zig");
pub const DNAME = @import("rdata/dname.zig");
pub const SOA = @import("rdata/soa.zig");
pub const PTR = @import("rdata/ptr.zig");
pub const MX = @import("rdata/mx.zig");
pub const TXT = @import("rdata/txt.zig");
pub const SRV = @import("rdata/srv.zig");
pub const SVCB = @import("rdata/svcb.zig");
pub const OPT = @import("rdata/opt.zig");
pub const DNSKEY = @import("rdata/dnskey.zig");
pub const DS = @import("rdata/ds.zig");
pub const RRSIG = @import("rdata/rrsig.zig");
pub const NSEC = @import("rdata/nsec.zig");
pub const NSEC3 = @import("rdata/nsec3.zig");
pub const NSEC3PARAM = @import("rdata/nsec3param.zig");
pub const TLSA = @import("rdata/tlsa.zig");
pub const SSHFP = @import("rdata/sshfp.zig");
pub const CAA = @import("rdata/caa.zig");
pub const NAPTR = @import("rdata/naptr.zig");
pub const Raw = @import("rdata/raw.zig");

pub const RData = union(Type) {
    a: A,
    ns: NS,
    cname: CNAME,
    soa: SOA,
    ptr: PTR,
    mx: MX,
    txt: TXT,
    sig: RRSIG,
    aaaa: AAAA,
    srv: SRV,
    naptr: NAPTR,
    dname: DNAME,
    opt: OPT,
    ds: DS,
    sshfp: SSHFP,
    rrsig: RRSIG,
    nsec: NSEC,
    dnskey: DNSKEY,
    nsec3: NSEC3,
    nsec3param: NSEC3PARAM,
    tlsa: TLSA,
    cds: DS,
    cdnskey: DNSKEY,
    svcb: SVCB,
    https: SVCB,
    caa: CAA,
    data: Raw,

    pub fn init(@"type": Type) RData {
        return switch (@"type") {
            .a => .{ .a = A.init() },
            .ns => .{ .ns = NS.init() },
            .cname => .{ .cname = CNAME.init() },
            .soa => .{ .soa = SOA.init() },
            .ptr => .{ .ptr = PTR.init() },
            .mx => .{ .mx = MX.init() },
            .txt => .{ .txt = TXT.init() },
            .sig => .{ .sig = RRSIG.init() },
            .aaaa => .{ .aaaa = AAAA.init() },
            .srv => .{ .srv = SRV.init() },
            .naptr => .{ .naptr = NAPTR.init() },
            .dname => .{ .dname = DNAME.init() },
            .opt => .{ .opt = OPT.init() },
            .ds => .{ .ds = DS.init() },
            .sshfp => .{ .sshfp = SSHFP.init() },
            .rrsig => .{ .rrsig = RRSIG.init() },
            .nsec => .{ .nsec = NSEC.init() },
            .dnskey => .{ .dnskey = DNSKEY.init() },
            .nsec3 => .{ .nsec3 = NSEC3.init() },
            .nsec3param => .{ .nsec3param = NSEC3PARAM.init() },
            .tlsa => .{ .tlsa = TLSA.init() },
            .cds => .{ .cds = DS.init() },
            .cdnskey => .{ .cdnskey = DNSKEY.init() },
            .svcb => .{ .svcb = SVCB.init() },
            .https => .{ .https = SVCB.init() },
            .caa => .{ .caa = CAA.init() },
            else => .{ .data = Raw.init() },
        };
    }

    pub fn decode(allocator: Allocator, @"type": Type, len: usize, reader: *Reader) !RData {
        return switch (@"type") {
            .a => .{ .a = try A.decode(allocator, reader, len) },
            .ns => .{ .ns = try NS.decode(allocator, reader, len) },
            .cname => .{ .cname = try CNAME.decode(allocator, reader, len) },
            .soa => .{ .soa = try SOA.decode(allocator, reader, len) },
            .ptr => .{ .ptr = try PTR.decode(allocator, reader, len) },
            .mx => .{ .mx = try MX.decode(allocator, reader, len) },
            .txt => .{ .txt = try TXT.decode(allocator, reader, len) },
            .sig => .{ .sig = try RRSIG.decode(allocator, reader, len) },
            .aaaa => .{ .aaaa = try AAAA.decode(allocator, reader, len) },
            .srv => .{ .srv = try SRV.decode(allocator, reader, len) },
            .naptr => .{ .naptr = try NAPTR.decode(allocator, reader, len) },
            .dname => .{ .dname = try DNAME.decode(allocator, reader, len) },
            .opt => .{ .opt = try OPT.decode(allocator, reader, len) },
            .ds => .{ .ds = try DS.decode(allocator, reader, len) },
            .sshfp => .{ .sshfp = try SSHFP.decode(allocator, reader, len) },
            .rrsig => .{ .rrsig = try RRSIG.decode(allocator, reader, len) },
            .nsec => .{ .nsec = try NSEC.decode(allocator, reader, len) },
            .dnskey => .{ .dnskey = try DNSKEY.decode(allocator, reader, len) },
            .nsec3 => .{ .nsec3 = try NSEC3.decode(allocator, reader, len) },
            .nsec3param => .{ .nsec3param = try NSEC3PARAM.decode(allocator, reader, len) },
            .tlsa => .{ .tlsa = try TLSA.decode(allocator, reader, len) },
            .cds => .{ .cds = try DS.decode(allocator, reader, len) },
            .cdnskey => .{ .cdnskey = try DNSKEY.decode(allocator, reader, len) },
            .svcb => .{ .svcb = try SVCB.decode(allocator, reader, len) },
            .https => .{ .https = try SVCB.decode(allocator, reader, len) },
            .caa => .{ .caa = try CAA.decode(allocator, reader, len) },
            else => .{ .data = try Raw.decode(allocator, reader, len) },
        };
    }

    pub fn encode(self: *const RData, writer: *Writer) !usize {
        return switch (self.*) {
            inline else => |*case| case.encode(writer),
        };
    }

    pub fn wireLen(self: *const RData) usize {
        return switch (self.*) {
            inline else => |*case| case.wireLen(),
        };
    }

    pub fn getLen(self: *RData) u16 {
        return @intCast(self.wireLen());
    }

    pub fn clone(self: *const RData, allocator: Allocator) !RData {
        return switch (self.*) {
            inline else => |*case, tag| @unionInit(RData, @tagName(tag), try case.clone(allocator)),
        };
    }

    pub fn deinit(self: *RData, allocator: Allocator) void {
        switch (self.*) {
            inline else => |*case| case.deinit(allocator),
        }
    }

    pub fn ensureOwned(self: *RData, allocator: Allocator) !void {
        switch (self.*) {
            inline else => |*case| try case.ensureOwned(allocator),
        }
    }

    pub fn parse(self: *RData, allocator: Allocator, data: []const u8) !void {
        const trimmed = std.mem.trim(u8, data, " \t\n\r");
        switch (self.*) {
            .a => |*a| a.addr = try std.Io.net.Ip4Address.parse(trimmed, 0),
            .aaaa => |*aaaa| aaaa.addr = try std.Io.net.Ip6Address.parse(trimmed, 0),
            .data => |*raw| try raw.bytes.appendSlice(allocator, trimmed),
            else => return error.UnsupportedTextRData,
        }
    }

    pub fn format(self: RData, writer: *std.Io.Writer) !void {
        try writer.print("<{any} rdata {d} bytes>", .{ std.meta.activeTag(self), self.wireLen() });
    }
};

