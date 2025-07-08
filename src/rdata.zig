const std = @import("std");
const message = @import("message.zig");
const rr = @import("rr.zig");
const DNSSEC = @import("dnssec.zig");
const Reader = message.Reader;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Name = rr.Name;
const Type = rr.Type;

fn initRData(T: type, comptime tag: Type, allocator: Allocator) RData {
    var ret: T = undefined;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.meta.hasFn(field.type, "init")) {
                    @field(ret, field.name) = field.type.init(allocator);
                } else if (@typeInfo(field.type) == .int) {
                    @field(ret, field.name) = 0;
                }
            }
            return @unionInit(RData, @tagName(tag), ret);
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn deinitRData(comptime T: type, data: *T) void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.meta.hasFn(field.type, "deinit")) {
                    @field(data, field.name).deinit();
                }
            }
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn decodeRData(T: type, comptime tag: Type, allocator: Allocator, size: usize, buffered_reader: *Reader) !RData {
    var ret: T = undefined;
    var reader = buffered_reader.reader();
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.mem.startsWith(u8, field.name, "_")) {} else if (std.meta.hasFn(field.type, "decode")) {
                    @field(ret, field.name) = try field.type.decode(allocator, buffered_reader);
                } else if (@typeInfo(field.type) == .int) {
                    @field(ret, field.name) = try reader.readInt(field.type, .big);
                } else if (@typeInfo(field.type) == .@"enum") {
                    @field(ret, field.name) = @enumFromInt(try reader.readInt(@typeInfo(field.type).@"enum".tag_type, .big));
                } else if (field.type == ArrayList(u8)) {
                    var array = try ArrayList(u8).initCapacity(allocator, size);

                    reader.readUntilDelimiterArrayList(&array, 0xaa, size) catch |err| switch (err) {
                        error.EndOfStream => undefined,
                        error.StreamTooLong => undefined,
                        else => return err,
                    };

                    @field(ret, field.name) = array;
                }
            }
            return @unionInit(RData, @tagName(tag), ret);
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn encodeRData(comptime T: type, data: *T, writer: std.io.AnyWriter) !usize {
    var len: usize = 0;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.mem.startsWith(u8, field.name, "_")) {} else if (field.type == ArrayList(u8)) {
                    len += try writer.write(@field(data, field.name).items);
                } else if (std.meta.hasFn(field.type, "encode")) {
                    len += try @field(data, field.name).encode(writer);
                } else if (@typeInfo(field.type) == .int) {
                    try writer.writeInt(field.type, @field(data, field.name), .big);
                    len += @typeInfo(field.type).int.bits / 8;
                } else if (@typeInfo(field.type) == .@"enum") {
                    try writer.writeInt(@typeInfo(field.type).@"enum".tag_type, @intFromEnum(@field(data, field.name)), .big);
                    len += @typeInfo(@typeInfo(field.type).@"enum".tag_type).int.bits / 8;
                }
            }
            return len;
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn getLenRData(comptime T: type, data: *T) u16 {
    var len: u16 = 0;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (field.type == ArrayList(u8)) {
                    len += @intCast(@field(data, field.name).items.len);
                } else if (std.meta.hasFn(field.type, "getLen")) {
                    len += @field(data, field.name).getLen();
                } else if (@typeInfo(field.type) == .int) {
                    len += @typeInfo(field.type).int.bits / 8;
                }
            }
            return len;
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

pub const RData = union(Type) {
    // TODO:
    // 1. Implement printing support
    // 2. Full rdata type support
    a: struct {
        addr: std.net.Ip4Address = undefined,
    },
    ns: struct {
        name: Name,
    },
    cname: struct {
        name: Name,
    },
    soa: struct {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    ptr: struct {
        name: Name,
    },
    mx: struct {
        preface: u16,
        exchange: Name,
    },
    txt: struct {
        name: Name,
    },
    aaaa: struct {
        addr: std.net.Ip6Address = undefined,
    },
    srv: struct {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    dnskey: DNSSEC.DnsKey,
    ds: DNSSEC.DS,
    sig: DNSSEC.Sig,
    data: ArrayList(u8),

    pub fn init(allocator: Allocator, rtype: Type) RData {
        return switch (rtype) {
            inline .cname,
            .ns,
            .ptr,
            .mx,
            .txt,
            .soa,
            .srv,
            .dnskey,
            .ds,
            .sig,
            => |t| return initRData(std.meta.TagPayload(RData, t), t, allocator),
            .a => RData{ .a = .{} },
            .aaaa => RData{ .aaaa = .{} },
            else => RData{ .data = ArrayList(u8).init(allocator) },
        };
    }

    pub fn deinit(self: *RData) void {
        switch (self.*) {
            .data => |*case| case.deinit(),
            inline else => |*t| deinitRData(@TypeOf(t.*), t),
        }
    }

    pub fn decode(allocator: Allocator, @"type": Type, size: usize, buffered_reader: *Reader) !RData {
        var reader = buffered_reader.reader();
        switch (@"type") {
            inline .cname,
            .ns,
            .ptr,
            .mx,
            .txt,
            .soa,
            .srv,
            .dnskey,
            .sig,
            => |t| return decodeRData(std.meta.TagPayload(RData, t), t, allocator, size, buffered_reader),
            Type.a => {
                var data: [4]u8 = undefined;
                _ = try reader.read(&data);
                return RData{ .a = .{
                    .addr = std.net.Ip4Address.init(data, 0),
                } };
            },
            Type.aaaa => {
                var data: [16]u8 = undefined;
                _ = try reader.read(&data);
                return RData{ .aaaa = .{ .addr = std.net.Ip6Address.init(data, 0, 0, 0) } };
            },
            Type.ds => {
                const key_tag = try reader.readInt(u16, .big);
                const algorithm: DNSSEC.Algorithm = @enumFromInt(try reader.readByte());
                const digest_type: DNSSEC.DigestType = @enumFromInt(try reader.readByte());
                const digest_size: usize = switch (digest_type) {
                    .sha1 => 20,
                    .sha256, .gost3411 => 32,
                    .sha384 => 48,
                    .sha512 => 64,
                    .sha224 => 28,
                    else => return error.UnknownDigestType,
                };

                var digest = try ArrayList(u8).initCapacity(allocator, digest_size);
                errdefer digest.deinit();

                reader.readAllArrayList(&digest, digest_size) catch |err| switch (err) {
                    error.StreamTooLong => undefined,
                    else => return err,
                };

                return RData{ .ds = .{
                    .key_tag = key_tag,
                    .algorithm = algorithm,
                    .digest_type = digest_type,
                    .digest = digest,
                } };
            },
            else => {
                var array = try ArrayList(u8).initCapacity(allocator, size);
                errdefer array.deinit();
                reader.readUntilDelimiterArrayList(&array, 0xaa, size) catch |err| switch (err) {
                    error.EndOfStream => undefined,
                    error.StreamTooLong => undefined,
                    else => return err,
                };

                return RData{ .data = array };
            },
        }
    }

    pub fn encode(self: *RData, writer: std.io.AnyWriter) !usize {
        switch (self.*) {
            .a => |*a| {
                const bytes = @as([4]u8, @bitCast(a.addr.sa.addr));
                return try writer.write(&bytes);
            },
            .aaaa => |*aaaa| {
                const bytes = aaaa.addr.sa.addr;
                return try writer.write(&bytes);
            },
            .data => |data| return writer.write(data.items),
            inline else => |*case| return encodeRData(@TypeOf(case.*), case, writer),
        }
    }

    pub fn getLen(self: *RData) u16 {
        switch (self.*) {
            .a => return 4,
            .aaaa => return 16,
            .data => |*case| return @intCast(case.items.len),
            inline else => |*case| return getLenRData(@TypeOf(case.*), case),
        }
    }
};
