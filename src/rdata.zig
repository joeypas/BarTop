const std = @import("std");
const rr = @import("rr.zig");
const DNSSEC = @import("dnssec.zig");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Name = rr.Name;
const Type = rr.Type;
const Bytes = DNSSEC.Bytes;

const SvcParam = struct {
    key: u16,
    value: []const u8,
};

const SvcParamBlock = union(enum) {
    borrowed: []const u8,
    owned: ArrayList(u8),
};

const SvcParamIterator = struct {
    block: []const u8,
    offset: usize = 0,

    fn init(block: []const u8) SvcParamIterator {
        return .{ .block = block };
    }

    fn next(self: *SvcParamIterator) !?SvcParam {
        if (self.offset == self.block.len) return null;
        const remaining = self.block.len - self.offset;
        if (remaining < 4) return error.BadRData;

        const key = std.mem.readInt(u16, self.block[self.offset..][0..2], .big);
        const value_len = std.mem.readInt(u16, self.block[self.offset + 2 ..][0..2], .big);
        const value_start = self.offset + 4;
        const value_end = value_start + value_len;
        if (value_end > self.block.len) return error.BadRData;

        self.offset = value_end;
        return .{
            .key = key,
            .value = self.block[value_start..value_end],
        };
    }
};

const Svcb = struct {
    priority: u16,
    target: Name,
    params_block: SvcParamBlock,

    pub fn init() Svcb {
        return .{
            .priority = 0,
            .target = Name.init(),
            .params_block = .{ .owned = .empty },
        };
    }

    pub fn deinit(self: *Svcb, allocator: Allocator) void {
        self.target.deinit(allocator);
        switch (self.params_block) {
            .borrowed => {},
            .owned => |*list| list.deinit(allocator),
        }
        self.params_block = .{ .owned = .empty };
    }

    pub fn clone(self: *const Svcb, allocator: Allocator) !Svcb {
        var out = Svcb.init();
        out.priority = self.priority;
        out.target = try self.target.clone(allocator);

        switch (self.params_block) {
            .borrowed => |bytes| {
                var copied = try ArrayList(u8).initCapacity(allocator, bytes.len);
                copied.appendSliceAssumeCapacity(bytes);
                out.params_block = .{ .owned = copied };
            },
            .owned => |*list| {
                out.params_block = .{ .owned = try list.clone(allocator) };
            },
        }
        return out;
    }

    pub fn ensureOwned(self: *Svcb, allocator: Allocator) !void {
        try self.target.ensureOwned(allocator);
        switch (self.params_block) {
            .owned => return,
            .borrowed => |bytes| {
                var out = try ArrayList(u8).initCapacity(allocator, bytes.len);
                out.appendSliceAssumeCapacity(bytes);
                self.params_block = .{ .owned = out };
            },
        }
    }

    fn paramsBytes(self: *const Svcb) []const u8 {
        return switch (self.params_block) {
            .borrowed => |bytes| bytes,
            .owned => |list| list.items,
        };
    }

    fn paramsIterator(self: *const Svcb) SvcParamIterator {
        return SvcParamIterator.init(self.paramsBytes());
    }
};

fn decodeSvcb(allocator: Allocator, size: usize, reader: *Reader) !Svcb {
    const start_seek = reader.seek;
    var out = Svcb.init();

    out.priority = try reader.takeInt(u16, .big);
    out.target = try Name.decode(allocator, reader);

    const used = reader.seek - start_seek;
    if (used > size) return error.EndOfStream;

    const params_len = size - used;
    const params_start = reader.seek;
    const params_end = params_start + params_len;
    if (params_end > reader.end) return error.EndOfStream;
    reader.seek = params_end;

    const params = reader.buffer[params_start..params_end];
    try validateSvcParamBlock(params);
    out.params_block = .{ .borrowed = params };
    return out;
}

fn validateSvcParamBlock(block: []const u8) !void {
    var it = SvcParamIterator.init(block);
    while (try it.next()) |param| {
        try validateSvcParam(param.key, param.value);
    }
}

fn validateSvcParam(key: u16, value: []const u8) !void {
    switch (key) {
        0 => { // mandatory
            if (value.len % 2 != 0) return error.BadRData;
        },
        1 => { // alpn
            var i: usize = 0;
            while (i < value.len) {
                const l = value[i];
                i += 1;
                if (i + l > value.len) return error.BadRData;
                i += l;
            }
        },
        2 => { // no-default-alpn
            if (value.len != 0) return error.BadRData;
        },
        3 => { // port
            if (value.len != 2) return error.BadRData;
        },
        4 => { // ipv4hint
            if (value.len % 4 != 0) return error.BadRData;
        },
        5 => { // echconfig
        },
        6 => { // ipv6hint
            if (value.len % 16 != 0) return error.BadRData;
        },
        7 => { // dohpath
        },
        else => {},
    }
}

fn encodeSvcb(data: *Svcb, writer: *Writer) !usize {
    var len: usize = 0;
    try writer.writeInt(u16, data.priority, .big);
    len += 2;
    len += try data.target.encode(writer);
    const param_bytes = data.paramsBytes();
    len += try writer.write(param_bytes);
    return len;
}

fn getLenSvcb(data: *Svcb) u16 {
    return @intCast(2 + data.target.getLen() + data.paramsBytes().len);
}

fn takeBytes(reader: *Reader, size: usize) ![]const u8 {
    const start = reader.seek;
    const end = start + size;
    if (end > reader.end) return error.EndOfStream;
    reader.seek = end;
    return reader.buffer[start..end];
}

fn decodeDnsKey(size: usize, reader: *Reader) !RData {
    if (size < 4) return error.EndOfStream;
    const flags = try reader.takeInt(u16, .big);
    const protocol: DNSSEC.KeyProtocol = @enumFromInt(try reader.takeByte());
    const algorithm: DNSSEC.Algorithm = @enumFromInt(try reader.takeByte());
    const public_key = try takeBytes(reader, size - 4);
    return RData{ .dnskey = .{
        .flags = flags,
        .protocol = protocol,
        .algorithm = algorithm,
        .public_key = Bytes.fromBorrowed(public_key),
    } };
}

fn decodeDs(size: usize, reader: *Reader) !RData {
    if (size < 4) return error.EndOfStream;
    const key_tag = try reader.takeInt(u16, .big);
    const algorithm: DNSSEC.Algorithm = @enumFromInt(try reader.takeByte());
    const digest_type: DNSSEC.DigestType = @enumFromInt(try reader.takeByte());
    const digest_len: usize = switch (digest_type) {
        .sha1 => 20,
        .sha256, .gost3411 => 32,
        .sha384 => 48,
        .sha512 => 64,
        .sha224 => 28,
        else => return error.UnknownDigestType,
    };
    if (size != digest_len + 4) return error.BadRData;

    const digest = try takeBytes(reader, digest_len);
    return RData{ .ds = .{
        .key_tag = key_tag,
        .algorithm = algorithm,
        .digest_type = digest_type,
        .digest = Bytes.fromBorrowed(digest),
    } };
}

fn decodeSig(allocator: Allocator, comptime tag: Type, size: usize, reader: *Reader) !RData {
    const start = reader.seek;

    var sig = DNSSEC.Sig{
        .type_covered = @enumFromInt(try reader.takeInt(u16, .big)),
        .algorithm = @enumFromInt(try reader.takeByte()),
        .label_count = try reader.takeByte(),
        .original_ttl = try reader.takeInt(u32, .big),
        .expiration = try reader.takeInt(i64, .big),
        .inception = try reader.takeInt(i64, .big),
        .key_tag = try reader.takeInt(u16, .big),
        .signers_name = try Name.decode(allocator, reader),
        .signature = Bytes.init(),
    };

    const consumed = reader.seek - start;
    if (consumed > size) return error.EndOfStream;
    sig.signature = Bytes.fromBorrowed(try takeBytes(reader, size - consumed));
    return @unionInit(RData, @tagName(tag), sig);
}

fn decodeNsec3(size: usize, reader: *Reader) !RData {
    const start = reader.seek;

    const hash_algorithm: DNSSEC.NSEC3HashAlgorithm = @enumFromInt(try reader.takeByte());
    const flags = try reader.takeByte();
    const iterations = try reader.takeInt(u16, .big);
    const salt_len = try reader.takeByte();
    const salt = try takeBytes(reader, salt_len);
    const hash_len = try reader.takeByte();
    const hash = try takeBytes(reader, hash_len);

    const consumed = reader.seek - start;
    if (consumed > size) return error.EndOfStream;
    const type_bitmap = try takeBytes(reader, size - consumed);

    return RData{ .nsec3 = .{
        .hash_algorithm = hash_algorithm,
        .flags = flags,
        .iterations = iterations,
        .salt_len = salt_len,
        .salt = Bytes.fromBorrowed(salt),
        .hash_len = hash_len,
        .hash = Bytes.fromBorrowed(hash),
        .type_bitmap = Bytes.fromBorrowed(type_bitmap),
    } };
}

fn initRData(T: type, comptime tag: Type) RData {
    var ret: T = undefined;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.meta.hasFn(field.type, "init")) {
                    @field(ret, field.name) = field.type.init();
                } else if (@typeInfo(field.type) == .int) {
                    @field(ret, field.name) = 0;
                }
            }
            return @unionInit(RData, @tagName(tag), ret);
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn deinitRData(comptime T: type, data: *T, allocator: Allocator) void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.meta.hasFn(field.type, "deinit")) {
                    @field(data, field.name).deinit(allocator);
                }
            }
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn decodeRData(T: type, comptime tag: Type, allocator: Allocator, size: usize, reader: *Reader) !RData {
    _ = size;
    var ret: T = undefined;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.mem.startsWith(u8, field.name, "_")) {} else if (field.type == Name) {
                    @field(ret, field.name) = try Name.decode(allocator, reader);
                } else if (std.meta.hasFn(field.type, "decode")) {
                    @field(ret, field.name) = try field.type.decode(reader);
                } else if (@typeInfo(field.type) == .int) {
                    @field(ret, field.name) = try reader.takeInt(field.type, .big);
                } else if (@typeInfo(field.type) == .@"enum") {
                    @field(ret, field.name) = @enumFromInt(try reader.takeInt(@typeInfo(field.type).@"enum".tag_type, .big));
                }
            }
            return @unionInit(RData, @tagName(tag), ret);
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn encodeRData(comptime T: type, data: *T, writer: *Writer) !usize {
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
                } else if (@typeInfo(field.type) == .@"enum") {
                    len += @typeInfo(@typeInfo(field.type).@"enum".tag_type).int.bits / 8;
                }
            }
            return len;
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn cloneRData(comptime T: type, comptime tag: Type, data: *const T, allocator: Allocator) !RData {
    var ret: T = undefined;
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                const src = @field(data, field.name);
                if (std.meta.hasFn(field.type, "clone")) {
                    const clone_fn = @TypeOf(field.type.clone);
                    const params = @typeInfo(clone_fn).@"fn".params;
                    if (params.len == 2) {
                        @field(ret, field.name) = try src.clone(allocator);
                    } else {
                        @field(ret, field.name) = try src.clone();
                    }
                } else {
                    @field(ret, field.name) = src;
                }
            }
            return @unionInit(RData, @tagName(tag), ret);
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn ensureOwnedRData(comptime T: type, data: *T, allocator: Allocator) !void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.meta.hasFn(field.type, "ensureOwned")) {
                    _ = try @field(data, field.name).ensureOwned(allocator);
                }
            }
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

fn rdataFromString(comptime T: type, self: *T, allocator: Allocator, data: []const u8) !void {
    var tokens = std.mem.tokenizeAny(u8, data, " \t");
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                if (std.mem.startsWith(u8, field.name, "_")) {} else if (std.meta.hasFn(field.type, "parse")) {
                    const parse_fn = @TypeOf(field.type.parse);
                    const params = @typeInfo(parse_fn).@"fn".params;
                    const token = tokens.next() orelse return error.MissingData;
                    if (params.len == 3) {
                        try @field(self, field.name).parse(allocator, token);
                    } else {
                        try @field(self, field.name).parse(token);
                    }
                } else if (@typeInfo(field.type) == .int) {
                    @field(self, field.name) = try std.fmt.parseInt(field.type, tokens.next() orelse return error.MissingData, 10);
                } else if (@typeInfo(field.type) == .@"enum") {
                    @field(self, field.name) = @enumFromInt(try std.fmt.parseInt(@typeInfo(field.type).@"enum".tag_type, tokens.next() orelse return error.MissingData, 10));
                } else if (field.type == ArrayList(u8)) {
                    while (tokens.next()) |token| {
                        try @field(self, field.name).appendSlice(allocator, token);
                    }
                }
            }
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

pub fn formatRData(comptime T: type, data: T, writer: *std.Io.Writer) !void {
    switch (@typeInfo(T)) {
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                try writer.print("  ", .{});
                if (field.type == ArrayList(u8)) {
                    try writer.print("{s}", .{@field(data, field.name).items});
                } else if (@typeInfo(field.type) == .int) {
                    try writer.print("{d}", .{@field(data, field.name)});
                } else if (std.meta.hasFn(field.type, "format")) {
                    try writer.print("{f}", .{@field(data, field.name)});
                } else {
                    try writer.print("{any}", .{@field(data, field.name)});
                }
                try writer.print("\t", .{});
            }
        },
        else => @compileError("Expected struct, found '" ++ @typeName(T) ++ "'"),
    }
}

pub const RData = union(Type) {
    // TODO:
    // 1. Implement printing support
    // 2. Full rdata type support
    a: struct {
        addr: std.Io.net.Ip4Address = undefined,
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
        addr: std.Io.net.Ip6Address = undefined,
    },
    srv: struct {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    svcb: Svcb,
    https: Svcb,
    rrsig: DNSSEC.Sig,
    dnskey: DNSSEC.DnsKey,
    ds: DNSSEC.DS,
    sig: DNSSEC.Sig,
    nsec3: DNSSEC.NSEC3,
    data: Bytes,

    pub fn init(@"type": Type) RData {
        return switch (@"type") {
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
            .rrsig,
            .nsec3,
            => |t| return initRData(@FieldType(RData, @tagName(t)), t),
            .a => RData{ .a = .{} },
            .aaaa => RData{ .aaaa = .{} },
            .svcb => RData{ .svcb = Svcb.init() },
            .https => RData{ .https = Svcb.init() },
            else => RData{ .data = Bytes.init() },
        };
    }

    pub fn deinit(self: *RData, allocator: Allocator) void {
        switch (self.*) {
            .data => |*case| case.deinit(allocator),
            .svcb => |*case| case.deinit(allocator),
            .https => |*case| case.deinit(allocator),
            inline else => |*t| deinitRData(@TypeOf(t.*), t, allocator),
        }
    }

    pub fn clone(self: *const RData, allocator: Allocator) !RData {
        return switch (self.*) {
            .data => |*bytes| RData{ .data = try bytes.clone(allocator) },
            .a => |*a| RData{ .a = .{ .addr = a.addr } },
            .aaaa => |*a| RData{ .aaaa = .{ .addr = a.addr } },
            .cname => |*t| cloneRData(@TypeOf(t.*), .cname, t, allocator),
            .ns => |*t| cloneRData(@TypeOf(t.*), .ns, t, allocator),
            .ptr => |*t| cloneRData(@TypeOf(t.*), .ptr, t, allocator),
            .mx => |*t| cloneRData(@TypeOf(t.*), .mx, t, allocator),
            .txt => |*t| cloneRData(@TypeOf(t.*), .txt, t, allocator),
            .soa => |*t| cloneRData(@TypeOf(t.*), .soa, t, allocator),
            .srv => |*t| cloneRData(@TypeOf(t.*), .srv, t, allocator),
            .svcb => |*t| RData{ .svcb = try t.clone(allocator) },
            .https => |*t| RData{ .https = try t.clone(allocator) },
            .dnskey => |*t| cloneRData(@TypeOf(t.*), .dnskey, t, allocator),
            .ds => |*t| cloneRData(@TypeOf(t.*), .ds, t, allocator),
            .sig => |*t| cloneRData(@TypeOf(t.*), .sig, t, allocator),
            .nsec3 => |*t| cloneRData(@TypeOf(t.*), .nsec3, t, allocator),
            .rrsig => |*t| cloneRData(@TypeOf(t.*), .rrsig, t, allocator),
        };
    }

    pub fn ensureOwned(self: *RData, allocator: Allocator) !void {
        switch (self.*) {
            .a, .aaaa => return,
            .data => |*bytes| _ = try bytes.ensureOwned(allocator),
            .svcb => |*svcb| try svcb.ensureOwned(allocator),
            .https => |*https| try https.ensureOwned(allocator),
            inline else => |*case| try ensureOwnedRData(@TypeOf(case.*), case, allocator),
        }
    }

    pub fn decode(allocator: Allocator, @"type": Type, size: usize, reader: *Reader) !RData {
        switch (@"type") {
            inline .cname,
            .ns,
            .ptr,
            .mx,
            .txt,
            .soa,
            .srv,
            => |t| return decodeRData(@FieldType(RData, @tagName(t)), t, allocator, size, reader),
            Type.a => {
                const data = try reader.takeArray(4);
                return RData{ .a = .{
                    .addr = .{ .bytes = data.*, .port = 0 },
                } };
            },
            Type.aaaa => {
                const data = try reader.takeArray(16);
                return RData{ .aaaa = .{ .addr = .{ .bytes = data.*, .port = 0, .flow = 0, .interface = .none } } };
            },
            Type.svcb => {
                return RData{ .svcb = try decodeSvcb(allocator, size, reader) };
            },
            Type.https => {
                return RData{ .https = try decodeSvcb(allocator, size, reader) };
            },
            Type.dnskey => return decodeDnsKey(size, reader),
            Type.ds => return decodeDs(size, reader),
            Type.sig => return decodeSig(allocator, .sig, size, reader),
            Type.rrsig => return decodeSig(allocator, .rrsig, size, reader),
            Type.nsec3 => return decodeNsec3(size, reader),
            else => {
                return RData{ .data = Bytes.fromBorrowed(try takeBytes(reader, size)) };
            },
        }
    }

    pub fn encode(self: *RData, writer: *Writer) !usize {
        switch (self.*) {
            .a => |*a| {
                return try writer.write(a.addr.bytes[0..]);
            },
            .aaaa => |*aaaa| {
                return try writer.write(aaaa.addr.bytes[0..]);
            },
            .svcb => |*svcb| return encodeSvcb(svcb, writer),
            .https => |*https| return encodeSvcb(https, writer),
            .data => |*data| return data.encode(writer),
            inline else => |*case| return encodeRData(@TypeOf(case.*), case, writer),
        }
    }

    pub fn getLen(self: *RData) u16 {
        switch (self.*) {
            .a => return 4,
            .aaaa => return 16,
            .svcb => |*case| return getLenSvcb(case),
            .https => |*case| return getLenSvcb(case),
            .data => |*case| return case.getLen(),
            inline else => |*case| return getLenRData(@TypeOf(case.*), case),
        }
    }

    pub fn parse(self: *RData, allocator: Allocator, data: []const u8) !void {
        const dat = std.mem.trim(u8, data, " \t\n\r");
        return switch (self.*) {
            .a => |*a| a.addr = try std.Io.net.Ip4Address.parse(dat, 0),
            .aaaa => |*aaaa| aaaa.addr = try std.Io.net.Ip6Address.parse(dat, 0),
            .data => |*bytes| try bytes.appendSlice(allocator, dat),
            inline else => |*case| rdataFromString(@TypeOf(case.*), case, allocator, dat),
        };
    }

    pub fn format(self: RData, writer: *std.Io.Writer) !void {
        switch (self) {
            .data => |*case| try writer.print("{f}", .{case.*}),
            inline else => |*case| try formatRData(@TypeOf(case.*), case.*, writer),
        }
    }
};
