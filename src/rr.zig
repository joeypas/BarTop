const std = @import("std");
const RData = @import("rdata.zig").RData;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Owned DNS domain name stored as length-prefixed labels without the root terminator.
pub const Name = struct {
    wire: ArrayList(u8) = .empty,

    pub fn init() Name {
        return .{};
    }

    pub fn deinit(self: *Name, allocator: Allocator) void {
        self.wire.deinit(allocator);
        self.* = .{};
    }

    fn appendLabel(self: *Name, allocator: Allocator, label: []const u8) !void {
        if (label.len > 63) return error.BadName;
        try self.wire.append(allocator, @intCast(label.len));
        try self.wire.appendSlice(allocator, label);
    }

    pub fn addLabel(self: *Name, allocator: Allocator, label: []const u8) !void {
        try self.appendLabel(allocator, label);
    }

    pub fn getLen(self: *const Name) u16 {
        return @intCast(self.wire.items.len + 1);
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Name {
        return (try NameRef.decode(reader)).toOwned(allocator);
    }

    pub fn skip(reader: *Reader) !void {
        try NameRef.skip(reader);
    }

    pub fn encode(self: *const Name, writer: *Writer) !usize {
        const len = try writer.write(self.wire.items);
        try writer.writeByte(0x00);
        return len + 1;
    }

    pub fn copy(self: *Name, allocator: Allocator, other: *const Name) !void {
        try self.wire.appendSlice(allocator, other.wire.items);
    }

    pub fn clone(self: *const Name, allocator: Allocator) !Name {
        return .{ .wire = try self.wire.clone(allocator) };
    }

    pub fn print(self: *const Name, buf: []u8, @"type": ?Type) ![]u8 {
        var writer: std.Io.Writer = .fixed(buf);
        var it = self.iter();
        while (it.next()) |label| {
            _ = try writer.write(label);
            try writer.writeByte('.');
        }
        if (@"type") |t| {
            const bytes: [2]u8 = @bitCast(@intFromEnum(t));
            _ = try writer.write(&bytes);
        }
        return buf[0..writer.end];
    }

    pub fn allocPrint(self: *const Name, allocator: Allocator) ![]u8 {
        var ret: ArrayList(u8) = .empty;
        var it = self.iter();
        while (it.next()) |label| {
            try ret.appendSlice(allocator, label);
            try ret.append(allocator, '.');
        }
        return ret.toOwnedSlice(allocator);
    }

    pub fn format(self: Name, writer: *std.Io.Writer) !void {
        var it = self.iter();
        while (it.next()) |label| {
            try writer.print("{s}.", .{label});
        }
    }

    pub fn labelCount(self: *const Name) usize {
        var it = self.iter();
        var count: usize = 0;
        while (it.next()) |_| count += 1;
        return count;
    }

    pub fn removeFirstLabel(self: *Name) bool {
        if (self.wire.items.len == 0) return false;
        const label_len = @as(usize, self.wire.items[0]);
        const encoded_len = label_len + 1;
        if (encoded_len > self.wire.items.len) return false;

        const remaining_len = self.wire.items.len - encoded_len;
        std.mem.copyForwards(u8, self.wire.items[0..remaining_len], self.wire.items[encoded_len..]);
        self.wire.items = self.wire.items[0..remaining_len];
        return true;
    }

    pub fn equalsIgnoreCase(a: *const Name, b: *const Name) bool {
        var ia = a.iter();
        var ib = b.iter();
        while (true) {
            const al = ia.next();
            const bl = ib.next();
            if (al == null or bl == null) return al == null and bl == null;
            if (al.?.len != bl.?.len) return false;
            if (!std.ascii.eqlIgnoreCase(al.?, bl.?)) return false;
        }
    }

    pub fn ensureOwned(_: *Name, _: Allocator) !void {}

    fn iter(self: *const Name) LabelIterator {
        return LabelIterator.init(self.wire.items, 0, false);
    }

    pub fn parse(self: *Name, allocator: Allocator, name: []const u8) !void {
        var itr = std.mem.splitAny(u8, name, ". ");
        while (itr.next()) |part| {
            if (part.len == 0) continue;
            try self.appendLabel(allocator, part);
        }
    }

    pub fn initString(allocator: Allocator, name: []const u8) !Name {
        var ret = Name.init();
        errdefer ret.deinit(allocator);
        try ret.parse(allocator, name);
        return ret;
    }
};

/// Borrowed DNS name view into a packet. Safe only while `packet` remains alive.
pub const NameRef = struct {
    packet: []const u8,
    offset: usize,

    pub fn decode(reader: *Reader) !NameRef {
        const packet = reader.buffer[0..reader.end];
        const offset = reader.seek;
        try skip(reader);
        return .{ .packet = packet, .offset = offset };
    }

    pub fn skip(reader: *Reader) !void {
        const packet = reader.buffer[0..reader.end];
        reader.seek += try encodedNameLen(packet, reader.seek);
    }

    pub fn toOwned(self: NameRef, allocator: Allocator) !Name {
        var out = Name.init();
        errdefer out.deinit(allocator);
        var it = self.iter();
        while (it.next()) |label| try out.addLabel(allocator, label);
        return out;
    }

    pub fn encode(self: NameRef, writer: *Writer) !usize {
        var len: usize = 0;
        var it = self.iter();
        while (it.next()) |label| {
            try writer.writeByte(@intCast(label.len));
            len += 1;
            len += try writer.write(label);
        }
        try writer.writeByte(0x00);
        return len + 1;
    }

    pub fn print(self: NameRef, buf: []u8, @"type": ?Type) ![]u8 {
        var writer: std.Io.Writer = .fixed(buf);
        var it = self.iter();
        while (it.next()) |label| {
            _ = try writer.write(label);
            try writer.writeByte('.');
        }
        if (@"type") |t| {
            const bytes: [2]u8 = @bitCast(@intFromEnum(t));
            _ = try writer.write(&bytes);
        }
        return buf[0..writer.end];
    }

    pub fn allocPrint(self: NameRef, allocator: Allocator) ![]u8 {
        var ret: ArrayList(u8) = .empty;
        var it = self.iter();
        while (it.next()) |label| {
            try ret.appendSlice(allocator, label);
            try ret.append(allocator, '.');
        }
        return ret.toOwnedSlice(allocator);
    }

    pub fn format(self: NameRef, writer: *std.Io.Writer) !void {
        var it = self.iter();
        while (it.next()) |label| try writer.print("{s}.", .{label});
    }

    pub fn labelCount(self: NameRef) usize {
        var it = self.iter();
        var count: usize = 0;
        while (it.next()) |_| count += 1;
        return count;
    }

    fn iter(self: NameRef) LabelIterator {
        return LabelIterator.init(self.packet, self.offset, true);
    }
};

const LabelIterator = struct {
    buffer: []const u8,
    cursor: usize,
    allow_compression: bool,
    jumps: usize = 0,
    done: bool = false,

    fn init(buffer: []const u8, offset: usize, allow_compression: bool) LabelIterator {
        return .{ .buffer = buffer, .cursor = offset, .allow_compression = allow_compression };
    }

    fn next(self: *LabelIterator) ?[]const u8 {
        while (true) {
            if (self.done) return null;
            if (self.cursor >= self.buffer.len) return null;
            const len = self.buffer[self.cursor];
            if (len == 0) {
                self.done = true;
                return null;
            }
            if ((len & 0xC0) == 0xC0) {
                if (!self.allow_compression or self.cursor + 1 >= self.buffer.len) {
                    self.done = true;
                    return null;
                }
                const ptr = ((@as(usize, len & 0x3F)) << 8) | @as(usize, self.buffer[self.cursor + 1]);
                if (ptr >= self.buffer.len) {
                    self.done = true;
                    return null;
                }
                self.cursor = ptr;
                self.jumps += 1;
                if (self.jumps > self.buffer.len) {
                    self.done = true;
                    return null;
                }
                continue;
            }
            if ((len & 0xC0) != 0) {
                self.done = true;
                return null;
            }
            const label_len: usize = len;
            if (label_len > 63) {
                self.done = true;
                return null;
            }
            const start = self.cursor + 1;
            const end = start + label_len;
            if (end > self.buffer.len) {
                self.done = true;
                return null;
            }
            self.cursor = end;
            return self.buffer[start..end];
        }
    }
};

fn encodedNameLen(buffer: []const u8, offset: usize) !usize {
    if (offset >= buffer.len) return error.EndOfStream;
    var cursor = offset;
    while (true) {
        if (cursor >= buffer.len) return error.EndOfStream;
        const len = buffer[cursor];
        if (len == 0) return cursor - offset + 1;
        if ((len & 0xC0) == 0xC0) {
            if (cursor + 1 >= buffer.len) return error.EndOfStream;
            const ptr = ((@as(usize, len & 0x3F)) << 8) | @as(usize, buffer[cursor + 1]);
            if (ptr >= buffer.len) return error.EndOfStream;
            return cursor - offset + 2;
        }
        if ((len & 0xC0) != 0) return error.BadRData;
        const label_len: usize = len;
        if (label_len > 63) return error.BadRData;
        cursor += 1;
        if (cursor + label_len > buffer.len) return error.EndOfStream;
        cursor += label_len;
    }
}

pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    sig = 24,
    aaaa = 28,
    srv = 33,
    naptr = 35,
    dname = 39,
    opt = 41,
    ds = 43,
    sshfp = 44,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    nsec3param = 51,
    tlsa = 52,
    cds = 59,
    cdnskey = 60,
    svcb = 64,
    https = 65,
    //ixfr = 251,
    //axfr = 252,
    //any = 255,
    caa = 257,
    data = 65535,
    _,
};

pub const Class = enum(u16) {
    in = 1,
    cs = 2,
    ch = 3,
    hs = 4,
    any = 255,
    _,
};

pub const Question = struct {
    qname: Name,
    qtype: Type = .a,
    qclass: Class = .in,
    ref: bool = false,

    pub fn init() Question {
        return Question{
            .qname = Name.init(),
        };
    }

    pub fn deinit(self: *Question, allocator: Allocator) void {
        if (!self.ref) self.qname.deinit(allocator);
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Question {
        return Question{
            .qname = try Name.decode(allocator, reader),
            .qtype = @enumFromInt(try reader.takeInt(u16, .big)),
            .qclass = @enumFromInt(try reader.takeInt(u16, .big)),
        };
    }

    pub fn skip(reader: *Reader) !void {
        try Name.skip(reader);
        _ = try reader.takeInt(u16, .big);
        _ = try reader.takeInt(u16, .big);
    }

    pub fn encode(self: *Question, writer: *Writer) !usize {
        var len: usize = 0;
        len += try self.qname.encode(writer);
        try writer.writeInt(u16, @intFromEnum(self.qtype), .big);
        len += 2;
        try writer.writeInt(u16, @intFromEnum(self.qclass), .big);
        len += 2;

        return len;
    }

    pub fn clone(self: *const Question, allocator: Allocator) !Question {
        return Question{
            .qname = try self.qname.clone(allocator),
            .qtype = self.qtype,
            .qclass = self.qclass,
        };
    }

    pub fn print(self: *Question, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Question: [
            \\  qname: {f},
            \\  qtype: {any},
            \\  qclass: {any},
            \\],
        ,
            .{ self.qname, self.qtype, self.qclass },
        );
    }

    pub fn format(self: Question, writer: *std.Io.Writer) !void {
        try writer.print(
            "{f}\t\t{any}\t{any}",
            .{ self.qname, self.qclass, self.qtype },
        );
    }
};

pub const QuestionRef = struct {
    qname: NameRef,
    qtype: Type = .a,
    qclass: Class = .in,

    pub fn decode(reader: *Reader) !QuestionRef {
        return .{
            .qname = try NameRef.decode(reader),
            .qtype = @enumFromInt(try reader.takeInt(u16, .big)),
            .qclass = @enumFromInt(try reader.takeInt(u16, .big)),
        };
    }

    pub fn toOwned(self: QuestionRef, allocator: Allocator) !Question {
        return .{
            .qname = try self.qname.toOwned(allocator),
            .qtype = self.qtype,
            .qclass = self.qclass,
        };
    }

    pub fn deinit(_: *QuestionRef, _: Allocator) void {}

    pub fn encode(self: *QuestionRef, writer: *Writer) !usize {
        var len: usize = 0;
        len += try self.qname.encode(writer);
        try writer.writeInt(u16, @intFromEnum(self.qtype), .big);
        len += 2;
        try writer.writeInt(u16, @intFromEnum(self.qclass), .big);
        len += 2;
        return len;
    }

    pub fn print(self: *QuestionRef, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Question: [
            \\  qname: {f},
            \\  qtype: {any},
            \\  qclass: {any},
            \\],
        ,
            .{ self.qname, self.qtype, self.qclass },
        );
    }

    pub fn format(self: QuestionRef, writer: *std.Io.Writer) !void {
        try writer.print(
            "{f}\t\t{any}\t{any}",
            .{ self.qname, self.qclass, self.qtype },
        );
    }
};

pub const Record = struct {
    name: Name,
    type: Type = .a,
    class: Class = .in,
    ttl: u32 = 0,
    rdlength: u16 = 4,
    rdata: RData,
    ref: bool = false,

    pub fn init(@"type": Type) Record {
        return Record{
            .name = Name.init(),
            .rdata = RData.init(@"type"),
            .type = @"type",
            .rdlength = 0,
        };
    }

    pub fn deinit(self: *Record, allocator: Allocator) void {
        if (!self.ref) {
            self.name.deinit(allocator);
            self.rdata.deinit(allocator);
        }
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Record {
        return (try RecordRef.decode(reader)).toOwned(allocator);
    }

    pub fn skip(reader: *Reader) !void {
        try Name.skip(reader);
        _ = try reader.takeInt(u16, .big);
        _ = try reader.takeInt(u16, .big);
        _ = try reader.takeInt(u32, .big);
        const rdlength = try reader.takeInt(u16, .big);
        const end = reader.seek + @as(usize, rdlength);
        if (end > reader.end) return error.EndOfStream;
        reader.seek = end;
    }

    pub fn encode(self: *Record, writer: *Writer) !usize {
        var len: usize = 0;

        len += try self.name.encode(writer);
        try writer.writeInt(u16, @intFromEnum(self.type), .big);
        len += 2;
        try writer.writeInt(u16, @intFromEnum(self.class), .big);
        len += 2;
        try writer.writeInt(u32, self.ttl, .big);
        len += 4;
        try writer.writeInt(u16, @intCast(self.rdata.getLen()), .big);
        len += 2;
        len += try self.rdata.encode(writer);

        return len;
    }

    pub fn print(self: *Record, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Record: [
            \\  name: {},
            \\  type: {any},
            \\  class: {any},
            \\  ttl: {d},
            \\  rdlength: {d},
            \\  rdata: {},
            \\],
        ,
            .{ self.name, self.type, self.class, self.ttl, self.rdlength, self.rdata },
        );
    }

    pub fn format(self: Record, writer: *std.Io.Writer) !void {
        try writer.print(
            "{f}\t{d}\t{any}\t{any}\t{f}",
            .{ self.name, self.ttl, self.class, self.type, self.rdata },
        );
    }

    pub fn clone(self: *const Record, allocator: Allocator) !Record {
        var name = try self.name.clone(allocator);
        errdefer name.deinit(allocator);
        const rdata = try self.rdata.clone(allocator);
        return Record{
            .name = name,
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            .rdlength = self.rdlength,
            .rdata = rdata,
        };
    }

    pub fn setRData(self: *Record, allocator: Allocator, rdata: *const RData) !void {
        const next = try rdata.clone(allocator);
        self.rdata.deinit(allocator);
        self.rdata = next;
        self.rdlength = @intCast(self.rdata.wireLen());
    }
};

pub const RDataRef = struct {
    packet: []const u8,
    offset: usize,
    size: usize,
    type: Type,

    pub fn toOwned(self: RDataRef, allocator: Allocator) !RData {
        var reader = Reader.fixed(self.packet);
        reader.seek = self.offset;
        var parsed = try RData.decode(allocator, self.type, self.size, &reader);
        errdefer parsed.deinit(allocator);
        try parsed.ensureOwned(allocator);
        return parsed;
    }

    pub fn encode(self: RDataRef, writer: *Writer) !usize {
        return writer.write(self.packet[self.offset..][0..self.size]);
    }

    pub fn format(self: RDataRef, writer: *std.Io.Writer) !void {
        try writer.print("<{any} rdata {d} bytes>", .{ self.type, self.size });
    }
};

pub const RecordRef = struct {
    name: NameRef,
    type: Type = .a,
    class: Class = .in,
    ttl: u32 = 0,
    rdlength: u16 = 0,
    rdata: RDataRef,

    pub fn decode(reader: *Reader) !RecordRef {
        const packet = reader.buffer[0..reader.end];
        const name = try NameRef.decode(reader);
        const type_: Type = @enumFromInt(try reader.takeInt(u16, .big));
        const class: Class = @enumFromInt(try reader.takeInt(u16, .big));
        const ttl = try reader.takeInt(u32, .big);
        const rdlength = try reader.takeInt(u16, .big);
        const rdata_offset = reader.seek;
        const end = rdata_offset + @as(usize, rdlength);
        if (end > reader.end) return error.EndOfStream;
        reader.seek = end;
        return .{
            .name = name,
            .type = type_,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = .{
                .packet = packet,
                .offset = rdata_offset,
                .size = rdlength,
                .type = type_,
            },
        };
    }

    pub fn toOwned(self: RecordRef, allocator: Allocator) !Record {
        var name = try self.name.toOwned(allocator);
        errdefer name.deinit(allocator);
        const raw = try self.rdata.toOwned(allocator);
        return .{
            .name = name,
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            .rdlength = self.rdlength,
            .rdata = raw,
        };
    }

    pub fn deinit(_: *RecordRef, _: Allocator) void {}

    pub fn encode(self: *RecordRef, writer: *Writer) !usize {
        var len: usize = 0;
        len += try self.name.encode(writer);
        try writer.writeInt(u16, @intFromEnum(self.type), .big);
        len += 2;
        try writer.writeInt(u16, @intFromEnum(self.class), .big);
        len += 2;
        try writer.writeInt(u32, self.ttl, .big);
        len += 4;
        try writer.writeInt(u16, self.rdlength, .big);
        len += 2;
        len += try self.rdata.encode(writer);
        return len;
    }

    pub fn print(self: *RecordRef, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Record: [
            \\  name: {},
            \\  type: {any},
            \\  class: {any},
            \\  ttl: {d},
            \\  rdlength: {d},
            \\  rdata: {},
            \\],
        ,
            .{ self.name, self.type, self.class, self.ttl, self.rdlength, self.rdata },
        );
    }

    pub fn format(self: RecordRef, writer: *std.Io.Writer) !void {
        try writer.print(
            "{f}\t{d}\t{any}\t{any}\t{f}",
            .{ self.name, self.ttl, self.class, self.type, self.rdata },
        );
    }
};
