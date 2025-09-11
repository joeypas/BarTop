const std = @import("std");
const RData = @import("rdata.zig").RData;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Represents a Domain Name
pub const Name = struct {
    allocator: Allocator,
    labels: ArrayList(ArrayList(u8)),

    pub fn init(allocator: Allocator) Name {
        return .{
            .allocator = allocator,
            .labels = .empty,
        };
    }

    pub fn deinit(self: *Name, allocator: Allocator) void {
        for (self.labels.items) |*label| {
            label.deinit(allocator);
        }

        self.labels.deinit(allocator);
    }

    pub fn addLabel(self: *Name, label: []const u8) !void {
        var array = try ArrayList(u8).initCapacity(self.allocator, label.len);
        errdefer array.deinit(self.allocator);
        array.appendSliceAssumeCapacity(label);
        try self.labels.append(self.allocator, array);
    }

    pub fn getLen(self: *Name) u16 {
        var len: u16 = 0;

        for (self.labels.items) |item| {
            len += 1;
            len += @intCast(item.items.len);
        }

        len += 1;

        return len;
    }

    fn checkPointer(allocator: Allocator, labels: *ArrayList(ArrayList(u8)), reader: *Reader) !bool {
        if (reader.end - reader.seek >= 2) {
            const buf = try reader.peek(2);
            const pointer = buf[0];
            if (pointer >= 0xC0) {
                const ptr = try reader.takeInt(u16, .big);
                const offset = @as(usize, ptr & 0x3FFF);
                var fbs = std.Io.Reader.fixed(reader.buffer[0..]);
                fbs.seek = offset;
                var size = try fbs.takeByte();
                while (size != 0x00) {
                    var writer = try Writer.Allocating.initCapacity(allocator, @intCast(size));
                    errdefer writer.deinit();
                    try fbs.streamExact(&writer.writer, @intCast(size));
                    try labels.append(allocator, writer.toArrayList());
                    // Edge case where a pointer points to another pointer
                    if (try checkPointer(allocator, labels, &fbs)) break;
                    size = try fbs.takeByte();
                }
                return true;
            }
            return false;
        }
        return false;
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Name {
        var labels: ArrayList(ArrayList(u8)) = .empty;

        if (try checkPointer(allocator, &labels, reader)) {
            return Name{
                .allocator = allocator,
                .labels = labels,
            };
        }

        var size = try reader.takeByte();

        while (size != 0) {
            var array = try Writer.Allocating.initCapacity(allocator, @intCast(size));
            try reader.streamExact(&array.writer, @intCast(size));
            try labels.append(allocator, array.toArrayList());
            if (try checkPointer(allocator, &labels, reader)) break;
            size = try reader.takeByte();
        }

        return Name{
            .allocator = allocator,
            .labels = labels,
        };
    }

    pub fn encode(self: *Name, writer: *Writer) !usize {
        var len: usize = 0;
        for (self.labels.items) |label| {
            try writer.writeByte(@truncate(label.items.len));
            len += 1;
            len += try writer.write(label.items);
        }

        try writer.writeByte(0x00);
        len += 1;

        return len;
    }

    pub fn copy(self: *Name, other: *Name) !void {
        for (other.labels.items) |*item| {
            try self.labels.append(self.allocator, try item.clone());
        }
    }

    pub fn clone(self: *Name) !Name {
        var ret = Name.init(self.allocator);
        try ret.copy(self);
        return ret;
    }

    pub fn print(self: *Name, buf: []u8, @"type": ?Type) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        var size: usize = 0;
        var writer = fbs.writer();

        for (self.labels.items) |*item| {
            size += try writer.write(item.items);
            try writer.writeByte('.');
            size += 1;
        }

        if (@"type") |t| {
            size += try writer.write(&@as([2]u8, @bitCast(@intFromEnum(t))));
        }

        return buf[0..size];
    }

    pub fn allocPrint(self: *Name, allocator: Allocator) ![]u8 {
        var ret: ArrayList(u8) = .empty;
        for (self.labels.items) |*item| {
            try ret.appendSlice(allocator, item.items);
            try ret.append(allocator, '.');
        }

        return ret.toOwnedSlice(allocator);
    }

    pub fn format(self: Name, writer: *std.io.Writer) !void {
        for (self.labels.items) |item| {
            try writer.print("{s}.", .{item.items});
        }
    }

    /// Given a string representation of a Domain Name, split into labels and add to internal list
    pub fn parse(self: *Name, name: []const u8) !void {
        var itr = std.mem.splitAny(u8, name, ". ");

        while (itr.next()) |part| {
            if (part.len == 0) continue;
            var array = try ArrayList(u8).initCapacity(self.allocator, name.len);
            errdefer array.deinit(self.allocator);
            const slice = array.addManyAsSliceAssumeCapacity(part.len);
            @memcpy(slice[0..], part);
            try self.labels.append(self.allocator, array);
        }
    }

    pub fn initString(allocator: Allocator, name: []const u8) !Name {
        var ret = Name.init(allocator);
        errdefer ret.deinit();
        try ret.parse(name);
        return ret;
    }
};

pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    //opt = 41,
    rrsig = 46,
    //nsec = 47,
    dnskey = 48,
    ds = 43,
    sig = 24,
    nsec3 = 50,
    //ixfr = 251,
    //axfr = 252,
    //any = 255,
    //caa = 257,
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
    allocator: Allocator,
    qname: Name,
    qtype: Type = .a,
    qclass: Class = .in,
    ref: bool = false,

    pub fn init(allocator: Allocator) Question {
        return Question{
            .allocator = allocator,
            .qname = Name.init(allocator),
        };
    }

    pub fn deinit(self: *Question, allocator: Allocator) void {
        if (!self.ref) self.qname.deinit(allocator);
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Question {
        return Question{
            .allocator = allocator,
            .qname = Name.decode(allocator, reader) catch unreachable,
            .qtype = @enumFromInt(try reader.takeInt(u16, .big)),
            .qclass = @enumFromInt(try reader.takeInt(u16, .big)),
        };
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

    pub fn clone(self: *Question) !Question {
        return Question{
            .allocator = self.allocator,
            .qname = try self.qname.clone(),
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

    pub fn format(self: Question, writer: *std.io.Writer) !void {
        try writer.print(
            \\Question: [
            \\  qname: {f},
            \\  qtype: {any},
            \\  qclass: {any},
            \\],
        ,
            .{ self.qname, self.qtype, self.qclass },
        );
    }
};

pub const Record = struct {
    allocator: Allocator,
    name: Name,
    type: Type = .a,
    class: Class = .in,
    ttl: u32 = 0,
    rdlength: u16 = 4,
    rdata: RData,
    ref: bool = false,

    pub fn init(allocator: Allocator, @"type": Type) Record {
        return Record{
            .allocator = allocator,
            .name = Name.init(allocator),
            .rdata = RData.init(allocator, @"type"),
            .type = @"type",
        };
    }

    pub fn deinit(self: *Record, allocator: Allocator) void {
        if (!self.ref) {
            self.name.deinit(allocator);
            self.rdata.deinit(allocator);
        }
    }

    pub fn decode(allocator: Allocator, reader: *Reader) !Record {
        const name = try Name.decode(allocator, reader);
        const type_: Type = @enumFromInt(try reader.takeInt(u16, .big));
        const class: Class = @enumFromInt(try reader.takeInt(u16, .big));
        const ttl = try reader.takeInt(u32, .big);
        var rdlength = try reader.takeInt(u16, .big);

        var rdata = try RData.decode(allocator, type_, @intCast(rdlength), reader);

        rdlength = rdata.getLen();

        return Record{
            .allocator = allocator,
            .name = name,
            .type = type_,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = rdata,
        };
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
        try writer.writeInt(u16, self.rdlength, .big);
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

    pub fn format(self: Record, writer: *std.io.Writer) !void {
        try writer.print(
            \\Record: [
            \\  name: {f},
            \\  type: {any},
            \\  class: {any},
            \\  ttl: {d},
            \\  rdlength: {d},
            \\  rdata: {f},
            \\],
        ,
            .{ self.name, self.type, self.class, self.ttl, self.rdlength, self.rdata },
        );
    }

    pub fn clone(self: *Record) !Record {
        return Record{
            .allocator = self.allocator,
            .name = try self.name.clone(),
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            .rdlength = self.rdlength,
            .rdata = try self.rdata.clone(),
        };
    }
};
