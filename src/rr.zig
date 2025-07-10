const std = @import("std");
const Reader = @import("message.zig").Reader;
const RData = @import("rdata.zig").RData;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

/// Represents a Domain Name
pub const Name = struct {
    allocator: Allocator,
    labels: ArrayList(ArrayList(u8)),

    pub fn init(allocator: Allocator) Name {
        return .{
            .allocator = allocator,
            .labels = ArrayList(ArrayList(u8)).init(allocator),
        };
    }

    pub fn deinit(self: *Name) void {
        for (self.labels.items) |label| {
            label.deinit();
        }

        self.labels.deinit();
    }

    pub fn addLabel(self: *Name, label: []const u8) !void {
        var array = try ArrayList(u8).initCapacity(self.allocator, label.len);
        errdefer array.deinit();
        array.appendSliceAssumeCapacity(label);
        try self.labels.append(array);
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

    fn checkPointer(allocator: Allocator, labels: *ArrayList(ArrayList(u8)), buffered_reader: *Reader) !bool {
        if (buffered_reader.end - buffered_reader.start >= 2) {
            const buf = buffered_reader.buf[buffered_reader.start .. buffered_reader.start + 2];
            const pointer = buf[0];
            if (pointer >= 0xC0) {
                const ptr = std.mem.readInt(u16, buf[0..2], .big);
                const offset = @as(usize, ptr & 0x3FFF);
                try buffered_reader.reader().skipBytes(2, .{});
                var fbs = std.io.fixedBufferStream(buffered_reader.buf[offset..]);
                var reader = fbs.reader();
                var size = try reader.readByte();
                while (size != 0x00) {
                    var array = try ArrayList(u8).initCapacity(allocator, @intCast(size));
                    const bytes = array.addManyAsSliceAssumeCapacity(@intCast(size));
                    _ = try reader.read(bytes);
                    try labels.append(array);
                    size = try reader.readByte();
                }
                return true;
            }
            return false;
        }
        return false;
    }

    pub fn decode(allocator: Allocator, buffered_reader: *Reader) !Name {
        var reader = buffered_reader.reader();

        var labels = ArrayList(ArrayList(u8)).init(allocator);

        if (try checkPointer(allocator, &labels, buffered_reader)) {
            return Name{
                .allocator = allocator,
                .labels = labels,
            };
        }

        var size = try reader.readByte();

        while (size != 0) {
            var array = try ArrayList(u8).initCapacity(allocator, @intCast(size));
            const bytes = array.addManyAsSliceAssumeCapacity(@intCast(size));
            _ = try reader.read(bytes);
            try labels.append(array);
            if (try checkPointer(allocator, &labels, buffered_reader)) break;
            size = try reader.readByte();
        }

        return Name{
            .allocator = allocator,
            .labels = labels,
        };
    }

    pub fn encode(self: *Name, writer: std.io.AnyWriter) !usize {
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
            try self.labels.append(try item.clone());
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
        var ret = ArrayList(u8).init(allocator);
        for (self.labels.items) |*item| {
            try ret.appendSlice(item.items);
            try ret.append('.');
        }

        return ret.toOwnedSlice();
    }

    pub fn format(self: Name, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        for (self.labels.items) |item| {
            try writer.print("{s}.", .{item.items});
        }
    }

    /// Given a string representation of a Domain Name, split into labels and add to internal list
    pub fn fromString(self: *Name, name: []const u8) !void {
        var itr = std.mem.splitAny(u8, name, ". ");

        while (itr.next()) |part| {
            if (part.len == 0) continue;
            var array = try ArrayList(u8).initCapacity(self.allocator, name.len);
            errdefer array.deinit();
            const slice = array.addManyAsSliceAssumeCapacity(part.len);
            @memcpy(slice[0..], part);
            try self.labels.append(array);
        }
    }

    pub fn initString(allocator: Allocator, name: []const u8) !Name {
        var ret = Name.init(allocator);
        errdefer ret.deinit();
        try ret.fromString(name);
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
    //rrsig = 46,
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

    pub fn deinit(self: *Question) void {
        if (!self.ref) self.qname.deinit();
    }

    pub fn decode(allocator: Allocator, buffered_reader: *Reader) !Question {
        return Question{
            .allocator = allocator,
            .qname = Name.decode(allocator, buffered_reader) catch unreachable,
            .qtype = @enumFromInt(try buffered_reader.reader().readInt(u16, .big)),
            .qclass = @enumFromInt(try buffered_reader.reader().readInt(u16, .big)),
        };
    }

    pub fn encode(self: *Question, writer: std.io.AnyWriter) !usize {
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
            \\  qname: {},
            \\  qtype: {any},
            \\  qclass: {any},
            \\],
        ,
            .{ self.qname, self.qtype, self.qclass },
        );
    }

    pub fn format(self: Question, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print(
            \\Question: [
            \\  qname: {},
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

    pub fn deinit(self: *Record) void {
        if (!self.ref) {
            self.name.deinit();
            self.rdata.deinit();
        }
    }

    pub fn decode(allocator: Allocator, buffered_reader: *Reader) !Record {
        var reader = buffered_reader.reader();
        const name = try Name.decode(allocator, buffered_reader);
        const type_: Type = @enumFromInt(try reader.readInt(u16, .big));
        const class: Class = @enumFromInt(try reader.readInt(u16, .big));
        const ttl = try reader.readInt(u32, .big);
        var rdlength = try reader.readInt(u16, .big);

        var rdata = try RData.decode(allocator, type_, @intCast(rdlength), buffered_reader);

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

    pub fn encode(self: *Record, writer: std.io.AnyWriter) !usize {
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

    pub fn format(self: Record, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print(
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
