const std = @import("std");
const RData = @import("rdata.zig").RData;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Represents a Domain Name
pub const Name = struct {
    const OwnedLabels = ArrayList(u8);
    const Storage = union(enum) {
        owned: OwnedLabels,
        borrowed: Borrowed,
    };
    const Borrowed = struct {
        buffer: []const u8 = &.{},
        offset: usize = 0,
    };

    storage: Storage = .{ .borrowed = .{} },

    pub fn init() Name {
        return .{
            .storage = .{ .owned = .empty },
        };
    }

    pub fn deinit(self: *Name, allocator: Allocator) void {
        switch (self.storage) {
            .owned => |*labels| {
                for (labels.items) |*label| {
                    label.deinit(allocator);
                }
                labels.deinit(allocator);
            },
            .borrowed => {},
        }
        self.storage = .{ .owned = .empty };
    }

    pub fn addLabel(self: *Name, allocator: Allocator, label: []const u8) !void {
        try self.ensureOwned(allocator);
        var array = try ArrayList(u8).initCapacity(allocator, label.len);
        errdefer array.deinit(allocator);
        array.appendSliceAssumeCapacity(label);
        try self.storage.owned.append(allocator, array);
    }

    pub fn getLen(self: *Name) u16 {
        var it = self.iter();
        var len: usize = 1; // root terminator
        while (it.next()) |label| {
            len += 1;
            len += label.len;
        }
        return @intCast(len);
    }

    pub fn decode(reader: *Reader) !Name {
        const base = reader.buffer[0..reader.end];
        const start = reader.seek;
        try skip(reader);
        return .{
            .storage = .{ .borrowed = .{
                .buffer = base,
                .offset = start,
            } },
        };
    }

    pub fn skip(reader: *Reader) !void {
        const base = reader.buffer[0..reader.end];
        const consumed = try encodedNameLen(base, reader.seek);
        reader.seek += consumed;
    }

    pub fn encode(self: *Name, writer: *Writer) !usize {
        var it = self.iter();
        var len: usize = 0;
        while (it.next()) |label| {
            try writer.writeByte(@intCast(label.len));
            len += 1;
            len += try writer.write(label);
        }
        try writer.writeByte(0x00);
        len += 1;
        return len;
    }

    pub fn copy(self: *Name, allocator: Allocator, other: *const Name) !void {
        try self.ensureOwned(allocator);
        var it = other.iter();
        while (it.next()) |label| {
            var out = try ArrayList(u8).initCapacity(allocator, label.len);
            errdefer out.deinit(allocator);
            out.appendSliceAssumeCapacity(label);
            try self.storage.owned.append(allocator, out);
        }
    }

    pub fn clone(self: *const Name, allocator: Allocator) !Name {
        var ret = Name.init();
        try ret.copy(allocator, self);
        return ret;
    }

    pub fn print(self: *Name, buf: []u8, @"type": ?Type) ![]u8 {
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

    pub fn allocPrint(self: *Name, allocator: Allocator) ![]u8 {
        var ret: ArrayList(u8) = .empty;
        var it = self.iter();
        while (it.next()) |label| {
            try ret.appendSlice(allocator, label);
            try ret.append(allocator, '.');
        }
        return ret.toOwnedSlice(allocator);
    }

    pub fn format(self: Name, writer: *std.Io.Writer) !void {
        var name_copy = self;
        var it = name_copy.iter();
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

    pub fn ensureOwned(self: *Name, allocator: Allocator) !void {
        switch (self.storage) {
            .owned => return,
            .borrowed => |borrowed| {
                var out: OwnedLabels = .empty;
                errdefer {
                    for (out.items) |*label| label.deinit(allocator);
                    out.deinit(allocator);
                }

                var it = Iterator.initBorrowed(borrowed.buffer, borrowed.offset);
                while (it.next()) |label| {
                    var label_copy = try ArrayList(u8).initCapacity(allocator, label.len);
                    errdefer label_copy.deinit(allocator);
                    label_copy.appendSliceAssumeCapacity(label);
                    try out.append(allocator, label_copy);
                }
                self.storage = .{ .owned = out };
            },
        }
    }

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

    fn iter(self: *const Name) Iterator {
        return switch (self.storage) {
            .owned => |labels| Iterator{ .owned = .{ .labels = labels.items } },
            .borrowed => |borrowed| Iterator.initBorrowed(borrowed.buffer, borrowed.offset),
        };
    }

    const Iterator = union(enum) {
        owned: struct {
            labels: []const ArrayList(u8),
            index: usize = 0,
        },
        borrowed: struct {
            buffer: []const u8,
            cursor: usize,
            jumps: usize = 0,
            done: bool = false,
        },

        fn initBorrowed(buffer: []const u8, offset: usize) Iterator {
            return .{ .borrowed = .{
                .buffer = buffer,
                .cursor = offset,
            } };
        }

        fn next(self: *Iterator) ?[]const u8 {
            return switch (self.*) {
                .owned => |*owned| blk: {
                    if (owned.index >= owned.labels.len) break :blk null;
                    defer owned.index += 1;
                    break :blk owned.labels[owned.index].items;
                },
                .borrowed => |*borrowed| blk: {
                    while (true) {
                        if (borrowed.done) break :blk null;
                        if (borrowed.cursor >= borrowed.buffer.len) break :blk null;
                        const len = borrowed.buffer[borrowed.cursor];
                        if (len == 0) {
                            borrowed.done = true;
                            break :blk null;
                        }
                        if ((len & 0xC0) == 0xC0) {
                            if (borrowed.cursor + 1 >= borrowed.buffer.len) {
                                borrowed.done = true;
                                break :blk null;
                            }
                            const ptr = ((@as(usize, len & 0x3F)) << 8) | @as(usize, borrowed.buffer[borrowed.cursor + 1]);
                            if (ptr >= borrowed.buffer.len) {
                                borrowed.done = true;
                                break :blk null;
                            }
                            borrowed.cursor = ptr;
                            borrowed.jumps += 1;
                            if (borrowed.jumps > borrowed.buffer.len) {
                                borrowed.done = true;
                                break :blk null;
                            }
                            continue;
                        }
                        if ((len & 0xC0) != 0) {
                            borrowed.done = true;
                            break :blk null;
                        }
                        const label_len: usize = len;
                        if (label_len > 63) {
                            borrowed.done = true;
                            break :blk null;
                        }
                        const start = borrowed.cursor + 1;
                        const end = start + label_len;
                        if (end > borrowed.buffer.len) {
                            borrowed.done = true;
                            break :blk null;
                        }
                        borrowed.cursor = end;
                        break :blk borrowed.buffer[start..end];
                    }
                },
            };
        }
    };

    /// Given a string representation of a Domain Name, split into labels and add to internal list
    pub fn parse(self: *Name, allocator: Allocator, name: []const u8) !void {
        try self.ensureOwned(allocator);
        var itr = std.mem.splitAny(u8, name, ". ");

        while (itr.next()) |part| {
            if (part.len == 0) continue;
            var array = try ArrayList(u8).initCapacity(allocator, name.len);
            errdefer array.deinit(allocator);
            const slice = array.addManyAsSliceAssumeCapacity(part.len);
            @memcpy(slice[0..], part);
            try self.storage.owned.append(allocator, array);
        }
    }

    pub fn initString(allocator: Allocator, name: []const u8) !Name {
        var ret = Name.init();
        errdefer ret.deinit(allocator);
        try ret.parse(allocator, name);
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
    svcb = 64,
    https = 65,
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

    pub fn decode(reader: *Reader) !Question {
        return Question{
            .qname = try Name.decode(reader),
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
        };
    }

    pub fn deinit(self: *Record, allocator: Allocator) void {
        if (!self.ref) {
            self.name.deinit(allocator);
            self.rdata.deinit(allocator);
        }
    }

    pub fn decode(reader: *Reader) !Record {
        const name = try Name.decode(reader);
        const type_: Type = @enumFromInt(try reader.takeInt(u16, .big));
        const class: Class = @enumFromInt(try reader.takeInt(u16, .big));
        const ttl = try reader.takeInt(u32, .big);
        var rdlength = try reader.takeInt(u16, .big);

        var rdata = try RData.decode(type_, @intCast(rdlength), reader);

        rdlength = rdata.getLen();

        return Record{
            .name = name,
            .type = type_,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = rdata,
        };
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

    pub fn format(self: Record, writer: *std.Io.Writer) !void {
        try writer.print(
            "{f}\t{d}\t{any}\t{any}\t{f}",
            .{ self.name, self.ttl, self.class, self.type, self.rdata },
        );
    }

    pub fn clone(self: *const Record, allocator: Allocator) !Record {
        return Record{
            .name = try self.name.clone(allocator),
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            .rdlength = self.rdlength,
            .rdata = try self.rdata.clone(allocator),
        };
    }
};
