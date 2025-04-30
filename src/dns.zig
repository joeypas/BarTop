const std = @import("std");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;

const Reader = std.io.BufferedReader(4096, std.io.AnyReader);
const Writer = std.io.BufferedWriter(4096, std.io.AnyWriter);

pub const Message = struct {
    allocator: Allocator,
    header: Header,
    questions: ArrayList(Question),
    answers: ArrayList(Record),
    authorities: ArrayList(Record),
    additionals: ArrayList(Record),
    ref: bool = false,

    pub fn init(allocator: Allocator) Message {
        return .{
            .allocator = allocator,
            .header = .{},
            .questions = ArrayList(Question).init(allocator),
            .answers = ArrayList(Record).init(allocator),
            .authorities = ArrayList(Record).init(allocator),
            .additionals = ArrayList(Record).init(allocator),
        };
    }

    pub fn deinit(self: *Message) void {
        if (!self.ref) {
            for (self.questions.items) |*question| {
                question.deinit();
            }
        }
        self.questions.deinit();

        if (!self.ref) {
            for (self.answers.items) |*answer| {
                answer.deinit();
            }
        }
        self.answers.deinit();

        if (!self.ref) {
            for (self.authorities.items) |*answer| {
                answer.deinit();
            }
        }
        self.authorities.deinit();

        if (!self.ref) {
            for (self.additionals.items) |*answer| {
                answer.deinit();
            }
        }
        self.additionals.deinit();
    }

    pub fn decode(allocator: Allocator, reader: std.io.AnyReader) !Message {
        var buf_reader = std.io.bufferedReader(reader);

        const header = try Header.decode(&buf_reader);
        var questions = ArrayList(Question).init(allocator);

        for (0..header.qd_count) |_| {
            const question = try questions.addOne();
            question.* = try Question.decode(allocator, &buf_reader);
        }

        var answers = ArrayList(Record).init(allocator);

        for (0..header.an_count) |_| {
            const answer = try answers.addOne();
            answer.* = try Record.decode(allocator, &buf_reader);
        }

        var authorities = ArrayList(Record).init(allocator);

        for (0..header.ns_count) |_| {
            const authority = try authorities.addOne();
            authority.* = try Record.decode(allocator, &buf_reader);
        }

        var additionals = ArrayList(Record).init(allocator);

        for (0..header.ar_count) |_| {
            const additional = try additionals.addOne();
            additional.* = try Record.decode(allocator, &buf_reader);
        }

        return Message{
            .allocator = allocator,
            .header = header,
            .questions = questions,
            .answers = answers,
            .authorities = authorities,
            .additionals = additionals,
        };
    }

    pub fn encode(self: *Message, writer: std.io.AnyWriter) !usize {
        var c_writer = std.io.countingWriter(writer);

        _ = try self.header.encode(c_writer.writer().any());

        for (self.questions.items) |*question| {
            _ = try question.encode(c_writer.writer().any());
        }

        for (self.answers.items) |*answer| {
            _ = try answer.encode(c_writer.writer().any());
        }

        for (self.authorities.items) |*authority| {
            _ = try authority.encode(c_writer.writer().any());
        }

        for (self.additionals.items) |*additional| {
            _ = try additional.encode(c_writer.writer().any());
        }

        return c_writer.bytes_written;
    }

    pub fn addQuestion(self: *Message) !*Question {
        const q = try self.questions.addOne();
        q.* = Question.init(self.allocator);
        return q;
    }

    pub fn addAnswer(self: *Message, rtype: RDataType) !*Record {
        const a = try self.answers.addOne();
        a.* = Record.init(self.allocator, rtype);
        return a;
    }

    pub fn addAuthority(self: *Message, rtype: RDataType) !*Record {
        const a = try self.answers.addOne();
        a.* = Record.init(self.allocator, rtype);
        return a;
    }

    pub fn addAdditional(self: *Message, rtype: RDataType) !*Record {
        const a = try self.answers.addOne();
        a.* = Record.init(self.allocator, rtype);
        return a;
    }

    pub fn allocPrint(self: *Message, allocator: Allocator) ![]u8 {
        var array = ArrayList(u8).init(allocator);
        errdefer array.deinit();

        var header_buf: [512]u8 = undefined;
        try array.appendSlice(try self.header.print(&header_buf));

        for (self.questions.items) |*question| {
            var question_buf: [1024]u8 = undefined;
            try array.appendSlice(try question.print(&question_buf));
        }

        for (self.answers.items) |*record| {
            var record_buf: [1024]u8 = undefined;
            try array.appendSlice(try record.print(&record_buf));
        }

        for (self.authorities.items) |*record| {
            var record_buf: [1024]u8 = undefined;
            try array.appendSlice(try record.print(&record_buf));
        }

        for (self.additionals.items) |*record| {
            var record_buf: [1024]u8 = undefined;
            try array.appendSlice(try record.print(&record_buf));
        }

        return array.toOwnedSlice();
    }
};

// bitcast to go from struct to int
pub const Flags = packed struct {
    response_code: enum(u4) {
        no_error,
        format_error,
        server_failure,
        name_error,
        not_implemented,
        refused,
        _,
    } = .no_error,
    check_disable: bool = false,
    authenticated: bool = false,
    z: u1 = 0,
    recursion_available: bool = false,
    recursion_desired: bool = false,
    truncated: bool = false,
    authoritative: bool = false,
    op_code: enum(u4) {
        query,
        iquery,
        status,
        _,
    } = .query,
    response: bool = false,
};

pub const Header = packed struct {
    id: u16 = 0,
    flags: Flags = .{},
    qd_count: u16 = 0,
    an_count: u16 = 0,
    ns_count: u16 = 0,
    ar_count: u16 = 0,

    pub fn decode(buffered_reader: *Reader) !Header {
        var reader = buffered_reader.reader();
        return Header{
            .id = try reader.readInt(u16, .big),
            .flags = @bitCast(try reader.readInt(u16, .big)),
            .qd_count = try reader.readInt(u16, .big),
            .an_count = try reader.readInt(u16, .big),
            .ns_count = try reader.readInt(u16, .big),
            .ar_count = try reader.readInt(u16, .big),
        };
    }

    pub fn encode(self: *Header, writer: std.io.AnyWriter) !usize {
        try writer.writeInt(u16, self.id, .big);
        try writer.writeInt(u16, @bitCast(self.flags), .big);
        try writer.writeInt(u16, self.qd_count, .big);
        try writer.writeInt(u16, self.an_count, .big);
        try writer.writeInt(u16, self.ns_count, .big);
        try writer.writeInt(u16, self.ar_count, .big);
        return 12;
    }

    pub fn print(self: *Header, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Header: [
            \\  id: {d},
            \\  flags: {any},
            \\  qd_count: {d},
            \\  an_count: {d},
            \\  ns_count: {d},
            \\  ar_count: {d},
            \\],
        ,
            .{ self.id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count },
        );
    }
};

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

    pub fn fromString(self: *Name, name: []const u8) !void {
        var itr = std.mem.splitScalar(u8, name, '.');

        while (itr.next()) |part| {
            var array = try ArrayList(u8).initCapacity(self.allocator, part.len);
            errdefer array.deinit();
            array.appendSliceAssumeCapacity(part);
            try self.labels.append(array);
        }
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
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    ixfr = 251,
    axfr = 252,
    any = 255,
    caa = 257,
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
        var name_buf: [255]u8 = undefined;
        return std.fmt.bufPrint(
            buf,
            \\Question: [
            \\  qname: {s},
            \\  qtype: {any},
            \\  qclass: {any},
            \\],
        ,
            .{ try self.qname.print(&name_buf, null), self.qtype, self.qclass },
        );
    }
};

pub const RDataType = enum {
    cname,
    ns,
    ptr,
    mx,
    txt,
    soa,
    a,
    aaaa,
    data,
};

pub const RData = union(RDataType) {
    cname: Name,
    ns: Name,
    ptr: Name,
    mx: struct {
        preface: u16,
        exchange: Name,
    },
    txt: Name,
    soa: struct {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    a: struct {
        addr: std.net.Ip4Address = undefined,
    },
    aaaa: struct {
        addr: std.net.Ip6Address = undefined,
    },
    data: ArrayList(u8),

    pub fn clone(self: *RData) !RData {
        switch (self.*) {
            .cname => |*case| return RData{ .cname = try case.clone() },
            .ns => |*case| return RData{ .ns = try case.clone() },
            .ptr => |*case| return RData{ .ptr = try case.clone() },
            .mx => |*case| return RData{ .mx = .{
                .preface = case.preface,
                .exchange = try case.exchange.clone(),
            } },
            .txt => |*case| return RData{ .txt = try case.clone() },
            .soa => |*case| return RData{ .soa = .{
                .mname = try case.mname.clone(),
                .rname = try case.rname.clone(),
                .serial = case.serial,
                .refresh = case.refresh,
                .retry = case.retry,
                .expire = case.expire,
                .minimum = case.minimum,
            } },
            .a => |*case| return RData{ .a = .{ .addr = case.addr } },
            .aaaa => |*case| return RData{ .aaaa = .{ .addr = case.addr } },
            .data => |*case| return RData{ .data = try case.clone() },
        }
    }

    pub fn init(allocator: Allocator, rtype: RDataType) RData {
        return switch (rtype) {
            .cname => RData{ .cname = Name.init(allocator) },
            .ns => RData{ .ns = Name.init(allocator) },
            .ptr => RData{ .ptr = Name.init(allocator) },
            .mx => RData{ .mx = .{
                .preface = 0,
                .exchange = Name.init(allocator),
            } },
            .txt => RData{ .txt = Name.init(allocator) },
            .soa => RData{ .soa = .{
                .mname = Name.init(allocator),
                .rname = Name.init(allocator),
                .serial = 0,
                .refresh = 0,
                .retry = 0,
                .expire = 0,
                .minimum = 0,
            } },
            .a => RData{ .a = .{} },
            .aaaa => RData{ .aaaa = .{} },
            .data => RData{ .data = ArrayList(u8).init(allocator) },
        };
    }

    pub fn deinit(self: *RData) void {
        switch (self.*) {
            .cname => |*case| case.deinit(),
            .ns => |*case| case.deinit(),
            .ptr => |*case| case.deinit(),
            .mx => |*case| case.exchange.deinit(),
            .txt => |*case| case.deinit(),
            .soa => |*case| {
                case.mname.deinit();
                case.rname.deinit();
            },
            .data => |*case| case.deinit(),
            else => return,
        }
    }

    pub fn decode(allocator: Allocator, @"type": Type, size: usize, buffered_reader: *Reader) !RData {
        var reader = buffered_reader.reader();
        switch (@"type") {
            Type.cname => return RData{ .cname = try Name.decode(allocator, buffered_reader) },
            Type.ns => return RData{ .ns = try Name.decode(allocator, buffered_reader) },
            Type.ptr => return RData{ .ptr = try Name.decode(allocator, buffered_reader) },
            Type.mx => return RData{ .mx = .{
                .preface = try reader.readInt(u16, .big),
                .exchange = try Name.decode(allocator, buffered_reader),
            } },
            Type.txt => return RData{ .txt = try Name.decode(allocator, buffered_reader) },
            Type.soa => return RData{ .soa = .{
                .mname = try Name.decode(allocator, buffered_reader),
                .rname = try Name.decode(allocator, buffered_reader),
                .serial = try reader.readInt(u32, .big),
                .refresh = try reader.readInt(u32, .big),
                .retry = try reader.readInt(u32, .big),
                .expire = try reader.readInt(u32, .big),
                .minimum = try reader.readInt(u32, .big),
            } },
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
            else => {
                var array = try ArrayList(u8).initCapacity(allocator, size);
                errdefer array.deinit();
                const data = array.addManyAsSliceAssumeCapacity(size);

                _ = try reader.read(data);

                return RData{ .data = array };
            },
        }
    }

    pub fn encode(self: *RData, writer: std.io.AnyWriter) !usize {
        var len: usize = 0;
        switch (self.*) {
            .cname => |*cname| return cname.encode(writer),
            .ns => |*ns| return ns.encode(writer),
            .ptr => |*ptr| return ptr.encode(writer),
            .mx => |*mx| {
                try writer.writeInt(u16, mx.preface, .big);
                len += 2;
                len += try mx.exchange.encode(writer);
                return len;
            },
            .txt => |*txt| return txt.encode(writer),
            .soa => |*soa| {
                len += try soa.mname.encode(writer);
                len += try soa.rname.encode(writer);

                try writer.writeInt(u32, soa.serial, .big);
                len += 4;

                try writer.writeInt(u32, soa.refresh, .big);
                len += 4;

                try writer.writeInt(u32, soa.retry, .big);
                len += 4;

                try writer.writeInt(u32, soa.expire, .big);
                len += 4;

                try writer.writeInt(u32, soa.minimum, .big);
                len += 4;
                return len;
            },
            .a => |*a| {
                const bytes = @as([4]u8, @bitCast(a.addr.sa.addr));
                return try writer.write(&bytes);
            },
            .aaaa => |*aaaa| {
                const bytes = aaaa.addr.sa.addr;
                return try writer.write(&bytes);
            },
            .data => |data| return writer.write(data.items),
        }
    }

    pub fn getLen(self: *RData) u16 {
        var len: u16 = 0;

        switch (self.*) {
            .cname => |*case| return case.getLen(),
            .ns => |*case| return case.getLen(),
            .ptr => |*case| return case.getLen(),
            .mx => |*case| {
                len += 2;
                len += case.exchange.getLen();
                return len;
            },
            .txt => |*case| return case.getLen(),
            .soa => |*case| {
                len += case.mname.getLen();
                len += case.rname.getLen();
                return len + 20;
            },
            .a => return 4,
            .aaaa => return 16,
            .data => |*case| return @intCast(case.items.len),
        }
    }
};

pub const RType = enum {
    answer,
    authority,
    additional,
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

    pub fn init(allocator: Allocator, @"type": RDataType) Record {
        return Record{
            .allocator = allocator,
            .name = Name.init(allocator),
            .rdata = RData.init(allocator, @"type"),
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
        var name_buf: [255]u8 = undefined;
        return std.fmt.bufPrint(
            buf,
            \\Record: [
            \\  name: {s},
            \\  type: {any},
            \\  class: {any},
            \\  ttl: {d},
            \\  rdlength: {d},
            \\  rdata: {any},
            \\],
        ,
            .{ try self.name.print(&name_buf, null), self.type, self.class, self.ttl, self.rdlength, self.rdata },
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var message = Message.init(allocator);

    message.header.flags.recursion_desired = true;
    message.header.flags.recursion_available = true;
    message.header.qd_count = 1;
    message.header.ns_count = 1;

    var q = try message.addQuestion();
    q.qclass = .in;
    q.qtype = .ns;
    try q.qname.fromString("www.google.com");

    var a = try message.addAuthority(.ns);
    try a.name.fromString("google.com");

    a.type = .ns;
    a.ttl = 30;
    a.rdlength = 12;
    try a.rdata.ns.fromString("ns2.google.com");

    std.debug.print("{any}\n", .{message});

    var data: [1232]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&data);
    const len = try message.encode(fbs.writer().any());
    std.debug.print("{d}\n {x}\n", .{ len, data[0..len] });

    message.deinit();

    var fbr = std.io.fixedBufferStream(data[0..len]);
    var ret = try Message.decode(allocator, fbr.reader().any());
    defer ret.deinit();

    const question = try ret.allocPrint(allocator);
    defer allocator.free(question);

    std.debug.print("{s}\n", .{question});
}
