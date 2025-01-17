const std = @import("std");
const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const assert = std.debug.assert;
const Reader = @import("reader.zig");
const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

pub const Name = ArrayListUnmanaged(ArrayListUnmanaged(u8));
pub const QList = ArrayList(Question);
pub const RList = ArrayList(Record);

pub const Message = struct {
    header: Header,
    questions: QList,
    answers: RList,
    authorities: RList,
    additionals: RList,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Message {
        return .{
            .header = std.mem.zeroInit(Header, .{}),
            .questions = ArrayList(Question).init(allocator),
            .answers = ArrayList(Record).init(allocator),
            .authorities = ArrayList(Record).init(allocator),
            .additionals = ArrayList(Record).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Message) void {
        for (self.questions.items) |*q| {
            q.*.deinit();
        }
        self.questions.deinit();
        for (self.answers.items) |*r| {
            r.*.deinit();
        }
        self.answers.deinit();
        for (self.authorities.items) |*r| {
            r.*.deinit();
        }
        self.authorities.deinit();
        for (self.additionals.items) |*r| {
            r.*.deinit();
        }
        self.additionals.deinit();
    }

    pub fn fromBytes(allocator: Allocator, data: []const u8) !Message {
        var parser = Parser.init(allocator, data);
        return try parser.read();
    }

    /// Serializes the entire DNS message into a byte array.
    pub fn bytesAlloc(self: *Message, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize header
        const header_bytes = try self.header.bytesAlloc(allocator);
        defer allocator.free(header_bytes);

        try builder.appendSlice(header_bytes);

        // Serialize questions
        for (self.questions.items) |*question| {
            const question_bytes = try question.bytesAlloc(allocator);
            defer allocator.free(question_bytes);
            try builder.appendSlice(question_bytes);
        }

        // Serialize answers
        for (self.answers.items) |*answer| {
            const answer_bytes = try answer.bytesAlloc(allocator);
            defer allocator.free(answer_bytes);
            try builder.appendSlice(answer_bytes);
        }

        // Serialize authorities
        for (self.authorities.items) |*authority| {
            const authority_bytes = try authority.bytesAlloc(allocator);
            defer allocator.free(authority_bytes);
            try builder.appendSlice(authority_bytes);
        }

        // Serialize additionals
        for (self.additionals.items) |*additional| {
            const additional_bytes = try additional.bytesAlloc(allocator);
            defer allocator.free(additional_bytes);
            try builder.appendSlice(additional_bytes);
        }

        return builder.toOwnedSlice();
    }

    pub fn bytes(self: *Message, buf: []u8) ![]u8 {
        var size: usize = 0;

        const header_bytes = try self.header.bytes(buf[0..]);
        size += header_bytes.len;

        for (self.questions.items) |*item| {
            const item_bytes = try item.*.bytes(buf[size..]);
            size += item_bytes.len;
        }

        for (self.answers.items) |*item| {
            const item_bytes = try item.*.bytes(buf[size..]);
            size += item_bytes.len;
        }

        for (self.authorities.items) |*item| {
            const item_bytes = try item.*.bytes(buf[size..]);
            size += item_bytes.len;
        }

        for (self.additionals.items) |*item| {
            const item_bytes = try item.*.bytes(buf[size..]);
            size += item_bytes.len;
        }

        return buf[0..size];
    }

    /// Initializes a Question and appends it to internal ArrayList
    /// returns pointer to new element
    pub fn addQuestion(self: *Message) !*Question {
        var question = try self.questions.addOne();
        question.allocator = self.allocator;
        question.qname = try Name.initCapacity(self.allocator, 0);
        return question;
    }

    /// Initializes an Answer Record and appends it to internal ArrayList
    /// returns pointer to new element
    pub fn addAnswer(self: *Message) !*Record {
        var answer = try self.answers.addOne();
        answer.allocator = self.allocator;
        answer.name = try Name.initCapacity(self.allocator, 0);
        //answer.rdata = ArrayList(u8).init(self.allocator);
        return answer;
    }

    /// Initializes an Authority Record and appends it to internal ArrayList
    /// returns pointer to new element
    pub fn addAuthority(self: *Message) !*Record {
        var authority = try self.authorities.addOne();
        authority.allocator = self.allocator;
        authority.name = try Name.initCapacity(self.allocator, 0);
        //authority.rdata = ArrayList(u8).init(self.allocator);
        return authority;
    }

    /// Initializes an Additional Record and appends it to internal ArrayList
    /// returns pointer to new element
    pub fn addAdditional(self: *Message) !*Record {
        var additional = try self.additionals.addOne();
        additional.allocator = self.allocator;
        additional.name = try Name.initCapacity(self.allocator, 0);
        //additional.rdata = ArrayList(u8).init(self.allocator);
        return additional;
    }

    pub fn copyFromOther(self: *Message, other: Message) !void {
        for (other.questions.items) |*item| {
            try self.questions.append(try item.clone());
        }
        for (other.answers.items) |*item| {
            try self.answers.append(try item.clone());
        }
        for (other.authorities.items) |*item| {
            try self.authorities.append(try item.clone());
        }
        for (other.additionals.items) |*item| {
            try self.additionals.append(try item.clone());
        }
    }
};

pub const Header = packed struct(u96) {
    id: u16,
    flags: Flags,
    qcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub const Opcode = enum(u4) {
        query,
        inverse_query,
        status_request,
        _,
    };

    pub const ResponseCode = enum(u4) {
        no_error,
        format_error,
        server_failure,
        name_error,
        not_implemented,
        refused,
        _,
    };

    pub const Flags = packed struct(u16) {
        qr: bool,
        opcode: Opcode,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        z: u3 = 3,
        rcode: ResponseCode,

        pub fn toU16(self: Flags) u16 {
            return (@as(u16, @intFromBool(self.qr)) << 15) |
                (@as(u16, @intFromEnum(self.opcode)) << 11) |
                (@as(u16, @intFromBool(self.aa)) << 10) |
                (@as(u16, @intFromBool(self.tc)) << 9) |
                (@as(u16, @intFromBool(self.rd)) << 8) |
                (@as(u16, @intFromBool(self.ra)) << 7) |
                (@as(u16, self.z) << 4) |
                (@as(u16, @intFromEnum(self.rcode)));
        }

        // This is pretty messy but I want to use my deserializer
        pub fn getFlags(f: u16) Flags {
            return Flags{
                .qr = bigToNative(u8, @intCast((f & 0x8000) >> 15)) != 0,
                .opcode = @enumFromInt(@as(u4, @truncate(bigToNative(u8, @intCast((f & 0x8000) >> 15))))),
                .aa = bigToNative(u8, @intCast((f & 0x0400) >> 10)) != 0,
                .tc = bigToNative(u8, @intCast((f & 0x0200) >> 9)) != 0,
                .rd = bigToNative(u8, @intCast((f & 0x0100) >> 8)) != 0,
                .ra = bigToNative(u8, @intCast((f & 0x0080) >> 7)) != 0,
                .z = 0,
                .rcode = @enumFromInt(@as(u4, @truncate(bigToNative(u8, @intCast(f & 0x000F))))),
            };
        }
    };

    /// Convert a Header to bytes in big endian order
    pub fn bytesAlloc(self: *Header, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize 'id' field
        const id_be = u16ToBeBytes(self.id);
        try builder.appendSlice(&id_be);

        // Serialize 'flags' field
        const flags_be = u16ToBeBytes(self.flags.toU16());
        try builder.appendSlice(&flags_be);

        // Serialize 'qcount', 'ancount', 'nscount', 'arcount' fields
        const qcount_be = u16ToBeBytes(self.qcount);
        try builder.appendSlice(&qcount_be);

        const ancount_be = u16ToBeBytes(self.ancount);
        try builder.appendSlice(&ancount_be);

        const nscount_be = u16ToBeBytes(self.nscount);
        try builder.appendSlice(&nscount_be);

        const arcount_be = u16ToBeBytes(self.arcount);
        try builder.appendSlice(&arcount_be);

        return builder.toOwnedSlice();
    }
    pub fn bytes(self: *Header, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        var size: usize = 0;
        var writer = fbs.writer();

        const id_be = u16ToBeBytes(self.id);
        size += try writer.write(&id_be);

        const flags_be = u16ToBeBytes(self.flags.toU16());
        size += try writer.write(&flags_be);

        const qcount_be = u16ToBeBytes(self.qcount);
        size += try writer.write(&qcount_be);

        const ancount_be = u16ToBeBytes(self.ancount);
        size += try writer.write(&ancount_be);

        const nscount_be = u16ToBeBytes(self.nscount);
        size += try writer.write(&nscount_be);

        const arcount_be = u16ToBeBytes(self.arcount);
        size += try writer.write(&arcount_be);

        return buf[0..size];
    }
};

pub const Question = struct {
    qname: Name = .{},
    qtype: QType,
    qclass: QClass,
    allocator: Allocator,

    pub const QType = enum(u16) {
        a = 1,
        ns = 2,
        md = 3,
        mf = 4,
        cname = 5,
        soa = 6,
        mb = 7,
        mg = 8,
        mr = 9,
        null = 10,
        wks = 11,
        ptr = 12,
        hinfo = 13,
        minfo = 14,
        mx = 15,
        txt = 16,
        axfr = 252,
        mailb = 253,
        maila = 254,
        any = 255,
        _,
    };

    pub const QClass = enum(u16) {
        in = 1,
        cs = 2,
        ch = 3,
        hs = 4,
        any = 255,
        _,
    };

    pub fn deinit(self: *Question) void {
        for (self.qname.items) |*part| {
            part.deinit(self.allocator);
        }
        self.qname.deinit(self.allocator);
    }

    /// Convert a Question to bytes in big endian order
    pub fn bytesAlloc(self: *Question, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize qname (domain name)
        for (self.qname.items) |label| {
            if (label.items.len > 256) {
                break;
            }
            try builder.append(@as(u8, @intCast(label.items.len)));
            try builder.appendSlice(label.items);
        }
        // Terminate qname with a zero-length label
        try builder.append(0);

        // Serialize qtype and qclass in big-endian order
        const qtype_be = u16ToBeBytes(@intFromEnum(self.qtype));
        try builder.appendSlice(&qtype_be);

        const qclass_be = u16ToBeBytes(@intFromEnum(self.qclass));
        try builder.appendSlice(&qclass_be);

        return builder.toOwnedSlice();
    }

    pub fn bytes(self: *Question, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        var size: usize = 0;
        var writer = fbs.writer();
        for (self.qname.items) |*label| {
            try writer.writeByte(@as(u8, @intCast(label.items.len)));
            size += 1;
            size += try writer.write(label.items);
        }
        try writer.writeByte(0);
        size += 1;

        const type_be = u16ToBeBytes(@intFromEnum(self.qtype));
        size += try writer.write(&type_be);

        const class_be = u16ToBeBytes(@intFromEnum(self.qclass));
        size += try writer.write(&class_be);

        return buf[0..size];
    }

    pub fn qnameAppendSlice(self: *Question, slice: []const u8) !void {
        const list = try self.qname.addOne(self.allocator);
        list.* = .{};
        try list.appendSlice(self.allocator, slice);
    }

    pub fn qnameAppendSlice2D(self: *Question, slice: [][]const u8) !void {
        for (slice) |part| {
            // Because of the way that a record is deinitialized, a record must own memory
            // of the slices contained in name to avoid an invalid free,
            // and the easiest way to do this is by copying the slice
            const list = try self.qname.addOne(self.allocator);
            list.* = .{};
            try list.appendSlice(self.allocator, part);
        }
    }

    pub fn qnameCloneOther(self: *Question, other: Name) !void {
        for (other.items) |*item| {
            //try self.qname.append(try item.clone());
            const tmp = try self.qname.addOne(self.allocator);
            tmp.* = try item.clone(self.allocator);
        }
    }

    pub fn qnameToStringAlloc(self: *Question, allocator: Allocator) ![]const u8 {
        var tmp = ArrayList(u8).init(allocator);
        for (self.qname.items) |item| {
            try tmp.appendSlice(item.items);
            try tmp.append('.');
        }

        return tmp.toOwnedSlice();
    }

    pub fn qnameToString(self: *Question, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        var size: usize = 0;
        var writer = fbs.writer();

        for (self.qname.items) |*item| {
            size += try writer.write(item.items);
            try writer.writeByte('.');
            size += 1;
        }
        return buffer[0..size];
    }

    pub fn clone(self: *Question) !Question {
        var question = Question{
            .qname = Name.init(self.allocator),
            .qtype = self.qtype,
            .qclass = self.qclass,
            .allocator = self.allocator,
        };
        try question.qnameCloneOther(self.qname);
        return question;
    }
};

pub const Record = struct {
    name: Name,
    type: Type,
    class: Class,
    ttl: u32,
    rdlength: u16,
    rdata: ArrayListUnmanaged(u8) = .{},
    allocator: Allocator,

    pub const Type = enum(u16) {
        a = 1,
        ns,
        md,
        mf,
        cname,
        soa,
        mb,
        mg,
        mr,
        null,
        wks,
        ptr,
        hinfo,
        minfo,
        mx,
        txt,
        _,
    };

    pub const Class = enum(u16) {
        in = 1,
        cs,
        ch,
        hs,
        _,
    };

    pub fn deinit(self: *Record) void {
        for (self.name.items) |*part| {
            part.deinit(self.allocator);
        }
        self.name.deinit(self.allocator);
        self.rdata.deinit(self.allocator);
    }

    /// Convert a Record to bytes in big endian order
    pub fn bytesAlloc(self: *Record, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize name (domain name)
        for (self.name.items) |label| {
            try builder.append(@as(u8, @intCast(label.items.len)));
            try builder.appendSlice(label.items);
        }

        // Terminate name with a zero-length label
        try builder.append(0);

        // Serialize type, class, ttl, and rdlength in big-endian order
        const type_be = u16ToBeBytes(@intFromEnum(self.type));
        try builder.appendSlice(&type_be);

        const class_be = u16ToBeBytes(@intFromEnum(self.class));
        try builder.appendSlice(&class_be);

        const ttl_be = u32ToBeBytes(self.ttl);
        try builder.appendSlice(&ttl_be);

        const rdlength_be = u16ToBeBytes(self.rdlength);
        try builder.appendSlice(&rdlength_be);

        // Append rdata
        try builder.appendSlice(self.rdata.items);

        return builder.toOwnedSlice();
    }

    pub fn bytes(self: *Record, buf: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buf);
        var size: usize = 0;
        var writer = fbs.writer();
        for (self.name.items) |*label| {
            try writer.writeByte(@as(u8, @intCast(label.items.len)));
            size += 1;
            size += try writer.write(label.items);
        }
        try writer.writeByte(0);
        size += 1;

        const type_be = u16ToBeBytes(@intFromEnum(self.type));
        size += try writer.write(&type_be);

        const class_be = u16ToBeBytes(@intFromEnum(self.class));
        size += try writer.write(&class_be);

        const ttl_be = u32ToBeBytes(self.ttl);
        size += try writer.write(&ttl_be);

        const rdlength_be = u16ToBeBytes(self.rdlength);
        size += try writer.write(&rdlength_be);

        size += try writer.write(self.rdata.items);

        return buf[0..size];
    }

    pub fn nameAppendSlice(self: *Record, slice: []const u8) !void {
        const list = try self.name.addOne(self.allocator);
        list.* = try std.ArrayListUnmanaged(u8).initCapacity(self.allocator, 0);
        try list.appendSlice(self.allocator, slice);
    }

    pub fn nameAppendSlice2D(self: *Record, slice: [][]const u8) !void {
        for (slice) |part| {
            // Because of the way that a record is deinitialized, a record must own memory
            // of the slices contained in name to avoid an invalid free,
            // and the easiest way to do this is by copying the slice
            const list = try self.name.addOne(self.allocator);
            list.* = try ArrayListUnmanaged(u8).initCapacity(self.allocator, 0);
            try list.appendSlice(self.allocator, part);
        }
    }

    pub fn nameCloneOther(self: *Record, other: Name) !void {
        for (other.items) |*item| {
            const tmp = try self.name.addOne(self.allocator);
            tmp.* = try item.clone(self.allocator);
        }
    }

    pub fn rdataAppendSlice(self: *Record, slice: []const u8) !void {
        self.rdata = try ArrayListUnmanaged(u8).initCapacity(self.allocator, 0);
        try self.rdata.appendSlice(self.allocator, slice);
        //self.rdata.shrinkAndFree(slice.len);
    }

    pub fn rdataCloneOther(self: *Record, other: ArrayListUnmanaged(u8)) !void {
        self.rdata.deinit(self.allocator);
        self.rdata = try other.clone(self.allocator);
    }

    pub fn nameToStringAlloc(self: *Record, allocator: Allocator) ![]const u8 {
        var tmp = ArrayList(u8).init(allocator);
        for (self.name.items) |item| {
            try tmp.appendSlice(item.items);
            try tmp.append('.');
        }

        return tmp.toOwnedSlice();
    }

    pub fn clone(self: *Record) !Record {
        var record = Record{
            .name = Name.init(self.allocator),
            .type = self.type,
            .class = self.class,
            .ttl = self.ttl,
            .rdlength = self.rdlength,
            .rdata = try self.rdata.clone(),
            .allocator = self.allocator,
        };
        try record.nameCloneOther(self.name);
        return record;
    }
};

/// A DNS packet deserializer.
/// Memory is only allocated with a call to read
const Parser = struct {
    reader: Reader,
    alloc: Allocator,

    /// Does not need to be deinitialized
    pub fn init(alloc: Allocator, data: []const u8) Parser {
        return .{
            .reader = Reader.init(data),
            .alloc = alloc,
        };
    }

    // TODO: Properly Handle Errors/When to return null

    /// Parse `Message` from string of bytes `data`
    /// Resulting Message needs to be deinitialized
    pub fn read(self: *Parser) !Message {
        var message = Message.init(self.alloc);
        errdefer message.deinit();

        // Parse the packet header
        message.header = try self.readHeader();

        if (message.header.qcount > 0) {
            for (0..@as(usize, message.header.qcount)) |i| {
                _ = i;
                const question = try message.addQuestion();
                try self.readQuestion(question);
            }
        }
        if (message.header.ancount > 0) {
            for (0..@as(usize, message.header.ancount)) |i| {
                _ = i;
                const ans = try message.addAnswer();
                try self.readRecord(ans);
            }
        }
        if (message.header.nscount > 0) {
            for (0..@as(usize, message.header.nscount)) |i| {
                _ = i;
                const ns = try message.addAuthority();
                try self.readRecord(ns);
            }
        }
        if (message.header.arcount > 0) {
            for (0..@as(usize, message.header.arcount)) |i| {
                _ = i;
                const ar = try message.addAdditional();
                try self.readRecord(ar);
            }
        }

        return message;
    }

    pub fn readQuestion(self: *Parser, question: *Question) !void {
        try self.handleName(&question.qname);
        question.*.qtype = @enumFromInt(try self.reader.read(u16));
        question.*.qclass = @enumFromInt(try self.reader.read(u16));
    }

    pub fn readRecord(self: *Parser, record: *Record) !void {
        //const alloc = self.alloc;
        try self.handleName(&record.name);

        record.*.type = @enumFromInt(try self.reader.read(u16));
        record.*.class = @enumFromInt(try self.reader.read(u16));
        record.*.ttl = try self.reader.read(u32);
        record.*.rdlength = try self.reader.read(u16);
        //const slice = try record.*.rdata.addManyAsSlice(@as(usize, record.*.rdlength));
        record.*.rdata = try ArrayListUnmanaged(u8).initCapacity(self.alloc, @intCast(record.rdlength));
        //errdefer record.rdata.deinit(self.alloc);
        try readList(self.alloc, &record.rdata, &self.reader, @as(usize, record.rdlength));
    }

    pub fn readHeader(self: *Parser) !Header {
        const T = struct {
            id: u16,
            flags: u16,
            qdcount: u16,
            ancount: u16,
            nscount: u16,
            arcount: u16,
        };

        const header = try self.reader.read(T);

        return .{
            .id = header.id,
            .flags = Header.Flags.getFlags(header.flags),
            .qcount = header.qdcount,
            .ancount = header.ancount,
            .nscount = header.nscount,
            .arcount = header.arcount,
        };
    }

    /// Reads name/qname field from packet, returns list of strings
    /// *Internal use only
    inline fn handleName(self: *Parser, list: *Name) !void {
        //var list = std.ArrayList([]u8).init(self.alloc);
        //errdefer list.deinit();

        const pointer: u16 = try self.reader.read(u16);
        if ((pointer & 0xF) == 0xc) {
            const offset = @as(usize, pointer & 0xFFF);
            var tmp_rd = Reader.init(self.reader.bytes[offset..]);
            try self.read2DList(&tmp_rd, list);
        } else {
            self.reader.index -= 2;
            try self.read2DList(&self.reader, list);
        }

        //return list.toOwnedSlice();
    }

    /// Reads a list of u8 values from the reader into the buffer
    /// *Internal use only
    inline fn readList(allocator: Allocator, buf: *ArrayListUnmanaged(u8), reader: *Reader, size: usize) !void {
        for (0..size) |i| {
            _ = i;
            try buf.append(allocator, try reader.read(u8));
        }
    }

    /// Reads name fields of packet
    /// *Internal use only
    inline fn read2DList(self: *Parser, reader: *Reader, list: *Name) !void {
        var size: u8 = try reader.read(u8);
        var i: usize = 0;
        while (size != 0x00) : (i += 1) {
            const buf = try list.addOne(self.alloc);
            //buf.* = ArrayList(u8).init(self.alloc);
            buf.* = .{};
            try readList(self.alloc, buf, reader, @as(usize, size));
            size = try reader.read(u8);
        }
    }
};

/// Helper to convert u16 to bytes
pub fn u16ToBeBytes(value: u16) [2]u8 {
    return [2]u8{
        @as(u8, @intCast((value >> 8) & 0xff)),
        @as(u8, @intCast(value & 0xff)),
    };
}

/// Helper to convert u32 to bytes
pub fn u32ToBeBytes(value: u32) [4]u8 {
    return [4]u8{
        @as(u8, @intCast((value >> 24) & 0xff)),
        @as(u8, @intCast((value >> 16) & 0xff)),
        @as(u8, @intCast((value >> 8) & 0xff)),
        @as(u8, @intCast(value & 0xff)),
    };
}

test "read" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44 };

    var packet = try Message.fromBytes(allocator, &data);
    defer packet.deinit();

    var buf: [32]u8 = undefined;

    const addr = try std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        packet.answers.items[0].rdata.items[0],
        packet.answers.items[0].rdata.items[1],
        packet.answers.items[0].rdata.items[2],
        packet.answers.items[0].rdata.items[3],
    });

    var buf2: [512]u8 = undefined;

    const bytes = try packet.bytesAlloc(allocator);
    const bytes2 = try packet.bytes(&buf2);

    std.debug.print("{x}\nlen: {d}\n{x}\nlen: {d}\n", .{ bytes, bytes.len, bytes2, bytes2.len });

    assert(std.mem.eql(u8, bytes, bytes2));

    defer allocator.free(bytes);

    const name = try packet.answers.items[0].nameToStringAlloc(allocator);
    defer allocator.free(name);

    std.debug.print("{s}\nAddr: {s}\n", .{ name, addr });
    std.debug.print("Bytes: {x}\n", .{bytes});
    std.debug.print("Original: {x}\n", .{data});
}
