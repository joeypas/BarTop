const std = @import("std");
const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const Reader = @import("reader.zig");
const bigToNative = std.mem.bigToNative;
const nativeToBig = std.mem.nativeToBig;

pub const Message = struct {
    header: Header,
    questions: ArrayList(Question),
    answers: ArrayList(Record),
    authorities: ArrayList(Record),
    additionals: ArrayList(Record),
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
        for (self.questions.items) |q| {
            q.deinit();
        }
        self.questions.deinit();
        for (self.answers.items) |r| {
            r.deinit();
        }
        self.answers.deinit();
        for (self.authorities.items) |r| {
            r.deinit();
        }
        self.authorities.deinit();
        for (self.additionals.items) |r| {
            r.deinit();
        }
        self.additionals.deinit();
    }

    /// Serializes the entire DNS message into a byte array.
    pub fn bytes(self: *Message, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize header
        const header_bytes = try self.header.bytes(allocator);
        defer allocator.free(header_bytes);

        try builder.appendSlice(header_bytes);

        // Serialize questions
        for (self.questions.items) |question| {
            const question_bytes = try question.bytes(allocator);
            defer allocator.free(question_bytes);
            try builder.appendSlice(question_bytes);
        }

        // Serialize answers
        for (self.answers.items) |answer| {
            const answer_bytes = try answer.bytes(allocator);
            defer allocator.free(answer_bytes);
            try builder.appendSlice(answer_bytes);
        }

        // Serialize authorities
        for (self.authorities.items) |authority| {
            const authority_bytes = try authority.bytes(allocator);
            defer allocator.free(authority_bytes);
            try builder.appendSlice(authority_bytes);
        }

        // Serialize additionals
        for (self.additionals.items) |additional| {
            const additional_bytes = try additional.bytes(allocator);
            defer allocator.free(additional_bytes);
            try builder.appendSlice(additional_bytes);
        }

        return builder.toOwnedSlice();
    }

    pub fn addQuestion(self: *Message) !*Question {
        var question = try self.questions.addOne();
        question.allocator = self.allocator;
        question.qname = ArrayList([]u8).init(self.allocator);
        return question;
    }

    pub fn addAnswer(self: *Message) !*Record {
        var answer = try self.answers.addOne();
        answer.allocator = self.allocator;
        answer.name = ArrayList([]u8).init(self.allocator);
        return answer;
    }

    pub fn addAuthority(self: *Message) !*Record {
        var authority = try self.authorities.addOne();
        authority.allocator = self.allocator;
        authority.name = ArrayList([]u8).init(self.allocator);
        return authority;
    }

    pub fn addAdditional(self: *Message) !*Record {
        var additional = try self.additionals.addOne();
        additional.allocator = self.allocator;
        additional.name = ArrayList([]u8).init(self.allocator);
        return additional;
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
    pub fn bytes(self: *const Header, allocator: Allocator) ![]u8 {
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
};

pub const Question = struct {
    qname: ArrayList([]u8),
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

    pub fn deinit(self: *const Question) void {
        for (self.qname.items) |part| {
            self.allocator.free(part);
        }
        self.qname.deinit();
    }

    /// Convert a Question to bytes in big endian order
    pub fn bytes(self: *const Question, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize qname (domain name)
        for (self.qname.items) |label| {
            if (label.len > 256) {
                break;
            }
            try builder.append(@as(u8, @intCast(label.len)));
            try builder.appendSlice(label);
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

    pub fn qnameAppendSlice(self: *Question, slice: [][]u8) !void {
        for (slice) |part| {
            try self.qname.append(try self.allocator.alloc(u8, part.len));
            std.mem.copyForwards(u8, self.qname.getLast(), part);
        }
    }
};

pub const Record = struct {
    name: ArrayList([]u8),
    type: Type,
    class: Class,
    ttl: u32,
    rdlength: u16,
    rdata: []u8,
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

    pub fn deinit(self: *const Record) void {
        for (self.name.items) |part| {
            self.allocator.free(part);
        }
        self.name.deinit();
        self.allocator.free(self.rdata);
    }

    /// Convert a Record to bytes in big endian order
    pub fn bytes(self: *const Record, allocator: Allocator) ![]u8 {
        var builder = std.ArrayList(u8).init(allocator);
        defer builder.deinit();

        // Serialize name (domain name)
        for (self.name.items) |label| {
            try builder.append(@as(u8, @intCast(label.len)));
            try builder.appendSlice(label);
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
        try builder.appendSlice(self.rdata);

        return builder.toOwnedSlice();
    }

    pub fn nameAppendSlice(self: *Record, slice: [][]u8) !void {
        for (slice) |part| {
            try self.name.append(try self.allocator.alloc(u8, part.len));
            std.mem.copyForwards(u8, self.name.getLast(), part);
        }
    }
};

/// A DNS packet deserializer.
/// This struct internally stores a `std.heap.ArenaAllocator` for memory management.
/// To free all memory allocated in this struct call `deinit`
pub const Parser = struct {
    reader: Reader,
    alloc: Allocator,

    /// Does not need to be deinitialized
    pub fn init(data: []const u8, alloc: Allocator) Parser {
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
        const alloc = self.alloc;
        try self.handleName(&record.name);

        record.*.type = @enumFromInt(try self.reader.read(u16));
        record.*.class = @enumFromInt(try self.reader.read(u16));
        record.*.ttl = try self.reader.read(u32);
        record.*.rdlength = try self.reader.read(u16);
        record.*.rdata = try alloc.alloc(u8, @as(usize, record.rdlength));

        try readList(record.rdata, &self.reader, @as(usize, record.rdlength));
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
    inline fn handleName(self: *Parser, list: *ArrayList([]u8)) !void {
        //var list = std.ArrayList([]u8).init(self.alloc);
        errdefer list.deinit();

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
    inline fn readList(buf: []u8, reader: *Reader, size: usize) !void {
        for (0..size) |i| {
            buf[i] = try reader.read(u8);
        }
    }

    /// Reads name fields of packet
    /// *Internal use only
    inline fn read2DList(self: *Parser, reader: *Reader, list: *ArrayList([]u8)) !void {
        var size: u8 = try reader.read(u8);
        var i: usize = 0;
        while (size != 0x00) : (i += 1) {
            try list.append(try self.alloc.alloc(u8, @as(usize, size)));
            try readList(list.items[i], reader, @as(usize, size));
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

    var dns = Parser.init(&data, allocator);

    var packet = try dns.read();
    defer packet.deinit();

    var buf: [32]u8 = undefined;

    const addr = try std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        packet.answers.items[0].rdata[0],
        packet.answers.items[0].rdata[1],
        packet.answers.items[0].rdata[2],
        packet.answers.items[0].rdata[3],
    });

    const bytes = try packet.bytes(allocator);
    defer allocator.free(bytes);

    std.debug.print("{s}\nAddr: {s}\n", .{ packet.answers.items[0].name.items, addr });
    std.debug.print("Bytes: {x}\n", .{bytes});
    std.debug.print("Original: {x}\n", .{data});
}
