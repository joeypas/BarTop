//! Dns message abstractions.
const std = @import("std");

const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;

pub const Reader = std.io.BufferedReader(4096, std.io.AnyReader);
const Writer = std.io.BufferedWriter(4096, std.io.AnyWriter);

pub const Message = @This();

pub const RData = @import("rdata.zig").RData;
const rr = @import("rr.zig");
pub const Question = rr.Question;
pub const Record = rr.Record;
pub const Type = rr.Type;
pub const Class = rr.Class;
pub const Name = rr.Name;

allocator: Allocator,
header: Header,
questions: ArrayList(Question),
answers: ArrayList(Record),
authorities: ArrayList(Record),
additionals: ArrayList(Record),
/// Is this message a refrence to another
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

pub fn addAnswer(self: *Message, rtype: Type) !*Record {
    const a = try self.answers.addOne();
    a.* = Record.init(self.allocator, rtype);
    return a;
}

pub fn addAuthority(self: *Message, rtype: Type) !*Record {
    const a = try self.answers.addOne();
    a.* = Record.init(self.allocator, rtype);
    return a;
}

pub fn addAdditional(self: *Message, rtype: Type) !*Record {
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

pub const ResponseCode = enum(u4) {
    no_error,
    format_error,
    server_failure,
    name_error,
    not_implemented,
    refused,
    _,
};

pub const OpCode = enum(u4) {
    query,
    iquery,
    status,
    _,
};

// bitcast to go from struct to int
pub const Flags = packed struct {
    response_code: ResponseCode = .no_error,
    check_disable: bool = false,
    authenticated: bool = false,
    z: u1 = 0,
    recursion_available: bool = false,
    recursion_desired: bool = false,
    truncated: bool = false,
    authoritative: bool = false,
    op_code: OpCode = .query,
    response: bool = false,
};

pub const Header = packed struct {
    id: u16 = 0,
    flags: Flags = .{},
    /// Question count
    qd_count: u16 = 0,
    /// Answer count
    an_count: u16 = 0,
    /// Authority count
    ns_count: u16 = 0,
    // Additional count
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
