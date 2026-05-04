//! Dns message abstractions.
const std = @import("std");

const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

pub const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

pub const Message = @This();
const message_reader = @import("message_reader.zig");
const message_header = @import("message_header.zig");

pub const RData = @import("rdata.zig").RData;
const rr = @import("rr.zig");
pub const Question = rr.Question;
pub const QuestionRef = rr.QuestionRef;
pub const Record = rr.Record;
pub const RecordRef = rr.RecordRef;
pub const Type = rr.Type;
pub const Class = rr.Class;
pub const Name = rr.Name;
pub const NameRef = rr.NameRef;
pub const ResponseCode = message_header.ResponseCode;
pub const OpCode = message_header.OpCode;
pub const Flags = message_header.Flags;
pub const Header = message_header.Header;

header: Header,
questions: ArrayList(Question),
answers: ArrayList(Record),
authorities: ArrayList(Record),
additionals: ArrayList(Record),
/// Is this message a refrence to another
ref: bool = false,

pub const DecodeOptions = struct {
    decode_questions: bool = true,
    decode_answers: bool = true,
    decode_authorities: bool = true,
    decode_additionals: bool = true,
};

pub fn init() Message {
    return .{
        .header = .{},
        .questions = .empty,
        .answers = .empty,
        .authorities = .empty,
        .additionals = .empty,
    };
}

pub fn deinit(self: *Message, allocator: Allocator) void {
    if (!self.ref) {
        for (self.questions.items) |*question| {
            question.deinit(allocator);
        }
    }
    self.questions.deinit(allocator);

    if (!self.ref) {
        for (self.answers.items) |*answer| {
            answer.deinit(allocator);
        }
    }
    self.answers.deinit(allocator);

    if (!self.ref) {
        for (self.authorities.items) |*answer| {
            answer.deinit(allocator);
        }
    }
    self.authorities.deinit(allocator);

    if (!self.ref) {
        for (self.additionals.items) |*answer| {
            answer.deinit(allocator);
        }
    }
    self.additionals.deinit(allocator);
}

pub fn decode(allocator: Allocator, reader: *Reader) !Message {
    return decodeWithOptions(allocator, reader, .{});
}

pub fn decodeWithOptions(allocator: Allocator, reader: *Reader, options: DecodeOptions) !Message {
    var msg = Message.init();
    errdefer msg.deinit(allocator);
    var parsed = try message_reader.MessageReader.initAt(reader.buffer[0..reader.end], reader.seek);

    msg.header = parsed.header;

    if (options.decode_questions) {
        msg.questions = try parsed.getAllQuestions(allocator);
    }
    if (options.decode_answers) {
        msg.answers = try parsed.getAllAnswers(allocator);
    }
    if (options.decode_authorities) {
        msg.authorities = try parsed.getAllAuthorities(allocator);
    }
    if (options.decode_additionals) {
        msg.additionals = try parsed.getAllAdditionals(allocator);
    }

    reader.seek = parsed.section_offsets.end;
    return msg;
}

pub fn encode(self: *Message, writer: *Writer) !void {
    _ = try self.header.encode(writer);

    for (self.questions.items) |*question| {
        _ = try question.encode(writer);
    }

    for (self.answers.items) |*answer| {
        _ = try answer.encode(writer);
    }

    for (self.authorities.items) |*authority| {
        _ = try authority.encode(writer);
    }

    for (self.additionals.items) |*additional| {
        _ = try additional.encode(writer);
    }
}

pub fn addQuestion(self: *Message, allocator: Allocator) !*Question {
    const q = try self.questions.addOne(allocator);
    q.* = Question.init();
    return q;
}

pub fn addAnswer(self: *Message, allocator: Allocator, rtype: Type) !*Record {
    const a = try self.answers.addOne(allocator);
    a.* = Record.init(rtype);
    return a;
}

pub fn addAuthority(self: *Message, allocator: Allocator, rtype: Type) !*Record {
    const a = try self.authorities.addOne(allocator);
    a.* = Record.init(rtype);
    return a;
}

pub fn addAdditional(self: *Message, allocator: Allocator, rtype: Type) !*Record {
    const a = try self.additionals.addOne(allocator);
    a.* = Record.init(rtype);
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

pub fn format(self: Message, writer: *std.Io.Writer) !void {
    try writer.print("{f}\n", .{self.header});

    for (self.questions.items) |question| {
        try writer.print("{f}\n", .{question});
    }

    for (self.answers.items) |*record| {
        try writer.print("{f}\n", .{record});
    }

    for (self.authorities.items) |*record| {
        try writer.print("{f}\n", .{record});
    }

    for (self.additionals.items) |*record| {
        try writer.print("{f}\n", .{record});
    }
}
