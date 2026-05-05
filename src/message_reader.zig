const std = @import("std");
const rr = @import("rr.zig");
const message_header = @import("message_header.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Reader = std.Io.Reader;

const Question = rr.Question;
const Record = rr.Record;
const QuestionRef = rr.QuestionRef;
const RecordRef = rr.RecordRef;
const Header = message_header.Header;

pub const SectionOffsets = struct {
    questions: usize = 0,
    answers: usize = 0,
    authorities: usize = 0,
    additionals: usize = 0,
    end: usize = 0,
};

pub const QuestionIterator = struct {
    reader: Reader,
    remaining: u16,

    pub fn init(packet: []const u8, offset: usize, count: u16) QuestionIterator {
        var iter_reader = Reader.fixed(packet);
        iter_reader.seek = offset;
        return .{
            .reader = iter_reader,
            .remaining = count,
        };
    }

    pub fn next(self: *QuestionIterator) !?QuestionRef {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        return try QuestionRef.decode(&self.reader);
    }

    pub fn skipRemaining(self: *QuestionIterator) !void {
        while (self.remaining > 0) {
            self.remaining -= 1;
            try Question.skip(&self.reader);
        }
    }
};

pub const RecordIterator = struct {
    reader: Reader,
    remaining: u16,

    pub fn init(packet: []const u8, offset: usize, count: u16) RecordIterator {
        var iter_reader = Reader.fixed(packet);
        iter_reader.seek = offset;
        return .{
            .reader = iter_reader,
            .remaining = count,
        };
    }

    pub fn next(self: *RecordIterator) !?RecordRef {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        return try RecordRef.decode(&self.reader);
    }

    pub fn skipRemaining(self: *RecordIterator) !void {
        while (self.remaining > 0) {
            self.remaining -= 1;
            try Record.skip(&self.reader);
        }
    }
};

pub fn readSectionOffsets(reader: *Reader, header: Header) !SectionOffsets {
    var offsets: SectionOffsets = .{
        .questions = reader.seek,
    };
    for (0..header.qd_count) |_| try Question.skip(reader);

    offsets.answers = reader.seek;
    for (0..header.an_count) |_| try Record.skip(reader);

    offsets.authorities = reader.seek;
    for (0..header.ns_count) |_| try Record.skip(reader);

    offsets.additionals = reader.seek;
    for (0..header.ar_count) |_| try Record.skip(reader);

    offsets.end = reader.seek;
    return offsets;
}

pub const MessageReader = struct {
    header: Header,
    packet: []const u8,
    section_offsets: SectionOffsets,
    next_question_it: QuestionIterator,
    next_answer_it: RecordIterator,
    next_authority_it: RecordIterator,
    next_additional_it: RecordIterator,

    pub fn parse(packet: []const u8) !MessageReader {
        return initAt(packet, 0);
    }

    pub fn initAt(packet: []const u8, start_offset: usize) !MessageReader {
        var reader = Reader.fixed(packet);
        reader.seek = start_offset;
        const header = try Header.decode(&reader);
        const offsets = try readSectionOffsets(&reader, header);

        return .{
            .header = header,
            .packet = packet,
            .section_offsets = offsets,
            .next_question_it = QuestionIterator.init(packet, offsets.questions, header.qd_count),
            .next_answer_it = RecordIterator.init(packet, offsets.answers, header.an_count),
            .next_authority_it = RecordIterator.init(packet, offsets.authorities, header.ns_count),
            .next_additional_it = RecordIterator.init(packet, offsets.additionals, header.ar_count),
        };
    }

    pub fn encode(self: *MessageReader, writer: *std.Io.Writer) !usize {
        var size: usize = 0;
        size += self.header.encode(writer);

        var q_it = self.questionIterator();
        while (try q_it.next()) |*q| {
            size += try q.encode(writer);
        }

        var an_it = self.answerIterator();
        while (try an_it.next()) |*a| {
            size += try a.encode(writer);
        }

        var ns_it = self.authorityIterator();
        while (try ns_it.next()) |*a| {
            size += try a.encode(writer);
        }

        var ar_it = self.authorityIterator();
        while (try ar_it.next()) |*a| {
            size += try a.encode(writer);
        }

        return size;
    }

    pub fn nextQuestion(self: *MessageReader) !?QuestionRef {
        return self.next_question_it.next();
    }

    pub fn nextAnswer(self: *MessageReader) !?RecordRef {
        return self.next_answer_it.next();
    }

    pub fn nextAuthority(self: *MessageReader) !?RecordRef {
        return self.next_authority_it.next();
    }

    pub fn nextAdditional(self: *MessageReader) !?RecordRef {
        return self.next_additional_it.next();
    }

    pub fn questionIterator(self: *const MessageReader) QuestionIterator {
        return QuestionIterator.init(self.packet, self.section_offsets.questions, self.header.qd_count);
    }

    pub fn answerIterator(self: *const MessageReader) RecordIterator {
        return RecordIterator.init(self.packet, self.section_offsets.answers, self.header.an_count);
    }

    pub fn authorityIterator(self: *const MessageReader) RecordIterator {
        return RecordIterator.init(self.packet, self.section_offsets.authorities, self.header.ns_count);
    }

    pub fn additionalIterator(self: *const MessageReader) RecordIterator {
        return RecordIterator.init(self.packet, self.section_offsets.additionals, self.header.ar_count);
    }

    pub fn getAllQuestions(self: *MessageReader, allocator: Allocator) !ArrayList(Question) {
        var out = try ArrayList(Question).initCapacity(allocator, self.header.qd_count);
        errdefer {
            for (out.items) |*question| question.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.questionIterator();
        while (try it.next()) |question| {
            try out.append(allocator, try question.toOwned(allocator));
        }
        return out;
    }

    pub fn getAllAnswers(self: *MessageReader, allocator: Allocator) !ArrayList(Record) {
        var out = try ArrayList(Record).initCapacity(allocator, self.header.an_count);
        errdefer {
            for (out.items) |*record| record.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.answerIterator();
        while (try it.next()) |*record| {
            var owned = try record.toOwned(allocator);
            errdefer owned.deinit(allocator);
            try out.append(allocator, owned);
        }
        return out;
    }

    pub fn getAllAuthorities(self: *MessageReader, allocator: Allocator) !ArrayList(Record) {
        var out = try ArrayList(Record).initCapacity(allocator, self.header.ns_count);
        errdefer {
            for (out.items) |*record| record.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.authorityIterator();
        while (try it.next()) |record| {
            var owned = try record.toOwned(allocator);
            errdefer owned.deinit(allocator);
            try out.append(allocator, owned);
        }
        return out;
    }

    pub fn getAllAdditionals(self: *MessageReader, allocator: Allocator) !ArrayList(Record) {
        var out = try ArrayList(Record).initCapacity(allocator, self.header.ar_count);
        errdefer {
            for (out.items) |*record| record.deinit(allocator);
            out.deinit(allocator);
        }

        var it = self.additionalIterator();
        while (try it.next()) |record| {
            var owned = try record.toOwned(allocator);
            errdefer owned.deinit(allocator);
            try out.append(allocator, owned);
        }
        return out;
    }

    pub fn format(self: MessageReader, writer: *std.Io.Writer) !void {
        try writer.print("{f}\n", .{self.header});

        var q_itr = self.questionIterator();
        while (q_itr.next() catch return error.WriteFailed) |question| {
            try writer.print("{f}\n", .{question});
        }

        var an_itr = self.answerIterator();
        while (an_itr.next() catch return error.WriteFailed) |record| {
            try writer.print("{f}\n", .{record});
        }

        var ns_itr = self.authorityIterator();
        while (ns_itr.next() catch return error.WriteFailed) |record| {
            try writer.print("{f}\n", .{record});
        }

        var ad_itr = self.additionalIterator();
        while (ad_itr.next() catch return error.WriteFailed) |record| {
            try writer.print("{f}\n", .{record});
        }
    }
};
