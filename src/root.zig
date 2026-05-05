pub const Message = @import("message.zig");
pub const MessageReader = @import("message_reader.zig").MessageReader;
const rr = @import("rr.zig");
pub const dns_server = @import("dns_server.zig");
pub const server = @import("stub_resolver_async.zig");
pub const resolver = @import("resolver.zig");
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const std = @import("std");
test "name encode/decode" {
    const alloc = std.testing.allocator;
    var name = Message.Name.init();
    defer name.deinit(alloc);

    try name.parse(alloc, "example.com");
    try std.testing.expectEqual(@as(u16, 13), name.getLen());

    var buf: [64]u8 = undefined;
    var fbs = Writer.fixed(&buf);
    const len = try name.encode(&fbs);
    try fbs.flush();

    var fbr = Reader.fixed(buf[0..len]);

    var decoded = try Message.Name.decode(alloc, &fbr);
    defer decoded.deinit(alloc);

    const got = try decoded.allocPrint(alloc);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("example.com.", got);
}

test "name removeFirstLabel" {
    const alloc = std.testing.allocator;
    var name = try Message.Name.initString(alloc, "www.api.example.com");
    defer name.deinit(alloc);

    try std.testing.expect(name.removeFirstLabel());
    var got = try name.allocPrint(alloc);
    try std.testing.expectEqualStrings("api.example.com.", got);
    alloc.free(got);

    try std.testing.expect(name.removeFirstLabel());
    got = try name.allocPrint(alloc);
    try std.testing.expectEqualStrings("example.com.", got);
    alloc.free(got);

    try std.testing.expect(name.removeFirstLabel());
    try std.testing.expect(name.removeFirstLabel());
    try std.testing.expect(!name.removeFirstLabel());
    try std.testing.expectEqual(@as(usize, 0), name.labelCount());
    try std.testing.expectEqual(@as(u16, 1), name.getLen());
}

test "header encode/decode" {
    var header = Message.Header{
        .id = 0x1234,
        .flags = .{
            .response = true,
            .op_code = .query,
            .authoritative = true,
            .truncated = false,
            .recursion_desired = true,
            .recursion_available = true,
            .authenticated = true,
            .check_disable = true,
            .response_code = .no_error,
        },
        .qd_count = 1,
        .an_count = 2,
        .ns_count = 3,
        .ar_count = 4,
    };

    var buf: [12]u8 = undefined;
    var fbs = Writer.fixed(&buf);
    const len = try header.encode(&fbs);
    try fbs.flush();
    try std.testing.expectEqual(@as(usize, 12), len);

    var fbr = Reader.fixed(buf[0..len]);
    const decoded = try Message.Header.decode(&fbr);

    try std.testing.expectEqualDeep(header, decoded);
}

test "record encode/decode" {
    const alloc = std.testing.allocator;
    var record = Message.Record.init(.a);
    defer record.deinit(alloc);

    try record.name.parse(alloc, "example.com");
    record.ttl = 60;
    var rdata = Message.RData.init(.a);
    defer rdata.deinit(alloc);
    rdata.a.addr = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 0 };
    try record.setRData(alloc, &rdata);

    var buf: [128]u8 = undefined;
    var fbs = Writer.fixed(&buf);
    const len = try record.encode(&fbs);
    try fbs.flush();

    var fbr = Reader.fixed(buf[0..len]);

    var decoded = try Message.Record.decode(alloc, &fbr);
    defer decoded.deinit(alloc);

    const name1 = try record.name.allocPrint(alloc);
    defer alloc.free(name1);
    const name2 = try decoded.name.allocPrint(alloc);
    defer alloc.free(name2);
    try std.testing.expectEqualStrings(name1, name2);
    try std.testing.expectEqual(record.ttl, decoded.ttl);
    try std.testing.expectEqual(record.type, decoded.type);
    try std.testing.expectEqualSlices(u8, record.rdata.asSlice(), decoded.rdata.asSlice());
}

test "message encode/decode" {
    const alloc = std.testing.allocator;
    var msg = Message.init();
    defer msg.deinit(alloc);

    msg.header.id = 0xaaaa;
    msg.header.qd_count = 1;
    msg.header.an_count = 1;

    const q = try msg.addQuestion(alloc);
    try q.qname.parse(alloc, "example.com");
    q.qtype = .nsec3;

    const a = try msg.addAnswer(alloc, .nsec3);
    try a.name.parse(alloc, "example.com");
    var ardata = Message.RData.init(.nsec3);
    defer ardata.deinit(alloc);
    ardata.nsec3.hash_algorithm = .sha224;
    ardata.nsec3.flags = 244;
    ardata.nsec3.iterations = 22;
    try ardata.nsec3.salt.appendSlice(alloc, "12345");
    ardata.nsec3.salt_len = @intCast(ardata.nsec3.salt.asSlice().len);
    try ardata.nsec3.hash.appendSlice(alloc, "123456");
    ardata.nsec3.hash_len = @intCast(ardata.nsec3.hash.asSlice().len);
    try ardata.nsec3.type_bitmap.appendSlice(alloc, "LSKDJFOISDFH");

    a.ttl = 120;
    try a.setRData(alloc, &ardata);

    var buf: [1024]u8 = undefined;
    var fbs = Writer.fixed(&buf);
    try msg.encode(&fbs);
    const len = fbs.end;
    defer fbs.flush() catch unreachable;

    var fbr = Reader.fixed(buf[0..len]);
    var decoded = try Message.decode(alloc, &fbr);
    defer decoded.deinit(alloc);

    try std.testing.expectEqualDeep(msg.header, decoded.header);
    try std.testing.expectEqual(@as(usize, 1), decoded.questions.items.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.answers.items.len);

    const dq = &decoded.questions.items[0];
    const name1 = try q.qname.allocPrint(alloc);
    defer alloc.free(name1);
    const name2 = try dq.qname.allocPrint(alloc);
    defer alloc.free(name2);
    try std.testing.expectEqualStrings(name1, name2);

    const da = &decoded.answers.items[0];
    const aname1 = try a.name.allocPrint(alloc);
    defer alloc.free(aname1);
    const aname2 = try da.name.allocPrint(alloc);
    defer alloc.free(aname2);
    try std.testing.expectEqualStrings(aname1, aname2);
    var parsed_da = try da.parseRData(alloc);
    defer parsed_da.deinit(alloc);
    try std.testing.expectEqual(ardata.nsec3.hash_algorithm, parsed_da.nsec3.hash_algorithm);
    try std.testing.expectEqual(ardata.nsec3.flags, parsed_da.nsec3.flags);
    try std.testing.expectEqual(ardata.nsec3.iterations, parsed_da.nsec3.iterations);
    try std.testing.expectEqual(ardata.nsec3.salt_len, parsed_da.nsec3.salt_len);
    try std.testing.expectEqualSlices(u8, ardata.nsec3.salt.asSlice(), parsed_da.nsec3.salt.asSlice());
    try std.testing.expectEqual(ardata.nsec3.hash_len, parsed_da.nsec3.hash_len);
    try std.testing.expectEqualSlices(u8, ardata.nsec3.hash.asSlice(), parsed_da.nsec3.hash.asSlice());
    try std.testing.expectEqualSlices(u8, ardata.nsec3.type_bitmap.asSlice(), parsed_da.nsec3.type_bitmap.asSlice());
    try std.testing.expectEqual(a.ttl, da.ttl);
}

test "message decode with skipped sections and message reader lazy access" {
    const alloc = std.testing.allocator;
    var msg = Message.init();
    defer msg.deinit(alloc);

    msg.header.id = 0xbeef;
    msg.header.qd_count = 1;
    msg.header.an_count = 1;

    const q = try msg.addQuestion(alloc);
    try q.qname.parse(alloc, "example.com");
    q.qtype = .a;
    q.qclass = .in;

    const a = try msg.addAnswer(alloc, .a);
    try a.name.parse(alloc, "example.com");
    a.class = .in;
    a.ttl = 300;
    var ardata = Message.RData.init(.a);
    defer ardata.deinit(alloc);
    ardata.a.addr = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 0 };
    try a.setRData(alloc, &ardata);

    var buf: [1024]u8 = undefined;
    var writer = Writer.fixed(&buf);
    try msg.encode(&writer);
    const len = writer.end;
    defer writer.flush() catch unreachable;

    var reader = Reader.fixed(buf[0..len]);
    var decoded = try Message.decodeWithOptions(alloc, &reader, .{
        .decode_questions = false,
        .decode_answers = false,
        .decode_authorities = false,
        .decode_additionals = false,
    });
    defer decoded.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), decoded.questions.items.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.answers.items.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.authorities.items.len);
    try std.testing.expectEqual(@as(usize, 0), decoded.additionals.items.len);

    var lazy = try MessageReader.parse(buf[0..len]);
    var dq = (try lazy.nextQuestion()) orelse return error.ExpectedQuestion;
    defer dq.deinit(alloc);
    const qname = try dq.qname.allocPrint(alloc);
    defer alloc.free(qname);
    try std.testing.expectEqualStrings("example.com.", qname);
    try std.testing.expectEqual(Message.Type.a, dq.qtype);
    try std.testing.expect((try lazy.nextQuestion()) == null);

    var da = (try lazy.nextAnswer()) orelse return error.ExpectedAnswer;
    defer da.deinit(alloc);
    try std.testing.expectEqual(Message.Type.a, da.type);
    try std.testing.expectEqual(@as(u32, 300), da.ttl);
    try std.testing.expect((try lazy.nextAnswer()) == null);
}

test "message reader next and getAll accessors" {
    const alloc = std.testing.allocator;
    var msg = Message.init();
    defer msg.deinit(alloc);

    msg.header.id = 0x1337;
    msg.header.qd_count = 1;
    msg.header.an_count = 1;

    const q = try msg.addQuestion(alloc);
    try q.qname.parse(alloc, "example.com");
    q.qtype = .a;
    q.qclass = .in;

    const a = try msg.addAnswer(alloc, .a);
    try a.name.parse(alloc, "example.com");
    a.class = .in;
    a.ttl = 42;
    var ardata = Message.RData.init(.a);
    defer ardata.deinit(alloc);
    ardata.a.addr = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 0 };
    try a.setRData(alloc, &ardata);

    var buf: [1024]u8 = undefined;
    var writer = Writer.fixed(&buf);
    try msg.encode(&writer);
    const len = writer.end;
    defer writer.flush() catch unreachable;

    var reader = try MessageReader.parse(buf[0..len]);
    try std.testing.expectEqual(@as(u16, 1), reader.header.qd_count);
    try std.testing.expectEqual(@as(u16, 1), reader.header.an_count);

    var nq = (try reader.nextQuestion()) orelse return error.ExpectedQuestion;
    defer nq.deinit(alloc);
    const qname = try nq.qname.allocPrint(alloc);
    defer alloc.free(qname);
    try std.testing.expectEqualStrings("example.com.", qname);

    var nr = (try reader.nextAnswer()) orelse return error.ExpectedAnswer;
    defer nr.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 42), nr.ttl);

    var all_q = try reader.getAllQuestions(alloc);
    defer {
        for (all_q.items) |*qq| qq.deinit(alloc);
        all_q.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), all_q.items.len);

    var all_a = try reader.getAllAnswers(alloc);
    defer {
        for (all_a.items) |*record_item| record_item.deinit(alloc);
        all_a.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), all_a.items.len);
    try std.testing.expectEqual(@as(u32, 42), all_a.items[0].ttl);
}

test "deferred rdata parsing keeps packet context for compressed names" {
    const alloc = std.testing.allocator;
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
    };

    var reader = Reader.fixed(packet[0..]);
    var decoded = try Message.decode(alloc, &reader);
    defer decoded.deinit(alloc);

    const answer = &decoded.answers.items[0];
    try std.testing.expectEqual(Message.Type.cname, answer.type);

    var parsed = try answer.parseRData(alloc);
    defer parsed.deinit(alloc);

    const target = try parsed.cname.name.allocPrint(alloc);
    defer alloc.free(target);
    try std.testing.expectEqualStrings("example.com.", target);
}

// Crypto tests removed (OpenSSL dependency dropped for Zig 0.16 migration).
