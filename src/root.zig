pub const Message = @import("message.zig");
const rr = @import("rr.zig");
pub const dnssec = @import("dnssec.zig");
pub const util = @import("util/root.zig");
pub const server = @import("stub_resolver.zig");
const crypto = util.crypto;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

pub const Zone = @import("zone.zig").Zone;

const std = @import("std");
test "name encode/decode" {
    const alloc = std.testing.allocator;
    var name = Message.Name.init(alloc);
    defer name.deinit(alloc);

    try name.parse("example.com");
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
    var record = Message.Record.init(alloc, .a);
    defer record.deinit(alloc);

    try record.name.parse("example.com");
    record.ttl = 60;
    record.rdata.a.addr = std.net.Ip4Address.init(.{ 1, 2, 3, 4 }, 0);
    record.rdlength = record.rdata.getLen();

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
    try std.testing.expectEqualDeep(record.rdata, decoded.rdata);
}

test "message encode/decode" {
    const alloc = std.testing.allocator;
    var msg = Message.init(alloc);
    defer msg.deinit();

    msg.header.id = 0xaaaa;
    msg.header.qd_count = 1;
    msg.header.an_count = 1;

    const q = try msg.addQuestion();
    try q.qname.parse("example.com");
    q.qtype = .nsec3;

    const a = try msg.addAnswer(.nsec3);
    try a.name.parse("example.com");
    a.rdata.nsec3.hash_algorithm = .sha224;
    a.rdata.nsec3.flags = 244;
    a.rdata.nsec3.iterations = 22;
    a.rdata.nsec3.salt_len = 5;
    a.rdata.nsec3.salt = try std.ArrayList(u8).initCapacity(alloc, 5);
    a.rdata.nsec3.salt.appendSliceAssumeCapacity("12345");
    a.rdata.nsec3.hash_len = 6;
    a.rdata.nsec3.hash = try std.ArrayList(u8).initCapacity(alloc, 6);
    a.rdata.nsec3.hash.appendSliceAssumeCapacity("123456");
    a.rdata.nsec3.type_bitmap = try std.ArrayList(u8).initCapacity(alloc, 12);
    a.rdata.nsec3.type_bitmap.appendSliceAssumeCapacity("LSKDJFOISDFH");

    a.ttl = 120;
    a.rdlength = a.rdata.getLen();

    var buf: [1024]u8 = undefined;
    var fbs = Writer.fixed(&buf);
    try msg.encode(&fbs);
    const len = fbs.end;
    defer fbs.flush() catch unreachable;

    var fbr = Reader.fixed(buf[0..len]);
    var decoded = try Message.decode(alloc, &fbr);
    defer decoded.deinit();

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
    try std.testing.expectEqualDeep(a.rdata, da.rdata);
    try std.testing.expectEqual(a.ttl, da.ttl);
}

test "crypto_gen/sign" {
    const alloc = std.testing.allocator;
    var ctx = crypto.Context.init();
    defer ctx.deinit();

    var key = crypto.Key.init(alloc, ctx, .ecdsap384sha384);
    defer key.deinit();

    try key.gen();
    try key.toFileDer("private.der");

    var key2 = crypto.Key.init(alloc, ctx, .ecdsap384sha384);
    defer key2.deinit();
    try key2.fromFileDer("private.der");

    const test_msg = "This is a test Message.";

    const sig = try key2.sign(alloc, test_msg);
    defer alloc.free(sig);

    try std.testing.expect(try key.verify(sig, test_msg));
}

test "crypto pubkey" {
    const alloc = std.testing.allocator;
    var ctx = crypto.Context.init();
    defer ctx.deinit();

    var key = crypto.Key.init(alloc, ctx, .ed448);
    defer key.deinit();

    try key.gen();

    const pubkey = try key.publicKeyBase64(alloc);
    defer alloc.free(pubkey);

    std.debug.print("len: {d}\nkey: {s}\n", .{ pubkey.len, pubkey });
}
