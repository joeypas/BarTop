pub const dns = @import("dns.zig");
pub const dnssec = @import("dnssec.zig");
pub const util = @import("util/root.zig");
pub const server = @import("stub_resolver.zig");
const crypto = util.crypto;
pub const zone = @import("zone.zig");

const std = @import("std");
test "name encode/decode" {
    const alloc = std.testing.allocator;
    var name = dns.Name.init(alloc);
    defer name.deinit();

    try name.fromString("example.com");
    try std.testing.expectEqual(@as(u16, 13), name.getLen());

    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const len = try name.encode(fbs.writer().any());

    var fbr = std.io.fixedBufferStream(buf[0..len]);
    var br = std.io.bufferedReader(fbr.reader().any());

    var decoded = try dns.Name.decode(alloc, &br);
    defer decoded.deinit();

    const got = try decoded.allocPrint(alloc);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("example.com.", got);
}

test "header encode/decode" {
    var header = dns.Header{
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
    var fbs = std.io.fixedBufferStream(&buf);
    const len = try header.encode(fbs.writer().any());
    try std.testing.expectEqual(@as(usize, 12), len);

    var fbr = std.io.fixedBufferStream(buf[0..len]);
    var br = std.io.bufferedReader(fbr.reader().any());
    const decoded = try dns.Header.decode(&br);

    try std.testing.expectEqualDeep(header, decoded);
}

test "record encode/decode" {
    const alloc = std.testing.allocator;
    var record = dns.Record.init(alloc, .a);
    defer record.deinit();

    try record.name.fromString("example.com");
    record.ttl = 60;
    record.rdata.a.addr = std.net.Ip4Address.init(.{ 1, 2, 3, 4 }, 0);
    record.rdlength = record.rdata.getLen();

    var buf: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const len = try record.encode(fbs.writer().any());

    var fbr = std.io.fixedBufferStream(buf[0..len]);
    var br = std.io.bufferedReader(fbr.reader().any());

    var decoded = try dns.Record.decode(alloc, &br);
    defer decoded.deinit();

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
    var msg = dns.Message.init(alloc);
    defer msg.deinit();

    msg.header.id = 0xaaaa;
    msg.header.qd_count = 1;
    msg.header.an_count = 1;

    const q = try msg.addQuestion();
    try q.qname.fromString("example.com");
    q.qtype = .a;

    const a = try msg.addAnswer(.a);
    try a.name.fromString("example.com");
    a.rdata.a.addr = std.net.Ip4Address.init(.{ 5, 6, 7, 8 }, 0);
    a.ttl = 120;
    a.rdlength = a.rdata.getLen();

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const len = try msg.encode(fbs.writer().any());

    var fbr = std.io.fixedBufferStream(buf[0..len]);
    var decoded = try dns.Message.decode(alloc, fbr.reader().any());
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

    var key = crypto.Key.init(alloc, ctx, .ed25519);
    defer key.deinit();

    try key.gen();
    try key.toFilePem("private.pem");

    var key2 = crypto.Key.init(alloc, ctx, .ed25519);
    defer key2.deinit();
    try key2.fromFilePem("private.pem");

    const test_msg = "This is a test Message.";

    const sig = try key2.sign(alloc, test_msg);
    defer alloc.free(sig);

    try std.testing.expect(try key.verify(sig, test_msg));
}

test "crypto pubkey" {
    const alloc = std.testing.allocator;
    var ctx = crypto.Context.init();
    defer ctx.deinit();

    var key = crypto.Key.init(alloc, ctx, .dsa);
    defer key.deinit();

    try key.gen();

    const pubkey = try key.buildDnskeyBase64(alloc);
    defer alloc.free(pubkey);

    std.debug.print("len: {d}\nkey: {s}\n", .{ pubkey.len, pubkey });
}

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
