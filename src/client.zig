const std = @import("std");
const Dns = @import("dns.zig");
const clap = @import("clap");
const rand = std.crypto.random;

pub fn getQname(allocator: std.mem.Allocator) ![][]u8 {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\<str>...              Hostname to query.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        // Report useful error and exit
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        std.debug.print("--help\n", .{});
        return error.Help;
    } else {
        if (res.positionals.len > 0) {
            var itr = std.mem.splitAny(u8, res.positionals[0], ".");
            var ret = std.ArrayList([]u8).init(allocator);
            errdefer ret.deinit();

            while (itr.next()) |part| {
                try ret.append(@constCast(part));
            }

            return ret.toOwnedSlice();
        } else {
            diag.report(std.io.getStdErr().writer(), clap.streaming.Error.MissingValue) catch {};
            return clap.streaming.Error.MissingValue;
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    var allocator = gpa.allocator();

    var packet = Dns.Message.init(allocator);
    defer packet.deinit();

    const qname = getQname(allocator) catch |err| switch (err) {
        error.Help => return,
        else => return err,
    };
    defer allocator.free(qname);

    packet.header = .{
        .id = rand.int(u16),
        .flags = .{
            .qr = false,
            .opcode = Dns.Header.Opcode.query,
            .tc = false,
            .aa = false,
            .rd = true,
            .ra = false,
            .z = 0,
            .rcode = Dns.Header.ResponseCode.no_error,
        },
        .qcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    const question = try packet.addQuestion();
    try question.qnameAppendSlice2D(qname);
    question.*.qtype = Dns.Question.QType.a;
    question.*.qclass = Dns.Question.QClass.in;

    //const data = [_]u8{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };
    //const data = [_]u8{ 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };
    const data = try packet.bytesAlloc(allocator);
    std.debug.print("Data len: {d}\n", .{data.len});
    defer allocator.free(data);
    //_ = packet;
    const addr = try std.net.Address.parseIp("127.0.0.1", 5553);
    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sock);

    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());

    _ = try std.posix.send(sock, data[0..], 0);
    var buf: [512]u8 = undefined;

    const recv_bytes = try std.posix.recv(sock, buf[0..], 0);

    var message = try Dns.Message.fromBytes(allocator, buf[0..recv_bytes]);
    defer message.deinit();

    if (message.header.id != packet.header.id) {
        std.debug.print("EXPECTED ID: {d}, GOT: {d}\n", .{ packet.header.id, message.header.id });
    }

    if (message.header.flags.rcode != .no_error) {
        std.debug.print(
            "RECIEVED ERR=> {s}\n",
            .{std.meta.fieldNames(Dns.Header.ResponseCode)[@intFromEnum(message.header.flags.rcode)]},
        );
    } else {
        const name = try message.answers.items[0].nameToString();
        defer allocator.free(name);
        std.debug.print("RECIEVED=> {s}: {any}", .{ name, message.answers.items[0].rdata.items });
    }
}
