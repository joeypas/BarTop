const std = @import("std");
const dns = @import("dns").Message;
const clap = @import("clap");
const rand = std.crypto.random;

pub fn getQname(allocator: std.mem.Allocator) ![]const u8 {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help            Display this help and exit.
        \\-t, --type <str>      Type of query to send
        \\<str>...              Hostname to query.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        // Report useful error and exit
        var stderr_fd = std.fs.File.stderr();
        defer stderr_fd.close();
        diag.reportToFile(stderr_fd, err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        std.debug.print("--help\n", .{});
        return error.Help;
    } else {
        if (res.positionals.len > 0) {
            return res.positionals[0][0];
        } else {
            diag.report(std.io.getStdErr().writer(), clap.streaming.Error.MissingValue) catch {};
            return clap.streaming.Error.MissingValue;
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var message = dns.Message.init(allocator);
    defer message.deinit();

    const qname = getQname(allocator) catch |err| switch (err) {
        error.Help => return,
        else => return err,
    };

    message.header = .{
        .id = rand.int(u16),
        .flags = .{
            .response = false,
            .op_code = .query,
            .truncated = false,
            .authoritative = false,
            .recursion_desired = true,
            .recursion_available = false,
            .z = 0,
            .response_code = .no_error,
        },
        .qd_count = 1,
        .an_count = 0,
        .ns_count = 0,
        .ar_count = 0,
    };

    const question = try message.addQuestion();
    try question.qname.parse(qname);
    question.*.qtype = .ns;
    question.*.qclass = .in;

    var data_buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&data_buf);
    try message.encode(&writer);
    const data = writer.end;
    try writer.flush();
    std.debug.print("Data len: {d}\n", .{data});
    const addr = try std.net.Address.parseIp("127.0.0.1", 53);
    const sock = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM,
        std.posix.IPPROTO.UDP,
    );
    defer std.posix.close(sock);

    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());

    _ = try std.posix.send(sock, data_buf[0..data], 0);
    var buf: [512]u8 = undefined;

    const recv_bytes = try std.posix.recv(sock, buf[0..], 0);

    var fbr = std.Io.Reader.fixed(buf[0..recv_bytes]);
    var message_data = try dns.Message.decode(allocator, &fbr);
    defer message_data.deinit();

    if (message.header.id != message.header.id) {
        std.debug.print("EXPECTED ID: {d}, GOT: {d}\n", .{ message.header.id, message.header.id });
    }

    if (message.header.flags.response_code != .no_error) {
        std.debug.print(
            "RECIEVED ERR=> {s}\n",
            .{std.meta.fieldNames(dns.Flags)[@intFromEnum(message.header.flags.response_code)]},
        );
    } else {
        std.debug.print("RECIEVED=>\n{f}\n", .{message});
    }
}
