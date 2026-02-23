const std = @import("std");
const dns = @import("dns").Message;
const clap = @import("clap");

pub fn getQname(allocator: std.mem.Allocator, args: std.process.Args) ![]const u8 {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help            Display this help and exit.
        \\-t, --type <str>      Type of query to send
        \\<str>...              Hostname to query.
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, args, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        // Report useful error and exit
        const stderr = std.debug.lockStderr(&.{});
        defer std.debug.unlockStderr();
        diag.report(&stderr.file_writer.interface, err) catch {};
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
            const stderr = std.debug.lockStderr(&.{});
            defer std.debug.unlockStderr();
            diag.report(&stderr.file_writer.interface, clap.streaming.Error.MissingValue) catch {};
            return clap.streaming.Error.MissingValue;
        }
    }
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rand_source = std.Random.IoSource{ .io = io };
    const rng = rand_source.interface();

    var message = dns.Message.init(allocator);
    defer message.deinit();

    const qname = getQname(allocator, init.minimal.args) catch |err| switch (err) {
        error.Help => return,
        else => return err,
    };

    message.header = .{
        .id = rng.int(u16),
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
    const data_len = writer.end;
    try writer.flush();
    std.debug.print("Data len: {d}\n", .{data_len});

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 53);

    var bind_addr = try std.Io.net.IpAddress.parse("0.0.0.0", 0);
    const sock = try std.Io.net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer sock.close(io);

    try sock.send(io, &addr, data_buf[0..data_len]);
    var buf: [512]u8 = undefined;

    const incoming = try sock.receive(io, buf[0..]);

    var fbr = std.Io.Reader.fixed(incoming.data);
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
