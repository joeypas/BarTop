const std = @import("std");
const dns = @import("root.zig");
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

pub fn printQuestions(data: dns.MessageReader, writer: *std.Io.Writer) !void {
    var q_itr = data.questionIterator();
    while (try q_itr.next()) |question| {
        try writer.print(";{f}\n", .{question});
    }
}

pub fn printAnswers(data: dns.MessageReader, writer: *std.Io.Writer) !void {
    var an_itr = data.answerIterator();
    while (try an_itr.next()) |record| {
        try writer.print("{f}\n", .{record});
    }

    var ns_itr = data.authorityIterator();
    while (try ns_itr.next()) |record| {
        try writer.print("{f}\n", .{record});
    }

    var ad_itr = data.additionalIterator();
    while (try ad_itr.next()) |record| {
        try writer.print("{f}\n", .{record});
    }
}

pub fn printResponse(
    data: dns.MessageReader,
    server: std.Io.net.IpAddress,
    time: std.Io.Clock.Duration,
    writer: *std.Io.Writer,
) !void {
    const header = data.header;
    try writer.print(
        ";; ->>HEADER<<- opcode: {any}, status: {any}, id: {d}\n",
        .{ header.flags.op_code, header.flags.response_code, header.id },
    );
    try writer.print(
        ";; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n",
        .{ header.qd_count, header.an_count, header.ns_count, header.ar_count },
    );

    try writer.print("\n;; QUESTION SECTION:\n", .{});
    try printQuestions(data, writer);

    try writer.print("\n;; ANSWER SECTION:\n", .{});
    try printAnswers(data, writer);

    try writer.print("\n;; Query time: {d} msec\n", .{time.raw.toMilliseconds()});
    try writer.print(";; SERVER: {f}\n", .{server});
    try writer.print(";; MSG SIZE  rcvd: {d}\n", .{data.packet.len});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // var threaded = std.Io.Threaded.init(allocator, .{});
    // defer threaded.deinit();
    // const io = threaded.io();

    var rand_source = std.Random.IoSource{ .io = io };
    const rng = rand_source.interface();

    var message = dns.Message.init();
    defer message.deinit(allocator);

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

    const question = try message.addQuestion(allocator);
    try question.qname.parse(allocator, qname);
    question.*.qtype = .a;
    question.*.qclass = .in;

    var data_buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&data_buf);
    try message.encode(&writer);
    const data_len = writer.end;
    try writer.flush();
    std.debug.print("Data len: {d}\n", .{data_len});

    const addr = try std.Io.net.IpAddress.parse("1.1.1.1", 53);

    var bind_addr = try std.Io.net.IpAddress.parse("0.0.0.0", 0);
    const sock = try std.Io.net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer sock.close(io);

    const clock = std.Io.Clock.real;

    const start = std.Io.Clock.Timestamp.now(io, clock);

    try sock.send(io, &addr, data_buf[0..data_len]);
    var buf: [512]u8 = undefined;

    const incoming = try sock.receive(io, buf[0..]);

    const elapsed = std.Io.Clock.Timestamp.durationFromNow(start, io);
    const message_data = try dns.MessageReader.parse(incoming.data);

    if (message_data.header.id != message.header.id) {
        std.debug.print("EXPECTED ID: {d}, GOT: {d}\n", .{ message.header.id, message_data.header.id });
    }

    if (message_data.header.flags.response_code != .no_error) {
        std.debug.print(
            "RECEIVED ERR=> {s}\n",
            .{std.meta.fieldNames(dns.Message.Flags)[@intFromEnum(message_data.header.flags.response_code)]},
        );
    } else {
        var stdout_handle = std.Io.File.stdout();
        var write_buf: [1024]u8 = undefined;
        var stdout = stdout_handle.writer(io, &write_buf);
        try printResponse(message_data, incoming.from, elapsed, &stdout.interface);
        try stdout.flush();
    }
}
