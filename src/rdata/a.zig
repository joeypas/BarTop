const std = @import("std");
const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;

addr: std.Io.net.Ip4Address = undefined,

pub fn init() @This() {
    return .{};
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len != 4) return error.BadRData;
    const data = try reader.takeArray(4);
    return .{ .addr = .{ .bytes = data.*, .port = 0 } };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return writer.write(self.addr.bytes[0..]);
}

pub fn wireLen(_: *const @This()) usize {
    return 4;
}

pub fn clone(self: *const @This(), _: Allocator) !@This() {
    return self.*;
}

pub fn deinit(_: *@This(), _: Allocator) void {}

pub fn ensureOwned(_: *@This(), _: Allocator) !void {}

