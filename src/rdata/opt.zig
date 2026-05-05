const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

options: Bytes,

pub fn init() @This() {
    return .{ .options = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    return .{ .options = Bytes.fromBorrowed(try common.takeBytes(reader, len)) };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return self.options.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return common.bytesLen(self.options);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .options = try self.options.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.options.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.options.ensureOwned(allocator);
}

