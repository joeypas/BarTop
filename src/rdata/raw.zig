const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

bytes: Bytes,

pub fn init() @This() {
    return .{ .bytes = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    return .{ .bytes = Bytes.fromBorrowed(try common.takeBytes(reader, len)) };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return self.bytes.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return common.bytesLen(self.bytes);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .bytes = try self.bytes.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.bytes.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.bytes.ensureOwned(allocator);
}

