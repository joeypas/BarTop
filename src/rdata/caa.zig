const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

flags: u8,
tag: Bytes,
value: Bytes,

pub fn init() @This() {
    return .{ .flags = 0, .tag = Bytes.init(), .value = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 2) return error.EndOfStream;
    const flags = try reader.takeByte();
    const tag_len = try reader.takeByte();
    if (2 + @as(usize, tag_len) > len) return error.BadRData;
    return .{
        .flags = flags,
        .tag = Bytes.fromBorrowed(try common.takeBytes(reader, tag_len)),
        .value = Bytes.fromBorrowed(try common.takeBytes(reader, len - 2 - tag_len)),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    const tag_len = common.bytesLen(self.tag);
    if (tag_len > 255) return error.BadRData;
    try writer.writeByte(self.flags);
    try writer.writeByte(@intCast(tag_len));
    return 2 + try self.tag.encode(writer) + try self.value.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 2 + common.bytesLen(self.tag) + common.bytesLen(self.value);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .flags = self.flags, .tag = try self.tag.clone(allocator), .value = try self.value.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.tag.deinit(allocator);
    self.value.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.tag.ensureOwned(allocator);
    _ = try self.value.ensureOwned(allocator);
}

