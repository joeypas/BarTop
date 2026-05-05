const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

usage: u8,
selector: u8,
matching_type: u8,
certificate: Bytes,

pub fn init() @This() {
    return .{ .usage = 0, .selector = 0, .matching_type = 0, .certificate = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 3) return error.EndOfStream;
    return .{
        .usage = try reader.takeByte(),
        .selector = try reader.takeByte(),
        .matching_type = try reader.takeByte(),
        .certificate = Bytes.fromBorrowed(try common.takeBytes(reader, len - 3)),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeByte(self.usage);
    try writer.writeByte(self.selector);
    try writer.writeByte(self.matching_type);
    return 3 + try self.certificate.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 3 + common.bytesLen(self.certificate);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .usage = self.usage, .selector = self.selector, .matching_type = self.matching_type, .certificate = try self.certificate.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.certificate.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.certificate.ensureOwned(allocator);
}

