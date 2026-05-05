const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

algorithm: u8,
fingerprint_type: u8,
fingerprint: Bytes,

pub fn init() @This() {
    return .{ .algorithm = 0, .fingerprint_type = 0, .fingerprint = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 2) return error.EndOfStream;
    return .{
        .algorithm = try reader.takeByte(),
        .fingerprint_type = try reader.takeByte(),
        .fingerprint = Bytes.fromBorrowed(try common.takeBytes(reader, len - 2)),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeByte(self.algorithm);
    try writer.writeByte(self.fingerprint_type);
    return 2 + try self.fingerprint.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 2 + common.bytesLen(self.fingerprint);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .algorithm = self.algorithm, .fingerprint_type = self.fingerprint_type, .fingerprint = try self.fingerprint.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.fingerprint.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.fingerprint.ensureOwned(allocator);
}

