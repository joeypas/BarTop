const common = @import("common.zig");
const dnssec_types = @import("dnssec_types.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

hash_algorithm: dnssec_types.NSEC3HashAlgorithm,
flags: u8,
iterations: u16,
salt: Bytes,

pub fn init() @This() {
    return .{ .hash_algorithm = .unknown, .flags = 0, .iterations = 0, .salt = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 5) return error.EndOfStream;
    const hash_algorithm: dnssec_types.NSEC3HashAlgorithm = @enumFromInt(try reader.takeByte());
    const flags = try reader.takeByte();
    const iterations = try reader.takeInt(u16, .big);
    const salt_len = try reader.takeByte();
    if (salt_len != len - 5) return error.BadRData;
    return .{ .hash_algorithm = hash_algorithm, .flags = flags, .iterations = iterations, .salt = Bytes.fromBorrowed(try common.takeBytes(reader, salt_len)) };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    const salt_len = common.bytesLen(self.salt);
    if (salt_len > 255) return error.BadRData;
    try writer.writeByte(@intFromEnum(self.hash_algorithm));
    try writer.writeByte(self.flags);
    try writer.writeInt(u16, self.iterations, .big);
    try writer.writeByte(@intCast(salt_len));
    return 5 + try self.salt.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 5 + common.bytesLen(self.salt);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .hash_algorithm = self.hash_algorithm, .flags = self.flags, .iterations = self.iterations, .salt = try self.salt.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.salt.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.salt.ensureOwned(allocator);
}
