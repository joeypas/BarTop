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
hash: Bytes,
type_bitmap: Bytes,

pub fn init() @This() {
    return .{ .hash_algorithm = .unknown, .flags = 0, .iterations = 0, .salt = Bytes.init(), .hash = Bytes.init(), .type_bitmap = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    const start = reader.seek;
    var out = init();
    out.hash_algorithm = @enumFromInt(try reader.takeByte());
    out.flags = try reader.takeByte();
    out.iterations = try reader.takeInt(u16, .big);
    const salt_len = try reader.takeByte();
    out.salt = Bytes.fromBorrowed(try common.takeBytes(reader, salt_len));
    const hash_len = try reader.takeByte();
    out.hash = Bytes.fromBorrowed(try common.takeBytes(reader, hash_len));
    const used = reader.seek - start;
    if (used > len) return error.EndOfStream;
    out.type_bitmap = Bytes.fromBorrowed(try common.takeBytes(reader, len - used));
    return out;
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    const salt_len = common.bytesLen(self.salt);
    const hash_len = common.bytesLen(self.hash);
    if (salt_len > 255 or hash_len > 255) return error.BadRData;
    try writer.writeByte(@intFromEnum(self.hash_algorithm));
    try writer.writeByte(self.flags);
    try writer.writeInt(u16, self.iterations, .big);
    try writer.writeByte(@intCast(salt_len));
    _ = try self.salt.encode(writer);
    try writer.writeByte(@intCast(hash_len));
    _ = try self.hash.encode(writer);
    return 6 + salt_len + hash_len + try self.type_bitmap.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 6 + common.bytesLen(self.salt) + common.bytesLen(self.hash) + common.bytesLen(self.type_bitmap);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{
        .hash_algorithm = self.hash_algorithm,
        .flags = self.flags,
        .iterations = self.iterations,
        .salt = try self.salt.clone(allocator),
        .hash = try self.hash.clone(allocator),
        .type_bitmap = try self.type_bitmap.clone(allocator),
    };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.salt.deinit(allocator);
    self.hash.deinit(allocator);
    self.type_bitmap.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.salt.ensureOwned(allocator);
    _ = try self.hash.ensureOwned(allocator);
    _ = try self.type_bitmap.ensureOwned(allocator);
}
