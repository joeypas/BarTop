const common = @import("common.zig");
const dnssec_types = @import("dnssec_types.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

key_tag: u16,
algorithm: dnssec_types.Algorithm,
digest_type: dnssec_types.DigestType,
digest: Bytes,

pub fn init() @This() {
    return .{ .key_tag = 0, .algorithm = .unknown, .digest_type = .unknown, .digest = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 4) return error.EndOfStream;
    return .{
        .key_tag = try reader.takeInt(u16, .big),
        .algorithm = @enumFromInt(try reader.takeByte()),
        .digest_type = @enumFromInt(try reader.takeByte()),
        .digest = Bytes.fromBorrowed(try common.takeBytes(reader, len - 4)),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.key_tag, .big);
    try writer.writeByte(@intFromEnum(self.algorithm));
    try writer.writeByte(@intFromEnum(self.digest_type));
    return 4 + try self.digest.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 4 + common.bytesLen(self.digest);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .key_tag = self.key_tag, .algorithm = self.algorithm, .digest_type = self.digest_type, .digest = try self.digest.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.digest.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.digest.ensureOwned(allocator);
}
