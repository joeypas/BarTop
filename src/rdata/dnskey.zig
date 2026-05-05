const common = @import("common.zig");
const dnssec_types = @import("dnssec_types.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

flags: u16,
protocol: dnssec_types.KeyProtocol,
algorithm: dnssec_types.Algorithm,
public_key: Bytes,

pub fn init() @This() {
    return .{ .flags = 0, .protocol = .dnssec, .algorithm = .unknown, .public_key = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    if (len < 4) return error.EndOfStream;
    return .{
        .flags = try reader.takeInt(u16, .big),
        .protocol = @enumFromInt(try reader.takeByte()),
        .algorithm = @enumFromInt(try reader.takeByte()),
        .public_key = Bytes.fromBorrowed(try common.takeBytes(reader, len - 4)),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.flags, .big);
    try writer.writeByte(@intFromEnum(self.protocol));
    try writer.writeByte(@intFromEnum(self.algorithm));
    return 4 + try self.public_key.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 4 + common.bytesLen(self.public_key);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .flags = self.flags, .protocol = self.protocol, .algorithm = self.algorithm, .public_key = try self.public_key.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.public_key.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.public_key.ensureOwned(allocator);
}
