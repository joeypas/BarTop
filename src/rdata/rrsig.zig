const common = @import("common.zig");
const dnssec_types = @import("dnssec_types.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;
const Type = common.Type;
const Bytes = common.Bytes;

type_covered: Type,
algorithm: dnssec_types.Algorithm,
label_count: u8,
original_ttl: u32,
expiration: i64,
inception: i64,
key_tag: u16,
signers_name: Name,
signature: Bytes,

pub fn init() @This() {
    return .{
        .type_covered = .a,
        .algorithm = .unknown,
        .label_count = 0,
        .original_ttl = 0,
        .expiration = 0,
        .inception = 0,
        .key_tag = 0,
        .signers_name = Name.init(),
        .signature = Bytes.init(),
    };
}

pub fn decode(allocator: Allocator, reader: *Reader, len: usize) !@This() {
    const start = reader.seek;
    var out = init();
    out.type_covered = @enumFromInt(try reader.takeInt(u16, .big));
    out.algorithm = @enumFromInt(try reader.takeByte());
    out.label_count = try reader.takeByte();
    out.original_ttl = try reader.takeInt(u32, .big);
    out.expiration = try reader.takeInt(u32, .big);
    out.inception = try reader.takeInt(u32, .big);
    out.key_tag = try reader.takeInt(u16, .big);
    out.signers_name = try Name.decode(allocator, reader);

    const used = reader.seek - start;
    if (used > len) return error.EndOfStream;
    out.signature = Bytes.fromBorrowed(try common.takeBytes(reader, len - used));
    return out;
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, @intFromEnum(self.type_covered), .big);
    try writer.writeByte(@intFromEnum(self.algorithm));
    try writer.writeByte(self.label_count);
    try writer.writeInt(u32, self.original_ttl, .big);
    try writer.writeInt(u32, @intCast(self.expiration), .big);
    try writer.writeInt(u32, @intCast(self.inception), .big);
    try writer.writeInt(u16, self.key_tag, .big);
    return 18 + try self.signers_name.encode(writer) + try self.signature.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 18 + self.signers_name.getLen() + common.bytesLen(self.signature);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{
        .type_covered = self.type_covered,
        .algorithm = self.algorithm,
        .label_count = self.label_count,
        .original_ttl = self.original_ttl,
        .expiration = self.expiration,
        .inception = self.inception,
        .key_tag = self.key_tag,
        .signers_name = try self.signers_name.clone(allocator),
        .signature = try self.signature.clone(allocator),
    };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.signers_name.deinit(allocator);
    self.signature.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.signers_name.ensureOwned(allocator);
    _ = try self.signature.ensureOwned(allocator);
}
