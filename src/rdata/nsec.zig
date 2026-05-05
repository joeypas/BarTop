const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;
const Bytes = common.Bytes;

next_name: Name,
type_bitmap: Bytes,

pub fn init() @This() {
    return .{ .next_name = Name.init(), .type_bitmap = Bytes.init() };
}

pub fn decode(allocator: Allocator, reader: *Reader, len: usize) !@This() {
    const start = reader.seek;
    var out = init();
    out.next_name = try Name.decode(allocator, reader);
    const used = reader.seek - start;
    if (used > len) return error.EndOfStream;
    out.type_bitmap = Bytes.fromBorrowed(try common.takeBytes(reader, len - used));
    return out;
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return try self.next_name.encode(writer) + try self.type_bitmap.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return self.next_name.getLen() + common.bytesLen(self.type_bitmap);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .next_name = try self.next_name.clone(allocator), .type_bitmap = try self.type_bitmap.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.next_name.deinit(allocator);
    self.type_bitmap.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.next_name.ensureOwned(allocator);
    _ = try self.type_bitmap.ensureOwned(allocator);
}

