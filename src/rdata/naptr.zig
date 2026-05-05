const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;
const Bytes = common.Bytes;

order: u16,
preference: u16,
flags: Bytes,
services: Bytes,
regexp: Bytes,
replacement: Name,

pub fn init() @This() {
    return .{
        .order = 0,
        .preference = 0,
        .flags = Bytes.init(),
        .services = Bytes.init(),
        .regexp = Bytes.init(),
        .replacement = Name.init(),
    };
}

pub fn decode(allocator: Allocator, reader: *Reader, len: usize) !@This() {
    const end = reader.seek + len;
    if (end > reader.end) return error.EndOfStream;
    var out = init();
    out.order = try reader.takeInt(u16, .big);
    out.preference = try reader.takeInt(u16, .big);
    out.flags = Bytes.fromBorrowed(try common.decodeCharacterString(reader, end));
    out.services = Bytes.fromBorrowed(try common.decodeCharacterString(reader, end));
    out.regexp = Bytes.fromBorrowed(try common.decodeCharacterString(reader, end));
    out.replacement = try Name.decode(allocator, reader);
    if (reader.seek != end) return error.BadRData;
    return out;
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.order, .big);
    try writer.writeInt(u16, self.preference, .big);
    var len: usize = 4;
    len += try common.encodeCharacterString(self.flags.asSlice(), writer);
    len += try common.encodeCharacterString(self.services.asSlice(), writer);
    len += try common.encodeCharacterString(self.regexp.asSlice(), writer);
    len += try self.replacement.encode(writer);
    return len;
}

pub fn wireLen(self: *const @This()) usize {
    return 7 + common.bytesLen(self.flags) + common.bytesLen(self.services) + common.bytesLen(self.regexp) + self.replacement.getLen();
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{
        .order = self.order,
        .preference = self.preference,
        .flags = try self.flags.clone(allocator),
        .services = try self.services.clone(allocator),
        .regexp = try self.regexp.clone(allocator),
        .replacement = try self.replacement.clone(allocator),
    };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.flags.deinit(allocator);
    self.services.deinit(allocator);
    self.regexp.deinit(allocator);
    self.replacement.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.flags.ensureOwned(allocator);
    _ = try self.services.ensureOwned(allocator);
    _ = try self.regexp.ensureOwned(allocator);
    try self.replacement.ensureOwned(allocator);
}

