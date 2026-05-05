const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Bytes = common.Bytes;

strings: Bytes,

pub fn init() @This() {
    return .{ .strings = Bytes.init() };
}

pub fn decode(_: Allocator, reader: *Reader, len: usize) !@This() {
    const bytes = try common.takeBytes(reader, len);
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const str_len = bytes[cursor];
        cursor += 1;
        if (cursor + str_len > bytes.len) return error.BadRData;
        cursor += str_len;
    }
    return .{ .strings = Bytes.fromBorrowed(bytes) };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return self.strings.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return common.bytesLen(self.strings);
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .strings = try self.strings.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.strings.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    _ = try self.strings.ensureOwned(allocator);
}

