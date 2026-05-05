const std = @import("std");

pub const Reader = std.Io.Reader;
pub const Writer = std.Io.Writer;
pub const Allocator = std.mem.Allocator;
pub const ArrayList = std.ArrayList;
pub const rr = @import("../rr.zig");
pub const Name = rr.Name;
pub const Type = rr.Type;
pub const Bytes = @import("bytes.zig").Bytes;

pub fn takeBytes(reader: *Reader, size: usize) ![]const u8 {
    const start = reader.seek;
    const end = start + size;
    if (end > reader.end) return error.EndOfStream;
    reader.seek = end;
    return reader.buffer[start..end];
}

pub fn cloneBytes(bytes: []const u8, allocator: Allocator) !ArrayList(u8) {
    var out = try ArrayList(u8).initCapacity(allocator, bytes.len);
    out.appendSliceAssumeCapacity(bytes);
    return out;
}

pub fn encodeCharacterString(bytes: []const u8, writer: *Writer) !usize {
    if (bytes.len > 255) return error.BadRData;
    try writer.writeByte(@intCast(bytes.len));
    return 1 + try writer.write(bytes);
}

pub fn decodeCharacterString(reader: *Reader, end: usize) ![]const u8 {
    if (reader.seek >= end) return error.EndOfStream;
    const len = try reader.takeByte();
    if (reader.seek + len > end) return error.EndOfStream;
    return takeBytes(reader, len);
}

pub fn bytesLen(bytes: Bytes) usize {
    var copy = bytes;
    return copy.asSlice().len;
}
