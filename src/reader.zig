const std = @import("std");
const bigToNative = std.mem.bigToNative;

const Reader = @This();

bytes: []const u8,
index: usize,

pub fn init(bytes: []const u8) Reader {
    return .{
        .bytes = bytes,
        .index = 0,
    };
}

pub fn read(self: *Reader, comptime T: type) !T {
    return switch (comptime @typeInfo(T)) {
        .Int => try self.readInt(T),
        .Array => |array| {
            var arr: [array.len]array.child = undefined;
            var index: usize = 0;
            while (index < array.len) : (index += 1) {
                arr[index] = try self.read(array.child);
            }
            return arr;
        },
        .Struct => try self.readStruct(T),
        else => @compileError("Unsupported type"),
    };
}

fn readInt(self: *Reader, comptime T: type) !T {
    const size = @sizeOf(T);
    if (self.index + size > self.bytes.len) return error.EndOfStream;

    const slice = self.bytes[self.index .. self.index + size];
    const value: T = std.mem.bytesToValue(T, slice);
    self.index += size;
    return bigToNative(T, value);
}

fn readStruct(self: *Reader, comptime T: type) !T {
    const fields = std.meta.fields(T);

    var item: T = undefined;
    inline for (fields) |field| {
        @field(item, field.name) = try self.read(field.type);
    }

    return item;
}
