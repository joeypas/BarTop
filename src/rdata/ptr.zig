const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;

name: Name,

pub fn init() @This() {
    return .{ .name = Name.init() };
}

pub fn decode(allocator: Allocator, reader: *Reader, _: usize) !@This() {
    return .{ .name = try Name.decode(allocator, reader) };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    return self.name.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return self.name.getLen();
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .name = try self.name.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.name.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.name.ensureOwned(allocator);
}

