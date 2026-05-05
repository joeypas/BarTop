const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;

priority: u16,
weight: u16,
port: u16,
target: Name,

pub fn init() @This() {
    return .{ .priority = 0, .weight = 0, .port = 0, .target = Name.init() };
}

pub fn decode(allocator: Allocator, reader: *Reader, _: usize) !@This() {
    return .{
        .priority = try reader.takeInt(u16, .big),
        .weight = try reader.takeInt(u16, .big),
        .port = try reader.takeInt(u16, .big),
        .target = try Name.decode(allocator, reader),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.priority, .big);
    try writer.writeInt(u16, self.weight, .big);
    try writer.writeInt(u16, self.port, .big);
    return 6 + try self.target.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 6 + self.target.getLen();
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{
        .priority = self.priority,
        .weight = self.weight,
        .port = self.port,
        .target = try self.target.clone(allocator),
    };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.target.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.target.ensureOwned(allocator);
}

