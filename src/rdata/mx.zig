const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;

preference: u16,
exchange: Name,

pub fn init() @This() {
    return .{ .preference = 0, .exchange = Name.init() };
}

pub fn decode(allocator: Allocator, reader: *Reader, _: usize) !@This() {
    return .{
        .preference = try reader.takeInt(u16, .big),
        .exchange = try Name.decode(allocator, reader),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.preference, .big);
    return 2 + try self.exchange.encode(writer);
}

pub fn wireLen(self: *const @This()) usize {
    return 2 + self.exchange.getLen();
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{ .preference = self.preference, .exchange = try self.exchange.clone(allocator) };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.exchange.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.exchange.ensureOwned(allocator);
}

