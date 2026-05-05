const common = @import("common.zig");

const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const Name = common.Name;

mname: Name,
rname: Name,
serial: u32,
refresh: u32,
retry: u32,
expire: u32,
minimum: u32,

pub fn init() @This() {
    return .{
        .mname = Name.init(),
        .rname = Name.init(),
        .serial = 0,
        .refresh = 0,
        .retry = 0,
        .expire = 0,
        .minimum = 0,
    };
}

pub fn decode(allocator: Allocator, reader: *Reader, _: usize) !@This() {
    return .{
        .mname = try Name.decode(allocator, reader),
        .rname = try Name.decode(allocator, reader),
        .serial = try reader.takeInt(u32, .big),
        .refresh = try reader.takeInt(u32, .big),
        .retry = try reader.takeInt(u32, .big),
        .expire = try reader.takeInt(u32, .big),
        .minimum = try reader.takeInt(u32, .big),
    };
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    var len = try self.mname.encode(writer);
    len += try self.rname.encode(writer);
    try writer.writeInt(u32, self.serial, .big);
    try writer.writeInt(u32, self.refresh, .big);
    try writer.writeInt(u32, self.retry, .big);
    try writer.writeInt(u32, self.expire, .big);
    try writer.writeInt(u32, self.minimum, .big);
    return len + 20;
}

pub fn wireLen(self: *const @This()) usize {
    return self.mname.getLen() + self.rname.getLen() + 20;
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    return .{
        .mname = try self.mname.clone(allocator),
        .rname = try self.rname.clone(allocator),
        .serial = self.serial,
        .refresh = self.refresh,
        .retry = self.retry,
        .expire = self.expire,
        .minimum = self.minimum,
    };
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.mname.deinit(allocator);
    self.rname.deinit(allocator);
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.mname.ensureOwned(allocator);
    try self.rname.ensureOwned(allocator);
}

