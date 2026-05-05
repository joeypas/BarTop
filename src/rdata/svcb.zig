const common = @import("common.zig");

const std = @import("std");
const Reader = common.Reader;
const Writer = common.Writer;
const Allocator = common.Allocator;
const ArrayList = common.ArrayList;
const Name = common.Name;

const SvcParam = struct {
    key: u16,
    value: []const u8,
};

const SvcParamBlock = union(enum) {
    borrowed: []const u8,
    owned: ArrayList(u8),
};

priority: u16,
target: Name,
params_block: SvcParamBlock,

pub fn init() @This() {
    return .{
        .priority = 0,
        .target = Name.init(),
        .params_block = .{ .owned = .empty },
    };
}

pub fn decode(allocator: Allocator, reader: *Reader, len: usize) !@This() {
    const start = reader.seek;
    var out = init();
    out.priority = try reader.takeInt(u16, .big);
    out.target = try Name.decode(allocator, reader);

    const used = reader.seek - start;
    if (used > len) return error.EndOfStream;

    const params = try common.takeBytes(reader, len - used);
    try validateSvcParamBlock(params);
    out.params_block = .{ .borrowed = params };
    return out;
}

pub fn encode(self: *const @This(), writer: *Writer) !usize {
    try writer.writeInt(u16, self.priority, .big);
    return 2 + try self.target.encode(writer) + try writer.write(self.paramsBytes());
}

pub fn wireLen(self: *const @This()) usize {
    return 2 + self.target.getLen() + self.paramsBytes().len;
}

pub fn clone(self: *const @This(), allocator: Allocator) !@This() {
    var out = init();
    out.priority = self.priority;
    out.target = try self.target.clone(allocator);
    out.params_block = .{ .owned = try common.cloneBytes(self.paramsBytes(), allocator) };
    return out;
}

pub fn deinit(self: *@This(), allocator: Allocator) void {
    self.target.deinit(allocator);
    switch (self.params_block) {
        .borrowed => {},
        .owned => |*list| list.deinit(allocator),
    }
    self.* = init();
}

pub fn ensureOwned(self: *@This(), allocator: Allocator) !void {
    try self.target.ensureOwned(allocator);
    switch (self.params_block) {
        .owned => {},
        .borrowed => |bytes| self.params_block = .{ .owned = try common.cloneBytes(bytes, allocator) },
    }
}

fn paramsBytes(self: *const @This()) []const u8 {
    return switch (self.params_block) {
        .borrowed => |bytes| bytes,
        .owned => |list| list.items,
    };
}

fn validateSvcParamBlock(block: []const u8) !void {
    var offset: usize = 0;
    while (offset < block.len) {
        if (block.len - offset < 4) return error.BadRData;
        const key = std.mem.readInt(u16, block[offset..][0..2], .big);
        const value_len = std.mem.readInt(u16, block[offset + 2 ..][0..2], .big);
        const value_start = offset + 4;
        const value_end = value_start + value_len;
        if (value_end > block.len) return error.BadRData;
        try validateSvcParam(key, block[value_start..value_end]);
        offset = value_end;
    }
}

fn validateSvcParam(key: u16, value: []const u8) !void {
    switch (key) {
        0 => if (value.len % 2 != 0) return error.BadRData,
        1 => {
            var i: usize = 0;
            while (i < value.len) {
                const l = value[i];
                i += 1;
                if (i + l > value.len) return error.BadRData;
                i += l;
            }
        },
        2 => if (value.len != 0) return error.BadRData,
        3 => if (value.len != 2) return error.BadRData,
        4 => if (value.len % 4 != 0) return error.BadRData,
        6 => if (value.len % 16 != 0) return error.BadRData,
        else => {},
    }
}

