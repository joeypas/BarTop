const std = @import("std");

const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

pub const Bytes = union(enum) {
    borrowed: []const u8,
    owned: ArrayList(u8),

    pub fn init() Bytes {
        return .{ .owned = .empty };
    }

    pub fn fromBorrowed(bytes: []const u8) Bytes {
        return .{ .borrowed = bytes };
    }

    pub fn deinit(self: *Bytes, allocator: Allocator) void {
        switch (self.*) {
            .borrowed => {},
            .owned => |*list| list.deinit(allocator),
        }
        self.* = init();
    }

    pub fn clone(self: *const Bytes, allocator: Allocator) !Bytes {
        const data = self.asSlice();
        var out = try ArrayList(u8).initCapacity(allocator, data.len);
        out.appendSliceAssumeCapacity(data);
        return .{ .owned = out };
    }

    pub fn appendSlice(self: *Bytes, allocator: Allocator, data: []const u8) !void {
        var list = try self.ensureOwned(allocator);
        try list.appendSlice(allocator, data);
    }

    pub fn parse(self: *Bytes, allocator: Allocator, data: []const u8) !void {
        try self.appendSlice(allocator, data);
    }

    pub fn asSlice(self: *const Bytes) []const u8 {
        return switch (self.*) {
            .borrowed => |bytes| bytes,
            .owned => |list| list.items,
        };
    }

    pub fn getLen(self: *const Bytes) u16 {
        return @intCast(self.asSlice().len);
    }

    pub fn encode(self: *const Bytes, writer: *Writer) !usize {
        return writer.write(self.asSlice());
    }

    pub fn format(self: Bytes, writer: *std.Io.Writer) !void {
        try writer.print("{s}", .{self.asSlice()});
    }

    pub fn ensureOwned(self: *Bytes, allocator: Allocator) !*ArrayList(u8) {
        switch (self.*) {
            .owned => |*list| return list,
            .borrowed => |bytes| {
                var out = try ArrayList(u8).initCapacity(allocator, bytes.len);
                out.appendSliceAssumeCapacity(bytes);
                self.* = .{ .owned = out };
                return &self.owned;
            },
        }
    }
};

