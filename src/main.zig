pub const std = @import("std");
pub const server = @import("stub_resolver.zig");

pub fn main() !void {
    try server.run();
}
