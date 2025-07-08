pub const std = @import("std");
pub const server = @import("dns").server;

pub fn main() !void {
    try server.run();
}
