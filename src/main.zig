pub const std = @import("std");
pub const server = @import("dns").server;

pub fn main(init: std.process.Init) !void {
    try server.run(init.io, init.gpa);
}
