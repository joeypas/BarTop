const std = @import("std");
const resolver = @import("resolver.zig");

pub fn main(init: std.process.Init) !void {
    try resolver.run(init.io, init.gpa);
}
