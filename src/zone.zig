const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const Record = @import("dns.zig").Record;

pub const Context = struct {
    origin: []const u8,
    default_ttl: u32,
};

pub fn getType(typ: []const u8) Record.Type {
    var buf: [6]u8 = undefined;
    if (std.meta.stringToEnum(Record.Type, std.ascii.lowerString(&buf, typ))) |ret| {
        return ret;
    } else {
        return Record.Type.null;
    }
}

pub fn getClass(class: []const u8) Record.Class {
    var buf: [5]u8 = undefined;
    if (std.meta.stringToEnum(Record.Class, std.ascii.lowerString(&buf, class))) |ret| {
        return ret;
    } else {
        return Record.Class.in;
    }
}

pub const Zone = struct {
    file: fs.File,
    arena: Arena,
    records: ArrayList(Record),
    context: Context,

    pub fn init(allocator: Allocator, file_name: []const u8) !Zone {
        return .{
            .file = try fs.cwd().openFile(file_name, .{}),
            .records = ArrayList(Record).init(allocator),
            .context = undefined,
            .arena = Arena.init(allocator),
        };
    }

    pub fn deinit(self: *Zone) void {
        self.file.close();
        self.records.deinit();
        self.arena.deinit();
    }

    pub fn read(self: *Zone) !void {
        var reader = self.file.reader();
        const allocator = self.arena.allocator();

        var line_maybe = try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 512);

        while (line_maybe) |line| {
            const trimmed = mem.trim(u8, line, " \t\n\r");
            if (trimmed[0] == '$') {
                var tokens = mem.splitAny(u8, trimmed, " \t");
                const first = tokens.next() orelse undefined;
                if (std.mem.eql(u8, first, "$ORIGIN")) {
                    self.context.origin = tokens.next() orelse undefined;
                } else if (std.mem.eql(u8, first, "$TTL")) {
                    self.context.default_ttl = try std.fmt.parseInt(
                        u32,
                        tokens.next() orelse undefined,
                        10,
                    );
                }
            } else {
                var tokens = std.mem.tokenize(u8, trimmed, " \t");

                if (tokens.next()) |name| {
                    std.debug.print("Name: {s}\n", .{name});
                    if (tokens.next()) |class| {
                        if (tokens.next()) |typ| {

                            // Read record data (name, ttl, class, typ)
                            const rdata = trimmed[tokens.index..];
                            try self.records.append(Record{
                                .name = name,
                                .ttl = self.context.default_ttl,
                                .class = getClass(class),
                                .type = getType(typ),
                                .rdlength = @intCast(rdata.len),
                                .rdata = rdata,
                            });
                        }
                    }
                }
            }

            line_maybe = try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 512);
        }
    }
};

test "read" {
    const allocator = std.testing.allocator;
    var zone = try Zone.init(allocator, "resource/test.zone");
    defer zone.deinit();
    try zone.read();

    std.debug.print("Size: {d}\n", .{zone.records.items.len});

    for (zone.records.items) |record| {
        std.debug.print("Record: {s}\n", .{record.name});
    }
}
