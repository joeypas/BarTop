const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const Record = @import("dns.zig").Record;

pub const Context = struct {
    origin: [][]const u8,
    default_ttl: u32,
    class: Record.Class,
};

pub const State = enum {
    ttl,
    class,
    type,
    rdata,
    done,
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
    state: State,
    last: [][]const u8,

    pub fn init(allocator: Allocator, file_name: []const u8) !Zone {
        return .{
            .file = try fs.cwd().openFile(file_name, .{}),
            .records = ArrayList(Record).init(allocator),
            .context = undefined,
            .state = .ttl,
            .last = undefined,
            .arena = Arena.init(allocator),
        };
    }

    pub fn deinit(self: *Zone) void {
        self.file.close();
        self.records.deinit();
        self.arena.allocator().free(self.context.origin);
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
                    var names = ArrayList([]const u8).init(allocator);
                    var name_split = std.mem.splitAny(
                        u8,
                        tokens.next() orelse undefined,
                        ".",
                    );
                    while (name_split.next()) |n| {
                        try names.append(n);
                    }
                    self.context.origin = try names.toOwnedSlice();
                } else if (std.mem.eql(u8, first, "$TTL")) {
                    self.context.default_ttl = try std.fmt.parseInt(
                        u32,
                        trimmed[tokens.index.?..],
                        10,
                    );
                }
            } else {
                try self.records.append(try self.handleLine(line));
            }

            line_maybe = try reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 512);
        }

        if (line_maybe) |line| {
            allocator.free(line);
        }
    }

    fn handleLine(self: *Zone, line: []u8) !Record {
        self.state = .ttl;
        const allocator = self.arena.allocator();
        var index: usize = 0;
        var ret: Record = undefined;
        var found_ttl = false;
        var found_class = false;

        if (std.ascii.isWhitespace(line[0])) {
            ret.name = self.last;
        } else {
            var tokens = std.mem.tokenize(u8, line, " \t");
            var name_split = std.mem.splitAny(u8, tokens.next().?, ".");
            var names = ArrayList([]const u8).init(allocator);
            if (name_split.peek()) |first| {
                if (std.mem.eql(u8, first, "@")) {
                    try names.appendSlice(self.context.origin);
                } else {
                    while (name_split.next()) |n| {
                        try names.append(n);
                    }
                }
            }
            index += tokens.index;
            ret.name = try names.toOwnedSlice();
            self.last = ret.name;
        }

        const trimmed = mem.trim(u8, line[index..], " ");
        var tokens = std.mem.tokenize(u8, trimmed, " \t");

        while (tokens.peek()) |token| {
            if (self.state == .done) break;
            blk: {
                switch (self.state) {
                    .ttl => {
                        if (!std.ascii.isDigit(token[0])) {
                            if (found_class) {
                                _ = tokens.next();
                                self.state = .type;
                            } else {
                                self.state = .class;
                            }
                            break :blk;
                        }
                        found_ttl = true;
                        ret.ttl = try std.fmt.parseInt(u32, token, 10);
                        _ = tokens.next();
                        if (found_class) {
                            self.state = .type;
                            ret.class = self.context.class;
                            break :blk;
                        }
                        self.state = .class;
                        break :blk;
                    },
                    .class => {
                        const c = getClass(token);
                        self.context.class = c;
                        ret.class = c;
                        found_class = true;
                        if (found_ttl) {
                            _ = tokens.next();
                            self.state = .type;
                            break :blk;
                        }
                        ret.ttl = self.context.default_ttl;
                        self.state = .ttl;
                        break :blk;
                    },
                    .type => {
                        ret.type = getType(token);
                        self.state = .rdata;
                        _ = tokens.next();
                        break :blk;
                    },
                    .rdata => {
                        var rdata = ArrayList(u8).init(allocator);
                        std.debug.print("rdata: {s}\n", .{trimmed[tokens.index..]});
                        try rdata.appendSlice(trimmed[tokens.index..]);
                        ret.rdata = try rdata.toOwnedSlice();
                        _ = tokens.next();
                        self.state = .done;
                    },
                    else => unreachable,
                }
            }
        }
        return ret;
    }

    pub fn getRecords(self: *Zone, t: Record.Type, c: Record.Class, allocator: Allocator) ![]Record {
        var ret = ArrayList(Record).init(allocator);
        errdefer ret.deinit();

        for (self.records.items) |record| {
            if (record.type == t and record.class == c) {
                try ret.append(record);
            }
        }
        return ret.toOwnedSlice();
    }
};

test "read" {
    const allocator = std.testing.allocator;
    var zone = try Zone.init(allocator, "resource/test.zone");
    defer zone.deinit();
    try zone.read();

    std.debug.print("Size: {d}\n", .{zone.records.items.len});

    for (zone.records.items) |record| {
        std.debug.print(
            "Record: ( {s}, {d}, {any}, {any}, {s} )\n",
            .{ record.name, record.ttl, record.class, record.type, record.rdata },
        );
    }
}
