const std = @import("std");
const Message = @import("message.zig");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

pub const Zone = struct {
    soa: Message.Record,
    records: ArrayList(Message.Record),
    allocator: Allocator,

    pub fn init(allocator: Allocator) Zone {
        var soa = Message.Record.init(allocator, .soa);
        soa.ref = true;
        return Zone{
            .soa = soa,
            .records = ArrayList(Message.Record).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Zone) void {
        self.soa.ref = false;
        self.soa.deinit();
        for (self.records.items) |*record| {
            record.deinit();
        }
        self.records.deinit();
    }

    pub fn getSoa(self: *Zone) *Message.Record {
        return &self.soa;
    }

    /// Record becomes managed by the zone, it is freed on deinit
    pub fn addRecord(self: *Zone, record: Message.Record) !void {
        try self.records.append(record);
    }

    /// Records become managed by the zone, they are freed on deinit
    pub fn addRecords(self: *Zone, records: []Message.Record) !void {
        try self.records.appendSlice(records);
    }

    pub fn getRecords(self: *Zone) []const Message.Record {
        return self.records.items;
    }

    // This is a mess but it works for now
    pub fn parseFromString(allocator: Allocator, content: []const u8) !Zone {
        var zone = Zone.init(allocator);
        errdefer zone.deinit();

        var lines = std.mem.splitAny(u8, content, "\n\r");
        var origin: ?[]const u8 = null;
        var default_ttl: u32 = 86400;
        var last_name: ?[]const u8 = null;
        var multi_line_buffer = ArrayList(u8).init(allocator);
        defer multi_line_buffer.deinit();
        var in_parentheses = false;

        while (lines.next()) |line| {
            var trimmed = std.mem.trim(u8, line, " \t");

            // remove inline comments
            if (std.mem.indexOf(u8, trimmed, ";")) |comment_pos| {
                trimmed = std.mem.trim(u8, trimmed[0..comment_pos], " \t");
            }

            // skip empty lines after comment removal
            if (trimmed.len == 0) continue;

            // handle multi-line records with parentheses
            if (std.mem.indexOf(u8, trimmed, "(") != null) {
                in_parentheses = true;
                // remove parentheses and add to buffer
                const cleaned = std.mem.replaceOwned(u8, allocator, trimmed, "(", "") catch trimmed;
                defer if (cleaned.ptr != trimmed.ptr) allocator.free(cleaned);

                // check if this is actually a fake multi-line record
                if (std.mem.indexOf(u8, cleaned, ")")) |idx| {
                    try processRecord(allocator, &zone, cleaned[0..idx], &origin, &default_ttl, &last_name);
                    in_parentheses = false;
                    continue;
                }
                try multi_line_buffer.appendSlice(cleaned);
                try multi_line_buffer.append(' ');
                continue;
            }

            if (in_parentheses) {
                if (std.mem.indexOf(u8, trimmed, ")") != null) {
                    const cleaned = std.mem.replaceOwned(u8, allocator, trimmed, ")", "") catch trimmed;
                    defer if (cleaned.ptr != trimmed.ptr) allocator.free(cleaned);

                    try multi_line_buffer.appendSlice(cleaned);
                    if (std.mem.indexOf(u8, trimmed, ";")) |comment_pos| {
                        trimmed = std.mem.trim(u8, trimmed[0..comment_pos], " \t");
                    }
                    const complete_line = std.mem.trim(u8, multi_line_buffer.items, " \t");
                    try processRecord(allocator, &zone, complete_line, &origin, &default_ttl, &last_name);

                    multi_line_buffer.clearRetainingCapacity();
                    in_parentheses = false;
                } else {
                    try multi_line_buffer.appendSlice(trimmed);
                    try multi_line_buffer.append(' ');
                }
                continue;
            }

            try processRecord(allocator, &zone, trimmed, &origin, &default_ttl, &last_name);
        }

        return zone;
    }

    /// Parse DNS zone file from file
    pub fn parseFromFile(allocator: Allocator, file_path: []const u8) !Zone {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(content);

        return parseFromString(allocator, content);
    }

    fn processRecord(
        allocator: Allocator,
        zone: *Zone,
        line: []const u8,
        origin: *?[]const u8,
        default_ttl: *u32,
        last_name: *?[]const u8,
    ) !void {
        // Handle directives
        if (line[0] == '$') {
            try parseDirective(line, origin, default_ttl);
            return;
        }

        var record = try parseResourceRecord(allocator, line, origin.*, default_ttl.*, last_name);
        errdefer record.deinit();
        if (record.type == .soa) {
            zone.soa.deinit();
            zone.soa = record;
            zone.soa.ref = true;
        } else {
            try zone.addRecord(record);
        }
    }
};

fn parseResourceRecord(allocator: Allocator, line: []const u8, origin: ?[]const u8, default_ttl: u32, last_name: *?[]const u8) !Message.Record {
    var tokens = try tokenize(allocator, line);
    defer tokens.deinit();

    const rec = try collectFields(origin, last_name.*, default_ttl, tokens);
    defer allocator.free(rec.data);

    var record = Message.Record.init(allocator, rec.type);
    errdefer record.deinit();

    last_name.* = rec.name;
    try record.name.fromString(rec.name);

    // rhHandle relative host name
    if (record.name.labels.items.len <= 1) {
        try record.name.fromString(origin.?);
    }
    record.ttl = rec.ttl;
    record.class = rec.class;

    // ew
    record.rdata.deinit();
    record.rdata = Message.RData.fromString(rec.type, allocator, rec.data) catch |err| {
        std.debug.print("Err at: {s}\n", .{rec.data});
        return err;
    };

    return record;
}

fn parseDirective(line: []const u8, origin: *?[]const u8, default_ttl: *u32) !void {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");
    const directive = tokens.next() orelse return;

    if (std.mem.eql(u8, directive, "$ORIGIN")) {
        if (tokens.next()) |value| {
            origin.* = value;
        } else {
            return error.MissingOrigin;
        }
    } else if (std.mem.eql(u8, directive, "$TTL")) {
        if (tokens.next()) |value| {
            default_ttl.* = try std.fmt.parseInt(u32, value, 10);
        }
    }
}

const TokenType = enum {
    name,
    ttl,
    class,
    type,
    data,
};

const Token = union(TokenType) {
    name: ?[]const u8,
    ttl: u32,
    class: Message.Class,
    type: Message.Type,
    data: []const u8,
};

fn tokenize(allocator: Allocator, line: []const u8) !ArrayList(Token) {
    var ret = ArrayList(Token).init(allocator);
    errdefer ret.deinit();
    var tokens = std.mem.tokenizeAny(u8, line, " \t");

    var data_buf = ArrayList(u8).init(allocator);
    errdefer data_buf.deinit();

    var got_type = false;
    var first = true;
    while (tokens.next()) |tok| {
        var buf: [255]u8 = undefined;
        if (std.ascii.isDigit(tok[0]) and got_type == false) {
            const ttl = try std.fmt.parseInt(u32, tok, 10);
            try ret.append(Token{ .ttl = ttl });
        } else if (tok[0] == '@') {
            try ret.append(Token{ .name = null });
        } else if (std.meta.stringToEnum(Message.Class, std.ascii.lowerString(&buf, tok))) |class| {
            try ret.append(Token{ .class = class });
        } else if (std.meta.stringToEnum(Message.Type, std.ascii.lowerString(&buf, tok))) |typ| {
            // edge case where relative host name is also a type
            if (!first) {
                try ret.append(Token{ .type = typ });
                got_type = true;
            } else {
                try ret.append(Token{ .name = tok });
            }
        } else {
            if (got_type) {
                try data_buf.appendSlice(tok);
                try data_buf.append(' ');
            } else {
                try ret.append(Token{ .name = tok });
            }
        }
        first = false;
    }

    try ret.append(Token{ .data = try data_buf.toOwnedSlice() });

    return ret;
}

const Rec = struct {
    name: []const u8,
    ttl: u32,
    class: Message.Class,
    type: Message.Type,
    data: []const u8,
};

fn collectFields(origin: ?[]const u8, prev_name: ?[]const u8, default_ttl: u32, tokens: ArrayList(Token)) !Rec {
    const NullRec = struct {
        name: ?[]const u8 = null,
        ttl: ?u32 = null,
        class: ?Message.Class = null,
        type: ?Message.Type = null,
        data: ?[]const u8 = null,
    };
    var ret = NullRec{};
    for (tokens.items) |token| {
        switch (token) {
            .name => |name| {
                if (ret.name != null) return error.DuplicateField;
                if (name == null) {
                    if (origin == null) return error.NoOrigin;
                    ret.name = origin;
                } else {
                    ret.name = name;
                }
            },
            .ttl => |ttl| {
                if (ret.ttl != null) return error.DuplicateField;
                ret.ttl = ttl;
            },
            .class => |class| {
                if (ret.class != null) return error.DuplicateField;
                ret.class = class;
            },
            .type => |@"type"| {
                if (ret.type != null) return error.DuplicateField;
                ret.type = @"type";
            },
            .data => |data| {
                if (ret.data != null) return error.DuplicateField;
                ret.data = data;
            },
        }
    }
    return Rec{
        .name = ret.name orelse prev_name orelse return error.NoName,
        .ttl = ret.ttl orelse default_ttl,
        .class = ret.class orelse return error.MissingClass,
        .type = ret.type orelse return error.MissingType,
        .data = ret.data orelse return error.MissingData,
    };
}

test "get Rec" {
    const allocator = std.testing.allocator;
    var tokens = try tokenize(allocator, "IN  MX    10 mail.example.com.");
    defer tokens.deinit();
    const rec = try collectFields("test.com.", "example.com.", 3200, tokens);
    defer allocator.free(rec.data);
    var rdata = try Message.RData.fromString(rec.type, allocator, rec.data);
    defer rdata.deinit();
    std.debug.print("{}\n", .{rdata});
}

test "parse zone" {
    const allocator = std.testing.allocator;

    const zone_content =
        \\$ORIGIN example.com.
        \\$TTL 3600
        \\@    IN    SOA   ns1.example.com. admin.example.com. (
        \\                2023120101  ; Serial
        \\                10800       ; Refresh
        \\                3600        ; Retry
        \\                604800      ; Expire
        \\                86400 )     ; Minimum TTL
        \\
        \\@    IN    NS    ns1.example.com.
        \\     IN    NS    ns2.example.com.
        \\@    IN    A     192.0.2.1
        \\www  IN    A     192.0.2.2
        \\mail IN    A     192.0.2.3
        \\@    IN    MX    10 mail.example.com.
        \\ftp  IN    CNAME www.example.com.
    ;

    // Parse from string
    var zone = try Zone.parseFromString(allocator, zone_content);
    defer zone.deinit();

    var zone2 = try Zone.parseFromFile(allocator, "resource/test.zone");
    defer zone2.deinit();

    std.debug.print("Zone parsed successfully!\n", .{});
    std.debug.print("Number of records: {}\n", .{zone2.records.items.len});
    for (zone2.records.items) |record| {
        std.debug.print("{s}\n", .{record});
    }
    std.debug.print("{s}\n", .{zone2.soa});
}
