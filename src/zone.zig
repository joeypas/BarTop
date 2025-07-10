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

    pub fn parseFromString(allocator: Allocator, content: []const u8) !Zone {
        var zone = Zone.init(allocator);
        errdefer zone.deinit();

        //86400
        try ZoneParser.parse(&zone, 86400, content);
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
};

const ZoneParser = struct {
    zone: *Zone,
    allocator: Allocator,
    origin: ?[]const u8 = null,
    default_ttl: u32,
    last_name: ?[]const u8 = null,

    // This is a mess but it works for now
    // TODO: Add more comprehensive error messages (line info, error type, etc.)
    pub fn parse(zone: *Zone, default_ttl: u32, content: []const u8) !void {
        var self = ZoneParser{
            .zone = zone,
            .allocator = zone.allocator,
            .default_ttl = default_ttl,
        };

        var lines = std.mem.splitAny(u8, content, "\n\r");

        var multi_line_buffer = ArrayList(u8).init(self.allocator);
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
                const cleaned = std.mem.replaceOwned(u8, self.allocator, trimmed, "(", "") catch trimmed;
                defer if (cleaned.ptr != trimmed.ptr) self.allocator.free(cleaned);

                // check if this is actually a fake multi-line record
                if (std.mem.indexOf(u8, cleaned, ")")) |idx| {
                    try self.processRecord(cleaned[0..idx]);
                    in_parentheses = false;
                    continue;
                }
                try multi_line_buffer.appendSlice(cleaned);
                try multi_line_buffer.append(' ');
                continue;
            }

            if (in_parentheses) {
                if (std.mem.indexOf(u8, trimmed, ")") != null) {
                    const cleaned = std.mem.replaceOwned(u8, self.allocator, trimmed, ")", "") catch trimmed;
                    defer if (cleaned.ptr != trimmed.ptr) self.allocator.free(cleaned);

                    try multi_line_buffer.appendSlice(cleaned);
                    if (std.mem.indexOf(u8, trimmed, ";")) |comment_pos| {
                        trimmed = std.mem.trim(u8, trimmed[0..comment_pos], " \t");
                    }
                    const complete_line = std.mem.trim(u8, multi_line_buffer.items, " \t");
                    try self.processRecord(complete_line);

                    multi_line_buffer.clearRetainingCapacity();
                    in_parentheses = false;
                } else {
                    try multi_line_buffer.appendSlice(trimmed);
                    try multi_line_buffer.append(' ');
                }
                continue;
            }

            try self.processRecord(trimmed);
        }
    }

    fn processRecord(self: *ZoneParser, line: []const u8) !void {
        // Handle directives
        if (line[0] == '$') {
            try self.parseDirective(line);
            return;
        }

        var record = try self.parseResourceRecord(line);
        errdefer record.deinit();
        if (record.type == .soa) {
            self.zone.soa.deinit();
            self.zone.soa = record;
            self.zone.soa.ref = true;
        } else {
            try self.zone.addRecord(record);
        }
    }

    fn parseResourceRecord(self: *ZoneParser, line: []const u8) !Message.Record {
        var tokens = try self.tokenize(line);
        defer tokens.deinit();

        const rec = try self.collectFields(tokens);
        defer self.allocator.free(rec.data);

        var record = Message.Record.init(self.allocator, rec.type);
        errdefer record.deinit();

        self.last_name = rec.name;
        try record.name.parse(rec.name);

        // rhHandle relative host name
        if (record.name.labels.items.len <= 1) {
            try record.name.parse(self.origin.?);
        }
        record.ttl = rec.ttl;
        record.class = rec.class;

        record.rdata.parse(rec.data) catch |err| {
            std.debug.print("Err at: {s}\n", .{rec.data});
            return err;
        };

        return record;
    }

    fn parseDirective(self: *ZoneParser, line: []const u8) !void {
        var tokens = std.mem.tokenizeAny(u8, line, " \t");
        const directive = tokens.next() orelse return;

        if (std.mem.eql(u8, directive, "$ORIGIN")) {
            if (tokens.next()) |value| {
                self.origin = value;
            } else {
                return error.MissingOrigin;
            }
        } else if (std.mem.eql(u8, directive, "$TTL")) {
            if (tokens.next()) |value| {
                self.default_ttl = try std.fmt.parseInt(u32, value, 10);
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

    fn tokenize(self: *ZoneParser, line: []const u8) !ArrayList(Token) {
        var ret = ArrayList(Token).init(self.allocator);
        errdefer ret.deinit();
        var tokens = std.mem.tokenizeAny(u8, line, " \t");

        var data_buf = ArrayList(u8).init(self.allocator);
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

    fn collectFields(self: *ZoneParser, tokens: ArrayList(Token)) !Rec {
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
                        if (self.origin == null) return error.NoOrigin;
                        ret.name = self.origin;
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
            .name = ret.name orelse self.last_name orelse return error.NoName,
            .ttl = ret.ttl orelse self.default_ttl,
            .class = ret.class orelse return error.MissingClass,
            .type = ret.type orelse return error.MissingType,
            .data = ret.data orelse return error.MissingData,
        };
    }
};

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
