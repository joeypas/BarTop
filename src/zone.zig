const std = @import("std");
const dns = @import("dns.zig");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

pub const Zone = struct {
    soa: dns.Record,
    records: ArrayList(dns.Record),
    allocator: Allocator,

    pub fn init(allocator: Allocator) Zone {
        var soa = dns.Record.init(allocator, .soa);
        soa.ref = true;
        return Zone{
            .soa = soa,
            .records = ArrayList(dns.Record).init(allocator),
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

    pub fn getSoa(self: *Zone) *dns.Record {
        return &self.soa;
    }

    /// Record becomes managed by the zone, it is freed on deinit
    pub fn addRecord(self: *Zone, record: dns.Record) !void {
        try self.records.append(record);
    }

    /// Records become managed by the zone, they are freed on deinit
    pub fn addRecords(self: *Zone, records: []dns.Record) !void {
        try self.records.appendSlice(records);
    }

    pub fn getRecords(self: *Zone) []const dns.Record {
        return self.records.items;
    }

    pub fn parseFromString(allocator: Allocator, content: []const u8) !Zone {
        var zone = Zone.init(allocator);
        errdefer zone.deinit();

        var lines = std.mem.splitAny(u8, content, "\n");
        var origin: ?[]const u8 = null;
        var default_ttl: u32 = 86400;
        var last_name: ?[]const u8 = null;
        var multi_line_buffer = ArrayList(u8).init(allocator);
        defer multi_line_buffer.deinit();
        var in_parentheses = false;

        while (lines.next()) |line| {
            var trimmed = std.mem.trim(u8, line, " \t\r");

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

                try multi_line_buffer.appendSlice(cleaned);
                try multi_line_buffer.append(' ');
                continue;
            }

            if (in_parentheses) {
                if (std.mem.indexOf(u8, trimmed, ")") != null) {
                    const cleaned = std.mem.replaceOwned(u8, allocator, trimmed, ")", "") catch trimmed;
                    defer if (cleaned.ptr != trimmed.ptr) allocator.free(cleaned);

                    try multi_line_buffer.appendSlice(cleaned);

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

        if (try parseResourceRecord(allocator, line, origin.*, default_ttl.*, last_name)) |record| {
            if (record.type == .soa) {
                zone.soa.deinit();
                zone.soa = record;
                zone.soa.ref = true;
            } else {
                try zone.addRecord(record);
            }
        }
    }
};

fn parseResourceRecord(
    allocator: Allocator,
    line: []const u8,
    origin: ?[]const u8,
    default_ttl: u32,
    last_name: *?[]const u8,
) !?dns.Record {
    var tokens = std.mem.tokenizeAny(u8, line, " \t");

    var name: []const u8 = undefined;
    var first_token = tokens.next() orelse return null;

    if (first_token[0] == '@') {
        // origin
        name = "";
        first_token = tokens.next() orelse return null;
    } else if (std.mem.indexOf(u8, first_token, ".") != null or
        isRecordType(first_token) or parseClass(first_token) != null)
    {
        // prev
        name = last_name.* orelse "";
        var remaining = line;
        if (std.mem.indexOf(u8, line, first_token)) |pos| {
            remaining = line[pos..];
        }
        tokens = std.mem.tokenizeAny(u8, remaining, " \t");
        first_token = tokens.next() orelse return null;
    } else {
        // full name
        name = first_token;
        last_name.* = name;
        first_token = tokens.next() orelse return null;
    }

    var ttl = default_ttl;
    var class: dns.Class = .in;
    var record_type_str: []const u8 = undefined;

    // get class and ttl
    if (std.fmt.parseInt(u32, first_token, 10)) |parsed_ttl| {
        ttl = parsed_ttl;
        first_token = tokens.next() orelse return null;
    } else |_| {}

    if (parseClass(first_token)) |parsed_class| {
        class = parsed_class;
        first_token = tokens.next() orelse return null;
    }

    // get type
    record_type_str = first_token;
    const record_type = parseRecordType(record_type_str) orelse return null;

    var record = dns.Record.init(allocator, record_type);
    record.ttl = ttl;
    record.class = class;
    record.type = record_type;

    try record.name.addLabel(name);
    try record.name.fromString(origin orelse "");

    // parse data
    try parseRData(&record, &tokens, allocator);

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

fn isRecordType(str: []const u8) bool {
    const types = [_][]const u8{ "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT" };
    for (types) |t| {
        if (std.ascii.eqlIgnoreCase(str, t)) return true;
    }
    return false;
}

fn parseRecordType(str: []const u8) ?dns.Type {
    if (std.ascii.eqlIgnoreCase(str, "A")) return .a;
    if (std.ascii.eqlIgnoreCase(str, "AAAA")) return .aaaa;
    if (std.ascii.eqlIgnoreCase(str, "CNAME")) return .cname;
    if (std.ascii.eqlIgnoreCase(str, "MX")) return .mx;
    if (std.ascii.eqlIgnoreCase(str, "NS")) return .ns;
    if (std.ascii.eqlIgnoreCase(str, "PTR")) return .ptr;
    if (std.ascii.eqlIgnoreCase(str, "SOA")) return .soa;
    if (std.ascii.eqlIgnoreCase(str, "SRV")) return .srv;
    if (std.ascii.eqlIgnoreCase(str, "TXT")) return .txt;
    return null;
}

fn parseClass(str: []const u8) ?dns.Class {
    if (std.ascii.eqlIgnoreCase(str, "IN")) return .in;
    if (std.ascii.eqlIgnoreCase(str, "CS")) return .cs;
    if (std.ascii.eqlIgnoreCase(str, "CH")) return .ch;
    if (std.ascii.eqlIgnoreCase(str, "HS")) return .hs;
    return null;
}

fn parseRData(record: *dns.Record, tokens: *std.mem.TokenIterator(u8, .any), allocator: Allocator) !void {
    switch (record.type) {
        .a => {
            const addr_str = tokens.next() orelse return error.MissingRData;
            const addr = std.net.Ip4Address.parse(addr_str, 0) catch return error.InvalidAddress;
            record.rdata = dns.RData{ .a = .{ .addr = addr } };
        },
        .aaaa => {
            const addr_str = tokens.next() orelse return error.MissingRData;
            const addr = std.net.Ip6Address.parse(addr_str, 0) catch return error.InvalidAddress;
            record.rdata = dns.RData{ .aaaa = .{ .addr = addr } };
        },
        .cname, .ns, .ptr => {
            const name_str = tokens.next() orelse return error.MissingRData;
            var name = dns.Name.init(allocator);
            try name.fromString(name_str);

            switch (record.type) {
                .cname => record.rdata = dns.RData{ .cname = .{ .name = name } },
                .ns => record.rdata = dns.RData{ .ns = .{ .name = name } },
                .ptr => record.rdata = dns.RData{ .ptr = .{ .name = name } },
                else => unreachable,
            }
        },
        .mx => {
            const priority_str = tokens.next() orelse return error.MissingRData;
            const exchange_str = tokens.next() orelse return error.MissingRData;

            const priority = std.fmt.parseInt(u16, priority_str, 10) catch return error.InvalidPriority;
            var exchange = dns.Name.init(allocator);
            try exchange.fromString(exchange_str);

            record.rdata = dns.RData{ .mx = .{ .preface = priority, .exchange = exchange } };
        },
        .soa => {
            const mname_str = tokens.next() orelse return error.MissingRData;
            const rname_str = tokens.next() orelse return error.MissingRData;
            const serial_str = tokens.next() orelse return error.MissingRData;
            const refresh_str = tokens.next() orelse return error.MissingRData;
            const retry_str = tokens.next() orelse return error.MissingRData;
            const expire_str = tokens.next() orelse return error.MissingRData;
            const minimum_str = tokens.next() orelse return error.MissingRData;

            var mname = dns.Name.init(allocator);
            try mname.fromString(mname_str);

            var rname = dns.Name.init(allocator);
            try rname.fromString(rname_str);

            const serial = std.fmt.parseInt(u32, serial_str, 10) catch return error.InvalidSerial;
            const refresh = std.fmt.parseInt(u32, refresh_str, 10) catch return error.InvalidRefresh;
            const retry = std.fmt.parseInt(u32, retry_str, 10) catch return error.InvalidRetry;
            const expire = std.fmt.parseInt(u32, expire_str, 10) catch return error.InvalidExpire;
            const minimum = std.fmt.parseInt(u32, minimum_str, 10) catch return error.InvalidMinimum;

            record.rdata = dns.RData{ .soa = .{
                .mname = mname,
                .rname = rname,
                .serial = serial,
                .refresh = refresh,
                .retry = retry,
                .expire = expire,
                .minimum = minimum,
            } };
        },
        .srv => {
            const priority_str = tokens.next() orelse return error.MissingRData;
            const weight_str = tokens.next() orelse return error.MissingRData;
            const port_str = tokens.next() orelse return error.MissingRData;
            const target_str = tokens.next() orelse return error.MissingRData;

            const priority = std.fmt.parseInt(u16, priority_str, 10) catch return error.InvalidPriority;
            const weight = std.fmt.parseInt(u16, weight_str, 10) catch return error.InvalidWeight;
            const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

            var target = dns.Name.init(allocator);
            try target.fromString(target_str);

            record.rdata = dns.RData{ .srv = .{
                .priority = priority,
                .weight = weight,
                .port = port,
                .target = target,
            } };
        },
        .txt => {
            var txt_data = ArrayList(u8).init(allocator);
            while (tokens.next()) |token| {
                if (txt_data.items.len > 0) {
                    try txt_data.append(' ');
                }
                try txt_data.appendSlice(token);
            }

            if (txt_data.items.len >= 2 and txt_data.items[0] == '"' and txt_data.items[txt_data.items.len - 1] == '"') {
                const content = txt_data.items[1 .. txt_data.items.len - 1];
                txt_data.clearAndFree();
                try txt_data.appendSlice(content);
            }

            var name = dns.Name.init(allocator);
            try name.fromString("");

            record.rdata = dns.RData{ .txt = .{ .name = name } };
        },
        else => {
            var raw_data = ArrayList(u8).init(allocator);
            while (tokens.next()) |token| {
                if (raw_data.items.len > 0) {
                    try raw_data.append(' ');
                }
                try raw_data.appendSlice(token);
            }
            record.rdata = dns.RData{ .data = raw_data };
        },
    }

    record.rdlength = record.rdata.getLen();
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

    std.debug.print("Zone parsed successfully!\n", .{});
    std.debug.print("Number of records: {}\n", .{zone.records.items.len});
    for (zone.records.items) |*record| {
        var buf: [512]u8 = undefined;
        const str = try record.print(&buf);
        std.debug.print("{s}\n", .{str});
    }
    var buf: [1024]u8 = undefined;
    const str = try zone.soa.print(&buf);
    std.debug.print("{s}\n", .{str});
}
