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
            record.ref = false;
            record.deinit();
        }
        self.records.deinit();
    }

    pub fn getSoa(self: *Zone) *dns.Record {
        return &self.soa;
    }

    /// Record becomes managed by the zone, it is freed on deinit
    pub fn addRecord(self: *Zone, record: dns.Record) !void {
        record.ref = true;
        try self.records.append(record);
    }

    /// Records become managed by the zone, they are freed on deinit
    pub fn addRecords(self: *Zone, records: []dns.Record) !void {
        for (records) |*record| {
            record.ref = true;
        }

        try self.records.appendSlice(records);
    }

    pub fn getRecords(self: *Zone) ![]const dns.Record {
        return self.records.items;
    }
};
