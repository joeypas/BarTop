const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const AutoHashMap = std.AutoHashMap;

pub fn CacheEntry(comptime T: type) type {
    return struct {
        key: u64,
        value: T,
        prev: ?*CacheEntry(T),
        next: ?*CacheEntry(T),
    };
}

pub fn LRU(comptime T: type) type {
    return struct {
        const Self = @This();
        capacity: usize,
        map: AutoHashMap(u64, *CacheEntry(T)),
        head: ?*CacheEntry(T),
        tail: ?*CacheEntry(T),
        allocator: Allocator,

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .capacity = capacity,
                .map = AutoHashMap(u64, *CacheEntry(T)).init(allocator),
                .head = null,
                .tail = null,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                self.allocator.destroy(entry.value_ptr.*);
            }
            self.map.deinit();
        }

        fn removeEntry(self: *Self, entry: *CacheEntry(T)) void {
            if (entry.prev) |prev_entry| {
                prev_entry.next = entry.next;
            } else {
                self.head = entry.next;
            }
            if (entry.next) |next_entry| {
                next_entry.prev = entry.prev;
            } else {
                self.tail = entry.prev;
            }
        }

        fn addToHead(self: *Self, entry: *CacheEntry(T)) void {
            entry.prev = null;
            entry.next = self.head;
            if (self.head) |head_entry| {
                head_entry.prev = entry;
            }
            self.head = entry;
            if (self.tail == null) {
                self.tail = entry;
            }
        }

        fn moveToHead(self: *Self, entry: *CacheEntry(T)) void {
            self.removeEntry(entry);
            self.addToHead(entry);
        }

        pub fn remove(self: *Self, key: u64) void {
            if (self.map.get(key)) |entry| {
                self.removeEntry(entry);
                self.allocator.destroy(entry);
            }
            _ = self.map.remove(key);
        }

        pub fn get(self: *Self, key: u64) ?T {
            if (self.map.get(key)) |entry| {
                self.moveToHead(entry);
                return entry.value;
            } else {
                return null;
            }
        }

        pub fn put(self: *Self, key: u64, value: T) !void {
            if (self.map.get(key)) |entry| {
                entry.value = value;
                self.moveToHead(entry);
            } else {
                if (self.map.count() >= self.capacity) {
                    if (self.tail) |tail_entry| {
                        if (!self.map.remove(tail_entry.key)) return error.Remove;
                        self.removeEntry(tail_entry);
                        self.allocator.destroy(tail_entry);
                    }
                }
                const new_entry = try self.allocator.create(CacheEntry(T));
                new_entry.* = .{
                    .key = key,
                    .value = value,
                    .prev = null,
                    .next = null,
                };
                self.addToHead(new_entry);
                try self.map.put(key, new_entry);
            }
        }
    };
}

test "LRU" {
    const allocator = std.testing.allocator;
    var cache = LRU(u64).init(allocator, 2);

    try cache.put(1, 1);
    try cache.put(2, 2);
    try std.testing.expect(cache.get(1) == 1);
    try cache.put(3, 3); // Evicts key 2
    try std.testing.expect(cache.get(2) == null);
    try cache.put(4, 4); // Evicts key 1
    try std.testing.expect(cache.get(1) == null);
    try std.testing.expect(cache.get(3) == 3);
    try std.testing.expect(cache.get(4) == 4);

    cache.deinit();
}
