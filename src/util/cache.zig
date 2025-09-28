const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const AutoHashMap = std.StringHashMap;
const Mutex = std.Thread.Mutex;
const DoublyLinkedList = std.DoublyLinkedList;
const Node = DoublyLinkedList.Node;

pub fn CacheEntry(comptime T: type) type {
    const destroy = std.meta.hasMethod(T, "deinit");
    return struct {
        key: []u8,
        value: T,
        node: Node = .{},

        pub fn next(self: *CacheEntry(T)) ?*CacheEntry(T) {
            return if (self.node.next) |next_node| @alignCast(@fieldParentPtr("node", next_node)) else null;
        }

        pub fn deinit(self: *CacheEntry(T), allocator: Allocator) void {
            allocator.free(self.key);
            if (destroy) {
                self.value.deinit();
            }
        }
    };
}
pub fn EntryPool(comptime T: type) type {
    return std.heap.MemoryPoolExtra(CacheEntry(T), .{ .alignment = mem.Alignment.of(CacheEntry(T)) });
}

pub fn LRU(comptime T: type) type {
    return struct {
        const Self = @This();
        capacity: usize,
        map: AutoHashMap(*CacheEntry(T)),
        list: DoublyLinkedList = .{},
        allocator: Allocator,
        entry_pool: EntryPool(T),
        mutex: Mutex = .{},

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .capacity = capacity,
                .map = AutoHashMap(*CacheEntry(T)).init(allocator),
                .allocator = allocator,
                .entry_pool = EntryPool(T).initPreheated(allocator, capacity) catch undefined,
            };
        }

        pub fn deinit(self: *Self) void {
            self.entry_pool.deinit();
            self.map.deinit();
        }

        fn removeEntry(self: *Self, entry: *CacheEntry(T)) void {
            self.list.remove(&entry.node);
        }

        fn addToHead(self: *Self, entry: *CacheEntry(T)) void {
            self.list.prepend(&entry.node);
        }

        fn moveToHead(self: *Self, entry: *CacheEntry(T)) void {
            self.removeEntry(entry);
            self.addToHead(entry);
        }

        pub fn remove(self: *Self, key: []u8) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.get(key)) |entry| {
                self.removeEntry(entry);
                entry.deinit(self.allocator);
                self.entry_pool.destroy(entry);
            }
            _ = self.map.remove(key);
        }

        pub fn get(self: *Self, key: []u8) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.get(key)) |entry| {
                self.moveToHead(entry);
                return entry.value;
            } else {
                return null;
            }
        }

        pub fn put(self: *Self, key: []const u8, value: T) !void {
            const k = try self.allocator.dupe(u8, key[0..]);
            errdefer self.allocator.free(k);

            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.map.get(k)) |entry| {
                entry.value = value;
                self.moveToHead(entry);
            } else {
                if (self.map.count() >= self.capacity) {
                    if (self.list.pop()) |tail_entry| {
                        const entry: *CacheEntry(T) = @alignCast(@fieldParentPtr("node", tail_entry));
                        if (!self.map.remove(entry.key)) return error.Remove;
                        entry.deinit(self.allocator);
                        self.entry_pool.destroy(entry);
                    }
                }
                const new_entry = try self.entry_pool.create();
                new_entry.* = .{
                    .key = k,
                    .value = value,
                };
                self.addToHead(new_entry);
                try self.map.put(k, new_entry);
            }
        }

        pub fn head(self: *Self) ?*CacheEntry(T) {
            return if (self.list.first) |first| @alignCast(@fieldParentPtr("node", first)) else null;
        }

        pub fn acquireLock(self: *Self) void {
            self.mutex.lock();
        }

        pub fn releaseLock(self: *Self) void {
            self.mutex.unlock();
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
