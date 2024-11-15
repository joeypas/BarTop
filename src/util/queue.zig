const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn DualQueue(comptime T: type) type {
    return struct {
        const Self = @This();
        const MemoryPool = std.heap.MemoryPoolExtra(DualQueue(T).Node, .{ .alignment = @alignOf(T) });

        const Node = struct {
            value: T,
            prev: ?*Node,
            next: ?*Node,
        };

        pool: MemoryPool,
        head: ?*Node = null,
        tail: ?*Node = null,
        len: usize = 0,

        pub fn init(allocator: Allocator) Self {
            return Self{
                .pool = MemoryPool.init(allocator),
                .head = null,
                .tail = null,
                .len = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            //var current = self.head;
            //while (current) |node| {
            //    const next_node = node.next;
            //    self.pool.destroy(node);
            //    current = next_node;
            //}
            self.pool.deinit();
            self.head = null;
            self.tail = null;
            self.len = 0;
        }

        pub fn pushFront(self: *Self, value: T) !void {
            const node = try self.pool.create();
            node.* = Node{
                .value = value,
                .prev = null,
                .next = self.head,
            };
            if (self.head) |head_node| {
                head_node.prev = node;
            } else {
                self.tail = node;
            }
            self.head = node;
            self.len += 1;
        }

        pub fn pushBack(self: *Self, value: T) !void {
            const node = try self.pool.create();
            node.* = Node{
                .value = value,
                .prev = self.tail,
                .next = null,
            };
            if (self.tail) |tail_node| {
                tail_node.next = node;
            } else {
                self.head = node;
            }
            self.tail = node;
            self.len += 1;
        }

        pub fn popFront(self: *Self) ?T {
            if (self.head) |head_node| {
                const value = head_node.value;
                self.head = head_node.next;
                if (self.head) |new_head| {
                    new_head.prev = null;
                } else {
                    self.tail = null;
                }
                self.pool.destroy(head_node);
                self.len -= 1;
                return value;
            } else {
                return null;
            }
        }

        pub fn popBack(self: *Self) ?T {
            if (self.tail) |tail_node| {
                const value = tail_node.value;
                self.tail = tail_node.prev;
                if (self.tail) |new_tail| {
                    new_tail.next = null;
                } else {
                    self.head = null;
                }
                self.pool.destroy(tail_node);
                self.len -= 1;
                return value;
            } else {
                return null;
            }
        }

        pub fn iterator(self: *Self) Iterator {
            return Iterator{
                .current = self.head,
            };
        }

        pub const Iterator = struct {
            current: ?*Node,

            pub fn next(self: *Iterator) ?T {
                if (self.current) |node| {
                    const value = node.value;
                    self.current = node.next;
                    return value;
                } else {
                    return null;
                }
            }
        };

        pub fn isEmpty(self: *Self) bool {
            return self.len == 0;
        }

        pub fn length(self: *Self) usize {
            return self.len;
        }
    };
}
