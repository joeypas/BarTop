const std = @import("std");
const zio = @import("zio");
const Dns = @import("root").Message;
const Cache = @import("root").util.cache.LRU;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.cache_hub);

const BUFFER_SIZE = 1024;

/// Request types for the cache server
pub const CacheRequest = union(enum) {
    get: GetRequest,
    put: PutRequest,
    invalidate: InvalidateRequest,
    shutdown: void,
};

pub const GetRequest = struct {
    key: []const u8,
    response_channel: *zio.Channel(CacheResponse),
};

pub const PutRequest = struct {
    key: []const u8,
    value: Dns.Message,
};

pub const InvalidateRequest = struct {
    key: []const u8,
};

/// Response types from the cache server
pub const CacheResponse = union(enum) {
    hit: Dns.Message,
    miss: void,
};

pub const CacheHandle = struct {
    request_channel: *zio.Channel(CacheRequest),
    allocator: Allocator,

    pub fn get(self: *CacheHandle, rt: *zio.Runtime, key: []const u8) !?Dns.Message {
        var buf: [1]CacheResponse = undefined;
        var response_chan = zio.Channel(CacheResponse).init(&buf);
        defer response_chan.close(true);

        const key_copy = try self.allocator.alloc(u8, key.len);
        defer self.allocator.free(key_copy);
        @memcpy(&key_copy, &key);

        const request = CacheRequest{
            .get = .{
                .key = key_copy,
                .response_channel = &response_chan,
            },
        };

        try self.request_channel.send(rt, request);

        const result = try response_chan.receive(rt);

        return switch (result) {
            .hit => |msg| msg,
            .miss => null,
        };
    }

    pub fn put(self: *CacheHandle, rt: *zio.Runtime, key: []const u8, value: Dns.Message) !void {
        const key_copy = try self.allocator.alloc(u8, key.len);
        errdefer self.allocator.free(key_copy);

        @memcpy(&key_copy, &key);

        const request = CacheRequest{
            .put = .{
                .key = key_copy,
                .value = value,
            },
        };

        try self.request_channel.send(rt, request);
    }

    pub fn invalidate(self: *CacheHandle, rt: *zio.Runtime, key: []const u8) !void {
        const key_copy = try self.allocator.alloc(u8, key.len);
        errdefer self.allocator.free(key_copy);

        @memcpy(&key_copy, &key);

        const request = CacheRequest{
            .invalidate = .{
                .key = key_copy,
            },
        };

        try self.request_channel.send(rt, request);
    }

    pub fn shutdown(self: *CacheHandle, rt: *zio.Runtime) !void {
        try self.request_channel.send(rt, .shutdown);
    }
};

pub const CacheHub = struct {
    allocator: Allocator,
    cache: Cache(Dns.Message),
    request_channel: zio.Channel(CacheRequest),
    chan_buf: []CacheRequest,
    ttl_check_interval_ms: u64,

    pub fn init(
        allocator: Allocator,
        capacity: usize,
        channel_capacity: usize,
    ) !CacheHub {
        var chan_buf = try allocator.alloc(CacheRequest, channel_capacity);

        return .{
            .allocator = allocator,
            .cache = Cache(Dns.Message).init(allocator, capacity),
            .request_channel = zio.Channel(CacheRequest).init(&chan_buf),
            .chan_buf = chan_buf,
            .ttl_check_interval_ms = 1000,
        };
    }

    pub fn deinit(self: *CacheHub) void {
        var head = self.cache.head();
        while (head) |entry| {
            entry.*.value.deinit();
            self.allocator.free(entry.*.key);
            head = entry.next();
        }
        self.cache.deinit();
        self.request_channel.close(true);
        self.allocator.free(self.chan_buf);
    }

    pub fn getHandle(self: *CacheHub) CacheHandle {
        return .{
            .request_channel = &self.request_channel,
            .allocator = self.allocator,
        };
    }

    pub fn run(self: *CacheHub, rt: *zio.Runtime) !void {
        log.info("Cache server started", .{});

        var ttl_task = try rt.spawn(ttlMaintenanceTask, .{ self, rt }, .{});
        ttl_task.detach(rt);

        while (true) {
            const request = self.request_channel.receive(rt) catch |err| {
                log.err("Error receiving request: {}", .{err});
                continue;
            };

            switch (request) {
                .get => |get_req| {
                    self.handleGet(rt, get_req) catch |err| {
                        log.err("Failed to send cache response: {}", .{err});
                    };
                },
                .put => |put_req| {
                    self.handlePut(put_req) catch |err| {
                        log.err("Failed to store in cache: {}", .{err});
                    };
                },
                .invalidate => |inv_req| {
                    self.handleInvalidate(inv_req);
                },
                .shutdown => {
                    log.info("Cache server shutting down", .{});
                    return;
                },
            }
        }
    }

    fn handleGet(self: *CacheHub, rt: *zio.Runtime, req: GetRequest) !void {
        const response: CacheResponse = if (self.cache.get(&req.key)) |cached| blk: {
            log.debug("Cache hit for key: {s}", .{req.key});

            break :blk .{ .hit = cached.*.clone(self.allocator) catch {
                break :blk .miss;
            } };
        } else .miss;

        try req.response_channel.send(rt, response);
    }

    fn handlePut(self: *CacheHub, req: PutRequest) !void {
        errdefer {
            req.value.deinit();
            self.allocator.free(req.key);
        }

        try self.cache.put(req.key, req.value);
    }

    fn handleInvalidate(self: *CacheHub, req: InvalidateRequest) void {
        self.cache.remove(&req.key);
    }

    fn ttlMaintenanceTask(self: *CacheHub, rt: *zio.Runtime) void {
        while (true) {
            // Sleep for the TTL check interval
            zio.time.sleep(rt, self.ttl_check_interval_ms * std.time.ns_per_ms) catch return;

            var head = self.cache.head();
            while (head) |entry| {
                var should_remove = false;

                // Check answers
                for (entry.*.value.answers.items) |*item| {
                    if (item.ttl == 0) {
                        should_remove = true;
                        break;
                    }
                    item.ttl -= 1;
                }

                if (!should_remove) {
                    // Check authorities
                    for (entry.*.value.authorities.items) |*item| {
                        if (item.ttl == 0) {
                            should_remove = true;
                            break;
                        }
                        item.ttl -= 1;
                    }
                }

                if (!should_remove) {
                    // Check additionals
                    for (entry.*.value.additionals.items) |*item| {
                        if (item.ttl == 0) {
                            should_remove = true;
                            break;
                        }
                        item.ttl -= 1;
                    }
                }

                const next = entry.next();
                if (should_remove) {
                    entry.*.value.deinit();
                    self.allocator.free(entry.*.key);
                    self.cache.remove(entry.*.key);
                }
                head = next;
            }
        }
    }
};
