const std = @import("std");
const net = std.net;
const posix = std.posix;
const system = std.posix.system;
const linux = std.os.linux;
const Client = @import("server.zig").Client;

pub const Loop = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd => KQueue,
    .linux => Epoll,
    else => @panic("Platform not supported"),
};

const Event = union(enum) {
    accept: void,
    read: *Client,
    write: *Client,
};

const KQueue = struct {
    kfd: posix.fd_t,
    event_list: [128]system.Kevent = undefined,
    change_list: [16]system.Kevent = undefined,
    change_count: usize = 0,

    pub const Iterator = struct {
        index: usize,
        event_list: []system.Kevent,

        pub fn next(self: *Iterator) ?Event {
            const index = self.index;
            const event_list = self.event_list;
            if (index == event_list.len) {
                return null;
            }

            self.index = index + 1;
            const event = event_list[index];
            switch (event.udata) {
                0 => return .{ .accept = {} },
                else => |nptr| {
                    const filter = event.filter;
                    const client: *Client = @ptrFromInt(nptr);
                    if (filter == system.EVFILT_READ) {
                        return .{ .read = client };
                    }
                    return .{ .write = client };
                },
            }
        }
    };

    pub fn init() !KQueue {
        return .{
            .kfd = try posix.kqueue(),
        };
    }

    pub fn deinit(self: *KQueue) void {
        posix.close(self.kfd);
    }

    pub fn wait(self: *KQueue, timeout_ms: i32) Iterator {
        const event_list = &self.event_list;
        const timeout = posix.timespec{
            .tv_sec = @intCast(@divTrunc(timeout_ms, 1000)),
            .tv_nsec = @intCast(@mod(timeout_ms, 1000) * 1000000),
        };
        const count = try posix.kevent(
            self.kfd,
            self.change_list[0..self.change_count],
            event_list,
            &timeout,
        );

        self.change_count = 0;
        return .{
            .index = 0,
            .event_list = event_list[0..count],
        };
    }

    pub fn addListener(self: *KQueue, listener: posix.socket_t) !void {
        try self.queueChange(.{
            .ident = @intCast(listener),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ADD,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });
    }

    pub fn removeListener(self: *KQueue, listener: posix.socket_t) !void {
        try self.queueChange(.{
            .ident = @intCast(listener),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });
    }

    pub fn newClient(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ADD,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_ADD | posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    pub fn readMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    pub fn writeMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .flags = posix.system.EV_ENABLE,
            .filter = posix.system.EVFILT_WRITE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn queueChange(self: *KQueue, event: system.Kevent) !void {
        var count = self.change_count;
        if (count == self.change_list.len) {
            _ = try posix.kevent(self.kfd, &self.change_list, &.{}, null);
            count = 0;
        }
        self.change_list[count] = event;
        self.change_count = count + 1;
    }
};

const Epoll = struct {
    efd: posix.fd_t,
    ready_list: [128]linux.epoll_event = undefined,

    pub const Iterator = struct {
        index: usize,
        ready_list: []linux.epoll_event,

        pub fn next(self: *Iterator) ?Event {
            const index = self.index;
            const ready_list = self.ready_list;
            if (index == ready_list.len) {
                return null;
            }

            self.index = index + 1;
            const ready = ready_list[index];
            switch (ready.data.ptr) {
                0 => return .{ .accept = {} },
                else => |nptr| {
                    const client: *Client = @ptrFromInt(nptr);
                    if (ready.events & linux.EPOLL.IN == linux.EPOLL.IN) {
                        return .{ .read = client };
                    }
                    return .{ .write = client };
                },
            }
        }
    };

    pub fn init() !Epoll {
        return .{
            .efd = try posix.epoll_create1(0),
        };
    }

    pub fn deinit(self: *Epoll) void {
        posix.close(self.efd);
    }

    pub fn wait(self: *Epoll, timeout: i32) Iterator {
        const ready_list = &self.ready_list;
        const count = posix.epoll_wait(self.efd, ready_list, timeout);

        return .{
            .index = 0,
            .ready_list = ready_list[0..count],
        };
    }

    pub fn addListener(self: *Epoll, listener: posix.socket_t) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .ptr = 0 },
        };
        try posix.epoll_ctl(self.efd, linux.EPOLL.CTL_ADD, listener, &event);
    }

    pub fn removeListener(self: *Epoll, listener: posix.socket_t) !void {
        try posix.epoll_ctl(self.efd, linux.EPOLL.CTL_DEL, listener, null);
    }

    pub fn newClient(self: *Epoll, client: *Client) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .ptr = @intFromPtr(client) },
        };
        try posix.epoll_ctl(self.efd, linux.EPOLL.CTL_MOD, client.socket, &event);
    }

    pub fn readMode(self: *Epoll, client: *Client) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .ptr = @intFromPtr(client) },
        };
        try posix.epoll_ctl(self.efd, linux.EPOLL.CTL_MOD, client.socket, &event);
    }

    pub fn writeMode(self: *Epoll, client: *Client) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.OUT,
            .data = .{ .ptr = @intFromPtr(client) },
        };
        try posix.epoll_ctl(self.efd, linux.EPOLL.CTL_MOD, client.socket, &event);
    }
};
