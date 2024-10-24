const std = @import("std");
const dns = @import("dns.zig");
const net = std.net;
const fs = std.fs;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const AutoHashMap = std.AutoHashMap;
const LRU = @import("util/lru.zig").LRU;

pub const Server = @This();
const BUFFER_SIZE = 1024;
var dns_mutex = Mutex{};
const Options = struct {
    external_server: ?[]const u8 = null,
    bind_addr: []const u8 = "127.0.0.1",
    bind_port: u16 = 53,
};

arena: std.heap.ArenaAllocator,
allocator: Allocator,
dns_cache: LRU([]const u8),
dns_store: AutoHashMap(u64, []const u8),
pool: Thread.Pool,
resolv: []const u8,
sock: posix.socket_t,
options: Options,

fn getResolv(allocator: Allocator, external_server: ?[]const u8) ![]const u8 {
    if (external_server) |r| {
        const ret = try allocator.alloc(u8, r.len);
        std.mem.copyForwards(u8, ret, r);
        return ret;
    }
    const file = try std.fs.openFileAbsolute("/etc/resolv.conf", .{});
    defer file.close();

    const resolv_contents = try file.reader().readAllAlloc(
        allocator,
        (try file.stat()).size,
    );
    defer allocator.free(resolv_contents);

    const start_index = std.mem.indexOf(u8, resolv_contents, "nameserver").? + 11;
    const end_index = std.mem.indexOf(u8, resolv_contents[start_index..], "\n").? + start_index;

    const ret = try allocator.alloc(u8, end_index - start_index);
    std.mem.copyForwards(u8, ret, resolv_contents[start_index..end_index]);
    return ret;
}

pub fn init(allocator: Allocator, options: Options) !Server {
    return .{
        .dns_cache = LRU([]const u8).init(allocator, 100),
        .dns_store = AutoHashMap(u64, []const u8).init(allocator),
        .resolv = try getResolv(allocator, options.external_server),
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .pool = undefined,
        .sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        ),
        .options = options,
    };
}

pub fn deinit(self: *Server) void {
    self.pool.deinit();
    self.allocator.free(self.resolv);
    posix.close(self.sock);
    self.dns_cache.deinit();
    self.dns_store.deinit();
    self.arena.deinit();
}

pub fn run(self: *Server) !void {
    // TODO: Change this line with local dns info
    var example = std.ArrayList([]const u8).init(self.allocator);
    defer example.deinit();
    try example.append("example");
    try example.append("com");
    const put = try example.toOwnedSlice();
    defer self.allocator.free(put);
    try self.dns_store.put(hashFn(put), &[4]u8{ 192, 168, 1, 1 });

    const addr = try net.Address.parseIp(self.options.bind_addr, self.options.bind_port);

    try posix.bind(self.sock, &addr.any, addr.getOsSockLen());

    std.debug.print("Listen on {any}\n", .{addr});

    var thread_safe = std.heap.ThreadSafeAllocator{
        .child_allocator = self.arena.allocator(),
    };
    const alloc = thread_safe.allocator();

    try Thread.Pool.init(&self.pool, .{ .allocator = alloc, .n_jobs = 8 });

    var buffer: [BUFFER_SIZE]u8 = undefined;

    var count: usize = 0;
    while (count < 5) : (count += 1) {
        var from_addr: posix.sockaddr = undefined;
        var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        const recv_len = try posix.recvfrom(
            self.sock,
            buffer[0..],
            0,
            &from_addr,
            &from_addrlen,
        );
        std.debug.print("Received {d} bytes from {any};\n", .{ recv_len, net.Address.initPosix(@alignCast(&from_addr)) });
        const client = Client{
            .socket = self.sock,
            .address = net.Address.initPosix(@alignCast(&from_addr)),
            .buffer = &buffer,
            .recv_len = recv_len,
            .allocator = self.pool.allocator,
            .store_ptr = &self.dns_store,
            .cache_ptr = &self.dns_cache,
            .resolv = self.resolv[0..],
        };
        std.mem.copyForwards(u8, client.buffer, buffer[0..]);

        // Spawn thread to handle DNS query
        try self.pool.spawn(Client.handle, .{client});
    }
}

fn hashFn(data: [][]const u8) u64 {
    const p: u64 = 31;
    const m: u64 = 1e9 + 9;
    var hash: u64 = 0;
    var p_pow: u64 = 1;
    for (data) |list| {
        for (list) |byte| {
            hash = (hash + (byte - 97 + 1) * p_pow) % m;
            p_pow = (p_pow * p) % m;
        }
    }
    return hash;
}

const Client = struct {
    socket: posix.fd_t,
    address: std.net.Address,
    buffer: []u8,
    recv_len: usize,
    allocator: Allocator,
    store_ptr: *AutoHashMap(u64, []const u8),
    cache_ptr: *LRU([]const u8),
    resolv: []const u8,

    fn handle(self: Client) void {
        self.handleDnsQuery() catch |err| {
            dns_mutex.lock();
            defer dns_mutex.unlock();
            std.io.getStdErr().writer().print(
                "[{any}] client handle error: {}\n",
                .{ self.address, err },
            ) catch {};
            const message = createDnsError(.format_error);
            const bytes = message.bytes(self.allocator) catch "";
            defer self.allocator.free(bytes);
            _ = posix.sendto(
                self.socket,
                bytes,
                0,
                &self.address.any,
                self.address.getOsSockLen(),
            ) catch |serr| {
                std.io.getStdErr().writer().print(
                    "[{any}] client handle error: {}\n",
                    .{ self.address, serr },
                ) catch {};
            };
        };
    }

    fn handleDnsQuery(self: Client) !void {
        const query = self.buffer[0..self.recv_len];
        var response = self.buffer[self.recv_len..];

        const header_len = 12;
        if (query.len < header_len) {
            return error.InvalidDNSQuery;
        }

        var len: usize = 0;

        var parser = dns.Parser.init(query, self.allocator);
        defer parser.deinit();

        if (try parser.read()) |packet| {
            //std.debug.print("{s}: {any}: {any}\n", .{ packet.questions[0].qname, packet.header.flags, packet.questions[0] });
            dns_mutex.lock();
            defer dns_mutex.unlock();
            //std.debug.print("Received DNS Packet: {any}\n", .{packet});
            const question = packet.questions[0];

            const qname_hash = hashFn(question.qname);

            if (self.cache_ptr.get(qname_hash)) |cached_response| {
                // Return cached response
                std.debug.print("Cache hit for {s}\n", .{question.qname});
                std.mem.copyForwards(u8, response, cached_response);

                // Make sure id matches question
                std.mem.copyForwards(u8, response[0..2], &dns.u16ToBeBytes(packet.header.id));
                //std.debug.print("Got: {x}\n", .{cached_response});
                len = cached_response.len;
            } else if (self.store_ptr.get(qname_hash)) |address| {
                // Return local response
                //std.debug.print("Found in local store: {s} -> {any}\n", .{ question.qname, address });

                var response_packet = createDnsResponse(packet, question.qname, address);
                const response_bytes = try response_packet.bytes(self.allocator);
                defer self.allocator.free(response_bytes);

                std.mem.copyForwards(u8, response, response_bytes);
                len = response_bytes.len;
            } else {
                // Query external server
                //std.debug.print("Not found in local store, querying external server...\n", .{});

                const external_len = try self.queryExternalServer(query, response);
                const res = try self.allocator.alloc(u8, external_len);
                //std.debug.print("Put: {x}\n", .{response[0..external_len]});
                std.mem.copyForwards(u8, res, response[0..external_len]);
                try self.cache_ptr.put(qname_hash, res);
                len = external_len;
            }
        } else {
            return error.InvalidDNSQuery;
        }

        //std.debug.print("Sending: {x}\n", .{response[0..len]});

        dns_mutex.lock();
        _ = try posix.sendto(
            self.socket,
            response[0..len],
            0,
            &self.address.any,
            self.address.getOsSockLen(),
        );
        dns_mutex.unlock();
    }

    inline fn queryExternalServer(self: Client, query: []const u8, response: []u8) !usize {
        // TODO: Placeholder implementation
        const external_server_port = 53;

        const addr = try net.Address.parseIp(self.resolv, external_server_port);
        const sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        );
        defer posix.close(sock);

        var from_addr: posix.sockaddr = undefined;
        var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        _ = try posix.sendto(
            sock,
            query,
            0,
            &addr.any,
            addr.getOsSockLen(),
        );

        var buf: [512]u8 = undefined;
        const recv_bytes = try posix.recvfrom(sock, buf[0..], 0, &from_addr, &from_addrlen);

        std.mem.copyForwards(u8, response, buf[0..recv_bytes]);
        return recv_bytes;
    }
};

inline fn createDnsResponse(packet: dns.Message, qname: [][]const u8, address: []const u8) dns.Message {
    return dns.Message{
        .header = dns.Header{
            .id = packet.header.id,
            .flags = dns.Header.Flags{
                .qr = true,
                .opcode = dns.Header.Opcode.query,
                .aa = false,
                .tc = false,
                .rd = packet.header.flags.rd,
                .ra = true,
                .rcode = dns.Header.ResponseCode.no_error,
            },
            .qcount = packet.header.qcount,
            .ancount = 1,
            .nscount = 0,
            .arcount = 0,
        },
        .questions = packet.questions,
        .answers = &[_]dns.Record{
            dns.Record{
                .name = qname,
                .type = dns.Record.Type.a,
                .class = dns.Record.Class.in,
                .ttl = 300,
                .rdlength = @as(u16, @intCast(address.len)),
                .rdata = address,
            },
        },
        .authorities = &[_]dns.Record{},
        .additionals = &[_]dns.Record{},
    };
}

inline fn createDnsError(err: dns.Header.ResponseCode) dns.Message {
    return dns.Message{
        .header = dns.Header{
            .id = 0,
            .flags = dns.Header.Flags{
                .qr = true,
                .opcode = dns.Header.Opcode.query,
                .aa = false,
                .tc = false,
                .rd = false,
                .ra = true,
                .rcode = err,
            },
            .qcount = 0,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        },
        .questions = &[_]dns.Question{},
        .answers = &[_]dns.Record{},
        .authorities = &[_]dns.Record{},
        .additionals = &[_]dns.Record{},
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Server.init(allocator, .{ .bind_port = 5553 });
    defer server.deinit();

    try server.run();
}
