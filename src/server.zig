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

const BUFFER_SIZE = 1024;
var dns_cache: LRU([]const u8) = undefined;
var dns_store: AutoHashMap(u64, []const u8) = undefined;
var dns_mutex: Mutex = Mutex{};
var resolv: []u8 = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file = try std.fs.openFileAbsolute("/etc/resolv.conf", .{});
    defer file.close();

    const resolv_contents = try file.reader().readAllAlloc(
        allocator,
        (try file.stat()).size,
    );
    defer allocator.free(resolv_contents);

    const start_index = std.mem.indexOf(u8, resolv_contents, "nameserver").? + 11;
    const end_index = std.mem.indexOf(u8, resolv_contents[start_index..], "\n").? + start_index;

    resolv = resolv_contents[start_index..end_index];

    dns_cache = LRU([]const u8).init(allocator, 100);
    defer dns_cache.deinit();

    dns_store = AutoHashMap(u64, []const u8).init(allocator);
    defer dns_store.deinit();

    // TODO: Change this line with local dns info
    var example = std.ArrayList([]const u8).init(allocator);
    defer example.deinit();
    try example.append("example");
    try example.append("com");
    const put = try example.toOwnedSlice();
    defer allocator.free(put);
    try dns_store.put(hashFn(put), &[4]u8{ 192, 168, 1, 1 });

    const addr = try net.Address.parseIp("127.0.0.1", 5553);

    const sock = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );

    defer posix.close(sock);

    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    std.debug.print("Listen on {any}\n", .{addr});

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var pool: Thread.Pool = undefined;
    try Thread.Pool.init(&pool, .{ .allocator = alloc, .n_jobs = 8 });
    defer pool.deinit();

    var buffer: [BUFFER_SIZE]u8 = undefined;

    var count: usize = 0;
    while (count < 5) : (count += 1) {
        var from_addr: posix.sockaddr = undefined;
        var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        const recv_len = try posix.recvfrom(
            sock,
            buffer[0..],
            0,
            &from_addr,
            &from_addrlen,
        );
        std.debug.print("Received {d} bytes from {any};\n", .{ recv_len, net.Address.initPosix(@alignCast(&from_addr)) });
        const client = Client{
            .socket = sock,
            .address = net.Address.initPosix(@alignCast(&from_addr)),
            .buffer = &buffer,
            .recv_len = recv_len,
            .allocator = pool.allocator,
        };
        std.mem.copyForwards(u8, client.buffer, buffer[0..]);
        // Spawn thread to handle DNS query
        //const handle_thread = try Thread.spawn(.{ .allocator = alloc }, Client.handle, .{client});
        //try pool.append(handle_thread);

        try pool.spawn(Client.handle, .{client});
    }
}

fn hashFn(data: [][]const u8) u64 {
    var hash: u64 = 5381;
    for (data) |list| {
        for (list) |byte| {
            hash = ((hash << 5) + hash) + byte;
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

    fn handle(self: Client) void {
        self.handleDnsQuery() catch |err| {
            dns_mutex.lock();
            defer dns_mutex.unlock();
            std.debug.print("[{any}] client handle error: {}\n", .{ self.address, err });

            const message = "Not a valid DNS packet!";
            _ = posix.sendto(
                self.socket,
                message,
                0,
                &self.address.any,
                self.address.getOsSockLen(),
            ) catch |serr| {
                std.debug.print("[{any}] send error: {}\n", .{ self.address, serr });
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
            dns_mutex.lock();
            defer dns_mutex.unlock();
            //std.debug.print("Received DNS Packet: {any}\n", .{packet});
            const question = packet.questions[0];

            const qname_hash = hashFn(question.qname);

            if (dns_cache.get(qname_hash)) |cached_response| {
                // Return cached response
                std.debug.print("Cache hit for {s}\n", .{question.qname});

                std.mem.copyForwards(u8, response, cached_response);
                std.debug.print("Got: {x}\n", .{cached_response});
                len = cached_response.len;
            } else if (dns_store.get(qname_hash)) |address| {
                // Return local response
                std.debug.print("Found in local store: {s} -> {any}\n", .{ question.qname, address });

                var response_packet = createDnsResponse(packet, question.qname, address);
                const response_bytes = try response_packet.bytes(self.allocator);
                defer self.allocator.free(response_bytes);

                std.mem.copyForwards(u8, response, response_bytes);
                len = response_bytes.len;
            } else {
                // Query external server
                std.debug.print("Not found in local store, querying external server...\n", .{});

                const external_len = try self.queryExternalServer(query, response);
                const res = try self.allocator.alloc(u8, external_len);
                std.debug.print("Put: {x}\n", .{response[0..external_len]});
                std.mem.copyForwards(u8, res, response[0..external_len]);
                try dns_cache.put(qname_hash, res);
                len = external_len;
            }
        } else {
            return error.InvalidDNSQuery;
        }

        std.debug.print("Sending: {x}\n", .{response[0..len]});

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

    fn queryExternalServer(self: Client, query: []const u8, response: []u8) !usize {
        // TODO: Placeholder implementation
        _ = self;
        const external_server_port = 53;

        const addr = try net.Address.parseIp(resolv, external_server_port);
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
        },
        .questions = &[_]dns.Question{},
        .answers = &[_]dns.Record{},
        .authorities = &[_]dns.Record{},
        .additionals = &[_]dns.Record{},
    };
}
