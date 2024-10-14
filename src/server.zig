const std = @import("std");
const dns = @import("dns.zig");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const Thread = std.Thread;
const Mutex = std.Thread.Mutex;
const StringHashMap = std.StringHashMap;
const LRU = @import("util/lru.zig").LRU;

var dns_cache: LRU([]const u8) = undefined;
var dns_store: StringHashMap([]const u8) = undefined;
var dns_mutex: Mutex = Mutex{};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    dns_cache = LRU([]const u8).init(allocator, 100);
    defer dns_cache.deinit();

    dns_store = StringHashMap([]const u8).init(allocator);
    defer dns_store.deinit();

    // TODO: Change this line with local dns info
    try dns_store.put("example.com", &[4]u8{ 192, 168, 1, 1 });

    const addr = try net.Address.parseIp("127.0.0.1", 5553);

    const sock = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );

    defer posix.close(sock);

    try posix.bind(sock, &addr.any, addr.getOsSockLen());

    std.debug.print("Listen on {any}\n", .{addr});

    const max_packet_size = 1024;
    var buffer: [max_packet_size]u8 = undefined;

    while (true) {
        var from_addr: posix.sockaddr = undefined;
        var from_addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        const recv_len = try posix.recvfrom(
            sock,
            buffer[0..],
            0,
            &from_addr,
            &from_addrlen,
        );
        std.debug.print("Received {d} bytes from {any};\n", .{ recv_len, from_addr });

        // Spawn thread to handle DNS query
        var handle_thread = try Thread.spawn(.{ .allocator = allocator }, handleDnsQuery, .{ buffer[0..recv_len], buffer[recv_len..], from_addr, from_addrlen, sock, allocator });
        handle_thread.detach();
    }
}

fn hashFn(data: []const u8) u64 {
    var hash: u64 = 5381;
    for (data) |byte| {
        hash = ((hash << 5) + hash) + byte;
    }
    return hash;
}

fn handleDnsQuery(query: []const u8, response: []u8, from_addr: posix.sockaddr, from_addrlen: posix.socklen_t, sock: posix.socket_t, allocator: Allocator) !void {
    const header_len = 12;
    if (query.len < header_len) {
        return error.InvalidDNSQuery;
    }

    var len: usize = 0;

    var parser = dns.Parser.init(query, allocator);
    defer parser.deinit();

    if (try parser.read()) |packet| {
        //std.debug.print("Received DNS Packet: {any}\n", .{packet});

        dns_mutex.lock();
        defer dns_mutex.unlock();

        const question = packet.questions[0];
        const qname_hash = hashFn(question.qname);

        if (dns_cache.get(qname_hash)) |cached_response| {
            // Return cached response
            std.debug.print("Cache hit for {s}\n", .{question.qname});

            std.mem.copyForwards(u8, response, cached_response);
            std.debug.print("Got: {x}\n", .{cached_response});
            len = cached_response.len;
        } else if (dns_store.get(question.qname)) |address| {
            // Return local response
            std.debug.print("Found in local store: {s} -> {s}\n", .{ question.qname, address });

            var response_packet = createDnsResponse(packet, question.qname, address);
            const response_bytes = try response_packet.bytes(allocator);
            defer allocator.free(response_bytes);

            std.mem.copyForwards(u8, response, response_bytes);
            len = response_bytes.len;
        } else {
            // Query external server
            std.debug.print("Not found in local store, querying external server...\n", .{});

            const external_len = try queryExternalServer(query, response);
            try dns_cache.put(qname_hash, response[0..external_len]);
            len = external_len;
        }
    } else {
        std.debug.print("Not a valid DNS Packet: {s}\n", .{query});
        const message = "Not a valid DNS packet!";
        std.mem.copyForwards(u8, response, message);
        len = message.len;
    }

    std.debug.print("Sending: {x}\n", .{response[0..len]});

    _ = try posix.sendto(
        sock,
        response[0..len],
        0,
        &from_addr,
        from_addrlen,
    );
}

fn createDnsResponse(packet: dns.Message, qname: []const u8, address: []const u8) dns.Message {
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

fn queryExternalServer(query: []const u8, response: []u8) !usize {
    // TODO: Placeholder implementation
    const external_server_ip = "8.8.8.8";
    const external_server_port = 53;

    const addr = try net.Address.parseIp(external_server_ip, external_server_port);
    const sock = try posix.socket(
        posix.AF.INET,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );
    defer posix.close(sock);

    try posix.connect(sock, &addr.any, addr.getOsSockLen());
    _ = try posix.send(sock, query, 0);

    var buf: [512]u8 = undefined;
    const recv_bytes = try posix.recv(sock, buf[0..], 0);

    std.mem.copyForwards(u8, response, buf[0..recv_bytes]);
    return recv_bytes;
}
