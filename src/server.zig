const std = @import("std");
const dns = @import("dns.zig");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
        std.debug.print("Recieved {d} bytes from {any};\n", .{ recv_len, from_addr });

        const respose_len = try handleDnsQuery(buffer[0..recv_len], buffer[recv_len..], allocator);
        _ = try posix.sendto(
            sock,
            buffer[0..respose_len],
            0,
            &from_addr,
            from_addrlen,
        );
    }
}

fn handleDnsQuery(query: []const u8, response: []u8, allocator: Allocator) !usize {
    const header_len = 12;
    if (query.len < header_len) {
        return error.InvalidDNSQuery;
    }

    var parser = dns.Parser.init(query, allocator);
    defer parser.deinit();

    const packet = parser.read() catch
        dns.Message{
        .header = undefined,
        .questions = undefined,
        .answers = undefined,
        .authorities = undefined,
        .additionals = undefined,
    };

    _ = packet;
    std.mem.copyForwards(u8, response, query);
    return query.len;
}
