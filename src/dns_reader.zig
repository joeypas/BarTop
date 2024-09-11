const std = @import("std");
const Reader = @import("reader.zig");
const bigToNative = std.mem.bigToNative;

pub const DnsHeader = struct {
    id: u16,
    flags: u16,
    questions: u16,
    a_rr: u16,
    au_rr: u16,
    ad_rr: u16,
};

pub const DnsQuestion = struct {
    qname: [][]u8,
    qtype: u16,
    qclass: u16,
};

pub const DnsAnswer = struct {
    name: [][]u8,
    type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []u8,
};

pub const DnsPacket = struct {
    header: DnsHeader,
    question: DnsQuestion,
    answer: DnsAnswer,
};

pub const Flags = struct {
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    ad: u8,
    cd: u8,
    rcode: u8,
};

pub fn getFlags(header: DnsHeader) Flags {
    const f = header.flags;
    return Flags{
        .qr = bigToNative(u8, @intCast((f & 0x8000) >> 15)),
        .opcode = bigToNative(u8, @intCast((f & 0x7800) >> 11)),
        .aa = bigToNative(u8, @intCast((f & 0x0400) >> 10)),
        .tc = bigToNative(u8, @intCast((f & 0x0200) >> 9)),
        .rd = bigToNative(u8, @intCast((f & 0x0100) >> 8)),
        .ra = bigToNative(u8, @intCast((f & 0x0080) >> 7)),
        .z = bigToNative(u8, @intCast((f & 0x0070) >> 4)),
        .ad = bigToNative(u8, @intCast((f & 0x0020) >> 5)),
        .cd = bigToNative(u8, @intCast((f & 0x0010) >> 4)),
        .rcode = bigToNative(u8, @intCast(f & 0x00F)),
    };
}

pub const Dns = struct {
    reader: Reader,
    arena: std.heap.ArenaAllocator,
    alloc: std.mem.Allocator,
    //packet: DnsPacket,

    pub fn init(data: []const u8, alloc: std.mem.Allocator) Dns {
        return .{
            .reader = Reader.init(data),
            .arena = std.heap.ArenaAllocator.init(alloc),
            //.packet = undefined,
            .alloc = undefined,
        };
    }

    pub fn deinit(self: *Dns) void {
        self.arena.deinit();
    }

    pub fn read(self: *Dns) !DnsPacket {
        self.alloc = self.arena.allocator();
        const header = try self.reader.read(DnsHeader);

        if (header.questions > 0) {
            var qname = std.ArrayList([]u8).init(self.alloc);

            var size: u8 = try self.reader.read(u8);
            var i: usize = 0;
            while (size != 0x00) : (i += 1) {
                try qname.append(try self.alloc.alloc(u8, @as(usize, size)));
                for (0..@as(usize, size)) |j| {
                    qname.items[i][j] = try self.reader.read(u8);
                }
                size = try self.reader.read(u8);
            }

            const qtype: u16 = try self.reader.read(u16);
            const qclass: u16 = try self.reader.read(u16);

            return DnsPacket{
                .header = header,
                .question = .{
                    .qname = try qname.toOwnedSlice(),
                    .qtype = qtype,
                    .qclass = qclass,
                },
                .answer = undefined,
            };
        } else {
            return error.Implement;
        }
    }
};

test "read" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44 };

    var dns = Dns.init(&data, allocator);
    defer dns.deinit();

    const packet = try dns.read();

    const flags = getFlags(packet.header);
    std.debug.print("{}\n", .{flags});

    std.debug.print("{s}.{s}.{s}\n", .{ packet.question.qname[0], packet.question.qname[1], packet.question.qname[2] });
}
