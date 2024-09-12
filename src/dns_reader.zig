const std = @import("std");
const assert = std.debug.assert;
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

/// Extract flag values from flags int in `DnsHeader`
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

/// A DNS packet deserializer.
/// This struct internally stores a `std.heap.ArenaAllocator` for memory management.
/// To free all memory allocated in this struct call `deinit`
pub const Dns = struct {
    reader: Reader,
    arena: std.heap.ArenaAllocator,
    alloc: std.mem.Allocator,

    /// Deinitialize with `deinit`
    pub fn init(data: []const u8, alloc: std.mem.Allocator) Dns {
        return .{
            .reader = Reader.init(data),
            .arena = std.heap.ArenaAllocator.init(alloc),
            .alloc = undefined,
        };
    }

    /// Release all allocated memory
    pub fn deinit(self: *Dns) void {
        self.arena.deinit();
    }

    /// Parse `DnsPacket` from string of bytes `data`
    pub fn read(self: *Dns) !DnsPacket {
        self.alloc = self.arena.allocator();

        // Parse the packet header
        const header = try self.reader.read(DnsHeader);

        var packet: DnsPacket = .{
            .header = header,
            .question = std.mem.zeroInit(DnsQuestion, .{}),
            .answer = std.mem.zeroInit(DnsAnswer, .{}),
        };

        if (header.questions > 0) {
            // This packet contains a question
            packet.question = DnsQuestion{
                .qname = try self.handleName(),
                .qtype = try self.reader.read(u16),
                .qclass = try self.reader.read(u16),
            };
        }
        if (header.a_rr > 0) {
            // This packet contains an answer
            const name = try self.handleName();

            const typ: u16 = try self.reader.read(u16);
            const class: u16 = try self.reader.read(u16);
            const ttl: u32 = try self.reader.read(u32);
            const rdlength: u16 = try self.reader.read(u16);
            const rdata = try self.alloc.alloc(u8, @as(usize, rdlength));

            try readList(rdata, &self.reader, @as(usize, rdlength));

            // Unfortunatly we have to do it this way so we can properly read rdata(need rdlength)
            packet.answer = DnsAnswer{
                .name = name,
                .type = typ,
                .class = class,
                .ttl = ttl,
                .rdlength = rdlength,
                .rdata = rdata,
            };
        }

        return packet;
    }

    /// Reads name/qname field from packet, returns list of strings
    /// *Internal use only
    inline fn handleName(self: *Dns) ![][]u8 {
        var list = std.ArrayList([]u8).init(self.alloc);

        const pointer: u16 = try self.reader.read(u16);
        if ((pointer & 0xF) == 0xc) {
            const offset = @as(usize, pointer & 0xFFF);
            var tmp_rd = Reader.init(self.reader.bytes[offset..]);
            try self.read2DList(&tmp_rd, &list);
        } else {
            self.reader.index -= 2;
            try self.read2DList(&self.reader, &list);
        }

        return list.toOwnedSlice();
    }

    /// Reads a list of u8 values from the reader into the buffer
    /// *Internal use only
    inline fn readList(buf: []u8, reader: *Reader, size: usize) !void {
        for (0..size) |i| {
            buf[i] = try reader.read(u8);
        }
    }

    /// Reads name fields of packet
    /// *Internal use only
    inline fn read2DList(self: *Dns, reader: *Reader, list: *std.ArrayList([]u8)) !void {
        var size: u8 = try reader.read(u8);
        var i: usize = 0;
        while (size != 0x00) : (i += 1) {
            try list.append(try self.alloc.alloc(u8, @as(usize, size)));
            try readList(list.items[i], reader, @as(usize, size));
            size = try reader.read(u8);
        }
    }
};

test "read" {
    const allocator = std.testing.allocator;
    const data = [_]u8{ 0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44 };

    var dns = Dns.init(&data, allocator);
    defer dns.deinit();

    const packet = try dns.read();

    const flags = getFlags(packet.header);
    std.debug.print("{}\n", .{flags});
    assert(flags.qr == 1);
    assert(flags.opcode == 0);
    assert(flags.rd == 1);
    assert(flags.ra == 1);

    var buf: [32]u8 = undefined;

    const addr = try std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
        packet.answer.rdata[0],
        packet.answer.rdata[1],
        packet.answer.rdata[2],
        packet.answer.rdata[3],
    });

    std.debug.print("{s}.{s}.{s}\nAddr: {s}\n", .{ packet.answer.name[0], packet.answer.name[1], packet.answer.name[2], addr });
}
