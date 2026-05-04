const std = @import("std");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

pub const ResponseCode = enum(u4) {
    no_error,
    format_error,
    server_failure,
    name_error,
    not_implemented,
    refused,
    _,
};

pub const OpCode = enum(u4) {
    query,
    iquery,
    status,
    _,
};

// bitcast to go from struct to int
pub const Flags = packed struct {
    response_code: ResponseCode = .no_error,
    check_disable: bool = false,
    authenticated: bool = false,
    z: u1 = 0,
    recursion_available: bool = false,
    recursion_desired: bool = false,
    truncated: bool = false,
    authoritative: bool = false,
    op_code: OpCode = .query,
    response: bool = false,
};

pub const Header = packed struct {
    id: u16 = 0,
    flags: Flags = .{},
    /// Question count
    qd_count: u16 = 0,
    /// Answer count
    an_count: u16 = 0,
    /// Authority count
    ns_count: u16 = 0,
    // Additional count
    ar_count: u16 = 0,

    pub fn decode(reader: *Reader) !Header {
        return Header{
            .id = try reader.takeInt(u16, .big),
            .flags = @bitCast(try reader.takeInt(u16, .big)),
            .qd_count = try reader.takeInt(u16, .big),
            .an_count = try reader.takeInt(u16, .big),
            .ns_count = try reader.takeInt(u16, .big),
            .ar_count = try reader.takeInt(u16, .big),
        };
    }

    pub fn encode(self: *Header, writer: *Writer) !usize {
        try writer.writeInt(u16, self.id, .big);
        try writer.writeInt(u16, @bitCast(self.flags), .big);
        try writer.writeInt(u16, self.qd_count, .big);
        try writer.writeInt(u16, self.an_count, .big);
        try writer.writeInt(u16, self.ns_count, .big);
        try writer.writeInt(u16, self.ar_count, .big);
        return 12;
    }

    pub fn print(self: *Header, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(
            buf,
            \\Header: [
            \\  id: {d},
            \\  flags: {any},
            \\  qd_count: {d},
            \\  an_count: {d},
            \\  ns_count: {d},
            \\  ar_count: {d},
            \\],
        ,
            .{ self.id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count },
        );
    }

    pub fn format(self: Header, writer: *std.Io.Writer) !void {
        try writer.print(
            \\Header: [
            \\  id: {d},
            \\  flags: {any},
            \\  qd_count: {d},
            \\  an_count: {d},
            \\  ns_count: {d},
            \\  ar_count: {d},
            \\],
        ,
            .{ self.id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count },
        );
    }
};
