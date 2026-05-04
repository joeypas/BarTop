const std = @import("std");
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const rr = @import("rr.zig");

pub const Bytes = union(enum) {
    borrowed: []const u8,
    owned: ArrayList(u8),

    pub fn init() Bytes {
        return .{ .owned = .empty };
    }

    pub fn fromBorrowed(bytes: []const u8) Bytes {
        return .{ .borrowed = bytes };
    }

    pub fn deinit(self: *Bytes, allocator: Allocator) void {
        switch (self.*) {
            .borrowed => {},
            .owned => |*list| list.deinit(allocator),
        }
        self.* = .{ .owned = .empty };
    }

    pub fn clone(self: *const Bytes, allocator: Allocator) !Bytes {
        const data = self.asSlice();
        var out = try ArrayList(u8).initCapacity(allocator, data.len);
        out.appendSliceAssumeCapacity(data);
        return .{ .owned = out };
    }

    pub fn appendSlice(self: *Bytes, allocator: Allocator, data: []const u8) !void {
        var list = try self.ensureOwned(allocator);
        try list.appendSlice(allocator, data);
    }

    pub fn parse(self: *Bytes, allocator: Allocator, data: []const u8) !void {
        try self.appendSlice(allocator, data);
    }

    pub fn asSlice(self: *const Bytes) []const u8 {
        return switch (self.*) {
            .borrowed => |bytes| bytes,
            .owned => |list| list.items,
        };
    }

    pub fn getLen(self: *const Bytes) u16 {
        return @intCast(self.asSlice().len);
    }

    pub fn encode(self: *const Bytes, writer: *Writer) !usize {
        return writer.write(self.asSlice());
    }

    pub fn format(self: Bytes, writer: *std.Io.Writer) !void {
        var copy = self;
        try writer.print("{s}", .{copy.asSlice()});
    }

    pub fn ensureOwned(self: *Bytes, allocator: Allocator) !*ArrayList(u8) {
        switch (self.*) {
            .owned => |*list| return list,
            .borrowed => |bytes| {
                var out = try ArrayList(u8).initCapacity(allocator, bytes.len);
                out.appendSliceAssumeCapacity(bytes);
                self.* = .{ .owned = out };
                return &self.owned;
            },
        }
    }
};

pub const Algorithm = enum(u8) {
    rsamd5 = 1, // RSA/MD5 [RFC4034][RFC3110]
    dsa = 3, // DSA/SHA-1 [RFC3755][RFC2536]
    rsasha1 = 5, // RSA/SHA-1 [RFC3110]
    rsasha1nsec3sha1 = 7, // [RFC5155]
    rsasha256 = 8, // RSA/SHA-256 [RFC5702]
    rsasha512 = 10, // RSA/SHA-512 [RFC5702]
    ecdsap256sha256 = 13, // ECDSA Curve P-256 with SHA-256 [RFC6605]
    ecdsap384sha384 = 14, // ECDSA Curve P-384 with SHA-384 [RFC6605]
    ed25519 = 15, // Ed25519 [RFC8080]
    ed448 = 16, // Ed448 [RFC8080]
    unknown = 255, // Reserved for Private Use
};

pub const KeyProtocol = enum(u8) {
    tls = 1,
    email = 2,
    dnssec = 3,
    ipsec = 4,
    all = 255,
};

pub const DigestType = enum(u8) {
    sha1 = 1, // SHA-1 [RFC3658]
    sha256 = 2, // SHA-256 [RFC4509]
    gost3411 = 3, // GOST R 34.11-94 [RFC5933]
    sha384 = 4, // SHA-384 [RFC6605]
    sha512 = 5, // SHA-512 [RFC6605]
    sha224 = 6, // SHA-224 [RFC6605]
    unknown = 255, // Reserved for Private Use
};

pub const NSEC3HashAlgorithm = enum(u8) {
    sha1 = 1, // [RFC5155]
    sha256 = 2, // [RFC6605]
    gost3411 = 3, // [RFC5933]
    sha384 = 4, // [RFC6605]
    sha512 = 5, // [RFC6605]
    sha224 = 6, // [RFC6605]
    unknown = 255, // Reserved for Private Use,
};

pub const DnsKey = struct {
    flags: u16,
    protocol: KeyProtocol,
    algorithm: Algorithm,
    public_key: Bytes,
};

pub const DS = struct {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: Bytes,
};

pub const Sig = struct {
    type_covered: rr.Type,
    algorithm: Algorithm,
    label_count: u8,
    original_ttl: u32,
    expiration: i64,
    inception: i64,
    key_tag: u16,
    signers_name: rr.Name,
    signature: Bytes,
};

pub const NSEC3 = struct {
    hash_algorithm: NSEC3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt_len: u8,
    salt: Bytes,
    hash_len: u8,
    hash: Bytes,
    type_bitmap: Bytes,
};

pub const NSEC = struct {
    next_name: rr.Name,
    type_bitmap: Bytes,
};
