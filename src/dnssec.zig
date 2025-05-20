const std = @import("std");
const ArrayList = std.ArrayList;
const DNS = @import("dns.zig");

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
    public_key: ArrayList(u8),
};

pub const DS = struct {
    key_tag: u16,
    algorithm: Algorithm,
    digest_type: DigestType,
    digest: ArrayList(u8),
};

pub const Sig = struct {
    type_covered: DNS.Type,
    algorithm: Algorithm,
    label_count: u8,
    original_ttl: u32,
    expiration: i64,
    inception: i64,
    key_tag: u16,
    signers_name: DNS.Name,
    signature: ArrayList(u8),
};
