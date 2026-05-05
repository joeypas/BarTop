pub const Algorithm = enum(u8) {
    rsamd5 = 1,
    dsa = 3,
    rsasha1 = 5,
    rsasha1nsec3sha1 = 7,
    rsasha256 = 8,
    rsasha512 = 10,
    ecdsap256sha256 = 13,
    ecdsap384sha384 = 14,
    ed25519 = 15,
    ed448 = 16,
    unknown = 255,
    _,
};

pub const KeyProtocol = enum(u8) {
    tls = 1,
    email = 2,
    dnssec = 3,
    ipsec = 4,
    all = 255,
    _,
};

pub const DigestType = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    gost3411 = 3,
    sha384 = 4,
    sha512 = 5,
    sha224 = 6,
    unknown = 255,
    _,
};

pub const NSEC3HashAlgorithm = enum(u8) {
    sha1 = 1,
    sha256 = 2,
    gost3411 = 3,
    sha384 = 4,
    sha512 = 5,
    sha224 = 6,
    unknown = 255,
    _,
};

