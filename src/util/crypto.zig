const std = @import("std");
const Allocator = std.mem.Allocator;
const dnssec = @import("../dnssec.zig");
const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/params.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/core_names.h");
    @cDefine("OPENSSL_NO_DEPRECATED", {});
});

var propq: [*]u8 = undefined;

pub const Context = struct {
    libctx: ?*c.OSSL_LIB_CTX,

    pub fn init() Context {
        return Context{
            .libctx = null,
        };
    }

    pub fn deinit(self: *Context) void {
        c.OSSL_LIB_CTX_free(self.libctx);
    }
};

const Digest = enum {
    md5,
    sha1,
    sha256,
    sha384,
    sha512,
    none,
};

// TODO: Once zig std has better crypto support (only EC, ED25519 have keygen/signing) migrate to that
pub const Key = struct {
    pkey: ?*c.EVP_PKEY,
    ctx: Context,
    bits: usize = 2048,
    algorithm: dnssec.Algorithm,
    digest: Digest,
    allocator: Allocator,

    pub fn init(allocator: Allocator, ctx: Context, algorithm: dnssec.Algorithm) Key {
        return Key{
            .pkey = null,
            .ctx = ctx,
            .algorithm = algorithm,
            .digest = switch (algorithm) {
                .rsamd5 => Digest.md5,
                .rsasha1, .rsasha1nsec3sha1 => Digest.sha1,
                .ecdsap256sha256, .rsasha256 => Digest.sha256,
                .ecdsap384sha384 => Digest.sha384,
                .rsasha512 => Digest.sha512,
                else => Digest.none,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Key) void {
        c.EVP_PKEY_free(self.pkey);
    }

    pub fn gen(self: *Key) !void {
        switch (self.algorithm) {
            .rsasha1, .rsasha1nsec3sha1, .rsasha256, .rsasha512, .rsamd5 => try self.genRSA(),
            .ecdsap256sha256, .ecdsap384sha384 => try self.genEC(),
            .ed25519, .ed448 => try self.genED(),
            else => return error.NotImplemented,
        }
    }

    fn genRSA(self: *Key) !void {
        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "RSA", self.bits);

        if (self.pkey == null) return error.GenerateKey;
    }

    fn genEC(self: *Key) !void {
        const group = switch (self.algorithm) {
            .ecdsap256sha256 => "P-256",
            .ecdsap384sha384 => "P-384",
            else => unreachable,
        };

        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "EC", group);
    }

    fn genED(self: *Key) !void {
        const typ = switch (self.algorithm) {
            .ed25519 => "ED25519",
            .ed448 => "ED448",
            else => unreachable,
        };
        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, typ);

        if (self.pkey == null) return error.GenerateKey;
    }

    pub fn fromFilePem(self: *Key, key_path: []const u8) !void {
        const bpriv = c.BIO_new_file(key_path.ptr, "r");
        defer c.BIO_free_all(bpriv);

        self.pkey = c.PEM_read_bio_PrivateKey_ex(bpriv, null, null, null, self.ctx.libctx, propq);
        if (self.pkey == null) return error.ReadKey;
    }

    pub fn fromFileDer(self: *Key, key_path: []const u8) !void {
        const bpriv = c.BIO_new_file(key_path.ptr, "r");
        defer c.BIO_free_all(bpriv);

        self.pkey = c.d2i_PrivateKey_ex_bio(bpriv, null, self.ctx.libctx, propq);
        if (self.pkey == null) return error.ReadKey;
    }

    pub fn toFilePem(self: Key, key_path: []const u8) !void {
        if (self.pkey == null) return error.KeyNotGenerated;
        const bpriv = c.BIO_new_file(key_path.ptr, "w+");
        defer c.BIO_free_all(bpriv);

        if (c.PEM_write_bio_PrivateKey(bpriv, self.pkey, null, null, 0, null, null) == 0) return error.WriteKey;
    }

    pub fn toFileDer(self: Key, key_path: []const u8) !void {
        if (self.pkey == null) return error.KeyNotGenerated;
        const bpriv = c.BIO_new_file(key_path.ptr, "w+");
        defer c.BIO_free_all(bpriv);

        if (c.i2d_PrivateKey_bio(bpriv, self.pkey) == 0) return error.WriteKey;
    }

    fn signED(self: *Key, allocator: Allocator, message: []const u8) ![]const u8 {
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;
        var sig_len: usize = 0;

        if (c.EVP_DigestSignInit_ex(mctx, null, null, self.ctx.libctx, propq, self.pkey, null) == 0) return error.InitializeContext;

        if (c.EVP_DigestSign(mctx, null, &sig_len, message.ptr, message.len) == 0) return error.GetSigLen;

        const sig = try allocator.alloc(u8, sig_len);
        errdefer allocator.free(sig);

        if (c.EVP_DigestSign(mctx, sig.ptr, &sig_len, message.ptr, message.len) == 0) return error.Sign;

        return sig;
    }

    fn verifyED(self: *Key, sig: []const u8, message: []const u8) !bool {
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;

        if (c.EVP_DigestVerifyInit_ex(mctx, null, null, self.ctx.libctx, propq, self.pkey, null) == 0) return error.InitializeContext;

        if (c.EVP_DigestVerify(mctx, sig.ptr, sig.len, message.ptr, message.len) == 0) return false;

        return true;
    }

    pub fn sign(self: *Key, allocator: Allocator, message: []const u8) ![]const u8 {
        if (self.algorithm == .ed25519 or self.algorithm == .ed448) return self.signED(allocator, message);
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;
        var sig_len: usize = 0;

        const name = switch (self.digest) {
            .md5 => "MD5",
            .sha1 => "SHA1",
            .sha256 => "SHA256",
            .sha512 => "SHA512",
            .sha384 => "SHA384",
            else => null,
        };

        if (c.EVP_DigestSignInit_ex(mctx, null, name orelse null, self.ctx.libctx, propq, self.pkey, null) == 0) return error.InitializeContext;

        if (c.EVP_DigestSignUpdate(mctx, message.ptr, message.len) == 0) return error.HashMessage;

        if (c.EVP_DigestSignFinal(mctx, null, &sig_len) == 0) return error.GetSigLen;

        const sig = try allocator.alloc(u8, sig_len);
        errdefer allocator.free(sig);

        if (c.EVP_DigestSignFinal(mctx, sig.ptr, &sig_len) == 0) return error.Sign;

        return sig;
    }

    pub fn verify(self: *Key, sig: []const u8, message: []const u8) !bool {
        if (self.algorithm == .ed25519 or self.algorithm == .ed448) return self.verifyED(sig, message);
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;

        const name = switch (self.digest) {
            .md5 => "MD5",
            .sha1 => "SHA1",
            .sha256 => "SHA256",
            .sha512 => "SHA512",
            .sha384 => "SHA384",
            else => null,
        };

        if (c.EVP_DigestVerifyInit_ex(mctx, null, name orelse null, self.ctx.libctx, propq, self.pkey, null) == 0) return error.InitializeContext;

        if (c.EVP_DigestVerifyUpdate(mctx, message.ptr, message.len) == 0) return error.HashMessage;

        if (c.EVP_DigestVerifyFinal(mctx, sig.ptr, sig.len) == 0) return false;

        return true;
    }

    pub fn publicKeyBase64(self: *Key, allocator: Allocator) ![]const u8 {
        const enc = std.base64.standard.Encoder;

        const key = try self.publicKey(allocator);
        defer allocator.free(key);

        var buf = try allocator.alloc(u8, enc.calcSize(key.len));
        return enc.encode(buf[0..], key);
    }

    pub fn publicKey(self: *Key, allocator: Allocator) ![]const u8 {
        return switch (c.EVP_PKEY_id(self.pkey)) {
            c.EVP_PKEY_RSA => self.buildRSADnskey(allocator),
            c.EVP_PKEY_EC => self.buildECDSADnskey(allocator),
            c.EVP_PKEY_ED25519, c.EVP_PKEY_ED448 => self.buildEDDnskey(allocator),
            else => error.InvalidKeyType,
        };
    }

    pub fn fromBase64(self: *Key, buf: []const u8) !void {
        const dec = std.base64.standard.Decoder;
        const len = try dec.calcSizeForSlice(buf);
        var buf_d = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf_d);
        try dec.decode(buf_d[0..], buf);

        return self.fromRaw(buf_d);
    }

    pub fn fromRaw(self: *Key, buf: []const u8) !void {
        return switch (c.EVP_PKEY_id(self.pkey)) {
            c.EVP_PKEY_RSA => self.fromRawRSA(buf),
            c.EVP_PKEY_EC => self.fromRawECDSA(buf),
            c.EVP_PKEY_ED25519, c.EVP_PKEY_ED448 => self.fromRawED(buf),
            else => error.InvalidKeyType,
        };
    }

    fn buildRSADnskey(self: *Key, allocator: Allocator) ![]const u8 {
        const n = try self.getBn(allocator, c.OSSL_PKEY_PARAM_RSA_N);
        defer allocator.free(n);
        const e = try self.getBn(allocator, c.OSSL_PKEY_PARAM_RSA_E);
        defer allocator.free(e);

        const size: usize = if (e.len < 256) 1 else 3;
        var buf = try allocator.alloc(u8, e.len + n.len + size);
        var pos: usize = 0;
        if (e.len < 256) {
            buf[pos] = @intCast(e.len);
            pos += 1;
        } else {
            buf[pos] = 0;
            pos += 1;
            buf[pos] = @intCast(e.len >> 8);
            pos += 1;
            buf[pos] = @intCast(e.len);
            pos += 1;
        }

        @memcpy(buf[pos .. pos + e.len], e);
        pos += e.len;
        @memcpy(buf[pos..], n);

        return buf;
    }

    fn buildEDDnskey(self: *Key, allocator: Allocator) ![]const u8 {
        return self.getOct(allocator, c.OSSL_PKEY_PARAM_PUB_KEY);
    }

    fn buildECDSADnskey(self: *Key, allocator: Allocator) ![]const u8 {
        const sec = try self.getOct(allocator, c.OSSL_PKEY_PARAM_PUB_KEY);
        defer allocator.free(sec);
        return allocator.dupe(u8, sec[1..]);
    }

    fn fromRawRSA(self: *Key, buf: []const u8) !void {
        var e_len: usize = 0;
        var pos: usize = 0;
        e_len = if (buf[0] == 0x00) (@as(usize, @intCast(buf[1])) << 8) | buf[2] else @intCast(buf[0]);
        pos = if (buf[0] == 0x00) 3 else 1;

        const rsa_params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_BN(c.OSSL_PKEY_PARAM_RSA_N, buf[pos + e_len ..].ptr, buf.len - pos - e_len),
            c.OSSL_PARAM_BN(c.OSSL_PKEY_PARAM_RSA_E, buf[pos..].ptr, e_len),
            c.OSSL_PARAM_END,
        };

        try self.fromParams(rsa_params, "RSA");
    }

    fn fromRawECDSA(self: *Key, buf: []const u8) !void {
        const group = switch (self.algorithm) {
            .ecdsap256sha256 => "P-256",
            .ecdsap384sha384 => "P-384",
            else => unreachable,
        };

        var sec = try self.allocator.alloc(u8, buf.len + 1);
        defer self.allocator.free(sec);
        sec[0] = 0x04;
        @memcpy(sec[1..], buf);

        const ec_params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_utf8_string(c.OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
            c.OSSL_PARAM_octet_string(c.OSSL_PKEY_PARAM_PUB_KEY, sec.ptr, sec.len),
            c.OSSL_PARAM_END,
        };

        try self.fromParams(ec_params, "EC");
    }

    fn fromRawED(self: *Key, buf: []const u8) !void {
        const ed_params = [_]c.OSSL_PARAM{
            c.OSSL_PARAM_octet_string(c.OSSL_PKEY_PARAM_PUB_KEY, buf.ptr, buf.len),
            c.OSSL_PARAM_END,
        };

        try self.fromParams(ed_params, "ED25519");
    }

    fn fromParams(self: *Key, params: []c.OSSL_PARAM, key_type: []const u8) !void {
        const ctx: ?*c.EVP_PKEY_CTX = c.EVP_PKEY_CTX_new_from_name(self.ctx.libctx, key_type.ptr, propq);
        defer c.EVP_PKEY_CTX_free(ctx);
        if (ctx == null) return error.CreateContext;

        if (c.EVP_PKEY_fromdata_init(ctx) <= 0) return error.FromDataInit;
        if (c.EVP_PKEY_fromdata(ctx, &self.pkey, c.EVP_PKEY_PUBLIC_KEY, params.ptr) <= 0) return error.FromData;
    }

    fn getBn(self: *Key, allocator: Allocator, name: []const u8) ![]u8 {
        var bn: ?*c.BIGNUM = null;
        defer c.BN_free(bn);

        if (c.EVP_PKEY_get_bn_param(self.pkey, name.ptr, &bn) <= 0) return error.GetParam;
        const out = try allocator.alloc(u8, @intCast(c.BN_num_bytes(bn)));
        _ = c.BN_bn2bin(bn, out.ptr);

        return out;
    }

    fn getOct(self: *Key, allocator: Allocator, name: []const u8) ![]u8 {
        var len: usize = 0;
        if (c.EVP_PKEY_get_octet_string_param(self.pkey, name.ptr, null, 0, &len) <= 0) return error.GetParam;

        const buf = try allocator.alloc(u8, len);
        errdefer allocator.free(buf);
        if (c.EVP_PKEY_get_octet_string_param(self.pkey, name.ptr, buf.ptr, len, &len) <= 0) return error.GetParam;

        return buf;
    }
};
