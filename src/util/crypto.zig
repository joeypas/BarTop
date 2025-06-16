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

pub const Key = struct {
    pkey: ?*c.EVP_PKEY,
    ctx: Context,
    bits: usize,
    algorithm: dnssec.Algorithm,
    digest: Digest,

    pub fn init(ctx: Context, algorithm: dnssec.Algorithm, bits: usize) Key {
        return Key{
            .pkey = null,
            .ctx = ctx,
            .algorithm = algorithm,
            .bits = bits,
            .digest = switch (algorithm) {
                .rsamd5 => Digest.md5,
                .dsa, .rsasha1, .rsasha1nsec3sha1 => Digest.sha1,
                .ecdsap256sha256, .rsasha256 => Digest.sha256,
                .ecdsap384sha384 => Digest.sha384,
                .rsasha512 => Digest.sha512,
                else => Digest.none,
            },
        };
    }

    pub fn deinit(self: *Key) void {
        c.EVP_PKEY_free(self.pkey);
    }

    pub fn gen(self: *Key) !void {
        switch (self.algorithm) {
            .dsa => try self.genDSA(),
            .rsasha1, .rsasha1nsec3sha1, .rsasha256, .rsasha512, .rsamd5 => try self.genRSA(),
            .ecdsap256sha256, .ecdsap384sha384 => try self.genEC(),
            .ed25519 => try self.genED(),
            else => return error.NotImplemented,
        }
    }

    fn genRSA(self: *Key) !void {
        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "RSA", self.bits);

        if (self.pkey == null) return error.GenerateKey;
    }

    fn genDSAParams(self: *Key) !?*c.EVP_PKEY {
        var ret: ?*c.EVP_PKEY = null;
        var ctx: ?*c.EVP_PKEY_CTX = null;

        ctx = c.EVP_PKEY_CTX_new_from_name(self.ctx.libctx, "DSA", propq);
        defer c.EVP_PKEY_CTX_free(ctx);
        if (ctx == null) return error.CreateContext;

        if (c.EVP_PKEY_paramgen_init(ctx) <= 0 or c.EVP_PKEY_paramgen(ctx, &ret) <= 0) return error.GenerateParams;

        return ret;
    }

    fn genDSA(self: *Key) !void {
        var ctx: ?*c.EVP_PKEY_CTX = null;
        const dsa_params = try self.genDSAParams();
        defer c.EVP_PKEY_free(dsa_params);

        ctx = c.EVP_PKEY_CTX_new_from_pkey(self.ctx.libctx, dsa_params, propq);
        defer c.EVP_PKEY_CTX_free(ctx);
        if (ctx == null) return error.CreateContext;

        if (c.EVP_PKEY_keygen_init(ctx) <= 0 or c.EVP_PKEY_keygen(ctx, &self.pkey) <= 0) return error.GenerateKey;
    }

    fn genEC(self: *Key) !void {
        self.pkey = switch (self.algorithm) {
            .ecdsap256sha256 => c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "EC", "P-256"),
            .ecdsap384sha384 => c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "EC", "P-384"),
            else => unreachable,
        };
    }

    fn genED(self: *Key) !void {
        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "ED25519");

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

        if (c.i2d_RSAPrivateKey_bio(bpriv, self.pkey) == 0) return error.WriteKey;
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
        if (self.algorithm == .ed25519) return self.signED(allocator, message);
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
        if (self.algorithm == .ed25519) return self.verifyED(sig, message);
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
};
