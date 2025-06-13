const std = @import("std");
const Allocator = std.mem.Allocator;
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

pub const Key = struct {
    pkey: ?*c.EVP_PKEY,
    ctx: Context,
    bits: usize,

    pub fn init(ctx: Context, bits: usize) Key {
        return Key{
            .pkey = null,
            .ctx = ctx,
            .bits = bits,
        };
    }

    pub fn deinit(self: *Key) void {
        c.EVP_PKEY_free(self.pkey);
    }

    pub fn gen(self: *Key) !void {
        self.pkey = c.EVP_PKEY_Q_keygen(self.ctx.libctx, propq, "RSA", self.bits);

        if (self.pkey == null) return error.GenerateKey;
    }

    pub fn sign(self: *Key, allocator: Allocator, message: []const u8) ![]const u8 {
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;
        var sig_len: usize = 0;

        var params: [2]c.OSSL_PARAM = undefined;

        var buf: [3]u8 = [_]u8{ 'p', 's', 's' };

        params[0] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_PAD_MODE, &buf, 0);
        params[1] = c.OSSL_PARAM_construct_end();

        if (c.EVP_DigestSignInit_ex(mctx, null, "SHA256", self.ctx.libctx, propq, self.pkey, &params) == 0) return error.InitializeContext;

        if (c.EVP_DigestSignUpdate(mctx, message.ptr, message.len) == 0) return error.HashMessage;

        if (c.EVP_DigestSignFinal(mctx, null, &sig_len) == 0) return error.GetSigLen;

        const sig = try allocator.alloc(u8, sig_len);
        errdefer allocator.free(sig);

        if (c.EVP_DigestSignFinal(mctx, sig.ptr, &sig_len) == 0) return error.Sign;

        return sig;
    }

    pub fn verify(self: *Key, sig: []const u8, message: []const u8) !bool {
        const mctx = c.EVP_MD_CTX_new();
        defer c.EVP_MD_CTX_free(mctx);
        if (mctx == null) return error.CreateContext;

        var params: [2]c.OSSL_PARAM = undefined;
        var buf: [3]u8 = [_]u8{ 'p', 's', 's' };

        params[0] = c.OSSL_PARAM_construct_utf8_string(c.OSSL_SIGNATURE_PARAM_PAD_MODE, &buf, 0);
        params[1] = c.OSSL_PARAM_construct_end();

        if (c.EVP_DigestVerifyInit_ex(mctx, null, "SHA256", self.ctx.libctx, propq, self.pkey, &params) == 0) return error.InitializeContext;

        if (c.EVP_DigestVerifyUpdate(mctx, message.ptr, message.len) == 0) return error.HashMessage;

        if (c.EVP_DigestVerifyFinal(mctx, sig.ptr, sig.len) == 0) return false;

        return true;
    }
};
