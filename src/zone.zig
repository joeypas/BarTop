const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const Dns = @import("dns.zig");
const Record = Dns.Record;
const Name = Dns.Name;

// TODO: This needs a full rewrite

pub const Zone = struct {
    origin: Name,
    ttl: u32,
    soa: Record,
    records: ArrayList(Record),
    arena: Arena,

    pub fn init(allocator: Allocator) Zone {
        var arena = Arena.init(allocator);
        const alloc = arena.allocator();
        return .{
            .origin = Name.init(alloc),
            .ttl = 0,
            .soa = Record.init(alloc, .soa),
            .records = ArrayList(Record).init(alloc),
            .arena = arena,
        };
    }

    pub fn deinit(self: *Zone) void {
        self.arena.deinit();
    }

    pub fn parseFile(self: *Zone, path: []const u8) !void {
        const alloc = self.arena.allocator();
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const stat = try file.stat();

        const contents = try file.readToEndAlloc(alloc, stat.size);

        var state = ParserState{
            .origin = "",
            .ttl = 0,
            .prev_owner = "",
            .prev_class = "",
        };
        var tokenizer = Tokenizer.init(contents);

        while (tokenizer.next()) |tok| {
            switch (tok.tag) {
                .newline => continue,
                .eof => break,
                .directive => try self.parseDirective(),
                else => try self.parseRecord(tok, &state, &tokenizer),
            }
        }
    }

    fn parseRecord(self: *Zone, first: Token, state: *ParserState, tokenizer: *Tokenizer) !void {
        const alloc = self.arena.allocator();
        var prefix = ArrayList(Token).init(alloc);
        defer prefix.deinit();

        var typ: Dns.Type = undefined;
        if (!first.isType()) {
            try prefix.append(first);
            while (tokenizer.next()) |tok| {
                if (tok.parseType()) |t| {
                    typ = t;
                    break;
                }
                try prefix.append(tok);
            }
        }

        var owner: ?[]const u8 = null;
        var ttl: ?u32 = null;
        var cls: ?Dns.Class = null;

        for (prefix.items) |tok| switch (tok.tag) {
            .number => {
                if (ttl == null) {
                    ttl = try std.fmt.parseInt(u32, tok.text, 10);
                } else {
                    owner = tok.text;
                }
            },
            .identifier => {
                if (tok.parseClass()) |class| {
                    cls = class;
                } else {
                    owner = tok.text;
                }
            },
            .at => owner = state.origin,
            else => return error.BadToken,
        };

        if (owner == null) owner = state.prev_owner;
        if (ttl == null) ttl = state.ttl;
        if (cls == null) cls = state.prev_class;

        state.prev_class = cls.?;
        state.prev_owner = owner.?;

        try self.handleRecord(owner.?, ttl.?, cls.?, typ, tokenizer);
    }

    fn handleRecord(
        self: *Zone,
        owner: []const u8,
        ttl: u32,
        class: Dns.Class,
        @"type": Dns.Type,
        tokenizer: *Tokenizer,
    ) !void {
        const alloc = self.arena.allocator();
        var record = try self.records.addOne();
        record.* = Dns.Record.init(alloc, @"type");
        try record.name.fromString(owner);
        record.class = class;
        record.ttl = ttl;

        switch (record.rdata) {
            inline else => |*case| {
                if (tokenizer.next()) |tok| {
                    try case.fromString(tok.text);
                }
            },
        }
    }
};

const ParserState = struct {
    origin: []const u8,
    ttl: u32,
    prev_owner: []const u8,
    prev_class: Dns.Class,
};

pub const TokenTag = enum {
    newline, // logical end-of-record   (only when parenDepth == 0)
    eof,

    // single-character symbols
    at, // '@'

    // atomic values
    identifier, // owner names, classes, types
    number, // TTL or numeric owner labels
    quoted, // content between "…", **unescaped**
    directive, // $ORIGIN, $TTL, $INCLUDE, $GENERATE
};

pub const Token = struct {
    tag: TokenTag,
    text: []const u8,
    line: usize,
    col: usize,

    pub fn isType(self: Token) bool {
        var buf: [6]u8 = undefined;
        if (self.text.len > 5) return false;
        const lower = std.ascii.lowerString(&buf, self.text);
        if (std.meta.stringToEnum(Dns.Type, lower) != null) return true else return false;
    }

    pub fn isClass(self: Token) bool {
        var buf: [2]u8 = undefined;
        if (self.text.len > 2) return false;
        const lower = std.ascii.lowerString(&buf, self.text);
        if (std.meta.stringToEnum(Dns.Class, lower) != null) return true else return false;
    }

    pub fn parseType(self: Token) ?Dns.Type {
        var buf: [6]u8 = undefined;
        if (self.text.len > 5) return null;
        const lower = std.ascii.lowerString(&buf, self.text);
        return std.meta.stringToEnum(Dns.Type, lower);
    }

    pub fn parseClass(self: Token) ?Dns.Class {
        var buf: [2]u8 = undefined;
        if (self.text.len > 2) return null;
        const lower = std.ascii.lowerString(&buf, self.text);
        return std.meta.stringToEnum(Dns.Class, lower);
    }
};

pub const Tokenizer = struct {
    source: []const u8,
    pos: usize = 0,
    line: usize = 0,
    col: usize = 0,
    paren_depth: usize = 0,
    cached: bool = false,
    cache: Token = undefined,

    pub fn init(src: []const u8) Tokenizer {
        return .{
            .source = src,
        };
    }

    pub fn next(self: *Tokenizer) ?Token {
        self.skipWS();

        if (self.atEnd()) return null;

        const c = self.peek();

        if (c == '(') {
            self.paren_depth += 1;
            self.advance();
        }
        if (c == ')') {
            if (self.paren_depth == 0) return null;
            self.paren_depth -= 1;
            self.advance();
        }

        // 3. single-char symbols
        switch (c) {
            '@' => return self.single(.at),
            '$' => return self.scanDirective(),
            '"' => return self.scanQuoted(),
            else => {
                if (std.ascii.isDigit(c)) {
                    return self.scanNumber();
                } else if (c == '\n') { // only possible when parenDepth==0
                    self.advance();
                    const tok = Token{ .tag = .newline, .text = "", .line = self.line, .col = self.col };
                    self.line += 1;
                    self.col = 1;
                    return tok;
                } else {
                    return self.scanIdentifier();
                }
            },
        }
    }

    fn peek(self: *Tokenizer) u8 {
        return self.source[self.pos];
    }

    fn advance(self: *Tokenizer) void {
        self.pos += 1;
    }

    fn atEnd(self: *Tokenizer) bool {
        return self.pos >= self.source.len;
    }

    fn skipWS(self: *Tokenizer) void {
        while (!self.atEnd()) {
            const c = self.peek();

            switch (c) {
                ' ', '\t', '\r' => self.advance(),
                ';' => { // comment until newline or EOF
                    while (!self.atEnd() and self.peek() != '\n') self.advance();
                },
                '\n' => { // treat as possible newline only *after* later check
                    if (self.paren_depth == 0) return;
                    self.advance(); // inside (), becomes whitespace
                },
                else => return,
            }
        }
    }

    fn scanQuoted(self: *Tokenizer) Token {
        const col = self.col;
        self.col += 1;
        self.advance(); // skip opening "
        const start = self.pos;

        while (!self.atEnd()) {
            const c = self.peek();
            if (c == '"') {
                self.advance();
                break;
            } else {
                self.advance();
            }
        }

        return Token{
            .tag = .quoted,
            .text = self.source[start .. self.pos - 1], // lives in arena
            .line = self.line,
            .col = col,
        };
    }

    fn single(self: *Tokenizer, tag: TokenTag) Token {
        const tok = Token{
            .tag = tag,
            .text = self.source[self.pos .. self.pos + 1],
            .line = self.line,
            .col = self.col,
        };
        self.col += 1;
        self.advance();
        return tok;
    }

    fn scanIdentifier(self: *Tokenizer) Token {
        const col = self.col;
        const start = self.pos;
        self.col += 1;

        while (!self.atEnd()) {
            const c = self.peek();
            if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') {
                self.advance();
            } else break;
        }

        return Token{
            .tag = .identifier,
            .text = self.source[start..self.pos],
            .line = self.line,
            .col = col,
        };
    }

    fn scanDirective(self: *Tokenizer) Token {
        const col = self.col;
        self.advance();
        const start = self.pos;
        self.col += 1;

        while (!self.atEnd()) {
            const c = self.peek();
            if (std.ascii.isAlphabetic(c)) self.advance() else break;
        }

        return Token{
            .tag = .directive,
            .text = self.source[start..self.pos],
            .line = self.line,
            .col = col,
        };
    }

    fn scanNumber(self: *Tokenizer) Token {
        const start = self.pos;
        const col = self.col;
        self.col += 1;
        while (!self.atEnd() and (std.ascii.isDigit(self.peek()) or self.peek() == '.')) self.advance();

        return Token{
            .tag = .number,
            .text = self.source[start..self.pos],
            .line = self.line,
            .col = col,
        };
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var file = try std.fs.cwd().openFile("resource/test.zone", .{});
    const stats = try file.stat();

    const contents = try file.readToEndAlloc(allocator, stats.size);

    var tokenizer = Tokenizer.init(contents);

    while (tokenizer.next()) |tok| {
        std.debug.print("{s}: {any}\n", .{ tok.text, tok.tag });
    }
}
