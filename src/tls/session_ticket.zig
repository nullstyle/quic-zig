//! Session-ticket keys for a server TLS context.
//!
//! A TLS 1.3 server hands each client a session ticket: the session,
//! sealed under a key that only the server has. A client that brings
//! the ticket back resumes (no certificate exchange) and, with 0-RTT
//! on, sends data in its first flight. BoringSSL makes that key at
//! random for each `SSL_CTX` and keeps it in memory only. So a new
//! process, and a context that is built again for a certificate
//! reload, cannot open the tickets of the one before it: every client
//! pays one full handshake and loses its 0-RTT.
//!
//! This module installs a key that the embedder supplies
//! (`Server.Config.session_ticket_key`), so tickets live through a
//! restart and a reload. It goes through the exported raw surface;
//! the embedder names no BoringSSL type.
//!
//! The 48 bytes, in BoringSSL's layout: a 16-byte key name (sent in
//! clear at the front of every ticket), a 16-byte HMAC-SHA256 key and
//! a 16-byte AES-128 key. Make them with a CSPRNG and treat them as a
//! secret of the same rank as the private key:
//!
//!  - TLS 1.3 resumes with a fresh key exchange (`psk_dhe_ke`), so a
//!    stolen ticket key does NOT open recorded 1-RTT traffic.
//!  - It DOES open recorded 0-RTT data, and it lets the thief answer
//!    as the server to any client that offers a ticket sealed under
//!    it, until those tickets expire.
//!
//! A key that is set by hand never rotates by itself (BoringSSL
//! rotates only its own random key, every two days).
//!
//! Two ways to give a context its key:
//!
//!  - `install`: BoringSSL's own setter. One key; a second `install`
//!    drops the first, and its tickets with it.
//!  - `Ring` + `installRing`: two keys, the one that seals and the
//!    one before it, behind BoringSSL's ticket-key callback. A
//!    change of key (`Ring.rotate`) loses no ticket. This is what
//!    `quic.Server` uses for `Config.session_ticket_key` and
//!    `Server.rotateSessionTicketKey`.
//!
//! Both make the same ticket (BoringSSL's format), so servers that
//! use one read the tickets of servers that use the other.

const std = @import("std");
const boringssl = @import("boringssl");

const raw = boringssl.raw;

/// Length of a session-ticket key in bytes.
pub const key_len: usize = 48;

/// A session-ticket key: key name (16), HMAC-SHA256 key (16), AES-128
/// key (16).
pub const Key = [key_len]u8;

/// The shortest ticket lifetime that can be set, in seconds.
pub const min_lifetime_s: u32 = 1;
/// The longest ticket lifetime, in seconds: 7 days. RFC 8446 section
/// 4.6.1: "Servers MUST NOT use any value greater than 604800
/// seconds".
pub const max_lifetime_s: u32 = 7 * 24 * 60 * 60;
/// What BoringSSL uses when no lifetime is set: 2 days.
pub const default_lifetime_s: u32 = 2 * 24 * 60 * 60;

/// True when `seconds` is a ticket lifetime that `setLifetime` takes.
pub fn isValidLifetime(seconds: u32) bool {
    return seconds >= min_lifetime_s and seconds <= max_lifetime_s;
}

/// Tickets that `ctx` seals from now on are good for `seconds` (it
/// is the lifetime that the client is told, and the server checks
/// the ticket's own age against it when the ticket comes back). A
/// ticket that is already out keeps the lifetime it was sealed with.
/// `seconds` must be valid (`isValidLifetime`).
///
/// TLS reads the wall clock for this, not the clock that the QUIC
/// loop is fed.
pub fn setLifetime(ctx: boringssl.tls.Context, seconds: u32) void {
    std.debug.assert(isValidLifetime(seconds));
    raw.zbssl_SSL_CTX_set_session_psk_dhe_timeout(ctx.inner, seconds);
}

pub const InstallError = error{
    /// BoringSSL could not take the key (it allocates a copy).
    OutOfMemory,
    /// The key that the context reports after the install is not the
    /// one that was given.
    KeyNotInstalled,
};

/// True when every byte of `key` is zero. A zeroed buffer is a key
/// that was never filled in, not a key.
pub fn isAllZero(key: *const Key) bool {
    return std.mem.allEqual(u8, key, 0);
}

/// Seal new tickets of `ctx` under `key`, and open only tickets that
/// were sealed under it. The context copies the bytes. The key is
/// read back and compared, so an install that did nothing is an
/// error and not a server that silently keeps its random key.
///
/// Call it before the context serves a handshake, or on the thread
/// that serves them: BoringSSL takes no lock here.
pub fn install(ctx: boringssl.tls.Context, key: *const Key) InstallError!void {
    if (raw.zbssl_SSL_CTX_set_tlsext_ticket_keys(ctx.inner, key, key_len) != 1) {
        // The only failures are a wrong length (not possible with
        // this type) and a failed allocation.
        return InstallError.OutOfMemory;
    }
    if (!isInstalled(ctx, key)) return InstallError.KeyNotInstalled;
}

/// True when `ctx` seals its new tickets under exactly `key`.
pub fn isInstalled(ctx: boringssl.tls.Context, key: *const Key) bool {
    var back: Key = undefined;
    defer std.crypto.secureZero(u8, &back);
    if (raw.zbssl_SSL_CTX_get_tlsext_ticket_keys(ctx.inner, &back, key_len) != 1) return false;
    return std.crypto.timing_safe.eql(Key, back, key.*);
}

/// Length of the key name at the front of a key and of every ticket.
pub const name_len: usize = 16;

/// The ticket keys of one server: the key that seals new tickets, and
/// the key before it, which still opens the tickets that are out.
///
/// `SSL_CTX_set_tlsext_ticket_keys` (`install`) holds ONE key and
/// drops the one before it, so a key change through it costs every
/// client one full handshake. With a `Ring` installed (`installRing`)
/// the context asks a callback instead: it seals with `current`, and
/// it opens with the key whose 16-byte name is at the front of the
/// ticket, `current` or `previous`.
///
/// The ticket format is BoringSSL's own (AES-128-CBC, HMAC-SHA256,
/// the 48-byte key layout), so a ticket that was sealed through
/// `install` opens through a ring with the same key, and the other
/// way round. Servers of a pool can move from one to the other one
/// at a time.
///
/// Not thread-safe: change it on the thread that runs the handshakes
/// of the contexts it is installed on.
pub const Ring = struct {
    current: Key,
    previous: ?Key = null,
    /// When `previous` stops opening tickets, on the clock of the
    /// caller (`Server` uses the `now_us` of `feed` and `tick`).
    /// Meaningless while `previous` is null.
    previous_expires_at_us: u64 = 0,

    pub const RotateError = error{
        /// The new key has the key name (the first 16 bytes) of the
        /// current one. A ticket says which key sealed it by that
        /// name alone.
        SameKeyName,
    };

    pub fn init(current: Key) Ring {
        return .{ .current = current };
    }

    /// `new_key` seals from now on. The key that sealed until now
    /// still opens tickets until `expires_at_us`. The key before
    /// that one is gone.
    pub fn rotate(self: *Ring, new_key: Key, expires_at_us: u64) RotateError!void {
        if (std.mem.eql(u8, new_key[0..name_len], self.current[0..name_len])) return RotateError.SameKeyName;
        if (self.previous) |*old| std.crypto.secureZero(u8, old);
        self.previous = self.current;
        self.previous_expires_at_us = expires_at_us;
        self.current = new_key;
    }

    /// Drop the previous key when its time is over. True when it was
    /// dropped by this call.
    pub fn expire(self: *Ring, now_us: u64) bool {
        if (self.previous == null) return false;
        if (now_us < self.previous_expires_at_us) return false;
        self.dropPrevious();
        return true;
    }

    fn dropPrevious(self: *Ring) void {
        if (self.previous) |*old| std.crypto.secureZero(u8, old);
        self.previous = null;
        self.previous_expires_at_us = 0;
    }

    /// The key that opens a ticket with this key name, if the ring
    /// has it.
    pub fn find(self: *const Ring, name: *const [name_len]u8) ?*const Key {
        if (std.mem.eql(u8, name, self.current[0..name_len])) return &self.current;
        if (self.previous) |*old| {
            if (std.mem.eql(u8, name, old[0..name_len])) return old;
        }
        return null;
    }

    /// Clear both keys. The ring must not be used after this.
    pub fn wipe(self: *Ring) void {
        self.dropPrevious();
        std.crypto.secureZero(u8, &self.current);
    }
};

/// The slot of an `SSL_CTX` that holds its `*Ring`. One for the
/// process; made on first use.
var ring_ex_index = std.atomic.Value(c_int).init(-1);

fn ringExIndex() ?c_int {
    const have = ring_ex_index.load(.acquire);
    if (have >= 0) return have;
    const fresh = raw.zbssl_SSL_CTX_get_ex_new_index(0, null, null, null, null);
    if (fresh < 0) return null;
    // Two threads may both get here. The loser's index stays unused,
    // which costs one slot number and nothing else.
    if (ring_ex_index.cmpxchgStrong(-1, fresh, .acq_rel, .acquire)) |winner| return winner;
    return fresh;
}

/// `ctx` seals and opens its tickets with the keys of `ring` from now
/// on. The context keeps the POINTER: `ring` must stay at its address
/// and outlive the context, and every connection made from it.
///
/// Like `install`: call it before the context serves a handshake, or
/// on the thread that serves them.
///
/// The only failure is memory: BoringSSL allocates the slot that
/// holds the pointer.
pub fn installRing(ctx: boringssl.tls.Context, ring: *Ring) error{OutOfMemory}!void {
    const idx = ringExIndex() orelse return error.OutOfMemory;
    if (raw.zbssl_SSL_CTX_set_ex_data(ctx.inner, idx, ring) != 1) return error.OutOfMemory;
    // Always returns 1.
    _ = raw.zbssl_SSL_CTX_set_tlsext_ticket_key_cb(ctx.inner, ticketKeyCallback);
}

/// The ring that `installRing` put on `ctx`, or null.
pub fn installedRing(ctx: boringssl.tls.Context) ?*Ring {
    const idx = ringExIndex() orelse return null;
    const ptr = raw.zbssl_SSL_CTX_get_ex_data(ctx.inner, idx) orelse return null;
    return @ptrCast(@alignCast(ptr));
}

/// BoringSSL's ticket-key callback (`SSL_CTX_set_tlsext_ticket_key_cb`).
/// It is called to seal a ticket (`encrypt` = 1) and to open one
/// (`encrypt` = 0). It picks the key and sets the two contexts up;
/// BoringSSL does the rest.
///
/// The construction is the one BoringSSL uses for its own key
/// (`ssl_encrypt_ticket_with_cipher_ctx`,
/// `ssl_decrypt_ticket_with_ticket_keys`): a random 16-byte IV,
/// AES-128-CBC with the last 16 bytes of the key, HMAC-SHA256 with
/// the middle 16.
///
/// Return values, by the header: to seal, 1 = go on, 0 = send no
/// ticket, -1 = error. To open, 1 = go on, 0 = the key is not known
/// (the handshake goes on as a full one), -1 = abort the handshake.
/// (There is also 2, "go on, and replace the ticket". It is for TLS
/// 1.2. A TLS 1.3 server sends fresh tickets after every handshake,
/// so a client that came with a ticket of the previous key leaves
/// with one of the current key anyway; a test holds that.)
fn ticketKeyCallback(
    ssl: ?*raw.SSL,
    key_name: [*c]u8,
    iv: [*c]u8,
    cipher_ctx: [*c]raw.EVP_CIPHER_CTX,
    hmac_ctx: [*c]raw.HMAC_CTX,
    encrypt: c_int,
) callconv(.c) c_int {
    // No ring (it cannot be: the callback is set with it): no ticket
    // goes out and none is opened. A handshake is never broken here.
    const ring = ringOfSsl(ssl) orelse return 0;
    const aes = raw.zbssl_EVP_aes_128_cbc();
    const sha256 = raw.zbssl_EVP_sha256();

    if (encrypt == 1) {
        const key = &ring.current;
        if (raw.zbssl_RAND_bytes(iv, 16) != 1) return -1;
        @memcpy(key_name[0..name_len], key[0..name_len]);
        if (raw.zbssl_EVP_EncryptInit_ex(cipher_ctx, aes, null, key[32..48], iv) != 1) return -1;
        if (raw.zbssl_HMAC_Init_ex(hmac_ctx, key[16..32], 16, sha256, null) != 1) return -1;
        return 1;
    }

    const key = ring.find(key_name[0..name_len]) orelse return 0;
    if (raw.zbssl_HMAC_Init_ex(hmac_ctx, key[16..32], 16, sha256, null) != 1) return -1;
    if (raw.zbssl_EVP_DecryptInit_ex(cipher_ctx, aes, null, key[32..48], iv) != 1) return -1;
    return 1;
}

fn ringOfSsl(ssl: ?*raw.SSL) ?*Ring {
    const idx = ringExIndex() orelse return null;
    const ctx = raw.zbssl_SSL_get_SSL_CTX(ssl) orelse return null;
    const ptr = raw.zbssl_SSL_CTX_get_ex_data(ctx, idx) orelse return null;
    return @ptrCast(@alignCast(ptr));
}

/// The ticket key that `ctx` seals new tickets under right now. For
/// tests: an embedder has its own copy, and code that logs this has
/// leaked the key.
pub fn currentKeyForTest(ctx: boringssl.tls.Context) ?Key {
    var out: Key = undefined;
    if (raw.zbssl_SSL_CTX_get_tlsext_ticket_keys(ctx.inner, &out, key_len) != 1) return null;
    return out;
}

// -- tests ---------------------------------------------------------------

fn testKey(fill: u8) Key {
    return @splat(fill);
}

test "Ring: a rotation keeps the key before, a second one drops it" {
    var ring = Ring.init(testKey(0xa1));
    try std.testing.expect(ring.previous == null);

    try ring.rotate(testKey(0xb2), 1000);
    try std.testing.expectEqualSlices(u8, &testKey(0xb2), &ring.current);
    try std.testing.expectEqualSlices(u8, &testKey(0xa1), &ring.previous.?);
    try std.testing.expectEqual(@as(u64, 1000), ring.previous_expires_at_us);

    try ring.rotate(testKey(0xc3), 2000);
    try std.testing.expectEqualSlices(u8, &testKey(0xc3), &ring.current);
    try std.testing.expectEqualSlices(u8, &testKey(0xb2), &ring.previous.?);
    try std.testing.expectEqual(@as(u64, 2000), ring.previous_expires_at_us);
}

test "Ring: a new key with the name of the current one is refused, and nothing changes" {
    var ring = Ring.init(testKey(0xa1));
    try ring.rotate(testKey(0xb2), 1000);

    // The same key.
    try std.testing.expectError(Ring.RotateError.SameKeyName, ring.rotate(testKey(0xb2), 5000));
    // Other secrets under the same name.
    var same_name = testKey(0xdd);
    @memcpy(same_name[0..name_len], ring.current[0..name_len]);
    try std.testing.expectError(Ring.RotateError.SameKeyName, ring.rotate(same_name, 5000));
    try std.testing.expectEqualSlices(u8, &testKey(0xb2), &ring.current);
    try std.testing.expectEqualSlices(u8, &testKey(0xa1), &ring.previous.?);
    try std.testing.expectEqual(@as(u64, 1000), ring.previous_expires_at_us);

    // One bit of difference in the name is another name. And the
    // name of the PREVIOUS key may come back: it is dropped by then.
    var other_name = ring.current;
    other_name[name_len - 1] ^= 1;
    try ring.rotate(other_name, 6000);
    try ring.rotate(testKey(0xa1), 7000);
}

test "Ring: the previous key goes at its time, not before, and only once" {
    var ring = Ring.init(testKey(0xa1));
    // Nothing to drop.
    try std.testing.expect(!ring.expire(std.math.maxInt(u64)));

    try ring.rotate(testKey(0xb2), 1000);
    try std.testing.expect(!ring.expire(0));
    try std.testing.expect(!ring.expire(999));
    try std.testing.expect(ring.previous != null);
    try std.testing.expect(ring.expire(1000));
    try std.testing.expect(ring.previous == null);
    try std.testing.expect(!ring.expire(1001));
    // The current key is not touched.
    try std.testing.expectEqualSlices(u8, &testKey(0xb2), &ring.current);
}

test "Ring: find by the 16-byte key name" {
    var ring = Ring.init(testKey(0xa1));
    const name_a: [name_len]u8 = @splat(0xa1);
    const name_b: [name_len]u8 = @splat(0xb2);
    const name_c: [name_len]u8 = @splat(0xc3);

    try std.testing.expect(ring.find(&name_a).? == &ring.current);
    try std.testing.expect(ring.find(&name_b) == null);

    try ring.rotate(testKey(0xb2), 1000);
    try std.testing.expect(ring.find(&name_b).? == &ring.current);
    try std.testing.expectEqualSlices(u8, &testKey(0xa1), ring.find(&name_a).?);
    try std.testing.expect(ring.find(&name_c) == null);

    // After its time the previous key is not found any more.
    _ = ring.expire(1000);
    try std.testing.expect(ring.find(&name_a) == null);
    try std.testing.expect(ring.find(&name_b).? == &ring.current);
}

test "Ring: wipe clears both keys" {
    var ring = Ring.init(testKey(0xa1));
    try ring.rotate(testKey(0xb2), 1000);
    ring.wipe();
    try std.testing.expect(ring.previous == null);
    try std.testing.expect(isAllZero(&ring.current));
}

test "installRing: the context holds the ring's address; a context without one has none" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var other = try boringssl.tls.Context.initServer(.{});
    defer other.deinit();
    try std.testing.expect(installedRing(ctx) == null);

    var ring = Ring.init(testKey(0xa1));
    try installRing(ctx, &ring);
    try std.testing.expect(installedRing(ctx).? == &ring);
    try std.testing.expect(installedRing(other) == null);

    // A second ring replaces the first.
    var ring2 = Ring.init(testKey(0xb2));
    try installRing(ctx, &ring2);
    try std.testing.expect(installedRing(ctx).? == &ring2);
}

/// A test key whose three parts differ (a key of 48 equal bytes
/// cannot tell the right part from a wrong one).
fn partsKey(seed: u8) Key {
    var key: Key = undefined;
    for (&key, 0..) |*b, i| b.* = seed ^ @as(u8, @intCast((i * 7 + i / 16 * 31) & 0xff));
    return key;
}

test "ticket callback: to seal, the current key's name and a fresh IV each time; to open, 1 for a key of the ring and 0 for any other" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var ring = Ring.init(partsKey(0x11));
    try installRing(ctx, &ring);
    var conn = try ctx.newQuicServer();
    defer conn.deinit();

    const cipher_ctx = raw.zbssl_EVP_CIPHER_CTX_new() orelse return error.OutOfMemory;
    defer raw.zbssl_EVP_CIPHER_CTX_free(cipher_ctx);
    const hmac_ctx = raw.zbssl_HMAC_CTX_new() orelse return error.OutOfMemory;
    defer raw.zbssl_HMAC_CTX_free(hmac_ctx);

    // Seal three times.
    var names: [3][name_len]u8 = @splat(@splat(0));
    var ivs: [3][16]u8 = @splat(@splat(0));
    for (&names, &ivs) |*name, *iv| {
        try std.testing.expectEqual(@as(c_int, 1), ticketKeyCallback(conn.inner, name, iv, cipher_ctx, hmac_ctx, 1));
        try std.testing.expectEqualSlices(u8, ring.current[0..name_len], name);
    }
    // An IV is 16 random bytes. Two equal ones, or one of all zeros,
    // is a callback that does not draw them.
    try std.testing.expect(!std.mem.eql(u8, &ivs[0], &ivs[1]));
    try std.testing.expect(!std.mem.eql(u8, &ivs[1], &ivs[2]));
    try std.testing.expect(!std.mem.eql(u8, &ivs[0], &ivs[2]));
    for (ivs) |iv| try std.testing.expect(!std.mem.allEqual(u8, &iv, 0));

    // Open: by the key name at the front of the ticket.
    var name_first: [name_len]u8 = partsKey(0x11)[0..name_len].*;
    var name_second: [name_len]u8 = partsKey(0x22)[0..name_len].*;
    var name_unknown: [name_len]u8 = partsKey(0x33)[0..name_len].*;
    var iv = ivs[0];
    try std.testing.expectEqual(@as(c_int, 1), ticketKeyCallback(conn.inner, &name_first, &iv, cipher_ctx, hmac_ctx, 0));
    try std.testing.expectEqual(@as(c_int, 0), ticketKeyCallback(conn.inner, &name_second, &iv, cipher_ctx, hmac_ctx, 0));

    // After a rotation both names open, and new tickets carry the
    // second name.
    try ring.rotate(partsKey(0x22), 1000);
    try std.testing.expectEqual(@as(c_int, 1), ticketKeyCallback(conn.inner, &name_first, &iv, cipher_ctx, hmac_ctx, 0));
    try std.testing.expectEqual(@as(c_int, 1), ticketKeyCallback(conn.inner, &name_second, &iv, cipher_ctx, hmac_ctx, 0));
    try std.testing.expectEqual(@as(c_int, 0), ticketKeyCallback(conn.inner, &name_unknown, &iv, cipher_ctx, hmac_ctx, 0));
    var name_out: [name_len]u8 = @splat(0);
    try std.testing.expectEqual(@as(c_int, 1), ticketKeyCallback(conn.inner, &name_out, &iv, cipher_ctx, hmac_ctx, 1));
    try std.testing.expectEqualSlices(u8, &name_second, &name_out);

    // When its time is over the first key opens nothing.
    try std.testing.expect(ring.expire(1000));
    try std.testing.expectEqual(@as(c_int, 0), ticketKeyCallback(conn.inner, &name_first, &iv, cipher_ctx, hmac_ctx, 0));
}

test "ticket callback: a context with no ring sends no ticket and opens none" {
    // It cannot happen through `installRing`; the callback must still
    // not break a handshake if it does.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try ctx.newQuicServer();
    defer conn.deinit();
    const cipher_ctx = raw.zbssl_EVP_CIPHER_CTX_new() orelse return error.OutOfMemory;
    defer raw.zbssl_EVP_CIPHER_CTX_free(cipher_ctx);
    const hmac_ctx = raw.zbssl_HMAC_CTX_new() orelse return error.OutOfMemory;
    defer raw.zbssl_HMAC_CTX_free(hmac_ctx);
    var name: [name_len]u8 = @splat(7);
    var iv: [16]u8 = @splat(7);
    try std.testing.expectEqual(@as(c_int, 0), ticketKeyCallback(conn.inner, &name, &iv, cipher_ctx, hmac_ctx, 1));
    try std.testing.expectEqual(@as(c_int, 0), ticketKeyCallback(conn.inner, &name, &iv, cipher_ctx, hmac_ctx, 0));
}

test "isValidLifetime: 1 second to 7 days" {
    try std.testing.expect(!isValidLifetime(0));
    try std.testing.expect(isValidLifetime(1));
    try std.testing.expect(isValidLifetime(default_lifetime_s));
    try std.testing.expect(isValidLifetime(604_800));
    try std.testing.expect(!isValidLifetime(604_801));
    try std.testing.expect(!isValidLifetime(std.math.maxInt(u32)));
    // The library default is BoringSSL's.
    try std.testing.expectEqual(@as(u32, raw.SSL_DEFAULT_SESSION_PSK_DHE_TIMEOUT), default_lifetime_s);
}

test "isAllZero: only a key of 48 zero bytes" {
    var key: Key = @splat(0);
    try std.testing.expect(isAllZero(&key));
    key[47] = 1;
    try std.testing.expect(!isAllZero(&key));
    key[47] = 0;
    key[0] = 0x80;
    try std.testing.expect(!isAllZero(&key));
}

test "install: the context seals under the given key, and a second install replaces it" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    // A fresh context has a key of its own (random, made on first
    // use); it is not ours.
    const key_a: Key = @splat(0xa5);
    const before = currentKeyForTest(ctx).?;
    try std.testing.expect(!std.mem.eql(u8, &before, &key_a));

    try install(ctx, &key_a);
    try std.testing.expectEqualSlices(u8, &key_a, &currentKeyForTest(ctx).?);

    var key_b: Key = undefined;
    for (&key_b, 0..) |*b, i| b.* = @intCast(i);
    try install(ctx, &key_b);
    try std.testing.expectEqualSlices(u8, &key_b, &currentKeyForTest(ctx).?);
}

test "isInstalled: true for the key of the context, false for every other key" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const key_a: Key = @splat(0xa5);
    var key_b: Key = @splat(0xa5);
    key_b[47] ^= 1;

    // The context's own random key is neither.
    try std.testing.expect(!isInstalled(ctx, &key_a));
    try install(ctx, &key_a);
    try std.testing.expect(isInstalled(ctx, &key_a));
    // One bit of difference, in the last byte.
    try std.testing.expect(!isInstalled(ctx, &key_b));
    try install(ctx, &key_b);
    try std.testing.expect(isInstalled(ctx, &key_b));
    try std.testing.expect(!isInstalled(ctx, &key_a));
}

test "install: two contexts with the same key hold the same key" {
    var ctx1 = try boringssl.tls.Context.initServer(.{});
    defer ctx1.deinit();
    var ctx2 = try boringssl.tls.Context.initServer(.{});
    defer ctx2.deinit();
    // Without an install the two differ: each makes its own.
    try std.testing.expect(!std.mem.eql(u8, &currentKeyForTest(ctx1).?, &currentKeyForTest(ctx2).?));

    const key: Key = @splat(0x3c);
    try install(ctx1, &key);
    try install(ctx2, &key);
    try std.testing.expectEqualSlices(u8, &currentKeyForTest(ctx1).?, &currentKeyForTest(ctx2).?);
}
