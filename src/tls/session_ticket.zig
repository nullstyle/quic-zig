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

/// The ticket key that `ctx` seals new tickets under right now. For
/// tests: an embedder has its own copy, and code that logs this has
/// leaked the key.
pub fn currentKeyForTest(ctx: boringssl.tls.Context) ?Key {
    var out: Key = undefined;
    if (raw.zbssl_SSL_CTX_get_tlsext_ticket_keys(ctx.inner, &out, key_len) != 1) return null;
    return out;
}

// -- tests ---------------------------------------------------------------

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
