//! Stateless Retry-token helper for QUIC address validation.
//!
//! The transport stays I/O-agnostic: callers provide canonical client
//! address bytes. Tokens are AEAD-sealed with AES-GCM-256 and bind
//! the client address, the Original Destination CID, the Retry
//! Source CID, the QUIC version, and an issue/expiry window. The
//! previous v1 HMAC-only format leaked all bound fields in plaintext
//! (only the HMAC tag was opaque); v2 keeps the same authenticity
//! guarantee while making the token bytes a uniformly random opaque
//! blob to peers and on-path observers (hardening item B2).
//!
//! Wire format (v2, fixed 96 bytes):
//!
//!     nonce (12)  |  ciphertext (68)  |  tag (16)
//!
//! Mint always pads the inner plaintext to exactly 68 bytes before
//! AEAD-sealing, so on-wire tokens are constant-length and cannot
//! be distinguished by the layout of bound fields.
//!
//! Inner plaintext (68 bytes after zero-padding):
//!
//!     version    (4 bytes,  big-endian)
//!     issued_at  (8 bytes,  big-endian, microseconds since epoch)
//!     expires_at (8 bytes,  big-endian, microseconds since epoch)
//!     addr_len   (1 byte)         | client_address (<= 22 bytes)
//!     odcid_len  (1 byte)         | original_dcid  (<= 20 bytes)
//!     scid_len   (1 byte)         | retry_scid     (<= 20 bytes)
//!     <pad>      (zero bytes to reach 68)
//!
//! Mint enforces a per-call sum constraint so the bound material
//! fits the fixed plaintext budget:
//!
//!     addr_len + odcid_len + scid_len <= 45  bytes  (= 68 - 23)
//!
//! With the 23-byte address context (full IPv6) and the default
//! 8-byte server SCID that leaves up to 14 bytes for the peer's
//! original DCID — comfortably above the 8-byte typical and the
//! 8-byte interop convention. Peers presenting unusually long initial
//! DCIDs (>14 bytes when paired with the default SCID length) cause
//! `mint` to return `Error.OutputTooSmall`; the server then drops
//! the Initial rather than minting a Retry. Operators that want
//! full 20-byte CID coverage should bump `max_token_len`.

const std = @import("std");

const path = @import("path.zig");
const token_envelope = @import("token_envelope.zig");

/// AES-GCM-256 key length in bytes (also `Key`).
pub const key_len: usize = token_envelope.key_len;
/// AEAD nonce length in bytes (12, GCM standard).
pub const nonce_len: usize = token_envelope.nonce_len;
/// AEAD authentication tag length in bytes (16, GCM standard).
pub const tag_len: usize = token_envelope.tag_len;

/// Maximum address length the format can carry. Tracks
/// `path.Address.context_max_len` so the token can always bind a full
/// client address context — including IPv6 (tag + 16 addr + port +
/// flow = 23 bytes). A stale literal here (22) previously rejected
/// every IPv6 peer's Retry, since `writeContext` emits 23 bytes.
pub const max_address_len: usize = path.Address.context_max_len;

/// Maximum CID length the format can carry. Matches the QUIC v1
/// limit (`path.max_cid_len = 20`). Note the per-call sum cap
/// described in this module's preamble — both CIDs at full 20
/// bytes plus a 23-byte address overflows the fixed plaintext
/// budget and `mint` will return `Error.OutputTooSmall`.
pub const max_cid_len: usize = path.max_cid_len;

/// Total token length on the wire (and in `Token`). Fixed at 96
/// bytes: a 12-byte AEAD nonce, a 68-byte ciphertext (zero-padded
/// plaintext under fixed-size AEAD), and a 16-byte authentication
/// tag. Owned by `token_envelope` because NEW_TOKEN must share the
/// exact same shape to stay indistinguishable on the wire.
pub const max_token_len: usize = token_envelope.token_len;

/// The shared AEAD envelope, instantiated with the v2 Retry domain
/// separator and the three bound fields in wire order. The envelope
/// owns the seal/open/parse/compare mechanics; this module keeps the
/// key material, error vocabulary, and budget policy.
const Env = token_envelope.Envelope(.{
    .domain_separator = "quic retry token v2",
    .field_caps = &.{ max_address_len, max_cid_len, max_cid_len },
});

comptime {
    // The plaintext budget must accommodate a full IPv6 address
    // context plus two default (8-byte) CIDs, or IPv6 Retry breaks
    // again. This couples the budget to `path.Address.context_max_len`
    // so a future Address change can't silently shrink token capacity.
    std.debug.assert(max_address_len >= path.Address.context_max_len);
    std.debug.assert(path.Address.context_max_len + 8 + 8 <= max_bound_total);
}

/// Maximum sum of the three bound-field lengths that fits in the
/// fixed plaintext budget. Mint enforces this at runtime via
/// `Error.OutputTooSmall`.
const max_bound_total: usize = Env.max_bound_total;

/// 32-byte AES-GCM-256 key. The server must keep this stable across
/// the token's lifetime so it can validate after a Retry round-trip.
/// Rotate to invalidate every outstanding Retry token at once;
/// outstanding (already-minted) tokens cannot be migrated to a new
/// key, so rotate at session boundaries or via a brief two-key
/// overlap window.
pub const Key = [key_len]u8;

/// Fixed-size Retry token (RFC 9000 §8.1.2). Always exactly
/// `max_token_len` bytes — `mint` zero-pads its plaintext before
/// AEAD-sealing so the wire shape doesn't reveal which fields are
/// bound (or how long they were).
pub const Token = [max_token_len]u8;

/// Errors raised by `mint` and (via `validate`) surfaced as `.malformed`.
pub const Error = error{
    /// Output buffer was smaller than `max_token_len`, or the
    /// requested bound-field combination doesn't fit the fixed
    /// plaintext budget.
    OutputTooSmall,
    /// `client_address` exceeded `max_address_len`.
    ContextTooLong,
    /// A Connection ID exceeded `max_cid_len`.
    DcidTooLong,
    /// AEAD seal/init failure (BoringSSL). Not peer-reachable in
    /// practice; surfaces only on out-of-memory or library misuse.
    AeadFailure,
    /// CSPRNG failure (BoringSSL). Same not-peer-reachable property.
    RandFailure,
};

/// Inputs to `mint`. The AEAD seal binds `client_address`,
/// `original_dcid`, `retry_scid`, `quic_version`, `now_us`, and the
/// expiry derived from `lifetime_us`.
pub const MintOptions = struct {
    key: *const Key,
    now_us: u64,
    lifetime_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
};

/// Inputs to `validate`. Must be byte-equal to the `MintOptions`
/// values used to issue the token (modulo `now_us`/`max_clock_skew_us`).
pub const ValidateOptions = struct {
    key: *const Key,
    now_us: u64,
    client_address: []const u8,
    original_dcid: []const u8,
    retry_scid: []const u8,
    quic_version: u32 = 0x00000001,
    max_clock_skew_us: u64 = 0,
};

/// Outcome of `validate`.
pub const ValidationResult = enum {
    /// AEAD opened cleanly, recovered fields match, and timestamps
    /// are within the allowed window.
    valid,
    /// Length, AEAD authentication, or recovered-field shape was
    /// wrong (also covers the case where a v1 HMAC-format token is
    /// presented to v2). Treat as untrusted.
    malformed,
    /// The QUIC version field did not match.
    wrong_version,
    /// `issued_at_us` is in the future beyond `max_clock_skew_us`.
    not_yet_valid,
    /// `expires_at_us` is in the past beyond `max_clock_skew_us`.
    expired,
    /// AEAD opened cleanly but a recovered bound field (address,
    /// ODCID, retry SCID) did not match the validator's expectation.
    invalid,
};

/// Mint a Retry token into `dst`. Returns the number of bytes
/// written (always `max_token_len`). Errors come from oversized
/// bound fields, a bound-total that doesn't fit the fixed plaintext
/// budget, a short output buffer, or an underlying BoringSSL
/// failure.
pub fn mint(dst: []u8, opts: MintOptions) Error!usize {
    if (dst.len < max_token_len) return Error.OutputTooSmall;
    try validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid);
    if (opts.client_address.len + opts.original_dcid.len + opts.retry_scid.len > max_bound_total) {
        return Error.OutputTooSmall;
    }

    try Env.seal(
        dst[0..max_token_len],
        opts.key,
        opts.quic_version,
        opts.now_us,
        opts.lifetime_us,
        .{ opts.client_address, opts.original_dcid, opts.retry_scid },
    );
    return max_token_len;
}

/// Convenience wrapper around `mint` that returns a fresh `Token`
/// by-value.
pub fn minted(opts: MintOptions) Error!Token {
    var token: Token = undefined;
    _ = try mint(&token, opts);
    return token;
}

/// Validate a Retry token. Returns `.valid` only if the AEAD opens
/// cleanly, every bound field matches the validator's expectation,
/// and the token is within its issue/expiry window (subject to
/// `max_clock_skew_us`). All failure modes are surfaced as enum
/// variants — the function never errors. Bound-field comparisons
/// run in constant time over the recovered plaintext.
pub fn validate(token: []const u8, opts: ValidateOptions) ValidationResult {
    validateBoundInputs(opts.client_address, opts.original_dcid, opts.retry_scid) catch return .malformed;
    return switch (Env.validate(
        token,
        opts.key,
        opts.quic_version,
        opts.now_us,
        opts.max_clock_skew_us,
        .{ opts.client_address, opts.original_dcid, opts.retry_scid },
    )) {
        .valid => .valid,
        .malformed => .malformed,
        .wrong_version => .wrong_version,
        .not_yet_valid => .not_yet_valid,
        .expired => .expired,
        .invalid => .invalid,
    };
}

fn validateBoundInputs(client_address: []const u8, original_dcid: []const u8, retry_scid: []const u8) Error!void {
    if (client_address.len > max_address_len) return Error.ContextTooLong;
    if (original_dcid.len > max_cid_len) return Error.DcidTooLong;
    if (retry_scid.len > max_cid_len) return Error.DcidTooLong;
}

const testing_key: Key = .{
    0x86, 0x71, 0x15, 0x0d, 0x9a, 0x2c, 0x5e, 0x04,
    0x31, 0xa8, 0x6a, 0xf9, 0x18, 0x44, 0xbd, 0x2b,
    0x4d, 0xee, 0x90, 0x3f, 0xa7, 0x61, 0x0c, 0x55,
    0xd6, 0x28, 0xb4, 0x72, 0x01, 0xc9, 0x3f, 0x6a,
};

test "Retry token validates with matching address CIDs version and time" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
}

test "Retry token binds a full IPv6 address context (regression: 23-byte context)" {
    // Regression for the constant drift that made `max_address_len` (22)
    // smaller than a real IPv6 `writeContext` output (23), which caused
    // mint to return ContextTooLong for every IPv6 peer and the server
    // to drop the Initial. Use the real 23-byte context, not a literal.
    var addr_buf: [path.Address.context_max_len]u8 = undefined;
    const ipv6: path.Address = .{ .ipv6 = .{
        .addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 4433,
        .flow = 0xABCDE,
    } };
    const ctx = ipv6.writeContext(&addr_buf);
    try std.testing.expectEqual(@as(usize, 23), ctx.len);

    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = ctx,
        .original_dcid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d, 0xaa, 0xbb, 0xcc, 0xdd },
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = ctx,
        .original_dcid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d, 0xaa, 0xbb, 0xcc, 0xdd },
    }));
}

test "Retry token rejects replay with changed address or connection IDs" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    });

    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4243",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 5 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9d },
    }));
    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
        .original_dcid = &.{ 1, 2, 3, 4 },
        .retry_scid = &.{ 0xc1, 0x5e, 0x71, 0x9e },
    }));
}

test "Retry token rejects wrong version expired future and malformed tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
        .quic_version = 1,
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 11_000_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    };
    var wrong_version = opts;
    wrong_version.quic_version = 0x6b3343cf;
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&token, wrong_version));

    var expired = opts;
    expired.now_us = 15_000_001;
    try std.testing.expectEqual(ValidationResult.expired, validate(&token, expired));

    var future = opts;
    future.now_us = 9_999_999;
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&token, future));

    // Truncating any byte makes the wire size != max_token_len, so
    // the length gate rejects before crypto state is touched.
    try std.testing.expectEqual(ValidationResult.malformed, validate(token[0 .. token.len - 1], opts));
    // Flipping the trailing tag byte breaks AEAD auth.
    token[token.len - 1] ^= 0x01;
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, opts));
    // Unflip and corrupt a nonce byte — also breaks auth.
    token[token.len - 1] ^= 0x01;
    token[0] ^= 0x01;
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, opts));
}

test "Retry token rejects v1 HMAC-format prefix as malformed under v2" {
    // Sanity: a token shaped like the legacy v1 wire format (53
    // bytes, no random nonce, HMAC tag at the tail) doesn't match
    // `max_token_len` and is rejected by the length gate. Operators
    // rotating from v1 to v2 see every outstanding token invalidate
    // cleanly.
    var legacy: [53]u8 = @splat(0xcd);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&legacy, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
    // Even at the right wire size, random bytes don't AEAD-open.
    var random_blob: [max_token_len]u8 = @splat(0xab);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&random_blob, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "Retry token mint rejects oversized bound fields" {
    var addr_buf: [max_address_len + 1]u8 = @splat(0);
    var dst: [max_token_len]u8 = undefined;
    try std.testing.expectError(Error.ContextTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_buf,
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));

    var cid_buf: [max_cid_len + 1]u8 = @splat(0);
    try std.testing.expectError(Error.DcidTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &cid_buf,
        .retry_scid = &.{2},
    }));
    try std.testing.expectError(Error.DcidTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &cid_buf,
    }));
}

test "Retry token mint rejects bound-total over plaintext budget" {
    var dst: [max_token_len]u8 = undefined;
    var addr_full: [max_address_len]u8 = @splat(0);
    var cid_full: [max_cid_len]u8 = @splat(0);
    // 22 + 20 + 20 = 62 > 45, doesn't fit the 68-byte plaintext.
    try std.testing.expectError(Error.OutputTooSmall, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_full,
        .original_dcid = &cid_full,
        .retry_scid = &cid_full,
    }));
}

test "Retry token mint rejects undersized output buffer" {
    var dst: [4]u8 = undefined;
    try std.testing.expectError(Error.OutputTooSmall, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    }));
}

test "Retry token mint produces fixed-length 96-byte tokens" {
    var dst: [max_token_len]u8 = undefined;
    const n = try mint(&dst, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    try std.testing.expectEqual(@as(usize, max_token_len), n);

    // Two mints under the same key/inputs differ in the random
    // nonce, so the wire bytes diverge. This is the ciphertext
    // indistinguishability property the v1 HMAC format lacked.
    var dst2: [max_token_len]u8 = undefined;
    _ = try mint(&dst2, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
        .original_dcid = &.{1},
        .retry_scid = &.{2},
    });
    try std.testing.expect(!std.mem.eql(u8, &dst, &dst2));
}

test "Retry token KAT: validate pins the v2 wire format" {
    // Known-answer token minted by the v2 codec under `testing_key`
    // with now_us = 1_700_000_000_000_000, lifetime_us = 30_000_000,
    // client_address = "ip4:203.0.113.7:443", original_dcid =
    // 01..08, retry_scid = aa bb cc dd ee ff 11 22, quic_version = 1.
    // Mint is nondeterministic (random nonce), but `validate` over
    // these fixed bytes is fully deterministic.
    //
    // If this test starts failing, the wire format changed and every
    // outstanding Retry token just got invalidated — that must be a
    // deliberate, versioned decision (bump the domain separator),
    // never a refactor side effect.
    const kat = [_]u8{
        0x2d, 0x18, 0x9e, 0xbb, 0x1f, 0x18, 0x20, 0x14, 0xcc, 0x7e, 0x23, 0x9c,
        0x00, 0xef, 0xef, 0xd2, 0x7b, 0x5e, 0x18, 0x02, 0x18, 0x1e, 0xf6, 0xe4,
        0x46, 0x54, 0x63, 0x0f, 0x97, 0xe1, 0xa0, 0xff, 0xb7, 0x97, 0xdb, 0xb5,
        0xeb, 0xcc, 0xf8, 0xed, 0x8e, 0xe8, 0x8b, 0x95, 0x0b, 0x91, 0xee, 0xfa,
        0xc6, 0x13, 0xa8, 0xf3, 0xdc, 0x71, 0x41, 0xd3, 0x50, 0x45, 0xdc, 0xc6,
        0x3e, 0x75, 0x32, 0x49, 0x2f, 0xb6, 0xc7, 0x3c, 0x0c, 0xb6, 0x3b, 0xd6,
        0x5a, 0x5d, 0xab, 0xf2, 0xa4, 0x2a, 0xbd, 0x8d, 0xb2, 0x7f, 0x63, 0xca,
        0x42, 0x61, 0x28, 0xeb, 0xb9, 0xb4, 0x77, 0x27, 0x62, 0xfb, 0x03, 0x28,
    };
    const addr = "ip4:203.0.113.7:443";
    const odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };

    try std.testing.expectEqual(ValidationResult.valid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_010_000_000,
        .client_address = addr,
        .original_dcid = &odcid,
        .retry_scid = &scid,
    }));
    // Same bytes against shifted expectations — pins each recovered
    // field, not just AEAD integrity.
    try std.testing.expectEqual(ValidationResult.expired, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_030_000_001,
        .client_address = addr,
        .original_dcid = &odcid,
        .retry_scid = &scid,
    }));
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_699_999_999_999_999,
        .client_address = addr,
        .original_dcid = &odcid,
        .retry_scid = &scid,
    }));
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_010_000_000,
        .client_address = addr,
        .original_dcid = &odcid,
        .retry_scid = &scid,
        .quic_version = 0x6b3343cf,
    }));
    const wrong_odcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 };
    try std.testing.expectEqual(ValidationResult.invalid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_010_000_000,
        .client_address = addr,
        .original_dcid = &wrong_odcid,
        .retry_scid = &scid,
    }));
    const wrong_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x23 };
    try std.testing.expectEqual(ValidationResult.invalid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_010_000_000,
        .client_address = addr,
        .original_dcid = &odcid,
        .retry_scid = &wrong_scid,
    }));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `validate` with arbitrary bytes and a fuzzer-chosen set of
// expected bound fields. Property: the function never panics or
// reaches `unreachable`, and never returns `.valid` for an input the
// fuzzer didn't mint with the same key. (The fuzzer's bytes are
// untrusted relative to `testing_key`; any `.valid` answer would
// imply a forgery against AES-GCM-256.)

test "fuzz: retry_token validate never panics" {
    try std.testing.fuzz({}, fuzzValidate, .{});
}

fn fuzzValidate(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [max_token_len * 2]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    // Fuzzer-chosen expectations clamped to the format's caps so
    // `validate` itself drives any length-based rejection rather
    // than short-circuiting on `validateBoundInputs`.
    var addr_buf: [max_address_len]u8 = undefined;
    const addr_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_address_len));
    smith.bytes(addr_buf[0..addr_len]);

    var odcid_buf: [max_cid_len]u8 = undefined;
    const odcid_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_cid_len));
    smith.bytes(odcid_buf[0..odcid_len]);

    var scid_buf: [max_cid_len]u8 = undefined;
    const scid_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_cid_len));
    smith.bytes(scid_buf[0..scid_len]);

    const result = validate(input, .{
        .key = &testing_key,
        .now_us = smith.value(u64),
        .client_address = addr_buf[0..addr_len],
        .original_dcid = odcid_buf[0..odcid_len],
        .retry_scid = scid_buf[0..scid_len],
        .quic_version = smith.value(u32),
        .max_clock_skew_us = smith.value(u64),
    });
    // Every byte string the fuzzer hands us is unauthenticated
    // relative to `testing_key`. A `.valid` answer would imply a
    // forgery against AES-GCM-256 — fail loud so the fuzzer
    // minimizes and persists the witness.
    if (result == .valid) return error.UnexpectedValid;
}
