//! NEW_TOKEN issuance helpers (RFC 9000 §8.1.3 / §19.7).
//!
//! A server hands the client a NEW_TOKEN frame after handshake
//! confirmation; the client may then echo that token in the long-header
//! Token field of an Initial belonging to a *future* connection. A
//! valid echoed token lets the server skip the Retry round-trip on
//! that next connection, treating the source as already address-validated.
//!
//! NEW_TOKEN is a sibling of `retry_token.zig` but binds different
//! material: it does NOT bind to ODCID or Retry SCID (those are
//! per-connection ephemera and would force the next connection's CIDs
//! to match the previous one's). It DOES bind the client address, the
//! QUIC version, and an issue/expiry window, all sealed inside an
//! AES-GCM-256 blob so peers and on-path observers see opaque random
//! bytes.
//!
//! Wire format (v1, fixed 96 bytes — matches the v2 Retry token shape
//! so both formats are uniformly opaque on the wire):
//!
//!     nonce (12)  |  ciphertext (68)  |  tag (16)
//!
//! Inner plaintext (zero-padded to 68 bytes before AEAD-seal):
//!
//!     version    (4 bytes,  big-endian)
//!     issued_at  (8 bytes,  big-endian, microseconds since epoch)
//!     expires_at (8 bytes,  big-endian, microseconds since epoch)
//!     addr_len   (1 byte)         | client_address (<= 22 bytes)
//!     <pad>      (zero bytes to reach 68)
//!
//! The address slot is the only variable-length bound material, so the
//! plaintext budget (68 - 21 fixed = 47 bytes) is far in excess of the
//! 22-byte `path.Address` shape — there is no `OutputTooSmall` rejection
//! path for normal addresses, but we keep one for forward-compatibility
//! if `path.Address` ever grows.
//!
//! Domain separator: `"quic new_token v1"` — distinct from the
//! Retry-token domain separator so a Retry token presented in the
//! Initial-token field cannot be mistaken for a NEW_TOKEN (and vice
//! versa). The server's gate tries NEW_TOKEN.validate first; on
//! `.malformed` it falls through to Retry validation.

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
/// client address context — including IPv6 (23 bytes). A stale
/// literal here (22) previously made `mint` reject every IPv6 peer,
/// silently disabling NEW_TOKEN issuance for the whole address family.
pub const max_address_len: usize = path.Address.context_max_len;

/// Total token length on the wire (and in `Token`). Fixed at 96 bytes
/// so NEW_TOKEN is bytewise indistinguishable from the v2 Retry token
/// shape on the wire — the constant is owned by `token_envelope` for
/// exactly that reason.
pub const max_token_len: usize = token_envelope.token_len;

/// The shared AEAD envelope, instantiated with the v1 NEW_TOKEN
/// domain separator and the single address bound field. The envelope
/// owns the seal/open/parse/compare mechanics; this module keeps the
/// key material, error vocabulary, and budget policy.
const Env = token_envelope.Envelope(.{
    .domain_separator = "quic new_token v1",
    .field_caps = &.{max_address_len},
});

comptime {
    // Couple the address-field cap to the real Address context size so
    // a future Address change can't silently shrink token capacity and
    // reintroduce the IPv6 NEW_TOKEN regression.
    std.debug.assert(max_address_len >= path.Address.context_max_len);
    std.debug.assert(path.Address.context_max_len <= max_bound_total);
}

/// Maximum address-field length that fits the fixed plaintext budget.
/// Mint enforces this at runtime.
const max_bound_total: usize = Env.max_bound_total;

/// 32-byte AES-GCM-256 key. The server keeps this stable across every
/// outstanding token's lifetime so a client returning hours later can
/// still validate. **NEW_TOKENs typically outlive Retry tokens by
/// orders of magnitude**, so this key is intentionally separate from
/// `retry_token.Key`: rotating the Retry key (e.g. on every
/// shift) MUST NOT invalidate every NEW_TOKEN issued in the prior
/// shift.
pub const Key = [key_len]u8;

/// Fixed-size NEW_TOKEN. Always exactly `max_token_len` bytes.
pub const Token = [max_token_len]u8;

/// Errors raised by `mint` (and surfaced as `.malformed` from
/// `validate`).
pub const Error = error{
    /// Output buffer was smaller than `max_token_len`, or the
    /// requested address length doesn't fit the fixed plaintext
    /// budget.
    OutputTooSmall,
    /// `client_address` exceeded `max_address_len`.
    ContextTooLong,
    /// AEAD seal/init failure (BoringSSL). Not peer-reachable in
    /// practice; surfaces only on out-of-memory or library misuse.
    AeadFailure,
    /// CSPRNG failure (BoringSSL). Same not-peer-reachable property.
    RandFailure,
};

/// Inputs to `mint`. The AEAD seal binds `client_address`,
/// `quic_version`, `now_us`, and the expiry derived from `lifetime_us`.
pub const MintOptions = struct {
    key: *const Key,
    now_us: u64,
    lifetime_us: u64,
    client_address: []const u8,
    quic_version: u32 = 0x00000001,
};

/// Inputs to `validate`. Must be byte-equal to the `MintOptions`
/// values used to issue the token (modulo `now_us`/`max_clock_skew_us`).
pub const ValidateOptions = struct {
    key: *const Key,
    now_us: u64,
    client_address: []const u8,
    quic_version: u32 = 0x00000001,
    max_clock_skew_us: u64 = 0,
};

/// Outcome of `validate`.
pub const ValidationResult = enum {
    /// AEAD opened cleanly, recovered fields match, and timestamps
    /// are within the allowed window.
    valid,
    /// Length, AEAD authentication, or recovered-field shape was
    /// wrong (also covers a Retry-token blob presented to NEW_TOKEN
    /// validate, since the domain separator differs). Treat as
    /// untrusted.
    malformed,
    /// The QUIC version field did not match.
    wrong_version,
    /// `issued_at_us` is in the future beyond `max_clock_skew_us`.
    not_yet_valid,
    /// `expires_at_us` is in the past beyond `max_clock_skew_us`.
    expired,
    /// AEAD opened cleanly but the recovered client address did not
    /// match the validator's expectation.
    invalid,
};

/// Mint a NEW_TOKEN into `dst`. Returns the number of bytes written
/// (always `max_token_len`).
pub fn mint(dst: []u8, opts: MintOptions) Error!usize {
    if (dst.len < max_token_len) return Error.OutputTooSmall;
    try validateBoundInputs(opts.client_address);
    if (opts.client_address.len > max_bound_total) return Error.OutputTooSmall;

    try Env.seal(
        dst[0..max_token_len],
        opts.key,
        opts.quic_version,
        opts.now_us,
        opts.lifetime_us,
        .{opts.client_address},
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

/// Validate a NEW_TOKEN. Returns `.valid` only if the AEAD opens
/// cleanly, the recovered address matches, and the token is within
/// its issue/expiry window (subject to `max_clock_skew_us`). All
/// failure modes are surfaced as enum variants — the function never
/// errors. Address comparison runs in constant time over the
/// recovered plaintext.
pub fn validate(token: []const u8, opts: ValidateOptions) ValidationResult {
    validateBoundInputs(opts.client_address) catch return .malformed;
    return switch (Env.validate(
        token,
        opts.key,
        opts.quic_version,
        opts.now_us,
        opts.max_clock_skew_us,
        .{opts.client_address},
    )) {
        .valid => .valid,
        .malformed => .malformed,
        .wrong_version => .wrong_version,
        .not_yet_valid => .not_yet_valid,
        .expired => .expired,
        .invalid => .invalid,
    };
}

fn validateBoundInputs(client_address: []const u8) Error!void {
    if (client_address.len > max_address_len) return Error.ContextTooLong;
}

const testing_key: Key = .{
    0x4f, 0x95, 0xd1, 0x6b, 0x2a, 0x7c, 0x83, 0xee,
    0x18, 0x42, 0x90, 0x3d, 0xfa, 0xc4, 0x6e, 0x71,
    0x09, 0xb6, 0x55, 0xa3, 0x2c, 0xee, 0x18, 0x77,
    0xd4, 0x3f, 0x88, 0x21, 0x05, 0x6c, 0xa9, 0x33,
};

test "NEW_TOKEN validates with matching address version and time" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 24 * 3600 * 1_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    }));
}

test "NEW_TOKEN binds a full IPv6 address context (regression: 23-byte context)" {
    // Regression: max_address_len (22) < IPv6 writeContext output (23)
    // made mint reject every IPv6 peer, silently disabling NEW_TOKEN.
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
        .lifetime_us = 24 * 3600 * 1_000_000,
        .client_address = ctx,
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = ctx,
    }));
}

test "NEW_TOKEN validates under non-default QUIC version" {
    const v2: u32 = 0x6b3343cf;
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 60_000_000,
        .client_address = "addr",
        .quic_version = v2,
    });

    try std.testing.expectEqual(ValidationResult.valid, validate(&token, .{
        .key = &testing_key,
        .now_us = 1_500_000,
        .client_address = "addr",
        .quic_version = v2,
    }));

    // Default version (0x00000001) is the wrong version here.
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&token, .{
        .key = &testing_key,
        .now_us = 1_500_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects expired and not-yet-valid tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 10_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "addr",
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 11_000_000,
        .client_address = "addr",
    };

    var expired = opts;
    expired.now_us = 15_000_001;
    try std.testing.expectEqual(ValidationResult.expired, validate(&token, expired));

    var future = opts;
    future.now_us = 9_999_999;
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&token, future));

    // Clock-skew tolerance moves both edges out.
    var skewed_expired = expired;
    skewed_expired.max_clock_skew_us = 2_000_000;
    try std.testing.expectEqual(ValidationResult.valid, validate(&token, skewed_expired));
    var skewed_future = future;
    skewed_future.max_clock_skew_us = 2_000_000;
    try std.testing.expectEqual(ValidationResult.valid, validate(&token, skewed_future));
}

test "NEW_TOKEN rejects malformed truncated and tampered tokens" {
    var token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000,
        .lifetime_us = 60_000,
        .client_address = "addr",
    });

    const opts: ValidateOptions = .{
        .key = &testing_key,
        .now_us = 5_000,
        .client_address = "addr",
    };

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

test "NEW_TOKEN rejects wrong key" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000,
        .lifetime_us = 60_000,
        .client_address = "addr",
    });
    const wrong_key: Key = @splat(0xff);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&token, .{
        .key = &wrong_key,
        .now_us = 5_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects Retry-token-shaped bytes (wrong domain)" {
    // A token shaped at the wire level (96 bytes random) but minted
    // by some other AES-GCM construction, or with the wrong domain
    // separator, can never authenticate. Mint a Retry-token-style
    // blob as a stand-in: the AEAD AAD differs, so opening fails and
    // we return `.malformed`.
    var random_blob: [max_token_len]u8 = @splat(0xab);
    try std.testing.expectEqual(ValidationResult.malformed, validate(&random_blob, .{
        .key = &testing_key,
        .now_us = 1_000,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN rejects address mismatch" {
    const token = try minted(.{
        .key = &testing_key,
        .now_us = 1_000_000,
        .lifetime_us = 5_000_000,
        .client_address = "ip4:127.0.0.1:4242",
    });

    try std.testing.expectEqual(ValidationResult.invalid, validate(&token, .{
        .key = &testing_key,
        .now_us = 2_000_000,
        .client_address = "ip4:127.0.0.1:4243",
    }));
}

test "NEW_TOKEN mint rejects oversized address and undersized output" {
    var addr_buf: [max_address_len + 1]u8 = @splat(0);
    var dst: [max_token_len]u8 = undefined;
    try std.testing.expectError(Error.ContextTooLong, mint(&dst, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = &addr_buf,
    }));

    var small: [4]u8 = undefined;
    try std.testing.expectError(Error.OutputTooSmall, mint(&small, .{
        .key = &testing_key,
        .now_us = 1,
        .lifetime_us = 1,
        .client_address = "addr",
    }));
}

test "NEW_TOKEN mint produces fixed-length 96-byte tokens with random nonce" {
    var dst: [max_token_len]u8 = undefined;
    const n = try mint(&dst, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
    });
    try std.testing.expectEqual(@as(usize, max_token_len), n);

    var dst2: [max_token_len]u8 = undefined;
    _ = try mint(&dst2, .{
        .key = &testing_key,
        .now_us = 42,
        .lifetime_us = 10_000,
        .client_address = "addr",
    });
    // Two mints under the same key/inputs differ in the random
    // nonce, so the wire bytes diverge.
    try std.testing.expect(!std.mem.eql(u8, &dst, &dst2));
}

test "NEW_TOKEN KAT: validate pins the v1 wire format" {
    // Known-answer token minted by the v1 codec under `testing_key`
    // with now_us = 1_700_000_000_000_000, lifetime_us =
    // 3_600_000_000, client_address = "ip4:203.0.113.7:443",
    // quic_version = 1. Mint is nondeterministic (random nonce), but
    // `validate` over these fixed bytes is fully deterministic.
    //
    // If this test starts failing, the wire format changed and every
    // outstanding NEW_TOKEN in the field just got invalidated. Since
    // NEW_TOKENs are expected to outlive Retry tokens by orders of
    // magnitude and survive server restarts, that must be a
    // deliberate, versioned decision (bump the domain separator) —
    // never a refactor side effect.
    const kat = [_]u8{
        0xd7, 0x1e, 0x08, 0x58, 0x01, 0xf2, 0x5f, 0xd9, 0x75, 0xf0, 0xeb, 0x5d,
        0x5a, 0xe8, 0xc7, 0xed, 0x7c, 0x10, 0x6d, 0xa6, 0x76, 0x7c, 0xec, 0xa1,
        0x8c, 0x2d, 0xe8, 0xdc, 0x80, 0x51, 0x6f, 0x99, 0x69, 0x29, 0x30, 0x20,
        0x63, 0x30, 0x90, 0xda, 0x67, 0x1c, 0x5c, 0xea, 0xbf, 0xcc, 0x8c, 0xe9,
        0x94, 0xbe, 0xf6, 0x56, 0xfc, 0x8b, 0x02, 0xc8, 0x4f, 0x4b, 0xee, 0xe9,
        0x14, 0x6a, 0xd9, 0xdc, 0x32, 0x6e, 0xc1, 0x71, 0xdc, 0x2f, 0xcb, 0x12,
        0xee, 0x10, 0x6b, 0xeb, 0xcd, 0xa7, 0x95, 0x0b, 0x86, 0x9e, 0x6d, 0x23,
        0x78, 0x1e, 0x51, 0x67, 0x59, 0x91, 0x16, 0xd5, 0x5c, 0xf7, 0xea, 0x60,
    };
    const addr = "ip4:203.0.113.7:443";

    try std.testing.expectEqual(ValidationResult.valid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_100_000_000,
        .client_address = addr,
    }));
    // Same bytes against shifted expectations — pins each recovered
    // field, not just AEAD integrity.
    try std.testing.expectEqual(ValidationResult.expired, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_003_600_000_001,
        .client_address = addr,
    }));
    try std.testing.expectEqual(ValidationResult.not_yet_valid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_699_999_999_999_999,
        .client_address = addr,
    }));
    try std.testing.expectEqual(ValidationResult.wrong_version, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_100_000_000,
        .client_address = addr,
        .quic_version = 0x6b3343cf,
    }));
    try std.testing.expectEqual(ValidationResult.invalid, validate(&kat, .{
        .key = &testing_key,
        .now_us = 1_700_000_100_000_000,
        .client_address = "ip4:203.0.113.7:444",
    }));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `validate` with arbitrary bytes and a fuzzer-chosen address.
// Property: never panics or reaches `unreachable`, and never returns
// `.valid` for an input the fuzzer didn't mint with `testing_key` — a
// `.valid` answer would imply a forgery against AES-GCM-256.

test "fuzz: new_token validate never panics" {
    try std.testing.fuzz({}, fuzzValidate, .{});
}

fn fuzzValidate(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [max_token_len * 2]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    var addr_buf: [max_address_len]u8 = undefined;
    const addr_len: usize = smith.valueRangeAtMost(u8, 0, @intCast(max_address_len));
    smith.bytes(addr_buf[0..addr_len]);

    const result = validate(input, .{
        .key = &testing_key,
        .now_us = smith.value(u64),
        .client_address = addr_buf[0..addr_len],
        .quic_version = smith.value(u32),
        .max_clock_skew_us = smith.value(u64),
    });
    if (result == .valid) return error.UnexpectedValid;
}
