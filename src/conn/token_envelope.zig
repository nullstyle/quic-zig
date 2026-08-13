//! Shared AEAD envelope for the two address-validation token codecs
//! (`new_token.zig`, `retry_token.zig`).
//!
//! Both tokens ride in the same Initial Token field and are required
//! to stay bytewise indistinguishable on the wire — `Server/dos.zig`
//! disambiguates them only by AEAD domain separator, trying
//! NEW_TOKEN.validate first and falling through to Retry on any
//! non-`.valid` result. This module owns the single copy of that
//! shared shape:
//!
//!     nonce (12)  |  ciphertext (68)  |  tag (16)     = 96 bytes
//!
//! with an inner plaintext of a fixed header (version, issued_at,
//! expires_at) followed by length-prefixed bound fields, zero-padded
//! to 68 bytes before AES-GCM-256 seal.
//!
//! What stays per-module, deliberately: the `Key` declarations and
//! rotation cadence (NEW_TOKENs outlive Retry tokens by orders of
//! magnitude — rotating one key must not invalidate the other's
//! tokens), the domain separators (independent format versions: a
//! bump to one must not invalidate the other's outstanding tokens),
//! the public `Error` sets, `ValidationResult` enums, mint budget
//! policy, and the option structs. The modules bind those onto
//! `Envelope(cfg)` instantiations; the envelope owns the mechanics
//! that history shows must move in lockstep (the 22-vs-23-byte
//! `max_address_len` bug had to be fixed in both files in one
//! commit — 70e2d31).

const std = @import("std");
const boringssl = @import("boringssl");

const AesGcm256 = boringssl.crypto.aead.AesGcm256;

/// AES-GCM-256 key length in bytes.
pub const key_len: usize = AesGcm256.key_len;
/// AEAD nonce length in bytes (12, GCM standard).
pub const nonce_len: usize = AesGcm256.nonce_len;
/// AEAD authentication tag length in bytes (16, GCM standard).
pub const tag_len: usize = AesGcm256.tag_len;

/// Total token length on the wire, shared by every envelope
/// instantiation — THE wire-indistinguishability constant. Bumping it
/// for one token format alone would break the other's documented
/// opacity property, so it is deliberately not part of `Config`.
pub const token_len: usize = 96;

/// Plaintext payload size: `token_len - nonce_len - tag_len`.
/// Plaintext is zero-padded to this length before AEAD seal so every
/// minted token is a constant-length opaque blob.
pub const plaintext_len: usize = token_len - nonce_len - tag_len;

/// Per-instantiation configuration. Only what genuinely differs
/// between the token formats lives here.
pub const Config = struct {
    /// AEAD AAD domain separator; encodes the instantiation's own
    /// format version (e.g. "quic new_token v1", "quic retry token
    /// v2"). Kept per-instantiation so one format can rev without
    /// invalidating the other's outstanding tokens.
    domain_separator: []const u8,
    /// Per-field capacity caps for the length-prefixed bound fields,
    /// in wire order. The array length fixes the field count.
    field_caps: []const usize,
};

/// Header fields common to every token format, written at fixed
/// offsets 0 / 4 / 12 of the plaintext.
pub const Header = struct {
    quic_version: u32,
    issued_at_us: u64,
    expires_at_us: u64,
};

/// Shared verdict ladder. The modules map this onto their own public
/// `ValidationResult` enums (kept separate so the embedder-visible
/// types stay distinct).
pub const Verdict = enum {
    valid,
    malformed,
    wrong_version,
    not_yet_valid,
    expired,
    invalid,
};

/// Seal-side failures. A strict subset of both modules' public
/// `Error` sets, so `try` coerces at the call site.
pub const SealError = error{
    /// AEAD seal/init failure (BoringSSL). Not peer-reachable in
    /// practice; surfaces only on out-of-memory or library misuse.
    AeadFailure,
    /// CSPRNG failure (BoringSSL). Same not-peer-reachable property.
    RandFailure,
};

/// The shared codec over a fixed field list. `cfg.field_caps.len`
/// bound fields, each length-prefixed with a single byte.
pub fn Envelope(comptime cfg: Config) type {
    return struct {
        pub const num_fields = cfg.field_caps.len;

        /// Plaintext layout overhead: the fixed header plus one
        /// length-prefix byte per bound field.
        pub const plaintext_fixed_overhead: usize = 4 + 8 + 8 + num_fields;

        /// Maximum sum of the bound-field lengths that fits in the
        /// fixed plaintext budget. The caller's mint enforces this at
        /// runtime (its error policy is per-module).
        pub const max_bound_total: usize = plaintext_len - plaintext_fixed_overhead;

        pub const Fields = [num_fields][]const u8;

        comptime {
            std.debug.assert(plaintext_len >= plaintext_fixed_overhead);
            // Each field's cap must be expressible in its one-byte
            // length prefix and must fit the budget alone.
            for (cfg.field_caps) |cap| {
                std.debug.assert(cap <= 255);
                std.debug.assert(cap <= max_bound_total);
            }
        }

        /// Mint the token: random nonce, fixed header (expiry derived
        /// by saturating add), length-prefixed fields, zero padding,
        /// AEAD seal under `cfg.domain_separator`.
        ///
        /// The caller has already validated each field against its
        /// cap and the field-length sum against `max_bound_total` —
        /// this function asserts rather than re-policing, so the
        /// per-module error vocabulary stays at the public boundary.
        pub fn seal(
            dst: *[token_len]u8,
            key: *const [key_len]u8,
            quic_version: u32,
            now_us: u64,
            lifetime_us: u64,
            fields: Fields,
        ) SealError!void {
            // Per-token random nonce. AES-GCM nonce reuse under a
            // fixed key breaks confidentiality and integrity, so the
            // CSPRNG path is load-bearing; boringssl-zig surfaces
            // RAND failures as an explicit error — bubble it up
            // rather than silently zeroing.
            var nonce: [nonce_len]u8 = undefined;
            boringssl.crypto.rand.fillBytes(&nonce) catch return SealError.RandFailure;
            @memcpy(dst[0..nonce_len], &nonce);

            var pt_buf: [plaintext_len]u8 = @splat(0);
            writePlaintext(&pt_buf, quic_version, now_us, lifetime_us, fields);

            var aead = AesGcm256.init(key) catch return SealError.AeadFailure;
            defer aead.deinit();
            const ct_len = aead.seal(
                dst[nonce_len..token_len],
                &nonce,
                cfg.domain_separator,
                &pt_buf,
            ) catch return SealError.AeadFailure;
            std.debug.assert(ct_len == plaintext_len + tag_len);
        }

        /// Validate a token against the expected bound fields: length
        /// gate, AEAD open, plaintext parse, version/issue/expiry
        /// ladder, then a constant-time compare per bound field. The
        /// whole pipeline lives here so a change to any step lands in
        /// every token format at once.
        pub fn validate(
            token: []const u8,
            key: *const [key_len]u8,
            quic_version: u32,
            now_us: u64,
            max_clock_skew_us: u64,
            expected_fields: Fields,
        ) Verdict {
            if (token.len != token_len) return .malformed;

            var nonce: [nonce_len]u8 = undefined;
            @memcpy(&nonce, token[0..nonce_len]);
            const ciphertext = token[nonce_len..token_len];

            var aead = AesGcm256.init(key) catch return .malformed;
            defer aead.deinit();
            var pt_buf: [plaintext_len]u8 = undefined;
            const opened_len = aead.open(&pt_buf, &nonce, cfg.domain_separator, ciphertext) catch return .malformed;
            std.debug.assert(opened_len == plaintext_len);

            var header: Header = undefined;
            var fields: Fields = undefined;
            parsePlaintext(&pt_buf, &header, &fields) catch return .malformed;

            if (header.quic_version != quic_version) return .wrong_version;
            if (addSat(now_us, max_clock_skew_us) < header.issued_at_us) return .not_yet_valid;
            if (now_us > addSat(header.expires_at_us, max_clock_skew_us)) return .expired;

            for (fields, expected_fields) |got, expected| {
                if (!equalCt(got, expected)) return .invalid;
            }
            return .valid;
        }

        /// Write the plaintext layout into `dst`, which the caller
        /// pre-zeroed for trailing padding.
        fn writePlaintext(
            dst: *[plaintext_len]u8,
            quic_version: u32,
            now_us: u64,
            lifetime_us: u64,
            fields: Fields,
        ) void {
            var pos: usize = 0;
            std.mem.writeInt(u32, dst[pos..][0..4], quic_version, .big);
            pos += 4;
            std.mem.writeInt(u64, dst[pos..][0..8], now_us, .big);
            pos += 8;
            std.mem.writeInt(u64, dst[pos..][0..8], addSat(now_us, lifetime_us), .big);
            pos += 8;

            inline for (0..num_fields) |i| {
                const f = fields[i];
                std.debug.assert(f.len <= cfg.field_caps[i]);
                dst[pos] = @intCast(f.len);
                pos += 1;
                @memcpy(dst[pos..][0..f.len], f);
                pos += f.len;
            }
            // Caller zero-initialised `dst`; trailing padding bytes
            // are well-defined zeros.
        }

        /// Parse the plaintext (length always `plaintext_len`).
        /// Trailing bytes after the last length-prefixed field are
        /// padding — the AEAD already authenticated them, so the pad
        /// shape needs no validation here.
        fn parsePlaintext(
            pt: *const [plaintext_len]u8,
            header: *Header,
            fields: *Fields,
        ) ParseError!void {
            header.quic_version = std.mem.readInt(u32, pt[0..4], .big);
            header.issued_at_us = std.mem.readInt(u64, pt[4..12], .big);
            header.expires_at_us = std.mem.readInt(u64, pt[12..20], .big);

            var pos: usize = 20;
            inline for (0..num_fields) |i| {
                fields[i] = try readLengthPrefixed(pt, &pos, cfg.field_caps[i]);
            }
        }
    };
}

const ParseError = error{TruncatedField};

fn readLengthPrefixed(pt: *const [plaintext_len]u8, pos: *usize, cap: usize) ParseError![]const u8 {
    if (pos.* + 1 > pt.len) return ParseError.TruncatedField;
    const len: usize = pt[pos.*];
    pos.* += 1;
    if (len > cap) return ParseError.TruncatedField;
    if (pos.* + len > pt.len) return ParseError.TruncatedField;
    const slice = pt[pos.* .. pos.* + len];
    pos.* += len;
    return slice;
}

/// Length-aware constant-time byte slice equality. `timing_safe.eql`
/// requires fixed-size arrays, so we route through fixed-size scratch
/// buffers sized to fit any bound field.
fn equalCt(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var sa: [plaintext_len]u8 = @splat(0);
    var sb: [plaintext_len]u8 = @splat(0);
    @memcpy(sa[0..a.len], a);
    @memcpy(sb[0..b.len], b);
    return std.crypto.timing_safe.eql([plaintext_len]u8, sa, sb);
}

/// Saturating add, used for the expiry computation and the clock-skew
/// window so a huge lifetime or skew can't wrap.
pub fn addSat(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}

test "envelope round-trips header and fields through seal/validate" {
    const Env = Envelope(.{
        .domain_separator = "envelope self-test",
        .field_caps = &.{ 23, 20 },
    });
    const key: [key_len]u8 = @splat(0x42);
    var token: [token_len]u8 = undefined;
    try Env.seal(&token, &key, 1, 1_000, 500, .{ "addr-bytes", "cid" });

    try std.testing.expectEqual(Verdict.valid, Env.validate(&token, &key, 1, 1_200, 0, .{ "addr-bytes", "cid" }));
    try std.testing.expectEqual(Verdict.expired, Env.validate(&token, &key, 1, 1_501, 0, .{ "addr-bytes", "cid" }));
    try std.testing.expectEqual(Verdict.not_yet_valid, Env.validate(&token, &key, 1, 999, 0, .{ "addr-bytes", "cid" }));
    try std.testing.expectEqual(Verdict.wrong_version, Env.validate(&token, &key, 2, 1_200, 0, .{ "addr-bytes", "cid" }));
    try std.testing.expectEqual(Verdict.invalid, Env.validate(&token, &key, 1, 1_200, 0, .{ "addr-bytes", "cix" }));
    try std.testing.expectEqual(Verdict.invalid, Env.validate(&token, &key, 1, 1_200, 0, .{ "addr-bytez", "cid" }));

    // Cross-domain rejection: same key, different separator.
    const Other = Envelope(.{
        .domain_separator = "envelope self-test B",
        .field_caps = &.{ 23, 20 },
    });
    try std.testing.expectEqual(Verdict.malformed, Other.validate(&token, &key, 1, 1_200, 0, .{ "addr-bytes", "cid" }));
}
