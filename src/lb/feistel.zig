//! Four-pass Feistel network operating over a `combined`-byte plaintext
//! block (draft-ietf-quic-load-balancers-21 §5.4.2).
//!
//! The Feistel structure is a length-preserving, round-keyed permutation:
//! plaintext and ciphertext are the same byte count (5..15 or 17..19 in
//! QUIC-LB; combined == 16 takes the §5.4.1 single-pass shortcut and is
//! NOT this module's territory). The round function is `AES-128-ECB`
//! over an `expand`-padded 16-byte block whose final two bytes carry the
//! plaintext length and the pass index, so each pass uses a structurally
//! distinct input even though the cipher key is identical.
//!
//! ## Algorithm (server-side encrypt)
//!
//! Per draft §5.4.2.3:
//!
//! 1. Concatenate `server_id || nonce` → `plaintext` (length
//!    `combined`). If `combined` is odd, clear the lower 4 bits of the
//!    last byte of `left_0` and the upper 4 bits of the first byte of
//!    `right_0` so the half-byte at the split boundary doesn't appear
//!    in both halves.
//! 2. Split into `left_0` and `right_0` of length `half_len = ceil(combined / 2)`.
//!    On odd lengths the two halves overlap by one byte at the split,
//!    with each half keeping only its own nibble of that byte.
//! 3-11. Four Feistel rounds:
//!      * Pass `n`: encrypt `expand(combined, n, side_(n-1))` with
//!        AES-128-ECB, XOR the first `half_len` bytes of the result
//!        into the *other* half. Re-clear the boundary nibble after
//!        every XOR for odd lengths.
//! 12. Concatenate `left_2 || right_2`; for odd lengths, fuse the
//!     boundary byte (left_2's high nibble + right_2's low nibble)
//!     so the final output is exactly `combined` bytes.
//!
//! ## Decrypt
//!
//! Decrypt runs the same four passes in reverse order, also using
//! AES-128-*encrypt* (Feistel only needs the round function to be
//! deterministic, never invertible). The embedder-facing server path
//! uses `encrypt`; `decrypt` is public so round-trip property tests and
//! operations tooling can recover the plaintext.

const std = @import("std");
const boringssl = @import("boringssl");

pub const Aes128 = boringssl.crypto.aes.Aes128;

pub const aes_block_size: usize = 16;
/// Maximum plaintext length the Feistel processes. Set by the QUIC-LB
/// combined-length cap (`server_id_len + nonce_len <= 19`).
pub const max_plaintext_len: usize = 19;
/// Maximum half length: `ceil(19 / 2) == 10`.
pub const max_half_len: usize = 10;

pub const Error = error{
    /// Plaintext length is outside the 5..19 range or equals 16
    /// (which is the single-pass §5.4.1 territory, not this module).
    /// `Factory` never feeds us those sizes — surfaces only when the
    /// module is called directly.
    InvalidPlaintextLen,
};

/// `expand(combined, pass, half) → 16 bytes`.
///
/// Layout per §5.4.2.2:
///
/// ```text
/// bytes 0..N        : input_bytes (the half just produced)
/// bytes N..14       : zero pad
/// byte  14          : combined plaintext length (5..19)
/// byte  15          : pass index (1..4)
/// ```
///
/// where `N = ceil(combined / 2) = half_len`. The length+pass tail
/// makes every pass's AES input distinct even under a fixed key.
pub fn expand(out: *[aes_block_size]u8, combined: u8, pass: u8, half: []const u8) void {
    @memset(out, 0);
    @memcpy(out[0..half.len], half);
    out[14] = combined;
    out[15] = pass;
}

/// Server-side four-pass Feistel encrypt. `plaintext.len ==
/// ciphertext.len == combined`, where `combined` is the configured
/// `server_id_len + nonce_len` and is NOT 16 (combined==16 selects
/// the §5.4.1 single-pass code path elsewhere).
pub fn encrypt(aes: *const Aes128, plaintext: []const u8, ciphertext: []u8) Error!void {
    return run(aes, plaintext, ciphertext, .{ 1, 2, 3, 4 });
}

/// Inverse of `encrypt`. Same constraints on lengths. Test/ops
/// tooling — production server code never decrypts.
pub fn decrypt(aes: *const Aes128, ciphertext: []const u8, plaintext: []u8) Error!void {
    return run(aes, ciphertext, plaintext, .{ 4, 3, 2, 1 });
}

/// Shared four-pass driver (§5.4.2.3 steps 1..12). Encrypt and
/// decrypt are the same routine differing only in the pass schedule
/// — the round function is AES-128-*encrypt* in both directions, so
/// there is no directional asymmetry beyond the order of `passes`.
/// `passes` stays comptime so the per-CID-mint `encrypt` path remains
/// fully unrolled.
fn run(aes: *const Aes128, in: []const u8, out: []u8, comptime passes: [4]u8) Error!void {
    try validateLen(in.len);
    std.debug.assert(out.len == in.len);

    const combined: u8 = @intCast(in.len);
    const half_len: usize = (in.len + 1) / 2;
    const odd: bool = (in.len & 1) == 1;

    var left: [max_half_len]u8 = undefined;
    var right: [max_half_len]u8 = undefined;
    splitHalves(in, &left, &right, half_len, odd);

    inline for (passes) |pass| {
        feistelRound(aes, combined, pass, left[0..half_len], right[0..half_len], odd);
    }

    assembleHalves(out, left[0..half_len], right[0..half_len], odd);
}

/// Steps 1-2: split `in` into halves of `half_len` bytes. The halves
/// overlap by one byte when `in.len` is odd (the split byte); the
/// clears restrict each half to its own nibble of that byte so the
/// Feistel round XORs don't recombine them through the boundary.
fn splitHalves(
    in: []const u8,
    left: *[max_half_len]u8,
    right: *[max_half_len]u8,
    half_len: usize,
    odd: bool,
) void {
    @memcpy(left[0..half_len], in[0..half_len]);
    @memcpy(right[0..half_len], in[in.len - half_len ..]);
    if (odd) {
        left[half_len - 1] &= 0xf0;
        right[0] &= 0x0f;
    }
}

/// Steps 3-11, one pass each: XOR
/// `truncate(AES(expand(combined, pass, source)))` into the target
/// half. Source and target are a pure function of pass parity — odd
/// passes read the left half and write the right, even passes the
/// reverse — which is what makes the same rounds run correctly in
/// either schedule order. On odd lengths the target's boundary nibble
/// is re-cleared after the XOR (right keeps only its low nibble of
/// the split byte, left only its high nibble).
fn feistelRound(
    aes: *const Aes128,
    combined: u8,
    pass: u8,
    left: []u8,
    right: []u8,
    odd: bool,
) void {
    const pass_is_odd = pass % 2 == 1;
    const source: []const u8 = if (pass_is_odd) left else right;
    const target: []u8 = if (pass_is_odd) right else left;

    var ex: [aes_block_size]u8 = undefined;
    var aes_out: [aes_block_size]u8 = undefined;
    expand(&ex, combined, pass, source);
    aes.encryptBlock(&ex, &aes_out);
    for (target, aes_out[0..target.len]) |*t, m| t.* ^= m;
    if (odd) {
        if (pass_is_odd) target[0] &= 0x0f else target[target.len - 1] &= 0xf0;
    }
}

/// Step 12: assemble the final output.
/// Even: simple concatenation.
/// Odd:  the last byte of `left` holds the high nibble (low nibble
///       cleared); the first byte of `right` holds the low nibble
///       (high nibble cleared); merge them via `or` into a single
///       shared byte so the output is exactly `out.len` bytes.
fn assembleHalves(out: []u8, left: []const u8, right: []const u8, odd: bool) void {
    const half_len = left.len;
    if (odd) {
        @memcpy(out[0 .. half_len - 1], left[0 .. half_len - 1]);
        out[half_len - 1] = left[half_len - 1] | right[0];
        @memcpy(out[half_len..], right[1..half_len]);
    } else {
        @memcpy(out[0..half_len], left[0..half_len]);
        @memcpy(out[half_len..], right[0..half_len]);
    }
}

fn validateLen(len: usize) Error!void {
    if (len < 5 or len > max_plaintext_len or len == 16) return Error.InvalidPlaintextLen;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "expand: example from draft §5.4.2.2" {
    // Spec example: expand(0x06, 0x02, 0xaaba3c) =
    //   aaba3c00000000000000000000000602
    var out: [aes_block_size]u8 = undefined;
    const input = [_]u8{ 0xaa, 0xba, 0x3c };
    expand(&out, 0x06, 0x02, &input);
    const expected = fromHex("aaba3c00000000000000000000000602");
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "expand: ten-byte input fills 0..10, then 4 zeros, then length+pass" {
    var out: [aes_block_size]u8 = undefined;
    const input: [10]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    expand(&out, 19, 4, &input);
    var expected: [16]u8 = undefined;
    @memcpy(expected[0..10], &input);
    @memset(expected[10..14], 0);
    expected[14] = 19;
    expected[15] = 4;
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "encrypt: §5.4.2.4 worked example (3+4 server_id || nonce)" {
    // Per the draft's narrative example (combined=7, odd):
    //   server_id = 31441a
    //   nonce     = 9c69c275
    //   key       = fdf726a9893ec05c0632d3956680baf0
    //   on-wire   = 0767947d29be054a (8 bytes; first octet 0x07)
    // The ciphertext body is therefore 67947d29be054a (7 bytes).
    const key = fromHex("fdf726a9893ec05c0632d3956680baf0");
    const plaintext = fromHex("31441a9c69c275");
    const expected_ct = fromHex("67947d29be054a");

    const aes = try Aes128.init(&key);
    var ct: [7]u8 = undefined;
    try encrypt(&aes, &plaintext, &ct);
    try testing.expectEqualSlices(u8, &expected_ct, &ct);
}

test "decrypt: round-trips the §5.4.2.4 worked example" {
    const key = fromHex("fdf726a9893ec05c0632d3956680baf0");
    const plaintext = fromHex("31441a9c69c275");
    const aes = try Aes128.init(&key);

    var ct: [7]u8 = undefined;
    try encrypt(&aes, &plaintext, &ct);

    var pt2: [7]u8 = undefined;
    try decrypt(&aes, &ct, &pt2);
    try testing.expectEqualSlices(u8, &plaintext, &pt2);
}

test "encrypt + decrypt round-trip: every supported even length" {
    const key: [16]u8 = @splat(0x42);
    const aes = try Aes128.init(&key);

    var combined: usize = 6;
    while (combined <= 18) : (combined += 2) {
        if (combined == 16) continue; // single-pass territory
        var plaintext_buf: [max_plaintext_len]u8 = undefined;
        for (plaintext_buf[0..combined], 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
        const plaintext = plaintext_buf[0..combined];

        var ct_buf: [max_plaintext_len]u8 = undefined;
        const ct = ct_buf[0..combined];
        try encrypt(&aes, plaintext, ct);
        try testing.expect(!std.mem.eql(u8, plaintext, ct));

        var pt_buf: [max_plaintext_len]u8 = undefined;
        const pt = pt_buf[0..combined];
        try decrypt(&aes, ct, pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
}

test "encrypt + decrypt round-trip: every supported odd length" {
    const key: [16]u8 = @splat(0x99);
    const aes = try Aes128.init(&key);

    var combined: usize = 5;
    while (combined <= 19) : (combined += 2) {
        var plaintext_buf: [max_plaintext_len]u8 = undefined;
        for (plaintext_buf[0..combined], 0..) |*b, i| b.* = @intCast((i * 11 + 5) & 0xff);
        const plaintext = plaintext_buf[0..combined];

        var ct_buf: [max_plaintext_len]u8 = undefined;
        const ct = ct_buf[0..combined];
        try encrypt(&aes, plaintext, ct);

        var pt_buf: [max_plaintext_len]u8 = undefined;
        const pt = pt_buf[0..combined];
        try decrypt(&aes, ct, pt);
        try testing.expectEqualSlices(u8, plaintext, pt);
    }
}

test "encrypt: rejects combined == 16 (single-pass territory)" {
    const key: [16]u8 = @splat(0xab);
    const aes = try Aes128.init(&key);
    const plaintext: [16]u8 = @splat(0);
    var ct: [16]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &plaintext, &ct));
}

test "encrypt: rejects combined < 5 and > 19" {
    const key: [16]u8 = @splat(0xab);
    const aes = try Aes128.init(&key);
    var pt_short: [4]u8 = @splat(0);
    var ct_short: [4]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &pt_short, &ct_short));
    var pt_long: [20]u8 = @splat(0);
    var ct_long: [20]u8 = undefined;
    try testing.expectError(Error.InvalidPlaintextLen, encrypt(&aes, &pt_long, &ct_long));
}

test "encrypt/decrypt: pinned vectors at an even and the max odd length" {
    // The draft only publishes an absolute ciphertext vector at
    // combined=7 (§5.4.2.4, above). Because encrypt and decrypt share
    // `run`, a symmetric mistake in the boundary-nibble scheme would
    // round-trip cleanly — these implementation-pinned vectors
    // (generated from the pre-`run` per-direction bodies) also catch
    // that, at an even length (which never touches the boundary
    // nibble) and at the maximum odd length.
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const aes = try Aes128.init(&key);
    {
        const pt = fromHex("a0a1a2a3a4a5");
        const expected_ct = fromHex("8f7a3b8e4a59");
        var ct: [6]u8 = undefined;
        try encrypt(&aes, &pt, &ct);
        try testing.expectEqualSlices(u8, &expected_ct, &ct);
        var pt2: [6]u8 = undefined;
        try decrypt(&aes, &expected_ct, &pt2);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
    {
        const pt = fromHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2");
        const expected_ct = fromHex("bca5b94692d3197fd5a4293e0a2b08055a8491");
        var ct: [19]u8 = undefined;
        try encrypt(&aes, &pt, &ct);
        try testing.expectEqualSlices(u8, &expected_ct, &ct);
        var pt2: [19]u8 = undefined;
        try decrypt(&aes, &expected_ct, &pt2);
        try testing.expectEqualSlices(u8, &pt, &pt2);
    }
}
