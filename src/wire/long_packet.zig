//! Long-header QUIC packet helpers: Initial (RFC 9000 §17.2.2),
//! 0-RTT (§17.2.3), Handshake (§17.2.4), and Retry (§17.2.5).
//!
//! Long-header packets carry a varint Length field that frames
//! their PN+payload+tag region; this lets multiple long-header
//! packets coalesce into a single UDP datagram (§12.2). The
//! seal/open API here returns `bytes_consumed` so callers can
//! advance through a coalesced datagram one packet at a time.
//!
//! Protection mechanics are identical to short_packet:
//!   - AEAD nonce = static_iv XOR pn (RFC 9001 §5.3).
//!   - Header-protection mask is suite-specific (§5.4.3/§5.4.4),
//!     XORed into the low 4 bits of byte 0 + the PN bytes.
//!   - Sample begins at pn_offset + 4 regardless of pn_len (§5.4.2).

const std = @import("std");
const boringssl = @import("boringssl");

const header = @import("header.zig");
const packet_number_mod = @import("packet_number.zig");
const protection = @import("protection.zig");
const short_packet = @import("short_packet.zig");
const varint = @import("varint.zig");

const AesGcm128 = boringssl.crypto.aead.AesGcm128;

/// Re-export of `short_packet.PacketKeys` so callers don't need to
/// reach across modules for long-header seal/open.
pub const PacketKeys = short_packet.PacketKeys;
/// Re-export of `short_packet.Suite` for the same reason as
/// `PacketKeys`.
pub const Suite = short_packet.Suite;

/// Errors returned by long-header seal/open and Retry helpers.
pub const Error = error{
    OutputTooSmall,
    NotInitialPacket,
    NotZeroRttPacket,
    NotHandshakePacket,
    DcidTooLong,
    ScidTooLong,
    UnsupportedSuite,
    /// The Length field claims more bytes than `src` provides.
    DeclaredLengthExceedsInput,
    /// The packet's payload is too short for the HP sample.
    PayloadTooShort,
} || protection.Error || header.Error || packet_number_mod.Error || varint.Error;

/// QUIC v1 Retry integrity key/nonce, RFC 9001 §5.8.
pub const retry_integrity_key_v1: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// QUIC v1 Retry integrity nonce (RFC 9001 §5.8). Companion to
/// `retry_integrity_key_v1`.
pub const retry_integrity_nonce_v1: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// QUIC v2 Retry integrity key (RFC 9368 §3.3.3).
pub const retry_integrity_key_v2: [16]u8 = .{
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
    0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
};

/// QUIC v2 Retry integrity nonce (RFC 9368 §3.3.3).
pub const retry_integrity_nonce_v2: [12]u8 = .{
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c,
    0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
};

/// Look up the Retry integrity key for `version`. Falls back to v1
/// for unknown versions.
pub fn retryIntegrityKeyFor(version: u32) *const [16]u8 {
    return switch (version) {
        header.quic_version_2 => &retry_integrity_key_v2,
        else => &retry_integrity_key_v1,
    };
}

/// Look up the Retry integrity nonce for `version`. Falls back to v1
/// for unknown versions.
pub fn retryIntegrityNonceFor(version: u32) *const [12]u8 {
    return switch (version) {
        header.quic_version_2 => &retry_integrity_nonce_v2,
        else => &retry_integrity_nonce_v1,
    };
}

const retry_pseudo_packet_max: usize = 4096;

/// Inputs to `sealRetry`. Server-side construction of a Retry packet
/// per RFC 9000 §17.2.5; the integrity tag is computed automatically.
pub const RetrySealOptions = struct {
    version: u32 = 0x00000001,
    /// Original Destination Connection ID from the client's first Initial.
    original_dcid: []const u8,
    /// Destination CID for the Retry packet: the client's Initial SCID.
    dcid: []const u8,
    /// Server-chosen Retry Source CID.
    scid: []const u8,
    retry_token: []const u8,
    unused_bits: u4 = 0,
};

// -- Initial -------------------------------------------------------------

/// Inputs to `sealInitial`. Builds an unprotected Initial header,
/// AEAD-seals the payload, and applies header protection per
/// RFC 9000 §17.2.2 + RFC 9001 §5.
pub const InitialSealOptions = struct {
    /// QUIC version. Defaults to v1.
    version: u32 = 0x00000001,
    /// Destination Connection ID.
    dcid: []const u8,
    /// Source Connection ID (the CID we want the peer to send back to us).
    scid: []const u8,
    /// Address-validation token. Empty for client first-flight; set
    /// by the client when responding to a Retry.
    token: []const u8 = &.{},
    /// Full 64-bit packet number to encode.
    pn: u64,
    /// Largest PN we've seen ACKed in the Initial PN space; used to
    /// choose PN truncation length.
    largest_acked: ?u64 = null,
    /// Frame bytes to encrypt.
    payload: []const u8,
    /// Initial-level packet keys (derived per RFC 9001 §5.2).
    keys: *const PacketKeys,
    /// Make the protected packet exactly this many bytes by appending
    /// PADDING frames (0x00) inside the AEAD payload. A packet that is
    /// already as long, or longer, is not changed. RFC 9000 §14
    /// requires the client's Initial UDP datagrams to be ≥ 1200 bytes.
    pad_to: usize = 0,
    /// Force a specific PN length (1..4). Must accommodate `pn`.
    pn_length_override: ?u8 = null,
    /// Long-header Reserved Bits (bits 3-2 of the first byte). RFC
    /// 9000 §17.2 says these MUST be 0 on transmit; the field exists
    /// here ONLY so test fixtures can construct malicious-but-authentic
    /// packets that exercise the receiver-side gate (§17.2.1 ¶17).
    /// Defaults to 0 — production callers MUST NOT change it.
    reserved_bits: u2 = 0,
    /// QUIC Bit (RFC 9000 §17.2 / RFC 9287 §3). Defaults to 1 so v1
    /// peers that don't understand grease still parse the packet.
    /// Once both peers advertised `grease_quic_bit`, the connection
    /// layer flips this on per packet.
    quic_bit: u1 = 1,
};

/// Build a fully-protected Initial packet into `dst`. Returns total
/// bytes written. Errors with `OutputTooSmall` if `dst` cannot fit
/// the header + AEAD ciphertext + tag (and any padding).
pub fn sealInitial(dst: []u8, opts: InitialSealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;
    if (opts.keys.suite != .aes128_gcm_sha256) return Error.UnsupportedSuite;

    const pn_len = opts.pn_length_override orelse packet_number_mod.chooseLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    // Plaintext padding to satisfy:
    //  (a) RFC 9001 §5.4.2: post-PN must be at least 4 bytes (so HP
    //      sample lies in ciphertext);
    //  (b) opts.pad_to: total datagram size floor.
    const min_pt_for_sample: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;

    const header_len_with_pn_no_length_field = blk: {
        // Pre-compute header length WITHOUT the Length varint so we
        // can iterate to the correct varint size below.
        var x: usize = 1 + 4; // first byte + version
        x += 1 + opts.dcid.len; // DCID len + bytes
        x += 1 + opts.scid.len; // SCID len + bytes
        x += varint.encodedLen(opts.token.len);
        x += opts.token.len;
        // Length varint goes here.
        x += pn_len; // PN bytes follow Length
        break :blk x;
    };

    // Find the plaintext length that satisfies the sample-floor, and
    // that makes the packet exactly `pad_to` bytes when it is shorter.
    var pt_len: usize = @max(opts.payload.len, min_pt_for_sample);
    var length_varint_size: usize = varint.encodedLen(pt_len + 16 + pn_len);
    // Everything but the Length field and the plaintext: the header
    // up to the token, the packet number, the AEAD tag.
    const fixed_len: usize = header_len_with_pn_no_length_field + 16;
    var total_size: usize = fixed_len + length_varint_size + pt_len;

    if (total_size < opts.pad_to) {
        // `pad_to` is a target, hit exactly: the caller sized a
        // datagram by it (RFC 9000 section 14.1 says "at least 1200",
        // section 14.2 says "no more than 1200 until the path is
        // probed", and a caller's buffer may be exactly that long).
        //
        // The padding can make the Length field longer (a value of 63
        // takes one byte, 64 takes two). Then the field grows FIRST,
        // and the padding is what is left: one byte less. If the
        // value then fits one byte again (it is 63), the field stays
        // at two bytes: a varint need not be the shortest one (RFC
        // 9000 section 16), and so every size can be made.
        //
        // Until v0.26.0 this was "a floor, not a target": a small
        // payload (an ACK frame, a PING) came out at `pad_to` + 1,
        // and the size check below used a number that was too small
        // by the whole padding. MEASURED 2026-10-04: every ACK-only
        // and PING-only Initial datagram of the client was 1201
        // bytes on the wire.
        var padded_pt = opts.pad_to - fixed_len - length_varint_size;
        const needed = varint.encodedLen(padded_pt + 16 + pn_len);
        if (needed > length_varint_size) {
            length_varint_size = needed;
            padded_pt = opts.pad_to - fixed_len - length_varint_size;
        }
        // `padded_pt >= pt_len`: the packet was at least one byte
        // short, and that byte is the longer Length field at worst.
        pt_len = padded_pt;
        total_size = fixed_len + length_varint_size + pt_len;
    }

    const length_field_value: u64 = @as(u64, pt_len) + 16 + pn_len;

    if (dst.len < total_size) return Error.OutputTooSmall;

    // Encode the unprotected header.
    const dcid_id = try header.ConnId.fromSlice(opts.dcid);
    const scid_id = try header.ConnId.fromSlice(opts.scid);
    const pn_length = header.PnLength.fromBytes(pn_len);
    const truncated = packet_number_mod.truncate(opts.pn, pn_len);

    const hdr_len = try header.encode(dst, .{ .initial = .{
        .version = opts.version,
        .dcid = dcid_id,
        .scid = scid_id,
        .token = opts.token,
        .pn_length = pn_length,
        .pn_truncated = truncated,
        .payload_length = length_field_value,
        .payload_length_bytes = @intCast(length_varint_size),
        .reserved_bits = opts.reserved_bits,
        .quic_bit = opts.quic_bit,
    } });
    const pn_offset = hdr_len - pn_len;

    // Stage plaintext (with PADDING zero bytes if needed).
    var stage_buf: [2048]u8 = undefined;
    if (pt_len > stage_buf.len) return Error.OutputTooSmall;
    @memcpy(stage_buf[0..opts.payload.len], opts.payload);
    @memset(stage_buf[opts.payload.len..pt_len], 0);

    // AEAD seal.
    const ct_len = try short_packet.sealPayloadWithKeys(
        opts.keys,
        null,
        opts.pn,
        dst[0..hdr_len],
        stage_buf[0..pt_len],
        dst[hdr_len..],
    );
    const total_len = hdr_len + ct_len;

    // Header-protect.
    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = try short_packet.headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .long, pn_offset, pn_len, mask);

    return total_len;
}

/// Result of opening a long-header packet. `payload` is a slice into
/// the caller's plaintext buffer; the CIDs and token are cheap copies.
pub const LongOpenResult = struct {
    pn: u64,
    payload: []u8,
    /// Bytes consumed from the input slice. The caller can use
    /// `src[bytes_consumed..]` to access any coalesced packet that
    /// follows.
    bytes_consumed: usize,
    /// Source Connection ID echoed back from the peer (useful for
    /// the client's first parse — that's where the server tells us
    /// its CID).
    scid: header.ConnId,
    /// Destination Connection ID. The receiver uses this to verify
    /// that the packet is actually addressed to us.
    dcid: header.ConnId,
    /// Address-validation token, for Initial only. Empty for
    /// Handshake.
    token: []const u8,
    /// Long-header Reserved Bits (bits 3-2 of the first byte after
    /// header protection has been removed). Authentic only because
    /// AEAD-open succeeded. RFC 9000 §17.2 says these bits MUST be 0
    /// on transmit, and §17.2.1 ¶17 says receivers MUST treat a
    /// non-zero value as a PROTOCOL_VIOLATION. The wire layer surfaces
    /// the value here; the connection-level handler is responsible for
    /// closing with the right error code.
    reserved_bits: u2,
};

/// Inputs to `openInitial` / `openZeroRtt` / `openHandshake`. Same
/// shape across the three variants: the peer's keys plus the largest
/// PN we've already opened in this PN space.
pub const InitialOpenOptions = struct {
    keys: *const PacketKeys,
    largest_received: u64 = 0,
};

/// The length on the wire of the long-header packet at the start of
/// `src`, read from the fields in front of the packet number. Header
/// protection does not cover them (RFC 9001 §5.4.1), so no key is
/// needed. Null if the header does not parse, if the type has no
/// Length field (Retry, Version Negotiation), or if the Length says
/// more than `src` holds.
///
/// For a receiver that does not open a packet (the keys are gone, or
/// the tag does not verify): RFC 9000 §12.2 says it MUST still try the
/// packets behind it in the datagram. Nothing here is authenticated.
/// A wrong Length only moves the place where the next packet is looked
/// for, and that packet has its own tag.
pub fn peekPacketLen(src: []const u8) ?usize {
    if (src.len < 5 or src[0] & 0x80 == 0) return null;
    const version = std.mem.readInt(u32, src[1..5], .big);
    if (version == 0) return null;
    const long_type = header.longTypeFromBits(version, @intCast((src[0] >> 4) & 0x03));
    if (long_type == .retry) return null;
    const common = header.peekLongCommon(src) catch return null;
    var pos: usize = common.end_pos;
    if (long_type == .initial) {
        const token_len = varint.decode(src[pos..]) catch return null;
        pos += token_len.bytes_read;
        if (token_len.value > src.len - pos) return null;
        pos += @intCast(token_len.value);
    }
    const length = varint.decode(src[pos..]) catch return null;
    pos += length.bytes_read;
    if (length.value > src.len - pos) return null;
    return pos + @as(usize, @intCast(length.value));
}

/// Open a protected Initial packet from `src`, writing plaintext into
/// `pt_dst`. Returns the recovered PN, plaintext slice, CIDs, token,
/// and `bytes_consumed` for advancing through coalesced datagrams.
pub fn openInitial(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .initial);
}

// -- 0-RTT / Handshake ----------------------------------------------------
//
// RFC 9000 §17.2.3 (0-RTT) and §17.2.4 (Handshake) specify
// byte-identical long-header layouts; the only wire difference is the
// 2-bit Long Packet Type, and even the QUIC v2 rotation of those bits
// (RFC 9368 §3.2) is absorbed inside `header.longTypeToBits`. Both
// seal variants therefore share one options struct and one body
// (`sealLongPn`), mirroring `openLongHeader` on the open side.

/// Which PN-carrying long-header type `sealLongPn` emits. Initial is
/// deliberately excluded: it carries a token varint, the RFC 9000 §14
/// pad_to reflow, and the AES-128-GCM suite pin, so `sealInitial`
/// keeps its own body.
const LongPnKind = enum { zero_rtt, handshake };

/// Inputs to `sealZeroRtt` / `sealHandshake`. The two packet types
/// take identical inputs (see the section comment), so they share
/// this struct via the `ZeroRttSealOptions` / `HandshakeSealOptions`
/// aliases.
pub const LongPnSealOptions = struct {
    version: u32 = 0x00000001,
    dcid: []const u8,
    scid: []const u8,
    pn: u64,
    largest_acked: ?u64 = null,
    payload: []const u8,
    keys: *const PacketKeys,
    pn_length_override: ?u8 = null,
    /// QUIC Bit. See `InitialSealOptions.quic_bit`.
    quic_bit: u1 = 1,
};

/// Inputs to `sealZeroRtt` (RFC 9000 §17.2.3).
pub const ZeroRttSealOptions = LongPnSealOptions;

/// Inputs to `sealHandshake` (RFC 9000 §17.2.4).
pub const HandshakeSealOptions = LongPnSealOptions;

/// Build a fully-protected 0-RTT packet into `dst`. Returns total
/// bytes written.
pub fn sealZeroRtt(dst: []u8, opts: ZeroRttSealOptions) Error!usize {
    return sealLongPn(dst, opts, .zero_rtt);
}

/// Open a protected 0-RTT packet from `src`. See `openInitial` for
/// the shared semantics.
pub fn openZeroRtt(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .zero_rtt);
}

/// Build a fully-protected Handshake packet into `dst`. Returns total
/// bytes written.
pub fn sealHandshake(dst: []u8, opts: HandshakeSealOptions) Error!usize {
    return sealLongPn(dst, opts, .handshake);
}

/// Open a protected Handshake packet from `src`. See `openInitial`
/// for the shared semantics.
pub fn openHandshake(pt_dst: []u8, src: []u8, opts: InitialOpenOptions) Error!LongOpenResult {
    return openLongHeader(pt_dst, src, opts.keys, opts.largest_received, .handshake);
}

/// Shared seal body for the PN-carrying non-Initial long-header
/// types: build the unprotected header, satisfy the RFC 9001 §5.4.2
/// sample floor, AEAD-seal the payload, and apply header protection.
fn sealLongPn(dst: []u8, opts: LongPnSealOptions, comptime kind: LongPnKind) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;

    const pn_len = opts.pn_length_override orelse packet_number_mod.chooseLength(opts.pn, opts.largest_acked);
    if (pn_len < 1 or pn_len > 4) return protection.Error.InvalidPnLength;

    const min_pt_for_sample: usize = if (pn_len < 4) @as(usize, 4 - pn_len) else 0;
    const pt_len: usize = @max(opts.payload.len, min_pt_for_sample);
    const length_field_value: u64 = @as(u64, pt_len) + 16 + pn_len;
    const length_varint_size = varint.encodedLen(length_field_value);

    const total_size: usize = 1 + 4 + 1 + opts.dcid.len + 1 + opts.scid.len +
        length_varint_size + pn_len + pt_len + 16;

    if (dst.len < total_size) return Error.OutputTooSmall;

    const dcid_id = try header.ConnId.fromSlice(opts.dcid);
    const scid_id = try header.ConnId.fromSlice(opts.scid);
    const pn_length = header.PnLength.fromBytes(pn_len);
    const truncated = packet_number_mod.truncate(opts.pn, pn_len);

    // `header.ZeroRtt` and `header.Handshake` are distinct structs
    // with identical fields; `@unionInit` gives the one literal the
    // kind-selected field type (`LongPnKind` tags mirror the
    // `header.Header` tags).
    const hdr_len = try header.encode(dst, @unionInit(header.Header, @tagName(kind), .{
        .version = opts.version,
        .dcid = dcid_id,
        .scid = scid_id,
        .pn_length = pn_length,
        .pn_truncated = truncated,
        .payload_length = length_field_value,
        .reserved_bits = 0,
        .quic_bit = opts.quic_bit,
    }));
    const pn_offset = hdr_len - pn_len;

    var stage_buf: [2048]u8 = undefined;
    if (pt_len > stage_buf.len) return Error.OutputTooSmall;
    @memcpy(stage_buf[0..opts.payload.len], opts.payload);
    @memset(stage_buf[opts.payload.len..pt_len], 0);

    const ct_len = try short_packet.sealPayloadWithKeys(
        opts.keys,
        null,
        opts.pn,
        dst[0..hdr_len],
        stage_buf[0..pt_len],
        dst[hdr_len..],
    );
    const total_len = hdr_len + ct_len;

    const sample = try protection.sampleAt(dst[0..total_len], pn_offset);
    const mask = try short_packet.headerProtectionMask(opts.keys, &sample);
    try protection.applyHpMask(dst[0..total_len], .long, pn_offset, pn_len, mask);

    return total_len;
}

// -- Retry ---------------------------------------------------------------

/// Compute the 16-byte Retry integrity tag (RFC 9001 §5.8 / RFC 9368
/// §3.3.3) over the pseudo-packet formed from the Original DCID
/// length, the ODCID bytes, and the Retry packet bytes preceding the
/// tag. The AEAD key/nonce is version-specific: v1 uses the §5.8
/// constants, v2 uses §3.3.3.
pub fn retryIntegrityTag(version: u32, original_dcid: []const u8, retry_without_tag: []const u8) Error![16]u8 {
    if (original_dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (1 + original_dcid.len + retry_without_tag.len > retry_pseudo_packet_max) {
        return Error.OutputTooSmall;
    }

    var pseudo: [retry_pseudo_packet_max]u8 = undefined;
    var pos: usize = 0;
    pseudo[pos] = @intCast(original_dcid.len);
    pos += 1;
    @memcpy(pseudo[pos .. pos + original_dcid.len], original_dcid);
    pos += original_dcid.len;
    @memcpy(pseudo[pos .. pos + retry_without_tag.len], retry_without_tag);
    pos += retry_without_tag.len;

    var aead = try AesGcm128.init(retryIntegrityKeyFor(version));
    defer aead.deinit();
    var out: [16]u8 = undefined;
    const n = try aead.seal(&out, retryIntegrityNonceFor(version), pseudo[0..pos], "");
    // Empty-plaintext AEAD should write exactly the 16-byte tag;
    // report a typed error instead of asserting if it does not.
    if (n != out.len) return Error.OutputTooSmall;
    return out;
}

/// Build a Retry packet into `dst`, computing and appending the
/// 16-byte integrity tag. Returns total bytes written.
pub fn sealRetry(dst: []u8, opts: RetrySealOptions) Error!usize {
    if (opts.dcid.len > header.max_cid_len) return Error.DcidTooLong;
    if (opts.scid.len > header.max_cid_len) return Error.ScidTooLong;

    const dcid = try header.ConnId.fromSlice(opts.dcid);
    const scid = try header.ConnId.fromSlice(opts.scid);
    const zero_tag: [16]u8 = @splat(0);
    const len = try header.encode(dst, .{ .retry = .{
        .version = opts.version,
        .dcid = dcid,
        .scid = scid,
        .retry_token = opts.retry_token,
        .integrity_tag = zero_tag,
        .unused_bits = opts.unused_bits,
    } });
    const tag = try retryIntegrityTag(opts.version, opts.original_dcid, dst[0 .. len - 16]);
    @memcpy(dst[len - 16 .. len], &tag);
    return len;
}

/// Verify the Retry integrity tag on `retry_packet` against the
/// client's original DCID. The version is read from the packet's
/// version field (bytes 1..5) so the right §5.8 / §3.3.3 constants
/// are used. Returns true on a match, false otherwise.
pub fn validateRetryIntegrity(original_dcid: []const u8, retry_packet: []const u8) Error!bool {
    if (retry_packet.len < 16) return Error.PayloadTooShort;
    if (retry_packet.len < 5) return Error.InsufficientBytes;
    const version = std.mem.readInt(u32, retry_packet[1..5], .big);
    const expected = try retryIntegrityTag(version, original_dcid, retry_packet[0 .. retry_packet.len - 16]);
    // Constant-time compare: per RFC 9001 §5.8 the tag is AEAD-derived
    // so a partial-match timing oracle on the wire would let a peer
    // bias forgery attempts byte-by-byte.
    const observed: *const [16]u8 = retry_packet[retry_packet.len - 16 ..][0..16];
    return std.crypto.timing_safe.eql([16]u8, expected, observed.*);
}

// -- shared open path ----------------------------------------------------

fn openLongHeader(
    pt_dst: []u8,
    src: []u8,
    keys: *const PacketKeys,
    largest_received: u64,
    expected_type: header.LongType,
) Error!LongOpenResult {
    if (src.len < 5) return Error.InsufficientBytes;
    if (src[0] & 0x80 == 0) {
        return unexpectedPacketType(expected_type);
    }
    // Read the version field (bytes 1..5) so we can decode long-type
    // bits under the right RFC 9000 §17.2 / RFC 9368 §3.2 layout.
    const version = std.mem.readInt(u32, src[1..5], .big);
    // Long-type bits (5-4 of the first byte) are NOT covered by HP
    // (which masks only bits 3-0 for long headers, RFC 9001 §5.4.1),
    // so we can check the type before any decryption.
    const long_type_bits_pre: u2 = @intCast((src[0] >> 4) & 0x03);
    const pre_type: header.LongType = header.longTypeFromBits(version, long_type_bits_pre);
    if (pre_type != expected_type) {
        return unexpectedPacketType(expected_type);
    }
    if (expected_type == .initial and keys.suite != .aes128_gcm_sha256) {
        return Error.UnsupportedSuite;
    }

    // Walk the unprotected version-invariant prefix via the shared
    // `header.peekLongCommon`; the PN bytes are still HP-masked, so
    // we deliberately avoid `header.parse` and re-derive pn_length /
    // pn_truncated ourselves after HP is removed.
    const common = try header.peekLongCommon(src);
    const dcid = try header.ConnId.fromSlice(common.dcid);
    const scid = try header.ConnId.fromSlice(common.scid);
    var pos: usize = common.end_pos;

    var token: []const u8 = &.{};
    if (expected_type == .initial) {
        const tok_len = try varint.decode(src[pos..]);
        pos += tok_len.bytes_read;
        if (tok_len.value > src.len - pos) return Error.InsufficientBytes;
        const tlen: usize = @intCast(tok_len.value);
        token = src[pos .. pos + tlen];
        pos += tlen;
    }

    const len_varint = try varint.decode(src[pos..]);
    pos += len_varint.bytes_read;
    const length_value = len_varint.value;
    const pn_offset = pos;

    if (length_value > src.len - pn_offset) return Error.DeclaredLengthExceedsInput;
    if (length_value < 4 + 16) return Error.PayloadTooShort;

    // Sample for HP.
    if (src.len < pn_offset + 4 + protection.sample_len) return Error.InsufficientCiphertext;
    const sample = try protection.sampleAt(src, pn_offset);
    const mask = try short_packet.headerProtectionMask(keys, &sample);

    // Strip HP from byte 0 (low 4 bits) and PN bytes.
    src[0] ^= mask[0] & 0x0f;
    const pn_len: u8 = @intCast((src[0] & 0x03) + 1);
    var i: u8 = 0;
    while (i < pn_len) : (i += 1) {
        src[pn_offset + i] ^= mask[1 + i];
    }

    // Now sanity-check actual_type. Bits 5-4 of the cleaned first byte.
    const long_type_bits: u2 = @intCast((src[0] >> 4) & 0x03);
    const actual_type: header.LongType = header.longTypeFromBits(version, long_type_bits);
    if (actual_type != expected_type) {
        return unexpectedPacketType(expected_type);
    }

    // Reconstruct PN.
    const truncated = try packet_number_mod.readTruncated(src[pn_offset..], pn_len);
    const full_pn = try packet_number_mod.decode(truncated, pn_len, largest_received);

    // AEAD-open. AAD = src[0..pn_offset+pn_len]; ciphertext is the
    // remaining `length_value - pn_len` bytes.
    const aad_len = pn_offset + pn_len;
    const length_value_usize: usize = @intCast(length_value);
    const ct_len: usize = length_value_usize - pn_len;
    const pt_len = try short_packet.openPayloadWithKeys(
        keys,
        null,
        full_pn,
        src[0..aad_len],
        src[aad_len .. aad_len + ct_len],
        pt_dst,
    );

    // Bits 3-2 of the post-HP first byte are the Reserved Bits per
    // RFC 9000 §17.2. AEAD has just authenticated `src[0..pn_offset]`,
    // so this read is now safe — a network attacker can't smuggle
    // non-zero bits past us.
    const reserved_bits: u2 = @intCast((src[0] >> 2) & 0x03);

    return .{
        .pn = full_pn,
        .payload = pt_dst[0..pt_len],
        .bytes_consumed = pn_offset + @as(usize, @intCast(length_value)),
        .scid = scid,
        .dcid = dcid,
        .token = token,
        .reserved_bits = reserved_bits,
    };
}

// -- helpers -------------------------------------------------------------

fn unexpectedPacketType(expected_type: header.LongType) Error {
    return switch (expected_type) {
        .initial => Error.NotInitialPacket,
        .zero_rtt => Error.NotZeroRttPacket,
        .handshake => Error.NotHandshakePacket,
        .retry => Error.NotInitialPacket,
    };
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const initial_mod = @import("initial.zig");

fn fromHex(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn fillSecret(dst: []u8, seed: u8) void {
    for (dst, 0..) |*b, i| {
        b.* = seed +% @as(u8, @truncate(i * 3));
    }
}

test "Initial seal/open round-trip under QUIC v2 keys [RFC9368 §3.3]" {
    // Round-trip a v2 Initial through seal/open. Failure here means
    // the v2 Initial-key derivation, the v2 long-header type bit
    // rotation, or the AEAD nonce / HP mask plumbing diverged.
    const dcid = fromHex("8394c8f03e515708");
    const init_keys = try initial_mod.deriveInitialKeysFor(0x6b3343cf, &dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "v2 Initial CRYPTO frame bytes";

    var packet: [2048]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .version = 0x6b3343cf,
        .dcid = &dcid,
        .scid = &scid,
        .pn = 2,
        .payload = payload,
        .keys = &keys,
    });

    // Sanity: the long-header type bits must be 0b01 under v2 (RFC 9368 §3.2).
    const type_bits: u2 = @intCast((packet[0] >> 4) & 0x03);
    try testing.expectEqual(@as(u2, 0b01), type_bits);

    var pt: [2048]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 1,
    });
    try testing.expectEqual(@as(u64, 2), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
}

test "Initial seal/open round-trip with §A.1 client keys" {
    const dcid = fromHex("8394c8f03e515708");
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "synthetic CRYPTO frame bytes go here";

    var packet: [2048]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 2,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [2048]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 1,
    });
    try testing.expectEqual(@as(u64, 2), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
    try testing.expectEqual(@as(usize, 0), opened.token.len);
    try testing.expectEqual(len, opened.bytes_consumed);
}

test "Initial seal pads to 1200 bytes when pad_to is set" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 9, 9, 9, 9 };
    const tiny_payload = "ch";

    var packet: [2048]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = tiny_payload,
        .keys = &keys,
        .pad_to = 1200,
    });
    try testing.expectEqual(@as(usize, 1200), len);

    var pt: [2048]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
    // The decrypted payload is the user payload + zero-byte PADDING
    // frames padded out to fit. Verify the prefix.
    try testing.expectEqualSlices(u8, tiny_payload, opened.payload[0..tiny_payload.len]);
    // The bytes after our payload are PADDING (RFC 9000 §19.1 = 0x00).
    for (opened.payload[tiny_payload.len..]) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "Initial seal pads to exactly pad_to, for every payload length and every target" {
    // A datagram is sized by this number, so it must be hit: one byte
    // more does not fit a buffer of 1200 bytes, and is more than a
    // sender may put on a path it has not probed (RFC 9000 14.2).
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const scid: [4]u8 = .{ 9, 9, 9, 9 };
    const payload_buf: [1100]u8 = @splat(0x01); // PING frames

    // Every payload length around the place where the Length field
    // goes from one byte to two (a value of 64), up to a full packet,
    // into a buffer of exactly 1200 bytes.
    var payload_len: usize = 1;
    while (payload_len <= payload_buf.len) : (payload_len += if (payload_len < 80) 1 else 53) {
        var packet: [1200]u8 = undefined;
        const len = try sealInitial(&packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 3,
            .payload = payload_buf[0..payload_len],
            .keys = &keys,
            .pad_to = 1200,
        });
        try testing.expectEqual(@as(usize, 1200), len);
        var pt: [2048]u8 = undefined;
        const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
        try testing.expectEqual(len, opened.bytes_consumed);
        try testing.expectEqualSlices(u8, payload_buf[0..payload_len], opened.payload[0..payload_len]);
        for (opened.payload[payload_len..]) |b| try testing.expectEqual(@as(u8, 0), b);
    }

    // Every target from one byte more than the packet needs: the
    // sender that fills a datagram behind other packets asks for
    // sizes like these (a Length value of 63 or 64 is among them).
    const small = payload_buf[0..10];
    var unpadded: [256]u8 = undefined;
    const base = try sealInitial(&unpadded, .{ .dcid = &dcid, .scid = &scid, .pn = 3, .payload = small, .keys = &keys });
    var target: usize = base + 1;
    while (target <= 160) : (target += 1) {
        var packet: [256]u8 = undefined;
        const len = try sealInitial(packet[0..target], .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 3,
            .payload = small,
            .keys = &keys,
            .pad_to = target,
        });
        try testing.expectEqual(target, len);
        var pt: [256]u8 = undefined;
        const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
        try testing.expectEqual(len, opened.bytes_consumed);
        try testing.expectEqualSlices(u8, small, opened.payload[0..small.len]);
    }

    // A packet that is already longer than the target is not changed.
    var longer: [256]u8 = undefined;
    const same = try sealInitial(&longer, .{ .dcid = &dcid, .scid = &scid, .pn = 3, .payload = small, .keys = &keys, .pad_to = base - 1 });
    try testing.expectEqual(base, same);
}

test "Initial seal token round-trips through open" {
    const dcid: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    const scid: [4]u8 = .{ 1, 2, 3, 4 };
    const payload = "frames";
    const token = [_]u8{ 0xa1, 0xb2, 0xc3 };

    var packet: [256]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .token = &token,
        .pn = 0,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openInitial(&pt, packet[0..len], .{ .keys = &keys });
    try testing.expectEqualSlices(u8, &token, opened.token);
}

test "Handshake seal/open round-trip" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    // Use synthetic 32-byte secret — Handshake keys don't have a
    // baked-in derivation; the connection layer derives them from
    // TLS handshake_traffic_secret.
    const secret = fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    const scid: [4]u8 = .{ 9, 9, 9, 9 };
    const payload = "CRYPTO + ACK frames";

    var packet: [256]u8 = undefined;
    const len = try sealHandshake(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 5,
        .largest_acked = 4,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openHandshake(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 4,
    });
    try testing.expectEqual(@as(u64, 5), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
}

test "0-RTT seal/open round-trip" {
    const dcid: [8]u8 = .{ 4, 3, 2, 1, 8, 7, 6, 5 };
    const secret = fromHex("d00df151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    const scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const payload = "early STREAM frames";

    var packet: [256]u8 = undefined;
    const len = try sealZeroRtt(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 9,
        .largest_acked = 8,
        .payload = payload,
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    const opened = try openZeroRtt(&pt, packet[0..len], .{
        .keys = &keys,
        .largest_received = 8,
    });
    try testing.expectEqual(@as(u64, 9), opened.pn);
    try testing.expectEqualSlices(u8, payload, opened.payload[0..payload.len]);
    try testing.expectEqualSlices(u8, &dcid, opened.dcid.slice());
    try testing.expectEqualSlices(u8, &scid, opened.scid.slice());
    try testing.expectEqual(len, opened.bytes_consumed);
}

test "Retry seal validates integrity tag" {
    const original_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_scid: [8]u8 = .{ 1, 3, 3, 7, 5, 8, 13, 21 };
    const token = "retry-token";

    var packet: [256]u8 = undefined;
    const len = try sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = token,
    });

    try testing.expect(try validateRetryIntegrity(&original_dcid, packet[0..len]));
    const parsed = try header.parse(packet[0..len], 0);
    try testing.expect(parsed.header == .retry);
    try testing.expectEqualSlices(u8, token, parsed.header.retry.retry_token);

    // Flip a bit in the last tag byte → mismatch detected.
    packet[len - 1] ^= 0x01;
    try testing.expect(!try validateRetryIntegrity(&original_dcid, packet[0..len]));
    packet[len - 1] ^= 0x01; // restore

    // Flip a bit in the first tag byte → still mismatched. Catches
    // any short-circuit compare that would only inspect the prefix.
    packet[len - 16] ^= 0x80;
    try testing.expect(!try validateRetryIntegrity(&original_dcid, packet[0..len]));
    packet[len - 16] ^= 0x80;

    // Restored packet validates again — confirms the in-place flips
    // were the only thing failing the prior asserts.
    try testing.expect(try validateRetryIntegrity(&original_dcid, packet[0..len]));
}

test "Handshake and 0-RTT support every negotiated QUIC v1 suite" {
    const suites = [_]Suite{
        .aes128_gcm_sha256,
        .aes256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };
    const dcid: [8]u8 = .{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid: [4]u8 = .{ 0xa0, 0xb0, 0xc0, 0xd0 };

    for (suites, 0..) |suite, suite_idx| {
        var secret: short_packet.TrafficSecret = @splat(0);
        fillSecret(secret[0..suite.secretLen()], @as(u8, @truncate(0x40 + suite_idx * 0x13)));
        const keys = try short_packet.derivePacketKeys(suite, secret[0..suite.secretLen()]);

        var handshake_packet: [256]u8 = undefined;
        const hs_payload = "suite-flexible HANDSHAKE CRYPTO frames";
        const hs_len = try sealHandshake(&handshake_packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 11,
            .largest_acked = 10,
            .payload = hs_payload,
            .keys = &keys,
        });

        var pt: [256]u8 = undefined;
        const hs_opened = try openHandshake(&pt, handshake_packet[0..hs_len], .{
            .keys = &keys,
            .largest_received = 10,
        });
        try testing.expectEqual(@as(u64, 11), hs_opened.pn);
        try testing.expectEqualSlices(u8, hs_payload, hs_opened.payload[0..hs_payload.len]);

        var zero_rtt_packet: [256]u8 = undefined;
        const zr_payload = "suite-flexible 0-RTT STREAM frames";
        const zr_len = try sealZeroRtt(&zero_rtt_packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 12,
            .largest_acked = 11,
            .payload = zr_payload,
            .keys = &keys,
        });

        const zr_opened = try openZeroRtt(&pt, zero_rtt_packet[0..zr_len], .{
            .keys = &keys,
            .largest_received = 11,
        });
        try testing.expectEqual(@as(u64, 12), zr_opened.pn);
        try testing.expectEqualSlices(u8, zr_payload, zr_opened.payload[0..zr_payload.len]);
    }
}

test "Initial rejects non-initial cipher suites" {
    var secret: short_packet.TrafficSecret = @splat(0);
    fillSecret(secret[0..Suite.aes256_gcm_sha384.secretLen()], 0x74);
    const keys = try short_packet.derivePacketKeys(
        .aes256_gcm_sha384,
        secret[0..Suite.aes256_gcm_sha384.secretLen()],
    );

    const dcid: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const scid: [4]u8 = .{ 8, 9, 10, 11 };
    var packet: [256]u8 = undefined;
    try testing.expectError(
        Error.UnsupportedSuite,
        sealInitial(&packet, .{
            .dcid = &dcid,
            .scid = &scid,
            .pn = 0,
            .payload = "x",
            .keys = &keys,
        }),
    );
}

test "openInitial rejects bytes whose first bit indicates short header" {
    const secret = fromHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &secret);

    var bytes = [_]u8{0x40} ++ @as([31]u8, @splat(0)); // first byte 0x40 → short header
    var pt: [64]u8 = undefined;
    try testing.expectError(
        Error.NotInitialPacket,
        openInitial(&pt, &bytes, .{ .keys = &keys }),
    );
}

test "openHandshake rejects an Initial packet" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, false);
    const keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const scid: [4]u8 = .{ 0, 0, 0, 0 };

    var packet: [256]u8 = undefined;
    const len = try sealInitial(&packet, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "x",
        .keys = &keys,
    });

    var pt: [256]u8 = undefined;
    try testing.expectError(
        Error.NotHandshakePacket,
        openHandshake(&pt, packet[0..len], .{ .keys = &keys }),
    );
}

test "Initial coalesced with Handshake: bytes_consumed lets us advance" {
    // Build a 2-packet coalesced datagram: Initial then Handshake.
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, true); // server side
    const i_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const hs_secret = fromHex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    );
    const hs_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &hs_secret);

    const scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    var dgram: [2048]u8 = undefined;
    const i_len = try sealInitial(&dgram, .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "I0",
        .keys = &i_keys,
    });
    const h_len = try sealHandshake(dgram[i_len..], .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "H0",
        .keys = &hs_keys,
    });
    const total = i_len + h_len;

    var pt: [2048]u8 = undefined;
    const o1 = try openInitial(&pt, dgram[0..total], .{ .keys = &i_keys });
    try testing.expectEqualSlices(u8, "I0", o1.payload[0..2]);
    try testing.expectEqual(i_len, o1.bytes_consumed);

    const o2 = try openHandshake(&pt, dgram[o1.bytes_consumed..total], .{ .keys = &hs_keys });
    try testing.expectEqualSlices(u8, "H0", o2.payload[0..2]);
    try testing.expectEqual(h_len, o2.bytes_consumed);
}

test "peekPacketLen: the length of a sealed packet, with no key" {
    const dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    const init_keys = try initial_mod.deriveInitialKeys(&dcid, true);
    const i_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    const hs_secret = fromHex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
    );
    const hs_keys = try short_packet.derivePacketKeys(.aes128_gcm_sha256, &hs_secret);

    // Three packets in one datagram: an Initial with a token, a 0-RTT
    // and a Handshake packet.
    var dgram: [2048]u8 = undefined;
    const i_len = try sealInitial(&dgram, .{
        .dcid = &dcid,
        .scid = &scid,
        .token = "a token",
        .pn = 0,
        .payload = "I0",
        .keys = &i_keys,
    });
    const z_len = try sealZeroRtt(dgram[i_len..], .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "Z0",
        .keys = &hs_keys,
    });
    const h_len = try sealHandshake(dgram[i_len + z_len ..], .{
        .dcid = &dcid,
        .scid = &scid,
        .pn = 0,
        .payload = "H0",
        .keys = &hs_keys,
    });
    const total = i_len + z_len + h_len;

    try testing.expectEqual(@as(?usize, i_len), peekPacketLen(dgram[0..total]));
    try testing.expectEqual(@as(?usize, z_len), peekPacketLen(dgram[i_len..total]));
    try testing.expectEqual(@as(?usize, h_len), peekPacketLen(dgram[i_len + z_len .. total]));
    // The last packet alone is the whole of its input.
    try testing.expectEqual(@as(?usize, h_len), peekPacketLen(dgram[i_len + z_len ..][0..h_len]));

    // A packet cut short has no length: every prefix of each one.
    for (0..i_len) |n| try testing.expectEqual(@as(?usize, null), peekPacketLen(dgram[0..n]));
    for (0..h_len) |n| try testing.expectEqual(@as(?usize, null), peekPacketLen(dgram[i_len + z_len ..][0..n]));

    // A Length that says more than there is. The Length of the
    // Handshake packet is at 1 + 4 + 1 + 8 + 1 + 4 = 19, in one byte
    // (the packet is small).
    var damaged: [2048]u8 = undefined;
    @memcpy(damaged[0..h_len], dgram[i_len + z_len ..][0..h_len]);
    try testing.expectEqual(@as(usize, h_len - 20), damaged[19]);
    damaged[19] = 0x3f;
    try testing.expect(h_len - 20 < 0x3f);
    try testing.expectEqual(@as(?usize, null), peekPacketLen(damaged[0..h_len]));
}

test "peekPacketLen: null for a packet with no Length field" {
    // A short header.
    var short: [41]u8 = @splat(0);
    short[0] = 0x40;
    try testing.expectEqual(@as(?usize, null), peekPacketLen(&short));
    // Version Negotiation: the version field is zero.
    var vneg: [45]u8 = @splat(0);
    vneg[0] = 0xc0;
    try testing.expectEqual(@as(?usize, null), peekPacketLen(&vneg));
    // Retry.
    const original_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packet: [256]u8 = undefined;
    const len = try sealRetry(&packet, .{
        .original_dcid = &original_dcid,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 1, 3, 3, 7, 5, 8, 13, 21 },
        .retry_token = "retry-token",
    });
    try testing.expectEqual(@as(?usize, null), peekPacketLen(packet[0..len]));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive the structural coalesced-datagram walker with arbitrary
// bytes. The receive path in `Connection.handle` walks coalesced
// QUIC packets by parsing a header, decrypting, then advancing by
// `bytes_consumed`. The structural walker here mirrors the
// pre-decryption shape: parse a header, compute the on-wire packet
// length from `pn_offset + payload_length`, advance, repeat. This
// catches walker-only failure modes (misframed length fields, header
// parses that report inconsistent offsets, infinite loops on
// degenerate inputs) without requiring decryption keys.
//
// Property: the walker terminates within a bounded iteration cap;
// every step advances by at least 1 byte; cumulative offset stays
// inside the input.

test "fuzz: coalesced long-header walker terminates with bounded advance" {
    try std.testing.fuzz({}, fuzzCoalescedWalker, .{});
}

fn fuzzCoalescedWalker(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [4096]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    const dcid_len_for_short = smith.valueRangeAtMost(u8, 0, 20);

    // Cap iterations: a 4 KiB datagram cannot legitimately hold more
    // than ~250 minimal packets (each long-header packet is at least
    // ~16 bytes). Anything past this cap is either degenerate input
    // or a walker bug.
    const max_iters: u32 = 256;
    var iters: u32 = 0;
    var pos: usize = 0;

    while (pos < input.len and iters < max_iters) : (iters += 1) {
        const slice = input[pos..];
        // `peekPacketLen` is the walker the receive path uses for a
        // packet it does not open. It never reads past its input, and
        // it never stands still.
        const peeked = peekPacketLen(slice);
        if (peeked) |n| {
            try std.testing.expect(n > 0);
            try std.testing.expect(n <= slice.len);
        }
        const parsed = header.parse(slice, dcid_len_for_short) catch return;

        // Compute the on-wire packet length. Long-header
        // Initial/0-RTT/Handshake carry an explicit `payload_length`
        // varint that frames the PN+payload+tag region. Retry / VN
        // and short-header packets cannot be coalesce-followed
        // (RFC 9000 §17), so the walker terminates after them.
        const advance: usize = switch (parsed.header) {
            .initial => |h| blk: {
                const payload_len = std.math.cast(usize, h.payload_length) orelse return;
                break :blk std.math.add(usize, parsed.pn_offset, payload_len) catch return;
            },
            .zero_rtt => |h| blk: {
                const payload_len = std.math.cast(usize, h.payload_length) orelse return;
                break :blk std.math.add(usize, parsed.pn_offset, payload_len) catch return;
            },
            .handshake => |h| blk: {
                const payload_len = std.math.cast(usize, h.payload_length) orelse return;
                break :blk std.math.add(usize, parsed.pn_offset, payload_len) catch return;
            },
            .retry, .version_negotiation, .one_rtt => break,
        };

        // Walker invariants:
        // - advance must lie within remaining input (no over-read).
        // - advance must be > 0 (no infinite loop on degenerate
        //   payload_length=0 inputs).
        if (advance == 0 or advance > slice.len) return;
        // Where the full header parse finds a packet that fits, the
        // peek finds the same end.
        try std.testing.expectEqual(@as(?usize, advance), peeked);
        pos += advance;
    }

    // Cumulative offset stays inside the input slice.
    try std.testing.expect(pos <= input.len);
    // The walker terminates within the cap.
    try std.testing.expect(iters < max_iters);
}
