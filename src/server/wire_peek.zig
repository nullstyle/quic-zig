//! Pure pre-decrypt wire peeking and CID-key derivation for the
//! server family: long-header field extraction, Initial detection
//! across v1/v2 type-bit rotations, DCID peeking for routing, and
//! the packed `cid_table` key format.
//!
//! This is a LEAF on purpose: it never imports `server.zig`, so the
//! sibling method files (routing, accept, dos, vneg) and the hub
//! itself can all share these helpers without round-tripping the
//! hub's namespace. Everything here is byte-in/value-out — no
//! `*Server`, no allocation, no state. If a helper needs the hub,
//! it does not belong in this file.
//!
//! The whole file is internal scaffolding for `src/server*`; nothing
//! is re-exported to embedders.

const std = @import("std");
const wire = @import("../wire/root.zig");
const conn_mod = @import("../conn/root.zig");
const ConnectionId = conn_mod.path.ConnectionId;

/// Length-prefixed packed CID key used as the `cid_table` HashMap
/// key. Byte 0 is the CID length (1..20); bytes 1..1+len are the
/// CID material; bytes past `len` are zeroed so the key compares
/// by value.
pub const CidKey = [21]u8;

pub fn cidKeyFromSlice(cid: []const u8) CidKey {
    // Defensive: callers (peekDcidForServer, ConnectionId.slice, etc.)
    // already bound CID length to ≤ 20 via header parse and config
    // validation, but we clamp here so a future caller that forgets
    // can't reach a buffer overflow on a peer-controlled length.
    const n = @min(cid.len, 20);
    var k: CidKey = @splat(0);
    k[0] = @intCast(n);
    @memcpy(k[1 .. 1 + n], cid[0..n]);
    return k;
}

pub fn cidKeyFromConnectionId(cid: ConnectionId) CidKey {
    return cidKeyFromSlice(cid.bytes[0..cid.len]);
}

pub const LongHeaderIds = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
};

pub fn peekLongHeaderIds(bytes: []const u8) ?LongHeaderIds {
    if (bytes.len < 6) return null;
    if ((bytes[0] & 0x80) == 0) return null;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    const dcid_len = bytes[5];
    if (dcid_len > 20) return null;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return null;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = bytes[pos];
    if (scid_len > 20) return null;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return null;
    const scid = bytes[pos .. pos + scid_len];

    return .{ .version = version, .dcid = dcid, .scid = scid };
}

/// True if `bytes` looks like a long-header Initial under the
/// supplied wire-format version. RFC 9368 §3.2 puts Initial at
/// 0b01 under v2 vs 0b00 under v1, so the caller has to pre-resolve
/// the version field — typically via `peekLongHeaderIds`.
pub fn isInitialLongHeader(bytes: []const u8, version: u32) bool {
    if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return false;
    if (bytes.len < 5) return false;
    if (version == 0) return false; // version negotiation
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    return wire.header.longTypeFromBits(version, long_type_bits) == .initial;
}

/// Peek the DCID from either header form. Long headers carry an
/// explicit length; short headers use the server's local-CID length.
pub fn peekDcidForServer(bytes: []const u8, local_cid_len: u8) ?[]const u8 {
    if (bytes.len == 0) return null;
    if ((bytes[0] & 0x80) != 0) {
        const ids = peekLongHeaderIds(bytes) orelse return null;
        return ids.dcid;
    }
    if (bytes.len < 1 + @as(usize, local_cid_len)) return null;
    return bytes[1 .. 1 + local_cid_len];
}

pub fn containsConnectionId(haystack: []const ConnectionId, needle: ConnectionId) bool {
    for (haystack) |cid| {
        if (ConnectionId.eql(cid, needle)) return true;
    }
    return false;
}

/// Extract the token slice from an Initial header, or null if the
/// packet didn't parse cleanly as one. The bytes returned are
/// borrowed from `bytes`.
pub fn peekInitialToken(bytes: []const u8) ?[]const u8 {
    const parsed = wire.header.parse(bytes, 0) catch return null;
    return switch (parsed.header) {
        .initial => |initial| initial.token,
        else => null,
    };
}

// -- tests ----------------------------------------------------------------

test "peekLongHeaderIds rejects too-short" {
    try std.testing.expect(peekLongHeaderIds(&.{}) == null);
    try std.testing.expect(peekLongHeaderIds(&.{0xc0}) == null);
}

test "isInitialLongHeader recognizes Initial type bits" {
    // Long header, type=0b00 (Initial under v1), version=1.
    const v1_bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v1_bytes, 0x00000001));

    // Long header, type=0b01 (Initial under v2 per RFC 9368 §3.2),
    // version = 0x6b3343cf. The same bit pattern is 0-RTT under v1
    // and Initial under v2, so the helper has to consult `version`.
    const v2_bytes = [_]u8{ 0xd0, 0x6b, 0x33, 0x43, 0xcf, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v2_bytes, 0x6b3343cf));
    try std.testing.expect(!isInitialLongHeader(&v2_bytes, 0x00000001));

    // Version negotiation (version=0) is *not* an Initial under
    // either version. The caller is expected to pass `version=0`
    // here (matching the bytes' version field); the helper rejects
    // outright.
    const vn = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&vn, 0));

    // Short header.
    const sh = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&sh, 0x00000001));
}

test "cidKey round-trips identical CIDs" {
    const a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const b = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const c = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 9 };
    const d = [_]u8{ 1, 2, 3, 4, 5, 6, 7 }; // different length

    try std.testing.expectEqual(cidKeyFromSlice(&a), cidKeyFromSlice(&b));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&c)));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&d)));
}

// -- fuzz harness --------------------------------------------------------
//
// `Server.feed` is the entry point an open-internet deployment exposes
// to arbitrary bytes; the header-peek helpers (`peekLongHeaderIds`,
// `isInitialLongHeader`, `peekDcidForServer`) gate it. None may panic
// on hostile input. We stop short of a full `Server` end-to-end fuzz
// (it would need a TLS context and an allocator-tracked
// `boringssl.tls.Context`) — the wire-level peek surface is the
// highest-yield target.

test "fuzz: peekLongHeaderIds never panics" {
    try std.testing.fuzz({}, fuzzPeekLongHeader, .{});
}

fn fuzzPeekLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const ids = peekLongHeaderIds(input) orelse return;
    // Returned CID slices must point into `input`.
    try std.testing.expect(ids.dcid.len <= 20);
    try std.testing.expect(ids.scid.len <= 20);
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) + ids.dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(@intFromPtr(ids.scid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.scid.ptr) + ids.scid.len <= @intFromPtr(input.ptr) + input.len);
}

test "fuzz: isInitialLongHeader never panics" {
    try std.testing.fuzz({}, fuzzIsInitialLongHeader, .{});
}

fn fuzzIsInitialLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    // Drive the helper under both versions so the v1 and v2 long-type
    // rotations are both exercised on the same input bytes.
    _ = isInitialLongHeader(input, 0x00000001);
    _ = isInitialLongHeader(input, 0x6b3343cf);
}

test "fuzz: peekDcidForServer never panics across all CID lengths" {
    try std.testing.fuzz({}, fuzzPeekDcid, .{});
}

fn fuzzPeekDcid(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    const local_cid_len = smith.valueRangeAtMost(u8, 0, 20);

    const dcid = peekDcidForServer(input, local_cid_len) orelse return;
    // The returned slice must lie inside `input`.
    try std.testing.expect(@intFromPtr(dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(dcid.ptr) + dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(dcid.len <= 20);
}
