//! GSO super-datagram assembly: pack consecutive same-destination,
//! same-size QUIC datagrams from one connection back-to-back into a
//! caller buffer so a single `sendmsg` with a `UDP_SEGMENT` cmsg
//! ships them all (Linux; see `socket_opts.probeUdpGso` — the probe
//! is load-bearing, never attach the cmsg without it).
//!
//! Pure transport-side logic over the public Connection API
//! (`pollDatagram` + `pmtu`) — no Connection changes, and usable by
//! foreign-loop embedders doing their own `sendmsg`. Platform-neutral
//! and unit-tested everywhere; only the socket that the result is
//! sent on is Linux-specific.

const std = @import("std");
const conn_mod = @import("../conn/root.zig");
const socket_opts = @import("socket_opts.zig");

const Connection = conn_mod.Connection;
const Address = conn_mod.path.Address;

/// Result of one `fillGsoBatch` pass.
pub const GsoBatch = struct {
    /// Segment size: every segment except possibly the last is exactly
    /// this long (the kernel splits `buf[0..total_len]` on this
    /// stride).
    seg_size: usize = 0,
    /// Number of segments in `buf[0..total_len]`.
    count: u32 = 0,
    /// Bytes of `buf` occupied by the batch.
    total_len: usize = 0,
    /// Destination for the whole batch (null = the connection's
    /// current peer / caller fallback).
    to: ?Address = null,
    /// A trailing datagram whose destination differed from the batch
    /// (migration probe, multipath switch): contiguous in
    /// `buf[carry_offset..carry_offset + carry_len]`, to be sent
    /// separately to `carry_to`.
    carry_offset: usize = 0,
    carry_len: usize = 0,
    carry_to: ?Address = null,

    pub fn hasCarry(self: GsoBatch) bool {
        return self.carry_len != 0;
    }
};

/// Drain up to `max_segments` datagrams from `conn` into `buf`,
/// packing equal-size segments for one GSO send. Stops on: empty
/// outbox, a short (final) segment, a destination change (returned as
/// `carry`), `max_segments`, or buffer exhaustion.
///
/// The FIRST datagram polls with the full remaining buffer — not a
/// segment-sized slice — so RFC 8899 DPLPMTUD probes (which need a
/// dst larger than the current PMTU) still emit; a first datagram
/// that isn't exactly PMTU-sized comes back as a count-1 batch and
/// ships as a plain send.
pub fn fillGsoBatch(
    conn: *Connection,
    buf: []u8,
    max_segments: u32,
    now_us: u64,
) conn_mod.Error!GsoBatch {
    var batch: GsoBatch = .{};
    if (max_segments == 0 or buf.len == 0) return batch;

    const pmtu_cap: usize = @min(conn.pmtu(), buf.len);
    if (pmtu_cap == 0) return batch;

    // First segment: full buffer so PMTUD probes can exceed the PMTU.
    const first = (try conn.pollDatagram(buf, now_us)) orelse return batch;
    batch.to = first.to;
    batch.total_len = first.len;
    batch.count = 1;
    batch.seg_size = first.len;
    if (first.len > pmtu_cap) {
        // DPLPMTUD probe — ship it alone.
        return batch;
    }
    // The FIRST datagram's length defines the GSO stride (the kernel
    // splits on this): follow-up polls are sliced to exactly it, so
    // middles are equal by construction and a shorter one is the tail.
    const seg = first.len;

    while (batch.count < max_segments) {
        const off = batch.total_len;
        if (off + seg > buf.len) break;
        const out = (try conn.pollDatagram(buf[off..][0..seg], now_us)) orelse break;
        const same_dest = destEql(batch.to, out.to);
        if (!same_dest) {
            // Different destination: hand it back as the carry; the
            // caller sends it separately. Zero copies — it is already
            // contiguous in `buf`.
            batch.carry_offset = off;
            batch.carry_len = out.len;
            batch.carry_to = out.to;
            break;
        }
        batch.total_len += out.len;
        batch.count += 1;
        if (out.len < seg) break; // short tail terminates the batch
    }
    return batch;
}

fn destEql(a: ?Address, b: ?Address) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return Address.eql(a.?, b.?);
}

// -- tests -------------------------------------------------------------------

const testing = std.testing;
const boringssl = @import("boringssl");

// NOTE: construct Connections inline in each test — `Connection` is
// multiple megabytes by value (embedded sent-packet trackers), and an
// extra helper return hop overflows the test thread's stack.
fn prepareSender(conn: *Connection) !void {
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 21,
        .initial_max_stream_data_bidi_remote = 1 << 21,
        .initial_max_streams_bidi = 16,
    });
    try @import("../conn/_test_util.zig").installTestApplicationWriteSecret(conn);
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
    });
    // Plenty of window and no pacing: the batch fill itself is what's
    // under test.
    conn.ccForApplication().setCwndForTest(1 << 20);
    conn.pacing_enabled = false;
}

test "fillGsoBatch packs equal-size segments and stops on the short tail" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareSender(&conn);

    // Queue ~6 full packets of stream data plus a partial tail.
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try conn.openBidi(0);
    var queued: usize = 0;
    while (queued < 7 * 1200) {
        queued += try s.send.write(data[0..@min(data.len, 7 * 1200 - queued)]);
    }

    var buf: [64 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(&conn, &buf, socket_opts.default_gso_max_segments, 1_000_000);
    try testing.expect(batch.count >= 2);
    try testing.expect(batch.seg_size > 0 and batch.seg_size <= conn.pmtu());
    // All middles are exactly seg_size; only the tail may be short:
    // total is (count-1) full segments plus a final in (0, seg].
    const full: usize = batch.seg_size * (batch.count - 1);
    try testing.expect(batch.total_len > full);
    try testing.expect(batch.total_len <= full + batch.seg_size);
    try testing.expect(!batch.hasCarry());

    // Draining the rest eventually returns an empty batch.
    var guard: u32 = 0;
    while (guard < 32) : (guard += 1) {
        const more = try fillGsoBatch(&conn, &buf, socket_opts.default_gso_max_segments, 1_000_000);
        if (more.count == 0) break;
    }
    try testing.expect(guard < 32);
}

test "fillGsoBatch respects max_segments" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareSender(&conn);

    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const s = try conn.openBidi(0);
    var queued: usize = 0;
    while (queued < 10 * 1200) {
        queued += try s.send.write(data[0..@min(data.len, 10 * 1200 - queued)]);
    }

    var buf: [64 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(&conn, &buf, 3, 1_000_000);
    try testing.expect(batch.count <= 3);
    try testing.expect(batch.count >= 2);
}

test "fillGsoBatch on an idle connection returns an empty batch" {
    const allocator = testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareSender(&conn);

    var buf: [4 * 1500]u8 = undefined;
    const batch = try fillGsoBatch(&conn, &buf, 64, 1_000_000);
    try testing.expectEqual(@as(u32, 0), batch.count);
    try testing.expectEqual(@as(usize, 0), batch.total_len);
}
