// Split from _state_tests.zig — see that file for the area index.
// Connection-level delivery-rate sampling (draft-cheng-02 / ccwg-bbr-06
// §4.1.2): transmit stamping through pollDatagram, app-limited marking
// on empty polls, sampler advancement through handleAckAtLevel, and
// C.lost accounting through PTO expiry. The multipath PATH_ACK twin
// shares every line of estimator logic with the primary handler and is
// covered by the sampler's own unit tests plus the existing multipath
// ACK integration tests.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const Connection = state.Connection;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;

/// Post-placement setup on the Connection at its final stable address
/// (the house pattern from _state_tests_pacing/_loss).
fn prepareClient(conn: *Connection) !void {
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    });
    try installTestApplicationWriteSecret(conn);
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
    });
}

fn queueBulkStream(conn: *Connection, bytes: usize) !void {
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    if (conn.stream(0) == null) _ = try conn.openBidi(0);
    var written: usize = 0;
    while (written < bytes) {
        const want = @min(data.len, bytes - written);
        // The real write path (not the raw `s.send.write` shortcut):
        // these tests ACK the polled packets, and the ACK dispatch
        // releases the resident-bytes budget `streamWrite` reserves —
        // the shortcut would underflow that accounting. Remembered
        // peer transport params in `prepareClient` give the stream a
        // real send window.
        const n = try conn.streamWrite(0, data[0..want]);
        if (n == 0) break;
        written += n;
    }
}

test "polled packets carry delivery-rate stamps; idle restart seeds the clocks" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareClient(&conn);
    conn.ccForApplication().setCwndForTest(120_000);
    try queueBulkStream(&conn, 8 * 1024);

    var pkt: [2048]u8 = undefined;
    const now_us: u64 = 1_000_000;
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) != null);
    const sent = conn.sentForLevel(.application);
    try std.testing.expectEqual(@as(u32, 1), sent.liveCount());
    const p0 = sent.packets[0];
    // Idle restart: the very first in-flight send seeds both clocks
    // to its own transmit time and measures from zero delivery.
    try std.testing.expectEqual(now_us, p0.first_sent_time_us);
    try std.testing.expectEqual(now_us, p0.delivered_time_us);
    try std.testing.expectEqual(@as(u64, 0), p0.delivered);
    try std.testing.expectEqual(@as(u64, 0), p0.lost_at_send);
    try std.testing.expectEqual(p0.bytes, p0.tx_in_flight);
    try std.testing.expect(!p0.is_app_limited);

    // Second packet: same epoch, in-flight includes both.
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us + 500)) != null);
    const p1 = sent.packets[1];
    try std.testing.expectEqual(now_us, p1.first_sent_time_us);
    try std.testing.expectEqual(p0.bytes + p1.bytes, p1.tx_in_flight);
}

test "empty poll with headroom marks app-limited; a cwnd-blocked poll does not" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareClient(&conn);
    conn.ccForApplication().setCwndForTest(120_000);
    try queueBulkStream(&conn, 2_000);

    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    while (try conn.pollDatagram(&pkt, now_us)) |_| now_us += 100;
    // The draining loop's final (empty) poll had cwnd headroom and no
    // data left: the connection is app-limited, marker = delivered
    // (0) + bytes still in flight.
    const est = &conn.primaryPath().path.delivery;
    try std.testing.expect(est.isAppLimited());
    try std.testing.expectEqual(
        conn.sentForLevel(.application).bytes_in_flight,
        est.app_limited_until,
    );

    // Packets sent while marked carry the taint.
    try queueBulkStream(&conn, 1_000);
    const live_before = conn.sentForLevel(.application).liveCount();
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) != null);
    const sent = conn.sentForLevel(.application);
    try std.testing.expect(sent.liveCount() == live_before + 1);
    try std.testing.expect(sent.packets[sent.count - 1].is_app_limited);

    // Contrast: data pending but the WINDOW is the limit — the empty
    // poll must NOT mark (that is congestion-, not app-limited).
    var ctx2 = try boringssl.tls.Context.initClient(.{});
    defer ctx2.deinit();
    var conn2 = try Connection.initClient(allocator, ctx2, "x");
    defer conn2.deinit();
    try prepareClient(&conn2);
    conn2.ccForApplication().setCwndForTest(2_400);
    try queueBulkStream(&conn2, 256 * 1024);
    var now2: u64 = 1_000_000;
    while (try conn2.pollDatagram(&pkt, now2)) |_| now2 += 100;
    try std.testing.expect(conn2.congestionBlocked(.application));
    try std.testing.expect(!conn2.primaryPath().path.delivery.isAppLimited());
}

test "an ACK advances the sampler and retires a passed app-limited marker" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareClient(&conn);
    conn.ccForApplication().setCwndForTest(120_000);

    // First flight, then the app runs dry -> marker at b0.
    try queueBulkStream(&conn, 900);
    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    while (try conn.pollDatagram(&pkt, now_us)) |_| now_us += 100;
    const est = &conn.primaryPath().path.delivery;
    try std.testing.expect(est.isAppLimited());
    const b0 = conn.sentForLevel(.application).packets[0].bytes;

    // Second flight while marked (tainted).
    try queueBulkStream(&conn, 900);
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) != null);
    const b1 = conn.sentForLevel(.application).packets[1].bytes;

    // ACK both: C.delivered = b0 + b1 > marker (b0) -> the sampler
    // retires the marker while closing the ACK event.
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 1,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, now_us + 50_000);
    try std.testing.expectEqual(b0 + b1, est.delivered);
    try std.testing.expectEqual(@as(u64, 0), est.lost);
    try std.testing.expect(!est.isAppLimited());
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).liveCount());
}

test "PTO-expired packets reach the sampler's loss ledger" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try prepareClient(&conn);
    conn.ccForApplication().setCwndForTest(120_000);
    try queueBulkStream(&conn, 900);

    var pkt: [2048]u8 = undefined;
    const now_us: u64 = 1_000_000;
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) != null);
    const b0 = conn.sentForLevel(.application).packets[0].bytes;

    // No ACK ever arrives; the PTO declares the flight lost.
    try conn.tick(now_us + 4 * conn.ptoDurationForLevel(.application));
    const est = &conn.primaryPath().path.delivery;
    try std.testing.expectEqual(b0, est.lost);
    try std.testing.expectEqual(@as(u64, 0), est.delivered);
}
