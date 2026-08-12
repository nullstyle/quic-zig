// Split from _state_tests.zig — see that file for the area index.
// Connection-level pacing behavior (RFC 9002 §7.7): the gate, the
// deadline surfacing, the kill-switch, and probe debt.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const Connection = state.Connection;
const TimerKind = state.TimerKind;
const default_mtu = state.default_mtu;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;

/// Post-placement setup: MUST run on the Connection at its final
/// stable address (after the `initClient` return copy), matching the
/// house pattern in every other _state_tests file.
fn preparePacedClient(conn: *Connection) !void {
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    });
    try installTestApplicationWriteSecret(conn);
    // No handshake in this fixture, so real peer params never arrive;
    // remembered limits give the streams a non-zero send window (the
    // _state_tests_loss pattern).
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
    });
}

fn queueBulkStream(conn: *Connection, bytes: usize) !void {
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    // Write into the stream buffer directly (the no-handshake fixture
    // pattern from _state_tests_send/_loss): `Connection.streamWrite`
    // would clamp to the peer's never-negotiated flow-control limits.
    const s = try conn.openBidi(0);
    var written: usize = 0;
    while (written < bytes) {
        const want = @min(data.len, bytes - written);
        const n = try s.send.write(data[0..want]);
        if (n == 0) break;
        written += n;
    }
}

test "paced sender emits the burst then blocks; deadline surfaces as TimerKind.pacing" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try preparePacedClient(&conn);

    // Give cwnd plenty of headroom (100 MSS) so the PACER is the
    // binding constraint: bucket = max(10 x MSS, ~1 ms of rate) stays
    // ~10 packets while the window would allow far more.
    conn.ccForApplication().setCwndForTest(120_000);
    try queueBulkStream(&conn, 256 * 1024);

    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    var emitted: u32 = 0;
    while (try conn.pollDatagram(&pkt, now_us)) |_| {
        emitted += 1;
        try std.testing.expect(emitted < 64); // pacing must bound the burst
    }
    // The initial bucket is 10 packets; coalescing/padding wiggle
    // gives a small margin but the burst must be near that.
    try std.testing.expect(emitted >= 8 and emitted <= 12);

    // Blocked on pacing now: data is pending, cwnd has room, so the
    // connection must surface a pacing deadline in the future.
    const deadline = conn.nextTimerDeadline(now_us).?;
    try std.testing.expectEqual(TimerKind.pacing, deadline.kind);
    try std.testing.expect(deadline.at_us > now_us);

    // Waking at (past) the deadline releases at least one datagram —
    // the liveness contract: deadline -> tick -> drain succeeds.
    now_us = deadline.at_us + 1_000;
    try conn.tick(now_us);
    try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) != null);
}

test "enable_pacing=false restores unpaced draining (the kill switch)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try preparePacedClient(&conn);
    conn.pacing_enabled = false;
    conn.ccForApplication().setCwndForTest(120_000);

    try queueBulkStream(&conn, 64 * 1024);

    // Unpaced: the whole cwnd drains in one poll loop (bounded by the
    // congestion window, not the pacer), and no pacing deadline ever
    // surfaces.
    var pkt: [2048]u8 = undefined;
    const now_us: u64 = 1_000_000;
    var emitted: u32 = 0;
    while (try conn.pollDatagram(&pkt, now_us)) |_| emitted += 1;
    // Far more than the ~10-packet pacing bucket would allow: the
    // whole 64 KiB drains inside the 100-MSS window in one loop.
    try std.testing.expect(emitted >= 20);
    if (conn.nextTimerDeadline(now_us)) |deadline| {
        try std.testing.expect(deadline.kind != .pacing);
    }
}

test "no pacing deadline without pending data or while cwnd-blocked" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try preparePacedClient(&conn);

    // Nothing queued: even with a drained pacer there is nothing a
    // pacing wake could do.
    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    if (conn.nextTimerDeadline(now_us)) |deadline| {
        try std.testing.expect(deadline.kind != .pacing);
    }

    // Drain the full window so the connection is cwnd-blocked, with
    // data still pending: a timer wake cannot unblock cwnd (only an
    // ACK can), so no pacing deadline may surface.
    try queueBulkStream(&conn, 256 * 1024);
    while (try conn.pollDatagram(&pkt, now_us)) |_| now_us += 100;
    var drain_guard: u32 = 0;
    while (drain_guard < 100) : (drain_guard += 1) {
        now_us += 50_000;
        try conn.tick(now_us);
        var burst: u32 = 0;
        while (try conn.pollDatagram(&pkt, now_us)) |_| burst += 1;
        if (burst == 0 and conn.congestionBlocked(.application)) break;
    }
    if (conn.congestionBlocked(.application)) {
        if (conn.nextTimerDeadline(now_us)) |deadline| {
            try std.testing.expect(deadline.kind != .pacing);
        }
    }
}

test "probe debt: PTO probes bypass the gate but delay the next data send" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    try preparePacedClient(&conn);

    conn.ccForApplication().setCwndForTest(120_000);
    try queueBulkStream(&conn, 256 * 1024);
    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    while (try conn.pollDatagram(&pkt, now_us)) |_| {}
    // Pacer is drained. Fire a PTO: the probe must emit despite an
    // empty bucket (pending_ping bypass) and push the bucket into debt.
    const tokens_before = conn.primaryPath().path.pacer.tokens;
    now_us = conn.ptoDurationForLevel(.application) + now_us;
    try conn.tick(now_us);
    const emitted_probe = (try conn.pollDatagram(&pkt, now_us)) != null;
    try std.testing.expect(emitted_probe);
    try std.testing.expect(conn.primaryPath().path.pacer.tokens < tokens_before);
}
