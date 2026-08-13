// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Connection = state.Connection;
const frame_mod = state.frame_mod;
const max_recv_plaintext = state.max_recv_plaintext;
const short_packet_mod = state.short_packet_mod;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestEarlyDataWriteSecret = util.installTestEarlyDataWriteSecret;

test "ACKed in-flight packets grow congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // The §7.8 app-limited gate only grows cwnd off a full pipe:
    // shrink the window to what this single 1200-byte packet fills.
    conn.ccForApplication().setCwndForTest(1200);
    const initial_cwnd = conn.congestionWindow();
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_010_000);

    try std.testing.expect(conn.congestionWindow() > initial_cwnd);
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "0-RTT poll emits long-header packet in Application PN space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(conn);
    conn.setEarlyDataEnabled(true);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expect((out[0] & 0x80) != 0);
    try std.testing.expectEqual(@as(u2, 1), @as(u2, @intCast((out[0] >> 4) & 0x03)));
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(conn.sentForLevel(.early_data).packets[0].is_early_data);
    try std.testing.expectEqual(@as(u64, 1), conn.pnSpaceForLevel(.early_data).next_pn);
}

test "pollLevel caps ACK ranges to packet budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 200) : (pn += 2) tracker.add(pn, 1_000);
    const tracked_lower_ranges = @as(u64, tracker.range_count - 1);

    var packet_buf: [128]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!tracker.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expectEqual(@as(u64, 198), decoded.frame.ack.largest_acked);
    try std.testing.expect(decoded.frame.ack.range_count < tracked_lower_ranges);
}
