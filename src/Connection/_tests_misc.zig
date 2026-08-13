// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const EncryptionLevel = state.EncryptionLevel;
const level_mod = state.level_mod;

test "EncryptionLevel idx round-trip" {
    inline for (level_mod.all) |lvl| {
        try std.testing.expectEqual(lvl.idx(), @backingInt(lvl));
    }
}

test "Connection.stats snapshots counters, active path, and gauges" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try state.Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const fresh = conn.stats();
    try std.testing.expectEqual(@as(u64, 0), fresh.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), fresh.packets_received);
    try std.testing.expectEqual(@as(u64, 0), fresh.packets_lost);
    try std.testing.expectEqual(conn.activePathId(), fresh.active_path_id);
    try std.testing.expectEqual(@as(usize, 0), fresh.streams_open);
    try std.testing.expectEqual(conn.closeState(), fresh.close_state);
    try std.testing.expectEqual(conn.pmtu(), fresh.pmtu);
    // The active-path section mirrors pathStats for the same id.
    if (conn.pathStats(fresh.active_path_id)) |ps| {
        try std.testing.expectEqual(ps.cwnd, fresh.cwnd);
        try std.testing.expectEqual(ps.smoothed_rtt_us, fresh.smoothed_rtt_us);
        try std.testing.expectEqual(ps.congestion_window_state, fresh.congestion_state);
    }

    // Aggregate counters are read straight off the connection.
    conn.qlog_bytes_sent = 1234;
    conn.qlog_bytes_received = 567;
    conn.qlog_packets_sent = 8;
    conn.qlog_packets_received = 6;
    conn.qlog_packets_lost = 1;
    const counted = conn.stats();
    try std.testing.expectEqual(@as(u64, 1234), counted.bytes_sent);
    try std.testing.expectEqual(@as(u64, 567), counted.bytes_received);
    try std.testing.expectEqual(@as(u64, 8), counted.packets_sent);
    try std.testing.expectEqual(@as(u64, 6), counted.packets_received);
    try std.testing.expectEqual(@as(u64, 1), counted.packets_lost);

    // Stream gauge follows the live table.
    try conn.setTransportParams(.{ .initial_max_streams_bidi = 4 });
    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 1), conn.stats().streams_open);

    // The snapshot is a by-value copy: mutating the connection after
    // the call must not affect an already-taken snapshot.
    const before = conn.stats();
    conn.qlog_bytes_sent += 1;
    try std.testing.expectEqual(@as(u64, 1234), before.bytes_sent);
}
