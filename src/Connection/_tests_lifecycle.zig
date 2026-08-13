// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const CloseErrorSpace = state.CloseErrorSpace;
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const ConnectionPhase = state.ConnectionPhase;
const Error = state.Error;
const frame_mod = state.frame_mod;

test "peer close records transport error details" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = true,
            .error_code = 0x0a,
            .frame_type = 0x08,
            .reason_phrase = "bad stream frame",
        },
    });
    try conn.dispatchFrames(.application, payload[0..n], 1_000_000);

    const sticky = conn.closeEvent().?;
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expectEqual(CloseSource.peer, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x0a), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0x08), sticky.frame_type);
    try std.testing.expectEqualStrings("bad stream frame", sticky.reason);
    try std.testing.expectEqual(@as(u64, 1_000_000), sticky.at_us.?);
    try std.testing.expect(sticky.draining_deadline_us != null);
}

test "beginGracefulShutdown refuses local opens but stays open" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.peer_max_streams_bidi = 100;
    conn.peer_max_streams_uni = 100;

    _ = try conn.openNextBidi(); // fine before shutdown
    try std.testing.expect(!conn.gracefulShutdownActive());

    conn.beginGracefulShutdown();
    try std.testing.expect(conn.gracefulShutdownActive());
    try std.testing.expectError(Error.ShuttingDown, conn.openNextBidi());
    try std.testing.expectError(Error.ShuttingDown, conn.openNextUni());
    try std.testing.expectError(Error.ShuttingDown, conn.openBidi(40));
    try std.testing.expectError(Error.ShuttingDown, conn.openUni(42));

    // Graceful shutdown is not a close state — the connection stays open.
    try std.testing.expectEqual(CloseState.open, conn.closeState());
    conn.beginGracefulShutdown(); // idempotent
    try std.testing.expect(conn.gracefulShutdownActive());
}

test "phase() reports initial before keys and closing after close()" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Fresh connection: no handshake/application keys yet.
    try std.testing.expectEqual(ConnectionPhase.initial, conn.phase());

    // A non-open close state wins over the handshake epoch.
    conn.close(true, 0x1, "bye");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(ConnectionPhase.closing, conn.phase());
}

test "per-space tracker capacities: 256 for Initial/Handshake, 4096 for Application" {
    // Wiring pin for the right-sizing decision recorded at
    // `sent_packets.initial_handshake_max_tracked`: the two
    // connection-level spaces must get the small capacity, the
    // per-path Application space the large one. If this fails after
    // an intentional resize, update the constants' rationale first.
    const sent_packets = state.sent_packets_mod;
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try std.testing.expectEqual(
        @as(u32, sent_packets.initial_handshake_max_tracked),
        conn.sentForLevel(.initial).capacity(),
    );
    try std.testing.expectEqual(
        @as(u32, sent_packets.initial_handshake_max_tracked),
        conn.sentForLevel(.handshake).capacity(),
    );
    try std.testing.expectEqual(
        @as(u32, sent_packets.max_tracked),
        conn.sentForLevel(.application).capacity(),
    );
}
