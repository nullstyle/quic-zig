// Split from _tests.zig — see that file for the area index.
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
const TimerKind = state.TimerKind;
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
    const sent_packets = state.SentPacketTracker;
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

test "handshake timeout: anchored at first tick, fires at the deadline" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handshake_timeout_us = 1_000;
    // Pre-arm: nextTimerDeadline must already surface the projected
    // deadline so a loop parking before the first tick wakes in time.
    const projected = conn.nextTimerDeadline(0).?;
    try std.testing.expectEqual(TimerKind.handshake_timeout, projected.kind);
    try std.testing.expectEqual(@as(u64, 1_000), projected.at_us);

    // First tick anchors the deadline; it must not drift on later
    // ticks (the budget is from connection start, not from the most
    // recent activity — a client retrying forever must still die).
    try conn.tick(100);
    try std.testing.expectEqual(@as(u64, 1_100), conn.handshake_deadline_us.?);
    try conn.tick(500);
    try std.testing.expectEqual(@as(u64, 1_100), conn.handshake_deadline_us.?);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    // At the deadline: draining with the typed cause — same posture
    // as the idle timeout (no CONNECTION_CLOSE to an unresponsive
    // peer).
    try conn.tick(1_100);
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.handshake_timeout, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqualStrings("handshake timeout", close_event.reason);
}

test "handshake timeout: disabled knob never arms" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handshake_timeout_us = 0;
    try conn.tick(0);
    try conn.tick(1_000_000_000);
    try std.testing.expectEqual(@as(?u64, null), conn.handshake_deadline_us);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "handshake timeout: disarms at handshake confirmation" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handshake_timeout_us = 1_000;
    try conn.tick(100);
    try std.testing.expect(conn.handshake_deadline_us != null);

    // Confirmation latch (RFC 9001 §4.9.2 key discard): the timer
    // disarms and the connection survives far past the budget.
    conn.handshake_keys_discarded = true;
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(?u64, null), conn.handshake_deadline_us);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
    try std.testing.expect(conn.closeEvent() == null);
}
