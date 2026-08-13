// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const CloseErrorSpace = state.CloseErrorSpace;
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const frame_mod = state.frame_mod;
const max_crypto_reassembly_gap = state.max_crypto_reassembly_gap;
const max_pending_crypto_bytes_per_level = state.max_pending_crypto_bytes_per_level;
const max_pending_crypto_fragments_per_level = state.max_pending_crypto_fragments_per_level;
const transport_error_protocol_violation = state.transport_error_protocol_violation;

test "stateless reset token closes without CONNECTION_CLOSE" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const token: [16]u8 = .{
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{ 0xaa, 0xbb, 0xcc, 0xdd });

    var packet: [24]u8 = .{
        0x40, 0xaa, 0xbb, 0xcc,
        0xdd, 0x55, 0x66, 0x77,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
        0,    0,    0,    0,
    };
    @memcpy(packet[packet.len - 16 ..], &token);

    try conn.handle(&packet, null, 3_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.lifecycle.pending_close == null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.stateless_reset, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqualStrings("stateless reset", close_event.reason);
    try std.testing.expectEqual(@as(u64, 3_000_000), close_event.at_us.?);
}

test "stateless reset matcher requires short packet with known token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const token: [16]u8 = .{
        0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f,
    };
    conn.cached_peer_transport_params = .{ .stateless_reset_token = token };
    try conn.setPeerDcid(&.{0xaa});

    var long_packet = @as([24]u8, @splat(0));
    long_packet[0] = 0xc0;
    @memcpy(long_packet[long_packet.len - 16 ..], &token);
    try std.testing.expect(!conn.isKnownStatelessReset(long_packet[0..]));

    var unknown_short = @as([24]u8, @splat(0));
    unknown_short[0] = 0x40;
    const unknown_token: [16]u8 = @splat(0xee);
    @memcpy(unknown_short[unknown_short.len - 16 ..], &unknown_token);
    try std.testing.expect(!conn.isKnownStatelessReset(unknown_short[0..]));

    var short_packet = @as([24]u8, @splat(0));
    short_packet[0] = 0x40;
    @memcpy(short_packet[short_packet.len - 16 ..], &token);
    try std.testing.expect(conn.isKnownStatelessReset(short_packet[0..]));
}

test "packetPayloadAckEliciting ignores ACK-only payloads" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .padding = .{ .count = 2 } });
    pos += try frame_mod.encode(buf[pos..], .{ .ack = .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
    } });
    try std.testing.expect(!Connection.packetPayloadAckEliciting(buf[0..pos]));

    pos += try frame_mod.encode(buf[pos..], .{ .ping = .{} });
    try std.testing.expect(Connection.packetPayloadAckEliciting(buf[0..pos]));
}

test "packetPayloadNeedsImmediateAck flags stream finality and resets" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_offset = false,
        .has_length = true,
        .fin = false,
    } });
    try std.testing.expect(!Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .data = "",
        .has_offset = true,
        .has_length = true,
        .fin = true,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));

    pos = 0;
    pos += try frame_mod.encode(buf[pos..], .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 42,
        .final_size = 1,
    } });
    try std.testing.expect(Connection.packetPayloadNeedsImmediateAck(buf[0..pos]));
}

test "CRYPTO reassembly: out-of-order fragments delivered in order" {
    // Tests the same shape quic-go sends on the wire: a high-offset
    // fragment first, then the low-offset fragment, then a tiny
    // bridge fragment, then the tail.
    const allocator = std.testing.allocator;

    // We don't need a real Connection for this — we exercise the
    // reassembly machinery via a bare struct that holds the same
    // fields. Cleaner: use a real Connection but skip TLS bring-up.
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();

    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    // Don't bind/handshake — we're only testing reassembly, which
    // doesn't need TLS.

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();

    // First fragment: out-of-order high range.
    try conn.handleCrypto(lvl, .{ .offset = 69, .data = "BBBBBBBB" });
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_pending[idx].items.len);

    // Second fragment: in-order low range — delivers immediately.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "AAAAAAAAAAA" }); // 11 bytes
    try std.testing.expectEqual(@as(u64, 11), conn.crypto_recv_offset[idx]);

    // Third fragment: bridges the gap [11, 69) — delivers, then
    // drains the pending [69, 77).
    var bridge: [58]u8 = @splat('M');
    try conn.handleCrypto(lvl, .{ .offset = 11, .data = &bridge });
    try std.testing.expectEqual(@as(u64, 77), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);

    // Inbox should have all 77 bytes in the right order.
    try std.testing.expectEqual(@as(usize, 77), conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, "AAAAAAAAAAA", conn.inbox[idx].buf[0..11]);
    for (conn.inbox[idx].buf[11..69]) |b| try std.testing.expectEqual(@as(u8, 'M'), b);
    try std.testing.expectEqualSlices(u8, "BBBBBBBB", conn.inbox[idx].buf[69..77]);
}

test "CRYPTO reassembly: out-of-order fragment count is bounded (M1: O(n^2) drain guard)" {
    // A peer can flood tiny out-of-order CRYPTO fragments that all fit
    // the byte budget; without a fragment-count cap, drainPendingCrypto's
    // O(n^2) scan becomes a CPU-exhaustion vector. Feeding one past the
    // cap must close with PROTOCOL_VIOLATION, not keep buffering.
    const allocator = std.testing.allocator;
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();

    // Feed exactly `cap` one-byte out-of-order fragments at distinct
    // offsets (offset 0 stays a gap so nothing drains). Each buffers.
    var i: u64 = 0;
    while (i < max_pending_crypto_fragments_per_level) : (i += 1) {
        const one = [_]u8{@intCast(i & 0xff)};
        try conn.handleCrypto(lvl, .{ .offset = i + 1, .data = &one });
    }
    try std.testing.expectEqual(
        max_pending_crypto_fragments_per_level,
        conn.crypto_pending[idx].items.len,
    );
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    // One more out-of-order fragment trips the count cap and closes.
    const extra = [_]u8{0xff};
    try conn.handleCrypto(lvl, .{ .offset = 100_000, .data = &extra });
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    const ce = conn.closeEvent() orelse return error.NoCloseEvent;
    try std.testing.expectEqual(transport_error_protocol_violation, ce.error_code);
    // The flood did not grow the pending list past the cap.
    try std.testing.expectEqual(
        max_pending_crypto_fragments_per_level,
        conn.crypto_pending[idx].items.len,
    );
}

test "CRYPTO reassembly: duplicate fragment is silently ignored" {
    const allocator = std.testing.allocator;
    const boringssl_tls = boringssl.tls;
    var ctx = try boringssl_tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);

    // Retransmit of the same range — should be a no-op.
    try conn.handleCrypto(lvl, .{ .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 6), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 6), conn.inbox[idx].len);

    // Partial overlap (offset=3 covers bytes already delivered + new).
    try conn.handleCrypto(lvl, .{ .offset = 3, .data = "defGHI" });
    try std.testing.expectEqual(@as(u64, 9), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqualSlices(u8, "abcdefGHI", conn.inbox[idx].buf[0..9]);
}

test "CRYPTO reassembly: deterministic shuffled fragment smoke" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const lvl: EncryptionLevel = .initial;
    const idx = lvl.idx();
    const total: usize = 4096;
    const chunk: usize = 64;
    const chunks = total / chunk;

    var data: [total]u8 = undefined;
    var indices: [chunks]usize = undefined;
    var prng = std.Random.DefaultPrng.init(0xc274_7074_6f66_757a);
    const rng = prng.random();
    rng.bytes(&data);
    for (&indices, 0..) |*slot, i| slot.* = i;
    rng.shuffle(usize, &indices);

    for (indices, 0..) |chunk_idx, order| {
        const off = chunk_idx * chunk;
        const bytes = data[off..][0..chunk];
        try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        if ((order % 9) == 0) {
            try conn.handleCrypto(lvl, .{ .offset = @intCast(off), .data = bytes });
        }
    }

    try std.testing.expectEqual(@as(u64, total), conn.crypto_recv_offset[idx]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[idx].items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[idx]);
    try std.testing.expectEqual(total, conn.inbox[idx].len);
    try std.testing.expectEqualSlices(u8, &data, conn.inbox[idx].buf[0..total]);
}

test "ACK with largest_acked == next_pn is a PROTOCOL_VIOLATION" {
    // Boundary case: next_pn is the *next* PN to assign on send,
    // so an ACK whose largest_acked equals next_pn is also illegal.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 1;

    // ACK claims PN 1, but next_pn is 1 (we've never sent PN 1).
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(transport_error_protocol_violation, conn.closeEvent().?.error_code);
}

test "handleCrypto bounds out-of-order reassembly" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.handleCrypto(.initial, .{ .offset = max_crypto_reassembly_gap + 1, .data = "x" });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        var huge: [max_pending_crypto_bytes_per_level + 1]u8 = @splat(0);
        try conn.handleCrypto(.initial, .{ .offset = 1, .data = &huge });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), conn.crypto_pending_bytes[0]);
    }
}
