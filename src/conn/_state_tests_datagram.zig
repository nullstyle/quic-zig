// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const CloseState = state.CloseState;
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const Error = state.Error;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const long_packet_mod = state.long_packet_mod;
const max_pending_datagram_count = state.max_pending_datagram_count;
const max_supported_udp_payload_size = state.max_supported_udp_payload_size;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestEarlyDataWriteSecret = util.installTestEarlyDataWriteSecret;
const installTestEarlyDataReadSecret = util.installTestEarlyDataReadSecret;
const testEarlyDataPacketKeys = util.testEarlyDataPacketKeys;

test "closing and draining ignore incoming datagrams" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.close(false, 0x42, "closing");
    var random_short = [_]u8{ 0x40, 0, 1, 2, 3, 4, 5 };
    try conn.handle(&random_short, null, 1_000_000);
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPathConst().path.bytes_received);

    var peer_ctx = try boringssl.tls.Context.initClient(.{});
    defer peer_ctx.deinit();
    var peer_closed = try Connection.initClient(allocator, peer_ctx, "x");
    defer peer_closed.deinit();
    var payload: [128]u8 = undefined;
    const n = try frame_mod.encode(&payload, .{
        .connection_close = .{
            .is_transport = false,
            .error_code = 0x7,
            .reason_phrase = "bye",
        },
    });
    try peer_closed.dispatchFrames(.application, payload[0..n], 2_000_000);
    try std.testing.expectEqual(CloseState.draining, peer_closed.closeState());
    const deadline = peer_closed.lifecycle.draining_deadline_us.?;
    try peer_closed.handle(&random_short, null, 2_000_001);
    try std.testing.expectEqual(@as(u64, 0), peer_closed.last_activity_us);
    try peer_closed.tick(deadline);
    try std.testing.expectEqual(CloseState.closed, peer_closed.closeState());
    try std.testing.expect(peer_closed.nextTimerDeadline(deadline) == null);
}

test "setTransportParams advertises bounded UDP payload limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_datagram_frame_size = 9000 });
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, max_supported_udp_payload_size), conn.local_transport_params.max_datagram_frame_size);

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{ .max_udp_payload_size = default_mtu - 1 }));
}

test "handle rejects UDP datagrams above local payload limit before path credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_udp_payload_size = default_mtu });

    var bytes: [default_mtu + 1]u8 = @splat(0);
    try conn.handle(&bytes, null, 123);

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), conn.last_activity_us);
}

test "sendDatagram enforces peer support and bounded queue" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 0 };
    try std.testing.expectError(Error.DatagramUnavailable, conn.sendDatagram("x"));

    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 4 };
    try std.testing.expectError(Error.DatagramTooLarge, conn.sendDatagram("12345"));
    try conn.sendDatagram("1234");
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 4), conn.pending_frames.send_datagram_bytes);

    while (conn.pending_frames.send_datagrams.items.len < max_pending_datagram_count) {
        try conn.sendDatagram("x");
    }
    try std.testing.expectError(Error.DatagramQueueFull, conn.sendDatagram("x"));
}

test "maxDatagramPayload tracks the live PMTU and the peer frame-size cap" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Peer hasn't enabled DATAGRAM yet.
    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 0 };
    try std.testing.expectError(Error.DatagramUnavailable, conn.maxDatagramPayload());

    // With a generous peer cap the payload is bounded by the path MTU; at the
    // 1200-byte floor that is the historical default_mtu - 9 = 1191, so the
    // floor behavior is unchanged.
    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 65535 };
    try std.testing.expectEqual(@as(usize, default_mtu - 9), try conn.maxDatagramPayload());

    // A validated larger PMTU grows the budget one-for-one...
    conn.activePath().pmtu = 1500;
    try std.testing.expectEqual(@as(usize, 1500 - 9), try conn.maxDatagramPayload());
    // ...and a PMTU black-hole shrinks it below the floor.
    conn.activePath().pmtu = 1000;
    try std.testing.expectEqual(@as(usize, 1000 - 9), try conn.maxDatagramPayload());

    // The peer's max_datagram_frame_size still caps it under a big PMTU.
    conn.activePath().pmtu = 1500;
    conn.cached_peer_transport_params = .{ .max_datagram_frame_size = 200 };
    try std.testing.expectEqual(@as(usize, 200), try conn.maxDatagramPayload());
}

test "tracked DATAGRAM emits ack event when packet is acknowledged" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("ack-me");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    const sent = conn.primaryPath().sent.packets[0];
    try std.testing.expect(sent.datagram != null);
    try std.testing.expectEqual(id, sent.datagram.?.id);
    try std.testing.expectEqual(@as(usize, 6), sent.datagram.?.len);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 6), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expectEqual(@as(u32, 0), event.datagram_acked.path_id);
    try std.testing.expect(!event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "tracked DATAGRAM emits loss event without retransmission" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    const id = try conn.sendDatagramTracked("lost");
    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;

    var lost = conn.primaryPath().sent.removeAt(0);
    defer lost.deinit(conn.allocator);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expect(!(try conn.requeueLostPacket(.application, &lost)));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(id, event.datagram_lost.id);
    try std.testing.expectEqual(@as(usize, 4), event.datagram_lost.len);
    try std.testing.expectEqual(lost.pn, event.datagram_lost.packet_number);
}

test "handleDatagram enforces local DATAGRAM limit and queue budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.recv_datagrams.items.len);
    }

    {
        var conn = try Connection.initServer(allocator, ctx);
        defer conn.deinit();
        conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
        while (conn.pending_frames.recv_datagrams.items.len < max_pending_datagram_count) {
            try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        }
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_frames.recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count, conn.pending_frames.recv_datagram_bytes);

        var buf: [1]u8 = undefined;
        const info = conn.receiveDatagramInfo(&buf).?;
        try std.testing.expectEqual(@as(usize, 1), info.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_frames.recv_datagrams.items.len);
        try std.testing.expectEqual(max_pending_datagram_count - 1, conn.pending_frames.recv_datagram_bytes);

        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try conn.handleDatagram(.application, .{ .data = "x", .has_length = true });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    }
}

test "0-RTT rejection requeues STREAM data but not DATAGRAM payloads" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-datagram");
    const s = try conn.openBidi(0);
    _ = try s.send.write("early-stream");

    var out: [512]u8 = undefined;
    const n = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expect(n > 0);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);

    try conn.requeueRejectedEarlyData();

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.send_datagrams.items.len);
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 12), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-stream", s.send.chunkBytes(chunk));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_id, event.datagram_lost.id);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
}

test "0-RTT DATAGRAM ack event carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    const datagram_id = try conn.sendDatagramTracked("early-ack");
    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;

    const sent = conn.sentForLevel(.early_data).packets[0];
    try std.testing.expect(sent.is_early_data);
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = sent.pn,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_id, event.datagram_acked.id);
    try std.testing.expectEqual(@as(usize, 9), event.datagram_acked.len);
    try std.testing.expectEqual(sent.pn, event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);
    try std.testing.expect(conn.pollEvent() == null);
}

test "0-RTT DATAGRAM packet-threshold loss carries early-data metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);
    conn.setEarlyDataEnabled(true);

    var datagram_ids: [4]u64 = undefined;
    var out: [256]u8 = undefined;
    for (&datagram_ids, 0..) |*id, i| {
        id.* = try conn.sendDatagramTracked(if (i == 0) "lost" else "acked");
        _ = (try conn.pollLevel(.early_data, &out, 1_000 + @as(u64, @intCast(i)))).?;
    }
    try std.testing.expectEqual(@as(u32, 4), conn.sentForLevel(.early_data).count);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_acked);
    try std.testing.expectEqual(datagram_ids[3], event.datagram_acked.id);
    try std.testing.expectEqual(@as(u64, 3), event.datagram_acked.packet_number);
    try std.testing.expect(event.datagram_acked.arrived_in_early_data);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .datagram_lost);
    try std.testing.expectEqual(datagram_ids[0], event.datagram_lost.id);
    try std.testing.expectEqual(@as(u64, 0), event.datagram_lost.packet_number);
    try std.testing.expect(event.datagram_lost.arrived_in_early_data);
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.early_data).count);
}

test "server marks accepted 0-RTT DATAGRAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    conn.local_transport_params.max_datagram_frame_size = max_supported_udp_payload_size;
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .datagram = .{
        .data = "early-dgram",
        .has_length = true,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    const consumed = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expectEqual(packet_len, consumed);

    var buf: [32]u8 = undefined;
    const info = conn.receiveDatagramInfo(&buf).?;
    try std.testing.expectEqual(@as(usize, 11), info.len);
    try std.testing.expect(info.arrived_in_early_data);
    try std.testing.expectEqualSlices(u8, "early-dgram", buf[0..info.len]);
}

test "pollDatagram can select a non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.{ .ipv4 = .{ .addr = .{ 1, 2, 3, 4 }, .port = 0 } }, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try std.testing.expect(conn.setActivePath(path_id));
    try conn.queuePathStatus(path_id, true, 1);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(datagram.to != null);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(u32, 1), conn.paths.get(path_id).?.sent.count);
}
