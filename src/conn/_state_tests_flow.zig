// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const Connection = state.Connection;
const StreamType = state.StreamType;
const ConnectionId = state.ConnectionId;
const ConnectionIdReplenishReason = state.ConnectionIdReplenishReason;
const Error = state.Error;
const FlowBlockedKind = state.FlowBlockedKind;
const FlowBlockedSource = state.FlowBlockedSource;
const PathCidsBlockedInfo = state.PathCidsBlockedInfo;
const default_connection_receive_window = state.default_connection_receive_window;
const default_mtu = state.default_mtu;
const default_stream_receive_window = state.default_stream_receive_window;
const frame_types = state.frame_types;
const max_initial_connection_receive_window = state.max_initial_connection_receive_window;
const max_initial_stream_receive_window = state.max_initial_stream_receive_window;
const max_stream_count_limit = state.max_stream_count_limit;
const max_streams_per_connection = state.max_streams_per_connection;
const max_supported_active_connection_id_limit = state.max_supported_active_connection_id_limit;
const max_supported_path_id = state.max_supported_path_id;
const max_tracked_stream_data_blocked = state.max_tracked_stream_data_blocked;
const min_quic_udp_payload_size = state.min_quic_udp_payload_size;
const sent_packets_mod = state.sent_packets_mod;
const transport_error_flow_control = state.transport_error_flow_control;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const transport_error_stream_limit = state.transport_error_stream_limit;
const transport_error_stream_state = state.transport_error_stream_state;
const transport_error_transport_parameter = state.transport_error_transport_parameter;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const markTestMultipathNegotiated = util.markTestMultipathNegotiated;

test "congestionBlocked gates application data but allows PTO probes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.ccForApplication().setCwndForTest(1200);
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try std.testing.expect(conn.congestionBlocked(.application));
    try std.testing.expect(!conn.congestionBlocked(.initial));
    conn.pendingPingForLevel(.application).* = true;
    try std.testing.expect(!conn.congestionBlocked(.application));
    conn.pendingPingForLevel(.application).* = false;
    conn.primaryPath().pto_probe_count = 1;
    try std.testing.expect(!conn.congestionBlocked(.application));
}

test "peer transport parameter limit violations use transport parameter error" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    {
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.cached_peer_transport_params = .{ .max_udp_payload_size = min_quic_udp_payload_size - 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer max udp payload below minimum", conn.lifecycle.pending_close.?.reason);
    }

    {
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.cached_peer_transport_params = .{ .initial_max_streams_bidi = max_stream_count_limit + 1 };
        conn.validatePeerTransportLimits();
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqualStrings("peer stream count exceeds maximum", conn.lifecycle.pending_close.?.reason);
    }
}

test "local transport params reject allocation policy overflows" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_bidi = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_uni = max_streams_per_connection + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_path_id = max_supported_path_id + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_data = max_initial_connection_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_local = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_bidi_remote = max_initial_stream_receive_window + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_stream_data_uni = max_initial_stream_receive_window + 1,
    }));
}

test "bounded policy clamps MAX_STREAMS MAX_PATH_ID and peer CID fanout" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_streams_bidi = 0;
    conn.peer_max_streams_uni = 0;
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = max_streams_per_connection + 100 });
    conn.handleMaxStreams(.{ .bidi = false, .maximum_streams = max_streams_per_connection + 100 });
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.peer_max_streams_uni);

    conn.queueMaxStreams(true, max_streams_per_connection + 100);
    conn.queueMaxStreams(false, max_streams_per_connection + 100);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_uni);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_frames.max_streams_bidi.?);
    try std.testing.expectEqual(max_streams_per_connection, conn.pending_frames.max_streams_uni.?);

    conn.queueMaxPathId(max_supported_path_id + 100);
    try std.testing.expectEqual(max_supported_path_id, conn.local_max_path_id);
    try std.testing.expectEqual(max_supported_path_id, conn.pending_frames.max_path_id.?);

    conn.cached_peer_transport_params = .{
        .active_connection_id_limit = max_supported_active_connection_id_limit + 100,
    };
    try std.testing.expectEqual(
        max_supported_active_connection_id_limit,
        conn.peerActiveConnectionIdLimit(),
    );
}

test "STREAM_DATA_BLOCKED tracking is bounded and validates stream space" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.setTransportParams(.{ .initial_max_streams_bidi = 1 });
        try conn.handleStreamDataBlocked(.{ .stream_id = 0, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close == null);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);

        try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_limit, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 1), conn.peer_stream_data_blocked.items.len);
    }

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.handleStreamDataBlocked(.{ .stream_id = 3, .maximum_stream_data = 7 });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_stream_state, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(usize, 0), conn.peer_stream_data_blocked.items.len);
    }

    {
        var list: std.ArrayList(frame_types.StreamDataBlocked) = .empty;
        defer list.deinit(allocator);
        var i: usize = 0;
        while (i < max_tracked_stream_data_blocked) : (i += 1) {
            try list.append(allocator, .{
                .stream_id = @as(u64, @intCast(i)) * 4,
                .maximum_stream_data = 1,
            });
        }
        try std.testing.expectError(Error.StreamLimitExceeded, Connection.upsertStreamBlocked(&list, allocator, .{
            .stream_id = @as(u64, @intCast(max_tracked_stream_data_blocked)) * 4,
            .maximum_stream_data = 1,
        }));
        try std.testing.expectEqual(max_tracked_stream_data_blocked, list.items.len);
    }
}

test "STREAM receive enforces stream and connection flow control" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.setTransportParams(.{
            .initial_max_data = 16,
            .initial_max_stream_data_bidi_remote = 3,
            .initial_max_streams_bidi = 1,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "abcd",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 0), conn.peer_sent_stream_data);
    }

    {
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.setTransportParams(.{
            .initial_max_data = 5,
            .initial_max_stream_data_bidi_remote = 8,
            .initial_max_streams_bidi = 2,
        });
        try conn.handleStream(.application, .{
            .stream_id = 0,
            .offset = 0,
            .data = "hello",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close == null);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
        try conn.handleStream(.application, .{
            .stream_id = 4,
            .offset = 0,
            .data = "!",
            .has_length = true,
        });
        try std.testing.expect(conn.lifecycle.pending_close != null);
        try std.testing.expectEqual(transport_error_flow_control, conn.lifecycle.pending_close.?.error_code);
        try std.testing.expectEqual(@as(u64, 5), conn.peer_sent_stream_data);
    }
}

test "MAX_DATA MAX_STREAM_DATA and MAX_STREAMS raise send-side limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s0 = try conn.openBidi(0);
    s0.send_max_data = 4;

    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(4));
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 2 });
    _ = try conn.openBidi(4);

    conn.handleMaxData(.{ .maximum_data = 32 });
    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 16 });
    try std.testing.expectEqual(@as(u64, 32), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 16), conn.stream(0).?.send_max_data);
}

// -- StreamType + openNext* convenience openers (RFC 9000 §2.1) ---------
// HTTP/3 (and any embedder) classifies streams and opens its control /
// QPACK streams by the low-two-bit id encoding; these helpers remove the
// hand-rolled bit math from the downstream layer.

test "openNextBidi / openNextUni choose client-initiated ids automatically" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.peer_max_streams_bidi = 100;
    conn.peer_max_streams_uni = 100;

    try std.testing.expectEqual(@as(u64, 0), (try conn.openNextBidi()).id);
    try std.testing.expectEqual(@as(u64, 4), (try conn.openNextBidi()).id);

    const first_uni = try conn.openNextUni();
    try std.testing.expectEqual(@as(u64, 2), first_uni.id);
    try std.testing.expectEqual(@as(u64, 6), (try conn.openNextUni()).id);
    try std.testing.expectEqual(StreamType.client_uni, StreamType.fromId(first_uni.id));
    try std.testing.expectEqual(StreamType.client_bidi, conn.localStreamType(false));
}

test "openNext* choose server-initiated ids for a server" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();
    conn.peer_max_streams_bidi = 100;
    conn.peer_max_streams_uni = 100;

    try std.testing.expectEqual(@as(u64, 1), (try conn.openNextBidi()).id);
    try std.testing.expectEqual(@as(u64, 5), (try conn.openNextBidi()).id);
    try std.testing.expectEqual(@as(u64, 3), (try conn.openNextUni()).id);
    try std.testing.expectEqual(StreamType.server_uni, conn.localStreamType(true));
}

test "peekNextBidi / peekNextUni return the next id without consuming it" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.peer_max_streams_bidi = 100;
    conn.peer_max_streams_uni = 100;

    // Peek is idempotent — it never advances the counter.
    try std.testing.expectEqual(@as(u64, 0), conn.peekNextBidi());
    try std.testing.expectEqual(@as(u64, 0), conn.peekNextBidi());
    try std.testing.expectEqual(@as(u64, 2), conn.peekNextUni());
    try std.testing.expectEqual(@as(u64, 2), conn.peekNextUni());

    // The peeked id is exactly what the matching openNext* then consumes,
    // and the peek advances only once the open succeeds.
    try std.testing.expectEqual(conn.peekNextBidi(), (try conn.openNextBidi()).id);
    try std.testing.expectEqual(@as(u64, 4), conn.peekNextBidi());
    try std.testing.expectEqual(conn.peekNextUni(), (try conn.openNextUni()).id);
    try std.testing.expectEqual(@as(u64, 6), conn.peekNextUni());
}

test "beginGracefulShutdown withholds MAX_STREAMS credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.local_max_streams_bidi = 10;
    // Normally, granting more credit advances the limit and queues a frame.
    conn.queueMaxStreams(true, 20);
    try std.testing.expectEqual(@as(u64, 20), conn.local_max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 20), conn.pending_frames.max_streams_bidi);
    conn.pending_frames.max_streams_bidi = null;

    // After graceful shutdown, credit freezes: no advance, no queued frame.
    conn.beginGracefulShutdown();
    conn.queueMaxStreams(true, 50);
    try std.testing.expectEqual(@as(u64, 20), conn.local_max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_bidi);
}

test "send-side STREAM emission is capped by flow-control allowance" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_data = 4;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 8;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), limited.length);
    try std.testing.expect(!limited.fin);

    conn.recordStreamFlowSent(s, limited);
    try std.testing.expectEqual(@as(u64, 4), conn.we_sent_stream_data);
    try std.testing.expectEqual(@as(u64, 4), s.send_flow_highest);
    const retransmit_only = (try conn.limitChunkToSendFlow(s, raw)).?;
    try std.testing.expectEqual(@as(u64, 4), retransmit_only.length);
    try std.testing.expect(!retransmit_only.fin);
    try std.testing.expectEqual(@as(?u64, 4), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 4), conn.pending_frames.data_blocked);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxData(.{ .maximum_data = 16 });
    try std.testing.expectEqual(@as(?u64, null), conn.localDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
}

test "receive flow-control MAX updates are paced by half-window" {
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(!Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2 - 1,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        default_stream_receive_window / 2,
        default_stream_receive_window,
        default_stream_receive_window,
    ));
    try std.testing.expect(Connection.shouldQueueReceiveCredit(
        1,
        16,
        default_stream_receive_window,
    ));

    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_bidi_remote = default_stream_receive_window,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.max_stream_data.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_data);
}

test "stream flow block queues STREAM_DATA_BLOCKED and clears on MAX_STREAM_DATA" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_data = 16;
    conn.peer_max_streams_bidi = 1;
    const s = try conn.openBidi(0);
    s.send_max_data = 4;
    _ = try s.send.write("abcdefgh");

    const raw = s.send.peekChunk(64).?;
    const limited = (try conn.limitChunkToSendFlow(s, raw)).?;
    conn.recordStreamFlowSent(s, limited);
    _ = (try conn.limitChunkToSendFlow(s, raw)).?;

    try std.testing.expectEqual(@as(?u64, 4), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stream_data_blocked.items.len);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 0), event.flow_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 4), event.flow_blocked.limit);

    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 8 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamDataBlockedAt(0));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
}

test "STREAMS_BLOCKED is queued when local stream opening hits peer limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_streams_bidi = 0;
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openBidi(0));
    try std.testing.expectEqual(@as(?u64, 0), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_frames.streams_blocked_bidi);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, true), event.flow_blocked.bidi);

    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = 1 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamsBlockedAt(true));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);
}

test "blocked frames emit with retransmit metadata and requeue on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);

    var out: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &out, 1_000)).?;
    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 3), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[1] == .stream_data_blocked);
    try std.testing.expect(sent.retransmit_frames.items[2] == .streams_blocked);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(?u64, 7), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, 3), conn.pending_frames.streams_blocked_bidi);
}

test "stale blocked frames are not requeued after peer raises limits" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.noteDataBlocked(7);
    try conn.noteStreamDataBlocked(0, 11);
    conn.noteStreamsBlocked(true, 3);
    conn.clearLocalDataBlocked(8);
    conn.clearLocalStreamDataBlocked(0, 12);
    conn.clearLocalStreamsBlocked(true, 4);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 9,
        .sent_time_us = 1_000,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);
    try packet.addRetransmitFrame(allocator, .{ .data_blocked = .{ .maximum_data = 7 } });
    try packet.addRetransmitFrame(allocator, .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 11,
    } });
    try packet.addRetransmitFrame(allocator, .{ .streams_blocked = .{
        .bidi = true,
        .maximum_streams = 3,
    } });

    try std.testing.expect(!(try conn.dispatchLostControlFrames(&packet)));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.data_blocked);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.stream_data_blocked.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_bidi);
}

test "inbound blocked frames update peer state and pollable events" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{ .initial_max_streams_bidi = 2 });
    conn.handleDataBlocked(.{ .maximum_data = 10 });
    try conn.handleStreamDataBlocked(.{ .stream_id = 4, .maximum_stream_data = 20 });
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = 2 });

    try std.testing.expectEqual(@as(?u64, 10), conn.peerDataBlockedAt());
    try std.testing.expectEqual(@as(?u64, 20), conn.peerStreamDataBlockedAt(4));
    try std.testing.expectEqual(@as(?u64, 2), conn.peerStreamsBlockedAt(false));

    var event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.peer, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.data, event.flow_blocked.kind);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.stream_data, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?u64, 4), event.flow_blocked.stream_id);

    event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, false), event.flow_blocked.bidi);
}

test "draining a peer-initiated stream returns MAX_STREAMS credit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = 1,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, 17), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 17), conn.local_max_streams_bidi);
}

test "MAX_STREAMS replenishes early enough for pipelining peers" {
    // Regression test: with `initial_max_streams_bidi = 1000` (the cap the
    // interop `multiplexing` testcase enforces), a peer that pipelines
    // streams aggressively (notably quiche) must observe a MAX_STREAMS
    // increase well before it has consumed the full initial allotment.
    // The previous 1/2 watermark held credit until the peer had drained
    // 500 streams, by which point quiche's RTT-windowed burst could
    // already exhaust the cap. The 1/4 watermark issues credit after the
    // peer has drained ~250 streams, leaving headroom for the in-flight
    // burst before it actually hits the limit.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    const initial_limit: u64 = 1000;
    try conn.setTransportParams(.{
        .initial_max_data = 64 * 1024,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = initial_limit,
    });

    // Drain peer-initiated bidi streams 0, 4, 8, ... one at a time and
    // capture the stream count at the moment the first MAX_STREAMS frame
    // gets queued.
    var first_grant_at: ?u64 = null;
    var first_grant_limit: ?u64 = null;
    var i: u64 = 0;
    while (i < initial_limit) : (i += 1) {
        const sid = i * 4; // client-initiated bidi: 4n
        try conn.handleStream(.application, .{
            .stream_id = sid,
            .offset = 0,
            .data = "x",
            .has_length = true,
            .fin = true,
        });
        var buf: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(sid, &buf));
        if (first_grant_at == null) {
            if (conn.pending_frames.max_streams_bidi) |new_limit| {
                first_grant_at = i + 1;
                first_grant_limit = new_limit;
                break;
            }
        }
    }

    // Credit must arrive while the peer still has substantial pipelining
    // headroom: strictly before half the initial allotment is consumed.
    // The previous 1/2 watermark only fired AT 500 streams drained, which
    // was too late for quiche's RTT-windowed burst — we now fire by ~250
    // (i.e. once a quarter of the cap is consumed).
    try std.testing.expect(first_grant_at != null);
    try std.testing.expect(first_grant_at.? < initial_limit / 2);
    // And the new advertised limit must strictly advance past the cap so
    // an in-flight pipelined burst beyond `initial_limit` has somewhere
    // to land.
    try std.testing.expect(first_grant_limit != null);
    try std.testing.expect(first_grant_limit.? > initial_limit);
    try std.testing.expectEqual(first_grant_limit.?, conn.local_max_streams_bidi);
}

test "draining at stream cap does not queue duplicate MAX_STREAMS" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_streams_bidi = max_streams_per_connection,
    });
    try conn.handleStream(.application, .{
        .stream_id = 0,
        .offset = 0,
        .data = "x",
        .has_length = true,
        .fin = true,
    });

    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(max_streams_per_connection, conn.local_max_streams_bidi);
}

test "PATH_CIDS_BLOCKED cannot skip local cid sequence numbers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 2 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "PATH_CIDS_BLOCKED can be surfaced and replenished within peer active cid limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 1,
        .active_connection_id_limit = 3,
    };
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));

    conn.handlePathCidsBlocked(.{ .path_id = path_id, .next_sequence_number = 1 });
    const blocked = conn.pendingPathCidsBlocked().?;
    try std.testing.expectEqual(path_id, blocked.path_id);
    try std.testing.expectEqual(@as(u64, 1), blocked.next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.path_cids_blocked, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(?u64, 1), event.connection_ids_needed.blocked_next_sequence_number);
    try std.testing.expectEqual(@as(usize, 2), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(?PathCidsBlockedInfo, null), conn.pendingPathCidsBlocked());
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(path_id));
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 3), conn.nextLocalConnectionIdSequence(path_id));

    try std.testing.expectError(
        Error.ConnectionIdLimitExceeded,
        conn.queuePathNewConnectionId(path_id, 3, 0, &.{0xc5}, @splat(0xc5)),
    );
    try conn.queuePathNewConnectionId(path_id, 3, 1, &.{0xc5}, @splat(0xc5));
    try std.testing.expectEqual(@as(usize, 3), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 4), conn.nextLocalConnectionIdSequence(path_id));
}

test "PATHS_BLOCKED below current local limit is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 2);
    conn.handlePathsBlocked(.{ .maximum_path_id = 1 });
    try std.testing.expectEqual(@as(?u32, null), conn.peer_paths_blocked_at);
    conn.handlePathsBlocked(.{ .maximum_path_id = 2 });
    try std.testing.expectEqual(@as(?u32, 2), conn.peer_paths_blocked_at);
}
