// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
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
const max_concurrent_streams_per_kind = state.max_concurrent_streams_per_kind;
const max_supported_active_connection_id_limit = state.max_supported_active_connection_id_limit;
const max_supported_path_id = state.max_supported_path_id;
const max_tracked_stream_data_blocked = state.max_tracked_stream_data_blocked;
const min_quic_udp_payload_size = state.min_quic_udp_payload_size;
const SentPacketTracker = state.SentPacketTracker;
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
        .initial_max_streams_bidi = max_concurrent_streams_per_kind + 1,
    }));
    try std.testing.expectError(error.InvalidValue, conn.setTransportParams(.{
        .initial_max_streams_uni = max_concurrent_streams_per_kind + 1,
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

test "bounded policy: a manual MAX_STREAMS, MAX_PATH_ID and peer CID fanout are clamped; a peer's MAX_STREAMS is not" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // What the PEER grants is taken as sent, in its transport parameters
    // and in MAX_STREAMS. There is no ceiling on the streams a
    // connection opens over its life but the id space.
    conn.cached_peer_transport_params = .{
        .initial_max_streams_bidi = 100_000,
        .initial_max_streams_uni = max_stream_count_limit,
    };
    conn.validatePeerTransportLimits();
    try std.testing.expectEqual(@as(u64, 100_000), conn.local_bidi_ids.limit);
    try std.testing.expectEqual(max_stream_count_limit, conn.local_uni_ids.limit);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());

    conn.local_bidi_ids.limit = 0;
    conn.local_uni_ids.limit = 0;
    conn.handleMaxStreams(.{ .bidi = true, .maximum_streams = max_concurrent_streams_per_kind + 100 });
    conn.handleMaxStreams(.{ .bidi = false, .maximum_streams = max_stream_count_limit });
    try std.testing.expectEqual(max_concurrent_streams_per_kind + 100, conn.local_bidi_ids.limit);
    try std.testing.expectEqual(max_stream_count_limit, conn.local_uni_ids.limit);
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());

    // What WE grant by hand is bounded: never more than
    // `max_concurrent_streams_per_kind` ahead of the streams that have
    // closed, so a peer can never have more than that open at once.
    conn.queueMaxStreams(true, max_concurrent_streams_per_kind + 100);
    conn.queueMaxStreams(false, max_concurrent_streams_per_kind + 100);
    try std.testing.expectEqual(max_concurrent_streams_per_kind, conn.peer_bidi_ids.limit);
    try std.testing.expectEqual(max_concurrent_streams_per_kind, conn.peer_uni_ids.limit);
    try std.testing.expectEqual(max_concurrent_streams_per_kind, conn.pending_frames.max_streams_bidi.?);
    try std.testing.expectEqual(max_concurrent_streams_per_kind, conn.pending_frames.max_streams_uni.?);
    // Ten streams have closed: ten more ids may be given.
    conn.peer_bidi_ids.closed = 10;
    conn.queueMaxStreams(true, max_stream_count_limit);
    try std.testing.expectEqual(max_concurrent_streams_per_kind + 10, conn.peer_bidi_ids.limit);
    try std.testing.expectEqual(max_concurrent_streams_per_kind + 10, conn.pending_frames.max_streams_bidi.?);

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
    conn.local_bidi_ids.limit = 1;
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

test "sendWindow / streamSendWindow report credit, backlog, and net writable" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    });
    try installTestApplicationWriteSecret(conn);

    conn.peer_max_data = 10_000;
    const s0 = try conn.openBidi(0);
    s0.send_max_data = 6_000;

    // Fresh stream: full credits, nothing queued, stream limit binds.
    try std.testing.expectEqual(@as(u64, 10_000), conn.sendWindow());
    var w = conn.streamSendWindow(0).?;
    try std.testing.expectEqual(@as(u64, 10_000), w.connection);
    try std.testing.expectEqual(@as(u64, 6_000), w.stream);
    try std.testing.expectEqual(@as(u64, 0), w.queued);
    try std.testing.expectEqual(@as(u64, 6_000), w.writable);

    // Buffered-but-unsent bytes shrink writable without touching the
    // credits — nothing is on the wire yet.
    var data: [2_000]u8 = @splat(0xab);
    try std.testing.expectEqual(@as(usize, 2_000), try conn.streamWrite(0, &data));
    w = conn.streamSendWindow(0).?;
    try std.testing.expectEqual(@as(u64, 10_000), w.connection);
    try std.testing.expectEqual(@as(u64, 6_000), w.stream);
    try std.testing.expectEqual(@as(u64, 2_000), w.queued);
    try std.testing.expectEqual(@as(u64, 4_000), w.writable);

    // On the wire: both credit levels fall by the sent bytes, the
    // queue drains, and writable is unchanged (the same bytes moved
    // from "queued" to "spent").
    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    while (try conn.pollDatagram(&pkt, now_us)) |_| now_us += 100;
    w = conn.streamSendWindow(0).?;
    try std.testing.expectEqual(@as(u64, 8_000), w.connection);
    try std.testing.expectEqual(@as(u64, 8_000), conn.sendWindow());
    try std.testing.expectEqual(@as(u64, 4_000), w.stream);
    try std.testing.expectEqual(@as(u64, 0), w.queued);
    try std.testing.expectEqual(@as(u64, 4_000), w.writable);

    // Peer window raises are visible immediately.
    conn.handleMaxStreamData(.{ .stream_id = 0, .maximum_stream_data = 9_000 });
    w = conn.streamSendWindow(0).?;
    try std.testing.expectEqual(@as(u64, 7_000), w.stream);
    try std.testing.expectEqual(@as(u64, 7_000), w.writable);

    // A second stream draws on the SAME connection credit: its
    // generous stream window is capped by the shared 8_000.
    conn.local_bidi_ids.limit = 4;
    const s4 = try conn.openBidi(4);
    s4.send_max_data = 100_000;
    const w4 = conn.streamSendWindow(4).?;
    try std.testing.expectEqual(@as(u64, 8_000), w4.connection);
    try std.testing.expectEqual(@as(u64, 100_000), w4.stream);
    try std.testing.expectEqual(@as(u64, 8_000), w4.writable);

    // Guards: a peer-initiated uni stream is never sendable by us,
    // and unknown streams report null rather than zero.
    try std.testing.expectEqual(@as(?state.SendWindow, null), conn.streamSendWindow(3));
    try std.testing.expectEqual(@as(?state.SendWindow, null), conn.streamSendWindow(8));
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
    conn.local_bidi_ids.limit = 100;
    conn.local_uni_ids.limit = 100;

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
    conn.local_bidi_ids.limit = 100;
    conn.local_uni_ids.limit = 100;

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
    conn.local_bidi_ids.limit = 100;
    conn.local_uni_ids.limit = 100;

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

    conn.peer_bidi_ids.limit = 10;
    // Normally, granting more credit advances the limit and queues a frame.
    conn.queueMaxStreams(true, 20);
    try std.testing.expectEqual(@as(u64, 20), conn.peer_bidi_ids.limit);
    try std.testing.expectEqual(@as(?u64, 20), conn.pending_frames.max_streams_bidi);
    conn.pending_frames.max_streams_bidi = null;

    // After graceful shutdown, credit freezes: no advance, no queued frame.
    conn.beginGracefulShutdown();
    conn.queueMaxStreams(true, 50);
    try std.testing.expectEqual(@as(u64, 20), conn.peer_bidi_ids.limit);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_bidi);
}

test "send-side STREAM emission is capped by flow-control allowance" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.peer_max_data = 4;
    conn.local_bidi_ids.limit = 1;
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
    conn.local_bidi_ids.limit = 1;
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

    conn.local_bidi_ids.limit = 0;
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

test "uni STREAMS_BLOCKED is queued, requeued on loss, and cleared by MAX_STREAMS" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.local_uni_ids.limit = 0;
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openUni(2));
    try std.testing.expectEqual(@as(?u64, 0), conn.localStreamsBlockedAt(false));
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_frames.streams_blocked_uni);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .flow_blocked);
    try std.testing.expectEqual(FlowBlockedSource.local, event.flow_blocked.source);
    try std.testing.expectEqual(FlowBlockedKind.streams, event.flow_blocked.kind);
    try std.testing.expectEqual(@as(?bool, false), event.flow_blocked.bidi);

    // Pretend the frame was emitted, then lost: while the local uni
    // blocked state still matches, the loss path requeues it.
    conn.pending_frames.streams_blocked_uni = null;
    var packet: SentPacketTracker.SentPacket = .{
        .pn = 9,
        .sent_time_us = 1_000,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);
    try packet.addRetransmitFrame(allocator, .{ .streams_blocked = .{
        .bidi = false,
        .maximum_streams = 0,
    } });
    try std.testing.expect(try conn.dispatchLostControlFrames(&packet));
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_frames.streams_blocked_uni);

    conn.handleMaxStreams(.{ .bidi = false, .maximum_streams = 1 });
    try std.testing.expectEqual(@as(?u64, null), conn.localStreamsBlockedAt(false));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.streams_blocked_uni);
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

    var packet: SentPacketTracker.SentPacket = .{
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

/// A server with a window of `uni` peer-opened unidirectional streams
/// and `bidi` bidirectional ones.
fn windowServer(ctx: boringssl.tls.Context, bidi: u64, uni: u64) !*Connection {
    const conn = try Connection.createServer(std.testing.allocator, ctx);
    errdefer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 16,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_stream_data_uni = 64,
        .initial_max_streams_bidi = bidi,
        .initial_max_streams_uni = uni,
    });
    return conn;
}

/// The id of the client-initiated unidirectional stream at `index`.
fn peerUni(index: u64) u64 {
    return index * 4 + 2;
}

/// One byte and FIN arrive on the peer's uni stream at `index`, the
/// application reads it, and a tick reaps the stream.
fn openReadReapPeerUni(conn: *Connection, index: u64) !void {
    const sid = peerUni(index);
    try conn.handleStream(.application, .{ .stream_id = sid, .offset = 0, .data = "x", .has_length = true, .fin = true });
    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(sid, &buf));
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(sid) == null);
}

test "stream credit: a window of one is one stream at a time, for as long as you like" {
    // The limit is the window plus the streams that closed. Under the
    // rule this replaces, a limit of 1 became 17 after one close, so
    // `initial_max_streams_*` did not bound concurrency.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 1);
    defer conn.destroy();

    var i: u64 = 0;
    while (i < 20) : (i += 1) {
        try std.testing.expectEqual(i + 1, conn.peer_uni_ids.limit);
        try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
        try openReadReapPeerUni(conn, i);
        // One stream closed: one more id, and the peer has none left,
        // so it is told at once.
        try std.testing.expectEqual(@as(?u64, i + 2), conn.pending_frames.max_streams_uni);
        try std.testing.expectEqual(i + 2, conn.peer_uni_ids.limit);
        conn.pending_frames.max_streams_uni = null; // the frame was sent
    }
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
}

test "stream credit: half a window at a time while the peer still has ids" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 8);
    defer conn.destroy();

    // Three streams open and close, one after the other. Three ids of
    // credit is less than half the window of eight, and the peer has
    // five unused ids: nothing is sent yet.
    for (0..3) |i| try openReadReapPeerUni(conn, i);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 8), conn.peer_uni_ids.limit);

    // The fourth close makes half a window: one frame returns all four.
    try openReadReapPeerUni(conn, 3);
    try std.testing.expectEqual(@as(?u64, 12), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 12), conn.peer_uni_ids.limit);
}

test "stream credit: given at once when the peer has used every id" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 4);
    defer conn.destroy();

    // The peer opens all four streams and keeps them open.
    for (0..4) |i| {
        try conn.handleStream(.application, .{ .stream_id = peerUni(i), .offset = 0, .data = "x", .has_length = true });
    }
    try std.testing.expectEqual(@as(usize, 4), conn.streamCount());
    // A fifth is over the limit. (Checked on a second connection below;
    // here the connection must stay open.)

    // One of them finishes. One id of credit is less than half a
    // window, but the peer has no id left: it is told at once.
    try conn.handleStream(.application, .{ .stream_id = peerUni(0), .offset = 1, .data = "", .has_length = true, .fin = true });
    var buf: [1]u8 = undefined;
    _ = try conn.streamRead(peerUni(0), &buf);
    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(?u64, 5), conn.pending_frames.max_streams_uni);
    // Three live streams and one free id: the window of four.
    try std.testing.expectEqual(@as(usize, 3), conn.streamCount());
    try std.testing.expectEqual(@as(u64, 3), conn.peer_uni_ids.inUse());
    try std.testing.expectEqual(@as(u64, 5), conn.peer_uni_ids.limit);
}

test "stream credit: the window bounds the streams that are open at once" {
    // With W streams open, stream W + 1 is STREAM_LIMIT_ERROR, however
    // many streams the connection has closed before.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 2);
    defer conn.destroy();

    for (0..10) |i| try openReadReapPeerUni(conn, i);
    try std.testing.expectEqual(@as(u64, 12), conn.peer_uni_ids.limit);
    // Two open at once: fine.
    try conn.handleStream(.application, .{ .stream_id = peerUni(10), .offset = 0, .data = "x", .has_length = true });
    try conn.handleStream(.application, .{ .stream_id = peerUni(11), .offset = 0, .data = "x", .has_length = true });
    try std.testing.expectEqual(state.CloseState.open, conn.closeState());
    // A third, with two still open: the peer broke the limit.
    try conn.handleStream(.application, .{ .stream_id = peerUni(12), .offset = 0, .data = "x", .has_length = true });
    try std.testing.expectEqual(transport_error_stream_limit, conn.closeEvent().?.error_code);
}

test "stream credit: a bidirectional stream returns its id when both directions are done" {
    // The window counts a stream until it is fully closed. If the id
    // came back when only the peer's side was done, a peer could keep
    // any number of half-open streams alive here.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 2, 0);
    defer conn.destroy();

    // The request arrives complete, and the application reads it.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "x", .has_length = true, .fin = true });
    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(0, &buf));
    try conn.tick(1_000_000);
    // Our side is still open: the stream is live and holds its id.
    try std.testing.expect(conn.stream(0) != null);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 2), conn.peer_bidi_ids.limit);

    // The reply is finished and its FIN is acknowledged.
    try conn.streamFinish(0);
    const s = conn.stream(0).?;
    s.send.fin_acked = true;
    s.send.state = .data_recvd;
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(0) == null);
    try std.testing.expectEqual(@as(?u64, 3), conn.pending_frames.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_bidi_ids.limit);
}

test "stream credit: a FIN that arrives after the data was read still returns the id" {
    // The credit used to be returned from two call sites (after a read,
    // and on RESET_STREAM). A FIN-only frame that arrived after the
    // application had read every byte passed through neither.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 1);
    defer conn.destroy();

    const sid = peerUni(0);
    try conn.handleStream(.application, .{ .stream_id = sid, .offset = 0, .data = "x", .has_length = true });
    var buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try conn.streamRead(sid, &buf));
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(sid) != null);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);

    // The FIN comes alone, and nobody reads again.
    try conn.handleStream(.application, .{ .stream_id = sid, .offset = 1, .data = "", .has_length = true, .fin = true });
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(sid) == null);
    try std.testing.expectEqual(@as(?u64, 2), conn.pending_frames.max_streams_uni);
}

test "stream credit: a peer RESET_STREAM returns the id" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 1);
    defer conn.destroy();

    const sid = peerUni(0);
    try conn.handleStream(.application, .{ .stream_id = sid, .offset = 0, .data = "x", .has_length = true });
    try conn.handleResetStream(.{ .stream_id = sid, .application_error_code = 7, .final_size = 1 });
    try conn.tick(1_000_000);
    try std.testing.expect(conn.stream(sid) == null);
    try std.testing.expectEqual(@as(?u64, 2), conn.pending_frames.max_streams_uni);
}

test "stream credit: STREAMS_BLOCKED at the current limit releases held credit" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 8);
    defer conn.destroy();

    // One id of credit is held back: less than half a window, and by
    // our count the peer has seven ids left.
    try openReadReapPeerUni(conn, 0);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);

    // A STREAMS_BLOCKED below the limit is stale: it answers a limit
    // the peer has since passed. Nothing to do.
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = 7 });
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    // And one for the other kind of stream does not release this kind.
    conn.handleStreamsBlocked(.{ .bidi = true, .maximum_streams = 0 });
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);

    // The peer says it is blocked at the limit we gave it. It knows
    // better than our count: the credit goes out now.
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = 8 });
    try std.testing.expectEqual(@as(?u64, 9), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 9), conn.peer_uni_ids.limit);
}

test "stream credit: none under graceful shutdown" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 1);
    defer conn.destroy();

    conn.beginGracefulShutdown();
    try openReadReapPeerUni(conn, 0);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_uni_ids.limit);
}

test "stream credit: a skipped id holds its place in the window" {
    // The peer uses stream 3 first. Streams 0 to 2 are open too
    // (RFC 9000 §2.1) and have not closed, so all four units are in
    // use; closing stream 3 frees one.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 4);
    defer conn.destroy();

    // While stream 3 is open, a fifth stream is over the limit: the
    // three skipped ids count. (The limit check is on the id, so this
    // is just `limit == 4`.)
    try std.testing.expectEqual(@as(u64, 4), conn.peer_uni_ids.limit);
    try openReadReapPeerUni(conn, 3);
    // One unit came back, the three skipped ids keep theirs, and the
    // peer has used every id it had: it is told at once.
    try std.testing.expectEqual(@as(?u64, 5), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_uni_ids.inUse());
    try std.testing.expectEqual(@as(u64, 3), conn.peer_uni_ids.holeCount());

    // The skipped streams arrive late and close: their units come back.
    conn.pending_frames.max_streams_uni = null;
    for (0..3) |i| try openReadReapPeerUni(conn, i);
    try std.testing.expectEqual(@as(u64, 0), conn.peer_uni_ids.holeCount());
    try std.testing.expectEqual(@as(u64, 0), conn.peer_uni_ids.inUse());
    try std.testing.expectEqual(@as(u64, 8), conn.peer_uni_ids.target());
    // Half a window (two ids) went out in one frame; the last id waits
    // for its own half window, since the peer now has ids to spare.
    try std.testing.expectEqual(@as(?u64, 7), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 7), conn.peer_uni_ids.limit);
}

test "stream credit: credit held for batching goes out when the peer uses its last id" {
    // One stream of four closed while the peer still had ids to spare:
    // one id of credit, less than half the window, is held back. Then
    // the peer opens the rest. It now has three streams live in a
    // window of four, and no id to open the fourth with. An endpoint
    // must not wait for STREAMS_BLOCKED before it gives credit (RFC
    // 9000 §4.6), and these three streams may stay open for a long
    // time: the id goes out when the last one is used.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, 4);
    defer conn.destroy();

    try openReadReapPeerUni(conn, 0);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    try conn.handleStream(.application, .{ .stream_id = peerUni(1), .offset = 0, .data = "x", .has_length = true });
    try conn.handleStream(.application, .{ .stream_id = peerUni(2), .offset = 0, .data = "x", .has_length = true });
    // The peer still has one id.
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    try conn.handleStream(.application, .{ .stream_id = peerUni(3), .offset = 0, .data = "x", .has_length = true });
    try std.testing.expectEqual(@as(?u64, 5), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 5), conn.peer_uni_ids.limit);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_uni_ids.inUse());
}

test "stream credit: the last id can be used by a jump over lower ids, or by RESET_STREAM" {
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    {
        // Stream 3 arrives first. Streams 1 and 2 are open with it
        // (RFC 9000 §2.1), so every id is used.
        const conn = try windowServer(ctx, 0, 4);
        defer conn.destroy();
        try openReadReapPeerUni(conn, 0);
        try conn.handleStream(.application, .{ .stream_id = peerUni(3), .offset = 0, .data = "x", .has_length = true });
        try std.testing.expectEqual(@as(?u64, 5), conn.pending_frames.max_streams_uni);
    }
    {
        // The frame that opens the last stream is a RESET_STREAM.
        const conn = try windowServer(ctx, 0, 4);
        defer conn.destroy();
        try openReadReapPeerUni(conn, 0);
        try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
        try conn.handleResetStream(.{ .stream_id = peerUni(3), .application_error_code = 0, .final_size = 0 });
        try std.testing.expectEqual(@as(?u64, 5), conn.pending_frames.max_streams_uni);
    }
}

test "stream credit: at the largest window the limit still rises past it" {
    // There is no lifetime cap. With the window at the largest value
    // the transport parameters accept, a closed stream is still one
    // more id, and the limit goes past `max_concurrent_streams_per_kind`.
    // (This number was a ceiling on the limit itself through 0.23.0: a
    // connection stopped at 4096 streams of each type.)
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try windowServer(ctx, 0, max_concurrent_streams_per_kind);
    defer conn.destroy();

    try openReadReapPeerUni(conn, 0);
    // One id is far less than half the window and the peer has ids to
    // spare, so it is held for batching.
    try std.testing.expectEqual(@as(?u64, null), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(max_concurrent_streams_per_kind, conn.peer_uni_ids.limit);
    // A STREAMS_BLOCKED at the limit releases it.
    conn.handleStreamsBlocked(.{ .bidi = false, .maximum_streams = max_concurrent_streams_per_kind });
    try std.testing.expectEqual(@as(?u64, max_concurrent_streams_per_kind + 1), conn.pending_frames.max_streams_uni);
    try std.testing.expectEqual(max_concurrent_streams_per_kind + 1, conn.peer_uni_ids.limit);
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

test "RFC 9000 §7.4.1: earlyDataParamReduced flags exactly the seven 0-RTT-load-bearing limits" {
    const base: state.TransportParams = .{
        .active_connection_id_limit = 4,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 16,
        .initial_max_stream_data_bidi_remote = 1 << 16,
        .initial_max_stream_data_uni = 1 << 16,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 4,
    };

    // Identical and strictly-raised parameters are both fine.
    try std.testing.expectEqual(@as(?[]const u8, null), state.earlyDataParamReduced(base, base));
    var raised = base;
    raised.initial_max_data += 1;
    raised.initial_max_streams_uni += 1;
    try std.testing.expectEqual(@as(?[]const u8, null), state.earlyDataParamReduced(raised, base));

    // Each of the seven, reduced alone, is flagged by name.
    const fields = .{
        "active_connection_id_limit",
        "initial_max_data",
        "initial_max_stream_data_bidi_local",
        "initial_max_stream_data_bidi_remote",
        "initial_max_stream_data_uni",
        "initial_max_streams_bidi",
        "initial_max_streams_uni",
    };
    inline for (fields) |name| {
        var reduced = base;
        @field(reduced, name) -= 1;
        const hit = state.earlyDataParamReduced(reduced, base) orelse
            return error.ReductionNotFlagged;
        try std.testing.expectEqualStrings(name, hit);
    }

    // Parameters OUTSIDE the §7.4.1 set may shrink freely (e.g.
    // max_idle_timeout is renegotiated, not relied upon by 0-RTT).
    var other = base;
    other.max_idle_timeout_ms = 1;
    try std.testing.expectEqual(@as(?[]const u8, null), state.earlyDataParamReduced(other, base));
}
