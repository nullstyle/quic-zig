// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const c = boringssl.raw;
const Connection = state.Connection;
const StreamType = state.StreamType;
const Error = state.Error;
const RecvStream = state.RecvStream;
const SendStream = state.SendStream;
const Stream = state.Stream;
const StreamSendStats = state.StreamSendStats;
const StreamRecvState = state.StreamRecvState;
const StreamPriority = state.StreamPriority;
const application_ack_eliciting_threshold = state.application_ack_eliciting_threshold;
const default_connection_receive_window = state.default_connection_receive_window;
const default_stream_receive_window = state.default_stream_receive_window;
const frame_mod = state.frame_mod;
const long_packet_mod = state.long_packet_mod;
const max_streams_per_connection = state.max_streams_per_connection;
const send_stream_mod = state.send_stream_mod;
const transport_error_stream_limit = state.transport_error_stream_limit;
const util = @import("_test_util.zig");
const installTestEarlyDataReadSecret = util.installTestEarlyDataReadSecret;
const testEarlyDataPacketKeys = util.testEarlyDataPacketKeys;

test "streamReset publicly aborts the send half" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 5), try conn.streamWrite(0, "hello"));
    try conn.streamReset(0, 0xdead);

    const s = conn.stream(0).?;
    try std.testing.expectEqual(send_stream_mod.State.reset_sent, s.send.state);
    try std.testing.expect(s.send.reset != null);
    try std.testing.expectEqual(@as(u64, 0xdead), s.send.reset.?.error_code);
    try std.testing.expectEqual(@as(u64, 5), s.send.reset.?.final_size);
    try std.testing.expectError(send_stream_mod.Error.StreamClosed, conn.streamWrite(0, "late"));
    try std.testing.expectError(Error.StreamNotFound, conn.streamReset(4, 0));
}

test "streamSendStats snapshots the send half; null for missing streams" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Unopened stream → null (same signal a reaped stream gives).
    try std.testing.expectEqual(@as(?StreamSendStats, null), conn.streamSendStats(0));

    _ = try conn.openBidi(0);
    try std.testing.expectEqual(@as(usize, 11), try conn.streamWrite(0, "hello world"));

    const stats = conn.streamSendStats(0) orelse return error.MissingStats;
    try std.testing.expectEqual(@as(u64, 11), stats.written);
    try std.testing.expectEqual(@as(u64, 0), stats.acked); // nothing acked yet
    try std.testing.expectEqual(@as(u64, 11), stats.buffered); // written - acked
    try std.testing.expect(stats.has_pending); // buffered, unsent

    // A never-opened higher id is still null, not a resurrected zero-stat stream.
    try std.testing.expectEqual(@as(?StreamSendStats, null), conn.streamSendStats(400));
}

test "send scheduler orders ready streams by RFC 9218 priority (urgency then id)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 4096,
        .initial_max_streams_bidi = max_streams_per_connection,
    });

    // Three client bidi streams (ids 0, 4, 8), each with a pending send byte.
    _ = try conn.openBidi(0);
    _ = try conn.openBidi(4);
    _ = try conn.openBidi(8);
    _ = try conn.streamWrite(0, "a");
    _ = try conn.streamWrite(4, "b");
    _ = try conn.streamWrite(8, "c");

    var buf: [8]*Stream = undefined;

    // Default: every stream is urgency 3, so the scheduler order is stream-id
    // ascending (deterministic, independent of hash-map iteration order).
    {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 3), ready.len);
        try std.testing.expectEqual(@as(u64, 0), ready[0].id);
        try std.testing.expectEqual(@as(u64, 4), ready[1].id);
        try std.testing.expectEqual(@as(u64, 8), ready[2].id);
    }

    // Invert by urgency: stream 8 most urgent, stream 0 least. Urgency wins
    // over stream id, so the order becomes 8, 4, 0.
    try conn.streamSetPriority(8, .{ .urgency = 0 });
    try conn.streamSetPriority(4, .{ .urgency = 3 });
    try conn.streamSetPriority(0, .{ .urgency = 7 });
    {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 3), ready.len);
        try std.testing.expectEqual(@as(u64, 8), ready[0].id);
        try std.testing.expectEqual(@as(u64, 4), ready[1].id);
        try std.testing.expectEqual(@as(u64, 0), ready[2].id);
    }

    // streamPriority reflects the set value; unknown/reaped id → null, and
    // setting priority on an absent stream is a typed error.
    try std.testing.expectEqual(@as(u3, 0), conn.streamPriority(8).?.urgency);
    try std.testing.expectEqual(@as(?StreamPriority, null), conn.streamPriority(400));
    try std.testing.expectError(error.StreamNotFound, conn.streamSetPriority(400, .{}));
}

test "send scheduler: non-incremental leads its band, incremental streams round-robin" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 4096,
        .initial_max_streams_bidi = max_streams_per_connection,
    });

    // Same urgency: three incremental streams (0, 4, 8) plus one
    // non-incremental (12), each with pending send data.
    for ([_]u64{ 0, 4, 8, 12 }) |id| {
        _ = try conn.openBidi(id);
        _ = try conn.streamWrite(id, "x");
    }
    try conn.streamSetPriority(0, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(4, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(8, .{ .urgency = 3, .incremental = true });
    try conn.streamSetPriority(12, .{ .urgency = 3, .incremental = false });

    var buf: [8]*Stream = undefined;
    var incremental_leads: [3]u64 = undefined;
    for (&incremental_leads) |*lead| {
        const ready = conn.collectSendableStreamsByPriority(&buf);
        try std.testing.expectEqual(@as(usize, 4), ready.len);
        // The non-incremental stream always leads the band (head-of-line).
        try std.testing.expectEqual(@as(u64, 12), ready[0].id);
        try std.testing.expect(!ready[0].priority.incremental);
        // The incremental streams follow; which one is first rotates.
        try std.testing.expect(ready[1].priority.incremental);
        lead.* = ready[1].id;
    }
    // Over three packets each incremental stream leads once — a fair rotation,
    // not the same stream monopolizing the band.
    try std.testing.expect(incremental_leads[0] != incremental_leads[1]);
    try std.testing.expect(incremental_leads[1] != incremental_leads[2]);
    try std.testing.expect(incremental_leads[0] != incremental_leads[2]);
}

test "streamReadFin reports FIN inline with the last read; streamRecvState tracks it" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = max_streams_per_connection,
    });

    // Unknown stream → null recv-state (the same "gone" signal a reaped
    // stream gives, so a downstream needn't hold a *Stream across a reap).
    try std.testing.expectEqual(@as(?StreamRecvState, null), conn.streamRecvState(0));

    _ = try conn.openBidi(0);

    // Peer sends 3 bytes, no FIN yet.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 0, .data = "abc", .has_length = true, .fin = false });
    {
        const rs = conn.streamRecvState(0).?;
        try std.testing.expect(!rs.fin_seen and !rs.reset_seen and !rs.terminal);
    }
    var buf: [8]u8 = undefined;
    {
        const r = try conn.streamReadFin(0, &buf); // drains 3 bytes, FIN not seen yet
        try std.testing.expectEqual(@as(usize, 3), r.n);
        try std.testing.expect(!r.fin);
    }

    // Peer sends 2 more bytes WITH the FIN bit.
    try conn.handleStream(.application, .{ .stream_id = 0, .offset = 3, .data = "de", .has_length = true, .fin = true });
    {
        const r = try conn.streamReadFin(0, &buf); // the last read carries FIN inline
        try std.testing.expectEqual(@as(usize, 2), r.n);
        try std.testing.expect(r.fin);
    }
    {
        const rs = conn.streamRecvState(0).?;
        try std.testing.expect(rs.fin_seen and !rs.reset_seen and rs.terminal);
    }
}

test "streamRecvState distinguishes a peer RESET from a clean FIN" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setTransportParams(.{
        .initial_max_data = 64,
        .initial_max_stream_data_bidi_local = 64,
        .initial_max_stream_data_bidi_remote = 64,
        .initial_max_streams_bidi = max_streams_per_connection,
    });
    _ = try conn.openBidi(0);

    try conn.handleResetStream(.{ .stream_id = 0, .application_error_code = 7, .final_size = 0 });
    const rs = conn.streamRecvState(0).?;
    // RESET is terminal but is NOT a clean FIN — the distinction
    // `recvFullyTerminated` collapses.
    try std.testing.expect(!rs.fin_seen and rs.reset_seen and rs.terminal);
}

test "peer-created streams respect advertised stream count" {
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
        .data = "a",
        .has_length = true,
    });
    try std.testing.expectEqual(@as(u64, 1), conn.peer_opened_streams_bidi);
    try std.testing.expect(conn.lifecycle.pending_close == null);

    try conn.handleStream(.application, .{
        .stream_id = 4,
        .offset = 0,
        .data = "b",
        .has_length = true,
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_stream_limit, conn.lifecycle.pending_close.?.error_code);
}

test "StreamType encodes RFC 9000 §2.1 low-two-bit stream classes" {
    try std.testing.expectEqual(StreamType.client_bidi, StreamType.fromId(0));
    try std.testing.expectEqual(StreamType.server_bidi, StreamType.fromId(1));
    try std.testing.expectEqual(StreamType.client_uni, StreamType.fromId(2));
    try std.testing.expectEqual(StreamType.server_uni, StreamType.fromId(3));
    // High-index ids classify by their low two bits only.
    try std.testing.expectEqual(StreamType.client_bidi, StreamType.fromId(400));
    try std.testing.expectEqual(StreamType.server_uni, StreamType.fromId(403));

    // id composition round-trips through fromId, and the index survives.
    inline for (.{
        StreamType.client_bidi,
        StreamType.server_bidi,
        StreamType.client_uni,
        StreamType.server_uni,
    }) |t| {
        const id = t.streamId(7);
        try std.testing.expectEqual(t, StreamType.fromId(id));
        try std.testing.expectEqual(@as(u64, 7), Connection.streamIndex(id));
    }

    try std.testing.expect(StreamType.client_bidi.isBidi() and !StreamType.client_bidi.isUni());
    try std.testing.expect(StreamType.server_uni.isUni() and StreamType.server_uni.initiatedByServer());
    try std.testing.expect(StreamType.client_uni.initiatedByClient());
}

test "openNextBidi surfaces StreamLimitExceeded without consuming the id" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.peer_max_streams_bidi = 0;

    try std.testing.expectError(Error.StreamLimitExceeded, conn.openNextBidi());
    // Not consumed: after the peer raises the limit the next open reuses index 0.
    conn.peer_max_streams_bidi = 1;
    try std.testing.expectEqual(@as(u64, 0), (try conn.openNextBidi()).id);
}

test "server handles accepted 0-RTT STREAM frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    installTestEarlyDataReadSecret(conn);
    try conn.setTransportParams(.{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_remote = 1024,
        .initial_max_streams_bidi = 1,
    });
    const keys = try testEarlyDataPacketKeys();

    var payload: [64]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .has_offset = false,
        .has_length = true,
        .fin = false,
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
    if (application_ack_eliciting_threshold == 1) {
        try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.pending_ack);
    } else {
        try std.testing.expect(!conn.pnSpaceForLevel(.early_data).received.pending_ack);
    }
    try std.testing.expect(conn.pnSpaceForLevel(.early_data).received.delayed_ack_armed);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try conn.streamRead(0, &buf));
    try std.testing.expectEqualSlices(u8, "hello", buf[0..5]);
    try std.testing.expectEqual(true, conn.streamArrivedInEarlyData(0).?);
}

test "gcClosedStreams reclaims bidi streams whose send + recv halves are both terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const n: u64 = 100;
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const id = i << 2; // client-initiated bidi
        _ = try conn.openBidi(id);
        const s = conn.stream(id).?;
        // Force both halves to terminal without driving real packets.
        // Send: data_recvd (FIN ACKed, base_offset == final_size).
        s.send.fin_marked = true;
        s.send.fin_in_flight = true;
        s.send.fin_acked = true;
        s.send.final_size = 0;
        s.send.state = .data_recvd;
        // Recv: data_recvd (peer FIN seen, all bytes drained).
        s.recv.fin_seen = true;
        s.recv.final_size = 0;
        s.recv.state = .data_recvd;
    }
    try std.testing.expectEqual(@as(usize, n), conn.streamCount());

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams reclaims bidi streams whose send is reset_recvd and recv is reset_recvd" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Local RESET_STREAM, peer ACKed.
    s.send.reset = .{ .error_code = 0xdead, .final_size = 0, .queued = true, .acked = true };
    s.send.state = .reset_recvd;
    // Peer RESET_STREAM observed.
    s.recv.reset = .{ .error_code = 0xbeef, .final_size = 0 };
    s.recv.final_size = 0;
    s.recv.state = .reset_recvd;

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams keeps streams where only the send half is terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Send terminal but recv still .recv (peer hasn't FIN'd).
    s.send.fin_marked = true;
    s.send.fin_in_flight = true;
    s.send.fin_acked = true;
    s.send.final_size = 0;
    s.send.state = .data_recvd;
    // s.recv stays at default `.recv`.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 1), conn.streamCount());
    try std.testing.expect(conn.stream(0) != null);
}

test "gcClosedStreams keeps streams where only the recv half is terminal" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    _ = try conn.openBidi(0);
    const s = conn.stream(0).?;
    // Recv terminal, but local hasn't called streamFinish yet.
    s.recv.fin_seen = true;
    s.recv.final_size = 0;
    s.recv.state = .data_recvd;
    // s.send stays at default `.ready`.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 1), conn.streamCount());
    try std.testing.expect(conn.stream(0) != null);
}

test "gcClosedStreams reclaims local-initiated uni streams once send is terminal (recv unused)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Client-initiated uni: low bits 0b10 (id 2, 6, 10, ...).
    const id: u64 = 2;
    _ = try conn.openUni(id);
    const s = conn.stream(id).?;
    s.send.fin_marked = true;
    s.send.fin_in_flight = true;
    s.send.fin_acked = true;
    s.send.final_size = 0;
    s.send.state = .data_recvd;
    // recv stays at .recv — peer can't send on a local-initiated uni
    // stream, so the recv half is structurally dead from the start.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams reclaims peer-initiated uni streams once recv is terminal (send unused)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Server-initiated uni from a client connection's POV: low bits 0b11.
    const id: u64 = 3;
    // Simulate the receive-side path: bypass `recordPeerStreamOpenOrClose`
    // by reaching into the private `openStream` to plant a peer-side
    // entry without driving the full peer-side state machine.
    const ptr = try allocator.create(Stream);
    errdefer allocator.destroy(ptr);
    ptr.* = .{
        .id = id,
        .send = SendStream.init(allocator),
        .recv = RecvStream.init(allocator),
        .recv_max_data = conn.initialRecvStreamLimit(id),
        .send_max_data = 0,
    };
    try conn.streams.put(allocator, id, ptr);

    const s = conn.stream(id).?;
    s.recv.fin_seen = true;
    s.recv.final_size = 0;
    s.recv.state = .data_recvd;
    // send stays at .ready — local can't send on a peer-initiated uni.

    try conn.tick(1_000_000);
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}

test "gcClosedStreams: a reaped peer stream is not resurrected by a replayed frame (L2)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_uni = default_stream_receive_window,
        .initial_max_streams_uni = 4,
    });

    // Client-initiated uni stream 0 (peer stream from the server's view).
    const sid: u64 = 2;

    // Open + finish it through the real receive path (bumps the
    // peer-opened watermark, unlike a direct streams.put).
    try conn.handleStream(.application, .{
        .stream_id = sid,
        .offset = 0,
        .data = "hi",
        .has_length = true,
        .fin = true,
    });
    try std.testing.expect(conn.streams.get(sid) != null);
    try std.testing.expectEqual(@as(u64, 1), conn.peer_opened_streams_uni);

    // Consume all bytes so the recv half is fully terminal, then reap.
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 2), try conn.streamRead(sid, &buf));
    try conn.tick(1_000_000);
    try std.testing.expect(conn.streams.get(sid) == null);
    // Contiguous reaped watermark advanced past uni index 0.
    try std.testing.expectEqual(@as(u64, 1), conn.peer_reaped_below_uni);

    // Replay a STREAM frame for the reaped id — must be ignored (RFC 9000
    // §3.2), not resurrected with fresh state.
    try conn.handleStream(.application, .{
        .stream_id = sid,
        .offset = 0,
        .data = "XX",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(sid) == null);

    // A replayed RESET_STREAM for the reaped id is likewise ignored.
    try conn.handleResetStream(.{ .stream_id = sid, .application_error_code = 0, .final_size = 2 });
    try std.testing.expect(conn.streams.get(sid) == null);

    // A higher, never-before-seen peer uni stream still opens normally —
    // the watermark only suppresses the specific reaped id.
    const sid2: u64 = 6; // client uni stream 1
    try conn.handleStream(.application, .{
        .stream_id = sid2,
        .offset = 0,
        .data = "yo",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(sid2) != null);
}

test "gcClosedStreams: an out-of-order reaped peer stream above the watermark is not resurrected (L2 sparse)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = default_connection_receive_window,
        .initial_max_stream_data_uni = default_stream_receive_window,
        .initial_max_streams_uni = 8,
    });

    // Three client-initiated uni streams (peer streams from the server's
    // view): indices 0, 1, 2 → ids 2, 6, 10. Open each with a FIN so its
    // recv half can go terminal once its bytes are read.
    const id0: u64 = 2;
    const id1: u64 = 6;
    const id2: u64 = 10;
    for ([_]u64{ id0, id1, id2 }) |sid| {
        try conn.handleStream(.application, .{
            .stream_id = sid,
            .offset = 0,
            .data = "hi",
            .has_length = true,
            .fin = true,
        });
    }
    try std.testing.expectEqual(@as(u64, 3), conn.peer_opened_streams_uni);

    // Read + reap indices 0 and 2, but leave index 1 ALIVE — its bytes stay
    // unread, so its recv half is not terminal and gcClosedStreams keeps it.
    var buf: [8]u8 = undefined;
    _ = try conn.streamRead(id0, &buf);
    _ = try conn.streamRead(id2, &buf);
    try conn.tick(1_000_000);
    try std.testing.expect(conn.streams.get(id0) == null);
    try std.testing.expect(conn.streams.get(id2) == null);
    try std.testing.expect(conn.streams.get(id1) != null);

    // The contiguous watermark only advanced past index 0 (blocked by the
    // still-live index 1). Index 2 is reaped but ABOVE the watermark —
    // tracked only by its bit, not the watermark.
    try std.testing.expectEqual(@as(u64, 1), conn.peer_reaped_below_uni);
    try std.testing.expect(conn.peer_reaped_bits_uni.isSet(2));

    // A replayed STREAM frame for the out-of-order reaped id (index 2) MUST
    // be ignored (RFC 9000 §3.2), not resurrected — the reaped bit, not just
    // the contiguous watermark, has to suppress it.
    try conn.handleStream(.application, .{
        .stream_id = id2,
        .offset = 0,
        .data = "XX",
        .has_length = true,
    });
    try std.testing.expect(conn.streams.get(id2) == null);

    // A replayed RESET_STREAM for the same reaped id is likewise ignored.
    try conn.handleResetStream(.{ .stream_id = id2, .application_error_code = 0, .final_size = 2 });
    try std.testing.expect(conn.streams.get(id2) == null);

    // The still-live in-between stream is unaffected.
    try std.testing.expect(conn.streams.get(id1) != null);
}

test "initialSendStreamLimit: remembered 0-RTT params bound the pre-params send window (L6)" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // A plain (non-0-RTT) client with no params and no early-data keys
    // grants no pre-params send window (previously an unbounded maxInt).
    try std.testing.expectEqual(@as(u64, 0), conn.initialSendStreamLimit(0));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), conn.peer_max_data);

    // Install remembered peer params (a 0-RTT resumption): pre-params
    // windows are now bounded by them, per-stream and connection-level.
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_remote = 2048,
        .initial_max_stream_data_uni = 512,
    });
    // Client-initiated bidi stream 0 → remembered bidi_remote limit.
    try std.testing.expectEqual(@as(u64, 2048), conn.initialSendStreamLimit(0));
    // Client-initiated uni stream (id 2) → remembered uni limit.
    try std.testing.expectEqual(@as(u64, 512), conn.initialSendStreamLimit(2));
    // Connection-level send window tightened from maxInt to the remembered value.
    try std.testing.expectEqual(@as(u64, 4096), conn.peer_max_data);
}

test "send-side ops on a peer-initiated uni stream fail fast with StreamNotWritable" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Plant a peer-initiated (client-initiated) uni stream the way inbound
    // STREAM frames leave it in the live table, then confirm every send-side
    // op rejects it instead of queueing into a send half the scheduler
    // never transmits.
    conn.local_transport_params.initial_max_streams_uni = 4;
    conn.local_transport_params.initial_max_stream_data_uni = 1024;
    const id: u64 = 2;
    const peer = try allocator.create(Stream);
    errdefer allocator.destroy(peer);
    peer.* = .{
        .id = id,
        .send = SendStream.init(allocator),
        .recv = RecvStream.init(allocator),
        .recv_max_data = conn.initialRecvStreamLimit(id),
        .send_max_data = 0,
    };
    try conn.streams.put(allocator, id, peer);

    try std.testing.expectError(Error.StreamNotWritable, conn.streamWrite(2, "black hole"));
    try std.testing.expectError(Error.StreamNotWritable, conn.streamFinish(2));
    try std.testing.expectError(Error.StreamNotWritable, conn.streamReset(2, 0));

    // Nothing landed in the stream's send half.
    const st = conn.stream(2).?;
    try std.testing.expectEqual(@as(u64, 0), st.send.writtenBytes());
    try std.testing.expect(!st.send.hasPendingChunk());

    // The guard is directional, not a blanket write ban: a local bidi
    // stream still accepts writes normally.
    const bidi = try conn.openNextBidi();
    try std.testing.expectEqual(@as(usize, 2), try conn.streamWrite(bidi.id, "ok"));
}

test "recv-side reads on a local-initiated uni stream fail fast with StreamNotReadable" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // A locally-opened uni stream has no receive half on this side.
    // Reads used to return 0 forever — indistinguishable from "nothing
    // readable right now" — the receive-side twin of the send black
    // hole above. They must fail fast instead.
    conn.peer_max_streams_uni = 4;
    const uni = try conn.openNextUni();
    var buf: [16]u8 = undefined;
    try std.testing.expectError(Error.StreamNotReadable, conn.streamRead(uni.id, &buf));
    try std.testing.expectError(Error.StreamNotReadable, conn.streamReadFin(uni.id, &buf));

    // Directional, not a blanket read ban: a local bidi stream's
    // receive half still reads normally (empty right now).
    const bidi = try conn.openNextBidi();
    try std.testing.expectEqual(@as(usize, 0), try conn.streamRead(bidi.id, &buf));
}
