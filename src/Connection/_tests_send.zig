// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const frame_mod = state.frame_mod;
const initial_keys_mod = state.initial_keys_mod;
const long_packet_mod = state.long_packet_mod;
const max_recv_plaintext = state.max_recv_plaintext;
const short_packet_mod = state.short_packet_mod;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestEarlyDataWriteSecret = util.installTestEarlyDataWriteSecret;
const TestQlogRecorder = util.TestQlogRecorder;

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

/// A client that can send 1-RTT stream data with no handshake, no
/// pacing, and a congestion window that never binds: the only thing
/// left to stop the sender is the sent-packet tracker.
fn prepareUnboundSender(conn: *Connection) !void {
    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    try conn.setTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_streams_bidi = 16,
    });
    try installTestApplicationWriteSecret(conn);
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
        .initial_max_streams_bidi = 1 << 16,
        .initial_max_streams_uni = 1 << 16,
    });
    conn.pacing_enabled = false;
    conn.ccForApplication().setCwndForTest(1 << 30);
}

/// Acknowledge every 1-RTT packet sent so far, in one ACK frame.
fn ackEverythingSent(conn: *Connection, now_us: u64) !void {
    const largest = conn.pnSpaceForLevel(.application).next_pn - 1;
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = largest,
        .ack_delay = 0,
        .first_range = largest,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, now_us);
}

test "a full sent-packet tracker stops the sender; the connection stays open and goes on when ACKs come" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareUnboundSender(conn);

    // A 100-byte datagram carries 46 bytes of stream data, so this is
    // 10,000 packets: more than twice what the tracker holds.
    const per_packet: usize = 46;
    const packets: usize = 10_000;
    const s = try conn.openBidi(0);
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var written: usize = 0;
    while (written < packets * per_packet) {
        const want = @min(data.len, packets * per_packet - written);
        const n = try conn.streamWrite(s.id, data[0..want]);
        try std.testing.expect(n > 0);
        written += n;
    }

    const tracker = conn.sentForLevel(.application);
    const cap = tracker.capacity();
    var small: [100]u8 = undefined;
    var now_us: u64 = 1_000_000;
    var emitted: usize = 0;
    var rounds: usize = 0;
    while (true) : (rounds += 1) {
        try std.testing.expect(rounds < 16);
        // Send until `pollDatagram` has nothing more. It must never
        // return an error: a full tracker is a reason to wait, like a
        // full congestion window.
        var in_round: usize = 0;
        while (try conn.pollDatagram(&small, now_us)) |_| {
            emitted += 1;
            in_round += 1;
            try std.testing.expect(in_round <= cap);
        }
        try std.testing.expectEqual(state.CloseState.open, conn.closeState());
        if (tracker.liveCount() == 0) break;
        // The first round stops because the tracker is full, with
        // data still to send.
        if (rounds == 0) {
            try std.testing.expectEqual(cap, tracker.liveCount());
            try std.testing.expect(s.send.hasPendingChunk());
        }
        now_us += 10_000;
        try ackEverythingSent(conn, now_us);
        try std.testing.expectEqual(@as(u32, 0), tracker.liveCount());
    }
    try std.testing.expectEqual(packets, emitted);
    try std.testing.expect(!s.send.hasPendingChunk());
}

test "a full sent-packet tracker does not stop an ACK or a CONNECTION_CLOSE" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareUnboundSender(conn);

    const s = try conn.openBidi(0);
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var written: usize = 0;
    while (written < 300_000) written += try conn.streamWrite(s.id, &data);

    const tracker = conn.sentForLevel(.application);
    var small: [100]u8 = undefined;
    const now_us: u64 = 1_000_000;
    while (try conn.pollDatagram(&small, now_us)) |_| {}
    try std.testing.expectEqual(tracker.capacity(), tracker.liveCount());

    // A packet from the peer wants an ACK. An ACK is not tracked, so
    // it goes out through a full tracker.
    const received = &conn.primaryPath().app_pn_space.received;
    received.add(0, 1_000);
    try std.testing.expect(received.pending_ack);
    const ack = (try conn.pollDatagram(&small, now_us)).?;
    try std.testing.expect(ack.len > 0);
    try std.testing.expect(!received.pending_ack);
    try std.testing.expectEqual(tracker.capacity(), tracker.liveCount());

    // The application closes. The CONNECTION_CLOSE goes out too.
    conn.close(false, 0, "done");
    const close = (try conn.pollDatagram(&small, now_us)).?;
    try std.testing.expect(close.len > 0);
    try std.testing.expect(conn.closeState() != .open);
}

test "a full sent-packet tracker gives no pacing deadline: only an ACK or a loss opens it" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareUnboundSender(conn);
    conn.pacing_enabled = true;

    const s = try conn.openBidi(0);
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var written: usize = 0;
    while (written < 300_000) written += try conn.streamWrite(s.id, &data);

    // The pacer lets a burst out and then blocks: data is waiting, the
    // window has room, the bucket is short.
    const now_us: u64 = 1_000_000;
    var pkt: [2048]u8 = undefined;
    var burst: usize = 0;
    while (try conn.pollDatagram(&pkt, now_us)) |_| burst += 1;
    try std.testing.expect(burst > 0 and burst < 64);
    try std.testing.expect(conn.canSend());

    // The control: with room in the tracker that state gives a pacing
    // deadline.
    const tracker = conn.sentForLevel(.application);
    try std.testing.expect(!tracker.isFull());
    const open = conn.nextTimerDeadline(now_us).?;
    try std.testing.expectEqual(state.TimerKind.pacing, open.kind);

    // Fill the tracker by hand (the pacer would take long to let 4096
    // packets out). Nothing else changes.
    var pn = conn.pnSpaceForLevel(.application).next_pn;
    while (!tracker.isFull()) : (pn += 1) {
        try tracker.record(.{
            .pn = pn,
            .sent_time_us = now_us,
            .bytes = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    conn.pnSpaceForLevel(.application).next_pn = pn;

    // Now the pacer's clock opens nothing. A pacing deadline would
    // wake the embedder for a poll that sends nothing, again and
    // again.
    const full = conn.nextTimerDeadline(now_us).?;
    try std.testing.expect(full.kind != .pacing);
    try std.testing.expect((try conn.pollDatagram(&pkt, open.at_us)) == null);
}

/// Fill the 1-RTT tracker of an `prepareUnboundSender` client with
/// small stream packets, and leave stream data waiting.
fn fillTrackerWithStreamData(conn: *Connection, now_us: u64) !void {
    const s = try conn.openBidi(0);
    var data: [4096]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var written: usize = 0;
    while (written < 300_000) written += try conn.streamWrite(s.id, &data);
    var small: [100]u8 = undefined;
    while (try conn.pollDatagram(&small, now_us)) |_| {}
    try std.testing.expect(conn.sentForLevel(.application).isFull());
    try std.testing.expect(s.send.hasPendingChunk());
}

/// The peer acknowledges the oldest packet in the 1-RTT tracker: one
/// slot is free.
fn ackOldest(conn: *Connection, now_us: u64) !void {
    var pns: [1]u64 = undefined;
    const tracker = conn.sentForLevel(.application);
    var i: u32 = 0;
    while (tracker.packets[i].dead) i += 1;
    pns[0] = tracker.packets[i].pn;
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = pns[0],
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, now_us);
    try std.testing.expect(!tracker.isFull());
}

test "a full sent-packet tracker holds back every ack-eliciting frame, and each one goes out when a slot is free" {
    // Each of these frames is built outside the congestion gate on
    // purpose (a probe must get past a full window). A full tracker
    // is different: there is no slot to record the packet in. The
    // frame must stay queued, not be built and lost.
    const Case = enum { ping, path_response, path_challenge, path_challenge_first, pmtud_probe };
    for ([_]Case{ .ping, .path_response, .path_challenge, .path_challenge_first, .pmtud_probe }) |case| {
        const allocator = std.testing.allocator;
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        try prepareUnboundSender(conn);
        try std.testing.expect(conn.markPathValidated(0));
        if (case == .pmtud_probe) conn.setPmtudConfig(.{ .enable = true });

        const now_us: u64 = 1_000_000;
        try fillTrackerWithStreamData(conn, now_us);
        const tracker = conn.sentForLevel(.application);
        const path = conn.primaryPath();
        const token: [8]u8 = @splat(0x5a);
        switch (case) {
            .ping => conn.requestPing(),
            .path_response => conn.queuePathResponseOnPath(0, token, null),
            .path_challenge, .path_challenge_first => {
                conn.pending_frames.path_challenge = token;
                conn.pending_frames.path_challenge_path_id = 0;
                if (case == .path_challenge_first) {
                    path.pending_migration_reset = true;
                    path.path.validator.status = .pending;
                }
            },
            .pmtud_probe => try std.testing.expect(path.pmtudIsSearching()),
        }

        // Full: nothing goes out, no error, and the frame is still
        // queued.
        var pkt: [2048]u8 = undefined;
        const next_pn = conn.pnSpaceForLevel(.application).next_pn;
        try std.testing.expect((try conn.pollDatagram(&pkt, now_us)) == null);
        try std.testing.expectEqual(next_pn, conn.pnSpaceForLevel(.application).next_pn);
        try std.testing.expect(tracker.isFull());
        switch (case) {
            .ping => try std.testing.expect(path.pending_ping),
            .path_response => try std.testing.expect(conn.pending_frames.path_response != null),
            .path_challenge, .path_challenge_first => try std.testing.expect(conn.pending_frames.path_challenge != null),
            .pmtud_probe => try std.testing.expect(path.pmtudIsSearching()),
        }

        // One slot free: the frame goes out.
        try ackOldest(conn, now_us + 10_000);
        try std.testing.expect((try conn.pollDatagram(&pkt, now_us + 10_000)) != null);
        switch (case) {
            .ping => try std.testing.expect(!path.pending_ping),
            .path_response => try std.testing.expect(conn.pending_frames.path_response == null),
            .path_challenge, .path_challenge_first => try std.testing.expect(conn.pending_frames.path_challenge == null),
            .pmtud_probe => try std.testing.expect(!path.pmtudIsSearching()),
        }
    }
}

// -- datagram size (RFC 9000 section 14) ---------------------------------

const initial_test_odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

/// A client that has CRYPTO data to send in an Initial packet, with
/// no TLS handshake behind it.
fn prepareInitialSender(conn: *Connection, crypto: []const u8, offset: u64) !void {
    try conn.setInitialDcid(&initial_test_odcid);
    try conn.setLocalScid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    try conn.setPeerDcid(&initial_test_odcid);
    const bytes = try conn.allocator.dupe(u8, crypto);
    errdefer conn.allocator.free(bytes);
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(conn.allocator, .{
        .offset = offset,
        .data = bytes,
    });
}

const SeenCrypto = struct { offset: u64, len: usize, first: u8, last: u8 };

/// Open an Initial packet of the client above, and return the CRYPTO
/// frame in it.
fn cryptoInClientInitial(datagram: []const u8, largest_received: u64) !SeenCrypto {
    const init_keys = try initial_keys_mod.deriveInitialKeys(&initial_test_odcid, false);
    var keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);
    defer keys.deinitAead();
    var copy: [4096]u8 = undefined;
    @memcpy(copy[0..datagram.len], datagram);
    var plaintext: [max_recv_plaintext]u8 = undefined;
    const opened = try long_packet_mod.openInitial(&plaintext, copy[0..datagram.len], .{
        .keys = &keys,
        .largest_received = largest_received,
    });
    var it = frame_mod.iter(opened.payload);
    while (try it.next()) |f| switch (f) {
        .crypto => |c| return .{ .offset = c.offset, .len = c.data.len, .first = c.data[0], .last = c.data[c.data.len - 1] },
        else => {},
    };
    return error.NoCryptoFrame;
}

test "the padding of a client's Initial datagram counts: 1200 bytes on the wire, in flight, and in the qlog event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareInitialSender(conn, &@as([300]u8, @splat(0xab)), 0);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    conn.setQlogPacketEvents(true);

    // `pollDatagram` seals the Initial packet without padding, builds
    // the rest of the datagram (nothing here), and seals the packet
    // again with the padding. Every count must be the final one.
    var buf: [4096]u8 = undefined;
    const n = (try conn.poll(&buf, 1_000_000)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), n);
    try std.testing.expectEqual(@as(u64, 1200), conn.sentForLevel(.initial).bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.packet_sent));
    try std.testing.expectEqual(@as(?u32, 1200), recorder.first(.packet_sent).?.packet_size);
    try std.testing.expectEqual(@as(u64, 1200), conn.qlog_bytes_sent);
    // The packet opens, and the data is in it.
    const seen = try cryptoInClientInitial(buf[0..n], 0);
    try std.testing.expectEqual(@as(u64, 0), seen.offset);
    try std.testing.expectEqual(@as(usize, 300), seen.len);
}

test "a client with a buffer of exactly 1200 bytes sends its Initial datagram; with 1199 it gets an error and sends nothing short" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try prepareInitialSender(conn, &@as([300]u8, @splat(0xab)), 0);

    // RFC 9000 section 14.1: a client's datagram with an Initial
    // packet is 1200 bytes at least. A shorter buffer cannot hold it.
    var short: [1199]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, conn.poll(&short, 1_000_000));
    // Nothing was lost by the refusal: the data goes out when the
    // buffer is long enough.
    var exact: [1200]u8 = undefined;
    const n = (try conn.poll(&exact, 1_000_100)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), n);
    const seen = try cryptoInClientInitial(exact[0..n], 0);
    try std.testing.expectEqual(@as(usize, 300), seen.len);
}

test "a CRYPTO chunk that does not fit one packet is cut, and the rest goes in the next packet" {
    // A chunk in the retransmission queue is as long as the room was
    // when its data first went out. Until v0.26.0 a chunk that did not
    // fit the packet whole was not sent (and nothing behind it): one
    // frame more in front of it, or a shorter packet, and it waited.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // 1300 bytes: more than one Initial packet holds. The data starts
    // at offset 40 of the CRYPTO stream.
    var data: [1300]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    try prepareInitialSender(conn, &data, 40);
    const queue = &conn.crypto_retx[EncryptionLevel.initial.idx()];

    var buf: [4096]u8 = undefined;
    const first_len = (try conn.poll(&buf, 1_000_000)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), first_len);
    const first = try cryptoInClientInitial(buf[0..first_len], 0);
    try std.testing.expectEqual(@as(u64, 40), first.offset);
    try std.testing.expect(first.len >= 1000 and first.len < 1300);
    try std.testing.expectEqual(data[0], first.first);
    try std.testing.expectEqual(data[first.len - 1], first.last);
    // The rest is first in the queue, at its own offset.
    try std.testing.expectEqual(@as(usize, 1), queue.items.len);
    try std.testing.expectEqual(@as(u64, 40 + first.len), queue.items[0].offset);
    try std.testing.expectEqualSlices(u8, data[first.len..], queue.items[0].data);

    const second_len = (try conn.poll(&buf, 1_000_100)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), second_len);
    const second = try cryptoInClientInitial(buf[0..second_len], 0);
    try std.testing.expectEqual(@as(u64, 40 + first.len), second.offset);
    try std.testing.expectEqual(@as(usize, 1300 - first.len), second.len);
    try std.testing.expectEqual(data[first.len], second.first);
    try std.testing.expectEqual(data[1299], second.last);
    try std.testing.expectEqual(@as(usize, 0), queue.items.len);
    // Each piece is tracked with the packet it went in.
    try std.testing.expectEqual(@as(usize, 2), conn.sent_crypto[EncryptionLevel.initial.idx()].items.len);
}

test "a server that may not send 1200 bytes sends no ack-eliciting Initial packet, and sends it padded when it may" {
    // RFC 9000 section 14.1: a datagram of a server with an
    // ack-eliciting Initial packet is 1200 bytes at least, and every
    // byte of it counts against the anti-amplification limit
    // (section 8.1).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();
    try conn.setInitialDcid(&initial_test_odcid);
    try conn.setLocalScid(&.{ 0xb1, 0xb2, 0xb3, 0xb4 });
    try conn.setPeerDcid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const bytes = try allocator.dupe(u8, &@as([120]u8, @splat(0x5e)));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{ .offset = 0, .data = bytes });
    const queue = &conn.crypto_retx[EncryptionLevel.initial.idx()];

    // The client gave 399 bytes: the server may send 1197.
    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 399;
    path.path.bytes_sent = 0;

    // It owes an ACK too. The ACK goes (it is not ack-eliciting, and
    // it is not padded); the ServerHello waits.
    conn.pnSpaceForLevel(.initial).received.add(0, 1_000);
    var buf: [4096]u8 = undefined;
    const ack_len = (try conn.poll(&buf, 1_000_000)) orelse return error.NoAckSent;
    try std.testing.expect(ack_len < 100);
    try std.testing.expectEqual(@as(usize, 1), queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sentForLevel(.initial).bytes_in_flight);
    try std.testing.expect((try conn.poll(&buf, 1_000_100)) == null);

    // One byte more from the client: 1200 are allowed now (less what
    // the ACK took, so give it that again too).
    path.path.bytes_received = 400 + (ack_len + 2) / 3;
    const hello_len = (try conn.poll(&buf, 1_000_200)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), hello_len);
    try std.testing.expectEqual(@as(usize, 0), queue.items.len);
    try std.testing.expectEqual(@as(u64, 1200), conn.sentForLevel(.initial).bytes_in_flight);
    try std.testing.expect(path.path.bytes_sent <= 3 * path.path.bytes_received);
}

test "a server that may not send 1200 bytes sends no PING in an Initial packet either" {
    // A probe is ack-eliciting too. (The CRYPTO case is the test
    // above.)
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();
    try conn.setInitialDcid(&initial_test_odcid);
    try conn.setLocalScid(&.{ 0xb1, 0xb2, 0xb3, 0xb4 });
    try conn.setPeerDcid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });

    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 399;
    path.path.bytes_sent = 0;

    const ping = conn.pendingPingForLevelOnPath(.initial, path);
    ping.* = true;
    var buf: [4096]u8 = undefined;
    try std.testing.expect((try conn.poll(&buf, 1_000_000)) == null);
    try std.testing.expect(ping.*);

    path.path.bytes_received = 400;
    const n = (try conn.poll(&buf, 1_000_100)) orelse return error.NothingSent;
    try std.testing.expectEqual(@as(usize, 1200), n);
    try std.testing.expect(!ping.*);
}

test "pollLevel(.initial) pads its own packet when there is no datagram around it" {
    // `pollDatagram` pads the datagram when it is complete. A caller
    // of `pollLevel(.initial, ...)` gets one packet, which is the
    // whole datagram then: it must come out at 1200 bytes where RFC
    // 9000 section 14.1 says so.
    const allocator = std.testing.allocator;
    var buf: [4096]u8 = undefined;

    // A client: every Initial packet. CRYPTO data, and a close.
    {
        var ctx = try boringssl.tls.Context.initClient(.{});
        defer ctx.deinit();
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        try prepareInitialSender(conn, &@as([300]u8, @splat(0xab)), 0);
        const n = (try conn.pollLevel(.initial, &buf, 1_000_000)) orelse return error.NothingSent;
        try std.testing.expectEqual(@as(usize, 1200), n);
        try std.testing.expectEqual(@as(u64, 1200), conn.sentForLevel(.initial).bytes_in_flight);

        conn.close(true, 0x0a, "no");
        const close_len = (try conn.pollLevel(.initial, &buf, 1_000_100)) orelse return error.NoCloseSent;
        try std.testing.expectEqual(@as(usize, 1200), close_len);
    }

    // A server: an ack-eliciting Initial packet, and not an ACK alone.
    {
        var ctx = try boringssl.tls.Context.initServer(.{});
        defer ctx.deinit();
        const conn = try Connection.createServer(allocator, ctx);
        defer conn.destroy();
        try conn.setInitialDcid(&initial_test_odcid);
        try conn.setLocalScid(&.{ 0xb1, 0xb2, 0xb3, 0xb4 });
        try conn.setPeerDcid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
        conn.primaryPath().path.markValidated();

        conn.pnSpaceForLevel(.initial).received.add(0, 1_000);
        const ack_len = (try conn.pollLevel(.initial, &buf, 1_000_000)) orelse return error.NoAckSent;
        try std.testing.expect(ack_len < 100);

        const bytes = try allocator.dupe(u8, &@as([120]u8, @splat(0x5e)));
        try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{ .offset = 0, .data = bytes });
        const hello_len = (try conn.pollLevel(.initial, &buf, 1_000_100)) orelse return error.NothingSent;
        try std.testing.expectEqual(@as(usize, 1200), hello_len);
    }
}

test "the packets of one datagram share the anti-amplification allowance" {
    // RFC 9000 section 8.1 limits the bytes a server sends to an
    // address it has not validated. A datagram can hold an Initial
    // and a Handshake packet. Until v0.26.0 each of them was held to
    // the WHOLE allowance on its own (the path counts a datagram when
    // it is complete), so the two together could go over it.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();
    try conn.setInitialDcid(&initial_test_odcid);
    try conn.setLocalScid(&.{ 0xb1, 0xb2, 0xb3, 0xb4 });
    try conn.setPeerDcid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });

    // The client gave 200 bytes: the server may send 600.
    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 200;
    path.path.bytes_sent = 0;

    // An ACK to send in an Initial packet, and more Handshake data
    // than the allowance has room for.
    conn.pnSpaceForLevel(.initial).received.add(0, 1_000);
    var material: state.SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    @memset(material.secret[0..32], 0x42);
    conn.levels[EncryptionLevel.handshake.idx()].write = material;
    const bytes = try allocator.dupe(u8, &@as([900]u8, @splat(0x5e)));
    try conn.crypto_retx[EncryptionLevel.handshake.idx()].append(allocator, .{ .offset = 0, .data = bytes });

    var buf: [4096]u8 = undefined;
    const n = (try conn.poll(&buf, 1_000_000)) orelse return error.NothingSent;
    // Both packets are in the datagram ...
    const initial_len = long_packet_mod.peekPacketLen(buf[0..n]) orelse return error.NotALongHeader;
    try std.testing.expect((buf[0] & 0xf0) == 0xc0);
    try std.testing.expect(initial_len < n);
    try std.testing.expect((buf[initial_len] & 0xf0) == 0xe0);
    // ... and together they are within the allowance. The Handshake
    // packet took what the Initial packet left, and no more.
    try std.testing.expect(n <= 600);
    try std.testing.expect(n > 600 - 40);
    try std.testing.expect(path.path.bytes_sent <= 3 * path.path.bytes_received);
}
