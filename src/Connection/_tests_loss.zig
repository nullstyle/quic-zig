// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const LossStats = state.LossStats;
const CloseErrorSpace = state.CloseErrorSpace;
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const Stream = state.Stream;
const TimerDeadline = state.TimerDeadline;
const TimerKind = state.TimerKind;
const application_ack_eliciting_threshold = state.application_ack_eliciting_threshold;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const max_close_reason_len = state.max_close_reason_len;
const max_recv_plaintext = state.max_recv_plaintext;
const SentPacketTracker = state.SentPacketTracker;
const short_packet_mod = state.short_packet_mod;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestEarlyDataWriteSecret = util.installTestEarlyDataWriteSecret;

test "local close is exposed as sticky and pollable event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.close(false, 0x42, "shutting down");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.application, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x42), sticky.error_code);
    try std.testing.expectEqual(@as(u64, 0), sticky.frame_type);
    try std.testing.expectEqualStrings("shutting down", sticky.reason);
    try std.testing.expect(!sticky.reason_truncated);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqualStrings("shutting down", event.close.reason);
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expect(conn.closeEvent() != null);
}

test "local close truncates long reason and keeps sticky event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var reason: [max_close_reason_len + 32]u8 = undefined;
    @memset(&reason, 'x');
    conn.close(true, 0x1337, reason[0..]);

    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(@as(u64, 0x1337), sticky.error_code);
    try std.testing.expectEqual(max_close_reason_len, sticky.reason.len);
    try std.testing.expect(sticky.reason_truncated);
    for (sticky.reason) |byte| {
        try std.testing.expectEqual(@as(u8, 'x'), byte);
    }

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .close);
    try std.testing.expectEqual(max_close_reason_len, event.close.reason.len);
    try std.testing.expect(event.close.reason_truncated);
    try std.testing.expect(conn.pollEvent() == null);

    const after_poll = conn.closeEvent().?;
    try std.testing.expectEqual(max_close_reason_len, after_poll.reason.len);
    try std.testing.expect(after_poll.reason_truncated);
}

test "timer deadline reports ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    conn.pnSpaceForLevel(.application).recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "delayed_ack_packet_threshold tunes the immediate-ACK gate" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Threshold = 1: every ack-eliciting packet forces an immediate
    // ACK with no delayed-ACK arming.
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(0, 1_000, true, 1);
    var tracker = &conn.primaryPath().app_pn_space.received;
    try std.testing.expect(tracker.pending_ack);

    // Reset and try threshold=4. The first three ack-eliciting
    // packets arm but don't promote; the fourth promotes.
    conn.primaryPath().app_pn_space.received = .{};
    tracker = &conn.primaryPath().app_pn_space.received;
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(10, 1_000, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    try std.testing.expect(tracker.delayed_ack_armed);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(11, 1_001, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(12, 1_002, true, 4);
    try std.testing.expect(!tracker.pending_ack);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(13, 1_003, true, 4);
    try std.testing.expect(tracker.pending_ack);

    // The Connection-level field defaults to
    // `application_ack_eliciting_threshold`.
    try std.testing.expectEqual(application_ack_eliciting_threshold, conn.delayed_ack_packet_threshold);
    conn.delayed_ack_packet_threshold = 4;
    try std.testing.expectEqual(@as(u8, 4), conn.delayed_ack_packet_threshold);
}

test "application delayed ACK waits for configured threshold or timer" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const tracker = &conn.primaryPath().app_pn_space.received;
    const delayed_ack_threshold = 2;
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(7, 1000, true, delayed_ack_threshold);

    try std.testing.expect(!tracker.pending_ack);
    try std.testing.expect(tracker.delayed_ack_armed);
    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);

    try conn.tick(1_009_000);
    try std.testing.expect(!tracker.pending_ack);
    try conn.tick(1_010_000);
    try std.testing.expect(tracker.pending_ack);

    tracker.markAckSent();
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(8, 1011, true, delayed_ack_threshold);
    conn.primaryPath().app_pn_space.recordReceivedPacketDelayed(9, 1012, true, delayed_ack_threshold);
    try std.testing.expect(tracker.pending_ack);
}

test "PTO requeues application stream data and arms a probe" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");
    const chunk = s.send.peekChunk(100).?;
    try s.send.recordSent(4, chunk);
    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 4,
        .sent_time_us = 0,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
        .stream_ref = .{ .stream_id = s.id, .stream_key = 4 },
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(u32, 0), app_sent.liveCount());
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u8, 1), conn.primaryPath().pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
    const resent = s.send.peekChunk(100).?;
    try std.testing.expectEqual(@as(u64, 0), resent.offset);
    try std.testing.expectEqual(@as(u64, 5), resent.length);
}

test "PTO requeues retransmittable control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var packet: SentPacketTracker.SentPacket = .{
        .pn = 8,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(?u64, 4096), conn.pending_frames.max_data);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "PTO arms PING when no retransmittable data can be requeued" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const app_sent = conn.sentForLevel(.application);
    try app_sent.record(.{
        .pn = 9,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expect(conn.pendingPingForLevel(.application).*);
    try std.testing.expectEqual(@as(u32, 1), conn.ptoCountForLevel(.application).*);
}

test "PTO requeues CRYPTO bytes at original offsets" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const level: EncryptionLevel = .initial;
    const level_idx = level.idx();
    const bytes = try allocator.dupe(u8, "crypto-fragment");
    var bytes_moved = false;
    errdefer if (!bytes_moved) allocator.free(bytes);
    try conn.sent_crypto[level_idx].append(allocator, .{
        .pn = 2,
        .offset = 123,
        .data = bytes,
    });
    bytes_moved = true;
    try conn.sentForLevel(level).record(.{
        .pn = 2,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try conn.tick(conn.ptoDurationForLevel(level));

    try std.testing.expectEqual(@as(usize, 0), conn.sent_crypto[level_idx].items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[level_idx].items.len);
    try std.testing.expectEqual(@as(u64, 123), conn.crypto_retx[level_idx].items[0].offset);
    try std.testing.expectEqualStrings("crypto-fragment", conn.crypto_retx[level_idx].items[0].data);
}

test "ACK of ack-eliciting packet resets PTO count and updates RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.ptoCountForLevel(.application).* = 3;
    try conn.sentForLevel(.application).record(.{
        .pn = 11,
        .sent_time_us = 1_000_000,
        .bytes = 120,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 12;
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 11,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), conn.ptoCountForLevel(.application).*);
    try std.testing.expectEqual(@as(u64, 50_000), conn.rttForLevel(.application).latest_rtt_us);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).liveCount());
}

test "ACK with largest_acked >= next_pn is a PROTOCOL_VIOLATION" {
    // RFC 9000 §13.1 / RFC 9002 §A.3: "Receipt of an acknowledgment
    // for a packet that was not sent ... MUST be treated as a
    // connection error of type PROTOCOL_VIOLATION." A peer that
    // claims to have acked a PN we never sent is either buggy or
    // hostile; we must close the connection rather than poison
    // packet-threshold loss detection on our legitimate in-flight
    // packets.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // We have two in-flight packets at PNs 0 and 1.
    try conn.sentForLevel(.application).record(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 1_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pnSpaceForLevel(.application).next_pn = 2;

    // Peer claims an ACK for PN 7 — well beyond next_pn = 2.
    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 7,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 100_000);

    // Connection must be closing with PROTOCOL_VIOLATION.
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    const sticky = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, sticky.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, sticky.error_space);
    try std.testing.expectEqual(transport_error_protocol_violation, sticky.error_code);

    // Critically, our in-flight packets must NOT have been declared
    // lost or had their largest_acked_sent updated to the bogus 7.
    try std.testing.expectEqual(@as(u32, 2), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(?u64, null), conn.pnSpaceForLevel(.application).largest_acked_sent);
}

test "packet-threshold loss reduces congestion window" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Loss-based semantics under test (RFC 9002 §7.6's cwnd cut +
    // ssthresh arm): pin CUBIC — BBRv3 (the 0.16.0 default) answers
    // loss through its model, not an immediate window cut.
    conn.setCongestionAlgorithm(.cubic);
    const initial_cwnd = conn.congestionWindow();
    var pn: u64 = 0;
    while (pn <= 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 1_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    conn.pnSpaceForLevel(.application).next_pn = 5;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 4,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 50_000);

    try std.testing.expect(conn.congestionWindow() < initial_cwnd);
    try std.testing.expect(conn.ccForApplication().ssthreshBytes() != null);
}

test "persistent congestion resets congestion window to minimum" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.ccForApplication().setCwndForTest(30_000);
    conn.rttForLevel(.application).smoothed_rtt_us = 10_000;
    conn.rttForLevel(.application).latest_rtt_us = 10_000;
    conn.rttForLevel(.application).rtt_var_us = 1_000;
    conn.rttForLevel(.application).first_sample_taken = true;

    conn.pnSpaceForLevel(.application).largest_acked_sent = 10;
    var pn: u64 = 0;
    while (pn < 4) : (pn += 1) {
        try conn.sentForLevel(.application).record(.{
            .pn = pn,
            .sent_time_us = pn * 100_000,
            .bytes = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    try conn.tick(1_000_000);

    try std.testing.expectEqual(conn.ccForApplication().minWindow(), conn.congestionWindow());
    try std.testing.expectEqual(@as(u64, 0), conn.congestionBytesInFlight());
}

test "persistent congestion ignores non-ack-eliciting losses (RFC 9002 §7.6.1)" {
    // RFC 9002 §7.6.1: "Two ack-eliciting packets ... are declared
    // lost". A duration spanned only by non-ack-eliciting lost
    // packets must NOT establish persistent congestion.
    var stats: LossStats = .{};
    // Two non-ack-eliciting "lost" packets spanning a wide duration
    // (300ms). With pto = 30ms and threshold = 3, the unfiltered
    // earliest/largest range would easily satisfy the old check —
    // this regression-tests the ack-eliciting filter.
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 1,
        .sent_time_us = 300_000,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Adding a single ack-eliciting lost packet still doesn't
    // qualify — RFC requires *two* ack-eliciting losses bounding
    // the duration.
    stats.add(.{
        .pn = 2,
        .sent_time_us = 150_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));

    // Two ack-eliciting lost packets bounding the duration → fires.
    stats.add(.{
        .pn = 3,
        .sent_time_us = 400_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // duration (400ms − 150ms) = 250ms ≥ 3 × 30ms = 90ms → fires.
    try std.testing.expect(Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "persistent congestion duration uses only ack-eliciting bounds" {
    // Mixed losses: a wide-spanning non-ack-eliciting lost packet
    // must NOT inflate the duration computed from the narrower
    // ack-eliciting subset.
    var stats: LossStats = .{};
    // Non-ack-eliciting at t=0 (would extend duration to 100ms).
    stats.add(.{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = true,
    });
    // Two ack-eliciting losses inside a narrower window.
    stats.add(.{
        .pn = 1,
        .sent_time_us = 80_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    stats.add(.{
        .pn = 2,
        .sent_time_us = 100_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    // base_pto = 30ms → threshold = 90ms. Ack-eliciting duration is
    // only 20ms (100ms − 80ms), so persistent congestion must NOT
    // fire even though the unfiltered duration (100ms) exceeds the
    // threshold.
    try std.testing.expect(!Connection.isPersistentCongestionFromBasePto(30_000, stats));
}

test "0-RTT STREAM packet-threshold loss requeues early bytes" {
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
    _ = try s.send.write("early-loss");

    var out: [256]u8 = undefined;
    _ = (try conn.pollLevel(.early_data, &out, 1_000)).?;
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.early_data).count);
    try std.testing.expect(s.send.peekChunk(64) == null);
    // Pretend three more 1-RTT packets were sent at the application
    // layer so the ACK for PN 3 is legitimate (RFC 9000 §13.1).
    conn.pnSpaceForLevel(.application).next_pn = 4;

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 3,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 2_000);

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).liveCount());
    const chunk = s.send.peekChunk(64).?;
    try std.testing.expectEqual(@as(u64, 0), chunk.offset);
    try std.testing.expectEqual(@as(u64, 10), chunk.length);
    try std.testing.expectEqualSlices(u8, "early-loss", s.send.chunkBytes(chunk));
    try std.testing.expect(conn.pollEvent() == null);
}

test "pollLevel coalesces multiple STREAM frames with distinct loss keys" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    // This test emits 1-RTT stream data without a handshake, so the real
    // peer params never arrive; supply remembered limits so the streams
    // have a non-zero send window (previously implicit via the pre-params
    // maxInt default, which is now 0 without any known peer params).
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
    });

    const s0 = try conn.openBidi(0);
    const s1 = try conn.openBidi(4);
    const s2 = try conn.openBidi(8);
    _ = try s0.send.write("alpha");
    _ = try s1.send.write("bravo");
    _ = try s2.send.write("charlie");

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    const sent = conn.sentForLevel(.application);
    try std.testing.expectEqual(@as(u32, 1), sent.count);
    var refs = sent.packets[0].streamRefs();
    var ref_count: usize = 0;
    while (refs.next()) |_| ref_count += 1;
    try std.testing.expectEqual(@as(usize, 3), ref_count);
    try std.testing.expectEqual(@as(u32, 1), s0.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s1.send.in_flight.count());
    try std.testing.expectEqual(@as(u32, 1), s2.send.in_flight.count());
}

test "server HANDSHAKE_DONE emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    conn.primaryPath().path.markValidated();
    conn.pending_handshake_done = true;
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!conn.pending_handshake_done);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .handshake_done);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .handshake_done);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expect(conn.pending_handshake_done);
}

test "idle timer closes and enters draining" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Per RFC 9000 §10.1 ¶2 the effective idle timeout is the min of
    // local and peer; either side advertising 0 means no timeout. Set
    // both so the idle gate actually arms.
    try conn.setTransportParams(.{ .max_idle_timeout_ms = 5 });
    conn.cached_peer_transport_params = .{ .max_idle_timeout_ms = 5 };
    conn.last_activity_us = 1_000;
    const deadline = conn.nextTimerDeadline(1_000).?;
    try std.testing.expectEqual(TimerKind.idle, deadline.kind);
    try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);

    try conn.tick(6_000);
    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.draining, conn.closeState());
    try std.testing.expect(conn.lifecycle.draining_deadline_us != null);
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.idle_timeout, close_event.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, close_event.error_space);
    try std.testing.expectEqual(@as(u64, 0), close_event.error_code);
    try std.testing.expectEqualStrings("idle timeout", close_event.reason);

    try conn.tick(conn.lifecycle.draining_deadline_us.?);
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    try std.testing.expect(conn.nextTimerDeadline(10_000) == null);
}

test "idle timer disabled when either endpoint advertises 0 [RFC9000 §10.1 ¶2]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();

    const Helper = struct {
        fn run(
            a: std.mem.Allocator,
            tls_ctx: boringssl.tls.Context,
            local_ms: u64,
            peer_ms: u64,
        ) !?TimerDeadline {
            const conn_ptr = try a.create(Connection);
            defer a.destroy(conn_ptr);
            try Connection.initClientAt(conn_ptr, a, tls_ctx, "x");
            defer conn_ptr.deinit();
            try conn_ptr.setTransportParams(.{ .max_idle_timeout_ms = local_ms });
            conn_ptr.cached_peer_transport_params = .{ .max_idle_timeout_ms = peer_ms };
            conn_ptr.last_activity_us = 1_000;
            return conn_ptr.nextTimerDeadline(1_000);
        }
    };

    // Local says 0 → no timeout regardless of peer.
    {
        const next = try Helper.run(allocator, ctx, 0, 30_000);
        try std.testing.expect(next == null or next.?.kind != TimerKind.idle);
    }
    // Peer says 0 → no timeout regardless of local.
    {
        const next = try Helper.run(allocator, ctx, 30_000, 0);
        try std.testing.expect(next == null or next.?.kind != TimerKind.idle);
    }
    // Both non-zero → uses min.
    {
        const deadline = (try Helper.run(allocator, ctx, 30_000, 5)).?;
        try std.testing.expectEqual(TimerKind.idle, deadline.kind);
        try std.testing.expectEqual(@as(u64, 6_000), deadline.at_us);
    }
}

test "tick skips handshake-level PTO once handshake_keys_discarded latches" {
    // Regression for the failure mode: pre-fix, every PTO tick after
    // handshake completion would re-fire `firePtoAtLevel(.handshake)`
    // and replay the unACKed Finished CRYPTO. With the discard latch,
    // `tick` MUST treat the Handshake space as dead.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Stage a pre-discard packet to confirm the gate flips correctly:
    // record an in-flight ack-eliciting Handshake packet that would
    // otherwise drive a PTO, then set the latch (mimicking
    // post-discard state) and verify `tick` does NOT touch the
    // tracker. We don't attach a retransmit frame — the
    // `ack_eliciting + in_flight` combination is enough to make
    // `ptoDeadlineForLevel(.handshake)` return non-null pre-fix and
    // arm a PTO. Post-fix, the latch makes `tick` skip the level
    // entirely so the deadline never fires.
    const packet: SentPacketTracker.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 36,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try conn.sentForLevel(.handshake).record(packet);

    // Latch the discard but DON'T call `discardHandshakeKeys` itself —
    // we want to observe `tick` honoring the latch even if the sent
    // tracker still has stale entries (defensive: the latch is the
    // single source of truth for "this space is dead").
    conn.handshake_keys_discarded = true;

    // PTO would normally fire well after `ptoDurationForLevel` from
    // sent_time_us=0; pick a `now_us` deep into that future.
    const pto_us = conn.ptoDurationForLevel(.handshake);
    try conn.tick(pto_us +| 10 * pto_us);

    // No PTO firing means the retransmit frames stay in the sent
    // tracker (we didn't actually clear it), and `pending_ping[1]`
    // never flips true.
    try std.testing.expect(!conn.pending_ping[1]);
    // The phantom packet is still tracked because we didn't call
    // discardHandshakeKeys; that's intentional for this test (it
    // pins the gate's runtime check, not the helper's clear path).
    // `Connection.deinit` will deinit the planted entry alongside
    // the rest of `sent[1]`, so no manual cleanup is needed.
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.handshake).count);
}

// -- gcClosedStreams: per-Connection stream-map GC ------------------
//
// `Connection.streams` was monotonic for the connection's lifetime
// before this fix — every stream the embedder ever opened (or that
// the peer opened) stayed resident even after both sides hit terminal
// state. For a long-lived HTTP/3 session that opens many short
// request streams, the per-stream `Stream` (recv reassembly buffers,
// send chunk ring, ACK ranges, flow-control bookkeeping) accumulated
// to a measurable per-iteration leak in the WT memory profiler.
//
// The fix is `gcClosedStreams`, called at the tail of `tick`. These
// tests pin the contract: streams whose lifecycle is fully terminated
// drop out of `streams` on the next `tick`; partially-closed streams
// stay live; the iteration is safe across hashmap mutation; and the
// per-direction definition of "fully terminated" honors the bidi /
// uni / initiator distinction from RFC 9000 §3.1 / §3.2.

test "gcClosedStreams batch cap rolls surplus to the next tick" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Open one more than the per-pass GC batch cap. The first `tick`
    // should reclaim exactly the cap; the next `tick` mops up the
    // remainder. The cap is a private constant inside `gcClosedStreams`
    // (currently 128); test against the observable contract that the
    // map shrinks by *some* meaningful chunk per call and reaches zero
    // within a small number of ticks.
    const total: u64 = 200;
    var i: u64 = 0;
    while (i < total) : (i += 1) {
        const id = i << 2;
        _ = try conn.openBidi(id);
        const s = conn.stream(id).?;
        s.send.fin_marked = true;
        s.send.fin_in_flight = true;
        s.send.fin_acked = true;
        s.send.final_size = 0;
        s.send.state = .data_recvd;
        s.recv.fin_seen = true;
        s.recv.final_size = 0;
        s.recv.state = .data_recvd;
    }

    try conn.tick(1_000_000);
    // Batch cap is 128 — first pass leaves at most `total - 128`.
    try std.testing.expect(conn.streamCount() <= total - 128);
    // Bounded number of follow-up ticks fully drains the map.
    var ticks: u32 = 0;
    while (conn.streamCount() > 0 and ticks < 8) : (ticks += 1) {
        try conn.tick(1_000_000 + ticks * 1000);
    }
    try std.testing.expectEqual(@as(usize, 0), conn.streamCount());
}
