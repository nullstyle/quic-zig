//! The Acknowledgement Frequency extension (draft-ietf-quic-ack-
//! frequency): the frames, the transport parameter, the receiver that
//! honors a request, the sender that asks.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Connection = state.Connection;
const frame_mod = @import("../frame/root.zig");
const frame_types = @import("../frame/types.zig");
const AckTracker = @import("../conn/AckTracker.zig");
const conn_recv_dispatch = @import("recv_dispatch.zig");
const short_packet_mod = @import("../wire/short_packet.zig");
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const max_recv_plaintext = state.max_recv_plaintext;
const default_mtu = state.default_mtu;

test "ack frequency: the reordering threshold decides the immediate ACK" {
    // 0: reordering alone never asks for an ACK at once.
    var none: AckTracker = .{};
    none.addPacketDelayed(5, 0, true, 10, 0, 0, 0);
    none.addPacketDelayed(3, 0, true, 10, 0, 0, 0);
    try std.testing.expect(!none.pending_ack);
    none.addPacketDelayed(9, 0, true, 10, 0, 0, 0);
    try std.testing.expect(!none.pending_ack);

    // 2: a packet two or more behind the largest, or a gap of two or
    // more above it; one behind or a gap of one is not reordering.
    var two: AckTracker = .{};
    two.addPacketDelayed(5, 0, true, 10, 0, 0, 2);
    two.addPacketDelayed(4, 0, true, 10, 0, 0, 2);
    try std.testing.expect(!two.pending_ack);
    two.addPacketDelayed(7, 0, true, 10, 0, 0, 2);
    try std.testing.expect(!two.pending_ack);
    two.addPacketDelayed(2, 0, true, 10, 0, 0, 2);
    try std.testing.expect(two.pending_ack);
    var gap: AckTracker = .{};
    gap.addPacketDelayed(5, 0, true, 10, 0, 0, 2);
    gap.addPacketDelayed(8, 0, true, 10, 0, 0, 2);
    try std.testing.expect(gap.pending_ack);

    // 1 (RFC 9000's rule): any reordering.
    var one: AckTracker = .{};
    one.addPacketDelayed(5, 0, true, 10, 0, 0, 1);
    one.addPacketDelayed(4, 0, true, 10, 0, 0, 1);
    try std.testing.expect(one.pending_ack);
}

fn encodedFrame(buf: []u8, f: frame_types.Frame) ![]u8 {
    const n = try frame_mod.encode(buf, f);
    return buf[0..n];
}

test "ack frequency: a peer's ACK_FREQUENCY sets the threshold, the delay and the reordering rule; an older sequence is ignored; a delay below our min_ack_delay closes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.local_transport_params.min_ack_delay_us = 1_000;

    // RFC 9000's defaults before any request.
    try std.testing.expectEqual(conn.delayed_ack_packet_threshold, conn.effectiveAckThreshold());
    try std.testing.expectEqual(@as(u64, 1), conn.effectiveReorderThreshold());

    var buf: [64]u8 = undefined;
    const first = try encodedFrame(&buf, .{ .ack_frequency = .{
        .sequence_number = 1,
        .ack_eliciting_threshold = 9,
        .request_max_ack_delay_us = 20_000,
        .reordering_threshold = 0,
    } });
    try conn.dispatchFrames(.application, first, 1_000_000);
    try std.testing.expectEqual(@as(u8, 10), conn.effectiveAckThreshold());
    try std.testing.expectEqual(@as(u64, 20_000), conn.effectiveMaxAckDelayUs());
    try std.testing.expectEqual(@as(u64, 0), conn.effectiveReorderThreshold());

    // An older sequence number changes nothing.
    const older = try encodedFrame(&buf, .{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 2,
        .request_max_ack_delay_us = 5_000,
        .reordering_threshold = 1,
    } });
    try conn.dispatchFrames(.application, older, 1_001_000);
    try std.testing.expectEqual(@as(u8, 10), conn.effectiveAckThreshold());
    try std.testing.expect(conn.closeState() == .open);

    // A newer one with a huge threshold: the packet count saturates.
    const huge = try encodedFrame(&buf, .{ .ack_frequency = .{
        .sequence_number = 2,
        .ack_eliciting_threshold = 1_000_000,
        .request_max_ack_delay_us = 20_000,
        .reordering_threshold = 1,
    } });
    try conn.dispatchFrames(.application, huge, 1_002_000);
    try std.testing.expectEqual(@as(u8, 255), conn.effectiveAckThreshold());

    // A delay below our min_ack_delay is a PROTOCOL_VIOLATION.
    const below = try encodedFrame(&buf, .{ .ack_frequency = .{
        .sequence_number = 3,
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay_us = 500,
        .reordering_threshold = 1,
    } });
    try conn.dispatchFrames(.application, below, 1_003_000);
    try std.testing.expect(conn.closeState() != .open);
}

test "ack frequency: the frames are refused outside 1-RTT and without our min_ack_delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var buf: [64]u8 = undefined;
    {
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.local_transport_params.min_ack_delay_us = 1_000;
        const f = try encodedFrame(&buf, .{ .immediate_ack = .{} });
        try conn.dispatchFrames(.handshake, f, 1_000_000);
        try std.testing.expect(conn.closeState() != .open);
    }
    {
        const conn = try Connection.createClient(allocator, ctx, "x");
        defer conn.destroy();
        conn.local_transport_params.min_ack_delay_us = null;
        const f = try encodedFrame(&buf, .{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 1,
            .request_max_ack_delay_us = 25_000,
            .reordering_threshold = 1,
        } });
        try conn.dispatchFrames(.application, f, 1_000_000);
        try std.testing.expect(conn.closeState() != .open);
    }
}

test "ack frequency: IMMEDIATE_ACK makes the packet ack-eliciting and acknowledged at once" {
    var buf: [64]u8 = undefined;
    const f = try encodedFrame(&buf, .{ .immediate_ack = .{} });
    const cls = conn_recv_dispatch.classifyPayload(f);
    try std.testing.expect(cls.ack_eliciting);
    try std.testing.expect(cls.needs_immediate_ack);
}

/// A client with 1-RTT write keys and a peer that advertised
/// `min_ack_delay`, ready to poll (no handshake).
fn readyClient(allocator: std.mem.Allocator, ctx: boringssl.tls.Context) !*Connection {
    const conn = try Connection.createClient(allocator, ctx, "x");
    errdefer conn.destroy();
    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));
    conn.handshake_keys_discarded = true;
    conn.cached_peer_transport_params = .{
        .max_udp_payload_size = 65_527,
        .max_ack_delay_ms = 25,
        .min_ack_delay_us = 2_000,
    };
    return conn;
}

/// The frames of the one packet `pollLevel` builds at the application
/// level, decoded into `out`; the number of frames.
fn pollFrames(conn: *Connection, now_us: u64, out: []frame_types.Frame) !usize {
    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, now_us)) orelse return 0;
    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = keys,
        .largest_received = 0,
    });
    var count: usize = 0;
    var it = frame_mod.iter(opened.payload);
    while (try it.next()) |f| {
        if (count < out.len) out[count] = f;
        count += 1;
    }
    return count;
}

fn findAckFrequency(frames: []const frame_types.Frame) ?frame_types.AckFrequency {
    for (frames) |f| if (f == .ack_frequency) return f.ack_frequency;
    return null;
}

test "ack frequency: requestAckFrequency sends the frame, a lost copy goes again while it is the latest, IMMEDIATE_ACK goes once" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try readyClient(allocator, ctx);
    defer conn.destroy();

    // The delay is raised to the peer's min_ack_delay.
    try conn.requestAckFrequency(31, 1_000, 1);
    try std.testing.expectEqual(state.AckFrequencyPolicy.off, conn.ack_frequency_policy);
    var frames: [8]frame_types.Frame = undefined;
    var count = try pollFrames(conn, 1_000_000, &frames);
    const sent = findAckFrequency(frames[0..@min(count, frames.len)]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), sent.sequence_number);
    try std.testing.expectEqual(@as(u64, 31), sent.ack_eliciting_threshold);
    try std.testing.expectEqual(@as(u64, 2_000), sent.request_max_ack_delay_us);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);

    // The packet is lost: the request is queued again, and sent again.
    const tracker = &conn.primaryPath().sent;
    try std.testing.expectEqual(@as(u32, 1), tracker.liveCount());
    const lost = tracker.packets[0];
    _ = try conn.requeueLostPacket(.application, &lost);
    try std.testing.expect(conn.pending_frames.ack_frequency != null);
    try std.testing.expectEqual(@as(u64, 0), conn.pending_frames.ack_frequency.?.sequence_number);
    count = try pollFrames(conn, 1_001_000, &frames);
    try std.testing.expect(findAckFrequency(frames[0..@min(count, frames.len)]) != null);

    // A newer request supersedes: the older copy's loss queues nothing.
    try conn.requestAckFrequency(63, 25_000, 0);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.ack_frequency.?.sequence_number);
    const older = tracker.packets[1];
    _ = try conn.requeueLostPacket(.application, &older);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.ack_frequency.?.sequence_number);
    count = try pollFrames(conn, 1_002_000, &frames);
    const newest = findAckFrequency(frames[0..@min(count, frames.len)]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), newest.sequence_number);
    try std.testing.expectEqual(@as(u64, 0), newest.reordering_threshold);

    // IMMEDIATE_ACK: once, and not after a loss.
    try conn.requestImmediateAck();
    count = try pollFrames(conn, 1_003_000, &frames);
    var found = false;
    for (frames[0..@min(count, frames.len)]) |f| if (f == .immediate_ack) {
        found = true;
    };
    try std.testing.expect(found);
    try std.testing.expect(!conn.pending_frames.immediate_ack);
    const with_immediate = tracker.packets[tracker.count - 1];
    _ = try conn.requeueLostPacket(.application, &with_immediate);
    try std.testing.expect(!conn.pending_frames.immediate_ack);
}

test "ack frequency: without the peer's min_ack_delay a request is refused" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try std.testing.expectError(state.Error.AckFrequencyNotNegotiated, conn.requestAckFrequency(1, 25_000, 1));
    try std.testing.expectError(state.Error.AckFrequencyNotNegotiated, conn.requestImmediateAck());
    conn.cached_peer_transport_params = .{ .max_udp_payload_size = 65_527 };
    try std.testing.expectError(state.Error.AckFrequencyNotNegotiated, conn.requestAckFrequency(1, 25_000, 1));
}

test "ack frequency: the automatic policy asks once the window is large, again when it doubles, once per round trip" {
    try std.testing.expectEqual(@as(u64, 2), state.autoAckFrequencyPackets(16 * 1_200, 1_200));
    try std.testing.expectEqual(@as(u64, 40), state.autoAckFrequencyPackets(640 * 1_200, 1_200));
    try std.testing.expectEqual(@as(u64, 64), state.autoAckFrequencyPackets(2_000 * 1_200, 1_200));

    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try readyClient(allocator, ctx);
    defer conn.destroy();
    try std.testing.expectEqual(state.AckFrequencyPolicy.auto, conn.ack_frequency_policy);
    const path = conn.primaryPath();
    const mss = path.path.cc.config().max_datagram_size;
    path.path.rtt.smoothed_rtt_us = 20_000;
    path.path.rtt.latest_rtt_us = 20_000;
    path.path.rtt.rtt_var_us = 1_000;

    // A small window: RFC 9000's two packets, nothing to ask.
    path.path.cc.setCwndForTest(16 * mss);
    conn.maybeAutoAckFrequency(1_000_000);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);

    // 640 packets: one ACK per 40.
    path.path.cc.setCwndForTest(640 * mss);
    conn.maybeAutoAckFrequency(1_000_000);
    const first = conn.pending_frames.ack_frequency orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), first.sequence_number);
    try std.testing.expectEqual(@as(u64, 39), first.ack_eliciting_threshold);
    try std.testing.expectEqual(@as(u64, 25_000), first.request_max_ack_delay_us);
    conn.pending_frames.ack_frequency = null;

    // The same window again, and a window that grew by less than
    // double: no new request.
    conn.maybeAutoAckFrequency(1_100_000);
    path.path.cc.setCwndForTest(900 * mss);
    conn.maybeAutoAckFrequency(1_100_000);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);

    // Halved (320 packets: one ACK per 20), but inside the round
    // trip: not yet; past it: asked.
    path.path.cc.setCwndForTest(320 * mss);
    conn.maybeAutoAckFrequency(1_010_000);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);
    conn.maybeAutoAckFrequency(1_020_000);
    const second = conn.pending_frames.ack_frequency orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), second.sequence_number);
    try std.testing.expectEqual(@as(u64, 19), second.ack_eliciting_threshold);
    conn.pending_frames.ack_frequency = null;

    // Doubled and more (2,000 packets: the cap, one ACK per 64):
    // asked again after a round trip.
    path.path.cc.setCwndForTest(2_000 * mss);
    conn.maybeAutoAckFrequency(1_030_000);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);
    conn.maybeAutoAckFrequency(1_040_000);
    const third = conn.pending_frames.ack_frequency orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 2), third.sequence_number);
    try std.testing.expectEqual(@as(u64, 63), third.ack_eliciting_threshold);

    // The policy off: never.
    conn.pending_frames.ack_frequency = null;
    conn.ack_frequency_policy = .off;
    path.path.cc.setCwndForTest(4_000 * mss);
    conn.maybeAutoAckFrequency(2_000_000);
    try std.testing.expect(conn.pending_frames.ack_frequency == null);
}

test "ack frequency: a peer's min_ack_delay above its max_ack_delay is a TRANSPORT_PARAMETER_ERROR" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    conn.cached_peer_transport_params = .{
        .max_udp_payload_size = 65_527,
        .max_ack_delay_ms = 25,
        .min_ack_delay_us = 26_000,
    };
    conn.validatePeerTransportLimits();
    try std.testing.expect(conn.closeState() != .open);
}

test "ack frequency: our transport parameters offer min_ack_delay, no more than our max_ack_delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();
    try conn.setLocalScid(&.{0x11});
    try conn.setTransportParams(.{ .max_ack_delay_ms = 25 });
    try std.testing.expectEqual(@as(?u64, state.default_min_ack_delay_us), conn.local_transport_params.min_ack_delay_us);
    try conn.setTransportParams(.{ .max_ack_delay_ms = 0 });
    try std.testing.expectEqual(@as(?u64, 0), conn.local_transport_params.min_ack_delay_us);
    try conn.setTransportParams(.{ .max_ack_delay_ms = 25, .min_ack_delay_us = 5_000 });
    try std.testing.expectEqual(@as(?u64, 5_000), conn.local_transport_params.min_ack_delay_us);
}
