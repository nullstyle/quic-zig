// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const Address = state.Address;
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const EncryptionLevel = state.EncryptionLevel;
const Error = state.Error;
const PathSet = state.PathSet;
const TimerKind = state.TimerKind;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const incoming_ack_range_cap = state.incoming_ack_range_cap;
const max_recv_plaintext = state.max_recv_plaintext;
const path_mod = state.path_mod;
const sent_packets_mod = state.sent_packets_mod;
const short_packet_mod = state.short_packet_mod;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestEarlyDataWriteSecret = util.installTestEarlyDataWriteSecret;
const markTestMultipathNegotiated = util.markTestMultipathNegotiated;

test "poll helper emits one draft multipath control frame with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, false, 7);
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [max_recv_plaintext]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitOnePendingMultipathFrame(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(usize, 1), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_backup);

    const decoded = try frame_mod.decode(payload[0..pos]);
    try std.testing.expect(decoded.frame == .path_status_backup);
    try std.testing.expectEqual(@as(u32, 2), decoded.frame.path_status_backup.path_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.path_status_backup.sequence_number);
}

test "poll helper coalesces draft multipath control frames with retransmit metadata" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.queuePathStatus(2, true, 7);
    conn.queueMaxPathId(4);
    conn.queuePathsBlocked(3);

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
    };
    defer packet.deinit(allocator);
    var payload: [max_recv_plaintext]u8 = undefined;
    var pos: usize = 0;

    try std.testing.expect(try conn.emitPendingMultipathFrames(&packet, &payload, &pos, default_mtu));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.path_statuses.items.len);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_frames.max_path_id);
    try std.testing.expectEqual(@as(?u32, null), conn.pending_frames.paths_blocked);
    try std.testing.expectEqual(@as(usize, 3), packet.retransmit_frames.items.len);
    try std.testing.expect(packet.retransmit_frames.items[0] == .path_status_available);
    try std.testing.expect(packet.retransmit_frames.items[1] == .max_path_id);
    try std.testing.expect(packet.retransmit_frames.items[2] == .paths_blocked);

    var it = frame_mod.iter(payload[0..pos]);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const third = (try it.next()).?;
    try std.testing.expect(first == .path_status_available);
    try std.testing.expect(second == .max_path_id);
    try std.testing.expect(third == .paths_blocked);
    try std.testing.expect((try it.next()) == null);
}

test "PTO requeues retransmittable draft multipath control frames" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 11,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = 3,
        .error_code = 99,
    } });
    try conn.sentForLevel(.application).record(packet);

    try conn.tick(conn.ptoDurationForLevel(.application));

    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_abandons.items.len);
    try std.testing.expectEqual(@as(u32, 3), conn.pending_frames.path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_frames.path_abandons.items[0].error_code);
    try std.testing.expect(!conn.pendingPingForLevel(.application).*);
}

test "requestPing queues application PING on primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});

    conn.requestPing();
    try std.testing.expect(conn.primaryPath().pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!conn.primaryPath().pending_ping);
    try std.testing.expectEqual(@as(u32, 1), conn.primaryPath().sent.count);
    try std.testing.expect(conn.primaryPath().sent.packets[0].ack_eliciting);
}

test "requestPathPing queues application PING on non-primary path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    try conn.requestPathPing(path_id);
    const path = conn.paths.get(path_id).?;
    try std.testing.expect(path.pending_ping);

    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_000_000)).?;

    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);
    try std.testing.expect(path.sent.packets[0].ack_eliciting);
}

test "PathSet API exposes path lifecycle and application recovery state" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    conn.enableMultipath(true);
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
    const initial = conn.pathStats(0).?;
    try std.testing.expect(initial.validated);
    try std.testing.expectEqual(@as(u64, 0), initial.bytes_in_flight);

    try conn.sentForLevel(.application).record(.{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const after_send = conn.pathStats(0).?;
    try std.testing.expectEqual(@as(u64, 1200), after_send.bytes_in_flight);

    const id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    try std.testing.expectEqual(@as(u32, 1), id);
    try std.testing.expect(conn.setActivePath(id));
    try std.testing.expectEqual(id, conn.activePathId());
    try std.testing.expect(conn.markPathValidated(id));
    try std.testing.expect(conn.pathStats(id).?.validated);
    try std.testing.expect(conn.setPathBackup(id, true));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_statuses.items.len);
    try std.testing.expect(!conn.pending_frames.path_statuses.items[0].available);
    conn.setScheduler(.round_robin);
    try std.testing.expect(conn.abandonPath(id));
    try std.testing.expectEqual(path_mod.State.retiring, conn.pathStats(id).?.state);
    try std.testing.expectEqual(@as(u32, 0), conn.activePathId());
}

test "abandoned paths keep recovery until three largest PTOs elapse" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000,
        .bytes = 64,
        .ack_eliciting = false,
        .in_flight = false,
    });

    conn.primaryPath().pto_count = 1;
    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| 3 * conn.largestApplicationPtoDurationUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(expected_deadline, path.retire_deadline_us.?);
    try std.testing.expectEqual(expected_deadline, conn.pathStats(path_id).?.retire_deadline_us.?);

    const deadline = conn.nextTimerDeadline(now_us).?;
    try std.testing.expectEqual(TimerKind.path_retirement, deadline.kind);
    try std.testing.expectEqual(path_id, deadline.path_id);

    try conn.tick(expected_deadline - 1);
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqual(@as(u32, 1), path.sent.count);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(?u64, null), path.retire_deadline_us);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
}

test "PATH_ACK routes ACK processing to the indicated application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{1}), ConnectionId.fromSlice(&.{2}));
    const path = conn.paths.get(path_id).?;
    try path.sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    path.app_pn_space.next_pn = 1;

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.sent.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.largest_acked_sent);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.latest_rtt_us);
}

test "ACK / PATH_ACK range-count sum is bounded per handle cycle" {
    // Build a payload of 16 PATH_ACK frames each declaring 256 ranges
    // (the per-frame decoder cap). 16 * (256 + 1) > incoming_ack_range_cap,
    // so dispatch must skip frames once the cumulative count exceeds
    // the cap. We can't easily run real decode (the ranges are
    // synthetic), so drive `dispatchFrames` with a hand-rolled
    // payload using `range_count = 256, first_range = 0`.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Pre-record sent packets so handleAckAtLevel doesn't bail with
    // "ack of unsent packet". We'll only ack pn=0 from each frame,
    // since the synthetic ranges_bytes is empty (range_count is the
    // declared count; the iterator stops at the first invalid byte —
    // but we feed it through the in-source dispatch path using
    // pre-built frame_types.PathAck values that don't go through the
    // decoder).
    conn.paths.primary().app_pn_space.next_pn = 1;
    try conn.paths.primary().sent.record(.{
        .pn = 0,
        .sent_time_us = 1_000,
        .bytes = 32,
        .ack_eliciting = true,
        .in_flight = true,
    });

    // Simulate per-handle-cycle entry: counters reset.
    conn.incoming_ack_range_count = 0;

    // First frame: range_count = 256 → bump cumulative to 257.
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expectEqual(@as(u64, 257), conn.incoming_ack_range_count);

    // Three more frames bump the count past 4*256 = 1024.
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expect(!conn.exceedsIncomingAckRangeCap(256));
    // Fourth would push to 1028 — beyond the 1024 cap.
    try std.testing.expect(conn.exceedsIncomingAckRangeCap(256));
    // Counter stops advancing once the cap is reached.
    try std.testing.expectEqual(@as(u64, 771), conn.incoming_ack_range_count);
    // Subsequent frames continue to be rejected without further
    // bumping the counter (cap stays sticky for this cycle).
    try std.testing.expect(conn.exceedsIncomingAckRangeCap(256));
    try std.testing.expectEqual(@as(u64, 771), conn.incoming_ack_range_count);
}

test "0-RTT send path requires explicit per-connection opt-in" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setPeerDcid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try conn.setLocalScid(&.{ 9, 9, 9, 9 });
    installTestEarlyDataWriteSecret(&conn);

    const s = try conn.openBidi(0);
    _ = try s.send.write("hello");

    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.early_data, &out, 1_000));
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.early_data).count);
}

test "pollLevel emits PATH_ACK for non-zero application path ACKs" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(!path.app_pn_space.received.pending_ack);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
    try std.testing.expectEqual(@as(u64, 9), decoded.frame.path_ack.largest_acked);
}

test "multipath-negotiated non-zero path packets use draft-21 nonce" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    const keys = (try conn.packetKeys(.application, .write)).?;
    var plaintext: [max_recv_plaintext]u8 = undefined;

    try std.testing.expectError(
        boringssl.crypto.aead.Error.Auth,
        short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
            .dcid_len = 1,
            .keys = &keys,
            .largest_received = 0,
        }),
    );
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_ack);
    try std.testing.expectEqual(path_id, decoded.frame.path_ack.path_id);
}

test "unvalidated rebound path obeys anti-amplification before polling" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .ipv4 = .{ .addr = .{ 1, 1, 1, 1 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 2, 2, 2, 2 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    try conn.handlePeerAddressChange(path, new_addr, 1, 1_000_000);
    path.pending_ping = true;

    var packet_buf: [default_mtu]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.pollLevel(.application, &packet_buf, 1_001_000));
    try std.testing.expect(path.pending_ping);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
}

test "unvalidated path enforces anti-amplification on Initial sends" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Force the primary path to be unvalidated and simulate the peer
    // having sent us only a small Initial. RFC 9000 §8.1 caps the
    // server's send budget at 3x bytes_received until validation
    // succeeds — and that applies to Initial and Handshake bytes too,
    // not just 1-RTT.
    const path = conn.primaryPath();
    path.path.validated = false;
    path.path.validator = .{};
    path.path.bytes_received = 100;
    path.path.bytes_sent = 0;

    // Plant retransmittable Initial CRYPTO bytes so pollLevel actually
    // wants to emit a packet. Without anti-amp, sealInitial would
    // happily fill an MTU-sized datagram.
    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &(@as([800]u8, @splat(0xab))));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const result = try conn.pollLevel(.initial, &packet_buf, 1_000_000);

    if (result) |n| {
        // Anti-amp says we must not send more than 3 * 100 = 300 bytes.
        try std.testing.expect(n <= 300);
    }
    try std.testing.expect(path.path.antiAmpAllowance() <= 300);
}

test "validated path is not constrained by anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server primary starts unvalidated (RFC 9000 §8.1). Force-validate
    // it so we can exercise the "validated path bypasses anti-amp"
    // branch directly without driving a Handshake exchange.
    const path = conn.primaryPath();
    path.path.markValidated();
    try std.testing.expect(path.path.isValidated());
    path.path.bytes_received = 50;
    path.path.bytes_sent = 0;

    const odcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try conn.setInitialDcid(&odcid);
    try conn.setLocalScid(&.{0xc1});
    try conn.setPeerDcid(&odcid);

    const crypto_bytes = try allocator.dupe(u8, &(@as([800]u8, @splat(0xab))));
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = crypto_bytes,
    });

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &packet_buf, 1_000_000)).?;
    // Allowance is unbounded for a validated path, so we should be
    // able to send well over 3 * 50 = 150 bytes.
    try std.testing.expect(n > 150);
}

test "old address packets during pending rebinding do not lift new path anti-amplification" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 7, 7, 7, 7 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 8, 8, 8, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 10, 1_000_000);
    try std.testing.expectEqual(@as(u32, 0), conn.incomingPathId(old_addr));
    try std.testing.expect(conn.peerAddressChangeCandidate(0, old_addr) == null);

    try conn.recordAuthenticatedDatagramAddress(0, old_addr, 1200, 1_000_100);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 10), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(@as(u64, 30), path.path.antiAmpAllowance());
}

test "PATH_RESPONSE during pending rebinding is sent to the challenge address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 1, 0, 1, 0 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.handlePeerAddressChange(path, new_addr, 1200, 1_000_000);
    const token: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    conn.queuePathResponseOnPath(0, token, old_addr);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_100)).?;
    try std.testing.expect(datagram.to != null);
    try std.testing.expect(Address.eql(old_addr, datagram.to.?));
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expect(conn.pending_frames.path_response == null);
    try std.testing.expect(conn.pending_frames.path_challenge != null);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .path_response);
    try std.testing.expectEqualSlices(u8, &token, &decoded.frame.path_response.data);

    const followup = (try conn.pollDatagram(&packet_buf, 1_000_200)).?;
    try std.testing.expect(followup.to != null);
    try std.testing.expect(Address.eql(new_addr, followup.to.?));
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(path.path.bytes_sent > 0);
}

test "multipath frames are rejected unless draft-21 was negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .max_path_id = .{ .maximum_path_id = 1 } });
    try conn.dispatchFrames(.application, payload[0..payload_len], 1_000_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "setTransportParams advertises local multipath limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .initial_max_path_id = 2 });
    try std.testing.expect(conn.multipathEnabled());
    try std.testing.expectEqual(@as(u32, 2), conn.local_max_path_id);
}

test "openPath respects peer MAX_PATH_ID when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 1);
    _ = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expectEqual(@as(?u32, 1), conn.pending_frames.paths_blocked);
}

test "MAX_PATH_ID cannot reduce the peer initial path limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    markTestMultipathNegotiated(&conn, 2);
    conn.handleMaxPathId(.{ .maximum_path_id = 1 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "STREAM send tracking survives duplicate application PNs across paths" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    // See the companion test above: no handshake here, so seed a peer
    // send window so 1-RTT stream data can be emitted.
    conn.setRememberedPeerTransportParams(.{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
    });
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    const stream = try conn.openBidi(0);

    _ = try stream.send.write("hello");
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000)).?;

    _ = try stream.send.write("world");
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;

    try std.testing.expectEqual(@as(u64, 0), conn.primaryPath().sent.packets[0].pn);
    try std.testing.expectEqual(@as(u64, 0), path.sent.packets[0].pn);
    const primary_stream_ref = conn.primaryPath().sent.packets[0].stream_ref;
    const path_stream_ref = path.sent.packets[0].stream_ref;
    try std.testing.expect(!primary_stream_ref.isEmpty());
    try std.testing.expect(!path_stream_ref.isEmpty());
    try std.testing.expect(primary_stream_ref.stream_key != path_stream_ref.stream_key);
    try std.testing.expectEqual(@as(u32, 2), stream.send.in_flight.count());
}

test "timer deadline reports non-zero application path ACK delay" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try conn.setTransportParams(.{ .max_ack_delay_ms = 10 });
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(7, 1000);

    const deadline = conn.nextTimerDeadline(1_005_000).?;
    try std.testing.expectEqual(TimerKind.ack_delay, deadline.kind);
    try std.testing.expectEqual(EncryptionLevel.application, deadline.level.?);
    try std.testing.expectEqual(path_id, deadline.path_id);
    try std.testing.expectEqual(@as(u64, 1_010_000), deadline.at_us);
}

test "PTO requeues retransmittable controls on non-zero application path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0x02}));
    const path = conn.paths.get(path_id).?;
    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 90,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(allocator, .{ .path_abandon = .{
        .path_id = path_id,
        .error_code = 99,
    } });
    try path.sent.record(packet);

    try conn.tick(conn.ptoDurationForApplicationPath(path));

    try std.testing.expectEqual(@as(u32, 0), path.sent.count);
    try std.testing.expect(!path.pending_ping);
    try std.testing.expectEqual(@as(u8, 1), path.pto_probe_count);
    try std.testing.expectEqual(@as(u32, 1), path.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_abandons.items.len);
    try std.testing.expectEqual(path_id, conn.pending_frames.path_abandons.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 99), conn.pending_frames.path_abandons.items[0].error_code);
}
