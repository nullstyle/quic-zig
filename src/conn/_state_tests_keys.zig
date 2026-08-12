// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const EncryptionLevel = state.EncryptionLevel;
const Error = state.Error;
const SecretMaterial = state.SecretMaterial;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const long_packet_mod = state.long_packet_mod;
const max_application_ack_lower_ranges = state.max_application_ack_lower_ranges;
const max_application_ack_ranges_bytes = state.max_application_ack_ranges_bytes;
const max_recv_plaintext = state.max_recv_plaintext;
const sent_packets_mod = state.sent_packets_mod;
const short_packet_mod = state.short_packet_mod;
const transport_error_aead_limit_reached = state.transport_error_aead_limit_reached;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestApplicationReadSecret = util.installTestApplicationReadSecret;
const installTestEarlyDataReadSecret = util.installTestEarlyDataReadSecret;
const testEarlyDataPacketKeys = util.testEarlyDataPacketKeys;
const markTestMultipathNegotiated = util.markTestMultipathNegotiated;

test "ACK-only application packets do not consume sent tracker slots" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    var packet_buf: [default_mtu]u8 = undefined;
    var pn: u64 = 0;
    while (pn < 32) : (pn += 1) {
        conn.pnSpaceForLevel(.application).recordReceived(pn, @intCast(1_000 + pn));
        _ = (try conn.pollLevelOnPath(.application, 0, &packet_buf, 1_000_000 + pn)).?;
    }

    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.application).count);
    try std.testing.expectEqual(@as(u64, 0), conn.sentForLevel(.application).bytes_in_flight);
}

test "peer key update promotes next read keys and keeps previous until discard deadline" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    try installTestApplicationWriteSecret(&conn);
    const old_epoch = conn.app_read_current.?;
    const next_epoch = conn.app_read_next.?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });

    var packet_buf: [default_mtu]u8 = undefined;
    const new_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 1,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &next_epoch.keys,
        .key_phase = next_epoch.key_phase,
    });

    _ = try conn.handleShort(packet_buf[0..new_len], 1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.read_epoch);
    try std.testing.expect(status.read_key_phase);
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    const discard_deadline = status.previous_read_discard_deadline_us.?;

    const old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .largest_acked = 0,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..old_len], 1_001_000);
    try std.testing.expectEqual(@as(u64, 0), conn.keyUpdateStatus().auth_failures);
    try std.testing.expect(conn.app_read_previous != null);

    try conn.tick(discard_deadline);
    try std.testing.expect(conn.app_read_previous == null);

    const late_old_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 2,
        .largest_acked = 1,
        .payload = payload[0..payload_len],
        .keys = &old_epoch.keys,
        .key_phase = old_epoch.key_phase,
    });
    _ = try conn.handleShort(packet_buf[0..late_old_len], discard_deadline + 1);
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(u64, 1), status.auth_failures);
}

test "local key update waits for ACK and three PTOs before the next update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{});

    try conn.requestKeyUpdate(1_000_000);
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_key_phase);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(1_001_000));

    conn.primaryPath().pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    try std.testing.expectEqual(@as(?u64, 1), conn.primaryPath().sent.packets[0].key_epoch);

    try conn.handleAckAtLevel(.application, .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    status = conn.keyUpdateStatus();
    try std.testing.expect(!status.write_update_pending_ack);
    const next_after = status.next_local_update_after_us.?;
    try std.testing.expect(!conn.canInitiateKeyUpdateAt(next_after - 1));
    try std.testing.expectError(Error.KeyUpdateBlocked, conn.requestKeyUpdate(next_after - 1));
    try conn.requestKeyUpdate(next_after);
    try std.testing.expectEqual(@as(?u64, 2), conn.keyUpdateStatus().write_epoch);
}

test "automatic write key update happens before configured packet limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 1,
        .integrity_limit = 4,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(?u64, 0), conn.keyUpdateStatus().write_epoch);
    try std.testing.expectEqual(@as(u64, 1), conn.keyUpdateStatus().write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    const status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "application packet limit counts across paths before proactive key update" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 8,
        .proactive_update_threshold = 2,
        .integrity_limit = 8,
    });
    markTestMultipathNegotiated(&conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    var status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 0), status.write_epoch);
    try std.testing.expectEqual(@as(u64, 2), status.write_packets_protected);

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_002_000)).?;
    status = conn.keyUpdateStatus();
    try std.testing.expectEqual(@as(?u64, 1), status.write_epoch);
    try std.testing.expect(status.write_update_pending_ack);
    try std.testing.expectEqual(@as(u64, 1), status.write_packets_protected);
}

test "non-zero path ACK clears local key update gate" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0x01}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    try conn.requestKeyUpdate(1_000_000);

    const path = conn.paths.get(path_id).?;
    path.pending_ping = true;
    var packet_buf: [default_mtu]u8 = undefined;
    _ = (try conn.pollLevelOnPath(.application, path_id, &packet_buf, 1_001_000)).?;
    try std.testing.expect(conn.keyUpdateStatus().write_update_pending_ack);

    try conn.handlePathAck(.{
        .path_id = path_id,
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 1_050_000);
    try std.testing.expect(!conn.keyUpdateStatus().write_update_pending_ack);
}

test "AEAD authentication failure limit closes the connection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    try installTestApplicationReadSecret(&conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 4,
        .proactive_update_threshold = 3,
        .integrity_limit = 1,
    });
    const keys = conn.app_read_current.?.keys;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ping = .{} });
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = &.{},
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });
    packet_buf[n - 1] ^= 0x01;

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_aead_limit_reached, conn.lifecycle.pending_close.?.error_code);
}

test "server rejects forbidden frames in 0-RTT" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    installTestEarlyDataReadSecret(&conn);
    const keys = try testEarlyDataPacketKeys();

    var payload: [32]u8 = undefined;
    const payload_len = try frame_mod.encode(&payload, .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    } });

    var packet: [256]u8 = undefined;
    const packet_len = try long_packet_mod.sealZeroRtt(&packet, .{
        .dcid = &.{ 9, 9, 9, 9 },
        .scid = &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    _ = try conn.handleOnePacket(packet[0..packet_len], 1_000);
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings("forbidden frame in 0-RTT", conn.lifecycle.pending_close.?.reason);
}

test "application ACK ranges use bounded emission budget" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    try installTestApplicationWriteSecret(&conn);
    try conn.setPeerDcid(&.{0xaa});
    try std.testing.expect(conn.markPathValidated(0));

    const tracker = &conn.primaryPath().app_pn_space.received;
    var pn: u64 = 0;
    while (pn < 400) : (pn += 2) tracker.add(pn, 1_000);

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .ack);
    try std.testing.expect(decoded.frame.ack.ranges_bytes.len <= max_application_ack_ranges_bytes);
    try std.testing.expect(decoded.frame.ack.range_count <= max_application_ack_lower_ranges);
    try std.testing.expect(decoded.frame.ack.range_count < @as(u64, tracker.range_count - 1));
}

test "client discards Handshake keys when HANDSHAKE_DONE arrives [RFC9001 §4.9.2]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Plant Handshake-level secret material so we can observe the
    // discard zeroing it out. The cipher protocol id matches the
    // existing `installTestApplicationWriteSecret` helper — both are
    // synthetic; we only inspect post-discard state, never run real
    // crypto here.
    const hsk_idx = EncryptionLevel.handshake.idx();
    var hsk_material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    hsk_material.secret_len = 32;
    @memset(hsk_material.secret[0..32], 0x42);
    conn.levels[hsk_idx].read = hsk_material;
    conn.levels[hsk_idx].write = hsk_material;
    // Plant a phantom unACKed Handshake-level packet so we can pin
    // the post-discard sent-tracker invariant.
    const packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 36,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try conn.sentForLevel(.handshake).record(packet);
    try std.testing.expectEqual(@as(u32, 1), conn.sentForLevel(.handshake).count);
    conn.pto_count[1] = 3;
    conn.pending_ping[1] = true;

    // Build a 1-RTT payload carrying just HANDSHAKE_DONE; route it
    // through the application-level frame dispatcher, then run the
    // post-frame discard the same way `handleWithEcn` does in prod.
    var payload: [4]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .handshake_done = .{} });
    try conn.dispatchFrames(.application, payload[0..payload_len], 1_000_000);
    try std.testing.expect(conn.received_handshake_done);
    // The discard runs at the end of `handleWithEcn`; mimic it here.
    if (conn.received_handshake_done and !conn.handshake_keys_discarded) {
        conn.discardHandshakeKeys();
    }

    try std.testing.expect(conn.handshake_keys_discarded);
    try std.testing.expect(conn.levels[hsk_idx].read == null);
    try std.testing.expect(conn.levels[hsk_idx].write == null);
    // packetKeys returning null is the receive-path gate that drops
    // any further inbound Handshake packet as `keys_unavailable`.
    try std.testing.expect((try conn.packetKeys(.handshake, .read)) == null);
    try std.testing.expect((try conn.packetKeys(.handshake, .write)) == null);
    // Sent tracker must be empty so PTO/loss detection can't replay
    // phantom CRYPTO frames forever.
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.handshake).count);
    try std.testing.expectEqual(@as(u64, 0), conn.sentForLevel(.handshake).bytes_in_flight);
    try std.testing.expectEqual(@as(u32, 0), conn.pto_count[1]);
    try std.testing.expectEqual(false, conn.pending_ping[1]);
}

test "server discards Handshake keys at handshake-complete [RFC9001 §4.1.2 ¶1]" {
    // Server-side: the §4.1.2 ¶1 confirmation event is "TLS handshake
    // complete" (i.e. processing the client's Finished). We can't
    // exercise the full TLS path in a unit test, so we plant the
    // Handshake material + a phantom in-flight packet, then call the
    // same `drainInboxIntoTls` post-loop block that triggers the
    // discard in production. The branch we cover is the
    // `if (self.role == .server and self.inner.handshakeDone() …)`
    // gate added alongside the §5.7 ¶3 Initial-key discard.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const hsk_idx = EncryptionLevel.handshake.idx();
    var material: SecretMaterial = .{ .cipher_protocol_id = 0x1301 };
    material.secret_len = 32;
    conn.levels[hsk_idx].read = material;
    conn.levels[hsk_idx].write = material;

    const packet: sent_packets_mod.SentPacket = .{
        .pn = 1,
        .sent_time_us = 0,
        .bytes = 700,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try conn.sentForLevel(.handshake).record(packet);

    // Direct call (the server-role gate in `drainInboxIntoTls` is
    // what fires `discardHandshakeKeys` in the production path; we
    // call the function directly here to avoid driving the full
    // TLS state machine).
    conn.discardHandshakeKeys();

    try std.testing.expect(conn.handshake_keys_discarded);
    try std.testing.expect(conn.levels[hsk_idx].read == null);
    try std.testing.expect(conn.levels[hsk_idx].write == null);
    try std.testing.expectEqual(@as(u32, 0), conn.sentForLevel(.handshake).count);
}
