// Split from _tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const EncryptionLevel = state.EncryptionLevel;
const QlogLossReason = state.QlogLossReason;
const QlogPacketDropReason = state.QlogPacketDropReason;
const QlogPacketKind = state.QlogPacketKind;
const QlogPnSpace = state.QlogPnSpace;
const Role = state.Role;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const path_mod = state.path_mod;
const SentPacketTracker = state.SentPacketTracker;
const short_packet_mod = state.short_packet_mod;
const transport_error_aead_limit_reached = state.transport_error_aead_limit_reached;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestApplicationReadSecret = util.installTestApplicationReadSecret;
const TestQlogRecorder = util.TestQlogRecorder;

test "qlog callback records application key update lifecycle" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationReadSecret(conn);
    try installTestApplicationWriteSecret(conn);
    try std.testing.expect(recorder.contains(.application_read_key_installed));
    try std.testing.expect(recorder.contains(.application_write_key_installed));

    try conn.promoteApplicationReadKeys(1_000_000);
    try std.testing.expect(recorder.contains(.application_read_key_discard_scheduled));
    try std.testing.expect(recorder.contains(.application_read_key_updated));

    try conn.requestKeyUpdate(1_100_000);
    const write_epoch = conn.app_write_current.?;
    try std.testing.expect(recorder.contains(.application_write_key_updated));
    var packet: SentPacketTracker.SentPacket = .{
        .pn = 42,
        .sent_time_us = 1_100_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
        .key_epoch = write_epoch.epoch,
        .key_phase = write_epoch.key_phase,
    };
    conn.onApplicationPacketAckedForKeys(&packet, 1_150_000);
    try std.testing.expect(recorder.contains(.application_write_update_acked));

    const discard_deadline = conn.app_read_previous.?.discard_deadline_us.?;
    try conn.tick(discard_deadline);
    try std.testing.expect(recorder.contains(.application_read_key_discarded));
}

test "qlog records AEAD confidentiality-limit close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    try installTestApplicationWriteSecret(conn);
    conn.setApplicationKeyUpdateLimitsForTesting(.{
        .confidentiality_limit = 1,
        .proactive_update_threshold = 99,
        .integrity_limit = 99,
    });
    try conn.setPeerDcid(&.{});

    var packet_buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expect(!recorder.contains(.aead_confidentiality_limit_reached));

    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &packet_buf, 1_001_000)).?;
    try std.testing.expect(recorder.contains(.aead_confidentiality_limit_reached));
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.local, close_event.source);
    try std.testing.expectEqual(transport_error_aead_limit_reached, close_event.error_code);
    // First CC has been sealed → RFC 9000 §10.2.1 closing state. The
    // peer's CC hasn't arrived (and won't, since this is a unit test
    // with no peer), so we stay in closing until the §10.2 ¶5
    // 3*PTO deadline elapses.
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
}

test "qlog: connection_started and connection_state_updated fire on bind+close" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    // Client `bind` should have fired exactly one `connection_started`.
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));
    const started = recorder.first(.connection_started).?;
    try std.testing.expectEqual(@as(?Role, .client), started.role);

    // Re-bind shouldn't double-fire.
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.connection_started));

    // Closing transitions open → closing → draining → closed across the close pipeline.
    conn.close(true, transport_error_protocol_violation, "test close");
    try std.testing.expectEqual(CloseState.closing, conn.closeState());
    try std.testing.expect(recorder.countOf(.connection_state_updated) >= 1);
    const closing_event = blk: {
        var i: usize = 0;
        while (i < recorder.count) : (i += 1) {
            const e = recorder.events[i];
            if (e.name == .connection_state_updated and e.new_state == .closing) break :blk e;
        }
        return error.TestExpectedClosingTransition;
    };
    try std.testing.expectEqual(@as(?CloseState, .open), closing_event.old_state);
}

test "qlog: parameters_set carries top-level peer transport-parameter fields" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Pretend the peer's params arrived and the connection accepted them.
    conn.cached_peer_transport_params = .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1452,
        .initial_max_data = 65536,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 50,
        .active_connection_id_limit = 4,
        .max_ack_delay_ms = 25,
        .max_datagram_frame_size = 1200,
    };
    conn.emitPeerParametersSet();

    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
    const e = recorder.first(.parameters_set).?;
    try std.testing.expectEqual(@as(?u64, 30_000), e.peer_idle_timeout_ms);
    try std.testing.expectEqual(@as(?u64, 1452), e.peer_max_udp_payload_size);
    try std.testing.expectEqual(@as(?u64, 65536), e.peer_initial_max_data);
    try std.testing.expectEqual(@as(?u64, 100), e.peer_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(?u64, 50), e.peer_initial_max_streams_uni);
    try std.testing.expectEqual(@as(?u64, 4), e.peer_active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 25), e.peer_max_ack_delay_ms);
    try std.testing.expectEqual(@as(?u64, 1200), e.peer_max_datagram_frame_size);

    // Idempotent — second call is a no-op.
    conn.emitPeerParametersSet();
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.parameters_set));
}

test "qlog: packet_sent / packet_received are gated by setQlogPacketEvents" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);
    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{});
    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises the qlog gating, not the anti-amp path; force-validate
    // so pollLevel returns a packet.
    conn.primaryPath().path.markValidated();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // With per-packet events disabled (the default), nothing should fire.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), recorder.countOf(.packet_sent));
    // But the cheap counter should have advanced.
    try std.testing.expect(conn.qlog_packets_sent >= 1);

    // Enable the opt-in flag and try again — now we should see the event.
    conn.setQlogPacketEvents(true);
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_001_000)).?;
    try std.testing.expect(recorder.countOf(.packet_sent) >= 1);
    const sent_event = recorder.first(.packet_sent).?;
    try std.testing.expectEqual(@as(?QlogPnSpace, .application), sent_event.pn_space);
    try std.testing.expectEqual(@as(?QlogPacketKind, .one_rtt), sent_event.packet_kind);
    try std.testing.expect(sent_event.packet_size != null);
    try std.testing.expect(sent_event.packet_size.? > 0);
}

test "qlog: packet_dropped fires on AEAD authentication failure" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // Build a valid 1-RTT, then corrupt the tag so AEAD fails.
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
    try std.testing.expect(recorder.contains(.packet_dropped));
    const dropped = recorder.first(.packet_dropped).?;
    try std.testing.expectEqual(@as(?QlogPacketDropReason, .decryption_failure), dropped.drop_reason);
}

test "qlog: loss_detected fires from packet-threshold loss detection" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);
    conn.setQlogPacketEvents(true);

    // Inject a few sent packets at Initial level, then ack a later PN to
    // force packet-threshold loss detection on the early ones.
    const initial_sent = self_blk: {
        break :self_blk &conn.sent[EncryptionLevel.initial.idx()];
    };
    for ([_]u64{ 0, 1, 2 }) |pn| {
        try initial_sent.record(.{
            .pn = pn,
            .sent_time_us = pn * 1000,
            .bytes = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }
    // Set largest_acked > packet_threshold so the early ones look lost.
    conn.pnSpaceForLevel(.initial).next_pn = 10;
    try conn.handleAckAtLevel(.initial, .{
        .largest_acked = 9,
        .ack_delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges_bytes = &.{},
        .ecn_counts = null,
    }, 5_000);

    try std.testing.expect(recorder.countOf(.loss_detected) >= 1);
    const loss = recorder.first(.loss_detected).?;
    try std.testing.expectEqual(@as(?QlogLossReason, .packet_threshold), loss.loss_reason);
    try std.testing.expect(loss.lost_count != null);
    try std.testing.expect(loss.lost_count.? > 0);
    // packet_lost should fire too because we enabled per-packet events.
    try std.testing.expect(recorder.countOf(.packet_lost) >= 1);
    // The connection-level counter should also have moved.
    try std.testing.expect(conn.qlog_packets_lost >= 1);
}

test "qlog: peer-initiated streams emit stream_state_updated open before their terminal event" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try conn.setTransportParams(.{
        .initial_max_data = 65536,
        .initial_max_stream_data_uni = 65536,
        .initial_max_streams_uni = 4,
    });

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    // A stream materialized by an inbound STREAM frame must emit the
    // same `.open` event a local open does — historically only local
    // opens did, so gcClosedStreams later emitted `closed`/`reset` for
    // streams no qlog consumer ever saw open.
    try conn.handleStream(.application, .{
        .stream_id = 2, // client uni index 0 (peer stream for a server)
        .offset = 0,
        .data = "hi",
        .has_length = true,
        .fin = true,
    });
    try std.testing.expectEqual(@as(usize, 1), recorder.countOf(.stream_state_updated));
    const opened = recorder.first(.stream_state_updated).?;
    try std.testing.expectEqual(@as(?u64, 2), opened.stream_id);
    try std.testing.expectEqual(@as(?state.QlogStreamState, .open), opened.stream_state);

    // RESET_STREAM materializes a fresh peer stream through the same
    // prologue and must open it in the log too.
    try conn.handleResetStream(.{ .stream_id = 6, .application_error_code = 0, .final_size = 0 });
    try std.testing.expectEqual(@as(usize, 2), recorder.countOf(.stream_state_updated));

    // Drain stream 2 and reap: the log now closes what it opened.
    var buf: [8]u8 = undefined;
    _ = try conn.streamRead(2, &buf);
    try conn.tick(1_000_000);
    var saw_closed_2 = false;
    for (recorder.events[0..recorder.count]) |event| {
        if (event.name == .stream_state_updated and
            event.stream_id == @as(?u64, 2) and
            event.stream_state == @as(?state.QlogStreamState, .closed))
        {
            saw_closed_2 = true;
        }
    }
    try std.testing.expect(saw_closed_2);
}

test "qlog: pathStats exposes the new connection-level counters" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);
    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{});
    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises pathStats counters, not the anti-amp path; force-validate
    // so pollLevel returns a packet.
    conn.primaryPath().path.markValidated();

    // Drive a single send to bump counters.
    var buf: [default_mtu]u8 = undefined;
    conn.primaryPath().pending_ping = true;
    _ = (try conn.pollLevel(.application, &buf, 1_000_000)).?;

    const stats = conn.pathStats(0).?;
    try std.testing.expect(stats.packets_sent >= 1);
    try std.testing.expect(stats.total_bytes_sent >= 1);
    // RTT estimator hasn't run yet — values are at their initial defaults.
    try std.testing.expect(stats.srtt_us > 0); // default kInitialRtt
    try std.testing.expectEqual(stats.srtt_us, stats.smoothed_rtt_us);
    try std.testing.expectEqual(stats.rttvar_us, stats.srtt_us / 2);
    // Slow start phase before any loss.
    try std.testing.expectEqual(path_mod.CongestionState.slow_start, stats.congestion_window_state);
}
