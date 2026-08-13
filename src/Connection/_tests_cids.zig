// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const ConnectionIdReplenishReason = state.ConnectionIdReplenishReason;
const EncryptionLevel = state.EncryptionLevel;
const Error = state.Error;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const incoming_retire_cid_cap = state.incoming_retire_cid_cap;
const max_recv_plaintext = state.max_recv_plaintext;
const path_mod = state.path_mod;
const short_packet_mod = state.short_packet_mod;
const transport_error_protocol_violation = state.transport_error_protocol_violation;
const wire_header = state.wire_header;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestApplicationReadSecret = util.installTestApplicationReadSecret;
const markTestMultipathNegotiated = util.markTestMultipathNegotiated;

test "tokenEql matches std.mem.eql across boundary cases" {
    // Constant-time compare must agree with std.mem.eql for the
    // ordinary (non-adversarial) cases: equal tokens, fully different
    // tokens, and tokens differing in only one byte at varying
    // positions. RFC 9000 §10.3 mandates CT compare; this test ensures
    // we did not accidentally weaken correctness while doing so.
    const a: [16]u8 = .{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };
    try std.testing.expectEqual(std.mem.eql(u8, &a, &a), Connection.tokenEql(a, a));

    const b: [16]u8 = @splat(0xff);
    try std.testing.expectEqual(std.mem.eql(u8, &a, &b), Connection.tokenEql(a, b));

    var differ: [16]u8 = a;
    inline for (.{ 0, 1, 7, 8, 14, 15 }) |i| {
        differ = a;
        differ[i] ^= 0x01;
        try std.testing.expectEqual(
            std.mem.eql(u8, &a, &differ),
            Connection.tokenEql(a, differ),
        );
    }

    // All-zero tokens must compare equal (the default-initialized
    // value of an unfilled cached entry — guard against accidentally
    // returning false for zero arrays).
    const zero: [16]u8 = @splat(0);
    try std.testing.expect(Connection.tokenEql(zero, zero));
}

test "setTransportParams fills initial_source_connection_id from the local SCID (RFC 9000 §7.3)" {
    // A client that uses the low-level Connection API (setLocalScid +
    // setTransportParams) without explicitly setting
    // `initial_source_connection_id` must still advertise it — set to the
    // SCID it puts on its Initial. Omitting it is a hard handshake rejection
    // on strict peers (quic-go closes with TRANSPORT_PARAMETER_ERROR), which
    // is why in-tree loopback (lenient both ways) passed while every real
    // foreign peer failed.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const scid = [_]u8{ 0xc3, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
    try conn.setLocalScid(&scid);
    // Params that omit initial_source_connection_id entirely.
    try conn.setTransportParams(.{
        .initial_max_data = 1024 * 1024,
        .max_udp_payload_size = 65527,
    });

    const iscid = conn.localTransportParams().initial_source_connection_id orelse
        return error.MissingInitialSourceConnectionId;
    try std.testing.expectEqualSlices(u8, &scid, iscid.slice());
}

test "setLocalScid after setTransportParams back-fills the ISCID (order-independent, RFC 9000 §7.3)" {
    // The inverse ordering of the test above: a low-level caller (e.g. the
    // e2e harness) that sets transport params *before* latching the SCID.
    // setTransportParams can't know the ISCID yet, so it encodes without one;
    // the first setLocalScid must back-fill it so strict peers still see it.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Params first, no SCID latched — ISCID is absent at this point.
    try conn.setTransportParams(.{ .initial_max_data = 1024 * 1024, .max_udp_payload_size = 65527 });
    try std.testing.expect(conn.localTransportParams().initial_source_connection_id == null);

    // Latching the SCID back-fills the ISCID into the stored parameters.
    const scid = [_]u8{ 0xc3, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
    try conn.setLocalScid(&scid);

    const iscid = conn.localTransportParams().initial_source_connection_id orelse
        return error.MissingInitialSourceConnectionId;
    try std.testing.expectEqualSlices(u8, &scid, iscid.slice());
}

test "setLocalScid does not clobber a caller-supplied ISCID" {
    // If the caller advertised its own initial_source_connection_id, a later
    // SCID latch must leave it untouched — back-fill only fills a hole.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const explicit = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try conn.setTransportParams(.{
        .initial_max_data = 1024 * 1024,
        .max_udp_payload_size = 65527,
        .initial_source_connection_id = ConnectionId.fromSlice(&explicit),
    });

    const scid = [_]u8{ 0xc3, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
    try conn.setLocalScid(&scid);

    // The explicitly-set ISCID survives; back-fill saw a non-null hole and left it.
    const iscid = conn.localTransportParams().initial_source_connection_id orelse
        return error.MissingInitialSourceConnectionId;
    try std.testing.expectEqualSlices(u8, &explicit, iscid.slice());
}

test "retiring paths retain peer CIDs and emit PATH_ACK during drain" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    markTestMultipathNegotiated(conn, 1);
    try conn.setPeerDcid(&.{0xaa});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try std.testing.expect(conn.markPathValidated(path_id));
    const path = conn.paths.get(path_id).?;
    path.app_pn_space.recordReceived(9, 1_000);

    const now_us: u64 = 10_000;
    const expected_deadline = now_us +| conn.retiredPathRetentionUs();
    try std.testing.expect(conn.abandonPathAt(path_id, 42, now_us));
    try std.testing.expectEqual(path_mod.State.retiring, path.path.state);
    try std.testing.expectEqualSlices(u8, &.{0xbb}, path.path.peer_cid.slice());

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, now_us + 1)).?;
    try std.testing.expectEqual(path_id, datagram.path_id);
    try std.testing.expect(!path.app_pn_space.received.pending_ack);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
        .multipath_path_id = path_id,
    });

    var saw_path_ack = false;
    var saw_path_abandon = false;
    var it = frame_mod.iter(opened.payload);
    while (try it.next()) |frame| switch (frame) {
        .path_ack => |ack| {
            saw_path_ack = true;
            try std.testing.expectEqual(path_id, ack.path_id);
            try std.testing.expectEqual(@as(u64, 9), ack.largest_acked);
        },
        .path_abandon => |abandon| {
            saw_path_abandon = true;
            try std.testing.expectEqual(path_id, abandon.path_id);
            try std.testing.expectEqual(@as(u64, 42), abandon.error_code);
        },
        else => {},
    };
    try std.testing.expect(saw_path_ack);
    try std.testing.expect(saw_path_abandon);

    try conn.tick(expected_deadline);
    try std.testing.expectEqual(path_mod.State.failed, path.path.state);
    try std.testing.expectEqual(@as(u8, 0), path.path.peer_cid.len);
}

test "incoming short packets are routed by local CID before multipath nonce open" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);
    markTestMultipathNegotiated(conn, 1);
    try conn.setLocalScid(&.{0xa0});
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    const path = conn.paths.get(path_id).?;

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const n = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = path.path.local_cid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
        .multipath_path_id = path_id,
    });

    _ = try conn.handleShort(packet_buf[0..n], 1_000_000);
    try std.testing.expectEqual(path_id, conn.current_incoming_path_id);
    try std.testing.expectEqual(@as(?u64, 0), path.app_pn_space.received.largest);
    try std.testing.expectEqual(@as(?u64, null), conn.primaryPath().app_pn_space.received.largest);
}

test "queued path CIDs participate in incoming short-header routing and retirement" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xbb}));
    try conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc2}, @splat(0));

    const bytes = [_]u8{ 0x40, 0xc2, 0, 0, 0, 0 } ++ @as([16]u8, @splat(0));
    try std.testing.expectEqual(path_id, conn.incomingShortPath(&bytes).?.id);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expect(conn.incomingShortPath(&bytes) == null);
}

test "openPath requires common path id capacity and CIDs when multipath is negotiated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.unspecified, .unspecified, ConnectionId{}, ConnectionId.fromSlice(&.{0xd1})),
    );
    try std.testing.expectError(
        Error.ConnectionIdRequired,
        conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId{}),
    );

    conn.peer_max_path_id = 2;
    _ = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc2}), ConnectionId.fromSlice(&.{0xd2})),
    );
}

test "local CID issuance rejects reuse across paths and sequences" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 2);
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd2})),
    );
    try std.testing.expect(conn.paths.get(2) == null);
    try std.testing.expectEqual(@as(u32, 2), conn.paths.next_path_id);

    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queuePathNewConnectionId(path_id, 1, 0, &.{0xc1}, @splat(0xc1)),
    );
    try std.testing.expectError(
        Error.ConnectionIdAlreadyInUse,
        conn.queueNewConnectionId(1, 0, &.{0xc1}, @splat(0xc1)),
    );
}

test "RETIRE_CONNECTION_ID surfaces replacement CID budget to embedders" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 3 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));

    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    const info = conn.connectionIdReplenishInfo(0).?;
    try std.testing.expectEqual(@as(u32, 0), info.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, info.reason);
    try std.testing.expectEqual(@as(usize, 2), info.active_count);
    try std.testing.expectEqual(@as(usize, 3), info.active_limit);
    try std.testing.expectEqual(@as(usize, 1), info.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), info.next_sequence_number);

    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(@as(u32, 0), event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);

    const queued = try conn.replenishConnectionIds(&.{
        .{ .connection_id = &.{0xa3}, .stateless_reset_token = @splat(0xa3) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 0), conn.localConnectionIdIssueBudget(0));
    try std.testing.expect(conn.pollEvent() == null);
}

test "RETIRE_CONNECTION_ID with sequence we never issued is a PROTOCOL_VIOLATION" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    // We've issued sequences 0, 1, and 2 to the peer.
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // A peer that retires a sequence we never assigned (RFC 9000 §19.16)
    // is committing a PROTOCOL_VIOLATION. Without this gate an attacker
    // could spam fabricated retire frames to force expensive list walks.
    conn.handleRetireConnectionId(.{ .sequence_number = 99 });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "RETIRE_CONNECTION_ID for an already-retired sequence is allowed" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 4 };
    try conn.setLocalScid(&.{0xa0});
    try conn.queueNewConnectionId(1, 0, &.{0xa1}, @splat(0xa1));
    try conn.queueNewConnectionId(2, 0, &.{0xa2}, @splat(0xa2));

    // First retire of seq 1: legitimate.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
    // Second retire of seq 1 (could happen if we received a duplicate or
    // a delayed retransmission): still legitimate because seq 1 was issued
    // at some point. Only sequences strictly above the high watermark are
    // rejected.
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
}

test "retiring CID sequence 0 does not change long-header source CID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Server primary starts unvalidated (RFC 9000 §8.1). This test
    // exercises long-header SCID selection on a late Initial; not the
    // anti-amp path. Force-validate so pollLevel isn't gated.
    conn.primaryPath().path.markValidated();

    const initial_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const initial_scid = [_]u8{0xa0};
    const replacement_scid = [_]u8{0xa1};
    try conn.setInitialDcid(&initial_dcid);
    try conn.setPeerDcid(&.{});
    try conn.setLocalScid(&initial_scid);
    try conn.queueNewConnectionId(1, 0, &replacement_scid, @splat(0xa1));

    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    try std.testing.expectEqualSlices(u8, &replacement_scid, conn.local_scid.slice());
    try std.testing.expectEqualSlices(u8, &initial_scid, conn.longHeaderScid().slice());

    const bytes = try allocator.dupe(u8, "late-initial-ack");
    try conn.crypto_retx[EncryptionLevel.initial.idx()].append(allocator, .{
        .offset = 0,
        .data = bytes,
    });

    var out: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 1_000_000)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, &initial_scid, parsed.header.initial.scid.slice());
}

test "PATH_NEW_CONNECTION_ID rejects sequence reuse with different cid" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "PATH_NEW_CONNECTION_ID rejects path ids above local limit" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    try conn.handlePathNewConnectionId(.{
        .path_id = 2,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "unused negotiated path ids can be pre-provisioned with PATH_NEW_CONNECTION_ID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 3);
    conn.cached_peer_transport_params = .{
        .initial_max_path_id = 3,
        .active_connection_id_limit = 2,
    };

    const queued = try conn.replenishPathConnectionIds(2, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u32, 2), conn.pending_frames.path_new_connection_ids.items[0].path_id);
    try std.testing.expectEqual(@as(u64, 0), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
    try std.testing.expectEqual(@as(u64, 2), conn.nextLocalConnectionIdSequence(2));

    try std.testing.expectError(
        Error.PathLimitExceeded,
        conn.queuePathNewConnectionId(4, 0, 0, &.{0xc4}, @splat(0xc4)),
    );
}

test "PATH_RETIRE_CONNECTION_ID drops pending advertisements and allows replenishment" {
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
    _ = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc2}, .stateless_reset_token = @splat(0xc2) },
        .{ .connection_id = &.{0xc3}, .stateless_reset_token = @splat(0xc3) },
    });
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);

    conn.handlePathRetireConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
    });
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.pending_frames.path_new_connection_ids.items[0].sequence_number);
    try std.testing.expectEqual(@as(usize, 1), conn.localConnectionIdIssueBudget(path_id));
    const event = conn.pollEvent().?;
    try std.testing.expect(event == .connection_ids_needed);
    try std.testing.expectEqual(path_id, event.connection_ids_needed.path_id);
    try std.testing.expectEqual(ConnectionIdReplenishReason.retired, event.connection_ids_needed.reason);
    try std.testing.expectEqual(@as(usize, 1), event.connection_ids_needed.issue_budget);
    try std.testing.expectEqual(@as(u64, 3), event.connection_ids_needed.next_sequence_number);

    const queued = try conn.replenishPathConnectionIds(path_id, &.{
        .{ .connection_id = &.{0xc4}, .stateless_reset_token = @splat(0xc4) },
    });
    try std.testing.expectEqual(@as(usize, 1), queued);
    try std.testing.expectEqual(@as(usize, 2), conn.pending_frames.path_new_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 3), conn.pending_frames.path_new_connection_ids.items[1].sequence_number);
}

test "RETIRE_CONNECTION_ID emits with retransmit metadata and requeues on loss" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try conn.queueRetireConnectionId(7);
    try std.testing.expect(conn.canSend());

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_000)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_frames.retire_connection_ids.items.len);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..n], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });
    const decoded = try frame_mod.decode(opened.payload);
    try std.testing.expect(decoded.frame == .retire_connection_id);
    try std.testing.expectEqual(@as(u64, 7), decoded.frame.retire_connection_id.sequence_number);

    const sent = &conn.primaryPath().sent.packets[0];
    try std.testing.expectEqual(@as(usize, 1), sent.retransmit_frames.items.len);
    try std.testing.expect(sent.retransmit_frames.items[0] == .retire_connection_id);

    _ = try conn.dispatchLostControlFrames(sent);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 7), conn.pending_frames.retire_connection_ids.items[0].sequence_number);
}

test "peer cid registration enforces active cid limit per path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    conn.local_transport_params.active_connection_id_limit = 2;
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(1),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(2),
    });
    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_protocol_violation, conn.lifecycle.pending_close.?.error_code);
}

test "retire_prior_to retires peer cids only on the indicated path" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    markTestMultipathNegotiated(conn, 1);
    const path_id = try conn.openPath(.unspecified, .unspecified, ConnectionId.fromSlice(&.{0xc1}), ConnectionId.fromSlice(&.{0xd1}));
    try conn.handleNewConnectionId(.{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x20}),
        .stateless_reset_token = @splat(0x20),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x10}),
        .stateless_reset_token = @splat(0x10),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x11}),
        .stateless_reset_token = @splat(0x11),
    });
    try conn.handlePathNewConnectionId(.{
        .path_id = path_id,
        .sequence_number = 2,
        .retire_prior_to = 2,
        .connection_id = try frame_types.ConnId.fromSlice(&.{0x12}),
        .stateless_reset_token = @splat(0x12),
    });

    try std.testing.expectEqual(@as(usize, 2), conn.peerCidsCount());
    try std.testing.expectEqualSlices(u8, &.{0x12}, conn.paths.get(path_id).?.path.peer_cid.slice());
    try std.testing.expectEqualSlices(u8, &.{0x20}, conn.primaryPath().path.peer_cid.slice());
}

test "RETIRE_CONNECTION_ID flood beyond per-cycle cap closes with PROTOCOL_VIOLATION" {
    // Seed corpus entry mirroring an adversarial peer that bursts
    // `incoming_retire_cid_cap + 1` RETIRE frames in one datagram.
    // The fast-path skip handles the bulk (each retire targets a
    // sequence below the smallest live entry), so the closing
    // signal is the per-cycle counter, not the per-frame walk.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xb0});
    try conn.queueNewConnectionId(1, 0, &.{0xb1}, @splat(0xb1));
    try conn.queueNewConnectionId(2, 0, &.{0xb2}, @splat(0xb2));

    // Fresh handle cycle.
    conn.incoming_retire_cid_count = 0;

    var i: u64 = 0;
    while (i <= incoming_retire_cid_cap) : (i += 1) {
        // Use sequence 0 every time — it's a real local CID, so
        // the retire actually does something on the first call,
        // then the fast-path skip kicks in for the rest. Either
        // way, the per-cycle counter advances.
        conn.handleRetireConnectionId(.{ .sequence_number = 0 });
        if (conn.lifecycle.pending_close != null) break;
    }
    const close = conn.lifecycle.pending_close orelse return error.TestExpectedFloodClose;
    try std.testing.expectEqual(transport_error_protocol_violation, close.error_code);
    try std.testing.expectEqualStrings("retire_connection_id flood", close.reason);
}

test "RETIRE_CONNECTION_ID fast-path skips sequences already retired" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .active_connection_id_limit = 8 };
    try conn.setLocalScid(&.{0xc0});
    try conn.queueNewConnectionId(1, 0, &.{0xc1}, @splat(0xc1));
    try conn.queueNewConnectionId(2, 0, &.{0xc2}, @splat(0xc2));
    try conn.queueNewConnectionId(3, 0, &.{0xc3}, @splat(0xc3));

    // Real retire: removes seq 0 and 1 from local_cids.
    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    conn.handleRetireConnectionId(.{ .sequence_number = 1 });

    // smallestLiveLocalCidSeq(0) is now 2. A retire of seq 0 must
    // hit the fast-path skip (no close, no further state change).
    const closes_before = conn.incoming_retire_cid_count;
    conn.handleRetireConnectionId(.{ .sequence_number = 0 });
    try std.testing.expect(conn.lifecycle.pending_close == null);
    // Counter still bumped (the cap gates total frame count, not
    // just slow-path frames) but no work was done.
    try std.testing.expectEqual(closes_before + 1, conn.incoming_retire_cid_count);
    try std.testing.expectEqual(@as(u64, 2), conn.smallestLiveLocalCidSeq(0).?);
}
