// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("../Connection.zig");
const Address = state.Address;
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const Error = state.Error;
const MigrationDecision = state.MigrationDecision;
const QlogMigrationFailReason = state.QlogMigrationFailReason;
const Role = state.Role;
const TransportParams = state.TransportParams;
const congestion_mod = state.congestion_mod;
const default_mtu = state.default_mtu;
const frame_mod = state.frame_mod;
const frame_types = state.frame_types;
const max_recv_plaintext = state.max_recv_plaintext;
const min_path_challenge_interval_us = state.min_path_challenge_interval_us;
const path_mod = state.path_mod;
const rtt_mod = state.rtt_mod;
const sent_packets_mod = state.sent_packets_mod;
const short_packet_mod = state.short_packet_mod;
const transport_error_transport_parameter = state.transport_error_transport_parameter;
const transport_params_mod = state.transport_params_mod;
const util = @import("_test_util.zig");
const installTestApplicationWriteSecret = util.installTestApplicationWriteSecret;
const installTestApplicationReadSecret = util.installTestApplicationReadSecret;
const TestQlogRecorder = util.TestQlogRecorder;

fn expectServerOnlyPeerTransportParamRejected(params: TransportParams, reason: []const u8) !void {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.cached_peer_transport_params = params;
    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings(reason, conn.lifecycle.pending_close.?.reason);
}

const TestMigrationPolicy = struct {
    decision: MigrationDecision,
    invocations: u32 = 0,
    last_candidate: ?Address = null,
    last_current: ?Address = null,
    last_role: ?Role = null,

    fn callback(
        user_data: ?*anyopaque,
        conn: *const Connection,
        candidate_addr: Address,
        current_addr: ?Address,
    ) MigrationDecision {
        const self: *TestMigrationPolicy = @ptrCast(@alignCast(user_data.?));
        self.invocations += 1;
        self.last_candidate = candidate_addr;
        self.last_current = current_addr;
        self.last_role = conn.role;
        return self.decision;
    }
};

fn testServerPreferredAddress() transport_params_mod.PreferredAddress {
    // The shape doesn't matter for these tests — the API only
    // checks that `local_transport_params.preferred_address` is
    // non-null.
    return .{
        .ipv4_address = .{ 10, 0, 0, 1 },
        .ipv4_port = 4444,
    };
}

test "server rejects client-sent server-only transport parameters" {
    const reset_token: [16]u8 = .{
        0, 1, 2,  3,  4,  5,  6,  7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };

    try expectServerOnlyPeerTransportParamRejected(.{
        .original_destination_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    }, "client sent original destination cid");
    try expectServerOnlyPeerTransportParamRejected(.{
        .stateless_reset_token = reset_token,
    }, "client sent stateless reset token");
    try expectServerOnlyPeerTransportParamRejected(.{
        .preferred_address = .{
            .ipv4_address = .{ 192, 0, 2, 1 },
            .ipv4_port = 4433,
            .ipv6_address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .ipv6_port = 4433,
            .connection_id = ConnectionId.fromSlice(&.{ 0xc0, 0xc1 }),
            .stateless_reset_token = reset_token,
        },
    }, "client sent preferred address");
    try expectServerOnlyPeerTransportParamRejected(.{
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xcc, 0xdd }),
    }, "client sent retry source cid");
}

test "authenticated NAT rebinding starts validation and resets recovery after response" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);
    // The migration gate enforces handshakeDone() before honoring a
    // peer-address change. This test exercises post-handshake NAT
    // rebinding without driving an actual TLS handshake; opt out of
    // the gate so the test stays focused on the validation flow.
    conn.test_only_force_handshake_for_migration = true;
    try conn.setLocalScid(&.{0xa0});
    const old_addr = Address{ .ipv4 = .{ .addr = .{ 1, 2, 3, 4 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.rtt.smoothed_rtt_us = 50_000;
    path.path.rtt.latest_rtt_us = 40_000;
    path.path.rtt.first_sample_taken = true;
    path.path.cc.setCwndForTest(30_000);

    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const packet_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = conn.local_scid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    try conn.handle(packet_buf[0..packet_len], new_addr, 1_000_000);

    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expectEqual(@as(u64, packet_len), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), path.path.bytes_sent);
    try std.testing.expectEqual(.pending, path.path.validator.status);
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback != null);
    try std.testing.expect(!conn.pathStats(0).?.validated);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expectEqual(@as(u64, 50_000), path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 30_000), path.path.cc.cwndBytes());

    conn.recordPathResponse(0, path.path.validator.pending_token);

    try std.testing.expect(conn.pathStats(0).?.validated);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(rtt_mod.initial_rtt_us, path.path.rtt.smoothed_rtt_us);
    try std.testing.expectEqual(@as(u64, 0), path.path.rtt.latest_rtt_us);
    const expected_cwnd = (congestion_mod.Config{ .max_datagram_size = default_mtu }).initialWindow();
    try std.testing.expectEqual(expected_cwnd, path.path.cc.cwndBytes());
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "client peer-address rebind: pollDatagram exposes the new server tuple after migration" {
    // RFC 9000 §9 / interop `rebind-addr`: the network simulator can
    // rewrite source addresses transparently below the embedder
    // socket. From the QUIC client's POV the server's apparent
    // source 4-tuple changes mid-connection. The transport contract
    // is that an embedder forwarding the inbound source address into
    // `Connection.handle*` triggers PATH_CHALLENGE on the active
    // path AND that the next `pollDatagram` reflects the new peer
    // address, so the embedder's `sock.send` lands on the post-rebind
    // tuple instead of the original `connect()` target.
    //
    // This test pins both halves of the contract: passive detection
    // of the new tuple and the post-detection `out.to` reflecting it
    // — the second is the half a stale qns client driver missed
    // (it called `conn.poll` and routed to a hardcoded target,
    // ignoring the migration). Without the source-address forwarding
    // and the pollDatagram-based send loop, `client × {quic-go,
    // quiche} × rebind-addr` failed end-to-end because outbound 1-RTT
    // packets continued to land on the pre-rebind 4-tuple even after
    // the server validated the new path.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try installTestApplicationReadSecret(conn);
    try installTestApplicationWriteSecret(conn);
    // Same `test_only_force_handshake_for_migration` opt-in as
    // "authenticated NAT rebinding ...": this test exercises the
    // post-handshake migration window without driving an actual TLS
    // handshake.
    conn.test_only_force_handshake_for_migration = true;
    try conn.setLocalScid(&.{0xa0});
    try conn.setPeerDcid(&.{0xaa});
    const old_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 7, 7, 7, 7 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);

    // Inject an authenticated 1-RTT datagram from the *new* server
    // tuple — the wire-level shape that arrives after the simulator
    // rewrites the server's source address.
    var payload: [16]u8 = undefined;
    const payload_len = try frame_mod.encode(payload[0..], .{ .ping = .{} });
    const keys = (try conn.packetKeys(.application, .read)).?;
    var packet_buf: [default_mtu]u8 = undefined;
    const packet_len = try short_packet_mod.seal1Rtt(&packet_buf, .{
        .dcid = conn.local_scid.slice(),
        .pn = 0,
        .payload = payload[0..payload_len],
        .keys = &keys,
    });

    try conn.handle(packet_buf[0..packet_len], new_addr, 1_000_000);

    // Detection half: the active path observed the new tuple and
    // queued PATH_CHALLENGE.
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);

    // Routing half: the next `pollDatagram` MUST hand the embedder
    // the new tuple as `out.to` — this is the per-datagram destination
    // that an embedder routes through `sock.send`. A driver that
    // ignored `out.to` (or used `conn.poll` which drops it) would
    // continue addressing the original `server_addr`, the runner's
    // `rebind-addr` failure mode.
    var tx_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&tx_buf, 1_001_000)).?;
    try std.testing.expect(datagram.to != null);
    try std.testing.expect(Address.eql(new_addr, datagram.to.?));

    // Sanity: the path migration is still pending (PATH_CHALLENGE in
    // flight). The embedder's send-side fix is what carries the
    // PATH_CHALLENGE packet to the new tuple in the first place.
    try std.testing.expectEqual(.pending, path.path.validator.status);
}

test "failed NAT rebinding validation rolls back to the previous address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 3, 3, 3, 3 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 4, 4, 4, 4 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    path.path.bytes_received = 900;
    path.path.bytes_sent = 300;

    try conn.handlePeerAddressChange(path, new_addr, 40, 1_000_000);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(@as(u64, 40), path.path.bytes_received);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    const stale_token = path.path.validator.pending_token;

    try conn.tick(1_000_000 + path.path.validator.timeout_us + 1);

    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expect(path.path.isValidated());
    try std.testing.expectEqual(.validated, path.path.validator.status);
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expectEqual(path_mod.State.active, path.path.state);
    try std.testing.expectEqual(@as(u64, 900), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 300), path.path.bytes_sent);
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    var stale_packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 1_000_000,
        .bytes = 64,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer stale_packet.deinit(allocator);
    try stale_packet.addRetransmitFrame(allocator, .{ .path_challenge = .{ .data = stale_token } });
    try std.testing.expect(!(try conn.dispatchLostControlFrames(&stale_packet)));
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "peer-initiated migration emits PATH_CHALLENGE as the first frame even with backlogged ACKs and MAX_DATA" {
    // Reproduces the interop bug surfaced by `server × quiche × rebind-addr`:
    // when the server's primary path receives a peer-rebind, the FIRST
    // datagram emitted on the new tuple MUST lead with PATH_CHALLENGE.
    // The historical drain order placed PATH_CHALLENGE behind ACK,
    // MAX_DATA, MAX_STREAMS, NEW_CONNECTION_ID etc. — quiche's
    // path-validation state machine misroutes the packet when the
    // probing frame isn't first.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try conn.setLocalScid(&.{0xc1});
    conn.test_only_force_handshake_for_migration = true;

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    // Substantial anti-amp credit so the seal can fit a 1200-byte datagram.
    path.path.bytes_received = 4_000;

    // Pre-queue a fat ACK and a connection-level MAX_DATA so the
    // historical drain order would push PATH_CHALLENGE to (at best)
    // the third frame in the packet — and at worst out of the
    // packet entirely.
    path.app_pn_space.recordReceived(0, 1_000_000);
    path.app_pn_space.recordReceived(2, 1_000_010);
    path.app_pn_space.recordReceived(4, 1_000_020);
    path.app_pn_space.recordReceived(7, 1_000_030);
    conn.pending_frames.max_data = 65_536;
    conn.pending_frames.max_streams_bidi = 256;
    conn.pending_frames.max_streams_uni = 100;

    // Trigger the peer-initiated migration. `handlePeerAddressChange`
    // queues PATH_CHALLENGE on this path AFTER the receive side has
    // already populated the ACK / MAX_* backlogs above.
    try conn.handlePeerAddressChange(path, new_addr, 1200, 1_000_100);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expect(path.pending_migration_reset);

    // Drive one poll. The fast-path emission MUST put PATH_CHALLENGE
    // first in the resulting packet.
    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_200)).?;
    try std.testing.expect(datagram.to != null);
    try std.testing.expect(Address.eql(new_addr, datagram.to.?));
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    var plaintext: [max_recv_plaintext]u8 = undefined;
    const keys = (try conn.packetKeys(.application, .write)).?;
    const opened = try short_packet_mod.open1Rtt(&plaintext, packet_buf[0..datagram.len], .{
        .dcid_len = 1,
        .keys = &keys,
        .largest_received = 0,
    });

    // The FIRST decoded frame must be PATH_CHALLENGE (modulo a leading
    // PADDING run — quiche tolerates pre-PADDING but it's never emitted
    // here, so we assert on the strict invariant).
    var it = frame_mod.iter(opened.payload);
    const first_frame = (try it.next()).?;
    try std.testing.expect(first_frame == .path_challenge);

    // Also assert no STREAM / CRYPTO / DATAGRAM frames precede the
    // probing frame. The iterator already consumed the first frame
    // above; walk the rest and confirm no app-data ahead of where
    // PATH_CHALLENGE landed (which is impossible by construction since
    // it's first, but the explicit walk pins the property for future
    // refactors that might reintroduce a coalesced STREAM ahead of
    // path_challenge).
    var saw_app_data_after_pc = false;
    while (try it.next()) |f| switch (f) {
        .stream, .crypto, .datagram => saw_app_data_after_pc = true,
        else => {},
    };
    // App-data after PATH_CHALLENGE is fine — quiche's complaint is
    // about WHAT'S BEFORE the probing frame, not after. But on a freshly
    // migrated path the server has no in-flight streams (the path is
    // unvalidated; `congestionBlockedOnPath` rejects fresh stream sends
    // until validation completes), so app-data after PATH_CHALLENGE
    // shouldn't actually appear under this scenario either.
    try std.testing.expect(!saw_app_data_after_pc);

    // RFC 9000 §8.2.1 ¶3: a datagram carrying a PATH_CHALLENGE MUST be
    // padded to at least 1200 bytes (subject to anti-amp). Anti-amp
    // here is 3 * 1200 = 3600 bytes (margin we set above), well above
    // the floor. Confirm the seal honored the §8.2.1 floor.
    try std.testing.expect(datagram.len >= default_mtu);
}

test "non-migration polls do not pad short-header datagrams to 1200 bytes" {
    // Regression guard for the PATH_CHALLENGE-first fix: when no
    // peer migration is active, ordinary 1-RTT packets MUST NOT be
    // forced to 1200 bytes. The ACK-only flush below would balloon
    // every keepalive heartbeat from ~30 bytes to 1200 if the
    // pad-to-1200 logic leaked outside the migration window.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{0xaa});
    try conn.setLocalScid(&.{0xc1});

    const peer_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(peer_addr);
    path.path.markValidated();
    path.path.bytes_received = 4_000;

    // Queue a single ACK; that's the only frame the server owes the
    // peer right now, no migration in progress.
    path.app_pn_space.recordReceived(0, 1_000_000);
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(!path.pending_migration_reset);

    var packet_buf: [default_mtu]u8 = undefined;
    const datagram = (try conn.pollDatagram(&packet_buf, 1_000_100)).?;

    // The resulting datagram MUST be small (an ACK frame only),
    // not padded out to 1200 bytes.
    try std.testing.expect(datagram.len < 200);
}

test "migration callback: allow lets path validation start as usual" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Bypass the handshake-done migration gate; this test verifies
    // post-handshake migration-callback behavior without driving TLS.
    conn.test_only_force_handshake_for_migration = true;

    var policy: TestMigrationPolicy = .{ .decision = .allow };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // The callback was consulted once with the right addresses.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);
    try std.testing.expect(policy.last_candidate != null);
    try std.testing.expect(Address.eql(new_addr, policy.last_candidate.?));
    try std.testing.expect(policy.last_current != null);
    try std.testing.expect(Address.eql(old_addr, policy.last_current.?));
    try std.testing.expectEqual(@as(?Role, .client), policy.last_role);

    // Allow path: PATH_CHALLENGE was queued and migration began.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);

    // Drive validation to completion and confirm the path validates.
    conn.recordPathResponse(0, path.path.validator.pending_token);
    try std.testing.expect(path.path.isValidated());
    try std.testing.expect(recorder.contains(.migration_path_validated));
    // No policy_denied event was emitted on the allow path.
    try std.testing.expect(!recorder.contains(.migration_path_failed));
}

test "migration callback: deny skips PATH_CHALLENGE and keeps the old 4-tuple live" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Bypass the handshake-done migration gate (post-handshake-only
    // behavior is exercised here without driving the actual TLS).
    conn.test_only_force_handshake_for_migration = true;

    var policy: TestMigrationPolicy = .{ .decision = .deny };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 192, 168, 9, 9 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();
    const orig_bytes_received = path.path.bytes_received;

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // Callback was consulted exactly once.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);

    // Deny: no PATH_CHALLENGE, no rollback snapshot, peer_addr unchanged.
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expect(path.path.isValidated());
    // markValidated set the validator to .validated; deny path must
    // not perturb that — it should leave the existing validator state
    // alone (no new challenge, no transition to pending/idle/failed).
    try std.testing.expectEqual(.validated, path.path.validator.status);

    // The triggering datagram's bytes credited the existing path's
    // anti-amp rather than vanishing.
    try std.testing.expectEqual(orig_bytes_received + 1200, path.path.bytes_received);

    // qlog observability: migration_path_failed with policy_denied.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const fail_event = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .policy_denied),
        fail_event.migration_fail_reason,
    );
    try std.testing.expectEqual(@as(?u32, 0), fail_event.path_id);

    // The peer can keep talking on the old 4-tuple — confirm a
    // subsequent same-address datagram is still credited cleanly.
    try conn.recordAuthenticatedDatagramAddress(0, old_addr, 800, 1_000_500);
    try std.testing.expectEqual(orig_bytes_received + 1200 + 800, path.path.bytes_received);
    // Callback is not consulted for same-address traffic.
    try std.testing.expectEqual(@as(u32, 1), policy.invocations);
}

test "migration callback: no callback installed preserves prior migration behavior" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Bypass the handshake-done migration gate; the post-handshake
    // no-callback path is what's under test here.
    conn.test_only_force_handshake_for_migration = true;

    // Explicitly leave the callback unset — this is the pre-existing
    // behavior path. The same setup that drives an allow-with-callback
    // succeeds without one, identically.
    try std.testing.expect(conn.migration_callback == null);

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 7, 7, 7, 7 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 8, 8, 8, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    path.path.markValidated();

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // PATH_CHALLENGE queued, migration in progress — same as before.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expect(Address.eql(new_addr, path.path.peer_addr));
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);
}

test "pre-handshake migration: peer-address change is dropped, no PATH_CHALLENGE" {
    // Hardening guide §4.8 / RFC 9000 §9.6: an authenticated peer-
    // address change before handshake confirmation is not legitimate
    // migration. The gate must drop the datagram (no anti-amp credit,
    // no validator state, no PATH_CHALLENGE) and emit
    // `migration_path_failed` with reason `pre_handshake`.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Note: NOT setting test_only_force_handshake_for_migration here
    // — the gate is what we're testing.
    try std.testing.expect(!conn.handshakeDone());

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const old_addr = Address{ .ipv4 = .{ .addr = .{ 1, 1, 1, 1 }, .port = 0 } };
    const new_addr = Address{ .ipv4 = .{ .addr = .{ 2, 2, 2, 2 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(old_addr);
    const orig_bytes_received = path.path.bytes_received;

    try conn.recordAuthenticatedDatagramAddress(0, new_addr, 1200, 1_000_000);

    // Drop semantics: peer_addr unchanged, no anti-amp credit, no
    // PATH_CHALLENGE, no validator state mutation, last-challenge
    // clock not stamped.
    try std.testing.expect(Address.eql(old_addr, path.path.peer_addr));
    try std.testing.expectEqual(orig_bytes_received, path.path.bytes_received);
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expectEqual(@as(?u64, null), path.path.last_path_challenge_at_us);

    // qlog event: migration_path_failed / pre_handshake.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .pre_handshake),
        evt.migration_fail_reason,
    );
    try std.testing.expectEqual(@as(?u32, 0), evt.path_id);
}

test "post-handshake migration: PATH_CHALLENGE rate-limit blocks rapid-fire probes" {
    // Hardening guide §4.8: per-path PATH_CHALLENGE rate limit
    // (`min_path_challenge_interval_us`). The first migration after
    // handshake fires a challenge; a second migration arriving
    // sooner than the interval is rate-limited (no second challenge).
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.test_only_force_handshake_for_migration = true;

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const addr_a = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 1 }, .port = 0 } };
    const addr_b = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 2 }, .port = 0 } };
    const addr_c = Address{ .ipv4 = .{ .addr = .{ 10, 0, 0, 3 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(addr_a);
    path.path.markValidated();

    // First migration: challenge fires, last_path_challenge_at_us stamped.
    const t0: u64 = 1_000_000;
    try conn.recordAuthenticatedDatagramAddress(0, addr_b, 1200, t0);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(?u64, t0), path.path.last_path_challenge_at_us);

    // Drain the queued challenge so the next migration tries a fresh
    // queue, otherwise the queue-already-set assertion would mask the
    // rate-limit verdict.
    conn.pending_frames.path_challenge = null;

    // Second migration arrives 50 ms later — well inside the 100 ms
    // rate limit. Must be rejected with `rate_limited`.
    const t1: u64 = t0 + 50_000;
    try conn.recordAuthenticatedDatagramAddress(0, addr_c, 1200, t1);
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    const fail_evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .rate_limited),
        fail_evt.migration_fail_reason,
    );

    // Third migration after the interval elapses: clears the gate.
    const t2: u64 = t0 + min_path_challenge_interval_us + 1;
    try conn.recordAuthenticatedDatagramAddress(0, addr_c, 1200, t2);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(?u64, t2), path.path.last_path_challenge_at_us);
}

test "migration callback: setMigrationCallback installs and clears the hook" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    var policy: TestMigrationPolicy = .{ .decision = .deny };
    conn.setMigrationCallback(TestMigrationPolicy.callback, &policy);
    try std.testing.expect(conn.migration_callback != null);
    try std.testing.expect(conn.migration_user_data == @as(?*anyopaque, &policy));

    conn.setMigrationCallback(null, null);
    try std.testing.expect(conn.migration_callback == null);
    try std.testing.expect(conn.migration_user_data == null);
}

test "client active migration: rotates DCID, queues PATH_CHALLENGE, snapshots rollback" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // The migration gate enforces handshakeDone() before honoring an
    // active migration request; flip the test-only override since we
    // aren't driving a real TLS handshake here.
    conn.test_only_force_handshake_for_migration = true;

    try conn.setLocalScid(&.{0xa0});
    try conn.setPeerDcid(&.{0xb0});
    const server_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const old_local = Address{ .ipv4 = .{ .addr = .{ 1, 2, 3, 4 }, .port = 0 } };
    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(server_addr);
    path.setLocalAddress(old_local);
    path.path.markValidated();
    path.path.bytes_received = 12_345;
    path.path.bytes_sent = 6_789;

    // Need at least one peer-issued CID beyond the current one so the
    // §5.1.2 ¶1 rotation step can succeed.
    const fresh_cid = ConnectionId.fromSlice(&.{0xc1});
    try conn.registerPeerCidForTesting(1, 0, fresh_cid, @splat(0));

    try conn.beginClientActiveMigration(new_local, 1_000_000);

    // DCID rotated to the fresh peer-issued CID.
    try std.testing.expect(ConnectionId.eql(fresh_cid, path.path.peer_cid));
    try std.testing.expect(ConnectionId.eql(fresh_cid, conn.peer_dcid));
    try std.testing.expect(conn.peer_dcid_set);

    // PATH_CHALLENGE queued on the active path; validator armed.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expectEqual(.pending, path.path.validator.status);
    try std.testing.expectEqual(@as(?u64, 1_000_000), path.path.last_path_challenge_at_us);

    // Local address bookkeeping updated; peer address untouched.
    try std.testing.expect(Address.eql(new_local, path.path.local_addr));
    try std.testing.expect(Address.eql(server_addr, path.path.peer_addr));

    // Rollback snapshot retained so a validation timeout can revert.
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback != null);

    // Counters NOT zeroed (anti-amp doesn't apply when only the local
    // address changed and the peer was already validated). The path
    // remains validated for outbound bytes; only the validator state
    // tracks PATH_CHALLENGE in flight.
    try std.testing.expectEqual(@as(u64, 12_345), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 6_789), path.path.bytes_sent);
    try std.testing.expect(path.path.isValidated());
}

test "client active migration: refuses without a fresh peer CID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.test_only_force_handshake_for_migration = true;
    try conn.setLocalScid(&.{0xa0});
    try conn.setPeerDcid(&.{0xb0});
    // peer_dcid is registered as sequence 0; consumeFreshPeerCidForMigration
    // skips the current cid, leaving no candidate.

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    try std.testing.expectError(
        error.MigrationNoFreshPeerCid,
        conn.beginClientActiveMigration(new_local, 1_000_000),
    );

    // Nothing was mutated.
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(!conn.primaryPath().pending_migration_reset);
    try std.testing.expect(conn.primaryPath().migration_rollback == null);

    // qlog: migration_path_failed / no_fresh_peer_cid.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .no_fresh_peer_cid),
        evt.migration_fail_reason,
    );
}

test "client active migration: refuses before handshake completion" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    // Note: NOT setting test_only_force_handshake_for_migration; the
    // gate is what we're testing. handshakeDone() returns false on a
    // freshly-initialized client.
    try std.testing.expect(!conn.handshakeDone());

    try conn.setLocalScid(&.{0xa0});
    try conn.setPeerDcid(&.{0xb0});
    const fresh_cid = ConnectionId.fromSlice(&.{0xc1});
    try conn.registerPeerCidForTesting(1, 0, fresh_cid, @splat(0));

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try std.testing.expectError(
        error.MigrationPreHandshake,
        conn.beginClientActiveMigration(new_local, 1_000_000),
    );
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "client active migration: server-role connection is rejected" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try std.testing.expectError(
        error.NotClientContext,
        conn.beginClientActiveMigration(new_local, 1_000_000),
    );
}

test "client active migration: PATH_RESPONSE clears migration state and resets recovery" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.test_only_force_handshake_for_migration = true;
    try conn.setLocalScid(&.{0xa0});
    try conn.setPeerDcid(&.{0xb0});

    const path = conn.primaryPath();
    path.setPeerAddress(.{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } });
    path.path.markValidated();
    path.path.rtt.smoothed_rtt_us = 50_000;
    path.path.cc.setCwndForTest(30_000);

    const fresh_cid = ConnectionId.fromSlice(&.{0xc2});
    try conn.registerPeerCidForTesting(1, 0, fresh_cid, @splat(0));

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try conn.beginClientActiveMigration(new_local, 1_000_000);
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);

    conn.recordPathResponse(0, path.path.validator.pending_token);

    try std.testing.expect(!path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback == null);
    try std.testing.expect(path.path.validator.isValidated());
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    // RFC 9000 §9.4: RTT and CC reset to initial values after a
    // successful migration.
    try std.testing.expectEqual(rtt_mod.initial_rtt_us, path.path.rtt.smoothed_rtt_us);
    const expected_cwnd = (congestion_mod.Config{ .max_datagram_size = default_mtu }).initialWindow();
    try std.testing.expectEqual(expected_cwnd, path.path.cc.cwndBytes());
}

// -- noteServerLocalAddressChanged (RFC 9000 §5.1.1 server PA migration) -----

test "noteServerLocalAddressChanged: queues PATH_CHALLENGE and arms validator on server" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Mark the server as having advertised a preferred_address. The
    // gate inside `noteServerLocalAddressChanged` only checks that
    // the field is non-null; we don't need a fully configured value.
    conn.local_transport_params.preferred_address = testServerPreferredAddress();

    // Server-side migration is post-handshake (RFC 9000 §9.6); we
    // bypass the real TLS handshake using the test-only override.
    conn.test_only_force_handshake_for_migration = true;

    const peer_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const old_local = Address{ .ipv4 = .{ .addr = .{ 1, 2, 3, 4 }, .port = 0 } };
    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(peer_addr);
    path.setLocalAddress(old_local);
    path.path.markValidated();
    path.path.bytes_received = 12_345;
    path.path.bytes_sent = 6_789;

    try conn.noteServerLocalAddressChanged(new_local, 1_000_000);

    // PATH_CHALLENGE queued on the active path; validator armed.
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expectEqual(@as(u32, 0), conn.pending_frames.path_challenge_path_id);
    try std.testing.expectEqual(.pending, path.path.validator.status);
    try std.testing.expectEqual(@as(?u64, 1_000_000), path.path.last_path_challenge_at_us);

    // Local address bookkeeping updated; peer address untouched.
    try std.testing.expect(Address.eql(new_local, path.path.local_addr));
    try std.testing.expect(Address.eql(peer_addr, path.path.peer_addr));

    // Rollback snapshot retained so a validation timeout can revert.
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expect(path.migration_rollback != null);

    // Counters NOT zeroed (anti-amp doesn't apply when only the local
    // address changed and the peer was already validated). Mirrors
    // `beginClientActiveMigration` rationale.
    try std.testing.expectEqual(@as(u64, 12_345), path.path.bytes_received);
    try std.testing.expectEqual(@as(u64, 6_789), path.path.bytes_sent);
    try std.testing.expect(path.path.isValidated());
}

test "noteServerLocalAddressChanged: refuses before handshake completion" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.local_transport_params.preferred_address = testServerPreferredAddress();
    // Note: NOT setting test_only_force_handshake_for_migration; the
    // gate is what we're testing. handshakeDone() returns false on a
    // freshly-initialized server connection.
    try std.testing.expect(!conn.handshakeDone());

    var recorder: TestQlogRecorder = .{};
    conn.setQlogCallback(TestQlogRecorder.callback, &recorder);

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try std.testing.expectError(
        error.PathLimitExceeded,
        conn.noteServerLocalAddressChanged(new_local, 1_000_000),
    );

    // No mutation; no PATH_CHALLENGE queued.
    try std.testing.expect(conn.pending_frames.path_challenge == null);
    try std.testing.expect(!conn.primaryPath().pending_migration_reset);

    // qlog: migration_path_failed / pre_handshake.
    try std.testing.expect(recorder.contains(.migration_path_failed));
    const evt = recorder.first(.migration_path_failed).?;
    try std.testing.expectEqual(
        @as(?QlogMigrationFailReason, .pre_handshake),
        evt.migration_fail_reason,
    );
}

test "noteServerLocalAddressChanged: rejects when no preferred_address advertised" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // Deliberately leave local_transport_params.preferred_address null.
    conn.test_only_force_handshake_for_migration = true;

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try std.testing.expectError(
        error.PreferredAddressNotAdvertised,
        conn.noteServerLocalAddressChanged(new_local, 1_000_000),
    );
    try std.testing.expect(conn.pending_frames.path_challenge == null);
}

test "noteServerLocalAddressChanged: client-role connection is rejected" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    try std.testing.expectError(
        error.NotServerContext,
        conn.noteServerLocalAddressChanged(new_local, 1_000_000),
    );
}

test "noteServerLocalAddressChanged: idempotent on the same local address" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.local_transport_params.preferred_address = testServerPreferredAddress();
    conn.test_only_force_handshake_for_migration = true;

    const peer_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(peer_addr);
    path.path.markValidated();

    try conn.noteServerLocalAddressChanged(new_local, 1_000_000);
    const token_after_first = path.path.validator.pending_token;
    try std.testing.expect(conn.pending_frames.path_challenge != null);

    // A duplicate / stale post-migration datagram lands. The local
    // addr already matches, so this should no-op (NOT mint a fresh
    // PATH_CHALLENGE token, which would invalidate the in-flight
    // validator).
    try conn.noteServerLocalAddressChanged(new_local, 1_500_000);
    try std.testing.expect(std.mem.eql(u8, &token_after_first, &path.path.validator.pending_token));
    try std.testing.expectEqual(@as(?u64, 1_000_000), path.path.last_path_challenge_at_us);
}

test "noteServerLocalAddressChanged: refuses while a different migration is pending" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.local_transport_params.preferred_address = testServerPreferredAddress();
    conn.test_only_force_handshake_for_migration = true;

    const peer_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const local_a = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const local_b = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 9 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(peer_addr);
    path.path.markValidated();

    try conn.noteServerLocalAddressChanged(local_a, 1_000_000);
    try std.testing.expectEqual(.pending, path.path.validator.status);

    // Second migration request to a *different* local-addr while the
    // first is still in flight: refused.
    try std.testing.expectError(
        error.PathLimitExceeded,
        conn.noteServerLocalAddressChanged(local_b, 1_500_000),
    );
}

test "noteServerLocalAddressChanged: PATH_CHALLENGE-first emit on the freshly-migrated path" {
    // E2E-style assertion: after the API call, the very next
    // application-level packet leads with PATH_CHALLENGE (RFC 9000
    // §8.2 / §9 — the ngtcp2 connectionmigration interop testcase
    // expects this). Routes through the existing
    // `emit_path_challenge_first` machinery which gates on
    // `pending_migration_reset` + `validator.status == .pending`.
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.local_transport_params.preferred_address = testServerPreferredAddress();
    conn.test_only_force_handshake_for_migration = true;

    // Install application write keys and a peer DCID so pollLevel
    // can actually seal a 1-RTT packet.
    try installTestApplicationWriteSecret(conn);
    try conn.setPeerDcid(&.{ 0xaa, 0xbb });
    try conn.setLocalScid(&.{0xcc});

    const peer_addr = Address{ .ipv4 = .{ .addr = .{ 9, 9, 9, 9 }, .port = 0 } };
    const new_local = Address{ .ipv4 = .{ .addr = .{ 5, 6, 7, 8 }, .port = 0 } };
    const path = conn.primaryPath();
    path.setPeerAddress(peer_addr);
    path.path.markValidated();

    // Force a non-trivial bytes_received so anti-amp doesn't clamp
    // the post-migration poll. Server primary starts unvalidated;
    // markValidated above lifts that, so anti-amp is moot — but we
    // also want a realistic budget for the assertion.
    path.path.bytes_received = 8000;
    path.path.bytes_sent = 0;

    try conn.noteServerLocalAddressChanged(new_local, 1_000_000);
    try std.testing.expect(conn.pending_frames.path_challenge != null);
    try std.testing.expect(path.pending_migration_reset);
    try std.testing.expectEqual(.pending, path.path.validator.status);

    // Capture the queued PATH_CHALLENGE token so we can confirm it's
    // first in the packet payload.
    const expected_token = conn.pending_frames.path_challenge.?;

    var packet_buf: [default_mtu]u8 = undefined;
    const n = (try conn.pollLevel(.application, &packet_buf, 1_000_500)) orelse {
        return error.NoPacketEmitted;
    };
    try std.testing.expect(n > 0);

    // After the poll, the queued PATH_CHALLENGE has been consumed.
    try std.testing.expect(conn.pending_frames.path_challenge == null);

    // Decode the sealed packet and confirm the FIRST frame is a
    // PATH_CHALLENGE bearing `expected_token`. We don't have a
    // direct decode helper for sealed short-header packets in the
    // test surface; instead we leverage the fact that the
    // emit_path_challenge_first branch writes the 9-byte
    // PATH_CHALLENGE before any other frame into the inner payload.
    // The retransmit-frame slot on the path's most recent SentPacket
    // captures the same frame for retransmission, so we can read it
    // there to confirm ordering.
    try std.testing.expect(path.sent.count > 0);
    const last_pkt = &path.sent.packets[path.sent.count - 1];
    try std.testing.expect(last_pkt.retransmit_frames.items.len > 0);
    const first_frame = last_pkt.retransmit_frames.items[0];
    switch (first_frame) {
        .path_challenge => |pc| {
            try std.testing.expect(std.mem.eql(u8, &expected_token, &pc.data));
        },
        else => return error.FirstFrameNotPathChallenge,
    }
}

// -- Connection-level fuzz harnesses (state-machine invariant fuzzing) ----
//
// These sit one layer above the per-buffer fuzz harnesses landed in
// `recv_stream.zig` / `send_stream.zig` / `flow_control.zig` /
// `path_validator.zig` / `ack_tracker.zig`. The per-buffer harnesses
// proved each state machine in isolation; here we drive a fully
// constructed `Connection` so the fuzzer also exercises the
// integration paths that include `bytes_resident` accounting against
// `max_connection_memory`, peer-state stream-count gating, and the
// per-path migration rate limiter / validator wiring.
//
// Each harness uses `std.testing.allocator` and `defer conn.destroy()`
// so a failed assertion still cleans up; aborting on uninteresting
// input is `return` (not `error`) to keep the corpus tight.

test "advertiseAlternativeV4Address rejects client role" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    try std.testing.expectError(
        Error.NotServerContext,
        conn.advertiseAlternativeV4Address(.{ 192, 0, 2, 1 }, 4433, .{}),
    );
    try std.testing.expectError(
        Error.NotServerContext,
        conn.advertiseAlternativeV6Address(@splat(0), 4433, .{}),
    );
}

test "advertiseAlternative*Address rejects when peer hasn't advertised support" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    // No peer transport params at all → predicate returns false.
    try std.testing.expect(!conn.peerSupportsAlternativeAddress());
    try std.testing.expectError(
        Error.AlternativeAddressNotNegotiated,
        conn.advertiseAlternativeV4Address(.{ 192, 0, 2, 1 }, 4433, .{}),
    );

    // Peer params present but flag absent → still rejected.
    conn.cached_peer_transport_params = .{ .alternative_address = false };
    try std.testing.expect(!conn.peerSupportsAlternativeAddress());
    try std.testing.expectError(
        Error.AlternativeAddressNotNegotiated,
        conn.advertiseAlternativeV6Address(@splat(0), 4433, .{}),
    );
}

test "advertiseAlternativeV4Address queues a frame and increments the shared sequence" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .alternative_address = true };
    try std.testing.expect(conn.peerSupportsAlternativeAddress());

    const seq0 = try conn.advertiseAlternativeV4Address(
        .{ 192, 0, 2, 1 },
        4433,
        .{ .preferred = true },
    );
    const seq1 = try conn.advertiseAlternativeV6Address(
        @splat(0),
        4433,
        .{ .retire = true },
    );
    const seq2 = try conn.advertiseAlternativeV4Address(
        .{ 198, 51, 100, 7 },
        4433,
        .{},
    );

    try std.testing.expectEqual(@as(u64, 0), seq0);
    try std.testing.expectEqual(@as(u64, 1), seq1);
    try std.testing.expectEqual(@as(u64, 2), seq2);
    try std.testing.expectEqual(@as(usize, 3), conn.pending_frames.alternative_addresses.items.len);

    // The queue order matches the call order so the sequence numbers
    // come out monotonically increasing on the wire.
    const items = conn.pending_frames.alternative_addresses.items;
    try std.testing.expect(items[0] == .v4);
    try std.testing.expectEqual(@as(u64, 0), items[0].v4.status_sequence_number);
    try std.testing.expect(items[0].v4.preferred);
    try std.testing.expect(items[1] == .v6);
    try std.testing.expectEqual(@as(u64, 1), items[1].v6.status_sequence_number);
    try std.testing.expect(items[1].v6.retire);
    try std.testing.expect(items[2] == .v4);
    try std.testing.expectEqual(@as(u64, 2), items[2].v4.status_sequence_number);

    // canSend reports work pending while the queue is non-empty so the
    // outer poll loop won't park before we drain.
    try std.testing.expect(conn.canSend());
}

test "lost ALTERNATIVE_V4_ADDRESS frame is requeued for retransmission" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);

    const original: frame_types.AlternativeV4Address = .{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 9,
        .address = .{ 198, 51, 100, 7 },
        .port = 4433,
    };
    try packet.addRetransmitFrame(allocator, .{ .alternative_v4_address = original });

    const requeued = try conn.dispatchLostControlFramesOnPath(&packet, conn.activePath().id);
    try std.testing.expect(requeued);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.alternative_addresses.items.len);

    const got = conn.pending_frames.alternative_addresses.items[0];
    try std.testing.expect(got == .v4);
    try std.testing.expectEqual(original.status_sequence_number, got.v4.status_sequence_number);
    try std.testing.expectEqual(original.address, got.v4.address);
    try std.testing.expectEqual(original.port, got.v4.port);
    try std.testing.expectEqual(original.preferred, got.v4.preferred);
}

test "lost ALTERNATIVE_V6_ADDRESS frame is requeued for retransmission" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    var packet: sent_packets_mod.SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer packet.deinit(allocator);

    const original: frame_types.AlternativeV6Address = .{
        .preferred = false,
        .retire = true,
        .status_sequence_number = 42,
        .address = .{
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
        },
        .port = 8443,
    };
    try packet.addRetransmitFrame(allocator, .{ .alternative_v6_address = original });

    const requeued = try conn.dispatchLostControlFramesOnPath(&packet, conn.activePath().id);
    try std.testing.expect(requeued);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_frames.alternative_addresses.items.len);

    const got = conn.pending_frames.alternative_addresses.items[0];
    try std.testing.expect(got == .v6);
    try std.testing.expectEqual(original.status_sequence_number, got.v6.status_sequence_number);
    try std.testing.expectEqual(original.retire, got.v6.retire);
    try std.testing.expectEqualSlices(u8, &original.address, &got.v6.address);
}

test "advertise errors with AlternativeAddressSequenceExhausted at the u64 boundary" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    const conn = try Connection.createServer(allocator, ctx);
    defer conn.destroy();

    conn.cached_peer_transport_params = .{ .alternative_address = true };
    // Pre-position the counter one short of u64::max so the next
    // advertise drains the very last allocatable sequence and the
    // call after that fails closed.
    conn.next_alternative_address_sequence = std.math.maxInt(u64) - 1;

    const last = try conn.advertiseAlternativeV4Address(.{ 0, 0, 0, 0 }, 0, .{});
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64) - 1), last);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), conn.next_alternative_address_sequence);

    // Saturating would silently violate §6 ¶5 by reissuing
    // u64::max-1 (the receiver dedupes on equal sequence numbers and
    // drops the duplicate as a retransmit). The boundary now fails
    // closed.
    try std.testing.expectError(
        Error.AlternativeAddressSequenceExhausted,
        conn.advertiseAlternativeV4Address(.{ 0, 0, 0, 0 }, 0, .{}),
    );
    // V6 sibling shares the counter and trips the same boundary.
    try std.testing.expectError(
        Error.AlternativeAddressSequenceExhausted,
        conn.advertiseAlternativeV6Address(@splat(0), 0, .{}),
    );
}

// -- ALT-4 receive surface -------------------------------------------

test "handleAlternativeAddressV4 surfaces a typed event for a fresh sequence" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handleAlternativeAddressV4(.{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    });

    const event = conn.pollEvent() orelse return error.TestUnexpectedNull;
    try std.testing.expect(event == .alternative_server_address);
    const inner = event.alternative_server_address;
    try std.testing.expect(inner == .v4);
    try std.testing.expectEqual(@as(u64, 1), inner.statusSequenceNumber());
    try std.testing.expect(inner.preferred());
    try std.testing.expect(!inner.retire());
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &inner.v4.address);
    try std.testing.expectEqual(@as(u16, 4433), inner.v4.port);
    try std.testing.expectEqual(@as(?u64, 1), conn.highestAlternativeAddressSequenceSeen());

    // Queue is now drained.
    try std.testing.expect(conn.pollEvent() == null);
}

test "handleAlternativeAddressV6 surfaces a typed event with the IPv6 address bytes" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const ipv6: [16]u8 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0x42,
    };
    conn.handleAlternativeAddressV6(.{
        .preferred = false,
        .retire = true,
        .status_sequence_number = 7,
        .address = ipv6,
        .port = 8443,
    });

    const event = conn.pollEvent() orelse return error.TestUnexpectedNull;
    try std.testing.expect(event.alternative_server_address == .v6);
    const v6 = event.alternative_server_address.v6;
    try std.testing.expectEqualSlices(u8, &ipv6, &v6.address);
    try std.testing.expectEqual(@as(u16, 8443), v6.port);
    try std.testing.expectEqual(@as(u64, 7), v6.status_sequence_number);
    try std.testing.expect(v6.retire);
    try std.testing.expectEqual(@as(?u64, 7), conn.highestAlternativeAddressSequenceSeen());
}

test "handleAlternativeAddressV4 ignores a duplicate Status Sequence Number" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    const original: frame_types.AlternativeV4Address = .{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 5,
        .address = .{ 192, 0, 2, 1 },
        .port = 4433,
    };
    conn.handleAlternativeAddressV4(original);
    conn.handleAlternativeAddressV4(original); // idempotent retransmit

    // First call queued the event; second call MUST NOT.
    try std.testing.expect(conn.pollEvent() != null);
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expectEqual(@as(?u64, 5), conn.highestAlternativeAddressSequenceSeen());
}

test "handleAlternativeAddressV4 drops a stale (lower) sequence as out-of-order delivery" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handleAlternativeAddressV4(.{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 10,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    });
    // Stale reorder: a packet carrying seq=3 arrives after seq=10.
    // QUIC's app-PN space allows that. The receiver MUST NOT close;
    // the older update is treated as superseded.
    conn.handleAlternativeAddressV4(.{
        .preferred = true,
        .retire = false,
        .status_sequence_number = 3,
        .address = .{ 198, 51, 100, 7 },
        .port = 4433,
    });

    // Only the seq=10 event surfaces; the stale seq=3 is dropped.
    const event = conn.pollEvent() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(@as(u64, 10), event.alternative_server_address.statusSequenceNumber());
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expectEqual(@as(?u64, 10), conn.highestAlternativeAddressSequenceSeen());
}

test "monotonicity tracker shares the sequence space across V4 and V6" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    const conn = try Connection.createClient(allocator, ctx, "x");
    defer conn.destroy();

    conn.handleAlternativeAddressV4(.{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    });
    conn.handleAlternativeAddressV6(.{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 2,
        .address = @splat(0),
        .port = 0,
    });
    // Stale V4 with seq=1 (already-seen) — silently absorbed.
    conn.handleAlternativeAddressV4(.{
        .preferred = false,
        .retire = false,
        .status_sequence_number = 1,
        .address = .{ 0, 0, 0, 0 },
        .port = 0,
    });

    // Two events queued; the seq-1 retransmit is dropped.
    const e1 = conn.pollEvent() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(@as(u64, 1), e1.alternative_server_address.statusSequenceNumber());
    try std.testing.expect(e1.alternative_server_address == .v4);
    const e2 = conn.pollEvent() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(@as(u64, 2), e2.alternative_server_address.statusSequenceNumber());
    try std.testing.expect(e2.alternative_server_address == .v6);
    try std.testing.expect(conn.pollEvent() == null);
    try std.testing.expectEqual(@as(?u64, 2), conn.highestAlternativeAddressSequenceSeen());
}

// -- RFC 9368 §6 client-side compatible-version-negotiation upgrade --
