// Split from _state_tests.zig — see that file for the area index.
// Test bodies are verbatim; only this alias header is per-file.

const std = @import("std");
const boringssl = @import("boringssl");
const state = @import("state.zig");
const CloseSource = state.CloseSource;
const CloseState = state.CloseState;
const Connection = state.Connection;
const ConnectionId = state.ConnectionId;
const EncryptionLevel = state.EncryptionLevel;
const Error = state.Error;
const TransportParams = state.TransportParams;
const initial_keys_mod = state.initial_keys_mod;
const long_packet_mod = state.long_packet_mod;
const quic_version_1 = state.quic_version_1;
const short_packet_mod = state.short_packet_mod;
const transport_error_transport_parameter = state.transport_error_transport_parameter;
const wire_header = state.wire_header;

const quic_version_2 = initial_keys_mod.quic_version_2;

test "Version Negotiation with no compatible version closes terminally" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const versions = [_]u8{
        0x6b, 0x33, 0x43, 0xcf,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_000);

    try std.testing.expect(conn.isClosed());
    try std.testing.expectEqual(CloseState.closed, conn.closeState());
    const close_event = conn.closeEvent().?;
    try std.testing.expectEqual(CloseSource.version_negotiation, close_event.source);
    try std.testing.expectEqualStrings("no compatible QUIC version", close_event.reason);
}

test "Version Negotiation is ignored when it lists QUIC v1 or has wrong CID echo" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const includes_v1 = [_]u8{
        0x00, 0x00, 0x00, 0x01,
        0xff, 0x00, 0x00, 0x20,
    };
    var packet: [128]u8 = undefined;
    var n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &includes_v1,
    } });
    try conn.handle(packet[0..n], null, 4_000_000);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .scid = try wire_header.ConnId.fromSlice(&odcid),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_001);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation is ignored with wrong SCID echo or malformed versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&client_scid),
        .scid = try wire_header.ConnId.fromSlice(&.{ 0xde, 0xad }),
        .versions_bytes = &other_versions,
    } });
    try conn.handle(packet[0..n], null, 4_000_002);
    try std.testing.expectEqual(CloseState.open, conn.closeState());

    var malformed: [128]u8 = undefined;
    var pos: usize = 0;
    malformed[pos] = 0x80;
    pos += 1;
    std.mem.writeInt(u32, malformed[pos..][0..4], 0, .big);
    pos += 4;
    malformed[pos] = @intCast(client_scid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + client_scid.len], &client_scid);
    pos += client_scid.len;
    malformed[pos] = @intCast(odcid.len);
    pos += 1;
    @memcpy(malformed[pos .. pos + odcid.len], &odcid);
    pos += odcid.len;
    @memcpy(malformed[pos .. pos + 3], &[_]u8{ 0x6b, 0x33, 0x43 });
    pos += 3;

    try conn.handle(malformed[0..pos], null, 4_000_003);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Version Negotiation packets are ignored by servers" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const other_versions = [_]u8{ 0x6b, 0x33, 0x43, 0xcf };
    var packet: [128]u8 = undefined;
    const n = try wire_header.encode(&packet, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(&.{ 8, 7, 6, 5 }),
        .scid = try wire_header.ConnId.fromSlice(&.{ 1, 2, 3, 4 }),
        .versions_bytes = &other_versions,
    } });

    try conn.handle(packet[0..n], null, 4_000_004);
    try std.testing.expectEqual(CloseState.open, conn.closeState());
    try std.testing.expect(conn.closeEvent() == null);
}

test "Retry is accepted once and re-arms Initial crypto with token" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const retry_token = "retry-token";
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = retry_token,
    });

    const sent_copy = try allocator.dupe(u8, "client hello");
    try conn.sent_crypto[EncryptionLevel.initial.idx()].append(allocator, .{
        .pn = 0,
        .offset = 0,
        .data = sent_copy,
    });
    try conn.sent[0].record(.{
        .pn = 0,
        .sent_time_us = 100,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    conn.pn_spaces[0].next_pn = 9;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, retry_token, conn.retry_token.items);
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.peer_dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, conn.initial_dcid.slice());
    try std.testing.expectEqualSlices(u8, &odcid, conn.original_initial_dcid.slice());
    try std.testing.expectEqual(@as(u64, 9), conn.pn_spaces[0].next_pn);
    try std.testing.expectEqual(@as(u32, 0), conn.sent[0].count);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_retx[EncryptionLevel.initial.idx()].items.len);

    var out: [1500]u8 = undefined;
    const n = (try conn.pollLevel(.initial, &out, 4_000_001)).?;
    const parsed = try wire_header.parse(out[0..n], 0);
    try std.testing.expect(parsed.header == .initial);
    try std.testing.expectEqualSlices(u8, retry_token, parsed.header.initial.token);
}

test "Retry with invalid integrity tag is ignored" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    try conn.setPeerDcid(&odcid);
    try conn.setLocalScid(&client_scid);

    var packet: [256]u8 = undefined;
    const retry_len = try long_packet_mod.sealRetry(&packet, .{
        .original_dcid = &odcid,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .retry_token = "retry-token",
    });
    packet[retry_len - 1] ^= 0x01;

    try conn.handle(packet[0..retry_len], null, 4_000_000);

    try std.testing.expect(!conn.retry_accepted);
    try std.testing.expectEqualSlices(u8, &odcid, conn.peer_dcid.slice());
    try std.testing.expectEqual(CloseState.open, conn.closeState());
}

test "Retry source CID transport parameter is validated" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    const odcid = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    try conn.setInitialDcid(&odcid);
    conn.retry_accepted = true;
    conn.retry_source_cid = ConnectionId.fromSlice(&retry_scid);
    conn.retry_source_cid_set = true;

    conn.cached_peer_transport_params = .{
        .original_destination_connection_id = ConnectionId.fromSlice(&odcid),
        .retry_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb }),
    };
    conn.validatePeerTransportConnectionIds();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    try std.testing.expectEqual(transport_error_transport_parameter, conn.lifecycle.pending_close.?.error_code);
    try std.testing.expectEqualStrings("retry source cid mismatch", conn.lifecycle.pending_close.?.reason);
}

test "server writeRetry emits a Retry addressed to the client Initial SCID" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const odcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const retry_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&odcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .dcid = &odcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var retry: [256]u8 = undefined;
    const retry_len = try conn.writeRetry(
        &retry,
        initial[0..initial_len],
        &retry_scid,
        "server-token",
    );

    const parsed = try wire_header.parse(retry[0..retry_len], 0);
    try std.testing.expect(parsed.header == .retry);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.retry.dcid.slice());
    try std.testing.expectEqualSlices(u8, &retry_scid, parsed.header.retry.scid.slice());
    try std.testing.expectEqualSlices(u8, "server-token", parsed.header.retry.retry_token);
    try std.testing.expect(try long_packet_mod.validateRetryIntegrity(&odcid, retry[0..retry_len]));
}

test "server writeVersionNegotiation echoes client CIDs and versions" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    const client_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5 };
    const init_keys = try initial_keys_mod.deriveInitialKeys(&client_dcid, false);
    const keys = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret);

    var initial: [256]u8 = undefined;
    const initial_len = try long_packet_mod.sealInitial(&initial, .{
        .version = 0x6b3343cf,
        .dcid = &client_dcid,
        .scid = &client_scid,
        .pn = 0,
        .payload = "CRYPTO",
        .keys = &keys,
    });

    var vn: [128]u8 = undefined;
    const vn_len = try conn.writeVersionNegotiation(
        &vn,
        initial[0..initial_len],
        &.{quic_version_1},
    );

    const parsed = try wire_header.parse(vn[0..vn_len], 0);
    try std.testing.expect(parsed.header == .version_negotiation);
    try std.testing.expectEqualSlices(u8, &client_scid, parsed.header.version_negotiation.dcid.slice());
    try std.testing.expectEqualSlices(u8, &client_dcid, parsed.header.version_negotiation.scid.slice());
    try std.testing.expectEqual(@as(usize, 1), parsed.header.version_negotiation.versionCount());
    try std.testing.expectEqual(quic_version_1, parsed.header.version_negotiation.version(0));
}

test "peekNextBidi returns the id a limit-blocked retry will reuse" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();
    conn.peer_max_streams_bidi = 0;

    // A limit-blocked open doesn't consume the id, so peek still points at it
    // — this is the GOAWAY-gate-then-open sequence a downstream relies on.
    try std.testing.expectError(Error.StreamLimitExceeded, conn.openNextBidi());
    try std.testing.expectEqual(@as(u64, 0), conn.peekNextBidi());
    conn.peer_max_streams_bidi = 1;
    try std.testing.expectEqual(conn.peekNextBidi(), (try conn.openNextBidi()).id);
}

test "clientAcceptCompatibleVersion flips to an advertised candidate [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // The client-style local transport params advertise both the
    // wire version (v1) and a compatible upgrade target (v2).
    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    conn.local_transport_params = params;

    try std.testing.expect(conn.clientAcceptCompatibleVersion(quic_version_2));
    try std.testing.expectEqual(quic_version_2, conn.version);
}

test "clientAcceptCompatibleVersion rejects a candidate not on the client's list [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Client only advertises v1; the server choosing v2 is unsolicited
    // and MUST be ignored (the inbound packet then fails AEAD auth
    // under wire-version keys, which is the spec-compliant fallback).
    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{quic_version_1});
    conn.local_transport_params = params;

    try std.testing.expect(!conn.clientAcceptCompatibleVersion(quic_version_2));
    try std.testing.expectEqual(quic_version_1, conn.version);
}

test "clientAcceptCompatibleVersion is a no-op for the active version [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    conn.local_transport_params = params;

    // Same-version flip returns false — nothing to do, no observability.
    try std.testing.expect(!conn.clientAcceptCompatibleVersion(quic_version_1));
    try std.testing.expectEqual(quic_version_1, conn.version);
}

test "clientAcceptCompatibleVersion rejects unknown wire versions [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{ quic_version_1, 0xdeadbeef });
    conn.local_transport_params = params;

    // Even if the client misconfigured itself with a version we
    // can't derive Initial keys for, the upgrade hook silently
    // declines so the connection just falls back to wire-version
    // AEAD auth (which will fail and the packet is dropped).
    try std.testing.expect(!conn.clientAcceptCompatibleVersion(0xdeadbeef));
    try std.testing.expectEqual(quic_version_1, conn.version);
}

test "clientAcceptCompatibleVersion rejects upgrade after Initial keys discarded [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    conn.local_transport_params = params;
    // Simulate Initial-keys discard (post-handshake-complete state).
    conn.initial_keys_discarded = true;

    try std.testing.expect(!conn.clientAcceptCompatibleVersion(quic_version_2));
    try std.testing.expectEqual(quic_version_1, conn.version);
}

test "clientAcceptCompatibleVersion is server-role inert [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    // Build a server connection — it has no local transport params
    // advertising compatible_versions, but even if it did the hook
    // is client-only.
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    var params: TransportParams = .{};
    try params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    conn.local_transport_params = params;

    try std.testing.expect(!conn.clientAcceptCompatibleVersion(quic_version_2));
    try std.testing.expectEqual(quic_version_1, conn.version);
}

test "validatePeerTransportRole closes when chosen_version mismatches wire [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Active wire version is v1, but the (forged) peer params
    // advertise chosen_version=v2 first. Per RFC 9368 §6 ¶6/¶7
    // this is a downgrade attack and the connection MUST close.
    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{ quic_version_2, quic_version_1 });
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    const pending = conn.lifecycle.pending_close.?;
    try std.testing.expect(pending.is_transport);
    try std.testing.expectEqual(transport_error_transport_parameter, pending.error_code);
}

test "validatePeerTransportRole accepts matching chosen_version [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // Active wire version is v1 and the server's chosen_version
    // matches — the §6 downgrade guard is silent.
    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close == null);
}

test "validatePeerTransportRole accepts absent version_information [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    var conn = try Connection.initClient(allocator, ctx, "x");
    defer conn.deinit();

    // No compatible_versions on the peer side — a v0.x server that
    // never advertises version_information. The §6 downgrade guard
    // is silent because there is no `chosen_version` to check
    // against.
    var peer_params: TransportParams = .{};
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close == null);
}

// -- RFC 9368 §6 server-side downgrade-attack guard --

test "server validatePeerTransportRole accepts matching client chosen_version [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server `versions = [v1]`, client sent its first Initial under
    // v1 with `chosen_version = v1`. `initial_wire_version` matches
    // the advertised chosen_version → §6 downgrade guard stays silent.
    conn.initial_wire_version = quic_version_1;
    conn.version = quic_version_1;

    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{quic_version_1});
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close == null);
}

test "server validatePeerTransportRole accepts wire-version chosen after compatible upgrade [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server `versions = [v2, v1]`. Client sent its first Initial
    // under v1 with `chosen_version = v1, available_versions =
    // [v1, v2]`. Server picked the upgrade target v2 and flipped
    // `self.version` (via `applyPendingVersionUpgrade`), but
    // `initial_wire_version` still records the original v1 wire
    // version. The client's `chosen_version = v1` matches the
    // wire version, so the §6 guard MUST stay silent — even though
    // `self.version` is now v2.
    conn.initial_wire_version = quic_version_1;
    conn.version = quic_version_2;

    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{ quic_version_1, quic_version_2 });
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close == null);
}

test "server validatePeerTransportRole closes when client chosen_version mismatches wire [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Server `versions = [v1]`, client's first Initial arrived on
    // the wire under v1 (`initial_wire_version = v1`), but a
    // (forged) ClientHello advertises `chosen_version = v2`. Per
    // RFC 9368 §6 ¶6/¶7 this is a downgrade attack and the server
    // MUST close with TRANSPORT_PARAMETER_ERROR (0x08).
    conn.initial_wire_version = quic_version_1;
    conn.version = quic_version_1;

    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{ quic_version_2, quic_version_1 });
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close != null);
    const pending = conn.lifecycle.pending_close.?;
    try std.testing.expect(pending.is_transport);
    try std.testing.expectEqual(transport_error_transport_parameter, pending.error_code);
    try std.testing.expectEqualStrings(
        "client chosen_version mismatches wire version",
        pending.reason,
    );
}

test "server validatePeerTransportRole accepts when initial_wire_version is unset [RFC9368 §6]" {
    const allocator = std.testing.allocator;
    var ctx = try boringssl.tls.Context.initServer(.{});
    defer ctx.deinit();
    var conn = try Connection.initServer(allocator, ctx);
    defer conn.deinit();

    // Graceful fallback: when the snapshot wasn't captured (e.g.
    // a handshake started before this code was active, or a test
    // path that bypasses `acceptInitial`), the §6 server-side guard
    // ignores the check rather than rejecting the connection.
    try std.testing.expect(conn.initial_wire_version == null);

    var peer_params: TransportParams = .{};
    try peer_params.setCompatibleVersions(&.{ quic_version_2, quic_version_1 });
    peer_params.initial_source_connection_id = ConnectionId.fromSlice(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    conn.cached_peer_transport_params = peer_params;

    conn.validatePeerTransportRole();

    try std.testing.expect(conn.lifecycle.pending_close == null);
}

// -- HANDSHAKE_DONE → discard handshake keys (RFC 9001 §4.9.2) -------
//
// Failure mode (pre-fix): a quic_zig client kept its Handshake-level
// secrets and sent tracker alive forever after the TLS handshake
// completed. If the client's last Handshake-CRYPTO Finished went
// unACKed (typical: peers like quic-go and quiche discard their own
// Handshake send keys before sending an ACK at Handshake level, then
// only emit the implicit confirmation via HANDSHAKE_DONE), the client
// would PTO the Handshake space indefinitely. In the QUIC interop
// `rebind-addr` cell against the (slower) quiche server those PTO
// probes were the ONLY thing the client emitted during the post-rebind
// stall — and quiche's strict §4.9.2 server-side discard meant the
// probes were dropped as `invalid packet`, never reaching the path-
// validation code that would have unstuck the connection.
//
// The fix is RFC-mandated: §4.1.2 ¶2 says the client confirms the
// handshake on receipt of HANDSHAKE_DONE, and §4.9.2 says an endpoint
// MUST discard its handshake keys at confirmation. The three tests
// below pin the behavior at three abstraction levels.
