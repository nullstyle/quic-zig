//! Hardening guide §11.2 #14 regression: all-unknown-frames payload.
//!
//! A peer that fills a 1-RTT packet with bytes that all decode as
//! unknown QUIC frame types must not be able to make the receiver
//! CPU-spin on the drain loop. The frame-level decoder rejects the
//! first unknown type byte with `error.UnknownFrameType` (RFC 9000
//! §12.4 — frames with type values not assigned in §19 are a
//! FRAME_ENCODING_ERROR), and `Connection.dispatchFrames` converts
//! that decode error into a FRAME_ENCODING_ERROR connection close, so
//! the cost of processing a thousand-byte all-unknown-frames payload
//! is one varint decode + one switch-default, regardless of how long
//! the payload is.
//!
//! What this file pins:
//!
//!   1. After driving a real handshake to completion (so both ends
//!      have application keys), we hand-seal a 1-RTT packet whose
//!      decrypted payload is ~1000 single-byte unknown-type varints
//!      (`0x21`, RFC 9000 §19 unallocated).
//!   2. Feeding that packet through `server.handle` succeeds (no error
//!      escapes) but transitions the connection into a closing state
//!      carrying FRAME_ENCODING_ERROR (0x07) — the decode fails on the
//!      very first byte, so the reject is constant-cost and fires
//!      *before* the drain loop observes the rest of the payload.
//!   3. The server is not pushed into any zombie state or CPU spin —
//!      it is cleanly closing, and a follow-up `poll` (which emits the
//!      CONNECTION_CLOSE) succeeds with no infinite loop or panic.
//!
//! Frame type byte choice: `0x21` is a single-byte QUIC varint
//! (top 2 bits `00`, value `0x21 = 33`) that is not allocated to any
//! v1 or draft-21 multipath frame type — see the type-byte table at
//! `src/frame/decode.zig:94-130`. A multi-byte choice (e.g. the
//! commonly-suggested `0x42`) would require *two* bytes per
//! "frame", halving payload density without gaining coverage.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const InitialDcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
const ClientScid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
const ServerScid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

/// Drive a real Initial/Handshake/1-RTT exchange between two
/// `quic_zig.Connection`s until both sides have application keys. Mirror
/// of the loop in `path_challenge_flood_smoke.zig` — kept inline so
/// this file does not collide with parallel agents editing the
/// existing e2e files.
fn driveHandshake(
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
    start_now_us: u64,
) !u64 {
    var buf_c2s: [2048]u8 = undefined;
    var buf_s2c: [2048]u8 = undefined;
    var iters: u32 = 0;
    var now_us = start_now_us;
    while (iters < 100) : (iters += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        if (try client.poll(&buf_c2s, now_us)) |n| {
            try server.handle(buf_c2s[0..n], null, now_us);
        }
        if (try server.poll(&buf_s2c, now_us)) |n| {
            try client.handle(buf_s2c[0..n], null, now_us);
        }
        now_us += 10_000;
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
    return now_us;
}

/// Stand up a paired client/server `Connection` ready for 1-RTT
/// frames.
fn buildPair(
    allocator: std.mem.Allocator,
    server_tls: *boringssl.tls.Context,
    client_tls: *boringssl.tls.Context,
) !struct {
    client: *quic_zig.Connection,
    server: *quic_zig.Connection,
} {
    const protos = [_][]const u8{"hq-test"};
    server_tls.* = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);

    client_tls.* = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });

    const client = try allocator.create(quic_zig.Connection);
    errdefer allocator.destroy(client);
    client.* = try quic_zig.Connection.initClient(allocator, client_tls.*, "localhost");
    errdefer client.deinit();

    const server = try allocator.create(quic_zig.Connection);
    errdefer allocator.destroy(server);
    server.* = try quic_zig.Connection.initServer(allocator, server_tls.*);
    errdefer server.deinit();

    try client.bind();
    try server.bind();

    try client.setLocalScid(&ClientScid);
    try client.setInitialDcid(&InitialDcid);
    try client.setPeerDcid(&InitialDcid);
    try server.setLocalScid(&ServerScid);

    var tp = common.defaultParams();
    // Advertise DATAGRAM support so the replay test below can exercise
    // the (non-idempotent) DATAGRAM receive path; harmless for the
    // unknown-frames test, which sends no DATAGRAMs.
    tp.max_datagram_frame_size = 1200;
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try client.advance();
    return .{ .client = client, .server = server };
}

test "all-unknown-frames payload: Connection rejects with FRAME_ENCODING_ERROR (no CPU spin) (§11.2 #14)" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    var pair = try buildPair(allocator, &server_tls, &client_tls);
    defer {
        pair.client.deinit();
        allocator.destroy(pair.client);
        pair.server.deinit();
        allocator.destroy(pair.server);
        server_tls.deinit();
        client_tls.deinit();
    }

    const client = pair.client;
    const server = pair.server;
    var now_us = try driveHandshake(client, server, 1_000_000);

    // Capture the post-handshake baseline so we can assert the
    // server didn't slip into a zombie state after rejecting the
    // unknown-frames payload.
    const baseline_close = server.closeState();
    try std.testing.expectEqual(quic_zig.CloseState.open, baseline_close);

    // Drain any handshake tail so the server's PN tracker is on a
    // settled application baseline before we inject the malicious
    // packet.
    var drain: [2048]u8 = undefined;
    if (try client.poll(&drain, now_us)) |n| {
        try server.handle(drain[0..n], null, now_us);
    }
    if (try server.poll(&drain, now_us)) |n| {
        try client.handle(drain[0..n], null, now_us);
    }
    now_us += 10_000;

    // Build the malicious 1-RTT payload: ~1000 bytes of `0x21`. Each
    // byte is a self-contained 1-byte varint that decodes to 33 —
    // not in any frame-type table, so `frame.decode` returns
    // `error.UnknownFrameType` on the first iteration of the
    // `dispatchFrames` drain loop.
    const unknown_byte: u8 = 0x21;
    var payload_buf: [1024]u8 = undefined;
    @memset(&payload_buf, unknown_byte);
    const payload = payload_buf[0..1000];

    // Pull the client's outbound 1-RTT keys + next PN. We use the
    // CLIENT's write keys (= server's read keys) so the server
    // accepts the AEAD on the receive side. The DCID is the server's
    // local SCID — what the server expects to see on the wire.
    const keys = (try client.packetKeys(.application, .write)) orelse
        return error.NoApplicationWriteKeys;
    const client_path = client.paths.get(0) orelse return error.NoClientPath;
    const pn = client_path.app_pn_space.nextPn() orelse
        return error.PnSpaceExhausted;
    const dcid = server.local_scid.slice();

    // Seal the malicious payload as a real protected 1-RTT packet.
    var packet_buf: [1500]u8 = undefined;
    const packet_len = try quic_zig.wire.short_packet.seal1Rtt(&packet_buf, .{
        .dcid = dcid,
        .pn = pn,
        .largest_acked = null,
        .payload = payload,
        .keys = &keys,
    });

    // Feed the packet through the public `handle` API and pin the
    // observed behavior. The dispatch path is:
    //
    //   server.handle
    //     -> handleOnePacket (decrypts the 1-RTT)
    //     -> dispatchFrames (.application)
    //       -> frame.iter(payload).next()
    //         -> decode(payload[0..]) at byte 0x21
    //           -> Error.UnknownFrameType
    //             -> dispatchFrames catches it -> close(FRAME_ENCODING_ERROR)
    //
    // `dispatchFrames` converts the decode error into a connection
    // close (RFC 9000 §12.4) instead of letting it escape, so `handle`
    // returns *successfully* — a single malformed frame from an
    // authenticated peer can no longer tear down the embedder's loop.
    // The load-bearing property is unchanged: the reject fires after
    // the FIRST byte of the payload, not after walking all 1000 bytes.
    const before_recv_pn = if (server.paths.get(0)) |sp|
        sp.app_pn_space.received.largest
    else
        null;
    try server.handle(packet_buf[0..packet_len], null, now_us);

    // The server's app PN tracker should have recorded the packet's
    // PN before the frame-level reject fired (frames are dispatched
    // *after* the PN is recorded — see
    // `recordApplicationReceivedPacket` upstream of `dispatchFrames`
    // in `handleOnePacket`). This pins that the reject is at the
    // frame layer, not the AEAD/PN layer.
    const after_recv_pn = if (server.paths.get(0)) |sp|
        sp.app_pn_space.received.largest
    else
        null;
    try std.testing.expect(after_recv_pn != null);
    if (before_recv_pn) |prev| {
        try std.testing.expect(after_recv_pn.? > prev);
    }

    // The connection is now cleanly CLOSING with a locally-originated
    // FRAME_ENCODING_ERROR (0x07) — not the post-handshake baseline,
    // and not a zombie/open state.
    try std.testing.expect(baseline_close == .open);
    try std.testing.expectEqual(quic_zig.CloseState.closing, server.closeState());
    const ce = server.closeEvent() orelse return error.NoCloseEvent;
    try std.testing.expectEqual(@as(u64, 0x07), ce.error_code);

    // A follow-up `poll` (which emits the CONNECTION_CLOSE) succeeds
    // with no infinite loop or panic; the connection stays closing.
    var poll_buf: [2048]u8 = undefined;
    _ = try server.poll(&poll_buf, now_us + 1_000);
    try std.testing.expectEqual(quic_zig.CloseState.closing, server.closeState());
}

test "replayed 1-RTT DATAGRAM packet is delivered only once (L1)" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    var pair = try buildPair(allocator, &server_tls, &client_tls);
    defer {
        pair.client.deinit();
        allocator.destroy(pair.client);
        pair.server.deinit();
        allocator.destroy(pair.server);
        server_tls.deinit();
        client_tls.deinit();
    }

    const client = pair.client;
    const server = pair.server;
    var now_us = try driveHandshake(client, server, 1_000_000);

    // Settle the handshake tail so the server's app PN space is on a
    // clean baseline.
    var drain: [2048]u8 = undefined;
    if (try client.poll(&drain, now_us)) |n| try server.handle(drain[0..n], null, now_us);
    if (try server.poll(&drain, now_us)) |n| try client.handle(drain[0..n], null, now_us);
    now_us += 10_000;

    // A 1-RTT payload of exactly one DATAGRAM frame (type 0x30 = no LEN,
    // data runs to the end of the packet — legal as the last frame).
    const dg_data = "replay-me";
    var payload_buf: [64]u8 = undefined;
    payload_buf[0] = 0x30;
    @memcpy(payload_buf[1 .. 1 + dg_data.len], dg_data);
    const payload = payload_buf[0 .. 1 + dg_data.len];

    const keys = (try client.packetKeys(.application, .write)) orelse
        return error.NoApplicationWriteKeys;
    const client_path = client.paths.get(0) orelse return error.NoClientPath;
    const pn = client_path.app_pn_space.nextPn() orelse return error.PnSpaceExhausted;
    const dcid = server.local_scid.slice();

    var packet_buf: [1500]u8 = undefined;
    const packet_len = try quic_zig.wire.short_packet.seal1Rtt(&packet_buf, .{
        .dcid = dcid,
        .pn = pn,
        .largest_acked = null,
        .payload = payload,
        .keys = &keys,
    });

    const before = server.pendingDatagrams();

    // First delivery: the DATAGRAM is accepted and queued once.
    try server.handle(packet_buf[0..packet_len], null, now_us);
    try std.testing.expectEqual(before + 1, server.pendingDatagrams());
    const resident_after_first = server.bytes_resident;

    // Replay the identical sealed packet (same PN). It re-decrypts fine
    // but the duplicate-PN guard must skip frame dispatch: no second
    // DATAGRAM delivery, and no second resident-bytes charge.
    try server.handle(packet_buf[0..packet_len], null, now_us + 1_000);
    try std.testing.expectEqual(before + 1, server.pendingDatagrams());
    try std.testing.expectEqual(resident_after_first, server.bytes_resident);
}
