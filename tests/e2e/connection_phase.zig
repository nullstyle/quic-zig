//! End-to-end coverage for `Connection.phase()` and `beginGracefulShutdown`
//! across a real lifecycle.
//!
//! `phase()` composes the handshake epoch (initial → handshake →
//! established, from installed write keys) with the RFC 9000 §10 close
//! states (closing / draining / closed). The unit tests in
//! `_state_tests.zig` pin the `.initial` and `.closing` mappings against a
//! bare connection; this file drives an actual Initial/Handshake/1-RTT
//! exchange between two `Connection`s and asserts the live transitions an
//! embedder (e.g. an HTTP/3 layer gating stream creation / shutdown) will
//! observe: initial → established, then a local close → `.closing` on the
//! initiator and `.draining` on the peer that receives the CONNECTION_CLOSE.
//!
//! The handshake harness is kept inline (mirroring the other e2e files) so
//! this file does not depend on helpers private to them.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const InitialDcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
const ClientScid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
const ServerScid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };

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

    const tp = common.defaultParams();
    try client.setTransportParams(tp);
    try server.setTransportParams(tp);

    try client.advance();
    return .{ .client = client, .server = server };
}

test "phase(): initial -> established -> closing/draining across a real lifecycle" {
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

    // Pre-handshake: only Initial keys are installed on either side.
    try std.testing.expectEqual(quic_zig.ConnectionPhase.initial, client.phase());
    try std.testing.expectEqual(quic_zig.ConnectionPhase.initial, server.phase());

    var now_us = try driveHandshake(client, server, 1_000_000);

    // Both ends now hold 1-RTT (application) write keys.
    try std.testing.expectEqual(quic_zig.ConnectionPhase.established, client.phase());
    try std.testing.expectEqual(quic_zig.ConnectionPhase.established, server.phase());

    // A local close moves the initiator into the closing state (§10.2.1),
    // which wins over the (still-established) handshake epoch.
    client.close(false, 0x100, "app done");
    try std.testing.expectEqual(quic_zig.ConnectionPhase.closing, client.phase());

    // Deliver the CONNECTION_CLOSE; the peer enters draining (§10.2.2).
    var buf: [2048]u8 = undefined;
    now_us += 10_000;
    const n = (try client.poll(&buf, now_us)) orelse return error.NoCloseEmitted;
    try server.handle(buf[0..n], null, now_us);
    try std.testing.expectEqual(quic_zig.ConnectionPhase.draining, server.phase());
}

test "beginGracefulShutdown: local opens refused while an in-flight stream drains" {
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

    // Put a bidi stream in flight (opened + partially written) before the
    // shutdown, so we can prove it still completes afterwards.
    _ = try client.openBidi(0);
    _ = try client.streamWrite(0, "in-flight payload");

    // Begin graceful shutdown: new local opens are refused, but the
    // connection stays open/established (no CONNECTION_CLOSE).
    client.beginGracefulShutdown();
    try std.testing.expect(client.gracefulShutdownActive());
    try std.testing.expectError(error.ShuttingDown, client.openNextBidi());
    try std.testing.expectError(error.ShuttingDown, client.openNextUni());
    try std.testing.expectEqual(quic_zig.CloseState.open, client.closeState());
    try std.testing.expectEqual(quic_zig.ConnectionPhase.established, client.phase());

    // The in-flight stream still drains to the server in full, FIN included.
    // The whole payload fits one 1-RTT packet, so client -> server delivery
    // is all that's needed here (no ACK round-trip to make progress).
    try client.streamFinish(0);
    var c2s: [2048]u8 = undefined;
    var acc: [128]u8 = undefined;
    var acc_len: usize = 0;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        if (try client.poll(&c2s, now_us)) |n| try server.handle(c2s[0..n], null, now_us);
        acc_len += server.streamRead(0, acc[acc_len..]) catch 0;
        now_us += 10_000;
    }
    try std.testing.expectEqualStrings("in-flight payload", acc[0..acc_len]);

    // And the server observed the FIN — the stream reached a terminal recv
    // state, i.e. it genuinely completed rather than merely delivering bytes.
    try std.testing.expect(server.stream(0) == null or server.stream(0).?.recv.state != .recv);
}
