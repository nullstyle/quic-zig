//! End-to-end pins for peer identity access on established
//! connections — the mTLS embedder's "who am I talking to?" surface:
//!
//!   1. `Connection.peerCertSpkiDigest` on an mTLS loopback pair:
//!      each side's digest matches the fingerprint of the OTHER
//!      side's certificate, computed independently (openssl CLI
//!      pipeline on the fixture, embedded as a KAT constant).
//!   2. Null before the handshake completes (both roles) and on a
//!      server configured to verify-but-not-require client certs
//!      when the client presented none.
//!   3. The digest survives session resumption: a resumed connection
//!      reports the same server identity as the original full
//!      handshake (BoringSSL keeps the session's peer certificate).
//!
//! The KAT constants are the whole point: they pin the digest
//! PREIMAGE (DER-encoded SubjectPublicKeyInfo) against a computation
//! done outside this codebase, so a drift that would silently change
//! every embedder's PeerId fails here.

const std = @import("std");
const quic = @import("quic");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const peer_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xab), .port = 0 } };

/// SHA-256 over the DER-encoded SubjectPublicKeyInfo of
/// tests/data/test_cert.pem:
///   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER |
///   openssl dgst -sha256
const trusted_spki_sha256 = [32]u8{
    0xa9, 0xf8, 0x24, 0xa8, 0x09, 0x75, 0x5b, 0x5f,
    0x75, 0x7a, 0xa2, 0x40, 0x28, 0x93, 0x61, 0x8d,
    0x9d, 0x81, 0xaa, 0x98, 0x58, 0xde, 0x5f, 0x38,
    0xda, 0xe9, 0x5c, 0xca, 0xee, 0x40, 0xed, 0x46,
};

/// Same pipeline over tests/data/test_untrusted_cert.pem.
const untrusted_spki_sha256 = [32]u8{
    0xfb, 0x88, 0xec, 0xc4, 0xe0, 0xd8, 0xec, 0xfe,
    0x29, 0xc9, 0x36, 0xcc, 0x5c, 0x75, 0x25, 0xa7,
    0xa3, 0x06, 0xa3, 0x45, 0xbe, 0x3a, 0x9e, 0x0b,
    0xdb, 0x52, 0x24, 0x9b, 0x35, 0x99, 0x88, 0x9e,
};

/// Pump both directions until the client and ANY server slot report
/// handshakeDone (mirrors tls_verify_e2e.zig's helper).
fn driveToCompletion(cli: *quic.Client, srv: *quic.Server, base_us: u64) !bool {
    var rx: [4096]u8 = undefined;
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        const now_us: u64 = base_us + @as(u64, step) * 1_000;
        while (try cli.conn.poll(&rx, now_us)) |len| {
            _ = try srv.feed(rx[0..len], peer_addr, now_us);
        }
        while (srv.drainStatelessResponse()) |_| {}
        for (srv.iterator()) |slot| {
            while (try slot.conn.poll(&rx, now_us)) |len| {
                try cli.conn.handle(rx[0..len], null, now_us);
            }
        }
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone()) {
            for (srv.iterator()) |slot| {
                if (slot.conn.handshakeDone()) return true;
            }
        }
    }
    return false;
}

test "mTLS: each side's peerCertSpkiDigest matches the other side's independently-computed fingerprint" {
    // Distinct identities per role so a both-sides-read-the-same-cert
    // bug cannot pass vacuously: the server presents the trusted
    // fixture, the client presents the untrusted one, and the server
    // pins the UNTRUSTED cert as its client-CA (it is self-signed
    // CA:TRUE, so it chains to itself).
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_untrusted_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // Client-side pre-handshake: no server certificate exists yet.
    var cli = try quic.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
        .client_cert_pem = common.test_untrusted_cert_pem,
        .client_key_pem = common.test_untrusted_key_pem,
    });
    defer cli.deinit();
    try std.testing.expect(cli.conn.peerCertSpkiDigest() == null);

    try std.testing.expect(try driveToCompletion(&cli, &srv, 0));

    // Client authenticated the server (trusted fixture)...
    const client_digest = cli.conn.peerCertSpkiDigest() orelse
        return error.NoServerCertDigestClientSide;
    try std.testing.expectEqualSlices(u8, &trusted_spki_sha256, &client_digest);

    // ...and the server authenticated the client (untrusted fixture).
    const slot_digest = srv.iterator()[0].conn.peerCertSpkiDigest() orelse
        return error.NoClientCertDigestServerSide;
    try std.testing.expectEqualSlices(u8, &untrusted_spki_sha256, &slot_digest);
}

test "peerCertSpkiDigest is null server-side until the handshake completes" {
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_key_pem,
    });
    defer cli.deinit();

    // Drive exactly one client flight: the server opens a slot and
    // answers, but its handshake cannot be complete yet (TLS 1.3
    // needs the client's Finished, which has not been sent).
    var rx: [4096]u8 = undefined;
    try cli.conn.advance();
    while (try cli.conn.poll(&rx, 1_000)) |len| {
        _ = try srv.feed(rx[0..len], peer_addr, 1_000);
    }
    try std.testing.expectEqual(@as(usize, 1), srv.iterator().len);
    try std.testing.expect(!srv.iterator()[0].conn.handshakeDone());
    try std.testing.expect(srv.iterator()[0].conn.peerCertSpkiDigest() == null);

    // ...and completes to a non-null digest with the full drive.
    try std.testing.expect(try driveToCompletion(&cli, &srv, 2_000));
    const digest = srv.iterator()[0].conn.peerCertSpkiDigest() orelse
        return error.NoClientCertDigestServerSide;
    try std.testing.expectEqualSlices(u8, &trusted_spki_sha256, &digest);
}

test "optional client certs: server-side digest is null when none was presented" {
    // A server that VERIFIES client certs when presented but does not
    // REQUIRE them — `installTrustAnchors(.verify_peer)` on an
    // override context, the dual of `Config.client_ca_pem`'s require
    // posture. The certificate-less client completes the handshake;
    // the server must report no peer identity.
    const allocator = std.testing.allocator;

    var tls_ctx = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    defer tls_ctx.deinit();
    try tls_ctx.loadCertChainAndKey(common.test_cert_pem, common.test_key_pem);
    try quic.tls.pem.installTrustAnchors(tls_ctx, common.test_cert_pem, .verify_peer);

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        // Inert under an override (the context owns its cert); the
        // struct requires them, so hand it the same fixture.
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .tls_context_override = tls_ctx,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // this test targets the server side
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    try std.testing.expect(try driveToCompletion(&cli, &srv, 0));

    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    // No client certificate was presented: identity must read null,
    // never a stale or zero digest.
    try std.testing.expect(srv.iterator()[0].conn.peerCertSpkiDigest() == null);
    // The server still presented ITS certificate, so the client side
    // stays non-null — the gating is per-role evidence, not global.
    const client_digest = cli.conn.peerCertSpkiDigest() orelse
        return error.NoServerCertDigestClientSide;
    try std.testing.expectEqualSlices(u8, &trusted_spki_sha256, &client_digest);
}

/// Captures the latest resumption_state envelope (same shape as
/// zero_rtt_wrapper.zig's EnvelopeSink).
const EnvelopeSink = struct {
    allocator: std.mem.Allocator,
    captured: ?[]u8 = null,

    fn cb(user_data: ?*anyopaque, resumption_state: []const u8) void {
        const self: *EnvelopeSink = @ptrCast(@alignCast(user_data.?));
        const copy = self.allocator.dupe(u8, resumption_state) catch return;
        if (self.captured) |old| self.allocator.free(old);
        self.captured = copy;
    }

    fn deinit(self: *EnvelopeSink) void {
        if (self.captured) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }
};

test "peerCertSpkiDigest is unchanged on a resumed session" {
    const allocator = std.testing.allocator;
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    // Connection 1: full handshake, capture a session ticket. Keep
    // pumping past completion so the NewSessionTicket flight lands.
    {
        var cli = try quic.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test cert
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
            .new_session_callback = EnvelopeSink.cb,
            .new_session_user_data = &sink,
        });
        defer cli.deinit();

        var rx: [4096]u8 = undefined;
        try cli.conn.advance();
        var now_us: u64 = 1_000;
        var step: u32 = 0;
        while (step < 48 and sink.captured == null) : (step += 1) {
            while (try cli.conn.poll(&rx, now_us)) |len| {
                _ = try srv.feed(rx[0..len], peer_addr, now_us);
            }
            while (srv.drainStatelessResponse()) |_| {}
            for (srv.iterator()) |slot| {
                while (try slot.conn.poll(&rx, now_us)) |len| {
                    try cli.conn.handle(rx[0..len], null, now_us);
                }
            }
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 1_000;
        }
        try std.testing.expect(cli.conn.handshakeDone());
        try std.testing.expect(sink.captured != null);
        // Sanity: the full handshake's digest is the KAT.
        const digest = cli.conn.peerCertSpkiDigest() orelse
            return error.NoDigestOnFullHandshake;
        try std.testing.expectEqualSlices(u8, &trusted_spki_sha256, &digest);
    }

    // Connection 2: resume off the captured envelope. The resumed
    // handshake skips the Certificate flight, so a digestAccessor
    // that read the live flight state (rather than the session)
    // would return null here — it must not.
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli2.deinit();

    try std.testing.expect(try driveToCompletion(&cli2, &srv, 5_000_000));
    const resumed_digest = cli2.conn.peerCertSpkiDigest() orelse
        return error.NoDigestOnResumedHandshake;
    try std.testing.expectEqualSlices(u8, &trusted_spki_sha256, &resumed_digest);
}
