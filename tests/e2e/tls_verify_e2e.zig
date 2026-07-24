//! Hermetic end-to-end coverage for the verifying TLS paths the
//! wrappers expose without a `tls_context_override`:
//!
//!   1. `Client.Config.ca_pem` — pin the self-signed test fixture as
//!      the only trust anchor and complete a *verified* handshake
//!      (the fixture is CA:TRUE with SAN localhost/127.0.0.1, so it
//!      chains to itself and matches `server_name = "localhost"`).
//!   2. The same pinned client MUST reject a `server_name` outside
//!      the certificate's SAN — proving `ca_pem` buys identity
//!      binding (X509_VERIFY_PARAM_set1_host via `setHostname`),
//!      not just chain validation.
//!   3. `Server.Config.client_ca_pem` + `Client.Config.client_cert_pem`
//!      / `client_key_pem` — full mTLS: the server requires a client
//!      certificate chaining to its pinned roots, and the handshake
//!      completes when the client presents one.
//!   4. The same mTLS server MUST refuse a client that presents no
//!      certificate (`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`)...
//!   5. ...and MUST refuse a client presenting a certificate that
//!      does not chain to `client_ca_pem` (the `test_untrusted` pair
//!      shares the profile of the trusted fixture but not its key),
//!      proving the server *verifies* the chain rather than merely
//!      requiring presence.
//!   6. The mTLS posture survives `replaceTlsContext(.{ .pem = ... })`
//!      rotation, and the `.override` variant is rejected while mTLS
//!      is configured (it would silently drop enforcement).
//!   7. `tls.pem` failure-path coverage on real fixtures: a bundle
//!      with a malformed trailing block, a garbage key after a valid
//!      chain, and a well-formed key that mismatches the chain.
//!
//! Before 0.10.0 scenarios 1-3 were untestable by construction: a
//! non-null `ca_pem` was rejected outright, so every e2e handshake in
//! this suite ran with `insecure_skip_verify = true`. The pump loop
//! mirrors `server_client_handshake.zig`.

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const peer_addr: quic_zig.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xab), .port = 0 } };

/// Pump both directions until the client and ANY server slot report
/// handshakeDone, or the step budget runs out. `base_us` keeps time
/// monotonic when several drives run against one Server. Returns
/// true on a completed handshake. `try`s every error — use only for
/// scenarios expected to succeed.
fn driveToCompletion(cli: *quic_zig.Client, srv: *quic_zig.Server, base_us: u64) !bool {
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

/// Pump both directions for a scenario that MUST fail. Two rejection
/// shapes count: an error on either side (client-side chain /
/// hostname failure surfaces as `HandshakeFailed` / `PeerAlerted`
/// from poll/handle/tick), or a recorded close event (a server-side
/// mTLS refusal is handled inside `Server.feed`, which closes the
/// slot — no error escapes, but the slot latches `closeEvent`).
///
/// Deliberately keeps pumping after the CLIENT reports
/// handshakeDone: in TLS 1.3 the client's handshake completes before
/// the server has processed the client's Certificate flight, so a
/// server-side refusal (empty or untrusted client cert) arrives
/// after that point. The invariant that must hold for every
/// rejection scenario is that the SERVER never reaches a completed
/// handshake.
///
/// Guards against passing vacuously: the client bootstrap `advance`
/// must succeed and at least one datagram must actually reach
/// `Server.feed` — a rejection observed before the server ever saw
/// the attempt would prove nothing about the verifying path.
///
/// Returns true if a rejection was observed, the server received at
/// least one datagram, and no server slot ever completed the
/// handshake.
fn driveExpectingRejection(cli: *quic_zig.Client, srv: *quic_zig.Server, base_us: u64) !bool {
    var rx: [4096]u8 = undefined;
    var saw_rejection = false;
    var server_completed = false;
    var fed_server: usize = 0;
    try cli.conn.advance();
    var step: u32 = 0;
    pump: while (step < 32) : (step += 1) {
        const now_us: u64 = base_us + @as(u64, step) * 1_000;
        while (true) {
            const len_opt = cli.conn.poll(&rx, now_us) catch {
                saw_rejection = true;
                break :pump;
            };
            const len = len_opt orelse break;
            _ = srv.feed(rx[0..len], peer_addr, now_us) catch {
                saw_rejection = true;
                break :pump;
            };
            fed_server += 1;
        }
        while (srv.drainStatelessResponse()) |_| {}
        for (srv.iterator()) |slot| {
            while (true) {
                const len_opt = slot.conn.poll(&rx, now_us) catch {
                    saw_rejection = true;
                    break :pump;
                };
                const len = len_opt orelse break;
                cli.conn.handle(rx[0..len], null, now_us) catch {
                    saw_rejection = true;
                    break :pump;
                };
            }
        }
        try srv.tick(now_us);
        cli.conn.tick(now_us) catch {
            saw_rejection = true;
            break :pump;
        };
        if (cli.conn.closeEvent() != null) {
            saw_rejection = true;
            break :pump;
        }
        for (srv.iterator()) |slot| {
            if (slot.conn.handshakeDone()) server_completed = true;
            if (slot.conn.closeEvent() != null) {
                saw_rejection = true;
                break :pump;
            }
        }
    }
    return saw_rejection and fed_server > 0 and !server_completed;
}

test "ca_pem pins the fixture root and the verified handshake completes (no insecure_skip_verify)" {
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost", // matches the fixture SAN
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
    });
    defer cli.deinit();

    try std.testing.expect(try driveToCompletion(&cli, &srv, 0));
}

test "ca_pem client rejects a server_name outside the certificate SAN (identity, not just chain)" {
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // The chain still verifies (same pinned root); only the hostname
    // differs from the SAN (localhost / 127.0.0.1). If this
    // handshake completes, `ca_pem` silently skipped identity
    // binding — the exact failure a private-CA embedder cannot
    // afford.
    var cli = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "not-the-cert.example",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
    });
    defer cli.deinit();

    try std.testing.expect(try driveExpectingRejection(&cli, &srv, 0));
}

test "ca_pem client rejects a server whose certificate chains to a different root" {
    // The server presents the untrusted fixture; the client pins the
    // trusted one. Same SAN, same profile, different key — so the
    // only thing that can fail the handshake is the chain check
    // against the pinned anchors. This is the test that catches an
    // installTrustAnchors regression to a no-op: the client context
    // is built with `verify = .none` and only the install flips it
    // to SSL_VERIFY_PEER, so a no-op would let this handshake
    // complete and the rejection assertion below fail.
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_untrusted_cert_pem,
        .tls_key_pem = common.test_untrusted_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
    });
    defer cli.deinit();

    try std.testing.expect(try driveExpectingRejection(&cli, &srv, 0));
}

test "mTLS: server requires a client certificate and the handshake completes when one is presented" {
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // The fixture doubles as the client identity: it is CA:TRUE and
    // self-signed, so it chains to itself against the server's
    // pinned bundle. Both verifying directions are live — no
    // insecure_skip_verify anywhere.
    var cli = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_key_pem,
    });
    defer cli.deinit();

    try std.testing.expect(try driveToCompletion(&cli, &srv, 0));
}

test "mTLS: a client presenting no certificate is refused" {
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .insecure_skip_verify = true, // this test targets the server-side gate
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    try std.testing.expect(try driveExpectingRejection(&cli, &srv, 0));
}

test "mTLS: a client certificate not chaining to client_ca_pem is refused" {
    // Distinguishes VERIFYING the presented chain from merely
    // REQUIRING one: a regression that kept
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT but accepted any presented
    // certificate would pass the no-cert test above and the happy
    // path — only this test catches it.
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
        .client_cert_pem = common.test_untrusted_cert_pem,
        .client_key_pem = common.test_untrusted_key_pem,
    });
    defer cli.deinit();

    try std.testing.expect(try driveExpectingRejection(&cli, &srv, 0));
}

test "mTLS posture survives replaceTlsContext(.pem) rotation; .override is rejected" {
    var srv = try quic_zig.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // An adopted override context would silently drop the
    // required-client-cert posture, so it is refused outright while
    // client_ca_pem is configured (validated before the context is
    // touched, so an undefined inner pointer is safe here).
    try std.testing.expectError(
        quic_zig.Server.Error.InvalidConfig,
        srv.replaceTlsContext(.{ .override = .{ .inner = undefined, .mode = .server } }),
    );

    // Hot cert rotation via the supported .pem path. Deleting the
    // client_ca_pem re-install in replaceTlsContext is a one-line
    // regression; this is the test that catches it.
    try srv.replaceTlsContext(.{ .pem = .{
        .cert_pem = common.test_cert_pem,
        .key_pem = common.test_key_pem,
    } });

    // A certificate-less client must still be refused post-rotation...
    var bare = try quic_zig.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer bare.deinit();
    try std.testing.expect(try driveExpectingRejection(&bare, &srv, 0));

    // ...and a certificate-bearing client must still complete
    // (proving rotation didn't just break TLS wholesale). Later
    // time base keeps the shared server's clock monotonic.
    var authed = try quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = common.test_cert_pem,
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_key_pem,
    });
    defer authed.deinit();
    try std.testing.expect(try driveToCompletion(&authed, &srv, 1_000_000));
}

test "tls.pem failure paths on real fixtures: truncated bundle, garbage key, mismatched key" {
    // A bundle whose SECOND block is malformed must fail loudly —
    // silently installing a prefix of the roots is how a truncated
    // secrets-manager payload turns into unexplained production
    // rejects (tls.pem distinguishes clean end-of-input from a
    // malformed block via PEM_R_NO_START_LINE).
    const truncated_bundle = common.test_cert_pem ++
        "-----BEGIN CERTIFICATE-----\nnot-base64!!\n";
    var cli_err = quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .ca_pem = truncated_bundle,
    });
    try std.testing.expectError(quic_zig.Client.Error.InvalidPem, cli_err);

    // Valid client chain + unparseable key.
    cli_err = quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = "-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n",
    });
    try std.testing.expectError(quic_zig.Client.Error.InvalidPem, cli_err);

    // Valid client chain + well-formed key belonging to a different
    // certificate — the classic wrong-key-file mistake. BoringSSL
    // checks key/leaf consistency eagerly inside SSL_CTX_use_PrivateKey
    // when a certificate is already installed, so the mismatch
    // surfaces as UsePrivateKeyFailed (KeyMismatch is the
    // check_private_key backstop, unreachable on this ordering).
    cli_err = quic_zig.Client.connect(.{
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_untrusted_key_pem,
    });
    try std.testing.expectError(quic_zig.Client.Error.UsePrivateKeyFailed, cli_err);
}
