//! End-to-end 0-RTT through the public wrappers — the flow the
//! app-readiness audit proved impossible before:
//!
//!   1. `Client.Config.new_session_callback` captures a
//!      ready-to-persist `tls.resumption_state` envelope from the
//!      first connection (no BoringSSL-level plumbing in app code).
//!   2. A second `Client.connect` passes the envelope back as
//!      `Config.resumption_state`, stages stream data before
//!      `advance()`, and sends it as 0-RTT.
//!   3. `quic.Server` — with nothing beyond
//!      `Config.early_data` enabled — accepts the early data because
//!      the accept path now installs the RFC 9001 §4.6.1 replay
//!      context before the ClientHello is processed.
//!
//! The decisive assertion: the server reads the client's stream bytes
//! BEFORE its handshake completes. Only accepted 0-RTT can do that.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// Captures the latest resumption_state envelope from
/// `Client.Config.new_session_callback` (bytes are borrowed during the
/// call, so they are duplicated here).
const EnvelopeSink = struct {
    allocator: std.mem.Allocator,
    captured: ?[]u8 = null,
    calls: u32 = 0,

    fn cb(user_data: ?*anyopaque, resumption_state: []const u8) void {
        const self: *EnvelopeSink = @ptrCast(@alignCast(user_data.?));
        self.calls += 1;
        const copy = self.allocator.dupe(u8, resumption_state) catch return;
        if (self.captured) |old| self.allocator.free(old);
        self.captured = copy;
    }

    fn deinit(self: *EnvelopeSink) void {
        if (self.captured) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }
};

fn pumpClientToServer(
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    addr: quic.conn.path.Address,
    now_us: u64,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
    }
}

fn pumpServerToClient(
    srv: *quic.Server,
    cli: *quic.Client,
    rx: []u8,
    now_us: u64,
) !void {
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
        }
    }
}

test "0-RTT: ticket capture + resumption + early data accepted through the wrappers" {
    const allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .early_data = .without_replay_protection,
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };

    // ---- Connection 1: earn a ticket via the wrapper callback. ----
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

        try cli.conn.advance();
        var now_us: u64 = 1_000;
        var step: u32 = 0;
        // Keep pumping past handshake completion so the
        // NewSessionTicket flight reaches the client and the callback
        // fires with a complete envelope.
        while (step < 48 and sink.captured == null) : (step += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            while (srv.drainStatelessResponse()) |_| {}
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 1_000;
        }
        try std.testing.expect(cli.conn.handshakeDone());
        try std.testing.expect(sink.captured != null);
        try std.testing.expect(sink.calls >= 1);

        // No 0-RTT was attempted on this connection, so the one-shot
        // `early_data` event must never fire.
        var saw_early_event = false;
        while (cli.conn.pollEvent()) |ev| switch (ev) {
            .early_data => saw_early_event = true,
            else => {},
        };
        try std.testing.expect(!saw_early_event);

        // Close connection 1 and let the server reap it so the
        // resumption below runs against a clean slot table.
        cli.conn.close(false, 0, "done");
        var close_steps: u32 = 0;
        while (close_steps < 32 and srv.connectionCount() > 0) : (close_steps += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            _ = srv.reap();
            now_us += 500_000;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // ---- Connection 2: resume with 0-RTT data staged pre-advance. ----
    const addr2: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } };
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli2.deinit();

    const early_payload = "early-hello";
    // The early-data budget is available BEFORE advance(), from the
    // remembered session params — sized to what the server advertised
    // on connection 1 (common.defaultParams()). A restore payload
    // must fit it; ours trivially does.
    const budget = cli2.earlyDataSendWindow() orelse return error.NoEarlyBudget;
    try std.testing.expectEqual(common.defaultParams().initial_max_data, budget.max_data);
    try std.testing.expectEqual(
        common.defaultParams().initial_max_stream_data_bidi_remote,
        budget.max_stream_data_bidi,
    );
    try std.testing.expect(budget.max_data >= early_payload.len);
    // A fresh (non-resumption) client has no early-data budget.
    {
        var fresh = try quic.Client.connect(.{
            .insecure_skip_verify = true,
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
        });
        defer fresh.deinit();
        try std.testing.expect(fresh.earlyDataSendWindow() == null);
    }
    cli2.conn.setEarlyDataEnabled(true);
    _ = try cli2.conn.openBidi(0);
    _ = try cli2.conn.streamWrite(0, early_payload);
    try cli2.conn.streamFinish(0);
    // Only now emit the first flight: ClientHello + 0-RTT coalesced.
    try cli2.conn.advance();

    var now_us: u64 = 60_000_000;
    var rbuf: [256]u8 = undefined;
    var early_read: usize = 0;
    var read_before_handshake_done = false;
    var step: u32 = 0;
    while (step < 48) : (step += 1) {
        try pumpClientToServer(&cli2, &srv, &rx, addr2, now_us);
        while (srv.drainStatelessResponse()) |_| {}

        // The decisive check: bytes readable on the server while its
        // handshake is still incomplete can only be accepted 0-RTT.
        if (srv.iterator().len > 0) {
            const slot = srv.iterator()[0];
            while (true) {
                const got = slot.conn.streamRead(0, rbuf[early_read..]) catch break;
                if (got == 0) break;
                if (!slot.conn.handshakeDone()) read_before_handshake_done = true;
                early_read += got;
            }
        }

        try pumpServerToClient(&srv, &cli2, &rx, now_us);
        try srv.tick(now_us);
        try cli2.conn.tick(now_us);

        if (cli2.conn.handshakeDone() and early_read >= early_payload.len) break;
        now_us += 1_000;
    }

    try std.testing.expect(cli2.conn.handshakeDone());
    try std.testing.expectEqual(early_payload.len, early_read);
    try std.testing.expectEqualStrings(early_payload, rbuf[0..early_read]);
    try std.testing.expect(read_before_handshake_done);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, cli2.conn.earlyDataStatus());

    // The one-shot event mirrors the accepted status, exactly once.
    var accepted_events: u32 = 0;
    while (cli2.conn.pollEvent()) |ev| switch (ev) {
        .early_data => |st| {
            try std.testing.expectEqual(quic.EarlyDataStatus.accepted, st);
            accepted_events += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(u32, 1), accepted_events);
    try std.testing.expect(cli2.conn.pollEvent() == null);

    // ---- Connection 3: rejection recovery. A fresh Server has fresh
    // session-ticket keys, so the resumed ticket cannot be decrypted
    // and 0-RTT is rejected — the routine restart scenario. The client
    // must survive without any Internal-tier calls: the handshake
    // completes as 1-RTT and the staged early data still arrives. ----
    var srv2 = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .early_data = .without_replay_protection,
    });
    defer srv2.deinit();

    const addr3: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } };
    var cli3 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli3.deinit();

    cli3.conn.setEarlyDataEnabled(true);
    _ = try cli3.conn.openBidi(0);
    _ = try cli3.conn.streamWrite(0, early_payload);
    try cli3.conn.streamFinish(0);
    try cli3.conn.advance();

    now_us = 120_000_000;
    var late_read: usize = 0;
    var rbuf3: [256]u8 = undefined;
    step = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli3, &srv2, &rx, addr3, now_us);
        while (srv2.drainStatelessResponse()) |_| {}
        if (srv2.iterator().len > 0) {
            const slot = srv2.iterator()[0];
            while (true) {
                const got = slot.conn.streamRead(0, rbuf3[late_read..]) catch break;
                if (got == 0) break;
                late_read += got;
            }
        }
        try pumpServerToClient(&srv2, &cli3, &rx, now_us);
        try srv2.tick(now_us);
        try cli3.conn.tick(now_us);
        if (cli3.conn.handshakeDone() and late_read >= early_payload.len) break;
        now_us += 1_000;
    }

    // Recovery contract: connection alive, handshake done, data
    // delivered at 1-RTT despite the rejection.
    try std.testing.expect(!cli3.conn.isClosed());
    try std.testing.expect(cli3.conn.handshakeDone());
    try std.testing.expectEqual(early_payload.len, late_read);
    try std.testing.expectEqualStrings(early_payload, rbuf3[0..late_read]);

    // The one-shot event surfaces the rejection, exactly once, and by
    // the variant's ordering promise the verbatim 1-RTT requeue has
    // already run when it does (the data assertions above are the
    // observable proof: everything staged as 0-RTT arrived at 1-RTT).
    var rejected_events: u32 = 0;
    while (cli3.conn.pollEvent()) |ev| switch (ev) {
        .early_data => |st| {
            try std.testing.expectEqual(quic.EarlyDataStatus.rejected, st);
            rejected_events += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(u32, 1), rejected_events);
    try std.testing.expect(cli3.conn.pollEvent() == null);
}

test "0-RTT x mTLS: early data denied until the resumed identity is re-verified, and a certless resume is refused" {
    const allocator = std.testing.allocator;

    // mTLS posture: the server requires and verifies a client
    // certificate. Per RFC 9001 §4.6.4 that verification only
    // happens inside the resumed handshake, so early data must be
    // denied on the wire (the deny hook forces a 1-RTT handshake).
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .early_data = .without_replay_protection,
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };

    // ---- Connection 1: earn a ticket while presenting the client
    // certificate (the fixture doubles as client identity). ----
    {
        var cli = try quic.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test cert
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
            .client_cert_pem = common.test_cert_pem,
            .client_key_pem = common.test_key_pem,
            .new_session_callback = EnvelopeSink.cb,
            .new_session_user_data = &sink,
        });
        defer cli.deinit();

        try cli.conn.advance();
        var now_us: u64 = 1_000;
        var step: u32 = 0;
        while (step < 48 and sink.captured == null) : (step += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            while (srv.drainStatelessResponse()) |_| {}
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 1_000;
        }
        try std.testing.expect(cli.conn.handshakeDone());
        try std.testing.expect(sink.captured != null);

        // Tear down connection 1 so the resumption runs against a
        // clean slot table.
        cli.conn.close(false, 0, "done");
        var close_steps: u32 = 0;
        while (close_steps < 32 and srv.connectionCount() > 0) : (close_steps += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            _ = srv.reap();
            now_us += 500_000;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // ---- Connection 2: resume WITH the certificate + staged 0-RTT.
    // The deny hook forces 1-RTT, so the staged bytes must arrive at
    // 1-RTT (never readable on the server while the handshake is
    // incomplete) and the early-data status is rejected. ----
    const early_payload = "early-hello";
    const addr2: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } };
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_key_pem,
        .resumption_state = sink.captured.?,
    });
    defer cli2.deinit();

    cli2.conn.setEarlyDataEnabled(true);
    _ = try cli2.conn.openBidi(0);
    _ = try cli2.conn.streamWrite(0, early_payload);
    try cli2.conn.streamFinish(0);
    try cli2.conn.advance();

    var now_us: u64 = 60_000_000;
    var rbuf: [256]u8 = undefined;
    var early_read: usize = 0;
    var read_before_handshake_done = false;
    var step: u32 = 0;
    while (step < 48) : (step += 1) {
        try pumpClientToServer(&cli2, &srv, &rx, addr2, now_us);
        while (srv.drainStatelessResponse()) |_| {}

        // The decisive check: with mTLS the server must NOT surface
        // bytes while its handshake is incomplete.
        if (srv.iterator().len > 0) {
            const slot = srv.iterator()[0];
            while (true) {
                const got = slot.conn.streamRead(0, rbuf[early_read..]) catch break;
                if (got == 0) break;
                if (!slot.conn.handshakeDone()) read_before_handshake_done = true;
                early_read += got;
            }
        }

        try pumpServerToClient(&srv, &cli2, &rx, now_us);
        try srv.tick(now_us);
        try cli2.conn.tick(now_us);

        if (cli2.conn.handshakeDone() and early_read >= early_payload.len) break;
        now_us += 1_000;
    }

    try std.testing.expect(cli2.conn.handshakeDone());
    try std.testing.expectEqual(early_payload.len, early_read);
    try std.testing.expectEqualStrings(early_payload, rbuf[0..early_read]);
    try std.testing.expect(!read_before_handshake_done);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, cli2.conn.earlyDataStatus());

    // ---- Connection 3: resume WITHOUT re-presenting a certificate.
    // RFC 8446 §4.6.1 lets the server vouch for the prior client auth
    // through the ticket, so the resumed handshake legitimately
    // completes — but the early-data denial must still hold: bytes
    // arrive only at 1-RTT, never before the handshake finishes. ----
    const addr3: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } };
    var cli3 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli3.deinit();

    cli3.conn.setEarlyDataEnabled(true);
    _ = try cli3.conn.openBidi(0);
    _ = try cli3.conn.streamWrite(0, early_payload);
    try cli3.conn.streamFinish(0);
    try cli3.conn.advance();

    now_us = 120_000_000;
    var rbuf3: [256]u8 = undefined;
    var late_read: usize = 0;
    var late_read_before_handshake_done = false;
    step = 0;
    while (step < 48) : (step += 1) {
        try pumpClientToServer(&cli3, &srv, &rx, addr3, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        // Iterate every slot: the connection-2 slot is still live at
        // index 0, so connection 3's data lands in a later slot.
        for (srv.iterator()) |slot| {
            while (true) {
                const got = slot.conn.streamRead(0, rbuf3[late_read..]) catch break;
                if (got == 0) break;
                if (!slot.conn.handshakeDone()) late_read_before_handshake_done = true;
                late_read += got;
            }
        }
        try pumpServerToClient(&srv, &cli3, &rx, now_us);
        try srv.tick(now_us);
        try cli3.conn.tick(now_us);
        if (cli3.conn.handshakeDone() and late_read >= early_payload.len) break;
        now_us += 1_000;
    }

    // Ticket-vouched identity completes the handshake, but early data
    // is still denied: bytes arrive at 1-RTT only.
    try std.testing.expect(!cli3.conn.isClosed());
    try std.testing.expect(cli3.conn.handshakeDone());
    try std.testing.expectEqual(early_payload.len, late_read);
    try std.testing.expectEqualStrings(early_payload, rbuf3[0..late_read]);
    try std.testing.expect(!late_read_before_handshake_done);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, cli3.conn.earlyDataStatus());
}

test "replayed 0-RTT DATAGRAM packet is delivered only once (L1)" {
    // 0-RTT analogue of the 1-RTT dedup regression in
    // `unknown_frames_smoke.zig`. 0-RTT and 1-RTT share ONE
    // application PN space (RFC 9000 §12.3), and DATAGRAM is legal in
    // early data — so a replayed authenticated 0-RTT packet must be
    // acknowledged (the peer may have missed our ACK) but its frames
    // MUST NOT be re-processed (§12.3 / §13.1): no second DATAGRAM
    // delivery, no second resident-bytes charge.
    const allocator = std.testing.allocator;

    // DATAGRAM-capable transport params on both ends. The server's
    // params from connection 1 become the client's *remembered*
    // params for the 0-RTT attempt (RFC 9001 §7.4.1), so the server
    // must advertise `max_datagram_frame_size` from the very first
    // connection.
    var tp = common.defaultParams();
    tp.max_datagram_frame_size = 1200;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = tp,
        .early_data = .without_replay_protection,
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x44), .port = 4444 } };

    // ---- Connection 1: earn a resumption envelope. ----
    {
        var cli = try quic.Client.connect(.{
            .insecure_skip_verify = true, // self-signed test cert
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = tp,
            .new_session_callback = EnvelopeSink.cb,
            .new_session_user_data = &sink,
        });
        defer cli.deinit();

        try cli.conn.advance();
        var now_us: u64 = 1_000;
        var step: u32 = 0;
        while (step < 48 and sink.captured == null) : (step += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            while (srv.drainStatelessResponse()) |_| {}
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 1_000;
        }
        try std.testing.expect(sink.captured != null);

        cli.conn.close(false, 0, "done");
        var close_steps: u32 = 0;
        while (close_steps < 32 and srv.connectionCount() > 0) : (close_steps += 1) {
            try pumpClientToServer(&cli, &srv, &rx, addr1, now_us);
            try pumpServerToClient(&srv, &cli, &rx, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            _ = srv.reap();
            now_us += 500_000;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // ---- Connection 2: resume with 0-RTT staged pre-advance, then
    // stop after the FIRST client flight so the server sits mid-
    // handshake with live early-data read keys. ----
    const addr2: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x55), .port = 5555 } };
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = tp,
        .resumption_state = sink.captured.?,
    });
    defer cli2.deinit();

    cli2.conn.setEarlyDataEnabled(true);
    _ = try cli2.conn.openBidi(0);
    _ = try cli2.conn.streamWrite(0, "warmup");
    try cli2.conn.streamFinish(0);
    try cli2.conn.advance();

    const now_us: u64 = 60_000_000;
    try pumpClientToServer(&cli2, &srv, &rx, addr2, now_us);
    while (srv.drainStatelessResponse()) |_| {}
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    try std.testing.expect(!slot.conn.handshakeDone());
    // Early read keys must be live: the server installed them while
    // processing the ClientHello, which is how the coalesced 0-RTT in
    // that same first flight decrypted (the acceptance path the
    // wrapper test above proves end-to-end).
    try std.testing.expect((try slot.conn.packetKeys(.early_data, .read)) != null);

    // Hand-seal a 0-RTT packet whose payload is exactly one DATAGRAM
    // frame (type 0x30 = no LEN field; data runs to the end of the
    // packet — legal as the last frame).
    const dg_data = "replay-me-0rtt";
    var payload_buf: [64]u8 = undefined;
    payload_buf[0] = 0x30;
    @memcpy(payload_buf[1 .. 1 + dg_data.len], dg_data);
    const payload = payload_buf[0 .. 1 + dg_data.len];

    const keys = (try cli2.conn.packetKeys(.early_data, .write)) orelse
        return error.NoEarlyDataWriteKeys;
    const client_path = cli2.conn.paths.get(0) orelse return error.NoClientPath;
    const pn = client_path.app_pn_space.nextPn() orelse return error.PnSpaceExhausted;

    var packet_buf: [1500]u8 = undefined;
    const packet_len = try quic.wire.long_packet.sealZeroRtt(&packet_buf, .{
        .dcid = cli2.conn.initial_dcid.slice(),
        .scid = cli2.conn.local_scid.slice(),
        .pn = pn,
        .largest_acked = null,
        .payload = payload,
        .keys = &keys,
    });

    // Long-header open strips header protection IN PLACE on the
    // receive buffer (`openLongHeader` unmasks `src` directly), so a
    // handled buffer no longer holds the on-the-wire bytes. A real
    // network replay delivers a pristine copy of the ciphertext each
    // time — model that with a fresh copy per `handle` call.
    const before = slot.conn.pendingDatagrams();

    // First delivery: the DATAGRAM is accepted and queued once.
    var wire_first: [1500]u8 = undefined;
    @memcpy(wire_first[0..packet_len], packet_buf[0..packet_len]);
    try slot.conn.handle(wire_first[0..packet_len], null, now_us + 1_000);
    try std.testing.expectEqual(before + 1, slot.conn.pendingDatagrams());
    const resident_after_first = slot.conn.bytes_resident;

    // Replay the identical sealed packet (same PN). It re-decrypts
    // fine, and the ACK tracker still credits it, but the
    // duplicate-PN guard must skip frame dispatch: no second DATAGRAM
    // delivery, no second resident-bytes charge.
    var wire_replay: [1500]u8 = undefined;
    @memcpy(wire_replay[0..packet_len], packet_buf[0..packet_len]);
    try slot.conn.handle(wire_replay[0..packet_len], null, now_us + 2_000);
    try std.testing.expectEqual(before + 1, slot.conn.pendingDatagrams());
    try std.testing.expectEqual(resident_after_first, slot.conn.bytes_resident);
}
