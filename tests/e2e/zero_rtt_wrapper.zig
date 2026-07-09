//! End-to-end 0-RTT through the public wrappers — the flow the
//! app-readiness audit proved impossible before:
//!
//!   1. `Client.Config.new_session_callback` captures a
//!      ready-to-persist `tls.resumption_state` envelope from the
//!      first connection (no BoringSSL-level plumbing in app code).
//!   2. A second `Client.connect` passes the envelope back as
//!      `Config.resumption_state`, stages stream data before
//!      `advance()`, and sends it as 0-RTT.
//!   3. `quic_zig.Server` — with nothing beyond
//!      `Config.enable_0rtt = true` — accepts the early data because
//!      the accept path now installs the RFC 9001 §4.6.1 replay
//!      context before the ClientHello is processed.
//!
//! The decisive assertion: the server reads the client's stream bytes
//! BEFORE its handshake completes. Only accepted 0-RTT can do that.

const std = @import("std");
const quic_zig = @import("quic_zig");
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
    cli: *quic_zig.Client,
    srv: *quic_zig.Server,
    rx: []u8,
    addr: quic_zig.conn.path.Address,
    now_us: u64,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
    }
}

fn pumpServerToClient(
    srv: *quic_zig.Server,
    cli: *quic_zig.Client,
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

    var srv = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .enable_0rtt = true,
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic_zig.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };

    // ---- Connection 1: earn a ticket via the wrapper callback. ----
    {
        var cli = try quic_zig.Client.connect(.{
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
    const addr2: quic_zig.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } };
    var cli2 = try quic_zig.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli2.deinit();

    const early_payload = "early-hello";
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
    try std.testing.expectEqual(quic_zig.EarlyDataStatus.accepted, cli2.conn.earlyDataStatus());

    // ---- Connection 3: rejection recovery. A fresh Server has fresh
    // session-ticket keys, so the resumed ticket cannot be decrypted
    // and 0-RTT is rejected — the routine restart scenario. The client
    // must survive without any Internal-tier calls: the handshake
    // completes as 1-RTT and the staged early data still arrives. ----
    var srv2 = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .enable_0rtt = true,
    });
    defer srv2.deinit();

    const addr3: quic_zig.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } };
    var cli3 = try quic_zig.Client.connect(.{
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
}
