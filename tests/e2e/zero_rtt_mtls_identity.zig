//! mTLS × 0-RTT identity test — the false-positive regression the
//! SHA256(ticket || client_random) anti-replay identity fixes.
//!
//! RFC 9001 §4.6.4 posture: a server that requires client
//! authentication re-verifies the resuming client identity before
//! granting early data. The ticket binds the identity (it was minted
//! from a client-authenticated session and BoringSSL re-validates it
//! with the server's ticket keys on resumption), and the anti-replay
//! trampoline additionally binds each GRANT to that attempt's
//! ClientHello random. With a ticket-only identity, two DISTINCT
//! legitimate resumptions of one multi-use ticket collided on a
//! single tracker Id and the second was false-positive downgraded to
//! 1-RTT. This test pins the fixed behavior:
//!
//!   1. Connection 1 earns a resumption envelope under mTLS (client
//!      presents a certificate chaining to the server's pinned root).
//!   2. Connection 2 resumes that ticket WITH the certificate and
//!      staged 0-RTT bytes: early data is ACCEPTED (server reads the
//!      bytes before its handshake completes), tracker size 1.
//!   3. Connection 3 resumes the SAME ticket WITHOUT re-presenting a
//!      certificate (the ticket vouches for the identity) with fresh
//!      0-RTT bytes: early data is ACCEPTED again — the decisive
//!      assertion a ticket-only identity fails — tracker size 2, and
//!      the two consumed identities differ.

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

fn serverHandshakeDone(srv: *quic.Server) bool {
    for (srv.iterator()) |slot| {
        if (slot.conn.handshakeDone()) return true;
    }
    return false;
}

/// Drive a connected client until its staged 0-RTT bytes are fully
/// readable on the server AND the server's handshake has completed
/// (the client finishes its handshake first in TLS 1.3; closing a
/// connection whose server is still mid-handshake loses the
/// application-level CONNECTION_CLOSE, so teardown waits). Returns
/// true if any server slot delivered bytes while that slot's
/// handshake was still incomplete — the observable signature of
/// ACCEPTED 0-RTT (1-RTT delivery can only happen after the
/// handshake completes).
fn driveResumption(
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    addr: quic.conn.path.Address,
    start_us: u64,
    payload: []const u8,
) !struct { read_before_handshake_done: bool, read_total: usize, buf: [256]u8 } {
    var read_total: usize = 0;
    var read_before_handshake_done = false;
    var buf: [256]u8 = undefined;
    var now_us = start_us;
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(cli, srv, rx, addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}

        for (srv.iterator()) |slot| {
            while (true) {
                const got = slot.conn.streamRead(0, buf[read_total..]) catch break;
                if (got == 0) break;
                if (!slot.conn.handshakeDone()) read_before_handshake_done = true;
                read_total += got;
            }
        }

        try pumpServerToClient(srv, cli, rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        if (cli.conn.handshakeDone() and read_total >= payload.len and serverHandshakeDone(srv)) break;
        now_us += 1_000;
    }
    return .{
        .read_before_handshake_done = read_before_handshake_done,
        .read_total = read_total,
        .buf = buf,
    };
}

/// Close a connection and pump until the server reaps its slot.
fn closeAndReap(
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    addr: quic.conn.path.Address,
    start_us: u64,
) !void {
    cli.conn.close(false, 0, "done");
    var now_us = start_us;
    var step: u32 = 0;
    while (step < 32 and srv.connectionCount() > 0) : (step += 1) {
        try pumpClientToServer(cli, srv, rx, addr, now_us);
        try pumpServerToClient(srv, cli, rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        _ = srv.reap();
        now_us += 500_000;
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

test "mTLS x 0-RTT identity: two distinct resumptions of one ticket are both accepted" {
    const allocator = std.testing.allocator;

    var tracker = try quic.tls.AntiReplayTracker.init(allocator, .{});
    defer tracker.deinit();

    // mTLS posture + TLS-layer anti-replay. buildServerContext
    // installs the anti-replay hook after the mTLS deny hook, so the
    // per-attempt identity (not the blanket deny) governs.
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .early_data = .{ .with_anti_replay = &tracker },
    });
    defer srv.deinit();

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();

    var rx: [4096]u8 = undefined;
    const addr1: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = 1111 } };

    // ---- Connection 1: earn a resumption envelope under mTLS. ----
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

        try closeAndReap(&cli, &srv, &rx, addr1, now_us);
    }
    try std.testing.expectEqual(@as(usize, 0), tracker.size());

    // ---- Connection 2: first resumption of the ticket, WITH the
    // client certificate re-presented and 0-RTT bytes staged. ----
    const payload2 = "first-resume";
    const addr2: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2222 } };
    var cli2 = try quic.Client.connect(.{
        .insecure_skip_verify = true,
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
    _ = try cli2.conn.streamWrite(0, payload2);
    try cli2.conn.streamFinish(0);
    try cli2.conn.advance();

    const res2 = try driveResumption(&cli2, &srv, &rx, addr2, 60_000_000, payload2);
    try std.testing.expect(cli2.conn.handshakeDone());
    try std.testing.expect(res2.read_before_handshake_done);
    try std.testing.expectEqual(payload2.len, res2.read_total);
    try std.testing.expectEqualStrings(payload2, res2.buf[0..res2.read_total]);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, cli2.conn.earlyDataStatus());
    try std.testing.expectEqual(@as(usize, 1), tracker.size());

    var accepted_events2: u32 = 0;
    while (cli2.conn.pollEvent()) |ev| switch (ev) {
        .early_data => |st| {
            try std.testing.expectEqual(quic.EarlyDataStatus.accepted, st);
            accepted_events2 += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(u32, 1), accepted_events2);

    try closeAndReap(&cli2, &srv, &rx, addr2, 80_000_000);

    // ---- Connection 3: second resumption of the SAME ticket,
    // WITHOUT a certificate — the ticket vouches for the previously
    // verified client identity (RFC 8446 §4.2.11: certificate-based
    // client auth is carried by the PSK on resumption). A fresh
    // ClientHello random must yield a DISTINCT tracker identity, so
    // this legitimate resumption is accepted rather than
    // false-positive rejected as a replay. ----
    const payload3 = "second-resume";
    const addr3: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = 3333 } };
    var cli3 = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .resumption_state = sink.captured.?,
    });
    defer cli3.deinit();

    cli3.conn.setEarlyDataEnabled(true);
    _ = try cli3.conn.openBidi(0);
    _ = try cli3.conn.streamWrite(0, payload3);
    try cli3.conn.streamFinish(0);
    try cli3.conn.advance();

    const res3 = try driveResumption(&cli3, &srv, &rx, addr3, 140_000_000, payload3);
    try std.testing.expect(cli3.conn.handshakeDone());
    try std.testing.expect(res3.read_before_handshake_done);
    try std.testing.expectEqual(payload3.len, res3.read_total);
    try std.testing.expectEqualStrings(payload3, res3.buf[0..res3.read_total]);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, cli3.conn.earlyDataStatus());

    // Both attempts consumed one identity each, and the two
    // identities DIFFER — the property a ticket-only SHA-256 breaks,
    // and the whole reason the second resumption was downgraded
    // before SHA256(ticket || client_random).
    try std.testing.expectEqual(@as(usize, 2), tracker.size());
    try std.testing.expectEqual(@as(usize, 2), tracker.entries.items.len);
    try std.testing.expect(!std.mem.eql(
        u8,
        &tracker.entries.items[0].id,
        &tracker.entries.items[1].id,
    ));

    // A byte-replay of the SAME flight would still collide: the
    // identity is stable per attempt. Replay rejection at the TLS
    // layer is covered by zero_rtt_replay_smoke.zig's tracker
    // contract; here the decisive property is distinctness across
    // legitimate attempts.
}
