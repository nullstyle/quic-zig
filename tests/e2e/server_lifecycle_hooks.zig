//! End-to-end pins for the Server embedder-lifecycle additions:
//! `Slot.user_data` (embedder-owned per-connection pointer),
//! `Config.on_connection_will_close` (ordered-teardown hook that runs
//! inside `reap` while the slot is still fully valid),
//! `Config.on_handshake_complete` (per-slot discovery hook that fires
//! from `feed` the moment the TLS handshake completes), and
//! `Server.nextTimerDeadline` (aggregate earliest-deadline accessor for
//! event-loop sleep sizing).

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const HookCtx = struct {
    fired: u32 = 0,
    slot_id: ?u64 = null,
    user_data_seen: ?*anyopaque = null,
    conn_close_state_inside: ?quic.CloseState = null,
};

fn onWillClose(user_data: ?*anyopaque, slot: *quic.Server.Slot) void {
    const ctx: *HookCtx = @ptrCast(@alignCast(user_data.?));
    ctx.fired += 1;
    ctx.slot_id = slot.slot_id;
    ctx.user_data_seen = slot.user_data;
    // The contract: `slot.conn` must still be dereferenceable here.
    ctx.conn_close_state_inside = slot.conn.closeState();
}

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

test "on_connection_will_close fires inside reap with the slot still valid" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var hook_ctx: HookCtx = .{};
    var app_state: u32 = 0xbeef;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = onWillClose,
        .on_connection_will_close_user_data = &hook_ctx,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xcd), .port = 0 } };

    try cli.conn.advance();

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(usize, 1), srv.iterator().len);

    // Hang app state off the slot the way a real embedder would.
    const slot = srv.iterator()[0];
    slot.user_data = &app_state;
    const expected_slot_id = slot.slot_id;

    // Client closes; pump so the server sees CONNECTION_CLOSE, then run
    // the clock past the draining deadline so the slot latches .closed.
    cli.conn.close(false, 0x0, "done");
    var close_steps: u32 = 0;
    while (close_steps < 64 and srv.iterator()[0].conn.closeState() != .closed) : (close_steps += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 500_000; // stride past 3xPTO quickly
    }
    try std.testing.expectEqual(quic.CloseState.closed, srv.iterator()[0].conn.closeState());

    // Reap runs the hook exactly once, before teardown, with user_data
    // and the connection still intact.
    try std.testing.expectEqual(@as(u32, 0), hook_ctx.fired);
    const reaped = srv.reap();
    try std.testing.expectEqual(@as(usize, 1), reaped);
    try std.testing.expectEqual(@as(u32, 1), hook_ctx.fired);
    try std.testing.expectEqual(expected_slot_id, hook_ctx.slot_id.?);
    try std.testing.expectEqual(@as(?*anyopaque, &app_state), hook_ctx.user_data_seen);
    try std.testing.expectEqual(quic.CloseState.closed, hook_ctx.conn_close_state_inside.?);

    // Nothing left to reap; the hook does not re-fire.
    try std.testing.expectEqual(@as(usize, 0), srv.reap());
    try std.testing.expectEqual(@as(u32, 1), hook_ctx.fired);
}

const HandshakeHookCtx = struct {
    fired: u32 = 0,
    slot_id: ?u64 = null,
    handshake_done_inside: ?bool = null,
    peer_digest_inside: ?[32]u8 = null,
};

fn onHandshakeComplete(user_data: ?*anyopaque, slot: *quic.Server.Slot) void {
    const ctx: *HandshakeHookCtx = @ptrCast(@alignCast(user_data.?));
    ctx.fired += 1;
    ctx.slot_id = slot.slot_id;
    // The contract: the connection is established and open here, so
    // the authenticated peer identity is already readable — the
    // mTLS-embedder flow the hook exists for.
    ctx.handshake_done_inside = slot.conn.handshakeDone();
    ctx.peer_digest_inside = slot.conn.peerCertSpkiDigest();
}

test "on_handshake_complete fires once per slot from feed, with the peer identity readable" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var hook_ctx: HandshakeHookCtx = .{};

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .client_ca_pem = common.test_cert_pem, // mTLS: identity is readable
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_handshake_complete = onHandshakeComplete,
        .on_handshake_complete_user_data = &hook_ctx,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .client_cert_pem = common.test_cert_pem,
        .client_key_pem = common.test_key_pem,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xcd), .port = 0 } };

    try cli.conn.advance();
    try std.testing.expectEqual(@as(u32, 0), hook_ctx.fired);

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // Fired exactly once, during a feed, after the handshake completed
    // — and the client's authenticated identity was already available
    // inside the callback (the KAT digest of the client fixture).
    try std.testing.expectEqual(@as(u32, 1), hook_ctx.fired);
    try std.testing.expectEqual(srv.iterator()[0].slot_id, hook_ctx.slot_id.?);
    try std.testing.expectEqual(true, hook_ctx.handshake_done_inside.?);
    const digest = hook_ctx.peer_digest_inside orelse return error.NoDigestInsideCallback;
    const want = [32]u8{
        0xa9, 0xf8, 0x24, 0xa8, 0x09, 0x75, 0x5b, 0x5f,
        0x75, 0x7a, 0xa2, 0x40, 0x28, 0x93, 0x61, 0x8d,
        0x9d, 0x81, 0xaa, 0x98, 0x58, 0xde, 0x5f, 0x38,
        0xda, 0xe9, 0x5c, 0xca, 0xee, 0x40, 0xed, 0x46,
    };
    try std.testing.expectEqualSlices(u8, &want, &digest);

    // Keep feeding the completed connection: the once-per-slot latch
    // holds — no duplicate notifications on subsequent routed feeds.
    var extra_steps: u32 = 0;
    while (extra_steps < 4) : (extra_steps += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expectEqual(@as(u32, 1), hook_ctx.fired);
}

test "Server.nextTimerDeadline aggregates the earliest slot deadline" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    // No slots: nothing to sleep on.
    try std.testing.expectEqual(
        @as(?quic.TimerDeadline, null),
        srv.nextTimerDeadline(0),
    );

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xef), .port = 0 } };

    try cli.conn.advance();

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 32) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expectEqual(@as(usize, 1), srv.iterator().len);

    // With one live slot the aggregate is exactly that slot's deadline.
    const slot_deadline = srv.iterator()[0].conn.nextTimerDeadline(now_us);
    const agg = srv.nextTimerDeadline(now_us);
    try std.testing.expect(slot_deadline != null);
    try std.testing.expect(agg != null);
    try std.testing.expectEqual(slot_deadline.?.at_us, agg.?.at_us);
    try std.testing.expectEqual(slot_deadline.?.kind, agg.?.kind);
}

test "auto-replenished CIDs make client active migration work against a default server" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    // A keyed server with the default auto-replenish posture. Before
    // the proactive top-up existed, this exact scenario failed with
    // PathLimitExceeded: the server never issued spare CIDs and the
    // client had nothing to migrate to.
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .stateless_reset_key = @splat(0x5a),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    const peer_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x77), .port = 7777 } };

    try cli.conn.advance();

    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 48) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, peer_addr, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        // Run past handshake completion so the post-handshake
        // NEW_CONNECTION_ID top-up reaches the client.
        if (cli.conn.handshakeDone() and step > 12) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // The load-bearing assertion: active migration succeeds without
    // any app-side CID provisioning.
    const new_local: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x78), .port = 7878 } };
    try cli.conn.beginClientActiveMigration(new_local, now_us);
}
