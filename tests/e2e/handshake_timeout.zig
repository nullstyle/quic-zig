//! Handshake liveness — the pre-confirmation dead-dial / dead-slot
//! backstop (`Connection.handshake_timeout_us`, surfaced as
//! `CloseSource.handshake_timeout`).
//!
//! The gap these tests pin (measured downstream in capnp-zig's
//! fanout soak, 2026-08-27, and reproduced against pre-fix quic-zig
//! in this file's first draft): a connection whose handshake never
//! completes and whose peer goes quiet NEVER dies. RFC 9000 §10.1's
//! idle timeout cannot cover the phase — the effective value is
//! min(local, peer) of advertised parameters, which either haven't
//! arrived yet (dropped-server dial) or are 0 (idle opted out) — so
//! the client-side shape is an eternal dial (Initial retransmission
//! budget, then silence forever) and the server-side shape is the
//! QUIC SYN-flood analog (every `max_concurrent_connections` slot a
//! half-open zombie, endpoint mute).
//!
//! All black-hole tests advertise `max_idle_timeout_ms = 0` from the
//! client — the downstream posture under pressure — so the idle
//! machinery provably provides no backstop and the only thing that
//! can kill these connections is the handshake timer under test.
//!
//! The disarm boundary under test is CONFIRMATION
//! (`handshake_keys_discarded`), not TLS completion: the
//! mid-confirmation stall (server flight delivered, client's
//! Finished lost) has application write keys on both sides yet is
//! exactly the shape that must still die.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// Client config with the idle timeout opted out (see module doc)
/// and an explicit handshake budget.
fn deadDialClientConfig(handshake_timeout_ms: u64) quic.Client.Config {
    var tp = common.defaultParams();
    tp.max_idle_timeout_ms = 0;
    return .{
        .allocator = undefined, // filled by caller
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .insecure_skip_verify = true,
        .transport_params = tp,
        .handshake_timeout_ms = handshake_timeout_ms,
    };
}

fn testServer(allocator: std.mem.Allocator, handshake_timeout_ms: u64) !quic.Server {
    return quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .handshake_timeout_ms = handshake_timeout_ms,
    });
}

/// Drive both endpoints' clocks WITHOUT delivering anything: drain
/// and discard both sides' retransmissions (the black hole swallows
/// them), tick both, and periodically reap the server so closed
/// slots actually leave the table. 1 s per step; returns the step
/// index at which `until` held, or null if `max_steps` ran out.
fn blackhole(
    srv: *quic.Server,
    cli: *quic.Client,
    start_us: u64,
    max_steps: usize,
    ctx: anytype,
    until: *const fn (@TypeOf(ctx), u64) bool,
) !?usize {
    var scratch: [4096]u8 = undefined;
    var now = start_us;
    var steps: usize = 0;
    while (steps < max_steps) : (steps += 1) {
        now += 1_000_000;
        while (try cli.conn.poll(&scratch, now)) |_| {}
        for (srv.iterator()) |slot| {
            while (try slot.conn.poll(&scratch, now)) |_| {}
        }
        try srv.tick(now);
        try cli.conn.tick(now);
        _ = srv.reap();
        if (until(ctx, now)) return steps;
    }
    return null;
}

const BothDead = struct {
    srv: *quic.Server,
    cli: *quic.Client,
    fn done(self: BothDead, now_us: u64) bool {
        _ = now_us;
        return self.cli.conn.closeState() == .closed and
            self.srv.connectionCount() == 0;
    }
};

test "black-holed handshake: both endpoints die, slot reaped, cause distinguishable" {
    // The regression: pre-fix, this exact shape stays .open forever
    // (verified: 600 simulated seconds, both sides .open, no
    // CloseEvent). Post-fix both die within the budget and the
    // sticky event names the cause.
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, 10_000);
    defer srv.deinit();
    var config = deadDialClientConfig(30_000);
    config.allocator = allocator;
    var cli = try quic.Client.connect(config);
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    try cli.conn.advance();
    _ = try lb.pumpClientToServer(); // Initial delivered; slot opens
    _ = try lb.pumpServerToClient(); // server flight delivered; TLS
    // completes client-side — the mid-confirmation stall shape.

    const ctx = BothDead{ .srv = &srv, .cli = &cli };
    const step = try blackhole(&srv, &cli, lb.now_us, 300, ctx, BothDead.done);
    try std.testing.expect(step != null); // died within 300 s

    // The client's sticky event is the typed handshake cause.
    const ev = cli.conn.closeEvent() orelse return error.NoCloseEvent;
    try std.testing.expectEqual(quic.CloseSource.handshake_timeout, ev.source);
    try std.testing.expectEqualStrings("handshake timeout", ev.reason);
    try std.testing.expect(ev.at_us != null);
    // And pollEvent delivers it as a close event too.
    var saw_close = false;
    while (cli.conn.pollEvent()) |event| switch (event) {
        .close => |c| {
            try std.testing.expectEqual(quic.CloseSource.handshake_timeout, c.source);
            saw_close = true;
        },
        else => {},
    };
    try std.testing.expect(saw_close);
    // The server slot reported the same cause before reaping freed it.
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

test "black-holed dial with nothing delivered: client dies alone" {
    // Variant: the server never sees the Initial at all — the
    // client-side eternal dial. No server slot exists; only the
    // client must die (there is no one to feed it anything).
    const allocator = std.testing.allocator;
    var config = deadDialClientConfig(30_000);
    config.allocator = allocator;
    var cli = try quic.Client.connect(config);
    defer cli.deinit();
    var scratch: [4096]u8 = undefined;

    try cli.conn.advance();
    var now: u64 = 1_000;
    var closed_at: ?u64 = null;
    var steps: usize = 0;
    while (steps < 300) : (steps += 1) {
        now += 1_000_000;
        while (try cli.conn.poll(&scratch, now)) |_| {} // retransmits lost
        try cli.conn.tick(now);
        if (cli.conn.closeState() == .closed) {
            closed_at = now;
            break;
        }
    }
    try std.testing.expect(closed_at != null);
    const ev = cli.conn.closeEvent() orelse return error.NoCloseEvent;
    try std.testing.expectEqual(quic.CloseSource.handshake_timeout, ev.source);
}

test "a confirmed handshake disarms the timer" {
    // Complete a real handshake against a SHORT budget (2 s), then
    // fast-forward past the budget with the connection idle-but-
    // confirmed. The timer must not fire: confirmation disarmed it,
    // and liveness belongs to the (here disabled) idle machinery.
    // This also proves the timer never trips DURING the completing
    // handshake — it finishes in single-digit simulated milliseconds,
    // far under the budget, and stays up long past it.
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, 2_000);
    defer srv.deinit();
    var config = deadDialClientConfig(2_000);
    config.allocator = allocator;
    var cli = try quic.Client.connect(config);
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    try lb.handshake(&quic.testing.NullDriver{});
    const slot = srv.iterator()[0];
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(slot.conn.handshakeDone());
    // Confirmed both directions: client saw HANDSHAKE_DONE, server
    // processed the client's Finished — the disarm latch each side
    // consults.
    try std.testing.expect(cli.conn.handshake_keys_discarded);
    try std.testing.expect(slot.conn.handshake_keys_discarded);

    // Fast-forward to 10x the budget. Keep pumping so the only thing
    // that could kill the connection is the (disarmed) handshake
    // timer — the idle timeout is opted out. `drive` ends with the
    // expected budget exhaustion (the predicate never fires).
    lb.drive(&quic.testing.NullDriver{}, .{
        .budget_steps = 40,
        .step_us = 500_000, // 20 s total
        .until = struct {
            fn f(_: *quic.testing.Loopback) bool {
                return false;
            }
        }.f,
    }) catch |err| switch (err) {
        error.DriveBudgetExhausted => {}, // the expected exit
        else => return err,
    };
    try std.testing.expectEqual(quic.CloseState.open, cli.conn.closeState());
    try std.testing.expect(cli.conn.closeEvent() == null);
    try std.testing.expectEqual(quic.ConnectionPhase.established, cli.conn.phase());
    // The server slot survived its (equally disarmed) budget too.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
}

test "abandoned-dial load: the server table recovers" {
    // The capnp-zig soak shape, shrunk: fill the entire connection
    // table with abandoned dials (every slot a half-open zombie —
    // pre-fix this is a PERMANENT mute endpoint), then watch the
    // handshake timer reclaim every slot and a fresh dial succeed.
    const allocator = std.testing.allocator;
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .handshake_timeout_ms = 10_000,
        .max_concurrent_connections = 4,
    });
    defer srv.deinit();

    var scratch: [4096]u8 = undefined;
    var now: u64 = 1_000;

    // Four abandoned dials: Initial delivered, everything after lost.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var config = deadDialClientConfig(30_000);
        config.allocator = allocator;
        var cli = try quic.Client.connect(config);
        defer cli.deinit();
        try cli.conn.advance();
        while (try cli.conn.poll(&scratch, now)) |len| {
            _ = try srv.feed(scratch[0..len], quic.testing.loopback_addr, now);
        }
        now += 1_000; // stagger so the per-source Initial limiter
        // (32/s window) never engages.
    }
    try std.testing.expectEqual(@as(usize, 4), srv.connectionCount());
    // Table full: a fifth dial's Initial is dropped on the floor.

    // Fast-forward the server alone past its budget; every slot must
    // reach .closed and be reaped.
    var steps: usize = 0;
    while (steps < 300 and srv.connectionCount() != 0) : (steps += 1) {
        now += 1_000_000;
        for (srv.iterator()) |slot| {
            while (try slot.conn.poll(&scratch, now)) |_| {}
        }
        try srv.tick(now);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // The endpoint is audible again: a fresh dial completes a full
    // handshake through the recovered table.
    var config = deadDialClientConfig(30_000);
    config.allocator = allocator;
    var cli = try quic.Client.connect(config);
    defer cli.deinit();
    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();
    try lb.handshake(&quic.testing.NullDriver{});
    try std.testing.expect(cli.conn.handshakeDone());
}

test "0-RTT resumption dial: a stalled resumption dies too" {
    // Resumed dials walk the same client path and open the same
    // server slot, so the budget must bound them: earn a ticket on
    // connection 1, then stall connection 2 mid-resumption and
    // assert both ends die with the handshake cause.
    const allocator = std.testing.allocator;

    // ---- Connection 1: earn a resumption envelope. ----
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .handshake_timeout_ms = 10_000,
        // Replay protection is irrelevant to a stalled-resumption
        // liveness test (nothing is accepted; the dial just dies),
        // and this variant needs no tracker to outlive the server.
        .early_data = .without_replay_protection,
    });
    defer srv.deinit();
    var config1 = deadDialClientConfig(30_000);
    config1.allocator = allocator;
    var sink = EnvelopeSink{ .allocator = allocator };
    defer sink.deinit();
    config1.new_session_callback = EnvelopeSink.cb;
    config1.new_session_user_data = &sink;
    var cli1 = try quic.Client.connect(config1);
    defer cli1.deinit();
    {
        var lb = try quic.testing.Loopback.init(.{
            .allocator = allocator,
            .server = &srv,
            .client = &cli1,
        });
        defer lb.deinit();
        try lb.handshake(&quic.testing.NullDriver{});
        // Tickets arrive post-handshake; a little traffic coaxes one.
        lb.drive(&quic.testing.NullDriver{}, .{
            .budget_steps = 64,
            .until = struct {
                fn f(_: *quic.testing.Loopback) bool {
                    return false;
                }
            }.f,
        }) catch |err| switch (err) {
            error.DriveBudgetExhausted => {},
            else => return err,
        };
        try std.testing.expect(sink.captured != null);
        cli1.conn.close(false, 0, "done");
        // Deliver the close so connection 1's slot drains and reaps
        // before connection 2's census: a CONFIRMED slot with the
        // idle timeout opted out is immortal by contract (the
        // handshake backstop deliberately disarms at confirmation),
        // so it must be torn down through the normal close path, not
        // left behind.
        lb.drive(&quic.testing.NullDriver{}, .{
            .budget_steps = 128,
            .step_us = 100_000,
            .until = struct {
                fn f(_: *quic.testing.Loopback) bool {
                    return false;
                }
            }.f,
        }) catch |err| switch (err) {
            error.DriveBudgetExhausted => {},
            else => return err,
        };
        _ = srv.reap();
        try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    }

    // ---- Connection 2: resume, then black-hole mid-resumption. ----
    var config2 = deadDialClientConfig(30_000);
    config2.allocator = allocator;
    config2.resumption_state = sink.captured.?;
    var cli2 = try quic.Client.connect(config2);
    defer cli2.deinit();
    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli2,
    });
    defer lb.deinit();
    try cli2.conn.advance();
    _ = try lb.pumpClientToServer(); // resumed Initial (+0-RTT) delivered
    _ = try lb.pumpServerToClient(); // server flight delivered

    const ctx = BothDead{ .srv = &srv, .cli = &cli2 };
    const step = try blackhole(&srv, &cli2, lb.now_us, 300, ctx, BothDead.done);
    try std.testing.expect(step != null);
    const ev = cli2.conn.closeEvent() orelse return error.NoCloseEvent;
    try std.testing.expectEqual(quic.CloseSource.handshake_timeout, ev.source);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

/// Captures the resumption envelope from
/// `Client.Config.new_session_callback` (same shape as
/// zero_rtt_wrapper.zig's, duplicated here to keep this file's
/// dependency surface small).
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
