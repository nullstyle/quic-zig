//! Session tickets and 0-RTT across the life of a server, at the
//! public wrappers (`quic.Server`, `quic.Client`, datagrams passed in
//! memory).
//!
//! Every test has the same shape. A first connection earns a ticket
//! (the client's `new_session_callback` gets a resumption envelope).
//! A second connection resumes with 11 bytes of early data that are
//! written before its first flight. What the test looks at:
//!
//!   - what the client says (`earlyDataStatus`), and
//!   - WHEN the server could read the bytes: before its own handshake
//!     was done (they came as 0-RTT), or after (they came as 1-RTT).
//!
//! The second is the one that counts. A client says `.accepted` also
//! when its early data came late (see the Retry test).

const std = @import("std");
const quic = @import("quic");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const early_payload = "early-hello";

/// Keeps the latest resumption envelope that
/// `Client.Config.new_session_callback` hands out (the bytes are
/// borrowed during the call, so they are copied).
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

const ServerOptions = struct {
    /// Answer the first Initial packet of each client with a Retry.
    retry: bool = false,
    transport_params: ?quic.tls.TransportParams = null,
    ticket_key: ?quic.SessionTicketKey = null,
    ticket_lifetime_s: ?u32 = null,
};

const key_a: quic.SessionTicketKey = @splat(0xa5);
const key_b: quic.SessionTicketKey = @splat(0x5b);

const retry_key: quic.RetryTokenKey = @splat(0x42);

fn newServer(allocator: std.mem.Allocator, opts: ServerOptions) !quic.Server {
    return quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = opts.transport_params orelse common.defaultParams(),
        .early_data = .without_replay_protection,
        .retry_token_key = if (opts.retry) retry_key else null,
        .session_ticket_key = opts.ticket_key,
        .session_ticket_lifetime_s = opts.ticket_lifetime_s,
    });
}

fn newClient(allocator: std.mem.Allocator, sink: ?*EnvelopeSink, envelope: ?[]const u8) !quic.Client {
    return quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test certificate
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .new_session_callback = if (sink != null) EnvelopeSink.cb else null,
        .new_session_user_data = sink,
        .resumption_state = envelope,
    });
}

/// Every datagram the client has, to the server. A Retry that the
/// server queues goes back to the client at once. Returns the number
/// of Retry packets.
fn clientToServer(cli: *quic.Client, srv: *quic.Server, addr: quic.conn.path.Address, now_us: u64) !u32 {
    var rx: [4096]u8 = undefined;
    var retries: u32 = 0;
    while (try cli.conn.poll(&rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
        while (srv.drainStatelessResponse()) |resp| {
            var buf: [512]u8 = undefined;
            @memcpy(buf[0..resp.len], resp.slice());
            // Long header, type 3 (QUIC v1): a Retry.
            if (buf[0] & 0xb0 == 0xb0) retries += 1;
            try cli.conn.handle(buf[0..resp.len], null, now_us);
        }
    }
    return retries;
}

fn serverToClient(srv: *quic.Server, cli: *quic.Client, now_us: u64) !void {
    var rx: [4096]u8 = undefined;
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(&rx, now_us)) |len| {
            try cli.conn.handle(rx[0..len], null, now_us);
        }
    }
}

/// Close the client's connection and step until the server has no
/// connection left, so the next client finds slot 0.
fn closeAndReap(cli: *quic.Client, srv: *quic.Server, addr: quic.conn.path.Address, from_us: u64) !void {
    cli.conn.close(false, 0, "done");
    var now_us = from_us;
    var steps: u32 = 0;
    while (steps < 32 and srv.connectionCount() > 0) : (steps += 1) {
        _ = try clientToServer(cli, srv, addr, now_us);
        try serverToClient(srv, cli, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        _ = srv.reap();
        now_us += 500_000;
    }
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

/// A first connection to `srv` that runs until the client has a
/// resumption envelope in `sink`.
fn earnTicket(allocator: std.mem.Allocator, srv: *quic.Server, sink: *EnvelopeSink, port: u16) !void {
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x11), .port = port } };
    var cli = try newClient(allocator, sink, null);
    defer cli.deinit();
    try cli.conn.advance();
    var now_us: u64 = 1_000;
    var step: u32 = 0;
    while (step < 64 and sink.captured == null) : (step += 1) {
        _ = try clientToServer(&cli, srv, addr, now_us);
        try serverToClient(srv, &cli, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(sink.captured != null);
    try closeAndReap(&cli, srv, addr, now_us);
}

const Resumed = struct {
    /// What the client's TLS says about its early data.
    status: quic.EarlyDataStatus,
    /// The server could read early bytes while its own handshake was
    /// not done: they came as 0-RTT.
    read_before_handshake_done: bool,
    /// Bytes of the early payload that the server read, in all.
    read: usize,
    /// Retry packets the client got.
    retries: u32,
};

/// A resumed connection to `srv` with `early_payload` written before
/// the first flight. Runs until the client's handshake is done and
/// the server has the whole payload.
fn resumeWithEarlyData(allocator: std.mem.Allocator, srv: *quic.Server, envelope: []const u8, port: u16) !Resumed {
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = port } };
    var cli = try newClient(allocator, null, envelope);
    defer cli.deinit();
    cli.conn.setEarlyDataEnabled(true);
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, early_payload);
    try cli.conn.streamFinish(0);
    try cli.conn.advance();

    var out: Resumed = .{ .status = .not_offered, .read_before_handshake_done = false, .read = 0, .retries = 0 };
    var now_us: u64 = 60_000_000;
    var rbuf: [64]u8 = undefined;
    var step: u32 = 0;
    while (step < 200) : (step += 1) {
        out.retries += try clientToServer(&cli, srv, addr, now_us);
        if (srv.iterator().len > 0) {
            const slot = srv.iterator()[0];
            while (true) {
                const got = slot.conn.streamRead(0, rbuf[out.read..]) catch break;
                if (got == 0) break;
                if (!slot.conn.handshakeDone()) out.read_before_handshake_done = true;
                out.read += got;
            }
        }
        try serverToClient(srv, &cli, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and out.read >= early_payload.len) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(!cli.conn.isClosed());
    try std.testing.expectEqualStrings(early_payload, rbuf[0..out.read]);
    out.status = cli.conn.earlyDataStatus();
    try closeAndReap(&cli, srv, addr, now_us);
    return out;
}

// ------------------------------------------- a ticket and a new server

test "session ticket key: a new server with the same key takes the tickets of the old one, with 0-RTT" {
    // "A new server" stands for a process that started again, and for
    // the next server of a pool.
    const allocator = std.testing.allocator;
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    {
        var old = try newServer(allocator, .{ .ticket_key = key_a });
        defer old.deinit();
        try earnTicket(allocator, &old, &sink, 1101);
    }
    var new = try newServer(allocator, .{ .ticket_key = key_a });
    defer new.deinit();
    const r = try resumeWithEarlyData(allocator, &new, sink.captured.?, 2101);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);
}

test "session ticket key: a new server with no key, or with another key, cannot open the ticket; the early data still arrives" {
    const allocator = std.testing.allocator;
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    {
        var old = try newServer(allocator, .{ .ticket_key = key_a });
        defer old.deinit();
        try earnTicket(allocator, &old, &sink, 1102);
    }
    for ([_]?quic.SessionTicketKey{ null, key_b }, 0..) |other, i| {
        var new = try newServer(allocator, .{ .ticket_key = other });
        defer new.deinit();
        const r = try resumeWithEarlyData(allocator, &new, sink.captured.?, @intCast(2110 + i));
        try std.testing.expectEqual(quic.EarlyDataStatus.rejected, r.status);
        try std.testing.expect(!r.read_before_handshake_done);
        // `resumeWithEarlyData` has checked that all the bytes came.
        try std.testing.expectEqual(early_payload.len, r.read);
    }
    // And a ticket of a server that had NO key is lost at a restart,
    // whatever the new server has.
    var sink2: EnvelopeSink = .{ .allocator = allocator };
    defer sink2.deinit();
    {
        var old = try newServer(allocator, .{});
        defer old.deinit();
        try earnTicket(allocator, &old, &sink2, 1103);
    }
    var new = try newServer(allocator, .{ .ticket_key = key_a });
    defer new.deinit();
    const r = try resumeWithEarlyData(allocator, &new, sink2.captured.?, 2112);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, r.status);
    try std.testing.expect(!r.read_before_handshake_done);
}

test "session ticket key: a certificate reload keeps the tickets when a key is set, and loses them when none is" {
    const allocator = std.testing.allocator;
    const reload: quic.Server.TlsReload = .{ .pem = .{
        .cert_pem = common.test_cert_pem,
        .key_pem = common.test_key_pem,
    } };

    // With a key: the context that the reload builds gets it too.
    {
        var srv = try newServer(allocator, .{ .ticket_key = key_a });
        defer srv.deinit();
        var sink: EnvelopeSink = .{ .allocator = allocator };
        defer sink.deinit();
        try earnTicket(allocator, &srv, &sink, 1104);
        try std.testing.expectEqualSlices(u8, &key_a, &quic.tls.session_ticket.currentKeyForTest(srv.tls_ctx).?);

        try srv.replaceTlsContext(reload);
        try std.testing.expectEqualSlices(u8, &key_a, &quic.tls.session_ticket.currentKeyForTest(srv.tls_ctx).?);
        const r = try resumeWithEarlyData(allocator, &srv, sink.captured.?, 2104);
        try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
        try std.testing.expect(r.read_before_handshake_done);

        // A second reload, and a ticket from before the first one.
        try srv.replaceTlsContext(reload);
        const r2 = try resumeWithEarlyData(allocator, &srv, sink.captured.?, 2105);
        try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r2.status);
        try std.testing.expect(r2.read_before_handshake_done);
    }
    // With no key: each context has a key of its own.
    {
        var srv = try newServer(allocator, .{});
        defer srv.deinit();
        var sink: EnvelopeSink = .{ .allocator = allocator };
        defer sink.deinit();
        try earnTicket(allocator, &srv, &sink, 1106);
        try srv.replaceTlsContext(reload);
        const r = try resumeWithEarlyData(allocator, &srv, sink.captured.?, 2106);
        try std.testing.expectEqual(quic.EarlyDataStatus.rejected, r.status);
        try std.testing.expect(!r.read_before_handshake_done);
    }
}

test "session ticket key: init refuses a zero key, a key with a context of the embedder, and a key with the replay tracker" {
    const allocator = std.testing.allocator;
    const base: quic.Server.Config = .{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    };

    // 48 zero bytes: a buffer that was never filled in.
    {
        var cfg = base;
        cfg.session_ticket_key = @splat(0);
        try std.testing.expectError(error.InvalidConfig, quic.Server.init(cfg));
    }
    // One byte that is not zero is a key.
    {
        var cfg = base;
        var key: quic.SessionTicketKey = @splat(0);
        key[47] = 1;
        cfg.session_ticket_key = key;
        var srv = try quic.Server.init(cfg);
        defer srv.deinit();
        try std.testing.expectEqualSlices(u8, &key, &quic.tls.session_ticket.currentKeyForTest(srv.tls_ctx).?);
    }
    // A context that the embedder built: the key belongs on it.
    {
        var ctx = try boringssl.tls.Context.initServer(.{
            .min_version = boringssl.raw.TLS1_3_VERSION,
            .max_version = boringssl.raw.TLS1_3_VERSION,
            .alpn = &protos,
        });
        defer ctx.deinit();
        var cfg = base;
        cfg.tls_context_override = ctx;
        cfg.session_ticket_key = key_a;
        try std.testing.expectError(error.InvalidConfig, quic.Server.init(cfg));
    }
    // The replay tracker is process memory; a key that outlives the
    // process would let a recorded 0-RTT flight be "fresh" again.
    {
        var tracker = try quic.tls.AntiReplayTracker.init(allocator, .{});
        defer tracker.deinit();
        var cfg = base;
        cfg.early_data = .{ .with_anti_replay = &tracker };
        cfg.session_ticket_key = key_a;
        try std.testing.expectError(error.InvalidConfig, quic.Server.init(cfg));
        // The tracker alone is fine, and so is the key alone.
        cfg.session_ticket_key = null;
        var with_tracker = try quic.Server.init(cfg);
        with_tracker.deinit();
    }
    // A key with 0-RTT off, and with unprotected 0-RTT: both taken.
    for ([_]quic.Server.EarlyData{ .disabled, .without_replay_protection }) |early| {
        var cfg = base;
        cfg.early_data = early;
        cfg.session_ticket_key = key_a;
        var srv = try quic.Server.init(cfg);
        defer srv.deinit();
        try std.testing.expectEqualSlices(u8, &key_a, &quic.tls.session_ticket.currentKeyForTest(srv.tls_ctx).?);
    }
    // No key: the context keeps a key of its own.
    {
        var srv = try quic.Server.init(base);
        defer srv.deinit();
        const own = quic.tls.session_ticket.currentKeyForTest(srv.tls_ctx).?;
        try std.testing.expect(!std.mem.eql(u8, &own, &key_a));
    }
}

test "session ticket key: with 0-RTT off, a new server with the same key still resumes the session" {
    // Resumption without early data. What is asked here is TLS's own
    // answer (`SSL_session_reused`): a resumed TLS 1.3 handshake
    // sends no certificate and checks none.
    const allocator = std.testing.allocator;
    const Dial = struct {
        /// One connection to `srv`; true when TLS resumed a session.
        fn resumed(alloc: std.mem.Allocator, srv: *quic.Server, envelope: ?[]const u8, sink: ?*EnvelopeSink, port: u16) !bool {
            const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = port } };
            var cli = try newClient(alloc, sink, envelope);
            defer cli.deinit();
            try cli.conn.advance();
            var now_us: u64 = 90_000_000;
            var step: u32 = 0;
            while (step < 64) : (step += 1) {
                _ = try clientToServer(&cli, srv, addr, now_us);
                try serverToClient(srv, &cli, now_us);
                try srv.tick(now_us);
                try cli.conn.tick(now_us);
                if (cli.conn.handshakeDone() and (sink == null or sink.?.captured != null)) break;
                now_us += 1_000;
            }
            try std.testing.expect(cli.conn.handshakeDone());
            const client_says = boringssl.raw.zbssl_SSL_session_reused(cli.conn.inner.inner) == 1;
            const server_says = boringssl.raw.zbssl_SSL_session_reused(srv.iterator()[0].conn.inner.inner) == 1;
            try std.testing.expectEqual(client_says, server_says);
            try closeAndReap(&cli, srv, addr, now_us);
            return client_says;
        }
    };
    const noEarly = struct {
        fn server(alloc: std.mem.Allocator, key: ?quic.SessionTicketKey) !quic.Server {
            return quic.Server.init(.{
                .allocator = alloc,
                .tls_cert_pem = common.test_cert_pem,
                .tls_key_pem = common.test_key_pem,
                .alpn_protocols = &protos,
                .transport_params = common.defaultParams(),
                .early_data = .disabled,
                .session_ticket_key = key,
            });
        }
    }.server;

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    {
        var old = try noEarly(allocator, key_a);
        defer old.deinit();
        try std.testing.expect(!try Dial.resumed(allocator, &old, null, &sink, 3001));
        try std.testing.expect(sink.captured != null);
    }
    var same = try noEarly(allocator, key_a);
    defer same.deinit();
    try std.testing.expect(try Dial.resumed(allocator, &same, sink.captured.?, null, 3002));
    var other = try noEarly(allocator, key_b);
    defer other.deinit();
    try std.testing.expect(!try Dial.resumed(allocator, &other, sink.captured.?, null, 3003));
    var none = try noEarly(allocator, null);
    defer none.deinit();
    try std.testing.expect(!try Dial.resumed(allocator, &none, sink.captured.?, null, 3004));
}

// --------------------------------------------------- the ticket lifetime

/// TLS reads the wall clock for the age of a ticket, not the `now_us`
/// of the QUIC loop. These tests give one server context a clock of
/// their own, in seconds. (The client keeps the real clock. Its
/// ticket age in the ClientHello is then a few milliseconds, and
/// BoringSSL takes early data while that age and the server's own
/// differ by 60 s at most, so the tests stay below that.)
var test_tls_clock_s: i64 = 0;
const test_tls_clock_base_s: i64 = 1_800_000_000;

fn testTlsClock(ssl: ?*const boringssl.raw.SSL, out_clock: [*c]boringssl.raw.struct_timeval) callconv(.c) void {
    _ = ssl;
    out_clock.*.tv_sec = @intCast(test_tls_clock_s);
    out_clock.*.tv_usec = 0;
}

/// The server's CURRENT context reads `test_tls_clock_s` from now on.
/// A context that `replaceTlsContext` builds needs the call again.
fn useTestTlsClock(srv: *quic.Server) void {
    boringssl.raw.zbssl_SSL_CTX_set_current_time_cb(srv.tls_ctx.inner, testTlsClock);
}

test "ticket lifetime: a ticket is taken while it is younger than the lifetime, and refused from then on" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_lifetime_s = 10 });
    defer srv.deinit();
    test_tls_clock_s = test_tls_clock_base_s;
    useTestTlsClock(&srv);
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1201);
    // The envelope of the FIRST ticket is used each time (a resumed
    // connection hands out new tickets; they are not looked at).
    const envelope = try allocator.dupe(u8, sink.captured.?);
    defer allocator.free(envelope);

    test_tls_clock_s = test_tls_clock_base_s + 9;
    const young = try resumeWithEarlyData(allocator, &srv, envelope, 2201);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, young.status);
    try std.testing.expect(young.read_before_handshake_done);

    test_tls_clock_s = test_tls_clock_base_s + 10;
    const old = try resumeWithEarlyData(allocator, &srv, envelope, 2202);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, old.status);
    try std.testing.expect(!old.read_before_handshake_done);
    try std.testing.expectEqual(early_payload.len, old.read);
}

test "ticket lifetime: with none set, a ticket of the same age is still taken (the control)" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{});
    defer srv.deinit();
    test_tls_clock_s = test_tls_clock_base_s;
    useTestTlsClock(&srv);
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1203);
    const envelope = try allocator.dupe(u8, sink.captured.?);
    defer allocator.free(envelope);

    test_tls_clock_s = test_tls_clock_base_s + 10;
    const r = try resumeWithEarlyData(allocator, &srv, envelope, 2203);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);
}

test "ticket lifetime: a certificate reload keeps it" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_lifetime_s = 10 });
    defer srv.deinit();
    try srv.replaceTlsContext(.{ .pem = .{
        .cert_pem = common.test_cert_pem,
        .key_pem = common.test_key_pem,
    } });
    // The context that the reload built seals this ticket.
    test_tls_clock_s = test_tls_clock_base_s;
    useTestTlsClock(&srv);
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1204);
    const envelope = try allocator.dupe(u8, sink.captured.?);
    defer allocator.free(envelope);

    test_tls_clock_s = test_tls_clock_base_s + 9;
    const young = try resumeWithEarlyData(allocator, &srv, envelope, 2204);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, young.status);

    test_tls_clock_s = test_tls_clock_base_s + 10;
    const old = try resumeWithEarlyData(allocator, &srv, envelope, 2205);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, old.status);
}

test "ticket lifetime: init takes 1 second to 7 days, and no lifetime with a context of the embedder" {
    const allocator = std.testing.allocator;
    const base: quic.Server.Config = .{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    };
    for ([_]u32{ 0, 604_801, std.math.maxInt(u32) }) |bad| {
        var cfg = base;
        cfg.session_ticket_lifetime_s = bad;
        try std.testing.expectError(error.InvalidConfig, quic.Server.init(cfg));
    }
    for ([_]u32{ 1, 3600, 604_800 }) |good| {
        var cfg = base;
        cfg.session_ticket_lifetime_s = good;
        var srv = try quic.Server.init(cfg);
        srv.deinit();
    }
    {
        var ctx = try boringssl.tls.Context.initServer(.{
            .min_version = boringssl.raw.TLS1_3_VERSION,
            .max_version = boringssl.raw.TLS1_3_VERSION,
            .alpn = &protos,
        });
        defer ctx.deinit();
        var cfg = base;
        cfg.tls_context_override = ctx;
        cfg.session_ticket_lifetime_s = 3600;
        try std.testing.expectError(error.InvalidConfig, quic.Server.init(cfg));
    }
}

// ------------------------------------------------- 0-RTT and a Retry

test "0-RTT with no Retry in the way: the server reads the early data before its handshake is done" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{});
    defer srv.deinit();
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1001);

    const r = try resumeWithEarlyData(allocator, &srv, sink.captured.?, 2001);
    try std.testing.expectEqual(@as(u32, 0), r.retries);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);
}

test "0-RTT after a Retry: the client sends its early data again, and the server reads it before its handshake is done" {
    // A server with Retry on has no connection for the client's first
    // flight, so the 0-RTT packets in it are gone. RFC 9000 section
    // 17.2.5.3: a client may send its 0-RTT data again after a Retry,
    // to the connection ID of the Retry. TLS accepts the early data
    // either way (the ClientHello of the second flight is the same),
    // so `earlyDataStatus` cannot tell the two apart; the moment at
    // which the server can read the bytes can.
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .retry = true });
    defer srv.deinit();
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1002);

    const r = try resumeWithEarlyData(allocator, &srv, sink.captured.?, 2002);
    try std.testing.expectEqual(@as(u32, 1), r.retries);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expectEqual(early_payload.len, r.read);
    try std.testing.expect(r.read_before_handshake_done);
}

/// The number of live early-data packets in the client's sent tracker,
/// and the lowest packet number among them.
fn earlyPacketsInFlight(cli: *quic.Client) struct { count: u32, lowest_pn: ?u64 } {
    const path = cli.conn.paths.get(0).?;
    var count: u32 = 0;
    var lowest: ?u64 = null;
    var i: u32 = 0;
    while (i < path.sent.count) : (i += 1) {
        const p = path.sent.packets[i];
        if (p.dead or !p.is_early_data) continue;
        count += 1;
        if (lowest == null or p.pn < lowest.?) lowest = p.pn;
    }
    return .{ .count = count, .lowest_pn = lowest };
}

test "0-RTT after a Retry: the early packets leave the flight, nothing is counted as lost, and packet numbers go on" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .retry = true });
    defer srv.deinit();
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1004);

    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2004 } };
    var cli = try newClient(allocator, null, sink.captured.?);
    defer cli.deinit();
    cli.conn.setEarlyDataEnabled(true);
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, early_payload);
    try cli.conn.streamFinish(0);
    try cli.conn.advance();
    try std.testing.expect(!cli.conn.retryAccepted());

    // The first flight goes to the server, which answers with a Retry
    // and keeps nothing. The Retry is held back for a moment.
    const now_us: u64 = 60_000_000;
    var rx: [4096]u8 = undefined;
    var retry_buf: [512]u8 = undefined;
    var retry_len: usize = 0;
    while (try cli.conn.poll(&rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
        while (srv.drainStatelessResponse()) |resp| {
            @memcpy(retry_buf[0..resp.len], resp.slice());
            retry_len = resp.len;
        }
    }
    try std.testing.expect(retry_len > 0);
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());

    // Before the Retry arrives: the early data is in flight.
    const path = cli.conn.paths.get(0).?;
    const before = earlyPacketsInFlight(&cli);
    try std.testing.expect(before.count >= 1);
    const pn_before = path.app_pn_space.next_pn;
    try std.testing.expect(pn_before > before.lowest_pn.?);
    const stats_before = cli.conn.stats();
    try std.testing.expect(stats_before.bytes_in_flight > 0);
    try std.testing.expectEqual(@as(u64, 0), stats_before.packets_lost);

    try cli.conn.handle(retry_buf[0..retry_len], null, now_us);
    try std.testing.expect(cli.conn.retryAccepted());

    // After it: no early packet is in flight, nothing is lost, the
    // congestion window is what it was, and no packet number was
    // given back.
    try std.testing.expectEqual(@as(u32, 0), earlyPacketsInFlight(&cli).count);
    const stats_after = cli.conn.stats();
    try std.testing.expectEqual(@as(u64, 0), stats_after.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), stats_after.packets_lost);
    try std.testing.expectEqual(stats_before.cwnd, stats_after.cwnd);
    try std.testing.expectEqual(pn_before, path.app_pn_space.next_pn);

    // The second flight carries the early data again, in packets with
    // new numbers.
    while (try cli.conn.poll(&rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
    }
    const again = earlyPacketsInFlight(&cli);
    try std.testing.expect(again.count >= 1);
    try std.testing.expect(again.lowest_pn.? >= pn_before);
    try std.testing.expect(path.app_pn_space.next_pn > pn_before);
    try std.testing.expectEqual(@as(u64, 0), cli.conn.stats().packets_lost);
    // The server made a connection for this flight, and the early
    // bytes are readable at once.
    try std.testing.expectEqual(@as(usize, 1), srv.connectionCount());
    const slot = srv.iterator()[0];
    var rbuf: [64]u8 = undefined;
    const got = try slot.conn.streamRead(0, &rbuf);
    try std.testing.expectEqualStrings(early_payload, rbuf[0..got]);
    try std.testing.expect(!slot.conn.handshakeDone());
}

test "0-RTT after a Retry at a new server with the same ticket key: the early data is read before the handshake is done" {
    // The whole case of a crash-restart behind source validation: the
    // new process has the ticket key of the old one, and it answers
    // the client's first flight with a Retry (it has no NEW_TOKEN key
    // of the old process to validate the address with).
    const allocator = std.testing.allocator;
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    {
        var old = try newServer(allocator, .{ .retry = true, .ticket_key = key_a });
        defer old.deinit();
        try earnTicket(allocator, &old, &sink, 1105);
    }
    var new = try newServer(allocator, .{ .retry = true, .ticket_key = key_a });
    defer new.deinit();
    const r = try resumeWithEarlyData(allocator, &new, sink.captured.?, 2107);
    try std.testing.expectEqual(@as(u32, 1), r.retries);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);
}

// ------------------------------------------- the number of 0-RTT streams

test "0-RTT: before the handshake a resumed client opens no more streams than it remembers" {
    // RFC 9000 section 7.4.1: a client that sends 0-RTT data uses the
    // limits that the server gave on the connection that the ticket
    // comes from. That holds for the NUMBER of streams too.
    const allocator = std.testing.allocator;
    var params = common.defaultParams();
    params.initial_max_streams_bidi = 3;
    params.initial_max_streams_uni = 2;
    var srv = try newServer(allocator, .{ .transport_params = params });
    defer srv.deinit();
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1003);

    var cli = try newClient(allocator, null, sink.captured.?);
    defer cli.deinit();
    cli.conn.setEarlyDataEnabled(true);
    // Client-initiated bidirectional streams are 0, 4, 8, ...;
    // unidirectional ones are 2, 6, 10, ...
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.openBidi(4);
    _ = try cli.conn.openBidi(8);
    try std.testing.expectError(error.StreamLimitExceeded, cli.conn.openBidi(12));
    _ = try cli.conn.openUni(2);
    _ = try cli.conn.openUni(6);
    try std.testing.expectError(error.StreamLimitExceeded, cli.conn.openUni(10));
}

test "0-RTT: after the handshake the server's new limits replace the remembered ones" {
    // The new server has the ticket key of the old one and allows
    // MORE streams. (Its transport parameters differ, so it refuses
    // the early data itself; the session still resumes, and the
    // early bytes arrive after the handshake.)
    const allocator = std.testing.allocator;
    var small = common.defaultParams();
    small.initial_max_streams_bidi = 3;
    var large = common.defaultParams();
    large.initial_max_streams_bidi = 5;

    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    {
        var old = try newServer(allocator, .{ .transport_params = small, .ticket_key = key_a });
        defer old.deinit();
        try earnTicket(allocator, &old, &sink, 1107);
    }
    var srv = try newServer(allocator, .{ .transport_params = large, .ticket_key = key_a });
    defer srv.deinit();

    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = 2108 } };
    var cli = try newClient(allocator, null, sink.captured.?);
    defer cli.deinit();
    cli.conn.setEarlyDataEnabled(true);
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, early_payload);
    try cli.conn.streamFinish(0);
    _ = try cli.conn.openBidi(4);
    _ = try cli.conn.openBidi(8);
    try std.testing.expectError(error.StreamLimitExceeded, cli.conn.openBidi(12));
    try cli.conn.advance();

    var now_us: u64 = 60_000_000;
    var step: u32 = 0;
    while (step < 100 and !cli.conn.handshakeDone()) : (step += 1) {
        _ = try clientToServer(&cli, &srv, addr, now_us);
        try serverToClient(&srv, &cli, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(!cli.conn.isClosed());

    // The limit is the server's new one: 5 streams, not 3.
    _ = try cli.conn.openBidi(12);
    _ = try cli.conn.openBidi(16);
    try std.testing.expectError(error.StreamLimitExceeded, cli.conn.openBidi(20));
}
