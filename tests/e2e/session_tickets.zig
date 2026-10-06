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
    previous_key: ?quic.SessionTicketKey = null,
    previous_until_us: ?u64 = null,
};

/// The client's own ticket limit (`Client.Config.session_ticket_lifetime_s`)
/// for the clients that `newClient` makes; null = BoringSSL's 2 days.
var client_ticket_limit_s: ?u32 = null;

/// A test key whose three parts (key name, HMAC key, AES key; 16
/// bytes each) all differ, and that differs from the key of another
/// seed in each part. A key of 48 equal bytes cannot tell a server
/// that takes the wrong part for a job from one that takes the right
/// one. (That is not a guess: with such keys, three mutants of the
/// ticket callback passed every test.)
fn testKey(comptime seed: u8) quic.SessionTicketKey {
    var key: quic.SessionTicketKey = undefined;
    for (&key, 0..) |*b, i| b.* = seed ^ @as(u8, @intCast((i * 7 + i / 16 * 31) & 0xff));
    return key;
}

const key_a: quic.SessionTicketKey = testKey(0xa5);
const key_b: quic.SessionTicketKey = testKey(0x5b);
const key_c: quic.SessionTicketKey = testKey(0x77);

comptime {
    for ([_]quic.SessionTicketKey{ key_a, key_b, key_c }) |k| {
        std.debug.assert(!std.mem.eql(u8, k[0..16], k[16..32]));
        std.debug.assert(!std.mem.eql(u8, k[16..32], k[32..48]));
        std.debug.assert(!std.mem.eql(u8, k[0..16], k[32..48]));
    }
    std.debug.assert(!std.mem.eql(u8, key_a[0..16], key_b[0..16]));
    std.debug.assert(!std.mem.eql(u8, key_b[0..16], key_c[0..16]));
    std.debug.assert(!std.mem.eql(u8, key_a[0..16], key_c[0..16]));
}

const st = quic.tls.session_ticket;

/// The key that the server's current TLS context seals tickets under,
/// when the Server manages the keys itself; null when BoringSSL does.
fn sealingKey(srv: *quic.Server) ?quic.SessionTicketKey {
    const ring = st.installedRing(srv.tls_ctx) orelse return null;
    return ring.current;
}

/// The key before it, while it still opens tickets.
fn previousKey(srv: *quic.Server) ?quic.SessionTicketKey {
    const ring = st.installedRing(srv.tls_ctx) orelse return null;
    return ring.previous;
}

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
        .previous_session_ticket_key = opts.previous_key,
        .previous_session_ticket_key_until_us = opts.previous_until_us,
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
        .session_ticket_lifetime_s = client_ticket_limit_s,
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
    return resumeWith(allocator, srv, envelope, port, .{});
}

const ResumeOptions = struct {
    /// Run on until the client has a NEW ticket from this connection
    /// in the sink (which must be empty at the call).
    sink: ?*EnvelopeSink = null,
    /// The server's clock (`now_us`) at the first datagram.
    start_us: u64 = 60_000_000,
};

/// `resumeWithEarlyData` with options.
fn resumeWith(allocator: std.mem.Allocator, srv: *quic.Server, envelope: []const u8, port: u16, opts: ResumeOptions) !Resumed {
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x22), .port = port } };
    const sink = opts.sink;
    if (sink) |s| try std.testing.expect(s.captured == null);
    var cli = try newClient(allocator, sink, envelope);
    defer cli.deinit();
    cli.conn.setEarlyDataEnabled(true);
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, early_payload);
    try cli.conn.streamFinish(0);
    try cli.conn.advance();

    var out: Resumed = .{ .status = .not_offered, .read_before_handshake_done = false, .read = 0, .retries = 0 };
    var now_us: u64 = opts.start_us;
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
        if (cli.conn.handshakeDone() and out.read >= early_payload.len and
            (sink == null or sink.?.captured != null)) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(!cli.conn.isClosed());
    try std.testing.expectEqualStrings(early_payload, rbuf[0..out.read]);
    if (sink) |s| try std.testing.expect(s.captured != null);
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
        try std.testing.expectEqualSlices(u8, &key_a, &sealingKey(&srv).?);

        try srv.replaceTlsContext(reload);
        try std.testing.expectEqualSlices(u8, &key_a, &sealingKey(&srv).?);
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
        try std.testing.expectEqualSlices(u8, &key, &sealingKey(&srv).?);
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
        try std.testing.expectEqualSlices(u8, &key_a, &sealingKey(&srv).?);
        try std.testing.expect(previousKey(&srv) == null);
    }
    // No key: BoringSSL keeps a key of its own for the context.
    {
        var srv = try quic.Server.init(base);
        defer srv.deinit();
        try std.testing.expect(sealingKey(&srv) == null);
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

// ------------------------------------------------------ a change of key

const us_per_s: u64 = 1_000_000;

test "key rotation: a ticket of the old key still resumes with 0-RTT, and the client leaves with a ticket of the new key" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    var old_ticket: EnvelopeSink = .{ .allocator = allocator };
    defer old_ticket.deinit();
    try earnTicket(allocator, &srv, &old_ticket, 1301);

    try srv.rotateSessionTicketKey(key_b, 50 * us_per_s);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
    try std.testing.expectEqualSlices(u8, &key_a, &previousKey(&srv).?);

    var new_ticket: EnvelopeSink = .{ .allocator = allocator };
    defer new_ticket.deinit();
    const r = try resumeWith(allocator, &srv, old_ticket.captured.?, 2301, .{ .sink = &new_ticket });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);

    // The new ticket is under the new key: a server that has ONLY the
    // new key takes it, and not the old ticket.
    var only_new = try newServer(allocator, .{ .ticket_key = key_b });
    defer only_new.deinit();
    const with_new = try resumeWithEarlyData(allocator, &only_new, new_ticket.captured.?, 2302);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, with_new.status);
    try std.testing.expect(with_new.read_before_handshake_done);
    const with_old = try resumeWithEarlyData(allocator, &only_new, old_ticket.captured.?, 2303);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, with_old.status);
    // And a server that has only the OLD key does not take the new
    // ticket.
    var only_old = try newServer(allocator, .{ .ticket_key = key_a });
    defer only_old.deinit();
    const new_at_old = try resumeWithEarlyData(allocator, &only_old, new_ticket.captured.?, 2304);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, new_at_old.status);
}

test "key rotation: the old key opens tickets for one ticket lifetime, then it is gone" {
    // The ticket lifetime is 10 s. The rotation is at 100 s on the
    // server's clock, so the old key is good until 110 s. (TLS's own
    // clock, which ages the tickets, does not move in this test.)
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
    defer srv.deinit();
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1305);
    const old_ticket = try allocator.dupe(u8, sink.captured.?);
    defer allocator.free(old_ticket);

    try srv.rotateSessionTicketKey(key_b, 100 * us_per_s);

    try srv.tick(109 * us_per_s);
    try std.testing.expect(previousKey(&srv) != null);
    const before = try resumeWith(allocator, &srv, old_ticket, 2305, .{ .start_us = 109 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, before.status);
    try std.testing.expect(before.read_before_handshake_done);
    // (The helper closes that connection over some seconds of the
    // server's clock, so the old key may be gone already here.)

    // The first datagram at 110 s already finds the old key gone.
    const after = try resumeWith(allocator, &srv, old_ticket, 2306, .{ .start_us = 110 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, after.status);
    try std.testing.expect(!after.read_before_handshake_done);
    try std.testing.expect(previousKey(&srv) == null);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
}

test "key rotation: `tick` alone clears the old key when its time is over; with no lifetime set that is after 2 days" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    try srv.rotateSessionTicketKey(key_b, 7 * us_per_s);
    const two_days_us: u64 = 2 * 24 * 60 * 60 * us_per_s;

    try srv.tick(7 * us_per_s + two_days_us - 1);
    try std.testing.expectEqualSlices(u8, &key_a, &previousKey(&srv).?);
    try srv.tick(7 * us_per_s + two_days_us);
    try std.testing.expect(previousKey(&srv) == null);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
}

test "key rotation: a second rotation drops the first key at once" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    var ticket_a: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_a.deinit();
    try earnTicket(allocator, &srv, &ticket_a, 1307);

    try srv.rotateSessionTicketKey(key_b, 50 * us_per_s);
    var ticket_b: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_b.deinit();
    try earnTicket(allocator, &srv, &ticket_b, 1308);

    try srv.rotateSessionTicketKey(key_c, 51 * us_per_s);
    try std.testing.expectEqualSlices(u8, &key_c, &sealingKey(&srv).?);
    try std.testing.expectEqualSlices(u8, &key_b, &previousKey(&srv).?);

    const first = try resumeWithEarlyData(allocator, &srv, ticket_a.captured.?, 2307);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, first.status);
    const second = try resumeWithEarlyData(allocator, &srv, ticket_b.captured.?, 2308);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, second.status);
    try std.testing.expect(second.read_before_handshake_done);
}

test "key rotation: a certificate reload keeps both keys" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    var ticket_a: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_a.deinit();
    try earnTicket(allocator, &srv, &ticket_a, 1309);

    try srv.rotateSessionTicketKey(key_b, 50 * us_per_s);
    try srv.replaceTlsContext(.{ .pem = .{
        .cert_pem = common.test_cert_pem,
        .key_pem = common.test_key_pem,
    } });
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
    try std.testing.expectEqualSlices(u8, &key_a, &previousKey(&srv).?);

    var ticket_b: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_b.deinit();
    const r = try resumeWith(allocator, &srv, ticket_a.captured.?, 2309, .{ .sink = &ticket_b });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    try std.testing.expect(r.read_before_handshake_done);
    var only_new = try newServer(allocator, .{ .ticket_key = key_b });
    defer only_new.deinit();
    const with_new = try resumeWithEarlyData(allocator, &only_new, ticket_b.captured.?, 2310);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, with_new.status);
}

test "key rotation: refused on a server with no key, for a zero key, and for a key with the name of the current one" {
    const allocator = std.testing.allocator;
    {
        var srv = try newServer(allocator, .{});
        defer srv.deinit();
        try std.testing.expectError(error.InvalidConfig, srv.rotateSessionTicketKey(key_b, 1));
        try std.testing.expect(sealingKey(&srv) == null);
    }
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    try std.testing.expectError(error.InvalidConfig, srv.rotateSessionTicketKey(@splat(0), 1));
    // The same key again.
    try std.testing.expectError(error.InvalidConfig, srv.rotateSessionTicketKey(key_a, 1));
    // Other secrets under the same 16-byte name: a ticket could not
    // say which of the two sealed it.
    var same_name = key_b;
    @memcpy(same_name[0..16], key_a[0..16]);
    try std.testing.expectError(error.InvalidConfig, srv.rotateSessionTicketKey(same_name, 1));
    // Nothing changed.
    try std.testing.expectEqualSlices(u8, &key_a, &sealingKey(&srv).?);
    try std.testing.expect(previousKey(&srv) == null);
    // A key that differs in the name is taken.
    try srv.rotateSessionTicketKey(key_b, 1);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
}

test "key rotation: a datagram alone clears the old key when its time is over" {
    // `feed` checks before it looks at the datagram, so the handshake
    // that a datagram starts never opens a ticket with a key whose
    // time is over.
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
    defer srv.deinit();
    try srv.rotateSessionTicketKey(key_b, 100 * us_per_s);
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x44), .port = 4444 } };
    var junk: [40]u8 = @splat(0x41);

    _ = try srv.feed(&junk, addr, 110 * us_per_s - 1);
    try std.testing.expect(previousKey(&srv) != null);
    _ = try srv.feed(&junk, addr, 110 * us_per_s);
    try std.testing.expect(previousKey(&srv) == null);
}

test "key rotation: a process that restarts before the old key's time is over starts with the old key and rotates again" {
    // `Config.session_ticket_key` is one key, so a process that STARTS
    // with the new key cannot open the tickets of the old one. The
    // way to keep them (the doc of `rotateSessionTicketKey` gives it):
    // start with the old key and repeat the rotation before the first
    // datagram, with the `now_us` of the first rotation. The clock
    // here goes on across the restart. Lifetime 10 s, first rotation
    // at 100 s: the old key is good until 110 s, also in the process
    // after the restart. (Found by capnp-zig.)
    const allocator = std.testing.allocator;
    const rotated_at_us: u64 = 100 * us_per_s;
    var ticket_a: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_a.deinit();
    var ticket_b: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_b.deinit();
    {
        // The process before the restart gives a ticket under each key.
        var before = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
        defer before.deinit();
        try earnTicket(allocator, &before, &ticket_a, 1311);
        try before.rotateSessionTicketKey(key_b, rotated_at_us);
        try earnTicket(allocator, &before, &ticket_b, 1312);
    }
    {
        // The control: a process that starts with the new key takes
        // the ticket of the new key, and not the ticket of the old one.
        var plain = try newServer(allocator, .{ .ticket_key = key_b, .ticket_lifetime_s = 10 });
        defer plain.deinit();
        const old = try resumeWith(allocator, &plain, ticket_a.captured.?, 2311, .{ .start_us = 104 * us_per_s });
        try std.testing.expectEqual(quic.EarlyDataStatus.rejected, old.status);
        const new = try resumeWith(allocator, &plain, ticket_b.captured.?, 2312, .{ .start_us = 104 * us_per_s });
        try std.testing.expectEqual(quic.EarlyDataStatus.accepted, new.status);
    }

    // The process after the restart. Its first datagram comes at 104 s.
    var srv = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
    defer srv.deinit();
    try srv.rotateSessionTicketKey(key_b, rotated_at_us);
    try srv.tick(104 * us_per_s);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
    try std.testing.expectEqualSlices(u8, &key_a, &previousKey(&srv).?);

    const old = try resumeWith(allocator, &srv, ticket_a.captured.?, 2313, .{ .start_us = 104 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, old.status);
    try std.testing.expect(old.read_before_handshake_done);
    const new = try resumeWith(allocator, &srv, ticket_b.captured.?, 2314, .{ .start_us = 105 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, new.status);
    try std.testing.expect(new.read_before_handshake_done);
    const late = try resumeWith(allocator, &srv, ticket_a.captured.?, 2315, .{ .start_us = 110 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, late.status);
    try std.testing.expect(previousKey(&srv) == null);

    // The old key ends at 110 s, where it would have ended with no
    // restart, and not one lifetime after the restart (114 s). The
    // helper above moves the clock while it closes a connection, so
    // the exact moment is looked at on a server of its own.
    var edge = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
    defer edge.deinit();
    try edge.rotateSessionTicketKey(key_b, rotated_at_us);
    try edge.tick(110 * us_per_s - 1);
    try std.testing.expect(previousKey(&edge) != null);
    try edge.tick(110 * us_per_s);
    try std.testing.expect(previousKey(&edge) == null);
}

test "session ticket key: an init that fails after the key was taken leaves nothing behind" {
    // The Server keeps its ticket keys on the heap. `init` fails here
    // at the certificate; the testing allocator reports a leak if the
    // keys were not freed.
    const allocator = std.testing.allocator;
    try std.testing.expect(std.meta.isError(quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n",
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .session_ticket_key = key_a,
    })));
}

test "ticket format: a server with the setting and a server with BoringSSL's plain key setter read each other's tickets" {
    // A pool can move its servers one at a time from "the key set on
    // the TLS context by hand" (`SSL_CTX_set_tlsext_ticket_keys`,
    // here through `tls.session_ticket.install`) to
    // `Config.session_ticket_key`. The Server seals through a
    // callback of its own, so this holds only because the callback
    // builds the ticket exactly as BoringSSL does.
    const allocator = std.testing.allocator;

    // From the setting to the plain setter.
    var from_setting: EnvelopeSink = .{ .allocator = allocator };
    defer from_setting.deinit();
    {
        var srv = try newServer(allocator, .{ .ticket_key = key_a });
        defer srv.deinit();
        try earnTicket(allocator, &srv, &from_setting, 1311);
    }
    var by_hand = try newServer(allocator, .{});
    defer by_hand.deinit();
    try st.install(by_hand.tls_ctx, &key_a);
    const r1 = try resumeWithEarlyData(allocator, &by_hand, from_setting.captured.?, 2311);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r1.status);
    try std.testing.expect(r1.read_before_handshake_done);

    // From the plain setter to the setting.
    var from_hand: EnvelopeSink = .{ .allocator = allocator };
    defer from_hand.deinit();
    try earnTicket(allocator, &by_hand, &from_hand, 1312);
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    const r2 = try resumeWithEarlyData(allocator, &srv, from_hand.captured.?, 2312);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r2.status);
    try std.testing.expect(r2.read_before_handshake_done);
}

test "ticket format: the plain setter on top of the setting changes nothing (the setting's keys are used)" {
    // An embedder that still sets the key by hand after `Server.init`
    // (capnp-zig did, before the setting existed) and also uses the
    // setting: BoringSSL asks the callback and ignores the plain key.
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a });
    defer srv.deinit();
    try st.install(srv.tls_ctx, &key_c);
    var sink: EnvelopeSink = .{ .allocator = allocator };
    defer sink.deinit();
    try earnTicket(allocator, &srv, &sink, 1313);

    var same_setting = try newServer(allocator, .{ .ticket_key = key_a });
    defer same_setting.deinit();
    const r = try resumeWithEarlyData(allocator, &same_setting, sink.captured.?, 2313);
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, r.status);
    var plain_c = try newServer(allocator, .{});
    defer plain_c.deinit();
    try st.install(plain_c.tls_ctx, &key_c);
    const r2 = try resumeWithEarlyData(allocator, &plain_c, sink.captured.?, 2314);
    try std.testing.expectEqual(quic.EarlyDataStatus.rejected, r2.status);
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

// ------------------------------------------- a previous key at start

test "previous key at start: a process that starts with the new key and the old one opens the tickets of both" {
    // Lifetime 10 s. The process before rotated from A to B at 100 s
    // and gave a ticket under each key. The next process starts with
    // B as its key and A as the previous one, with the old time (110 s):
    // both tickets resume with 0-RTT, and A ends at 110 s.
    const allocator = std.testing.allocator;
    var ticket_a: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_a.deinit();
    var ticket_b: EnvelopeSink = .{ .allocator = allocator };
    defer ticket_b.deinit();
    {
        var before = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 10 });
        defer before.deinit();
        try earnTicket(allocator, &before, &ticket_a, 1321);
        try before.rotateSessionTicketKey(key_b, 100 * us_per_s);
        try earnTicket(allocator, &before, &ticket_b, 1322);
    }

    var srv = try newServer(allocator, .{ .ticket_key = key_b, .ticket_lifetime_s = 10, .previous_key = key_a, .previous_until_us = 110 * us_per_s });
    defer srv.deinit();
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);
    try std.testing.expectEqualSlices(u8, &key_a, &previousKey(&srv).?);

    const old = try resumeWith(allocator, &srv, ticket_a.captured.?, 2321, .{ .start_us = 104 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, old.status);
    try std.testing.expect(old.read_before_handshake_done);
    const new = try resumeWith(allocator, &srv, ticket_b.captured.?, 2322, .{ .start_us = 105 * us_per_s });
    try std.testing.expectEqual(quic.EarlyDataStatus.accepted, new.status);
    try std.testing.expect(new.read_before_handshake_done);

    // The time given is the end, not one lifetime from the start.
    var edge = try newServer(allocator, .{ .ticket_key = key_b, .ticket_lifetime_s = 10, .previous_key = key_a, .previous_until_us = 110 * us_per_s });
    defer edge.deinit();
    try edge.tick(110 * us_per_s - 1);
    try std.testing.expect(previousKey(&edge) != null);
    try edge.tick(110 * us_per_s);
    try std.testing.expect(previousKey(&edge) == null);
}

test "previous key at start: with no time given, the old key ends one lifetime after the first tick or feed" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_b, .ticket_lifetime_s = 10, .previous_key = key_a });
    defer srv.deinit();
    try std.testing.expect(previousKey(&srv) != null);
    // The first tick anchors the time: 7 s + 10 s.
    try srv.tick(7 * us_per_s);
    try std.testing.expect(previousKey(&srv) != null);
    try srv.tick(17 * us_per_s - 1);
    try std.testing.expect(previousKey(&srv) != null);
    try srv.tick(17 * us_per_s);
    try std.testing.expect(previousKey(&srv) == null);
    try std.testing.expectEqualSlices(u8, &key_b, &sealingKey(&srv).?);

    // A datagram anchors it as well.
    var by_feed = try newServer(allocator, .{ .ticket_key = key_b, .previous_key = key_a });
    defer by_feed.deinit();
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x45), .port = 4545 } };
    var junk: [40]u8 = @splat(0x41);
    _ = try by_feed.feed(&junk, addr, 3 * us_per_s);
    const two_days_us: u64 = 2 * 24 * 60 * 60 * us_per_s;
    _ = try by_feed.feed(&junk, addr, 3 * us_per_s + two_days_us - 1);
    try std.testing.expect(previousKey(&by_feed) != null);
    _ = try by_feed.feed(&junk, addr, 3 * us_per_s + two_days_us);
    try std.testing.expect(previousKey(&by_feed) == null);
}

test "previous key at start: refused with no key, for a zero key, and for a key with the name of the current one" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidConfig, newServer(allocator, .{ .previous_key = key_a }));
    try std.testing.expectError(error.InvalidConfig, newServer(allocator, .{ .ticket_key = key_b, .previous_key = @splat(0) }));
    var same_name = key_a;
    @memcpy(same_name[0..16], key_b[0..16]);
    try std.testing.expectError(error.InvalidConfig, newServer(allocator, .{ .ticket_key = key_b, .previous_key = same_name }));
}

// ------------------------------------------- the client's own limit

test "ticket lifetime at the client: a BoringSSL client keeps a ticket for 2 days at most, unless its own limit is raised" {
    // The server says 7 days. A client with the default limit keeps
    // the ticket for 2 days; a client whose limit is 7 days keeps it
    // for 7. The lifetime kept is read from the saved envelope.
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 604800 });
    defer srv.deinit();

    var capped: EnvelopeSink = .{ .allocator = allocator };
    defer capped.deinit();
    try earnTicket(allocator, &srv, &capped, 1331);
    try std.testing.expectEqual(@as(u32, 172800), try quic.Client.resumptionTicketLifetimeSeconds(capped.captured.?));

    client_ticket_limit_s = 604800;
    defer client_ticket_limit_s = null;
    var raised: EnvelopeSink = .{ .allocator = allocator };
    defer raised.deinit();
    try earnTicket(allocator, &srv, &raised, 1332);
    try std.testing.expectEqual(@as(u32, 604800), try quic.Client.resumptionTicketLifetimeSeconds(raised.captured.?));

    // The smaller of the two: a server lifetime of 600 s stays 600 s
    // at a client that allows 7 days.
    var short = try newServer(allocator, .{ .ticket_key = key_a, .ticket_lifetime_s = 600 });
    defer short.deinit();
    var ten_minutes: EnvelopeSink = .{ .allocator = allocator };
    defer ten_minutes.deinit();
    try earnTicket(allocator, &short, &ten_minutes, 1333);
    try std.testing.expectEqual(@as(u32, 600), try quic.Client.resumptionTicketLifetimeSeconds(ten_minutes.captured.?));

    // Not an envelope: an error, not a number.
    try std.testing.expectError(error.InvalidFormat, quic.Client.resumptionTicketLifetimeSeconds("not an envelope"));
}

test "ticket lifetime at the client: connect refuses 0, more than 7 days, and a limit with a context of the embedder" {
    const allocator = std.testing.allocator;
    client_ticket_limit_s = 0;
    defer client_ticket_limit_s = null;
    try std.testing.expectError(error.InvalidConfig, newClient(allocator, null, null));
    client_ticket_limit_s = 604801;
    try std.testing.expectError(error.InvalidConfig, newClient(allocator, null, null));
    client_ticket_limit_s = null;

    var ctx = try boringssl.tls.Context.initClient(.{});
    defer ctx.deinit();
    try std.testing.expectError(error.InvalidConfig, quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .tls_context_override = ctx,
        .session_ticket_lifetime_s = 3600,
    }));
}
