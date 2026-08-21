//! End-to-end pins for `quic.app.Driver`: the typed application
//! dispatcher over the Server/Client wrappers. The tests drive a real
//! TLS handshake over in-memory datagram pumps and assert the
//! behaviors the Driver exists to guarantee:
//!
//!  - typed callbacks fire in order (connect → stream open → data →
//!    stream end), with no app-side casting or slot-diffing;
//!  - end-of-stream is detected on `streamRecvState().terminal`, so a
//!    reordering hole below the FIN never truncates the stream;
//!  - short-write staging (the Outbox) preserves byte order under
//!    backpressure;
//!  - sessions are freed exactly once, in the will-close hook.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const EchoApp = struct {
    pub const StreamState = struct { received: usize = 0 };
    pub const ConnState = struct { opens: u32 = 0, datagrams: u32 = 0 };

    allocator: std.mem.Allocator,

    connected: u32 = 0,
    handshakes: u32 = 0,
    disconnected: u32 = 0,
    /// Running total of stream bytes delivered through onStreamData —
    /// the progress signal the reordering test waits on (onStreamEnd
    /// is exactly what must NOT fire there).
    total_received: usize = 0,
    stream_ends: u32 = 0,
    last_end: ?quic.app.StreamEnd = null,
    last_received: usize = 0,
    closes: u32 = 0,
    /// Events landing in the dispatch's `else` arm (`on_event`) — the
    /// tracked-datagram ACK below guarantees at least one.
    other_events: u32 = 0,
    datagram_payloads: std.ArrayListUnmanaged([]u8) = .empty,

    fn onConnect(app: *EchoApp, session: *D.Session) anyerror!void {
        app.connected += 1;
        try std.testing.expect(session.app.opens == 0);
    }

    fn onHandshake(app: *EchoApp, session: *D.Session) anyerror!void {
        _ = session;
        app.handshakes += 1;
    }

    fn onStreamOpen(_: *EchoApp, session: *D.Session, _: *D.StreamEntry, bidi: bool) anyerror!void {
        if (bidi) session.app.opens += 1;
    }

    fn onStreamData(app: *EchoApp, session: *D.Session, entry: *D.StreamEntry, chunk: []const u8) anyerror!void {
        entry.state.received += chunk.len;
        app.total_received += chunk.len;
        try session.outbox.push(session.conn, entry.id, chunk);
    }

    fn onStreamEnd(app: *EchoApp, session: *D.Session, entry: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        app.stream_ends += 1;
        app.last_end = end;
        app.last_received = entry.state.received;
        if (end == .fin) try session.outbox.finish(session.conn, entry.id);
    }

    fn onDatagram(app: *EchoApp, session: *D.Session, data: []const u8) anyerror!void {
        session.app.datagrams += 1;
        const copy = try app.allocator.dupe(u8, data);
        try app.datagram_payloads.append(app.allocator, copy);
        // Tracked send: the eventual `datagram_acked` event exercises
        // the Driver's `on_event` (else-arm) dispatch deterministically.
        _ = session.conn.sendDatagramTracked(data) catch |err| switch (err) {
            error.DatagramUnavailable, error.DatagramTooLarge => @as(u64, 0),
            else => return err,
        };
    }

    fn onClose(app: *EchoApp, session: *D.Session, ev: quic.CloseEvent) anyerror!void {
        _ = session;
        _ = ev;
        app.closes += 1;
    }

    fn onEvent(app: *EchoApp, session: *D.Session, ev: quic.ConnectionEvent) anyerror!void {
        _ = session;
        _ = ev;
        app.other_events += 1;
    }

    fn onDisconnect(app: *EchoApp, session: *D.Session) void {
        app.disconnected += 1;
        // Session (and its slot) still fully valid here.
        std.debug.assert(session.conn == session.slot.conn);
        for (app.datagram_payloads.items) |p| app.allocator.free(p);
        app.datagram_payloads.clearRetainingCapacity();
    }
};

const D = quic.app.Driver(EchoApp);

const RefuseApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;
    fn onStreamData(_: *RefuseApp, _: *RD.Session, _: *RD.StreamEntry, _: []const u8) anyerror!void {}
};

const RD = quic.app.Driver(RefuseApp);

comptime {
    // Canary: if EchoApp's callbacks are invisible to comptime here,
    // every stream assertion below would silently test a datagram-only
    // server. Fail the build instead.
    if (!@hasDecl(EchoApp, "onStreamData")) @compileError("EchoApp decls invisible at Driver instantiation");
    if (!@hasDecl(EchoApp, "onStreamEnd")) @compileError("EchoApp decls invisible at Driver instantiation");
}

/// One c2s→service→s2c→tick iteration. Plain helper functions below
/// mirror the shape `runUdpServer` runs, with the Driver's service
/// pass slotted where `on_iteration` fires (before every `tick`).
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xcd), .port = 0 } };

fn pumpClientToServer(
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    now_us: u64,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        _ = try srv.feed(rx[0..len], addr, now_us);
    }
}

fn pumpClientToServerHolding(
    allocator: std.mem.Allocator,
    cli: *quic.Client,
    srv: *quic.Server,
    rx: []u8,
    now_us: u64,
    hold_idx: u32,
    held: *std.ArrayListUnmanaged([]u8),
    counter: *u32,
) !void {
    while (try cli.conn.poll(rx, now_us)) |len| {
        counter.* += 1;
        if (counter.* == hold_idx) {
            try held.append(allocator, try allocator.dupe(u8, rx[0..len]));
            continue;
        }
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

fn handshakePump(
    cli: *quic.Client,
    srv: *quic.Server,
    driver: *D,
    rx: []u8,
    now_us: *u64,
) !void {
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(cli, srv, rx, now_us.*);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(srv);
        try pumpServerToClient(srv, cli, rx, now_us.*);
        try srv.tick(now_us.*);
        try cli.conn.tick(now_us.*);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us.* += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
}

/// Close from the client, pump until the server observes it and the
/// slot drains, then reap so the Driver's session frees through the
/// will-close hook (leak-check hygiene: sessions are only freed there).
fn closeAndReap(
    cli: *quic.Client,
    srv: *quic.Server,
    driver: *D,
    rx: []u8,
    now_us: *u64,
) !void {
    cli.conn.close(false, 0, "done");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(cli, srv, rx, now_us.*);
        try driver.service(srv);
        try pumpServerToClient(srv, cli, rx, now_us.*);
        now_us.* += 10_000;
        try srv.tick(now_us.*);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}

test "Driver: echo application over the Server/Client wrappers, with lifecycle hooks" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: EchoApp = .{ .allocator = allocator };
    defer app.datagram_payloads.deinit(allocator);
    var driver = try D.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_connect = EchoApp.onConnect,
            .on_handshake = EchoApp.onHandshake,
            .on_stream_open = EchoApp.onStreamOpen,
            .on_stream_data = EchoApp.onStreamData,
            .on_stream_end = EchoApp.onStreamEnd,
            .on_datagram = EchoApp.onDatagram,
            .on_close = EchoApp.onClose,
            .on_event = EchoApp.onEvent,
            .on_disconnect = EchoApp.onDisconnect,
        },
        .max_tracked_streams = common.defaultParams().initial_max_streams_bidi +
            common.defaultParams().initial_max_streams_uni,
    });
    defer driver.deinit();
    // The loud canary: if the driver failed to resolve the stream
    // callback, every echo assertion below would test a datagram-only
    // server. Fail here, with a name that says what happened.
    try std.testing.expect(driver.streamsServiced());
    try std.testing.expect(driver.datagramsDelivered());

    var params = common.defaultParams();
    params.max_datagram_frame_size = 1200;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .on_connection_will_close = D.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = params,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try handshakePump(&cli, &srv, &driver, &rx, &now_us);

    // Application payload: 100 KiB across many packets, plus a
    // DATAGRAM. Both echo back.
    const total: usize = 100 * 1024;
    const payload = try allocator.alloc(u8, total);
    defer allocator.free(payload);
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    prng.random().bytes(payload);

    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, payload);
    try cli.conn.streamFinish(stream.id);
    try cli.conn.sendDatagram("driver-ping");

    var echo: std.ArrayListUnmanaged(u8) = .empty;
    defer echo.deinit(allocator);
    var rbuf: [4096]u8 = undefined;

    // Latched across iterations: the echoed DATAGRAM pops exactly
    // once, almost never on the same iteration the stream completes.
    var got_dg = false;
    var iters: u32 = 0;
    while (iters < 200_000) : (iters += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);

        while (true) {
            const n = cli.conn.streamRead(stream.id, &rbuf) catch |err| switch (err) {
                // The stream reached terminal and was GC'd — done.
                error.StreamNotFound => break,
                else => return err,
            };
            if (n == 0) break;
            try echo.appendSlice(allocator, rbuf[0..n]);
        }

        const st = cli.conn.streamRecvState(stream.id);
        var dgbuf: [1500]u8 = undefined;
        while (cli.conn.receiveDatagramInfo(&dgbuf)) |_| {
            got_dg = true;
        }
        const recv_done = st == null or st.?.terminal;
        const done = recv_done and echo.items.len == total and got_dg;
        if (done) break;
        now_us += 1_000;
    }

    // The echo is byte-exact and complete. Distinct error names so a
    // failure says which half broke.
    if (echo.items.len != total) {
        std.debug.print("echo truncated: got {d} of {d} bytes\n", .{ echo.items.len, total });
        return error.EchoTruncated;
    }
    try std.testing.expectEqualSlices(u8, payload, echo.items);
    try std.testing.expectEqual(@as(u32, 1), app.connected);
    try std.testing.expectEqual(@as(u32, 1), app.handshakes);
    try std.testing.expectEqual(@as(u32, 1), app.stream_ends);
    try std.testing.expect(app.last_end != null and app.last_end.? == .fin);
    try std.testing.expectEqual(total, app.last_received);
    try std.testing.expectEqual(@as(u32, 1), app.datagram_payloads.items.len);
    try std.testing.expectEqualStrings("driver-ping", app.datagram_payloads.items[0]);

    // Settle until the client's delayed ACK (max_ack_delay 25 ms) for
    // the datagram-carrying packet lands: the server's tracked send
    // then surfaces `datagram_acked`, which must reach the app via the
    // `on_event` (else-arm) dispatch.
    var settle: u32 = 0;
    while (settle < 100) : (settle += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
        if (app.other_events > 0) break;
    }
    try std.testing.expect(app.other_events > 0);

    // Teardown: close, drain, reap — the session must free exactly
    // once, through the will-close hook, and the close event must
    // reach the app through the `on_close` dispatch on the way out.
    try closeAndReap(&cli, &srv, &driver, &rx, &now_us);
    try std.testing.expectEqual(@as(u32, 1), app.disconnected);
    try std.testing.expect(app.closes >= 1);
}

test "Driver: stream end waits for a reordering hole below the FIN, not the FIN frame" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: EchoApp = .{ .allocator = allocator };
    var driver = try D.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = EchoApp.onStreamData,
            .on_stream_end = EchoApp.onStreamEnd,
        },
        .max_tracked_streams = 32,
    });
    defer driver.deinit();

    var params = common.defaultParams();
    params.max_datagram_frame_size = 1200;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .on_connection_will_close = D.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = params,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try handshakePump(&cli, &srv, &driver, &rx, &now_us);

    // Payload spans several packets. The FIN rides the last one; the
    // datagram held back below is a mid-stream data packet, so the
    // server sees the FIN with a hole below it. A FIN-frame-based end
    // test fires early and truncates; the terminal-state test must
    // not. (The hold counter starts AFTER the handshake so it counts
    // only stream-data datagrams.)
    const total: usize = 4 * 1024;
    const payload = try allocator.alloc(u8, total);
    defer allocator.free(payload);
    @memset(payload, 0xab);

    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, payload);
    try cli.conn.streamFinish(stream.id);

    var held: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (held.items) |h| allocator.free(h);
        held.deinit(allocator);
    }
    var c2s_idx: u32 = 0; // post-handshake datagram counter
    const hold_at: u32 = 2; // a mid-stream data packet, past the first

    // Phase 1: everything except `hold_at` is delivered. The server
    // sees the FIN (it rides a later packet) but has a hole below it.
    var phase1: u32 = 0;
    while (phase1 < 4_000) : (phase1 += 1) {
        try pumpClientToServerHolding(allocator, &cli, &srv, &rx, now_us, hold_at, &held, &c2s_idx);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
        if (app.total_received > 0) break; // server received *something*
    }
    try std.testing.expect(app.total_received > 0);
    try std.testing.expectEqual(@as(u32, 0), app.stream_ends); // the hole holds the end back
    try std.testing.expectEqual(@as(usize, 1), held.items.len);

    // Phase 2: release the held datagram. Now every byte arrives, the
    // recv half goes terminal, and the end fires exactly once with
    // the FULL byte count.
    _ = try srv.feed(held.items[0], addr, now_us);
    var phase2: u32 = 0;
    var echo: std.ArrayListUnmanaged(u8) = .empty;
    defer echo.deinit(allocator);
    var rbuf: [4096]u8 = undefined;
    while (phase2 < 100_000) : (phase2 += 1) {
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        while (true) {
            const n = cli.conn.streamRead(stream.id, &rbuf) catch |err| switch (err) {
                error.StreamNotFound => break,
                else => return err,
            };
            if (n == 0) break;
            try echo.appendSlice(allocator, rbuf[0..n]);
        }
        if (app.stream_ends == 1 and echo.items.len == total) break;
        now_us += 1_000;
    }

    try std.testing.expectEqual(@as(u32, 1), app.stream_ends);
    try std.testing.expect(app.last_end.? == .fin);
    try std.testing.expectEqual(total, app.last_received);
    try std.testing.expectEqualSlices(u8, payload, echo.items);

    try closeAndReap(&cli, &srv, &driver, &rx, &now_us);
}

test "Driver: full stream table refuses via STOP_SENDING, not a silent hang" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: RefuseApp = .{};
    // Table of one: the second peer stream cannot be tracked.
    var driver = try RD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{ .on_stream_data = RefuseApp.onStreamData },
        .max_tracked_streams = 1,
    });
    defer driver.deinit();

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = RD.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;

    // Minimal handshake pump (no Driver-echo interplay needed).
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // Open three client bidi streams. Only one fits the server's
    // table; the other two must earn a STOP_SENDING (observed by the
    // client as a recv-half reset).
    const s0 = try cli.conn.openNextBidi();
    const s1 = try cli.conn.openNextBidi();
    _ = s0;
    _ = try cli.conn.streamWrite(s1.id, "two");
    try cli.conn.streamFinish(s1.id);

    var iters: u32 = 0;
    while (iters < 5_000) : (iters += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        // STOP_SENDING lands on the client as a send-half abort of
        // the refused (client-initiated) stream: reset_sent, possibly
        // already reset_recvd once the server ACKs the RESET_STREAM.
        if (cli.conn.stream(s1.id)) |cs| {
            if (cs.send.state == .reset_sent or cs.send.state == .reset_recvd) break;
        }
        now_us += 1_000;
    }
    // The overflowed stream was refused on the wire: the client's
    // send half of s1 aborted after receiving STOP_SENDING.
    const cs1 = cli.conn.stream(s1.id) orelse return error.RefusedStreamMissing;
    try std.testing.expect(cs1.send.reset != null);

    // Teardown: same close-and-reap, typed for this test's driver.
    cli.conn.close(false, 0, "done");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        now_us += 10_000;
        try srv.tick(now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}

// -- Abrupt-disconnect teardown --------------------------------------------

const LeakApp = struct {
    pub const StreamState = struct { buf: std.ArrayListUnmanaged(u8) = .empty };
    pub const ConnState = void;

    allocator: std.mem.Allocator,
    received: usize = 0,
    ends: u32 = 0,
    last_end: ?quic.app.StreamEnd = null,
    freed_bytes: usize = 0,

    fn onStreamData(app: *LeakApp, _: *LD.Session, e: *LD.StreamEntry, chunk: []const u8) anyerror!void {
        app.received += chunk.len;
        try e.state.buf.appendSlice(app.allocator, chunk);
    }

    fn onStreamEnd(app: *LeakApp, _: *LD.Session, e: *LD.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        app.ends += 1;
        app.last_end = end;
        app.freed_bytes += e.state.buf.items.len;
        e.state.buf.deinit(app.allocator);
    }
};

const LD = quic.app.Driver(LeakApp);

test "Driver: abrupt disconnect mid-request still delivers the stream end (no state leak)" {
    // A stream is tracked, has buffered app state, and is nowhere near
    // finished when the peer vanishes. No service pass observes an end
    // — the will-close hook must synthesize `.reaped` so the app frees
    // its per-stream state (std.testing.allocator turns a miss into a
    // leak failure).
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: LeakApp = .{ .allocator = allocator };
    var driver = try LD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = LeakApp.onStreamData,
            .on_stream_end = LeakApp.onStreamEnd,
        },
        .max_tracked_streams = 32,
    });
    defer driver.deinit();

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = LD.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;

    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // A request that never finishes: bytes, no FIN.
    const partial = "half a request";
    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, partial);

    var phase1: u32 = 0;
    while (phase1 < 4_000) : (phase1 += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
        if (app.received == partial.len) break;
    }
    try std.testing.expectEqual(partial.len, app.received);
    try std.testing.expectEqual(@as(u32, 0), app.ends); // still mid-request

    // Abrupt teardown: the close is delivered and the slot reaped with
    // NO further service passes — nothing else can end the stream.
    cli.conn.close(false, 0, "gone");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        now_us += 10_000;
        try srv.tick(now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);

    try std.testing.expectEqual(@as(u32, 1), app.ends);
    try std.testing.expect(app.last_end.? == .reaped);
    try std.testing.expectEqual(partial.len, app.freed_bytes);
}

// -- Driver fault containment ----------------------------------------------

const FaultApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;

    trip_load: bool = false, // next onStreamData -> error.ExcessiveLoad
    fail_connect: bool = false, // next onConnect -> error.ConnectRefused
    fail_end: bool = false, // next onStreamEnd -> error.AppStop
    connects: u32 = 0,
    ends: u32 = 0,
    disconnects: u32 = 0,

    fn onConnect(app: *FaultApp, _: *FD.Session) anyerror!void {
        app.connects += 1;
        if (app.fail_connect) {
            app.fail_connect = false;
            return error.ConnectRefused;
        }
    }

    fn onStreamData(app: *FaultApp, _: *FD.Session, _: *FD.StreamEntry, _: []const u8) anyerror!void {
        if (app.trip_load) {
            app.trip_load = false;
            return error.ExcessiveLoad;
        }
    }

    fn onStreamEnd(app: *FaultApp, _: *FD.Session, _: *FD.StreamEntry, _: quic.app.StreamEnd) anyerror!void {
        app.ends += 1;
        if (app.fail_end) {
            app.fail_end = false;
            return error.AppStop;
        }
    }

    fn onDisconnect(app: *FaultApp, _: *FD.Session) void {
        app.disconnects += 1;
    }
};

const FD = quic.app.Driver(FaultApp);

fn faultPair(
    allocator: std.mem.Allocator,
    driver: *FD,
    srv: *quic.Server,
    cli: *quic.Client,
) !void {
    const protos = [_][]const u8{"hq-test"};
    srv.* = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = FD.willCloseHook,
        .on_connection_will_close_user_data = driver,
    });
    errdefer srv.deinit();
    cli.* = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

test "Driver: error.ExcessiveLoad closes the one connection, not the server" {
    const allocator = std.testing.allocator;
    var app: FaultApp = .{};
    var driver = try FD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_connect = FaultApp.onConnect,
            .on_stream_data = FaultApp.onStreamData,
            .on_stream_end = FaultApp.onStreamEnd,
            .on_disconnect = FaultApp.onDisconnect,
        },
        .max_tracked_streams = 32,
    });
    defer driver.deinit();

    var srv: quic.Server = undefined;
    var cli: quic.Client = undefined;
    try faultPair(allocator, &driver, &srv, &cli);
    defer srv.deinit();
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // Arm the trip, deliver a chunk: service must swallow the
    // connection-scoped error (server survives), closing that slot.
    app.trip_load = true;
    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, "ping");
    try pumpClientToServer(&cli, &srv, &rx, now_us);
    try driver.service(&srv); // must NOT return the error

    // The tripped connection drains and reaps; the driver session
    // frees through the normal will-close path.
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        now_us += 10_000;
        try srv.tick(now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
    try std.testing.expectEqual(@as(u32, 1), app.disconnects);
}

test "Driver: a failing on_connect unwinds the session completely and retries" {
    const allocator = std.testing.allocator;
    var app: FaultApp = .{ .fail_connect = true };
    var driver = try FD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_connect = FaultApp.onConnect,
            .on_stream_data = FaultApp.onStreamData,
            .on_disconnect = FaultApp.onDisconnect,
        },
        .max_tracked_streams = 32,
    });
    defer driver.deinit();

    var srv: quic.Server = undefined;
    var cli: quic.Client = undefined;
    try faultPair(allocator, &driver, &srv, &cli);
    defer srv.deinit();
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try cli.conn.advance();
    var connect_errors: u32 = 0;
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        driver.service(&srv) catch |err| {
            // The app error propagates (the supported stop-the-loop
            // path). The half-born session must be fully unwound: no
            // dangling slot.user_data for the next pass to chase.
            try std.testing.expectEqual(error.ConnectRefused, err);
            connect_errors += 1;
            try std.testing.expect(srv.iterator()[0].user_data == null);
        };
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expectEqual(@as(u32, 1), connect_errors);
    // The retry created a live session on the next pass.
    try std.testing.expectEqual(@as(u32, 2), app.connects);

    try closeAndReapFD(&cli, &srv, &driver, &rx, &now_us);
    try std.testing.expectEqual(@as(u32, 1), app.disconnects);
}

test "Driver: an on_stream_end error still releases the entry (end fires exactly once)" {
    const allocator = std.testing.allocator;
    var app: FaultApp = .{ .fail_end = true };
    var driver = try FD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = FaultApp.onStreamData,
            .on_stream_end = FaultApp.onStreamEnd,
            .on_disconnect = FaultApp.onDisconnect,
        },
        .max_tracked_streams = 32,
    });
    defer driver.deinit();

    var srv: quic.Server = undefined;
    var cli: quic.Client = undefined;
    try faultPair(allocator, &driver, &srv, &cli);
    defer srv.deinit();
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, "whole request");
    try cli.conn.streamFinish(stream.id);

    var end_errors: u32 = 0;
    var iters: u32 = 0;
    while (iters < 4_000 and app.ends == 0) : (iters += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        driver.service(&srv) catch |err| {
            try std.testing.expectEqual(error.AppStop, err);
            end_errors += 1;
        };
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expectEqual(@as(u32, 1), app.ends);
    try std.testing.expectEqual(@as(u32, 1), end_errors);

    // Despite the error, the entry was released: the teardown sweep
    // must NOT deliver a second end (which would double-deinit state
    // under the canonical `defer e.state.deinit` pattern).
    try closeAndReapFD(&cli, &srv, &driver, &rx, &now_us);
    try std.testing.expectEqual(@as(u32, 1), app.ends);
    try std.testing.expectEqual(@as(u32, 1), app.disconnects);
}

fn closeAndReapFD(
    cli: *quic.Client,
    srv: *quic.Server,
    driver: *FD,
    rx: []u8,
    now_us: *u64,
) !void {
    cli.conn.close(false, 0, "done");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(cli, srv, rx, now_us.*);
        try driver.service(srv);
        try pumpServerToClient(srv, cli, rx, now_us.*);
        now_us.* += 10_000;
        try srv.tick(now_us.*);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}

const MuteApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;
};

const MD = quic.app.Driver(MuteApp);

test "Driver: with no stream hooks, peer streams are refused loudly, not black-holed" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: MuteApp = .{};
    var driver = try MD.init(.{
        .allocator = allocator,
        .app = &app,
        // No hooks at all: a datagram-/event-only posture. Streams
        // cannot be serviced, so they must be refused on the wire.
    });
    defer driver.deinit();

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = MD.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    const s = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(s.id, "anyone home?");
    try cli.conn.streamFinish(s.id);

    var iters: u32 = 0;
    while (iters < 5_000) : (iters += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.stream(s.id)) |cs| {
            if (cs.send.state == .reset_sent or cs.send.state == .reset_recvd) break;
        }
        now_us += 1_000;
    }
    const cs = cli.conn.stream(s.id) orelse return error.RefusedStreamMissing;
    try std.testing.expect(cs.send.reset != null);

    cli.conn.close(false, 0, "done");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        now_us += 10_000;
        try srv.tick(now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}

// -- Undersized DATAGRAM delivery buffer -----------------------------------

const DgApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;
    fn onDatagram(_: *DgApp, _: *GD.Session, _: []const u8) anyerror!void {}
};

const GD = quic.app.Driver(DgApp);

test "Driver: undersized datagram_buf_bytes fails loudly with DatagramBufferTooSmall" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: DgApp = .{};
    var driver = try GD.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{ .on_datagram = DgApp.onDatagram },
        // Deliberately smaller than the peer's datagram below: the
        // service pass must error instead of silently dropping the tail.
        .datagram_buf_bytes = 8,
    });
    defer driver.deinit();

    var params = common.defaultParams();
    params.max_datagram_frame_size = 1200;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .on_connection_will_close = GD.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = params,
    });
    defer cli.deinit();

    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;

    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        while (srv.drainStatelessResponse()) |_| {}
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and
            srv.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    try cli.conn.sendDatagram("sixteen-plus-byte payload");
    try pumpClientToServer(&cli, &srv, &rx, now_us);
    try std.testing.expectError(error.DatagramBufferTooSmall, driver.service(&srv));

    // The oversized datagram was popped with the error; the connection
    // is otherwise healthy — teardown drains normally.
    cli.conn.close(false, 0, "done");
    var td: u32 = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try pumpClientToServer(&cli, &srv, &rx, now_us);
        try driver.service(&srv);
        try pumpServerToClient(&srv, &cli, &rx, now_us);
        now_us += 10_000;
        try srv.tick(now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}
