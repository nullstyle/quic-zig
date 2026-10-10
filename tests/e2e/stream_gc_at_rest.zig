//! Pin for the 0.37.2 repair: a connection at rest still reclaims its
//! ended streams.
//!
//! The defect (found by capnp-zig on its move to v0.37.1, 2026-10-08):
//! since 0.36.0 a connection at rest answers `tick` from its cached
//! deadline, and `atRest` did not look at the stream table. A stream
//! whose halves had ended (the ACK of our FIN; the peer's FIN or
//! RESET_STREAM received; a stop) was work for the next `tick`, the
//! one that reclaims it, gives its id back to the peer and records its
//! end for `streamRecvEnd`, and that `tick` never ran: in a Debug
//! build the self-check asserted (`tickFull` reclaimed the stream and
//! touched); in a release build the stream stayed until something
//! else touched the connection, and a sender ran out of stream ids
//! (capnp-zig: two transfers of 10,240 frames stopped at 10,185 and
//! 10,177, both sides at rest). The order that hits it is the natural
//! one: feed, drain, tick.
//!
//! Pinned here, at the public wrappers (`quic.Server` + `quic.Client`,
//! in memory, real TLS): a client uni stream sent and finished in one
//! datagram, the server's ACK back, both sides drained to rest, then
//! one `tick` with no time passed reclaims the stream on both sides;
//! the same for a stream the server stopped; and a host on the ready
//! API sees that connection due at once.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe2), .port = 7 } };

fn c2s(cli: *quic.Client, srv: *quic.Server, now_us: u64) !void {
    var rx: [4096]u8 = undefined;
    while (try cli.conn.poll(&rx, now_us)) |len| _ = try srv.feed(rx[0..len], addr, now_us);
}

fn s2c(srv: *quic.Server, cli: *quic.Client, now_us: u64) !void {
    var rx: [4096]u8 = undefined;
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(&rx, now_us)) |len| try cli.conn.handle(rx[0..len], null, now_us);
    }
}

fn handshake(srv: *quic.Server, cli: *quic.Client, now_us: *u64) !void {
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try c2s(cli, srv, now_us.*);
        try s2c(srv, cli, now_us.*);
        try srv.tick(now_us.*);
        try cli.conn.tick(now_us.*);
        now_us.* += 1_000;
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and srv.iterator()[0].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
}

/// Both sides exchange what they owe and tick until nothing moves,
/// with time passing (the handshake's tail: HANDSHAKE_DONE, its ACK,
/// the delayed ACKs).
fn settle(srv: *quic.Server, cli: *quic.Client, now_us: *u64) !void {
    var step: u32 = 0;
    while (step < 8) : (step += 1) {
        try c2s(cli, srv, now_us.*);
        try s2c(srv, cli, now_us.*);
        try srv.tick(now_us.*);
        try cli.conn.tick(now_us.*);
        now_us.* += 30_000;
    }
}

fn serverInit() !quic.Server {
    return quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

fn clientConnect() !quic.Client {
    return quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

test "a stream ended on both sides is reclaimed by the next tick of a connection at rest (feed, drain, tick)" {
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    try settle(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    // A client uni stream: "abc" and the FIN in one datagram.
    const id: u64 = 2;
    _ = try cli.conn.openUni(id);
    _ = try cli.conn.streamWrite(id, "abc");
    try cli.conn.streamFinish(id);
    // Feed: the server gets the data and the FIN (its receive half has
    // ended, nobody read it: that is the GC's work), and answers a lone
    // packet with its ACK at once; the client gets the ACK (its send
    // half has ended).
    try c2s(&cli, &srv, now_us);
    try s2c(&srv, &cli, now_us);
    // The server reads to the FIN (a stream with unread bytes is not
    // reclaimable: the application may still read them).
    var buf: [8]u8 = undefined;
    const r = try sconn.streamReadFin(id, &buf);
    try std.testing.expectEqual(@as(usize, 3), r.n);
    try std.testing.expect(r.fin);
    // Drain (the read may have queued stream credit, and that gets its
    // ACK): nothing more to send on either side; both come to rest.
    try c2s(&cli, &srv, now_us);
    try s2c(&srv, &cli, now_us);
    try c2s(&cli, &srv, now_us);
    try s2c(&srv, &cli, now_us);
    try std.testing.expect(sconn.stream(id) != null);
    try std.testing.expect(cli.conn.stream(id) != null);
    // The ended stream keeps the connection from resting until the
    // tick that reclaims it: its deadline is now, on both sides.
    try std.testing.expect(!sconn.atRest());
    try std.testing.expect(!cli.conn.atRest());
    const sd = sconn.nextTimerDeadline(now_us) orelse return error.NoDeadline;
    try std.testing.expect(sd.at_us <= now_us);
    const cd = cli.conn.nextTimerDeadline(now_us) orelse return error.NoDeadline;
    try std.testing.expect(cd.at_us <= now_us);

    // Tick, no time passed: reclaimed on both sides; the server gives
    // the id back (a uni stream credit) and keeps the end for
    // `streamRecvEnd`.
    try srv.tick(now_us);
    try cli.conn.tick(now_us);
    try std.testing.expect(sconn.stream(id) == null);
    try std.testing.expect(cli.conn.stream(id) == null);
    try std.testing.expect(sconn.streamRecvWasReaped(id));
    const end = sconn.streamRecvEnd(id) orelse return error.NoEnd;
    try std.testing.expect(end.isClean());
    try std.testing.expectEqual(@as(u64, 3), end.final_size);
    // The GC gave the id back: a MAX_STREAMS to send, then its ACK;
    // after that both are at rest, with a real deadline ahead.
    try s2c(&srv, &cli, now_us);
    try c2s(&cli, &srv, now_us);
    try std.testing.expect(sconn.atRest());
    try std.testing.expect(cli.conn.atRest());
}

test "a stream the application stopped is reclaimed by the next tick of a connection at rest" {
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    try settle(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    // A client uni stream with data but no FIN; the server stops it.
    const id: u64 = 2;
    _ = try cli.conn.openUni(id);
    _ = try cli.conn.streamWrite(id, "abc");
    try c2s(&cli, &srv, now_us);
    try sconn.streamStopSending(id, 9);
    // The STOP_SENDING goes out; the client resets the stream; the
    // RESET_STREAM comes back; both acknowledge.
    try settle(&srv, &cli, &now_us);
    try std.testing.expect(sconn.stream(id) == null);
    try std.testing.expect(cli.conn.stream(id) == null);
    try std.testing.expect(sconn.atRest());
    try std.testing.expect(cli.conn.atRest());
}

test "tick reclaims an ended stream while unrelated stream work keeps the connection busy" {
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    try settle(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    // A live bidi request beside a uni stream that ends on both sides.
    _ = try cli.conn.openBidi(0);
    _ = try cli.conn.streamWrite(0, "request");
    _ = try cli.conn.openUni(2);
    _ = try cli.conn.streamWrite(2, "abc");
    try cli.conn.streamFinish(2);
    try c2s(&cli, &srv, now_us);
    try s2c(&srv, &cli, now_us);
    var buf: [8]u8 = undefined;
    const r = try sconn.streamReadFin(2, &buf);
    try std.testing.expectEqual(@as(usize, 3), r.n);
    try std.testing.expect(r.fin);
    try std.testing.expect(sconn.streams_gc_pending);
    try std.testing.expect(cli.conn.streams_gc_pending);

    // Neither endpoint can use the rest shortcut. The ordinary tick
    // must still reclaim the ended stream, and keep the unrelated one.
    _ = try sconn.streamWrite(0, "reply pending");
    cli.conn.requestPing();
    try srv.tick(now_us);
    try cli.conn.tick(now_us);
    try std.testing.expect(sconn.stream(2) == null);
    try std.testing.expect(cli.conn.stream(2) == null);
    try std.testing.expect(sconn.stream(0) != null);
    try std.testing.expect(cli.conn.stream(0) != null);
    try std.testing.expect(sconn.stream(0).?.send.hasPendingChunk());
    try std.testing.expect(!sconn.streams_gc_pending);
    try std.testing.expect(!cli.conn.streams_gc_pending);
    try std.testing.expectEqual(sconn.bytes_resident, sconn.residentBytesSum());
    try std.testing.expectEqual(cli.conn.bytes_resident, cli.conn.residentBytesSum());
}
