//! CONNECTION_CLOSE during the handshake (RFC 9000 section 10.2.3).
//!
//! An endpoint that gives a handshake up says why, in a
//! CONNECTION_CLOSE frame. The peer can read the frame only in a
//! packet that it has the keys for, and during the handshake the two
//! ends do not have the same keys at the same time:
//!
//!   - a server has 1-RTT WRITE keys as soon as it has built its
//!     flight, and the client has the matching read keys only when it
//!     has the whole flight;
//!   - a client that has sent a Handshake packet has no Initial keys;
//!   - a server has 1-RTT READ keys only when it has the client's
//!     Finished.
//!
//! So the close goes into one datagram with a packet for each level
//! the sender has keys for ("a server SHOULD send a CONNECTION_CLOSE
//! frame in both Handshake and Initial packets", "an endpoint SHOULD
//! send a CONNECTION_CLOSE frame in both Handshake and 1-RTT
//! packets"). Until v0.26.0 it went at one level only, and with 1-RTT
//! write keys that level was 1-RTT: a peer in the middle of the
//! handshake could not read it, learned no error code, and waited for
//! its own timeout (10 to 30 s).
//!
//! Each test here puts the two ends into one handshake phase, has one
//! end close, delivers what that end sends, and asks the other end
//! what it knows.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// A certificate chain that makes the server's flight three
/// datagrams long (the same one `handshake_loss.zig` uses).
const wide_cert_pem = @embedFile("../data/test_cert_wide.pem");
const wide_key_pem = @embedFile("../data/test_key_wide_cert.pem");

const CloseSource = quic.conn.lifecycle.CloseSource;
const CloseErrorSpace = quic.conn.lifecycle.CloseErrorSpace;

const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = .{ 192, 0, 2, 9 }, .port = 4433 } };

const connection_refused: u64 = 0x02;
const protocol_violation: u64 = 0x0a;
const application_error: u64 = 0x0c;

/// The packets of one datagram, by kind, read from the headers.
const Kinds = struct {
    initial: usize = 0,
    handshake: usize = 0,
    short: usize = 0,

    fn of(datagram: []const u8) Kinds {
        var out: Kinds = .{};
        var pos: usize = 0;
        while (pos < datagram.len) {
            const first = datagram[pos];
            if ((first & 0x80) == 0) {
                out.short += 1;
                break;
            }
            const typ = (first & 0x30) >> 4;
            if (typ == 0) out.initial += 1;
            if (typ == 2) out.handshake += 1;
            var i = pos + 5;
            if (i >= datagram.len) break;
            i += 1 + @as(usize, datagram[i]);
            if (i >= datagram.len) break;
            i += 1 + @as(usize, datagram[i]);
            if (typ == 0) {
                const token_len = readVarint(datagram, &i) orelse break;
                i += @intCast(token_len);
            }
            const payload_len = readVarint(datagram, &i) orelse break;
            pos = i + @as(usize, @intCast(payload_len));
        }
        return out;
    }
};

fn readVarint(buf: []const u8, i: *usize) ?u64 {
    if (i.* >= buf.len) return null;
    const b0 = buf[i.*];
    const len: usize = @as(usize, 1) << @intCast(b0 >> 6);
    if (i.* + len > buf.len) return null;
    var v: u64 = b0 & 0x3f;
    for (1..len) |k| v = (v << 8) | buf[i.* + k];
    i.* += len;
    return v;
}

const Pair = struct {
    srv: *quic.Server,
    cli: *quic.Client,
    now_us: u64 = 1_000,
    buf: [4096]u8 = undefined,
    /// The last datagram each end sent: its length and its packets
    /// (and for the client the bytes as they were before the server
    /// opened them in place).
    last_client_len: usize = 0,
    last_client: Kinds = .{},
    last_client_bytes: [4096]u8 = undefined,
    last_server_len: usize = 0,
    last_server: Kinds = .{},

    /// The client sends all it has. The datagrams go to the server,
    /// or are lost. Returns how many there were.
    fn clientSends(self: *Pair, deliver: bool) !usize {
        var n: usize = 0;
        while (try self.cli.conn.poll(&self.buf, self.now_us)) |len| {
            n += 1;
            self.last_client_len = len;
            self.last_client = Kinds.of(self.buf[0..len]);
            @memcpy(self.last_client_bytes[0..len], self.buf[0..len]);
            if (deliver) _ = try self.srv.feed(self.buf[0..len], addr, self.now_us);
        }
        return n;
    }

    /// The server sends all it has. The first `deliver` datagrams go
    /// to the client, the rest is lost. Returns how many there were.
    fn serverSends(self: *Pair, deliver: usize) !usize {
        var n: usize = 0;
        for (self.srv.iterator()) |slot| {
            while (try slot.conn.poll(&self.buf, self.now_us)) |len| {
                n += 1;
                self.last_server_len = len;
                self.last_server = Kinds.of(self.buf[0..len]);
                if (n <= deliver) try self.cli.conn.handle(self.buf[0..len], null, self.now_us);
            }
        }
        return n;
    }

    fn serverConn(self: *Pair) *quic.conn.Connection {
        return self.srv.iterator()[0].conn;
    }

    /// Both ends run their timers at a later time.
    fn later(self: *Pair, us: u64) !void {
        self.now_us += us;
        try self.srv.tick(self.now_us);
        try self.cli.conn.tick(self.now_us);
    }
};

const everything: usize = std.math.maxInt(usize);

fn initServer(cert: enum { small, wide }, reveal_reason: bool) !quic.Server {
    return try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = if (cert == .wide) wide_cert_pem else common.test_cert_pem,
        .tls_key_pem = if (cert == .wide) wide_key_pem else common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .reveal_close_reason_on_wire = reveal_reason,
    });
}

fn initClient(reveal_reason: bool) !quic.Client {
    return try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test cert
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .reveal_close_reason_on_wire = reveal_reason,
    });
}

test "handshake close: a server closes and the client has nothing from it yet: the close is in an Initial packet too" {
    var srv = try initServer(.small, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    try std.testing.expectEqual(@as(usize, 1), try pair.clientSends(true));
    // The whole flight is lost.
    try std.testing.expect(try pair.serverSends(0) >= 1);
    try std.testing.expect(!cli.conn.handshakeDone());

    pair.serverConn().close(true, connection_refused, "no");
    // One datagram, with the close at each level the server has keys
    // for. The client has Initial keys only.
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(everything));
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.initial);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.short);

    const ev = cli.conn.closeEvent() orelse return error.ClientDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(connection_refused, ev.error_code);
}

test "handshake close: a server closes and the client has part of the flight and no Initial keys: the close is in a Handshake packet too" {
    var srv = try initServer(.wide, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    _ = try pair.clientSends(true);
    // The first datagram of the flight arrives (the ServerHello and
    // the start of the Handshake data), the rest is lost.
    try std.testing.expect(try pair.serverSends(1) >= 2);
    // The client acknowledges in a Handshake packet, and with that it
    // gives its Initial keys up (RFC 9001 4.9.1).
    try std.testing.expect(try pair.clientSends(true) >= 1);
    try std.testing.expect(cli.conn.initial_keys_discarded);
    try std.testing.expect(!cli.conn.handshakeDone());
    _ = try pair.serverSends(0);

    pair.serverConn().close(true, connection_refused, "no");
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(everything));
    // The server has no Initial keys either by now (it read a
    // Handshake packet of the client).
    try std.testing.expectEqual(@as(usize, 0), pair.last_server.initial);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.short);

    const ev = cli.conn.closeEvent() orelse return error.ClientDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(connection_refused, ev.error_code);
}

test "handshake close: a client closes and the server does not have its Finished: the close is in a Handshake packet too" {
    var srv = try initServer(.small, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    _ = try pair.clientSends(true);
    _ = try pair.serverSends(everything);
    // The client has the whole flight: its handshake is done, and it
    // has 1-RTT keys. Its Finished is lost, so the server has no
    // 1-RTT read keys.
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(try pair.clientSends(false) >= 1);
    try std.testing.expect(!pair.serverConn().handshakeDone());

    cli.conn.close(true, protocol_violation, "no");
    try std.testing.expectEqual(@as(usize, 1), try pair.clientSends(true));
    try std.testing.expectEqual(@as(usize, 0), pair.last_client.initial);
    try std.testing.expectEqual(@as(usize, 1), pair.last_client.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_client.short);

    const ev = pair.serverConn().closeEvent() orelse return error.ServerDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(protocol_violation, ev.error_code);
}

test "handshake close: an application close in a Handshake packet is APPLICATION_ERROR with no reason (RFC 9000 10.2.3)" {
    // "A CONNECTION_CLOSE of type 0x1d MUST be replaced by a
    // CONNECTION_CLOSE of type 0x1c when sending the frame in Initial
    // or Handshake packets. ... Endpoints MUST clear the value of the
    // Reason Phrase field and SHOULD use the APPLICATION_ERROR code".
    // Both ends are told to put close reasons on the wire here; the
    // reason of an application close must still not be in a packet
    // that is not 1-RTT.
    var srv = try initServer(.small, true);
    defer srv.deinit();
    var cli = try initClient(true);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    _ = try pair.clientSends(true);
    _ = try pair.serverSends(everything);
    try std.testing.expect(cli.conn.handshakeDone());
    _ = try pair.clientSends(false);
    try std.testing.expect(!pair.serverConn().handshakeDone());

    cli.conn.close(false, 0x100, "the application's own words");
    try std.testing.expectEqual(@as(usize, 1), try pair.clientSends(true));

    // The server reads the Handshake packet (it cannot read the
    // 1-RTT one): a transport close, the generic code, no reason.
    const ev = pair.serverConn().closeEvent() orelse return error.ServerDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(CloseErrorSpace.transport, ev.error_space);
    try std.testing.expectEqual(application_error, ev.error_code);
    try std.testing.expectEqualStrings("", ev.reason);
}

test "handshake close: the close that is sent again in the closing state is at every level too (RFC 9000 10.2.1)" {
    var srv = try initServer(.wide, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    _ = try pair.clientSends(true);
    _ = try pair.serverSends(1);
    _ = try pair.clientSends(true);
    try std.testing.expect(cli.conn.initial_keys_discarded);
    _ = try pair.serverSends(0);

    // The client's last datagram (a Handshake packet), kept: the test
    // gives it to the server again later, at times it picks.
    var kept: [4096]u8 = undefined;
    const kept_len = pair.last_client_len;
    @memcpy(kept[0..kept_len], pair.last_client_bytes[0..kept_len]);

    // The server closes, and the close itself is lost.
    const server = pair.serverConn();
    server.close(true, connection_refused, "no");
    const closed_at = pair.now_us;
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(0));
    try std.testing.expect(cli.conn.closeEvent() == null);

    // The server is in the closing state now, for three probe
    // timeouts. A packet of the client that arrives in that time is
    // answered with the close again, but not every packet (RFC 9000
    // 10.2.1: an endpoint SHOULD limit the rate). The rule in
    // `conn/lifecycle.zig`: the first packet after the close earns
    // the close again; the next repeat needs two more packets, then
    // four, and so on.
    //
    // Until v0.28.1 the rule was time: not before TWO probe timeouts
    // since the last close, so the window for the first repeat was
    // the last third of the closing state, and a peer that probes on
    // its own timer came into it only by luck (MEASURED here before
    // this test gave the packet by hand: probes at 100 to 9000 ms
    // after the close, no answer to any of them).
    const closing_ends = server.lifecycle.closing_deadline_us orelse return error.NotInClosingState;
    const third = (closing_ends - closed_at) / 3;
    try std.testing.expect(third > 0);

    // One probe timeout after the close, the client's first packet:
    // the close goes again, in a Handshake packet and in a 1-RTT
    // packet, as the first one did.
    pair.now_us = closed_at + third;
    var copy: [4096]u8 = undefined;
    @memcpy(copy[0..kept_len], kept[0..kept_len]);
    _ = try srv.feed(copy[0..kept_len], addr, pair.now_us);
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(everything));
    try std.testing.expectEqual(@as(usize, 0), pair.last_server.initial);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.short);

    const ev = cli.conn.closeEvent() orelse return error.ClientDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(connection_refused, ev.error_code);

    // The next repeat needs two packets: the first gets no answer,
    // the second does. (The client has the close by now; the server
    // cannot know that, and a peer that did not would still send.)
    pair.now_us = closed_at + third + third / 2;
    @memcpy(copy[0..kept_len], kept[0..kept_len]);
    _ = try srv.feed(copy[0..kept_len], addr, pair.now_us);
    try std.testing.expectEqual(@as(usize, 0), try pair.serverSends(everything));
    pair.now_us = closed_at + 2 * third;
    @memcpy(copy[0..kept_len], kept[0..kept_len]);
    _ = try srv.feed(copy[0..kept_len], addr, pair.now_us);
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(everything));
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.short);
}

test "handshake close: after the handshake is confirmed the close is one 1-RTT packet (the control)" {
    var srv = try initServer(.small, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    var step: usize = 0;
    while (step < 16 and !cli.conn.handshake_keys_discarded) : (step += 1) {
        _ = try pair.clientSends(true);
        _ = try pair.serverSends(everything);
        try pair.later(1_000);
    }
    try std.testing.expect(cli.conn.handshake_keys_discarded);
    try std.testing.expect(pair.serverConn().handshakeDone());
    _ = try pair.clientSends(true);
    _ = try pair.serverSends(everything);

    // An application close keeps its own code and space: nothing
    // makes a transport close of it here.
    pair.serverConn().close(false, 0x100, "bye");
    try std.testing.expectEqual(@as(usize, 1), try pair.serverSends(everything));
    try std.testing.expectEqual(@as(usize, 0), pair.last_server.initial);
    try std.testing.expectEqual(@as(usize, 0), pair.last_server.handshake);
    try std.testing.expectEqual(@as(usize, 1), pair.last_server.short);
    const ev = cli.conn.closeEvent() orelse return error.ClientDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseErrorSpace.application, ev.error_space);
    try std.testing.expectEqual(@as(u64, 0x100), ev.error_code);
}

test "handshake close: a client's close with an Initial packet is a 1200-byte datagram (RFC 9000 14.1)" {
    // The server drops a datagram that begins with an Initial packet
    // and is shorter than 1200 bytes, and the close with it.
    var srv = try initServer(.small, false);
    defer srv.deinit();
    var cli = try initClient(false);
    defer cli.deinit();
    var pair: Pair = .{ .srv = &srv, .cli = &cli };

    try cli.conn.advance();
    _ = try pair.clientSends(true);
    try std.testing.expect(try pair.serverSends(0) >= 1);

    // The client has Initial keys only.
    cli.conn.close(true, protocol_violation, "no");
    try std.testing.expectEqual(@as(usize, 1), try pair.clientSends(true));
    try std.testing.expectEqual(@as(usize, 1), pair.last_client.initial);
    try std.testing.expectEqual(@as(usize, 1200), pair.last_client_len);

    const ev = pair.serverConn().closeEvent() orelse return error.ServerDidNotLearnOfTheClose;
    try std.testing.expectEqual(CloseSource.peer, ev.source);
    try std.testing.expectEqual(protocol_violation, ev.error_code);
}
