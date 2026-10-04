//! The handshake when the network loses datagrams.
//!
//! MEASURED 2026-10-03 (quic-interop-runner `handshakecorruption`, a
//! quic-go client, 30% of the packets corrupted each way): the server
//! sent its flight at 0, 1, 3, 7 and 15 s. Between those times the
//! client asked again seven times (its ClientHello once more, then
//! PINGs), and the server answered each time with an ACK and nothing
//! else. The client gave up at 10 s. Four tries inside 10 s, each lost
//! with probability 0.3, is 0.8% of the connections, and 1 run in 3 of
//! a 50-connection test.
//!
//! Two rules of RFC 9002 are about this, and these tests hold both:
//!
//! - Section 6.2.3: a peer that sends handshake data again, or probes,
//!   did not get our flight. We send the unacknowledged CRYPTO data
//!   again at once, not at the next probe timeout.
//! - Section 6.2.2.1: a client that has nothing in flight, and whose
//!   handshake is not done, keeps probing. A server at its
//!   anti-amplification limit can send nothing until the client does.
//!
//! The tests drive a real `quic.Server` and `quic.Client` in memory,
//! one datagram at a time, with a clock that only the test moves.
//! Every assertion is about WHEN something goes out: a test that only
//! asks "did the handshake finish" passes on the slow path too.
//!
//! Every run also checks RFC 9000 section 8.1 from the outside: until
//! the server has validated the client's address, the bytes it sent
//! are at most 3 times the bytes it was given.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// The client's ALPN offer for a ClientHello of two Initial packets:
/// the real name and five names that only take room. A ClientHello
/// with a post-quantum key share is this large too (quic-go's is).
fn longName(comptime first: u8) *const [251]u8 {
    comptime {
        var name: [251]u8 = @splat('x');
        name[0] = first;
        const done = name;
        return &done;
    }
}
const split_hello_protos = [_][]const u8{ "hq-test", longName('a'), longName('b'), longName('c'), longName('d'), longName('e') };

/// Same wide certificate as initial_padding.zig: with it the server's
/// flight needs two datagrams.
const wide_cert_pem = @embedFile("../data/test_cert_wide.pem");
const wide_key_pem = @embedFile("../data/test_key_wide_cert.pem");

/// A certificate of 5.4 KB: the server's flight is more than three
/// 1200-byte datagrams, which is more than 3 times a 1200-byte
/// ClientHello. The server reaches its anti-amplification limit with a
/// part of the flight still to send.
const huge_cert_pem = @embedFile("../data/test_cert_huge.pem");
const huge_key_pem = @embedFile("../data/test_key_huge_cert.pem");

const Cert = enum { small, wide, huge };

/// A long-header packet from the server that is longer than this
/// carries CRYPTO data. An ACK alone or a PING alone is about 50
/// bytes, and the smallest packet with CRYPTO data (the ServerHello)
/// is about 140.
const crypto_packet_min_bytes: usize = 100;

const us_per_ms: u64 = 1_000;
const us_per_s: u64 = 1_000_000;

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

const Shape = struct {
    /// Some Initial or Handshake packet in the datagram is long enough
    /// to carry CRYPTO data.
    carries_crypto: bool = false,
    leads_with_initial: bool = false,
    leads_with_handshake: bool = false,
    /// The datagram holds a 1-RTT packet.
    has_short: bool = false,
};

/// What a datagram holds, read from the long headers only (nothing is
/// decrypted). A short header is always last.
fn shape(datagram: []const u8) Shape {
    var out: Shape = .{};
    var pos: usize = 0;
    while (pos < datagram.len) {
        const first = datagram[pos];
        if ((first & 0x80) == 0) {
            out.has_short = true;
            break;
        }
        const typ = (first & 0x30) >> 4;
        if (pos == 0 and typ == 0) out.leads_with_initial = true;
        if (pos == 0 and typ == 2) out.leads_with_handshake = true;
        var i = pos + 5;
        if (i >= datagram.len) break;
        const dcid_len = datagram[i];
        i += 1 + dcid_len;
        if (i >= datagram.len) break;
        const scid_len = datagram[i];
        i += 1 + scid_len;
        if (i >= datagram.len) break;
        if (typ == 0) {
            const token_len = readVarint(datagram, &i) orelse break;
            i += @intCast(token_len);
        }
        const payload_len = readVarint(datagram, &i) orelse break;
        const total = (i - pos) + @as(usize, @intCast(payload_len));
        if ((typ == 0 or typ == 2) and total > crypto_packet_min_bytes) out.carries_crypto = true;
        pos += total;
    }
    return out;
}

/// What the network does to a datagram.
const Verdict = enum { deliver, drop };

const Options = struct {
    cert: Cert = .small,
    /// Make the ClientHello larger than one Initial packet. The server
    /// then acknowledges the first packet before it has a flight to
    /// send, so the client gets an RTT sample from an ACK alone, and
    /// its retries come at the pace of the real round trip (not at the
    /// 1 s of a client that never heard anything).
    split_client_hello: bool = false,
    /// Drop this many of the server's datagrams that carry CRYPTO data
    /// (the flight and every copy of it), counted from the first.
    drop_server_flights: usize = 0,
    /// Drop every datagram of the server that carries CRYPTO data for
    /// this long from the start: an outage that begins just after the
    /// server's first ACK got through.
    no_flight_for_us: u64 = 0,
    /// Drop `count` datagrams of the client, from its `first`-th
    /// (the ClientHello is the first).
    drop_client: struct { first: usize = 0, count: usize = 0 } = .{},
    /// Drop `count` datagrams of the server, from its `first`-th.
    drop_server: struct { first: usize = 0, count: usize = 0 } = .{},
    /// The network delivers this datagram of the client twice (0 =
    /// none). The server answers the first copy before the second
    /// arrives.
    duplicate_client: usize = 0,
    /// Random loss toward the server and toward the client, in
    /// percent, and the seed. The network never drops more than
    /// `max_burst` datagrams in a row in one direction (the interop
    /// simulator's rule).
    loss_to_server: u8 = 0,
    loss_to_client: u8 = 0,
    max_burst: u8 = 3,
    seed: u64 = 0,
    /// Run until the client has CONFIRMED the handshake (it got
    /// HANDSHAKE_DONE and discarded its Handshake keys), not only until
    /// both ends have the TLS handshake done.
    until_confirmed: bool = false,
    /// Stop when this much virtual time has gone by.
    budget_us: u64 = 40 * us_per_s,
    verbose: bool = trace_every_run,
};

/// Set to true to print every datagram of every run (a debugging aid).
const trace_every_run = false;

const max_marks = 64;

const Outcome = struct {
    done: bool = false,
    /// Virtual time from the start at which both ends reported the
    /// handshake done.
    done_at_us: u64 = 0,
    /// Virtual time from the start at which the client confirmed the
    /// handshake (only with `until_confirmed`).
    confirmed: bool = false,
    confirmed_at_us: u64 = 0,
    /// Times (from the start) at which the server put a datagram with
    /// CRYPTO data on the wire, delivered or not.
    flight_us: [max_marks]u64 = @splat(0),
    flights: usize = 0,
    flights_dropped: usize = 0,
    /// Times (from the start) at which the client put a datagram on
    /// the wire, the ClientHello included.
    client_us: [max_marks]u64 = @splat(0),
    client_datagrams: usize = 0,
    client_dropped: usize = 0,
    /// Client datagrams that lead with an Initial packet (the
    /// ClientHello included), and with a Handshake packet.
    client_initials: usize = 0,
    client_handshakes: usize = 0,
    server_datagrams: usize = 0,
    /// How many times each end sent its unacknowledged CRYPTO data
    /// again on a cue from the peer (RFC 9002 section 6.2.3).
    server_early_copies: usize = 0,
    client_early_copies: usize = 0,
    /// How many times the server queued HANDSHAKE_DONE again because
    /// the client still sent Handshake packets.
    server_done_resends: usize = 0,
};

const Net = struct {
    o: Options,
    cli: *quic.Client,
    srv: *quic.Server,
    lb: *quic.testing.Loopback,
    start_us: u64,
    out: Outcome = .{},
    prng: std.Random.DefaultPrng,
    burst_to_server: u8 = 0,
    burst_to_client: u8 = 0,
    /// Bytes the server was given and bytes it sent while the client's
    /// address was not validated.
    server_bytes_in: u64 = 0,
    server_bytes_out: u64 = 0,

    fn sinceStart(self: *const Net) u64 {
        return self.lb.now_us - self.start_us;
    }

    fn randomLoss(self: *Net, percent: u8, burst: *u8) bool {
        if (percent == 0) return false;
        if (burst.* >= self.o.max_burst) {
            burst.* = 0;
            return false;
        }
        if (self.prng.random().uintLessThan(u8, 100) < percent) {
            burst.* += 1;
            return true;
        }
        burst.* = 0;
        return false;
    }

    fn serverDone(self: *Net) bool {
        return self.srv.iterator().len > 0 and self.srv.iterator()[0].conn.handshakeDone();
    }

    fn serverValidated(self: *Net) bool {
        if (self.srv.iterator().len == 0) return false;
        const stats = self.srv.iterator()[0].conn.pathStats(0) orelse return false;
        return stats.validated;
    }

    /// One datagram from the client: count it, and give it to the
    /// server unless the network drops it.
    fn fromClient(self: *Net, datagram: []u8) anyerror!void {
        const s = shape(datagram);
        if (self.out.client_datagrams < max_marks) self.out.client_us[self.out.client_datagrams] = self.sinceStart();
        self.out.client_datagrams += 1;
        if (s.leads_with_initial) self.out.client_initials += 1;
        if (s.leads_with_handshake) self.out.client_handshakes += 1;
        var verdict: Verdict = .deliver;
        const index = self.out.client_datagrams;
        if (index >= self.o.drop_client.first and index < self.o.drop_client.first + self.o.drop_client.count) verdict = .drop;
        if (verdict == .deliver and self.randomLoss(self.o.loss_to_server, &self.burst_to_server)) verdict = .drop;
        if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us C->S #{d} {d}B initial={} handshake={} crypto={} short={} {t}\n", .{ self.sinceStart(), index, datagram.len, s.leads_with_initial, s.leads_with_handshake, s.carries_crypto, s.has_short, verdict });
        if (verdict == .drop) {
            self.out.client_dropped += 1;
            return;
        }
        if (!self.serverValidated()) self.server_bytes_in += datagram.len;
        if (index == self.o.duplicate_client) {
            // `feed` opens the packet in place, so keep a copy of the
            // datagram as it was on the wire.
            var copy: [4096]u8 = undefined;
            @memcpy(copy[0..datagram.len], datagram);
            _ = try self.srv.feed(datagram, quic.testing.loopback_addr, self.lb.now_us);
            _ = try self.serverSends();
            if (!self.serverValidated()) self.server_bytes_in += datagram.len;
            if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us C->S #{d} again (a duplicate)\n", .{ self.sinceStart(), index });
            _ = try self.srv.feed(copy[0..datagram.len], quic.testing.loopback_addr, self.lb.now_us);
            return;
        }
        _ = try self.srv.feed(datagram, quic.testing.loopback_addr, self.lb.now_us);
    }

    /// Everything the server has to send now, one datagram at a time.
    /// The client answers each one before it sees the next, and its
    /// answers go to the server at once (the server speaks again on
    /// the next call). Returns true if the server sent anything.
    fn serverSends(self: *Net) anyerror!bool {
        var held: [8][4096]u8 = undefined;
        var lens: [8]usize = undefined;
        var count: usize = 0;
        for (self.srv.iterator()) |slot| {
            while (count < held.len) {
                const validated_before = self.serverValidated();
                const len = (try slot.conn.poll(held[count][0..], self.lb.now_us)) orelse break;
                lens[count] = len;
                count += 1;
                if (!validated_before) {
                    // RFC 9000 section 8.1, checked from the outside.
                    self.server_bytes_out += len;
                    try std.testing.expect(self.server_bytes_out <= 3 * self.server_bytes_in);
                }
            }
        }
        while (self.srv.drainStatelessResponse()) |_| {}
        for (0..count) |i| {
            const datagram = held[i][0..lens[i]];
            const s = shape(datagram);
            self.out.server_datagrams += 1;
            var verdict: Verdict = .deliver;
            const server_index = self.out.server_datagrams;
            if (server_index >= self.o.drop_server.first and server_index < self.o.drop_server.first + self.o.drop_server.count) verdict = .drop;
            if (s.carries_crypto) {
                if (self.out.flights < max_marks) self.out.flight_us[self.out.flights] = self.sinceStart();
                self.out.flights += 1;
                if (self.out.flights_dropped < self.o.drop_server_flights) verdict = .drop;
                if (self.sinceStart() < self.o.no_flight_for_us) verdict = .drop;
            }
            if (verdict == .deliver and self.randomLoss(self.o.loss_to_client, &self.burst_to_client)) verdict = .drop;
            if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us S->C {d}B initial={} handshake={} crypto={} short={} {t}\n", .{ self.sinceStart(), datagram.len, s.leads_with_initial, s.leads_with_handshake, s.carries_crypto, s.has_short, verdict });
            if (verdict == .drop) {
                if (s.carries_crypto) self.out.flights_dropped += 1;
                continue;
            }
            try self.cli.conn.handle(datagram, null, self.lb.now_us);
            while (try self.cli.conn.poll(self.lb.rx, self.lb.now_us)) |len| {
                try self.fromClient(self.lb.rx[0..len]);
            }
        }
        return count > 0;
    }

    /// Both ends talk until neither has anything to send at this
    /// instant. The server answers a datagram of the client before it
    /// sees the next one: a real server reads one datagram, then
    /// sends. That order matters here. A ClientHello of two packets
    /// gets an ACK for the first packet before the flight exists.
    fn exchange(self: *Net) !void {
        while (true) {
            var any = false;
            while (try self.cli.conn.poll(self.lb.rx, self.lb.now_us)) |len| {
                any = true;
                try self.fromClient(self.lb.rx[0..len]);
                _ = try self.serverSends();
            }
            if (try self.serverSends()) any = true;
            if (!any) break;
        }
    }
};

/// One handshake over the network that `o` describes.
fn run(allocator: std.mem.Allocator, o: Options) !Outcome {
    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = switch (o.cert) {
            .small => common.test_cert_pem,
            .wide => wide_cert_pem,
            .huge => huge_cert_pem,
        },
        .tls_key_pem = switch (o.cert) {
            .small => common.test_key_pem,
            .wide => wide_key_pem,
            .huge => huge_key_pem,
        },
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = if (o.split_client_hello) &split_hello_protos else &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    var net: Net = .{
        .o = o,
        .cli = &cli,
        .srv = &srv,
        .lb = &lb,
        .start_us = lb.now_us,
        .prng = std.Random.DefaultPrng.init(o.seed),
    };

    try cli.conn.advance();
    while (net.sinceStart() < o.budget_us) {
        try net.exchange();
        if (!net.out.done and cli.conn.handshakeDone() and net.serverDone()) {
            net.out.done = true;
            net.out.done_at_us = net.sinceStart();
        }
        if (net.out.done and !o.until_confirmed) break;
        if (cli.conn.handshake_keys_discarded) {
            net.out.confirmed = true;
            net.out.confirmed_at_us = net.sinceStart();
            break;
        }
        // A connection that gave up (handshake timeout, idle timeout)
        // has nothing more to say; do not spin to the budget.
        if (cli.conn.closeState() != .open) break;
        try srv.tick(lb.now_us);
        try cli.conn.tick(lb.now_us);
        lb.now_us += us_per_ms;
    }
    if (srv.iterator().len > 0) {
        net.out.server_early_copies = srv.iterator()[0].conn.early_handshake_retransmits;
        net.out.server_done_resends = srv.iterator()[0].conn.early_handshake_done_resends;
    }
    net.out.client_early_copies = cli.conn.early_handshake_retransmits;
    if (o.verbose) std.debug.print("[handshake_loss] done={} at={d}us flights={d} dropped={d} client: {d} datagrams ({d} initial, {d} handshake, {d} dropped) server: {d} datagrams, {d} B out for {d} B in before validation\n", .{ net.out.done, net.out.done_at_us, net.out.flights, net.out.flights_dropped, net.out.client_datagrams, net.out.client_initials, net.out.client_handshakes, net.out.client_dropped, net.out.server_datagrams, net.server_bytes_out, net.server_bytes_in });
    return net.out;
}

test "handshake loss: with no loss, nothing is sent twice" {
    // The control. The rules under test must send nothing more when
    // nothing is lost.
    const small = try run(std.testing.allocator, .{});
    try std.testing.expect(small.done);
    try std.testing.expectEqual(@as(usize, 1), small.flights);
    try std.testing.expect(small.done_at_us < 100 * us_per_ms);
    // One Initial from the client that is not an answer: the
    // ClientHello. No probe.
    try std.testing.expect(small.client_initials <= 2);
    // Nobody took a packet for a retry. The client's Finished is an
    // ack-eliciting Handshake packet that arrives while the server's
    // ServerHello is still unacknowledged (the client never
    // acknowledges it when the whole flight is one datagram): it
    // brings NEW CRYPTO data, so it is progress, not a retry.
    try std.testing.expectEqual(@as(usize, 0), small.server_early_copies);
    try std.testing.expectEqual(@as(usize, 0), small.client_early_copies);

    const wide = try run(std.testing.allocator, .{ .cert = .wide });
    try std.testing.expect(wide.done);
    try std.testing.expectEqual(@as(usize, 3), wide.flights);
    try std.testing.expect(wide.done_at_us < 100 * us_per_ms);
    try std.testing.expectEqual(@as(usize, 0), wide.server_early_copies);
    try std.testing.expectEqual(@as(usize, 0), wide.client_early_copies);

    const huge = try run(std.testing.allocator, .{ .cert = .huge });
    try std.testing.expect(huge.done);
    try std.testing.expectEqual(@as(usize, 6), huge.flights);
    try std.testing.expect(huge.done_at_us < 100 * us_per_ms);
    try std.testing.expectEqual(@as(usize, 0), huge.server_early_copies);
    try std.testing.expectEqual(@as(usize, 0), huge.client_early_copies);

    const split = try run(std.testing.allocator, .{ .split_client_hello = true });
    try std.testing.expect(split.done);
    try std.testing.expectEqual(@as(usize, 1), split.flights);
    try std.testing.expectEqual(@as(usize, 0), split.server_early_copies);
    try std.testing.expectEqual(@as(usize, 0), split.client_early_copies);

    // To the end of the handshake: the client has HANDSHAKE_DONE at
    // once, and the server sent it once.
    for ([_]Cert{ .small, .wide, .huge }) |cert| {
        const out = try run(std.testing.allocator, .{ .cert = cert, .until_confirmed = true });
        try std.testing.expect(out.confirmed);
        try std.testing.expect(out.confirmed_at_us < 100 * us_per_ms);
        try std.testing.expectEqual(@as(usize, 0), out.server_done_resends);
    }
}

test "handshake loss: the flight is lost 5 times, and each retry of the client brings a copy (RFC 9002 6.2.3)" {
    // The server has no RTT sample (nothing it sent was acknowledged),
    // so its probe timeout is about 1 s and then doubles: on its own
    // timer the copies go out at 1, 3, 7 and 15 s. The client retries
    // long before that (it has an RTT sample from the ACK of its first
    // packet), and each retry is the cue.
    //
    // MEASURED 2026-10-03 on the code before the rule: the server
    // answered the client's retry with an ACK alone, the client then
    // had nothing in flight and was silent, and the copies went out at
    // 1, 3 and 7 s; the server gave up at its 10 s handshake timeout.
    const out = try run(std.testing.allocator, .{ .split_client_hello = true, .drop_server_flights = 5 });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 5), out.flights_dropped);
    try std.testing.expectEqual(@as(usize, 6), out.flights);
    // WHEN: all six copies left inside 100 ms, long before the
    // server's first probe timeout.
    try std.testing.expect(out.flight_us[5] < 100 * us_per_ms);
    try std.testing.expect(out.done_at_us < 100 * us_per_ms);
    try std.testing.expectEqual(@as(usize, 5), out.server_early_copies);
}

test "handshake loss: an outage of 100 ms toward the client costs the client's next retry, not a second" {
    // A short outage is what a real network does (the interop
    // simulator never loses more than 3 datagrams in a row). The
    // client's retries come at 2, 5, 10, 19, 36, 69 and 134 ms: each
    // twice as late as the one before. The first six are inside the
    // outage. The limit on early copies must be large enough that the
    // seventh still gets one. MEASURED 2026-10-03: done at 134 ms with
    // a limit of 8, and at 1019 ms (the server's probe timeout) with a
    // limit of 4.
    const out = try run(std.testing.allocator, .{ .split_client_hello = true, .no_flight_for_us = 100 * us_per_ms });
    try std.testing.expect(out.done);
    try std.testing.expect(out.done_at_us < 200 * us_per_ms);
}

test "handshake loss: the limit on early copies holds, and the probe timer works behind it" {
    // The flight is lost 9 times: the first copy and the 8 early ones
    // (`max_early_handshake_retransmits`). The server answers the
    // client's next retries with an ACK alone, and the tenth copy goes
    // out at the server's probe timeout, 1 s after the ninth.
    const out = try run(std.testing.allocator, .{ .split_client_hello = true, .drop_server_flights = 9 });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 9), out.flights_dropped);
    try std.testing.expectEqual(@as(usize, 10), out.flights);
    try std.testing.expect(out.flight_us[8] < 400 * us_per_ms);
    const wait_us = out.flight_us[9] - out.flight_us[8];
    try std.testing.expect(wait_us >= 900 * us_per_ms and wait_us <= 1100 * us_per_ms);
    // The client asked all that time. Its probes back off (RFC 9002
    // section 6.2.1: an ACK in an Initial packet does not reset a
    // client's backoff), so there are few of them: the two packets of
    // the ClientHello, 9 retries that got a copy or an ACK, and the
    // probes after that, each twice as late as the one before.
    try std.testing.expect(out.client_initials <= 14);
}

test "handshake loss: a datagram that the network delivers twice is not a retry" {
    // The control for the next line of the rule: the cue is a NEW
    // packet with old data. The same packet again (same packet number)
    // is the network's duplicate. It gets an ACK and no copy of the
    // flight; an attacker who replays one captured datagram gets
    // nothing more out of the server.
    const base = try run(std.testing.allocator, .{ .split_client_hello = true, .drop_server_flights = 2 });
    try std.testing.expect(base.done);
    try std.testing.expectEqual(@as(usize, 3), base.flights);
    // The client's third datagram is its first retry.
    const dup = try run(std.testing.allocator, .{ .split_client_hello = true, .drop_server_flights = 2, .duplicate_client = 3 });
    try std.testing.expect(dup.done);
    try std.testing.expectEqual(@as(usize, 3), dup.flights);
    // The duplicate changed nothing: the third copy of the flight left
    // at the client's NEXT retry, as it does without the duplicate.
    try std.testing.expect(dup.flight_us[2] > dup.flight_us[1]);
    try std.testing.expectEqual(base.flight_us[2], dup.flight_us[2]);
    try std.testing.expectEqual(base.done_at_us, dup.done_at_us);
    try std.testing.expectEqual(@as(usize, 2), dup.server_early_copies);
}

test "handshake loss: a probe in a Handshake packet is a cue too" {
    // The client gets the first datagram of the flight (the
    // ServerHello and the start of the certificate), so it has
    // Handshake keys. The second and third datagram are lost, and so
    // is the client's ACK. The server has no RTT sample: its probe
    // timeout is 1 s. The client has nothing in flight, so it probes
    // (RFC 9002 section 6.2.2.1), in a Handshake packet. That PING is
    // the cue: the rest of the flight comes at once.
    const out = try run(std.testing.allocator, .{
        .cert = .wide,
        .drop_server = .{ .first = 2, .count = 2 },
        .drop_client = .{ .first = 2, .count = 1 },
    });
    try std.testing.expect(out.done);
    try std.testing.expect(out.client_handshakes >= 1);
    try std.testing.expect(out.done_at_us < 100 * us_per_ms);
}

test "handshake loss: 4 datagrams of a three-datagram flight are lost, and the client's retries bring them again" {
    // Each datagram of the flight counts: 4 losses are the whole first
    // flight and the first datagram of the second.
    const out = try run(std.testing.allocator, .{ .cert = .wide, .split_client_hello = true, .drop_server_flights = 4 });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 4), out.flights_dropped);
    try std.testing.expect(out.done_at_us < 100 * us_per_ms);
}

test "handshake loss: a server at its anti-amplification limit, and a client whose ACKs were lost (RFC 9002 6.2.2.1)" {
    // The server may send 3600 bytes for the 1200-byte ClientHello:
    // three datagrams of a five-datagram flight. The client gets all
    // three and acknowledges them, and the network loses those three
    // ACK datagrams. Now the server may send nothing, and the client
    // has nothing in flight. If the client does not probe, nobody
    // sends again, and the handshake ends at its timeout.
    const out = try run(std.testing.allocator, .{
        .cert = .huge,
        .drop_client = .{ .first = 2, .count = 3 },
    });
    try std.testing.expectEqual(@as(usize, 3), out.client_dropped);
    try std.testing.expect(out.done);
    try std.testing.expect(out.done_at_us < 1 * us_per_s);
}

test "handshake loss: HANDSHAKE_DONE is lost 3 times, and each Finished of the client brings it again" {
    // The client's first Finished is lost, so the server completes the
    // handshake on the client's retry, with no RTT sample of its own
    // (nothing it sent was acknowledged in a packet it got). It sends
    // HANDSHAKE_DONE and discards its Handshake keys. That datagram is
    // lost, and the next two. The client goes on sending its Finished
    // (it has no other way to know); the server cannot open those
    // packets any more, but each one says "I do not have
    // HANDSHAKE_DONE".
    //
    // MEASURED 2026-10-03 on the code before the rule: the server
    // ignored them, and sent HANDSHAKE_DONE again at its own probe
    // timeout: confirmed at 1027 ms. With the rule: at 19 ms.
    const out = try run(std.testing.allocator, .{
        .drop_client = .{ .first = 2, .count = 1 },
        .drop_server = .{ .first = 2, .count = 3 },
        .until_confirmed = true,
    });
    try std.testing.expect(out.confirmed);
    try std.testing.expect(out.confirmed_at_us < 100 * us_per_ms);
    try std.testing.expectEqual(@as(usize, 3), out.server_done_resends);
}

test "handshake loss: the limit on HANDSHAKE_DONE resends holds, and the probe timer works behind it" {
    // Nothing of the server arrives for 600 ms after the handshake.
    // The client sends its Finished 9 times in that time; the server
    // answers 8 of them (`max_early_handshake_retransmits`), and then
    // its probe timer takes over.
    const out = try run(std.testing.allocator, .{
        .drop_client = .{ .first = 2, .count = 1 },
        .drop_server = .{ .first = 2, .count = 12 },
        .until_confirmed = true,
    });
    try std.testing.expect(out.confirmed);
    try std.testing.expectEqual(@as(usize, 8), out.server_done_resends);
    try std.testing.expect(out.confirmed_at_us > 900 * us_per_ms);
    try std.testing.expect(out.confirmed_at_us < 3 * us_per_s);
}

const SweepStats = struct {
    runs: usize,
    not_done: usize,
    /// Runs that took 900 ms or more: they waited for a probe timeout
    /// of an end that had no RTT sample (about 1 s).
    slow: usize,
    median_us: u64,
    p90_us: u64,
    worst_us: u64,
    worst_seed: u64,
};

/// `base` over `count` seeds, from seed 1. A run that is not done at
/// its budget counts as `not_done`, and as the budget in the times.
fn sweep(allocator: std.mem.Allocator, base: Options, comptime count: usize) !SweepStats {
    var times: [count]u64 = undefined;
    var stats: SweepStats = .{ .runs = count, .not_done = 0, .slow = 0, .median_us = 0, .p90_us = 0, .worst_us = 0, .worst_seed = 0 };
    for (0..count) |k| {
        var o = base;
        o.seed = k + 1;
        const out = try run(allocator, o);
        times[k] = if (out.done) out.done_at_us else o.budget_us;
        if (!out.done) {
            stats.not_done += 1;
            if (print_sweeps) std.debug.print("[handshake_loss] not done: seed {d} (flights {d}, dropped {d}, client datagrams {d}, dropped {d})\n", .{ o.seed, out.flights, out.flights_dropped, out.client_datagrams, out.client_dropped });
        }
        if (times[k] >= 900 * us_per_ms) stats.slow += 1;
        if (times[k] > stats.worst_us) {
            stats.worst_us = times[k];
            stats.worst_seed = o.seed;
        }
    }
    std.mem.sort(u64, &times, {}, std.sort.asc(u64));
    stats.median_us = times[count / 2];
    stats.p90_us = times[count * 9 / 10];
    if (print_sweeps) std.debug.print("[handshake_loss] sweep cert={t} split={} loss to server {d}% to client {d}% budget={d}ms: {d} runs, {d} not done, {d} slower than 900 ms, median {d} ms, p90 {d} ms, worst {d} ms (seed {d})\n", .{ base.cert, base.split_client_hello, base.loss_to_server, base.loss_to_client, base.budget_us / us_per_ms, count, stats.not_done, stats.slow, stats.median_us / us_per_ms, stats.p90_us / us_per_ms, stats.worst_us / us_per_ms, stats.worst_seed });
    return stats;
}

/// Set to true to print the numbers of every sweep (a measuring aid).
const print_sweeps = false;

test "handshake loss: 30% loss toward the client" {
    // Only the server's datagrams are lost, so every retry of the
    // client arrives. MEASURED 2026-10-03, these 300 seeds: on the
    // code before the two rules, 5 handshakes were not done at 10 s
    // and 90 took 900 ms or more (they waited for the server's probe
    // timeout). After: none not done, and 23 at 900 ms or more. Those
    // 23 lost the ACK of the first ClientHello packet too, so the
    // client had no RTT sample, and a client that never heard anything
    // waits 1 s (RFC 9002 section 6.2.2) whatever the server does.
    const stats = try sweep(std.testing.allocator, .{ .loss_to_client = 30, .budget_us = 10 * us_per_s, .split_client_hello = true }, 300);
    try std.testing.expectEqual(@as(usize, 0), stats.not_done);
    try std.testing.expect(stats.slow <= 30);
    try std.testing.expect(stats.p90_us < 100 * us_per_ms);
}

test "handshake loss: 30% loss each way" {
    // The interop test `handshakeloss` in small: 30% of the datagrams
    // lost in each direction, never more than 3 in a row, a 10 s
    // budget (what quic-go gives a handshake).
    //
    // This one is a guard, not a proof. MEASURED 2026-10-03, these 300
    // seeds, ClientHello of two packets: 7 not done and 126 at 900 ms
    // or more before the two rules, 4 and 79 after. What is left is
    // the client's own first second: when its ClientHello is lost and
    // it never heard anything, it tries again at 1, 3 and 7 s.
    const two = try sweep(std.testing.allocator, .{ .loss_to_server = 30, .loss_to_client = 30, .budget_us = 10 * us_per_s, .split_client_hello = true }, 300);
    try std.testing.expect(two.not_done <= 4);
    try std.testing.expect(two.slow <= 90);
}
