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
    /// Some packet in the datagram is a Handshake packet.
    has_handshake: bool = false,
    /// Some packet in the datagram has a long header (Initial, 0-RTT
    /// or Handshake).
    has_long: bool = false,
    /// The datagram holds a 1-RTT packet.
    has_short: bool = false,
};

/// RFC 9000 section 14: the size every QUIC path carries, the size a
/// datagram with an Initial packet must have, and the most an endpoint
/// may send before it has probed the path for more.
const min_path_datagram_len: usize = 1200;

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
        out.has_long = true;
        if (pos == 0 and typ == 0) out.leads_with_initial = true;
        if (pos == 0 and typ == 2) out.leads_with_handshake = true;
        if (typ == 2) out.has_handshake = true;
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
    /// Drop `count` datagrams of the server, from its `first`-th; or,
    /// with `until_us`, every one from the `first`-th until that time.
    drop_server: struct { first: usize = 0, count: usize = 0, until_us: u64 = 0 } = .{},
    /// The network delivers this datagram of the client twice (0 =
    /// none). The server answers the first copy before the second
    /// arrives.
    duplicate_client: usize = 0,
    /// The network delivers the server's second datagram before its
    /// first, once (reordering: the Handshake packets of the flight
    /// come before the ServerHello).
    swap_server_first_two: bool = false,
    /// The network damages the `index`-th datagram of the client, or
    /// of the server, and delivers it (0 = none).
    damage_client: Damage = .{},
    damage_server: Damage = .{},
    /// Random loss toward the server and toward the client, in
    /// percent, and the seed. The network never drops more than
    /// `max_burst` datagrams in a row in one direction (the interop
    /// simulator's rule).
    loss_to_server: u8 = 0,
    loss_to_client: u8 = 0,
    max_burst: u8 = 3,
    seed: u64 = 0,
    /// The server has 1-RTT data to send before the handshake is done
    /// ("0.5-RTT" data; the interop server's NEW_CONNECTION_ID is
    /// that): a PING, queued as soon as the server has the connection.
    server_early_data: bool = false,
    /// Run until the client has CONFIRMED the handshake (it got
    /// HANDSHAKE_DONE and discarded its Handshake keys), not only until
    /// both ends have the TLS handshake done.
    until_confirmed: bool = false,
    /// Stop when this much virtual time has gone by.
    budget_us: u64 = 40 * us_per_s,
    verbose: bool = trace_every_run,
};

/// One damaged datagram. `.flip` changes the byte at `offset` (the
/// interop simulator corrupts a datagram this way, in its first 51
/// bytes). `.cut` delivers only the first `offset` bytes (a receive
/// buffer that is too small does that). A datagram too short for the
/// damage is delivered as it is.
const Damage = struct {
    index: usize = 0,
    kind: enum { flip, cut } = .flip,
    offset: usize = 0,
    /// For `.flip`: the byte is XORed with this.
    flip: u8 = 0xff,

    /// The datagram as the receiver gets it, or null if this is not
    /// the datagram to damage.
    fn apply(self: Damage, index: usize, datagram: []u8) ?[]u8 {
        if (self.index == 0 or index != self.index) return null;
        if (self.offset >= datagram.len) return null;
        switch (self.kind) {
            .flip => {
                datagram[self.offset] ^= self.flip;
                return datagram;
            },
            .cut => return if (self.offset == 0) null else datagram[0..self.offset],
        }
    }
};

/// Set to true to print every datagram of every run (a debugging aid).
const trace_every_run = false;

/// Every run fails if a datagram breaks a size rule of RFC 9000
/// section 14 (see the end of `run`). False only to measure.
const check_datagram_sizes = true;

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
    /// Datagrams of the server that held a 1-RTT packet and nothing
    /// else, sent before the server's handshake was done. The client
    /// cannot open those: it has no 1-RTT keys yet.
    server_lone_1rtt_before_done: usize = 0,
    /// Datagrams of the server that lead with an Initial packet, sent
    /// after a datagram of the client with a Handshake packet was
    /// delivered to it.
    server_initials_after_client_handshake: usize = 0,
    /// Datagrams of the client that lead with an Initial packet, sent
    /// after a datagram of the client with a Handshake packet.
    client_initials_after_handshake: usize = 0,
    /// Datagrams that the network damaged and delivered.
    damaged: usize = 0,
    /// The client datagram (1 = the ClientHello) whose delivery made
    /// the server validate the client's address (0 = none did).
    validated_by_client_datagram: usize = 0,
    /// The server had no Initial keys just after it was given the
    /// damaged datagram of the client.
    server_initial_keys_gone_after_damage: bool = false,
    /// The server still has the connection, and it is open.
    server_open: bool = false,
    client_open: bool = false,
    /// The longest datagram of each end that holds a long-header
    /// packet (both ends poll with 4096-byte buffers, so nothing but
    /// the endpoint itself limits it).
    longest_client_handshake_datagram: usize = 0,
    longest_server_handshake_datagram: usize = 0,
    /// Datagrams with a long-header packet that are longer than 1200
    /// bytes (RFC 9000 section 14.2: not before the path is probed;
    /// and a probe is a 1-RTT packet alone in its datagram).
    oversized_handshake_datagrams: usize = 0,
    /// Datagrams of the client that hold an Initial packet and are
    /// shorter than 1200 bytes (RFC 9000 section 14.1: MUST NOT be).
    client_unexpanded_initials: usize = 0,
    /// Datagrams of the server that hold an ack-eliciting Initial
    /// packet and are shorter than 1200 bytes (section 14.1 too).
    server_unexpanded_initials: usize = 0,
    /// Datagrams of the server that hold an ack-eliciting Initial
    /// packet (the ServerHello and its copies, and probes).
    server_ack_eliciting_initials: usize = 0,
    /// Flight datagrams of the server, by length (the first eight).
    flight_len: [8]usize = @splat(0),
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
    server_early_data_queued: bool = false,
    /// A datagram of the client that holds a Handshake packet was
    /// delivered to the server.
    client_handshake_delivered: bool = false,
    /// The client sent a datagram that holds a Handshake packet.
    client_sent_handshake: bool = false,
    /// `Options.swap_server_first_two` was applied.
    swapped: bool = false,
    /// The client's first Destination Connection ID. The Initial keys
    /// of both directions come from it (RFC 9001 section 5.2), so the
    /// harness can open every Initial packet, as anyone on the path
    /// can.
    first_dcid: [20]u8 = @splat(0),
    first_dcid_len: usize = 0,

    fn sinceStart(self: *const Net) u64 {
        return self.lb.now_us - self.start_us;
    }

    /// Does the Initial packet at the front of this datagram ask for
    /// an acknowledgment? Null if the datagram does not lead with an
    /// Initial packet, or if the packet does not open.
    fn leadingInitialIsAckEliciting(self: *Net, datagram: []const u8, from_server: bool) ?bool {
        if (datagram.len < 7 or datagram.len > 4096) return null;
        if ((datagram[0] & 0x80) == 0 or ((datagram[0] & 0x30) >> 4) != 0) return null;
        if (self.first_dcid_len == 0) {
            if (from_server) return null;
            const n: usize = datagram[5];
            if (n > self.first_dcid.len or datagram.len < 6 + n) return null;
            @memcpy(self.first_dcid[0..n], datagram[6 .. 6 + n]);
            self.first_dcid_len = n;
        }
        const init_keys = quic.wire.initial.deriveInitialKeys(self.first_dcid[0..self.first_dcid_len], from_server) catch return null;
        var keys = quic.wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret) catch return null;
        defer keys.deinitAead();
        // The open removes the header protection in place: work on a
        // copy, the datagram itself goes to its receiver untouched.
        var copy: [4096]u8 = undefined;
        @memcpy(copy[0..datagram.len], datagram);
        var pt: [4096]u8 = undefined;
        const opened = quic.wire.long_packet.openInitial(&pt, copy[0..datagram.len], .{ .keys = &keys }) catch return null;
        var it = quic.frame.iter(opened.payload);
        var ack_eliciting = false;
        while (it.next() catch return null) |f| switch (f) {
            .padding, .ack, .connection_close => {},
            else => ack_eliciting = true,
        };
        return ack_eliciting;
    }

    /// RFC 9000 section 14, checked from the outside for one datagram
    /// as its sender made it (before the network touches it).
    fn checkSize(self: *Net, datagram: []const u8, s: Shape, from_server: bool) void {
        if (s.has_long) {
            const longest = if (from_server) &self.out.longest_server_handshake_datagram else &self.out.longest_client_handshake_datagram;
            longest.* = @max(longest.*, datagram.len);
            if (datagram.len > min_path_datagram_len) self.out.oversized_handshake_datagrams += 1;
        }
        if (!s.leads_with_initial) return;
        if (from_server) {
            if (self.leadingInitialIsAckEliciting(datagram, true) orelse false) {
                self.out.server_ack_eliciting_initials += 1;
                if (datagram.len < min_path_datagram_len) self.out.server_unexpanded_initials += 1;
            }
        } else {
            // Called for the side effect too: the first datagram of
            // the client gives the keys.
            _ = self.leadingInitialIsAckEliciting(datagram, false);
            if (datagram.len < min_path_datagram_len) self.out.client_unexpanded_initials += 1;
        }
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
        if (self.client_sent_handshake and s.leads_with_initial) self.out.client_initials_after_handshake += 1;
        if (s.has_handshake) self.client_sent_handshake = true;
        self.checkSize(datagram, s, false);
        var verdict: Verdict = .deliver;
        const index = self.out.client_datagrams;
        if (index >= self.o.drop_client.first and index < self.o.drop_client.first + self.o.drop_client.count) verdict = .drop;
        if (verdict == .deliver and self.randomLoss(self.o.loss_to_server, &self.burst_to_server)) verdict = .drop;
        if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us C->S #{d} {d}B initial={} handshake={} crypto={} short={} {t}\n", .{ self.sinceStart(), index, datagram.len, s.leads_with_initial, s.leads_with_handshake, s.carries_crypto, s.has_short, verdict });
        if (verdict == .drop) {
            self.out.client_dropped += 1;
            return;
        }
        var delivered = datagram;
        if (self.o.damage_client.apply(index, datagram)) |damaged| {
            delivered = damaged;
            self.out.damaged += 1;
            if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us C->S #{d} damaged ({t} at {d})\n", .{ self.sinceStart(), index, self.o.damage_client.kind, self.o.damage_client.offset });
        } else if (s.has_handshake) {
            self.client_handshake_delivered = true;
        }
        if (!self.serverValidated()) self.server_bytes_in += delivered.len;
        if (index == self.o.duplicate_client) {
            // `feed` opens the packet in place, so keep a copy of the
            // datagram as it was on the wire.
            var copy: [4096]u8 = undefined;
            @memcpy(copy[0..delivered.len], delivered);
            _ = try self.srv.feed(delivered, quic.testing.loopback_addr, self.lb.now_us);
            _ = try self.serverSends();
            if (!self.serverValidated()) self.server_bytes_in += delivered.len;
            if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us C->S #{d} again (a duplicate)\n", .{ self.sinceStart(), index });
            _ = try self.srv.feed(copy[0..delivered.len], quic.testing.loopback_addr, self.lb.now_us);
            return;
        }
        _ = try self.srv.feed(delivered, quic.testing.loopback_addr, self.lb.now_us);
        if (self.out.validated_by_client_datagram == 0 and self.serverValidated()) self.out.validated_by_client_datagram = index;
        if (index == self.o.damage_client.index and self.srv.iterator().len > 0) {
            self.out.server_initial_keys_gone_after_damage = self.srv.iterator()[0].conn.initial_keys_discarded;
        }
    }

    /// Everything the server has to send now, one datagram at a time.
    /// The client answers each one before it sees the next, and its
    /// answers go to the server at once (the server speaks again on
    /// the next call). Returns true if the server sent anything.
    fn serverSends(self: *Net) anyerror!bool {
        var held: [8][4096]u8 = undefined;
        var lens: [8]usize = undefined;
        var count: usize = 0;
        const done_before = self.serverDone();
        const handshake_seen_before = self.client_handshake_delivered;
        for (self.srv.iterator()) |slot| {
            if (self.o.server_early_data and !self.server_early_data_queued) {
                slot.conn.requestPing();
                self.server_early_data_queued = true;
            }
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
        if (self.o.swap_server_first_two and !self.swapped and count >= 2) {
            self.swapped = true;
            std.mem.swap([4096]u8, &held[0], &held[1]);
            std.mem.swap(usize, &lens[0], &lens[1]);
        }
        for (0..count) |i| {
            const datagram = held[i][0..lens[i]];
            const s = shape(datagram);
            self.out.server_datagrams += 1;
            if (!done_before and s.has_short and !s.leads_with_initial and !s.leads_with_handshake) {
                self.out.server_lone_1rtt_before_done += 1;
            }
            if (handshake_seen_before and s.leads_with_initial) {
                self.out.server_initials_after_client_handshake += 1;
            }
            self.checkSize(datagram, s, true);
            var verdict: Verdict = .deliver;
            const server_index = self.out.server_datagrams;
            if (server_index >= self.o.drop_server.first and server_index < self.o.drop_server.first + self.o.drop_server.count) verdict = .drop;
            if (self.o.drop_server.first != 0 and server_index >= self.o.drop_server.first and self.sinceStart() < self.o.drop_server.until_us) verdict = .drop;
            if (s.carries_crypto) {
                if (self.out.flights < max_marks) self.out.flight_us[self.out.flights] = self.sinceStart();
                if (self.out.flights < self.out.flight_len.len) self.out.flight_len[self.out.flights] = datagram.len;
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
            var delivered = datagram;
            if (self.o.damage_server.apply(server_index, datagram)) |damaged| {
                delivered = damaged;
                self.out.damaged += 1;
                if (self.o.verbose) std.debug.print("[handshake_loss] t={d}us S->C #{d} damaged ({t} at {d})\n", .{ self.sinceStart(), server_index, self.o.damage_server.kind, self.o.damage_server.offset });
            }
            try self.cli.conn.handle(delivered, null, self.lb.now_us);
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
    net.out.server_open = srv.iterator().len > 0 and srv.iterator()[0].conn.closeState() == .open;
    net.out.client_open = cli.conn.closeState() == .open;
    // RFC 9000 section 14, in every run of this file: whatever was
    // lost or damaged, no end may put a handshake datagram on the wire
    // that is longer than 1200 bytes, and a datagram with an Initial
    // packet that must be expanded is expanded.
    if (check_datagram_sizes and (net.out.oversized_handshake_datagrams != 0 or
        net.out.client_unexpanded_initials != 0 or
        net.out.server_unexpanded_initials != 0))
    {
        std.debug.print("[handshake_loss] datagram sizes: {d} with a long header are over 1200 B (longest: client {d}, server {d}); with an Initial packet and under 1200 B: client {d}, server {d} (of {d} ack-eliciting)\n", .{
            net.out.oversized_handshake_datagrams,
            net.out.longest_client_handshake_datagram,
            net.out.longest_server_handshake_datagram,
            net.out.client_unexpanded_initials,
            net.out.server_unexpanded_initials,
            net.out.server_ack_eliciting_initials,
        });
        return error.DatagramSizeRule;
    }
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

const print_datagram_sizes = false;

test "handshake loss: a handshake datagram is 1200 bytes at most, and exactly 1200 with an Initial packet that must be expanded (RFC 9000 14.1, 14.2)" {
    // Both ends poll with 4096-byte buffers here, so only the endpoint
    // limits what it sends.
    //
    // Until v0.26.0 each PACKET of a datagram was capped at 1200 on
    // its own. MEASURED then: the server's ServerHello + Handshake
    // datagram was 1310 bytes (wide certificate), the client's padded
    // Initial + Handshake ACK 1250, an ACK-only client Initial 1201;
    // and the server did not pad at all: with the small certificate
    // its whole flight was one datagram of 831 bytes.
    //
    // `run` checks the rules in every run of this file. This test
    // holds the numbers of the plain case.
    for ([_]Cert{ .small, .wide, .huge }) |cert| {
        const out = try run(std.testing.allocator, .{ .cert = cert, .until_confirmed = true });
        try std.testing.expect(out.confirmed);
        if (print_datagram_sizes) {
            std.debug.print("[handshake_loss] {t}: {d} flight datagrams {any}; longest with a long header: client {d}, server {d}; ack-eliciting server Initial datagrams: {d}\n", .{
                cert,                                  out.flights,                           out.flight_len[0..@min(out.flights, out.flight_len.len)],
                out.longest_client_handshake_datagram, out.longest_server_handshake_datagram, out.server_ack_eliciting_initials,
            });
        }
        try std.testing.expectEqual(@as(usize, 0), out.oversized_handshake_datagrams);
        try std.testing.expectEqual(@as(usize, 0), out.client_unexpanded_initials);
        try std.testing.expectEqual(@as(usize, 0), out.server_unexpanded_initials);
        // The ServerHello goes out in one datagram, and that one is
        // full: 14.1 gives the least and 14.2 the most.
        try std.testing.expectEqual(@as(usize, 1), out.server_ack_eliciting_initials);
        try std.testing.expectEqual(min_path_datagram_len, out.flight_len[0]);
        try std.testing.expectEqual(min_path_datagram_len, out.longest_server_handshake_datagram);
        try std.testing.expectEqual(min_path_datagram_len, out.longest_client_handshake_datagram);
    }

    // The same under loss: copies and probes obey the rules too.
    var seed: u64 = 1;
    while (seed <= 40) : (seed += 1) {
        const out = try run(std.testing.allocator, .{
            .cert = if (seed % 2 == 0) .wide else .small,
            .loss_to_server = 30,
            .loss_to_client = 30,
            .seed = seed,
            .until_confirmed = true,
        });
        try std.testing.expectEqual(@as(usize, 0), out.oversized_handshake_datagrams);
        try std.testing.expectEqual(@as(usize, 0), out.client_unexpanded_initials);
        try std.testing.expectEqual(@as(usize, 0), out.server_unexpanded_initials);
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

test "handshake loss: the client's probe timeout sends its ClientHello in two datagrams (RFC 9002 6.2.4)" {
    // The ClientHello is lost and nothing comes back: the client has
    // no RTT sample, so its first probe timeout is about 1 s. The
    // probe is two datagrams, not one, so that a network which loses
    // up to three datagrams in a row cannot hold the client off past
    // its second probe. MEASURED on the code before: one datagram at
    // 1, 3, 7 and 15 s, and a quic-go server that forgets the
    // connection after 5 s (interop `handshakeloss`, client role: 5
    // passes of 10).
    const out = try run(std.testing.allocator, .{ .drop_client = .{ .first = 1, .count = 1 } });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 1), out.client_dropped);
    // The probe: two datagrams at the same instant, about 1 s in.
    try std.testing.expect(out.client_datagrams >= 3);
    try std.testing.expect(out.client_us[1] >= 900 * us_per_ms);
    try std.testing.expect(out.client_us[1] < 1200 * us_per_ms);
    try std.testing.expectEqual(out.client_us[1], out.client_us[2]);
    try std.testing.expect(out.done_at_us < 1200 * us_per_ms);
}

test "handshake loss: a ClientHello lost eight times in a row is sent again every second, two datagrams each time" {
    // The probe timeout of a client with no RTT sample is about 1 s,
    // and the bound on the handshake backoff (`max_handshake_pto_us`)
    // keeps it there instead of 1, 2, 4, 8 s: with the first eight
    // datagrams lost (the ClientHello, then two per probe at 1, 2 and
    // 3 s, then the first of the probe at 4 s) the ninth gets through
    // at 4 s; with the doubling it was the probe at 8 s. MEASURED
    // 2026-10-06 with the bound alone (client x quiche x
    // handshakecorruption): the deadline ran from the oldest packet,
    // each expiry left the next-oldest past its deadline, and the
    // probes were 2, then 4, then 8 datagrams. The deadline runs from
    // the last packet sent now (RFC 9002 A.8): one expiry per second,
    // two datagrams each.
    const out = try run(std.testing.allocator, .{ .drop_client = .{ .first = 1, .count = 8 } });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 8), out.client_dropped);
    try std.testing.expect(out.client_datagrams >= 9);
    var k: usize = 1;
    while (k <= 7) : (k += 2) {
        const expected_us = @as(u64, (k + 1) / 2) * us_per_s;
        try std.testing.expect(out.client_us[k] >= expected_us - 100 * us_per_ms);
        try std.testing.expect(out.client_us[k] < expected_us + 200 * us_per_ms);
        try std.testing.expectEqual(out.client_us[k], out.client_us[k + 1]);
    }
    try std.testing.expect(out.done_at_us >= 4 * us_per_s - 100 * us_per_ms);
    try std.testing.expect(out.done_at_us < 4 * us_per_s + 500 * us_per_ms);
}

test "handshake loss: a Handshake packet that arrives before the ServerHello is kept and read when the ServerHello comes (RFC 9000 12.2)" {
    // A flight of three datagrams; the network delivers the second
    // (Handshake packets) before the first (the ServerHello). The
    // client has no Handshake keys yet when the second comes. It keeps
    // the packet, opens it when the ServerHello gives it the keys, and
    // the handshake is done with no copy of anything. Until v0.28.1
    // the packet was dropped, and the server sent it again after its
    // loss detection (one more flight, one more round trip).
    const out = try run(std.testing.allocator, .{ .cert = .wide, .swap_server_first_two = true });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 3), out.flights);
    try std.testing.expectEqual(@as(usize, 0), out.flights_dropped);
    try std.testing.expectEqual(@as(usize, 0), out.server_early_copies);
    try std.testing.expect(out.done_at_us < 100 * us_per_ms);
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
    // out at the server's probe timeout, 1 s after the ninth. The
    // server has no RTT sample (nothing it sent was acknowledged), so
    // that probe is two datagrams (RFC 9002 section 6.2.4): the tenth
    // and the eleventh copy leave together.
    const out = try run(std.testing.allocator, .{ .split_client_hello = true, .drop_server_flights = 9 });
    try std.testing.expect(out.done);
    try std.testing.expectEqual(@as(usize, 9), out.flights_dropped);
    try std.testing.expectEqual(@as(usize, 11), out.flights);
    try std.testing.expect(out.flight_us[8] < 400 * us_per_ms);
    const wait_us = out.flight_us[9] - out.flight_us[8];
    try std.testing.expect(wait_us >= 900 * us_per_ms and wait_us <= 1100 * us_per_ms);
    try std.testing.expectEqual(out.flight_us[9], out.flight_us[10]);
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
    // Nothing of the server arrives for 600 ms after its flight. The
    // client sends its Finished 9 times in that time; the server
    // answers 8 of them (`max_early_handshake_retransmits`), and then
    // its probe timer takes over.
    const out = try run(std.testing.allocator, .{
        .drop_client = .{ .first = 2, .count = 1 },
        .drop_server = .{ .first = 2, .until_us = 600 * us_per_ms },
        .until_confirmed = true,
    });
    try std.testing.expect(out.confirmed);
    try std.testing.expectEqual(@as(usize, 8), out.server_done_resends);
    try std.testing.expect(out.confirmed_at_us > 900 * us_per_ms);
    try std.testing.expect(out.confirmed_at_us < 3 * us_per_s);
}

test "handshake loss: the server does not probe its 1-RTT data while the handshake is not done (RFC 9002 6.2.1)" {
    // The server has 1-RTT data in flight from its first flight on (a
    // PING here; the interop server's NEW_CONNECTION_ID in the capture
    // this test comes from). The flight is lost 9 times, so the
    // handshake takes more than a second: long enough for a 1-RTT
    // probe timer to run out. It must not run. The client has no
    // 1-RTT keys, so it cannot open such a probe, and the probe is one
    // more datagram on a path that already loses them.
    //
    // MEASURED 2026-10-03 (quic-interop-runner `handshakecorruption`):
    // the network forwarded the 4th and the 8th datagram of the server
    // after 3 corrupted ones each time. Both were these probes, and
    // six copies of the flight around them were corrupted.
    const out = try run(std.testing.allocator, .{
        .split_client_hello = true,
        .drop_server_flights = 9,
        .server_early_data = true,
    });
    try std.testing.expect(out.done);
    try std.testing.expect(out.done_at_us > 1 * us_per_s);
    try std.testing.expectEqual(@as(usize, 0), out.server_lone_1rtt_before_done);
}

test "handshake loss: no Initial packet once an end has Handshake packets to go on (RFC 9001 4.9.1)" {
    // "A client MUST discard Initial keys when it first sends a
    // Handshake packet and a server MUST discard Initial keys when it
    // first successfully processes a Handshake packet. Endpoints MUST
    // NOT send Initial packets after this point."
    //
    // An Initial packet after that point is worse than useless. Each
    // end puts its Initial packet FIRST in a datagram, and a peer that
    // cannot open the first packet may drop the whole datagram, with
    // the Handshake packet behind it (quiche does).
    //
    // MEASURED 2026-10-03 (quic-interop-runner `handshakecorruption`,
    // a quiche client): the client's Finished was lost three times.
    // Its Handshake PINGs arrived, and the server answered each with
    // ServerHello + Handshake data + its Handshake ACK in one
    // datagram. quiche logged "dropped invalid packet" for each, never
    // saw the ACK, kept its 1 s probe timer with no RTT sample, and
    // gave up after 32 s.
    //
    // Here: the client gets the first datagram of a three-datagram
    // flight (so it has Handshake keys), the rest is lost, and so is
    // the client's answer. The client's Handshake PING is the first
    // Handshake packet the server reads. On the code before, the
    // server answered it with a datagram that began with the
    // ServerHello, and the client acknowledged that in an Initial
    // packet of its own.
    const out = try run(std.testing.allocator, .{
        .cert = .wide,
        .drop_server = .{ .first = 2, .count = 2 },
        .drop_client = .{ .first = 2, .count = 1 },
        .until_confirmed = true,
    });
    try std.testing.expect(out.confirmed);
    try std.testing.expect(out.client_handshakes >= 1);
    try std.testing.expectEqual(@as(usize, 0), out.server_initials_after_client_handshake);
    try std.testing.expectEqual(@as(usize, 0), out.client_initials_after_handshake);

    // The client's half on its own. Every datagram of the client is
    // lost for the first second, so the server has read no Handshake
    // packet when its probe timeout sends the ServerHello again, in an
    // Initial packet. The client has sent Handshake packets by then
    // (its answer and its probes), so it has no Initial keys and sends
    // no Initial packet: before, it acknowledged that ServerHello in
    // one. Its next probe gets through, and the handshake completes.
    const late = try run(std.testing.allocator, .{
        .cert = .wide,
        .drop_server = .{ .first = 2, .count = 2 },
        .drop_client = .{ .first = 2, .count = 10 },
        .until_confirmed = true,
    });
    try std.testing.expect(late.confirmed);
    // The server did send its flight again after the first three
    // datagrams (the probe timeout at 1 s), and the client had sent
    // Handshake packets before that.
    try std.testing.expect(late.flights > 3);
    try std.testing.expect(late.flight_us[3] >= us_per_s);
    try std.testing.expect(late.client_handshakes >= 10);
    try std.testing.expectEqual(@as(usize, 0), late.client_initials_after_handshake);
    try std.testing.expectEqual(@as(usize, 0), late.server_initials_after_client_handshake);
}

test "handshake loss: a Handshake packet that does not authenticate takes no Initial keys from the server" {
    // The server discards its Initial keys when it PROCESSES a
    // Handshake packet: one that authenticated. A packet that only
    // says it is a Handshake packet proves nothing. If it could make
    // the server discard, anyone could stop a handshake with one
    // datagram: the server could no longer read the client's Initial
    // packets or send its ServerHello again.
    //
    // Here the client's first answer is lost, and its second datagram
    // (a Handshake packet alone) has one byte changed.
    const out = try run(std.testing.allocator, .{
        .cert = .wide,
        .drop_client = .{ .first = 2, .count = 1 },
        .damage_client = .{ .index = 3, .kind = .flip, .offset = 30 },
        .until_confirmed = true,
    });
    try std.testing.expectEqual(@as(usize, 1), out.damaged);
    try std.testing.expect(!out.server_initial_keys_gone_after_damage);
    try std.testing.expect(out.confirmed);
}

test "handshake loss: a Handshake packet behind an Initial packet that does not open is still read (RFC 9000 12.2)" {
    // The client's first answer is two packets in one datagram: an
    // Initial packet (the ACK for the ServerHello) and a Handshake
    // packet. One byte of the Initial packet is changed on the way.
    // That packet does not authenticate. The Handshake packet behind
    // it is intact, and the server must read it: "the receiver ...
    // MUST attempt to process the remaining packets."
    //
    // What shows it from the outside: a Handshake packet from the
    // client validates its address (RFC 9000 section 8.1). With the
    // packet read, the server has the address validated after the
    // client's second datagram, as with no damage at all.
    const control = try run(std.testing.allocator, .{ .cert = .wide, .until_confirmed = true });
    try std.testing.expectEqual(@as(usize, 2), control.validated_by_client_datagram);

    // Offset 40 is in the protected payload of the Initial packet (its
    // header is 26 bytes), so the Length field is as it was sent.
    const out = try run(std.testing.allocator, .{
        .cert = .wide,
        .damage_client = .{ .index = 2, .kind = .flip, .offset = 40 },
        .until_confirmed = true,
    });
    try std.testing.expectEqual(@as(usize, 1), out.damaged);
    try std.testing.expect(out.confirmed);
    try std.testing.expectEqual(@as(usize, 2), out.validated_by_client_datagram);
}

test "handshake loss: one damaged datagram ends no connection" {
    // The interop simulator's `handshakecorruption` changes one byte
    // in the first 51 bytes of a datagram: the first byte, the
    // version, the connection IDs and their lengths, the token length,
    // the Length field, the packet number. A receive buffer that is
    // too small cuts a datagram short. A packet that cannot be
    // authenticated is a packet to drop (RFC 9000 section 12.2), and
    // loss recovery repairs it. It is never a reason to close: anyone
    // who can write one datagram could end the connection.
    //
    // FOUND 2026-10-03 with this sweep, on the code before: 75 of
    // 2448 cases with one changed byte ended the connection. A changed
    // length field made `Connection.handle` return an error (four
    // different ones), and an error from `handle` ends the connection
    // in `Server.feed` and in the bundled client loop. And one case
    // left a connection that could not finish: the server had taken
    // the client's connection ID from the damaged header of the first
    // datagram and kept it.
    var runs: usize = 0;
    var damaged: usize = 0;
    var failures: usize = 0;
    //
    // The wide certificate: with it the first four datagrams of each
    // end are every shape a handshake has (an Initial packet alone,
    // Initial + Handshake, Handshake alone, Handshake + 1-RTT, 1-RTT).
    const cuts = [_]usize{ 1, 2, 5, 6, 7, 14, 15, 16, 22, 23, 24, 25, 26, 27, 30, 40, 50, 60, 100, 200, 600, 1199 };
    for ([_]Cert{.wide}) |cert| {
        for (1..5) |index| {
            for ([_]bool{ false, true }) |to_client| {
                for (0..51 * 3 + cuts.len) |case| {
                    const d: Damage = if (case < 51 * 3)
                        .{ .index = index, .kind = .flip, .offset = case / 3, .flip = ([_]u8{ 0xff, 0x01, 0x40 })[case % 3] }
                    else
                        .{ .index = index, .kind = .cut, .offset = cuts[case - 51 * 3] };
                    runs += 1;
                    const out = run(std.testing.allocator, .{
                        .cert = cert,
                        .damage_client = if (to_client) .{} else d,
                        .damage_server = if (to_client) d else .{},
                        .until_confirmed = true,
                    }) catch |e| {
                        failures += 1;
                        if (print_damage_failures) std.debug.print("[handshake_loss] damage cert={t} to_client={} index={d} {t} offset={d} flip={x}: error {t}\n", .{ cert, to_client, index, d.kind, d.offset, d.flip, e });
                        continue;
                    };
                    damaged += out.damaged;
                    if (!out.confirmed or !out.server_open or !out.client_open) {
                        failures += 1;
                        if (print_damage_failures) std.debug.print("[handshake_loss] damage cert={t} to_client={} index={d} {t} offset={d} flip={x}: confirmed={} server_open={} client_open={}\n", .{ cert, to_client, index, d.kind, d.offset, d.flip, out.confirmed, out.server_open, out.client_open });
                    }
                }
            }
        }
    }
    // The sweep did damage datagrams (it is not a sweep of nothing).
    try std.testing.expect(damaged > runs / 2);
    try std.testing.expectEqual(@as(usize, 0), failures);
}

/// Set to true to print each case of the damage sweep that fails.
const print_damage_failures = false;

test "handshake loss: a first datagram with a damaged Source Connection ID Length does not poison the connection" {
    // The one case of the sweep above that did not end the connection
    // and did not let it finish. The client's ClientHello arrives with
    // its Source Connection ID Length changed from 8 to 9. The packet
    // does not authenticate and is dropped, and the client's next copy
    // is fine. But the server had made the connection from the
    // header of the first datagram, with a 9-byte ID for the client,
    // and kept it. The client could read the server's long-header
    // packets (they say how long the ID is) and none of its 1-RTT
    // packets (they do not), so it never got HANDSHAKE_DONE.
    const out = try run(std.testing.allocator, .{
        .damage_client = .{ .index = 1, .kind = .flip, .offset = 14, .flip = 0x01 },
        .until_confirmed = true,
    });
    try std.testing.expectEqual(@as(usize, 1), out.damaged);
    try std.testing.expect(out.confirmed);
    // One probe timeout of the client (1 s with no RTT sample) for the
    // ClientHello that was dropped, and then a normal handshake.
    try std.testing.expect(out.confirmed_at_us < 1100 * us_per_ms);
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
