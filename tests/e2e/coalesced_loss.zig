//! Loss of the client's first coalesced post-handshake datagram.
//!
//! Once the client has the whole server flight it emits ONE datagram that
//! coalesces the Handshake Finished and its first 1-RTT packet (here:
//! STREAM "hello"). Initial keys are already gone by then (the client
//! discards them the moment TLS completes, in `drainInboxIntoTls`), so the
//! datagram leads with a Handshake packet; and because the path counts as
//! validated once the handshake completes, that first 1-RTT packet is also
//! the first DPLPMTUD probe, padded to `initial_mtu + probe_step` = 1264
//! bytes, which makes the whole datagram ~1353 bytes. A real path has been
//! observed to lose exactly that datagram. The stack must recover through
//! loss detection alone: the Finished must be retransmitted so the server
//! completes the handshake, and the 1-RTT STREAM data must be
//! retransmitted so the server eventually reads "hello" — even on a path
//! that never carries a datagram larger than 1252 bytes (IPv4 + UDP on a
//! 1280-byte MTU link), where every probe-sized retransmission is lost too.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

/// Same wide certificate as initial_padding.zig: the server flight needs
/// two datagrams, so the client's Finished only becomes available once the
/// second one arrives, which lines up with the first 1-RTT data.
const wide_cert_pem = @embedFile("../data/test_cert_wide.pem");
const wide_key_pem = @embedFile("../data/test_key_wide_cert.pem");

const hello = "hello";

fn leadsWithInitial(datagram: []const u8) bool {
    if (datagram.len == 0) return false;
    const first = datagram[0];
    return (first & 0x80) != 0 and (first & 0x30) == 0x00;
}

/// Render the coalesced packets in a datagram as `initial(145) handshake(1165)`
/// for the `verbose` trace. Only the long-header length field is parsed;
/// a short header is always last so its size is whatever remains.
fn describe(datagram: []const u8, out: []u8) []const u8 {
    var w = std.Io.Writer.fixed(out);
    var pos: usize = 0;
    while (pos < datagram.len) {
        const first = datagram[pos];
        if ((first & 0x80) == 0) {
            w.print("short({d})", .{datagram.len - pos}) catch {};
            break;
        }
        const typ: []const u8 = switch ((first & 0x30) >> 4) {
            0 => "initial",
            1 => "0rtt",
            2 => "handshake",
            else => "retry",
        };
        var i = pos + 5;
        if (i >= datagram.len) break;
        const dl = datagram[i];
        i += 1 + dl;
        if (i >= datagram.len) break;
        const sl = datagram[i];
        i += 1 + sl;
        if (i >= datagram.len) break;
        if ((first & 0x30) == 0) {
            const tok = readVarint(datagram, &i) orelse break;
            i += @intCast(tok);
        }
        const plen = readVarint(datagram, &i) orelse break;
        const total = (i - pos) + @as(usize, @intCast(plen));
        w.print("{s}({d}) ", .{ typ, total }) catch {};
        pos += total;
    }
    return w.buffered();
}

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

fn leadsWithHandshake(datagram: []const u8) bool {
    if (datagram.len == 0) return false;
    const first = datagram[0];
    return (first & 0x80) != 0 and (first & 0x30) == 0x20;
}

const Ctx = struct {
    cli: *quic.Client,
    srv: *quic.Server,
    lb: *quic.testing.Loopback,
    stream_id: ?u64 = null,
    /// Drop policy: `once` drops exactly the first datagram the client
    /// emits after it opened the stream; `over` drops every
    /// client->server datagram larger than `over` bytes (a path whose
    /// MTU cannot carry the coalesced datagram, nor the probes).
    policy: union(enum) { once, over: usize },
    /// Which kind of client-opened stream carries "hello". qmsg's HELLO
    /// rides a client unidirectional stream (id 2); requests ride bidi.
    stream_kind: enum { bidi, uni },
    /// The one coalesced datagram that gets dropped, once.
    dropped: bool = false,
    dropped_len: usize = 0,
    drops: usize = 0,
    verbose: bool = false,
    client_datagrams: usize = 0,
    server_datagrams: usize = 0,
    got: std.ArrayListUnmanaged(u8) = .empty,

    fn openStreamIfReady(self: *Ctx) !void {
        if (self.stream_id != null) return;
        if (!self.cli.conn.handshakeDone()) return;
        const stream = switch (self.stream_kind) {
            .bidi => try self.cli.conn.openNextBidi(),
            .uni => try self.cli.conn.openNextUni(),
        };
        self.stream_id = stream.id;
        const n = try self.cli.conn.streamWrite(stream.id, hello);
        try std.testing.expectEqual(hello.len, n);
    }

    /// Client -> server, dropping the first datagram that coalesces the
    /// padded Initial ACK, Finished and the 1-RTT STREAM.
    fn pumpClient(self: *Ctx) !void {
        while (try self.cli.conn.poll(self.lb.rx, self.lb.now_us)) |len| {
            const datagram = self.lb.rx[0..len];
            self.client_datagrams += 1;
            if (self.verbose) {
                var dbuf: [256]u8 = undefined;
                std.debug.print("[coalesced_loss] t={d}us C->S #{d} {d}B: {s} (cli_hs={} stream={?d})\n", .{ self.lb.now_us, self.client_datagrams, len, describe(datagram, &dbuf), self.cli.conn.handshakeDone(), self.stream_id });
            }
            if (leadsWithInitial(datagram)) try std.testing.expect(len >= 1200);
            const under_test = !self.dropped and self.stream_id != null;
            if (under_test) {
                // The datagram under test: the first one the client emits
                // once it holds the whole server flight and has 1-RTT data
                // to send. It carries the Handshake Finished and the first
                // 1-RTT packet.
                try std.testing.expect(len > 1300);
                try std.testing.expect(leadsWithHandshake(datagram));
                self.dropped = true;
                self.dropped_len = len;
            }
            const drop = switch (self.policy) {
                .once => under_test,
                .over => |limit| len > limit,
            };
            if (drop) {
                self.drops += 1;
                if (self.verbose) std.debug.print("[coalesced_loss] dropping client datagram #{d} ({d} bytes) at t={d}us\n", .{ self.client_datagrams, len, self.lb.now_us });
                continue;
            }
            _ = try self.srv.feed(datagram, quic.testing.loopback_addr, self.lb.now_us);
        }
    }

    /// Server -> client, one datagram at a time with the client answering
    /// in between (as a network delivers it).
    fn pumpServer(self: *Ctx) !void {
        var flight: [8][4096]u8 = undefined;
        var lens: [8]usize = undefined;
        var count: usize = 0;
        for (self.srv.iterator()) |slot| {
            while (count < flight.len) {
                const len = (try slot.conn.poll(flight[count][0..], self.lb.now_us)) orelse break;
                lens[count] = len;
                count += 1;
            }
        }
        while (self.srv.drainStatelessResponse()) |_| {}
        for (0..count) |i| {
            self.server_datagrams += 1;
            if (self.verbose) {
                var dbuf: [256]u8 = undefined;
                std.debug.print("[coalesced_loss] t={d}us S->C #{d} {d}B: {s} (srv_hs={})\n", .{ self.lb.now_us, self.server_datagrams, lens[i], describe(flight[i][0..lens[i]], &dbuf), self.srv.iterator()[0].conn.handshakeDone() });
            }
            try self.cli.conn.handle(flight[i][0..lens[i]], null, self.lb.now_us);
            try self.openStreamIfReady();
            try self.pumpClient();
        }
    }

    fn readServerStream(self: *Ctx, allocator: std.mem.Allocator) !void {
        const id = self.stream_id orelse return;
        for (self.srv.iterator()) |slot| {
            var buf: [256]u8 = undefined;
            const n = slot.conn.streamRead(id, &buf) catch |err| switch (err) {
                error.StreamNotFound => continue,
                else => return err,
            };
            if (n > 0) try self.got.appendSlice(allocator, buf[0..n]);
        }
    }

    fn serverDone(self: *Ctx) bool {
        if (self.srv.iterator().len == 0) return false;
        return self.srv.iterator()[0].conn.handshakeDone() and
            std.mem.eql(u8, self.got.items, hello);
    }
};

const Outcome = struct {
    done_at_step: ?usize,
    done_at_us: u64,
    drops: usize,
    dropped_len: usize,
    client_datagrams: usize,
    server_datagrams: usize,
};

fn run(allocator: std.mem.Allocator, policy: @FieldType(Ctx, "policy"), stream_kind: @FieldType(Ctx, "stream_kind"), verbose: bool) !Outcome {
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = wide_cert_pem,
        .tls_key_pem = wide_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
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

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    var ctx: Ctx = .{ .cli = &cli, .srv = &srv, .lb = &lb, .policy = policy, .stream_kind = stream_kind, .verbose = verbose };
    defer ctx.got.deinit(allocator);

    try cli.conn.advance();
    var steps: usize = 0;
    var done_at_step: ?usize = null;
    while (steps < 3000) : (steps += 1) {
        try ctx.openStreamIfReady();
        try ctx.pumpClient();
        try ctx.readServerStream(allocator);
        try ctx.pumpServer();
        try ctx.readServerStream(allocator);
        if (ctx.serverDone()) {
            done_at_step = steps;
            break;
        }
        try srv.tick(lb.now_us);
        try cli.conn.tick(lb.now_us);
        lb.now_us += 1_000;
    }
    if (verbose) std.debug.print(
        "[coalesced_loss] dropped={} ({d} bytes) drops={d} client_datagrams={d} server_datagrams={d} done_at_step={?d} t={d}us cli_hs={} srv_slots={d} got={s}\n",
        .{ ctx.dropped, ctx.dropped_len, ctx.drops, ctx.client_datagrams, ctx.server_datagrams, done_at_step, lb.now_us, cli.conn.handshakeDone(), srv.iterator().len, ctx.got.items },
    );
    // The datagram under test was seen and dropped.
    try std.testing.expect(ctx.dropped);
    try std.testing.expect(ctx.dropped_len > 1300);
    // Recovery: both handshakes complete and the server read the bytes.
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(srv.iterator().len > 0);
    try std.testing.expect(srv.iterator()[0].conn.handshakeDone());
    try std.testing.expectEqualStrings(hello, ctx.got.items);
    return .{
        .done_at_step = done_at_step,
        .done_at_us = lb.now_us,
        .drops = ctx.drops,
        .dropped_len = ctx.dropped_len,
        .client_datagrams = ctx.client_datagrams,
        .server_datagrams = ctx.server_datagrams,
    };
}

test "handshake and first 1-RTT data recover when the coalesced Finished+STREAM datagram is lost once" {
    const out = try run(std.testing.allocator, .once, .bidi, false);
    try std.testing.expectEqual(@as(usize, 1), out.drops);
    // Finished comes back on the Handshake PTO within a few ms; the
    // STREAM data waits for the 1-RTT PTO (~27 ms at loopback RTT).
    try std.testing.expect(out.done_at_step.? < 100);
}

test "handshake and first 1-RTT data recover on a path that cannot carry datagrams over 1252 bytes" {
    // Every datagram over 1252 bytes vanishes: the coalesced
    // Finished+probe datagram and every later DPLPMTUD probe. The
    // requeued STREAM data must eventually leave in a datagram the
    // path can carry.
    const out = try run(std.testing.allocator, .{ .over = 1252 }, .bidi, false);
    // The original datagram plus at least one probe-sized retransmission
    // (with the default probe_threshold of 3 it is three: the requeued
    // STREAM data rides in the next probe each time, ~28/81/186 ms).
    try std.testing.expect(out.drops >= 2);
    try std.testing.expect(out.done_at_step.? < 1000);
}

test "same recovery when the first 1-RTT data is on a client unidirectional stream" {
    const once = try run(std.testing.allocator, .once, .uni, false);
    try std.testing.expectEqual(@as(usize, 1), once.drops);
    try std.testing.expect(once.done_at_step.? < 100);
    const narrow = try run(std.testing.allocator, .{ .over = 1252 }, .uni, false);
    try std.testing.expect(narrow.drops >= 2);
    try std.testing.expect(narrow.done_at_step.? < 1000);
}
