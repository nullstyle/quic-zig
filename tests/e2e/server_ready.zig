//! The server's ready list and timer heap (`takeReady`, `slotDrained`,
//! `tickDue`, `nextDeadline`): a loop built on them touches only the
//! slots that have work. One client against one server in memory.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x44), .port = 4444 } };

const Loop = struct {
    srv: *quic.Server,
    cli: *quic.Client,
    now_us: u64 = 1_000,
    rx: [4096]u8 = undefined,

    /// One pass of a loop built on the ready API: the client's
    /// datagrams in, the due timers, the ready slots drained.
    fn pass(self: *Loop) !bool {
        var moved = false;
        while (try self.cli.conn.poll(&self.rx, self.now_us)) |n| {
            _ = try self.srv.feed(self.rx[0..n], addr, self.now_us);
            moved = true;
        }
        try self.srv.tickDue(self.now_us);
        for (self.srv.takeReady()) |slot| {
            while (try slot.conn.pollDatagram(&self.rx, self.now_us)) |d| {
                try self.cli.conn.handle(self.rx[0..d.len], null, self.now_us);
                moved = true;
            }
            self.srv.slotDrained(slot, self.now_us);
        }
        try self.cli.conn.tick(self.now_us);
        self.now_us += 1_000;
        return moved;
    }

    fn settle(self: *Loop) !void {
        var quiet: u32 = 0;
        while (quiet < 3) quiet = if (try self.pass()) 0 else quiet + 1;
    }
};

fn makeServer(allocator: std.mem.Allocator) !quic.Server {
    return quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

fn makeClient(allocator: std.mem.Allocator) !quic.Client {
    return quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test certificate
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

test "ready list: a new slot is ready once, a drained slot stays out until it is touched, a due timer brings it back" {
    const allocator = std.testing.allocator;
    var srv = try makeServer(allocator);
    defer srv.deinit();
    var cli = try makeClient(allocator);
    defer cli.deinit();
    var loop: Loop = .{ .srv = &srv, .cli = &cli };
    try cli.conn.advance();

    // The first client datagram makes the slot: ready, and armed.
    const first = (try cli.conn.poll(&loop.rx, loop.now_us)).?;
    try std.testing.expectEqual(quic.Server.FeedOutcome.accepted, try srv.feed(loop.rx[0..first], addr, loop.now_us));
    const slot = srv.iterator()[0];
    // A look does not take.
    try std.testing.expectEqual(@as(usize, 1), srv.peekReady().len);
    try std.testing.expect(srv.peekReady()[0] == slot);
    const ready = srv.takeReady();
    try std.testing.expectEqual(@as(usize, 1), ready.len);
    try std.testing.expect(ready[0] == slot);
    try std.testing.expectEqual(@as(usize, 0), srv.peekReady().len);
    try std.testing.expect(srv.nextDeadline(loop.now_us) != null);
    // Taken once: the next call has nothing.
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);
    // The slot was not drained yet: its flight is still queued, and a
    // drain gives it to the client.
    while (try slot.conn.pollDatagram(&loop.rx, loop.now_us)) |d| try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
    srv.slotDrained(slot, loop.now_us);

    // The handshake and its tail, through the ready API alone.
    var step: u32 = 0;
    while (step < 64 and !(cli.conn.handshakeDone() and slot.conn.handshakeDone())) : (step += 1) _ = try loop.pass();
    try std.testing.expect(cli.conn.handshakeDone());
    try std.testing.expect(slot.conn.handshakeDone());
    try loop.settle();

    // At rest: nothing ready, and the heap's top is what the sweep
    // finds (the idle timeout).
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);
    const sweep = srv.nextTimerDeadline(loop.now_us).?;
    const top = srv.nextDeadline(loop.now_us).?;
    try std.testing.expectEqual(sweep.at_us, top.at_us);
    try std.testing.expectEqual(quic.conn.state.TimerKind.idle, sweep.kind);
    try std.testing.expectEqual(sweep.kind, top.kind);

    // `touch` by hand marks the slot ready, once.
    slot.conn.touch();
    try std.testing.expectEqual(@as(usize, 1), srv.takeReady().len);
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);

    // An application write touches the connection: the slot is ready
    // again, once, and the client gets the bytes.
    const s = try slot.conn.openNextBidi();
    _ = try slot.conn.streamWrite(s.id, "hello");
    try slot.conn.streamFinish(s.id);
    const after_write = srv.takeReady();
    try std.testing.expectEqual(@as(usize, 1), after_write.len);
    try std.testing.expect(after_write[0] == slot);
    var got: usize = 0;
    while (try slot.conn.pollDatagram(&loop.rx, loop.now_us)) |d| {
        try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
        got += 1;
    }
    try std.testing.expect(got > 0);
    srv.slotDrained(slot, loop.now_us);
    // The packet in flight moved the deadline to its loss or probe timer.
    const in_flight_at = srv.nextDeadline(loop.now_us).?.at_us;
    try std.testing.expect(in_flight_at < sweep.at_us);
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try cli.conn.streamRead(s.id, &buf));
    try std.testing.expectEqualStrings("hello", buf[0..5]);
    // The client's ACK comes back: the slot is ready (an inbound
    // datagram), and once drained its deadline moves on (the idle
    // timeout again); the heap still holds the older entry, stale.
    while (try cli.conn.poll(&loop.rx, loop.now_us)) |n| _ = try srv.feed(loop.rx[0..n], addr, loop.now_us);
    const after_ack = srv.takeReady();
    try std.testing.expectEqual(@as(usize, 1), after_ack.len);
    while (try slot.conn.pollDatagram(&loop.rx, loop.now_us)) |d| try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
    srv.slotDrained(slot, loop.now_us);
    // (No deadline query here: it would skim the stale entry off the
    // top before `tickDue` meets it.)
    // The stale entry comes due: `tickDue` skips it, and wakes nothing.
    loop.now_us = in_flight_at + 1;
    try srv.tickDue(loop.now_us);
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);
    try loop.settle();
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);

    // The idle timeout passes: `tickDue` closes the connection and the
    // slot is ready (a close is work for the loop).
    loop.now_us += 31 * std.time.us_per_s;
    try srv.tickDue(loop.now_us);
    try std.testing.expect(slot.conn.closeState() != .open);
    const after_idle = srv.takeReady();
    try std.testing.expectEqual(@as(usize, 1), after_idle.len);
    srv.slotDrained(slot, loop.now_us);

    // Through draining to closed by the sweep tick (the APIs mix), so
    // the heap still holds the slot's draining entry; then reaped:
    // nothing is left in the lists or the heap.
    loop.now_us += 10 * std.time.us_per_s;
    try std.testing.expect(srv.timers.items.len > 0);
    try srv.tick(loop.now_us);
    try std.testing.expectEqual(quic.CloseState.closed, slot.conn.closeState());
    try std.testing.expectEqual(@as(usize, 1), srv.reap());
    // Nothing of the slot is left anywhere (its entries held its
    // pointer): checked before any query could skim the heap.
    try std.testing.expectEqual(@as(usize, 0), srv.timers.items.len);
    try std.testing.expectEqual(@as(usize, 0), srv.ready.items.len);
    try std.testing.expectEqual(@as(usize, 0), srv.ready_taken.items.len);
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);
    try std.testing.expect(srv.nextDeadline(loop.now_us) == null);
}

test "ready list: a loss found by the time threshold is sent again at the next drain, and a re-arm to the same deadline adds no entry" {
    const allocator = std.testing.allocator;
    var srv = try makeServer(allocator);
    defer srv.deinit();
    var cli = try makeClient(allocator);
    defer cli.deinit();
    var loop: Loop = .{ .srv = &srv, .cli = &cli };
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64 and srv.iterator().len == 0) : (step += 1) _ = try loop.pass();
    const slot = srv.iterator()[0];
    step = 0;
    while (step < 64 and !(cli.conn.handshakeDone() and slot.conn.handshakeDone())) : (step += 1) _ = try loop.pass();
    try loop.settle();
    try std.testing.expectEqual(@as(usize, 0), srv.takeReady().len);

    // At rest, drained again and again: the heap does not grow.
    const entries_at_rest = srv.timers.items.len;
    var k: u32 = 0;
    while (k < 50) : (k += 1) {
        slot.conn.touch();
        for (srv.takeReady()) |ready| {
            while (try ready.conn.pollDatagram(&loop.rx, loop.now_us)) |_| {}
            srv.slotDrained(ready, loop.now_us);
        }
    }
    try std.testing.expectEqual(entries_at_rest, srv.timers.items.len);

    // Two packets from the server; the first is lost on the way, the
    // second arrives and is acknowledged: the time threshold finds the
    // first (RFC 9002 6.1.2), in `tickDue`, and the slot is drained
    // again with the retransmission.
    const s = try slot.conn.openNextBidi();
    _ = try slot.conn.streamWrite(s.id, "first");
    var lost: [4096]u8 = undefined;
    const lost_len = (try slot.conn.pollDatagram(&lost, loop.now_us)).?.len;
    _ = lost_len;
    _ = try slot.conn.streamWrite(s.id, "second");
    try slot.conn.streamFinish(s.id);
    while (try slot.conn.pollDatagram(&loop.rx, loop.now_us)) |d| try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
    _ = srv.takeReady();
    srv.slotDrained(slot, loop.now_us);
    loop.now_us += 1_000;
    try cli.conn.tick(loop.now_us);
    // The client's ACK (the second packet only) reaches the server.
    while (try cli.conn.poll(&loop.rx, loop.now_us)) |n| _ = try srv.feed(loop.rx[0..n], addr, loop.now_us);
    for (srv.takeReady()) |ready| {
        while (try ready.conn.pollDatagram(&loop.rx, loop.now_us)) |d| try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
        srv.slotDrained(ready, loop.now_us);
    }
    const loss_at = srv.nextDeadline(loop.now_us).?;
    try std.testing.expectEqual(quic.conn.state.TimerKind.loss_detection, loss_at.kind);
    // Nothing to send until then.
    try std.testing.expect((try slot.conn.pollDatagram(&loop.rx, loop.now_us)) == null);
    loop.now_us = @max(loop.now_us, loss_at.at_us + 1);
    try srv.tickDue(loop.now_us);
    const due = srv.takeReady();
    try std.testing.expectEqual(@as(usize, 1), due.len);
    var resent: usize = 0;
    while (try due[0].conn.pollDatagram(&loop.rx, loop.now_us)) |d| {
        try cli.conn.handle(loop.rx[0..d.len], null, loop.now_us);
        resent += 1;
    }
    try std.testing.expect(resent > 0);
    srv.slotDrained(due[0], loop.now_us);
    var buf: [64]u8 = undefined;
    var got: usize = 0;
    while (true) {
        const n = try cli.conn.streamRead(s.id, &buf);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqual(@as(usize, 11), got);
}
