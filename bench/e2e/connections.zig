//! Many connections on one `Server`, in memory, no sockets: what an
//! idle connection costs the loop and the heap, and what a request
//! costs when a few connections are active while the rest idle.
//!
//! Two loop shapes are measured, the ones the embedders run:
//! - `one_pass`: the bundled `runUdpServer` shape. One sweep of every
//!   slot per iteration (poll until empty, then tick), the timer scan
//!   once per iteration.
//! - `from_zero`: qmsg's `drainOutbound` shape (nest runs it). For every
//!   outgoing datagram a scan from slot 0 until one slot yields.
//! - `ready`: the ready list and the timer heap (`Server.takeReady`,
//!   `tickDue`, `nextDeadline`): only the slots with work are touched.

const std = @import("std");
const quic = @import("quic");
const counting_allocator = @import("counting_allocator.zig");
const CountingAllocator = counting_allocator.CountingAllocator;
const nowNanos = @import("harness.zig").nowNanos;

const test_cert_pem = @embedFile("support/test_cert.pem");
const test_key_pem = @embedFile("support/test_key.pem");
const protos = [_][]const u8{"hq-bench"};

pub const ConnectionsOptions = struct {
    name: []const u8,
    connections: u32 = 1_000,
    /// How many of the connections send a request in one active cycle.
    active: u32 = 10,
    request_bytes: usize = 64,
    reply_bytes: usize = 256,
    /// Timed idle passes (the median is reported).
    idle_passes: u32 = 15,
    /// Timed active cycles per loop shape (the median is reported).
    active_cycles: u32 = 15,
};

pub const ConnectionsResult = struct {
    name: []const u8,
    connections: u32,
    active: u32,
    /// Wall time of every handshake (both ends in this process).
    handshake_wall_ns: u64,
    handshake_us_per_connection: f64,
    /// The server's Zig heap after the handshakes, per connection.
    bytes_per_connection: u64,
    /// The server's Zig heap at its peak during the handshakes, per
    /// connection.
    peak_bytes_per_connection: u64,
    /// One idle pass: `tick`, `nextTimerDeadline`, a poll of every slot
    /// that finds nothing. Medians, per connection.
    tick_ns_per_connection: f64,
    deadline_ns_per_connection: f64,
    poll_ns_per_connection: f64,
    idle_pass_ns: u64,
    /// One idle pass through the ready API: `tickDue`, `nextDeadline`,
    /// `takeReady` (empty).
    idle_pass_ready_ns: u64,
    /// Datagrams a slot produced during the idle passes (0 = idle).
    idle_strays: u64,
    /// One active cycle: `active` requests sent, answered and read,
    /// with every slot swept each pass. Medians.
    cycle_ns_one_pass: u64,
    cycle_ns_from_zero: u64,
    cycle_ns_ready: u64,
    us_per_request_one_pass: f64,
    us_per_request_from_zero: f64,
    us_per_request_ready: f64,
};

const Peer = struct {
    client: quic.Client,
    addr: quic.conn.path.Address,
    slot: *quic.Server.Slot = undefined,
    stream_id: u64 = 0,
    replied: bool = false,
};

const Sweep = enum { one_pass, from_zero, ready };

/// The virtual clock's step during the handshakes and the settle
/// passes. Small, so that thousands of handshakes in a row stay far
/// inside the idle timeout (30 s): 4,000 handshakes of 70 steps are
/// 28 virtual seconds at 100 us.
const step_us: u64 = 100;

const Run = struct {
    allocator: std.mem.Allocator,
    srv: *quic.Server,
    peers: []Peer,
    now_us: u64 = 1_000,
    rx: [4096]u8 = undefined,
    request: []const u8,
    reply: []const u8,

    fn feedClientToServer(self: *Run, i: usize) !void {
        const p = &self.peers[i];
        while (try p.client.conn.poll(&self.rx, self.now_us)) |len| {
            _ = try self.srv.feed(self.rx[0..len], p.addr, self.now_us);
        }
    }

    fn deliverSlotToClient(self: *Run, i: usize) !bool {
        const p = &self.peers[i];
        var any = false;
        while (try p.slot.conn.pollDatagram(&self.rx, self.now_us)) |d| {
            try p.client.conn.handle(self.rx[0..d.len], null, self.now_us);
            any = true;
        }
        return any;
    }

    /// One handshake, the client-to-server packets through `feed`.
    fn handshake(self: *Run, i: usize) !void {
        const p = &self.peers[i];
        try p.client.conn.advance();
        var have_slot = false;
        var step: u32 = 0;
        while (step < 64) : (step += 1) {
            while (try p.client.conn.poll(&self.rx, self.now_us)) |len| {
                const outcome = try self.srv.feed(self.rx[0..len], p.addr, self.now_us);
                if (outcome == .accepted) {
                    const slots = self.srv.iterator();
                    p.slot = slots[slots.len - 1];
                    have_slot = true;
                }
            }
            while (self.srv.drainStatelessResponse()) |_| {}
            if (have_slot) _ = try self.deliverSlotToClient(i);
            try self.srv.tick(self.now_us);
            try p.client.conn.tick(self.now_us);
            self.now_us += step_us;
            if (have_slot and p.client.conn.handshakeDone() and p.slot.conn.handshakeDone()) break;
        }
        if (!have_slot or !p.client.conn.handshakeDone() or !p.slot.conn.handshakeDone()) {
            std.debug.print("connections: handshake {d} stalled (slot {}, client done {}, slots {d})\n", .{
                i, have_slot, p.client.conn.handshakeDone(), self.srv.iterator().len,
            });
            return error.HandshakeStalled;
        }
        // The tail: HANDSHAKE_DONE, NEW_TOKEN, the session ticket, their ACKs.
        var quiet: u32 = 0;
        while (quiet < 2) {
            var moved = false;
            var n: u32 = 0;
            while (try p.client.conn.poll(&self.rx, self.now_us)) |len| {
                _ = try self.srv.feed(self.rx[0..len], p.addr, self.now_us);
                n += 1;
            }
            if (try self.deliverSlotToClient(i)) moved = true;
            if (n > 0) moved = true;
            try self.srv.tick(self.now_us);
            try p.client.conn.tick(self.now_us);
            self.now_us += step_us;
            quiet = if (moved) 0 else quiet + 1;
        }
    }

    /// Everything that is still queued anywhere, both ways, until two
    /// passes move nothing.
    fn settleAll(self: *Run) !void {
        var quiet: u32 = 0;
        while (quiet < 2) {
            var moved = false;
            for (self.peers, 0..) |*p, i| {
                var n: u32 = 0;
                while (try p.client.conn.poll(&self.rx, self.now_us)) |len| {
                    _ = try self.srv.feed(self.rx[0..len], p.addr, self.now_us);
                    n += 1;
                }
                if (n > 0) moved = true;
                if (try self.deliverSlotToClient(i)) moved = true;
                try p.client.conn.tick(self.now_us);
            }
            try self.srv.tick(self.now_us);
            self.now_us += step_us;
            quiet = if (moved) 0 else quiet + 1;
        }
    }

    const IdlePass = struct { tick_ns: u64, deadline_ns: u64, poll_ns: u64, strays: u64 };

    fn idlePass(self: *Run) !IdlePass {
        const t0 = nowNanos();
        try self.srv.tick(self.now_us);
        const t1 = nowNanos();
        _ = self.srv.nextTimerDeadline(self.now_us);
        const t2 = nowNanos();
        var strays: u64 = 0;
        for (self.srv.iterator(), 0..) |slot, i| {
            while (try slot.conn.pollDatagram(&self.rx, self.now_us)) |d| {
                try self.peers[i].client.conn.handle(self.rx[0..d.len], null, self.now_us);
                strays += 1;
            }
        }
        const t3 = nowNanos();
        self.now_us += 1;
        return .{ .tick_ns = t1 - t0, .deadline_ns = t2 - t1, .poll_ns = t3 - t2, .strays = strays };
    }

    /// The active peers: spread over the slot range, as the busy
    /// connections of a real server sit anywhere in its table.
    fn activeIndex(self: *Run, k: usize, active: usize) usize {
        return k * (self.peers.len / active);
    }

    fn idlePassReady(self: *Run) !u64 {
        const t0 = nowNanos();
        try self.srv.tickDue(self.now_us);
        _ = self.srv.nextDeadline(self.now_us);
        for (self.srv.takeReady()) |slot| {
            const i: usize = @intCast(slot.slot_id);
            _ = try self.deliverSlotToClient(i);
            self.srv.slotDrained(slot, self.now_us);
        }
        const t1 = nowNanos();
        self.now_us += 1;
        return t1 - t0;
    }

    /// The server application: read a request to its end, answer it.
    fn serveActive(self: *Run, active: usize) !void {
        var buf: [1024]u8 = undefined;
        for (0..active) |k| {
            const p = &self.peers[self.activeIndex(k, active)];
            const conn = p.slot.conn;
            if (conn.streamRecvState(p.stream_id)) |_| {
                while (try conn.streamRead(p.stream_id, &buf) != 0) {}
                if (conn.streamRecvState(p.stream_id).?.terminal and !conn.stream(p.stream_id).?.send.fin_marked) {
                    _ = try conn.streamWrite(p.stream_id, self.reply);
                    try conn.streamFinish(p.stream_id);
                }
            }
        }
    }

    fn readActive(self: *Run, active: usize) !bool {
        var buf: [1024]u8 = undefined;
        var all = true;
        for (0..active) |k| {
            const p = &self.peers[self.activeIndex(k, active)];
            if (p.replied) continue;
            const conn = p.client.conn;
            if (conn.streamRecvState(p.stream_id)) |_| {
                while (try conn.streamRead(p.stream_id, &buf) != 0) {}
                if (conn.streamRecvState(p.stream_id).?.terminal) p.replied = true;
            }
            if (!p.replied) all = false;
        }
        return all;
    }

    /// The server's outbound sweep, in one of the two embedder shapes,
    /// then the tick of every slot.
    fn sweep(self: *Run, shape: Sweep) !void {
        switch (shape) {
            .one_pass => {
                for (self.srv.iterator(), 0..) |_, i| {
                    _ = try self.deliverSlotToClient(i);
                }
            },
            .from_zero => {
                while (true) {
                    var yielded = false;
                    for (self.srv.iterator(), 0..) |slot, i| {
                        if (try slot.conn.pollDatagram(&self.rx, self.now_us)) |d| {
                            try self.peers[i].client.conn.handle(self.rx[0..d.len], null, self.now_us);
                            yielded = true;
                            break;
                        }
                    }
                    if (!yielded) break;
                }
            },
            .ready => {
                try self.srv.tickDue(self.now_us);
                for (self.srv.takeReady()) |slot| {
                    const i: usize = @intCast(slot.slot_id);
                    _ = try self.deliverSlotToClient(i);
                    self.srv.slotDrained(slot, self.now_us);
                }
                _ = self.srv.nextDeadline(self.now_us);
                return;
            },
        }
        try self.srv.tick(self.now_us);
    }

    /// `active` requests sent, answered and read; every slot swept in
    /// each pass. Returns the wall time of the whole cycle.
    fn activeCycle(self: *Run, active: usize, shape: Sweep) !u64 {
        const t0 = nowNanos();
        for (0..active) |k| {
            const p = &self.peers[self.activeIndex(k, active)];
            const s = try p.client.conn.openNextBidi();
            p.stream_id = s.id;
            p.replied = false;
            _ = try p.client.conn.streamWrite(s.id, self.request);
            try p.client.conn.streamFinish(s.id);
        }
        var pass: u32 = 0;
        while (pass < 200) : (pass += 1) {
            for (0..active) |k| try self.feedClientToServer(self.activeIndex(k, active));
            try self.serveActive(active);
            try self.sweep(shape);
            _ = self.srv.nextTimerDeadline(self.now_us);
            for (0..active) |k| try self.peers[self.activeIndex(k, active)].client.conn.tick(self.now_us);
            const done = try self.readActive(active);
            self.now_us += 100;
            if (done) break;
        }
        if (pass == 200) return error.ActiveCycleStalled;
        // The closing tail (the FIN's ACK, the stream credit) so the
        // next cycle starts clean.
        var k: u32 = 0;
        while (k < 3) : (k += 1) {
            for (0..active) |a| try self.feedClientToServer(self.activeIndex(a, active));
            try self.sweep(if (shape == .ready) .ready else .one_pass);
            for (0..active) |a| try self.peers[self.activeIndex(a, active)].client.conn.tick(self.now_us);
            self.now_us += 100;
        }
        return nowNanos() - t0;
    }
};

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

pub fn runConnectionsOnce(allocator: std.mem.Allocator, opts: ConnectionsOptions) !ConnectionsResult {
    var counting = CountingAllocator.init(allocator);
    const server_allocator = counting.allocator();

    const params: quic.tls.TransportParams = .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 18,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_stream_data_uni = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
    };
    var srv = try quic.Server.init(.{
        .allocator = server_allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .initial_source_rate_limit = .disabled,
        .max_concurrent_connections = opts.connections + 16,
    });
    defer srv.deinit();
    const after_server = counting.snapshot();

    const request = try allocator.alloc(u8, opts.request_bytes);
    defer allocator.free(request);
    @memset(request, 'q');
    const reply = try allocator.alloc(u8, opts.reply_bytes);
    defer allocator.free(reply);
    @memset(reply, 'r');

    const peers = try allocator.alloc(Peer, opts.connections);
    defer allocator.free(peers);
    var made: usize = 0;
    defer for (peers[0..made]) |*p| p.client.deinit();

    var run: Run = .{
        .allocator = allocator,
        .srv = &srv,
        .peers = peers,
        .request = request,
        .reply = reply,
    };

    const hs_start = nowNanos();
    for (peers, 0..) |*p, i| {
        const port: u16 = @intCast(1_024 + (i % 60_000));
        const octet: u8 = @intCast(1 + (i / 60_000));
        p.* = .{
            .client = try quic.Client.connect(.{
                .insecure_skip_verify = true, // self-signed bench certificate
                .allocator = allocator,
                .server_name = "localhost",
                .alpn_protocols = &protos,
                .transport_params = params,
            }),
            .addr = .{ .ipv4 = .{ .addr = .{ 10, 0, octet, 1 }, .port = port } },
        };
        made = i + 1;
        try run.handshake(i);
    }
    try run.settleAll();
    const handshake_wall_ns = nowNanos() - hs_start;
    if (srv.connectionCount() != opts.connections) return error.ConnectionCountMismatch;
    for (srv.iterator()) |slot| {
        if (slot.conn.closeState() != .open) return error.ConnectionNotOpen;
    }
    const after_handshakes = counting.snapshot();
    const n: u64 = opts.connections;

    // Idle passes.
    var ticks: [64]u64 = undefined;
    var deadlines: [64]u64 = undefined;
    var polls: [64]u64 = undefined;
    var strays: u64 = 0;
    const idle_n: usize = @min(opts.idle_passes, 64);
    for (0..idle_n) |k| {
        const r = try run.idlePass();
        ticks[k] = r.tick_ns;
        deadlines[k] = r.deadline_ns;
        polls[k] = r.poll_ns;
        strays += r.strays;
    }
    const tick_ns = median(ticks[0..idle_n]);
    const deadline_ns = median(deadlines[0..idle_n]);
    const poll_ns = median(polls[0..idle_n]);
    var ready_passes: [64]u64 = undefined;
    for (0..idle_n) |k| ready_passes[k] = try run.idlePassReady();
    const idle_ready_ns = median(ready_passes[0..idle_n]);
    const nf: f64 = @floatFromInt(n);

    // Active cycles, both loop shapes.
    const active: usize = @min(opts.active, opts.connections);
    var cycles: [64]u64 = undefined;
    const cycle_n: usize = @min(opts.active_cycles, 64);
    for (0..cycle_n) |k| cycles[k] = try run.activeCycle(active, .one_pass);
    const cycle_one_pass = median(cycles[0..cycle_n]);
    for (0..cycle_n) |k| cycles[k] = try run.activeCycle(active, .from_zero);
    const cycle_from_zero = median(cycles[0..cycle_n]);
    for (0..cycle_n) |k| cycles[k] = try run.activeCycle(active, .ready);
    const cycle_ready = median(cycles[0..cycle_n]);
    const af: f64 = @floatFromInt(active);

    return .{
        .name = opts.name,
        .connections = opts.connections,
        .active = @intCast(active),
        .handshake_wall_ns = handshake_wall_ns,
        .handshake_us_per_connection = @as(f64, @floatFromInt(handshake_wall_ns)) / nf / 1000.0,
        .bytes_per_connection = (after_handshakes.live_bytes - after_server.live_bytes) / n,
        .peak_bytes_per_connection = (after_handshakes.peak_live_bytes - after_server.live_bytes) / n,
        .tick_ns_per_connection = @as(f64, @floatFromInt(tick_ns)) / nf,
        .deadline_ns_per_connection = @as(f64, @floatFromInt(deadline_ns)) / nf,
        .poll_ns_per_connection = @as(f64, @floatFromInt(poll_ns)) / nf,
        .idle_pass_ns = tick_ns + deadline_ns + poll_ns,
        .idle_pass_ready_ns = idle_ready_ns,
        .idle_strays = strays,
        .cycle_ns_one_pass = cycle_one_pass,
        .cycle_ns_from_zero = cycle_from_zero,
        .cycle_ns_ready = cycle_ready,
        .us_per_request_one_pass = @as(f64, @floatFromInt(cycle_one_pass)) / af / 1000.0,
        .us_per_request_from_zero = @as(f64, @floatFromInt(cycle_from_zero)) / af / 1000.0,
        .us_per_request_ready = @as(f64, @floatFromInt(cycle_ready)) / af / 1000.0,
    };
}
