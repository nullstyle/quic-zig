//! Deterministic single-path impairment network for the e2e
//! benchmarks: seeded probabilistic loss and reordering with virtual
//! time. Same seed + same driver loop = identical delivery schedule,
//! so impairment goodput is a deterministic number, not a sample.
//!
//! Ported from the `MultipathNet` shape in
//! tests/e2e/mock_transport_stream_exchange.zig, with probabilistic
//! (rather than scripted) loss and delivery in release-time order so
//! reordering actually reorders.

const std = @import("std");
const quic_zig = @import("quic_zig");

pub const Options = struct {
    seed: u64,
    /// Per-packet drop probability in permille (50 = 5%).
    loss_permille: u16 = 0,
    /// Probability that a packet is held back an extra
    /// `reorder_extra_us`, letting later packets overtake it.
    reorder_permille: u16 = 0,
    base_delay_us: u64 = 1_000,
    reorder_extra_us: u64 = 5_000,
    /// Bottleneck link rate in bytes/second, 0 = unlimited (the
    /// historical behavior: every packet takes exactly base_delay).
    ///
    /// With a rate set, the link serializes packets: a packet arriving
    /// while the link is busy waits, so its delay grows with the
    /// standing queue. That queueing delay is what inflates RTT under
    /// an overshooting sender — the signal RFC 9406 HyStart++ exists
    /// to detect, and the reason a pure fixed-delay sim cannot
    /// evaluate slow-start exit at all.
    bottleneck_bytes_per_s: u64 = 0,
    /// Tail-drop threshold: a packet that would wait longer than this
    /// for the link finds the queue full and is dropped. Models a
    /// finite router buffer.
    max_queue_delay_us: u64 = 100_000,
};

const Packet = struct {
    bytes: []u8,
    from_client: bool,
    release_us: u64,
    seq: u64,
};

pub const SimNet = struct {
    allocator: std.mem.Allocator,
    prng: std.Random.DefaultPrng,
    opts: Options,
    queue: std.ArrayList(Packet) = .empty,
    next_seq: u64 = 0,
    enqueued: u64 = 0,
    dropped: u64 = 0,
    delivered: u64 = 0,
    delivered_bytes_hash: u64 = 0,
    /// When the bottleneck link finishes transmitting everything
    /// already queued (bottleneck model only).
    link_free_at_us: u64 = 0,
    /// Packets tail-dropped because the bottleneck queue was full.
    queue_dropped: u64 = 0,
    /// Largest queueing delay any delivered packet experienced.
    peak_queue_delay_us: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, opts: Options) SimNet {
        return .{
            .allocator = allocator,
            .prng = std.Random.DefaultPrng.init(opts.seed),
            .opts = opts,
        };
    }

    pub fn deinit(self: *SimNet) void {
        for (self.queue.items) |pkt| self.allocator.free(pkt.bytes);
        self.queue.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn enqueue(self: *SimNet, from_client: bool, bytes: []const u8, now_us: u64) !void {
        self.enqueued += 1;
        const random = self.prng.random();
        const loss_roll = random.uintLessThan(u16, 1000);
        const reorder_roll = random.uintLessThan(u16, 1000);
        if (loss_roll < self.opts.loss_permille) {
            self.dropped += 1;
            return;
        }
        var delay = self.opts.base_delay_us;
        if (reorder_roll < self.opts.reorder_permille) delay += self.opts.reorder_extra_us;

        // Bottleneck serialization. Only the data direction contends
        // for the link; ACKs are small enough that modelling them adds
        // noise rather than realism.
        if (self.opts.bottleneck_bytes_per_s != 0 and from_client) {
            const start_tx = @max(now_us, self.link_free_at_us);
            const queue_delay = start_tx - now_us;
            if (queue_delay > self.opts.max_queue_delay_us) {
                // Buffer full: tail drop.
                self.dropped += 1;
                self.queue_dropped += 1;
                return;
            }
            const tx_us = std.math.lossyCast(
                u64,
                (@as(u128, bytes.len) * std.time.us_per_s) / self.opts.bottleneck_bytes_per_s,
            );
            self.link_free_at_us = start_tx +| tx_us;
            delay += queue_delay + tx_us;
            if (queue_delay > self.peak_queue_delay_us) {
                self.peak_queue_delay_us = queue_delay;
            }
        }

        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.queue.append(self.allocator, .{
            .bytes = copy,
            .from_client = from_client,
            .release_us = now_us + delay,
            .seq = self.next_seq,
        });
        self.next_seq += 1;
    }

    /// Delivers every due packet in (release_us, seq) order — linear
    /// scans are fine at BDP-bounded queue sizes.
    pub fn deliverDue(
        self: *SimNet,
        client: *quic_zig.Connection,
        server: *quic_zig.Connection,
        now_us: u64,
    ) !void {
        while (true) {
            var best: ?usize = null;
            for (self.queue.items, 0..) |pkt, i| {
                if (pkt.release_us > now_us) continue;
                if (best) |b| {
                    const cur = self.queue.items[b];
                    if (pkt.release_us < cur.release_us or
                        (pkt.release_us == cur.release_us and pkt.seq < cur.seq))
                    {
                        best = i;
                    }
                } else {
                    best = i;
                }
            }
            const idx = best orelse return;
            const pkt = self.queue.swapRemove(idx);
            defer self.allocator.free(pkt.bytes);
            self.delivered += 1;
            self.delivered_bytes_hash = std.hash.Wyhash.hash(self.delivered_bytes_hash, pkt.bytes);
            if (pkt.from_client) {
                try server.handle(pkt.bytes, null, now_us);
            } else {
                try client.handle(pkt.bytes, null, now_us);
            }
        }
    }

    /// Earliest pending release time, for driver loops that want to
    /// skip virtual time forward instead of spinning.
    pub fn earliestRelease(self: *const SimNet) ?u64 {
        var earliest: ?u64 = null;
        for (self.queue.items) |pkt| {
            if (earliest == null or pkt.release_us < earliest.?) earliest = pkt.release_us;
        }
        return earliest;
    }
};

test "same seed produces the identical loss/reorder schedule" {
    // Drive two SimNets with the same seed through the same enqueue
    // pattern (no Connections involved: deliver into counters via the
    // stats fields) and require identical drop decisions and delivery
    // hashing. This is the determinism property the impairment
    // benchmark's comparability rests on.
    const allocator = std.testing.allocator;

    var payload: [64]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);

    var results: [2]struct { dropped: u64, order_hash: u64 } = undefined;
    for (&results) |*result| {
        var net = SimNet.init(allocator, .{
            .seed = 0xbe9c4,
            .loss_permille = 100,
            .reorder_permille = 200,
        });
        defer net.deinit();

        var now_us: u64 = 0;
        var i: u64 = 0;
        while (i < 500) : (i += 1) {
            payload[0] = @intCast(i & 0xff);
            try net.enqueue(i % 2 == 0, &payload, now_us);
            now_us += 137;
        }
        // Drain by hand in release order, mirroring deliverDue's
        // selection, hashing the delivery order.
        var order_hash: u64 = 0;
        now_us += 10_000;
        while (net.queue.items.len != 0) {
            var best: usize = 0;
            for (net.queue.items, 0..) |pkt, j| {
                const cur = net.queue.items[best];
                if (pkt.release_us < cur.release_us or
                    (pkt.release_us == cur.release_us and pkt.seq < cur.seq))
                {
                    best = j;
                }
            }
            const pkt = net.queue.swapRemove(best);
            order_hash = std.hash.Wyhash.hash(order_hash +% pkt.seq, pkt.bytes);
            allocator.free(pkt.bytes);
        }
        result.* = .{ .dropped = net.dropped, .order_hash = order_hash };
    }

    try std.testing.expect(results[0].dropped > 0);
    try std.testing.expectEqual(results[0].dropped, results[1].dropped);
    try std.testing.expectEqual(results[0].order_hash, results[1].order_hash);
}

test "reorder delay lets later packets overtake" {
    const allocator = std.testing.allocator;
    var net = SimNet.init(allocator, .{
        .seed = 7,
        .loss_permille = 0,
        .reorder_permille = 1000, // every packet gets the extra delay...
        .reorder_extra_us = 5_000,
    });
    defer net.deinit();

    // ...except we enqueue the second packet with reorder disabled by
    // flipping the option between calls: packet A (t=0, +5ms) releases
    // at 6ms; packet B (t=100us, base only) releases at 1.1ms — B
    // overtakes A.
    try net.enqueue(true, "AAAA", 0);
    net.opts.reorder_permille = 0;
    try net.enqueue(true, "BBBB", 100);

    try std.testing.expectEqual(@as(?u64, 1_100), net.earliestRelease());
    try std.testing.expectEqual(@as(u64, 0), net.dropped);
}

test "bottleneck link serializes packets and builds a standing queue" {
    const allocator = std.testing.allocator;
    // 1 MB/s link: a 1000-byte packet takes 1000 us to transmit.
    var net = SimNet.init(allocator, .{
        .seed = 1,
        .bottleneck_bytes_per_s = 1_000_000,
        .base_delay_us = 1_000,
    });
    defer net.deinit();

    var payload: [1000]u8 = undefined;
    @memset(&payload, 0xab);

    // Three back-to-back packets at t=0: the first goes out
    // immediately, the others wait 1 ms and 2 ms for the link.
    try net.enqueue(true, &payload, 0);
    try net.enqueue(true, &payload, 0);
    try net.enqueue(true, &payload, 0);
    try std.testing.expectEqual(@as(usize, 3), net.queue.items.len);
    // release = base_delay + queue_delay + tx_time
    try std.testing.expectEqual(@as(u64, 2_000), net.queue.items[0].release_us);
    try std.testing.expectEqual(@as(u64, 3_000), net.queue.items[1].release_us);
    try std.testing.expectEqual(@as(u64, 4_000), net.queue.items[2].release_us);
    try std.testing.expectEqual(@as(u64, 2_000), net.peak_queue_delay_us);
    try std.testing.expectEqual(@as(u64, 0), net.queue_dropped);
}

test "bottleneck tail-drops once the queue exceeds its depth" {
    const allocator = std.testing.allocator;
    var net = SimNet.init(allocator, .{
        .seed = 1,
        .bottleneck_bytes_per_s = 1_000_000,
        .max_queue_delay_us = 5_000,
    });
    defer net.deinit();

    var payload: [1000]u8 = undefined;
    @memset(&payload, 0xcd);
    // Each packet adds 1 ms of queue; past 5 ms of standing queue the
    // rest are tail-dropped rather than queued forever.
    var i: u32 = 0;
    while (i < 20) : (i += 1) try net.enqueue(true, &payload, 0);
    try std.testing.expect(net.queue_dropped > 0);
    try std.testing.expectEqual(net.queue_dropped, net.dropped);
    try std.testing.expect(net.queue.items.len < 20);
}

test "no bottleneck configured keeps the fixed-delay behavior" {
    const allocator = std.testing.allocator;
    var net = SimNet.init(allocator, .{ .seed = 1, .base_delay_us = 1_000 });
    defer net.deinit();
    var payload: [1000]u8 = undefined;
    @memset(&payload, 0x01);
    try net.enqueue(true, &payload, 0);
    try net.enqueue(true, &payload, 0);
    // Both release at the same instant: no serialization.
    try std.testing.expectEqual(@as(u64, 1_000), net.queue.items[0].release_us);
    try std.testing.expectEqual(@as(u64, 1_000), net.queue.items[1].release_us);
    try std.testing.expectEqual(@as(u64, 0), net.peak_queue_delay_us);
}
