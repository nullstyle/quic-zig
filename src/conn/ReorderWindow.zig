//! A late packet is not a lost packet. This is the sender's memory of
//! the packets it declared lost, and the loss thresholds it widens when
//! one of them turns out to have arrived.
//!
//! RFC 9002 §6.1 fixes the thresholds at 3 packets and 9/8 of the RTT,
//! and says in the same section that a sender MAY widen them when it
//! finds a loss was spurious ("algorithms that increase the reordering
//! threshold after spuriously detecting losses, such as RACK, have
//! proven to be useful in TCP and are expected to be at least as useful
//! in QUIC"). MEASURED 2026-10-03 (`impairment_reorder10pct`: nothing
//! dropped, 10% of the packets 5 ms late on a 2 ms path): with the
//! fixed thresholds 10.4% of the packets were declared lost although
//! every one arrived, and every controller saw a path with 10% loss.
//!
//! The rule, after Chromium's `GeneralLossAlgorithm` (its adaptive
//! packet threshold has shipped on by default for years):
//!
//! - A packet declared lost is remembered here: its number, its send
//!   time, and the controller's loss episode it was counted in.
//! - An ACK that covers a remembered packet is a spurious loss: the
//!   packet arrived. The packet threshold grows to one more than the
//!   distance the packet trailed the largest acknowledged packet, and
//!   the time threshold grows (9/8 -> 5/4 -> 3/2 -> 2 times the RTT)
//!   until it would have covered how late the packet was.
//! - The thresholds only grow, for the life of the connection; the
//!   packet threshold stops at `max_packet_threshold`, the time
//!   threshold at twice the RTT (where RACK's window stops too). A
//!   real loss is still found: by the time threshold within two
//!   round trips at the widest, and by the probe timeout always.
//!
//! The memory is a ring of `ring_slots` records, allocated at the
//! first loss (a connection that loses nothing pays nothing) and
//! released with the tracker. When it is full the oldest record is
//! forgotten; a spurious loss that is forgotten before its ACK comes
//! costs nothing but the adaptation it would have caused.
//!
//! The controller's reaction to a spurious episode is taken back by
//! the controller (`onSpuriousLoss`); this module only tells it.

const ReorderWindow = @This();

const std = @import("std");
const RttEstimator = @import("RttEstimator.zig").RttEstimator;
const granularity_us = @import("RttEstimator.zig").granularity_us;

/// kPacketThreshold from RFC 9002 §6.1.1: 3. The starting point.
pub const initial_packet_threshold: u64 = 3;
/// The widest packet threshold: the most packets a space holds in
/// flight (`SentPacketTracker.max_tracked`), so no distance a tracked
/// packet can trail by is out of reach. Chromium has no cap either. A
/// wide packet threshold costs nothing on a path without reordering
/// (nothing trails), and on one with it the time threshold still finds
/// a real loss within twice the RTT. MEASURED: the 1 ms reorder cell
/// sends 300 packets a tick in Startup, so 1 ms of reordering there
/// is more than 256 packets.
pub const max_packet_threshold: u64 = 4096;
/// The time threshold is `rtt + (rtt >> time_shift)`: 3 is RFC 9002's
/// 9/8, 0 is twice the RTT.
pub const initial_time_shift: u2 = 3;
/// Records the ring holds. Sized with `max_packet_threshold`: a burst
/// of that many packets declared lost at once fits.
pub const ring_slots: usize = 256;

/// One packet declared lost.
pub const LostRecord = struct {
    pn: u64,
    sent_time_us: u64,
    /// The controller's loss episode this packet was counted in, from
    /// `stampLast`; a spurious loss from an older episode widens the
    /// thresholds but takes nothing back.
    episode: u32 = 0,
};

/// A record whose packet was found to have arrived, or whose slot was
/// never filled.
const tombstone_pn: u64 = std.math.maxInt(u64);

/// The ring, `ring_slots` long once allocated; empty before the first
/// loss.
records: []LostRecord = &.{},
/// Index of the oldest record.
head: u32 = 0,
/// Records in the ring, tombstones included.
len: u32 = 0,
/// Records in the ring that are not tombstones. Zero means an ACK has
/// nothing to look for.
live: u32 = 0,

/// The current packet threshold (RFC 9002 §6.1.1), widened by
/// `widen`.
packet_threshold: u64 = initial_packet_threshold,
/// The current time threshold shift (see `timeThresholdUs`), widened
/// by `widen`.
time_shift: u2 = initial_time_shift,
/// Packets declared lost that arrived, for the life of the window.
spurious_count: u64 = 0,

/// RFC 9002 §6.1.2 time threshold at the current width:
/// `max(rtt + (rtt >> time_shift), kGranularity)` over `max(latest_rtt,
/// smoothed_rtt)`. At the initial shift this is the RFC's 9/8 exactly
/// (`r + r/8 == 9r/8` in integers).
pub fn timeThresholdUs(self: *const ReorderWindow, rtt_est: *const RttEstimator) u64 {
    const reference_rtt = @max(rtt_est.latest_rtt_us, rtt_est.smoothed_rtt_us);
    return @max(reference_rtt +| (reference_rtt >> self.time_shift), granularity_us);
}

/// Remember a packet declared lost. The ring is allocated here at the
/// first loss; if that fails the loss is not remembered, which costs
/// only the adaptation it could have caused.
pub fn remember(self: *ReorderWindow, allocator: std.mem.Allocator, pn: u64, sent_time_us: u64) void {
    if (self.records.len == 0) {
        self.records = allocator.alloc(LostRecord, ring_slots) catch return;
    }
    const cap: u32 = @intCast(self.records.len);
    if (self.len == cap) {
        // Full: the oldest record goes.
        if (self.records[self.head].pn != tombstone_pn) self.live -= 1;
        self.head = (self.head + 1) % cap;
        self.len -= 1;
    }
    self.records[(self.head + self.len) % cap] = .{ .pn = pn, .sent_time_us = sent_time_us };
    self.len += 1;
    self.live += 1;
}

/// Stamp the newest `n` records with the controller's loss episode,
/// once the controller has been told about the sweep that produced
/// them (the episode may have opened in that call).
pub fn stampLast(self: *ReorderWindow, n: u32, episode: u32) void {
    const cap: u32 = @intCast(self.records.len);
    if (cap == 0) return;
    var i: u32 = @min(n, self.len);
    while (i > 0) : (i -= 1) {
        const idx = (self.head + self.len - i) % cap;
        self.records[idx].episode = episode;
    }
}

/// Find the remembered packets an ACK range covers: for each one,
/// `callback(context, record)` runs and the record is forgotten (an
/// ACK range that is repeated in the next ACK frame finds nothing the
/// second time). Returns how many were found.
pub fn takeCovered(
    self: *ReorderWindow,
    smallest: u64,
    largest: u64,
    context: anytype,
    comptime callback: fn (@TypeOf(context), LostRecord) void,
) u32 {
    if (self.live == 0) return 0;
    const cap: u32 = @intCast(self.records.len);
    var found: u32 = 0;
    var i: u32 = 0;
    while (i < self.len) : (i += 1) {
        const rec = &self.records[(self.head + i) % cap];
        if (rec.pn == tombstone_pn) continue;
        if (rec.pn < smallest or rec.pn > largest) continue;
        const copy = rec.*;
        rec.pn = tombstone_pn;
        self.live -= 1;
        found += 1;
        callback(context, copy);
    }
    if (self.live == 0) {
        self.head = 0;
        self.len = 0;
    }
    return found;
}

/// Widen the thresholds so that the spurious loss `rec` would not have
/// been declared: the packet threshold to one past the distance the
/// packet trailed `previous_largest_acked` (the largest acknowledged
/// packet before the ACK that covered it), the time threshold until it
/// covers how late the packet's ACK was, each within its cap.
pub fn widen(
    self: *ReorderWindow,
    rec: LostRecord,
    previous_largest_acked: ?u64,
    now_us: u64,
    rtt_est: *const RttEstimator,
) void {
    self.spurious_count += 1;
    // Only for a packet the widest thresholds could have covered. A
    // packet later than twice the RTT is declared lost at any width
    // (the time threshold stops there), so widening for it would only
    // move its detection from the prompt packet rule to the slower
    // time rule and send its copy later. MEASURED (10% of the packets
    // 5 ms late on a 2 ms path, 2.5 round trips): with the thresholds
    // widened for such packets the BBR transfer is 12 times slower in
    // the median; left alone, the copy arrives before the original.
    const needed = now_us -| rec.sent_time_us;
    const reference_rtt = @max(rtt_est.latest_rtt_us, rtt_est.smoothed_rtt_us);
    if (needed > reference_rtt +| reference_rtt) return;
    if (previous_largest_acked) |la| {
        if (la > rec.pn) {
            const distance = la - rec.pn;
            self.packet_threshold = @max(
                self.packet_threshold,
                @min(distance + 1, max_packet_threshold),
            );
        }
    }
    while (self.time_shift > 0 and
        reference_rtt +| (reference_rtt >> self.time_shift) < needed) : (self.time_shift -= 1)
    {}
}

/// Release the ring. The thresholds stay as they are.
pub fn release(self: *ReorderWindow, allocator: std.mem.Allocator) void {
    if (self.records.len != 0) allocator.free(self.records);
    self.records = &.{};
    self.head = 0;
    self.len = 0;
    self.live = 0;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

const Collector = struct {
    pns: [16]u64 = undefined,
    n: usize = 0,
    fn add(self: *Collector, rec: LostRecord) void {
        self.pns[self.n] = rec.pn;
        self.n += 1;
    }
};

test "nothing is allocated until the first loss, and an ACK over an empty memory finds nothing" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    try testing.expectEqual(@as(usize, 0), w.records.len);
    var c: Collector = .{};
    try testing.expectEqual(@as(u32, 0), w.takeCovered(0, 1000, &c, Collector.add));
    try testing.expectEqual(@as(usize, 0), c.n);
}

test "a remembered packet is found once by the ACK range that covers it" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    w.remember(testing.allocator, 10, 1000);
    w.remember(testing.allocator, 12, 1200);
    w.remember(testing.allocator, 30, 3000);
    try testing.expectEqual(@as(usize, ring_slots), w.records.len);
    try testing.expectEqual(@as(u32, 3), w.live);

    var c: Collector = .{};
    try testing.expectEqual(@as(u32, 2), w.takeCovered(10, 20, &c, Collector.add));
    try testing.expectEqual(@as(usize, 2), c.n);
    try testing.expectEqual(@as(u64, 10), c.pns[0]);
    try testing.expectEqual(@as(u64, 12), c.pns[1]);
    // The same range again: nothing (the records are gone).
    try testing.expectEqual(@as(u32, 0), w.takeCovered(10, 20, &c, Collector.add));
    try testing.expectEqual(@as(u32, 1), w.live);
    // The last one; the ring is then empty and reset.
    try testing.expectEqual(@as(u32, 1), w.takeCovered(30, 30, &c, Collector.add));
    try testing.expectEqual(@as(u32, 0), w.live);
    try testing.expectEqual(@as(u32, 0), w.len);
}

test "a full ring forgets the oldest record, and keeps its live count right" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    var pn: u64 = 0;
    while (pn < ring_slots + 10) : (pn += 1) w.remember(testing.allocator, pn, pn);
    try testing.expectEqual(@as(u32, ring_slots), w.len);
    try testing.expectEqual(@as(u32, ring_slots), w.live);
    var c: Collector = .{};
    // The first 10 are forgotten.
    try testing.expectEqual(@as(u32, 0), w.takeCovered(0, 9, &c, Collector.add));
    // 10 and 11 are there.
    try testing.expectEqual(@as(u32, 2), w.takeCovered(10, 11, &c, Collector.add));
    try testing.expectEqual(@as(u32, ring_slots - 2), w.live);
    // Two more pushes take the two oldest slots, which hold the
    // tombstones of 10 and 11: nothing live is forgotten.
    w.remember(testing.allocator, 1000, 1000);
    w.remember(testing.allocator, 1001, 1001);
    try testing.expectEqual(@as(u32, ring_slots), w.live);
    try testing.expectEqual(@as(u32, 2), w.takeCovered(12, 13, &c, Collector.add));
    try testing.expectEqual(@as(u32, 2), w.takeCovered(1000, 1001, &c, Collector.add));
    try testing.expectEqual(@as(u32, ring_slots - 4), w.live);
    // Four more: the first two take the tombstones of 12 and 13, the
    // next two forget 14 and 15, which were live.
    w.remember(testing.allocator, 1002, 1002);
    w.remember(testing.allocator, 1003, 1003);
    w.remember(testing.allocator, 1004, 1004);
    w.remember(testing.allocator, 1005, 1005);
    try testing.expectEqual(@as(u32, ring_slots - 2), w.live);
    try testing.expectEqual(@as(u32, 0), w.takeCovered(14, 15, &c, Collector.add));
    try testing.expectEqual(@as(u32, 2), w.takeCovered(16, 17, &c, Collector.add));
    try testing.expectEqual(@as(u32, 4), w.takeCovered(1002, 1005, &c, Collector.add));
}

test "stampLast marks the newest records with the episode" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    w.stampLast(5, 7); // nothing allocated: a no-op
    w.remember(testing.allocator, 1, 1);
    w.remember(testing.allocator, 2, 2);
    w.remember(testing.allocator, 3, 3);
    w.stampLast(2, 9);
    const cap = w.records.len;
    try testing.expectEqual(@as(u32, 0), w.records[(w.head + 0) % cap].episode);
    try testing.expectEqual(@as(u32, 9), w.records[(w.head + 1) % cap].episode);
    try testing.expectEqual(@as(u32, 9), w.records[(w.head + 2) % cap].episode);
    // More than the ring holds: clamped.
    w.stampLast(100, 4);
    try testing.expectEqual(@as(u32, 4), w.records[(w.head + 0) % cap].episode);
}

test "the thresholds start at RFC 9002's and widen to what the spurious loss needed" {
    var w: ReorderWindow = .{};
    var rtt: RttEstimator = .{};
    rtt.latest_rtt_us = 2000;
    rtt.smoothed_rtt_us = 2000;
    try testing.expectEqual(@as(u64, 3), w.packet_threshold);
    try testing.expectEqual(@as(u64, 2250), w.timeThresholdUs(&rtt)); // 9/8

    // A packet 40 behind the largest acked, acked 2.5 ms after it was
    // sent: the packet threshold goes to 41, the time threshold to 5/4
    // (2500 >= 2500).
    w.widen(.{ .pn = 100, .sent_time_us = 10_000 }, 140, 12_500, &rtt);
    try testing.expectEqual(@as(u64, 41), w.packet_threshold);
    try testing.expectEqual(@as(u2, 2), w.time_shift);
    try testing.expectEqual(@as(u64, 2500), w.timeThresholdUs(&rtt));
    try testing.expectEqual(@as(u64, 1), w.spurious_count);

    // A smaller reordering changes nothing: the thresholds only grow.
    w.widen(.{ .pn = 200, .sent_time_us = 20_000 }, 210, 22_100, &rtt);
    try testing.expectEqual(@as(u64, 41), w.packet_threshold);
    try testing.expectEqual(@as(u2, 2), w.time_shift);

    // 5 ms late on a 2 ms path: past the widest setting (twice the
    // RTT), so nothing moves: no width could have covered this
    // packet, and widening for it would only delay the copy.
    w.widen(.{ .pn = 300, .sent_time_us = 30_000 }, 400, 37_000, &rtt);
    try testing.expectEqual(@as(u2, 2), w.time_shift);
    try testing.expectEqual(@as(u64, 41), w.packet_threshold);
    // 3.9 ms late: within reach, and the threshold goes to its widest.
    w.widen(.{ .pn = 310, .sent_time_us = 31_000, .episode = 0 }, 311, 34_900, &rtt);
    try testing.expectEqual(@as(u2, 0), w.time_shift);
    try testing.expectEqual(@as(u64, 4000), w.timeThresholdUs(&rtt));
    // Exactly twice the RTT late: still within reach (no change left).
    w.widen(.{ .pn = 320, .sent_time_us = 32_000 }, 321, 36_000, &rtt);
    try testing.expectEqual(@as(u2, 0), w.time_shift);

    // The packet threshold has a cap too.
    w.widen(.{ .pn = 400, .sent_time_us = 40_000 }, 40_000, 40_001, &rtt);
    try testing.expectEqual(max_packet_threshold, w.packet_threshold);
    // No largest-acked (nothing acked before): only the time rule runs.
    w.widen(.{ .pn = 500, .sent_time_us = 50_000 }, null, 50_001, &rtt);
    try testing.expectEqual(max_packet_threshold, w.packet_threshold);
    try testing.expectEqual(@as(u64, 7), w.spurious_count);
}

test "the time threshold keeps the granularity floor at every width" {
    var w: ReorderWindow = .{};
    var rtt: RttEstimator = .{};
    rtt.latest_rtt_us = 100;
    rtt.smoothed_rtt_us = 100;
    try testing.expectEqual(granularity_us, w.timeThresholdUs(&rtt));
    w.time_shift = 0;
    try testing.expectEqual(granularity_us, w.timeThresholdUs(&rtt));
}
