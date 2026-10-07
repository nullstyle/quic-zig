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
//! - The packet threshold stops at `max_packet_threshold`, the time
//!   threshold at twice the RTT (where RACK's window stops too). A
//!   real loss is still found: by the time threshold within two
//!   round trips at the widest, and by the probe timeout always.
//! - The thresholds shrink back (since v0.32.0), after RFC 8985's
//!   rule for RACK's window (its section 6.2.3: the window grows on a
//!   DSACK and resets after 16 loss recoveries without one). A
//!   remembered loss whose packet is older than the reach (twice the
//!   RTT since its send) can never widen the thresholds again, so it
//!   is a settled, real loss. A round trip (by send time) with such
//!   losses counts once, a spurious hit restarts the count and its
//!   own round counts for nothing, and after `decay_after_rounds`
//!   clean rounds the thresholds go back to RFC 9002's. The rounds
//!   are the window's own, not the controller's loss episodes: BBR
//!   extends one recovery period at every later loss, so under
//!   steady loss its episode never ends (MEASURED 2026-10-07: with
//!   episodes counted the rule never fired for BBR). Nothing moves on
//!   a path that keeps reordering (a hit every few rounds) or never
//!   loses (no rounds).
//!   MEASURED 2026-10-06 (`impairment_reorder_then_loss_20ms`, a 15 ms
//!   reordering burst on a 20 ms path, then 0.5% loss): with the
//!   thresholds left at their widest the loss phase detected a loss
//!   after 45 ms on average, two RTTs; see the cell for the numbers
//!   with the decay.
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
/// Clean rounds with real losses in a row after which the thresholds
/// go back to RFC 9002's: RFC 8985's `RACK.reo_wnd_persist` (16 loss
/// recoveries).
pub const decay_after_rounds: u32 = 16;

/// One packet declared lost.
pub const LostRecord = struct {
    pn: u64,
    sent_time_us: u64,
    /// The controller's loss episode this packet was counted in, from
    /// `stampLast`; a spurious loss from an older episode widens the
    /// thresholds but takes nothing back.
    episode: u32 = 0,
    /// Older than the reach, so a real loss, counted toward the decay
    /// (`settle`); never counted twice.
    settled: bool = false,
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
/// Rounds with real losses settled, in a row since the last spurious
/// hit (`settle`); the thresholds go back at `decay_after_rounds`.
clean_rounds: u32 = 0,
/// The send time of the last settled loss that counted: a settled
/// loss sent within a round trip after it is of the same round.
last_counted_sent_us: ?u64 = null,
/// The send time of the last spurious hit's packet: a settled loss
/// sent within a round trip of it counts for nothing (the path
/// reordered in that round).
last_spurious_sent_us: ?u64 = null,
/// How often the thresholds went back, for the life of the window.
decays: u64 = 0,

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
    // The path reorders: the decay starts its count over, and the
    // settled losses of this round count for nothing.
    self.clean_rounds = 0;
    self.last_spurious_sent_us = rec.sent_time_us;
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

/// Settle the remembered losses the reach has passed: a record whose
/// packet is older than twice the RTT can never widen the thresholds
/// (`widen` ignores a later ACK), so it is a real loss. A round trip
/// of such losses (by send time) counts once, a round with a spurious
/// hit not at all, and after `decay_after_rounds` clean rounds in a
/// row the thresholds go back to RFC 9002's (the count starts over).
/// Called with every ACK of the space, before the ACK's ranges are
/// searched.
pub fn settle(self: *ReorderWindow, now_us: u64, rtt_est: *const RttEstimator) void {
    if (self.live == 0) return;
    const reference_rtt = @max(rtt_est.latest_rtt_us, rtt_est.smoothed_rtt_us);
    const reach = reference_rtt +| reference_rtt;
    const cap: u32 = @intCast(self.records.len);
    var i: u32 = 0;
    while (i < self.len) : (i += 1) {
        const rec = &self.records[(self.head + i) % cap];
        if (rec.pn == tombstone_pn or rec.settled) continue;
        // Records are remembered in declaration order, so the first
        // one inside the reach ends the settled prefix.
        if (now_us -| rec.sent_time_us <= reach) break;
        rec.settled = true;
        if (self.last_spurious_sent_us) |sp| {
            if (rec.sent_time_us <= sp +| reference_rtt and sp <= rec.sent_time_us +| reference_rtt) continue;
        }
        if (self.last_counted_sent_us) |lc| {
            if (rec.sent_time_us < lc +| reference_rtt) continue;
        }
        self.last_counted_sent_us = rec.sent_time_us;
        self.clean_rounds += 1;
        if (self.clean_rounds >= decay_after_rounds) {
            self.clean_rounds = 0;
            if (self.packet_threshold == initial_packet_threshold and self.time_shift == initial_time_shift) continue;
            self.packet_threshold = initial_packet_threshold;
            self.time_shift = initial_time_shift;
            self.decays += 1;
        }
    }
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

test "settled real losses count once per round trip, and sixteen clean rounds put the thresholds back" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    var rtt: RttEstimator = .{};
    rtt.latest_rtt_us = 2_000;
    rtt.smoothed_rtt_us = 2_000;
    // Widened by a spurious loss of a packet sent at 10 ms.
    w.remember(testing.allocator, 1, 10_000);
    w.widen(.{ .pn = 1, .sent_time_us = 10_000 }, 30, 12_500, &rtt);
    try testing.expectEqual(@as(u64, 30), w.packet_threshold);
    try testing.expectEqual(@as(u2, 2), w.time_shift);
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);

    // Sixteen rounds of real losses, 10 ms (five round trips) apart,
    // two records each sent 1 ms apart (the same round), every one
    // older than the reach (4 ms) when settled.
    var now: u64 = 100_000;
    var round: u32 = 1;
    while (round <= 16) : (round += 1) {
        w.remember(testing.allocator, 100 + round * 2, now);
        w.remember(testing.allocator, 101 + round * 2, now + 1_000);
        now += 10_000;
        // Within the reach: nothing settles yet.
        w.settle(now - 8_000, &rtt);
        try testing.expectEqual(round - 1, w.clean_rounds);
        // Past it: this round counts, once (two records).
        w.settle(now, &rtt);
        if (round < 16) try testing.expectEqual(round, w.clean_rounds);
    }
    // The sixteenth clean round put the thresholds back.
    try testing.expectEqual(initial_packet_threshold, w.packet_threshold);
    try testing.expectEqual(initial_time_shift, w.time_shift);
    try testing.expectEqual(@as(u64, 1), w.decays);
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);
    // Settling again changes nothing: the records are settled.
    w.settle(now + 100_000, &rtt);
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);
    // Sixteen more clean rounds at the RFC's thresholds: the count
    // wraps, nothing went back.
    round = 1;
    while (round <= 16) : (round += 1) {
        w.remember(testing.allocator, 200 + round, now);
        now += 10_000;
        w.settle(now, &rtt);
    }
    try testing.expectEqual(@as(u64, 1), w.decays);
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);
}

test "a spurious hit restarts the decay's count, and its own round counts for nothing" {
    var w: ReorderWindow = .{};
    defer w.release(testing.allocator);
    var rtt: RttEstimator = .{};
    rtt.latest_rtt_us = 2_000;
    rtt.smoothed_rtt_us = 2_000;
    // Ten clean rounds.
    var now: u64 = 100_000;
    var round: u32 = 1;
    while (round <= 10) : (round += 1) {
        w.remember(testing.allocator, round, now);
        now += 10_000;
        w.settle(now, &rtt);
    }
    try testing.expectEqual(@as(u32, 10), w.clean_rounds);
    // Round 11: of two packets sent 1 ms apart one arrives after all
    // (a hit), one is real.
    w.remember(testing.allocator, 50, now);
    w.remember(testing.allocator, 51, now + 1_000);
    w.widen(.{ .pn = 50, .sent_time_us = now }, 60, now + 2_500, &rtt);
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);
    now += 10_000;
    w.settle(now, &rtt);
    // The real one settles but counts for nothing: its round
    // reordered.
    try testing.expectEqual(@as(u32, 0), w.clean_rounds);
    // The next round counts again.
    w.remember(testing.allocator, 70, now);
    now += 10_000;
    w.settle(now, &rtt);
    try testing.expectEqual(@as(u32, 1), w.clean_rounds);
    try testing.expectEqual(@as(u64, 0), w.decays);
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
