//! Packet pacing (RFC 9002 §7.7): a token bucket that spreads sends
//! across the RTT instead of bursting a full congestion window into
//! the network.
//!
//! One `Pacer` per path, by value next to the congestion controller.
//! The design constraints, in order of importance:
//!
//!  1. NEVER blocks and never sleeps — the send path asks `canSend`
//!     and, when short, the connection surfaces "earliest send time"
//!     through `nextTimerDeadline` (`TimerKind.pacing`). Caller-drives
//!     embedders that ignore pacing simply see `pollDatagram` return
//!     null until their next wake; the packaged loops park on the
//!     deadline.
//!  2. Exempt sends (PTO probes, CONNECTION_CLOSE, ACK-only, path
//!     probes) bypass the gate but still DEBIT the bucket — tokens go
//!     negative and delay the next data send, keeping the rate
//!     accounting truthful.
//!  3. Burst capacity scales with the wake granularity: a fixed
//!     10-packet bucket under a 1–5 ms loop would clamp throughput to
//!     bucket/wake-interval. Capacity is
//!     `max(10 × MSS, rate × granularity)` (a 1 ms quantum of line
//!     rate), so coarse loops sustain any rate while the worst-case
//!     burst stays ≤ 1 ms of line rate — the "lumpy pacing" approach.
//!
//! Rate: supplied by the congestion controller (`pacingRateBps` on
//! the union). Loss-based controllers use `rateBytesPerSecond` below —
//! `gain × cwnd / srtt`, gain 2.0 in slow start (pacing must never
//! throttle exponential growth) and 1.25 in congestion avoidance
//! (RFC 9002 §7.7's N); rate-based controllers (BBR) supply the rate
//! from their bandwidth model instead. srtt is pre-seeded by the RTT
//! estimator (333 ms initial), so the loss-based rate is always
//! finite; before the first sample the initial-window burst capacity
//! dominates anyway.

const std = @import("std");

/// RFC 9002 §7.7: allow the initial congestion window as a burst.
pub const burst_packets: u64 = 10;
/// Pacing gain while in slow start (2.0).
pub const gain_num_ss: u64 = 2;
pub const gain_den_ss: u64 = 1;
/// Pacing gain in congestion avoidance (1.25 — §7.7's N).
pub const gain_num_ca: u64 = 5;
pub const gain_den_ca: u64 = 4;
/// Lumpy-release quantum: one bucket refill covers this much line
/// rate, so loops waking at millisecond granularity sustain full rate.
pub const granularity_us: u64 = 1_000;

/// Pacing rate in bytes/second for the given controller state. srtt
/// is floored at the RFC 9002 kGranularity (1 ms) — a zero or sub-ms
/// estimate (loopback, in-process tests) paces at cwnd-per-millisecond
/// instead of degenerating into an unbounded rate.
pub fn rateBytesPerSecond(cwnd: u64, srtt_us: u64, slow_start: bool) u64 {
    const srtt = @max(srtt_us, granularity_us);
    const num: u64 = if (slow_start) gain_num_ss else gain_num_ca;
    const den: u64 = if (slow_start) gain_den_ss else gain_den_ca;
    const scaled = (@as(u128, cwnd) * num * std.time.us_per_s) / (@as(u128, den) * srtt);
    return std.math.lossyCast(u64, scaled);
}

/// Bucket capacity in bytes: the §7.7 initial-window burst floor, or
/// one `granularity_us` quantum of line rate, whichever is larger.
pub fn bucketCapacity(rate_bytes_per_s: u64, mds: u64) u64 {
    const quantum = std.math.lossyCast(
        u64,
        (@as(u128, rate_bytes_per_s) * granularity_us) / std.time.us_per_s,
    );
    return @max(burst_packets * mds, quantum);
}

pub const Pacer = struct {
    /// Available send credit in bytes. NEGATIVE = debt left behind by
    /// exempt sends (probes, close, ACK-only) that bypass the gate.
    tokens: i64 = 0,
    last_refill_us: u64 = 0,
    /// First use seeds a full bucket (the §7.7 initial burst).
    primed: bool = false,

    /// Bring the bucket up to date at `now_us` for the given pacing
    /// rate. Call before `canSend`/`consume` on the send path; refill
    /// is lazy — there is no timer-driven upkeep. The rate comes from
    /// the congestion controller (`pacingRateBps`): loss-based
    /// controllers derive it as gain x cwnd / srtt via
    /// `rateBytesPerSecond`; rate-based controllers supply their own
    /// bandwidth-model rate. The bucket itself is rate-agnostic.
    pub fn refill(
        self: *Pacer,
        now_us: u64,
        rate_bytes_per_s: u64,
        mds: u64,
    ) void {
        const rate = rate_bytes_per_s;
        const capacity = std.math.lossyCast(i64, bucketCapacity(rate, mds));
        if (!self.primed) {
            self.primed = true;
            self.last_refill_us = now_us;
            self.tokens = capacity;
            return;
        }
        const elapsed = now_us -| self.last_refill_us;
        self.last_refill_us = now_us;
        if (elapsed != 0) {
            const add = std.math.lossyCast(
                i64,
                (@as(u128, rate) * elapsed) / std.time.us_per_s,
            );
            self.tokens = self.tokens +| add;
        }
        if (self.tokens > capacity) self.tokens = capacity;
    }

    /// Is there credit for a `bytes`-sized datagram right now?
    pub fn canSend(self: *const Pacer, bytes: u64) bool {
        return self.tokens >= std.math.lossyCast(i64, bytes);
    }

    /// Debit `bytes`. May push the bucket negative (exempt sends).
    pub fn consume(self: *Pacer, bytes: u64) void {
        self.tokens -|= std.math.lossyCast(i64, bytes);
    }

    /// Earliest time a `bytes`-sized datagram will have credit at the
    /// given pacing rate — WITHOUT mutating the bucket (safe from
    /// `nextTimerDeadline`'s const walk). Returns null when it is
    /// ready now (or the pacer has never been used).
    pub fn nextReadyUs(
        self: *const Pacer,
        now_us: u64,
        bytes: u64,
        rate_bytes_per_s: u64,
        mds: u64,
    ) ?u64 {
        if (!self.primed) return null;
        const rate = rate_bytes_per_s;
        const capacity = std.math.lossyCast(i64, bucketCapacity(rate, mds));
        // Project the lazy refill forward from last_refill_us.
        const elapsed = now_us -| self.last_refill_us;
        const accrued = std.math.lossyCast(i64, (@as(u128, rate) * elapsed) / std.time.us_per_s);
        const effective = @min(self.tokens +| accrued, capacity);
        const need = std.math.lossyCast(i64, bytes);
        if (effective >= need) return null;
        if (rate == 0) return null; // degenerate; treat as unpaced
        const deficit: u128 = @intCast(need - effective);
        const wait_us = std.math.lossyCast(u64, (deficit * std.time.us_per_s) / rate);
        return now_us +| @max(wait_us, 1);
    }
};

// -- tests -------------------------------------------------------------------

const testing = std.testing;

test "rate follows gain x cwnd / srtt with the slow-start boost" {
    // cwnd 125_000 B, srtt 100 ms: base rate 1.25 MB/s; CA gain 1.25x
    // -> 1_562_500 B/s; SS gain 2x -> 2_500_000 B/s.
    try testing.expectEqual(@as(u64, 1_562_500), rateBytesPerSecond(125_000, 100_000, false));
    try testing.expectEqual(@as(u64, 2_500_000), rateBytesPerSecond(125_000, 100_000, true));
    // Zero/sub-ms srtt floors at kGranularity (1 ms): cwnd/ms pace.
    try testing.expectEqual(@as(u64, 156_250_000), rateBytesPerSecond(125_000, 0, false));
    try testing.expectEqual(
        rateBytesPerSecond(125_000, granularity_us, false),
        rateBytesPerSecond(125_000, 500, false),
    );
}

test "bucket capacity: initial-window floor vs line-rate quantum" {
    // Low rate: the 10-packet floor wins.
    try testing.expectEqual(@as(u64, 12_000), bucketCapacity(1_000_000, 1200));
    // High rate (1 GB/s): the 1 ms quantum (1 MB) wins.
    try testing.expectEqual(@as(u64, 1_000_000), bucketCapacity(1_000_000_000, 1200));
}

test "first use seeds a full burst; steady state refills at the pacing rate" {
    var pacer: Pacer = .{};
    // 12_000-byte bucket (floor), rate 1.25 MB/s.
    const rate = rateBytesPerSecond(100_000, 100_000, false);
    pacer.refill(1_000_000, rate, 1200);
    try testing.expect(pacer.canSend(12_000));
    try testing.expect(!pacer.canSend(12_001));

    // Drain, then refill after exactly 1 ms: 1.25 MB/s x 1 ms = 1250 B.
    pacer.consume(12_000);
    try testing.expect(!pacer.canSend(1));
    pacer.refill(1_001_000, rate, 1200);
    try testing.expect(pacer.canSend(1250));
    try testing.expect(!pacer.canSend(1251));
}

test "exempt sends drive tokens negative and delay the next data send" {
    var pacer: Pacer = .{};
    const rate = rateBytesPerSecond(100_000, 100_000, false);
    pacer.refill(0, rate, 1200);
    pacer.consume(12_000); // drain the burst
    pacer.consume(2_400); // exempt send: two probe packets of debt
    try testing.expectEqual(@as(i64, -2_400), pacer.tokens);
    // Next 1200-byte send needs 3_600 bytes of credit at 1.25 MB/s
    // = 2_880 us.
    const ready = pacer.nextReadyUs(0, 1200, rate, 1200).?;
    try testing.expectEqual(@as(u64, 2_880), ready);
}

test "nextReadyUs projects the lazy refill without mutating" {
    var pacer: Pacer = .{};
    const rate = rateBytesPerSecond(100_000, 100_000, false);
    pacer.refill(0, rate, 1200);
    pacer.consume(12_000);
    const tokens_before = pacer.tokens;
    // 1 ms later, 1250 accrued credit is visible to the projection...
    const ready = pacer.nextReadyUs(1_000, 1250, rate, 1200);
    try testing.expectEqual(@as(?u64, null), ready);
    // ...but the bucket itself was untouched.
    try testing.expectEqual(tokens_before, pacer.tokens);
    // A bigger ask reports the residual wait from now.
    const later = pacer.nextReadyUs(1_000, 2_450, rate, 1200).?;
    try testing.expect(later > 1_000);
}

test "liveness: a paced sender sustains rate x T minus one bucket" {
    // Simulated 5 ms-granularity wake loop: at each wake, refill and
    // send full 1200-byte datagrams while credit lasts. Over 1 s the
    // cumulative bytes must be at least rate x T minus one bucket —
    // pacing must never starve a coarse loop.
    var pacer: Pacer = .{};
    const cwnd: u64 = 125_000;
    const srtt: u64 = 100_000;
    const rate = rateBytesPerSecond(cwnd, srtt, false);
    var sent: u64 = 0;
    var now: u64 = 0;
    while (now <= 1_000_000) : (now += 5_000) {
        pacer.refill(now, rate, 1200);
        while (pacer.canSend(1200)) {
            pacer.consume(1200);
            sent += 1200;
        }
    }
    const floor = rate - bucketCapacity(rate, 1200);
    try testing.expect(sent >= floor);
    // And never more than rate x T plus one bucket (no runaway).
    try testing.expect(sent <= rate + bucketCapacity(rate, 1200));
}
