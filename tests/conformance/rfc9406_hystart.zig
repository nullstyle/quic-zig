//! RFC 9406 — HyStart++: Modified Slow Start for TCP (applied to QUIC).
//!
//! Pins the slow-start-exit behavior quic implements in
//! `quic.conn.hystart`, shared by both congestion controllers.
//! The state machine's own edge cases are unit-tested next to the
//! implementation; this suite carries the RFC-traceable claims and
//! checks that both `NewReno` and `Cubic` honour them through the
//! `CongestionController` union.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9406 §4.2 ¶?  MUST     defaults are N_RTT_SAMPLE=8,
//!                             MIN_RTT_THRESH=4ms, MAX_RTT_THRESH=16ms,
//!                             MIN_RTT_DIVISOR=8, CSS_GROWTH_DIVISOR=4,
//!                             CSS_ROUNDS=5
//!   RFC9406 §4.2 ¶?  MUST     the inflation threshold is
//!                             clamp(lastRoundMinRTT/8, 4ms, 16ms)
//!   RFC9406 §4.2 ¶?  MUST     sustained inflation past the threshold
//!                             enters Conservative Slow Start
//!   RFC9406 §4.2 ¶?  MUST     cwnd growth in CSS is divided by
//!                             CSS_GROWTH_DIVISOR
//!   RFC9406 §4.2 ¶?  MUST     CSS_ROUNDS of sustained inflation exits
//!                             slow start (ssthresh = cwnd) without loss
//!   RFC9406 §4.2 ¶?  MUST     a round whose minRTT falls back below the
//!                             CSS baseline returns to standard slow start
//!   RFC9406 §4.3 ¶?  MUST NOT alter behavior once congestion avoidance
//!                             has been entered
//!
//! Out of scope here:
//!   RFC9406 §4.1 (the TCP-specific "limited slow start" interaction) —
//!   QUIC's sender is byte-based and quic applies HyStart++ on top
//!   of the RFC 9002 §7.3 slow-start branch directly.

const std = @import("std");
const quic = @import("quic");

const congestion = quic.conn.congestion;
const hystart = quic.conn.hystart;
const CongestionController = congestion.CongestionController;

/// Drive one full round of `samples` RTT observations at `rtt_us`,
/// closing the round with an ACK that covers its end marker.
fn round(state: *hystart.State, rtt_us: u64, samples: u32, idx: u64) bool {
    var i: u32 = 0;
    while (i < samples) : (i += 1) {
        _ = state.onAckProcessed(idx * 100, rtt_us, (idx + 1) * 100);
    }
    return state.onAckProcessed((idx + 1) * 100, rtt_us, (idx + 2) * 100);
}

test "MUST use the RFC-recommended default parameters [RFC9406 §4.2]" {
    const cfg: hystart.Config = .{};
    try std.testing.expectEqual(@as(u32, 8), cfg.n_rtt_sample);
    try std.testing.expectEqual(@as(u64, 4_000), cfg.min_rtt_thresh_us);
    try std.testing.expectEqual(@as(u64, 16_000), cfg.max_rtt_thresh_us);
    try std.testing.expectEqual(@as(u64, 8), cfg.min_rtt_divisor);
    try std.testing.expectEqual(@as(u64, 4), cfg.css_growth_divisor);
    try std.testing.expectEqual(@as(u32, 5), cfg.css_rounds);
}

test "MUST clamp the inflation threshold to [MIN_RTT_THRESH, MAX_RTT_THRESH] [RFC9406 §4.2]" {
    // 8 ms path: 8ms/8 = 1ms scales under the 4 ms floor, so a 2 ms
    // rise must not trigger, while a 5 ms rise must.
    var low: hystart.State = .{};
    try std.testing.expect(!round(&low, 8_000, 8, 0));
    try std.testing.expect(!round(&low, 10_000, 8, 1));
    try std.testing.expect(!low.inCss());

    var low_over: hystart.State = .{};
    try std.testing.expect(!round(&low_over, 8_000, 8, 0));
    try std.testing.expect(!round(&low_over, 13_000, 8, 1));
    try std.testing.expect(low_over.inCss());

    // 400 ms path: 400ms/8 = 50ms scales over the 16 ms ceiling, so a
    // 20 ms rise is already enough.
    var high: hystart.State = .{};
    try std.testing.expect(!round(&high, 400_000, 8, 0));
    try std.testing.expect(!round(&high, 420_000, 8, 1));
    try std.testing.expect(high.inCss());
}

test "MUST enter CSS on sustained RTT inflation [RFC9406 §4.2]" {
    var s: hystart.State = .{};
    try std.testing.expect(!round(&s, 50_000, 8, 0)); // baseline round
    try std.testing.expect(!s.inCss());
    try std.testing.expect(!round(&s, 70_000, 8, 1)); // inflated round
    try std.testing.expect(s.inCss());
}

test "MUST divide slow-start growth by CSS_GROWTH_DIVISOR while in CSS [RFC9406 §4.2]" {
    var s: hystart.State = .{};
    // Outside CSS, growth is the full acked byte count.
    try std.testing.expectEqual(@as(u64, 1200), s.slowStartGrowth(1200));
    try std.testing.expect(!round(&s, 50_000, 8, 0));
    try std.testing.expect(!round(&s, 70_000, 8, 1));
    try std.testing.expect(s.inCss());
    try std.testing.expectEqual(@as(u64, 1200 / 4), s.slowStartGrowth(1200));
}

test "MUST exit slow start after CSS_ROUNDS of sustained inflation [RFC9406 §4.2]" {
    var s: hystart.State = .{};
    try std.testing.expect(!round(&s, 50_000, 8, 0));
    try std.testing.expect(!round(&s, 70_000, 8, 1)); // -> CSS (round 1)
    try std.testing.expect(s.inCss());

    var exited = false;
    var i: u64 = 2;
    while (i < 12 and !exited) : (i += 1) exited = round(&s, 70_000, 8, i);
    try std.testing.expect(exited);
}

test "MUST return to standard slow start on a false alarm [RFC9406 §4.2]" {
    var s: hystart.State = .{};
    try std.testing.expect(!round(&s, 50_000, 8, 0));
    try std.testing.expect(!round(&s, 70_000, 8, 1));
    try std.testing.expect(s.inCss());
    // The next round's minimum drops back under the CSS baseline:
    // transient, so CSS is abandoned and full growth resumes.
    try std.testing.expect(!round(&s, 40_000, 8, 2));
    try std.testing.expect(!s.inCss());
    try std.testing.expectEqual(@as(u64, 1200), s.slowStartGrowth(1200));
}

test "MUST NOT alter congestion avoidance [RFC9406 §4.3] (both algorithms)" {
    inline for ([_]congestion.Algorithm{ .new_reno, .cubic }) |algo| {
        var cc = CongestionController.init(.{ .max_datagram_size = 1200, .algorithm = algo });
        // Force congestion avoidance: cwnd at ssthresh.
        cc.setCwndForTest(50_000);
        cc.onPacketLost(1200, 1_000_000); // sets ssthresh, leaves slow start
        try std.testing.expect(!cc.isSlowStart());
        const cwnd_before = cc.cwndBytes();
        // Wildly inflating RTT must not move cwnd through HyStart++,
        // and must never report CSS outside slow start.
        var i: u64 = 0;
        while (i < 40) : (i += 1) {
            cc.onAckProcessed(i * 10, 500_000, (i + 1) * 10);
        }
        try std.testing.expect(!cc.isInCss());
        try std.testing.expectEqual(cwnd_before, cc.cwndBytes());
    }
}

test "disabling HyStart++ restores plain RFC 9002 slow start (both algorithms)" {
    inline for ([_]congestion.Algorithm{ .new_reno, .cubic }) |algo| {
        var cc = CongestionController.init(.{
            .max_datagram_size = 1200,
            .algorithm = algo,
            .hystart = .{ .enabled = false },
        });
        try std.testing.expect(cc.isSlowStart());
        // Sustained inflation across many rounds: with HyStart++ off
        // the controller never enters CSS and never leaves slow start
        // on delay alone.
        var i: u64 = 0;
        while (i < 60) : (i += 1) {
            cc.onAckProcessed(i * 10, 50_000 + i * 5_000, (i + 1) * 10);
        }
        try std.testing.expect(!cc.isInCss());
        try std.testing.expect(cc.isSlowStart());
    }
}

test "HyStart++ exit sets ssthresh without a loss event (both algorithms)" {
    inline for ([_]congestion.Algorithm{ .new_reno, .cubic }) |algo| {
        var cc = CongestionController.init(.{ .max_datagram_size = 1200, .algorithm = algo });
        try std.testing.expect(cc.isSlowStart());
        try std.testing.expectEqual(@as(?u64, null), cc.ssthreshBytes());

        // Baseline round, then sustained inflation until slow start ends.
        var idx: u64 = 0;
        var guard: u32 = 0;
        while (cc.isSlowStart() and guard < 40) : (guard += 1) {
            const rtt: u64 = if (idx == 0) 50_000 else 70_000;
            var s: u32 = 0;
            while (s < 8) : (s += 1) cc.onAckProcessed(idx * 100, rtt, (idx + 1) * 100);
            cc.onAckProcessed((idx + 1) * 100, rtt, (idx + 2) * 100);
            idx += 1;
        }
        // Left slow start purely on the delay signal — no loss was ever
        // reported, so no recovery period was armed.
        try std.testing.expect(!cc.isSlowStart());
        try std.testing.expect(cc.ssthreshBytes() != null);
        try std.testing.expectEqual(@as(?u64, null), cc.recoveryStartTimeUs());
    }
}
