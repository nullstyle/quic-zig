//! HyStart++ slow-start exit (RFC 9406).
//!
//! Standard slow start only stops when it overruns the bottleneck and
//! loses packets — the loss it causes is the signal. HyStart++ watches
//! for sustained RTT inflation across a round instead, and leaves slow
//! start *before* the overshoot. It ships in Linux TCP, Cloudflare
//! quiche, msquic, ngtcp2, and picoquic.
//!
//! The algorithm is orthogonal to the loss-response curve, so this
//! state is shared: both `congestion.NewReno` and
//! `congestion_cubic.Cubic` embed it and consult it from their
//! slow-start branch (CUBIC + HyStart++ is the common production
//! pairing). Everything here is pure integer arithmetic over
//! microseconds and bytes; the controller stays in charge of its own
//! `cwnd`/`ssthresh` — `onAckProcessed` only reports *when* to leave
//! slow start.
//!
//! Round-trip boundaries are tracked the way RFC 9406 §3.2 describes:
//! record the next packet number the sender will use at the start of a
//! round; the round ends once an ACK covers it.

const std = @import("std");

/// RFC 9406 §4.2 tunables. Defaults are the RFC's recommended values,
/// which every major deployment uses unchanged.
pub const Config = struct {
    /// `N_RTT_SAMPLE`: minimum RTT samples in a round before the
    /// inflation test may fire.
    n_rtt_sample: u32 = 8,
    /// `MIN_RTT_THRESH`: floor on the inflation delta (4 ms).
    min_rtt_thresh_us: u64 = 4_000,
    /// `MAX_RTT_THRESH`: ceiling on the inflation delta (16 ms).
    max_rtt_thresh_us: u64 = 16_000,
    /// `MIN_RTT_DIVISOR`: scales the delta with path latency.
    min_rtt_divisor: u64 = 8,
    /// `CSS_GROWTH_DIVISOR`: slow-start growth is divided by this
    /// while in Conservative Slow Start (4).
    css_growth_divisor: u64 = 4,
    /// `CSS_ROUNDS`: CSS rounds to survive before leaving slow start.
    css_rounds: u32 = 5,
    /// Master switch. False makes every entry point a no-op, so the
    /// controller behaves exactly as it did before HyStart++.
    enabled: bool = true,
};

/// Per-controller HyStart++ state. Reset by loss and by persistent
/// congestion, both of which end slow start through the normal
/// ssthresh path.
pub const State = struct {
    cfg: Config = .{},
    /// Smallest RTT in the previous round; null until a round completes.
    last_round_min_rtt_us: ?u64 = null,
    /// Smallest RTT so far this round.
    current_round_min_rtt_us: ?u64 = null,
    /// `lastRoundMinRTT` snapshot at CSS entry — the false-alarm
    /// threshold that sends us back to plain slow start.
    css_baseline_min_rtt_us: ?u64 = null,
    /// RTT samples taken this round.
    rtt_sample_count: u32 = 0,
    /// CSS rounds completed so far.
    css_rounds_seen: u32 = 0,
    /// In Conservative Slow Start (RFC 9406 §4.2)?
    in_css: bool = false,
    /// The round ends once an ACK covers this packet number. Null
    /// until the first ACK is observed.
    round_end_pn: ?u64 = null,

    pub fn init(cfg: Config) State {
        return .{ .cfg = cfg };
    }

    /// Drop all round/CSS tracking, keeping the configuration.
    pub fn reset(self: *State) void {
        const cfg = self.cfg;
        self.* = .{ .cfg = cfg };
    }

    pub fn inCss(self: *const State) bool {
        return self.in_css;
    }

    /// Slow-start cwnd increase for `bytes_acked`. RFC 9406 §4.2:
    /// growth is divided by `CSS_GROWTH_DIVISOR` inside CSS, and is
    /// plain `bytes_acked` otherwise.
    pub fn slowStartGrowth(self: *const State, bytes_acked: u64) u64 {
        if (!self.cfg.enabled or !self.in_css) return bytes_acked;
        return bytes_acked / self.cfg.css_growth_divisor;
    }

    /// Feed one processed ACK. `latest_rtt_us` is null when the ACK
    /// produced no fresh RTT sample (non-ack-eliciting largest-acked),
    /// which HyStart++ ignores. `next_pn_to_send` is the sender's next
    /// packet number — the first PN of the round that starts now.
    ///
    /// Returns true when slow start should end (the caller sets
    /// `ssthresh = cwnd` and resets this state). Callers must only
    /// invoke this while actually in slow start.
    pub fn onAckProcessed(
        self: *State,
        largest_acked_pn: u64,
        latest_rtt_us: ?u64,
        next_pn_to_send: u64,
    ) bool {
        if (!self.cfg.enabled) return false;

        // Seed the round marker on the first ACK we ever see.
        if (self.round_end_pn == null) self.round_end_pn = next_pn_to_send;

        if (latest_rtt_us) |rtt| {
            const cur = self.current_round_min_rtt_us;
            if (cur == null or rtt < cur.?) self.current_round_min_rtt_us = rtt;
            self.rtt_sample_count += 1;

            // RFC 9406 §4.2: with enough samples in hand, sustained
            // inflation over the previous round means a queue is
            // building at the bottleneck. Only tested before CSS.
            if (!self.in_css and
                self.rtt_sample_count >= self.cfg.n_rtt_sample and
                self.last_round_min_rtt_us != null and
                self.current_round_min_rtt_us != null)
            {
                const last_min = self.last_round_min_rtt_us.?;
                const cur_min = self.current_round_min_rtt_us.?;
                const scaled = last_min / self.cfg.min_rtt_divisor;
                const rtt_thresh = @max(
                    self.cfg.min_rtt_thresh_us,
                    @min(self.cfg.max_rtt_thresh_us, scaled),
                );
                if (cur_min >= last_min +| rtt_thresh) {
                    self.in_css = true;
                    self.css_baseline_min_rtt_us = last_min;
                    self.css_rounds_seen = 0;
                }
            }
        }

        // Round end: this ACK covers everything outstanding when the
        // round began (RFC 9406 §3.2).
        if (largest_acked_pn < self.round_end_pn.?) return false;

        // §4.2 false alarm: the round's minimum dropped back below the
        // CSS baseline, so the inflation was transient — resume plain
        // slow start rather than exiting on a blip.
        if (self.in_css) {
            if (self.css_baseline_min_rtt_us) |baseline| {
                if (self.current_round_min_rtt_us) |cur_min| {
                    if (cur_min < baseline) {
                        self.in_css = false;
                        self.css_baseline_min_rtt_us = null;
                        self.css_rounds_seen = 0;
                    }
                }
            }
        }

        if (self.in_css) {
            self.css_rounds_seen += 1;
            if (self.css_rounds_seen >= self.cfg.css_rounds) {
                // Leave slow start without having caused loss.
                return true;
            }
        }

        // Roll the round forward.
        self.last_round_min_rtt_us = self.current_round_min_rtt_us;
        self.current_round_min_rtt_us = null;
        self.rtt_sample_count = 0;
        self.round_end_pn = next_pn_to_send;
        return false;
    }
};

// -- tests -------------------------------------------------------------------

const testing = std.testing;

/// Drive one full round: `samples` RTT observations, then an ACK that
/// closes the round. Returns true if the round-closing ACK asked to
/// exit slow start.
fn driveRound(state: *State, rtt_us: u64, samples: u32, round: u64) bool {
    var i: u32 = 0;
    while (i < samples) : (i += 1) {
        // Mid-round ACKs: PN below the round-end marker.
        _ = state.onAckProcessed(round * 100, rtt_us, (round + 1) * 100);
    }
    // Closing ACK: covers the round-end marker.
    return state.onAckProcessed((round + 1) * 100, rtt_us, (round + 2) * 100);
}

test "disabled HyStart++ is inert" {
    var s = State.init(.{ .enabled = false });
    try testing.expectEqual(@as(u64, 1200), s.slowStartGrowth(1200));
    try testing.expect(!driveRound(&s, 50_000, 8, 0));
    try testing.expect(!s.inCss());
    try testing.expectEqual(@as(?u64, null), s.round_end_pn);
}

test "steady RTT never leaves slow start" {
    var s: State = .{};
    var round: u64 = 0;
    while (round < 20) : (round += 1) {
        try testing.expect(!driveRound(&s, 50_000, 8, round));
        try testing.expect(!s.inCss());
    }
    // Full-rate growth throughout.
    try testing.expectEqual(@as(u64, 1200), s.slowStartGrowth(1200));
}

test "sustained inflation enters CSS and exits after CSS_ROUNDS" {
    var s: State = .{};
    // Round 0 establishes the baseline at 50 ms.
    try testing.expect(!driveRound(&s, 50_000, 8, 0));
    try testing.expect(!s.inCss());

    // Round 1 inflates well past max(4ms, min(16ms, 50ms/8)=6.25ms).
    try testing.expect(!driveRound(&s, 70_000, 8, 1));
    try testing.expect(s.inCss());
    // CSS throttles growth by the divisor.
    try testing.expectEqual(@as(u64, 300), s.slowStartGrowth(1200));

    // Staying inflated for CSS_ROUNDS exits slow start. Round 1's
    // close already counted as the first CSS round.
    var exited = false;
    var round: u64 = 2;
    while (round < 10 and !exited) : (round += 1) {
        exited = driveRound(&s, 70_000, 8, round);
    }
    try testing.expect(exited);
}

test "false alarm: RTT dropping back below baseline resumes slow start" {
    var s: State = .{};
    try testing.expect(!driveRound(&s, 50_000, 8, 0)); // baseline
    try testing.expect(!driveRound(&s, 70_000, 8, 1)); // inflate -> CSS
    try testing.expect(s.inCss());

    // The next round comes back under the baseline: transient, not a
    // real queue. CSS is abandoned and full-rate growth resumes.
    try testing.expect(!driveRound(&s, 40_000, 8, 2));
    try testing.expect(!s.inCss());
    try testing.expectEqual(@as(u64, 1200), s.slowStartGrowth(1200));
}

test "inflation below the threshold does not trigger CSS" {
    var s: State = .{};
    try testing.expect(!driveRound(&s, 50_000, 8, 0));
    // 50ms/8 = 6.25ms threshold; +3 ms is under it.
    try testing.expect(!driveRound(&s, 53_000, 8, 1));
    try testing.expect(!s.inCss());
}

test "fewer than N_RTT_SAMPLE samples suppresses the test" {
    var s: State = .{};
    try testing.expect(!driveRound(&s, 50_000, 8, 0));
    // Massive inflation but only 2 samples this round: not enough
    // evidence, so no CSS.
    try testing.expect(!driveRound(&s, 200_000, 2, 1));
    try testing.expect(!s.inCss());
}

test "the RTT threshold is clamped into [MIN_RTT_THRESH, MAX_RTT_THRESH]" {
    // Very low latency path: 8ms/8 = 1ms scales below the 4 ms floor,
    // so a 2 ms bump must NOT trigger.
    var low: State = .{};
    try testing.expect(!driveRound(&low, 8_000, 8, 0));
    try testing.expect(!driveRound(&low, 10_000, 8, 1));
    try testing.expect(!low.inCss());
    // ...but a bump past the 4 ms floor does.
    var low2: State = .{};
    try testing.expect(!driveRound(&low2, 8_000, 8, 0));
    try testing.expect(!driveRound(&low2, 13_000, 8, 1));
    try testing.expect(low2.inCss());

    // Very high latency path: 400ms/8 = 50ms scales above the 16 ms
    // ceiling, so a 20 ms bump is enough.
    var high: State = .{};
    try testing.expect(!driveRound(&high, 400_000, 8, 0));
    try testing.expect(!driveRound(&high, 420_000, 8, 1));
    try testing.expect(high.inCss());
}

test "reset clears round state but keeps configuration" {
    var s = State.init(.{ .css_rounds = 3 });
    _ = driveRound(&s, 50_000, 8, 0);
    _ = driveRound(&s, 70_000, 8, 1);
    try testing.expect(s.inCss());
    s.reset();
    try testing.expect(!s.inCss());
    try testing.expectEqual(@as(?u64, null), s.round_end_pn);
    try testing.expectEqual(@as(u32, 3), s.cfg.css_rounds);
}

test "ACKs without an RTT sample advance rounds but never trigger CSS" {
    var s: State = .{};
    var round: u64 = 0;
    while (round < 12) : (round += 1) {
        _ = s.onAckProcessed((round + 1) * 100, null, (round + 2) * 100);
    }
    try testing.expect(!s.inCss());
    try testing.expectEqual(@as(u32, 0), s.rtt_sample_count);
}
