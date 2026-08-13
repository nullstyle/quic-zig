//! RFC 9438 — CUBIC for Fast and Long-Distance Networks.
//!
//! Pins the CUBIC controller quic exposes as
//! `quic.conn.congestion.Cubic` (selected via
//! `Config.congestion_control = .cubic`). Deep mechanics (curve
//! shape, epoch handling, app-limited freezing) are unit-tested next
//! to the implementation in `src/conn/congestion_cubic.zig`; this
//! suite carries the RFC-traceable normative claims.
//!
//! ## Coverage
//!
//! Covered:
//!   RFC9438 §4.6 ¶2  MUST      multiplicative decrease uses β_cubic = 0.7
//!   RFC9438 §4.6 ¶?  MUST NOT  reduce below the RFC 9002 minimum window
//!   RFC9438 §4.7 ¶2  SHOULD    fast convergence halves toward (1+β)/2·cwnd
//!                              when reducing below the previous W_max
//!   RFC9438 §4.2 ¶?  MUST      W_cubic(K) = W_max — the curve regains the
//!                              pre-reduction window at t = K
//!   RFC9438 §4.3 ¶?  MUST      Reno-friendly region: cwnd never falls below
//!                              the W_est trajectory (α = 3(1−β)/(1+β))
//!   RFC9438 §5.8 /
//!   RFC9002 §7.8 ¶1  SHOULD NOT grow cwnd on application-limited ACKs
//!                              (parameterized over both algorithms)
//!   RFC9002 §7.3.1 ¶? MUST NOT re-enter recovery for losses inside an
//!                              existing recovery period (parity with NewReno)
//!   RFC9002 §7.6 ¶2  MUST      persistent congestion collapses to the
//!                              minimum window
//!
//! Out of scope here:
//!   RFC9438 §4.10 (HyStart++ slow-start exit) — implemented as the
//!   shared `hystart.zig` module both loss-based controllers embed;
//!   its conformance suite is rfc9406_hystart.zig.

const std = @import("std");
const quic = @import("quic");
const congestion = quic.conn.congestion;

const Cubic = congestion.Cubic;
const NewReno = congestion.NewReno;
const CongestionController = congestion.CongestionController;

test "MUST multiply cwnd by beta_cubic = 0.7 on a congestion event [RFC9438 §4.6 ¶2]" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(@as(u64, 70_000), cubic.cwnd);
    try std.testing.expectEqual(@as(?u64, 70_000), cubic.ssthresh);

    // The ECN-CE decrease path applies the same factor.
    var cubic_ce = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic_ce.cwnd = 100_000;
    cubic_ce.onCongestionEvent(1_000_000);
    try std.testing.expectEqual(@as(u64, 70_000), cubic_ce.cwnd);
}

test "MUST NOT reduce below the minimum window [RFC9438 §4.6 / RFC9002 §7.2]" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 2_500; // 0.7x would be 1750, below 2*MSS = 2400
    cubic.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(cubic.cfg.minWindow(), cubic.cwnd);
}

test "SHOULD apply fast convergence when reducing below the previous W_max [RFC9438 §4.7 ¶2]" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000);
    // First reduction was from the ceiling: W_max = the old cwnd.
    try std.testing.expectEqual(@as(u64, 100_000), cubic.w_max);
    // Second reduction happens below that ceiling: W_max takes the
    // (1+β)/2 haircut of the current window — 70_000 · 0.85 = 59_500.
    cubic.onPacketLost(1200, 2_000_000);
    try std.testing.expectEqual(@as(u64, 59_500), cubic.w_max);
}

test "MUST regain W_max on the cubic curve at t = K [RFC9438 §4.2]" {
    // Property of the curve itself: W_cubic(K) = W_max exactly (float
    // rounding aside), from below.
    const mss: u64 = 1200;
    const w_max: u64 = 120_000;
    const cwnd_epoch: u64 = 84_000; // post-0.7 reduction
    const k = congestion.cubicK(w_max - cwnd_epoch, mss);
    const at_k = congestion.cubicWindowBytes(k, k, w_max, mss);
    try std.testing.expect(at_k >= w_max - 2 and at_k <= w_max + 2);
    try std.testing.expect(congestion.cubicWindowBytes(k / 2, k, w_max, mss) < w_max);
}

test "MUST NOT fall below the Reno-friendly trajectory [RFC9438 §4.3]" {
    // In the short-RTT region the cubic term is tiny; growth must be
    // carried by W_est. After many full-pipe RTTs the window must
    // exceed its post-reduction value by at least the α-scaled Reno
    // slope (one α·MSS per RTT).
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 12_000;
    cubic.ssthresh = 12_000; // congestion avoidance
    cubic.w_max = 240_000; // ceiling far away: cubic term ~flat

    var now: u64 = 1_000_000;
    const srtt: u64 = 5_000; // 5 ms: deeply Reno-friendly
    const rtts: u64 = 100;
    var i: u64 = 0;
    while (i < rtts) : (i += 1) {
        cubic.onPacketAcked(cubic.cwnd, now, now, srtt, cubic.cwnd);
        now += srtt;
    }
    // α = 9/17 ≈ 0.53 MSS per RTT; require at least half of the exact
    // trajectory to keep the bound robust to integer rounding.
    const min_growth = (rtts * 1200 * congestion.cubic_alpha_num) /
        (2 * congestion.cubic_alpha_den);
    try std.testing.expect(cubic.cwnd >= 12_000 + min_growth);
}

test "SHOULD NOT grow cwnd when application limited [RFC9002 §7.8 ¶1] (all algorithms)" {
    // For the loss-based controllers the §7.8 utilization gate blocks
    // growth on this ACK; for BBR the claim holds structurally —
    // onPacketAcked never grows cwnd at all (growth is sample-driven
    // and gated on rs.is_app_limited inside the bandwidth model).
    inline for ([_]congestion.Algorithm{ .new_reno, .cubic, .bbr }) |algo| {
        var cc = CongestionController.init(.{ .max_datagram_size = 1200, .algorithm = algo });
        cc.setCwndForTest(50_000);
        const before = cc.cwndBytes();
        // 1200 bytes acked with an empty pipe against a 50k window.
        cc.onPacketAcked(1_200, 100, 1_000, 25_000, 0);
        try std.testing.expectEqual(before, cc.cwndBytes());
    }
}

test "MUST NOT re-enter recovery for losses inside the recovery period [RFC9002 §7.3.1]" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000);
    const once = cubic.cwnd;
    cubic.onPacketLost(1200, 999_999);
    try std.testing.expectEqual(once, cubic.cwnd);
}

test "MUST collapse to the minimum window on persistent congestion [RFC9002 §7.6 ¶2]" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 90_000;
    cubic.onPersistentCongestion();
    try std.testing.expectEqual(cubic.cfg.minWindow(), cubic.cwnd);
}

test "config selects CUBIC through the wrapper-facing union" {
    var cc = CongestionController.init(.{ .max_datagram_size = 1200, .algorithm = .cubic });
    try std.testing.expectEqual(congestion.Algorithm.cubic, cc.algorithm());
    // The dispatched surface behaves: a loss applies the CUBIC β.
    cc.setCwndForTest(100_000);
    cc.onPacketLost(1200, 1_000_000);
    try std.testing.expectEqual(@as(u64, 70_000), cc.cwndBytes());
}
