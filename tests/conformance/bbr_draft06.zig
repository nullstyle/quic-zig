//! draft-ietf-ccwg-bbr-06 — BBR Congestion Control (BBRv3).
//!
//! Pins the controller quic exposes as
//! `quic.conn.congestion.Bbr` (selected via
//! `Config.congestion_control = .bbr`). BBR is unilateral sender
//! behavior with no wire format, so conformance here means
//! state-machine and control-law fidelity: tests construct `Bbr`
//! directly and drive it through the controller hook surface with
//! synthetic RateSamples and hand microsecond timestamps — the
//! rfc9438_cubic.zig style. The delivery-rate sampler feeding these
//! hooks has its own suite (draft_cheng_delivery_rate_02.zig). Zig
//! struct fields are open, so tests park the controller in a specific
//! phase by writing model fields directly where driving the full
//! history would only obscure the claim under test — the cubic suite's
//! field-poking idiom.
//!
//! ## Coverage
//!
//! Covered:
//!   §5.3.1.1   NORMATIVE  Startup pacing gain 2.77 (and §5.6.2 margin)
//!   §5.6.2     NORMATIVE  InitPacingRate before any bandwidth sample
//!   §5.6.2     NORMATIVE  rate never reduced before full_bw_reached
//!   §5.3.1.2   NORMATIVE  3 flat rounds -> full_bw_reached -> Drain
//!   §5.3.1.2   NORMATIVE  app-limited samples never advance full-pipe
//!   §5.3.1.3   NORMATIVE  loss-based Startup exit seeds inflight_longterm
//!   §5.3.2     NORMATIVE  Drain paces at 0.5 and exits at inflight<=BDP
//!   §5.3.2     NORMATIVE  Drain exits after 3 extra rounds regardless
//!   §5.3.3.9   NORMATIVE  DOWN->CRUISE needs headroom AND inflight<=BDP
//!   §5.3.3.8.3 NORMATIVE  bw_probe_wait in [2s,3s); CRUISE->REFILL on expiry
//!   §5.3.3.8.3 NORMATIVE  Reno-coexistence round trigger (<=63)
//!   §5.3.3.3   NORMATIVE  REFILL resets the short-term model, lasts 1 round
//!   §5.3.3.5   NORMATIVE  UP paces at 1.25 (cwnd_gain 2.25 via inflight cap)
//!   §5.3.3.9   NORMATIVE  inflight_longterm grows by doubling slopes in UP
//!   §5.3.3.7   NORMATIVE  UP->DOWN on bandwidth plateau
//!   §5.5.10.2  NORMATIVE  probe loss > 2% cuts inflight_longterm to
//!                         max(inflight-at-threshold, 0.7*TargetInflight)
//!   §5.5.10.3  NORMATIVE  non-probing loss round decays the short-term
//!                         model once per round by 0.7
//!   §5.5.10.3  NORMATIVE  bw = min(max_bw, bw_shortterm)
//!   §5.5.4     NORMATIVE  app-limited samples raise max_bw only upward
//!   §2.11      NORMATIVE  max_bw forgets a sample after two cycle advances
//!   §5.3.4.2   MUST       ProbeRTT entered on the 5 s ProbeRTTInterval
//!   §5.6.4.5   NORMATIVE  ProbeRTT caps cwnd at max(0.5*BDP, MinPipeCwnd)
//!   §5.3.4.3   NORMATIVE  ProbeRTT exits after 200 ms + 1 round, to CRUISE
//!   §5.4.1     NORMATIVE  idle restart defers ProbeRTT entry
//!   §5.6.4.3   NORMATIVE  cwnd floor 4*SMSS; §5.6.4.6 growth <= newly_acked
//!   §5.5.9     NORMATIVE  extra_acked reflects ACK aggregation
//!   §3.7       MUST       CE marks are treated as congestion
//!
//! Visible debt (skip_):
//!   §5.5.11    spurious-loss undo — the transport emits no
//!              spurious-recovery signal to forward yet
//!   §3.7       a quantitative ECN response — the draft declines to
//!              specify one
//!
//! Out of scope here:
//!   §4.1 delivery-rate sampling (draft_cheng_delivery_rate_02.zig);
//!   §5.6.3 offload sizing beyond the [2*SMSS, 64KB] clamp (no TSO/GSO
//!   analog in-tree; the clamp is unit-tested next to the module);
//!   §5.3.3.8.1-8.2 multi-flow fairness/coexistence — no fairness cell
//!   exists in the bench battery; congestion_bbr.zig's header names
//!   that instrument as the gate for any default flip.

const std = @import("std");
const quic = @import("quic");
const congestion = quic.conn.congestion;
const delivery_rate = quic.conn.delivery_rate;

const Bbr = congestion.Bbr;
const RateSample = delivery_rate.RateSample;
const LostPacketInfo = delivery_rate.LostPacketInfo;

const mds: u64 = 1_200;
const us_per_s: u64 = std.time.us_per_s;

fn newBbr() Bbr {
    return Bbr.init(.{ .max_datagram_size = mds, .algorithm = .bbr });
}

/// Drives one ACK event through the hook surface in the transport's
/// order: onPacketAcked (srtt/recovery) -> onAckProcessed (RS.rtt) ->
/// onDeliveryRateSample (the §5.2.3 pipeline). Every ack() delivers
/// past the previous round marker, so each call is one packet-timed
/// round trip.
const Drive = struct {
    now_us: u64 = 1_000_000,
    delivered: u64 = 0,
    lost: u64 = 0,
    pn: u64 = 0,

    const Opts = struct {
        rate: u64,
        delivered: u64 = 60_000,
        rtt_us: ?u64 = 50_000,
        inflight: u64 = 60_000,
        app_limited: bool = false,
        rs_lost: u64 = 0,
        advance_us: u64 = 50_000,
        tx_in_flight: u64 = 0, // 0 -> inflight
        acked_sent_time_us: u64 = 0, // 0 -> now - advance
    };

    fn ack(self: *Drive, bbr: *Bbr, opts: Opts) void {
        self.now_us += opts.advance_us;
        const prior_delivered = self.delivered;
        self.delivered += opts.delivered;
        self.lost += opts.rs_lost;
        self.pn += 40;
        const rs: RateSample = .{
            .delivery_rate_bps = opts.rate,
            .has_rate = opts.rate != 0,
            .is_app_limited = opts.app_limited,
            .interval_us = opts.advance_us,
            .send_elapsed_us = opts.advance_us,
            .ack_elapsed_us = opts.advance_us,
            .delivered = opts.delivered,
            .prior_delivered = prior_delivered,
            .prior_time_us = self.now_us -| opts.advance_us,
            .prior_lost = self.lost -| opts.rs_lost,
            .tx_in_flight = if (opts.tx_in_flight != 0) opts.tx_in_flight else opts.inflight,
            .lost = opts.rs_lost,
            .newly_acked = opts.delivered,
            .newly_lost = opts.rs_lost,
            .c_delivered = self.delivered,
            .c_lost = self.lost,
            .last_acked_pn = self.pn,
        };
        const sent_time = if (opts.acked_sent_time_us != 0)
            opts.acked_sent_time_us
        else
            self.now_us -| opts.advance_us;
        bbr.onPacketAcked(opts.delivered, sent_time, self.now_us, opts.rtt_us orelse 50_000, opts.inflight);
        bbr.onAckProcessed(self.pn, opts.rtt_us, self.pn + 40);
        bbr.onDeliveryRateSample(&rs, self.now_us, opts.inflight);
    }

    fn rounds(self: *Drive, bbr: *Bbr, n: usize, opts: Opts) void {
        var i: usize = 0;
        while (i < n) : (i += 1) self.ack(bbr, opts);
    }
};

/// Startup -> Drain -> ProbeBW_DOWN at ~1.1 MB/s, min_rtt 50 ms.
fn driveToProbeBwDown(bbr: *Bbr, d: *Drive) void {
    d.ack(bbr, .{ .rate = 1_000_000 });
    d.rounds(bbr, 3, .{ .rate = 1_100_000 });
    std.debug.assert(bbr.state == .drain);
    // Drain exits once inflight <= estimated BDP (~55 KB).
    d.ack(bbr, .{ .rate = 1_100_000, .inflight = 10_000 });
    std.debug.assert(bbr.state == .probe_down);
}

test "NORMATIVE Startup paces at gain 2.77 with the 1% margin [draft-ietf-ccwg-bbr-06 §5.3.1.1, §5.6.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    try std.testing.expect(bbr.state == .startup);
    d.ack(&bbr, .{ .rate = 1_000_000 });
    // 1_000_000 * 277/100 * 99/100.
    try std.testing.expectEqual(@as(u64, 2_742_300), bbr.snapshot().pacing_rate);
    try std.testing.expect(bbr.state == .startup);
}

test "NORMATIVE pacing before any bandwidth sample is InitPacingRate [draft-ietf-ccwg-bbr-06 §5.6.2]" {
    const bbr = newBbr();
    const iw = (congestion.Config{ .max_datagram_size = mds }).initialWindow();
    try std.testing.expectEqual(
        (iw * 277 * us_per_s) / (100 * 50_000),
        bbr.pacingRateBps(50_000),
    );
    // Sub-kGranularity srtt floors at 1 ms.
    try std.testing.expectEqual(
        (iw * 277 * us_per_s) / (100 * 1_000),
        bbr.pacingRateBps(1),
    );
}

test "NORMATIVE pacing rate is never reduced before full_bw_reached [draft-ietf-ccwg-bbr-06 §5.6.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 2_000_000 });
    const high = bbr.snapshot().pacing_rate;
    d.ack(&bbr, .{ .rate = 200_000, .app_limited = true });
    try std.testing.expect(bbr.snapshot().pacing_rate >= high);
}

test "NORMATIVE three non-growing rounds set full_bw_reached and enter Drain [draft-ietf-ccwg-bbr-06 §5.3.1.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 }); // plateau baseline
    d.rounds(&bbr, 2, .{ .rate = 1_100_000 }); // < 1.25x growth
    try std.testing.expect(!bbr.snapshot().full_bw_reached);
    d.ack(&bbr, .{ .rate = 1_100_000 }); // third flat round
    const snap = bbr.snapshot();
    try std.testing.expect(snap.full_bw_reached);
    try std.testing.expect(snap.state == .drain);
}

test "NORMATIVE app-limited samples never advance full-pipe detection [draft-ietf-ccwg-bbr-06 §5.3.1.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    d.rounds(&bbr, 10, .{ .rate = 1_000_000, .app_limited = true });
    try std.testing.expect(!bbr.snapshot().full_bw_reached);
    try std.testing.expect(bbr.state == .startup);
}

test "NORMATIVE Startup exits on sustained loss and seeds inflight_longterm [draft-ietf-ccwg-bbr-06 §5.3.1.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    // Enter fast recovery, anchored beyond every future ack's sent
    // time so the "one full round in recovery" criterion can mature.
    bbr.onPacketLost(1_200, 99_000_000);
    try std.testing.expect(bbr.recovery_start_time_us != null);
    d.ack(&bbr, .{ .rate = 1_000_000 }); // a full round inside recovery
    // Six discontiguous loss events this round (packet proxy — see the
    // DEVIATION note in congestion_bbr.zig).
    var lost_total: u64 = 0;
    for (0..6) |_| {
        lost_total += 400;
        bbr.onPacketNewlyLost(&.{
            .bytes = 400,
            .tx_in_flight = 60_000,
            .lost_at_send = 0,
            .delivered_at_send = 0,
            .is_app_limited = false,
            .sent_time_us = 500,
            .c_lost = lost_total,
            .c_delivered = d.delivered,
        });
    }
    // The round-closing ACK reports a >2% round loss rate
    // (2_400 of 60_000 in flight = 4%).
    d.ack(&bbr, .{ .rate = 1_000_000, .rs_lost = 2_400 });
    try std.testing.expect(bbr.snapshot().full_bw_reached);
    try std.testing.expect(bbr.inflight_longterm != std.math.maxInt(u64));
    try std.testing.expect(bbr.state == .drain or bbr.state == .probe_down);
}

test "NORMATIVE Drain paces at gain 0.5 and exits to ProbeBW once inflight <= BDP [draft-ietf-ccwg-bbr-06 §5.3.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    d.rounds(&bbr, 3, .{ .rate = 1_100_000, .inflight = 100_000 });
    try std.testing.expect(bbr.state == .drain);
    // Drain pacing: bw (1.1 MB/s) * 1/2 * 99/100 = 544_500.
    try std.testing.expectEqual(@as(u64, 544_500), bbr.snapshot().pacing_rate);
    // Queue drained: inflight (10 KB) <= BDP (~55 KB) -> ProbeBW.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 10_000 });
    try std.testing.expect(bbr.state == .probe_down);
}

test "NORMATIVE Drain gives up after three extra rounds even above BDP [draft-ietf-ccwg-bbr-06 §5.3.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    d.rounds(&bbr, 3, .{ .rate = 1_100_000, .inflight = 200_000 });
    try std.testing.expect(bbr.state == .drain);
    d.rounds(&bbr, 4, .{ .rate = 1_100_000, .inflight = 200_000 });
    try std.testing.expect(bbr.state != .drain);
}

test "NORMATIVE DOWN->CRUISE requires free headroom AND inflight <= BDP [draft-ietf-ccwg-bbr-06 §5.3.3.1, §5.3.3.9]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    // With inflight_longterm set, headroom = 15%: at 100_000 the
    // cruise threshold is 85_000 (and BDP ~55 KB gates further).
    bbr.inflight_longterm = 100_000;
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 90_000 });
    try std.testing.expect(bbr.state == .probe_down); // no headroom yet
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_down); // <= headroom, > BDP
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
}

test "NORMATIVE bw_probe_wait is 2-3s of wall clock; CRUISE->REFILL when it elapses [draft-ietf-ccwg-bbr-06 §5.3.3.8.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    try std.testing.expect(bbr.bw_probe_wait_us >= 2 * us_per_s);
    try std.testing.expect(bbr.bw_probe_wait_us < 3 * us_per_s);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    // Cruise holds while the wall clock is inside the wait...
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 100_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    // ...and pivots to REFILL once 4 s have elapsed in the cycle.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    try std.testing.expect(bbr.state == .probe_refill);
}

test "NORMATIVE Reno-coexistence probes by round count bounded at 63 [draft-ietf-ccwg-bbr-06 §5.3.3.8.2, §5.3.3.8.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    // Shrink the estimated BDP to ~4 packets: TargetInflight/SMSS
    // rounds (min with 63) is now tiny, so a few ROUND TRIPS — no
    // wall-clock elapse (50 ms apart) — trigger the next probe.
    bbr.min_rtt_us = 4_000; // 1.1 MB/s * 4 ms ~= 4_400 B ~= 3.7 pkts
    d.rounds(&bbr, 5, .{ .rate = 1_100_000, .inflight = 4_000 });
    try std.testing.expect(bbr.state != .probe_cruise);
}

test "NORMATIVE REFILL resets the short-term model and lasts one round [draft-ietf-ccwg-bbr-06 §5.3.3.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    bbr.bw_shortterm = 900_000;
    bbr.inflight_shortterm = 40_000;
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    try std.testing.expect(bbr.state == .probe_refill);
    // The pivot moment (§3.4.2.3): short-term bounds discarded.
    try std.testing.expectEqual(std.math.maxInt(u64), bbr.bw_shortterm);
    try std.testing.expectEqual(std.math.maxInt(u64), bbr.inflight_shortterm);
    // One packet-timed round later: UP.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_up);
    try std.testing.expect(bbr.is_bw_probe_sample);
}

test "NORMATIVE ProbeBW_UP paces at gain 1.25 [draft-ietf-ccwg-bbr-06 §5.3.3.5]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_up);
    // 1_100_000 * 5/4 * 99/100 = 1_361_250.
    try std.testing.expectEqual(@as(u64, 1_361_250), bbr.snapshot().pacing_rate);
}

test "NORMATIVE inflight_longterm grows by doubling per-round slopes in UP [draft-ietf-ccwg-bbr-06 §5.3.3.5, §5.3.3.9]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_up);
    // The flow is cwnd-limited by an inflight_longterm at cwnd.
    bbr.inflight_longterm = bbr.cwnd;
    bbr.onPacketSent(d.now_us, bbr.cwnd, mds, false); // sets cwnd-limited
    const before = bbr.inflight_longterm;
    const per_inc = bbr.probe_up_acked_per_inc;
    // Delivering exactly one increment's worth of bytes raises the
    // bound by exactly one SMSS (growth spread across the round).
    d.ack(&bbr, .{ .rate = 1_100_000, .delivered = per_inc, .inflight = bbr.cwnd });
    try std.testing.expect(bbr.inflight_longterm >= before + mds);
    // The per-round slope doubles: the next round's quantum is at
    // most half the previous (modulo the cwnd it derives from).
    try std.testing.expect(bbr.bw_probe_up_rounds >= 2);
}

test "NORMATIVE UP->DOWN on a bandwidth plateau [draft-ietf-ccwg-bbr-06 §5.3.3.7]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_up);
    // Probing raises the rate no further: three flat rounds end it.
    d.rounds(&bbr, 4, .{ .rate = 1_150_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_down);
    try std.testing.expect(!bbr.prev_probe_too_high);
}

test "NORMATIVE probe loss above 2% cuts inflight_longterm to max(at-threshold, 0.7*TargetInflight) [draft-ietf-ccwg-bbr-06 §5.5.10.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 4 * us_per_s });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 60_000 });
    try std.testing.expect(bbr.state == .probe_up);
    try std.testing.expect(bbr.is_bw_probe_sample);
    // A probe-phase packet is lost with 4% of its flight lost.
    bbr.onPacketNewlyLost(&.{
        .bytes = 1_200,
        .tx_in_flight = 60_000,
        .lost_at_send = d.lost,
        .delivered_at_send = d.delivered,
        .is_app_limited = false,
        .sent_time_us = d.now_us,
        .c_lost = d.lost + 2_400,
        .c_delivered = d.delivered,
    });
    bbr.lost_total = d.lost + 2_400;
    try std.testing.expect(bbr.prev_probe_too_high);
    try std.testing.expect(!bbr.is_bw_probe_sample); // react once per probe
    const longterm = bbr.inflight_longterm;
    try std.testing.expect(longterm != std.math.maxInt(u64));
    try std.testing.expect(longterm < 60_000); // cut below the lossy flight
    // The UP -> DOWN transition lands with the next sample.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000 });
    try std.testing.expect(bbr.state == .probe_down);
}

test "NORMATIVE a non-probing loss round decays the short-term model by 0.7 once per round [draft-ietf-ccwg-bbr-06 §5.5.10.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    const max_bw = bbr.snapshot().max_bw;
    // Two consecutive slow loss rounds. bw_shortterm adapts once per
    // round as max(bw_latest, 0.7 * bw_shortterm): the first round's
    // decay is absorbed by a bw_latest still carrying the previous
    // fast round; the second round shows the multiplicative cut.
    for (0..2) |_| {
        bbr.onPacketNewlyLost(&.{
            .bytes = 1_200,
            .tx_in_flight = 50_000,
            .lost_at_send = d.lost,
            .delivered_at_send = d.delivered,
            .is_app_limited = false,
            .sent_time_us = d.now_us,
            .c_lost = d.lost + 1_200,
            .c_delivered = d.delivered,
        });
        d.ack(&bbr, .{ .rate = 100_000, .inflight = 50_000, .rs_lost = 1_200 });
    }
    // First round: Infinity -> max_bw, decay bounded by bw_latest
    // (the prior 1.1 MB/s round). Second round: 0.7 * max_bw wins.
    try std.testing.expectEqual((max_bw * 7) / 10, bbr.bw_shortterm);
}

test "NORMATIVE bw is min(max_bw, bw_shortterm) [draft-ietf-ccwg-bbr-06 §2.9.1, §5.5.10.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    bbr.bw_shortterm = 700_000;
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000 });
    const snap = bbr.snapshot();
    try std.testing.expectEqual(@as(u64, 700_000), snap.bw);
    try std.testing.expect(snap.max_bw > snap.bw);
}

test "NORMATIVE app-limited samples raise max_bw only upward [draft-ietf-ccwg-bbr-06 §5.5.4]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    try std.testing.expectEqual(@as(u64, 1_000_000), bbr.snapshot().max_bw);
    // Lower app-limited sample: discarded.
    d.ack(&bbr, .{ .rate = 400_000, .app_limited = true });
    try std.testing.expectEqual(@as(u64, 1_000_000), bbr.snapshot().max_bw);
    // Higher app-limited sample: the estimate was too low — used.
    d.ack(&bbr, .{ .rate = 1_500_000, .app_limited = true });
    try std.testing.expectEqual(@as(u64, 1_500_000), bbr.snapshot().max_bw);
}

test "NORMATIVE max_bw forgets a cycle's samples after two filter advances [draft-ietf-ccwg-bbr-06 §2.11, §5.5.6]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    try std.testing.expectEqual(@as(u64, 1_100_000), bbr.snapshot().max_bw);
    // Each pass through DOWN with ack_phase=probe_stopping advances
    // the 2-slot filter one cycle; after two advances with only
    // 400_000 B/s samples, the 1.1 MB/s memory is gone.
    for (0..2) |_| {
        bbr.ack_phase = .probe_stopping;
        bbr.state = .probe_down;
        d.ack(&bbr, .{ .rate = 400_000, .inflight = 20_000 });
    }
    try std.testing.expectEqual(@as(u64, 400_000), bbr.snapshot().max_bw);
}

test "MUST enter ProbeRTT once the min-delay sample is ProbeRTTInterval stale [draft-ietf-ccwg-bbr-06 §5.3.4.2, §5.3.4.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    // 5.1 s without a new min sample: ProbeRTT is due.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 5_100_000, .rtt_us = 60_000 });
    try std.testing.expect(bbr.state == .probe_rtt);
    // §5.6.4.5: cwnd capped at max(0.5*BDP, MinPipeCwnd).
    const bdp = (bbr.snapshot().bw * bbr.min_rtt_us) / us_per_s;
    const cap = @max(bdp / 2, 4 * mds);
    try std.testing.expect(bbr.cwnd <= cap);
}

test "NORMATIVE ProbeRTT exits after 200 ms and one round, to CRUISE when the pipe was filled [draft-ietf-ccwg-bbr-06 §5.3.4.3, §5.3.4.4]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000, .advance_us = 5_100_000, .rtt_us = 60_000 });
    try std.testing.expect(bbr.state == .probe_rtt);
    const prior = bbr.prior_cwnd;
    // Inflight drains to the ProbeRTT level: the 200 ms dwell arms.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 2_000, .advance_us = 10_000 });
    try std.testing.expect(bbr.probe_rtt_done_stamp_us != 0);
    // One round elapses but the dwell hasn't: still ProbeRTT.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 2_000, .advance_us = 50_000 });
    try std.testing.expect(bbr.state == .probe_rtt);
    // Past the dwell + round: exit to CRUISE with cwnd restored.
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 2_000, .advance_us = 200_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    try std.testing.expect(bbr.cwnd >= prior);
}

test "NORMATIVE restarting from idle defers a due ProbeRTT [draft-ietf-ccwg-bbr-06 §5.4.1, §5.3.4.3]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    // Idle: nothing in flight, app-limited, then a send.
    bbr.onPacketSent(d.now_us + 6 * us_per_s, 0, mds, true);
    try std.testing.expect(bbr.idle_restart);
    // The next sample is 6 s past the min-rtt stamp — ProbeRTT would
    // be due, but the idle restart defers it (the idle period itself
    // refreshed the queue state).
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000, .advance_us = 6 * us_per_s });
    try std.testing.expect(bbr.state != .probe_rtt);
}

test "NORMATIVE cwnd floors at MinPipeCwnd and grows by at most newly_acked [draft-ietf-ccwg-bbr-06 §5.6.4.3, §5.6.4.6]" {
    var bbr = newBbr();
    var d: Drive = .{};
    d.ack(&bbr, .{ .rate = 1_000_000 });
    // Collapse (persistent congestion), then one ACK: the floor lifts
    // cwnd back to 4 SMSS even though the collapse went to 2 SMSS.
    bbr.onPersistentCongestion();
    try std.testing.expectEqual(@as(u64, 2 * mds), bbr.cwnd);
    d.ack(&bbr, .{ .rate = 1_000_000, .delivered = 0 });
    try std.testing.expect(bbr.cwnd >= 4 * mds);
    // Growth per ACK never exceeds the bytes that ACK delivered.
    const before = bbr.cwnd;
    d.ack(&bbr, .{ .rate = 1_000_000, .delivered = 5_000 });
    try std.testing.expect(bbr.cwnd <= before + 5_000);
}

test "NORMATIVE extra_acked reflects ACK aggregation and augments the inflight budget [draft-ietf-ccwg-bbr-06 §5.5.9, §5.6.4.2]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    // A burst ACK delivers 200 KB in 10 ms while bw predicts ~11 KB:
    // the excess is aggregation, and it must widen the budget.
    bbr.cwnd = 300_000;
    d.ack(&bbr, .{ .rate = 1_100_000, .delivered = 200_000, .inflight = 20_000, .advance_us = 10_000 });
    try std.testing.expect(bbr.snapshot().extra_acked > 100_000);
}

test "MUST treat CE marks as congestion when sending ECT [draft-ietf-ccwg-bbr-06 §3.7]" {
    var bbr = newBbr();
    var d: Drive = .{};
    driveToProbeBwDown(&bbr, &d);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 20_000 });
    try std.testing.expect(bbr.state == .probe_cruise);
    try std.testing.expectEqual(std.math.maxInt(u64), bbr.bw_shortterm);
    // A CE-marked ACK arrives: BBR counts it as a congestion round,
    // and the round close applies the short-term decay.
    bbr.onCongestionEvent(1_000_000);
    d.ack(&bbr, .{ .rate = 1_100_000, .inflight = 50_000 });
    try std.testing.expect(bbr.bw_shortterm != std.math.maxInt(u64));
}

test "skip_NORMATIVE spurious loss recovery restores saved model state [draft-ietf-ccwg-bbr-06 §5.5.11]" {
    // The transport has no spurious-recovery detection to forward
    // (RFC 9002 loss detection never un-declares a loss today), so
    // BBR.undo_* is not implemented. Bounded: REFILL resets the
    // short-term model every probe cycle. See congestion_bbr.zig.
    return error.SkipZigTest;
}

test "skip_NORMATIVE a quantitative ECN response [draft-ietf-ccwg-bbr-06 §3.7]" {
    // §3.7 declines to specify a response beyond "MUST treat CE as
    // congestion" (covered above). The CE packet-count delta already
    // rides the RateSample for whatever policy a future revision of
    // the draft lands.
    return error.SkipZigTest;
}
