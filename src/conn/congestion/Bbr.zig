//! BBRv3 congestion control (draft-ietf-ccwg-bbr-06).
//!
//! Loss-based control (NewReno, CUBIC) infers the path from the losses
//! it causes; BBR builds an explicit model — the maximum recent
//! delivery rate (BBR.max_bw) and minimum recent round-trip time
//! (BBR.min_rtt) — and paces at the estimated bottleneck bandwidth
//! while bounding data in flight to a small multiple of the estimated
//! BDP. The model is fed exclusively by the delivery-rate sampler
//! (`delivery_rate.zig`); the state machine cycles
//! Startup -> Drain -> ProbeBW(DOWN -> CRUISE -> REFILL -> UP -> ...)
//! with periodic ProbeRTT dips to re-measure the propagation delay.
//!
//! Section references (§) are to draft-ietf-ccwg-bbr-06 (2026-07-06;
//! the conformance suite tests/conformance/bbr_draft06.zig pins that
//! revision). Everything is integer arithmetic over bytes and
//! microseconds with u128 intermediates and rational gain constants —
//! the congestion/Cubic.zig unit discipline; no floats, no allocation,
//! and the struct is relocatable by value (Path lives in an ArrayList).
//!
//! Deliberate deviations, each conservative and marked DEVIATION at
//! its implementation site:
//!  - §5.5.11 spurious-loss undo is NOT implemented: the transport has
//!    no spurious-recovery signal to forward. Damage is bounded —
//!    REFILL resets the short-term model every probe cycle (§5.3.3.3).
//!  - §5.3.1.3's "6 discontiguous sequence ranges" Startup-loss
//!    criterion is approximated by 6 lost packets in the round (the
//!    per-packet loss inlet has no range structure). More permissive =
//!    earlier Startup exit = under-utilization, never over-drive.
//!  - §5.3.4.3 HandleProbeRTT's MarkConnectionAppLimited() has no
//!    channel from controller to sampler; instead full-pipe detection
//!    is suppressed while in ProbeRTT (the max_bw filter needs no
//!    guard — a max cannot be dragged down by low samples).
//!  - §3.7 ECN: the draft declines to specify a quantitative response;
//!    a CE-marked ACK counts as a congestion round (the once-per-round
//!    §5.5.10.3 short-term decay), nothing more. The CE packet-count
//!    delta already rides the RateSample for a future policy.
//!
//! DEFAULT-FLIP RECORD (2026-08-21, .bbr became the default): the
//! gate this header used to demand was built (`zig build bench-e2e
//! -- --scenario fairness`: >= 2 Pairs share one SimNet bottleneck;
//! per-flow goodput + Jain index) and passed on pre-registered
//! criteria — 2-flow BBR Jain 1.0000 at 97.1% utilization (CUBIC
//! reference 0.9996), 4-flow 0.9970, 5 s-staggered joiner converges
//! to 1.0000, BBR-vs-CUBIC no-starvation both buffer depths (31.1%
//! deep / 61.3% shallow BBR share), peak queue 43 ms vs CUBIC's
//! 100 ms — plus the full interop battery, per the d611e0b ->
//! 5629357 opt-in-then-flip precedent. First light also caught a
//! three-defect transport deadlock (Pacer quantization freeze, the
//! trickle-latch this file's pacing floor now guards, and
//! credit-starvation behind the pacing gate) — fixed before the
//! flip; the fairness cells are the regression instrument. Rollback
//! is one line at any layer: `congestion_control = .cubic`.
//!
//! External evidence (capnp-zig, 2026-08-21, post-flip): their RPC
//! churn soak A/B on identical v0.16.0 code — 60 s / 8 workers,
//! connect/bootstrap/call/close loops + chaos closes + 1 ms-deadline
//! cancellation sessions, loopback — read bbr-vs-cubic as a clean
//! no-regression: +3.7% calls, p50 +0.7 ms, p99 −6%, memory flat,
//! cancellations identical. Loopback caveat applies (no bottleneck
//! to bind against); cite as theirs, workload as described.

const Bbr = @This();

const std = @import("std");
const congestion = @import("../congestion.zig");
const delivery_rate = @import("../delivery_rate.zig");

const infinity: u64 = std.math.maxInt(u64);
const us_per_s: u64 = std.time.us_per_s;

// -- constants (§2.5/§2.6/§2.8/§2.12/§2.16, §5.3.x, §5.6.x), as rationals --

/// §2.5: StartupPacingGain = 4 * ln(2) ~= 2.77.
pub const startup_pacing_gain_num: u64 = 277;
pub const startup_pacing_gain_den: u64 = 100;
/// §2.5 / §5.3.2: DrainPacingGain = 0.5.
pub const drain_pacing_gain_num: u64 = 1;
pub const drain_pacing_gain_den: u64 = 2;
/// §5.3.3.1: ProbeBW_DOWN pacing gain = 0.90.
pub const probe_down_pacing_gain_num: u64 = 9;
pub const probe_down_pacing_gain_den: u64 = 10;
/// §5.3.3.5: ProbeBW_UP pacing gain = 1.25.
pub const probe_up_pacing_gain_num: u64 = 5;
pub const probe_up_pacing_gain_den: u64 = 4;
/// §2.6: DefaultCwndGain = 2.
pub const default_cwnd_gain_num: u64 = 2;
pub const default_cwnd_gain_den: u64 = 1;
/// §5.3.3.5: ProbeBW_UP cwnd gain = 2.25.
pub const probe_up_cwnd_gain_num: u64 = 9;
pub const probe_up_cwnd_gain_den: u64 = 4;
/// §2.16.2: ProbeRTTCwndGain = 0.5.
pub const probe_rtt_cwnd_gain_num: u64 = 1;
pub const probe_rtt_cwnd_gain_den: u64 = 2;
/// §2.8: Beta = 0.7.
pub const beta_num: u64 = 7;
pub const beta_den: u64 = 10;
/// §2.8: LossThresh = 2% = 1/50.
pub const loss_thresh_num: u64 = 1;
pub const loss_thresh_den: u64 = 50;
/// §2.8: Headroom = 0.15.
pub const headroom_num: u64 = 3;
pub const headroom_den: u64 = 20;
/// §2.8: MinPipeCwnd = 4 * SMSS.
pub const min_pipe_cwnd_packets: u64 = 4;
/// §5.6.2: PacingMarginPercent = 1 (pace at 99% of gain * bw).
pub const pacing_margin_num: u64 = 99;
pub const pacing_margin_den: u64 = 100;
/// §5.3.1.2: full-pipe plateau = < 25% growth over 3 rounds.
pub const full_bw_growth_num: u64 = 5;
pub const full_bw_growth_den: u64 = 4;
pub const full_bw_count_target: u8 = 3;
/// §5.3.1.3: BBRStartupFullLossCnt (see the range-proxy DEVIATION).
pub const startup_full_loss_cnt: u16 = 6;
/// §2.12 / §5.5.9: extra_acked window, rounds (1 during Startup).
pub const extra_acked_filter_len_rounds: u64 = 10;
/// §2.16.1: MinRTTFilterLen = 10 s.
pub const min_rtt_filter_len_us: u64 = 10 * us_per_s;
/// §2.16.2: ProbeRTTInterval = 5 s; ProbeRTTDuration = 200 ms.
pub const probe_rtt_interval_us: u64 = 5 * us_per_s;
pub const probe_rtt_duration_us: u64 = 200 * std.time.us_per_ms;
/// §5.3.3.8.3: bw_probe_wait = 2 s + uniform [0, 1) s.
pub const bw_probe_wait_base_us: u64 = 2 * us_per_s;
pub const bw_probe_wait_rand_us: u64 = 1 * us_per_s;
/// §5.3.3.8.2/8.3: Reno-coexistence round bound (62..63 combined with
/// the randomized 0/1 reseed of rounds_since_probe_up).
pub const reno_coexistence_rounds_cap: u64 = 63;
/// §5.3.2: Drain gives up and enters ProbeBW after 3 extra rounds.
pub const drain_exit_extra_rounds: u64 = 3;
/// §5.3.3.9 RaiseInflightLongtermSlope: doubling-round cap.
pub const probe_up_rounds_cap: u8 = 30;
/// §5.6.3: send quantum in [2 * SMSS, 64 KB].
pub const send_quantum_max_bytes: u64 = 64 * 1024;
pub const send_quantum_min_packets: u64 = 2;
/// Fixed SplitMix64 seed ("bbr3") for §5.3.3.8.3's probe-wait jitter.
/// A fixed seed keeps SimNet bench runs bit-reproducible; the draft's
/// de-synchronization goal is served by the sequence varying across
/// probes within a connection. Cross-connection phase alignment is a
/// fairness-cell concern — see the DEFAULT-FLIP GATE note above.
pub const prng_seed: u64 = 0x62627233;

/// §5.1 states, with ProbeBW's four phases (§5.3.3) flattened in.
pub const State = enum(u8) {
    startup,
    drain,
    probe_down,
    probe_cruise,
    probe_refill,
    probe_up,
    probe_rtt,
};

/// §2.14 ack_phase: what the current ACK stream means with respect to
/// bandwidth probing.
const AckPhase = enum(u8) {
    init,
    refilling,
    probe_starting,
    probe_feedback,
    probe_stopping,
};

/// Model observability for bench/debug tooling
/// (`CongestionController.bbrSnapshot`).
pub const Snapshot = struct {
    state: State,
    max_bw: u64,
    bw: u64,
    bw_shortterm: u64,
    min_rtt_us: u64,
    inflight_longterm: u64,
    inflight_shortterm: u64,
    pacing_rate: u64,
    extra_acked: u64,
    full_bw_reached: bool,
    round_count: u64,
};

/// Kathleen Nichols style 3-estimate windowed max over a u64 virtual
/// time axis ([KN_FILTER], the implementation §5.5.5 points at). The
/// window length is a per-update argument because §5.5.9 switches
/// between 1 round (Startup) and 10 rounds (steady state).
const WindowedMaxFilter = struct {
    val: [3]u64 = .{ 0, 0, 0 },
    t: [3]u64 = .{ 0, 0, 0 },

    fn max(self: *const WindowedMaxFilter) u64 {
        return self.val[0];
    }

    fn update(self: *WindowedMaxFilter, now: u64, v: u64, window: u64) u64 {
        if (v >= self.val[0] or now -| self.t[2] > window) {
            // New overall max, or the whole window has aged out.
            self.val = .{ v, v, v };
            self.t = .{ now, now, now };
            return self.val[0];
        }
        if (v >= self.val[1]) {
            self.val[1] = v;
            self.t[1] = now;
            self.val[2] = v;
            self.t[2] = now;
        } else if (v >= self.val[2]) {
            self.val[2] = v;
            self.t[2] = now;
        }
        // Age the front estimate out of the window.
        while (now -| self.t[0] > window) {
            self.val[0] = self.val[1];
            self.t[0] = self.t[1];
            self.val[1] = self.val[2];
            self.t[1] = self.t[2];
            self.val[2] = v;
            self.t[2] = now;
            if (self.t[0] == self.t[1] and self.val[0] == self.val[1]) break;
        }
        return self.val[0];
    }
};

/// BBRv3 controller. One per QUIC path, by value, relocatable.
// -- union contract fields (congestion.zig accessors reach these) --
cfg: congestion.Config,
/// C.cwnd; init = the transport's initial window (§5.6.4.1).
cwnd: u64,
/// Always null: BBR has no slow-start threshold, and mapping any
/// model bound here would hand loss-based semantics to qlog/stats
/// readers. Rich model state is `CongestionController.bbrSnapshot`.
ssthresh: ?u64 = null,
/// RFC 9002-style recovery anchor, the NewReno/Cubic edge
/// convention: set on the first loss outside a recovery period,
/// cleared by an ACK of a packet sent after it. BBR does NOT
/// freeze cwnd inside the period — the in-period response is the
/// §5.5.10 model response; the edges drive SaveCwnd/RestoreCwnd
/// (§5.6.4.4) and §5.3.1.3's "one full round in recovery" gate.
recovery_start_time_us: ?u64 = null,

// -- §2.7 general state --
state: State = .startup,
ack_phase: AckPhase = .init,
round_count: u64 = 0,
next_round_delivered: u64 = 0,
round_start: bool = false,
rounds_since_probe_up: u64 = 0,
idle_restart: bool = false,
drain_start_round: u64 = 0,

// -- carriers between hooks within one ACK event --
/// RS.rtt: QUIC's latest_rtt measures the newest acked packet,
/// exactly §5.5.7.1's minimum-candidate rule. Stashed by
/// onAckProcessed, consumed once by the sample that closes the
/// event.
stashed_rtt_us: ?u64 = null,
/// srtt for the InitPacingRate fallback (§5.6.2).
stashed_srtt_us: u64 = 0,
/// C.is_cwnd_limited over the current round: set by sends that
/// fill the window, read by §5.3.3.9, reset at round close.
cwnd_limited_in_round: bool = false,
/// Freshest C.inflight view at a transmit (§5.3.3.6/7's
/// "C.inflight reaches BBR.inflight_longterm" trigger).
last_inflight_at_send: u64 = 0,
/// A loss-decided ProbeBW_UP -> DOWN transition parked until a
/// wall clock is available (the loss walk has none); consumed by
/// the next sample. inflight_longterm was already cut
/// synchronously — only the phase change waits, at most one ACK.
probe_down_pending: bool = false,

// -- §2.9.1 data-rate model --
/// §2.11: 2-slot max filter over ProbeBW-cycle virtual time.
max_bw_slots: [2]u64 = .{ 0, 0 },
cycle_count: u1 = 0,
bw_shortterm: u64 = infinity,
/// §2.9.1: BBR.bw = min(max_bw, bw_shortterm), cached each ACK.
bw: u64 = 0,

// -- §2.9.2 data-volume model --
min_rtt_us: u64 = infinity,
min_rtt_stamp_us: u64 = 0,
inflight_longterm: u64 = infinity,
inflight_shortterm: u64 = infinity,
extra_acked_filter: WindowedMaxFilter = .{},
extra_acked_interval_start_us: u64 = 0,
extra_acked_delivered: u64 = 0,
extra_acked: u64 = 0,

// -- §2.10 congestion-response state --
bw_latest: u64 = 0,
inflight_latest: u64 = 0,
is_loss_in_round: bool = false,
loss_events_in_round: u16 = 0,
loss_round_delivered: u64 = 0,
loss_round_start: bool = false,
/// Captured at loss-round close for same-ACK consumers
/// (CheckStartupHighLoss) — the live counters reset at close.
closed_round_had_loss: bool = false,
closed_round_loss_events: u16 = 0,
/// round_count at recovery entry (§5.3.1.3's one-round gate).
recovery_entry_round: u64 = 0,

// -- §2.13 Startup full-pipe estimator --
full_bw: u64 = 0,
full_bw_count: u8 = 0,
full_bw_now: bool = false,
full_bw_reached: bool = false,

// -- §2.14 ProbeBW cycle state --
is_bw_probe_sample: bool = false,
bw_probe_up_acked: u64 = 0,
probe_up_acked_per_inc: u64 = infinity,
bw_probe_up_rounds: u8 = 0,
cycle_stamp_us: u64 = 0,
bw_probe_wait_us: u64 = 0,
prev_probe_too_high: bool = false,
prev_probe_precautionary: bool = false,

// -- §2.16 ProbeRTT / min_rtt scheduling --
probe_rtt_min_delay_us: u64 = infinity,
probe_rtt_min_stamp_us: u64 = 0,
probe_rtt_expired: bool = false,
probe_rtt_done_stamp_us: u64 = 0,
probe_rtt_round_done: bool = false,
prior_cwnd: u64 = 0,

// -- control outputs (§2.4/§2.5) --
/// 0 = no bandwidth sample yet; `pacingRateBps` then serves
/// InitPacingRate (§5.6.2).
pacing_rate: u64 = 0,
send_quantum: u64 = 0,

/// SplitMix64 state (see `prng_seed`).
prng: u64 = prng_seed,

/// C.delivered / C.lost mirrors (the sampler owns the truth; BBR
/// keeps copies because controllers hold no pointers).
delivered_total: u64 = 0,
lost_total: u64 = 0,

/// §5.2.1 OnInit. srtt is unknown at controller construction (the
/// union has no RTT until the first ACK), so min_rtt starts at
/// Infinity, the wall-clock stamps seed lazily on the first
/// sample, and InitPacingRate is served lazily by `pacingRateBps`.
/// Everything else in OnInit is a field default; Startup is the
/// default state with its gains implied by `state`.
pub fn init(cfg: congestion.Config) Bbr {
    return .{
        .cfg = cfg,
        .cwnd = cfg.initialWindow(),
    };
}

// =======================================================================
// event surface (union contract)
// =======================================================================

/// Recovery-exit maintenance only (§5.6.4.4 RestoreCwnd edge) plus
/// the srtt stash. No cwnd growth here — growth is sample-driven
/// (§5.6.4.6).
pub fn onPacketAcked(
    self: *Bbr,
    bytes_acked: u64,
    largest_acked_sent_time_us: u64,
    now_us: u64,
    srtt_us: u64,
    bytes_in_flight: u64,
) void {
    _ = bytes_acked;
    _ = now_us;
    _ = bytes_in_flight;
    self.stashed_srtt_us = srtt_us;
    if (self.recovery_start_time_us) |rec_start| {
        if (largest_acked_sent_time_us > rec_start) {
            self.recovery_start_time_us = null;
            self.restoreCwnd();
        }
    }
}

/// Stash RS.rtt for the sample that closes this ACK event.
pub fn onAckProcessed(
    self: *Bbr,
    largest_acked_pn: u64,
    latest_rtt_us: ?u64,
    next_pn_to_send: u64,
) void {
    _ = largest_acked_pn;
    _ = next_pn_to_send;
    if (latest_rtt_us) |rtt| self.stashed_rtt_us = rtt;
}

/// §5.2.3 UpdateOnACK minus GenerateRateSample (the transport's
/// sampler produced `rs`): UpdateModelAndState then
/// UpdateControlParameters, in the draft's order.
pub fn onDeliveryRateSample(
    self: *Bbr,
    rs: *const delivery_rate.RateSample,
    now_us: u64,
    bytes_in_flight: u64,
) void {
    self.delivered_total = rs.c_delivered;
    self.lost_total = @max(self.lost_total, rs.c_lost);

    // UpdateModelAndState:
    self.updateLatestDeliverySignals(rs);
    self.updateCongestionSignals(rs);
    self.updateAckAggregation(rs, now_us);
    self.checkStartupDone(rs);
    self.checkDrainDone(bytes_in_flight);
    self.updateProbeBWCyclePhase(rs, now_us, bytes_in_flight);
    self.updateMinRtt(now_us);
    self.checkProbeRtt(rs, now_us, bytes_in_flight);
    self.advanceLatestDeliverySignals(rs);
    self.boundBwForModel();

    // UpdateControlParameters:
    self.setPacingRate();
    self.setSendQuantum();
    self.setCwnd(rs);

    self.stashed_rtt_us = null; // RS.rtt is per-event
}

/// §5.2.2 OnTransmit -> §5.4.1 HandleRestartFromIdle, plus
/// C.is_cwnd_limited tracking. `bytes_in_flight_before` excludes
/// the packet being sent.
pub fn onPacketSent(
    self: *Bbr,
    now_us: u64,
    bytes_in_flight_before: u64,
    bytes: u64,
    is_app_limited: bool,
) void {
    const inflight_now = bytes_in_flight_before +| bytes;
    self.last_inflight_at_send = inflight_now;
    if (inflight_now >= self.cwnd) self.cwnd_limited_in_round = true;
    if (bytes_in_flight_before == 0 and is_app_limited) {
        self.idle_restart = true;
        self.extra_acked_interval_start_us = now_us;
        self.extra_acked_delivered = 0;
        if (self.isInAProbeBWState()) {
            // Restart by pacing at exactly bw (gain 1): back to
            // rate balance within one min_rtt (§5.4.1/§5.4.2).
            self.setPacingRateWithGain(1, 1);
        } else if (self.state == .probe_rtt) {
            self.checkProbeRttDone(now_us);
        }
    }
}

/// §5.5.10.2 HandleLostPacket, fed per newly-lost in-flight packet
/// during the loss walk (before the aggregate onPacketLost).
pub fn onPacketNewlyLost(self: *Bbr, info: *const delivery_rate.LostPacketInfo) void {
    self.lost_total = @max(self.lost_total, info.c_lost);
    self.noteLoss(info.c_delivered);
    if (!self.is_bw_probe_sample) return; // only packets sent while probing
    var tx_in_flight = info.tx_in_flight;
    const lost = self.lost_total -| info.lost_at_send;
    if (!inflightTooHigh(lost, tx_in_flight)) return;
    tx_in_flight = inflightAtLoss(tx_in_flight, lost, info.bytes);
    self.handleInflightTooHigh(info.is_app_limited, tx_in_flight);
}

/// Aggregate loss: the recovery-entry edge (§5.6.4.4
/// OnEnterFastRecovery — SaveCwnd). cwnd is NOT cut here; the
/// §5.5.10 model response owns the reaction.
pub fn onPacketLost(self: *Bbr, bytes_lost: u64, lost_largest_sent_time_us: u64) void {
    _ = bytes_lost;
    if (self.recovery_start_time_us) |rec_start| {
        // RFC 9002 §7.3.1: losses inside the period don't re-arm.
        if (lost_largest_sent_time_us <= rec_start) return;
        self.recovery_start_time_us = lost_largest_sent_time_us;
        return;
    }
    self.saveCwnd();
    self.recovery_entry_round = self.round_count;
    self.recovery_start_time_us = lost_largest_sent_time_us;
}

/// RFC 9002 §7.6.2 MUST: collapse to the transport's minimum
/// window (the draft's nearest analog, OnEnterRTO §5.6.4.4, is
/// equally drastic). The MODEL deliberately survives — recovering
/// quickly from a spurious collapse is BBR's design premise; the
/// next ACKs re-grow cwnd from bw * min_rtt. The §5.6.4.6 floor
/// lifts cwnd back to MinPipeCwnd (4 SMSS) on the next sample.
pub fn onPersistentCongestion(self: *Bbr) void {
    self.saveCwnd();
    self.cwnd = self.cfg.minWindow();
}

/// §3.7 MUST: when sending ECT, CE marks are treated as
/// congestion. Counted as a congestion round — the once-per-round
/// short-term decay (§5.5.10.3) fires at the round close.
/// DEVIATION: nothing quantitative beyond that; the draft declines
/// to specify a response magnitude.
pub fn onCongestionEvent(self: *Bbr, ce_packet_sent_time_us: u64) void {
    _ = ce_packet_sent_time_us;
    self.noteLoss(self.delivered_total);
}

// -- read surface -------------------------------------------------------

/// cwnd headroom in bytes; 0 means "wait". `cwnd` already carries
/// every §5.6.4.x modulation (MinPipeCwnd floor, ProbeRTT cap,
/// model bounds), so the plain difference is the whole answer.
pub fn sendAllowance(self: *const Bbr, bytes_in_flight: u64) u64 {
    if (bytes_in_flight >= self.cwnd) return 0;
    return self.cwnd - bytes_in_flight;
}

/// Startup is BBR's slow-start analog. Drain is deliberately
/// excluded: it is a deceleration phase.
pub fn isSlowStart(self: *const Bbr) bool {
    return self.state == .startup;
}

/// HyStart++ does not apply: Startup carries its own exit
/// machinery (§5.3.1), so `cfg.hystart` is ignored entirely.
pub fn isInCss(self: *const Bbr) bool {
    _ = self;
    return false;
}

pub fn isInRecovery(self: *const Bbr, sent_time_us: u64) bool {
    const rec_start = self.recovery_start_time_us orelse return false;
    return sent_time_us <= rec_start;
}

/// §5.6.2: the model-driven pacing rate (1% margin already
/// applied). Before the first bandwidth sample, InitPacingRate =
/// StartupPacingGain * InitialCwnd / max(srtt, 1 ms), computed
/// with the freshest srtt this controller has seen.
///
/// DEVIATION (floor): until the pipe has been observed full
/// (§5.3.1.2), the model rate never drops below InitPacingRate.
/// A trickle-only sender — the receive side of a bulk transfer,
/// whose only 1-RTT sends are the post-handshake control tail —
/// legitimately measures its own trickle (a few KB over an idle
/// gap) and would latch a garbage-low rate while parked in
/// Startup forever. Pacing that endpoint's flow-control credit at
/// KB/s starves the peer (found by the 2-flow BBR fairness cell);
/// a sender still probing for bandwidth has no evidence the path
/// is slower than a fresh connection's initial rate. Once
/// full_bw_reached, the model is trusted verbatim — including
/// below-floor rates on genuinely slow paths.
pub fn pacingRateBps(self: *const Bbr, srtt_us: u64) u64 {
    if (self.pacing_rate != 0 and self.full_bw_reached) return self.pacing_rate;
    const srtt = @max(if (srtt_us != 0) srtt_us else self.stashed_srtt_us, 1_000);
    const init_rate = std.math.lossyCast(
        u64,
        (@as(u128, self.cfg.initialWindow()) * startup_pacing_gain_num * us_per_s) /
            (@as(u128, startup_pacing_gain_den) * srtt),
    );
    return @max(self.pacing_rate, init_rate);
}

pub fn snapshot(self: *const Bbr) Snapshot {
    return .{
        .state = self.state,
        .max_bw = self.maxBw(),
        .bw = self.bw,
        .bw_shortterm = self.bw_shortterm,
        .min_rtt_us = self.min_rtt_us,
        .inflight_longterm = self.inflight_longterm,
        .inflight_shortterm = self.inflight_shortterm,
        .pacing_rate = self.pacing_rate,
        .extra_acked = self.extra_acked,
        .full_bw_reached = self.full_bw_reached,
        .round_count = self.round_count,
    };
}

// =======================================================================
// §5.5 model updates
// =======================================================================

fn maxBw(self: *const Bbr) u64 {
    return @max(self.max_bw_slots[0], self.max_bw_slots[1]);
}

/// §5.5.1 UpdateRound: the round test uses the newest delivered
/// packet's P.delivered (rs.prior_delivered).
fn updateRound(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    if (rs.prior_delivered >= self.next_round_delivered) {
        self.next_round_delivered = rs.c_delivered; // StartRound()
        self.round_count +%= 1;
        self.rounds_since_probe_up +|= 1;
        self.round_start = true;
    } else {
        self.round_start = false;
    }
}

/// §5.5.5 UpdateMaxBw (which per the pseudocode also advances the
/// round counter). §5.5.4: app-limited samples count only when
/// they RAISE the estimate; `has_rate` keeps unreliable intervals
/// out entirely.
fn updateMaxBw(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    self.updateRound(rs);
    if (rs.has_rate and rs.delivery_rate_bps > 0 and
        (rs.delivery_rate_bps >= self.maxBw() or !rs.is_app_limited))
    {
        const slot: usize = self.cycle_count;
        self.max_bw_slots[slot] = @max(self.max_bw_slots[slot], rs.delivery_rate_bps);
    }
}

/// §5.5.6 AdvanceMaxBwFilter: one tick of the 2-cycle virtual time.
fn advanceMaxBwFilter(self: *Bbr) void {
    self.cycle_count +%= 1;
    self.max_bw_slots[@as(usize, self.cycle_count)] = 0;
}

/// §5.5.10.3 UpdateLatestDeliverySignals.
fn updateLatestDeliverySignals(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    self.loss_round_start = false;
    if (rs.has_rate) self.bw_latest = @max(self.bw_latest, rs.delivery_rate_bps);
    self.inflight_latest = @max(self.inflight_latest, rs.delivered);
    if (rs.prior_delivered >= self.loss_round_delivered) {
        self.loss_round_delivered = rs.c_delivered;
        self.loss_round_start = true;
    }
}

/// §5.5.10.3 AdvanceLatestDeliverySignals, plus the round-scoped
/// cwnd-limited reset (its §5.3.3.9 consumers ran earlier in this
/// same ACK's pipeline).
fn advanceLatestDeliverySignals(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    if (self.loss_round_start) {
        self.bw_latest = if (rs.has_rate) rs.delivery_rate_bps else 0;
        self.inflight_latest = rs.delivered;
    }
    if (self.round_start) self.cwnd_limited_in_round = false;
}

/// §5.5.10.3 UpdateCongestionSignals: max_bw update plus the
/// once-per-loss-round short-term adaptation. The closing values
/// are captured for same-ACK consumers before the live counters
/// reset (CheckStartupHighLoss runs later in the pipeline).
fn updateCongestionSignals(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    self.updateMaxBw(rs);
    if (!self.loss_round_start) {
        self.closed_round_had_loss = false;
        self.closed_round_loss_events = 0;
        return; // wait until end of round trip
    }
    self.closed_round_had_loss = self.is_loss_in_round;
    self.closed_round_loss_events = self.loss_events_in_round;
    self.adaptLowerBoundsFromCongestion();
    self.is_loss_in_round = false;
    self.loss_events_in_round = 0;
}

/// §5.5.10.3 AdaptLowerBoundsFromCongestion + InitLowerBounds +
/// LossLowerBounds.
fn adaptLowerBoundsFromCongestion(self: *Bbr) void {
    if (self.isProbingBw()) return;
    if (!self.is_loss_in_round) return;
    if (self.bw_shortterm == infinity) self.bw_shortterm = self.maxBw();
    if (self.inflight_shortterm == infinity) self.inflight_shortterm = self.cwnd;
    self.bw_shortterm = @max(self.bw_latest, mulDiv(self.bw_shortterm, beta_num, beta_den));
    self.inflight_shortterm = @max(
        self.inflight_latest,
        mulDiv(self.inflight_shortterm, beta_num, beta_den),
    );
}

/// §5.5.10.3 ResetCongestionSignals.
fn resetCongestionSignals(self: *Bbr) void {
    self.is_loss_in_round = false;
    self.loss_events_in_round = 0;
    self.bw_latest = 0;
    self.inflight_latest = 0;
}

/// §5.5.10.3 ResetShortTermModel.
fn resetShortTermModel(self: *Bbr) void {
    self.bw_shortterm = infinity;
    self.inflight_shortterm = infinity;
}

/// §5.5.10.3 BoundBWForModel.
fn boundBwForModel(self: *Bbr) void {
    self.bw = @min(self.maxBw(), self.bw_shortterm);
}

/// §5.5.9 UpdateACKAggregation.
fn updateAckAggregation(self: *Bbr, rs: *const delivery_rate.RateSample, now_us: u64) void {
    if (self.extra_acked_interval_start_us == 0) {
        self.extra_acked_interval_start_us = now_us; // lazy OnInit
    }
    const interval_us = now_us -| self.extra_acked_interval_start_us;
    var expected = mulDiv(self.bw, interval_us, us_per_s);
    if (self.extra_acked_delivered <= expected) {
        // ACK rate at or below the expected bandwidth: any
        // aggregation episode is over; restart the interval.
        self.extra_acked_delivered = 0;
        self.extra_acked_interval_start_us = now_us;
        expected = 0;
    }
    self.extra_acked_delivered +|= rs.newly_acked;
    var extra = self.extra_acked_delivered -| expected;
    extra = @min(extra, self.cwnd);
    const window: u64 = if (self.full_bw_reached) extra_acked_filter_len_rounds else 1;
    self.extra_acked = self.extra_acked_filter.update(self.round_count, extra, window);
}

/// §5.3.4.3 UpdateMinRTT. Wall-clock stamps seed lazily on the
/// first sample (OnInit has no clock in this embedding).
fn updateMinRtt(self: *Bbr, now_us: u64) void {
    if (self.probe_rtt_min_stamp_us == 0) self.probe_rtt_min_stamp_us = now_us;
    if (self.min_rtt_stamp_us == 0) self.min_rtt_stamp_us = now_us;
    self.probe_rtt_expired =
        now_us > self.probe_rtt_min_stamp_us +| probe_rtt_interval_us;
    if (self.stashed_rtt_us) |rtt| {
        if (rtt < self.probe_rtt_min_delay_us or self.probe_rtt_expired) {
            self.probe_rtt_min_delay_us = rtt;
            self.probe_rtt_min_stamp_us = now_us;
        }
    }
    const min_rtt_expired =
        now_us > self.min_rtt_stamp_us +| min_rtt_filter_len_us;
    if (self.probe_rtt_min_delay_us < self.min_rtt_us or min_rtt_expired) {
        self.min_rtt_us = self.probe_rtt_min_delay_us;
        self.min_rtt_stamp_us = self.probe_rtt_min_stamp_us;
    }
}

/// §5.5.10.2/§5.5.10.3 NoteLoss. (SaveStateUponLoss is the §5.5.11
/// undo machinery — DEVIATION, not implemented; see the header.)
fn noteLoss(self: *Bbr, c_delivered_at_loss: u64) void {
    if (!self.is_loss_in_round) {
        self.loss_round_delivered = c_delivered_at_loss;
    }
    self.is_loss_in_round = true;
    self.loss_events_in_round +|= 1;
}

/// §5.5.10.2 HandleInflightTooHigh.
fn handleInflightTooHigh(self: *Bbr, is_app_limited: bool, tx_in_flight: u64) void {
    self.prev_probe_too_high = true;
    self.is_bw_probe_sample = false; // react once per bw probe
    if (!is_app_limited) {
        self.inflight_longterm = @max(
            tx_in_flight,
            mulDiv(self.targetInflight(), beta_num, beta_den),
        );
    }
    if (self.state == .probe_up) self.probe_down_pending = true;
}

// =======================================================================
// §5.3 state machine
// =======================================================================

/// §5.3.1.1 EnterStartup (gains are functions of `state`).
fn enterStartup(self: *Bbr) void {
    self.state = .startup;
}

/// §5.3.1.2 ResetFullBW.
fn resetFullBw(self: *Bbr) void {
    self.full_bw = 0;
    self.full_bw_count = 0;
    self.full_bw_now = false;
}

/// §5.3.1.2 CheckFullBWReached. DEVIATION: also suppressed while in
/// ProbeRTT, standing in for HandleProbeRTT's
/// MarkConnectionAppLimited (see the module header).
fn checkFullBwReached(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    if (self.full_bw_now or !self.round_start or rs.is_app_limited) return;
    if (self.state == .probe_rtt) return;
    if (!rs.has_rate) return;
    if (rs.delivery_rate_bps >= mulDiv(self.full_bw, full_bw_growth_num, full_bw_growth_den)) {
        self.resetFullBw();
        self.full_bw = rs.delivery_rate_bps; // still growing: new baseline
        return;
    }
    self.full_bw_count += 1; // another round without much growth
    self.full_bw_now = self.full_bw_count >= full_bw_count_target;
    if (self.full_bw_now) self.full_bw_reached = true;
}

/// §5.3.1.3 CheckStartupHighLoss, evaluated at loss-round close.
/// QUIC always has selective acks, so the multi-criteria branch
/// applies. DEVIATION: >= 6 lost packets stands in for "6
/// discontiguous sequence ranges" (conservative direction — may
/// exit Startup earlier, never later).
fn checkStartupHighLoss(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    if (self.state != .startup) return;
    if (!self.loss_round_start or !self.closed_round_had_loss) return;
    // In fast recovery for at least one full round trip:
    if (self.recovery_start_time_us == null) return;
    if (self.round_count <= self.recovery_entry_round) return;
    // Round loss rate above LossThresh:
    if (!inflightTooHigh(rs.lost, rs.tx_in_flight)) return;
    if (self.closed_round_loss_events < startup_full_loss_cnt) return;
    self.full_bw_reached = true;
    self.inflight_longterm = @max(self.bdp(), self.inflight_latest);
}

/// §5.3.1.1 CheckStartupDone.
fn checkStartupDone(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    self.checkFullBwReached(rs);
    self.checkStartupHighLoss(rs);
    if (self.state == .startup and self.full_bw_reached) self.enterDrain();
}

/// §5.3.2 EnterDrain.
fn enterDrain(self: *Bbr) void {
    self.state = .drain;
    self.drain_start_round = self.round_count;
}

/// §5.3.2 CheckDrainDone.
fn checkDrainDone(self: *Bbr, bytes_in_flight: u64) void {
    if (self.state != .drain) return;
    if (bytes_in_flight <= self.inflightForGain(1, 1) or
        self.round_count > self.drain_start_round +| drain_exit_extra_rounds)
    {
        // §5.3.3.9 EnterProbeBW = StartProbeBW_DOWN; the wall
        // clock arrives with this pass's
        // updateProbeBWCyclePhase(now), which consumes the flag.
        self.state = .probe_down;
        self.probe_down_pending = true;
    }
}

// -- §5.3.3 ProbeBW ------------------------------------------------------

/// §5.3.3.9 StartProbeBW_DOWN.
fn startProbeDown(self: *Bbr, now_us: u64) void {
    self.resetCongestionSignals();
    self.probe_up_acked_per_inc = infinity; // not growing inflight_longterm
    self.pickProbeWait();
    self.cycle_stamp_us = now_us; // start the wall clock
    self.ack_phase = .probe_stopping;
    self.next_round_delivered = self.delivered_total; // StartRound()
    self.state = .probe_down;
    self.probe_down_pending = false;
}

/// §5.3.3.9 StartProbeBW_CRUISE.
fn startProbeCruise(self: *Bbr) void {
    self.state = .probe_cruise;
}

/// §5.3.3.9 StartProbeBW_REFILL.
fn startProbeRefill(self: *Bbr) void {
    self.resetShortTermModel();
    self.bw_probe_up_rounds = 0;
    self.bw_probe_up_acked = 0;
    self.prev_probe_precautionary = false;
    self.ack_phase = .refilling;
    self.next_round_delivered = self.delivered_total; // StartRound()
    self.state = .probe_refill;
}

/// §5.3.3.9 StartProbeBW_UP.
fn startProbeUp(self: *Bbr, rs: *const delivery_rate.RateSample, now_us: u64) void {
    self.ack_phase = .probe_starting;
    self.next_round_delivered = self.delivered_total; // StartRound()
    self.cycle_stamp_us = now_us;
    self.resetFullBw();
    self.full_bw = if (rs.has_rate) rs.delivery_rate_bps else 0;
    self.state = .probe_up;
    self.raiseInflightLongtermSlope();
}

/// §5.3.3.9 UpdateProbeBWCyclePhase: the ProbeBW state logic, on
/// each ACK that produced a sample.
fn updateProbeBWCyclePhase(
    self: *Bbr,
    rs: *const delivery_rate.RateSample,
    now_us: u64,
    bytes_in_flight: u64,
) void {
    if (!self.full_bw_reached) return; // steady-state only
    if (self.probe_down_pending) {
        // A transition decided where no wall clock existed (the
        // loss walk, or Drain's exit) — finalize with this ACK's.
        self.startProbeDown(now_us);
        return;
    }
    if (self.adaptLongTermModel(rs)) return; // decided a transition
    if (!self.isInAProbeBWState()) return;

    switch (self.state) {
        .probe_down => {
            if (self.isTimeToProbeBw(now_us)) return;
            if (self.isTimeToCruise(bytes_in_flight)) self.startProbeCruise();
        },
        .probe_cruise => {
            if (self.isTimeToProbeBw(now_us)) return;
        },
        .probe_refill => {
            // After one round of REFILL, start UP.
            if (self.round_start) {
                self.is_bw_probe_sample = true;
                self.startProbeUp(rs, now_us);
            }
        },
        .probe_up => {
            if (self.isTimeToGoDown(rs, bytes_in_flight)) {
                self.prev_probe_too_high = false; // no high loss (yet)
                self.startProbeDown(now_us);
            }
        },
        else => {},
    }
}

fn isInAProbeBWState(self: *const Bbr) bool {
    return switch (self.state) {
        .probe_down, .probe_cruise, .probe_refill, .probe_up => true,
        else => false,
    };
}

/// §5.3.3.9 IsTimeToCruise: headroom AND queue drained.
fn isTimeToCruise(self: *const Bbr, bytes_in_flight: u64) bool {
    if (bytes_in_flight > self.inflightWithHeadroom()) return false;
    if (bytes_in_flight > self.inflightForMaxBw()) return false;
    return true;
}

/// §5.3.3.9 IsTimeToGoDown (+ §5.3.3.6 precautionary deceleration).
fn isTimeToGoDown(self: *Bbr, rs: *const delivery_rate.RateSample, bytes_in_flight: u64) bool {
    const inflight_seen = @max(self.last_inflight_at_send, bytes_in_flight);
    if (self.prev_probe_too_high and self.inflight_longterm != infinity and
        inflight_seen >= self.inflight_longterm)
    {
        self.prev_probe_precautionary = true;
        return true;
    }
    if (self.cwnd_limited_in_round and self.inflight_longterm != infinity and
        self.cwnd >= self.inflight_longterm)
    {
        // bw is limited by inflight_longterm — keep the full-pipe
        // estimator from concluding on a self-inflicted plateau.
        self.resetFullBw();
        self.full_bw = if (rs.has_rate) rs.delivery_rate_bps else 0;
    } else if (self.full_bw_now) {
        return true; // bandwidth plateau: the path is fully used
    }
    return false;
}

/// §5.3.3.9 IsProbingBW: the accelerating states.
fn isProbingBw(self: *const Bbr) bool {
    return switch (self.state) {
        .startup, .probe_refill, .probe_up => true,
        else => false,
    };
}

/// §5.3.3.8.3 IsTimeToProbeBW.
fn isTimeToProbeBw(self: *Bbr, now_us: u64) bool {
    if (now_us > self.cycle_stamp_us +| self.bw_probe_wait_us or
        self.isRenoCoexistenceProbeTime())
    {
        self.startProbeRefill();
        return true;
    }
    return false;
}

/// §5.3.3.8.3 PickProbeWait: re-seed the round counter with 0 or 1
/// and draw the 2..3 s wall-clock bound.
fn pickProbeWait(self: *Bbr) void {
    self.rounds_since_probe_up = self.nextRandom() & 1;
    self.bw_probe_wait_us =
        bw_probe_wait_base_us + (self.nextRandom() % bw_probe_wait_rand_us);
}

/// §5.3.3.8.3 IsRenoCoexistenceProbeTime. TargetInflight is bytes;
/// the draft's T_reno counts round trips numerically equal to the
/// BDP in PACKETS (§5.3.3.8.2's "BDP ~= 62 packets" arithmetic),
/// hence the SMSS division in this byte-based implementation.
fn isRenoCoexistenceProbeTime(self: *const Bbr) bool {
    const reno_rounds = self.targetInflight() / @max(self.cfg.max_datagram_size, 1);
    const rounds = @min(reno_rounds, reno_coexistence_rounds_cap);
    return self.rounds_since_probe_up >= rounds;
}

/// §5.3.3.8.3 TargetInflight: min(bdp, cwnd).
fn targetInflight(self: *const Bbr) u64 {
    return @min(self.bdp(), self.cwnd);
}

/// §5.3.3.9 InflightWithHeadroom: leave (at least one SMSS of)
/// free space under inflight_longterm for cross traffic.
fn inflightWithHeadroom(self: *const Bbr) u64 {
    if (self.inflight_longterm == infinity) return infinity;
    const headroom = @max(
        self.cfg.max_datagram_size,
        mulDiv(self.inflight_longterm, headroom_num, headroom_den),
    );
    return @max(self.inflight_longterm -| headroom, self.minPipeCwnd());
}

/// §5.3.3.9 RaiseInflightLongtermSlope: 1, 2, 4, ... SMSS per
/// round, spread across the round via probe_up_acked_per_inc.
fn raiseInflightLongtermSlope(self: *Bbr) void {
    const shift: u6 = @intCast(@min(self.bw_probe_up_rounds, 62));
    const growth_this_round = @as(u64, 1) << shift;
    self.bw_probe_up_rounds = @min(self.bw_probe_up_rounds + 1, probe_up_rounds_cap);
    self.probe_up_acked_per_inc =
        @max(self.cwnd / growth_this_round, self.cfg.max_datagram_size);
}

/// §5.3.3.9 ProbeInflightLongtermUpward.
fn probeInflightLongtermUpward(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    if (!self.cwnd_limited_in_round or self.cwnd < self.inflight_longterm) {
        return; // not fully using inflight_longterm: don't grow it
    }
    self.bw_probe_up_acked +|= rs.newly_acked;
    if (self.bw_probe_up_acked >= self.probe_up_acked_per_inc) {
        const delta = self.bw_probe_up_acked / self.probe_up_acked_per_inc;
        self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
        self.inflight_longterm +|= delta *| self.cfg.max_datagram_size;
    }
    if (self.round_start) self.raiseInflightLongtermSlope();
}

/// §5.3.3.9 AdaptLongTermModel. Returns true when it decided a
/// state transition.
fn adaptLongTermModel(self: *Bbr, rs: *const delivery_rate.RateSample) bool {
    if (self.ack_phase == .probe_starting and self.round_start) {
        self.ack_phase = .probe_feedback; // bw probing samples begin
    }
    if (self.ack_phase == .probe_stopping and self.round_start) {
        // End of samples from the bandwidth probing phase.
        self.is_bw_probe_sample = false;
        self.ack_phase = .init;
        if (self.isInAProbeBWState() and !rs.is_app_limited) {
            self.advanceMaxBwFilter();
        }
        // §5.3.3.6 precautionary acceleration: the cautious probe
        // survived a full feedback round without excess loss, so
        // return to REFILL immediately (bypassing CRUISE).
        if (self.isInAProbeBWState() and
            self.prev_probe_precautionary and !self.prev_probe_too_high)
        {
            self.startProbeRefill();
            return true;
        }
    }
    if (!inflightTooHigh(rs.lost, rs.tx_in_flight)) {
        // Loss rate is safe: adjust the upper bound upward.
        if (self.inflight_longterm == infinity) return false;
        if (rs.tx_in_flight > self.inflight_longterm) {
            self.inflight_longterm = rs.tx_in_flight;
        }
        if (self.state == .probe_up) self.probeInflightLongtermUpward(rs);
    }
    return false;
}

// -- §5.3.4 ProbeRTT -----------------------------------------------------

/// §5.3.4.3 CheckProbeRTT.
fn checkProbeRtt(
    self: *Bbr,
    rs: *const delivery_rate.RateSample,
    now_us: u64,
    bytes_in_flight: u64,
) void {
    if (self.state != .probe_rtt and self.probe_rtt_expired and !self.idle_restart) {
        self.state = .probe_rtt; // EnterProbeRTT (gains via state)
        self.saveCwnd();
        self.probe_rtt_done_stamp_us = 0;
        self.ack_phase = .probe_stopping;
        self.next_round_delivered = self.delivered_total; // StartRound()
    }
    if (self.state == .probe_rtt) {
        self.handleProbeRtt(now_us, bytes_in_flight);
    }
    if (rs.delivered > 0) self.idle_restart = false;
}

/// §5.3.4.3 HandleProbeRTT. DEVIATION: MarkConnectionAppLimited()
/// is replaced by the ProbeRTT guard inside checkFullBwReached
/// (the sampler is out of reach from the controller).
fn handleProbeRtt(self: *Bbr, now_us: u64, bytes_in_flight: u64) void {
    if (self.probe_rtt_done_stamp_us == 0 and bytes_in_flight <= self.probeRttCwnd()) {
        // Inflight has drained to the ProbeRTT level: dwell for at
        // least ProbeRTTDuration and one round.
        self.probe_rtt_done_stamp_us = now_us +| probe_rtt_duration_us;
        self.probe_rtt_round_done = false;
        self.next_round_delivered = self.delivered_total; // StartRound()
    } else if (self.probe_rtt_done_stamp_us != 0) {
        if (self.round_start) self.probe_rtt_round_done = true;
        if (self.probe_rtt_round_done) self.checkProbeRttDone(now_us);
    }
}

/// §5.3.4.3 CheckProbeRTTDone.
fn checkProbeRttDone(self: *Bbr, now_us: u64) void {
    if (self.probe_rtt_done_stamp_us != 0 and now_us > self.probe_rtt_done_stamp_us) {
        self.probe_rtt_min_stamp_us = now_us; // schedule next ProbeRTT
        self.restoreCwnd();
        self.exitProbeRtt(now_us);
    }
}

/// §5.3.4.4 ExitProbeRTT: reset the short-term model; re-enter
/// ProbeBW at CRUISE via a fresh DOWN (resetting the probe clock)
/// when the pipe was ever filled, else back to Startup.
fn exitProbeRtt(self: *Bbr, now_us: u64) void {
    self.resetShortTermModel();
    if (self.full_bw_reached) {
        self.startProbeDown(now_us);
        self.startProbeCruise();
    } else {
        self.enterStartup();
    }
}

// =======================================================================
// §5.6 control parameters
// =======================================================================

/// §5.6.1: BBR.pacing_gain and BBR.cwnd_gain are pure functions of
/// the state (the table), so they cannot drift from it.
fn pacingGainNum(self: *const Bbr) u64 {
    return switch (self.state) {
        .startup => startup_pacing_gain_num,
        .drain => drain_pacing_gain_num,
        .probe_down => probe_down_pacing_gain_num,
        .probe_cruise, .probe_refill, .probe_rtt => 1,
        .probe_up => probe_up_pacing_gain_num,
    };
}

fn pacingGainDen(self: *const Bbr) u64 {
    return switch (self.state) {
        .startup => startup_pacing_gain_den,
        .drain => drain_pacing_gain_den,
        .probe_down => probe_down_pacing_gain_den,
        .probe_cruise, .probe_refill, .probe_rtt => 1,
        .probe_up => probe_up_pacing_gain_den,
    };
}

fn cwndGainNum(self: *const Bbr) u64 {
    return switch (self.state) {
        .probe_rtt => probe_rtt_cwnd_gain_num,
        .probe_up => probe_up_cwnd_gain_num,
        else => default_cwnd_gain_num,
    };
}

fn cwndGainDen(self: *const Bbr) u64 {
    return switch (self.state) {
        .probe_rtt => probe_rtt_cwnd_gain_den,
        .probe_up => probe_up_cwnd_gain_den,
        else => default_cwnd_gain_den,
    };
}

/// §5.6.2 SetPacingRateWithGain: rate = gain * bw * 99%; applied
/// only when it raises the rate or the pipe was filled — never
/// throttle the Startup search on a shrinking (e.g. app-limited)
/// estimate.
fn setPacingRateWithGain(self: *Bbr, gain_num: u64, gain_den: u64) void {
    if (self.bw == 0) return; // pre-sample: InitPacingRate governs
    const rate = std.math.lossyCast(
        u64,
        (@as(u128, self.bw) * gain_num * pacing_margin_num) /
            (@as(u128, gain_den) * pacing_margin_den),
    );
    if (self.full_bw_reached or rate > self.pacing_rate) {
        self.pacing_rate = rate;
    }
}

/// §5.6.2 SetPacingRate.
fn setPacingRate(self: *Bbr) void {
    self.setPacingRateWithGain(self.pacingGainNum(), self.pacingGainDen());
}

/// §5.6.3 SetSendQuantum: 1 ms of pacing rate in [2*SMSS, 64KB].
/// §5.5.8.2: for QUIC the offload budget IS the send quantum.
fn setSendQuantum(self: *Bbr) void {
    var quantum = mulDiv(self.pacing_rate, 1_000, us_per_s);
    quantum = @min(quantum, send_quantum_max_bytes);
    quantum = @max(quantum, send_quantum_min_packets *| self.cfg.max_datagram_size);
    self.send_quantum = quantum;
}

/// §5.6.4.2 BBR.bdp = BBR.bw * BBR.min_rtt.
fn bdp(self: *const Bbr) u64 {
    if (self.min_rtt_us == infinity) return self.cfg.initialWindow();
    return mulDiv(self.bw, self.min_rtt_us, us_per_s);
}

/// §5.6.4.2 BDPMultiple(gain), against BBR.bw.
fn bdpMultiple(self: *const Bbr, gain_num: u64, gain_den: u64) u64 {
    if (self.min_rtt_us == infinity) {
        return self.cfg.initialWindow(); // no valid RTT samples yet
    }
    return std.math.lossyCast(
        u64,
        (@as(u128, self.bw) * self.min_rtt_us * gain_num) /
            (@as(u128, us_per_s) * gain_den),
    );
}

/// §5.6.4.2 Inflight(gain) = QuantizationBudget(BDPMultiple(gain)).
fn inflightForGain(self: *const Bbr, gain_num: u64, gain_den: u64) u64 {
    return self.quantizationBudget(self.bdpMultiple(gain_num, gain_den));
}

/// §5.3.3.9's IsTimeToCruise second test uses Inflight(max_bw, 1.0)
/// — the BDP against max_bw rather than the bounded bw.
fn inflightForMaxBw(self: *const Bbr) u64 {
    if (self.min_rtt_us == infinity) return self.cfg.initialWindow();
    const cap = std.math.lossyCast(
        u64,
        (@as(u128, self.maxBw()) * self.min_rtt_us) / us_per_s,
    );
    return self.quantizationBudget(cap);
}

/// §2.8 / §5.6.4.3 BBR.MinPipeCwnd.
fn minPipeCwnd(self: *const Bbr) u64 {
    return min_pipe_cwnd_packets *| self.cfg.max_datagram_size;
}

/// §5.6.4.2 QuantizationBudget.
fn quantizationBudget(self: *const Bbr, inflight_cap_in: u64) u64 {
    var cap = inflight_cap_in;
    cap = @max(cap, self.send_quantum); // QUIC offload budget (§5.5.8.2)
    cap = @max(cap, self.minPipeCwnd());
    if (self.state == .probe_up) cap +|= 2 *| self.cfg.max_datagram_size;
    return cap;
}

/// §5.6.4.2 UpdateMaxInflight.
fn maxInflight(self: *const Bbr) u64 {
    const cap = self.bdpMultiple(self.cwndGainNum(), self.cwndGainDen()) +| self.extra_acked;
    return self.quantizationBudget(cap);
}

/// §5.6.4.6 SetCwnd, then the §5.6.4.5/§5.6.4.7 bounds.
fn setCwnd(self: *Bbr, rs: *const delivery_rate.RateSample) void {
    const max_inflight = self.maxInflight();
    if (self.full_bw_reached) {
        self.cwnd = @min(self.cwnd +| rs.newly_acked, max_inflight);
    } else if (self.cwnd < max_inflight or self.delivered_total < self.cfg.initialWindow()) {
        self.cwnd = self.cwnd +| rs.newly_acked;
    }
    self.cwnd = @max(self.cwnd, self.minPipeCwnd());
    self.boundCwndForProbeRtt();
    self.boundCwndForModel();
}

/// §5.6.4.5 ProbeRTTCwnd = max(0.5 * BDP, MinPipeCwnd).
fn probeRttCwnd(self: *const Bbr) u64 {
    return @max(
        self.bdpMultiple(probe_rtt_cwnd_gain_num, probe_rtt_cwnd_gain_den),
        self.minPipeCwnd(),
    );
}

fn boundCwndForProbeRtt(self: *Bbr) void {
    if (self.state == .probe_rtt) {
        self.cwnd = @min(self.cwnd, self.probeRttCwnd());
    }
}

/// §5.6.4.7 BoundCwndForModel. The pseudocode is normative where
/// the §5.6.1 table disagrees (the table also lists
/// inflight_longterm for Drain; the pseudocode applies only the
/// short-term bound there).
fn boundCwndForModel(self: *Bbr) void {
    var cap: u64 = infinity;
    if (self.isInAProbeBWState() and self.state != .probe_cruise) {
        cap = self.inflight_longterm;
    } else if (self.state == .probe_rtt or self.state == .probe_cruise) {
        cap = self.inflightWithHeadroom();
    }
    cap = @min(cap, self.inflight_shortterm);
    cap = @max(cap, self.minPipeCwnd());
    self.cwnd = @min(self.cwnd, cap);
}

/// §5.6.4.4 SaveCwnd: remember the last-known-good cwnd
/// (unmodulated by recovery or ProbeRTT).
fn saveCwnd(self: *Bbr) void {
    if (self.recovery_start_time_us == null and self.state != .probe_rtt) {
        self.prior_cwnd = self.cwnd;
    } else {
        self.prior_cwnd = @max(self.prior_cwnd, self.cwnd);
    }
}

/// §5.6.4.4 RestoreCwnd.
fn restoreCwnd(self: *Bbr) void {
    self.cwnd = @max(self.cwnd, self.prior_cwnd);
}

/// SplitMix64 step (fixed documented seed; see `prng_seed`).
fn nextRandom(self: *Bbr) u64 {
    self.prng +%= 0x9e3779b97f4a7c15;
    var z = self.prng;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/// §5.5.10.2 IsInflightTooHigh: lost > tx_in_flight * LossThresh,
/// cross-multiplied in integers. QUIC always has selective acks, so
/// the single-loss fallback branch never applies.
fn inflightTooHigh(lost: u64, tx_in_flight: u64) bool {
    return @as(u128, lost) * loss_thresh_den > @as(u128, tx_in_flight) * loss_thresh_num;
}

/// §5.5.10.2 InflightAtLoss in integer form. With LossThresh = 1/50:
/// lost_prefix = (thresh*inflight_prev - lost_prev) / (1 - thresh)
///             = (inflight_prev - 50*lost_prev) / 49, floored at 0.
fn inflightAtLoss(tx_in_flight: u64, lost: u64, size: u64) u64 {
    const inflight_prev = tx_in_flight -| size;
    const lost_prev = lost -| size;
    const scaled_prev = @as(u128, inflight_prev) * loss_thresh_num;
    const scaled_lost = @as(u128, lost_prev) * loss_thresh_den;
    if (scaled_lost >= scaled_prev) return inflight_prev;
    const lost_prefix = (scaled_prev - scaled_lost) / (loss_thresh_den - loss_thresh_num);
    return inflight_prev +| std.math.lossyCast(u64, lost_prefix);
}

/// (a * num) / den with a u128 intermediate; saturating narrow.
fn mulDiv(a: u64, num: u64, den: u64) u64 {
    return std.math.lossyCast(u64, (@as(u128, a) * num) / den);
}

// -- tests -------------------------------------------------------------------

const testing = std.testing;

fn testCfg() congestion.Config {
    return .{ .max_datagram_size = 1_200, .algorithm = .bbr };
}

test "windowed max filter reports the in-window max and ages out" {
    var f: WindowedMaxFilter = .{};
    _ = f.update(1, 100, 10);
    _ = f.update(2, 80, 10);
    try testing.expectEqual(@as(u64, 100), f.max());
    // A larger sample takes over instantly.
    _ = f.update(3, 150, 10);
    try testing.expectEqual(@as(u64, 150), f.max());
    // Once its timestamp leaves the window, the max falls back to the
    // best surviving sample.
    _ = f.update(10, 90, 10);
    try testing.expectEqual(@as(u64, 150), f.max());
    _ = f.update(15, 70, 10);
    try testing.expect(f.max() < 150);
}

test "inflightTooHigh crosses at exactly 2% and inflightAtLoss inverts the threshold" {
    // 2% of 50_000 = 1_000: at the threshold is NOT too high (strict >).
    try testing.expect(!inflightTooHigh(1_000, 50_000));
    try testing.expect(inflightTooHigh(1_001, 50_000));
    try testing.expect(!inflightTooHigh(0, 0));

    // InflightAtLoss: with no prior loss, the prefix where losses
    // cross 2% of a 50_000-byte flight preceding a 1_200-byte packet:
    // inflight_prev = 48_800, lost_prev = 0 ->
    // prefix = 48_800/49 = 995 -> 49_795.
    try testing.expectEqual(@as(u64, 48_800 + 995), inflightAtLoss(50_000, 1_200, 1_200));
    // Losses already past the threshold clamp to inflight_prev.
    try testing.expectEqual(@as(u64, 48_800), inflightAtLoss(50_000, 3_000, 1_200));
}

test "pickProbeWait draws from [2s, 3s) deterministically from the fixed seed" {
    var bbr = Bbr.init(testCfg());
    var prev: u64 = 0;
    var differs = false;
    for (0..8) |_| {
        bbr.pickProbeWait();
        try testing.expect(bbr.bw_probe_wait_us >= bw_probe_wait_base_us);
        try testing.expect(bbr.bw_probe_wait_us < bw_probe_wait_base_us + bw_probe_wait_rand_us);
        try testing.expect(bbr.rounds_since_probe_up <= 1);
        if (prev != 0 and bbr.bw_probe_wait_us != prev) differs = true;
        prev = bbr.bw_probe_wait_us;
    }
    // The jitter must actually vary across probes (de-synchronization,
    // §5.3.3.8.2) even though the seed is fixed for reproducibility.
    try testing.expect(differs);
    // Determinism: a second controller draws the identical sequence.
    var bbr2 = Bbr.init(testCfg());
    bbr2.pickProbeWait();
    var bbr3 = Bbr.init(testCfg());
    bbr3.pickProbeWait();
    try testing.expectEqual(bbr3.bw_probe_wait_us, bbr2.bw_probe_wait_us);
}

test "recovery edges: SaveCwnd on entry, RestoreCwnd + re-bound on exit, no re-arm inside" {
    var bbr = Bbr.init(testCfg());
    bbr.cwnd = 60_000;
    bbr.onPacketLost(1_200, 1_000_000);
    try testing.expectEqual(@as(?u64, 1_000_000), bbr.recovery_start_time_us);
    try testing.expectEqual(@as(u64, 60_000), bbr.prior_cwnd);
    // Loss inside the period must not move the anchor.
    bbr.onPacketLost(1_200, 900_000);
    try testing.expectEqual(@as(?u64, 1_000_000), bbr.recovery_start_time_us);
    try testing.expect(bbr.isInRecovery(1_000_000));
    try testing.expect(!bbr.isInRecovery(1_000_001));
    // Model response may have shrunk cwnd meanwhile; the exit restores.
    bbr.cwnd = 20_000;
    bbr.onPacketAcked(1_200, 1_500_000, 2_000_000, 50_000, 10_000);
    try testing.expectEqual(@as(?u64, null), bbr.recovery_start_time_us);
    try testing.expectEqual(@as(u64, 60_000), bbr.cwnd);
}

test "persistent congestion collapses cwnd to the minimum window but keeps the model" {
    var bbr = Bbr.init(testCfg());
    bbr.cwnd = 100_000;
    bbr.max_bw_slots[0] = 5_000_000;
    bbr.min_rtt_us = 20_000;
    bbr.onPersistentCongestion();
    try testing.expectEqual(bbr.cfg.minWindow(), bbr.cwnd);
    try testing.expectEqual(@as(u64, 5_000_000), bbr.maxBw());
    try testing.expectEqual(@as(u64, 20_000), bbr.min_rtt_us);
}

test "restart from idle re-arms the aggregation clock and skips ProbeRTT entry" {
    var bbr = Bbr.init(testCfg());
    bbr.onPacketSent(9_000_000, 0, 1_200, true);
    try testing.expect(bbr.idle_restart);
    try testing.expectEqual(@as(u64, 9_000_000), bbr.extra_acked_interval_start_us);
    // A stale probe_rtt_min_delay would normally force ProbeRTT; the
    // idle_restart latch defers it (§5.3.4.3 CheckProbeRTT).
    bbr.probe_rtt_expired = true;
    const rs: delivery_rate.RateSample = .{};
    bbr.checkProbeRtt(&rs, 9_000_100, 0);
    try testing.expect(bbr.state != .probe_rtt);
}

test "InitPacingRate falls back to gain * IW / srtt until a bandwidth sample lands" {
    var bbr = Bbr.init(testCfg());
    const iw = testCfg().initialWindow();
    const expect_50ms = (iw * 277 * us_per_s) / (100 * 50_000);
    try testing.expectEqual(expect_50ms, bbr.pacingRateBps(50_000));
    // Sub-millisecond srtt floors at 1 ms.
    try testing.expectEqual((iw * 277 * us_per_s) / (100 * 1_000), bbr.pacingRateBps(3));
    // A model rate above the floor wins even before full_bw.
    bbr.pacing_rate = 900_000;
    try testing.expectEqual(@as(u64, 900_000), bbr.pacingRateBps(50_000));
}

test "pacing floor: a below-init model rate is floored until the pipe is observed full" {
    // The trickle-sender regression: a receive-mostly endpoint whose
    // only samples measured its own post-handshake control tail
    // latches a garbage-low rate while parked in Startup. Until
    // full_bw_reached, InitPacingRate is the floor; after it, the
    // model is trusted verbatim (genuinely slow paths pace slow).
    var bbr = Bbr.init(testCfg());
    const iw = testCfg().initialWindow();
    const init_50ms = (iw * 277 * us_per_s) / (100 * 50_000);
    bbr.pacing_rate = 5_361; // the observed fairness-cell latch
    try testing.expectEqual(init_50ms, bbr.pacingRateBps(50_000));
    bbr.full_bw_reached = true;
    try testing.expectEqual(@as(u64, 5_361), bbr.pacingRateBps(50_000));
}

test "send quantum clamps 1ms of rate into [2*SMSS, 64KB]" {
    var bbr = Bbr.init(testCfg());
    bbr.pacing_rate = 1_000_000; // 1 MB/s -> 1ms = 1000 B < 2*SMSS
    bbr.setSendQuantum();
    try testing.expectEqual(@as(u64, 2_400), bbr.send_quantum);
    bbr.pacing_rate = 200_000_000; // 200 MB/s -> 1ms = 200 KB > 64 KB
    bbr.setSendQuantum();
    try testing.expectEqual(@as(u64, 65_536), bbr.send_quantum);
}
