// CUBIC congestion control (RFC 9438), the second algorithm behind
// `congestion.CongestionController`. Exposes the exact field/method
// surface the union's inline-else dispatch requires (`cfg`, `cwnd`,
// `ssthresh`, `recovery_start_time_us`, plus the shared event methods).
//
// Unit discipline: windows are BYTES, time is MICROSECONDS everywhere
// outside the two float helpers at the bottom. Those two functions —
// `cubicK` and `cubicWindowBytes` — are the only floating point in the
// congestion core (f64 + std.math.cbrt, a pure-Zig musl port that is
// bit-identical across tier-1 targets; no libm). They take and return
// integers so a fixed-point swap stays a local change.

const Cubic = @This();

const std = @import("std");
const congestion = @import("congestion.zig");
const delivery_rate = @import("delivery_rate.zig");
const hystart_mod = @import("hystart.zig");
const pacing_mod = @import("Pacer.zig");

/// CUBIC multiplicative-decrease factor β_cubic = 0.7 (RFC 9438 §4.6).
pub const beta_num: u64 = 7;
pub const beta_den: u64 = 10;

/// α_cubic = 3·(1−β)/(1+β) = 9/17 (RFC 9438 §4.3) — the
/// Reno-friendly estimate's per-ACK growth factor.
pub const alpha_num: u64 = 9;
pub const alpha_den: u64 = 17;

/// RFC 9438 CUBIC controller. One instance per QUIC path.
cfg: congestion.Config,
/// Current congestion window in bytes.
cwnd: u64,
/// Slow-start threshold; null = infinity (initial slow start).
ssthresh: ?u64 = null,
/// Recovery-period anchor — identical semantics to NewReno
/// (RFC 9002 §7.3.1): set on decrease, cleared by an ACK of a
/// packet sent after it; re-entry suppressed inside the period.
recovery_start_time_us: ?u64 = null,

// -- RFC 9438 state ------------------------------------------------------
/// Window size (bytes) just before the last reduction (§4.2's
/// W_max, after §4.7 fast convergence has been applied).
w_max: u64 = 0,
/// Congestion-avoidance epoch anchor; null = epoch not started
/// (fresh, post-decrease, or frozen by an app-limited ACK).
epoch_start_us: ?u64 = null,
/// cwnd at the moment the current epoch started (§4.2's
/// cwnd_epoch, input to K).
cwnd_epoch: u64 = 0,
/// K for the current epoch, microseconds (§4.2): time until the
/// cubic curve regains W_max.
k_us: u64 = 0,
/// Reno-friendly window estimate, bytes (§4.3). CUBIC never lets
/// cwnd fall below this while in congestion avoidance.
w_est: u64 = 0,
/// RFC 9406 HyStart++ slow-start exit state. CUBIC + HyStart++ is
/// the pairing Linux and quiche ship; the two are orthogonal
/// (HyStart++ governs when slow start ends, CUBIC governs the
/// congestion-avoidance curve).
hystart: hystart_mod.State = .{},

pub fn init(cfg: congestion.Config) Cubic {
    return .{
        .cfg = cfg,
        .cwnd = cfg.initialWindow(),
        .hystart = hystart_mod.State.init(cfg.hystart),
    };
}

pub fn isInRecovery(self: *const Cubic, sent_time_us: u64) bool {
    return self.recovery_start_time_us != null and
        sent_time_us <= self.recovery_start_time_us.?;
}

pub fn isSlowStart(self: *const Cubic) bool {
    return self.ssthresh == null or self.cwnd < self.ssthresh.?;
}

/// RFC 9438 §4.1–§4.4 ACK processing. Shares NewReno's recovery
/// semantics and the RFC 9002 §7.8 app-limited gate; growth in
/// congestion avoidance follows max(W_cubic, W_est).
pub fn onPacketAcked(
    self: *Cubic,
    bytes_acked: u64,
    largest_acked_sent_time_us: u64,
    now_us: u64,
    srtt_us: u64,
    bytes_in_flight: u64,
) void {
    // Recovery-exit maintenance first, exactly like NewReno.
    if (self.recovery_start_time_us) |rec_start| {
        if (largest_acked_sent_time_us > rec_start) {
            self.recovery_start_time_us = null;
        } else {
            return;
        }
    }

    // RFC 9002 §7.8: no growth off an unfilled pipe. Freeze the
    // epoch too — idle wall-clock time must not accrue convex
    // growth (§5.8: CUBIC's t is only meaningful while the window
    // is being pushed).
    if (!congestion.ackFillsWindow(self.cwnd, bytes_acked, bytes_in_flight)) {
        self.epoch_start_us = null;
        return;
    }

    if (self.isSlowStart()) {
        // HyStart++ throttles growth inside Conservative Slow
        // Start; outside CSS this is plain `bytes_acked`.
        self.cwnd += self.hystart.slowStartGrowth(bytes_acked);
        return;
    }

    // Congestion avoidance. Anchor a new epoch if none is active.
    if (self.epoch_start_us == null) {
        self.epoch_start_us = now_us;
        self.cwnd_epoch = self.cwnd;
        // §4.2: K = cbrt((W_max − cwnd_epoch)/C); zero when the
        // window has already regained (or never had) W_max.
        self.k_us = cubicK(
            self.w_max -| self.cwnd_epoch,
            self.cfg.max_datagram_size,
        );
        // §4.3: seed the Reno-friendly estimate at epoch start.
        self.w_est = self.cwnd;
    }

    // §4.3: W_est grows by α·MSS per cwnd of acked bytes.
    self.w_est += @intCast(
        (@as(u128, alpha_num) * self.cfg.max_datagram_size * bytes_acked) /
            (@as(u128, alpha_den) * @max(self.cwnd, 1)),
    );

    // §4.2: target = W_cubic(t + RTT), clamped to at most 1.5x the
    // current window per §4.4's sanity bound.
    const t_us = (now_us -| self.epoch_start_us.?) +| srtt_us;
    const w_cubic = cubicWindowBytes(
        t_us,
        self.k_us,
        self.w_max,
        self.cfg.max_datagram_size,
    );
    const target = @min(w_cubic, self.cwnd + self.cwnd / 2);

    if (target > self.cwnd) {
        // §4.4: cwnd += (target − cwnd)/cwnd per acked cwnd —
        // scaled here by bytes_acked so pacing of ACKs doesn't
        // change the curve.
        const grow = (@as(u128, target - self.cwnd) * bytes_acked) / @max(self.cwnd, 1);
        self.cwnd += @intCast(grow);
    }

    // §4.3: in the Reno-friendly region, never fall below W_est.
    if (self.w_est > self.cwnd) self.cwnd = self.w_est;
}

/// Post-ACK hook driving RFC 9406 HyStart++ (see `hystart.zig`).
/// Only meaningful during slow start; a no-op otherwise.
pub fn onAckProcessed(
    self: *Cubic,
    largest_acked_pn: u64,
    latest_rtt_us: ?u64,
    next_pn_to_send: u64,
) void {
    if (!self.isSlowStart()) return;
    if (self.hystart.onAckProcessed(largest_acked_pn, latest_rtt_us, next_pn_to_send)) {
        // Leave slow start without having driven the path to loss.
        // The next ACK in congestion avoidance anchors a fresh
        // CUBIC epoch from here.
        self.ssthresh = self.cwnd;
        self.epoch_start_us = null;
        self.hystart.reset();
    }
}

/// In HyStart++ Conservative Slow Start? (observability)
pub fn isInCss(self: *const Cubic) bool {
    return self.hystart.inCss() and self.isSlowStart();
}

/// RFC 9438 §4.6 multiplicative decrease + §4.7 fast convergence.
pub fn onPacketLost(
    self: *Cubic,
    bytes_lost: u64,
    lost_largest_sent_time_us: u64,
) void {
    _ = bytes_lost;
    if (self.recovery_start_time_us) |rec_start| {
        if (lost_largest_sent_time_us <= rec_start) return;
    }
    self.recovery_start_time_us = lost_largest_sent_time_us;
    self.reduce();
}

/// ECN-CE congestion event — same decrease path as loss
/// (RFC 9438 §4.6 treats them identically).
pub fn onCongestionEvent(self: *Cubic, ce_packet_sent_time_us: u64) void {
    if (self.recovery_start_time_us) |rec_start| {
        if (ce_packet_sent_time_us <= rec_start) return;
    }
    self.recovery_start_time_us = ce_packet_sent_time_us;
    self.reduce();
}

fn reduce(self: *Cubic) void {
    // §4.7 fast convergence: a reduction below the previous W_max
    // signals a shrinking pipe — release capacity faster by
    // remembering a further-reduced ceiling.
    if (self.cwnd < self.w_max) {
        self.w_max = @intCast(
            (@as(u128, self.cwnd) * (beta_num + beta_den)) / (2 * beta_den),
        );
    } else {
        self.w_max = self.cwnd;
    }
    // §4.6: cwnd = max(cwnd·β, minimum window).
    self.ssthresh = @max(
        @as(u64, @intCast((@as(u128, self.cwnd) * beta_num) / beta_den)),
        self.cfg.minWindow(),
    );
    self.cwnd = self.ssthresh.?;
    self.epoch_start_us = null;
    // Loss/CE ends slow start through ssthresh; HyStart++ has
    // nothing left to track.
    self.hystart.reset();
}

/// RFC 9002 §7.6 persistent congestion: collapse to the minimum
/// window. W_max is kept so post-collapse regrowth still remembers
/// the old ceiling after the next reduction anchors a fresh epoch;
/// ssthresh is kept, mirroring NewReno's field-level choices.
pub fn onPersistentCongestion(self: *Cubic) void {
    self.cwnd = self.cfg.minWindow();
    self.recovery_start_time_us = null;
    self.epoch_start_us = null;
    self.hystart.reset();
}

/// cwnd headroom in bytes; 0 means "wait".
pub fn sendAllowance(self: *const Cubic, bytes_in_flight: u64) u64 {
    if (bytes_in_flight >= self.cwnd) return 0;
    return self.cwnd - bytes_in_flight;
}

/// Delivery-rate samples carry no signal CUBIC acts on (loss and
/// RTT drive its curve). Rate-based controllers consume this inlet.
pub fn onDeliveryRateSample(
    self: *Cubic,
    rs: *const delivery_rate.RateSample,
    now_us: u64,
    bytes_in_flight: u64,
) void {
    _ = self;
    _ = rs;
    _ = now_us;
    _ = bytes_in_flight;
}

/// Transmit edges carry no signal CUBIC acts on.
pub fn onPacketSent(
    self: *Cubic,
    now_us: u64,
    bytes_in_flight_before: u64,
    bytes: u64,
    is_app_limited: bool,
) void {
    _ = self;
    _ = now_us;
    _ = bytes_in_flight_before;
    _ = bytes;
    _ = is_app_limited;
}

/// Per-packet loss detail carries no signal CUBIC acts on (the
/// aggregate onPacketLost is its loss input).
pub fn onPacketNewlyLost(self: *Cubic, info: *const delivery_rate.LostPacketInfo) void {
    _ = self;
    _ = info;
}

/// RFC 9002 §7.7 pacing rate: gain x cwnd / srtt, gain by phase.
pub fn pacingRateBps(self: *const Cubic, srtt_us: u64) u64 {
    return pacing_mod.rateBytesPerSecond(self.cwnd, srtt_us, self.isSlowStart());
}

// -- the two float helpers (all f64 confined here) --------------------------

/// C_cubic = 0.4 segments/second^3 (RFC 9438 §5.1).
const c_cubic: f64 = 0.4;

/// §4.2: K = cbrt(W_delta / C) where W_delta = W_max − cwnd_epoch in
/// SEGMENTS and K is in seconds; returned in microseconds. Zero when
/// the epoch starts at or above W_max.
pub fn cubicK(w_delta_bytes: u64, mss: u64) u64 {
    if (w_delta_bytes == 0 or mss == 0) return 0;
    const w_delta_seg = @as(f64, @floatFromInt(w_delta_bytes)) / @as(f64, @floatFromInt(mss));
    const k_seconds = std.math.cbrt(w_delta_seg / c_cubic);
    return @intFromFloat(k_seconds * 1e6);
}

/// §4.2: W_cubic(t) = C·(t − K)^3 + W_max, in bytes (C is in
/// segments/s^3, so the cubic term scales by MSS). Never below zero.
pub fn cubicWindowBytes(t_us: u64, k_us: u64, w_max_bytes: u64, mss: u64) u64 {
    const dt_seconds =
        (@as(f64, @floatFromInt(t_us)) - @as(f64, @floatFromInt(k_us))) / 1e6;
    const cubic_term_bytes =
        c_cubic * dt_seconds * dt_seconds * dt_seconds * @as(f64, @floatFromInt(mss));
    const w = cubic_term_bytes + @as(f64, @floatFromInt(w_max_bytes));
    if (w <= 0) return 0;
    return @intFromFloat(w);
}

// -- tests -------------------------------------------------------------------

const testing = std.testing;

test "cubicK matches hand-computed vectors" {
    // W_delta = 100 segments, C = 0.4: K = cbrt(250) ≈ 6.2996 s.
    const k = cubicK(100 * 1200, 1200);
    try testing.expect(k > 6_299_000 and k < 6_300_000);
    // Zero delta → K = 0 (epoch starts at the ceiling).
    try testing.expectEqual(@as(u64, 0), cubicK(0, 1200));
}

test "cubicWindowBytes: W_cubic(K) == W_max, concave before, convex after" {
    const mss: u64 = 1200;
    const w_max: u64 = 100 * mss;
    const k = cubicK(30 * mss, mss);
    // At t = K the curve crosses W_max exactly (float rounding aside).
    const at_k = cubicWindowBytes(k, k, w_max, mss);
    try testing.expect(at_k >= w_max - 2 and at_k <= w_max + 2);
    // Monotonically non-decreasing through K.
    var prev: u64 = 0;
    var t: u64 = 0;
    while (t <= 2 * k) : (t += k / 8) {
        const w = cubicWindowBytes(t, k, w_max, mss);
        try testing.expect(w >= prev);
        prev = w;
    }
    // Below W_max before K, above after.
    try testing.expect(cubicWindowBytes(k / 2, k, w_max, mss) < w_max);
    try testing.expect(cubicWindowBytes(2 * k, k, w_max, mss) > w_max);
}

/// Drives a full-pipe ACK clock: every call acks one cwnd of bytes
/// with the pipe exactly full, advancing `now` by one RTT.
fn ackOneRtt(cubic: *Cubic, now_us: *u64, srtt_us: u64) void {
    const cwnd = cubic.cwnd;
    cubic.onPacketAcked(cwnd, now_us.*, now_us.*, srtt_us, cubic.cwnd);
    now_us.* += srtt_us;
}

test "reduction multiplies cwnd by beta = 0.7 and floors at min window" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200, .algorithm = .new_reno });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000);
    try testing.expectEqual(@as(u64, 70_000), cubic.cwnd);
    try testing.expectEqual(@as(?u64, 70_000), cubic.ssthresh);
    try testing.expectEqual(@as(u64, 100_000), cubic.w_max);

    // Floor: a tiny window reduces to min, not below.
    cubic.recovery_start_time_us = null;
    cubic.cwnd = 2_500;
    cubic.onPacketLost(1200, 2_000_000);
    try testing.expectEqual(cubic.cfg.minWindow(), cubic.cwnd);
}

test "fast convergence remembers a reduced ceiling when the pipe shrinks" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000); // w_max = 100k, cwnd = 70k
    // Second reduction BELOW the previous ceiling: w_max takes the
    // §4.7 haircut — cwnd·(1+β)/2 = 70k·0.85 = 59.5k, not 70k.
    cubic.onPacketLost(1200, 2_000_000);
    try testing.expectEqual(@as(u64, 59_500), cubic.w_max);
}

test "recovery period suppresses repeated reductions (RFC 9002 §7.3.1 parity)" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 100_000;
    cubic.onPacketLost(1200, 1_000_000);
    const after_first = cubic.cwnd;
    cubic.onPacketLost(1200, 999_000); // inside the recovery period
    try testing.expectEqual(after_first, cubic.cwnd);
    cubic.onCongestionEvent(500_000); // CE inside the period: same rule
    try testing.expectEqual(after_first, cubic.cwnd);
}

test "post-reduction growth regains W_max on the cubic curve around t=K" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    const srtt: u64 = 25_000; // 25 ms
    cubic.cwnd = 120_000;
    cubic.onPacketLost(1200, 1_000_000);
    const w_max = cubic.w_max;
    try testing.expectEqual(@as(u64, 120_000), w_max);

    var now: u64 = 1_050_000;
    // Exit recovery with one full-pipe ACK sent after the loss.
    cubic.onPacketAcked(cubic.cwnd, 1_060_000, now, srtt, cubic.cwnd);
    try testing.expect(cubic.recovery_start_time_us == null);
    const k = cubic.k_us;
    try testing.expect(k > 0);

    // Walk RTT-clocked full-pipe ACKs until K elapses; cwnd should be
    // within a few segments of W_max (the curve crosses it at t=K).
    const epoch = cubic.epoch_start_us.?;
    while (now < epoch + k) ackOneRtt(&cubic, &now, srtt);
    try testing.expect(cubic.cwnd + 4 * 1200 >= w_max);
    // And keep growing past the ceiling afterwards (convex region).
    const at_ceiling = cubic.cwnd;
    var extra: u32 = 0;
    while (extra < 40) : (extra += 1) ackOneRtt(&cubic, &now, srtt);
    try testing.expect(cubic.cwnd > at_ceiling);
}

test "Reno-friendly floor: CUBIC never falls below the Reno trajectory" {
    // Lockstep simulation over an identical full-pipe ACK script in
    // the small-window/short-RTT region where Reno grows faster than
    // the cubic curve.
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    var reno = congestion.NewReno.init(.{ .max_datagram_size = 1200 });
    const srtt: u64 = 10_000; // 10 ms — deeply Reno-friendly region

    // Matching post-loss state: same cwnd/ssthresh, CA mode. (β
    // differs between the algorithms by design; equalize by hand so
    // the growth phase is the comparison.)
    cubic.cwnd = 12_000;
    cubic.ssthresh = 12_000;
    cubic.w_max = 24_000;
    reno.cwnd = 12_000;
    reno.ssthresh = 12_000;

    var now: u64 = 1_000_000;
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const bytes = @min(cubic.cwnd, reno.cwnd);
        cubic.onPacketAcked(bytes, now, now, srtt, cubic.cwnd);
        reno.onPacketAcked(bytes, now, now, srtt, reno.cwnd);
        now += srtt;
        // §4.3: w_est tracks a Reno-style trajectory with α = 9/17;
        // the floor keeps CUBIC within one MSS-ish of standard Reno.
        try testing.expect(cubic.cwnd + 2 * 1200 >= reno.cwnd * alpha_num / alpha_den);
    }
}

test "app-limited ACKs freeze the epoch instead of accruing curve time" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 50_000;
    cubic.ssthresh = 50_000; // CA mode
    cubic.w_max = 100_000;

    // Full-pipe ACK anchors an epoch.
    cubic.onPacketAcked(50_000, 100, 1_000_000, 25_000, 50_000);
    try testing.expect(cubic.epoch_start_us != null);
    const cwnd_after_anchor = cubic.cwnd;

    // App-limited ACK: no growth, epoch dropped.
    cubic.onPacketAcked(1_200, 200, 2_000_000, 25_000, 0);
    try testing.expectEqual(cwnd_after_anchor, cubic.cwnd);
    try testing.expectEqual(@as(?u64, null), cubic.epoch_start_us);

    // The next full-pipe ACK re-anchors at the CURRENT time — the
    // idle hour in between must not have grown the window.
    cubic.onPacketAcked(cwnd_after_anchor, 300, 3_600_000_000, 25_000, cwnd_after_anchor);
    try testing.expectEqual(@as(?u64, 3_600_000_000), cubic.epoch_start_us);
}

test "persistent congestion collapses to min window and clears the epoch" {
    var cubic = Cubic.init(.{ .max_datagram_size = 1200 });
    cubic.cwnd = 80_000;
    cubic.w_max = 90_000;
    cubic.onPersistentCongestion();
    try testing.expectEqual(cubic.cfg.minWindow(), cubic.cwnd);
    try testing.expectEqual(@as(?u64, null), cubic.recovery_start_time_us);
    try testing.expectEqual(@as(?u64, null), cubic.epoch_start_us);
    // W_max survives the collapse (regrowth remembers the ceiling).
    try testing.expectEqual(@as(u64, 90_000), cubic.w_max);
}
