//! Delivery rate estimation (draft-cheng-iccrg-delivery-rate-estimation-02,
//! as embedded and updated by draft-ietf-ccwg-bbr-06 §4.1.2).
//!
//! Loss-based congestion control infers the path from loss events;
//! model-based control (BBR) instead measures what the path actually
//! delivered. That takes per-packet bookkeeping the ACK alone cannot
//! provide: each sent packet carries a snapshot of the connection's
//! delivery state at transmit (`SentPacket.delivered` and friends), and
//! each ACK turns the newest snapshot it covers into one `RateSample` —
//! bytes delivered over the sampling interval, with the send-side and
//! ack-side elapsed times kept separate so neither direction's
//! compression can inflate the estimate (rate over max(send_elapsed,
//! ack_elapsed), draft-cheng-02 §2.2/§3.3).
//!
//! Like `hystart.zig`, this is a shared sub-module: pure integer
//! arithmetic over bytes and microseconds, by-value state, no
//! allocation, no interior pointers (Path lives inside an ArrayList and
//! must stay relocatable). One `Estimator` sits on each `Path` next to
//! `cc`/`pacer`/`rtt`; the send path stamps outgoing packets, ACK
//! processing feeds delivered packets back, and loss detection reports
//! lost bytes. Only application/0-RTT in-flight packets participate —
//! the congestion controller is application-level only, and
//! `C.delivered` MUST NOT count pure ACKs (ccwg-bbr-06 §2.2), which the
//! call-site gates enforce by never stamping non-in-flight packets.
//!
//! Totals are lifetime: nothing here resets on migration or key
//! update. A packet stamped before such an event and acked after it
//! still describes real delivery; every subtraction below saturates,
//! so even a hypothetically stale stamp clamps to a zero-delta sample
//! instead of trapping.

const std = @import("std");
const sent_packets = @import("SentPacketTracker.zig");

const us_per_s: u64 = std.time.us_per_s;

/// One per-ACK-event delivery-rate sample (draft-cheng-02 §3.1.3 rs.*,
/// plus the ccwg-bbr-06 §2.3 per-ACK extensions BBR consumes). Plain
/// data — safe to hand to a by-value controller.
pub const RateSample = struct {
    /// delivered * 1e6 / interval_us (u128 intermediate). Only
    /// meaningful when `has_rate`; 0 otherwise.
    delivery_rate_bps: u64 = 0,
    /// True when the sample is reliable: the sampled packet carried a
    /// real snapshot and `interval_us` is nonzero and at least
    /// `min_rtt_us` (draft-cheng-02 §3.3 "no reliable sample" gate).
    has_rate: bool = false,
    /// `P.is_app_limited` of the newest delivered packet: this sample
    /// may under-state the path's bandwidth, never over-state it.
    is_app_limited: bool = false,
    /// max(send_elapsed, ack_elapsed) (draft-cheng-02 §3.3).
    interval_us: u64 = 0,
    send_elapsed_us: u64 = 0,
    ack_elapsed_us: u64 = 0,
    /// C.delivered - rs.prior_delivered: bytes delivered over the
    /// sampling interval.
    delivered: u64 = 0,
    /// P.delivered / P.delivered_time / P.lost of the newest delivered
    /// packet (BBR round counting and loss accounting inputs).
    prior_delivered: u64 = 0,
    prior_time_us: u64 = 0,
    prior_lost: u64 = 0,
    /// P.tx_in_flight of the newest delivered packet.
    tx_in_flight: u64 = 0,
    /// C.lost - rs.prior_lost: bytes declared lost between that
    /// packet's transmit and now (ccwg-bbr-06 §2.3 RS.lost).
    lost: u64 = 0,
    /// In-flight bytes newly ACKed by THIS ack event
    /// (ccwg-bbr-06 §2.3 RS.newly_acked).
    newly_acked: u64 = 0,
    /// C.lost accrued since `beginAckEvent` — losses declared while
    /// processing this ACK, including time-threshold losses folded
    /// into the same event (ccwg-bbr-06 §2.3 RS.newly_lost).
    newly_lost: u64 = 0,
    /// RFC 9000 §13.4.2 ECN-CE count increase reported by this ACK
    /// (packets, not bytes). ccwg-bbr-06 §3.7 declines to specify a
    /// quantitative ECN response; this is a passthrough for whatever
    /// policy the consuming controller implements.
    ce_delta: u64 = 0,
    /// Connection totals at sample time (C.delivered / C.lost).
    /// Carried in the sample because controllers are by-value and may
    /// not hold pointers back into the estimator.
    c_delivered: u64 = 0,
    c_lost: u64 = 0,
    /// PN of the newest delivered packet (RS.last_acked_packet_id).
    last_acked_pn: u64 = 0,
};

/// Per-lost-packet input for loss responses that need transmit-time
/// delivery state (ccwg-bbr-06 §5.5.10.2 HandleLostPacket /
/// InflightAtLoss).
pub const LostPacketInfo = struct {
    /// P.size — the lost packet's wire bytes.
    bytes: u64,
    /// P.tx_in_flight — in flight including P, at its transmit.
    tx_in_flight: u64,
    /// P.lost — C.lost when P was sent.
    lost_at_send: u64,
    /// P.delivered — C.delivered when P was sent.
    delivered_at_send: u64,
    is_app_limited: bool,
    sent_time_us: u64,
    /// C.lost AFTER counting this packet, so
    /// `c_lost - lost_at_send` includes P itself (matching
    /// InflightAtLoss's `lost_prev = RS.lost - P.size` convention).
    c_lost: u64,
    /// C.delivered at loss-detection time.
    c_delivered: u64,
};

/// Per-path delivery-rate estimator state. All fields are plain
/// integers; default-init (`.{}`) is the correct starting state.
pub const Estimator = struct {
    // -- C.* connection/path state (draft-cheng-02 §3.1.1 /
    //    ccwg-bbr-06 §4.1.2.1.1) --

    /// C.delivered: total in-flight bytes delivered (never pure ACKs).
    delivered: u64 = 0,
    /// C.delivered_time: when `delivered` last advanced (µs).
    delivered_time_us: u64 = 0,
    /// C.first_sent_time: send time of the packet that started the
    /// current sampling epoch (µs).
    first_sent_time_us: u64 = 0,
    /// C.lost: total in-flight bytes declared lost.
    lost: u64 = 0,
    /// C.app_limited: the value of C.delivered + bytes-in-flight at
    /// the moment the app last ran out of data (0 = not app-limited).
    /// Samples stay tainted until C.delivered passes this marker
    /// (draft-cheng-02 §3.1.1/§3.4).
    app_limited_until: u64 = 0,

    // -- per-ACK-event transients (InitRateSample / UpdateRateSample,
    //    ccwg-bbr-06 §4.1.2.3); reset by `beginAckEvent` --

    rs_has_sample: bool = false,
    rs_prior_delivered: u64 = 0,
    rs_prior_time_us: u64 = 0,
    rs_prior_lost: u64 = 0,
    rs_tx_in_flight: u64 = 0,
    rs_is_app_limited: bool = false,
    rs_send_elapsed_us: u64 = 0,
    rs_newest_sent_time_us: u64 = 0,
    rs_last_acked_pn: u64 = 0,
    event_newly_acked: u64 = 0,
    event_prior_lost: u64 = 0,

    /// Stamp P.* at transmit (draft-cheng-02 §3.2 / ccwg-bbr-06
    /// §4.1.2.2). `bytes_in_flight_before` is the tracker's
    /// bytes-in-flight BEFORE this packet is recorded;
    /// `P.tx_in_flight` includes the packet itself.
    ///
    /// Caller contract: only in-flight (ack-eliciting) application or
    /// 0-RTT packets — ACK-only sends must neither stamp nor reseed
    /// the idle clocks (C.delivered MUST NOT count pure ACKs,
    /// ccwg-bbr-06 §2.2), and Initial/Handshake flights are not
    /// sampled (the congestion controller is application-level only).
    pub fn onPacketSent(
        self: *Estimator,
        p: *sent_packets.SentPacket,
        bytes_in_flight_before: u64,
    ) void {
        // Restart from idle: with nothing in flight there is no ACK
        // clock running, so the elapsed time since the last delivery
        // says nothing about the path. Re-seed both clocks to this
        // packet's transmit (ccwg-bbr-06 §4.1.2.2).
        if (bytes_in_flight_before == 0) {
            self.first_sent_time_us = p.sent_time_us;
            self.delivered_time_us = p.sent_time_us;
        }
        p.delivered = self.delivered;
        p.delivered_time_us = self.delivered_time_us;
        p.first_sent_time_us = self.first_sent_time_us;
        p.tx_in_flight = bytes_in_flight_before +| p.bytes;
        p.lost_at_send = self.lost;
        p.is_app_limited = self.app_limited_until != 0;
    }

    /// Open a new ACK event: reset the per-event rate-sample state and
    /// snapshot C.lost so `newly_lost` can span everything this event
    /// declares lost. Call once per inbound ACK frame at the
    /// application level, before the range walk.
    pub fn beginAckEvent(self: *Estimator) void {
        self.rs_has_sample = false;
        self.rs_prior_delivered = 0;
        self.rs_prior_time_us = 0;
        self.rs_prior_lost = 0;
        self.rs_tx_in_flight = 0;
        self.rs_is_app_limited = false;
        self.rs_send_elapsed_us = 0;
        self.rs_newest_sent_time_us = 0;
        self.rs_last_acked_pn = 0;
        self.event_newly_acked = 0;
        self.event_prior_lost = self.lost;
    }

    /// Fold one newly-delivered packet into the event's sample
    /// (UpdateRateSample, ccwg-bbr-06 §4.1.2.3). Caller passes only
    /// in-flight packets; the tracker removes packets on ACK, so a PN
    /// is dispatched at most once (the draft's `P.delivered_time == 0`
    /// re-ack guard is unnecessary here).
    pub fn onPacketAcked(
        self: *Estimator,
        p: *const sent_packets.SentPacket,
        now_us: u64,
    ) void {
        self.delivered +|= p.bytes;
        self.delivered_time_us = now_us;
        self.event_newly_acked +|= p.bytes;

        // IsNewestPacket (ccwg-bbr-06 §4.1.2.3): adopt the snapshot of
        // the newest-sent packet this event delivers, PN as the
        // tie-break for equal send timestamps. draft-cheng-02 §3.3
        // used `P.delivered > rs.prior_delivered`; the two agree on
        // QUIC's monotone PNs except under equal timestamps, where the
        // consumer draft's rule is the one we implement.
        const newest = !self.rs_has_sample or
            p.sent_time_us > self.rs_newest_sent_time_us or
            (p.sent_time_us == self.rs_newest_sent_time_us and p.pn > self.rs_last_acked_pn);
        if (newest) {
            self.rs_prior_delivered = p.delivered;
            self.rs_prior_time_us = p.delivered_time_us;
            self.rs_prior_lost = p.lost_at_send;
            self.rs_tx_in_flight = p.tx_in_flight;
            self.rs_is_app_limited = p.is_app_limited;
            self.rs_newest_sent_time_us = p.sent_time_us;
            self.rs_last_acked_pn = p.pn;
            // send_elapsed = P.sent_time - P.first_sent_time, and the
            // next sampling epoch starts at this packet's transmit.
            self.rs_send_elapsed_us = p.sent_time_us -| p.first_sent_time_us;
            self.first_sent_time_us = p.sent_time_us;
        }
        self.rs_has_sample = true;
    }

    /// Account one newly-lost packet (C.lost += P.size) and return the
    /// transmit-time delivery state a model-based loss response needs.
    /// Caller contract: in-flight application/0-RTT packets only, and
    /// never DPLPMTUD probes (RFC 8899 §4.4 excludes probe loss from
    /// congestion accounting; the call sites share that gate with the
    /// congestion controller's own loss stats).
    pub fn onPacketLost(
        self: *Estimator,
        p: *const sent_packets.SentPacket,
    ) LostPacketInfo {
        self.lost +|= p.bytes;
        return .{
            .bytes = p.bytes,
            .tx_in_flight = p.tx_in_flight,
            .lost_at_send = p.lost_at_send,
            .delivered_at_send = p.delivered,
            .is_app_limited = p.is_app_limited,
            .sent_time_us = p.sent_time_us,
            .c_lost = self.lost,
            .c_delivered = self.delivered,
        };
    }

    /// Close the ACK event (GenerateRateSample, ccwg-bbr-06 §4.1.2.3):
    /// clear an app-limited marker the event's deliveries have passed,
    /// then build the sample. Returns null when the event delivered no
    /// in-flight bytes (nothing to sample — per-lost accounting has
    /// its own channel). `min_rtt_us` is the connection's lifetime
    /// minimum RTT (C.min_rtt); an interval shorter than it cannot be
    /// a reliable rate (draft-cheng-02 §3.3).
    pub fn generateRateSample(
        self: *Estimator,
        min_rtt_us: u64,
        ce_delta: u64,
    ) ?RateSample {
        // Marker clearing runs before the has-sample check, matching
        // the pseudocode order: a pure-duplicate ACK event can still
        // retire the app-limited bubble... except it cannot advance
        // C.delivered, so in practice clearing happens on delivering
        // events. Kept in the draft's order for fidelity.
        if (self.app_limited_until != 0 and self.delivered > self.app_limited_until) {
            self.app_limited_until = 0;
        }
        if (!self.rs_has_sample) return null;

        const send_elapsed = self.rs_send_elapsed_us;
        const ack_elapsed = self.delivered_time_us -| self.rs_prior_time_us;
        // Use the LONGER of the send and ack intervals: ACK
        // compression squeezes ack_elapsed and send-side pauses
        // stretch send_elapsed; taking the max under-states rate
        // rather than inflating it (draft-cheng-02 §2.2/§3.3).
        const interval = @max(send_elapsed, ack_elapsed);
        const delivered_in_sample = self.delivered -| self.rs_prior_delivered;
        // draft-cheng-02 §3.3: intervals shorter than min_rtt are
        // unreliable. Before the first RTT sample min_rtt_us is 0
        // (RttEstimator primes it lazily), which would admit every
        // burst-ACK interval on loopback as reliable and feed a
        // spuriously high early rate into BBR Startup. Floor the
        // gate at kGranularity (1 ms) until the estimator primes —
        // and ONLY until then. A permanent 1 ms floor (the old
        // @max(min_rtt, 1ms)) rejected every per-round sample on a
        // sub-millisecond path: with a 40 us loopback min_rtt only
        // >= 1 ms aggregates qualified, averaging across idle and
        // aggregation gaps into a systematic underestimate — BBR
        // Startup latched full_bw at ~2x below the path and short
        // transfers ran 3-6x slower than CUBIC (goodput smoke).
        const reliability_floor_us = if (min_rtt_us == 0) 1_000 else min_rtt_us;
        const has_rate = self.rs_prior_time_us != 0 and
            interval > 0 and interval >= reliability_floor_us;

        return .{
            .delivery_rate_bps = if (has_rate)
                std.math.lossyCast(u64, (@as(u128, delivered_in_sample) * us_per_s) / interval)
            else
                0,
            .has_rate = has_rate,
            .is_app_limited = self.rs_is_app_limited,
            .interval_us = interval,
            .send_elapsed_us = send_elapsed,
            .ack_elapsed_us = ack_elapsed,
            .delivered = delivered_in_sample,
            .prior_delivered = self.rs_prior_delivered,
            .prior_time_us = self.rs_prior_time_us,
            .prior_lost = self.rs_prior_lost,
            .tx_in_flight = self.rs_tx_in_flight,
            .lost = self.lost -| self.rs_prior_lost,
            .newly_acked = self.event_newly_acked,
            .newly_lost = self.lost -| self.event_prior_lost,
            .ce_delta = ce_delta,
            .c_delivered = self.delivered,
            .c_lost = self.lost,
            .last_acked_pn = self.rs_last_acked_pn,
        };
    }

    /// MarkConnectionAppLimited (draft-cheng-02 §3.4 / ccwg-bbr-06
    /// §4.1.2.4): the app ran out of data while the congestion window
    /// had headroom. Everything sent until C.delivered passes
    /// `delivered + bytes_in_flight` carries the app-limited taint.
    /// The floor of 1 keeps the marker truthy when both terms are 0.
    pub fn markAppLimited(self: *Estimator, bytes_in_flight: u64) void {
        self.app_limited_until = @max(self.delivered +| bytes_in_flight, 1);
    }

    pub fn isAppLimited(self: *const Estimator) bool {
        return self.app_limited_until != 0;
    }
};

// -- tests ------------------------------------------------------------------

const testing = std.testing;

fn testPacket(pn: u64, sent_time_us: u64, bytes: u64) sent_packets.SentPacket {
    return .{
        .pn = pn,
        .sent_time_us = sent_time_us,
        .bytes = bytes,
        .ack_eliciting = true,
        .in_flight = true,
    };
}

test "onPacketSent stamps transmit-time state and idle restart reseeds the clocks" {
    var est: Estimator = .{};
    est.delivered = 5_000;
    est.lost = 700;
    est.delivered_time_us = 1_000;
    est.first_sent_time_us = 900;

    // Idle restart: nothing in flight, so both clocks jump to this
    // packet's transmit (ccwg-bbr-06 §4.1.2.2).
    var p1 = testPacket(10, 2_000, 1_200);
    est.onPacketSent(&p1, 0);
    try testing.expectEqual(@as(u64, 2_000), est.first_sent_time_us);
    try testing.expectEqual(@as(u64, 2_000), est.delivered_time_us);
    try testing.expectEqual(@as(u64, 5_000), p1.delivered);
    try testing.expectEqual(@as(u64, 2_000), p1.delivered_time_us);
    try testing.expectEqual(@as(u64, 2_000), p1.first_sent_time_us);
    try testing.expectEqual(@as(u64, 1_200), p1.tx_in_flight); // includes P
    try testing.expectEqual(@as(u64, 700), p1.lost_at_send);
    try testing.expect(!p1.is_app_limited);

    // Busy pipe: clocks untouched, tx_in_flight = before + bytes.
    var p2 = testPacket(11, 2_500, 1_200);
    est.onPacketSent(&p2, 1_200);
    try testing.expectEqual(@as(u64, 2_000), p2.first_sent_time_us);
    try testing.expectEqual(@as(u64, 2_400), p2.tx_in_flight);
}

test "sample comes from the newest-sent acked packet with PN tie-break" {
    var est: Estimator = .{};
    var p1 = testPacket(1, 1_000, 1_000);
    var p2 = testPacket(2, 3_000, 1_000);
    var p3 = testPacket(3, 3_000, 1_000); // same send time as p2
    est.onPacketSent(&p1, 0);
    est.delivered = 1_000; // pretend p0 delivered meanwhile
    est.onPacketSent(&p2, 1_000);
    est.onPacketSent(&p3, 2_000);

    // Deliver out of order: p3, p1, p2. The adopted snapshot must be
    // p3's (newest send time; PN 3 beats PN 2 on the tie).
    est.beginAckEvent();
    est.onPacketAcked(&p3, 10_000);
    est.onPacketAcked(&p1, 10_000);
    est.onPacketAcked(&p2, 10_000);
    const rs = est.generateRateSample(0, 0).?;
    try testing.expectEqual(@as(u64, 3), rs.last_acked_pn);
    try testing.expectEqual(@as(u64, 1_000), rs.prior_delivered);
    try testing.expectEqual(@as(u64, 3_000), rs.delivered); // all three
    try testing.expectEqual(@as(u64, 3_000), rs.newly_acked);
}

test "rate uses delivered over max(send_elapsed, ack_elapsed)" {
    // send_elapsed = 40ms, ack_elapsed = 50ms: the ack leg is longer
    // and must win, keeping the rate an under-estimate.
    var est: Estimator = .{};
    var p_epoch = testPacket(1, 100_000, 1_000);
    est.onPacketSent(&p_epoch, 0); // seeds first_sent_time = 100ms
    var p = testPacket(2, 140_000, 1_000);
    est.onPacketSent(&p, 1_000);
    est.beginAckEvent();
    // Deliver only p (p_epoch still outstanding — e.g. reordered).
    est.onPacketAcked(&p, 150_000);
    const rs = est.generateRateSample(0, 0).?;
    try testing.expectEqual(@as(u64, 40_000), rs.send_elapsed_us);
    // ack_elapsed = delivered_time(150ms) - P.delivered_time(100ms).
    try testing.expectEqual(@as(u64, 50_000), rs.ack_elapsed_us);
    try testing.expectEqual(@as(u64, 50_000), rs.interval_us);
    try testing.expect(rs.has_rate);
    // 1000 bytes / 50ms = 20_000 bytes/s.
    try testing.expectEqual(@as(u64, 20_000), rs.delivery_rate_bps);
}

test "interval below min_rtt yields no rate but the signals survive" {
    var est: Estimator = .{};
    var p1 = testPacket(1, 1_000, 1_200);
    est.onPacketSent(&p1, 0);
    var p2 = testPacket(2, 2_000, 1_200);
    est.onPacketSent(&p2, 1_200);
    est.beginAckEvent();
    est.onPacketAcked(&p1, 2_500);
    est.onPacketAcked(&p2, 2_500);
    // interval: send_elapsed = 2000-1000 = 1000, ack_elapsed =
    // 2500 - 1000 = 1500 -> 1500us, below a 50ms min_rtt.
    const rs = est.generateRateSample(50_000, 3).?;
    try testing.expect(!rs.has_rate);
    try testing.expectEqual(@as(u64, 0), rs.delivery_rate_bps);
    try testing.expectEqual(@as(u64, 2_400), rs.newly_acked);
    try testing.expectEqual(@as(u64, 3), rs.ce_delta);
    try testing.expectEqual(@as(u64, 2_400), rs.c_delivered);
}

test "app-limited marker: set, stamps packets, clears when delivered passes it" {
    var est: Estimator = .{};
    var p1 = testPacket(1, 1_000, 1_000);
    est.onPacketSent(&p1, 0);
    try testing.expect(!est.isAppLimited());

    // App runs dry with 1000 bytes still in flight.
    est.markAppLimited(1_000);
    try testing.expect(est.isAppLimited());
    try testing.expectEqual(@as(u64, 1_000), est.app_limited_until);

    // Packets sent while marked carry the taint.
    var p2 = testPacket(2, 2_000, 500);
    est.onPacketSent(&p2, 1_000);
    try testing.expect(p2.is_app_limited);

    // Delivering p1 (1000 bytes) does NOT clear: delivered == marker,
    // and the rule is strictly-greater (draft-cheng-02 §3.3).
    est.beginAckEvent();
    est.onPacketAcked(&p1, 3_000);
    var rs = est.generateRateSample(0, 0).?;
    try testing.expect(!rs.is_app_limited); // p1 predates the marker
    try testing.expect(est.isAppLimited());

    // Delivering p2 pushes delivered past the marker; the NEXT event
    // observes the cleared state, and p2's own sample is tainted.
    est.beginAckEvent();
    est.onPacketAcked(&p2, 4_000);
    rs = est.generateRateSample(0, 0).?;
    try testing.expect(rs.is_app_limited);
    est.beginAckEvent();
    _ = est.generateRateSample(0, 0);
    try testing.expect(!est.isAppLimited());
}

test "markAppLimited floors the marker at 1 when nothing was delivered" {
    var est: Estimator = .{};
    est.markAppLimited(0);
    try testing.expect(est.isAppLimited());
    try testing.expectEqual(@as(u64, 1), est.app_limited_until);
}

test "first_sent_time chain advances to the newest delivered packet's send time" {
    var est: Estimator = .{};
    var p1 = testPacket(1, 1_000, 100);
    est.onPacketSent(&p1, 0);
    var p2 = testPacket(2, 5_000, 100);
    est.onPacketSent(&p2, 100);
    try testing.expectEqual(@as(u64, 1_000), p2.first_sent_time_us);

    est.beginAckEvent();
    est.onPacketAcked(&p2, 9_000);
    _ = est.generateRateSample(0, 0);
    // Epoch start moved to p2's transmit; the next send measures from
    // there.
    try testing.expectEqual(@as(u64, 5_000), est.first_sent_time_us);
    var p3 = testPacket(3, 9_500, 100);
    est.onPacketSent(&p3, 100);
    try testing.expectEqual(@as(u64, 5_000), p3.first_sent_time_us);
}

test "lost accounting: rs.lost spans the sampled packet's flight, newly_lost spans the event" {
    var est: Estimator = .{};
    var p1 = testPacket(1, 1_000, 1_000);
    est.onPacketSent(&p1, 0);
    var p_lost_early = testPacket(2, 1_100, 400);
    est.onPacketSent(&p_lost_early, 1_000);
    // A loss declared between events (time-threshold tick).
    const info_early = est.onPacketLost(&p_lost_early);
    try testing.expectEqual(@as(u64, 400), info_early.c_lost);
    try testing.expectEqual(@as(u64, 0), info_early.lost_at_send);

    var p2 = testPacket(3, 2_000, 1_000);
    est.onPacketSent(&p2, 1_000); // lost_at_send = 400
    try testing.expectEqual(@as(u64, 400), p2.lost_at_send);

    var p_lost_late = testPacket(4, 2_100, 300);
    est.onPacketSent(&p_lost_late, 2_000);

    est.beginAckEvent();
    est.onPacketAcked(&p2, 10_000);
    // Loss declared inside this event (packet-threshold via this ACK).
    const info_late = est.onPacketLost(&p_lost_late);
    try testing.expectEqual(@as(u64, 700), info_late.c_lost);
    const rs = est.generateRateSample(0, 0).?;
    // rs.lost = C.lost(700) - P.lost_at_send(400).
    try testing.expectEqual(@as(u64, 300), rs.lost);
    try testing.expectEqual(@as(u64, 400), rs.prior_lost);
    // newly_lost = C.lost delta since beginAckEvent.
    try testing.expectEqual(@as(u64, 300), rs.newly_lost);
}

test "no in-flight delivery this event yields null (loss has its own channel)" {
    var est: Estimator = .{};
    est.beginAckEvent();
    try testing.expectEqual(@as(?RateSample, null), est.generateRateSample(0, 0));
}

test "u128 intermediates: large totals and stale stamps saturate instead of trapping" {
    var est: Estimator = .{};
    est.delivered = std.math.maxInt(u64) - 1_000;
    est.delivered_time_us = 1_000;
    est.first_sent_time_us = 1_000;
    var p = testPacket(1, 2_000, 5_000);
    est.onPacketSent(&p, 0);
    est.beginAckEvent();
    est.onPacketAcked(&p, 3_000);
    const rs = est.generateRateSample(0, 0).?;
    // delivered saturates at maxInt; the sample delta stays sane.
    try testing.expectEqual(std.math.maxInt(u64), est.delivered);
    try testing.expect(rs.delivered <= 5_000);
    try testing.expect(rs.has_rate);

    // A stamp "from the future" (clock discontinuity) clamps to zero
    // elapsed rather than wrapping.
    var est2: Estimator = .{};
    var q = testPacket(1, 5_000, 100);
    est2.onPacketSent(&q, 0);
    q.first_sent_time_us = 9_999_999; // corrupt: later than sent_time
    est2.beginAckEvent();
    est2.onPacketAcked(&q, 6_000);
    const rs2 = est2.generateRateSample(0, 0).?;
    try testing.expectEqual(@as(u64, 0), rs2.send_elapsed_us);
    try testing.expect(rs2.ack_elapsed_us > 0);
}

test "property: estimator matches a naive replay reference over random sequences" {
    // Reference model: keeps every sent packet's stamps by replaying
    // the same rules from first principles on flat arrays, then
    // recomputes each expected sample from the packet list instead of
    // the estimator's incremental transients. Catches adopt-rule and
    // totals drift under random ack ordering, losses, idle restarts,
    // and app-limited markings.
    var prng = std.Random.DefaultPrng.init(0xdead_beef_0bb7);
    const random = prng.random();

    const N = 512;
    var est: Estimator = .{};

    const Ref = struct {
        delivered: u64 = 0,
        delivered_time_us: u64 = 0,
        first_sent_time_us: u64 = 0,
        lost: u64 = 0,
        app_limited_until: u64 = 0,
    };
    var ref: Ref = .{};

    var packets: [N]sent_packets.SentPacket = undefined;
    var state: [N]enum { unsent, in_flight, acked, lost } = @splat(.unsent);
    var next_send: usize = 0;
    var now_us: u64 = 1_000;
    var in_flight_bytes: u64 = 0;

    var rounds: usize = 0;
    while (rounds < 200) : (rounds += 1) {
        now_us += random.intRangeAtMost(u64, 1, 5_000);
        switch (random.intRangeAtMost(u8, 0, 9)) {
            // Send a burst.
            0, 1, 2, 3 => {
                var burst = random.intRangeAtMost(usize, 1, 4);
                while (burst > 0 and next_send < N) : (burst -= 1) {
                    const bytes = random.intRangeAtMost(u64, 100, 1_500);
                    packets[next_send] = testPacket(@intCast(next_send), now_us, bytes);
                    // Reference stamping.
                    if (in_flight_bytes == 0) {
                        ref.first_sent_time_us = now_us;
                        ref.delivered_time_us = now_us;
                    }
                    var expect_stamp = packets[next_send];
                    expect_stamp.delivered = ref.delivered;
                    expect_stamp.delivered_time_us = ref.delivered_time_us;
                    expect_stamp.first_sent_time_us = ref.first_sent_time_us;
                    expect_stamp.tx_in_flight = in_flight_bytes + bytes;
                    expect_stamp.lost_at_send = ref.lost;
                    expect_stamp.is_app_limited = ref.app_limited_until != 0;

                    est.onPacketSent(&packets[next_send], in_flight_bytes);
                    try testing.expectEqual(expect_stamp, packets[next_send]);

                    in_flight_bytes += bytes;
                    state[next_send] = .in_flight;
                    next_send += 1;
                    now_us += random.intRangeAtMost(u64, 0, 200);
                }
            },
            // ACK event over a random subset of in-flight packets,
            // possibly with losses folded in.
            4, 5, 6, 7 => {
                est.beginAckEvent();
                const ref_prior_lost = ref.lost;
                var newest_idx: ?usize = null;
                var newly_acked: u64 = 0;
                var any = false;
                var tries = random.intRangeAtMost(usize, 1, 6);
                while (tries > 0) : (tries -= 1) {
                    const idx = random.intRangeAtMost(usize, 0, N - 1);
                    if (state[idx] != .in_flight) continue;
                    state[idx] = .acked;
                    in_flight_bytes -= packets[idx].bytes;
                    est.onPacketAcked(&packets[idx], now_us);
                    // Reference totals.
                    ref.delivered += packets[idx].bytes;
                    ref.delivered_time_us = now_us;
                    newly_acked += packets[idx].bytes;
                    any = true;
                    const better = newest_idx == null or
                        packets[idx].sent_time_us > packets[newest_idx.?].sent_time_us or
                        (packets[idx].sent_time_us == packets[newest_idx.?].sent_time_us and
                            packets[idx].pn > packets[newest_idx.?].pn);
                    if (better) newest_idx = idx;
                }
                // Occasionally a loss inside the event.
                if (random.boolean()) {
                    const idx = random.intRangeAtMost(usize, 0, N - 1);
                    if (state[idx] == .in_flight) {
                        state[idx] = .lost;
                        in_flight_bytes -= packets[idx].bytes;
                        _ = est.onPacketLost(&packets[idx]);
                        ref.lost += packets[idx].bytes;
                    }
                }
                if (newest_idx) |ni| {
                    // Reference epoch advance.
                    ref.first_sent_time_us = packets[ni].sent_time_us;
                }
                const min_rtt = random.intRangeAtMost(u64, 0, 20_000);
                const rs_opt = est.generateRateSample(min_rtt, 0);
                // Reference app-limited clearing (strictly-greater).
                if (ref.app_limited_until != 0 and ref.delivered > ref.app_limited_until) {
                    ref.app_limited_until = 0;
                }
                if (!any) {
                    try testing.expectEqual(@as(?RateSample, null), rs_opt);
                } else {
                    const rs = rs_opt.?;
                    const np = &packets[newest_idx.?];
                    try testing.expectEqual(np.pn, rs.last_acked_pn);
                    try testing.expectEqual(np.delivered, rs.prior_delivered);
                    try testing.expectEqual(np.lost_at_send, rs.prior_lost);
                    try testing.expectEqual(np.tx_in_flight, rs.tx_in_flight);
                    try testing.expectEqual(np.is_app_limited, rs.is_app_limited);
                    try testing.expectEqual(ref.delivered, rs.c_delivered);
                    try testing.expectEqual(ref.lost, rs.c_lost);
                    try testing.expectEqual(ref.delivered - np.delivered, rs.delivered);
                    try testing.expectEqual(newly_acked, rs.newly_acked);
                    try testing.expectEqual(ref.lost - ref_prior_lost, rs.newly_lost);
                    try testing.expectEqual(ref.lost - np.lost_at_send, rs.lost);
                    const send_el = np.sent_time_us - np.first_sent_time_us;
                    const ack_el = now_us - np.delivered_time_us;
                    try testing.expectEqual(@max(send_el, ack_el), rs.interval_us);
                    const expect_has = np.delivered_time_us != 0 and
                        rs.interval_us > 0 and rs.interval_us >= min_rtt;
                    try testing.expectEqual(expect_has, rs.has_rate);
                }
            },
            // Standalone loss (time-threshold between ACKs).
            8 => {
                const idx = random.intRangeAtMost(usize, 0, N - 1);
                if (state[idx] == .in_flight) {
                    state[idx] = .lost;
                    in_flight_bytes -= packets[idx].bytes;
                    const info = est.onPacketLost(&packets[idx]);
                    ref.lost += packets[idx].bytes;
                    try testing.expectEqual(ref.lost, info.c_lost);
                }
            },
            // App runs dry.
            9 => {
                est.markAppLimited(in_flight_bytes);
                ref.app_limited_until = @max(ref.delivered + in_flight_bytes, 1);
                try testing.expectEqual(ref.app_limited_until, est.app_limited_until);
            },
            else => unreachable,
        }
        // Invariants after every step.
        try testing.expectEqual(ref.delivered, est.delivered);
        try testing.expectEqual(ref.lost, est.lost);
        try testing.expectEqual(ref.app_limited_until, est.app_limited_until);
        if (next_send >= N) break;
    }
}
