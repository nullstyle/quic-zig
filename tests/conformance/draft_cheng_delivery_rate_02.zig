//! draft-cheng-iccrg-delivery-rate-estimation-02 — Delivery Rate
//! Estimation, as embedded and updated by draft-ietf-ccwg-bbr-06
//! §4.1.2 (the expired individual draft's algorithm continues inside
//! the adopted BBR document; bbr-06 is cited below where a rule exists
//! only there).
//!
//! Pins the sampler quic exposes as
//! `quic.conn.delivery_rate.Estimator`, driven unit-level with
//! hand-stamped packets and microsecond timestamps — the same style as
//! rfc9438_cubic.zig. The Connection-level call-site gates (only
//! in-flight application/0-RTT packets are stamped; pure ACKs never
//! reach the estimator; the app-limited mark fires on an empty poll
//! with congestion headroom) are integration-tested next to the
//! implementation in `src/conn/_state_tests_delivery.zig`.
//!
//! ## Coverage
//!
//! Covered:
//!   draft-cheng-02 §3.1.2       MUST      per-packet delivery state is
//!                                         tracked at transmit
//!   draft-cheng-02 §3.2         NORMATIVE idle restart re-seeds the
//!                                         delivery clocks
//!   ccwg-bbr-06 §4.1.2.1.2      NORMATIVE transmit snapshots extend to
//!                                         tx_in_flight and lost
//!   ccwg-bbr-06 §4.1.2.3        NORMATIVE sample follows the newest-sent
//!                                         delivered packet (PN tie-break)
//!   draft-cheng-02 §2.2         NORMATIVE interval = max(send_elapsed,
//!                                         ack_elapsed)
//!   draft-cheng-02 §3.3         NORMATIVE interval < min_rtt yields no
//!                                         reliable rate
//!   draft-cheng-02 §2.2         MAY       delivery accounted in octets
//!   draft-cheng-02 §3.4         NORMATIVE app-limited marker lifecycle
//!   draft-cheng-02 §3.2         NORMATIVE samples carry the sampled
//!                                         packet's app-limited taint
//!   ccwg-bbr-06 §2.3            NORMATIVE rs.lost spans the packet's
//!                                         flight; newly_lost the event
//!
//! Out of scope here:
//!   draft-cheng-02 §4 TCP retransmission caveats — QUIC never
//!   retransmits a packet number, so a stamp is never rewritten.
//!   ccwg-bbr-06 §2.2 "MUST NOT count pure ACKs" — a call-site gate,
//!   integration-tested in src/conn/_state_tests_delivery.zig (the
//!   estimator never sees non-in-flight packets).

const std = @import("std");
const quic = @import("quic");
const delivery_rate = quic.conn.delivery_rate;
const sent_packets = quic.conn.sent_packets;

const Estimator = delivery_rate.Estimator;

fn packet(pn: u64, sent_time_us: u64, bytes: u64) sent_packets.SentPacket {
    return .{
        .pn = pn,
        .sent_time_us = sent_time_us,
        .bytes = bytes,
        .ack_eliciting = true,
        .in_flight = true,
    };
}

test "MUST track per-packet delivery state at transmit [draft-cheng-iccrg-delivery-rate-estimation-02 §3.1.2]" {
    var est: Estimator = .{};
    est.delivered = 42_000;
    est.delivered_time_us = 7_000;
    est.first_sent_time_us = 6_500;
    est.markAppLimited(1_000);

    var p = packet(9, 10_000, 1_200);
    est.onPacketSent(&p, 3_600);
    // P.delivered, P.delivered_time, P.first_sent_time,
    // P.is_app_limited — the four §3.1.2 fields.
    try std.testing.expectEqual(@as(u64, 42_000), p.delivered);
    try std.testing.expectEqual(@as(u64, 7_000), p.delivered_time_us);
    try std.testing.expectEqual(@as(u64, 6_500), p.first_sent_time_us);
    try std.testing.expect(p.is_app_limited);
}

test "NORMATIVE idle restart re-seeds the delivery clocks at the next send [draft-cheng-iccrg-delivery-rate-estimation-02 §3.2]" {
    var est: Estimator = .{};
    est.delivered_time_us = 1_000;
    est.first_sent_time_us = 900;
    // Nothing in flight: both clocks jump to this packet's transmit,
    // so the idle gap is never billed as sampling interval.
    var p = packet(1, 50_000, 1_200);
    est.onPacketSent(&p, 0);
    try std.testing.expectEqual(@as(u64, 50_000), est.delivered_time_us);
    try std.testing.expectEqual(@as(u64, 50_000), est.first_sent_time_us);
    try std.testing.expectEqual(@as(u64, 50_000), p.delivered_time_us);
    try std.testing.expectEqual(@as(u64, 50_000), p.first_sent_time_us);

    // Busy pipe: clocks stay put.
    var q = packet(2, 60_000, 1_200);
    est.onPacketSent(&q, 1_200);
    try std.testing.expectEqual(@as(u64, 50_000), q.first_sent_time_us);
}

test "NORMATIVE transmit snapshots extend to tx_in_flight and lost [draft-ietf-ccwg-bbr-06 §4.1.2.1.2]" {
    var est: Estimator = .{};
    var lost_one = packet(1, 1_000, 700);
    est.onPacketSent(&lost_one, 0);
    _ = est.onPacketLost(&lost_one);

    var p = packet(2, 2_000, 1_200);
    est.onPacketSent(&p, 4_800);
    // P.tx_in_flight includes the packet itself; P.lost snapshots
    // C.lost so rs.lost = C.lost - P.lost can span its flight.
    try std.testing.expectEqual(@as(u64, 6_000), p.tx_in_flight);
    try std.testing.expectEqual(@as(u64, 700), p.lost_at_send);
}

test "NORMATIVE sample follows the newest-sent delivered packet with PN tie-break [draft-ietf-ccwg-bbr-06 §4.1.2.3]" {
    // draft-cheng-02 §3.3 selected by largest P.delivered; bbr-06's
    // IsNewestPacket selects by send time with packet_id as the tie
    // break. On QUIC's monotone per-path PNs they agree except under
    // equal timestamps — this drives the consumer draft's rule.
    var est: Estimator = .{};
    var a = packet(1, 1_000, 100);
    var b = packet(2, 5_000, 100);
    var c = packet(3, 5_000, 100); // same transmit instant as b
    est.onPacketSent(&a, 0);
    est.onPacketSent(&b, 100);
    est.onPacketSent(&c, 200);

    est.beginAckEvent();
    est.onPacketAcked(&c, 9_000);
    est.onPacketAcked(&b, 9_000);
    est.onPacketAcked(&a, 9_000);
    const rs = est.generateRateSample(0, 0).?;
    try std.testing.expectEqual(@as(u64, 3), rs.last_acked_pn);
}

test "NORMATIVE rate interval is max(send_elapsed, ack_elapsed) [draft-cheng-iccrg-delivery-rate-estimation-02 §2.2]" {
    // ACK compression and send-side pauses each stretch one leg; the
    // longer leg must win so the estimate under-states, never
    // inflates.
    var est: Estimator = .{};
    var epoch = packet(1, 100_000, 1_000);
    est.onPacketSent(&epoch, 0);
    var p = packet(2, 140_000, 1_000);
    est.onPacketSent(&p, 1_000);

    est.beginAckEvent();
    est.onPacketAcked(&p, 150_000);
    const rs = est.generateRateSample(0, 0).?;
    try std.testing.expectEqual(@as(u64, 40_000), rs.send_elapsed_us);
    try std.testing.expectEqual(@as(u64, 50_000), rs.ack_elapsed_us);
    try std.testing.expectEqual(@as(u64, 50_000), rs.interval_us);
    try std.testing.expectEqual(@as(u64, 20_000), rs.delivery_rate_bps);
}

test "NORMATIVE an interval shorter than min_rtt yields no reliable rate [draft-cheng-iccrg-delivery-rate-estimation-02 §3.3]" {
    var est: Estimator = .{};
    var p = packet(1, 1_000, 1_200);
    est.onPacketSent(&p, 0);
    est.beginAckEvent();
    est.onPacketAcked(&p, 2_000);
    // interval 1ms against a 50ms min_rtt: below one round trip no
    // rate can be trusted, but the delivered/newly_acked signals must
    // survive for consumers that gate on has_rate.
    const rs = est.generateRateSample(50_000, 0).?;
    try std.testing.expect(!rs.has_rate);
    try std.testing.expectEqual(@as(u64, 0), rs.delivery_rate_bps);
    try std.testing.expectEqual(@as(u64, 1_200), rs.delivered);
    try std.testing.expectEqual(@as(u64, 1_200), rs.newly_acked);
}

test "MAY account delivery in octets [draft-cheng-iccrg-delivery-rate-estimation-02 §2.2]" {
    // The draft permits packet- or octet-granularity; quic uses
    // octets, matching the byte-based congestion controller surface.
    var est: Estimator = .{};
    var p = packet(1, 1_000, 977); // deliberately not a round packet count
    est.onPacketSent(&p, 0);
    est.beginAckEvent();
    est.onPacketAcked(&p, 2_000);
    try std.testing.expectEqual(@as(u64, 977), est.delivered);
}

test "NORMATIVE app-limited marker is delivered + in-flight with floor 1, cleared only when passed [draft-cheng-iccrg-delivery-rate-estimation-02 §3.4]" {
    var est: Estimator = .{};
    est.markAppLimited(0);
    try std.testing.expectEqual(@as(u64, 1), est.app_limited_until); // floor

    var p1 = packet(1, 1_000, 800);
    est.onPacketSent(&p1, 0);
    est.markAppLimited(800); // delivered(0) + inflight(800)
    try std.testing.expectEqual(@as(u64, 800), est.app_limited_until);

    // Delivering exactly up to the marker does NOT clear it — the
    // rule is strictly greater.
    est.beginAckEvent();
    est.onPacketAcked(&p1, 5_000);
    _ = est.generateRateSample(0, 0);
    try std.testing.expect(est.isAppLimited());

    // One more delivered byte past the marker clears it.
    var p2 = packet(2, 6_000, 100);
    est.onPacketSent(&p2, 0);
    est.beginAckEvent();
    est.onPacketAcked(&p2, 9_000);
    _ = est.generateRateSample(0, 0);
    try std.testing.expect(!est.isAppLimited());
}

test "NORMATIVE samples carry the sampled packet's app-limited taint [draft-cheng-iccrg-delivery-rate-estimation-02 §3.2]" {
    var est: Estimator = .{};
    var clean = packet(1, 1_000, 500);
    est.onPacketSent(&clean, 0);
    est.markAppLimited(500);
    var tainted = packet(2, 2_000, 500);
    est.onPacketSent(&tainted, 500);

    // Sample over the clean packet: no taint.
    est.beginAckEvent();
    est.onPacketAcked(&clean, 5_000);
    try std.testing.expect(!est.generateRateSample(0, 0).?.is_app_limited);

    // Sample over the tainted packet: taint rides the sample even
    // though the marker itself has been retired by then.
    est.beginAckEvent();
    est.onPacketAcked(&tainted, 6_000);
    const rs = est.generateRateSample(0, 0).?;
    try std.testing.expect(rs.is_app_limited);
}

test "NORMATIVE rs.lost spans the sampled packet's flight and newly_lost the ACK event [draft-ietf-ccwg-bbr-06 §2.3]" {
    var est: Estimator = .{};
    var early_loss = packet(1, 1_000, 400);
    est.onPacketSent(&early_loss, 0);
    _ = est.onPacketLost(&early_loss); // declared before the event

    var p = packet(2, 2_000, 1_000);
    est.onPacketSent(&p, 0); // P.lost snapshots C.lost = 400
    var late_loss = packet(3, 2_100, 300);
    est.onPacketSent(&late_loss, 1_000);

    est.beginAckEvent();
    est.onPacketAcked(&p, 10_000);
    _ = est.onPacketLost(&late_loss); // declared inside the event
    const rs = est.generateRateSample(0, 0).?;
    // rs.lost = C.lost(700) - P.lost(400): only what was lost during
    // the sampled packet's own flight.
    try std.testing.expectEqual(@as(u64, 300), rs.lost);
    // newly_lost = event-scoped delta.
    try std.testing.expectEqual(@as(u64, 300), rs.newly_lost);
    try std.testing.expectEqual(@as(u64, 700), rs.c_lost);
}
