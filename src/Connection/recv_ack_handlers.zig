//! Inbound ACK frame processing: per-encryption-level ACKs, the
//! multipath PATH_ACK twin, and the loss-recovery callback that
//! re-queues control frames RFC 9002 has declared lost. Free-function
//! siblings of `Connection`'s public method-style handlers; the
//! methods on `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_datagram = @import("datagram.zig");
const conn_qlog = @import("qlog.zig");
const conn_loss = @import("loss.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const PathState = state_mod.PathState;
const frame_types = state_mod.frame_types;
const ack_range_mod = state_mod.ack_range_mod;
const SentPacketTracker = state_mod.SentPacketTracker;
const PnSpace = state_mod.PnSpace;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

/// Scale a peer-reported ACK Delay (a varint, 0..2^62-1) by the peer's
/// `ack_delay_exponent`. RFC 9000 §18.2 permits an exponent up to 20,
/// so the product can exceed `u64`. Saturate instead of letting the
/// shift wrap: a wrapped value could silently deflate our RTT sample,
/// and — before `RttEstimator.update` guards its add — a large value
/// overflowed `min_rtt + ack_delay` and panicked in ReleaseSafe.
fn scaledAckDelayUs(raw: u64, exponent: u6) u64 {
    if (exponent == 0) return raw;
    const max: u64 = std.math.maxInt(u64);
    if (raw > (max >> exponent)) return max;
    return raw << exponent;
}

/// Validate the ECN counts trailer of a peer ACK frame against the
/// rules in RFC 9000 §13.4.2:
///
///   * The ECT0 + ECT1 + CE total in the new ACK MUST be at least
///     as large as the previous ACK's total at this level (each
///     individual count MUST be monotonically non-decreasing as
///     well).
///   * The CE count's increase MAY trigger a congestion event;
///     ECT0 / ECT1 increases are informational.
///
/// Returns a `bool` indicating whether the frame was accepted. On
/// rejection, the caller flips the level's `validation` to `failed`
/// so subsequent ACKs at this level stop emitting our own ECN
/// counts and stop reacting to peer-reported CE bumps.
fn validateAndApplyAckEcn(
    pn_space: *PnSpace.PnSpace,
    ecn_counts: ?frame_types.EcnCounts,
) bool {
    const counts = ecn_counts orelse return true; // No ECN trailer → no validation.
    if (pn_space.validation == .failed) return false;

    if (pn_space.peer_ack_ecn_seen) {
        if (counts.ect0 < pn_space.peer_ack_ect0) return false;
        if (counts.ect1 < pn_space.peer_ack_ect1) return false;
        if (counts.ecn_ce < pn_space.peer_ack_ce) return false;
    }
    pn_space.peer_ack_ect0 = counts.ect0;
    pn_space.peer_ack_ect1 = counts.ect1;
    pn_space.peer_ack_ce = counts.ecn_ce;
    pn_space.peer_ack_ecn_seen = true;
    return true;
}

/// Compute the change in CE count between this ACK and the previous
/// one at the same level. Returns `null` when no prior ECN counts
/// were captured (the bump signal isn't meaningful in isolation —
/// the first count we see is the *running total*, not a delta).
fn ceDelta(
    prev_seen: bool,
    prev_ce: u64,
    new_counts: ?frame_types.EcnCounts,
) ?u64 {
    if (!prev_seen) return null;
    const c = new_counts orelse return null;
    if (c.ecn_ce <= prev_ce) return 0;
    return c.ecn_ce - prev_ce;
}

/// The state one inbound ACK applies to, resolved from either entry
/// point. `handleAckAtLevel(.application, a)` and
/// `handleApplicationAckOnPath(primaryPath(), a)` build the same
/// target: for `lvl == .application` every level accessor on
/// `Connection` (pnSpaceForLevel, sentForLevel, rttForLevel,
/// ccForApplication, ptoCountForLevel) resolves to the primary path's
/// state. The dispatcher routes one wire frame to one entry or the
/// other purely on path id (`recv_multipath_handlers.handlePathAck`
/// sends id 0 to the level entry, id != 0 to the path entry), so a
/// behavior difference between them would be a behavior difference
/// between path 0 and path N for identical input.
const AckTarget = struct {
    pn_space: *PnSpace.PnSpace,
    sent: *SentPacketTracker,
    /// Owns delivery, cc, rtt, and the PMTUD probe state this ACK
    /// updates. For Initial / Handshake this is the primary path: no
    /// probes ride those levels, but the RFC 8899 counters stay
    /// coherent by consulting it.
    path: *PathState,
    lvl: EncryptionLevel,
    /// The PTO counter this ACK clears. Bound explicitly rather than
    /// derived: `Connection.ptoCountForLevel(.application)` resolves
    /// to the PRIMARY path's counter, which is the wrong one for a
    /// non-primary multipath target.
    pto_count: *u32,
    /// Which packet-threshold loss sweep this ACK triggers. The two
    /// sweeps genuinely differ (per-path requeue routing, and a
    /// per-path PTO base for persistent congestion), so the choice is
    /// carried per entry point rather than inferred.
    loss_scope: enum { level, path },

    /// True when this ACK carries 1-RTT semantics: delivery-rate
    /// sampling, PMTUD classification, key-epoch confirmation, stream
    /// dispatch, congestion control, and HyStart++ all key off it.
    /// Replaces the `lvl == .application` gates the level copy
    /// scattered through the pipeline.
    fn isApplication(target: AckTarget) bool {
        return target.lvl == .application;
    }
};

const AckDispatchCtx = struct {
    conn: *Connection,
    target: AckTarget,
    ack: frame_types.Ack,
    now_us: u64,
    largest_acked_send_time_us: ?u64 = null,
    largest_acked_ack_eliciting: bool = false,
    any_ack_eliciting_newly_acked: bool = false,
    in_flight_bytes_acked: u64 = 0,
    newest_acked_sent_time_us: u64 = 0,
    // RFC 8899 DPLPMTUD probe-ack vs regular-ack tracking.
    pmtud_probe_acked: bool = false,
    any_regular_acked: bool = false,
};

fn dispatchAcked(
    ctx: *AckDispatchCtx,
    acked: *SentPacketTracker.SentPacket,
) Error!void {
    defer acked.deinit(ctx.conn.allocator);
    if (acked.pn == ctx.ack.largest_acked) {
        ctx.largest_acked_send_time_us = acked.sent_time_us;
        ctx.largest_acked_ack_eliciting = acked.ack_eliciting;
    }
    if (acked.ack_eliciting) ctx.any_ack_eliciting_newly_acked = true;
    if (acked.in_flight) {
        ctx.in_flight_bytes_acked += acked.bytes;
        if (acked.sent_time_us > ctx.newest_acked_sent_time_us) {
            ctx.newest_acked_sent_time_us = acked.sent_time_us;
        }
        // Delivery-rate sampler: fold this delivery into the ACK
        // event's sample while the slot's transmit-time stamps are
        // still live (the deferred deinit runs after this handler).
        if (ctx.target.isApplication()) {
            ctx.target.path.path.delivery.onPacketAcked(acked, ctx.now_us);
        }
    }
    if (ctx.target.isApplication()) {
        // RFC 8899 §5.1 probe-vs-regular ack classification —
        // 1-RTT only.
        if (ctx.target.path.pmtu_probe_pn) |probe_pn| {
            if (probe_pn == acked.pn) {
                ctx.pmtud_probe_acked = true;
            } else {
                ctx.any_regular_acked = true;
            }
        } else {
            ctx.any_regular_acked = true;
        }
        // These two side effects are independent — the key epoch
        // touches only key state, the stream dispatch only send
        // buffers — so their relative order is free. Fixed here as
        // keys-then-streams: the per-path twin used the opposite
        // order, which was observable only on the error path (a
        // stream error left the key epoch unconfirmed on one side).
        ctx.conn.onApplicationPacketAckedForKeys(acked, ctx.now_us);
        try conn_loss.dispatchAckedPacketToStreams(ctx.conn, acked);
    }
    conn_loss.discardSentCryptoForPacket(ctx.conn, ctx.target.lvl, acked.pn);
    conn_loss.dispatchAckedControlFrames(ctx.conn, acked);
    conn_datagram.recordDatagramAcked(ctx.conn, acked);
}

/// Apply one inbound ACK to `target`: validate, walk the ranges,
/// fold the results into PMTUD / RTT / congestion / delivery-rate
/// state, run packet-threshold loss detection, and emit qlog.
///
/// The single implementation behind both public entry points. The
/// only step that genuinely differs between them is loss detection
/// (per-path requeue routing and a per-path PTO base for persistent
/// congestion), which is dispatched on the target rather than
/// unified — see `detectLosses` below.
fn apply(
    conn: *Connection,
    target: AckTarget,
    a: frame_types.Ack,
    now_us: u64,
) Error!void {
    // RFC 9000 §13.1 / RFC 9002 §A.3: an ACK that claims a packet
    // number we never sent (largest_acked >= next_pn) is a
    // PROTOCOL_VIOLATION. We must reject it before updating
    // largest_acked_sent — otherwise the bogus value would
    // poison packet-threshold loss detection on legitimate
    // in-flight packets.
    if (a.largest_acked >= target.pn_space.next_pn) {
        conn.close(true, transport_error_protocol_violation, "ack of unsent packet");
        return;
    }
    // RFC 9000 §13.4.2: validate peer-reported ECN counts BEFORE
    // we walk the ACK ranges, so we can compute the CE delta
    // against the captured baseline rather than the just-mutated
    // baseline. Validation that fails here flips the space's
    // ECN state to `failed`; future outbound ACKs stop emitting
    // ECN counts here (`ecn_enabled` still says yes overall, but
    // this space is bleached). Multipath PATH_ACK frames carry the
    // same ECN trailer and get the same monotonicity check.
    const prev_ecn_seen = target.pn_space.peer_ack_ecn_seen;
    const prev_ce = target.pn_space.peer_ack_ce;
    const ecn_ok = if (conn.ecn_enabled) validateAndApplyAckEcn(target.pn_space, a.ecn_counts) else true;
    if (!ecn_ok) {
        target.pn_space.validation = .failed;
    }
    target.pn_space.onAckReceived(a.largest_acked);

    var ctx: AckDispatchCtx = .{
        .conn = conn,
        .target = target,
        .ack = a,
        .now_us = now_us,
    };

    // Open the delivery-rate sampler's ACK event before the walk so
    // per-packet deliveries and any losses this event declares fold
    // into one sample.
    if (target.isApplication()) target.path.path.delivery.beginAckEvent();

    var ack_it = ack_range_mod.iter(a);
    while (try ack_it.next()) |interval| {
        // Walk the (small, bounded) sent-packet tracker rather
        // than every PN in [smallest, largest]. A peer-chosen
        // first_range can stretch interval.smallest down to 0;
        // iterating the PN range directly would let a single
        // ACK force O(next_pn) work, which on a long-lived
        // connection is a real DoS surface (RFC 9000 §13.1
        // only constrains largest_acked < next_pn). Walking
        // the tracker is O(K log N) where K = packets matched
        // and N = tracker size, both bounded by our own send
        // rate × CWND.
        const start = target.sent.lowerBound(interval.smallest) orelse continue;
        var end = start;
        while (end < target.sent.count and target.sent.packets[end].pn <= interval.largest) : (end += 1) {}
        try target.sent.removeRangeWithError(start, end, &ctx, dispatchAcked);
    }

    // Fold PMTUD ack outcomes back into path state.
    if (target.isApplication()) {
        if (ctx.pmtud_probe_acked) {
            _ = target.path.pmtudOnProbeAcked(
                conn.pmtud_config.probe_step,
                conn.pmtud_config.max_mtu,
            );
        }
        if (ctx.any_regular_acked) target.path.pmtudOnRegularAcked();
    }

    // Did this ACK yield a fresh RTT sample? HyStart++ only consumes
    // ACKs that did (RFC 9406 §4.2).
    var rtt_sampled = false;
    if (ctx.largest_acked_send_time_us) |sent_time_us| {
        if (ctx.largest_acked_ack_eliciting and now_us >= sent_time_us) {
            const ack_delay_us = scaledAckDelayUs(a.ack_delay, conn.peerAckDelayExponent());
            target.path.path.rtt.update(
                now_us - sent_time_us,
                ack_delay_us,
                conn.handshakeDone(),
                conn.peerMaxAckDelayUs(),
            );
            rtt_sampled = true;
        }
    }
    if (ctx.any_ack_eliciting_newly_acked) target.pto_count.* = 0;
    if (target.isApplication()) {
        const cc = &target.path.path.cc;
        if (ctx.in_flight_bytes_acked > 0) {
            cc.onPacketAcked(
                ctx.in_flight_bytes_acked,
                ctx.newest_acked_sent_time_us,
                now_us,
                target.path.path.rtt.smoothed_rtt_us,
                target.sent.bytes_in_flight,
            );
        }
        // RFC 9406 HyStart++: feed the processed ACK after cwnd
        // growth, so an exit decision applies to the window this ACK
        // just produced.
        cc.onAckProcessed(
            a.largest_acked,
            if (rtt_sampled) target.path.path.rtt.latest_rtt_us else null,
            target.pn_space.next_pn,
        );
    }

    // RFC 9000 §13.4.2 / RFC 9002 §B.7: a peer-reported CE bump on
    // application packets is a congestion event; halve cwnd and
    // arm recovery. We only credit the event when the ACK passed
    // §13.4.2 validation AND we have a baseline to diff against
    // (`ceDelta` returns `null` for the very first ECN-bearing ACK
    // — no monotonicity to compute yet, so no congestion event is
    // implied either). The largest newly-acked sent time anchors
    // the recovery period boundary; if no in-flight packets were
    // matched (an empty-range ACK with bumped CE is technically
    // legal but never useful), we fall back to `now_us`.
    const ce_delta_packets: u64 = if (ecn_ok and target.isApplication())
        ceDelta(prev_ecn_seen, prev_ce, a.ecn_counts) orelse 0
    else
        0;
    if (ce_delta_packets > 0) {
        const ce_anchor = if (ctx.newest_acked_sent_time_us != 0) ctx.newest_acked_sent_time_us else now_us;
        target.path.path.cc.onCongestionEvent(ce_anchor);
    }

    // Loss detection — packet-threshold only (time-threshold lives
    // in `tick`).
    try detectLosses(conn, target);

    // Close the delivery-rate sampler's ACK event AFTER loss
    // detection, so `newly_lost` covers everything this ACK declared
    // lost (ccwg-bbr-06 §2.3), and hand the sample to the controller
    // with the post-ACK, post-loss in-flight residue (the draft's
    // C.inflight at model-update time).
    if (target.isApplication()) {
        const min_rtt_us = target.path.path.rtt.min_rtt_us;
        if (target.path.path.delivery.generateRateSample(min_rtt_us, ce_delta_packets)) |rs| {
            target.path.path.cc.onDeliveryRateSample(&rs, now_us, target.sent.bytes_in_flight);
        }
    }

    // Snapshot metrics + congestion phase after a meaningful ACK.
    if (ctx.any_ack_eliciting_newly_acked or ctx.in_flight_bytes_acked > 0) {
        conn_qlog.emitCongestionStateIfChanged(conn, now_us);
        conn_qlog.emitMetricsSnapshot(conn, now_us);
    }
}

/// The one step that is not a container swap. The level and per-path
/// loss sweeps differ in requeue routing (`activePath().id` vs the
/// target path's id) and in the persistent-congestion PTO base
/// (level-wide vs per-path), so this dispatches rather than unifies.
fn detectLosses(conn: *Connection, target: AckTarget) Error!void {
    switch (target.loss_scope) {
        .level => try conn_loss.detectLossesByPacketThresholdAtLevel(conn, target.lvl),
        .path => try conn.detectLossesByPacketThresholdOnApplicationPath(target.path),
    }
}

pub fn handleAckAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    a: frame_types.Ack,
    now_us: u64,
) Error!void {
    return apply(conn, .{
        .pn_space = conn.pnSpaceForLevel(lvl),
        .sent = conn.sentForLevel(lvl),
        .path = conn.primaryPath(),
        .lvl = lvl,
        .pto_count = conn.ptoCountForLevel(lvl),
        .loss_scope = .level,
    }, a, now_us);
}

pub fn handleApplicationAckOnPath(
    conn: *Connection,
    path: *PathState,
    a: frame_types.Ack,
    now_us: u64,
) Error!void {
    return apply(conn, .{
        .pn_space = &path.app_pn_space,
        .sent = &path.sent,
        .path = path,
        .lvl = .application,
        .pto_count = &path.pto_count,
        .loss_scope = .path,
    }, a, now_us);
}

pub fn dispatchLostControlFrames(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) Error!bool {
    return conn.dispatchLostControlFramesOnPath(packet, conn.activePath().id);
}
