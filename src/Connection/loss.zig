//! RFC 9002 loss detection and PTO for Connection: PTO/backoff duration
//! math, the loss / PTO / idle timer deadlines, acked- and lost-packet
//! dispatch to streams and control-frame queues, packet- and
//! time-threshold loss detection, and PTO probe firing — in both
//! per-level and multipath per-path variants. Free-function siblings of
//! `Connection`'s method-style loss plumbing; the methods on
//! `Connection` are thin thunks that delegate here. The pure
//! estimator/tracker types live in loss_recovery.zig / SentPacketTracker.zig
//! / RttEstimator.zig; inbound ACK processing lives in
//! Connection/recv_ack_handlers.zig.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_qlog = @import("qlog.zig");
const conn_paths = @import("paths.zig");
const conn_streams = @import("streams.zig");
const conn_datagram = @import("datagram.zig");
const conn_flow = @import("flow.zig");
const conn_cids = @import("cids.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const PathState = state_mod.PathState;
const LossStats = state_mod.LossStats;
const TimerDeadline = state_mod.TimerDeadline;
const congestion_mod = state_mod.congestion_mod;
const loss_recovery_mod = state_mod.loss_recovery_mod;
const PendingFrameQueues = state_mod.PendingFrameQueues;
const RttEstimator = state_mod.RttEstimator;
const send_stream_mod = state_mod.send_stream_mod;
const SentPacketTracker = state_mod.SentPacketTracker;

fn backoffDuration(base: u64, count: u32) u64 {
    const shift: u6 = @intCast(@min(count, 16));
    const max_u64: u64 = std.math.maxInt(u64);
    if (base > (max_u64 >> shift)) return max_u64;
    return base << shift;
}

pub fn basePtoDurationForLevel(conn: *const Connection, lvl: EncryptionLevel) u64 {
    const max_ack_delay_us: u64 = switch (lvl) {
        .initial, .handshake => 0,
        .early_data, .application => conn.peerMaxAckDelayUs(),
    };
    return conn.rttForLevelConst(lvl).pto(max_ack_delay_us);
}

/// The longest wait between two probes in the Initial and Handshake
/// spaces: the probe timeout of an endpoint with no RTT sample (RFC
/// 9002 section 6.2.2, about 1 s). So a client WITH a sample never
/// probes less often than one without. RFC 9002 section 6.2.1 doubles
/// the timeout at every expiry without a bound; this bound is a
/// DEVIATION, for the handshake only, where the time is budgeted (a
/// peer forgets a half-open connection, an interop test gives 30 s).
/// MEASURED 2026-10-06 (client x quiche x handshakecorruption, 31% of
/// the datagrams corrupted both ways, `ccell-oi6-quicheC1-10`): a
/// client waiting for the rest of the server's flight probed at gaps
/// of 0.4, 0.7, 1.2, 2.3, 4.4, 8.7 s (a 150 ms base doubled), ten
/// probes in 30 s, and the flight never got through. A bound of 8
/// times the base instead floods a 2 ms path (the client's retries
/// inside a 100 ms outage used up the server's early copies, and the
/// handshake waited for the server's 1 s probe timeout: 134 ms ->
/// 1019 ms in tests/e2e/handshake_loss.zig), so the bound is a time.
/// The Application space keeps the RFC's doubling (quic-go bounds it
/// at 60 s; a lost packet there has no budget).
pub const max_handshake_pto_us: u64 = blk: {
    const no_sample: RttEstimator = .{};
    break :blk no_sample.pto(0);
};

pub fn ptoDurationForLevel(conn: *const Connection, lvl: EncryptionLevel) u64 {
    const base = basePtoDurationForLevel(conn, lvl);
    const backed_off = backoffDuration(base, conn.ptoCountForLevelConst(lvl).*);
    return switch (lvl) {
        .initial, .handshake => @max(base, @min(backed_off, max_handshake_pto_us)),
        .early_data, .application => backed_off,
    };
}

pub fn basePtoDurationForApplicationPath(conn: *const Connection, path: *const PathState) u64 {
    return path.path.rtt.pto(conn.peerMaxAckDelayUs());
}

pub fn ptoDurationForApplicationPath(conn: *const Connection, path: *const PathState) u64 {
    return backoffDuration(basePtoDurationForApplicationPath(conn, path), path.pto_count);
}

pub fn largestApplicationPtoDurationUs(conn: *const Connection) u64 {
    var largest: u64 = 0;
    for (conn.paths.paths.items) |*path| {
        if (path.path.state == .failed) continue;
        largest = @max(largest, ptoDurationForApplicationPath(conn, path));
    }
    if (largest == 0) largest = ptoDurationForApplicationPath(conn, conn.primaryPathConst());
    return largest;
}

pub fn retiredPathRetentionUs(conn: *const Connection) u64 {
    return Connection.saturatingMul(3, largestApplicationPtoDurationUs(
        conn,
    ));
}

pub fn considerDeadline(best: *?TimerDeadline, candidate: TimerDeadline) void {
    if (best.* == null or candidate.at_us < best.*.?.at_us) {
        best.* = candidate;
    }
}

/// Earliest time-threshold loss deadline over the tracked packets
/// below `largest_acked_sent`, or null when nothing is eligible.
/// Shared by the per-level and per-path deadline queries — the walk
/// and the RFC 9002 §6.1.2 threshold are identical for both; only
/// which tracker/space/estimator they read differs.
fn earliestLossDeadline(
    sent: *const SentPacketTracker,
    pn_space: *const state_mod.PnSpace,
    rtt: *const RttEstimator,
) ?u64 {
    const largest_acked = pn_space.largest_acked_sent orelse return null;
    const time_threshold = sent.reorder.timeThresholdUs(rtt);

    var best: ?u64 = null;
    var i: u32 = 0;
    while (i < sent.count) : (i += 1) {
        const p = sent.packets[i];
        if (p.dead) continue;
        if (p.pn > largest_acked) continue;
        const at_us = p.sent_time_us +| time_threshold;
        if (best == null or at_us < best.?) best = at_us;
    }
    return best;
}

/// Send time of the oldest live ack-eliciting tracked packet, which
/// anchors the PTO deadline. Shared by both PTO deadline queries.
fn oldestAckElicitingSentTime(sent: *const SentPacketTracker) ?u64 {
    var oldest: ?u64 = null;
    var i: u32 = 0;
    while (i < sent.count) : (i += 1) {
        const p = sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;
        if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
    }
    return oldest;
}

pub fn lossDeadlineForLevel(conn: *const Connection, lvl: EncryptionLevel) ?u64 {
    return earliestLossDeadline(
        conn.sentForLevelConst(lvl),
        conn.pnSpaceForLevelConst(lvl),
        conn.rttForLevelConst(lvl),
    );
}

pub fn lossDeadlineForApplicationPath(conn: *const Connection, path: *const PathState) ?u64 {
    _ = conn;
    return earliestLossDeadline(&path.sent, &path.app_pn_space, &path.path.rtt);
}

/// Send time of the newest live ack-eliciting tracked packet: the
/// anchor of the handshake spaces' probe deadline (RFC 9002 A.8,
/// `time_of_last_ack_eliciting_packet`). The deadline ran from the
/// OLDEST packet until 0.30.0; with a bounded backoff
/// (`max_handshake_pto_us`) that cascades: the expiry of the oldest
/// packet leaves the next-oldest already past its deadline, and one
/// probe timeout sent 2, then 4, then 8 datagrams (MEASURED
/// 2026-10-06, client x quiche x handshakecorruption, image `pr1`).
/// From the last send, a probe moves the deadline a whole timeout on.
fn newestAckElicitingSentTime(sent: *const SentPacketTracker) ?u64 {
    var newest: ?u64 = null;
    var i: u32 = 0;
    while (i < sent.count) : (i += 1) {
        const p = sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;
        if (newest == null or p.sent_time_us > newest.?) newest = p.sent_time_us;
    }
    return newest;
}

pub fn ptoDeadlineForLevel(conn: *const Connection, lvl: EncryptionLevel) ?u64 {
    if (newestAckElicitingSentTime(conn.sentForLevelConst(lvl))) |sent_at| {
        return sent_at +| ptoDurationForLevel(conn, lvl);
    }
    // Nothing in flight at this level. A client may still owe a probe.
    if (antiDeadlockLevel(conn) != lvl) return null;
    const anchor = conn.handshake_probe_anchor_us orelse return null;
    return anchor +| ptoDurationForLevel(conn, lvl);
}

/// RFC 9002 §6.2.2.1: the level at which a CLIENT owes a probe even
/// though it has nothing in flight, or null.
///
/// A server may send only 3 times what it received until it has
/// validated the client's address (RFC 9000 §8.1). If the client's
/// packets are lost, the server can be at that limit with a part of
/// its flight unsent, or with a lost flight it may not send again. It
/// can do nothing. The client has acknowledged all it got, so it has
/// nothing in flight, and its normal probe timer is off. If the client
/// now waits, nobody sends again (MEASURED 2026-10-03, in
/// tests/e2e/handshake_loss.zig: a 5.4 KB certificate, the client's
/// three ACK datagrams lost; both ends were silent until the handshake
/// timeout). So the client keeps its probe timer running until it
/// knows that the server validated its address: until an ACK arrives
/// in a Handshake packet, or the handshake is confirmed (then both
/// handshake spaces have no keys, and there is no level to probe at).
///
/// The probe goes out in a Handshake packet if the client has
/// Handshake keys (the server validates the address when it opens
/// one), and in an Initial packet if not (padded to 1200 bytes like
/// every client Initial, so it buys the server 3600 bytes).
pub fn antiDeadlockLevel(conn: *const Connection) ?EncryptionLevel {
    if (conn.role != .client) return null;
    if (conn.received_handshake_ack) return null;
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
        if (oldestAckElicitingSentTime(conn.sentForLevelConst(lvl)) != null) return null;
    }
    if (conn.levels[EncryptionLevel.handshake.idx()].write != null) return .handshake;
    if (!conn.initial_keys_discarded) return .initial;
    return null;
}

pub fn ptoDeadlineForApplicationPath(conn: *const Connection, path: *const PathState) ?u64 {
    if (applicationPtoHeld(conn)) return null;
    // RFC 9002 A.8: from the last ack-eliciting packet sent. An endpoint
    // that keeps sending keeps the probe timer ahead of it; the losses
    // in between are the ACKs' business (the thresholds). Until 0.30.0
    // the timer ran from the OLDEST packet, so a sender with a full
    // window saw a probe timeout for every packet the peer's ACK was
    // late for, and each one cost a packet declared lost and a window
    // reduction (see `firePtoOnApplicationPath`).
    const sent_at = newestAckElicitingSentTime(&path.sent) orelse return null;
    return sent_at +| ptoDurationForApplicationPath(conn, path);
}

/// RFC 9002 §6.2.1: the probe timer of the Application Data space is
/// not set until the handshake is confirmed. Before that the peer may
/// not have the keys to open a 1-RTT probe, or we may not have the
/// keys to open its ACK; the handshake spaces have their own timers,
/// and those are the ones that make progress.
///
/// MEASURED 2026-10-03 (quic-interop-runner `handshakecorruption`): a
/// server sends NEW_CONNECTION_ID in a 1-RTT packet with its first
/// flight. When the flight was lost, this timer ran out a second
/// later and sent that frame again, alone, to a client that had no
/// 1-RTT keys. Twice in one connection that useless packet was the
/// one datagram the network let through between two runs of three
/// corrupted ones, and six copies of the flight were lost around it.
///
/// "Confirmed" is the moment the Handshake keys are discarded: for a
/// server when the handshake completes, for a client at
/// HANDSHAKE_DONE (see `keys.discardHandshakeKeys`). The timer is the
/// normal one from then on, counted from the send time of the oldest
/// packet, so a probe that is due goes out at once.
///
/// A connection whose handshake does not run over packets has nothing
/// to wait for: the bench pair and the unit fixtures install their
/// keys by hand and never set an Initial connection ID.
pub fn applicationPtoHeld(conn: *const Connection) bool {
    return conn.initial_dcid_set and !conn.handshake_keys_discarded;
}

pub fn idleDeadline(conn: *const Connection) ?u64 {
    if (conn.last_activity_us == 0) return null;
    const timeout = conn.idleTimeoutUs() orelse return null;
    return conn.last_activity_us +| timeout;
}

pub fn dispatchAckedPacketToStreams(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) Error!void {
    var refs = packet.streamRefs();
    while (refs.next()) |ref| {
        const s = conn.streams.get(ref.stream_id) orelse continue;
        // Snapshot the send-buffer length so we can release the
        // matching budget when the ack advances the stream's
        // contiguous-acked floor (RFC 9000 §3.1: bytes ≤ floor are
        // dropped from the in-memory buffer).
        const before = s.send.bytes.len();
        s.send.onPacketAcked(ref.stream_key) catch |e| switch (e) {
            send_stream_mod.Error.UnknownPacket => continue,
            else => return e,
        };
        const after = s.send.bytes.len();
        if (after < before) conn.releaseResidentBytes(before - after);
        conn_streams.noteSendable(conn, s);
        // The ACK that completed the send half: the stream may be
        // reclaimable now; the next tick's GC decides.
        if (s.send.isTerminal()) conn.markStreamsGc();
    }
}

pub fn dispatchLostPacketToStreams(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) Error!bool {
    var any = false;
    var refs = packet.streamRefs();
    while (refs.next()) |ref| {
        const s = conn.streams.get(ref.stream_id) orelse continue;
        s.send.onPacketLost(ref.stream_key) catch |e| switch (e) {
            send_stream_mod.Error.UnknownPacket => continue,
            else => return e,
        };
        conn_streams.noteSendable(conn, s);
        any = true;
    }
    return any;
}

pub fn discardSentCryptoForPacket(
    conn: *Connection,
    lvl: EncryptionLevel,
    pn: u64,
) void {
    const idx = lvl.idx();
    var i: usize = 0;
    while (i < conn.sent_crypto[idx].items.len) {
        const chunk = conn.sent_crypto[idx].items[i];
        if (chunk.pn == pn) {
            const removed = conn.sent_crypto[idx].orderedRemove(i);
            conn.allocator.free(removed.data);
            continue;
        }
        i += 1;
    }
}

fn requeueSentCryptoForPacket(
    conn: *Connection,
    lvl: EncryptionLevel,
    pn: u64,
) Error!bool {
    const idx = lvl.idx();
    var any = false;
    var i: usize = 0;
    while (i < conn.sent_crypto[idx].items.len) {
        const chunk = conn.sent_crypto[idx].items[i];
        if (chunk.pn == pn) {
            try conn.crypto_retx[idx].ensureUnusedCapacity(conn.allocator, 1);
            const removed = conn.sent_crypto[idx].orderedRemove(i);
            conn.crypto_retx[idx].appendAssumeCapacity(.{
                .offset = removed.offset,
                .data = removed.data,
            });
            any = true;
            continue;
        }
        i += 1;
    }
    return any;
}

/// RFC 9002 §6.2.4: a probe timeout may send up to two full-sized
/// datagrams, "to avoid an expensive consecutive PTO expiration due to
/// a single lost datagram". A handshake probe here sends the CRYPTO
/// data of the expired packet again, in one packet; this queues that
/// data a second time, so the next packet of the level carries it
/// too, in a datagram of its own (the send path puts one CRYPTO chunk
/// of the queue into each packet, and one packet of a level into each
/// datagram).
///
/// Why: a client whose Initial datagram is lost sends it again after
/// 1 s, then 3 s, 7 s and 15 s (RFC 9002: the first probe timeout is
/// 1 s with no RTT sample, and it doubles), one datagram each time. A
/// quic-go server forgets a half-open connection after 5 s. So the
/// handshake fails when the datagrams at 0, 1 and 3 s are all lost,
/// which 30% loss does often enough (MEASURED 2026-10-04, interop
/// `handshakeloss` and `handshakecorruption`, client role against
/// quic-go: 5 and 2 passes of 10). With two datagrams for each probe,
/// a network that loses up to three datagrams in a row cannot hold
/// the client off past 3 s.
///
/// Only the Initial and Handshake spaces (the level-scoped probe
/// timer runs for those two alone: `tick` fires `fireDuePtoAtLevel`
/// for `.initial` and `.handshake`, and the 1-RTT probe is the path's
/// business), and only while the connection has no RTT sample. With a
/// sample, the probe timeout is
/// the real round trip and the retries are quick; a second datagram
/// would then only double the cues that the peer answers with a copy
/// of its flight (`retransmitHandshakeCryptoEarly` has a limit of 8
/// copies, and MEASURED in tests/e2e/handshake_loss.zig: with the
/// second datagram always, an outage of 100 ms toward the client used
/// up those copies and the handshake waited for the server's probe
/// timeout). The 1-RTT probe is the congestion controller's business,
/// and a PING probe (no CRYPTO data left to send) stays one datagram.
fn queueHandshakeProbeCopy(conn: *Connection, lvl: EncryptionLevel, queued_before: usize) Error!void {
    if (conn.rttForLevelConst(lvl).first_sample_taken) return;
    const idx = lvl.idx();
    const queued_now = conn.crypto_retx[idx].items.len;
    if (queued_now <= queued_before) return;
    try conn.crypto_retx[idx].ensureUnusedCapacity(conn.allocator, queued_now - queued_before);
    var i = queued_before;
    while (i < queued_now) : (i += 1) {
        const chunk = conn.crypto_retx[idx].items[i];
        const copy = try conn.allocator.dupe(u8, chunk.data);
        conn.crypto_retx[idx].appendAssumeCapacity(.{ .offset = chunk.offset, .data = copy });
    }
}

/// True if a packet with this number at `lvl` still owns CRYPTO data
/// that nobody acknowledged.
fn packetOwnsSentCrypto(conn: *const Connection, lvl: EncryptionLevel, pn: u64) bool {
    for (conn.sent_crypto[lvl.idx()].items) |chunk| {
        if (chunk.pn == pn) return true;
    }
    return false;
}

/// How many times one connection sends its unacknowledged handshake
/// CRYPTO data again before the probe timeout. RFC 9002 §6.2.3 allows
/// it "a limited number of times", and says that once recovers from a
/// single loss.
///
/// The number is a bound, not a rate: the retransmissions come at the
/// pace of the peer's own retries, and the peer backs off. It exists
/// for a peer that never stops asking. After the limit the probe
/// timer does the work, as it did before this rule.
///
/// MEASURED 2026-10-03, tests/e2e/handshake_loss.zig: 4000 handshakes,
/// a ClientHello of two packets, 30% of the datagrams toward the
/// client lost and never more than 3 in a row (the interop
/// simulator's rule), a 10 s budget. Limit 0 is this rule off and
/// everything else as it is:
///
///     limit   not done   900 ms or more   90th percentile
///       0        32          1199            1000 ms
///       1         8           612            1000 ms
///       2         4           417            1000 ms
///       3         0           346              10 ms
///     4 to 8      0           346              10 ms
///
/// (The 346 are handshakes where the client had no RTT sample when
/// the flight was lost: its first probe timeout is 1 s whatever the
/// server does.) The gain ends at 3 there because that network never
/// loses a fourth datagram in a row. A real network has outages. The
/// peer's retries come each twice as late as the one before, so 8 of
/// them cover 255 times its first probe timeout: on a path with a
/// 1 ms round trip that is a quarter of a second, and after that our
/// own 1 s probe timer is near. MEASURED the same day: an outage of
/// 100 ms toward the client, handshake done at 134 ms with a limit of
/// 8, and at 1019 ms with a limit of 4.
pub const max_early_handshake_retransmits: u8 = 8;

/// RFC 9002 §6.2.3, "Speeding up handshake completion". The peer just
/// sent an Initial or Handshake packet that asks for an answer and
/// brought no new CRYPTO data: its handshake data again, or a PING.
/// A peer does that when its probe timer ran out, so it does not have
/// our flight. Waiting for our own probe timer costs a second and
/// more, because a flight that nobody acknowledged gives no RTT
/// sample (MEASURED 2026-10-03: a server answered seven such retries
/// with an ACK alone and sent its flight at 0, 1, 3, 7 and 15 s; the
/// client gave up at 10 s).
///
/// So put every unacknowledged CRYPTO byte of the Initial and
/// Handshake spaces back into the retransmission queue now. The
/// packets that carried them leave the tracker: their data now
/// belongs to the packets that will carry it next, and the probe
/// timer starts again from those. This is not a loss (no loss
/// counter, no qlog loss event, no congestion signal) and not a probe
/// timeout (the backoff is untouched: nothing was acknowledged).
///
/// What limits it: the send path's anti-amplification accounting
/// (RFC 9000 §8.1), unchanged; `max_early_handshake_retransmits` per
/// connection; and one retransmission for each received datagram at
/// most, because a second cue finds the data already queued.
pub fn retransmitHandshakeCryptoEarly(conn: *Connection) Error!void {
    if (conn.lifecycle.closed or conn.lifecycle.pending_close != null) return;
    if (conn.early_handshake_retransmits >= max_early_handshake_retransmits) return;
    var any = false;
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
        const space_active = switch (lvl) {
            .initial => !conn.initial_keys_discarded,
            .handshake => !conn.handshake_keys_discarded,
            else => unreachable,
        };
        if (space_active) {
            const sent = conn.sentForLevel(lvl);
            var i: u32 = 0;
            while (i < sent.count) : (i += 1) {
                if (sent.packets[i].dead) continue;
                if (!packetOwnsSentCrypto(conn, lvl, sent.packets[i].pn)) continue;
                var gone = sent.removeAt(i);
                defer gone.deinit(conn.allocator);
                any = (try requeueLostPacket(conn, lvl, &gone)) or any;
            }
        }
    }
    if (any) conn.early_handshake_retransmits += 1;
}

/// The same idea as `retransmitHandshakeCryptoEarly`, one step later
/// in the handshake. A server discards its Handshake keys the moment
/// the handshake completes, so it never acknowledges the client's
/// Finished in a Handshake packet: the client learns that the
/// handshake is confirmed from HANDSHAKE_DONE alone, and sends its
/// Finished again and again until it has it. So a Handshake packet
/// that arrives at a server AFTER the discard says one thing: the
/// client does not have HANDSHAKE_DONE. Queue it again now.
///
/// MEASURED 2026-10-03 (quic-interop-runner `handshakeloss`, quic-go
/// client): the first packet with HANDSHAKE_DONE was lost. The client
/// sent its Finished again at 0.18, 0.36, 0.7, 1.4, 2.8, 5.7, 11, 23
/// and 46 s, and the server (which could not open those packets any
/// more) ignored them. The server had no RTT sample, so its own probe
/// timer sent HANDSHAKE_DONE again at 2, 10 and 43 s only; all three
/// were lost, and the client gave up at 53 s.
///
/// The cue cannot be authenticated (the keys are gone), so it only
/// queues one small frame the client is owed in any case, at most
/// `max_early_handshake_retransmits` times, and never after the
/// client acknowledged a HANDSHAKE_DONE.
pub fn resendHandshakeDoneEarly(conn: *Connection) void {
    if (conn.role != .server or !conn.handshake_keys_discarded) return;
    if (conn.lifecycle.closed or conn.lifecycle.pending_close != null) return;
    if (!conn.handshake_done_queued_once or conn.handshake_done_acked) return;
    if (conn.pending_handshake_done) return;
    if (conn.early_handshake_done_resends >= max_early_handshake_retransmits) return;
    conn.pending_handshake_done = true;
    conn.early_handshake_done_resends += 1;
}

pub fn dispatchAckedControlFrames(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) void {
    for (packet.retransmit_frames.items) |frame| {
        switch (frame) {
            .handshake_done => conn.handshake_done_acked = true,
            .reset_stream => |rs| {
                const s = conn.streams.get(rs.stream_id) orelse continue;
                if (s.send.reset) |r| {
                    if (r.error_code == rs.application_error_code and
                        r.final_size == rs.final_size)
                    {
                        s.send.onResetAcked();
                        conn_streams.noteSendable(conn, s);
                        conn.markStreamsGc();
                    }
                }
            },
            else => {},
        }
    }
}

pub fn dispatchLostControlFramesOnPath(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
    path_id: u32,
) Error!bool {
    var any = false;
    for (packet.retransmit_frames.items) |frame| {
        switch (frame) {
            .max_data => |md| {
                conn_flow.queueMaxData(conn, md.maximum_data);
                any = true;
            },
            .max_stream_data => |msd| {
                try conn_flow.queueMaxStreamData(
                    conn,
                    msd.stream_id,
                    msd.maximum_stream_data,
                );
                any = true;
            },
            .max_streams => |ms| {
                any = conn_flow.requeueLostMaxStreams(conn, ms.bidi, ms.maximum_streams) or any;
            },
            .data_blocked => |db| {
                any = conn_flow.requeueDataBlocked(conn, db.maximum_data) or any;
            },
            .stream_data_blocked => |sdb| {
                any = (try conn_flow.requeueStreamDataBlocked(conn, sdb)) or any;
            },
            .streams_blocked => |sb| {
                any = conn_flow.requeueStreamsBlocked(conn, sb) or any;
            },
            .new_connection_id => |nc| {
                // Only an ID that is still ours is sent again. The peer
                // may have retired it since this packet left (it had
                // the frame from another copy of the packet), and a
                // retired ID is gone from `local_cids`. Queued again,
                // its frame would be a NEW issuance: over the peer's
                // limit (`error.ConnectionIdLimitExceeded` out of loss
                // detection, which ends the connection; found with a
                // quic-go server under 30% loss), or, with room in the
                // limit, a retired ID that comes back to life.
                if (conn_cids.localCidSequenceExists(conn, 0, nc.sequence_number)) {
                    try conn.queueNewConnectionId(
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                }
            },
            .retire_connection_id => |rc| {
                try conn.queueRetireConnectionId(rc.sequence_number);
                any = true;
            },
            .handshake_done => {
                conn.pending_handshake_done = true;
                any = true;
            },
            .ack_frequency => |af| {
                // Only the latest request matters to the peer.
                if (conn.ack_frequency_last) |last| {
                    if (last.sequence_number == af.sequence_number and conn.pending_frames.ack_frequency == null) {
                        conn.pending_frames.ack_frequency = af;
                        conn.touch();
                        any = true;
                    }
                }
            },
            .stop_sending => |ss| {
                try conn_streams.queueStopSending(conn, .{
                    .stream_id = ss.stream_id,
                    .application_error_code = ss.application_error_code,
                });
                any = true;
            },
            .path_response => |pr| {
                if (conn.pending_frames.path_response == null) {
                    conn.queuePathResponseOnPath(path_id, pr.data, null);
                }
                any = true;
            },
            .path_challenge => |pc| {
                if (conn.pending_frames.path_challenge == null and
                    conn_paths.shouldRequeuePathChallenge(conn, path_id, pc.data))
                {
                    conn_paths.queuePathChallengeOnPath(conn, path_id, pc.data);
                    any = true;
                }
            },
            .reset_stream => |rs| {
                const s = conn.streams.get(rs.stream_id) orelse continue;
                if (s.send.reset) |r| {
                    if (r.error_code == rs.application_error_code and
                        r.final_size == rs.final_size)
                    {
                        s.send.onResetLost();
                        conn_streams.noteSendable(conn, s);
                    }
                }
                any = true;
            },
            .path_abandon => |pa| {
                try conn.queuePathAbandon(pa.path_id, pa.error_code);
                any = true;
            },
            .path_status_backup => |ps| {
                try conn.queuePathStatus(ps.path_id, false, ps.sequence_number);
                any = true;
            },
            .path_status_available => |ps| {
                try conn.queuePathStatus(ps.path_id, true, ps.sequence_number);
                any = true;
            },
            .path_new_connection_id => |nc| {
                // As for `.new_connection_id` above.
                if (conn_cids.localCidSequenceExists(conn, nc.path_id, nc.sequence_number)) {
                    try conn.queuePathNewConnectionId(
                        nc.path_id,
                        nc.sequence_number,
                        nc.retire_prior_to,
                        nc.connection_id.slice(),
                        nc.stateless_reset_token,
                    );
                    any = true;
                }
            },
            .path_retire_connection_id => |rc| {
                try conn.queuePathRetireConnectionId(rc.path_id, rc.sequence_number);
                any = true;
            },
            .max_path_id => |mp| {
                conn.queueMaxPathId(mp.maximum_path_id);
                any = true;
            },
            .paths_blocked => |pb| {
                conn.queuePathsBlocked(pb.maximum_path_id);
                any = true;
            },
            .path_cids_blocked => |pcb| {
                conn.queuePathCidsBlocked(pcb.path_id, pcb.next_sequence_number);
                any = true;
            },
            .new_token => |item| {
                // RFC 9000 §13.3 puts NEW_TOKEN on the
                // retransmittable list; if the application
                // hasn't already queued a fresh NEW_TOKEN over
                // the top, restage the bytes from the lost copy.
                if (conn.pending_frames.new_token == null) {
                    var stage: PendingFrameQueues.NewTokenItem = .{};
                    @memcpy(stage.bytes[0..item.len], item.slice());
                    stage.len = item.len;
                    conn.pending_frames.new_token = stage;
                    conn.touch();
                    any = true;
                }
            },
            .alternative_v4_address => |a| {
                // draft-munizaga-quic-alternative-server-address-00
                // §6 ¶5: monotonically-increasing Status Sequence
                // Numbers, but the spec is silent on retransmission.
                // RFC 9000 §13.3 default applies — control frames
                // that aren't redundant on receipt MUST be
                // retransmitted on loss with the same content. The
                // Status Sequence Number stays attached to the
                // semantic update (which IPv4 address, what flags),
                // so the requeued frame keeps its original
                // sequence number.
                try conn.pending_frames.alternative_addresses.append(
                    conn.allocator,
                    .{ .v4 = a },
                );
                conn.touch();
                any = true;
            },
            .alternative_v6_address => |a| {
                try conn.pending_frames.alternative_addresses.append(
                    conn.allocator,
                    .{ .v6 = a },
                );
                conn.touch();
                any = true;
            },
        }
    }
    return any;
}

pub fn requeueLostPacket(
    conn: *Connection,
    lvl: EncryptionLevel,
    packet: *const SentPacketTracker.SentPacket,
) Error!bool {
    return requeueLostPacketOnPath(conn, lvl, packet, conn.activePath().id);
}

fn requeueLostPacketOnPath(
    conn: *Connection,
    lvl: EncryptionLevel,
    packet: *const SentPacketTracker.SentPacket,
    path_id: u32,
) Error!bool {
    conn.touch();
    var any = false;
    conn_datagram.recordDatagramLost(conn, packet);
    if (lvl == .application or lvl == .early_data or packet.is_early_data) {
        any = (try dispatchLostPacketToStreams(conn, packet)) or any;
    }
    any = (try requeueSentCryptoForPacket(conn, lvl, packet.pn)) or any;
    any = (try dispatchLostControlFramesOnPath(conn, packet, path_id)) or any;
    return any;
}

pub fn isPersistentCongestionFromBasePto(base_pto_us: u64, stats: LossStats) bool {
    // RFC 9002 §7.6.1: persistent congestion is determined from
    // ack-eliciting packets only. Both the smallest and largest
    // lost packets in the persistent congestion window MUST be
    // ack-eliciting. A burst of lost PATH_RESPONSE-only or
    // PADDING-only packets, for example, is not enough on its
    // own to collapse cwnd to kMinimumWindow.
    const earliest = stats.earliest_ack_eliciting_lost_sent_time_us orelse return false;
    if (stats.ack_eliciting_count < 2 or
        stats.largest_ack_eliciting_lost_sent_time_us <= earliest)
    {
        return false;
    }
    const duration = stats.largest_ack_eliciting_lost_sent_time_us - earliest;
    const threshold = base_pto_us *
        congestion_mod.persistent_congestion_threshold;
    return duration >= threshold;
}

fn isPersistentCongestion(
    conn: *const Connection,
    lvl: EncryptionLevel,
    stats: LossStats,
) bool {
    return isPersistentCongestionFromBasePto(
        basePtoDurationForLevel(conn, lvl),
        stats,
    );
}

fn onPacketsLostAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    stats: LossStats,
    now_us: u64,
) void {
    if (stats.in_flight_bytes_lost == 0) return;
    if (lvl == .application) {
        const cc = conn.ccForApplication();
        cc.onPacketLost(
            stats.in_flight_bytes_lost,
            stats.largest_lost_sent_time_us,
            now_us,
        );
        if (isPersistentCongestion(conn, lvl, stats)) {
            cc.onPersistentCongestion();
        }
    }
}

fn onApplicationPathPacketsLost(
    conn: *Connection,
    path: *PathState,
    stats: LossStats,
    now_us: u64,
) void {
    if (stats.in_flight_bytes_lost == 0) return;
    path.path.cc.onPacketLost(
        stats.in_flight_bytes_lost,
        stats.largest_lost_sent_time_us,
        now_us,
    );
    if (isPersistentCongestionFromBasePto(
        basePtoDurationForApplicationPath(conn, path),
        stats,
    )) {
        path.path.cc.onPersistentCongestion();
    }
}

/// RFC 8899 DPLPMTUD probe-loss handler. If `lost.pn` matches the
/// in-flight probe on `path`, account it as a probe loss (clears
/// the probe slot, bumps `pmtu_fail_count`, possibly records the
/// upper bound) and return true so the caller skips normal
/// congestion-control processing. RFC 8899 §4.4 explicitly says
/// probe loss MUST NOT trigger CC reactions.
fn pmtudHandleProbeLossIfMatches(
    conn: *Connection,
    path: *PathState,
    lost: *const SentPacketTracker.SentPacket,
) bool {
    const probe_pn = path.pmtu_probe_pn orelse return false;
    if (probe_pn != lost.pn) return false;
    _ = path.pmtudOnProbeLost(
        conn.pmtud_config.probe_threshold,
        conn.pmtud_config.probe_step,
        conn.pmtud_config.max_mtu,
    );
    return true;
}

/// RFC 8899 §4.4 black-hole detection: invoke for every regular
/// (non-probe) packet declared lost on this path. Increments the
/// consecutive-regular-loss counter; at the threshold, halves
/// `pmtu` (down to `initial_mtu`) and re-enters search.
fn pmtudHandleRegularLoss(conn: *Connection, path: *PathState) void {
    if (!conn.pmtud_config.enable) return;
    if (path.pmtu_state == .disabled) return;
    _ = path.pmtudOnRegularLost(
        conn.pmtud_config.probe_threshold,
        conn.pmtud_config.initial_mtu,
    );
}

/// The state one loss sweep operates on, bound by each entry point.
/// The per-level and per-path families are two views of one
/// algorithm over one struct: for `lvl == .application` every level
/// accessor resolves to the primary path's state, and the multipath
/// dispatcher picks between them purely on path id.
const LossTarget = struct {
    sent: *SentPacketTracker,
    pn_space: *state_mod.PnSpace,
    /// Owns the delivery sampler, congestion controller, and RFC 8899
    /// probe state this sweep updates. For Initial / Handshake this is
    /// the primary path: no probes ride those levels, but the counters
    /// stay coherent by consulting it.
    path: *PathState,
    lvl: EncryptionLevel,
    /// Which family this sweep belongs to. Selects the requeue routing
    /// (level requeues to the ACTIVE path's id, per-path to its own)
    /// and the persistent-congestion PTO base (level-wide vs
    /// per-path). Both are deliberate per-family differences, so they
    /// stay dispatched rather than merged.
    scope: enum { level, path },

    fn isApplication(target: LossTarget) bool {
        return target.lvl == .application;
    }
};

/// Which packets a sweep declares lost. RFC 9002 §6.1 specifies
/// packet-threshold and time-threshold as one loop with a two-clause
/// predicate; they are split across entry points here only because
/// they run on different schedules (ACK receipt vs tick).
const LossPredicate = union(enum) {
    /// §6.1.1: `largest_acked - pn >= threshold`, the threshold being
    /// the space's (`ReorderWindow.packet_threshold`: kPacketThreshold
    /// until a spurious loss widens it).
    packet_threshold: struct { largest_acked: u64, threshold: u64 },
    /// §6.1.2: sent before `now - kTimeThreshold`, and at or below
    /// largest_acked (which may be absent, in which case nothing is
    /// eligible).
    time_threshold: struct { largest_acked: ?u64, cutoff: u64 },

    fn matches(self: LossPredicate, p: SentPacketTracker.SentPacket) bool {
        return switch (self) {
            .packet_threshold => |c| p.pn <= c.largest_acked and
                (c.largest_acked - p.pn) >= c.threshold,
            .time_threshold => |c| blk: {
                const la = c.largest_acked orelse break :blk false;
                break :blk p.pn <= la and p.sent_time_us < c.cutoff;
            },
        };
    }

    /// True once `p` is past the eligible range: the tracker is
    /// ordered by packet number and both clauses require
    /// `pn <= largest_acked`, so no later entry can match. Lets the
    /// walk stop at the in-flight tail instead of scanning it.
    fn exhausted(self: LossPredicate, p: SentPacketTracker.SentPacket) bool {
        return switch (self) {
            .packet_threshold => |c| p.pn > c.largest_acked,
            .time_threshold => |c| if (c.largest_acked) |la| p.pn > la else true,
        };
    }

    fn qlogReason(self: LossPredicate) conn_qlog.QlogLossReason {
        return switch (self) {
            .packet_threshold => .packet_threshold,
            .time_threshold => .time_threshold,
        };
    }
};

const SweepCtx = struct {
    conn: *Connection,
    target: LossTarget,
    reason: conn_qlog.QlogLossReason,
    now_us: u64,
    stats: LossStats = .{},

    fn handle(ctx: *SweepCtx, lost: *SentPacketTracker.SentPacket) Error!void {
        defer lost.deinit(ctx.conn.allocator);
        const target = ctx.target;
        conn_qlog.emitPacketLost(ctx.conn, target.lvl, lost.pn, @intCast(lost.bytes), ctx.reason);
        const is_probe = target.isApplication() and
            pmtudHandleProbeLossIfMatches(ctx.conn, target.path, lost);
        // Always requeue stream / control frames so a probe that
        // coalesced legitimate payload still progresses.
        _ = switch (target.scope) {
            .level => try requeueLostPacket(ctx.conn, target.lvl, lost),
            .path => try requeueLostPacketOnPath(ctx.conn, target.lvl, lost, target.path.id),
        };
        if (is_probe) {
            // RFC 8899 §4.4: probe loss MUST NOT trigger CC
            // reactions. Skip the LossStats add so neither cwnd nor
            // persistent-congestion fires for the probe's bytes.
            return;
        }
        ctx.stats.add(lost.*);
        // Delivery-rate sampler C.lost accounting (in-flight
        // application bytes only, DPLPMTUD probes excluded above — the
        // same gate the controller's LossStats ride), then the
        // per-packet loss inlet, BEFORE the aggregate onPacketLost
        // fires after the walk.
        if (target.isApplication()) {
            if (lost.in_flight) {
                const info = target.path.path.delivery.onPacketLost(lost);
                target.path.path.cc.onPacketNewlyLost(&info);
            }
            pmtudHandleRegularLoss(ctx.conn, target.path);
            // A late packet is not a lost packet: remember it, so the
            // ACK that covers it after all is a spurious loss
            // (`recv_ack_handlers`). The episode is stamped after the
            // controller has been told (`noteDeclaredLost`).
            target.sent.reorder.remember(ctx.conn.allocator, lost.pn, lost.sent_time_us);
            ctx.conn.qlog_loss_delay_sum_us +|= ctx.now_us -| lost.sent_time_us;
            ctx.conn.qlog_loss_delays +|= 1;
        }
    }
};

/// After the controller has been told about a sweep's losses: count
/// them in its loss episode and stamp their records with it, so the
/// ACK of one of them can take the episode's reaction back.
fn noteDeclaredLost(target: LossTarget, count: u32) void {
    if (!target.isApplication() or count == 0) return;
    const cc = &target.path.path.cc;
    cc.noteDeclaredLost(count);
    target.sent.reorder.stampLast(count, cc.lossEpisode());
}

/// The one loss-detection sweep: walk the tracker, remove contiguous
/// runs of packets the predicate declares lost, and fold the results
/// into PMTUD / delivery-rate / congestion state.
///
/// Runs are removed as spans rather than per packet, and the walk
/// re-enters at `start` afterwards — which is why tombstones must be
/// skipped explicitly, or a dead entry would re-match forever.
fn sweepLosses(
    conn: *Connection,
    target: LossTarget,
    pred: LossPredicate,
    now_us: u64,
) Error!void {
    var ctx: SweepCtx = .{
        .conn = conn,
        .target = target,
        .reason = pred.qlogReason(),
        .now_us = now_us,
    };

    var i: u32 = 0;
    while (i < target.sent.count) {
        if (target.sent.packets[i].dead) {
            i += 1;
            continue;
        }
        if (pred.exhausted(target.sent.packets[i])) break;
        if (pred.matches(target.sent.packets[i])) {
            const start = i;
            i += 1;
            while (i < target.sent.count) : (i += 1) {
                if (!pred.matches(target.sent.packets[i])) break;
            }
            try target.sent.removeRangeWithError(start, i, &ctx, SweepCtx.handle);
            i = start;
            continue;
        }
        i += 1;
    }

    conn.qlog_packets_lost +|= ctx.stats.count;
    conn_qlog.emitLossDetected(conn, target.lvl, ctx.stats, ctx.reason);
    switch (target.scope) {
        .level => onPacketsLostAtLevel(conn, target.lvl, ctx.stats, now_us),
        .path => onApplicationPathPacketsLost(conn, target.path, ctx.stats, now_us),
    }
    noteDeclaredLost(target, ctx.stats.count);
    conn_qlog.emitCongestionStateIfChanged(conn, now_us);
}

fn levelTarget(conn: *Connection, lvl: EncryptionLevel) LossTarget {
    return .{
        .sent = conn.sentForLevel(lvl),
        .pn_space = conn.pnSpaceForLevel(lvl),
        .path = conn.primaryPath(),
        .lvl = lvl,
        .scope = .level,
    };
}

fn pathTarget(path: *PathState) LossTarget {
    return .{
        .sent = &path.sent,
        .pn_space = &path.app_pn_space,
        .path = path,
        .lvl = .application,
        .scope = .path,
    };
}

pub fn detectLossesByPacketThresholdAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!void {
    const target = levelTarget(conn, lvl);
    const largest_acked = target.pn_space.largest_acked_sent orelse return;
    try sweepLosses(conn, target, .{ .packet_threshold = .{
        .largest_acked = largest_acked,
        .threshold = target.sent.reorder.packet_threshold,
    } }, now_us);
}

pub fn detectLossesByPacketThresholdOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!void {
    const target = pathTarget(path);
    const largest_acked = target.pn_space.largest_acked_sent orelse return;
    try sweepLosses(conn, target, .{ .packet_threshold = .{
        .largest_acked = largest_acked,
        .threshold = target.sent.reorder.packet_threshold,
    } }, now_us);
}

pub fn detectLossesByTimeThresholdAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!void {
    const target = levelTarget(conn, lvl);
    const time_threshold = target.sent.reorder.timeThresholdUs(conn.rttForLevelConst(lvl));
    if (now_us <= time_threshold) return;
    try sweepLosses(conn, target, .{ .time_threshold = .{
        .largest_acked = target.pn_space.largest_acked_sent,
        .cutoff = now_us - time_threshold,
    } }, now_us);
}

pub fn detectLossesByTimeThresholdOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!void {
    const target = pathTarget(path);
    const time_threshold = target.sent.reorder.timeThresholdUs(&path.path.rtt);
    if (now_us <= time_threshold) return;
    try sweepLosses(conn, target, .{ .time_threshold = .{
        .largest_acked = target.pn_space.largest_acked_sent,
        .cutoff = now_us - time_threshold,
    } }, now_us);
}

/// Expire the oldest live ack-eliciting packet on `target` as a PTO
/// probe loss. Returns true if one was found (and consumed), false if
/// the tracker held nothing eligible.
///
/// Shares the emit / probe-gate / requeue / delivery-inlet /
/// emitLossDetected / onPacketsLost spine with `sweepLosses`, but is
/// deliberately its own function: it removes a SINGLE packet via
/// removeAt rather than a span, and drives no PMTUD black-hole
/// accounting. The pending_ping / pto_count bookkeeping stays in the
/// two callers, which is where the families legitimately differ.
const PtoOutcome = union(enum) {
    /// The tracker held no live ack-eliciting packet — nothing fired,
    /// and the caller must not touch its PTO bookkeeping.
    nothing_eligible,
    /// The expired packet was a DPLPMTUD probe: no ping is armed and
    /// no CC / loss accounting ran (RFC 8899 §4.4).
    probe,
    /// A regular packet expired; `requeued` says whether its frames
    /// went back into a queue (if not, the caller arms a PING so the
    /// probe still elicits an ACK).
    regular: struct { requeued: bool },
};

fn firePtoOn(conn: *Connection, target: LossTarget, now_us: u64) Error!PtoOutcome {
    var i: u32 = 0;
    while (i < target.sent.count) : (i += 1) {
        const p = target.sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;

        var lost = target.sent.removeAt(i);
        defer lost.deinit(conn.allocator);
        conn_qlog.emitPacketLost(conn, target.lvl, lost.pn, @intCast(lost.bytes), .pto_probe);
        // RFC 8899 §4.4: a probe expired by PTO counts as a probe
        // loss, NOT a regular loss; CC stays unaffected. The requeue
        // path still runs so coalesced control / stream frames go back
        // into the queue.
        const is_probe = target.isApplication() and
            pmtudHandleProbeLossIfMatches(conn, target.path, &lost);
        const requeued = switch (target.scope) {
            .level => blk: {
                const queued_before = conn.crypto_retx[target.lvl.idx()].items.len;
                const r = try requeueLostPacket(conn, target.lvl, &lost);
                try queueHandshakeProbeCopy(conn, target.lvl, queued_before);
                break :blk r;
            },
            .path => try requeueLostPacketOnPath(conn, target.lvl, &lost, target.path.id),
        };
        if (is_probe) return .probe;

        var stats: LossStats = .{};
        stats.add(lost);
        // Delivery-rate sampler C.lost: PTO-expired packets are real
        // losses to the estimator too (probe losses returned above).
        if (target.isApplication()) {
            if (lost.in_flight) {
                const info = target.path.path.delivery.onPacketLost(&lost);
                target.path.path.cc.onPacketNewlyLost(&info);
            }
            // An expired packet that is acknowledged after all is a
            // spurious loss like any other (see `SweepCtx.handle`).
            target.sent.reorder.remember(conn.allocator, lost.pn, lost.sent_time_us);
            conn.qlog_loss_delay_sum_us +|= now_us -| lost.sent_time_us;
            conn.qlog_loss_delays +|= 1;
        }
        conn.qlog_packets_lost +|= stats.count;
        conn_qlog.emitLossDetected(conn, target.lvl, stats, .pto_probe);
        switch (target.scope) {
            .level => onPacketsLostAtLevel(conn, target.lvl, stats, now_us),
            .path => onApplicationPathPacketsLost(conn, target.path, stats, now_us),
        }
        noteDeclaredLost(target, stats.count);
        return .{ .regular = .{ .requeued = requeued } };
    }
    return .nothing_eligible;
}

fn firePtoAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!bool {
    switch (try firePtoOn(conn, levelTarget(conn, lvl), now_us)) {
        .nothing_eligible => {
            // The client's anti-deadlock probe (see
            // `antiDeadlockLevel`): nothing to send again, so a PING.
            // The timer starts again from now, and the backoff below
            // doubles it, so a server that takes long is not flooded.
            if (antiDeadlockLevel(conn) != lvl) return false;
            conn.pendingPingForLevel(lvl).* = true;
            conn.handshake_probe_anchor_us = now_us;
        },
        .probe => conn.pendingPingForLevel(lvl).* = false,
        .regular => |r| conn.pendingPingForLevel(lvl).* = !r.requeued,
    }
    conn.ptoCountForLevel(lvl).* +|= 1;
    // The probe does NOT say again what has arrived in this space (it
    // does not set `received.pending_ack`). An ACK goes out once, when
    // the peer's packet comes, and it looks like a gain to repeat it
    // with every probe: a peer whose copy was lost learns what we
    // have. TRIED 2026-10-03 (05c72b4) AND TAKEN BACK.
    //
    // For the peer whose copy was lost, the repeat is the FIRST
    // acknowledgement of its packet, and it takes a round-trip sample
    // from it. RFC 9002 §5.3 does not subtract the ACK delay from a
    // first sample, however true the delay we report.
    //
    // MEASURED (interop `handshakecorruption`, a quiche client, 30% of
    // the datagrams lost each way): a client whose first flight from
    // us was lost got the ACK of its ClientHello 1 s late, with the
    // flight that this probe timeout sent again. Its smoothed round
    // trip went from the 333 ms default to 1048 ms on a 38 ms path
    // (922 ms after the next sample), its probe timer to 3.5 s, and
    // its close took 10.5 s. The quiche log had `srtt` above 1 s on
    // 71 lines of one run, and on none without the repeat. The time
    // after the client's handshake, summed over a run: 243 s and
    // 120 s with the repeat; 59 s, 59 s and 94 s without. 1 run of 4
    // passed; 9 of 10 without.
    //
    // TRIED AGAIN 2026-10-04 FOR THE HANDSHAKE SPACE ALONE, AND NOT
    // SHIPPED (the change above with `lvl == .handshake`, and the
    // Handshake ACK owed again for a 1-RTT packet that arrives before
    // its keys). The idea: a peer that sends Handshake packets has a
    // sample from the Initial space. It has none when the datagram
    // with our one Initial ACK was lost; the copy of the flight that
    // it gets then has no ACK in it.
    //
    // MEASURED (interop `handshakeloss`, a quiche client, run 3 of 9):
    // the client got our flight 2 s late, with no ACK. Its Finished
    // was lost twice. Its Handshake PING arrived, and our ACK for it
    // was lost. 2.1 s later its 1-RTT packets came, and we said the
    // Handshake ACK again, with the true delay in it (2.10 s). It did
    // what it was built for: the client sent its Finished again at
    // once and had HANDSHAKE_DONE 35 ms later. It was also the
    // client's first sample: 2.137 s on a 30 ms path. Its probe timer
    // went to 6.4 s, 12.9 s and 25.7 s, its request was lost twice
    // more, and the connection timed out after 42.6 s with no file.
    //
    // So: a repeat is safe only for a peer that is KNOWN to have a
    // sample. That is a peer that has acknowledged a packet of ours
    // which carried an ACK frame for an ack-eliciting packet of its
    // own. Nothing here keeps that fact yet.
    return true;
}

/// The probe timeout of the Application space. RFC 9002 section
/// 6.2.4: "A PTO timer expiration event does not indicate packet loss
/// and MUST NOT cause prior unacknowledged packets to be marked as
/// lost." So nothing is declared lost here, the controller is not
/// told, and the oldest ack-eliciting packet STAYS in flight: the
/// probe carries its retransmittable frames again (the section's
/// "previously sent data"; a PING when it has none), and when the
/// probe's ACK comes the packet and time thresholds find what was
/// lost, which is where a reduction belongs. Until 0.30.0 the expiry
/// took the oldest packet out as lost and cut the window (NewReno and
/// CUBIC by 0.5 / 0.7, BBR into recovery with a loss event): a second
/// reaction for a real loss, a reaction for nothing when the ACK was
/// only late.
///
/// DATAGRAM frames are deliberately NOT sent again by the probe (never
/// sent again; their loss is the thresholds' finding, and the
/// application's hook hears of it then). A DPLPMTUD probe packet has
/// nothing to send again either (PADDING and a PING), so a PING goes
/// out, and its size verdict (RFC 8899 section 4.4) comes from the
/// thresholds when a later ACK shows it missing. The frames that are
/// copied leave their packet's record
/// alone: a stream chunk sent again gets a new key, so the old
/// packet's ACK or loss later finds nothing for it (`UnknownPacket`,
/// skipped), CRYPTO data moves to the retransmit queue once, and a
/// control frame queued twice carries the same current value. The
/// next probe, then, finds the oldest packet's data gone and walks on
/// to the oldest packet that still owns stream or CRYPTO data (the
/// copy, as a rule): every probe to a silent peer carries data.
///
/// The one exception is a full tracker: a probe needs a slot, and
/// nothing frees one while the peer is silent, so the old expiry
/// stays for that case alone (`firePtoOn`), as the escape the send
/// path's gate relies on.
fn firePtoOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!bool {
    if (path.sent.isFull()) {
        switch (try firePtoOn(conn, pathTarget(path), now_us)) {
            .nothing_eligible => return false,
            .probe => path.pending_ping = false,
            .regular => |r| {
                path.pending_ping = !r.requeued;
                if (r.requeued and path.pto_probe_count < 2) path.pto_probe_count += 1;
            },
        }
        path.pto_count +|= 1;
        return true;
    }

    var requeued = false;
    var found = false;
    var i: u32 = 0;
    while (i < path.sent.count) : (i += 1) {
        const p = &path.sent.packets[i];
        if (p.dead or !p.ack_eliciting) continue;
        if (!found) {
            found = true;
            const r = try requeueFramesForProbe(conn, p, path.id);
            requeued = r.any;
            if (r.data) break;
            continue;
        }
        // The oldest packet owns no data any more: its stream chunks
        // and CRYPTO bytes moved to a copy with an earlier probe (the
        // key goes with the copy), and it keeps control frames at
        // most. The probe still carries previously sent data, from
        // the oldest packet that owns some (the copy, as a rule).
        // Without this walk the second and every later probe to a
        // silent peer carried the control frames alone, or a PING:
        // found 2026-10-08 in the handshake-corruption interop cell
        // (a quic-go server, 30% of the bytes corrupted): the
        // request's packet and the first probe's copy lost, every
        // ACK the server sent corrupted, and one NEW_CONNECTION_ID
        // went out per probe for 30 s, until the idle timeout.
        if (try requeueDataForProbe(conn, p)) {
            requeued = true;
            break;
        }
    }
    if (!found) return false;
    path.pending_ping = !requeued;
    // Per-path only: a bounded probe counter feeding the multipath send
    // scheduler and the congestion gate's probe exemption (RFC 9002
    // section 7.5: a probe is not blocked by the controller; it is
    // counted as in flight on top).
    if (requeued and path.pto_probe_count < 2) path.pto_probe_count += 1;
    path.pto_count +|= 1;
    return true;
}

const ProbeRequeue = struct {
    /// Anything went into a queue again.
    any: bool,
    /// Stream chunks or CRYPTO bytes did ("previously sent data").
    data: bool,
};

/// The retransmittable frames of `packet` go into their queues again,
/// for a probe; the packet stays as it is. See
/// `firePtoOnApplicationPath` for what is left out and why the record
/// may stay.
fn requeueFramesForProbe(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
    path_id: u32,
) Error!ProbeRequeue {
    conn.touch();
    const data = try requeueDataForProbe(conn, packet);
    const control = try dispatchLostControlFramesOnPath(conn, packet, path_id);
    return .{ .any = data or control, .data = data };
}

/// The stream chunks and CRYPTO bytes `packet` still owns go again;
/// its control frames stay where they are. `true` when it owned any.
fn requeueDataForProbe(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) Error!bool {
    var any = false;
    any = (try dispatchLostPacketToStreams(conn, packet)) or any;
    any = (try requeueSentCryptoForPacket(conn, .application, packet.pn)) or any;
    return any;
}

pub fn fireDuePtoAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!void {
    const deadline = ptoDeadlineForLevel(conn, lvl) orelse return;
    if (now_us < deadline) return;
    conn.touch();
    _ = try firePtoAtLevel(conn, lvl, now_us);
}

pub fn fireDuePtoOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!void {
    const deadline = ptoDeadlineForApplicationPath(conn, path) orelse return;
    if (now_us < deadline) return;
    conn.touch();
    _ = try firePtoOnApplicationPath(conn, path, now_us);
}
