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

pub fn ptoDurationForLevel(conn: *const Connection, lvl: EncryptionLevel) u64 {
    return backoffDuration(basePtoDurationForLevel(conn, lvl), conn.ptoCountForLevelConst(lvl).*);
}

fn basePtoDurationForApplicationPath(conn: *const Connection, path: *const PathState) u64 {
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

pub fn lossDeadlineForLevel(conn: *const Connection, lvl: EncryptionLevel) ?u64 {
    const pn_space = conn.pnSpaceForLevelConst(lvl);
    const sent = conn.sentForLevelConst(lvl);
    const rtt = conn.rttForLevelConst(lvl);
    const largest_acked = pn_space.largest_acked_sent orelse return null;
    const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
    const time_threshold = @max(
        reference_rtt * loss_recovery_mod.time_threshold_num /
            loss_recovery_mod.time_threshold_den,
        RttEstimator.granularity_us,
    );

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

pub fn lossDeadlineForApplicationPath(conn: *const Connection, path: *const PathState) ?u64 {
    _ = conn;
    const largest_acked = path.app_pn_space.largest_acked_sent orelse return null;
    const reference_rtt = @max(path.path.rtt.latest_rtt_us, path.path.rtt.smoothed_rtt_us);
    const time_threshold = @max(
        reference_rtt * loss_recovery_mod.time_threshold_num /
            loss_recovery_mod.time_threshold_den,
        RttEstimator.granularity_us,
    );

    var best: ?u64 = null;
    var i: u32 = 0;
    while (i < path.sent.count) : (i += 1) {
        const p = path.sent.packets[i];
        if (p.dead) continue;
        if (p.pn > largest_acked) continue;
        const at_us = p.sent_time_us +| time_threshold;
        if (best == null or at_us < best.?) best = at_us;
    }
    return best;
}

pub fn ptoDeadlineForLevel(conn: *const Connection, lvl: EncryptionLevel) ?u64 {
    const sent = conn.sentForLevelConst(lvl);
    var oldest: ?u64 = null;
    var i: u32 = 0;
    while (i < sent.count) : (i += 1) {
        const p = sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;
        if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
    }
    const sent_at = oldest orelse return null;
    return sent_at +| ptoDurationForLevel(conn, lvl);
}

pub fn ptoDeadlineForApplicationPath(conn: *const Connection, path: *const PathState) ?u64 {
    var oldest: ?u64 = null;
    var i: u32 = 0;
    while (i < path.sent.count) : (i += 1) {
        const p = path.sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;
        if (oldest == null or p.sent_time_us < oldest.?) oldest = p.sent_time_us;
    }
    const sent_at = oldest orelse return null;
    return sent_at +| ptoDurationForApplicationPath(conn, path);
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
        const before = s.send.bytes.items.len;
        s.send.onPacketAcked(ref.stream_key) catch |e| switch (e) {
            send_stream_mod.Error.UnknownPacket => continue,
            else => return e,
        };
        const after = s.send.bytes.items.len;
        if (after < before) conn.releaseResidentBytes(before - after);
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

pub fn dispatchAckedControlFrames(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
) void {
    for (packet.retransmit_frames.items) |frame| {
        switch (frame) {
            .reset_stream => |rs| {
                const s = conn.streams.get(rs.stream_id) orelse continue;
                if (s.send.reset) |r| {
                    if (r.error_code == rs.application_error_code and
                        r.final_size == rs.final_size)
                    {
                        s.send.onResetAcked();
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
                conn.queueMaxStreams(ms.bidi, ms.maximum_streams);
                any = true;
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
                try conn.queueNewConnectionId(
                    nc.sequence_number,
                    nc.retire_prior_to,
                    nc.connection_id.slice(),
                    nc.stateless_reset_token,
                );
                any = true;
            },
            .retire_connection_id => |rc| {
                try conn.queueRetireConnectionId(rc.sequence_number);
                any = true;
            },
            .handshake_done => {
                conn.pending_handshake_done = true;
                any = true;
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
                try conn.queuePathNewConnectionId(
                    nc.path_id,
                    nc.sequence_number,
                    nc.retire_prior_to,
                    nc.connection_id.slice(),
                    nc.stateless_reset_token,
                );
                any = true;
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
                any = true;
            },
            .alternative_v6_address => |a| {
                try conn.pending_frames.alternative_addresses.append(
                    conn.allocator,
                    .{ .v6 = a },
                );
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
) void {
    if (stats.in_flight_bytes_lost == 0) return;
    if (lvl == .application) {
        const cc = conn.ccForApplication();
        cc.onPacketLost(
            stats.in_flight_bytes_lost,
            stats.largest_lost_sent_time_us,
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
) void {
    if (stats.in_flight_bytes_lost == 0) return;
    path.path.cc.onPacketLost(
        stats.in_flight_bytes_lost,
        stats.largest_lost_sent_time_us,
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
    _ = path.pmtudOnProbeLost(conn.pmtud_config.probe_threshold);
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

pub fn detectLossesByPacketThresholdAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
) Error!void {
    const pn_space = conn.pnSpaceForLevel(lvl);
    const sent = conn.sentForLevel(lvl);
    const largest_acked_opt = pn_space.largest_acked_sent;
    if (largest_acked_opt == null) return;
    const largest_acked = largest_acked_opt.?;
    const threshold: u64 = loss_recovery_mod.packet_threshold;
    // 1-RTT in-flight bookkeeping is owned by the primary path
    // until the multipath split (per `sentForLevel`). RFC 8899
    // probes only ride .application, so we only consult the
    // probe state when this is the application level.
    const path: *PathState = conn.primaryPath();

    var i: u32 = 0;
    var stats: LossStats = .{};
    const PacketThresholdCtx = struct {
        conn: *Connection,
        lvl: EncryptionLevel,
        path: *PathState,
        stats: *LossStats,

        fn handle(ctx: *@This(), lost: *SentPacketTracker.SentPacket) Error!void {
            defer lost.deinit(ctx.conn.allocator);
            conn_qlog.emitPacketLost(ctx.conn, ctx.lvl, lost.pn, @intCast(lost.bytes), .packet_threshold);
            const is_probe = ctx.lvl == .application and
                pmtudHandleProbeLossIfMatches(ctx.conn, ctx.path, lost);
            // Always requeue stream / control frames so a probe
            // that coalesced legitimate payload still progresses.
            _ = try requeueLostPacket(ctx.conn, ctx.lvl, lost);
            if (is_probe) {
                // RFC 8899 §4.4: probe loss MUST NOT trigger CC
                // reactions. Skip the LossStats add so neither
                // cwnd nor persistent-congestion fires for the
                // probe's bytes.
                return;
            }
            ctx.stats.add(lost.*);
            // Delivery-rate sampler C.lost accounting (in-flight
            // application bytes only, DPLPMTUD probes excluded above
            // — the same gate the controller's LossStats ride), then
            // the per-packet loss inlet, BEFORE the aggregate
            // onPacketLost fires after the walk.
            if (ctx.lvl == .application and lost.in_flight) {
                const info = ctx.path.path.delivery.onPacketLost(lost);
                ctx.path.path.cc.onPacketNewlyLost(&info);
            }
            if (ctx.lvl == .application) pmtudHandleRegularLoss(ctx.conn, ctx.path);
        }
    };
    var ctx: PacketThresholdCtx = .{
        .conn = conn,
        .lvl = lvl,
        .path = path,
        .stats = &stats,
    };
    while (i < sent.count) {
        const p = sent.packets[i];
        // Skip tombstones — a dead entry re-matching after the
        // `i = start` re-entry below would loop forever.
        if (p.dead) {
            i += 1;
            continue;
        }
        if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
            const start = i;
            i += 1;
            while (i < sent.count) : (i += 1) {
                const next = sent.packets[i];
                if (next.pn > largest_acked or (largest_acked - next.pn) < threshold) break;
            }
            try sent.removeRangeWithError(start, i, &ctx, PacketThresholdCtx.handle);
            i = start;
            continue;
        }
        i += 1;
    }
    conn.qlog_packets_lost +|= stats.count;
    conn_qlog.emitLossDetected(conn, lvl, stats, .packet_threshold);
    onPacketsLostAtLevel(conn, lvl, stats);
    conn_qlog.emitCongestionStateIfChanged(conn, 0);
}

pub fn detectLossesByPacketThresholdOnApplicationPath(
    conn: *Connection,
    path: *PathState,
) Error!void {
    const largest_acked_opt = path.app_pn_space.largest_acked_sent;
    if (largest_acked_opt == null) return;
    const largest_acked = largest_acked_opt.?;
    const threshold: u64 = loss_recovery_mod.packet_threshold;

    var i: u32 = 0;
    var stats: LossStats = .{};
    const PathPacketThresholdCtx = struct {
        conn: *Connection,
        path: *PathState,
        stats: *LossStats,

        fn handle(ctx: *@This(), lost: *SentPacketTracker.SentPacket) Error!void {
            defer lost.deinit(ctx.conn.allocator);
            conn_qlog.emitPacketLost(ctx.conn, .application, lost.pn, @intCast(lost.bytes), .packet_threshold);
            const is_probe = pmtudHandleProbeLossIfMatches(ctx.conn, ctx.path, lost);
            _ = try requeueLostPacketOnPath(ctx.conn, .application, lost, ctx.path.id);
            if (is_probe) return;
            ctx.stats.add(lost.*);
            // Delivery-rate sampler C.lost + per-packet inlet, per-path twin.
            if (lost.in_flight) {
                const info = ctx.path.path.delivery.onPacketLost(lost);
                ctx.path.path.cc.onPacketNewlyLost(&info);
            }
            pmtudHandleRegularLoss(ctx.conn, ctx.path);
        }
    };
    var ctx: PathPacketThresholdCtx = .{
        .conn = conn,
        .path = path,
        .stats = &stats,
    };
    while (i < path.sent.count) {
        const p = path.sent.packets[i];
        // Skip tombstones — see detectLossesByPacketThresholdAtLevel.
        if (p.dead) {
            i += 1;
            continue;
        }
        if (p.pn <= largest_acked and (largest_acked - p.pn) >= threshold) {
            const start = i;
            i += 1;
            while (i < path.sent.count) : (i += 1) {
                const next = path.sent.packets[i];
                if (next.pn > largest_acked or (largest_acked - next.pn) < threshold) break;
            }
            try path.sent.removeRangeWithError(start, i, &ctx, PathPacketThresholdCtx.handle);
            i = start;
            continue;
        }
        i += 1;
    }
    conn.qlog_packets_lost +|= stats.count;
    conn_qlog.emitLossDetected(conn, .application, stats, .packet_threshold);
    onApplicationPathPacketsLost(conn, path, stats);
    conn_qlog.emitCongestionStateIfChanged(conn, 0);
}

pub fn detectLossesByTimeThresholdAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!void {
    const rtt = conn.rttForLevelConst(lvl);
    const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
    const time_threshold = @max(
        reference_rtt * loss_recovery_mod.time_threshold_num /
            loss_recovery_mod.time_threshold_den,
        RttEstimator.granularity_us,
    );
    if (now_us <= time_threshold) return;
    const cutoff = now_us - time_threshold;
    const pn_space = conn.pnSpaceForLevel(lvl);
    const sent = conn.sentForLevel(lvl);
    const largest_acked_opt = pn_space.largest_acked_sent;
    const path: *PathState = conn.primaryPath();

    var i: u32 = 0;
    var stats: LossStats = .{};
    const TimeThresholdCtx = struct {
        conn: *Connection,
        lvl: EncryptionLevel,
        path: *PathState,
        stats: *LossStats,

        fn handle(ctx: *@This(), lost: *SentPacketTracker.SentPacket) Error!void {
            defer lost.deinit(ctx.conn.allocator);
            conn_qlog.emitPacketLost(ctx.conn, ctx.lvl, lost.pn, @intCast(lost.bytes), .time_threshold);
            const is_probe = ctx.lvl == .application and
                pmtudHandleProbeLossIfMatches(ctx.conn, ctx.path, lost);
            _ = try requeueLostPacket(ctx.conn, ctx.lvl, lost);
            if (is_probe) return;
            ctx.stats.add(lost.*);
            // Delivery-rate sampler C.lost accounting (in-flight
            // application bytes only, DPLPMTUD probes excluded above
            // — the same gate the controller's LossStats ride), then
            // the per-packet loss inlet, BEFORE the aggregate
            // onPacketLost fires after the walk.
            if (ctx.lvl == .application and lost.in_flight) {
                const info = ctx.path.path.delivery.onPacketLost(lost);
                ctx.path.path.cc.onPacketNewlyLost(&info);
            }
            if (ctx.lvl == .application) pmtudHandleRegularLoss(ctx.conn, ctx.path);
        }
    };
    var ctx: TimeThresholdCtx = .{
        .conn = conn,
        .lvl = lvl,
        .path = path,
        .stats = &stats,
    };
    while (i < sent.count) {
        const p = sent.packets[i];
        // Skip tombstones — see detectLossesByPacketThresholdAtLevel.
        if (p.dead) {
            i += 1;
            continue;
        }
        const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
        if (eligible and p.sent_time_us < cutoff) {
            const start = i;
            i += 1;
            while (i < sent.count) : (i += 1) {
                const next = sent.packets[i];
                const next_eligible = if (largest_acked_opt) |la| next.pn <= la else false;
                if (!next_eligible or next.sent_time_us >= cutoff) break;
            }
            try sent.removeRangeWithError(start, i, &ctx, TimeThresholdCtx.handle);
            i = start;
            continue;
        }
        i += 1;
    }
    conn.qlog_packets_lost +|= stats.count;
    conn_qlog.emitLossDetected(conn, lvl, stats, .time_threshold);
    onPacketsLostAtLevel(conn, lvl, stats);
    conn_qlog.emitCongestionStateIfChanged(conn, now_us);
}

pub fn detectLossesByTimeThresholdOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!void {
    const rtt = &path.path.rtt;
    const reference_rtt = @max(rtt.latest_rtt_us, rtt.smoothed_rtt_us);
    const time_threshold = @max(
        reference_rtt * loss_recovery_mod.time_threshold_num /
            loss_recovery_mod.time_threshold_den,
        RttEstimator.granularity_us,
    );
    if (now_us <= time_threshold) return;
    const cutoff = now_us - time_threshold;
    const largest_acked_opt = path.app_pn_space.largest_acked_sent;

    var i: u32 = 0;
    var stats: LossStats = .{};
    const PathTimeThresholdCtx = struct {
        conn: *Connection,
        path: *PathState,
        stats: *LossStats,

        fn handle(ctx: *@This(), lost: *SentPacketTracker.SentPacket) Error!void {
            defer lost.deinit(ctx.conn.allocator);
            conn_qlog.emitPacketLost(ctx.conn, .application, lost.pn, @intCast(lost.bytes), .time_threshold);
            const is_probe = pmtudHandleProbeLossIfMatches(ctx.conn, ctx.path, lost);
            _ = try requeueLostPacketOnPath(ctx.conn, .application, lost, ctx.path.id);
            if (is_probe) return;
            ctx.stats.add(lost.*);
            // Delivery-rate sampler C.lost + per-packet inlet, per-path twin.
            if (lost.in_flight) {
                const info = ctx.path.path.delivery.onPacketLost(lost);
                ctx.path.path.cc.onPacketNewlyLost(&info);
            }
            pmtudHandleRegularLoss(ctx.conn, ctx.path);
        }
    };
    var ctx: PathTimeThresholdCtx = .{
        .conn = conn,
        .path = path,
        .stats = &stats,
    };
    while (i < path.sent.count) {
        const p = path.sent.packets[i];
        // Skip tombstones — see detectLossesByPacketThresholdAtLevel.
        if (p.dead) {
            i += 1;
            continue;
        }
        const eligible = if (largest_acked_opt) |la| p.pn <= la else false;
        if (eligible and p.sent_time_us < cutoff) {
            const start = i;
            i += 1;
            while (i < path.sent.count) : (i += 1) {
                const next = path.sent.packets[i];
                const next_eligible = if (largest_acked_opt) |la| next.pn <= la else false;
                if (!next_eligible or next.sent_time_us >= cutoff) break;
            }
            try path.sent.removeRangeWithError(start, i, &ctx, PathTimeThresholdCtx.handle);
            i = start;
            continue;
        }
        i += 1;
    }
    conn.qlog_packets_lost +|= stats.count;
    conn_qlog.emitLossDetected(conn, .application, stats, .time_threshold);
    onApplicationPathPacketsLost(conn, path, stats);
    conn_qlog.emitCongestionStateIfChanged(conn, now_us);
}

fn firePtoAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
) Error!bool {
    const sent = conn.sentForLevel(lvl);
    const path: *PathState = conn.primaryPath();
    var i: u32 = 0;
    while (i < sent.count) : (i += 1) {
        const p = sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;

        var lost = sent.removeAt(i);
        defer lost.deinit(conn.allocator);
        conn_qlog.emitPacketLost(conn, lvl, lost.pn, @intCast(lost.bytes), .pto_probe);
        // RFC 8899 §4.4: a probe expired by PTO counts as a probe
        // loss, NOT a regular loss; CC stays unaffected. The
        // requeue path still runs so coalesced control / stream
        // frames go back into the queue.
        const is_probe = lvl == .application and
            pmtudHandleProbeLossIfMatches(conn, path, &lost);
        const requeued = try requeueLostPacket(conn, lvl, &lost);
        if (is_probe) {
            conn.pendingPingForLevel(lvl).* = false;
            conn.ptoCountForLevel(lvl).* +|= 1;
            return true;
        }
        var stats: LossStats = .{};
        stats.add(lost);
        // Delivery-rate sampler C.lost: PTO-expired packets are real
        // losses to the estimator too (probe losses returned above).
        if (lvl == .application and lost.in_flight) {
            const info = path.path.delivery.onPacketLost(&lost);
            path.path.cc.onPacketNewlyLost(&info);
        }
        conn.qlog_packets_lost +|= stats.count;
        conn_qlog.emitLossDetected(conn, lvl, stats, .pto_probe);
        onPacketsLostAtLevel(conn, lvl, stats);

        conn.pendingPingForLevel(lvl).* = !requeued;
        conn.ptoCountForLevel(lvl).* +|= 1;
        return true;
    }
    return false;
}

fn firePtoOnApplicationPath(
    conn: *Connection,
    path: *PathState,
) Error!bool {
    var i: u32 = 0;
    while (i < path.sent.count) : (i += 1) {
        const p = path.sent.packets[i];
        if (p.dead) continue;
        if (!p.ack_eliciting) continue;

        var lost = path.sent.removeAt(i);
        defer lost.deinit(conn.allocator);
        conn_qlog.emitPacketLost(conn, .application, lost.pn, @intCast(lost.bytes), .pto_probe);
        const is_probe = pmtudHandleProbeLossIfMatches(conn, path, &lost);
        const requeued = try requeueLostPacketOnPath(conn, .application, &lost, path.id);
        if (is_probe) {
            path.pending_ping = false;
            path.pto_count +|= 1;
            return true;
        }
        var stats: LossStats = .{};
        stats.add(lost);
        // Delivery-rate sampler C.lost + per-packet inlet, per-path PTO twin.
        if (lost.in_flight) {
            const info = path.path.delivery.onPacketLost(&lost);
            path.path.cc.onPacketNewlyLost(&info);
        }
        conn.qlog_packets_lost +|= stats.count;
        conn_qlog.emitLossDetected(conn, .application, stats, .pto_probe);
        onApplicationPathPacketsLost(conn, path, stats);

        path.pending_ping = !requeued;
        if (requeued and path.pto_probe_count < 2) path.pto_probe_count += 1;
        path.pto_count +|= 1;
        return true;
    }
    return false;
}

pub fn fireDuePtoAtLevel(
    conn: *Connection,
    lvl: EncryptionLevel,
    now_us: u64,
) Error!void {
    const deadline = ptoDeadlineForLevel(conn, lvl) orelse return;
    if (now_us < deadline) return;
    _ = try firePtoAtLevel(conn, lvl);
}

pub fn fireDuePtoOnApplicationPath(
    conn: *Connection,
    path: *PathState,
    now_us: u64,
) Error!void {
    const deadline = ptoDeadlineForApplicationPath(conn, path) orelse return;
    if (now_us < deadline) return;
    _ = try firePtoOnApplicationPath(conn, path);
}
