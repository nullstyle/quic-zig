//! Path management for Connection: the multipath lifecycle
//! (draft-ietf-quic-multipath — open/abandon/status/backup, scheduler),
//! path accessors, PATH_CHALLENGE / PATH_RESPONSE validation, path
//! retirement, and the probe/ping API. Free-function siblings of
//! `Connection`'s method-style path plumbing; the methods on
//! `Connection` are thin thunks that delegate here. The outbound
//! multipath frame queues live in path_frame_queue.zig and the inbound
//! handlers in Connection/recv_multipath_handlers.zig.

const std = @import("std");
const boringssl = @import("boringssl");
const state_mod = @import("../Connection.zig");
const conn_qlog = @import("qlog.zig");
const conn_cids = @import("cids.zig");
const conn_recv_multipath_handlers = @import("recv_multipath_handlers.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Address = state_mod.Address;
const ConnectionId = state_mod.ConnectionId;
const PathState = state_mod.PathState;
const PathStats = state_mod.PathStats;
const Scheduler = state_mod.Scheduler;
const path_mod = state_mod.path_mod;
const _internal = state_mod._internal;

/// Enable or disable the public multipath surface. The current
/// implementation keeps existing single-path behavior unless callers
/// explicitly open and schedule additional paths.
pub fn enableMultipath(conn: *Connection, enabled: bool) void {
    conn.multipath_enabled = enabled;
}

/// True if `enableMultipath(true)` has been called locally.
/// Doesn't imply the peer agreed — see `multipathNegotiated`.
pub fn multipathEnabled(conn: *const Connection) bool {
    return conn.multipath_enabled;
}

/// True only when *both* sides advertised
/// `initial_max_path_id` in transport parameters. Until this
/// returns true, `openPath` for non-zero path ids will fail.
pub fn multipathNegotiated(conn: *const Connection) bool {
    if (!conn.multipath_enabled) return false;
    if (conn.local_transport_params.initial_max_path_id == null) return false;
    const peer_params = conn.cached_peer_transport_params orelse return false;
    return peer_params.initial_max_path_id != null;
}

/// True only when *both* peers advertised the RFC 9287 §3
/// `grease_quic_bit` transport parameter. While this returns
/// true, every encoded long- or short-header packet draws bit 6
/// of the first byte (the QUIC Bit) at random; the wire decoder
/// has always accepted any value there.
pub fn peerSupportsGreaseQuicBit(conn: *const Connection) bool {
    if (!conn.local_transport_params.grease_quic_bit) return false;
    const peer_params = conn.cached_peer_transport_params orelse return false;
    return peer_params.grease_quic_bit;
}

/// Draw a fresh QUIC Bit value for the next outgoing packet.
/// Returns 1 unless `peerSupportsGreaseQuicBit()` is true, in
/// which case the bit is sampled uniformly at random per packet
/// from BoringSSL's CSPRNG (RFC 9287 §3 SHOULDs an unpredictable
/// value). Falls back to 1 if `RAND_bytes` errors so a transient
/// CSPRNG failure can't drop us off the wire.
pub fn nextQuicBit(conn: *const Connection) u1 {
    if (!peerSupportsGreaseQuicBit(
        conn,
    )) return 1;
    var byte: [1]u8 = undefined;
    boringssl.crypto.rand.fillBytes(&byte) catch return 1;
    return @intCast(byte[0] & 0x01);
}

/// Register a new application path. The path owns independent
/// Application PN, sent, RTT, congestion, validation, and PTO
/// state; the multipath control frames are emitted from
/// `emitPendingMultipathFrames` and the receive switch dispatches
/// the inbound side (see `Connection/recv_multipath_handlers.zig`).
pub fn openPath(
    conn: *Connection,
    peer_addr: Address,
    local_addr: Address,
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
) Error!u32 {
    const path_id = conn.paths.next_path_id;
    if (multipathNegotiated(
        conn,
    )) {
        if (path_id > conn.peer_max_path_id) {
            conn.queuePathsBlocked(conn.peer_max_path_id);
            return Error.PathLimitExceeded;
        }
        if (path_id > conn.local_max_path_id) return Error.PathLimitExceeded;
        if (local_cid.len == 0 or peer_cid.len == 0) return Error.ConnectionIdRequired;
        try _internal.ensureCanIssueLocalCid(conn, path_id, 0, 0, local_cid.len);
        try _internal.ensureLocalCidAvailable(conn, path_id, 0, local_cid);
    }
    const opened_path_id = try conn.paths.openPath(
        conn.allocator,
        peer_addr,
        local_addr,
        local_cid,
        peer_cid,
        .{
            .max_datagram_size = conn.mtu,
            .algorithm = conn.cc_algorithm,
            .hystart = conn.cc_hystart,
        },
    );
    // Seed RFC 8899 PMTUD state on the freshly-opened path.
    if (conn.paths.get(opened_path_id)) |new_path| {
        new_path.pmtudInit(conn.pmtud_config);
    }
    try _internal.rememberLocalCid(conn, opened_path_id, 0, 0, local_cid, @splat(0));
    return opened_path_id;
}

/// Make `path_id` the primary path for new application data.
/// Returns false if no such path exists.
pub fn setActivePath(conn: *Connection, path_id: u32) bool {
    return conn.paths.setActive(path_id);
}

/// Mark `path_id` for retirement at the current activity time
/// with error code 0. New traffic stops scheduling here; in-flight
/// frames may still be acked.
pub fn abandonPath(conn: *Connection, path_id: u32) bool {
    return abandonPathAt(conn, path_id, 0, conn.last_activity_us);
}

/// As `abandonPath` but with an explicit timestamp and PATH_ABANDON
/// error code (draft-21 §6.2). Useful when the embedder has a
/// tighter clock than `last_activity_us`.
pub fn abandonPathAt(
    conn: *Connection,
    path_id: u32,
    error_code: u64,
    now_us: u64,
) bool {
    return retirePath(conn, path_id, error_code, now_us, true);
}

/// Override the lifecycle state of `path_id` directly. Mainly
/// useful for tests; production code should drive paths via
/// `openPath`, `markPathValidated`, `abandonPath`.
pub fn setPathStatus(conn: *Connection, path_id: u32, state: path_mod.State) bool {
    const p = conn.paths.get(path_id) orelse return false;
    p.path.state = state;
    return true;
}

/// Mark `path_id` available (`backup=false`) or backup
/// (`backup=true`) and queue a PATH_STATUS_AVAILABLE /
/// PATH_STATUS_BACKUP frame to inform the peer (draft-21 §6.4).
pub fn setPathBackup(conn: *Connection, path_id: u32, backup: bool) bool {
    const p = conn.paths.get(path_id) orelse return false;
    p.local_status_sequence_number +|= 1;
    conn.queuePathStatus(
        path_id,
        !backup,
        p.local_status_sequence_number,
    ) catch return false;
    return true;
}

/// Treat `path_id` as validated without running PATH_CHALLENGE.
/// Useful when validation is provided out-of-band (e.g. tests
/// that drive multipath through a mock transport). Returns false
/// for unknown `path_id`.
pub fn markPathValidated(conn: *Connection, path_id: u32) bool {
    const p = conn.paths.get(path_id) orelse return false;
    p.path.markValidated();
    if (p.pending_migration_reset) resetPathRecoveryAfterMigration(conn, p);
    return true;
}

/// Choose how `poll` distributes application bytes across
/// validated paths: `primary`, `round_robin`, or
/// `lowest_rtt_cwnd`.
pub fn setScheduler(conn: *Connection, scheduler: Scheduler) void {
    conn.paths.setScheduler(scheduler);
}

/// Path id currently used as the primary (active) path. Always 0
/// for single-path connections.
pub fn activePathId(conn: *const Connection) u32 {
    return conn.paths.activeConst().id;
}

/// Read-only snapshot of `path_id`'s RTT, congestion, and loss
/// counters. Returns null for unknown `path_id`.
pub fn pathStats(conn: *const Connection, path_id: u32) ?PathStats {
    var st = conn.paths.stats(path_id) orelse return null;
    // Connection-level counters live on Connection, not on PathState,
    // because they aggregate across all paths/levels (and across migrations).
    st.total_bytes_sent = conn.qlog_bytes_sent;
    st.total_bytes_received = conn.qlog_bytes_received;
    st.packets_sent = conn.qlog_packets_sent;
    st.packets_received = conn.qlog_packets_received;
    st.packets_lost = conn.qlog_packets_lost;
    return st;
}

pub fn primaryPath(conn: *Connection) *PathState {
    return conn.paths.primary();
}

pub fn primaryPathConst(conn: *const Connection) *const PathState {
    return conn.paths.primaryConst();
}

pub fn activePath(conn: *Connection) *PathState {
    return conn.paths.active();
}

pub fn pathForId(conn: *Connection, path_id: u32) *PathState {
    return conn.paths.get(path_id) orelse primaryPath(
        conn,
    );
}

pub fn applicationPathForPoll(conn: *Connection) *PathState {
    if (conn.pending_frames.path_response != null) {
        const p = pathForId(conn, conn.pending_frames.path_response_path_id);
        if (p.path.state != .failed and p.path.state != .retiring) return p;
    }
    if (conn.pending_frames.path_challenge != null) {
        const p = pathForId(conn, conn.pending_frames.path_challenge_path_id);
        if (p.path.state != .failed and p.path.state != .retiring) return p;
    }
    for (conn.paths.paths.items) |*p| {
        if (p.path.state == .failed) continue;
        if (p.app_pn_space.received.pending_ack) return p;
    }
    for (conn.paths.paths.items) |*p| {
        if (p.path.state == .failed) continue;
        if (p.pending_ping) return p;
    }
    return conn.paths.selectForSending();
}

pub fn incomingPathId(conn: *Connection, from: ?Address) u32 {
    if (from) |addr| {
        for (conn.paths.paths.items) |*p| {
            if (p.matchesPeerAddress(addr)) return p.id;
        }
        return activePath(
            conn,
        ).id;
    }
    return activePath(
        conn,
    ).id;
}

pub fn peerAddressChangeCandidate(
    conn: *Connection,
    path_id: u32,
    from: ?Address,
) ?Address {
    const addr = from orelse return null;
    const path = pathForId(conn, path_id);
    if (!path.peer_addr_set) return null;
    if (path.matchesPeerAddress(addr)) return null;
    return addr;
}

fn clearQueuedPathChallengeForPath(conn: *Connection, path_id: u32) void {
    if (conn.pending_frames.path_challenge != null and
        conn.pending_frames.path_challenge_path_id == path_id)
    {
        conn.pending_frames.path_challenge = null;
    }
}

pub fn queuePathResponseOnPath(
    conn: *Connection,
    path_id: u32,
    token: [8]u8,
    addr: ?Address,
) void {
    conn.pending_frames.path_response = token;
    conn.pending_frames.path_response_path_id = path_id;
    conn.pending_frames.path_response_addr = addr;
}

pub fn queuePathChallengeOnPath(
    conn: *Connection,
    path_id: u32,
    token: [8]u8,
) void {
    conn.pending_frames.path_challenge = token;
    conn.pending_frames.path_challenge_path_id = path_id;
}

pub fn newPathChallengeToken(conn: *Connection) Error![8]u8 {
    _ = conn;
    var token: [8]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&token);
    return token;
}

fn resetPathRecoveryAfterMigration(
    conn: *Connection,
    path: *PathState,
) void {
    path.resetRecoveryAfterMigration(.{
        .max_datagram_size = conn.mtu,
        .algorithm = conn.cc_algorithm,
        .hystart = conn.cc_hystart,
    });
}

pub fn handlePathValidationFailure(
    conn: *Connection,
    path: *PathState,
) void {
    const path_id = path.id;
    if (path.pending_migration_reset and path.rollbackFailedMigration()) {
        clearQueuedPathChallengeForPath(conn, path_id);
        conn_qlog.emitQlog(conn, .{
            .name = .migration_path_failed,
            .path_id = path_id,
            .migration_fail_reason = .timeout,
        });
        return;
    }
    path.path.fail();
    path.pending_migration_reset = false;
    path.migration_rollback = null;
    clearQueuedPathChallengeForPath(conn, path_id);
    conn_qlog.emitQlog(conn, .{
        .name = .migration_path_failed,
        .path_id = path_id,
        .migration_fail_reason = .timeout,
    });
}

pub fn recordPathResponse(
    conn: *Connection,
    path_id: u32,
    token: [8]u8,
) void {
    const path = pathForId(conn, path_id);
    const matched = path.path.validator.recordResponse(token) catch return;
    if (!matched) return;
    path.path.validated = true;
    clearQueuedPathChallengeForPath(conn, path_id);
    if (path.pending_migration_reset) {
        resetPathRecoveryAfterMigration(conn, path);
    }
    conn_qlog.emitQlog(conn, .{ .name = .migration_path_validated, .path_id = path_id });
}

pub fn shouldRequeuePathChallenge(
    conn: *Connection,
    path_id: u32,
    token: [8]u8,
) bool {
    const path = conn.paths.get(path_id) orelse return false;
    if (path.path.validator.status != .pending) return false;
    return std.mem.eql(u8, &token, &path.path.validator.pending_token);
}

pub fn retirePath(
    conn: *Connection,
    path_id: u32,
    error_code: u64,
    now_us: u64,
    queue_abandon: bool,
) bool {
    if (!conn.paths.abandon(path_id)) return false;
    const path = conn.paths.get(path_id) orelse return false;
    path.retire_deadline_us = now_us +| conn.retiredPathRetentionUs();
    if (queue_abandon) {
        conn.queuePathAbandon(path_id, error_code) catch return false;
    }
    return true;
}

pub fn expireRetiringPaths(conn: *Connection, now_us: u64) void {
    for (conn.paths.paths.items) |*path| {
        if (path.path.state != .retiring) continue;
        const deadline = path.retire_deadline_us orelse continue;
        if (now_us < deadline) continue;
        path.clearRecovery(conn.allocator);
        conn_cids.retirePeerCidsForPath(conn, path.id);
        path.path.fail();
        path.retire_deadline_us = null;
    }
}

/// Initiate path validation by queueing a PATH_CHALLENGE on
/// the next outgoing 1-RTT packet. `timeout_us` is typically
/// `3 * pto` per RFC 9000 §8.2.4. Returns the token.
pub fn probePath(
    conn: *Connection,
    token: [8]u8,
    now_us: u64,
    timeout_us: u64,
) Error!void {
    try probePathId(conn, 0, token, now_us, timeout_us);
}

/// As `probePath` but for an explicit `path_id`. Returns
/// `error.PathNotFound` if the id is unknown.
pub fn probePathId(
    conn: *Connection,
    path_id: u32,
    token: [8]u8,
    now_us: u64,
    timeout_us: u64,
) Error!void {
    const path = conn.paths.get(path_id) orelse return Error.PathNotFound;
    path.path.validator.beginChallenge(token, now_us, timeout_us);
    queuePathChallengeOnPath(conn, path_id, token);
}

/// Queue an application-level PING on the primary path. This is
/// useful for embedders that need an explicit liveness probe even
/// when they have no stream or datagram bytes to send.
pub fn requestPing(conn: *Connection) void {
    if (conn.closeState() != .open) return;
    primaryPath(
        conn,
    ).pending_ping = true;
}

/// Queue an application-level PING on a specific path.
pub fn requestPathPing(conn: *Connection, path_id: u32) Error!void {
    if (conn.closeState() != .open) return;
    const path = conn.paths.get(path_id) orelse return Error.PathNotFound;
    if (path.path.state == .failed or path.path.state == .retiring) return Error.PathNotFound;
    path.pending_ping = true;
}

/// True iff the active path has been validated (either via the
/// validator's PATH_RESPONSE flow or by `markPathValidated`).
pub fn isPathValidated(conn: *const Connection) bool {
    return primaryPathConst(
        conn,
    ).path.validator.isValidated();
}
