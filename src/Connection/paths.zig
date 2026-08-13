// Path management for Connection: the multipath lifecycle
// (draft-ietf-quic-multipath — open/abandon/status/backup, scheduler),
// path accessors, PATH_CHALLENGE / PATH_RESPONSE validation, path
// retirement, and the probe/ping API. Free-function siblings of
// `Connection`'s method-style path plumbing; the methods on
// `Connection` are thin thunks that delegate here. The outbound
// multipath frame queues live in path_frame_queue.zig and the inbound
// handlers in conn_recv_multipath_handlers.zig.

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
pub fn enableMultipath(self: *Connection, enabled: bool) void {
    self.multipath_enabled = enabled;
}

/// True if `enableMultipath(true)` has been called locally.
/// Doesn't imply the peer agreed — see `multipathNegotiated`.
pub fn multipathEnabled(self: *const Connection) bool {
    return self.multipath_enabled;
}

/// True only when *both* sides advertised
/// `initial_max_path_id` in transport parameters. Until this
/// returns true, `openPath` for non-zero path ids will fail.
pub fn multipathNegotiated(self: *const Connection) bool {
    if (!self.multipath_enabled) return false;
    if (self.local_transport_params.initial_max_path_id == null) return false;
    const peer_params = self.cached_peer_transport_params orelse return false;
    return peer_params.initial_max_path_id != null;
}

/// True only when *both* peers advertised the RFC 9287 §3
/// `grease_quic_bit` transport parameter. While this returns
/// true, every encoded long- or short-header packet draws bit 6
/// of the first byte (the QUIC Bit) at random; the wire decoder
/// has always accepted any value there.
pub fn peerSupportsGreaseQuicBit(self: *const Connection) bool {
    if (!self.local_transport_params.grease_quic_bit) return false;
    const peer_params = self.cached_peer_transport_params orelse return false;
    return peer_params.grease_quic_bit;
}

/// Draw a fresh QUIC Bit value for the next outgoing packet.
/// Returns 1 unless `peerSupportsGreaseQuicBit()` is true, in
/// which case the bit is sampled uniformly at random per packet
/// from BoringSSL's CSPRNG (RFC 9287 §3 SHOULDs an unpredictable
/// value). Falls back to 1 if `RAND_bytes` errors so a transient
/// CSPRNG failure can't drop us off the wire.
pub fn nextQuicBit(self: *const Connection) u1 {
    if (!peerSupportsGreaseQuicBit(
        self,
    )) return 1;
    var byte: [1]u8 = undefined;
    boringssl.crypto.rand.fillBytes(&byte) catch return 1;
    return @intCast(byte[0] & 0x01);
}

/// Register a new application path. The path owns independent
/// Application PN, sent, RTT, congestion, validation, and PTO
/// state; the multipath control frames are emitted from
/// `emitPendingMultipathFrames` and the receive switch dispatches
/// the inbound side (see `conn_recv_multipath_handlers.zig`).
pub fn openPath(
    self: *Connection,
    peer_addr: Address,
    local_addr: Address,
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
) Error!u32 {
    const path_id = self.paths.next_path_id;
    if (multipathNegotiated(
        self,
    )) {
        if (path_id > self.peer_max_path_id) {
            self.queuePathsBlocked(self.peer_max_path_id);
            return Error.PathLimitExceeded;
        }
        if (path_id > self.local_max_path_id) return Error.PathLimitExceeded;
        if (local_cid.len == 0 or peer_cid.len == 0) return Error.ConnectionIdRequired;
        try _internal.ensureCanIssueLocalCid(self, path_id, 0, 0, local_cid.len);
        try _internal.ensureLocalCidAvailable(self, path_id, 0, local_cid);
    }
    const opened_path_id = try self.paths.openPath(
        self.allocator,
        peer_addr,
        local_addr,
        local_cid,
        peer_cid,
        .{
            .max_datagram_size = self.mtu,
            .algorithm = self.cc_algorithm,
            .hystart = self.cc_hystart,
        },
    );
    // Seed RFC 8899 PMTUD state on the freshly-opened path.
    if (self.paths.get(opened_path_id)) |new_path| {
        new_path.pmtudInit(self.pmtud_config);
    }
    try _internal.rememberLocalCid(self, opened_path_id, 0, 0, local_cid, @splat(0));
    return opened_path_id;
}

/// Make `path_id` the primary path for new application data.
/// Returns false if no such path exists.
pub fn setActivePath(self: *Connection, path_id: u32) bool {
    return self.paths.setActive(path_id);
}

/// Mark `path_id` for retirement at the current activity time
/// with error code 0. New traffic stops scheduling here; in-flight
/// frames may still be acked.
pub fn abandonPath(self: *Connection, path_id: u32) bool {
    return abandonPathAt(self, path_id, 0, self.last_activity_us);
}

/// As `abandonPath` but with an explicit timestamp and PATH_ABANDON
/// error code (draft-21 §6.2). Useful when the embedder has a
/// tighter clock than `last_activity_us`.
pub fn abandonPathAt(
    self: *Connection,
    path_id: u32,
    error_code: u64,
    now_us: u64,
) bool {
    return retirePath(self, path_id, error_code, now_us, true);
}

/// Override the lifecycle state of `path_id` directly. Mainly
/// useful for tests; production code should drive paths via
/// `openPath`, `markPathValidated`, `abandonPath`.
pub fn setPathStatus(self: *Connection, path_id: u32, state: path_mod.State) bool {
    const p = self.paths.get(path_id) orelse return false;
    p.path.state = state;
    return true;
}

/// Mark `path_id` available (`backup=false`) or backup
/// (`backup=true`) and queue a PATH_STATUS_AVAILABLE /
/// PATH_STATUS_BACKUP frame to inform the peer (draft-21 §6.4).
pub fn setPathBackup(self: *Connection, path_id: u32, backup: bool) bool {
    const p = self.paths.get(path_id) orelse return false;
    p.local_status_sequence_number +|= 1;
    self.queuePathStatus(
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
pub fn markPathValidated(self: *Connection, path_id: u32) bool {
    const p = self.paths.get(path_id) orelse return false;
    p.path.markValidated();
    if (p.pending_migration_reset) resetPathRecoveryAfterMigration(self, p);
    return true;
}

/// Choose how `poll` distributes application bytes across
/// validated paths: `primary`, `round_robin`, or
/// `lowest_rtt_cwnd`.
pub fn setScheduler(self: *Connection, scheduler: Scheduler) void {
    self.paths.setScheduler(scheduler);
}

/// Path id currently used as the primary (active) path. Always 0
/// for single-path connections.
pub fn activePathId(self: *const Connection) u32 {
    return self.paths.activeConst().id;
}

/// Read-only snapshot of `path_id`'s RTT, congestion, and loss
/// counters. Returns null for unknown `path_id`.
pub fn pathStats(self: *const Connection, path_id: u32) ?PathStats {
    var st = self.paths.stats(path_id) orelse return null;
    // Connection-level counters live on Connection, not on PathState,
    // because they aggregate across all paths/levels (and across migrations).
    st.total_bytes_sent = self.qlog_bytes_sent;
    st.total_bytes_received = self.qlog_bytes_received;
    st.packets_sent = self.qlog_packets_sent;
    st.packets_received = self.qlog_packets_received;
    st.packets_lost = self.qlog_packets_lost;
    return st;
}

pub fn primaryPath(self: *Connection) *PathState {
    return self.paths.primary();
}

pub fn primaryPathConst(self: *const Connection) *const PathState {
    return self.paths.primaryConst();
}

pub fn activePath(self: *Connection) *PathState {
    return self.paths.active();
}

pub fn pathForId(self: *Connection, path_id: u32) *PathState {
    return self.paths.get(path_id) orelse primaryPath(
        self,
    );
}

pub fn applicationPathForPoll(self: *Connection) *PathState {
    if (self.pending_frames.path_response != null) {
        const p = pathForId(self, self.pending_frames.path_response_path_id);
        if (p.path.state != .failed and p.path.state != .retiring) return p;
    }
    if (self.pending_frames.path_challenge != null) {
        const p = pathForId(self, self.pending_frames.path_challenge_path_id);
        if (p.path.state != .failed and p.path.state != .retiring) return p;
    }
    for (self.paths.paths.items) |*p| {
        if (p.path.state == .failed) continue;
        if (p.app_pn_space.received.pending_ack) return p;
    }
    for (self.paths.paths.items) |*p| {
        if (p.path.state == .failed) continue;
        if (p.pending_ping) return p;
    }
    return self.paths.selectForSending();
}

pub fn incomingPathId(self: *Connection, from: ?Address) u32 {
    if (from) |addr| {
        for (self.paths.paths.items) |*p| {
            if (p.matchesPeerAddress(addr)) return p.id;
        }
        return activePath(
            self,
        ).id;
    }
    return activePath(
        self,
    ).id;
}

pub fn peerAddressChangeCandidate(
    self: *Connection,
    path_id: u32,
    from: ?Address,
) ?Address {
    const addr = from orelse return null;
    const path = pathForId(self, path_id);
    if (!path.peer_addr_set) return null;
    if (path.matchesPeerAddress(addr)) return null;
    return addr;
}

fn clearQueuedPathChallengeForPath(self: *Connection, path_id: u32) void {
    if (self.pending_frames.path_challenge != null and
        self.pending_frames.path_challenge_path_id == path_id)
    {
        self.pending_frames.path_challenge = null;
    }
}

pub fn queuePathResponseOnPath(
    self: *Connection,
    path_id: u32,
    token: [8]u8,
    addr: ?Address,
) void {
    self.pending_frames.path_response = token;
    self.pending_frames.path_response_path_id = path_id;
    self.pending_frames.path_response_addr = addr;
}

pub fn queuePathChallengeOnPath(
    self: *Connection,
    path_id: u32,
    token: [8]u8,
) void {
    self.pending_frames.path_challenge = token;
    self.pending_frames.path_challenge_path_id = path_id;
}

pub fn newPathChallengeToken(self: *Connection) Error![8]u8 {
    _ = self;
    var token: [8]u8 = undefined;
    try boringssl.crypto.rand.fillBytes(&token);
    return token;
}

fn resetPathRecoveryAfterMigration(
    self: *Connection,
    path: *PathState,
) void {
    path.resetRecoveryAfterMigration(.{
        .max_datagram_size = self.mtu,
        .algorithm = self.cc_algorithm,
        .hystart = self.cc_hystart,
    });
}

pub fn handlePathValidationFailure(
    self: *Connection,
    path: *PathState,
) void {
    const path_id = path.id;
    if (path.pending_migration_reset and path.rollbackFailedMigration()) {
        clearQueuedPathChallengeForPath(self, path_id);
        conn_qlog.emitQlog(self, .{
            .name = .migration_path_failed,
            .path_id = path_id,
            .migration_fail_reason = .timeout,
        });
        return;
    }
    path.path.fail();
    path.pending_migration_reset = false;
    path.migration_rollback = null;
    clearQueuedPathChallengeForPath(self, path_id);
    conn_qlog.emitQlog(self, .{
        .name = .migration_path_failed,
        .path_id = path_id,
        .migration_fail_reason = .timeout,
    });
}

pub fn recordPathResponse(
    self: *Connection,
    path_id: u32,
    token: [8]u8,
) void {
    const path = pathForId(self, path_id);
    const matched = path.path.validator.recordResponse(token) catch return;
    if (!matched) return;
    path.path.validated = true;
    clearQueuedPathChallengeForPath(self, path_id);
    if (path.pending_migration_reset) {
        resetPathRecoveryAfterMigration(self, path);
    }
    conn_qlog.emitQlog(self, .{ .name = .migration_path_validated, .path_id = path_id });
}

pub fn shouldRequeuePathChallenge(
    self: *Connection,
    path_id: u32,
    token: [8]u8,
) bool {
    const path = self.paths.get(path_id) orelse return false;
    if (path.path.validator.status != .pending) return false;
    return std.mem.eql(u8, &token, &path.path.validator.pending_token);
}

pub fn retirePath(
    self: *Connection,
    path_id: u32,
    error_code: u64,
    now_us: u64,
    queue_abandon: bool,
) bool {
    if (!self.paths.abandon(path_id)) return false;
    const path = self.paths.get(path_id) orelse return false;
    path.retire_deadline_us = now_us +| self.retiredPathRetentionUs();
    if (queue_abandon) {
        self.queuePathAbandon(path_id, error_code) catch return false;
    }
    return true;
}

pub fn expireRetiringPaths(self: *Connection, now_us: u64) void {
    for (self.paths.paths.items) |*path| {
        if (path.path.state != .retiring) continue;
        const deadline = path.retire_deadline_us orelse continue;
        if (now_us < deadline) continue;
        path.clearRecovery(self.allocator);
        conn_cids.retirePeerCidsForPath(self, path.id);
        path.path.fail();
        path.retire_deadline_us = null;
    }
}

/// Initiate path validation by queueing a PATH_CHALLENGE on
/// the next outgoing 1-RTT packet. `timeout_us` is typically
/// `3 * pto` per RFC 9000 §8.2.4. Returns the token.
pub fn probePath(
    self: *Connection,
    token: [8]u8,
    now_us: u64,
    timeout_us: u64,
) Error!void {
    try probePathId(self, 0, token, now_us, timeout_us);
}

/// As `probePath` but for an explicit `path_id`. Returns
/// `error.PathNotFound` if the id is unknown.
pub fn probePathId(
    self: *Connection,
    path_id: u32,
    token: [8]u8,
    now_us: u64,
    timeout_us: u64,
) Error!void {
    const path = self.paths.get(path_id) orelse return Error.PathNotFound;
    path.path.validator.beginChallenge(token, now_us, timeout_us);
    queuePathChallengeOnPath(self, path_id, token);
}

/// Queue an application-level PING on the primary path. This is
/// useful for embedders that need an explicit liveness probe even
/// when they have no stream or datagram bytes to send.
pub fn requestPing(self: *Connection) void {
    if (self.closeState() != .open) return;
    primaryPath(
        self,
    ).pending_ping = true;
}

/// Queue an application-level PING on a specific path.
pub fn requestPathPing(self: *Connection, path_id: u32) Error!void {
    if (self.closeState() != .open) return;
    const path = self.paths.get(path_id) orelse return Error.PathNotFound;
    if (path.path.state == .failed or path.path.state == .retiring) return Error.PathNotFound;
    path.pending_ping = true;
}

/// True iff the active path has been validated (either via the
/// validator's PATH_RESPONSE flow or by `markPathValidated`).
pub fn isPathValidated(self: *const Connection) bool {
    return primaryPathConst(
        self,
    ).path.validator.isValidated();
}
