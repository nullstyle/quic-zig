// Connection-ID registries for both directions: local SCID issue /
// retire / budget (RFC 9000 §5.1.1), the peer-CID registry (§5.1.2),
// NEW_CONNECTION_ID / RETIRE_CONNECTION_ID queueing, replenish-event
// bookkeeping, and the multipath per-path CID budgets. Free-function
// siblings of `Connection`'s method-style CID plumbing; the methods on
// `Connection` are thin thunks that delegate here. Cross-subsystem CID
// helpers shared with _internal.zig stay there.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_recv_dispatch = @import("recv_dispatch.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const ConnectionId = state_mod.ConnectionId;
const ConnectionIdProvision = state_mod.ConnectionIdProvision;
const IssuedCid = state_mod.IssuedCid;
const frame_types = state_mod.frame_types;
const path_mod = state_mod.path_mod;
const path_frame_queue = state_mod.path_frame_queue;
const _internal = state_mod._internal;
const ConnectionIdReplenishInfo = state_mod.ConnectionIdReplenishInfo;
const ConnectionIdReplenishReason = state_mod.ConnectionIdReplenishReason;
const max_supported_active_connection_id_limit = state_mod.max_supported_active_connection_id_limit;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

/// Set the DCID we put on outgoing 1-RTT packets. A zero-length
/// CID is valid (RFC 9000 §5.1) and represents the case where
/// the peer has chosen not to identify itself with a CID;
/// `peer_dcid_set` flips to true regardless of length.
pub fn setPeerDcid(self: *Connection, cid: []const u8) !void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    self.peer_dcid = ConnectionId.fromSlice(cid);
    self.primaryPath().path.peer_cid = self.peer_dcid;
    self.peer_dcid_set = true;
    try self.installPeerTransportStatelessResetToken();
}

/// Set the SCID this endpoint identifies with. A zero-length
/// CID is permitted. Used as the SCID on outgoing long-header
/// packets and as the expected DCID length on every incoming
/// packet.
///
/// The *first* call latches the connection's Initial Source Connection ID
/// (RFC 9000 §7.3), which `setTransportParams` advertises. The two calls
/// interact but their order does not matter: if the parameters were
/// already encoded and pushed without an ISCID (a caller that set them
/// before latching the SCID — e.g. the e2e harness), this back-fills the
/// ISCID and re-pushes so the handshake still advertises it. Without that,
/// inverting the order would silently omit the ISCID and strict peers
/// (quic-go) would reject the handshake with TRANSPORT_PARAMETER_ERROR.
/// A later `setLocalScid` (the ISCID is already latched and immutable)
/// skips the back-fill. Back-fill assumes the handshake has not yet
/// consumed the parameters, which holds for the init-time sequencing all
/// real callers use.
pub fn setLocalScid(self: *Connection, cid: []const u8) !void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    const first_latch = !self.initial_source_cid_set;
    self.local_scid = ConnectionId.fromSlice(cid);
    if (first_latch) {
        self.initial_source_cid = self.local_scid;
        self.initial_source_cid_set = true;
        // Fold the just-latched ISCID into parameters that were set before
        // this call, then re-push. No-op when the SCID was latched first
        // (setTransportParams already filled it) or when a caller supplied
        // its own ISCID.
        if (self.local_transport_params_set and
            self.local_transport_params.initial_source_connection_id == null)
        {
            self.local_transport_params.initial_source_connection_id = self.initial_source_cid;
            var buf: [1024]u8 = undefined;
            const n = try self.local_transport_params.encode(&buf);
            try self.inner.setQuicTransportParams(buf[0..n]);
        }
    }
    self.primaryPath().path.local_cid = self.local_scid;
    self.local_scid_set = true;
    try _internal.rememberLocalCid(self, 0, 0, 0, self.local_scid, @splat(0));
}

/// Length of the local SCID — also the length of the DCID the
/// peer puts on incoming short-header packets.
pub fn localDcidLen(self: *const Connection) u8 {
    return self.local_scid.len;
}

pub fn longHeaderScid(self: *const Connection) ConnectionId {
    return if (self.initial_source_cid_set) self.initial_source_cid else self.local_scid;
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.rememberLocalCid`.
pub fn retireLocalCidsPriorTo(
    self: *Connection,
    path_id: u32,
    retire_prior_to: u64,
) void {
    var i: usize = 0;
    while (i < self.local_cids.items.len) {
        const item = self.local_cids.items[i];
        if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
            _ = self.local_cids.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    promoteLocalCidForPath(self, path_id);
}

fn promoteLocalCidForPath(self: *Connection, path_id: u32) void {
    const path = self.paths.get(path_id) orelse return;
    path.path.local_cid = .{};
    for (self.local_cids.items) |item| {
        if (item.path_id == path_id) {
            path.path.local_cid = item.cid;
            if (path_id == 0) self.local_scid = item.cid;
            return;
        }
    }
}

fn retireLocalCid(self: *Connection, path_id: u32, sequence_number: u64) void {
    var removed_cid: ?ConnectionId = null;
    var i: usize = 0;
    while (i < self.local_cids.items.len) {
        const item = self.local_cids.items[i];
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            removed_cid = item.cid;
            _ = self.local_cids.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    const cid = removed_cid orelse return;
    const path = self.paths.get(path_id) orelse return;
    if (ConnectionId.eql(path.path.local_cid, cid)) {
        promoteLocalCidForPath(self, path_id);
    }
}

pub fn retireLocalCidFromPeer(self: *Connection, path_id: u32, sequence_number: u64) void {
    const before_budget = localConnectionIdIssueBudget(self, path_id);
    retireLocalCid(self, path_id, sequence_number);
    if (localConnectionIdIssueBudget(self, path_id) > before_budget) {
        recordConnectionIdsNeeded(self, path_id, .retired, null);
    }
}

pub fn dropPendingLocalCidAdvertisement(
    self: *Connection,
    path_id: u32,
    sequence_number: u64,
) void {
    if (path_id == 0) {
        self.pending_frames.removeNewConnectionIdBySequence(sequence_number);
        return;
    }
    self.pending_frames.removePathNewConnectionIdBySequence(path_id, sequence_number);
}

/// Smallest sequence number still resident in `local_cids` for
/// `path_id`, or null when the path has no local CIDs at all.
/// Used by `handleRetireConnectionId` to short-circuit an
/// O(N) walk when the peer retires a sequence already gone from
/// the table.
pub fn smallestLiveLocalCidSeq(self: *const Connection, path_id: u32) ?u64 {
    var smallest: ?u64 = null;
    for (self.local_cids.items) |item| {
        if (item.path_id != path_id) continue;
        if (smallest == null or item.sequence_number < smallest.?) {
            smallest = item.sequence_number;
        }
    }
    return smallest;
}

/// Sequence number to use for the next NEW_CONNECTION_ID
/// the embedder issues on `path_id`. Useful when minting CIDs
/// outside of `replenishConnectionIds`.
pub fn nextLocalConnectionIdSequence(self: *const Connection, path_id: u32) u64 {
    return _internal.nextLocalCidSequence(self, path_id);
}

/// Number of currently-active local SCIDs across all paths
/// (initial SCID plus every still-unretired SCID issued via
/// NEW_CONNECTION_ID). Used by embedders that maintain a
/// CID-to-connection routing table outside the connection
/// (the canonical caller is `quic.Server`).
pub fn localScidCount(self: *const Connection) usize {
    return self.local_cids.items.len;
}

/// Snapshot the currently-active local SCIDs into `dst`.
/// Returns the number of CIDs actually written (`min(dst.len,
/// localScidCount())`). Caller is responsible for sizing `dst`
/// large enough; oversize is fine, undersize silently truncates.
/// CIDs are returned in insertion order — the initial SCID is
/// at index 0, with subsequent NEW_CONNECTION_ID-issued CIDs
/// following in the order they were minted, modulo retirements
/// (which compact the list).
pub fn localScids(self: *const Connection, dst: []ConnectionId) usize {
    const n = @min(dst.len, self.local_cids.items.len);
    for (0..n) |i| dst[i] = self.local_cids.items[i].cid;
    return n;
}

/// Returns true if `dcid` matches one of this connection's
/// currently-active local SCIDs. Per RFC 9000 §5.1, peers can
/// migrate to any CID we have advertised via NEW_CONNECTION_ID
/// at any time, so embedders that route by CID outside the
/// connection MUST treat any of those SCIDs as valid routing
/// keys, not just the initial one.
pub fn ownsLocalCid(self: *const Connection, dcid: []const u8) bool {
    for (self.local_cids.items) |item| {
        if (item.cid.len != dcid.len) continue;
        if (std.mem.eql(u8, item.cid.bytes[0..item.cid.len], dcid)) return true;
    }
    return false;
}

/// Return the issuance sequence number of the locally-issued CID
/// matching `dcid`, or `null` if `dcid` is not one of ours. The
/// initial SCID is sequence 0; subsequent NEW_CONNECTION_ID-issued
/// CIDs increment in mint order. Required by Server routing to
/// inform `Connection.handle` which CID the inbound packet was
/// addressed to so RFC 9000 §19.16 ¶3 (RETIRE_CONNECTION_ID for
/// the receiving CID is PROTOCOL_VIOLATION) can fire.
pub fn findLocalCidSequence(self: *const Connection, dcid: []const u8) ?u64 {
    for (self.local_cids.items) |item| {
        if (item.cid.len != dcid.len) continue;
        if (std.mem.eql(u8, item.cid.bytes[0..item.cid.len], dcid)) {
            return item.sequence_number;
        }
    }
    return null;
}

/// Tell the connection which locally-issued CID sequence the
/// next-handled inbound datagram is addressed to. The Server's
/// router calls this before `handle` based on the routing
/// `cid_table` lookup so per-frame handlers (notably
/// `handleRetireConnectionId`) can compare against it.
/// `null` means "unknown" (e.g. an Initial packet on the
/// pre-routing-table bootstrap path); the §19.16 ¶3 gate
/// short-circuits in that case.
pub fn setIncomingLocalCidSeq(self: *Connection, seq: ?u64) void {
    self.current_incoming_local_cid_seq = seq;
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.ensureCanIssueLocalCid`.
pub fn localCidSequenceExists(
    self: *const Connection,
    path_id: u32,
    sequence_number: u64,
) bool {
    for (self.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            return true;
        }
    }
    return false;
}

fn localCidForSequence(
    self: *const Connection,
    path_id: u32,
    sequence_number: u64,
) ?IssuedCid {
    for (self.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            return item;
        }
    }
    return null;
}

fn localCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
    var count: usize = 0;
    for (self.local_cids.items) |item| {
        if (item.path_id == path_id) count += 1;
    }
    return count;
}

fn localCidActiveCountForPathAfterRetirePriorTo(
    self: *const Connection,
    path_id: u32,
    retire_prior_to: u64,
) usize {
    var count: usize = 0;
    for (self.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number >= retire_prior_to) {
            count += 1;
        }
    }
    return count;
}

pub fn peerActiveConnectionIdLimit(self: *const Connection) u64 {
    const params = self.cached_peer_transport_params orelse return 2;
    return @min(params.active_connection_id_limit, max_supported_active_connection_id_limit);
}

fn peerActiveConnectionIdLimitUsize(self: *const Connection) usize {
    const limit = peerActiveConnectionIdLimit(
        self,
    );
    const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
    if (limit > max_usize_as_u64) return std.math.maxInt(usize);
    return @intCast(limit);
}

/// Number of fresh NEW_CONNECTION_ID frames the embedder may
/// queue on `path_id` without exceeding the peer's
/// `active_connection_id_limit`.
pub fn localConnectionIdIssueBudget(self: *const Connection, path_id: u32) usize {
    return localConnectionIdIssueBudgetAfterRetirePriorTo(self, path_id, 0);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.ensureCanIssueLocalCid`.
pub fn localConnectionIdIssueBudgetAfterRetirePriorTo(
    self: *const Connection,
    path_id: u32,
    retire_prior_to: u64,
) usize {
    const limit = peerActiveConnectionIdLimit(
        self,
    );
    const active: u64 = @intCast(
        localCidActiveCountForPathAfterRetirePriorTo(self, path_id, retire_prior_to),
    );
    if (active >= limit) return 0;
    const remaining = limit - active;
    const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
    if (remaining > max_usize_as_u64) return std.math.maxInt(usize);
    return @intCast(remaining);
}

fn cidPathCanBeManaged(self: *const Connection, path_id: u32) bool {
    if (path_id == 0) return true;
    if (self.paths.getConst(path_id) != null) return true;
    return self.multipathNegotiated() and path_id <= self.local_max_path_id;
}

/// Snapshot of how many local CIDs are active on `path_id`, the peer's
/// limit, and the embedder's remaining issuance budget. Returns `null`
/// when `path_id` does not name a manageable path. Embedders use this to
/// drive `provideConnectionId` proactively (RFC 9000 §5.1.1).
pub fn connectionIdReplenishInfo(
    self: *const Connection,
    path_id: u32,
) ?ConnectionIdReplenishInfo {
    if (!cidPathCanBeManaged(self, path_id)) return null;
    return connectionIdReplenishInfoFor(self, path_id, .retired, null);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.refreshConnectionIdEventsForPath`.
pub fn connectionIdReplenishInfoFor(
    self: *const Connection,
    path_id: u32,
    reason: ConnectionIdReplenishReason,
    blocked_next_sequence_number: ?u64,
) ConnectionIdReplenishInfo {
    return .{
        .path_id = path_id,
        .reason = reason,
        .active_count = localCidActiveCountForPath(self, path_id),
        .active_limit = peerActiveConnectionIdLimitUsize(
            self,
        ),
        .issue_budget = localConnectionIdIssueBudget(self, path_id),
        .next_sequence_number = _internal.nextLocalCidSequence(self, path_id),
        .blocked_next_sequence_number = blocked_next_sequence_number,
    };
}

pub fn recordConnectionIdsNeeded(
    self: *Connection,
    path_id: u32,
    reason: ConnectionIdReplenishReason,
    blocked_next_sequence_number: ?u64,
) void {
    if (!cidPathCanBeManaged(self, path_id)) return;
    const info = connectionIdReplenishInfoFor(self, path_id, reason, blocked_next_sequence_number);
    if (info.issue_budget == 0 and info.blocked_next_sequence_number == null) return;
    for (self.connection_id_events.slice()) |*existing| {
        if (existing.path_id == path_id and existing.reason == reason) {
            existing.* = info;
            return;
        }
    }
    self.connection_id_events.push(info);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.refreshConnectionIdEventsForPath`.
pub fn connectionIdEventStillNeeded(self: *const Connection, path_id: u32) bool {
    if (localConnectionIdIssueBudget(self, path_id) > 0) return true;
    if (self.pendingPathCidsBlocked()) |blocked| {
        if (blocked.path_id == path_id) return true;
    }
    return false;
}

/// Queue a NEW_CONNECTION_ID frame. Sequence 0 is the Initial
/// source CID; callers should normally start additional CIDs at
/// sequence 1.
pub fn queueNewConnectionId(
    self: *Connection,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) Error!void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    try _internal.ensureCanIssueLocalCid(self, 0, sequence_number, retire_prior_to, cid.len);
    const local_cid = ConnectionId.fromSlice(cid);
    try _internal.ensureLocalCidAvailable(self, 0, sequence_number, local_cid);
    for (self.pending_frames.new_connection_ids.items) |item| {
        if (item.sequence_number == sequence_number) {
            if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
            return;
        }
    }
    var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
    @memcpy(connection_id.bytes[0..cid.len], cid);
    try _internal.rememberLocalCid(self, 0, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
    try self.pending_frames.new_connection_ids.append(self.allocator, .{
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .stateless_reset_token = stateless_reset_token,
    });
    _internal.refreshConnectionIdEventsForPath(self, 0);
}

/// Queue a RETIRE_CONNECTION_ID frame asking the peer to drop a
/// previously-issued CID at `sequence_number`. Idempotent.
pub fn queueRetireConnectionId(
    self: *Connection,
    sequence_number: u64,
) Error!void {
    for (self.pending_frames.retire_connection_ids.items) |item| {
        if (item.sequence_number == sequence_number) return;
    }
    try self.pending_frames.retire_connection_ids.append(self.allocator, .{
        .sequence_number = sequence_number,
    });
}

/// Bulk-issue local CIDs on the default path (path_id 0) by emitting
/// NEW_CONNECTION_ID frames for each `ConnectionIdProvision`. Returns
/// the number of provisions actually accepted. RFC 9000 §19.15.
pub fn replenishConnectionIds(
    self: *Connection,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    return replenishLocalConnectionIds(self, 0, provisions);
}

/// Multipath variant of `replenishConnectionIds` — bulk-issues local
/// CIDs on `path_id` via PATH_NEW_CONNECTION_ID frames. Validates that
/// the path-id is permitted before queuing any frames.
/// draft-ietf-quic-multipath-21 §6.3.
pub fn replenishPathConnectionIds(
    self: *Connection,
    path_id: u32,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    try _internal.ensureCanIssueCidForPathId(self, path_id);
    return replenishLocalConnectionIds(self, path_id, provisions);
}

fn replenishLocalConnectionIds(
    self: *Connection,
    path_id: u32,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    var queued: usize = 0;
    if (self.pendingPathCidsBlocked()) |blocked| {
        if (blocked.path_id == path_id) {
            var seq = blocked.next_sequence_number;
            const next = _internal.nextLocalCidSequence(self, path_id);
            while (seq < next) : (seq += 1) {
                const issued = localCidForSequence(self, path_id, seq) orelse continue;
                if (path_id == 0) {
                    try queueNewConnectionId(
                        self,
                        issued.sequence_number,
                        issued.retire_prior_to,
                        issued.cid.slice(),
                        issued.stateless_reset_token,
                    );
                } else {
                    try self.queuePathNewConnectionId(
                        path_id,
                        issued.sequence_number,
                        issued.retire_prior_to,
                        issued.cid.slice(),
                        issued.stateless_reset_token,
                    );
                }
                queued += 1;
            }
        }
    }

    for (provisions) |provision| {
        if (localConnectionIdIssueBudget(self, path_id) == 0) break;
        const sequence_number = _internal.nextLocalCidSequence(self, path_id);
        if (path_id == 0) {
            try queueNewConnectionId(
                self,
                sequence_number,
                provision.retire_prior_to,
                provision.connection_id,
                provision.stateless_reset_token,
            );
        } else {
            try self.queuePathNewConnectionId(
                path_id,
                sequence_number,
                provision.retire_prior_to,
                provision.connection_id,
                provision.stateless_reset_token,
            );
        }
        queued += 1;
    }

    if (queued > 0) {
        path_frame_queue.clearSatisfiedPathCidsBlocked(self, path_id);
        _internal.refreshConnectionIdEventsForPath(self, path_id);
    }
    return queued;
}

/// Number of peer-issued connection IDs we currently have
/// stashed via NEW_CONNECTION_ID frames.
pub fn peerCidsCount(self: *const Connection) usize {
    return self.peer_cids.items.len;
}

/// The Destination Connection ID we currently use to address the
/// peer on the primary path. Migrates when the peer rotates CIDs
/// (RFC 9000 §5.1.2). Test-facing — embedders normally don't need
/// to inspect this.
pub fn peerDcid(self: *const Connection) ConnectionId {
    return self.peer_dcid;
}

/// Test-only: register an extra peer-issued CID directly into the
/// peer_cids pool, as if a peer NEW_CONNECTION_ID had arrived.
/// Conformance tests that exercise §5.1.2 ¶1 (CID rotation on
/// migration) use this to seed a fresh entry without driving a
/// full wire round-trip. Production callers MUST NOT use this —
/// the production path is a real `Connection.handleNewConnectionId`
/// invocation through the frame dispatcher.
pub fn registerPeerCidForTesting(
    self: *Connection,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
) Error!void {
    try registerPeerCid(self, 0, sequence_number, retire_prior_to, cid, stateless_reset_token);
}

pub fn peerCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
    var count: usize = 0;
    for (self.peer_cids.items) |item| {
        if (item.path_id == path_id) count += 1;
    }
    return count;
}

fn promotePeerCidForPath(self: *Connection, path_id: u32) void {
    const path = self.paths.get(path_id) orelse return;
    path.path.peer_cid = .{};
    for (self.peer_cids.items) |item| {
        if (item.path_id == path_id) {
            path.path.peer_cid = item.cid;
            break;
        }
    }
    if (path_id == 0) {
        self.peer_dcid = path.path.peer_cid;
        self.peer_dcid_set = self.peer_dcid.len != 0;
    }
}

fn retirePeerCidsPriorTo(
    self: *Connection,
    path_id: u32,
    retire_prior_to: u64,
) void {
    var i: usize = 0;
    var affected_current = false;
    const current = if (self.paths.get(path_id)) |path| path.path.peer_cid else ConnectionId{};
    while (i < self.peer_cids.items.len) {
        const item = self.peer_cids.items[i];
        if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
            if (ConnectionId.eql(item.cid, current)) affected_current = true;
            _ = self.peer_cids.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    if (affected_current) promotePeerCidForPath(self, path_id);
}

pub fn retirePeerCidsForPath(self: *Connection, path_id: u32) void {
    var i: usize = 0;
    while (i < self.peer_cids.items.len) {
        if (self.peer_cids.items[i].path_id == path_id) {
            _ = self.peer_cids.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    promotePeerCidForPath(self, path_id);
}

pub fn registerPeerCid(
    self: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
) Error!void {
    if (retire_prior_to > sequence_number) {
        self.close(true, transport_error_protocol_violation, "invalid connection id retire_prior_to");
        return;
    }
    if (self.multipathNegotiated() and !conn_recv_dispatch.pathIdAllowedByLocalLimit(self, path_id)) return;

    for (self.peer_cids.items) |*item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            if (!ConnectionId.eql(item.cid, cid) or
                !Connection.tokenEql(item.stateless_reset_token, stateless_reset_token))
            {
                self.close(true, transport_error_protocol_violation, "connection id sequence reused");
                return;
            }
            if (retire_prior_to > item.retire_prior_to) {
                item.retire_prior_to = retire_prior_to;
                retirePeerCidsPriorTo(self, path_id, retire_prior_to);
            }
            return;
        }
        if (cid.len != 0 and ConnectionId.eql(item.cid, cid)) {
            self.close(true, transport_error_protocol_violation, "connection id reused across paths");
            return;
        }
    }

    retirePeerCidsPriorTo(self, path_id, retire_prior_to);
    const active_limit = self.local_transport_params.active_connection_id_limit;
    if (@as(u64, @intCast(peerCidActiveCountForPath(self, path_id))) >= active_limit) {
        self.close(true, transport_error_protocol_violation, "active connection id limit exceeded");
        return;
    }
    try self.peer_cids.append(self.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .cid = cid,
        .stateless_reset_token = stateless_reset_token,
    });
    if (self.paths.get(path_id)) |path| {
        if (path.path.peer_cid.len == 0 or sequence_number == 0) {
            path.path.peer_cid = cid;
        }
    }
    if (path_id == 0 and (self.peer_dcid.len == 0 or sequence_number == 0)) {
        self.peer_dcid = cid;
        self.peer_dcid_set = true;
    }
}
