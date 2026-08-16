//! Connection-ID registries for both directions: local SCID issue /
//! retire / budget (RFC 9000 §5.1.1), the peer-CID registry (§5.1.2),
//! NEW_CONNECTION_ID / RETIRE_CONNECTION_ID queueing, replenish-event
//! bookkeeping, and the multipath per-path CID budgets. Free-function
//! siblings of `Connection`'s method-style CID plumbing; the methods on
//! `Connection` are thin thunks that delegate here. Cross-subsystem CID
//! helpers shared with _internal.zig stay there.

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
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const transport_error_connection_id_limit = state_mod.transport_error_connection_id_limit;

/// Set the DCID we put on outgoing 1-RTT packets. A zero-length
/// CID is valid (RFC 9000 §5.1) and represents the case where
/// the peer has chosen not to identify itself with a CID;
/// `peer_dcid_set` flips to true regardless of length.
pub fn setPeerDcid(conn: *Connection, cid: []const u8) !void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    conn.peer_dcid = ConnectionId.fromSlice(cid);
    conn.primaryPath().path.peer_cid = conn.peer_dcid;
    conn.peer_dcid_set = true;
    try conn.installPeerTransportStatelessResetToken();
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
pub fn setLocalScid(conn: *Connection, cid: []const u8) !void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    const first_latch = !conn.initial_source_cid_set;
    conn.local_scid = ConnectionId.fromSlice(cid);
    if (first_latch) {
        conn.initial_source_cid = conn.local_scid;
        conn.initial_source_cid_set = true;
        // Fold the just-latched ISCID into parameters that were set before
        // this call, then re-push. No-op when the SCID was latched first
        // (setTransportParams already filled it) or when a caller supplied
        // its own ISCID.
        if (conn.local_transport_params_set and
            conn.local_transport_params.initial_source_connection_id == null)
        {
            conn.local_transport_params.initial_source_connection_id = conn.initial_source_cid;
            var buf: [1024]u8 = undefined;
            const n = try conn.local_transport_params.encode(&buf);
            try conn.inner.setQuicTransportParams(buf[0..n]);
        }
    }
    conn.primaryPath().path.local_cid = conn.local_scid;
    conn.local_scid_set = true;
    try _internal.rememberLocalCid(conn, 0, 0, 0, conn.local_scid, @splat(0));
}

/// Length of the local SCID — also the length of the DCID the
/// peer puts on incoming short-header packets.
pub fn localDcidLen(conn: *const Connection) u8 {
    return conn.local_scid.len;
}

pub fn longHeaderScid(conn: *const Connection) ConnectionId {
    return if (conn.initial_source_cid_set) conn.initial_source_cid else conn.local_scid;
}

// ---- Direction-agnostic registry traversal ----------------------------
//
// The local-CID registry (RFC 9000 §5.1.1, `conn.local_cids`) and the
// peer-CID registry (§5.1.2, `conn.peer_cids`) store the same element
// type, `IssuedCid`, keyed by `(path_id, sequence_number)`. The helpers
// below own the shared traversal so a fix to it lands in both
// directions at once; everything direction-specific — the `local_scid`
// / `peer_dcid` mirrors, active-CID limits, and protocol-violation
// closes — stays in the direction-bound wrappers and their callers.

fn cidActiveCountForPath(items: []const IssuedCid, path_id: u32) usize {
    var count: usize = 0;
    for (items) |item| {
        if (item.path_id == path_id) count += 1;
    }
    return count;
}

/// First registry entry for `path_id` in insertion order — the
/// successor a promote falls back to — or null when the path has none.
fn firstCidForPath(items: []const IssuedCid, path_id: u32) ?ConnectionId {
    for (items) |item| {
        if (item.path_id == path_id) return item.cid;
    }
    return null;
}

/// Remove every `(path_id, sequence_number < retire_prior_to)` entry
/// from `list`. Returns true when `current` (the CID the path is
/// actively using) was among the removed entries, so callers can gate
/// re-promotion on the in-use CID actually having been retired.
fn removeCidsPriorTo(
    list: *std.ArrayList(IssuedCid),
    path_id: u32,
    retire_prior_to: u64,
    current: ConnectionId,
) bool {
    var removed_current = false;
    var i: usize = 0;
    while (i < list.items.len) {
        const item = list.items[i];
        if (item.path_id == path_id and item.sequence_number < retire_prior_to) {
            if (ConnectionId.eql(item.cid, current)) removed_current = true;
            _ = list.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    return removed_current;
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.rememberLocalCid`.
pub fn retireLocalCidsPriorTo(
    conn: *Connection,
    path_id: u32,
    retire_prior_to: u64,
) void {
    // The local direction promotes unconditionally (the removed-current
    // result is discarded), unlike `retirePeerCidsPriorTo`, which only
    // re-promotes when the in-use CID was actually swept — and unlike
    // the local single-sequence `retireLocalCid`, which carries the
    // same gate. The asymmetry predates this shared helper; aligning
    // the local bulk path with the gated form is a behavior change
    // that needs its own tests first.
    _ = removeCidsPriorTo(&conn.local_cids, path_id, retire_prior_to, .{});
    promoteLocalCidForPath(conn, path_id);
}

fn promoteLocalCidForPath(conn: *Connection, path_id: u32) void {
    const path = conn.paths.get(path_id) orelse return;
    const successor = firstCidForPath(conn.local_cids.items, path_id);
    path.path.local_cid = successor orelse .{};
    // Path-0 mirror: `local_scid` follows the promoted CID but is left
    // untouched when the path has no surviving entries (incoming
    // Version-Negotiation / Retry DCID matching keys off it), whereas
    // the peer twin clears `peer_dcid` in that case. Preserved as-is;
    // see `promotePeerCidForPath`.
    if (path_id == 0) {
        if (successor) |cid| conn.local_scid = cid;
    }
}

fn retireLocalCid(conn: *Connection, path_id: u32, sequence_number: u64) void {
    var removed_cid: ?ConnectionId = null;
    var i: usize = 0;
    while (i < conn.local_cids.items.len) {
        const item = conn.local_cids.items[i];
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            removed_cid = item.cid;
            _ = conn.local_cids.orderedRemove(i);
            continue;
        }
        i += 1;
    }
    const cid = removed_cid orelse return;
    const path = conn.paths.get(path_id) orelse return;
    if (ConnectionId.eql(path.path.local_cid, cid)) {
        promoteLocalCidForPath(conn, path_id);
    }
}

pub fn retireLocalCidFromPeer(conn: *Connection, path_id: u32, sequence_number: u64) void {
    const before_budget = localConnectionIdIssueBudget(conn, path_id);
    retireLocalCid(conn, path_id, sequence_number);
    if (localConnectionIdIssueBudget(conn, path_id) > before_budget) {
        recordConnectionIdsNeeded(conn, path_id, .retired, null);
    }
}

pub fn dropPendingLocalCidAdvertisement(
    conn: *Connection,
    path_id: u32,
    sequence_number: u64,
) void {
    if (path_id == 0) {
        conn.pending_frames.removeNewConnectionIdBySequence(sequence_number);
        return;
    }
    conn.pending_frames.removePathNewConnectionIdBySequence(path_id, sequence_number);
}

/// Single owner of the local-CID advertisement add-side for both frame
/// flavours: validates issuance, remembers the CID so packets bearing
/// it can be authenticated, and parks the frame in the queue matching
/// `path_id` — path 0 advertises via NEW_CONNECTION_ID (RFC 9000
/// §19.15), every other path via PATH_NEW_CONNECTION_ID
/// (draft-ietf-quic-multipath-21 §6.3). Mirror image of
/// `dropPendingLocalCidAdvertisement` above, which removes pending
/// advertisements under the same path-0-vs-path-N queue rule; keeping
/// both rules side by side means the add and drop sides cannot
/// disagree about where a path-0 advertisement lives.
// INTERNAL: pub for direct sibling import (path_frame_queue.zig).
pub fn queueLocalConnectionId(
    conn: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) Error!void {
    if (cid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    // Self-guards on path 0 (immediate return), so calling it
    // unconditionally is a no-op for the NEW_CONNECTION_ID flavour.
    try _internal.ensureCanIssueCidForPathId(conn, path_id);
    try _internal.ensureCanIssueLocalCid(conn, path_id, sequence_number, retire_prior_to, cid.len);
    const local_cid = ConnectionId.fromSlice(cid);
    try _internal.ensureLocalCidAvailable(conn, path_id, sequence_number, local_cid);
    // The two pending queues carry different frame types, so the dedupe
    // scan and the append each need a per-flavour arm; the ordering
    // contract (availability before remember, remember before append)
    // is shared and lives only here.
    if (path_id == 0) {
        for (conn.pending_frames.new_connection_ids.items) |item| {
            if (item.sequence_number == sequence_number) {
                if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
                return;
            }
        }
    } else {
        for (conn.pending_frames.path_new_connection_ids.items) |item| {
            if (item.path_id == path_id and item.sequence_number == sequence_number) {
                if (!std.mem.eql(u8, item.connection_id.slice(), cid)) return Error.ConnectionIdAlreadyInUse;
                return;
            }
        }
    }
    var connection_id: frame_types.ConnId = .{ .len = @intCast(cid.len) };
    @memcpy(connection_id.bytes[0..cid.len], cid);
    try _internal.rememberLocalCid(conn, path_id, sequence_number, retire_prior_to, local_cid, stateless_reset_token);
    if (path_id == 0) {
        try conn.pending_frames.new_connection_ids.append(conn.allocator, .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    } else {
        try conn.pending_frames.path_new_connection_ids.append(conn.allocator, .{
            .path_id = path_id,
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        });
    }
    _internal.refreshConnectionIdEventsForPath(conn, path_id);
}

/// Smallest sequence number still resident in `local_cids` for
/// `path_id`, or null when the path has no local CIDs at all.
/// Used by `handleRetireConnectionId` to short-circuit an
/// O(N) walk when the peer retires a sequence already gone from
/// the table.
pub fn smallestLiveLocalCidSeq(conn: *const Connection, path_id: u32) ?u64 {
    var smallest: ?u64 = null;
    for (conn.local_cids.items) |item| {
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
pub fn nextLocalConnectionIdSequence(conn: *const Connection, path_id: u32) u64 {
    return _internal.nextLocalCidSequence(conn, path_id);
}

/// Number of currently-active local SCIDs across all paths
/// (initial SCID plus every still-unretired SCID issued via
/// NEW_CONNECTION_ID). Used by embedders that maintain a
/// CID-to-connection routing table outside the connection
/// (the canonical caller is `quic.Server`).
pub fn localScidCount(conn: *const Connection) usize {
    return conn.local_cids.items.len;
}

/// Snapshot the currently-active local SCIDs into `dst`.
/// Returns the number of CIDs actually written (`min(dst.len,
/// localScidCount())`). Caller is responsible for sizing `dst`
/// large enough; oversize is fine, undersize silently truncates.
/// CIDs are returned in insertion order — the initial SCID is
/// at index 0, with subsequent NEW_CONNECTION_ID-issued CIDs
/// following in the order they were minted, modulo retirements
/// (which compact the list).
pub fn localScids(conn: *const Connection, dst: []ConnectionId) usize {
    const n = @min(dst.len, conn.local_cids.items.len);
    for (0..n) |i| dst[i] = conn.local_cids.items[i].cid;
    return n;
}

/// Returns true if `dcid` matches one of this connection's
/// currently-active local SCIDs. Per RFC 9000 §5.1, peers can
/// migrate to any CID we have advertised via NEW_CONNECTION_ID
/// at any time, so embedders that route by CID outside the
/// connection MUST treat any of those SCIDs as valid routing
/// keys, not just the initial one.
pub fn ownsLocalCid(conn: *const Connection, dcid: []const u8) bool {
    for (conn.local_cids.items) |item| {
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
pub fn findLocalCidSequence(conn: *const Connection, dcid: []const u8) ?u64 {
    for (conn.local_cids.items) |item| {
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
pub fn setIncomingLocalCidSeq(conn: *Connection, seq: ?u64) void {
    conn.current_incoming_local_cid_seq = seq;
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.ensureCanIssueLocalCid`.
pub fn localCidSequenceExists(
    conn: *const Connection,
    path_id: u32,
    sequence_number: u64,
) bool {
    for (conn.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            return true;
        }
    }
    return false;
}

fn localCidForSequence(
    conn: *const Connection,
    path_id: u32,
    sequence_number: u64,
) ?IssuedCid {
    for (conn.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            return item;
        }
    }
    return null;
}

fn localCidActiveCountForPath(conn: *const Connection, path_id: u32) usize {
    return cidActiveCountForPath(conn.local_cids.items, path_id);
}

fn localCidActiveCountForPathAfterRetirePriorTo(
    conn: *const Connection,
    path_id: u32,
    retire_prior_to: u64,
) usize {
    var count: usize = 0;
    for (conn.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number >= retire_prior_to) {
            count += 1;
        }
    }
    return count;
}

pub fn peerActiveConnectionIdLimit(conn: *const Connection) u64 {
    const params = conn.cached_peer_transport_params orelse return 2;
    return @min(params.active_connection_id_limit, max_supported_active_connection_id_limit);
}

fn peerActiveConnectionIdLimitUsize(conn: *const Connection) usize {
    const limit = peerActiveConnectionIdLimit(
        conn,
    );
    const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
    if (limit > max_usize_as_u64) return std.math.maxInt(usize);
    return @intCast(limit);
}

/// Number of fresh NEW_CONNECTION_ID frames the embedder may
/// queue on `path_id` without exceeding the peer's
/// `active_connection_id_limit`.
pub fn localConnectionIdIssueBudget(conn: *const Connection, path_id: u32) usize {
    return localConnectionIdIssueBudgetAfterRetirePriorTo(conn, path_id, 0);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.ensureCanIssueLocalCid`.
pub fn localConnectionIdIssueBudgetAfterRetirePriorTo(
    conn: *const Connection,
    path_id: u32,
    retire_prior_to: u64,
) usize {
    const limit = peerActiveConnectionIdLimit(
        conn,
    );
    const active: u64 = @intCast(
        localCidActiveCountForPathAfterRetirePriorTo(conn, path_id, retire_prior_to),
    );
    if (active >= limit) return 0;
    const remaining = limit - active;
    const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
    if (remaining > max_usize_as_u64) return std.math.maxInt(usize);
    return @intCast(remaining);
}

fn cidPathCanBeManaged(conn: *const Connection, path_id: u32) bool {
    if (path_id == 0) return true;
    if (conn.paths.getConst(path_id) != null) return true;
    return conn.multipathNegotiated() and path_id <= conn.local_max_path_id;
}

/// Snapshot of how many local CIDs are active on `path_id`, the peer's
/// limit, and the embedder's remaining issuance budget. Returns `null`
/// when `path_id` does not name a manageable path. Embedders use this to
/// drive `provideConnectionId` proactively (RFC 9000 §5.1.1).
pub fn connectionIdReplenishInfo(
    conn: *const Connection,
    path_id: u32,
) ?ConnectionIdReplenishInfo {
    if (!cidPathCanBeManaged(conn, path_id)) return null;
    return connectionIdReplenishInfoFor(conn, path_id, .retired, null);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.refreshConnectionIdEventsForPath`.
pub fn connectionIdReplenishInfoFor(
    conn: *const Connection,
    path_id: u32,
    reason: ConnectionIdReplenishReason,
    blocked_next_sequence_number: ?u64,
) ConnectionIdReplenishInfo {
    return .{
        .path_id = path_id,
        .reason = reason,
        .active_count = localCidActiveCountForPath(conn, path_id),
        .active_limit = peerActiveConnectionIdLimitUsize(
            conn,
        ),
        .issue_budget = localConnectionIdIssueBudget(conn, path_id),
        .next_sequence_number = _internal.nextLocalCidSequence(conn, path_id),
        .blocked_next_sequence_number = blocked_next_sequence_number,
    };
}

pub fn recordConnectionIdsNeeded(
    conn: *Connection,
    path_id: u32,
    reason: ConnectionIdReplenishReason,
    blocked_next_sequence_number: ?u64,
) void {
    if (!cidPathCanBeManaged(conn, path_id)) return;
    const info = connectionIdReplenishInfoFor(conn, path_id, reason, blocked_next_sequence_number);
    if (info.issue_budget == 0 and info.blocked_next_sequence_number == null) return;
    for (conn.connection_id_events.slice()) |*existing| {
        if (existing.path_id == path_id and existing.reason == reason) {
            existing.* = info;
            return;
        }
    }
    conn.connection_id_events.push(info);
}

// Pub for `_internal.zig` (subsystem-private). Called from `_internal.refreshConnectionIdEventsForPath`.
pub fn connectionIdEventStillNeeded(conn: *const Connection, path_id: u32) bool {
    if (localConnectionIdIssueBudget(conn, path_id) > 0) return true;
    if (conn.pendingPathCidsBlocked()) |blocked| {
        if (blocked.path_id == path_id) return true;
    }
    return false;
}

/// Queue a NEW_CONNECTION_ID frame. Sequence 0 is the Initial
/// source CID; callers should normally start additional CIDs at
/// sequence 1.
pub fn queueNewConnectionId(
    conn: *Connection,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) Error!void {
    return queueLocalConnectionId(conn, 0, sequence_number, retire_prior_to, cid, stateless_reset_token);
}

/// Queue a RETIRE_CONNECTION_ID frame asking the peer to drop a
/// previously-issued CID at `sequence_number`. Idempotent.
pub fn queueRetireConnectionId(
    conn: *Connection,
    sequence_number: u64,
) Error!void {
    for (conn.pending_frames.retire_connection_ids.items) |item| {
        if (item.sequence_number == sequence_number) return;
    }
    try conn.pending_frames.retire_connection_ids.append(conn.allocator, .{
        .sequence_number = sequence_number,
    });
}

/// Bulk-issue local CIDs on the default path (path_id 0) by emitting
/// NEW_CONNECTION_ID frames for each `ConnectionIdProvision`. Returns
/// the number of provisions actually accepted. RFC 9000 §19.15.
pub fn replenishConnectionIds(
    conn: *Connection,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    return replenishLocalConnectionIds(conn, 0, provisions);
}

/// Multipath variant of `replenishConnectionIds` — bulk-issues local
/// CIDs on `path_id` via PATH_NEW_CONNECTION_ID frames. Validates that
/// the path-id is permitted before queuing any frames.
/// draft-ietf-quic-multipath-21 §6.3.
pub fn replenishPathConnectionIds(
    conn: *Connection,
    path_id: u32,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    try _internal.ensureCanIssueCidForPathId(conn, path_id);
    return replenishLocalConnectionIds(conn, path_id, provisions);
}

fn replenishLocalConnectionIds(
    conn: *Connection,
    path_id: u32,
    provisions: []const ConnectionIdProvision,
) Error!usize {
    var queued: usize = 0;
    if (conn.pendingPathCidsBlocked()) |blocked| {
        if (blocked.path_id == path_id) {
            var seq = blocked.next_sequence_number;
            const next = _internal.nextLocalCidSequence(conn, path_id);
            while (seq < next) : (seq += 1) {
                const issued = localCidForSequence(conn, path_id, seq) orelse continue;
                try queueLocalConnectionId(
                    conn,
                    path_id,
                    issued.sequence_number,
                    issued.retire_prior_to,
                    issued.cid.slice(),
                    issued.stateless_reset_token,
                );
                queued += 1;
            }
        }
    }

    for (provisions) |provision| {
        if (localConnectionIdIssueBudget(conn, path_id) == 0) break;
        const sequence_number = _internal.nextLocalCidSequence(conn, path_id);
        try queueLocalConnectionId(
            conn,
            path_id,
            sequence_number,
            provision.retire_prior_to,
            provision.connection_id,
            provision.stateless_reset_token,
        );
        queued += 1;
    }

    if (queued > 0) {
        path_frame_queue.clearSatisfiedPathCidsBlocked(conn, path_id);
        _internal.refreshConnectionIdEventsForPath(conn, path_id);
    }
    return queued;
}

/// Number of peer-issued connection IDs we currently have
/// stashed via NEW_CONNECTION_ID frames.
pub fn peerCidsCount(conn: *const Connection) usize {
    return conn.peer_cids.items.len;
}

/// The Destination Connection ID we currently use to address the
/// peer on the primary path. Migrates when the peer rotates CIDs
/// (RFC 9000 §5.1.2). Test-facing — embedders normally don't need
/// to inspect this.
pub fn peerDcid(conn: *const Connection) ConnectionId {
    return conn.peer_dcid;
}

/// Test-only: register an extra peer-issued CID directly into the
/// peer_cids pool, as if a peer NEW_CONNECTION_ID had arrived.
/// Conformance tests that exercise §5.1.2 ¶1 (CID rotation on
/// migration) use this to seed a fresh entry without driving a
/// full wire round-trip. Production callers MUST NOT use this —
/// the production path is a real `Connection.handleNewConnectionId`
/// invocation through the frame dispatcher.
pub fn registerPeerCidForTesting(
    conn: *Connection,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
) Error!void {
    try registerPeerCid(conn, 0, sequence_number, retire_prior_to, cid, stateless_reset_token);
}

pub fn peerCidActiveCountForPath(conn: *const Connection, path_id: u32) usize {
    return cidActiveCountForPath(conn.peer_cids.items, path_id);
}

fn promotePeerCidForPath(conn: *Connection, path_id: u32) void {
    const path = conn.paths.get(path_id) orelse return;
    path.path.peer_cid = firstCidForPath(conn.peer_cids.items, path_id) orelse .{};
    if (path_id == 0) {
        conn.peer_dcid = path.path.peer_cid;
        conn.peer_dcid_set = conn.peer_dcid.len != 0;
    }
}

fn retirePeerCidsPriorTo(
    conn: *Connection,
    path_id: u32,
    retire_prior_to: u64,
) void {
    const current = if (conn.paths.get(path_id)) |path| path.path.peer_cid else ConnectionId{};
    if (removeCidsPriorTo(&conn.peer_cids, path_id, retire_prior_to, current)) {
        promotePeerCidForPath(conn, path_id);
    }
}

pub fn retirePeerCidsForPath(conn: *Connection, path_id: u32) void {
    // Peer sequence numbers arrive as wire varints (<= 2^62 - 1), so a
    // `retire_prior_to` of maxInt(u64) sweeps every entry on the path.
    _ = removeCidsPriorTo(&conn.peer_cids, path_id, std.math.maxInt(u64), .{});
    promotePeerCidForPath(conn, path_id);
}

pub fn registerPeerCid(
    conn: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
) Error!void {
    if (retire_prior_to > sequence_number) {
        // RFC 9000 §19.15: a NEW_CONNECTION_ID whose Retire Prior To
        // exceeds its Sequence Number is a FRAME_ENCODING_ERROR, not
        // a PROTOCOL_VIOLATION.
        conn.close(true, transport_error_frame_encoding, "invalid connection id retire_prior_to");
        return;
    }
    if (conn.multipathNegotiated() and !conn_recv_dispatch.pathIdAllowedByLocalLimit(conn, path_id)) return;

    for (conn.peer_cids.items) |*item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            if (!ConnectionId.eql(item.cid, cid) or
                !Connection.tokenEql(item.stateless_reset_token, stateless_reset_token))
            {
                conn.close(true, transport_error_protocol_violation, "connection id sequence reused");
                return;
            }
            if (retire_prior_to > item.retire_prior_to) {
                item.retire_prior_to = retire_prior_to;
                retirePeerCidsPriorTo(conn, path_id, retire_prior_to);
            }
            return;
        }
        if (cid.len != 0 and ConnectionId.eql(item.cid, cid)) {
            conn.close(true, transport_error_protocol_violation, "connection id reused across paths");
            return;
        }
    }

    retirePeerCidsPriorTo(conn, path_id, retire_prior_to);
    const active_limit = conn.local_transport_params.active_connection_id_limit;
    if (@as(u64, @intCast(peerCidActiveCountForPath(conn, path_id))) >= active_limit) {
        // RFC 9000 §5.1.1: receiving more connection IDs than the
        // advertised active_connection_id_limit is a
        // CONNECTION_ID_LIMIT_ERROR (0x09), not PROTOCOL_VIOLATION.
        conn.close(true, transport_error_connection_id_limit, "active connection id limit exceeded");
        return;
    }
    try conn.peer_cids.append(conn.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .cid = cid,
        .stateless_reset_token = stateless_reset_token,
    });
    if (conn.paths.get(path_id)) |path| {
        if (path.path.peer_cid.len == 0 or sequence_number == 0) {
            path.path.peer_cid = cid;
        }
    }
    if (path_id == 0 and (conn.peer_dcid.len == 0 or sequence_number == 0)) {
        conn.peer_dcid = cid;
        conn.peer_dcid_set = true;
    }
}
