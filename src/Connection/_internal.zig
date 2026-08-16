// Internal helpers shared across conn/ subsystem files.
//
// **Not for embedders.** The leading underscore on the filename is a
// convention signal: this module is internal to the conn/ subdirectory
// and is not part of the quic public API. Anything exported from here
// may change in any release without notice.
//
// Entries belong here when:
//   * a helper is needed by multiple subsystem files (e.g.
//     `path_frame_queue.zig` and a future `Connection/streams.zig`), AND
//   * making the helper a `pub fn` on `Connection` would pollute the
//     embedder-visible method namespace.
//
// Helpers used by only ONE subsystem file should live in that
// subsystem file as a private `fn`, not here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_cids = @import("cids.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const path_mod = @import("../conn/path.zig");
const ConnectionId = path_mod.ConnectionId;

/// Validate that the local endpoint is allowed to issue a path-scoped
/// CID for `path_id`. Returns `Error.PathLimitExceeded` /
/// `Error.PathNotFound` per draft-ietf-quic-multipath-21 §5.3 / §6.3.
pub fn ensureCanIssueCidForPathId(conn: *const Connection, path_id: u32) Error!void {
    if (path_id == 0) return;
    if (conn.multipathNegotiated() and path_id > conn.local_max_path_id) {
        return Error.PathLimitExceeded;
    }
    if (conn.paths.getConst(path_id) != null) return;
    if (conn.multipathNegotiated()) return;
    return Error.PathNotFound;
}

/// Validate that we have headroom (peer's active_connection_id_limit
/// after applying `retire_prior_to`) to issue a fresh local CID at
/// `(path_id, sequence_number)`. Re-issuing an existing
/// `(path_id, sequence_number)` is a no-op.
pub fn ensureCanIssueLocalCid(
    conn: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid_len: usize,
) Error!void {
    if (cid_len == 0) return;
    if (conn_cids.localCidSequenceExists(conn, path_id, sequence_number)) return;
    if (conn_cids.localConnectionIdIssueBudgetAfterRetirePriorTo(conn, path_id, retire_prior_to) == 0) {
        return Error.ConnectionIdLimitExceeded;
    }
}

/// Ensure `cid` is not already used by another `(path_id, sequence)`
/// pair on this connection. Reusing the same `(path_id, sequence)` with
/// the SAME `cid` is allowed (idempotent re-advertisement); reusing
/// with a DIFFERENT cid, or aliasing across pairs, is rejected.
pub fn ensureLocalCidAvailable(
    conn: *const Connection,
    path_id: u32,
    sequence_number: u64,
    cid: ConnectionId,
) Error!void {
    if (cid.len == 0) return;
    for (conn.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            if (!ConnectionId.eql(item.cid, cid)) return Error.ConnectionIdAlreadyInUse;
            continue;
        }
        if (ConnectionId.eql(item.cid, cid)) return Error.ConnectionIdAlreadyInUse;
    }
}

/// Persist a freshly-issued local CID so packets bearing it can be
/// authenticated. Updates the path's high-watermark sequence number and
/// retires CIDs older than `retire_prior_to` per RFC 9000 §19.16.
pub fn rememberLocalCid(
    conn: *Connection,
    path_id: u32,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
) Error!void {
    if (cid.len == 0) return;
    if (retire_prior_to > sequence_number) {
        // RFC 9000 §19.15: FRAME_ENCODING_ERROR (mirrors the
        // peer-registry check in cids.zig). retire_prior_to is
        // peer-influenced via RETIRE_CONNECTION_ID processing, so
        // this defensive invariant check shares the same close code.
        conn.close(true, state_mod.transport_error_frame_encoding, "invalid retire_prior_to");
        return;
    }
    try ensureLocalCidAvailable(conn, path_id, sequence_number, cid);
    for (conn.local_cids.items) |*item| {
        if (item.path_id == path_id and item.sequence_number == sequence_number) {
            item.retire_prior_to = retire_prior_to;
            item.cid = cid;
            item.stateless_reset_token = stateless_reset_token;
            return;
        }
    }
    conn_cids.retireLocalCidsPriorTo(conn, path_id, retire_prior_to);
    try conn.local_cids.append(conn.allocator, .{
        .path_id = path_id,
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .cid = cid,
        .stateless_reset_token = stateless_reset_token,
    });
    if (conn.paths.get(path_id)) |path| {
        if (path.path.local_cid.len == 0 or sequence_number == 0) {
            path.path.local_cid = cid;
            if (path_id == 0) conn.local_scid = cid;
        }
        if (sequence_number >= path.next_local_cid_seq) {
            path.next_local_cid_seq = sequence_number + 1;
        }
    }
}

/// Refresh queued connection-id events for `path_id` after a CID was
/// issued: drop events that are no longer needed and recompute remaining
/// events' replenish targets.
pub fn refreshConnectionIdEventsForPath(conn: *Connection, path_id: u32) void {
    var i: usize = 0;
    while (i < conn.connection_id_events.len) {
        const slice = conn.connection_id_events.slice();
        if (slice[i].path_id != path_id) {
            i += 1;
            continue;
        }
        if (!conn_cids.connectionIdEventStillNeeded(conn, path_id)) {
            conn.connection_id_events.removeAt(i);
            continue;
        }
        const event = slice[i];
        conn.connection_id_events.slice()[i] = conn_cids.connectionIdReplenishInfoFor(
            conn,
            path_id,
            event.reason,
            event.blocked_next_sequence_number,
        );
        i += 1;
    }
}

/// One past the highest local-CID sequence number ever issued on
/// `path_id`. Used to gate RETIRE_CONNECTION_ID validity per
/// RFC 9000 §19.16 ("MUST treat receipt of a RETIRE_CONNECTION_ID with
/// a sequence number that has not been issued as a connection error of
/// type PROTOCOL_VIOLATION").
pub fn nextLocalCidSequence(conn: *const Connection, path_id: u32) u64 {
    var next: u64 = 0;
    for (conn.local_cids.items) |item| {
        if (item.path_id == path_id and item.sequence_number >= next) {
            next = item.sequence_number + 1;
        }
    }
    return next;
}
