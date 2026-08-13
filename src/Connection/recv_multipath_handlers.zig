//! Inbound frame handlers for QUIC multipath (draft-ietf-quic-multipath-21):
//! PATH_ACK, PATH_ABANDON, PATH_STATUS, PATH_NEW_CONNECTION_ID,
//! PATH_RETIRE_CONNECTION_ID, MAX_PATH_ID, PATHS_BLOCKED,
//! PATH_CIDS_BLOCKED. Free-function siblings of `Connection`'s
//! public method-style handlers; the methods on `Connection` are
//! thin thunks that delegate here.
//!
//! These are the inbound counterparts of the `queuePath*` methods in
//! `path_frame_queue.zig`.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_paths = @import("paths.zig");
const conn_recv_dispatch = @import("recv_dispatch.zig");
const conn_recv_ack_handlers = @import("recv_ack_handlers.zig");
const conn_cids = @import("cids.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const frame_types = state_mod.frame_types;
const ConnectionId = state_mod.ConnectionId;
const _internal = state_mod._internal;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const max_supported_path_id = state_mod.max_supported_path_id;

fn pathAckToAck(pa: frame_types.PathAck) frame_types.Ack {
    return .{
        .largest_acked = pa.largest_acked,
        .ack_delay = pa.ack_delay,
        .first_range = pa.first_range,
        .range_count = pa.range_count,
        .ranges_bytes = pa.ranges_bytes,
        .ecn_counts = pa.ecn_counts,
    };
}

pub fn handlePathAck(
    conn: *Connection,
    pa: frame_types.PathAck,
    now_us: u64,
) Error!void {
    if (pa.path_id == 0) {
        return conn.handleAckAtLevel(.application, pathAckToAck(pa), now_us);
    }
    const path = conn.paths.get(pa.path_id) orelse return;
    try conn_recv_ack_handlers.handleApplicationAckOnPath(conn, path, pathAckToAck(pa), now_us);
}

pub fn handlePathAbandon(
    conn: *Connection,
    pa: frame_types.PathAbandon,
    now_us: u64,
) void {
    _ = conn_paths.retirePath(conn, pa.path_id, pa.error_code, now_us, true);
}

pub fn handlePathStatus(
    conn: *Connection,
    ps: frame_types.PathStatus,
    available: bool,
) void {
    const path = conn.paths.get(ps.path_id) orelse return;
    path.recordPeerStatus(available, ps.sequence_number);
}

pub fn handlePathNewConnectionId(
    conn: *Connection,
    nc: frame_types.PathNewConnectionId,
) Error!void {
    const cid = ConnectionId.fromSlice(nc.connection_id.slice());
    try conn.registerPeerCid(nc.path_id, nc.sequence_number, nc.retire_prior_to, cid, nc.stateless_reset_token);
}

pub fn handlePathRetireConnectionId(
    conn: *Connection,
    rc: frame_types.PathRetireConnectionId,
) void {
    // Multipath analogue of RFC 9000 §19.16. Same DoS surface — a
    // peer that walks ahead of the issued sequence forces us to do
    // a lookup-and-discard per frame.
    if (conn.paths.getConst(rc.path_id)) |path| {
        if (rc.sequence_number >= path.next_local_cid_seq) {
            conn.close(true, transport_error_protocol_violation, "path_retire_connection_id sequence not yet issued");
            return;
        }
    }
    conn_cids.retireLocalCidFromPeer(conn, rc.path_id, rc.sequence_number);
    conn_cids.dropPendingLocalCidAdvertisement(conn, rc.path_id, rc.sequence_number);
}

/// draft-ietf-quic-multipath-21: a MAX_PATH_ID below the peer's own
/// `initial_max_path_id` transport parameter would retract path
/// capacity the handshake already granted — path limits only ever
/// grow. Closes with PROTOCOL_VIOLATION and returns false on
/// violation. Single home for the rule and its close reason,
/// shared by the dispatcher's pre-switch multipath gate
/// (`validateIncomingMultipathFrame`) and `handleMaxPathId` (which
/// tests reach directly, bypassing dispatch).
// INTERNAL: pub for direct sibling import (recv_dispatch.zig).
pub fn maxPathIdRespectsPeerInitialLimit(conn: *Connection, mp: frame_types.MaxPathId) bool {
    if (conn.cached_peer_transport_params) |params| {
        if (params.initial_max_path_id) |initial_max_path_id| {
            if (mp.maximum_path_id < initial_max_path_id) {
                conn.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                return false;
            }
        }
    }
    return true;
}

/// draft-ietf-quic-multipath-21: PATH_CIDS_BLOCKED's Next Sequence
/// Number cannot exceed the next local CID sequence number we would
/// issue on that path — a peer claiming to be blocked past what we
/// ever issued is lying about our own allocations. Closes with
/// PROTOCOL_VIOLATION and returns false on violation. Single home
/// for the rule and its close reason, shared by the dispatcher's
/// pre-switch multipath gate (`validateIncomingMultipathFrame`) and
/// `handlePathCidsBlocked` (which tests reach directly, bypassing
/// dispatch). Callers gate `pcb.path_id` through
/// `pathIdAllowedByLocalLimit` first.
// INTERNAL: pub for direct sibling import (recv_dispatch.zig).
pub fn pathCidsBlockedSeqIsValid(conn: *Connection, pcb: frame_types.PathCidsBlocked) bool {
    const next = _internal.nextLocalCidSequence(conn, pcb.path_id);
    if (pcb.next_sequence_number > next) {
        conn.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
        return false;
    }
    return true;
}

pub fn handleMaxPathId(conn: *Connection, mp: frame_types.MaxPathId) void {
    if (!maxPathIdRespectsPeerInitialLimit(conn, mp)) return;
    if (mp.maximum_path_id > conn.peer_max_path_id) {
        conn.peer_max_path_id = @min(mp.maximum_path_id, max_supported_path_id);
    }
}

pub fn handlePathsBlocked(conn: *Connection, pb: frame_types.PathsBlocked) void {
    if (!conn_recv_dispatch.pathIdAllowedByLocalLimit(conn, pb.maximum_path_id)) return;
    if (pb.maximum_path_id < conn.local_max_path_id) return;
    conn.peer_paths_blocked_at = pb.maximum_path_id;
}

pub fn handlePathCidsBlocked(conn: *Connection, pcb: frame_types.PathCidsBlocked) void {
    if (!conn_recv_dispatch.pathIdAllowedByLocalLimit(conn, pcb.path_id)) return;
    if (!pathCidsBlockedSeqIsValid(conn, pcb)) return;
    conn.peer_path_cids_blocked_path_id = pcb.path_id;
    conn.peer_path_cids_blocked_next_sequence = pcb.next_sequence_number;
    conn_cids.recordConnectionIdsNeeded(conn, pcb.path_id, .path_cids_blocked, pcb.next_sequence_number);
}
