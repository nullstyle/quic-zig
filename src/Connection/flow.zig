//! Connection- and stream-level flow control bookkeeping (RFC 9000 §4,
//! §19.9-19.14): MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS credit
//! queueing, the local and peer *_BLOCKED state in both directions, and
//! the blocked-event surface. Free-function siblings of `Connection`'s
//! method-style flow plumbing; the methods on `Connection` are thin
//! thunks that delegate here. The inbound frame handlers live in
//! Connection/recv_flow_handlers.zig.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_streams = @import("streams.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const frame_types = state_mod.frame_types;
const max_stream_count_limit = state_mod.max_stream_count_limit;
const max_streams_per_connection = state_mod.max_streams_per_connection;
const Stream = state_mod.Stream;
const FlowBlockedInfo = state_mod.FlowBlockedInfo;
const min_stream_credit_return_batch = state_mod.min_stream_credit_return_batch;
const stream_credit_return_divisor = state_mod.stream_credit_return_divisor;
const max_tracked_stream_data_blocked = state_mod.max_tracked_stream_data_blocked;

/// If the *local* sender ran out of connection-level send credit
/// (RFC 9000 §4.1) and we therefore plan to emit a DATA_BLOCKED
/// frame, this returns the limit we hit. Diagnostic only.
pub fn localDataBlockedAt(conn: *const Connection) ?u64 {
    return conn.local_data_blocked_at;
}

/// As `localDataBlockedAt` but for one specific stream's
/// stream-level send credit (would emit STREAM_DATA_BLOCKED).
pub fn localStreamDataBlockedAt(conn: *const Connection, stream_id: u64) ?u64 {
    const idx = findStreamBlocked(conn.local_stream_data_blocked.items, stream_id) orelse return null;
    return conn.local_stream_data_blocked.items[idx].maximum_stream_data;
}

/// As `localDataBlockedAt` but for stream-count limits (would
/// emit STREAMS_BLOCKED). `bidi=true` checks bidi limits.
pub fn localStreamsBlockedAt(conn: *const Connection, bidi: bool) ?u64 {
    return if (bidi) conn.local_streams_blocked_bidi else conn.local_streams_blocked_uni;
}

/// If the *peer* told us they're stuck on connection-level send
/// credit (received a DATA_BLOCKED frame), this is the limit
/// they advertised. Useful for diagnosing flow-control deadlocks.
pub fn peerDataBlockedAt(conn: *const Connection) ?u64 {
    return conn.peer_data_blocked_at;
}

/// As `peerDataBlockedAt` but for a single stream
/// (received STREAM_DATA_BLOCKED).
pub fn peerStreamDataBlockedAt(conn: *const Connection, stream_id: u64) ?u64 {
    const idx = findStreamBlocked(conn.peer_stream_data_blocked.items, stream_id) orelse return null;
    return conn.peer_stream_data_blocked.items[idx].maximum_stream_data;
}

/// As `peerDataBlockedAt` but for stream-count limits
/// (received STREAMS_BLOCKED).
pub fn peerStreamsBlockedAt(conn: *const Connection, bidi: bool) ?u64 {
    return if (bidi) conn.peer_streams_blocked_bidi else conn.peer_streams_blocked_uni;
}

// INTERNAL: pub for Connection/streams.zig access; not part of the embedder API.
pub fn queueMaxStreamData(
    conn: *Connection,
    stream_id: u64,
    maximum_stream_data: u64,
) Error!void {
    if (conn.streams.get(stream_id)) |stream_ptr| {
        stream_ptr.recv_max_data = @max(stream_ptr.recv_max_data, maximum_stream_data);
    }
    clearStreamBlocked(&conn.peer_stream_data_blocked, stream_id, maximum_stream_data);
    for (conn.pending_frames.max_stream_data.items) |*item| {
        if (item.stream_id == stream_id) {
            if (maximum_stream_data > item.maximum_stream_data) {
                item.maximum_stream_data = maximum_stream_data;
            }
            return;
        }
    }
    try conn.pending_frames.max_stream_data.append(conn.allocator, .{
        .stream_id = stream_id,
        .maximum_stream_data = maximum_stream_data,
    });
}

// INTERNAL: pub for Connection/streams.zig access; not part of the embedder API.
pub fn queueMaxData(conn: *Connection, maximum_data: u64) void {
    if (maximum_data > conn.local_max_data) conn.local_max_data = maximum_data;
    if (conn.peer_data_blocked_at) |limit| {
        if (maximum_data > limit) conn.peer_data_blocked_at = null;
    }
    if (conn.pending_frames.max_data == null or maximum_data > conn.pending_frames.max_data.?) {
        conn.pending_frames.max_data = maximum_data;
    }
}

pub fn shouldQueueReceiveCredit(consumed: u64, advertised: u64, window: u64) bool {
    if (consumed == 0) return false;
    const target = consumed +| window;
    if (target <= advertised) return false;
    if (consumed >= advertised) return true;
    return advertised - consumed <= window / 2;
}

pub fn queueMaxStreams(conn: *Connection, bidi: bool, maximum_streams: u64) void {
    // Graceful shutdown withholds all further stream credit: the peer's
    // limit freezes at its current value, so it cannot open new streams
    // beyond what it has already been granted (RFC 9000 has no GOAWAY;
    // this is the transport-level equivalent). In-flight streams are
    // unaffected. Peer-blocked state is intentionally left set.
    if (conn.graceful_shutdown) return;
    if (maximum_streams > max_stream_count_limit) return;
    const bounded_maximum_streams = @min(maximum_streams, max_streams_per_connection);
    // Early-out if the limit has not strictly advanced. RFC 9000
    // §19.11: a peer MUST ignore MAX_STREAMS that does not advance.
    // Locally we mirror that — no point clearing peer-blocked state
    // or re-queuing a frame that doesn't move the cursor.
    const current = if (bidi) conn.local_max_streams_bidi else conn.local_max_streams_uni;
    if (bounded_maximum_streams <= current) return;
    if (bidi) {
        conn.local_max_streams_bidi = bounded_maximum_streams;
        if (conn.peer_streams_blocked_bidi) |limit| {
            if (bounded_maximum_streams > limit) conn.peer_streams_blocked_bidi = null;
        }
        if (conn.pending_frames.max_streams_bidi == null or bounded_maximum_streams > conn.pending_frames.max_streams_bidi.?) {
            conn.pending_frames.max_streams_bidi = bounded_maximum_streams;
        }
    } else {
        conn.local_max_streams_uni = bounded_maximum_streams;
        if (conn.peer_streams_blocked_uni) |limit| {
            if (bounded_maximum_streams > limit) conn.peer_streams_blocked_uni = null;
        }
        if (conn.pending_frames.max_streams_uni == null or bounded_maximum_streams > conn.pending_frames.max_streams_uni.?) {
            conn.pending_frames.max_streams_uni = bounded_maximum_streams;
        }
    }
}

pub fn maybeReturnPeerStreamCredit(conn: *Connection, s: *Stream) void {
    if (conn_streams.streamInitiatedByLocal(conn, s.id)) return;
    if (s.stream_count_credit_returned) return;
    if (!(s.recv.state == .data_recvd or
        s.recv.state == .data_read or
        s.recv.state == .reset_recvd or
        s.recv.state == .reset_read))
    {
        return;
    }
    s.stream_count_credit_returned = true;
    if (conn_streams.streamIsBidi(s.id)) {
        maybeQueueBatchedMaxStreams(conn, true);
    } else {
        maybeQueueBatchedMaxStreams(conn, false);
    }
}

fn maybeQueueBatchedMaxStreams(conn: *Connection, bidi: bool) void {
    const current = if (bidi) conn.local_max_streams_bidi else conn.local_max_streams_uni;
    if (current >= max_streams_per_connection) return;

    const opened = if (bidi) conn.peer_opened_streams_bidi else conn.peer_opened_streams_uni;
    const remaining = current -| opened;
    // Fire MAX_STREAMS once the peer has consumed at least a quarter of
    // the current limit (i.e. <= 3/4 of the cap remains). The previous
    // 1/2 watermark waited until the peer had drained 50% of the cap
    // before granting more, which left no room for an aggressively
    // pipelining peer (notably quiche) to keep going — by the time our
    // credit reached them they had already exhausted the 1000-stream
    // initial allotment the multiplexing interop testcase requires
    // (`initial_max_streams_bidi <= 1000`,
    // `quic-interop-runner/testcases_quic.py:286-288`). Dropping the
    // watermark to 1/4-consumed gives ~3 RTTs of headroom at typical
    // burst rates before the peer actually hits the cap, while still
    // batching enough closes per frame to keep MAX_STREAMS traffic low.
    const watermark = (current * 3) / 4;
    if (remaining > watermark) return;

    const batch = streamCreditReturnBatch(current);
    const grant = @min(batch, max_streams_per_connection - current);
    queueMaxStreams(conn, bidi, current + grant);
}

fn streamCreditReturnBatch(current_limit: u64) u64 {
    return @max(min_stream_credit_return_batch, current_limit / stream_credit_return_divisor);
}

pub fn recordFlowBlockedEvent(conn: *Connection, info: FlowBlockedInfo) void {
    for (conn.flow_blocked_events.slice()) |existing| {
        if (existing.source == info.source and
            existing.kind == info.kind and
            existing.limit == info.limit and
            existing.stream_id == info.stream_id and
            existing.bidi == info.bidi)
        {
            return;
        }
    }
    conn.flow_blocked_events.push(info);
}

fn findStreamBlocked(
    list: []const frame_types.StreamDataBlocked,
    stream_id: u64,
) ?usize {
    for (list, 0..) |item, i| {
        if (item.stream_id == stream_id) return i;
    }
    return null;
}

pub fn upsertStreamBlocked(
    list: *std.ArrayList(frame_types.StreamDataBlocked),
    allocator: std.mem.Allocator,
    item: frame_types.StreamDataBlocked,
) Error!bool {
    if (findStreamBlocked(list.items, item.stream_id)) |idx| {
        if (list.items[idx].maximum_stream_data == item.maximum_stream_data) return false;
        list.items[idx].maximum_stream_data = item.maximum_stream_data;
        return true;
    }
    if (list.items.len >= max_tracked_stream_data_blocked) return Error.StreamLimitExceeded;
    try list.append(allocator, item);
    return true;
}

fn clearStreamBlocked(
    list: *std.ArrayList(frame_types.StreamDataBlocked),
    stream_id: u64,
    new_limit: u64,
) void {
    const idx = findStreamBlocked(list.items, stream_id) orelse return;
    if (new_limit > list.items[idx].maximum_stream_data) {
        _ = list.orderedRemove(idx);
    }
}

pub fn noteDataBlocked(conn: *Connection, maximum_data: u64) void {
    const changed = conn.local_data_blocked_at == null or conn.local_data_blocked_at.? != maximum_data;
    conn.local_data_blocked_at = maximum_data;
    if (changed) {
        conn.pending_frames.data_blocked = maximum_data;
        recordFlowBlockedEvent(conn, .{
            .source = .local,
            .kind = .data,
            .limit = maximum_data,
        });
    }
}

pub fn requeueDataBlocked(conn: *Connection, maximum_data: u64) bool {
    if (conn.local_data_blocked_at == null or
        conn.local_data_blocked_at.? != maximum_data)
    {
        return false;
    }
    conn.pending_frames.data_blocked = maximum_data;
    return true;
}

pub fn clearLocalDataBlocked(conn: *Connection, new_limit: u64) void {
    if (conn.local_data_blocked_at) |limit| {
        if (new_limit > limit) conn.local_data_blocked_at = null;
    }
    if (conn.pending_frames.data_blocked) |limit| {
        if (new_limit > limit) conn.pending_frames.data_blocked = null;
    }
}

pub fn noteStreamDataBlocked(
    conn: *Connection,
    stream_id: u64,
    maximum_stream_data: u64,
) Error!void {
    const item: frame_types.StreamDataBlocked = .{
        .stream_id = stream_id,
        .maximum_stream_data = maximum_stream_data,
    };
    const changed = try upsertStreamBlocked(&conn.local_stream_data_blocked, conn.allocator, item);
    if (changed) {
        _ = try upsertStreamBlocked(&conn.pending_frames.stream_data_blocked, conn.allocator, item);
        recordFlowBlockedEvent(conn, .{
            .source = .local,
            .kind = .stream_data,
            .limit = maximum_stream_data,
            .stream_id = stream_id,
        });
    }
}

pub fn requeueStreamDataBlocked(
    conn: *Connection,
    item: frame_types.StreamDataBlocked,
) Error!bool {
    const idx = findStreamBlocked(conn.local_stream_data_blocked.items, item.stream_id) orelse return false;
    if (conn.local_stream_data_blocked.items[idx].maximum_stream_data != item.maximum_stream_data) {
        return false;
    }
    _ = try upsertStreamBlocked(&conn.pending_frames.stream_data_blocked, conn.allocator, item);
    return true;
}

pub fn clearLocalStreamDataBlocked(
    conn: *Connection,
    stream_id: u64,
    new_limit: u64,
) void {
    clearStreamBlocked(&conn.local_stream_data_blocked, stream_id, new_limit);
    clearStreamBlocked(&conn.pending_frames.stream_data_blocked, stream_id, new_limit);
}

pub fn noteStreamsBlocked(conn: *Connection, bidi: bool, maximum_streams: u64) void {
    if (bidi) {
        const changed = conn.local_streams_blocked_bidi == null or conn.local_streams_blocked_bidi.? != maximum_streams;
        conn.local_streams_blocked_bidi = maximum_streams;
        if (changed) {
            conn.pending_frames.streams_blocked_bidi = maximum_streams;
            recordFlowBlockedEvent(conn, .{
                .source = .local,
                .kind = .streams,
                .limit = maximum_streams,
                .bidi = true,
            });
        }
    } else {
        const changed = conn.local_streams_blocked_uni == null or conn.local_streams_blocked_uni.? != maximum_streams;
        conn.local_streams_blocked_uni = maximum_streams;
        if (changed) {
            conn.pending_frames.streams_blocked_uni = maximum_streams;
            recordFlowBlockedEvent(conn, .{
                .source = .local,
                .kind = .streams,
                .limit = maximum_streams,
                .bidi = false,
            });
        }
    }
}

pub fn requeueStreamsBlocked(conn: *Connection, item: frame_types.StreamsBlocked) bool {
    if (item.bidi) {
        if (conn.local_streams_blocked_bidi == null or
            conn.local_streams_blocked_bidi.? != item.maximum_streams)
        {
            return false;
        }
        conn.pending_frames.streams_blocked_bidi = item.maximum_streams;
    } else {
        if (conn.local_streams_blocked_uni == null or
            conn.local_streams_blocked_uni.? != item.maximum_streams)
        {
            return false;
        }
        conn.pending_frames.streams_blocked_uni = item.maximum_streams;
    }
    return true;
}

pub fn clearLocalStreamsBlocked(conn: *Connection, bidi: bool, new_limit: u64) void {
    if (bidi) {
        if (conn.local_streams_blocked_bidi) |limit| {
            if (new_limit > limit) conn.local_streams_blocked_bidi = null;
        }
        if (conn.pending_frames.streams_blocked_bidi) |limit| {
            if (new_limit > limit) conn.pending_frames.streams_blocked_bidi = null;
        }
    } else {
        if (conn.local_streams_blocked_uni) |limit| {
            if (new_limit > limit) conn.local_streams_blocked_uni = null;
        }
        if (conn.pending_frames.streams_blocked_uni) |limit| {
            if (new_limit > limit) conn.pending_frames.streams_blocked_uni = null;
        }
    }
}
