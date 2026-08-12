// Connection- and stream-level flow control bookkeeping (RFC 9000 §4,
// §19.9-19.14): MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS credit
// queueing, the local and peer *_BLOCKED state in both directions, and
// the blocked-event surface. Free-function siblings of `Connection`'s
// method-style flow plumbing; the methods on `Connection` are thin
// thunks that delegate here. The inbound frame handlers live in
// conn_recv_flow_handlers.zig.

const std = @import("std");
const state_mod = @import("state.zig");
const conn_streams = @import("conn_streams.zig");
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
pub fn localDataBlockedAt(self: *const Connection) ?u64 {
    return self.local_data_blocked_at;
}

/// As `localDataBlockedAt` but for one specific stream's
/// stream-level send credit (would emit STREAM_DATA_BLOCKED).
pub fn localStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
    const idx = findStreamBlocked(self.local_stream_data_blocked.items, stream_id) orelse return null;
    return self.local_stream_data_blocked.items[idx].maximum_stream_data;
}

/// As `localDataBlockedAt` but for stream-count limits (would
/// emit STREAMS_BLOCKED). `bidi=true` checks bidi limits.
pub fn localStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
    return if (bidi) self.local_streams_blocked_bidi else self.local_streams_blocked_uni;
}

/// If the *peer* told us they're stuck on connection-level send
/// credit (received a DATA_BLOCKED frame), this is the limit
/// they advertised. Useful for diagnosing flow-control deadlocks.
pub fn peerDataBlockedAt(self: *const Connection) ?u64 {
    return self.peer_data_blocked_at;
}

/// As `peerDataBlockedAt` but for a single stream
/// (received STREAM_DATA_BLOCKED).
pub fn peerStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
    const idx = findStreamBlocked(self.peer_stream_data_blocked.items, stream_id) orelse return null;
    return self.peer_stream_data_blocked.items[idx].maximum_stream_data;
}

/// As `peerDataBlockedAt` but for stream-count limits
/// (received STREAMS_BLOCKED).
pub fn peerStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
    return if (bidi) self.peer_streams_blocked_bidi else self.peer_streams_blocked_uni;
}

// INTERNAL: pub for conn_streams.zig access; not part of the embedder API.
pub fn queueMaxStreamData(
    self: *Connection,
    stream_id: u64,
    maximum_stream_data: u64,
) Error!void {
    if (self.streams.get(stream_id)) |stream_ptr| {
        stream_ptr.recv_max_data = @max(stream_ptr.recv_max_data, maximum_stream_data);
    }
    clearStreamBlocked(&self.peer_stream_data_blocked, stream_id, maximum_stream_data);
    for (self.pending_frames.max_stream_data.items) |*item| {
        if (item.stream_id == stream_id) {
            if (maximum_stream_data > item.maximum_stream_data) {
                item.maximum_stream_data = maximum_stream_data;
            }
            return;
        }
    }
    try self.pending_frames.max_stream_data.append(self.allocator, .{
        .stream_id = stream_id,
        .maximum_stream_data = maximum_stream_data,
    });
}

// INTERNAL: pub for conn_streams.zig access; not part of the embedder API.
pub fn queueMaxData(self: *Connection, maximum_data: u64) void {
    if (maximum_data > self.local_max_data) self.local_max_data = maximum_data;
    if (self.peer_data_blocked_at) |limit| {
        if (maximum_data > limit) self.peer_data_blocked_at = null;
    }
    if (self.pending_frames.max_data == null or maximum_data > self.pending_frames.max_data.?) {
        self.pending_frames.max_data = maximum_data;
    }
}

pub fn shouldQueueReceiveCredit(consumed: u64, advertised: u64, window: u64) bool {
    if (consumed == 0) return false;
    const target = consumed +| window;
    if (target <= advertised) return false;
    if (consumed >= advertised) return true;
    return advertised - consumed <= window / 2;
}

pub fn queueMaxStreams(self: *Connection, bidi: bool, maximum_streams: u64) void {
    // Graceful shutdown withholds all further stream credit: the peer's
    // limit freezes at its current value, so it cannot open new streams
    // beyond what it has already been granted (RFC 9000 has no GOAWAY;
    // this is the transport-level equivalent). In-flight streams are
    // unaffected. Peer-blocked state is intentionally left set.
    if (self.graceful_shutdown) return;
    if (maximum_streams > max_stream_count_limit) return;
    const bounded_maximum_streams = @min(maximum_streams, max_streams_per_connection);
    // Early-out if the limit has not strictly advanced. RFC 9000
    // §19.11: a peer MUST ignore MAX_STREAMS that does not advance.
    // Locally we mirror that — no point clearing peer-blocked state
    // or re-queuing a frame that doesn't move the cursor.
    const current = if (bidi) self.local_max_streams_bidi else self.local_max_streams_uni;
    if (bounded_maximum_streams <= current) return;
    if (bidi) {
        self.local_max_streams_bidi = bounded_maximum_streams;
        if (self.peer_streams_blocked_bidi) |limit| {
            if (bounded_maximum_streams > limit) self.peer_streams_blocked_bidi = null;
        }
        if (self.pending_frames.max_streams_bidi == null or bounded_maximum_streams > self.pending_frames.max_streams_bidi.?) {
            self.pending_frames.max_streams_bidi = bounded_maximum_streams;
        }
    } else {
        self.local_max_streams_uni = bounded_maximum_streams;
        if (self.peer_streams_blocked_uni) |limit| {
            if (bounded_maximum_streams > limit) self.peer_streams_blocked_uni = null;
        }
        if (self.pending_frames.max_streams_uni == null or bounded_maximum_streams > self.pending_frames.max_streams_uni.?) {
            self.pending_frames.max_streams_uni = bounded_maximum_streams;
        }
    }
}

pub fn maybeReturnPeerStreamCredit(self: *Connection, s: *Stream) void {
    if (conn_streams.streamInitiatedByLocal(self, s.id)) return;
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
        maybeQueueBatchedMaxStreams(self, true);
    } else {
        maybeQueueBatchedMaxStreams(self, false);
    }
}

fn maybeQueueBatchedMaxStreams(self: *Connection, bidi: bool) void {
    const current = if (bidi) self.local_max_streams_bidi else self.local_max_streams_uni;
    if (current >= max_streams_per_connection) return;

    const opened = if (bidi) self.peer_opened_streams_bidi else self.peer_opened_streams_uni;
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
    queueMaxStreams(self, bidi, current + grant);
}

fn streamCreditReturnBatch(current_limit: u64) u64 {
    return @max(min_stream_credit_return_batch, current_limit / stream_credit_return_divisor);
}

pub fn recordFlowBlockedEvent(self: *Connection, info: FlowBlockedInfo) void {
    for (self.flow_blocked_events.slice()) |existing| {
        if (existing.source == info.source and
            existing.kind == info.kind and
            existing.limit == info.limit and
            existing.stream_id == info.stream_id and
            existing.bidi == info.bidi)
        {
            return;
        }
    }
    self.flow_blocked_events.push(info);
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

pub fn noteDataBlocked(self: *Connection, maximum_data: u64) void {
    const changed = self.local_data_blocked_at == null or self.local_data_blocked_at.? != maximum_data;
    self.local_data_blocked_at = maximum_data;
    if (changed) {
        self.pending_frames.data_blocked = maximum_data;
        recordFlowBlockedEvent(self, .{
            .source = .local,
            .kind = .data,
            .limit = maximum_data,
        });
    }
}

pub fn requeueDataBlocked(self: *Connection, maximum_data: u64) bool {
    if (self.local_data_blocked_at == null or
        self.local_data_blocked_at.? != maximum_data)
    {
        return false;
    }
    self.pending_frames.data_blocked = maximum_data;
    return true;
}

pub fn clearLocalDataBlocked(self: *Connection, new_limit: u64) void {
    if (self.local_data_blocked_at) |limit| {
        if (new_limit > limit) self.local_data_blocked_at = null;
    }
    if (self.pending_frames.data_blocked) |limit| {
        if (new_limit > limit) self.pending_frames.data_blocked = null;
    }
}

pub fn noteStreamDataBlocked(
    self: *Connection,
    stream_id: u64,
    maximum_stream_data: u64,
) Error!void {
    const item: frame_types.StreamDataBlocked = .{
        .stream_id = stream_id,
        .maximum_stream_data = maximum_stream_data,
    };
    const changed = try upsertStreamBlocked(&self.local_stream_data_blocked, self.allocator, item);
    if (changed) {
        _ = try upsertStreamBlocked(&self.pending_frames.stream_data_blocked, self.allocator, item);
        recordFlowBlockedEvent(self, .{
            .source = .local,
            .kind = .stream_data,
            .limit = maximum_stream_data,
            .stream_id = stream_id,
        });
    }
}

pub fn requeueStreamDataBlocked(
    self: *Connection,
    item: frame_types.StreamDataBlocked,
) Error!bool {
    const idx = findStreamBlocked(self.local_stream_data_blocked.items, item.stream_id) orelse return false;
    if (self.local_stream_data_blocked.items[idx].maximum_stream_data != item.maximum_stream_data) {
        return false;
    }
    _ = try upsertStreamBlocked(&self.pending_frames.stream_data_blocked, self.allocator, item);
    return true;
}

pub fn clearLocalStreamDataBlocked(
    self: *Connection,
    stream_id: u64,
    new_limit: u64,
) void {
    clearStreamBlocked(&self.local_stream_data_blocked, stream_id, new_limit);
    clearStreamBlocked(&self.pending_frames.stream_data_blocked, stream_id, new_limit);
}

pub fn noteStreamsBlocked(self: *Connection, bidi: bool, maximum_streams: u64) void {
    if (bidi) {
        const changed = self.local_streams_blocked_bidi == null or self.local_streams_blocked_bidi.? != maximum_streams;
        self.local_streams_blocked_bidi = maximum_streams;
        if (changed) {
            self.pending_frames.streams_blocked_bidi = maximum_streams;
            recordFlowBlockedEvent(self, .{
                .source = .local,
                .kind = .streams,
                .limit = maximum_streams,
                .bidi = true,
            });
        }
    } else {
        const changed = self.local_streams_blocked_uni == null or self.local_streams_blocked_uni.? != maximum_streams;
        self.local_streams_blocked_uni = maximum_streams;
        if (changed) {
            self.pending_frames.streams_blocked_uni = maximum_streams;
            recordFlowBlockedEvent(self, .{
                .source = .local,
                .kind = .streams,
                .limit = maximum_streams,
                .bidi = false,
            });
        }
    }
}

pub fn requeueStreamsBlocked(self: *Connection, item: frame_types.StreamsBlocked) bool {
    if (item.bidi) {
        if (self.local_streams_blocked_bidi == null or
            self.local_streams_blocked_bidi.? != item.maximum_streams)
        {
            return false;
        }
        self.pending_frames.streams_blocked_bidi = item.maximum_streams;
    } else {
        if (self.local_streams_blocked_uni == null or
            self.local_streams_blocked_uni.? != item.maximum_streams)
        {
            return false;
        }
        self.pending_frames.streams_blocked_uni = item.maximum_streams;
    }
    return true;
}

pub fn clearLocalStreamsBlocked(self: *Connection, bidi: bool, new_limit: u64) void {
    if (bidi) {
        if (self.local_streams_blocked_bidi) |limit| {
            if (new_limit > limit) self.local_streams_blocked_bidi = null;
        }
        if (self.pending_frames.streams_blocked_bidi) |limit| {
            if (new_limit > limit) self.pending_frames.streams_blocked_bidi = null;
        }
    } else {
        if (self.local_streams_blocked_uni) |limit| {
            if (new_limit > limit) self.local_streams_blocked_uni = null;
        }
        if (self.pending_frames.streams_blocked_uni) |limit| {
            if (new_limit > limit) self.pending_frames.streams_blocked_uni = null;
        }
    }
}
