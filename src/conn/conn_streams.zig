// The stream layer of Connection: open/accept + stream-id algebra,
// per-direction limits and accounting, GC of fully-closed streams, the
// embedder-facing read/write/priority API, and stream termination
// (FIN / RESET_STREAM / STOP_SENDING). RFC 9000 §2-3, §19; RFC 9218
// priorities. Free-function siblings of `Connection`'s method-style
// stream API; the methods on `Connection` are thin thunks that
// delegate here.

const std = @import("std");
const state_mod = @import("state.zig");
const conn_flow = @import("conn_flow.zig");
const conn_qlog = @import("conn_qlog.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Stream = state_mod.Stream;
const StreamPriority = state_mod.StreamPriority;
const StreamType = state_mod.StreamType;
const StreamSendStats = state_mod.StreamSendStats;
const StreamReadResult = state_mod.StreamReadResult;
const StreamRecvState = state_mod.StreamRecvState;
const send_stream_mod = state_mod.send_stream_mod;
const SendStream = state_mod.SendStream;
const RecvStream = state_mod.RecvStream;
const StopSendingItem = state_mod.StopSendingItem;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const recv_stream_mod = state_mod.recv_stream_mod;
const max_stream_count_limit = state_mod.max_stream_count_limit;
const max_streams_per_connection = state_mod.max_streams_per_connection;
const default_stream_receive_window = state_mod.default_stream_receive_window;
const default_connection_receive_window = state_mod.default_connection_receive_window;
const transport_error_stream_limit = state_mod.transport_error_stream_limit;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

// Doc comment lives on the `Connection.openBidi` thunk in state.zig.
pub fn openBidi(self: *Connection, id: u64) Error!*Stream {
    if (!streamIsBidi(id) or !streamInitiatedByLocal(self, id)) return Error.InvalidStreamId;
    if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
    try recordLocalStreamOpen(self, id);
    return try openStream(self, id);
}

// Doc comment lives on the `Connection.openUni` thunk in state.zig.
pub fn openUni(self: *Connection, id: u64) Error!*Stream {
    if (!streamIsUni(id) or !streamInitiatedByLocal(self, id)) return Error.InvalidStreamId;
    if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
    try recordLocalStreamOpen(self, id);
    return try openStream(self, id);
}

// Doc comment lives on the `Connection.localStreamType` thunk in state.zig.
pub fn localStreamType(self: *const Connection, uni: bool) StreamType {
    return switch (self.role) {
        .client => if (uni) .client_uni else .client_bidi,
        .server => if (uni) .server_uni else .server_bidi,
    };
}

// Doc comment lives on the `Connection.openNextBidi` thunk in state.zig.
pub fn openNextBidi(self: *Connection) Error!*Stream {
    return openBidi(self, localStreamType(self, false).streamId(self.local_opened_streams_bidi));
}

// Doc comment lives on the `Connection.openNextUni` thunk in state.zig.
pub fn openNextUni(self: *Connection) Error!*Stream {
    return openUni(self, localStreamType(self, true).streamId(self.local_opened_streams_uni));
}

/// The stream id `openNextBidi` would use next, without opening anything
/// or advancing the counter. Lets an embedder learn the id up front — e.g.
/// to run an HTTP/3 GOAWAY / stream-limit gate keyed on the id *before*
/// committing to the open, then call `openNextBidi`. The returned id is
/// only valid until the next successful local bidi open on this
/// connection (`openNextBidi` or an `openBidi` at or above this id).
pub fn peekNextBidi(self: *const Connection) u64 {
    return localStreamType(self, false).streamId(self.local_opened_streams_bidi);
}

/// The stream id `openNextUni` would use next, without opening anything or
/// advancing the counter. Same validity caveat as `peekNextBidi`.
pub fn peekNextUni(self: *const Connection) u64 {
    return localStreamType(self, true).streamId(self.local_opened_streams_uni);
}

fn openStream(self: *Connection, id: u64) Error!*Stream {
    if (self.streams.contains(id)) return Error.StreamAlreadyOpen;
    const ptr = try self.allocator.create(Stream);
    errdefer self.allocator.destroy(ptr);
    ptr.* = .{
        .id = id,
        .send = SendStream.init(self.allocator),
        .recv = RecvStream.init(self.allocator),
        .recv_max_data = initialRecvStreamLimit(self, id),
        .send_max_data = initialSendStreamLimit(self, id),
    };
    try self.streams.put(self.allocator, id, ptr);
    conn_qlog.emitQlog(self, .{
        .name = .stream_state_updated,
        .stream_id = id,
        .stream_state = .open,
    });
    return ptr;
}

pub fn streamIsBidi(id: u64) bool {
    return (id & 0b10) == 0;
}

fn streamIsUni(id: u64) bool {
    return !streamIsBidi(id);
}

pub fn streamIndex(id: u64) u64 {
    return id >> 2;
}

fn streamInitiatedByClient(id: u64) bool {
    return (id & 0b01) == 0;
}

pub fn streamInitiatedByLocal(self: *const Connection, id: u64) bool {
    return streamInitiatedByClient(id) == (self.role == .client);
}

pub fn localMaySendOnStream(self: *const Connection, id: u64) bool {
    if (streamIsBidi(id)) return true;
    return streamInitiatedByLocal(self, id);
}

pub fn peerMaySendOnStream(self: *const Connection, id: u64) bool {
    if (streamIsBidi(id)) return true;
    return !streamInitiatedByLocal(self, id);
}

pub fn initialRecvStreamLimit(self: *const Connection, id: u64) u64 {
    const params = self.local_transport_params;
    if (streamIsUni(id)) {
        if (streamInitiatedByLocal(self, id)) return 0;
        return params.initial_max_stream_data_uni;
    }
    if (streamInitiatedByLocal(self, id)) {
        return params.initial_max_stream_data_bidi_local;
    }
    return params.initial_max_stream_data_bidi_remote;
}

pub fn initialSendStreamLimit(self: *const Connection, id: u64) u64 {
    // Prefer the real cached peer params; before they arrive, bound
    // early-data (0-RTT) sends by the embedder-supplied remembered
    // session params. With neither available, only a 0-RTT send
    // window is legitimate at all: grant the (client-self-limited)
    // unbounded window when early-data write keys are present, and
    // nothing otherwise — a non-0-RTT connection never sends
    // application stream data before its params are cached.
    // applyPeerFlowTransportParams later @max-raises each stream's
    // send_max_data to the true limit once the real params land.
    const params = self.cached_peer_transport_params orelse
        self.remembered_peer_transport_params orelse
        {
            if (self.haveSecret(.early_data, .write)) return std.math.maxInt(u64);
            return 0;
        };
    if (streamIsUni(id)) {
        if (!streamInitiatedByLocal(self, id)) return 0;
        return params.initial_max_stream_data_uni;
    }
    if (streamInitiatedByLocal(self, id)) {
        return params.initial_max_stream_data_bidi_remote;
    }
    return params.initial_max_stream_data_bidi_local;
}

fn recordLocalStreamOpen(self: *Connection, id: u64) Error!void {
    // During graceful shutdown we open no new local streams; in-flight
    // streams keep draining. Single chokepoint for openBidi/openUni and
    // the openNext* helpers.
    if (self.graceful_shutdown) return Error.ShuttingDown;
    const idx = streamIndex(id);
    if (idx >= max_stream_count_limit) return Error.InvalidStreamId;
    const next = idx + 1;
    if (streamIsBidi(id)) {
        if (idx >= self.peer_max_streams_bidi) {
            self.noteStreamsBlocked(true, self.peer_max_streams_bidi);
            return Error.StreamLimitExceeded;
        }
        if (next > self.local_opened_streams_bidi) self.local_opened_streams_bidi = next;
    } else {
        if (idx >= self.peer_max_streams_uni) {
            self.noteStreamsBlocked(false, self.peer_max_streams_uni);
            return Error.StreamLimitExceeded;
        }
        if (next > self.local_opened_streams_uni) self.local_opened_streams_uni = next;
    }
}

pub fn recordPeerStreamOpenOrClose(self: *Connection, id: u64) bool {
    const idx = streamIndex(id);
    if (idx >= max_stream_count_limit) {
        self.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
        return false;
    }
    const next = idx + 1;
    if (streamIsBidi(id)) {
        if (idx >= self.local_max_streams_bidi) {
            self.close(true, transport_error_stream_limit, "peer exceeded bidirectional stream limit");
            return false;
        }
        if (next > self.peer_opened_streams_bidi) self.peer_opened_streams_bidi = next;
    } else {
        if (idx >= self.local_max_streams_uni) {
            self.close(true, transport_error_stream_limit, "peer exceeded unidirectional stream limit");
            return false;
        }
        if (next > self.peer_opened_streams_uni) self.peer_opened_streams_uni = next;
    }
    return true;
}

/// True if `id` is a peer-initiated stream that was already opened,
/// driven to a terminal state, and reclaimed. A STREAM/RESET_STREAM for
/// such an id is a post-terminal frame that MUST be ignored (RFC 9000
/// §3.2) rather than resurrecting the stream. Only meaningful for
/// peer-initiated ids; callers gate on an absent, peer-initiated stream
/// first.
///
/// Two cases: below the contiguous watermark (a run of reaped indices
/// coalesced from the bottom), OR reaped-but-above the watermark because
/// a lower peer stream is still live — the latter is tracked individually
/// by its reaped bit until the watermark coalesces past it.
pub fn peerStreamAlreadyReaped(self: *const Connection, id: u64) bool {
    const idx = streamIndex(id);
    const bidi = streamIsBidi(id);
    if (idx < (if (bidi) self.peer_reaped_below_bidi else self.peer_reaped_below_uni)) return true;
    if (idx >= max_streams_per_connection) return false;
    const bits = if (bidi) &self.peer_reaped_bits_bidi else &self.peer_reaped_bits_uni;
    return bits.isSet(@intCast(idx));
}

/// Record that a peer-initiated stream was reaped, advancing the
/// contiguous reaped watermark. Local streams are ignored (their
/// absence is handled by the "peer referenced unopened local stream"
/// guards). Sets the index's bit, then advances the watermark past
/// any consecutive run of reaped indices from the bottom.
fn notePeerStreamReaped(self: *Connection, id: u64) void {
    if (streamInitiatedByLocal(self, id)) return;
    const idx = streamIndex(id);
    // Bounded by local_max_streams_* <= max_streams_per_connection.
    std.debug.assert(idx < max_streams_per_connection);
    const bidi = streamIsBidi(id);
    const bits = if (bidi) &self.peer_reaped_bits_bidi else &self.peer_reaped_bits_uni;
    const below = if (bidi) &self.peer_reaped_below_bidi else &self.peer_reaped_below_uni;
    const opened = if (bidi) self.peer_opened_streams_bidi else self.peer_opened_streams_uni;
    bits.set(@intCast(idx));
    // Coalesce: advance the watermark across consecutive reaped bits.
    // The `< opened` guard is load-bearing for paths that reap a
    // stream without bumping peer_opened_streams_* (e.g. direct-put
    // test setup); it keeps the loop trivially in range too.
    while (below.* < opened and bits.isSet(@intCast(below.*))) {
        bits.unset(@intCast(below.*));
        below.* += 1;
    }
}

pub fn peerStreamWithinLocalLimit(self: *Connection, id: u64) bool {
    const idx = streamIndex(id);
    if (idx >= max_stream_count_limit) {
        self.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
        return false;
    }
    if (streamIsBidi(id)) {
        if (idx >= self.local_max_streams_bidi) {
            self.close(true, transport_error_stream_limit, "peer referenced bidirectional stream above limit");
            return false;
        }
    } else {
        if (idx >= self.local_max_streams_uni) {
            self.close(true, transport_error_stream_limit, "peer referenced unidirectional stream above limit");
            return false;
        }
    }
    return true;
}

pub fn limitChunkToSendFlow(
    self: *Connection,
    s: *const Stream,
    chunk: send_stream_mod.Chunk,
) Error!?send_stream_mod.Chunk {
    return limitChunkToSendFlowAfterPlanned(self, s, chunk, 0);
}

pub fn limitChunkToSendFlowAfterPlanned(
    self: *Connection,
    s: *const Stream,
    chunk: send_stream_mod.Chunk,
    planned_conn_new_bytes: u64,
) Error!?send_stream_mod.Chunk {
    if (!localMaySendOnStream(self, s.id)) return null;
    if (chunk.length == 0) return chunk;

    const chunk_end = std.math.add(u64, chunk.offset, chunk.length) catch return null;
    const wants_new_data = chunk_end > s.send_flow_highest;
    const stream_new_allowance = if (s.send_flow_highest >= s.send_max_data)
        0
    else
        s.send_max_data - s.send_flow_highest;
    const planned_conn_sent = self.we_sent_stream_data +| planned_conn_new_bytes;
    const conn_new_allowance = if (planned_conn_sent >= self.peer_max_data)
        0
    else
        self.peer_max_data - planned_conn_sent;
    if (wants_new_data and stream_new_allowance == 0) {
        try self.noteStreamDataBlocked(s.id, s.send_max_data);
    }
    if (wants_new_data and conn_new_allowance == 0) {
        self.noteDataBlocked(self.peer_max_data);
    }
    const new_allowance = @min(stream_new_allowance, conn_new_allowance);

    const retransmit_end = if (chunk.offset < s.send_flow_highest)
        @min(chunk_end, s.send_flow_highest)
    else
        chunk.offset;
    const allowed_end = retransmit_end +| new_allowance;
    const send_end = @min(chunk_end, allowed_end);
    if (send_end <= chunk.offset) return null;

    var limited = chunk;
    limited.length = send_end - chunk.offset;
    limited.fin = chunk.fin and send_end == chunk_end;
    return limited;
}

pub fn streamFlowNewBytes(s: *const Stream, chunk: send_stream_mod.Chunk) u64 {
    const end = std.math.add(u64, chunk.offset, chunk.length) catch return 0;
    if (end <= s.send_flow_highest) return 0;
    return end - s.send_flow_highest;
}

pub fn recordStreamFlowSent(self: *Connection, s: *Stream, chunk: send_stream_mod.Chunk) void {
    const end = std.math.add(u64, chunk.offset, chunk.length) catch return;
    if (end <= s.send_flow_highest) return;
    const delta = end - s.send_flow_highest;
    s.send_flow_highest = end;
    self.we_sent_stream_data += delta;
}

// Doc comment lives on the `Connection.streamIterator` thunk in state.zig.
pub fn streamIterator(self: *Connection) std.AutoHashMapUnmanaged(u64, *Stream).Iterator {
    return self.streams.iterator();
}

/// Number of currently-open streams.
pub fn streamCount(self: *const Connection) usize {
    return self.streams.count();
}

/// Reclaim entries in `self.streams` whose lifecycle is fully
/// terminated in both the relevant directions. Without this the
/// map grows monotonically with the number of streams the
/// connection has ever seen — a long-lived HTTP/3 session that
/// opens many short request streams would accumulate `Stream`
/// state (recv reassembly, send chunk ring, ACK ranges) for
/// every closed-and-forgotten stream until `Connection.deinit`.
///
/// Reclaim criterion (RFC 9000 §3.1 / §3.2 stream lifecycle):
/// - bidi streams: both `send.isTerminal()` and
///   `recvFullyTerminated()` are true.
/// - uni streams the local opened: only the send side is used
///   (`recv_max_data == 0`), so just `send.isTerminal()`.
/// - uni streams the peer opened: only the recv side is used,
///   so just `recvFullyTerminated()`.
///
/// The send-terminal states are `data_recvd` (FIN ACKed) and
/// `reset_recvd` (peer ACKed our RESET_STREAM); the recv-
/// terminal states are `data_recvd`/`data_read` (peer FIN seen
/// and bytes drained) and `reset_recvd`/`reset_read` (peer
/// RESET_STREAM seen). At the moment all of those land, no
/// further frames can advance the stream — the per-stream
/// flow-control window, ACK tracker, and reassembly metadata
/// are dead weight.
///
/// Iteration safety: HashMap iteration invalidates on mutation,
/// so we collect ids in a small fixed-size buffer per pass and
/// only `fetchRemove` once iteration completes. If more than
/// `batch.len` streams reclaim in one tick (rare), the surplus
/// rolls to the next tick — still bounded, just not in one
/// shot.
///
/// Resident-bytes budget: `Stream.send.bytes` and
/// `Stream.recv.bytes` may still hold capacity that
/// `tryReserveResidentBytes` is tracking. We snapshot the live
/// `items.len` before destruction and release that count back
/// to the budget so a long-lived connection that GCs many
/// streams does not leak budget headroom.
pub fn gcClosedStreams(self: *Connection) void {
    var batch: [128]u64 = undefined;
    var n: usize = 0;
    var it = self.streams.iterator();
    while (it.next()) |entry| {
        const s = entry.value_ptr.*;
        const send_done = s.send.isTerminal();
        const recv_done = s.recvFullyTerminated();
        const reclaimable = if (streamIsBidi(s.id))
            send_done and recv_done
        else if (streamInitiatedByLocal(self, s.id))
            send_done
        else
            recv_done;
        if (!reclaimable) continue;
        if (n == batch.len) break;
        batch[n] = s.id;
        n += 1;
    }
    for (batch[0..n]) |id| {
        const removed = self.streams.fetchRemove(id) orelse continue;
        const s = removed.value;
        // Record the reap so a later STREAM/RESET_STREAM for this
        // peer-initiated id is treated as post-terminal (RFC 9000
        // §3.2) instead of resurrecting the stream with fresh state.
        notePeerStreamReaped(self, id);
        const held = s.send.bytes.items.len + s.recv.bytes.items.len;
        if (held > 0) self.releaseResidentBytes(held);
        conn_qlog.emitQlog(self, .{
            .name = .stream_state_updated,
            .stream_id = id,
            .stream_state = if (s.send.state == .reset_recvd or
                s.recv.state == .reset_recvd or
                s.recv.state == .reset_read)
                .reset
            else
                .closed,
        });
        s.send.deinit();
        s.recv.deinit();
        self.allocator.destroy(s);
    }
}

/// Pick the next available server-initiated unidirectional
/// stream id (low 2 bits = 0b11) starting from `start`. Skips
/// ids that are already open.
pub fn nextServerUniId(self: *const Connection, start: u64) u64 {
    var id = start | 0b11;
    while (self.streams.contains(id)) id += 4;
    return id;
}

/// Pick the next available server-initiated bidi stream id
/// (low 2 bits = 0b01). Skips ids already open.
pub fn nextServerBidiId(self: *const Connection, start: u64) u64 {
    var id = (start & ~@as(u64, 0b11)) | 0b01;
    while (self.streams.contains(id)) id += 4;
    return id;
}

// Doc comment lives on the `Connection.stream` thunk in state.zig.
pub fn stream(self: *const Connection, id: u64) ?*Stream {
    return self.streams.get(id);
}

// Doc comment lives on the `Connection.streamSendStats` thunk in state.zig.
pub fn streamSendStats(self: *const Connection, id: u64) ?StreamSendStats {
    const s = self.streams.get(id) orelse return null;
    const written = s.send.writtenBytes();
    const acked = s.send.ackedFloor();
    return .{
        .written = written,
        .acked = acked,
        .buffered = written - acked,
        .has_pending = s.send.hasPendingChunk(),
    };
}

// Doc comment lives on the `Connection.streamSetPriority` thunk in state.zig.
pub fn streamSetPriority(self: *Connection, id: u64, p: StreamPriority) Error!void {
    const s = self.streams.get(id) orelse return Error.StreamNotFound;
    s.priority = p;
}

// Doc comment lives on the `Connection.streamPriority` thunk in state.zig.
pub fn streamPriority(self: *const Connection, id: u64) ?StreamPriority {
    const s = self.streams.get(id) orelse return null;
    return s.priority;
}

/// Collect pointers to streams with pending send data, ordered by RFC 9218
/// priority (urgency asc, then stream id asc), into `buf`. Bounded to
/// `buf.len` — the per-packet chunk cap — so if more streams are ready than
/// fit one packet, the highest-priority `buf.len` are returned and the rest
/// are served on a later packet. Returns the filled prefix.
///
/// INTERNAL: pub for `_state_tests.zig` access; not part of the embedder
/// API (the scheduling it drives is observed through `pollDatagram`).
pub fn collectSendableStreamsByPriority(self: *Connection, buf: []*Stream) []*Stream {
    var n: usize = 0;
    var it = self.streams.iterator();
    while (it.next()) |entry| {
        const s = entry.value_ptr.*;
        if (!s.send.hasPendingChunk()) continue;
        insertStreamByPriority(buf, &n, s, self.priority_rr_cursor);
    }
    const result = buf[0..n];
    // Advance the round-robin cursor past the incremental stream that
    // leads this packet, so the next incremental stream of the same urgency
    // leads the next one. Non-incremental streams don't move the cursor.
    for (result) |s| {
        if (s.priority.incremental) {
            self.priority_rr_cursor = s.id +% 1;
            break;
        }
    }
    return result;
}

// Doc comment lives on the `Connection.streamRecvState` thunk in state.zig.
pub fn streamRecvState(self: *const Connection, id: u64) ?StreamRecvState {
    const s = self.streams.get(id) orelse return null;
    return .{
        .fin_seen = s.recv.fin_seen,
        .reset_seen = s.recv.reset != null,
        .terminal = s.recvFullyTerminated(),
    };
}

// Doc comment lives on the `Connection.streamWrite` thunk in state.zig.
pub fn streamWrite(self: *Connection, id: u64, data: []const u8) Error!usize {
    const s = self.streams.get(id) orelse return Error.StreamNotFound;
    // Hardening guide §3.5 / §8: pre-flight the resident-bytes
    // budget against the bytes we'd accept. The per-stream
    // `max_buffered` cap already gates a single stream; this
    // shares one budget with CRYPTO / DATAGRAM / recv reassembly
    // so opening many streams each near their per-stream cap
    // can't bypass the connection-wide ceiling.
    const before = s.send.bytes.items.len;
    const headroom = s.send.max_buffered -| before;
    const want = @min(data.len, headroom);
    if (want > 0) {
        try self.tryReserveResidentBytes(want);
    }
    const accepted = s.send.write(data) catch |err| {
        self.releaseResidentBytes(want);
        return err;
    };
    // `write` may accept fewer bytes than `want` if it short-writes
    // (e.g. on its own internal cap); reconcile so we only hold
    // budget for what actually landed in the buffer.
    if (accepted < want) {
        self.releaseResidentBytes(want - accepted);
    }
    return accepted;
}

// Doc comment lives on the `Connection.streamRead` thunk in state.zig.
pub fn streamRead(self: *Connection, id: u64, dst: []u8) Error!usize {
    const s = self.streams.get(id) orelse return Error.StreamNotFound;
    const before = s.recv.bytes.items.len;
    const n = s.recv.read(dst);
    // Hardening guide §3.5 / §8: every byte the app drains is
    // bytes the connection no longer holds in its recv buffer.
    // `RecvStream.read` shifts the buffer down and shrinks it to
    // exactly the live tail, so the delta is the bytes actually
    // freed.
    if (s.recv.bytes.items.len < before) {
        self.releaseResidentBytes(before - s.recv.bytes.items.len);
    }
    if (n > 0) {
        self.recv_stream_bytes_read += n;
        if (Connection.shouldQueueReceiveCredit(
            s.recv.read_offset,
            s.recv_max_data,
            default_stream_receive_window,
        )) {
            try conn_flow.queueMaxStreamData(self, id, s.recv.read_offset +| default_stream_receive_window);
        }
        if (Connection.shouldQueueReceiveCredit(
            self.recv_stream_bytes_read,
            self.local_max_data,
            default_connection_receive_window,
        )) {
            conn_flow.queueMaxData(self, self.recv_stream_bytes_read +| default_connection_receive_window);
        }
    }
    conn_flow.maybeReturnPeerStreamCredit(self, s);
    return n;
}

// Doc comment lives on the `Connection.streamReadFin` thunk in state.zig.
pub fn streamReadFin(self: *Connection, id: u64, dst: []u8) Error!StreamReadResult {
    const n = try streamRead(self, id, dst);
    // `streamRead` already returned `StreamNotFound` if the stream was
    // absent, and reaping (`gcClosedStreams`) runs only in `tick`, so the
    // stream is still live here; the `else` is a defensive dead branch.
    const fin = if (self.streams.get(id)) |s| s.recv.fin_seen else false;
    return .{ .n = n, .fin = fin };
}

/// Whether the receive side of `id` has seen any STREAM bytes in
/// 0-RTT. Returns null for an unknown stream.
pub fn streamArrivedInEarlyData(self: *const Connection, id: u64) ?bool {
    const s = self.streams.get(id) orelse return null;
    return s.arrived_in_early_data;
}

// Doc comment lives on the `Connection.streamFinish` thunk in state.zig.
pub fn streamFinish(self: *Connection, id: u64) Error!void {
    const s = self.streams.get(id) orelse return Error.StreamNotFound;
    try s.send.finish();
}

// Doc comment lives on the `Connection.streamReset` thunk in state.zig.
pub fn streamReset(
    self: *Connection,
    id: u64,
    application_error_code: u64,
) Error!void {
    const s = self.streams.get(id) orelse return Error.StreamNotFound;
    try s.send.resetStream(application_error_code);
}

// Doc comment lives on the `Connection.streamStopSending` thunk in state.zig.
pub fn streamStopSending(
    self: *Connection,
    stream_id: u64,
    application_error_code: u64,
) Error!void {
    try queueStopSending(self, .{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    });
}

pub fn queueStopSending(
    self: *Connection,
    item: StopSendingItem,
) Error!void {
    for (self.pending_frames.stop_sending.items) |queued| {
        if (queued.stream_id == item.stream_id and
            queued.application_error_code == item.application_error_code)
        {
            return;
        }
    }
    try self.pending_frames.stop_sending.append(self.allocator, .{
        .stream_id = item.stream_id,
        .application_error_code = item.application_error_code,
    });
}

/// Ordering for the RFC 9218 send scheduler. Lower urgency first (more
/// urgent). Within an urgency band (RFC 9218 §10): non-incremental streams
/// lead, in ascending stream-id order (head-of-line — serve each to
/// completion); then incremental streams, round-robined by distance from
/// `rr_cursor` so a different one leads each packet. With no explicit
/// priorities every stream is non-incremental urgency 3, so this is plain
/// stream-id order.
fn streamPriorityLess(a: *const Stream, b: *const Stream, rr_cursor: u64) bool {
    if (a.priority.urgency != b.priority.urgency) return a.priority.urgency < b.priority.urgency;
    if (a.priority.incremental != b.priority.incremental) return !a.priority.incremental;
    if (!a.priority.incremental) return a.id < b.id;
    return (a.id -% rr_cursor) < (b.id -% rr_cursor);
}

/// Insert `s` into the priority-sorted (best first) bounded buffer
/// `buf[0..n.*]`. When the buffer is full, `s` displaces the current worst
/// only if it ranks strictly higher, so the buffer always holds the
/// top-`buf.len` streams by priority.
fn insertStreamByPriority(buf: []*Stream, n: *usize, s: *Stream, rr_cursor: u64) void {
    if (n.* == buf.len) {
        if (!streamPriorityLess(s, buf[n.* - 1], rr_cursor)) return;
    } else {
        n.* += 1;
    }
    var i = n.* - 1;
    while (i > 0 and streamPriorityLess(s, buf[i - 1], rr_cursor)) : (i -= 1) {
        buf[i] = buf[i - 1];
    }
    buf[i] = s;
}
