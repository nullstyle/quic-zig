//! The stream layer of Connection: open/accept + stream-id algebra,
//! per-direction limits and accounting, GC of fully-closed streams, the
//! embedder-facing read/write/priority API, and stream termination
//! (FIN / RESET_STREAM / STOP_SENDING). RFC 9000 §2-3, §19; RFC 9218
//! priorities. Free-function siblings of `Connection`'s method-style
//! stream API; the methods on `Connection` are thin thunks that
//! delegate here.

const std = @import("std");
const builtin = @import("builtin");
const state_mod = @import("../Connection.zig");
const conn_flow = @import("flow.zig");
const conn_qlog = @import("qlog.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Stream = state_mod.Stream;
const StreamPriority = state_mod.StreamPriority;
const StreamType = state_mod.StreamType;
const StreamSendStats = state_mod.StreamSendStats;
const StreamReadResult = state_mod.StreamReadResult;
const StreamRecvState = state_mod.StreamRecvState;
const StreamRecvEnd = state_mod.StreamRecvEnd;
const RecvEndRing = state_mod.RecvEndRing;
const send_stream_mod = state_mod.send_stream_mod;
const SendStream = state_mod.SendStream;
const RecvStream = state_mod.RecvStream;
const StopSendingItem = state_mod.StopSendingItem;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const recv_stream_mod = state_mod.recv_stream_mod;
const max_stream_count_limit = state_mod.max_stream_count_limit;
const max_local_skipped_stream_ranges = state_mod.max_local_skipped_stream_ranges;
const StreamIdSpace = @import("../conn/StreamIdSpace.zig");
const transport_error_stream_limit = state_mod.transport_error_stream_limit;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

// Doc comment lives on the `Connection.openBidi` thunk in Connection.zig.
pub fn openBidi(conn: *Connection, id: u64) Error!*Stream {
    if (!streamIsBidi(id) or !streamInitiatedByLocal(conn, id)) return Error.InvalidStreamId;
    return openLocalStream(conn, id);
}

// Doc comment lives on the `Connection.openUni` thunk in Connection.zig.
pub fn openUni(conn: *Connection, id: u64) Error!*Stream {
    if (!streamIsUni(id) or !streamInitiatedByLocal(conn, id)) return Error.InvalidStreamId;
    return openLocalStream(conn, id);
}

/// Shared tail of `openBidi` / `openUni` (and so of the `openNext*`
/// helpers): `id` is a local id of the right kind.
///
/// The order of the checks is the order of the errors an embedder
/// sees: an id that is live, or that was used and closed, is
/// `StreamAlreadyOpen` (a used id is never free again, RFC 9000 §2.1);
/// then graceful shutdown; then the peer's stream limit.
fn openLocalStream(conn: *Connection, id: u64) Error!*Stream {
    const idx = streamIndex(id);
    const bidi = streamIsBidi(id);
    const ids = idSpace(conn, id);
    if (conn.streams.contains(id) or ids.classify(idx) == .used) return Error.StreamAlreadyOpen;
    // During graceful shutdown we open no new local streams; in-flight
    // streams keep draining. Single chokepoint for openBidi/openUni and
    // the openNext* helpers.
    if (conn.graceful_shutdown) return Error.ShuttingDown;
    if (idx >= max_stream_count_limit) return Error.InvalidStreamId;
    if (idx >= ids.limit) {
        conn.noteStreamsBlocked(bidi, ids.limit);
        return Error.StreamLimitExceeded;
    }
    return materializeStream(conn, id, max_local_skipped_stream_ranges);
}

// Doc comment lives on the `Connection.localStreamType` thunk in Connection.zig.
pub fn localStreamType(conn: *const Connection, uni: bool) StreamType {
    return switch (conn.role) {
        .client => if (uni) .client_uni else .client_bidi,
        .server => if (uni) .server_uni else .server_bidi,
    };
}

// Doc comment lives on the `Connection.openNextBidi` thunk in Connection.zig.
pub fn openNextBidi(conn: *Connection) Error!*Stream {
    return openBidi(conn, localStreamType(conn, false).streamId(conn.local_bidi_ids.opened));
}

// Doc comment lives on the `Connection.openNextUni` thunk in Connection.zig.
pub fn openNextUni(conn: *Connection) Error!*Stream {
    return openUni(conn, localStreamType(conn, true).streamId(conn.local_uni_ids.opened));
}

/// The stream id `openNextBidi` would use next, without opening anything
/// or advancing the counter. Lets an embedder learn the id up front — e.g.
/// to run an HTTP/3 GOAWAY / stream-limit gate keyed on the id *before*
/// committing to the open, then call `openNextBidi`. The returned id is
/// only valid until the next successful local bidi open on this
/// connection (`openNextBidi` or an `openBidi` at or above this id).
pub fn peekNextBidi(conn: *const Connection) u64 {
    return localStreamType(conn, false).streamId(conn.local_bidi_ids.opened);
}

/// The stream id `openNextUni` would use next, without opening anything or
/// advancing the counter. Same validity caveat as `peekNextBidi`.
pub fn peekNextUni(conn: *const Connection) u64 {
    return localStreamType(conn, true).streamId(conn.local_uni_ids.opened);
}

/// Create the stream object for `id` and mark its index used in its
/// id space. The caller has checked that `id` is absent, is not a
/// used index, and is below the limit.
///
/// The memory comes first and the id space last, so a failed
/// allocation leaves the id untouched. The other order would leave an
/// index marked used with no stream behind it, and that reads as "a
/// stream that was closed": every later frame for it would be ignored.
fn materializeStream(conn: *Connection, id: u64, max_hole_ranges: usize) Error!*Stream {
    try conn.streams.ensureUnusedCapacity(conn.allocator, 1);
    const ptr = try conn.allocator.create(Stream);
    errdefer conn.allocator.destroy(ptr);
    idSpace(conn, id).open(conn.allocator, streamIndex(id), max_hole_ranges) catch |err| return switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
        error.TooManySkippedIds => Error.TooManySkippedStreamIds,
        // Both were ruled out by the caller.
        error.LimitExceeded => Error.StreamLimitExceeded,
        error.AlreadyUsed => Error.StreamAlreadyOpen,
    };
    ptr.* = .{
        .id = id,
        .send = SendStream.init(conn.allocator),
        .recv = RecvStream.init(conn.allocator),
        .recv_max_data = initialRecvStreamLimit(conn, id),
        .recv_window = initialRecvStreamLimit(conn, id),
        .send_max_data = initialSendStreamLimit(conn, id),
    };
    // The connection's send buffer size at the open is the stream's
    // for its life (`Connection.max_buffered_send`).
    ptr.send.max_buffered = conn.max_buffered_send;
    conn.streams.putAssumeCapacity(id, ptr);
    conn_qlog.emitQlog(conn, .{
        .name = .stream_state_updated,
        .stream_id = id,
        .stream_state = .open,
    });
    return ptr;
}

/// Which inbound frame is asking for the stream. Selects the
/// CONNECTION_CLOSE reason phrases `ensurePeerStream`'s gates send to
/// the peer — the error codes are identical, only the wording differs
/// per frame type.
pub const PeerStreamFrame = enum { stream_data, reset_stream };

/// Shared STREAM / RESET_STREAM inbound prologue: run the peer-stream
/// gates in order, then return the stream — the existing one, or a
/// fresh one made by `materializeStream` (so peer-initiated
/// streams emit the same `stream_state_updated` `.open` qlog event as
/// local opens).
///
/// Gate order is load-bearing:
/// 1. `peerMaySendOnStream` — data/reset on our send-only uni stream
///    closes with STREAM_STATE_ERROR;
/// 2. an absent local bidi stream that was used and closed is
///    post-terminal and ignored; any other absent local stream (never
///    opened, or skipped) closes with STREAM_STATE_ERROR;
/// 3. RFC 9000 §3.2: an absent peer stream that already reached a
///    terminal state and was reaped is post-terminal — the frame is
///    dropped instead of resurrecting the stream with fresh
///    (final-size / reset) state. Checked before the limit, so the id
///    is neither re-counted nor recreated;
/// 4. the stream limit — closes the connection itself when the peer
///    overruns it.
///
/// Returns null when a gate closed the connection or decided the
/// frame must be ignored; the caller just returns.
///
/// INTERNAL: pub for direct sibling import (recv_data_handlers.zig,
/// recv_stream_control_handlers.zig).
pub fn ensurePeerStream(conn: *Connection, id: u64, frame: PeerStreamFrame) Error!?*Stream {
    if (!peerMaySendOnStream(conn, id)) {
        conn.close(true, transport_error_stream_state, switch (frame) {
            .stream_data => "stream data on receive-only stream",
            .reset_stream => "reset stream on receive-only stream",
        });
        return null;
    }
    const existing = conn.streams.get(id);
    if (existing) |ptr| return ptr;
    const idx = streamIndex(id);
    const ids = idSpace(conn, id);
    if (streamInitiatedByLocal(conn, id)) {
        if (ids.classify(idx) == .used) return null;
        conn.close(true, transport_error_stream_state, switch (frame) {
            .stream_data => "peer referenced unopened local stream",
            .reset_stream => "peer reset unopened local stream",
        });
        return null;
    }
    return openPeerStream(conn, id);
}

/// A frame names a stream the PEER initiates that has no live `Stream`.
/// Null when the stream was used before and is gone (closed and
/// reaped: the frame is late and is ignored, RFC 9000 §3.2), or when
/// the id is over a limit (the connection is closed here). Otherwise
/// the frame opens the stream.
fn openPeerStream(conn: *Connection, id: u64) Error!?*Stream {
    const idx = streamIndex(id);
    const ids = idSpace(conn, id);
    if (ids.classify(idx) == .used) return null;
    if (idx >= max_stream_count_limit) {
        conn.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
        return null;
    }
    if (idx >= ids.limit) {
        conn.close(true, transport_error_stream_limit, if (streamIsBidi(id))
            "peer exceeded bidirectional stream limit"
        else
            "peer exceeded unidirectional stream limit");
        return null;
    }
    // A peer space needs no cap of its own on skipped ranges: every
    // skipped id is below the limit we advertised.
    const s = try materializeStream(conn, id, std.math.maxInt(usize));
    // This open may have used the peer's last id while credit is held
    // back for batching. The peer must not have to ask for it (RFC
    // 9000 §4.6).
    conn_flow.maybeAdvertiseStreamCredit(conn, streamIsBidi(id));
    return s;
}

/// The two frames that name OUR sending part of a stream.
pub const SendPartFrame = enum { stop_sending, max_stream_data };

/// Inbound prologue for STOP_SENDING and MAX_STREAM_DATA (RFC 9000
/// §19.5, §19.10). Returns the stream to act on, or null when there is
/// nothing to do: the connection was closed here, or the stream was
/// closed and reaped and the frame is late (§3.2).
///
/// 1. A stream the peer opened as unidirectional has no sending part
///    of ours: STREAM_STATE_ERROR.
/// 2. A stream of ours that was used and is gone is a late frame. One
///    we never opened is a stream the peer cannot know:
///    STREAM_STATE_ERROR.
/// 3. A bidirectional stream of the peer that is not here yet is
///    CREATED by the frame (§3.2: "receipt of a MAX_STREAM_DATA or
///    STOP_SENDING frame for the sending part of the stream also
///    creates the receiving part"), under the same stream limit as any
///    first frame.
///
/// INTERNAL: pub for direct sibling import (recv_flow_handlers.zig,
/// recv_stream_control_handlers.zig).
pub fn sendPartForPeerFrame(conn: *Connection, id: u64, frame: SendPartFrame) Error!?*Stream {
    if (!localMaySendOnStream(conn, id)) {
        conn.close(true, transport_error_stream_state, switch (frame) {
            .stop_sending => "stop sending for receive-only stream",
            .max_stream_data => "max stream data for receive-only stream",
        });
        return null;
    }
    if (conn.streams.get(id)) |ptr| return ptr;
    if (streamInitiatedByLocal(conn, id)) {
        if (idSpace(conn, id).classify(streamIndex(id)) == .used) return null;
        conn.close(true, transport_error_stream_state, switch (frame) {
            .stop_sending => "stop sending for unopened local stream",
            .max_stream_data => "max stream data for unopened local stream",
        });
        return null;
    }
    return openPeerStream(conn, id);
}

/// The id space of `id`: by who initiated it, and its kind.
///
/// INTERNAL: pub for direct sibling import.
pub fn idSpace(conn: *Connection, id: u64) *StreamIdSpace {
    const bidi = streamIsBidi(id);
    return if (streamInitiatedByLocal(conn, id))
        (if (bidi) &conn.local_bidi_ids else &conn.local_uni_ids)
    else
        (if (bidi) &conn.peer_bidi_ids else &conn.peer_uni_ids);
}

fn idSpaceConst(conn: *const Connection, id: u64) *const StreamIdSpace {
    const bidi = streamIsBidi(id);
    return if (streamInitiatedByLocal(conn, id))
        (if (bidi) &conn.local_bidi_ids else &conn.local_uni_ids)
    else
        (if (bidi) &conn.peer_bidi_ids else &conn.peer_uni_ids);
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

pub fn streamInitiatedByLocal(conn: *const Connection, id: u64) bool {
    return streamInitiatedByClient(id) == (conn.role == .client);
}

pub fn localMaySendOnStream(conn: *const Connection, id: u64) bool {
    if (streamIsBidi(id)) return true;
    return streamInitiatedByLocal(conn, id);
}

pub fn peerMaySendOnStream(conn: *const Connection, id: u64) bool {
    if (streamIsBidi(id)) return true;
    return !streamInitiatedByLocal(conn, id);
}

pub fn initialRecvStreamLimit(conn: *const Connection, id: u64) u64 {
    const params = conn.local_transport_params;
    if (streamIsUni(id)) {
        if (streamInitiatedByLocal(conn, id)) return 0;
        return params.initial_max_stream_data_uni;
    }
    if (streamInitiatedByLocal(conn, id)) {
        return params.initial_max_stream_data_bidi_local;
    }
    return params.initial_max_stream_data_bidi_remote;
}

pub fn initialSendStreamLimit(conn: *const Connection, id: u64) u64 {
    // Prefer the real cached peer params; before they arrive, bound
    // early-data (0-RTT) sends by the embedder-supplied remembered
    // session params. With neither available, only a 0-RTT send
    // window is legitimate at all: grant the (client-conn-limited)
    // unbounded window when early-data write keys are present, and
    // nothing otherwise — a non-0-RTT connection never sends
    // application stream data before its params are cached.
    // applyPeerFlowTransportParams later @max-raises each stream's
    // send_max_data to the true limit once the real params land.
    const params = conn.cached_peer_transport_params orelse
        conn.remembered_peer_transport_params orelse
        {
            if (conn.haveSecret(.early_data, .write)) return std.math.maxInt(u64);
            return 0;
        };
    if (streamIsUni(id)) {
        if (!streamInitiatedByLocal(conn, id)) return 0;
        return params.initial_max_stream_data_uni;
    }
    if (streamInitiatedByLocal(conn, id)) {
        return params.initial_max_stream_data_bidi_remote;
    }
    return params.initial_max_stream_data_bidi_local;
}

/// True if `id` has no live stream because its stream was driven to a
/// terminal state and reclaimed. A STREAM / RESET_STREAM for such an
/// id is a post-terminal frame that MUST be ignored (RFC 9000 §3.2)
/// rather than resurrecting the stream.
///
/// The id space remembers which ids were ever used; the stream table
/// says which are live. Used and not live is closed. An id that was
/// only SKIPPED (a lower id, implicitly opened when a higher one was
/// used) is neither: its first frame may still arrive.
fn streamWasReaped(conn: *const Connection, id: u64) bool {
    return !conn.streams.contains(id) and idSpaceConst(conn, id).classify(streamIndex(id)) == .used;
}

// Doc comment lives on the Connection.streamRecvWasReaped thunk.
pub fn streamRecvWasReaped(conn: *const Connection, id: u64) bool {
    if (!peerMaySendOnStream(conn, id)) return false;
    return streamWasReaped(conn, id);
}

/// The one place that says how a live stream's receive half ended. Both
/// answers of `streamRecvEnd` — from the live stream and from the note
/// written when `tick` reclaims it — come from here, so they cannot
/// drift apart. Null while the receive half has not ended.
fn recvEndOf(s: *const Stream) ?StreamRecvEnd {
    if (!s.recvFullyTerminated()) return null;
    return .{
        .fin_seen = s.recv.fin_seen,
        .reset_code = if (s.recv.reset) |r| r.error_code else null,
        // A terminal receive half always has a locked final size (a FIN
        // or a RESET_STREAM set it); the fallback is defensive only.
        .final_size = s.recv.final_size orelse s.recv.read_offset,
        .read_offset = s.recv.read_offset,
        .stopped = s.recv_stopped,
        .arrived_in_early_data = s.arrived_in_early_data,
    };
}

fn recordOf(id: u64, end: StreamRecvEnd) RecvEndRing.Record {
    return .{
        .id = id,
        .final_size = end.final_size,
        .read_offset = end.read_offset,
        .reset_code = end.reset_code orelse 0,
        .flags = .{
            .fin_seen = end.fin_seen,
            .reset = end.reset_code != null,
            .stopped = end.stopped,
            .arrived_in_early_data = end.arrived_in_early_data,
        },
    };
}

fn endOfRecord(rec: RecvEndRing.Record) StreamRecvEnd {
    return .{
        .fin_seen = rec.flags.fin_seen,
        .reset_code = if (rec.flags.reset) rec.reset_code else null,
        .final_size = rec.final_size,
        .read_offset = rec.read_offset,
        .stopped = rec.flags.stopped,
        .arrived_in_early_data = rec.flags.arrived_in_early_data,
    };
}

// Doc comment lives on the Connection.streamRecvEnd thunk.
pub fn streamRecvEnd(conn: *const Connection, id: u64) ?StreamRecvEnd {
    if (!peerMaySendOnStream(conn, id)) return null;
    if (conn.streams.get(id)) |s| return recvEndOf(s);
    // Only an id the stream table reclaimed has a note; an id that was
    // never opened, or only skipped, has none and stays null.
    if (!streamWasReaped(conn, id)) return null;
    const ring = conn.recv_end_ring orelse return null;
    const rec = ring.find(id) orelse return null;
    return endOfRecord(rec);
}

pub fn peerStreamWithinLocalLimit(conn: *Connection, id: u64) bool {
    const idx = streamIndex(id);
    if (idx >= max_stream_count_limit) {
        conn.close(true, transport_error_frame_encoding, "stream id exceeds stream count space");
        return false;
    }
    if (streamIsBidi(id)) {
        if (idx >= conn.peer_bidi_ids.limit) {
            conn.close(true, transport_error_stream_limit, "peer referenced bidirectional stream above limit");
            return false;
        }
    } else {
        if (idx >= conn.peer_uni_ids.limit) {
            conn.close(true, transport_error_stream_limit, "peer referenced unidirectional stream above limit");
            return false;
        }
    }
    return true;
}

pub fn limitChunkToSendFlow(
    conn: *Connection,
    s: *const Stream,
    chunk: send_stream_mod.Chunk,
) Error!?send_stream_mod.Chunk {
    return limitChunkToSendFlowAfterPlanned(conn, s, chunk, 0);
}

pub fn limitChunkToSendFlowAfterPlanned(
    conn: *Connection,
    s: *const Stream,
    chunk: send_stream_mod.Chunk,
    planned_conn_new_bytes: u64,
) Error!?send_stream_mod.Chunk {
    if (!localMaySendOnStream(conn, s.id)) return null;
    if (chunk.length == 0) return chunk;

    const chunk_end = std.math.add(u64, chunk.offset, chunk.length) catch return null;
    const wants_new_data = chunk_end > s.send_flow_highest;
    const stream_new_allowance = if (s.send_flow_highest >= s.send_max_data)
        0
    else
        s.send_max_data - s.send_flow_highest;
    const planned_conn_sent = conn.we_sent_stream_data +| planned_conn_new_bytes;
    const conn_new_allowance = if (planned_conn_sent >= conn.peer_max_data)
        0
    else
        conn.peer_max_data - planned_conn_sent;
    if (wants_new_data and stream_new_allowance == 0) {
        try conn.noteStreamDataBlocked(s.id, s.send_max_data);
    }
    if (wants_new_data and conn_new_allowance == 0) {
        conn.noteDataBlocked(conn.peer_max_data);
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

/// Connection-level send flow credit: new stream bytes the peer's
/// MAX_DATA window would accept right now (RFC 9000 §4.1, sender
/// side). Before peer transport parameters arrive the limit reads as
/// unlimited — the same view the send gate itself enforces.
pub fn connectionSendWindow(conn: *const Connection) u64 {
    return conn.peer_max_data -| conn.we_sent_stream_data;
}

/// Send-window snapshot for `id` (see `state.SendWindow`). Null when
/// the stream is unknown or is a peer-initiated unidirectional stream
/// (we can never send there). Mirrors `limitChunkToSendFlow`'s
/// accounting exactly: the same fields, read instead of enforced.
pub fn streamSendWindow(conn: *const Connection, id: u64) ?state_mod.SendWindow {
    if (!localMaySendOnStream(conn, id)) return null;
    const s = conn.streams.get(id) orelse return null;
    const conn_credit = connectionSendWindow(conn);
    const stream_credit = s.send_max_data -| s.send_flow_highest;
    const queued = s.send.write_offset -| s.send_flow_highest;
    return .{
        .connection = conn_credit,
        .stream = stream_credit,
        .queued = queued,
        .writable = @min(conn_credit, stream_credit) -| queued,
    };
}

pub fn streamFlowNewBytes(s: *const Stream, chunk: send_stream_mod.Chunk) u64 {
    const end = std.math.add(u64, chunk.offset, chunk.length) catch return 0;
    if (end <= s.send_flow_highest) return 0;
    return end - s.send_flow_highest;
}

pub fn recordStreamFlowSent(conn: *Connection, s: *Stream, chunk: send_stream_mod.Chunk) void {
    const end = std.math.add(u64, chunk.offset, chunk.length) catch return;
    if (end <= s.send_flow_highest) return;
    const delta = end - s.send_flow_highest;
    s.send_flow_highest = end;
    conn.we_sent_stream_data += delta;
}

// Doc comment lives on the `Connection.streamIterator` thunk in Connection.zig.
pub fn streamIterator(conn: *Connection) std.AutoHashMapUnmanaged(u64, *Stream).Iterator {
    return conn.streams.iterator();
}

/// Number of currently-open streams.
pub fn streamCount(conn: *const Connection) usize {
    return conn.streams.count();
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
pub fn gcClosedStreams(conn: *Connection) void {
    // The batch size is owned by `RecvEndRing` so its survival guarantee
    // ("a note outlives the next tick") cannot drift from the GC.
    var batch: [RecvEndRing.gc_batch]u64 = undefined;
    var n: usize = 0;
    var it = conn.streams.iterator();
    while (it.next()) |entry| {
        const s = entry.value_ptr.*;
        // Nobody reads a stream the application stopped: read it
        // here, so that its receive half can end.
        if (s.recv_stopped) discardStopped(conn, s);
        const send_done = s.send.isTerminal();
        const recv_done = s.recvFullyTerminated();
        const reclaimable = if (streamIsBidi(s.id))
            send_done and recv_done
        else if (streamInitiatedByLocal(conn, s.id))
            send_done
        else
            recv_done;
        if (!reclaimable) continue;
        if (n == batch.len) break;
        batch[n] = s.id;
        n += 1;
    }
    // The note for `streamRecvEnd`: allocated once, here, and only when
    // this pass reclaims a stream that has a receive half. A failed
    // allocation records nothing and changes nothing else — every
    // reclaim below still happens, and the answer for those streams
    // degrades to "outcome unknown", which callers treat as cut.
    if (conn.recv_end_ring == null) {
        for (batch[0..n]) |id| {
            if (!peerMaySendOnStream(conn, id)) continue;
            if (conn.allocator.create(RecvEndRing)) |ring| {
                ring.* = .{};
                conn.recv_end_ring = ring;
            } else |_| {}
            break;
        }
    }
    if (n > 0) conn.touch();
    for (batch[0..n]) |id| {
        const removed = conn.streams.fetchRemove(id) orelse continue;
        const s = removed.value;
        if (s.in_sendable) sendableRemove(conn, s);
        // The id stays `used` in its id space, with no live stream: that
        // is the tombstone. A late STREAM/RESET_STREAM for it is
        // post-terminal, whichever endpoint initiated the stream.
        // Count the close only for an id the space knows: a stream put
        // straight into the table (test setup) never went through it.
        const ids = idSpace(conn, id);
        if (ids.classify(streamIndex(id)) == .used) {
            ids.noteClosed();
            // A closed peer stream is one more id the peer may open.
            if (!streamInitiatedByLocal(conn, id)) conn_flow.maybeAdvertiseStreamCredit(conn, streamIsBidi(id));
            // Same gate as `noteClosed`, so an id with a note is always
            // one `streamRecvWasReaped` reports as reclaimed.
            if (conn.recv_end_ring) |ring| {
                if (peerMaySendOnStream(conn, id)) {
                    if (recvEndOf(s)) |end| ring.push(recordOf(id, end));
                }
            }
        }
        const held = s.send.bytes.len() + s.recv.bytes.items.len;
        if (held > 0) conn.releaseResidentBytes(held);
        conn_qlog.emitQlog(conn, .{
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
        conn.allocator.destroy(s);
    }
}

/// Pick the next available server-initiated unidirectional
/// stream id (low 2 bits = 0b11) starting from `start`. Skips
/// ids that are already open.
pub fn nextServerUniId(conn: *const Connection, start: u64) u64 {
    var id = start | 0b11;
    while (conn.streams.contains(id)) id += 4;
    return id;
}

/// Pick the next available server-initiated bidi stream id
/// (low 2 bits = 0b01). Skips ids already open.
pub fn nextServerBidiId(conn: *const Connection, start: u64) u64 {
    var id = (start & ~@as(u64, 0b11)) | 0b01;
    while (conn.streams.contains(id)) id += 4;
    return id;
}

// Doc comment lives on the `Connection.stream` thunk in Connection.zig.
pub fn stream(conn: *const Connection, id: u64) ?*Stream {
    return conn.streams.get(id);
}

// Doc comment lives on the `Connection.streamSendStats` thunk in Connection.zig.
pub fn streamSendStats(conn: *const Connection, id: u64) ?StreamSendStats {
    const s = conn.streams.get(id) orelse return null;
    const written = s.send.writtenBytes();
    const acked = s.send.ackedFloor();
    return .{
        .written = written,
        .acked = acked,
        .buffered = written - acked,
        .has_pending = s.send.hasPendingChunk(),
    };
}

// Doc comment lives on the `Connection.streamSetPriority` thunk in Connection.zig.
pub fn streamSetPriority(conn: *Connection, id: u64, p: StreamPriority) Error!void {
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    // The sendable list is ordered by the priority: out under the old
    // one, in under the new.
    const was_sendable = s.in_sendable;
    if (was_sendable) sendableRemove(conn, s);
    s.priority = p;
    if (was_sendable) sendableInsert(conn, s);
}

/// The order of `Connection.sendable`: urgency, non-incremental
/// before incremental, then the id. `streamPriorityLess` without the
/// round-robin rotation, which `collectSendableStreamsByPriority`
/// applies when it reads the list.
fn sendableLess(a: *const Stream, b: *const Stream) bool {
    if (a.priority.urgency != b.priority.urgency) return a.priority.urgency < b.priority.urgency;
    if (a.priority.incremental != b.priority.incremental) return !a.priority.incremental;
    return a.id < b.id;
}

/// The position of `s` in the sendable list, or where it would go.
fn sendablePosition(conn: *const Connection, s: *const Stream) usize {
    const items = conn.sendable.items;
    var lo: usize = 0;
    var hi: usize = items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (sendableLess(items[mid], s)) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn sendableInsert(conn: *Connection, s: *Stream) void {
    const at = sendablePosition(conn, s);
    conn.sendable.insert(conn.allocator, at, s) catch {
        conn.sendable_degraded = true;
        return;
    };
    s.in_sendable = true;
}

fn sendableRemove(conn: *Connection, s: *Stream) void {
    const at = sendablePosition(conn, s);
    if (at < conn.sendable.items.len and conn.sendable.items[at] == s) {
        _ = conn.sendable.orderedRemove(at);
    } else {
        // Not where its order says (a degraded list): find it.
        for (conn.sendable.items, 0..) |item, i| {
            if (item == s) {
                _ = conn.sendable.orderedRemove(i);
                break;
            }
        }
    }
    s.in_sendable = false;
}

/// Keep `Connection.sendable` in step with the stream: in the list
/// while it has a chunk, a FIN or a reset to send, out otherwise.
/// Called after every transition of the send half (a write, a finish,
/// a reset, a chunk sent, acknowledged or lost).
// INTERNAL: pub for the Connection/ subsystem files; not part of the embedder API.
pub fn noteSendable(conn: *Connection, s: *Stream) void {
    const want = s.send.hasPendingChunk();
    if (want == s.in_sendable) return;
    if (want) sendableInsert(conn, s) else sendableRemove(conn, s);
}

// Doc comment lives on the `Connection.streamPriority` thunk in Connection.zig.
pub fn streamPriority(conn: *const Connection, id: u64) ?StreamPriority {
    const s = conn.streams.get(id) orelse return null;
    return s.priority;
}

/// Collect pointers to streams with pending send data, ordered by RFC 9218
/// priority (urgency asc, then stream id asc), into `buf`. Bounded to
/// `buf.len` — the per-packet chunk cap — so if more streams are ready than
/// fit one packet, the highest-priority `buf.len` are returned and the rest
/// are served on a later packet. Returns the filled prefix.
///
/// Perf note: this is a full stream-map walk + insertion sort per
/// packet — O(N) per packet at high stream fan-out. The common case
/// (one busy stream) is O(1)-ish, and the per-packet cap keeps the
/// sort tiny. A per-urgency ready-list (or min-heap keyed on
/// (urgency, stream_id, rr_cursor)) would bound this to the streams
/// that actually fit the packet, but the RFC 9218 round-robin
/// cursor and priority mutation semantics make it a dedicated
/// scheduler refactor — deliberate, measured, and separately
/// benchmarked — rather than an opportunistic change.
///
/// INTERNAL: pub for `_tests.zig` access; not part of the embedder
/// API (the scheduling it drives is observed through `pollDatagram`).
pub fn collectSendableStreamsByPriority(conn: *Connection, buf: []*Stream) []*Stream {
    var n: usize = 0;
    if (conn.sendable_degraded) {
        n = collectByWalk(conn, buf);
    } else {
        n = collectFromSendable(conn, buf);
        if (builtin.mode == .debug) {
            // The list and the walk agree, stream for stream.
            var check: [32]*Stream = undefined;
            const m = collectByWalk(conn, check[0..@min(check.len, buf.len)]);
            std.debug.assert(m == n);
            for (buf[0..n], check[0..m]) |a, b| std.debug.assert(a == b);
        }
    }
    const result = buf[0..n];
    // Advance the round-robin cursor past the incremental stream that
    // leads this packet, so the next incremental stream of the same urgency
    // leads the next one. Non-incremental streams don't move the cursor.
    for (result) |s| {
        if (s.priority.incremental) {
            conn.priority_rr_cursor = s.id +% 1;
            break;
        }
    }
    return result;
}

// Doc comment lives on the `Connection.streamRecvState` thunk in Connection.zig.
pub fn streamRecvState(conn: *const Connection, id: u64) ?StreamRecvState {
    // A locally-initiated unidirectional stream has no receive half:
    // it can never see a FIN or reach a terminal recv state, so a
    // caller polling for completion here would wait forever on a
    // state that cannot change. Null (same as an unknown stream)
    // says "nothing to observe" — the receive-side twin of
    // `streamRead`'s `StreamNotReadable` guard.
    if (!peerMaySendOnStream(conn, id)) return null;
    const s = conn.streams.get(id) orelse return null;
    return .{
        .fin_seen = s.recv.fin_seen,
        .reset_seen = s.recv.reset != null,
        .terminal = s.recvFullyTerminated(),
        .read_offset = s.recv.read_offset,
        .final_size = s.recv.final_size,
        .reset_code = if (s.recv.reset) |r| r.error_code else null,
    };
}

// Doc comment lives on the `Connection.streamWrite` thunk in Connection.zig.
pub fn streamWrite(conn: *Connection, id: u64, data: []const u8) Error!usize {
    if (!localMaySendOnStream(conn, id)) return Error.StreamNotWritable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    conn.touch();
    // Per-connection memory DoS cap: pre-flight the resident-bytes
    // budget against the bytes we'd accept. The per-stream
    // `max_buffered` cap already gates a single stream; this
    // shares one budget with CRYPTO / DATAGRAM / recv reassembly
    // so opening many streams each near their per-stream cap
    // can't bypass the connection-wide ceiling.
    const before = s.send.bytes.len();
    // The buffer follows the peer's credit (since v0.33.0): what the
    // peer still accepts beyond the acknowledged floor is worth
    // holding, up to the cap; a limit once raised stays, since the
    // peer's credit only grows and the buffer holds only what the
    // application wrote. `Connection.send_buffer_follows_credit`.
    if (conn.send_buffer_follows_credit) {
        const by_credit = s.send_max_data -| s.send.base_offset;
        const limit: usize = @intCast(@min(by_credit, @as(u64, conn.max_buffered_send_cap)));
        if (limit > s.send.max_buffered) s.send.max_buffered = limit;
    }
    const headroom = s.send.max_buffered -| before;
    // The connection's memory budget bounds the application's own
    // writes as back-pressure, not as a fault (since v0.33.0): a
    // write takes what the budget leaves and returns short, as it
    // does at the stream's limit. The budget's fault, ExcessiveLoad,
    // is for what the peer puts in buffers.
    const budget_left: usize = std.math.lossyCast(usize, conn.max_connection_memory -| conn.bytes_resident);
    const want = @min(data.len, @min(headroom, budget_left));
    if (want > 0) {
        try conn.tryReserveResidentBytes(want);
    }
    const accepted = s.send.write(data[0..want]) catch |err| {
        conn.releaseResidentBytes(want);
        return err;
    };
    noteSendable(conn, s);
    // `write` may accept fewer bytes than `want` if it short-writes
    // (e.g. on its own internal cap); reconcile so we only hold
    // budget for what actually landed in the buffer.
    if (accepted < want) {
        conn.releaseResidentBytes(want - accepted);
    }
    return accepted;
}

// Doc comment lives on the `Connection.streamRead` thunk in Connection.zig.
pub fn streamRead(conn: *Connection, id: u64, dst: []u8) Error!usize {
    if (!peerMaySendOnStream(conn, id)) return Error.StreamNotReadable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    const before = s.recv.bytes.items.len;
    const n = s.recv.read(dst);
    try afterStreamConsume(conn, s, id, before, n);
    return n;
}

// Doc comment lives on the `Connection.streamPeek` thunk in Connection.zig.
pub fn streamPeek(conn: *Connection, id: u64) Error![]const u8 {
    if (!peerMaySendOnStream(conn, id)) return Error.StreamNotReadable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    return s.recv.peek();
}

// Doc comment lives on the `Connection.streamConsume` thunk in Connection.zig.
pub fn streamConsume(conn: *Connection, id: u64, n: usize) Error!void {
    if (!peerMaySendOnStream(conn, id)) return Error.StreamNotReadable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    if (n > s.recv.peek().len) return Error.ConsumeBeyondReadable;
    const before = s.recv.bytes.items.len;
    s.recv.consume(n);
    try afterStreamConsume(conn, s, id, before, n);
}

/// Shared post-consumption bookkeeping for `streamRead` and
/// `streamConsume` — one body so the budget release and the
/// flow-control credit queueing can never drift between the copying
/// and zero-copy paths.
fn afterStreamConsume(
    conn: *Connection,
    s: *Stream,
    id: u64,
    physical_before: usize,
    n: usize,
) Error!void {
    // Per-connection memory DoS cap: the budget keys on the PHYSICAL
    // `bytes.items.len`. The sliding window advances without
    // shrinking most of the time (consumed bytes keep their budget
    // charge until the half-buffer compaction or the full-drain
    // reset), so this release fires only at those compaction points —
    // the over-charge in between is bounded by the half-buffer policy
    // and correct (the memory is genuinely allocated while the prefix
    // sits in it).
    if (s.recv.bytes.items.len < physical_before) {
        conn.releaseResidentBytes(physical_before - s.recv.bytes.items.len);
    }
    if (n > 0) {
        // The window kept open is the one this endpoint announced for
        // the stream (its transport parameter), smaller or larger
        // than the default: an embedder that announces 4 MiB on a fat
        // link needs it for the whole transfer, not only the first
        // 4 MiB. MEASURED 2026-10-07 (`impairment_clean_1gbit_rtt20ms`,
        // 8 MiB, bbr, the harness announcing 4 MiB): with the credit
        // falling back to the default's 1 MiB the sender held 546 KB
        // in flight, 361 ms; 285 ms with the announced window. And
        // since v0.33.0 the window tunes itself for a reader that
        // keeps up (`tuneWindow`).
        const conn_cap = connectionWindowCap(conn);
        // The pace the window is tuned on: the bytes the app read, or,
        // when it has read everything deliverable, the bytes received,
        // holes included. Under reordering the app is held by the
        // network, not slow, and the window must cover the rate times
        // the reorder delay as well as the round trip; a reader that
        // keeps up reads everything deliverable, so it is told apart
        // from a slow one by what it leaves. MEASURED (sprint B,
        // 2026-10-08, `impairment_reorder_gaps_1gbit_defaults`, 12
        // seeds, median): cubic 422 -> 378 ms, bbr 367 -> 311; the
        // window had stalled at 2 MiB for a 2.5 MB BDP plus a 20 ms
        // hole, with the sender out of credit half the time.
        const pace = if (s.recv.readableBytes() == 0) @max(s.recv.read_offset, s.recv.end_offset) else s.recv.read_offset;
        const grew = tuneWindow(conn, &s.recv_window, &s.recv_epoch_start_offset, &s.recv_epoch_start_us, pace, @min(conn.max_stream_receive_window, conn_cap));
        if (grew) {
            // A connection window at least one and a half times any
            // stream's, so the stream's growth is not held back at the
            // connection level (quic-go's coupling).
            const floor = @min(s.recv_window +| s.recv_window / 2, conn_cap);
            if (conn.conn_recv_window < floor) conn.conn_recv_window = floor;
        }
        const window = s.recv_window;
        if (Connection.shouldQueueReceiveCredit(s.recv.read_offset, s.recv_max_data, window)) {
            try conn_flow.queueMaxStreamData(conn, id, s.recv.read_offset +| window);
        }
        creditConnectionRecvWindow(conn, n);
    }
}

/// The connection window's cap: `max_connection_receive_window`, and
/// never more than half of `max_connection_memory`. The window bounds
/// what the peer may send unread, and the receive buffer charges the
/// budget up to twice the unread bytes until it compacts, so a cap
/// above half the budget would let an honest peer trip ExcessiveLoad.
/// Raise the budget with the cap on a fat link with many streams.
fn connectionWindowCap(conn: *const Connection) u64 {
    return @min(conn.max_connection_receive_window, conn.max_connection_memory / 2);
}

/// The receive windows' self-tuning (since v0.33.0), the rule quic-go
/// and Chromium use: an epoch starts when the reader has consumed
/// half the window; at the next half, if that took less than two
/// round trips (four times the consumed fraction of the window, times
/// the smoothed RTT, in general), the window doubles, up to `cap`.
/// `window`, `epoch_start_offset` and `epoch_start_us` are the stream's
/// or the connection's; `consumed` is its read offset or bytes read.
/// The clock is `Connection.clock_us` (the last `handle`, `poll` or
/// `tick`), since a read has no time of its own. Returns true when
/// the window grew. Off (`auto_tune_receive_windows` false) nothing
/// moves: the announced window stays, v0.32.0's behavior.
fn tuneWindow(
    conn: *const Connection,
    window: *u64,
    epoch_start_offset: *u64,
    epoch_start_us: *u64,
    consumed: u64,
    cap: u64,
) bool {
    if (!conn.auto_tune_receive_windows) return false;
    const consumed_in_epoch = consumed -| epoch_start_offset.*;
    if (consumed_in_epoch < window.* / 2) return false;
    const now = conn.clock_us;
    defer {
        epoch_start_offset.* = consumed;
        epoch_start_us.* = now;
    }
    // The first half window only starts the clock.
    if (epoch_start_us.* == 0) return false;
    const srtt = conn.rttForLevelConst(.application).smoothed_rtt_us;
    const elapsed = now -| epoch_start_us.*;
    // Fast enough: elapsed < 4 * (consumed_in_epoch / window) * srtt.
    const budget = std.math.lossyCast(u64, (@as(u128, 4) * consumed_in_epoch * srtt) / @max(window.*, 1));
    if (elapsed >= budget or window.* >= cap) return false;
    window.* = @min(window.* *| 2, cap);
    return true;
}

/// `n` bytes of stream data are done with on the receive side: give
/// them back to the connection-level window (MAX_DATA, RFC 9000 §4.1).
///
/// "Done with" is read by the application, or never going to be read:
/// the peer reset the stream, or the application stopped reading it.
/// The second kind used to be forgotten. Every stream the peer reset
/// took its unread bytes out of the window for good, and a connection
/// that lived long enough stalled at `initial_max_data`.
///
/// INTERNAL: pub for direct sibling import
/// (recv_stream_control_handlers.zig).
pub fn creditConnectionRecvWindow(conn: *Connection, n: u64) void {
    if (n == 0) return;
    conn.recv_stream_bytes_read += n;
    // The connection window: the announced one at the start, tuned
    // since v0.33.0 as a stream's is (`tuneWindow`), and never under
    // one and a half times a stream's that grew.
    _ = tuneWindow(conn, &conn.conn_recv_window, &conn.conn_epoch_start_read, &conn.conn_epoch_start_us, conn.recv_stream_bytes_read, connectionWindowCap(conn));
    const window = conn.conn_recv_window;
    if (Connection.shouldQueueReceiveCredit(conn.recv_stream_bytes_read, conn.local_max_data, window)) {
        conn_flow.queueMaxData(conn, conn.recv_stream_bytes_read +| window);
    }
}

/// Read a stream the application stopped reading (`recv_stopped`) as
/// far as it goes and throw the bytes away: release the buffer budget
/// and give the bytes back to the connection window, as a read does.
/// So FIN plus the last byte ends the receive half with nobody
/// reading.
///
/// No stream-level credit is given: after STOP_SENDING a peer resets
/// the stream, or has already sent all of it (RFC 9000 §3.5), so it
/// never needs more.
///
/// Called when data arrives for the stream and from `tick`, and NOT
/// from `streamStopSending` itself: an application calls that from
/// inside a read callback, with a slice of this very buffer in hand
/// and a `streamConsume` still to come.
///
/// INTERNAL: pub for direct sibling import (recv_data_handlers.zig).
pub fn discardStopped(conn: *Connection, s: *Stream) void {
    while (true) {
        const n = s.recv.peek().len;
        const physical_before = s.recv.bytes.items.len;
        // `consume(0)` still advances the state (a FIN with nothing
        // left to read).
        s.recv.consume(n);
        if (s.recv.bytes.items.len < physical_before) {
            conn.releaseResidentBytes(physical_before - s.recv.bytes.items.len);
        }
        creditConnectionRecvWindow(conn, n);
        if (n == 0) break;
    }
}

// Doc comment lives on the `Connection.streamReadFin` thunk in Connection.zig.
pub fn streamReadFin(conn: *Connection, id: u64, dst: []u8) Error!StreamReadResult {
    const n = try streamRead(conn, id, dst);
    // `streamRead` already returned `StreamNotFound` if the stream was
    // absent, and reaping (`gcClosedStreams`) runs only in `tick`, so the
    // stream is still live here; the `orelse` is a defensive dead branch.
    const s = conn.streams.get(id) orelse return .{ .n = n, .fin = false };
    // A RESET_STREAM keeps `fin_seen` (RecvStream.resetStream does not
    // clear it) but throws the unread bytes away, so `fin` must not
    // report a stream reset after its FIN as a clean end.
    const reset_code: ?u64 = if (s.recv.reset) |r| r.error_code else null;
    return .{ .n = n, .fin = s.recv.fin_seen and reset_code == null, .reset_code = reset_code };
}

/// Whether the receive side of `id` has seen any STREAM bytes in
/// 0-RTT. Returns null for an unknown stream.
pub fn streamArrivedInEarlyData(conn: *const Connection, id: u64) ?bool {
    const s = conn.streams.get(id) orelse return null;
    return s.arrived_in_early_data;
}

// Doc comment lives on the `Connection.streamFinish` thunk in Connection.zig.
pub fn streamFinish(conn: *Connection, id: u64) Error!void {
    if (!localMaySendOnStream(conn, id)) return Error.StreamNotWritable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    try s.send.finish();
    noteSendable(conn, s);
    conn.touch();
}

// Doc comment lives on the `Connection.streamReset` thunk in Connection.zig.
pub fn streamReset(
    conn: *Connection,
    id: u64,
    application_error_code: u64,
) Error!void {
    if (!localMaySendOnStream(conn, id)) return Error.StreamNotWritable;
    const s = conn.streams.get(id) orelse return Error.StreamNotFound;
    try s.send.resetStream(application_error_code);
    noteSendable(conn, s);
    conn.touch();
}

// Doc comment lives on the `Connection.streamStopSending` thunk in Connection.zig.
pub fn streamStopSending(
    conn: *Connection,
    stream_id: u64,
    application_error_code: u64,
) Error!void {
    if (!peerMaySendOnStream(conn, stream_id)) return Error.StreamNotReadable;
    const s = conn.streams.get(stream_id) orelse blk: {
        // A stream the peer opened by using a higher id (RFC 9000
        // §2.1) is open for the peer and has been reported to the
        // embedder, but has no `Stream` yet. Make it now: the refusal
        // has to be on record when its data arrives.
        if (streamInitiatedByLocal(conn, stream_id)) return Error.StreamNotFound;
        if (idSpace(conn, stream_id).classify(streamIndex(stream_id)) != .hole) return Error.StreamNotFound;
        break :blk try materializeStream(conn, stream_id, std.math.maxInt(usize));
    };
    // The peer has nothing more to send on a receive half that ended.
    if (s.recvFullyTerminated()) return;
    try queueStopSending(conn, .{
        .stream_id = stream_id,
        .application_error_code = application_error_code,
    });
    s.recv_stopped = true;
}

pub fn queueStopSending(
    conn: *Connection,
    item: StopSendingItem,
) Error!void {
    for (conn.pending_frames.stop_sending.items) |queued| {
        if (queued.stream_id == item.stream_id and
            queued.application_error_code == item.application_error_code)
        {
            return;
        }
    }
    try conn.pending_frames.stop_sending.append(conn.allocator, .{
        .stream_id = item.stream_id,
        .application_error_code = item.application_error_code,
    });
    conn.touch();
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

/// The first `buf.len` streams of `Connection.sendable` in the order
/// `streamPriorityLess` gives: each urgency's non-incremental streams
/// by id, then its incremental ones from the first id at or past the
/// round-robin cursor, wrapping.
fn collectFromSendable(conn: *const Connection, buf: []*Stream) usize {
    const items = conn.sendable.items;
    var n: usize = 0;
    var i: usize = 0;
    while (i < items.len and n < buf.len) {
        const urgency = items[i].priority.urgency;
        while (i < items.len and items[i].priority.urgency == urgency and !items[i].priority.incremental) : (i += 1) {
            if (n < buf.len) {
                buf[n] = items[i];
                n += 1;
            }
        }
        const start = i;
        while (i < items.len and items[i].priority.urgency == urgency) i += 1;
        const end = i;
        if (start == end or n == buf.len) continue;
        var k = start;
        while (k < end and items[k].id < conn.priority_rr_cursor) k += 1;
        var j = if (k < end) k else start;
        var taken: usize = 0;
        while (taken < end - start and n < buf.len) : (taken += 1) {
            buf[n] = items[j];
            n += 1;
            j += 1;
            if (j == end) j = start;
        }
    }
    return n;
}

/// Every stream of the connection with something to send, insertion-
/// sorted into `buf` (the top `buf.len` by priority): the fallback
/// after a failed list insertion, and the Debug check of the list.
fn collectByWalk(conn: *Connection, buf: []*Stream) usize {
    var n: usize = 0;
    var it = conn.streams.iterator();
    while (it.next()) |entry| {
        const s = entry.value_ptr.*;
        if (!s.send.hasPendingChunk()) continue;
        insertStreamByPriority(buf, &n, s, conn.priority_rr_cursor);
    }
    return n;
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
