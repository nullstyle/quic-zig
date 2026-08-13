//! Inbound frame handlers for stream-control termination from the
//! peer: STOP_SENDING (RFC 9000 §19.5) and RESET_STREAM (§19.4).
//! Free-function siblings of `Connection`'s public method-style
//! handlers; the methods on `Connection` are thin thunks that
//! delegate here.

const state_mod = @import("../Connection.zig");
const conn_streams = @import("streams.zig");
const conn_flow = @import("flow.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Stream = state_mod.Stream;
const SendStream = state_mod.SendStream;
const RecvStream = state_mod.RecvStream;
const frame_types = state_mod.frame_types;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_final_size = state_mod.transport_error_final_size;

pub fn handleStopSending(
    conn: *Connection,
    ss: frame_types.StopSending,
) Error!void {
    const ptr = conn.streams.get(ss.stream_id) orelse return;
    try ptr.send.resetStream(ss.application_error_code);
}

pub fn handleResetStream(conn: *Connection, rs: frame_types.ResetStream) Error!void {
    if (!conn_streams.peerMaySendOnStream(conn, rs.stream_id)) {
        conn.close(true, transport_error_stream_state, "reset stream on receive-only stream");
        return;
    }
    const existing = conn.streams.get(rs.stream_id);
    if (existing == null and conn_streams.streamInitiatedByLocal(conn, rs.stream_id)) {
        conn.close(true, transport_error_stream_state, "peer reset unopened local stream");
        return;
    }
    // RFC 9000 §3.2: a RESET_STREAM for an already-reaped peer stream is
    // post-terminal — ignore it rather than resurrecting the stream.
    if (existing == null and conn_streams.peerStreamAlreadyReaped(conn, rs.stream_id)) return;
    if (existing == null and !conn.recordPeerStreamOpenOrClose(rs.stream_id)) return;
    const ptr = existing orelse blk: {
        const new_ptr = try conn.allocator.create(Stream);
        errdefer conn.allocator.destroy(new_ptr);
        new_ptr.* = .{
            .id = rs.stream_id,
            .send = SendStream.init(conn.allocator),
            .recv = RecvStream.init(conn.allocator),
            .recv_max_data = conn.initialRecvStreamLimit(rs.stream_id),
            .send_max_data = conn.initialSendStreamLimit(rs.stream_id),
        };
        try conn.streams.put(conn.allocator, rs.stream_id, new_ptr);
        break :blk new_ptr;
    };
    const old_highest = ptr.recv.peerHighestOffset();
    const new_highest = @max(old_highest, rs.final_size);
    if (new_highest > ptr.recv_max_data) {
        conn.close(true, transport_error_flow_control, "peer reset exceeds stream data limit");
        return;
    }
    const delta = new_highest - old_highest;
    if (delta > 0 and
        (delta > conn.local_max_data or conn.peer_sent_stream_data > conn.local_max_data - delta))
    {
        conn.close(true, transport_error_flow_control, "peer reset exceeds connection data limit");
        return;
    }
    // Hardening guide §3.5 / §8: snapshot the recv buffer length
    // before `resetStream`, which discards buffered-but-undelivered
    // bytes (no-longer-needed reassembly state) and shrinks the
    // backing allocation to zero. Reconcile the global
    // resident-bytes counter against that drop.
    const recv_before = ptr.recv.bytes.items.len;
    ptr.recv.resetStream(rs.application_error_code, rs.final_size) catch |err| switch (err) {
        error.BeyondFinalSize, error.FinalSizeChanged => {
            conn.close(true, transport_error_final_size, "reset stream final size changed");
            return;
        },
        else => return err,
    };
    if (ptr.recv.bytes.items.len < recv_before) {
        conn.releaseResidentBytes(recv_before - ptr.recv.bytes.items.len);
    }
    conn.peer_sent_stream_data += delta;
    conn_flow.maybeReturnPeerStreamCredit(conn, ptr);
}
