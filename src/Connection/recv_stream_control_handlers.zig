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
const frame_types = state_mod.frame_types;
const transport_error_final_size = state_mod.transport_error_final_size;

pub fn handleStopSending(
    conn: *Connection,
    ss: frame_types.StopSending,
) Error!void {
    const ptr = conn.streams.get(ss.stream_id) orelse return;
    try ptr.send.resetStream(ss.application_error_code);
}

pub fn handleResetStream(conn: *Connection, rs: frame_types.ResetStream) Error!void {
    const ptr = (try conn_streams.ensurePeerStream(conn, rs.stream_id, .reset_stream)) orelse return;
    const delta = conn_flow.creditPeerStreamHighWater(conn, ptr, rs.final_size, .{
        .stream = "peer reset exceeds stream data limit",
        .conn = "peer reset exceeds connection data limit",
    }) orelse return;
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
