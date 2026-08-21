//! The DATAGRAM extension (RFC 9221): the embedder send/receive API,
//! payload sizing against the negotiated limits and current PMTU, and
//! the tracked-send acked/lost event bookkeeping. Free-function
//! siblings of `Connection`'s method-style datagram API; the methods on
//! `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const event_queue_mod = state_mod.event_queue_mod;
const SentPacketTracker = state_mod.SentPacketTracker;
const StoredDatagramSendEvent = event_queue_mod.StoredDatagramSendEvent;
const default_mtu = state_mod.default_mtu;
const max_datagram_frame_size = state_mod.max_datagram_frame_size;
const max_pending_datagram_count = state_mod.max_pending_datagram_count;
const max_outbound_datagram_payload_size = state_mod.max_outbound_datagram_payload_size;
const IncomingDatagram = state_mod.IncomingDatagram;
const max_pending_datagram_bytes = state_mod.max_pending_datagram_bytes;
const max_recv_plaintext = state_mod.max_recv_plaintext;

fn recordDatagramSendEvent(conn: *Connection, event: StoredDatagramSendEvent) void {
    conn.datagram_send_events.push(event);
}

pub fn recordDatagramAcked(conn: *Connection, packet: *const SentPacketTracker.SentPacket) void {
    const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
    recordDatagramSendEvent(conn, .{ .acked = event });
}

pub fn recordDatagramLost(conn: *Connection, packet: *const SentPacketTracker.SentPacket) void {
    const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
    recordDatagramSendEvent(conn, .{ .lost = event });
}

// Doc comment lives on the `Connection.sendDatagram` thunk in Connection.zig.
pub fn sendDatagram(conn: *Connection, payload: []const u8) Error!void {
    _ = try sendDatagramTracked(conn, payload);
}

// Doc comment lives on the `Connection.sendDatagramTracked` thunk in Connection.zig.
pub fn sendDatagramTracked(conn: *Connection, payload: []const u8) Error!u64 {
    const max_payload = try maxDatagramPayload(
        conn,
    );
    if (payload.len > max_payload) return Error.DatagramTooLarge;
    if (conn.pending_frames.send_datagrams.items.len >= max_pending_datagram_count) {
        return Error.DatagramQueueFull;
    }
    if (payload.len > max_pending_datagram_bytes or
        conn.pending_frames.send_datagram_bytes > max_pending_datagram_bytes - payload.len)
    {
        return Error.DatagramQueueFull;
    }
    const copy = try conn.allocator.alloc(u8, payload.len);
    errdefer conn.allocator.free(copy);
    @memcpy(copy, payload);
    if (conn.next_datagram_id == std.math.maxInt(u64)) return Error.DatagramIdExhausted;
    const id = conn.next_datagram_id;
    conn.next_datagram_id += 1;
    try conn.pending_frames.send_datagrams.append(conn.allocator, .{
        .id = id,
        .data = copy,
    });
    conn.pending_frames.send_datagram_bytes += payload.len;
    return id;
}

// Doc comment lives on the `Connection.maxDatagramPayload` thunk in Connection.zig.
pub fn maxDatagramPayload(conn: *const Connection) Error!usize {
    // Room a 1-RTT packet + DATAGRAM frame need around the payload. The
    // reserve matches the historical `default_mtu`-derived ceiling at the
    // 1200-byte floor, so behavior there is unchanged and only the
    // PMTU-scaling is new; the send-time build guard enforces exact fit.
    const packet_reserve: usize = default_mtu - max_outbound_datagram_payload_size;
    // Grow/shrink with the active path's PMTU, but never past the
    // plaintext buffer the send path builds a packet into.
    var limit: usize = @min(conn.pmtu() -| packet_reserve, max_recv_plaintext);
    if (conn.cached_peer_transport_params) |params| {
        if (params.max_datagram_frame_size == 0) return Error.DatagramUnavailable;
        limit = @min(limit, @as(usize, @intCast(params.max_datagram_frame_size)));
    }
    return limit;
}

// Doc comment lives on the `Connection.receiveDatagram` thunk in Connection.zig.
pub fn receiveDatagram(conn: *Connection, dst: []u8) Error!?usize {
    const pending = nextDatagramSize(conn) orelse return null;
    if (pending > dst.len) return Error.DatagramBufferTooSmall;
    const item = receiveDatagramInfo(conn, dst).?;
    return item.len;
}

// Doc comment lives on the `Connection.receiveDatagramInfo` thunk in Connection.zig.
pub fn receiveDatagramInfo(conn: *Connection, dst: []u8) ?IncomingDatagram {
    const item = conn.pending_frames.popRecvDatagram() orelse return null;
    defer conn.allocator.free(item.data);
    // Hardening guide §3.5 / §8: pair the resident-bytes release
    // with the queue dequeue. `popRecvDatagram` already decrements
    // `recv_datagram_bytes`; this drops the matching cents from
    // the global resident-bytes counter.
    defer conn.releaseResidentBytes(item.data.len);
    const n = @min(dst.len, item.data.len);
    @memcpy(dst[0..n], item.data[0..n]);
    return .{
        .len = n,
        .payload_len = item.data.len,
        .arrived_in_early_data = item.arrived_in_early_data,
    };
}

/// Full payload length of the oldest queued inbound DATAGRAM, without
/// dequeuing it. Lets an embedder size (or grow) its read buffer before
/// calling `receiveDatagramInfo`, making the `payload_len > len`
/// truncation case unreachable. Null when no DATAGRAM is queued.
pub fn nextDatagramSize(conn: *const Connection) ?usize {
    const items = conn.pending_frames.recv_datagrams.items;
    if (items.len == 0) return null;
    return items[0].data.len;
}

/// Number of inbound DATAGRAMs queued for the app to read.
pub fn pendingDatagrams(conn: *const Connection) usize {
    return conn.pending_frames.recv_datagrams.items.len;
}
