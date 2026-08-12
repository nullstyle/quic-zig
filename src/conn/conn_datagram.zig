// The DATAGRAM extension (RFC 9221): the embedder send/receive API,
// payload sizing against the negotiated limits and current PMTU, and
// the tracked-send acked/lost event bookkeeping. Free-function
// siblings of `Connection`'s method-style datagram API; the methods on
// `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("state.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const event_queue_mod = state_mod.event_queue_mod;
const sent_packets_mod = state_mod.sent_packets_mod;
const StoredDatagramSendEvent = event_queue_mod.StoredDatagramSendEvent;
const default_mtu = state_mod.default_mtu;
const max_datagram_frame_size = state_mod.max_datagram_frame_size;
const max_pending_datagram_count = state_mod.max_pending_datagram_count;
const max_outbound_datagram_payload_size = state_mod.max_outbound_datagram_payload_size;
const IncomingDatagram = state_mod.IncomingDatagram;
const max_pending_datagram_bytes = state_mod.max_pending_datagram_bytes;
const max_recv_plaintext = state_mod.max_recv_plaintext;

fn recordDatagramSendEvent(self: *Connection, event: StoredDatagramSendEvent) void {
    self.datagram_send_events.push(event);
}

pub fn recordDatagramAcked(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
    const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
    recordDatagramSendEvent(self, .{ .acked = event });
}

pub fn recordDatagramLost(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
    const event = event_queue_mod.datagramEventFromPacket(packet) orelse return;
    recordDatagramSendEvent(self, .{ .lost = event });
}

// Doc comment lives on the `Connection.sendDatagram` thunk in state.zig.
pub fn sendDatagram(self: *Connection, payload: []const u8) Error!void {
    _ = try sendDatagramTracked(self, payload);
}

// Doc comment lives on the `Connection.sendDatagramTracked` thunk in state.zig.
pub fn sendDatagramTracked(self: *Connection, payload: []const u8) Error!u64 {
    const max_payload = try maxDatagramPayload(
        self,
    );
    if (payload.len > max_payload) return Error.DatagramTooLarge;
    if (self.pending_frames.send_datagrams.items.len >= max_pending_datagram_count) {
        return Error.DatagramQueueFull;
    }
    if (payload.len > max_pending_datagram_bytes or
        self.pending_frames.send_datagram_bytes > max_pending_datagram_bytes - payload.len)
    {
        return Error.DatagramQueueFull;
    }
    const copy = try self.allocator.alloc(u8, payload.len);
    errdefer self.allocator.free(copy);
    @memcpy(copy, payload);
    if (self.next_datagram_id == std.math.maxInt(u64)) return Error.DatagramIdExhausted;
    const id = self.next_datagram_id;
    self.next_datagram_id += 1;
    try self.pending_frames.send_datagrams.append(self.allocator, .{
        .id = id,
        .data = copy,
    });
    self.pending_frames.send_datagram_bytes += payload.len;
    return id;
}

// Doc comment lives on the `Connection.maxDatagramPayload` thunk in state.zig.
pub fn maxDatagramPayload(self: *const Connection) Error!usize {
    // Room a 1-RTT packet + DATAGRAM frame need around the payload. The
    // reserve matches the historical `default_mtu`-derived ceiling at the
    // 1200-byte floor, so behavior there is unchanged and only the
    // PMTU-scaling is new; the send-time build guard enforces exact fit.
    const packet_reserve: usize = default_mtu - max_outbound_datagram_payload_size;
    // Grow/shrink with the active path's PMTU, but never past the
    // plaintext buffer the send path builds a packet into.
    var limit: usize = @min(self.pmtu() -| packet_reserve, max_recv_plaintext);
    if (self.cached_peer_transport_params) |params| {
        if (params.max_datagram_frame_size == 0) return Error.DatagramUnavailable;
        limit = @min(limit, @as(usize, @intCast(params.max_datagram_frame_size)));
    }
    return limit;
}

// Doc comment lives on the `Connection.receiveDatagram` thunk in state.zig.
pub fn receiveDatagram(self: *Connection, dst: []u8) ?usize {
    const item = receiveDatagramInfo(self, dst) orelse return null;
    return item.len;
}

// Doc comment lives on the `Connection.receiveDatagramInfo` thunk in state.zig.
pub fn receiveDatagramInfo(self: *Connection, dst: []u8) ?IncomingDatagram {
    const item = self.pending_frames.popRecvDatagram() orelse return null;
    defer self.allocator.free(item.data);
    // Hardening guide §3.5 / §8: pair the resident-bytes release
    // with the queue dequeue. `popRecvDatagram` already decrements
    // `recv_datagram_bytes`; this drops the matching cents from
    // the global resident-bytes counter.
    defer self.releaseResidentBytes(item.data.len);
    const n = @min(dst.len, item.data.len);
    @memcpy(dst[0..n], item.data[0..n]);
    return .{ .len = n, .arrived_in_early_data = item.arrived_in_early_data };
}

/// Number of inbound DATAGRAMs queued for the app to read.
pub fn pendingDatagrams(self: *const Connection) usize {
    return self.pending_frames.recv_datagrams.items.len;
}
