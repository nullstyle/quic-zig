// Inbound payload-bearing frame handlers: DATAGRAM (RFC 9221), CRYPTO
// (RFC 9001 §4.1.3 — including the bounded reassembly inbox and the
// drain into the TLS stack), and STREAM (RFC 9000 §19.8), plus the
// recv-side resident-bytes reconciliation. Free-function siblings of
// `Connection`'s method-style handlers; the methods on `Connection` are
// thin thunks that delegate here. Control-frame handlers live in the
// other conn_recv_*_handlers.zig siblings.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_streams = @import("streams.zig");
const conn_keys = @import("keys.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const Stream = state_mod.Stream;
const frame_types = state_mod.frame_types;
const level_mod = state_mod.level_mod;
const max_recv_plaintext = state_mod.max_recv_plaintext;
const max_pending_crypto_fragments_per_level = state_mod.max_pending_crypto_fragments_per_level;
const transport_error_excessive_load = state_mod.transport_error_excessive_load;
const max_supported_udp_payload_size = state_mod.max_supported_udp_payload_size;
const max_pending_datagram_count = state_mod.max_pending_datagram_count;
const max_crypto_reassembly_gap = state_mod.max_crypto_reassembly_gap;
const SendStream = state_mod.SendStream;
const RecvStream = state_mod.RecvStream;
const max_pending_datagram_bytes = state_mod.max_pending_datagram_bytes;
const max_pending_crypto_bytes_per_level = state_mod.max_pending_crypto_bytes_per_level;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const transport_error_stream_state = state_mod.transport_error_stream_state;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_final_size = state_mod.transport_error_final_size;
const transport_error_stream_limit = state_mod.transport_error_stream_limit;

/// Apply a peer-sent DATAGRAM frame (RFC 9221) to the inbound queue.
/// Public so per-connection hardening tests can drive the
/// resident-bytes accounting without crafting encrypted packets;
/// the production path is `handleOnePacket` → `handleApplication`.
pub fn handleDatagram(
    self: *Connection,
    lvl: EncryptionLevel,
    dg: frame_types.Datagram,
) Error!void {
    const local_max = self.local_transport_params.max_datagram_frame_size;
    if (local_max == 0 or dg.data.len > local_max or dg.data.len > max_supported_udp_payload_size) {
        self.close(true, transport_error_protocol_violation, "datagram exceeds local limit");
        return;
    }
    if (self.pending_frames.recv_datagrams.items.len >= max_pending_datagram_count) {
        self.close(true, transport_error_protocol_violation, "datagram receive queue exhausted");
        return;
    }
    if (dg.data.len > max_pending_datagram_bytes or
        self.pending_frames.recv_datagram_bytes > max_pending_datagram_bytes - dg.data.len)
    {
        self.close(true, transport_error_protocol_violation, "datagram receive budget exhausted");
        return;
    }
    // Hardening guide §3.5 / §8: the inbound DATAGRAM queue and
    // every other peer-controlled buffer share one resident-bytes
    // budget so a peer cannot bypass each per-buffer cap by
    // ballooning many of them at once.
    self.tryReserveResidentBytes(dg.data.len) catch {
        self.close(true, transport_error_excessive_load, "excessive resource use");
        return;
    };
    const copy = self.allocator.alloc(u8, dg.data.len) catch |err| {
        self.releaseResidentBytes(dg.data.len);
        return err;
    };
    errdefer {
        self.releaseResidentBytes(dg.data.len);
        self.allocator.free(copy);
    }
    @memcpy(copy, dg.data);
    try self.pending_frames.recv_datagrams.append(self.allocator, .{
        .data = copy,
        .arrived_in_early_data = lvl == .early_data,
    });
    self.pending_frames.recv_datagram_bytes += dg.data.len;
}

/// Apply a peer-sent CRYPTO frame's bytes at the given encryption
/// level. Public so per-connection hardening tests can drive the
/// reassembly path without crafting encrypted packets; the
/// production path is `handleOnePacket` → `handleInitial` etc.
pub fn handleCrypto(
    self: *Connection,
    lvl: EncryptionLevel,
    cr: frame_types.Crypto,
) Error!void {
    const idx = lvl.idx();
    if (cr.data.len == 0) return;

    const start = cr.offset;
    const data_len: u64 = @intCast(cr.data.len);
    const end = std.math.add(u64, cr.offset, data_len) catch {
        self.close(true, transport_error_protocol_violation, "crypto offset overflow");
        return;
    };
    const my_off = self.crypto_recv_offset[idx];

    // Already delivered → ignore (retransmit / overlap).
    if (end <= my_off) return;

    // Clip any prefix that was already delivered.
    const data_start: usize = if (start < my_off)
        @intCast(my_off - start)
    else
        0;
    const eff_offset: u64 = @max(start, my_off);
    const eff_data = cr.data[data_start..];

    if (eff_offset == my_off) {
        try self.inbox[idx].append(eff_data);
        self.crypto_recv_offset[idx] += eff_data.len;
        try drainPendingCrypto(self, idx);
    } else {
        // Out-of-order — buffer.
        if (eff_offset - my_off > max_crypto_reassembly_gap) {
            self.close(true, transport_error_protocol_violation, "crypto reassembly gap exceeds limit");
            return;
        }
        if (eff_data.len > max_pending_crypto_bytes_per_level or
            self.crypto_pending_bytes[idx] > max_pending_crypto_bytes_per_level - eff_data.len)
        {
            self.close(true, transport_error_protocol_violation, "crypto reassembly exceeds limit");
            return;
        }
        // Bound the fragment *count*, not just the byte volume: an
        // unbounded count of tiny fragments turns drainPendingCrypto's
        // O(n²) scan into a CPU-exhaustion vector (see the constant).
        if (self.crypto_pending[idx].items.len >= max_pending_crypto_fragments_per_level) {
            self.close(true, transport_error_protocol_violation, "crypto reassembly fragment count exceeds limit");
            return;
        }
        // Hardening guide §3.5 / §8: reserve from the global
        // resident-bytes budget *before* allocating. The per-level
        // crypto cap above gates a single level; this gates the
        // whole connection (CRYPTO + DATAGRAM + stream buffers
        // sharing one budget so a peer can't open many small
        // buffers and bypass each individual cap).
        self.tryReserveResidentBytes(eff_data.len) catch {
            self.close(true, transport_error_excessive_load, "excessive resource use");
            return;
        };
        const copy = self.allocator.alloc(u8, eff_data.len) catch |err| {
            self.releaseResidentBytes(eff_data.len);
            return err;
        };
        errdefer {
            self.releaseResidentBytes(eff_data.len);
            self.allocator.free(copy);
        }
        @memcpy(copy, eff_data);
        try self.crypto_pending[idx].append(self.allocator, .{
            .offset = eff_offset,
            .data = copy,
        });
        self.crypto_pending_bytes[idx] += eff_data.len;
    }
}

fn drainPendingCrypto(self: *Connection, idx: usize) Error!void {
    // Repeatedly find a pending chunk that starts at our floor
    // (or below it, in which case we clip), deliver it, and
    // bump the floor — until no chunk matches.
    outer: while (self.crypto_pending[idx].items.len > 0) {
        const my_off = self.crypto_recv_offset[idx];
        var i: usize = 0;
        while (i < self.crypto_pending[idx].items.len) : (i += 1) {
            const chunk = self.crypto_pending[idx].items[i];
            const c_end = std.math.add(u64, chunk.offset, @as(u64, @intCast(chunk.data.len))) catch {
                self.close(true, transport_error_protocol_violation, "crypto pending offset overflow");
                return;
            };
            if (c_end <= my_off) {
                // Wholly below the floor — drop.
                self.crypto_pending_bytes[idx] -= chunk.data.len;
                self.releaseResidentBytes(chunk.data.len);
                self.allocator.free(chunk.data);
                _ = self.crypto_pending[idx].orderedRemove(i);
                continue :outer;
            }
            if (chunk.offset <= my_off) {
                // Bridges the floor — deliver the new portion.
                const skip: usize = @intCast(my_off - chunk.offset);
                const tail = chunk.data[skip..];
                try self.inbox[idx].append(tail);
                self.crypto_recv_offset[idx] += tail.len;
                self.crypto_pending_bytes[idx] -= chunk.data.len;
                self.releaseResidentBytes(chunk.data.len);
                self.allocator.free(chunk.data);
                _ = self.crypto_pending[idx].orderedRemove(i);
                continue :outer;
            }
        }
        // No chunk reaches the floor → done.
        break;
    }
}

pub fn cryptoInboxQueued(self: *const Connection) bool {
    inline for (level_mod.all) |lvl| {
        if (self.inbox[lvl.idx()].len > 0) return true;
    }
    return false;
}

pub fn drainInboxIntoTls(self: *Connection) Error!void {
    inline for (level_mod.all) |lvl| {
        const idx = lvl.idx();
        if (self.inbox[idx].len > 0) {
            const bytes = self.inbox[idx].drain();
            try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
            if (self.inner.handshakeDone()) {
                try self.cachePeerTransportParams();
                try self.inner.processQuicPostHandshake();
            } else {
                try self.advanceHandshake();
            }
        }
    }
    if (!self.inner.handshakeDone()) try self.advanceHandshake();
    if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
    self.queueHandshakeDoneIfReady();
    // RFC 9001 §5.7 ¶3 / ¶4: discard Initial keys once handshake
    // confirms. The strict spec timing is "first Handshake packet
    // sent" (client) / "first Handshake packet processed" (server),
    // but in quic's flow the client's first Handshake send is
    // accompanied by an Initial-level ACK that's still needed by
    // the server, so we wait until handshake confirms — at which
    // point no further Initial activity is legitimate. Latched +
    // idempotent.
    if (self.inner.handshakeDone() and !self.initial_keys_discarded) {
        conn_keys.discardInitialKeys(
            self,
        );
    }
    // RFC 9001 §4.1.2 ¶1 / §4.9.2: the server's "TLS handshake
    // confirmed" event coincides with TLS handshake completion
    // (i.e. processing the client's Finished). The matching key
    // discard runs immediately. The client takes the symmetrical
    // path on receipt of HANDSHAKE_DONE — see the
    // `received_handshake_done` arm in the frame switch above and
    // the `handleWithEcn` post-loop discard.
    if (self.role == .server and self.inner.handshakeDone() and !self.handshake_keys_discarded) {
        self.discardHandshakeKeys();
    }
    try self.refreshEarlyDataStatus();
}

/// Apply a peer-sent STREAM frame to the matching stream's recv
/// reassembly buffer (creating the stream if it is peer-initiated
/// and not yet seen). Public so per-connection hardening tests can
/// drive the recv-reassembly path without crafting encrypted
/// packets; the production path is `handleOnePacket` →
/// `handleApplication`.
pub fn handleStream(
    self: *Connection,
    lvl: EncryptionLevel,
    s: frame_types.Stream,
) Error!void {
    if (!conn_streams.peerMaySendOnStream(self, s.stream_id)) {
        self.close(true, transport_error_stream_state, "stream data on receive-only stream");
        return;
    }
    const frame_end = std.math.add(u64, s.offset, @as(u64, @intCast(s.data.len))) catch {
        self.close(true, transport_error_flow_control, "stream offset overflow");
        return;
    };
    const existing = self.streams.get(s.stream_id);
    if (existing == null and conn_streams.streamInitiatedByLocal(self, s.stream_id)) {
        self.close(true, transport_error_stream_state, "peer referenced unopened local stream");
        return;
    }
    // RFC 9000 §3.2: a STREAM frame for a peer stream that already
    // reached a terminal state and was reaped is post-terminal — drop
    // it instead of resurrecting the stream with fresh (final-size /
    // reset) state. Checked before recordPeerStreamOpenOrClose so the
    // id is neither re-counted nor recreated.
    if (existing == null and conn_streams.peerStreamAlreadyReaped(self, s.stream_id)) return;
    if (existing == null and !self.recordPeerStreamOpenOrClose(s.stream_id)) return;

    const ptr = existing orelse blk: {
        const new_ptr = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(new_ptr);
        new_ptr.* = .{
            .id = s.stream_id,
            .send = SendStream.init(self.allocator),
            .recv = RecvStream.init(self.allocator),
            .recv_max_data = self.initialRecvStreamLimit(s.stream_id),
            .send_max_data = self.initialSendStreamLimit(s.stream_id),
        };
        try self.streams.put(self.allocator, s.stream_id, new_ptr);
        break :blk new_ptr;
    };
    if (lvl == .early_data) ptr.arrived_in_early_data = true;
    const old_highest = ptr.recv.peerHighestOffset();
    const new_highest = @max(old_highest, frame_end);
    if (new_highest > ptr.recv_max_data) {
        self.close(true, transport_error_flow_control, "peer exceeded stream data limit");
        return;
    }
    const delta = new_highest - old_highest;
    if (delta > 0 and
        (delta > self.local_max_data or self.peer_sent_stream_data > self.local_max_data - delta))
    {
        self.close(true, transport_error_flow_control, "peer exceeded connection data limit");
        return;
    }
    // Hardening guide §3.5 / §8: snapshot the recv-buffer length
    // around `recv()` and reconcile the global resident-bytes
    // budget. `RecvStream.recv` may grow its internal buffer to
    // cover [read_offset, frame_end) — the diff captures whatever
    // it actually allocated (overlapping ranges deduplicate, so
    // the diff can be 0 or smaller than `s.data.len`).
    const recv_before = ptr.recv.bytes.items.len;
    ptr.recv.recv(s.offset, s.data, s.fin) catch |err| switch (err) {
        error.BufferLimitExceeded => {
            reconcileRecvResidentBytes(self, ptr, recv_before);
            self.close(true, transport_error_protocol_violation, "stream reassembly exceeds allocation limit");
            return;
        },
        error.BeyondFinalSize, error.FinalSizeChanged => {
            reconcileRecvResidentBytes(self, ptr, recv_before);
            self.close(true, transport_error_final_size, "stream final size changed");
            return;
        },
        else => {
            reconcileRecvResidentBytes(self, ptr, recv_before);
            return err;
        },
    };
    if (ptr.recv.bytes.items.len > recv_before) {
        const grew = ptr.recv.bytes.items.len - recv_before;
        self.tryReserveResidentBytes(grew) catch {
            self.close(true, transport_error_excessive_load, "excessive resource use");
            return;
        };
    } else if (ptr.recv.bytes.items.len < recv_before) {
        self.releaseResidentBytes(recv_before - ptr.recv.bytes.items.len);
    }
    self.peer_sent_stream_data += delta;
}

/// Best-effort reconciliation of the resident-bytes counter when
/// `RecvStream.recv` partially advanced its internal buffer before
/// returning an error. Releases bytes the recv buffer dropped on
/// the error path; if the buffer grew, the bytes are conceded to
/// the running total but the connection is closing immediately so
/// the over-count never leaks past `tick` / `reap`.
fn reconcileRecvResidentBytes(self: *Connection, ptr: *Stream, recv_before: usize) void {
    const after = ptr.recv.bytes.items.len;
    if (after < recv_before) {
        self.releaseResidentBytes(recv_before - after);
    }
}
