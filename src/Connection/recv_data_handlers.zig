//! Inbound payload-bearing frame handlers: DATAGRAM (RFC 9221), CRYPTO
//! (RFC 9001 §4.1.3 — including the bounded reassembly inbox and the
//! drain into the TLS stack), and STREAM (RFC 9000 §19.8), plus the
//! recv-side resident-bytes reconciliation. Free-function siblings of
//! `Connection`'s method-style handlers; the methods on `Connection` are
//! thin thunks that delegate here. Control-frame handlers live in the
//! other conn_recv_*_handlers.zig siblings.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_streams = @import("streams.zig");
const conn_flow = @import("flow.zig");
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
const max_pending_datagram_bytes = state_mod.max_pending_datagram_bytes;
const max_pending_crypto_bytes_per_level = state_mod.max_pending_crypto_bytes_per_level;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const transport_error_flow_control = state_mod.transport_error_flow_control;
const transport_error_final_size = state_mod.transport_error_final_size;

/// Apply a peer-sent DATAGRAM frame (RFC 9221) to the inbound queue.
/// Public so per-connection hardening tests can drive the
/// resident-bytes accounting without crafting encrypted packets;
/// the production path is `handleOnePacket` → `handleApplication`.
pub fn handleDatagram(
    conn: *Connection,
    lvl: EncryptionLevel,
    dg: frame_types.Datagram,
) Error!void {
    const local_max = conn.local_transport_params.max_datagram_frame_size;
    if (local_max == 0 or dg.data.len > local_max or dg.data.len > max_supported_udp_payload_size) {
        conn.close(true, transport_error_protocol_violation, "datagram exceeds local limit");
        return;
    }
    if (conn.pending_frames.recv_datagrams.items.len >= max_pending_datagram_count) {
        conn.close(true, transport_error_protocol_violation, "datagram receive queue exhausted");
        return;
    }
    if (dg.data.len > max_pending_datagram_bytes or
        conn.pending_frames.recv_datagram_bytes > max_pending_datagram_bytes - dg.data.len)
    {
        conn.close(true, transport_error_protocol_violation, "datagram receive budget exhausted");
        return;
    }
    // Hardening guide §3.5 / §8: the inbound DATAGRAM queue and
    // every other peer-controlled buffer share one resident-bytes
    // budget so a peer cannot bypass each per-buffer cap by
    // ballooning many of them at once.
    conn.tryReserveResidentBytes(dg.data.len) catch {
        conn.close(true, transport_error_excessive_load, "excessive resource use");
        return;
    };
    const copy = conn.allocator.alloc(u8, dg.data.len) catch |err| {
        conn.releaseResidentBytes(dg.data.len);
        return err;
    };
    errdefer {
        conn.releaseResidentBytes(dg.data.len);
        conn.allocator.free(copy);
    }
    @memcpy(copy, dg.data);
    try conn.pending_frames.recv_datagrams.append(conn.allocator, .{
        .data = copy,
        .arrived_in_early_data = lvl == .early_data,
    });
    conn.pending_frames.recv_datagram_bytes += dg.data.len;
}

/// Apply a peer-sent CRYPTO frame's bytes at the given encryption
/// level. Public so per-connection hardening tests can drive the
/// reassembly path without crafting encrypted packets; the
/// production path is `handleOnePacket` → `handleInitial` etc.
pub fn handleCrypto(
    conn: *Connection,
    lvl: EncryptionLevel,
    cr: frame_types.Crypto,
) Error!void {
    const idx = lvl.idx();
    if (cr.data.len == 0) return;

    const start = cr.offset;
    const data_len: u64 = @intCast(cr.data.len);
    const end = std.math.add(u64, cr.offset, data_len) catch {
        conn.close(true, transport_error_protocol_violation, "crypto offset overflow");
        return;
    };
    const my_off = conn.crypto_recv_offset[idx];

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
        try conn.inbox[idx].append(eff_data);
        conn.crypto_recv_offset[idx] += eff_data.len;
        try drainPendingCrypto(conn, idx);
    } else {
        // Out-of-order — buffer.
        if (eff_offset - my_off > max_crypto_reassembly_gap) {
            conn.close(true, transport_error_protocol_violation, "crypto reassembly gap exceeds limit");
            return;
        }
        if (eff_data.len > max_pending_crypto_bytes_per_level or
            conn.crypto_pending_bytes[idx] > max_pending_crypto_bytes_per_level - eff_data.len)
        {
            conn.close(true, transport_error_protocol_violation, "crypto reassembly exceeds limit");
            return;
        }
        // Bound the fragment *count*, not just the byte volume: an
        // unbounded count of tiny fragments turns drainPendingCrypto's
        // O(n²) scan into a CPU-exhaustion vector (see the constant).
        if (conn.crypto_pending[idx].items.len >= max_pending_crypto_fragments_per_level) {
            conn.close(true, transport_error_protocol_violation, "crypto reassembly fragment count exceeds limit");
            return;
        }
        // Hardening guide §3.5 / §8: reserve from the global
        // resident-bytes budget *before* allocating. The per-level
        // crypto cap above gates a single level; this gates the
        // whole connection (CRYPTO + DATAGRAM + stream buffers
        // sharing one budget so a peer can't open many small
        // buffers and bypass each individual cap).
        conn.tryReserveResidentBytes(eff_data.len) catch {
            conn.close(true, transport_error_excessive_load, "excessive resource use");
            return;
        };
        const copy = conn.allocator.alloc(u8, eff_data.len) catch |err| {
            conn.releaseResidentBytes(eff_data.len);
            return err;
        };
        errdefer {
            conn.releaseResidentBytes(eff_data.len);
            conn.allocator.free(copy);
        }
        @memcpy(copy, eff_data);
        try conn.crypto_pending[idx].append(conn.allocator, .{
            .offset = eff_offset,
            .data = copy,
        });
        conn.crypto_pending_bytes[idx] += eff_data.len;
    }
}

fn drainPendingCrypto(conn: *Connection, idx: usize) Error!void {
    // Repeatedly find a pending chunk that starts at our floor
    // (or below it, in which case we clip), deliver it, and
    // bump the floor — until no chunk matches.
    outer: while (conn.crypto_pending[idx].items.len > 0) {
        const my_off = conn.crypto_recv_offset[idx];
        var i: usize = 0;
        while (i < conn.crypto_pending[idx].items.len) : (i += 1) {
            const chunk = conn.crypto_pending[idx].items[i];
            const c_end = std.math.add(u64, chunk.offset, @as(u64, @intCast(chunk.data.len))) catch {
                conn.close(true, transport_error_protocol_violation, "crypto pending offset overflow");
                return;
            };
            if (c_end <= my_off) {
                // Wholly below the floor — drop.
                conn.crypto_pending_bytes[idx] -= chunk.data.len;
                conn.releaseResidentBytes(chunk.data.len);
                conn.allocator.free(chunk.data);
                _ = conn.crypto_pending[idx].orderedRemove(i);
                continue :outer;
            }
            if (chunk.offset <= my_off) {
                // Bridges the floor — deliver the new portion.
                const skip: usize = @intCast(my_off - chunk.offset);
                const tail = chunk.data[skip..];
                try conn.inbox[idx].append(tail);
                conn.crypto_recv_offset[idx] += tail.len;
                conn.crypto_pending_bytes[idx] -= chunk.data.len;
                conn.releaseResidentBytes(chunk.data.len);
                conn.allocator.free(chunk.data);
                _ = conn.crypto_pending[idx].orderedRemove(i);
                continue :outer;
            }
        }
        // No chunk reaches the floor → done.
        break;
    }
}

pub fn cryptoInboxQueued(conn: *const Connection) bool {
    inline for (level_mod.all) |lvl| {
        if (conn.inbox[lvl.idx()].len > 0) return true;
    }
    return false;
}

/// Feed queued peer CRYPTO bytes into the TLS stack level-by-level
/// (low → high; keys for level N+1 are derived while processing
/// level N), make one extra handshake call for outgoing-only
/// progress, cache peer transport parameters once the handshake
/// completes, and queue HANDSHAKE_DONE if we owe the client one.
/// The shared pump behind the receive path (`drainInboxIntoTls`,
/// which appends the RFC 9001 key discards) and the embedder-facing
/// handshake driver (`Connection.advance`, which appends the
/// mock-transport shuttle and the alert check). Any fix to the pump
/// belongs here so both drivers stay in lockstep.
pub fn pumpTlsInbox(conn: *Connection) Error!void {
    inline for (level_mod.all) |lvl| {
        const idx = lvl.idx();
        if (conn.inbox[idx].len > 0) {
            const bytes = conn.inbox[idx].drain();
            try conn.inner.provideQuicData(lvl.toBoringssl(), bytes);
            if (conn.inner.handshakeDone()) {
                try conn.cachePeerTransportParams();
                try conn.inner.processQuicPostHandshake();
            } else {
                try conn.advanceHandshake();
            }
        }
    }
    if (!conn.inner.handshakeDone()) try conn.advanceHandshake();
    if (conn.inner.handshakeDone()) try conn.cachePeerTransportParams();
    conn.queueHandshakeDoneIfReady();
}

/// Receive-path TLS drain: `pumpTlsInbox` plus the RFC 9001 key
/// discards that belong to inbound-packet processing.
pub fn drainInboxIntoTls(conn: *Connection) Error!void {
    try pumpTlsInbox(conn);
    // RFC 9001 §5.7 ¶3 / ¶4: discard Initial keys once handshake
    // confirms. The strict spec timing is "first Handshake packet
    // sent" (client) / "first Handshake packet processed" (server),
    // but in quic's flow the client's first Handshake send is
    // accompanied by an Initial-level ACK that's still needed by
    // the server, so we wait until handshake confirms — at which
    // point no further Initial activity is legitimate. Latched +
    // idempotent.
    if (conn.inner.handshakeDone() and !conn.initial_keys_discarded) {
        conn_keys.discardInitialKeys(
            conn,
        );
    }
    // RFC 9001 §4.1.2 ¶1 / §4.9.2: the server's "TLS handshake
    // confirmed" event coincides with TLS handshake completion
    // (i.e. processing the client's Finished). The matching key
    // discard runs immediately. The client takes the symmetrical
    // path on receipt of HANDSHAKE_DONE — see the
    // `received_handshake_done` arm in the frame switch above and
    // the `handleWithEcn` post-loop discard.
    if (conn.role == .server and conn.inner.handshakeDone() and !conn.handshake_keys_discarded) {
        conn.discardHandshakeKeys();
    }
    try conn.refreshEarlyDataStatus();
}

/// Apply a peer-sent STREAM frame to the matching stream's recv
/// reassembly buffer (creating the stream if it is peer-initiated
/// and not yet seen). Public so per-connection hardening tests can
/// drive the recv-reassembly path without crafting encrypted
/// packets; the production path is `handleOnePacket` →
/// `handleApplication`.
pub fn handleStream(
    conn: *Connection,
    lvl: EncryptionLevel,
    s: frame_types.Stream,
) Error!void {
    const frame_end = std.math.add(u64, s.offset, @as(u64, @intCast(s.data.len))) catch {
        conn.close(true, transport_error_flow_control, "stream offset overflow");
        return;
    };
    const ptr = (try conn_streams.ensurePeerStream(conn, s.stream_id, .stream_data)) orelse return;
    if (lvl == .early_data) ptr.arrived_in_early_data = true;
    const delta = conn_flow.creditPeerStreamHighWater(conn, ptr, frame_end, .{
        .stream = "peer exceeded stream data limit",
        .conn = "peer exceeded connection data limit",
    }) orelse return;
    // Hardening guide §3.5 / §8: snapshot the recv-buffer length
    // around `recv()` and reconcile the global resident-bytes
    // budget. `RecvStream.recv` may grow its internal buffer to
    // cover [read_offset, frame_end) — the diff captures whatever
    // it actually allocated (overlapping ranges deduplicate, so
    // the diff can be 0 or smaller than `s.data.len`). The budget
    // keys on the PHYSICAL `bytes.items.len`: the sliding-window
    // consumed prefix keeps its charge until the next compaction
    // (bounded by the half-buffer policy), which is correct — the
    // memory is genuinely allocated while the prefix sits in it.
    const recv_before = ptr.recv.bytes.items.len;
    ptr.recv.recv(s.offset, s.data, s.fin) catch |err| switch (err) {
        error.BufferLimitExceeded => {
            reconcileRecvResidentBytes(conn, ptr, recv_before);
            conn.close(true, transport_error_protocol_violation, "stream reassembly exceeds allocation limit");
            return;
        },
        error.BeyondFinalSize, error.FinalSizeChanged => {
            reconcileRecvResidentBytes(conn, ptr, recv_before);
            conn.close(true, transport_error_final_size, "stream final size changed");
            return;
        },
        else => {
            reconcileRecvResidentBytes(conn, ptr, recv_before);
            return err;
        },
    };
    if (ptr.recv.bytes.items.len > recv_before) {
        const grew = ptr.recv.bytes.items.len - recv_before;
        conn.tryReserveResidentBytes(grew) catch {
            conn.close(true, transport_error_excessive_load, "excessive resource use");
            return;
        };
    } else if (ptr.recv.bytes.items.len < recv_before) {
        conn.releaseResidentBytes(recv_before - ptr.recv.bytes.items.len);
    }
    conn.peer_sent_stream_data += delta;
}

/// Best-effort reconciliation of the resident-bytes counter when
/// `RecvStream.recv` partially advanced its internal buffer before
/// returning an error. Releases bytes the recv buffer dropped on
/// the error path; if the buffer grew, the bytes are conceded to
/// the running total but the connection is closing immediately so
/// the over-count never leaks past `tick` / `reap`.
fn reconcileRecvResidentBytes(conn: *Connection, ptr: *Stream, recv_before: usize) void {
    const after = ptr.recv.bytes.items.len;
    if (after < recv_before) {
        conn.releaseResidentBytes(recv_before - after);
    }
}
