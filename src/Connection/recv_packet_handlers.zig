//! Inbound packet handlers for the six per-encryption-level packet
//! dispatch paths a `Connection` exposes: Version Negotiation, Initial,
//! Retry, 0-RTT (early data), Handshake, and 1-RTT (short header).
//! Each handler is responsible for header parse / AEAD open / reserved-
//! bits gate / per-level state updates and then defers frame-level
//! processing to `Connection.dispatchFrames`. Free-function siblings of
//! `Connection`'s public method-style handlers; the methods on
//! `Connection` are thin thunks that delegate here.
//!
//! `Connection.handleOnePacket` (the long-header type dispatcher) stays
//! in Connection.zig — it's the orchestrator that picks which of these six
//! handlers to invoke based on the first byte / version field.
//!
//! The per-level tails that the RFCs specify identically at every
//! level live in two private helpers at the bottom of this file:
//! `openLongOrDrop` (AEAD-auth drop + §17.2.1 ¶17 reserved-bits gate)
//! and `finishOpenedPacket` (§10.2.1 ¶3 closing attribution,
//! duplicate-PN dispatch guard, ACK-tracker recording, qlog, frame
//! dispatch). What genuinely differs per level — ACK timing, return
//! length, level-specific preludes — stays in the handlers.

const std = @import("std");
const boringssl = @import("boringssl");
const state_mod = @import("../Connection.zig");
const conn_paths = @import("paths.zig");
const conn_keys = @import("keys.zig");
const conn_qlog = @import("qlog.zig");
const conn_recv_dispatch = @import("recv_dispatch.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const ConnectionId = state_mod.ConnectionId;
const EncryptionLevel = state_mod.EncryptionLevel;
const PacketKeys = state_mod.PacketKeys;
const PnSpace = state_mod.PnSpace;
const wire_header_mod = state_mod.wire_header_mod;
const long_packet_mod = state_mod.long_packet_mod;
const path_mod = state_mod.path_mod;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;
const max_recv_plaintext = state_mod.max_recv_plaintext;

/// Handle a Version Negotiation packet (RFC 8999 §6 / RFC 9000 §6).
/// Client-only entrypoint: validate that the VN is bound to our
/// outstanding Initial (matches our SCID and the original DCID), then
/// either ignore it (if the peer still lists v1) or terminate the
/// connection if no compatible version is offered.
pub fn handleVersionNegotiation(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) usize {
    if (conn.role != .client or conn.inner.handshakeDone()) return bytes.len;
    const parsed = wire_header_mod.parse(bytes, 0) catch return bytes.len;
    if (parsed.header != .version_negotiation) return bytes.len;
    const vn = parsed.header.version_negotiation;
    if (!conn.local_scid_set or !conn.initial_dcid_set) return bytes.len;
    if (!std.mem.eql(u8, vn.dcid.slice(), conn.local_scid.slice())) return bytes.len;
    const odcid = if (conn.original_initial_dcid_set)
        conn.original_initial_dcid
    else
        conn.initial_dcid;
    if (!std.mem.eql(u8, vn.scid.slice(), odcid.slice())) return bytes.len;
    // The connection's currently-active version must NOT appear in the
    // VN list — RFC 8999 §6 / RFC 9000 §6 say a peer MUST send VN only
    // when it does NOT support our version. If our version is listed,
    // we silently ignore the VN per the same spec text (this includes
    // the v1↔v2 case where a server happens to support both).
    if (conn_recv_dispatch.versionListContains(vn, conn.version)) return bytes.len;

    conn.enterClosed(
        .version_negotiation,
        .transport,
        0,
        0,
        "no compatible QUIC version",
        now_us,
    );
    return bytes.len;
}

/// Handle a 1-RTT (short-header) packet (RFC 9000 §17.3 / RFC 9001 §5).
/// Resolves the receiving path, opens the packet under one of the
/// current/previous/next application read-key epochs, applies key
/// updates, and dispatches frames. Stateless-reset detection is folded
/// into both the no-keys and decryption-failure branches.
pub fn handleShort(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    const app_path = conn.incomingShortPath(bytes) orelse
        conn_paths.pathForId(conn, conn.current_incoming_path_id);
    conn.current_incoming_path_id = app_path.id;
    const app_pn_space = &app_path.app_pn_space;
    const largest_received = if (app_pn_space.received.largest) |l| l else 0;
    const multipath_path_id: ?u32 = if (conn.multipathNegotiated()) app_path.id else null;
    if (conn.app_read_current == null) {
        if (conn.isKnownStatelessReset(bytes)) {
            conn_qlog.emitPacketDropped(conn, .application, @intCast(bytes.len), .stateless_reset);
            conn.enterStatelessReset(now_us);
        } else {
            conn_qlog.emitPacketDropped(conn, .application, @intCast(bytes.len), .keys_unavailable);
        }
        return bytes.len;
    }

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const open_result = (try conn_recv_dispatch.openApplicationPacket(
        conn,
        &pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
    )) orelse {
        if (conn.isKnownStatelessReset(bytes)) {
            conn_qlog.emitPacketDropped(conn, .application, @intCast(bytes.len), .stateless_reset);
            conn.enterStatelessReset(now_us);
            return bytes.len;
        }
        conn_qlog.emitPacketDropped(conn, .application, @intCast(bytes.len), .decryption_failure);
        conn_keys.noteApplicationAuthFailure(
            conn,
        );
        return bytes.len;
    };
    if (open_result.slot == .next) {
        try conn.promoteApplicationReadKeys(now_us);
        try conn_keys.maybeRespondToPeerKeyUpdate(conn, now_us);
    }
    const opened = open_result.opened;

    // RFC 9000 §17.3 ¶3: short-header Reserved Bits MUST be 0 after
    // header protection is removed. AEAD just authenticated the
    // post-HP first byte (it's mixed into the AAD), so a non-zero
    // value is a peer protocol violation. (Same rule as the
    // long-header gate inside `openLongOrDrop`, but the bits sit at
    // different positions in the wire layout and the cite differs —
    // this copy is deliberately the short-header variant.)
    if (opened.reserved_bits != 0) {
        conn.close(true, transport_error_protocol_violation, "non-zero short-header reserved bits");
        return bytes.len;
    }

    return finishOpenedPacket(
        conn,
        .application,
        app_path.id,
        opened.pn,
        opened.payload,
        app_pn_space,
        bytes.len,
        now_us,
    );
}

/// Handle an Initial packet (RFC 9000 §17.2.2 / RFC 9001 §5.2). Server
/// side bootstraps `initial_dcid` from the unprotected long-header
/// bytes before any key derivation. Both roles validate the long-header
/// reserved-bits gate, then dispatch frames at the .initial level.
pub fn handleInitial(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    // Server-side bootstrap: discover `initial_dcid` from the
    // unprotected long-header bytes before any decryption can
    // happen. RFC 9001 §5.2 derives Initial keys from the DCID
    // the client put on its first Initial.
    if (conn.role == .server and !conn.initial_dcid_set) {
        if (bytes.len < 6) {
            conn_qlog.emitPacketDropped(conn, .initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        const dcid_len = bytes[5];
        if (dcid_len > path_mod.max_cid_len) {
            conn_qlog.emitPacketDropped(conn, .initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        if (bytes.len < @as(usize, 6) + dcid_len) {
            conn_qlog.emitPacketDropped(conn, .initial, @intCast(bytes.len), .header_decode_failure);
            return bytes.len;
        }
        try conn.setInitialDcid(bytes[6 .. 6 + dcid_len]);
    }
    // RFC 9368 §6 client-side compatible-version-negotiation upgrade
    // detection: the server may answer the client's wire-version
    // Initial under a *different* version drawn from the client's
    // advertised `version_information.available_versions`. When that
    // happens, the inbound long-header version field will not match
    // `conn.version`. Try to flip our active version so Initial-key
    // derivation below picks up the upgrade-target salt + HKDF labels.
    //
    // Defensive: `clientAcceptCompatibleVersion` re-validates the role,
    // the candidate's presence in our advertised list, and the
    // pre-handshake state. If it returns false the candidate is
    // dropped and decryption falls through to AEAD-auth failure under
    // the wire-version keys (which silently drops the packet — the
    // spec-compliant fallback). The check is gated on the receive-side
    // Initial space being empty so a stale-but-on-wire-version Initial
    // arriving after the upgrade can't accidentally flip us back.
    if (conn.role == .client and bytes.len >= 5) {
        const inbound_version = std.mem.readInt(u32, bytes[1..5], .big);
        if (inbound_version != conn.version and conn.pnSpaceForLevel(.initial).received.largest == null) {
            _ = conn.clientAcceptCompatibleVersion(inbound_version);
        }
    }
    try conn_keys.ensureInitialKeys(
        conn,
    );
    const r_keys_opt = conn.initial_keys_read;
    const r_keys = r_keys_opt orelse {
        conn_qlog.emitPacketDropped(conn, .initial, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = (try openLongOrDrop(
        conn,
        &pt_buf,
        bytes,
        .initial,
        &r_keys,
        if (conn.pnSpaceForLevel(.initial).received.largest) |l| l else 0,
    )) orelse return bytes.len;

    // Server side: discover peer's CIDs from the very first Initial.
    if (conn.role == .server) {
        if (!conn.peer_dcid_set) {
            conn.peer_dcid = ConnectionId.fromSlice(opened.scid.slice());
            conn.peer_dcid_set = true;
        }
        if (!conn.initial_dcid_set) {
            conn.initial_dcid = ConnectionId.fromSlice(opened.dcid.slice());
            conn.initial_dcid_set = true;
            try conn_keys.ensureInitialKeys(
                conn,
            );
        }
        conn_qlog.emitConnectionStartedOnce(
            conn,
        );
    }
    if (conn.role == .client) {
        const server_scid = ConnectionId.fromSlice(opened.scid.slice());
        if (!ConnectionId.eql(conn.primaryPath().path.peer_cid, server_scid)) {
            try conn.setPeerDcid(server_scid.slice());
        }
    }

    return finishOpenedPacket(
        conn,
        .initial,
        conn_paths.pathForId(conn, conn.current_incoming_path_id).id,
        opened.pn,
        opened.payload,
        conn.pnSpaceForLevel(.initial),
        opened.bytes_consumed,
        now_us,
    );
}

/// Handle a Retry packet (RFC 9000 §17.2.5). Client-only: validates
/// the Retry Integrity Tag against the original DCID, stashes the
/// retry token + new SCID, then resets the Initial recovery state so
/// the next Initial flight goes out under the server-supplied DCID
/// and carries the token.
pub fn handleRetry(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    _ = now_us;
    if (conn.role != .client or conn.retry_accepted or conn.inner.handshakeDone()) {
        return bytes.len;
    }
    const parsed = wire_header_mod.parse(bytes, 0) catch return bytes.len;
    if (parsed.header != .retry) return bytes.len;
    const retry = parsed.header.retry;
    // Retry's version field MUST match our active version; if a v1
    // server tries to Retry our v2 Initial (or vice versa) we silently
    // drop. RFC 9368 §3.3.3 ties the integrity tag to the Retry's
    // version, so a mismatched version here would also fail tag
    // validation a few lines below.
    if (retry.version != conn.version) return bytes.len;
    if (!conn.local_scid_set or !conn.initial_dcid_set) return bytes.len;
    if (!std.mem.eql(u8, retry.dcid.slice(), conn.local_scid.slice())) return bytes.len;

    const odcid = if (conn.original_initial_dcid_set)
        conn.original_initial_dcid
    else
        conn.initial_dcid;
    if (std.mem.eql(u8, retry.scid.slice(), odcid.slice())) {
        return bytes.len;
    }
    const retry_valid = long_packet_mod.validateRetryIntegrity(odcid.slice(), bytes) catch return bytes.len;
    if (!retry_valid) {
        return bytes.len;
    }

    try conn.retry_token.resize(conn.allocator, retry.retry_token.len);
    @memcpy(conn.retry_token.items, retry.retry_token);
    conn.retry_source_cid = ConnectionId.fromSlice(retry.scid.slice());
    conn.retry_source_cid_set = true;
    conn.retry_accepted = true;

    try conn.setPeerDcid(retry.scid.slice());
    try conn.setInitialDcid(retry.scid.slice());
    try conn.resetInitialRecoveryForRetry();
    return bytes.len;
}

/// Handle a 0-RTT (early data) packet (RFC 9001 §4.6). Server-only:
/// drop if 0-RTT was rejected or keys are unavailable. Otherwise open
/// under the early-data read keys, gate on the long-header reserved
/// bits, and dispatch frames at the .early_data level.
pub fn handleZeroRtt(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    if (conn.role != .server) {
        conn_qlog.emitPacketDropped(conn, .early_data, @intCast(bytes.len), .other);
        return bytes.len;
    }
    if (conn.inner.earlyDataStatus() == .rejected) {
        conn_qlog.emitPacketDropped(conn, .early_data, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    }

    const r_keys_opt = try conn.packetKeys(.early_data, .read);
    const r_keys = r_keys_opt orelse {
        conn_qlog.emitPacketDropped(conn, .early_data, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };
    const app_path = conn_paths.pathForId(conn, conn.current_incoming_path_id);
    const app_pn_space = &app_path.app_pn_space;
    const largest_received = if (app_pn_space.received.largest) |l| l else 0;

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = (try openLongOrDrop(
        conn,
        &pt_buf,
        bytes,
        .early_data,
        &r_keys,
        largest_received,
    )) orelse return bytes.len;

    return finishOpenedPacket(
        conn,
        .early_data,
        app_path.id,
        opened.pn,
        opened.payload,
        app_pn_space,
        opened.bytes_consumed,
        now_us,
    );
}

/// Handle a Handshake packet (RFC 9000 §17.2.4 / RFC 9001 §5.2).
/// Decrypt under the Handshake read keys, gate on long-header reserved
/// bits, then dispatch frames at the .handshake level.
pub fn handleHandshake(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    const r_keys_opt = try conn.packetKeys(.handshake, .read);
    const r_keys = r_keys_opt orelse {
        conn_qlog.emitPacketDropped(conn, .handshake, @intCast(bytes.len), .keys_unavailable);
        return bytes.len;
    };

    var pt_buf: [max_recv_plaintext]u8 = undefined;
    const opened = (try openLongOrDrop(
        conn,
        &pt_buf,
        bytes,
        .handshake,
        &r_keys,
        if (conn.pnSpaceForLevel(.handshake).received.largest) |l| l else 0,
    )) orelse return bytes.len;

    const incoming_path = conn_paths.pathForId(conn, conn.current_incoming_path_id);
    // RFC 9000 §8.1: a successfully decrypted Handshake packet from the
    // peer authenticates the source address (only the genuine peer holds
    // Handshake-level keys). For servers, this lifts the 3x
    // anti-amplification cap on the path. Idempotent if already
    // validated (e.g. via PATH_RESPONSE during migration).
    if (conn.role == .server) {
        incoming_path.path.markValidated();
    }
    return finishOpenedPacket(
        conn,
        .handshake,
        incoming_path.id,
        opened.pn,
        opened.payload,
        conn.pnSpaceForLevel(.handshake),
        opened.bytes_consumed,
        now_us,
    );
}

/// Open one long-header packet at `lvl` — `.initial`, `.early_data`,
/// or `.handshake`, the three levels whose wire-open functions share
/// `InitialOpenOptions`/`LongOpenResult` — owning the two tails every
/// long-header handler used to repeat:
///
///   * AEAD Auth failure → qlog `.decryption_failure` drop;
///   * RFC 9000 §17.2.1 ¶17: long-header Reserved Bits MUST be 0
///     after header protection is removed, else the connection closes
///     with PROTOCOL_VIOLATION. The gate deliberately runs *after*
///     the AEAD open — only a successful open authenticates the
///     post-HP first byte the bits live in.
///
/// Returns null when the packet was dropped or the violation close
/// fired; the caller responds by consuming the rest of the datagram
/// (`return bytes.len`).
fn openLongOrDrop(
    conn: *Connection,
    pt_buf: *[max_recv_plaintext]u8,
    bytes: []u8,
    lvl: EncryptionLevel,
    keys: *const PacketKeys,
    largest_received: u64,
) Error!?long_packet_mod.LongOpenResult {
    const opts: long_packet_mod.InitialOpenOptions = .{
        .keys = keys,
        .largest_received = largest_received,
    };
    const opened = (switch (lvl) {
        .initial => long_packet_mod.openInitial(pt_buf, bytes, opts),
        .early_data => long_packet_mod.openZeroRtt(pt_buf, bytes, opts),
        .handshake => long_packet_mod.openHandshake(pt_buf, bytes, opts),
        // Short-header packets take `openApplicationPacket` instead.
        .application => unreachable,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => {
            conn_qlog.emitPacketDropped(conn, lvl, @intCast(bytes.len), .decryption_failure);
            return null;
        },
        else => return e,
    };
    if (opened.reserved_bits != 0) {
        conn.close(true, transport_error_protocol_violation, "non-zero long-header reserved bits");
        return null;
    }
    return opened;
}

/// Shared tail for every successfully-opened-and-gated packet: path
/// attribution, the RFC 9000 §10.2.1 ¶3 closing-state short-circuit,
/// the duplicate-PN dispatch guard, ACK-tracker recording, ECN + qlog
/// accounting, and the frame dispatch itself.
///
/// The recording branch is deliberate, not incidental: application-
/// space packets (0-RTT and 1-RTT share one PN space, RFC 9000 §12.3)
/// take the delayed-ACK path, while RFC 9000 §13.2.1 forbids delaying
/// Initial/Handshake ACKs. `ret_len` is what the enclosing handler
/// returns — `bytes.len` for short headers (they consume the datagram
/// tail), `bytes_consumed` for coalesced long headers.
fn finishOpenedPacket(
    conn: *Connection,
    lvl: EncryptionLevel,
    path_id: u32,
    pn: u64,
    payload: []const u8,
    pn_space: *PnSpace,
    ret_len: usize,
    now_us: u64,
) Error!usize {
    conn.last_authenticated_path_id = path_id;
    if (conn_recv_dispatch.closingAttributionOnly(
        conn,
    )) {
        // RFC 9000 §10.2.1 ¶3 attribution path. Decrypt has
        // succeeded; mark the observation, scan for a peer CC,
        // and skip everything else (no ACK tracker update, no
        // dispatchFrames). The outer `handle` re-arms a CC
        // retransmit subject to the SHOULD-rate-limit.
        conn.closing_state_attribution_observed = true;
        conn_recv_dispatch.scanForPeerCloseFrame(conn, payload, now_us);
        return ret_len;
    }
    // Detect a duplicate PN *before* recording it. A replayed
    // authenticated packet is still acknowledged (the peer may have
    // missed our ACK) but its frames MUST NOT be re-processed
    // (RFC 9000 §12.3 / §13.1). Re-dispatch would re-deliver a
    // non-idempotent DATAGRAM frame and double-charge the
    // resident-bytes budget; that bites at 1-RTT *and* 0-RTT (both
    // feed the same application PN space, and DATAGRAM is legal in
    // early data). At Initial/Handshake every legal frame is
    // idempotent, so skipping the dispatch there is a no-op that is
    // also cheaper.
    const duplicate_pn = pn_space.received.contains(pn);
    // One classification pass serves ACK-eligibility bookkeeping, the
    // Initial/Handshake immediate-ACK rule, and the qlog frame count
    // (previously three separate full frame scans per packet).
    const cls = conn_recv_dispatch.classifyPayload(payload);
    switch (lvl) {
        .early_data, .application => conn_recv_dispatch.recordApplicationReceivedPacket(
            pn_space,
            pn,
            now_us,
            cls,
            conn.delayed_ack_packet_threshold,
        ),
        // RFC 9000 §13.2.1: Initial and Handshake packets MUST NOT
        // have their acknowledgements delayed.
        .initial, .handshake => pn_space.recordReceivedPacket(
            pn,
            now_us / 1000,
            cls.ack_eliciting,
        ),
    }
    pn_space.onPacketReceivedWithEcn(conn.last_recv_ecn);
    conn.qlog_packets_received +|= 1;
    conn_qlog.emitPacketReceived(conn, lvl, pn, @intCast(ret_len), cls.frame_count);
    if (!duplicate_pn) {
        try conn_recv_dispatch.dispatchFrames(conn, lvl, payload, now_us);
    }
    return ret_len;
}
