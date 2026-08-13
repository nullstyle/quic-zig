//! Connection migration and address change (RFC 9000 §9) plus the
//! draft-munizaga-quic-alternative-server-address extension: peer
//! address-change detection and policy (MigrationCallback), active
//! client migration, server local-address changes, and the alternative
//! server address advertise / receive surface. Free-function siblings
//! of `Connection`'s method-style migration plumbing; the methods on
//! `Connection` are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_qlog = @import("qlog.zig");
const conn_paths = @import("paths.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const Address = state_mod.Address;
const ConnectionId = state_mod.ConnectionId;
const PathState = state_mod.PathState;
const frame_types = state_mod.frame_types;
const path_mod = state_mod.path_mod;
const min_path_challenge_interval_us = state_mod.min_path_challenge_interval_us;

// Doc comment lives on the `Connection.setMigrationCallback` thunk in Connection.zig.
pub fn setMigrationCallback(
    conn: *Connection,
    callback: ?MigrationCallback,
    user_data: ?*anyopaque,
) void {
    conn.migration_callback = callback;
    conn.migration_user_data = user_data;
}

pub fn peerSupportsAlternativeAddress(conn: *const Connection) bool {
    const params = conn.cached_peer_transport_params orelse return false;
    return params.alternative_address;
}

/// True if this endpoint advertised the §4 `alternative_address`
/// transport parameter to its peer. Drives the receive-side gate
/// in the frame dispatcher: a client that didn't advertise
/// support is in a peer protocol-violation state on receipt of
/// any ALT_*_ADDRESS frame.
pub fn localAdvertisedAlternativeAddress(conn: *const Connection) bool {
    return conn.local_transport_params.alternative_address;
}

/// Queue an ALTERNATIVE_V4_ADDRESS frame
/// (draft-munizaga-quic-alternative-server-address-00 §6) for
/// emission at the application encryption level. Allocates a
/// fresh, monotonically-increasing Status Sequence Number shared
/// with the V6 sibling (§6 ¶5) and returns it.
///
/// Server-only API: §4 ¶2 forbids clients from sending these
/// frames. The peer MUST have advertised
/// `alternative_address = true` in its transport parameters
/// before this call — `Error.AlternativeAddressNotNegotiated` is
/// returned otherwise so the embedder can't accidentally force a
/// PROTOCOL_VIOLATION close on a non-supporting client. Returns
/// `Error.AlternativeAddressSequenceExhausted` once the
/// connection has emitted 2^64 advertisements, which is
/// functionally unreachable but bounded explicitly so the wire
/// contract can never silently break.
pub fn advertiseAlternativeV4Address(
    conn: *Connection,
    address: [4]u8,
    port: u16,
    opts: AdvertiseAlternativeAddressOptions,
) Error!u64 {
    if (conn.role != .server) return Error.NotServerContext;
    if (!peerSupportsAlternativeAddress(
        conn,
    )) {
        return Error.AlternativeAddressNotNegotiated;
    }
    const seq = try allocAlternativeAddressSequence(
        conn,
    );
    try conn.pending_frames.alternative_addresses.append(conn.allocator, .{
        .v4 = .{
            .preferred = opts.preferred,
            .retire = opts.retire,
            .status_sequence_number = seq,
            .address = address,
            .port = port,
        },
    });
    return seq;
}

/// IPv6 sibling of `advertiseAlternativeV4Address`. Same semantics
/// — same role gate, same shared sequence-number space, same
/// `AlternativeAddressSequenceExhausted` boundary handling.
pub fn advertiseAlternativeV6Address(
    conn: *Connection,
    address: [16]u8,
    port: u16,
    opts: AdvertiseAlternativeAddressOptions,
) Error!u64 {
    if (conn.role != .server) return Error.NotServerContext;
    if (!peerSupportsAlternativeAddress(
        conn,
    )) {
        return Error.AlternativeAddressNotNegotiated;
    }
    const seq = try allocAlternativeAddressSequence(
        conn,
    );
    try conn.pending_frames.alternative_addresses.append(conn.allocator, .{
        .v6 = .{
            .preferred = opts.preferred,
            .retire = opts.retire,
            .status_sequence_number = seq,
            .address = address,
            .port = port,
        },
    });
    return seq;
}

/// Allocate the next §6 ¶5 Status Sequence Number. Mirrors the
/// `next_datagram_id` allocator pattern: returns
/// `Error.AlternativeAddressSequenceExhausted` at the u64 cap
/// rather than wrapping or saturating. Wrapping back to 0 would
/// silently violate §6 ¶5 monotonicity; saturating would emit
/// two distinct logical updates with the same sequence number,
/// which the receiver would dedupe as a retransmit and drop the
/// second update on the floor.
fn allocAlternativeAddressSequence(conn: *Connection) Error!u64 {
    const seq = conn.next_alternative_address_sequence;
    if (seq == std.math.maxInt(u64)) {
        return Error.AlternativeAddressSequenceExhausted;
    }
    conn.next_alternative_address_sequence = seq + 1;
    return seq;
}

pub fn handlePeerAddressChange(
    conn: *Connection,
    path: *PathState,
    addr: Address,
    datagram_len: usize,
    now_us: u64,
) Error!void {
    // RFC 9000 §5.1.2 ¶1: "An endpoint MUST NOT use the same
    // connection ID on different paths." When a fresh peer-issued
    // CID is available (one we got via NEW_CONNECTION_ID that
    // isn't already in use on this path), rotate to it before
    // path validation begins. If no fresh CID is available
    // (peer hasn't issued more, or NAT rebinding without
    // deliberate CID issuance), quic proceeds with the existing
    // CID — silently rather than refusing the migration outright,
    // because a strict refusal breaks NAT rebinding scenarios
    // where the peer never sent a NEW_CONNECTION_ID. The
    // conformance test for §5.1.2 ¶1 exercises the rotate-when-
    // available path explicitly.
    if (consumeFreshPeerCidForMigration(conn, path)) |fresh_cid| {
        path.path.peer_cid = fresh_cid;
        if (path.id == 0) {
            conn.peer_dcid = fresh_cid;
            conn.peer_dcid_set = true;
        }
    }

    path.beginMigration(addr, datagram_len);

    try conn_paths.armMigrationPathChallenge(conn, path, now_us);
}

/// RFC 9000 §5.1.2 ¶1 helper: pick a peer-issued CID for `path`
/// that's NOT the one the path is currently using. Returns null if
/// the only available CID is the current one (the migration must
/// be refused — the peer needs to issue more CIDs via
/// NEW_CONNECTION_ID first).
///
/// Removes the chosen CID from `peer_cids` so a subsequent
/// migration can't pick the same one again.
pub fn consumeFreshPeerCidForMigration(
    conn: *Connection,
    path: *PathState,
) ?ConnectionId {
    const current = path.path.peer_cid;
    var i: usize = 0;
    while (i < conn.peer_cids.items.len) : (i += 1) {
        const item = conn.peer_cids.items[i];
        if (item.path_id != path.id) continue;
        if (ConnectionId.eql(item.cid, current)) continue;
        const chosen = item.cid;
        _ = conn.peer_cids.orderedRemove(i);
        return chosen;
    }
    return null;
}

/// Begin a client-initiated active connection migration to a new
/// local 4-tuple (RFC 9000 §9.2). Composes the existing migration
/// primitives — `consumeFreshPeerCidForMigration`,
/// `PathState.beginMigration`, `queuePathChallengeOnPath` — but
/// for the **client-side** case where the local endpoint chose
/// to move rather than reacting to a peer-initiated address change.
///
/// Preconditions:
///   - This is a client connection (`role == .client`).
///   - Handshake is complete (RFC 9000 §9.6: migration is forbidden
///     before handshake confirmation).
///   - No migration is currently pending (PATH_CHALLENGE outstanding
///     on the active path).
///   - At least one peer-issued CID is available beyond the current
///     one (so RFC 9000 §5.1.2 ¶1's CID-rotation requirement can
///     be satisfied).
///
/// Effect:
///   - Snapshots current path state into `migration_rollback` so
///     the path can revert if PATH_CHALLENGE times out.
///   - Rotates the active path's `peer_cid` to a fresh peer-issued
///     CID; updates `peer_dcid` to match (long-header packets
///     during the validation window pick up the new SCID).
///   - Updates the active path's `local_addr` to `new_local_addr`
///     (informational on the embedder side; nothing in the core
///     routes by local_addr).
///   - Resets the path's anti-amp counters and validation state so
///     unvalidated bytes are re-budgeted against the 3x cap.
///   - Generates a fresh PATH_CHALLENGE token, arms the validator,
///     and queues PATH_CHALLENGE for the next `poll`.
///
/// The embedder is responsible for binding a new local UDP socket
/// (which provides `new_local_addr`) and routing all subsequent
/// outbound datagrams through it. The new local SCID is **not**
/// minted here — peers route inbound by DCID and the path's
/// existing `local_cid` continues to work; embedders that want a
/// fresh local SCID on the wire (RFC 9000 §5.1.2 ¶1 from our side)
/// should call `queueNewConnectionId` ahead of this and then drive
/// the peer through normal CID retirement/promotion.
///
/// Refusals are typed so the caller knows what to wait for:
/// `MigrationPreHandshake` (retry after the handshake confirms),
/// `MigrationValidationPending` (retry once the in-flight path
/// validation settles), and `MigrationNoFreshPeerCid` (retry after
/// the peer issues a NEW_CONNECTION_ID).
pub fn beginClientActiveMigration(
    conn: *Connection,
    new_local_addr: Address,
    now_us: u64,
) Error!void {
    if (conn.role != .client) return Error.NotClientContext;
    const handshake_complete = conn.handshakeDone() or conn.test_only_force_handshake_for_migration;
    if (!handshake_complete) {
        // Mirror the diagnostic the peer-driven gate emits: §9.6
        // forbids migration before handshake confirmation. Even
        // though this is a local trigger rather than a peer event,
        // the wire effect is the same — we'd be sending PATH_CHALLENGE
        // off an unauthenticated path.
        conn_qlog.emitQlog(conn, .{
            .name = .migration_path_failed,
            .path_id = conn.activePath().id,
            .migration_fail_reason = .pre_handshake,
        });
        return Error.MigrationPreHandshake;
    }
    const path = conn.activePath();
    if (path.path.validator.status == .pending) {
        return Error.MigrationValidationPending;
    }
    const fresh_cid = consumeFreshPeerCidForMigration(conn, path) orelse {
        conn_qlog.emitQlog(conn, .{
            .name = .migration_path_failed,
            .path_id = path.id,
            .migration_fail_reason = .no_fresh_peer_cid,
        });
        return Error.MigrationNoFreshPeerCid;
    };

    // Snapshot rollback state before any mutation so a
    // validation timeout can revert peer_cid / peer_dcid /
    // local_addr cleanly.
    path.snapshotMigrationRollback();

    // Rotate to the fresh peer CID per RFC 9000 §5.1.2 ¶1. The
    // first short header we emit after this call carries the new
    // DCID, which is exactly what the runner's connectionmigration
    // check looks for in the client pcap.
    path.path.peer_cid = fresh_cid;
    if (path.id == 0) {
        conn.peer_dcid = fresh_cid;
        conn.peer_dcid_set = true;
    }

    // Update local address bookkeeping. We deliberately do NOT
    // zero `bytes_received` / `bytes_sent` or flip `validated` to
    // false (the way `beginMigration` does for peer-initiated
    // migration). Rationale: §8.1 anti-amp protects an endpoint
    // from sending to an unverified peer. The client's peer (the
    // server) hasn't moved — only the client's own local address
    // changed — so anti-amp is irrelevant here. Resetting the
    // counters would clamp the next `poll`'s `max_payload` to 0
    // and stall the transfer until PATH_RESPONSE returned, which
    // is the wrong constraint to apply to client-initiated
    // migration.
    //
    // The path validator still tracks PATH_CHALLENGE in flight so
    // the embedder can observe migration progress; failure rolls
    // back peer_cid via the rollback snapshot above.
    path.setLocalAddress(new_local_addr);
    path.pending_migration_reset = true;

    try conn_paths.armMigrationPathChallenge(conn, path, now_us);
}

/// Server-side counterpart to `beginClientActiveMigration`: the
/// embedder observed an authenticated datagram for this connection
/// arrive on a NEW local address (typically because a peer that
/// followed our advertised `preferred_address` flipped from the
/// primary listening socket to the alt-port one). RFC 9000 §5.1.1
/// requires the server to validate the new path before treating
/// it as the active 4-tuple, so this call mirrors
/// `handlePeerAddressChange` for the local-side flip — generates
/// a fresh PATH_CHALLENGE token, arms the validator, queues
/// PATH_CHALLENGE on the active path, and stamps the rate-limit
/// clock. The `emit_path_challenge_first` machinery
/// (`pending_migration_reset` + `validator.status == .pending`)
/// then guarantees the next emitted packet on the new local
/// address leads with PATH_CHALLENGE rather than burying it
/// behind ACK / PATH_RESPONSE / STREAM frames.
///
/// Preconditions:
///   - `role == .server` — clients drive their own migration via
///     `beginClientActiveMigration`.
///   - Handshake is complete (RFC 9000 §9.6: pre-handshake address
///     swaps are forbidden).
///   - `local_transport_params.preferred_address` is set — without
///     a server-advertised PA the embedder has no legitimate
///     trigger for this call. Returns
///     `PreferredAddressNotAdvertised` otherwise so embedder bugs
///     surface at the boundary.
///   - No migration is currently pending (PATH_CHALLENGE
///     outstanding on the active path) — re-firing for the same
///     local-addr on stale buffered datagrams is idempotent.
///
/// Effect:
///   - Snapshots current path state into `migration_rollback` so
///     the path can revert if PATH_CHALLENGE times out.
///   - Updates the active path's `local_addr` to `new_local_addr`
///     (informational on the embedder side; nothing in the core
///     routes by local_addr — the embedder picks the outbound
///     socket via its own bookkeeping such as
///     `Server.Slot.last_recv_socket_idx` or the qns endpoint's
///     `last_recv_socket`).
///   - Generates a fresh PATH_CHALLENGE token, arms the validator
///     with a `3 * PTO` timeout (RFC 9000 §8.2.4), and queues
///     PATH_CHALLENGE for the next `poll`.
///   - Sets `pending_migration_reset = true` so a successful
///     PATH_RESPONSE drives `resetRecoveryAfterMigration` (RFC
///     9000 §9.4) and so the `emit_path_challenge_first` gate in
///     the send path fires for the next outbound packet.
///   - Does NOT zero `bytes_received` / `bytes_sent`: the peer
///     already authenticated the datagram on the existing path's
///     keys — the §8.1 anti-amp 3x cap is irrelevant to a
///     local-side address flip (the peer wasn't the entity that
///     moved). This matches the rationale in
///     `beginClientActiveMigration`.
///
/// **Idempotence**: a no-op when the active path's `local_addr`
/// already equals `new_local_addr` (idempotent under stale
/// buffered datagrams that arrive shortly after the first
/// post-migration packet) and when the validator is already
/// `.pending` for this migration. Returns without error in both
/// cases.
///
/// Returns `PreferredAddressNotAdvertised` when no server
/// `preferred_address` was advertised, `NotServerContext` when
/// called on a client connection, and `PathLimitExceeded` when
/// the handshake is incomplete or another migration is already
/// pending (mirrors the diagnostic shape of
/// `beginClientActiveMigration`).
pub fn noteServerLocalAddressChanged(
    conn: *Connection,
    new_local_addr: Address,
    now_us: u64,
) Error!void {
    if (conn.role != .server) return Error.NotServerContext;
    // RFC 9000 §5.1.1 / §18.2: only meaningful when the server
    // has advertised a `preferred_address` to follow. Embedders
    // that have not configured one shouldn't be calling this API.
    if (conn.local_transport_params.preferred_address == null) {
        return Error.PreferredAddressNotAdvertised;
    }
    const handshake_complete = conn.handshakeDone() or conn.test_only_force_handshake_for_migration;
    if (!handshake_complete) {
        conn_qlog.emitQlog(conn, .{
            .name = .migration_path_failed,
            .path_id = conn.activePath().id,
            .migration_fail_reason = .pre_handshake,
        });
        return Error.PathLimitExceeded;
    }
    const path = conn.activePath();

    // Idempotence: a follow-up datagram for the same migrated
    // local-addr (e.g. a duplicate or stale buffered packet) just
    // returns success. Two cases:
    //   1. The path's local_addr already matches — we already ran
    //      this body for an earlier call.
    //   2. The validator is .pending and pending_migration_reset
    //      is set — a migration is in flight; double-firing
    //      would mint a fresh token and lose the original
    //      challenge, breaking the in-flight validation.
    if (path.local_addr_set and Address.eql(path.path.local_addr, new_local_addr)) {
        return;
    }
    if (path.path.validator.status == .pending and path.pending_migration_reset) {
        return Error.PathLimitExceeded;
    }

    // Snapshot pre-migration state for rollback on validator
    // timeout. `peer_addr` doesn't change on a server-side
    // local-addr flip, but the shared snapshot keeps the
    // `MigrationRollback` shape uniform across migration triggers.
    path.snapshotMigrationRollback();

    // Update local-address bookkeeping. Like the client-side
    // counterpart, we deliberately do NOT zero `bytes_received` /
    // `bytes_sent` — the peer hasn't moved (it just reached us
    // via a different local socket of ours), so RFC 9000 §8.1
    // anti-amp doesn't apply and the path stays validated for
    // outbound bytes. Resetting the counters would clamp the
    // first post-migration `poll`'s `max_payload` to 0, which is
    // exactly the bug we're fixing — the migrated path would
    // never send PATH_CHALLENGE because anti-amp would treat the
    // path as fresh.
    path.setLocalAddress(new_local_addr);
    path.pending_migration_reset = true;

    try conn_paths.armMigrationPathChallenge(conn, path, now_us);
}

pub fn recordAuthenticatedDatagramAddress(
    conn: *Connection,
    path_id: u32,
    addr: Address,
    datagram_len: usize,
    now_us: u64,
) Error!void {
    const path = conn_paths.pathForId(conn, path_id);
    if (!path.peer_addr_set) {
        path.setPeerAddress(addr);
        path.path.onDatagramReceived(datagram_len);
        return;
    }
    if (Address.eql(path.path.peer_addr, addr)) {
        path.path.onDatagramReceived(datagram_len);
        return;
    }
    if (path.matchesMigrationRollbackAddress(addr)) return;

    // RFC 9000 §9.6 (peer migration before handshake confirmation): peer-initiated
    // migration is forbidden before the handshake is confirmed.
    // The triggering datagram authenticated under existing keys,
    // so we know the peer holds them — but pre-handshake an
    // address swap is more likely to be a probe than legitimate
    // NAT churn, and the cost of being wrong is allowing the
    // peer to anchor connection state to a half-handshaked
    // 4-tuple. Drop the datagram (no anti-amp credit, no
    // PATH_CHALLENGE) and surface the event in qlog.
    if (!conn.handshakeDone() and !conn.test_only_force_handshake_for_migration) {
        conn_qlog.emitQlog(conn, .{
            .name = .migration_path_failed,
            .path_id = path_id,
            .migration_fail_reason = .pre_handshake,
        });
        return;
    }

    // Per-path PATH_CHALLENGE rate limit (path-probe flood defense:
    // "rate-limit path probes"). Caps how fast a peer can force
    // us to mint fresh challenge tokens and validator state. A
    // legitimate NAT rebinding + retry sequence completes inside
    // one RTT, so 100 ms between probes is well above the
    // legitimate floor; an adversarial probe flood is throttled
    // to one challenge per `min_path_challenge_interval_us`.
    if (path.path.last_path_challenge_at_us) |last_us| {
        if (now_us -| last_us < min_path_challenge_interval_us) {
            conn_qlog.emitQlog(conn, .{
                .name = .migration_path_failed,
                .path_id = path_id,
                .migration_fail_reason = .rate_limited,
            });
            return;
        }
    }

    if (conn.migration_callback) |callback| {
        const current = path.peerAddress();
        const verdict = callback(conn.migration_user_data, conn, addr, current);
        if (verdict == .deny) {
            // RFC 9000 §9 / design note: the triggering datagram
            // already decrypted cleanly under the existing path's
            // keys, so its frames are safe to credit against the
            // existing 4-tuple. Don't migrate; let the peer keep
            // using the old address.
            path.path.onDatagramReceived(datagram_len);
            conn_qlog.emitQlog(conn, .{
                .name = .migration_path_failed,
                .path_id = path_id,
                .migration_fail_reason = .policy_denied,
            });
            return;
        }
    }
    try handlePeerAddressChange(conn, path, addr, datagram_len, now_us);
}

pub fn incomingShortPath(conn: *Connection, bytes: []const u8) ?*PathState {
    if (bytes.len < 1) return null;
    var best: ?*PathState = null;
    var best_len: u8 = 0;
    for (conn.local_cids.items) |item| {
        const cid = item.cid.slice();
        if (cid.len == 0) continue;
        if (bytes.len < 1 + cid.len) continue;
        if (!std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) continue;
        if (cid.len > best_len) {
            if (conn.paths.get(item.path_id)) |path| {
                best = path;
                best_len = @intCast(cid.len);
            }
        }
    }
    if (best != null) return best;
    for (conn.paths.paths.items) |*p| {
        const cid = p.path.local_cid.slice();
        if (cid.len == 0) continue;
        if (bytes.len < 1 + cid.len) continue;
        if (std.mem.eql(u8, bytes[1 .. 1 + cid.len], cid)) return p;
    }
    return best;
}

/// Handle a received ALTERNATIVE_V4_ADDRESS frame
/// (draft-munizaga-quic-alternative-server-address-00 §6).
/// Caller has already validated the negotiation gate. Enforces
/// §6 ¶5 monotonicity: a strictly-greater Status Sequence Number
/// produces a fresh `ConnectionEvent.alternative_server_address`;
/// equal-or-lower is dropped (idempotent retransmit / out-of-
/// order delivery).
pub fn handleAlternativeAddressV4(
    conn: *Connection,
    a: frame_types.AlternativeV4Address,
) void {
    if (!acceptAltAddrSequence(conn, a.status_sequence_number)) return;
    conn.alternative_server_address_events.push(.{ .v4 = .{
        .address = a.address,
        .port = a.port,
        .status_sequence_number = a.status_sequence_number,
        .preferred = a.preferred,
        .retire = a.retire,
    } });
}

/// IPv6 sibling of `handleAlternativeAddressV4`. Same monotonicity
/// rules — V4 and V6 share the §6 ¶5 sequence space.
pub fn handleAlternativeAddressV6(
    conn: *Connection,
    a: frame_types.AlternativeV6Address,
) void {
    if (!acceptAltAddrSequence(conn, a.status_sequence_number)) return;
    conn.alternative_server_address_events.push(.{ .v6 = .{
        .address = a.address,
        .port = a.port,
        .status_sequence_number = a.status_sequence_number,
        .preferred = a.preferred,
        .retire = a.retire,
    } });
}

/// True if `seq` is strictly greater than every previously-seen
/// Status Sequence Number; updates `highest_alternative_address_sequence_seen`
/// as a side-effect on accept. Older or equal numbers return
/// false (idempotent retransmit / out-of-order delivery — §6 ¶5
/// is sender-side).
fn acceptAltAddrSequence(conn: *Connection, seq: u64) bool {
    if (conn.highest_alternative_address_sequence_seen) |highest| {
        if (seq <= highest) return false;
    }
    conn.highest_alternative_address_sequence_seen = seq;
    return true;
}

/// Highest Status Sequence Number this connection has received
/// across both ALT_*_ADDRESS frame types
/// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5), or
/// `null` when no frame has arrived yet. Useful for tests and
/// embedder-side debugging.
pub fn highestAlternativeAddressSequenceSeen(conn: *const Connection) ?u64 {
    return conn.highest_alternative_address_sequence_seen;
}

/// Allow / deny verdict returned by a `MigrationCallback`. The
/// callback is consulted before quic starts path validation on a
/// candidate 4-tuple (RFC 9000 §9). `.allow` proceeds with
/// PATH_CHALLENGE; `.deny` skips validation entirely and keeps the
/// existing path live.
pub const MigrationDecision = enum {
    /// Proceed with path validation on the candidate addresss.
    allow,
    /// Refuse the migration. PATH_CHALLENGE is not queued, the
    /// peer's existing 4-tuple stays in use, and a
    /// `migration_path_failed` qlog event with reason
    /// `policy_denied` is emitted.
    deny,
};

/// Embedder policy hook consulted when quic detects a peer migration
/// candidate (RFC 9000 §9). Fires synchronously, **before** the
/// PATH_CHALLENGE / PATH_RESPONSE round-trip — this lets the embedder
/// short-circuit purely-address-based allowlists ("only accept
/// migrations from corporate IPs") without paying for a probe. The
/// callback runs after the triggering datagram has decrypted cleanly
/// under the existing path's keys, so its frames are trustworthy.
///
/// Arguments:
/// - `user_data` — opaque pointer registered via
///   `Connection.setMigrationCallback`.
/// - `conn` — the live Connection, passed by const-pointer so the
///   callback can read state (e.g. role, peer SCID, scheduling
///   policy) but cannot mutate it. quic is single-threaded
///   internally; the callback must not call back into this
///   Connection.
/// - `candidate_addr` — the new peer 4-tuple address the datagram
///   arrived on.
/// - `current_addr` — the existing peer address on the affected
///   path, or `null` if the path had no peer address recorded yet
///   (in which case the callback is not consulted).
///
/// Return `.allow` to start path validation as usual, or `.deny` to
/// drop the migration attempt while keeping the connection alive on
/// the existing path.
pub const MigrationCallback = *const fn (
    user_data: ?*anyopaque,
    conn: *const Connection,
    candidate_addr: Address,
    current_addr: ?Address,
) MigrationDecision;

/// Callback fired when a client connection receives a NEW_TOKEN frame
/// (RFC 9000 §8.1.3). The embedder typically stashes the bytes
/// alongside the server's session ticket; on the next attempt to the
/// same server, supplying these bytes back via
/// `Client.Config.new_token` lets the server skip the Retry round
/// trip. Tokens are opaque to the client — treat the slice as a
/// blob.
///
/// The slice is borrowed from the inbound packet's decoded frame; if
/// the embedder needs to keep it past the callback's return,
/// it MUST copy.
pub const NewTokenCallback = *const fn (user_data: ?*anyopaque, token: []const u8) void;

// -- draft-munizaga-quic-alternative-server-address-00 ------------

/// Optional flags for `Connection.advertiseAlternative*Address`.
/// Both bits are off by default — embedders set them to drive the
/// §6 Preferred / Retire semantics on the receiving client.
pub const AdvertiseAlternativeAddressOptions = struct {
    /// §6: hint to the client that the path bound to this address
    /// SHOULD be migrated-to or otherwise prioritized.
    preferred: bool = false,
    /// §6: ask the client to close any path associated with this
    /// address (the SHOULD in §6 ¶3).
    retire: bool = false,
};
