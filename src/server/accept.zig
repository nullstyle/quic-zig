// Connection acceptance: openSlotFromInitial (slot allocation, TLS
// context wiring, transport-parameter setup, preferred-address
// advertisement, first-flight feed), the slot error-close mapping, and
// dispatchToSlot. Split from server.zig; the private methods on Server
// delegate here via private thunks where hub callers remain.

const std = @import("std");
const boringssl = @import("boringssl");
const server_mod = @import("../server.zig");
const server_vneg = @import("vneg.zig");
const Server = server_mod.Server;
const Slot = server_mod.Server.Slot;
const Error = server_mod.Server.Error;
const conn_mod = @import("../conn/root.zig");
const Connection = conn_mod.Connection;
const Address = conn_mod.path.Address;
const ConnectionId = conn_mod.path.ConnectionId;
const buildPreferredAddressParam = server_mod.buildPreferredAddressParam;
const cidKeyFromConnectionId = server_mod.cidKeyFromConnectionId;
const peekDcidForServer = server_mod.peekDcidForServer;
const peekLongHeaderIds = server_mod.peekLongHeaderIds;
const PendingUpgradeState = @import("vneg.zig").PendingUpgradeState;
const wire = @import("../wire/root.zig");
const RetryEcho = @import("dos.zig").RetryEcho;

pub fn openSlotFromInitial(
    self: *Server,
    bytes: []const u8,
    from: ?Address,
    now_us: u64,
    retry_ctx: ?RetryEcho,
) !*Slot {
    const ids = peekLongHeaderIds(bytes) orelse return error.InvalidInitial;

    const slot = try self.allocator.create(Slot);
    errdefer self.allocator.destroy(slot);

    const conn_ptr = try self.allocator.create(Connection);
    errdefer self.allocator.destroy(conn_ptr);

    conn_ptr.* = try Connection.initServer(self.allocator, self.tls_ctx);
    errdefer conn_ptr.deinit();
    conn_ptr.reveal_close_reason_on_wire = self.reveal_close_reason_on_wire;
    conn_ptr.max_connection_memory = self.max_connection_memory;
    conn_ptr.delayed_ack_packet_threshold = self.delayed_ack_packet_threshold;
    conn_ptr.ecn_enabled = self.ecn_enabled;
    // RFC 8899 DPLPMTUD: thread the embedder config to the
    // connection. setPmtudConfig also re-initialises every
    // existing path (only the primary at this point), so the
    // per-path pmtu / pmtu_state lands consistent with the config.
    conn_ptr.setPmtudConfig(self.pmtud_config);
    conn_ptr.setCongestionAlgorithm(self.congestion_control);

    try conn_ptr.bind();
    if (self.qlog_callback) |cb| conn_ptr.setQlogCallback(cb, self.qlog_user_data);

    // Post-Retry connections use the SCID we minted in the Retry
    // packet — that SCID was bound into the token HMAC and is
    // the DCID the peer is actually addressing. Pre-Retry (or
    // Retry-disabled) connections use a fresh random SCID.
    var server_scid: [20]u8 = undefined;
    var local_scid: []const u8 = undefined;
    if (retry_ctx) |echo| {
        local_scid = echo.retry_scid[0..echo.retry_scid_len];
        @memcpy(server_scid[0..echo.retry_scid_len], local_scid);
        local_scid = server_scid[0..echo.retry_scid_len];
    } else {
        try self.mintLocalScid(server_scid[0..self.local_cid_len]);
        local_scid = server_scid[0..self.local_cid_len];
    }
    try conn_ptr.setLocalScid(local_scid);

    // The original DCID for the transport-parameter binding is
    // the *first* Initial's DCID. Pre-Retry that's the DCID on
    // this datagram; post-Retry that was captured before we
    // emitted the Retry and the on-wire DCID here is our
    // server-issued retry_scid.
    const original_dcid = if (retry_ctx) |echo| echo.original_dcid else ConnectionId.fromSlice(ids.dcid);
    // The DCID the peer is addressing on the wire — which is
    // also the routing key — is what the Initial header
    // currently carries.
    const initial_dcid = ConnectionId.fromSlice(ids.dcid);

    var params = self.transport_params;
    params.original_destination_connection_id = original_dcid;
    params.initial_source_connection_id = ConnectionId.fromSlice(local_scid);
    if (retry_ctx) |_| {
        params.retry_source_connection_id = ConnectionId.fromSlice(local_scid);
    }

    // RFC 9000 §18.2 / §5.1.1 `preferred_address` advertise. When
    // `Config.preferred_address` is set, mint a fresh seq-1 SCID
    // through the same `mintLocalScid` path as seq-0, derive the
    // accompanying stateless-reset token from the
    // `Config.stateless_reset_key` (Server.init's validation
    // guarantees the key is set whenever `preferred_address` is),
    // and stamp both into the outbound transport parameter so the
    // EE BoringSSL serializes carries the value verbatim. The
    // matching NEW_CONNECTION_ID(seq=1) is queued below, after
    // `acceptInitial` so the connection's local-CID table is
    // ready to register a sequence-1 entry.
    var pa_alt_cid_storage: [20]u8 = undefined;
    var pa_alt_cid_slice: ?[]u8 = null;
    var pa_alt_token: [16]u8 = @splat(0);
    if (self.preferred_address) |pa_cfg| {
        const slice = pa_alt_cid_storage[0..self.local_cid_len];
        try self.mintLocalScid(slice);
        const key = self.stateless_reset_key orelse unreachable;
        pa_alt_token = conn_mod.stateless_reset.derive(&key, slice) catch
            return Error.RandFailed;
        pa_alt_cid_slice = slice;
        params.preferred_address = buildPreferredAddressParam(pa_cfg, slice, pa_alt_token);
    }

    // RFC 9368 §5/§6: pre-parse the inbound Initial under wire-
    // version keys to extract the client's `version_information`
    // (codepoint 0x11) transport parameter, and intersect with
    // our configured `versions` list. The first server-preferred
    // version that also appears in the client's
    // `available_versions` is our `chosen_version`; if it differs
    // from the wire version, we upgrade.
    //
    // The pre-parse is purely advisory — any failure (auth fail,
    // fragmented ClientHello, missing extension, malformed
    // payload) returns `null` and we fall back to "use the wire
    // version", which is always spec-compliant. We never refuse a
    // connection because pre-parse failed.
    //
    // The decision MUST land BEFORE BoringSSL produces the EE
    // (which embeds our transport_parameters): RFC 9368 §5
    // requires `chosen_version` in the EE to match the version
    // of the server's first Initial response carrying it, so the
    // outbound transport_params must already say chosen=v_upgrade
    // when BoringSSL serializes the EE. We arrange that by:
    //   (a) running the pre-parse here, before `acceptInitial`,
    //   (b) building `params.compatibleVersions = [chosen, ...]`
    //       so the EE points at the upgrade target,
    //   (c) calling `acceptInitial`, which pushes those params to
    //       BoringSSL and (separately) sets `self.version` to the
    //       wire version so `handleInitial` opens this datagram
    //       under wire-version keys,
    //   (d) flipping `self.version` to `chosen` AFTER the first
    //       `handleWithEcn` returns (in `dispatchToSlot`), so
    //       outbound packets sealed by `poll` go out under the
    //       upgrade-target keys.
    var ch_complete: bool = false;
    const upgrade_target = server_vneg.preparseUpgradeTarget(self, bytes, ids.version, &ch_complete);
    const chosen_version: u32 = upgrade_target orelse ids.version;
    if (self.versions.len > 1) {
        var ordered: [16]u32 = undefined;
        ordered[0] = chosen_version;
        var n: usize = 1;
        for (self.versions) |v| {
            if (v == chosen_version) continue;
            if (n >= ordered.len) break;
            ordered[n] = v;
            n += 1;
        }
        try params.setCompatibleVersions(ordered[0..n]);
    }
    try conn_ptr.acceptInitial(bytes, params);
    // RFC 9001 §4.6.1: install the 0-RTT replay context BEFORE the
    // first `handleWithEcn` processes the ClientHello. BoringSSL
    // compares a resumed ticket's stored context against the
    // connection's current one when deciding whether to accept
    // early data; a context installed after ClientHello processing
    // is invisible to that check, so early data would always be
    // rejected (and tickets issued here would never be
    // 0-RTT-capable). The digest builder deliberately excludes
    // per-connection identifiers (ODCID/ISCID/preferred-address),
    // so issuance-time and resumption-time digests match across
    // connections for a stable config. Failures degrade to
    // "0-RTT refused, connection proceeds" — except OOM, which the
    // accept path already treats as fatal.
    if (self.enable_0rtt and self.alpn_protocols.len > 0) {
        _ = conn_ptr.setEarlyDataContextForParams(
            params,
            self.alpn_protocols[0],
            self.early_data_application_context,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        };
    }
    // Stash the upgrade target so `dispatchToSlot` can flip
    // `self.version` after the first `handleWithEcn` consumes the
    // wire-version Initial under wire-version keys.
    if (upgrade_target) |upgraded| {
        if (upgraded != ids.version) {
            conn_ptr.setPendingVersionUpgrade(upgraded);
        }
    }

    // RFC 9368 §6 multi-Initial fallback: when the ClientHello
    // didn't fit in this single Initial and we're in multi-version
    // mode, attach a streaming reassembler so subsequent routed
    // Initials can drive the upgrade decision before BoringSSL
    // emits the EE. The reassembler is pre-seeded with this first
    // Initial's CRYPTO bytes so the next call to `feed` only has
    // to add what arrived later. Allocation or pre-seed failures
    // are non-fatal — the slot simply commits to the wire
    // version, which is always spec-compliant.
    const want_pending = !ch_complete and
        self.versions.len > 1 and
        wire.initial.isSupportedVersion(ids.version);
    var pending_upgrade: ?*PendingUpgradeState = null;
    if (want_pending) {
        pending_upgrade = server_vneg.openPendingUpgrade(self, bytes, ids.version);
    }
    errdefer if (pending_upgrade) |pu| self.allocator.destroy(pu);

    // Queue NEW_CONNECTION_ID(seq=1) carrying the alt-CID minted
    // for `preferred_address`. RFC 9000 §5.1.1 ¶6 says the client
    // treats the preferred-address `connection_id` as if it had
    // arrived in `NEW_CONNECTION_ID(seq=1)`; the server still
    // emits the matching frame on the wire, and the client's
    // `registerPeerCid` idempotently absorbs the duplicate. We
    // queue it AFTER `acceptInitial` so the connection's local-CID
    // table has its seq-0 entry already in place.
    if (pa_alt_cid_slice) |alt_cid| {
        const provision = conn_mod.ConnectionIdProvision{
            .connection_id = alt_cid,
            .stateless_reset_token = pa_alt_token,
        };
        // Propagate OOM (the broader feed loop expects to bubble
        // it). Any other failure (CID-issue budget saturated,
        // alt-CID collision with the seq-0 mint) silently skips
        // the queue: the transport parameter is still advertised,
        // and a post-migration packet bearing the unregistered
        // alt-CID will simply be dropped — pathological for the
        // server (a same-connection client whose
        // `active_connection_id_limit < 2` cannot follow the PA
        // anyway), no need to fail the handshake.
        _ = conn_ptr.replenishConnectionIds(&[_]conn_mod.ConnectionIdProvision{provision}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {},
        };
    }

    slot.* = .{
        .conn = conn_ptr,
        .initial_dcid = initial_dcid,
        .peer_addr = from,
        .last_activity_us = now_us,
        .slot_id = self.next_slot_id,
        .tls_generation = self.current_generation,
        .pending_upgrade = pending_upgrade,
        .last_recv_socket_idx = 0,
    };
    self.next_slot_id +%= 1;

    // Reserve a slot in the CID table for the initial DCID. If
    // this fails, the slot was never made visible to the router
    // and the deferred errdefer will tear down the Connection.
    try self.cid_table.put(self.allocator, cidKeyFromConnectionId(initial_dcid), slot);
    errdefer _ = self.cid_table.remove(cidKeyFromConnectionId(initial_dcid));

    try self.slots.append(self.allocator, slot);
    return slot;
}

/// Close code + local reason for a per-connection error that
/// escaped `Connection.handleWithEcn`. Pure and separately tested
/// (`slotErrorCloseCode maps ...` below) because the live path
/// almost never observes it: when BoringSSL raises an alert, the
/// `send_alert` callback has already closed the connection with
/// RFC 9001 §4.8's *specific* CRYPTO_ERROR (0x0100 + alert byte)
/// before the error unwinds, and `close` is first-wins — so that
/// specific code stands and the caller's `close` is a no-op. What
/// this mapping actually decides is the alert-less case, and there
/// §4.8's generic `handshake_failure` (0x0128) keeps the close
/// inside the CRYPTO_ERROR window: INTERNAL_ERROR would tell the
/// peer, and the embedder's metrics, that quic-zig broke when TLS
/// simply said no.
///
/// Reason strings are local-only by default
/// (`reveal_close_reason_on_wire`), so they are for the embedder's
/// close event, not the peer.
pub fn slotErrorCloseCode(err: anyerror) struct { code: u64, reason: []const u8 } {
    return switch (err) {
        error.HandshakeFailed, error.PeerAlerted => .{
            .code = conn_mod.state.transport_error_crypto_handshake_failure,
            .reason = "handshake failed",
        },
        // RFC 9000 §20.1 INTERNAL_ERROR (0x01) is the catch-all.
        // Note this bucket is not purely local-side: peer-driven
        // resource failures (e.g. a full per-level CRYPTO inbox)
        // land here too, because they reach this catch without a
        // more specific code of their own. Routing those to
        // EXCESSIVE_LOAD (0x09) would be more precise and is
        // deliberately left for a follow-up — it changes
        // wire-visible codes for cases this release does not
        // otherwise touch.
        else => .{
            .code = conn_mod.state.transport_error_internal,
            .reason = "Server.handle failed",
        },
    };
}

pub fn dispatchToSlot(
    self: *Server,
    slot: *Slot,
    bytes: []u8,
    from: ?Address,
    now_us: u64,
) Error!void {
    // RFC 9000 §19.16 ¶3 plumbing: tell the connection which of
    // its locally-issued CIDs this datagram was addressed to,
    // so `handleRetireConnectionId` can reject a frame retiring
    // the in-use CID. `null` (no DCID match) leaves the gate
    // inert — that path is the pre-routing-table bootstrap case
    // for a brand-new Initial.
    const dcid_opt = peekDcidForServer(bytes, self.local_cid_len);
    const seq_opt: ?u64 = if (dcid_opt) |d| slot.conn.findLocalCidSequence(d) else null;
    slot.conn.setIncomingLocalCidSeq(seq_opt);
    defer slot.conn.setIncomingLocalCidSeq(null);
    slot.conn.handleWithEcn(bytes, from, self.last_feed_ecn, now_us) catch |err| switch (err) {
        // OOM is fatal for the whole server — propagate. The
        // surrounding `feed` will return `OutOfMemory` to the
        // embedder, who can decide whether to retry, scale, or
        // bail.
        error.OutOfMemory => return Error.OutOfMemory,
        // Everything else is a per-connection failure: don't tear
        // down the server. If `Connection.handle` didn't already
        // transition the connection to `.closed` with a more
        // specific code, force it so the slot gets reaped on the
        // next `reap` call. `slotErrorCloseCode` picks the code;
        // see it for why this is usually a no-op.
        else => {
            if (!slot.conn.isClosed()) {
                const close_with = slotErrorCloseCode(err);
                slot.conn.close(true, close_with.code, close_with.reason);
            }
        },
    };
    // RFC 9368 §6 compatible-version-negotiation upgrade: the
    // wire-version Initial has now been opened under wire-version
    // keys and BoringSSL has consumed the ClientHello (producing
    // an EE that already embeds our chosen-version transport
    // params, since `openSlotFromInitial` set those before the
    // handshake advanced). Flip `self.version` to the upgrade
    // target so the next `poll` seals the response Initial under
    // the upgrade-target keys. Idempotent / no-op when no
    // upgrade was pending.
    _ = slot.conn.applyPendingVersionUpgrade();
}
