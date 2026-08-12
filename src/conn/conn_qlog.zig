// Qlog observability for Connection — the draft-ietf-quic-qlog event
// and enum surface plus the emit* helpers. Free-function siblings of
// `Connection`'s method-style emitters; the methods on `Connection`
// are thin thunks that delegate here, and state.zig re-exports every
// type declared in this file so the `quic_zig.conn.state.*` public
// path keeps resolving.

const state_mod = @import("state.zig");
const pacing_mod = @import("pacing.zig");
const Connection = state_mod.Connection;
const EncryptionLevel = state_mod.EncryptionLevel;
const ConnectionId = state_mod.ConnectionId;
const CloseState = state_mod.CloseState;
const Role = state_mod.Role;
const LossStats = state_mod.LossStats;

/// Tag identifying a qlog event (modeled on draft-ietf-quic-qlog-quic-events).
/// Used when the connection invokes its `qlog_callback` so consumers can route
/// the event without parsing arbitrary strings.
pub const QlogEventName = enum {
    application_read_key_installed,
    application_read_key_updated,
    application_read_key_discard_scheduled,
    application_read_key_discarded,
    application_write_key_installed,
    application_write_key_updated,
    application_write_update_acked,
    aead_confidentiality_limit_reached,
    aead_integrity_limit_reached,
    // -- new richer events (modeled after qlog draft-ietf-quic-qlog-quic-events) --
    /// One-shot event when the connection begins exchanging packets — emitted from
    /// the first call to `bind` for clients (or first authenticated packet for the
    /// server). Carries our role plus the SCID/DCID known at the time.
    connection_started,
    /// Emitted whenever `closeState()` transitions (open → closing → draining → closed).
    connection_state_updated,
    /// Emitted once when peer transport parameters are first decoded and
    /// validation passes.
    parameters_set,
    /// Opt-in (gated by `qlog_packet_events`): every outgoing packet.
    packet_sent,
    /// Opt-in (gated by `qlog_packet_events`): every incoming packet that
    /// we successfully authenticate.
    packet_received,
    /// A datagram or packet rejected before frame dispatch (header decode
    /// failure, AEAD failure, version mismatch, retired DCID, etc).
    packet_dropped,
    /// One or more packets declared lost via RFC 9002 logic.
    loss_detected,
    /// Opt-in (gated by `qlog_packet_events`): each individual lost packet.
    packet_lost,
    /// Congestion-controller phase transition (slow-start | recovery |
    /// application-limited). Emitted on transitions only, not periodically.
    congestion_state_updated,
    /// Snapshot of cwnd / RTT / bytes-in-flight after a meaningful update
    /// (currently emitted once per ack-eliciting ACK on the application
    /// path, which keeps volume bounded without per-packet overhead).
    metrics_updated,
    /// Path validation succeeded — PATH_RESPONSE matched a pending PATH_CHALLENGE.
    migration_path_validated,
    /// Path validation failed (timeout) or the peer abandoned the path.
    migration_path_failed,
    /// Stream lifecycle change (open / half-closed / closed).
    stream_state_updated,
    /// Generic key update notification — covers Initial, Handshake, 1-RTT
    /// installs and rotations beyond the more specific application_*
    /// variants above. Currently emitted from `installApplicationSecret`
    /// and `promoteApplicationReadKeys` callers as a duplicate of those
    /// finer-grained events to give a uniform "any key changed" stream.
    key_updated,
};

/// QUIC packet type as it appears in qlog `packet_sent` / `packet_received` /
/// `packet_lost` events.
pub const QlogPacketKind = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
    retry,
    version_negotiation,
};

/// Why a packet was dropped before frame dispatch — populates the qlog
/// `packet_dropped` event.
pub const QlogPacketDropReason = enum {
    /// Packet was too short or had a malformed header.
    header_decode_failure,
    /// AEAD authentication failed (key or content mismatch).
    decryption_failure,
    /// Long-header packet for an unsupported QUIC version.
    unsupported_version,
    /// Short-header DCID didn't map to any active local CID.
    unknown_connection_id,
    /// Packet payload exceeded the local `max_udp_payload_size`.
    payload_too_large,
    /// Stateless reset detected (the rest of the datagram is dropped).
    stateless_reset,
    /// Packet arrived after the keys for its level were dropped.
    keys_unavailable,
    /// Other / unspecified.
    other,
};

/// Packet number space tag carried in qlog packet/loss events.
pub const QlogPnSpace = enum {
    initial,
    handshake,
    application,
};

/// Stream lifecycle state reported via the qlog `stream_state_updated` event.
pub const QlogStreamState = enum {
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset,
};

/// Congestion-controller phase reported via qlog `congestion_state_updated`.
pub const QlogCongestionState = enum {
    slow_start,
    recovery,
    application_limited,
    congestion_avoidance,
};

/// Why a packet was declared lost — populates qlog `loss_detected` /
/// `packet_lost` events. Mirrors RFC 9002 §6 loss detection branches.
pub const QlogLossReason = enum {
    /// RFC 9002 §6.1.1 packet-threshold loss detection.
    packet_threshold,
    /// RFC 9002 §6.1.2 time-threshold loss detection.
    time_threshold,
    /// PTO probe — RFC 9002 §6.2 declared the leading ack-eliciting
    /// packet lost so a probe could go out.
    pto_probe,
};

/// Why a candidate path failed to validate — populates the qlog
/// `migration_path_failed` event. `timeout` is the RFC 9000 §8.2.4
/// 3 * PTO expiry; `policy_denied` is an embedder-installed
/// `MigrationCallback` returning `.deny` before validation began.
pub const QlogMigrationFailReason = enum {
    /// PATH_CHALLENGE went unanswered for 3 * PTO and the validator
    /// transitioned to `.failed`.
    timeout,
    /// A `MigrationCallback` returned `.deny`, so PATH_CHALLENGE was
    /// never queued and the candidate 4-tuple was abandoned.
    policy_denied,
    /// RFC 9000 §9.6 (migration before handshake confirmation) — peer attempted to
    /// migrate before the handshake was confirmed. The triggering
    /// authenticated datagram is dropped (no anti-amp credit, no
    /// PATH_CHALLENGE emitted) so the connection state stays
    /// anchored to the original 4-tuple.
    pre_handshake,
    /// A new PATH_CHALLENGE for this path arrived too soon after the
    /// last one (per `min_path_challenge_interval_us`). Path probe
    /// rate-limit fired; the peer's address change was not honored.
    rate_limited,
    /// RFC 9000 §5.1.2 ¶1: migration would require us to use a fresh
    /// peer-issued CID, but the peer hasn't issued any beyond the one
    /// already in use on this path. The peer needs to send more
    /// NEW_CONNECTION_ID frames before the migration can proceed.
    no_fresh_peer_cid,
};

/// Optional qlog event payload. Existing variants only populate the
/// previous fields; new variants additionally fill the per-event
/// fields below. Callers should branch on `name` and read only the
/// fields documented for that variant.
pub const QlogEvent = struct {
    name: QlogEventName,
    at_us: u64 = 0,
    level: EncryptionLevel = .application,
    key_epoch: ?u64 = null,
    key_phase: ?bool = null,
    packet_number: ?u64 = null,
    discard_deadline_us: ?u64 = null,
    details: []const u8 = &.{},

    // -- fields populated by new event variants ----------------------------
    /// Role and connection-id triple — populated by `connection_started`.
    role: ?Role = null,
    local_scid: ?ConnectionId = null,
    peer_scid: ?ConnectionId = null,
    /// Old/new state for `connection_state_updated`.
    old_state: ?CloseState = null,
    new_state: ?CloseState = null,
    /// Per-packet metadata used by packet_sent/packet_received/packet_lost.
    pn_space: ?QlogPnSpace = null,
    packet_kind: ?QlogPacketKind = null,
    packet_size: ?u32 = null,
    frames_summary: u32 = 0,
    drop_reason: ?QlogPacketDropReason = null,
    /// Loss-detection counts (loss_detected).
    lost_count: ?u32 = null,
    bytes_lost: ?u64 = null,
    loss_reason: ?QlogLossReason = null,
    /// Path-validation outcome (migration_path_*) and stream lifecycle.
    path_id: ?u32 = null,
    /// Why a `migration_path_failed` event fired. `null` for the
    /// `migration_path_validated` variant or when the embedder hasn't
    /// observed the new field yet (existing emit sites set this).
    migration_fail_reason: ?QlogMigrationFailReason = null,
    stream_id: ?u64 = null,
    stream_state: ?QlogStreamState = null,
    /// Congestion / RTT snapshot — congestion_state_updated + metrics_updated.
    cwnd: ?u64 = null,
    bytes_in_flight: ?u64 = null,
    ssthresh: ?u64 = null,
    smoothed_rtt_us: ?u64 = null,
    rtt_var_us: ?u64 = null,
    min_rtt_us: ?u64 = null,
    latest_rtt_us: ?u64 = null,
    pacing_rate: ?u64 = null,
    congestion_state: ?QlogCongestionState = null,
    /// Top-level numeric copy of the most relevant peer transport parameters.
    /// Filled only by `parameters_set`.
    peer_idle_timeout_ms: ?u64 = null,
    peer_max_udp_payload_size: ?u64 = null,
    peer_initial_max_data: ?u64 = null,
    peer_initial_max_streams_bidi: ?u64 = null,
    peer_initial_max_streams_uni: ?u64 = null,
    peer_active_connection_id_limit: ?u64 = null,
    peer_max_ack_delay_ms: ?u64 = null,
    peer_max_datagram_frame_size: ?u64 = null,
};

/// Embedder-supplied qlog sink. The Connection synchronously calls this with
/// each emitted `QlogEvent`; the callback must not call back into the same
/// Connection.
pub const QlogCallback = *const fn (user_data: ?*anyopaque, event: QlogEvent) void;

// Doc comment lives on the `Connection.setQlogCallback` thunk in state.zig.
pub fn setQlogCallback(
    self: *Connection,
    callback: ?QlogCallback,
    user_data: ?*anyopaque,
) void {
    self.qlog_callback = callback;
    self.qlog_user_data = user_data;
}

// Doc comment lives on the `Connection.setQlogPacketEvents` thunk in state.zig.
pub fn setQlogPacketEvents(self: *Connection, enabled: bool) void {
    self.qlog_packet_events = enabled;
}

pub fn emitQlog(self: *Connection, event: QlogEvent) void {
    if (self.qlog_callback) |callback| callback(self.qlog_user_data, event);
}

fn qlogPnSpaceFromLevel(lvl: EncryptionLevel) QlogPnSpace {
    return switch (lvl) {
        .initial => .initial,
        .handshake => .handshake,
        .early_data, .application => .application,
    };
}

fn qlogPacketKindFromLevel(lvl: EncryptionLevel) QlogPacketKind {
    return switch (lvl) {
        .initial => .initial,
        .handshake => .handshake,
        .early_data => .zero_rtt,
        .application => .one_rtt,
    };
}

/// One-shot `connection_started` emitter. Called from `bind` for
/// clients and from the handshake-progress callback for servers.
pub fn emitConnectionStartedOnce(self: *Connection) void {
    if (self.qlog_callback == null or self.qlog_started) return;
    self.qlog_started = true;
    emitQlog(self, .{
        .name = .connection_started,
        .role = self.role,
        .local_scid = if (self.local_scid_set) self.local_scid else null,
        .peer_scid = if (self.peer_dcid_set) self.peer_dcid else null,
    });
}

/// Re-evaluate close state and emit a `connection_state_updated`
/// if it changed since the last emit.
pub fn emitConnectionStateIfChanged(self: *Connection) void {
    if (self.qlog_callback == null) return;
    const new_state = self.closeState();
    if (new_state == self.qlog_last_state) return;
    const old = self.qlog_last_state;
    self.qlog_last_state = new_state;
    emitQlog(self, .{
        .name = .connection_state_updated,
        .old_state = old,
        .new_state = new_state,
    });
}

/// Emit `parameters_set` when the peer's transport parameters are
/// first decoded and accepted.
pub fn emitPeerParametersSet(self: *Connection) void {
    if (self.qlog_callback == null or self.qlog_params_emitted) return;
    const params = self.cached_peer_transport_params orelse return;
    self.qlog_params_emitted = true;
    emitQlog(self, .{
        .name = .parameters_set,
        .peer_idle_timeout_ms = params.max_idle_timeout_ms,
        .peer_max_udp_payload_size = params.max_udp_payload_size,
        .peer_initial_max_data = params.initial_max_data,
        .peer_initial_max_streams_bidi = params.initial_max_streams_bidi,
        .peer_initial_max_streams_uni = params.initial_max_streams_uni,
        .peer_active_connection_id_limit = params.active_connection_id_limit,
        .peer_max_ack_delay_ms = params.max_ack_delay_ms,
        .peer_max_datagram_frame_size = params.max_datagram_frame_size,
    });
}

pub fn emitPacketSent(
    self: *Connection,
    lvl: EncryptionLevel,
    pn: u64,
    size: u32,
    frames_count: u32,
) void {
    if (!self.qlog_packet_events or self.qlog_callback == null) return;
    emitQlog(self, .{
        .name = .packet_sent,
        .level = lvl,
        .pn_space = qlogPnSpaceFromLevel(lvl),
        .packet_kind = qlogPacketKindFromLevel(lvl),
        .packet_number = pn,
        .packet_size = size,
        .frames_summary = frames_count,
    });
}

pub fn emitPacketReceived(
    self: *Connection,
    lvl: EncryptionLevel,
    pn: u64,
    size: u32,
    frames_count: u32,
) void {
    if (!self.qlog_packet_events or self.qlog_callback == null) return;
    emitQlog(self, .{
        .name = .packet_received,
        .level = lvl,
        .pn_space = qlogPnSpaceFromLevel(lvl),
        .packet_kind = qlogPacketKindFromLevel(lvl),
        .packet_number = pn,
        .packet_size = size,
        .frames_summary = frames_count,
    });
}

pub fn emitPacketDropped(
    self: *Connection,
    lvl: ?EncryptionLevel,
    size: u32,
    reason: QlogPacketDropReason,
) void {
    if (self.qlog_callback == null) return;
    emitQlog(self, .{
        .name = .packet_dropped,
        .level = lvl orelse .application,
        .pn_space = if (lvl) |l| qlogPnSpaceFromLevel(l) else null,
        .packet_kind = if (lvl) |l| qlogPacketKindFromLevel(l) else null,
        .packet_size = size,
        .drop_reason = reason,
    });
}

pub fn emitLossDetected(
    self: *Connection,
    lvl: EncryptionLevel,
    stats: LossStats,
    reason: QlogLossReason,
) void {
    if (self.qlog_callback == null or stats.count == 0) return;
    emitQlog(self, .{
        .name = .loss_detected,
        .level = lvl,
        .pn_space = qlogPnSpaceFromLevel(lvl),
        .lost_count = stats.count,
        .bytes_lost = stats.bytes_lost,
        .loss_reason = reason,
    });
}

pub fn emitPacketLost(
    self: *Connection,
    lvl: EncryptionLevel,
    pn: u64,
    bytes: u32,
    reason: QlogLossReason,
) void {
    if (!self.qlog_packet_events or self.qlog_callback == null) return;
    emitQlog(self, .{
        .name = .packet_lost,
        .level = lvl,
        .pn_space = qlogPnSpaceFromLevel(lvl),
        .packet_number = pn,
        .packet_size = bytes,
        .loss_reason = reason,
    });
}

/// Compute the current congestion phase for the primary application
/// path and emit `congestion_state_updated` if it changed.
pub fn emitCongestionStateIfChanged(self: *Connection, now_us: u64) void {
    if (self.qlog_callback == null) return;
    const path = self.primaryPath();
    const cc = &path.path.cc;
    const new_state: QlogCongestionState = blk: {
        if (cc.recoveryStartTimeUs()) |rec_start| {
            if (now_us <= rec_start) break :blk .recovery;
        }
        if (cc.isSlowStart()) break :blk .slow_start;
        break :blk .congestion_avoidance;
    };
    if (self.qlog_last_congestion_state) |prev| {
        if (prev == new_state) return;
    }
    self.qlog_last_congestion_state = new_state;
    emitQlog(self, .{
        .name = .congestion_state_updated,
        .at_us = now_us,
        .congestion_state = new_state,
        .cwnd = cc.cwndBytes(),
        .ssthresh = cc.ssthreshBytes(),
        .bytes_in_flight = path.sent.bytes_in_flight,
    });
}

/// Emit `metrics_updated` with a snapshot of the primary path's
/// congestion / RTT counters.
pub fn emitMetricsSnapshot(self: *Connection, now_us: u64) void {
    if (self.qlog_callback == null) return;
    const path = self.primaryPath();
    const cc = &path.path.cc;
    const rtt = &path.path.rtt;
    emitQlog(self, .{
        .name = .metrics_updated,
        .at_us = now_us,
        .cwnd = cc.cwndBytes(),
        .ssthresh = cc.ssthreshBytes(),
        .bytes_in_flight = path.sent.bytes_in_flight,
        .smoothed_rtt_us = rtt.smoothed_rtt_us,
        .rtt_var_us = rtt.rtt_var_us,
        .min_rtt_us = rtt.min_rtt_us,
        .latest_rtt_us = rtt.latest_rtt_us,
        .pacing_rate = if (self.pacing_enabled)
            pacing_mod.rateBytesPerSecond(
                cc.cwndBytes(),
                rtt.smoothed_rtt_us,
                cc.isSlowStart(),
            )
        else
            null,
    });
}
