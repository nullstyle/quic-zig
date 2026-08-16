//! The inbound receive path of Connection: the handle/handleWithEcn
//! datagram entry points, per-datagram loop control and stateless-reset
//! detection, handleOnePacket orchestration, 1-RTT packet open against
//! the key epochs, frame counting/dispatch (dispatchFrames) with the
//! per-level frame gates, and incoming multipath frame validation.
//! Free-function siblings of `Connection`'s method-style receive
//! plumbing; the methods on `Connection` are thin thunks that delegate
//! here. Per-level packet handlers live in
//! Connection/recv_packet_handlers.zig and the frame handlers in the other
//! conn_recv_*_handlers.zig siblings.

const std = @import("std");
const boringssl = @import("boringssl");
const state_mod = @import("../Connection.zig");
const conn_recv_stream_control_handlers = @import("recv_stream_control_handlers.zig");
const conn_recv_multipath_handlers = @import("recv_multipath_handlers.zig");
const conn_recv_packet_handlers = @import("recv_packet_handlers.zig");
const conn_qlog = @import("qlog.zig");
const conn_keys = @import("keys.zig");
const conn_loss = @import("loss.zig");
const conn_paths = @import("paths.zig");
const conn_migration = @import("migration.zig");
const conn_recv_data_handlers = @import("recv_data_handlers.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const ApplicationKeyEpoch = state_mod.ApplicationKeyEpoch;
const ApplicationReadKeySlot = state_mod.ApplicationReadKeySlot;
const ApplicationOpenResult = state_mod.ApplicationOpenResult;
const wire_header = state_mod.wire_header;
const frame_mod = state_mod.frame_mod;
const frame_types = state_mod.frame_types;
const RttEstimator = state_mod.RttEstimator;
const short_packet_mod = state_mod.short_packet_mod;
const socket_opts_mod = state_mod.socket_opts_mod;
const stateless_reset_mod = state_mod.stateless_reset_mod;
const protection = @import("../wire/protection.zig");
const max_recv_plaintext = state_mod.max_recv_plaintext;
const Address = state_mod.Address;
const PathState = state_mod.PathState;
const PnSpace = state_mod.PnSpace;
const closeErrorSpace = state_mod.lifecycle_mod.closeErrorSpace;
const max_supported_udp_payload_size = state_mod.max_supported_udp_payload_size;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

// Doc comment lives on the `Connection.handle` thunk in Connection.zig.
pub fn handle(
    conn: *Connection,
    bytes: []u8,
    from: ?Address,
    now_us: u64,
) Error!void {
    return handleWithEcn(conn, bytes, from, .not_ect, now_us);
}

// Doc comment lives on the `Connection.handleWithEcn` thunk in Connection.zig.
pub fn handleWithEcn(
    conn: *Connection,
    bytes: []u8,
    from: ?Address,
    ecn: socket_opts_mod.EcnCodepoint,
    now_us: u64,
) Error!void {
    // Stash the ECN marking for the per-packet handlers below; the
    // per-packet decryption tail consults it when crediting the
    // received PN in the level's `PnSpace`. Cleared at handle
    // exit so a subsequent test driver call can't accidentally
    // reuse stale state — the cmsg is per-datagram.
    conn.last_recv_ecn = if (conn.ecn_enabled) ecn else .not_ect;
    defer conn.last_recv_ecn = .not_ect;
    const entry_state = conn.lifecycle.state();
    if (entry_state == .draining or entry_state == .closed) return;
    if (entry_state == .closing and conn.lifecycle.pending_close != null) return;
    // Closing-state attribution accumulator. Cleared on entry so
    // it reflects only this datagram's observations.
    conn.closing_state_attribution_observed = false;
    // Per-handle-cycle DoS gates. See `incoming_ack_range_cap` /
    // `incoming_retire_cid_cap` for the rationale.
    conn.incoming_ack_range_count = 0;
    conn.incoming_retire_cid_count = 0;
    if (bytes.len > localUdpPayloadLimit(
        conn,
    )) {
        // RFC 9000 §14.1: a datagram larger than the negotiated
        // max_udp_payload_size MAY be discarded — it must NOT close
        // the connection. This check runs before any header
        // protection removal or AEAD open, so the datagram is not
        // yet authenticated; closing here would hand an off-path
        // attacker who observed a CID a connection-kill vector (one
        // spoofed oversized datagram, no key knowledge). Drop it.
        conn_qlog.emitPacketDropped(conn, null, @intCast(bytes.len), .payload_too_large);
        return;
    }
    if (bytes.len > 0) {
        conn.last_activity_us = now_us;
        conn.qlog_bytes_received +|= bytes.len;
    }
    const incoming_path_id = conn.incomingPathId(from);
    conn.current_incoming_path_id = incoming_path_id;
    conn.current_incoming_addr = from;
    const incoming_path = conn_paths.pathForId(conn, incoming_path_id);
    const rebind_addr = conn.peerAddressChangeCandidate(incoming_path_id, from);
    const from_migration_rollback_addr = if (from) |addr|
        incoming_path.matchesMigrationRollbackAddress(addr)
    else
        false;
    if (rebind_addr == null) {
        if (!from_migration_rollback_addr) {
            incoming_path.path.onDatagramReceived(bytes.len);
        }
        if (from) |addr| {
            if (!incoming_path.peer_addr_set) incoming_path.setPeerAddress(addr);
        }
    }
    var rebind_recorded = false;
    var pos: usize = 0;
    while (pos < bytes.len) {
        const drain_tls_after_packet = shouldDrainTlsAfterPacket(bytes[pos..]);
        conn.last_authenticated_path_id = null;
        const consumed = try handleOnePacket(conn, bytes[pos..], now_us);
        if (consumed == 0) break;
        pos += consumed;
        if (!rebind_recorded) {
            if (rebind_addr) |addr| {
                if (conn.last_authenticated_path_id) |path_id| {
                    try conn.recordAuthenticatedDatagramAddress(path_id, addr, bytes.len, now_us);
                    rebind_recorded = true;
                }
            }
        }
        if (shouldStopDatagramLoop(
            conn,
        )) break;
        if (!drain_tls_after_packet) break;
        // Drain CRYPTO into TLS BETWEEN packets, not just at
        // the end. A coalesced Initial+Handshake datagram
        // delivers the ServerHello at Initial level — we have
        // to feed it to TLS (deriving Handshake keys) before
        // we can decrypt the trailing Handshake packet.
        try conn_recv_data_handlers.drainInboxIntoTls(
            conn,
        );
    }
    if (conn_recv_data_handlers.cryptoInboxQueued(
        conn,
    ) and !closingAttributionOnly(
        conn,
    )) try conn_recv_data_handlers.drainInboxIntoTls(
        conn,
    );
    // RFC 9001 §4.1.2 ¶2 + §4.9.2: client confirms the handshake
    // when it processes a HANDSHAKE_DONE frame, and an endpoint
    // MUST discard its handshake keys at confirmation. We latch
    // the receipt in the frame switch above (so the `handshake_done`
    // arm stays a small enum-tag write); the actual discard runs
    // here, after the datagram's frames are dispatched, so a late
    // ACK in the same datagram still credits the Handshake-level
    // sent tracker before we tear it down. `discardHandshakeKeys`
    // is idempotent — the latch + the function-local guard makes
    // a re-entry on a second HANDSHAKE_DONE a no-op.
    if (conn.received_handshake_done and !conn.handshake_keys_discarded) {
        conn.discardHandshakeKeys();
    }
    // RFC 9000 §10.2.1 ¶3: when in the closing state and an
    // attributed inbound packet arrived during this datagram,
    // re-arm a CONNECTION_CLOSE retransmit (subject to the SHOULD
    // rate-limit). The peer's CC, if any, would have transitioned
    // us to draining via `dispatchFrames` before we get here.
    maybeRearmClosingStateCloseRepeat(conn, now_us);

    // PATH_CHALLENGE → record-and-tick; the validator will
    // either succeed (echo arrived) or time out at PTO * 3.
    for (conn.paths.paths.items) |*path| {
        path.path.validator.tick(now_us);
        if (path.path.validator.status == .failed) {
            conn_paths.handlePathValidationFailure(conn, path);
        }
    }
    if (conn.alert) |_| return error.PeerAlerted;
}

fn localUdpPayloadLimit(conn: *const Connection) usize {
    return @intCast(@min(conn.local_transport_params.max_udp_payload_size, max_supported_udp_payload_size));
}

fn shouldDrainTlsAfterPacket(bytes: []const u8) bool {
    if (bytes.len < 1) return false;
    if ((bytes[0] & 0x80) == 0) return false;
    if (bytes.len < 5) return false;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    if (version == 0) return false;
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    // RFC 9368 §3.2: Retry's wire bits depend on the version
    // (v1 = 0b11, v2 = 0b00). Resolve through `longTypeFromBits`
    // so the TLS drain skip on Retry packets covers both layouts.
    const long_type = wire_header.longTypeFromBits(version, long_type_bits);
    return long_type != .retry;
}

/// True when the connection is in RFC 9000 §10.2.1's closing state
/// (the deadline-armed phase that follows the first
/// CONNECTION_CLOSE seal) AND no follow-up CC is currently
/// queued. The packet-decrypt tails consult this to decide whether
/// to run the full record-and-dispatch pipeline or the
/// closing-state-only "scan for peer CONNECTION_CLOSE, otherwise
/// flag attribution" tail.
pub fn closingAttributionOnly(conn: *const Connection) bool {
    return conn.lifecycle.closing_deadline_us != null and conn.lifecycle.pending_close == null and conn.lifecycle.draining_deadline_us == null;
}

/// Decide whether the per-datagram packet loop should bail out
/// after the most recent packet. Terminal states (draining /
/// closed) and a freshly-queued local close all force a break;
/// closing-state attribution mode keeps iterating so a CC tucked
/// into a later coalesced packet still transitions us to
/// draining.
fn shouldStopDatagramLoop(conn: *const Connection) bool {
    const cs = conn.lifecycle.state();
    if (cs == .draining or cs == .closed) return true;
    if (cs == .closing and conn.lifecycle.pending_close != null) return true;
    return false;
}

/// Iterate `payload` looking for a peer CONNECTION_CLOSE frame.
/// If found, transition the local lifecycle to draining (RFC 9000
/// §10.2.2 ¶3 license: "An endpoint MAY enter the draining state
/// from the closing state if it receives a CONNECTION_CLOSE
/// frame"). Other frames are ignored — §10.2.1 ¶5: "An endpoint
/// that is closing is not required to process any received
/// frame."
pub fn scanForPeerCloseFrame(
    conn: *Connection,
    payload: []const u8,
    now_us: u64,
) void {
    var it = frame_mod.iter(payload);
    while (it.next() catch return) |f| {
        switch (f) {
            .connection_close => |cc| {
                conn.enterDraining(
                    .peer,
                    closeErrorSpace(cc.is_transport),
                    cc.error_code,
                    if (cc.is_transport) cc.frame_type else 0,
                    cc.reason_phrase,
                    now_us,
                );
                return;
            },
            else => {},
        }
    }
}

/// Re-arm `pending_close` so the next `poll` retransmits the
/// CONNECTION_CLOSE, but only if (a) we're in the post-emit
/// closing state, (b) at least one packet authenticated under our
/// keys during the most recent `handle` call, and (c) the
/// §10.2.1 ¶3 SHOULD-rate-limit allows another emission.
///
/// The retransmit reuses the original close info captured on the
/// sticky `lifecycle.close_event` — same error code, same reason
/// phrase. Per §10.2.1 ¶2 ("An endpoint MAY send CONNECTION_CLOSE
/// frames of different sizes or with different error codes, but
/// the error code in all frames SHOULD be consistent"), keeping
/// them identical satisfies the SHOULD-consistent guidance.
fn maybeRearmClosingStateCloseRepeat(conn: *Connection, now_us: u64) void {
    if (!conn.closing_state_attribution_observed) return;
    conn.closing_state_attribution_observed = false;
    if (conn.lifecycle.state() != .closing) return;
    if (conn.lifecycle.closing_deadline_us == null) return;
    if (conn.lifecycle.pending_close != null) return;
    const base = conn_loss.basePtoDurationForLevel(conn, .application);
    if (!conn.lifecycle.shouldRearmCloseRepeat(now_us, base)) return;
    const stored = conn.lifecycle.close_event orelse return;
    conn.lifecycle.pending_close = .{
        .is_transport = stored.error_space == .transport,
        .error_code = stored.error_code,
        .frame_type = stored.frame_type,
        .reason = conn.lifecycle.close_reason_buf[0..stored.reason_len],
    };
    conn_qlog.emitConnectionStateIfChanged(
        conn,
    );
}

pub fn handleOnePacket(
    conn: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    if (bytes.len < 1) return 0;
    const first = bytes[0];

    if (first & 0x80 == 0) {
        // Short header → 1-RTT, last in datagram.
        return try conn.handleShort(bytes, now_us);
    }

    if (bytes.len < 5) return 0;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    if (version == 0) {
        return conn_recv_packet_handlers.handleVersionNegotiation(conn, bytes, now_us);
    }

    // RFC 9368 §3.2: long-header type bits rotate between v1 and
    // v2. Resolve through `longTypeFromBits` so a v2 packet with
    // wire bits 0b01 dispatches to `handleInitial`, not
    // `handleZeroRtt` (the v1 slot for that bit pattern). For
    // versions we don't recognize, the v1 mapping is the safest
    // default — those packets will fail downstream version /
    // AEAD gates anyway.
    const long_type_bits: u2 = @intCast((first >> 4) & 0x03);
    const long_type = wire_header.longTypeFromBits(version, long_type_bits);
    return switch (long_type) {
        .initial => try conn.handleInitial(bytes, now_us),
        .zero_rtt => try conn_recv_packet_handlers.handleZeroRtt(conn, bytes, now_us),
        .handshake => try conn_recv_packet_handlers.handleHandshake(conn, bytes, now_us),
        .retry => try conn.handleRetry(bytes, now_us),
    };
}

fn frameAckEliciting(f: frame_types.Frame) bool {
    return switch (f) {
        .padding,
        .ack,
        .path_ack,
        .connection_close,
        => false,
        else => true,
    };
}

/// One-pass classification of a payload's frames: ACK eligibility
/// (RFC 9000 §13.2.1), immediate-ACK triggering, and the qlog frame
/// count. Replaces what used to be three separate full frame
/// iterations per received packet.
pub const PayloadClassification = struct {
    ack_eliciting: bool = false,
    needs_immediate_ack: bool = false,
    frame_count: u32 = 0,
};

fn isImmediateAckFrame(f: frame_types.Frame) bool {
    return switch (f) {
        .stream => |s| s.fin,
        .reset_stream,
        .stop_sending,
        => true,
        else => false,
    };
}

pub fn classifyPayload(payload: []const u8) PayloadClassification {
    var cls: PayloadClassification = .{};
    var it = frame_mod.iter(payload);
    while (true) {
        const f = it.next() catch {
            // A payload that cannot be parsed cleanly is treated as
            // ack-eliciting + immediate-ack: the old scanners returned
            // true on decode error so a malformed-but-authenticated
            // packet could not slip into delayed-ACK bookkeeping
            // (dispatchFrames will close with FRAME_ENCODING_ERROR).
            cls.ack_eliciting = true;
            cls.needs_immediate_ack = true;
            return cls;
        } orelse return cls;
        cls.frame_count += 1;
        if (frameAckEliciting(f)) {
            cls.ack_eliciting = true;
            if (isImmediateAckFrame(f)) cls.needs_immediate_ack = true;
        }
    }
}

pub fn packetPayloadAckEliciting(payload: []const u8) bool {
    return classifyPayload(payload).ack_eliciting;
}

pub fn packetPayloadNeedsImmediateAck(payload: []const u8) bool {
    return classifyPayload(payload).needs_immediate_ack;
}

pub fn recordApplicationReceivedPacket(
    app_pn_space: *PnSpace,
    pn: u64,
    now_us: u64,
    cls: PayloadClassification,
    delayed_ack_threshold: u8,
) void {
    if (cls.ack_eliciting and cls.needs_immediate_ack) {
        app_pn_space.recordReceivedPacket(pn, now_us / RttEstimator.ms, true);
        return;
    }
    app_pn_space.recordReceivedPacketDelayed(
        pn,
        now_us / RttEstimator.ms,
        cls.ack_eliciting,
        delayed_ack_threshold,
    );
}

pub fn versionListContains(vn: wire_header.VersionNegotiation, version: u32) bool {
    var i: usize = 0;
    while (i < vn.versionCount()) : (i += 1) {
        if (vn.version(i) == version) return true;
    }
    return false;
}

pub fn openApplicationPacket(
    conn: *Connection,
    pt_buf: *[max_recv_plaintext]u8,
    bytes: []u8,
    app_path: *const PathState,
    largest_received: u64,
    multipath_path_id: ?u32,
) Error!?ApplicationOpenResult {
    // RFC 9001 §6: the header-protection key is retained across
    // application key updates, so the HP mask for this packet is
    // identical for every epoch attempt. Derive it once up front
    // (using whichever epoch's keys are handy — they all share the
    // same HP key) and hand it to each open attempt instead of
    // re-running the AES block encrypt per epoch.
    const hp_mask = blk: {
        const keys: ?*const short_packet_mod.PacketKeys = if (conn.app_read_current) |*e| &e.keys else if (conn.app_read_previous) |*e| &e.keys else if (conn.app_read_next) |*e| &e.keys else null;
        const epoch_keys = keys orelse break :blk null;
        const pn_offset: usize = 1 + @as(usize, app_path.path.local_cid.len);
        if (bytes.len < pn_offset + 4 + protection.sample_len) break :blk null;
        const sample = protection.sampleAt(bytes, pn_offset) catch break :blk null;
        break :blk short_packet_mod.headerProtectionMask(epoch_keys, &sample) catch null;
    };
    if (try tryOpenApplicationPacketWithEpoch(
        conn,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        hp_mask,
        conn.app_read_current,
        .current,
    )) |result| return result;
    if (try tryOpenApplicationPacketWithEpoch(
        conn,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        hp_mask,
        conn.app_read_previous,
        .previous,
    )) |result| return result;
    if (conn.app_read_next == null) try conn_keys.refreshNextApplicationReadKey(
        conn,
    );
    if (try tryOpenApplicationPacketWithEpoch(
        conn,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        hp_mask,
        conn.app_read_next,
        .next,
    )) |result| return result;
    return null;
}

fn tryOpenApplicationPacketWithEpoch(
    conn: *Connection,
    pt_buf: *[max_recv_plaintext]u8,
    bytes: []u8,
    app_path: *const PathState,
    largest_received: u64,
    multipath_path_id: ?u32,
    hp_mask: ?[protection.mask_len]u8,
    maybe_epoch: ?ApplicationKeyEpoch,
    slot: ApplicationReadKeySlot,
) Error!?ApplicationOpenResult {
    _ = conn;
    const epoch = maybe_epoch orelse return null;
    const opened = short_packet_mod.open1Rtt(pt_buf, bytes, .{
        .dcid_len = app_path.path.local_cid.len,
        .keys = &epoch.keys,
        .largest_received = largest_received,
        .multipath_path_id = multipath_path_id,
        .mask = hp_mask,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => return null,
        else => return e,
    };
    if (opened.key_phase != epoch.key_phase) return null;
    return .{ .opened = opened, .slot = slot };
}

pub fn dispatchFrames(
    conn: *Connection,
    lvl: EncryptionLevel,
    payload: []const u8,
    now_us: u64,
) Error!void {
    if (debugFramesEnabled()) {
        std.debug.print("[frames lvl={s} payload_len={d}] ", .{ @tagName(lvl), payload.len });
    }
    var it = frame_mod.iter(payload);
    while (true) {
        const maybe_frame = it.next() catch {
            // RFC 9000 §12.4: a frame that cannot be parsed — unknown
            // type, truncated, or otherwise malformed — is a peer
            // protocol violation that MUST be closed with
            // FRAME_ENCODING_ERROR. Convert the decode error into a
            // connection close here rather than letting it escape
            // dispatchFrames: otherwise a single malformed frame from
            // an authenticated peer propagates out as a fatal error,
            // tearing down the whole transport loop (client) or being
            // mislabeled as INTERNAL_ERROR (server).
            conn.close(true, transport_error_frame_encoding, "malformed frame");
            return;
        };
        const f = maybe_frame orelse break;
        if (debugFramesEnabled()) {
            switch (f) {
                .crypto => |cr| std.debug.print("CRYPTO(off={d},len={d}) ", .{ cr.offset, cr.data.len }),
                .padding => |p| std.debug.print("PADDING(n={d}) ", .{p.count}),
                .ack => |a| std.debug.print("ACK(la={d}) ", .{a.largest_acked}),
                .path_ack => |a| std.debug.print("PATH_ACK(path={d},la={d}) ", .{ a.path_id, a.largest_acked }),
                .stream => |s| std.debug.print("STREAM(id={d},off={d},len={d},fin={}) ", .{ s.stream_id, s.offset, s.data.len, s.fin }),
                .datagram => |d| std.debug.print("DATAGRAM(len={d}) ", .{d.data.len}),
                .reset_stream => |r| std.debug.print("RESET_STREAM(id={d},code={d},final={d}) ", .{ r.stream_id, r.application_error_code, r.final_size }),
                .path_abandon => |pa| std.debug.print("PATH_ABANDON(path={d},code={d}) ", .{ pa.path_id, pa.error_code }),
                .path_status_backup => |ps| std.debug.print("PATH_STATUS_BACKUP(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                .path_status_available => |ps| std.debug.print("PATH_STATUS_AVAILABLE(path={d},seq={d}) ", .{ ps.path_id, ps.sequence_number }),
                .path_new_connection_id => |nc| std.debug.print("PATH_NEW_CONNECTION_ID(path={d},seq={d}) ", .{ nc.path_id, nc.sequence_number }),
                .path_retire_connection_id => |rc| std.debug.print("PATH_RETIRE_CONNECTION_ID(path={d},seq={d}) ", .{ rc.path_id, rc.sequence_number }),
                .max_path_id => |mp| std.debug.print("MAX_PATH_ID(max={d}) ", .{mp.maximum_path_id}),
                .paths_blocked => |pb| std.debug.print("PATHS_BLOCKED(max={d}) ", .{pb.maximum_path_id}),
                .path_cids_blocked => |pcb| std.debug.print("PATH_CIDS_BLOCKED(path={d},next={d}) ", .{ pcb.path_id, pcb.next_sequence_number }),
                .ping => std.debug.print("PING ", .{}),
                else => |x| std.debug.print("{s} ", .{@tagName(x)}),
            }
        }
        // RFC 9000 §12.4 / Table 3: at the Initial and Handshake
        // encryption levels the only legal frames are PADDING,
        // PING, ACK, CRYPTO, and CONNECTION_CLOSE of type 0x1c
        // (transport variant — application CONNECTION_CLOSE 0x1d
        // is application-data only, hence 1-RTT only). Any other
        // frame at those levels is a peer protocol violation.
        if ((lvl == .initial or lvl == .handshake) and
            !frameAllowedInInitialOrHandshake(f))
        {
            conn.close(true, transport_error_protocol_violation, "forbidden frame at Initial/Handshake level");
            return;
        }
        if (lvl == .early_data and !frameAllowedInEarlyData(f)) {
            conn.close(true, transport_error_protocol_violation, "forbidden frame in 0-RTT");
            return;
        }
        // RFC 9000 §19.20: HANDSHAKE_DONE is a server-only frame.
        // "A server MUST treat receipt of a HANDSHAKE_DONE frame as
        // a connection error of type PROTOCOL_VIOLATION."
        if (f == .handshake_done and conn.role == .server) {
            conn.close(true, transport_error_protocol_violation, "HANDSHAKE_DONE received by server");
            return;
        }
        if (lvl != .application and isMultipathFrame(f)) {
            conn.close(true, transport_error_protocol_violation, "multipath frame outside 1-RTT");
            return;
        }
        if (lvl == .application and isMultipathFrame(f) and !conn.multipathNegotiated()) {
            conn.close(true, transport_error_protocol_violation, "multipath frame without negotiation");
            return;
        }
        if (lvl == .application and isMultipathFrame(f) and
            !validateIncomingMultipathFrame(conn, f))
        {
            return;
        }
        // draft-munizaga-quic-alternative-server-address-00 §6.
        // ALTERNATIVE_V4/V6_ADDRESS frames are gated by the
        // `alternative_address` transport parameter (§4) — only
        // a server may send them, and only after the client
        // advertised support. Receipt outside that envelope is
        // a peer protocol violation. One gate for both frame
        // types: the §4/§7 negotiation policy reads only the
        // role and the negotiated parameter, never the address
        // payload, so it must not be able to diverge per family.
        if (isAlternativeAddressFrame(f) and
            (conn.role != .client or !conn.localAdvertisedAlternativeAddress()))
        {
            conn.close(
                true,
                transport_error_protocol_violation,
                "alternative_address frame without negotiation",
            );
            return;
        }
        switch (f) {
            .padding, .ping => {},
            .handshake_done => {
                // RFC 9001 §4.1.2 ¶2: client confirms the handshake
                // on receipt of HANDSHAKE_DONE. The validity gate
                // above already rejected this frame on the server
                // role with PROTOCOL_VIOLATION, so we know we're
                // the client. RFC 9001 §4.9.2 then mandates the
                // Handshake-key discard. Latching the receipt here
                // (rather than at end-of-datagram) keeps the gate
                // and the discard atomic with respect to ACK
                // processing — the ACK arm below uses
                // `handshake_keys_discarded` to short-circuit a
                // late peer ACK that arrives after we've cleaned
                // the sent tracker.
                conn.received_handshake_done = true;
            },
            .ack => |a| {
                if (conn.exceedsIncomingAckRangeCap(a.range_count)) continue;
                try conn.handleAckAtLevel(lvl, a, now_us);
            },
            .path_ack => |a| {
                if (conn.exceedsIncomingAckRangeCap(a.range_count)) continue;
                try conn.handlePathAck(a, now_us);
            },
            .crypto => |cr| try conn.handleCrypto(lvl, cr),
            .stream => |s| try conn.handleStream(lvl, s),
            .reset_stream => |rs| try conn.handleResetStream(rs),
            .datagram => |dg| try conn.handleDatagram(lvl, dg),
            .path_challenge => |pc| {
                conn.queuePathResponseOnPath(
                    conn.current_incoming_path_id,
                    pc.data,
                    conn.current_incoming_addr,
                );
                // RFC 9000 §5.1.2 ¶1: an endpoint MUST NOT use the
                // same connection ID on different paths. If our
                // peer sent us a PATH_CHALLENGE on the current
                // active path, the peer believes it has detected
                // a peer-initiated migration on our end (e.g. the
                // runner's `rebind-addr` simulator rewrites the
                // client's source IP transparently — the kernel
                // socket is unchanged so we never observe the
                // migration locally, but the server sees a new
                // 4-tuple and probes it). Match the peer's view
                // by rotating to a fresh peer-issued CID for
                // subsequent outbound packets. Without this,
                // quiche's server-side §5.1.2 enforcement logs
                // "Peer reused cid seq 0 ... on (new tuple)" and
                // the `client × quiche × rebind-addr` cell fails
                // because the runner's pcap check rejects the
                // CID reuse.
                //
                // No-op if no fresh peer CID is available — the
                // peer hasn't issued NEW_CONNECTION_ID beyond
                // what we're already using on this path. The
                // PATH_RESPONSE we just queued still ships under
                // the existing DCID, which preserves liveness.
                const path = conn_paths.pathForId(conn, conn.current_incoming_path_id);
                if (conn_migration.consumeFreshPeerCidForMigration(conn, path)) |fresh_cid| {
                    path.path.peer_cid = fresh_cid;
                    if (path.id == 0) {
                        conn.peer_dcid = fresh_cid;
                        conn.peer_dcid_set = true;
                    }
                }
            },
            .path_response => |pr| conn.recordPathResponse(conn.current_incoming_path_id, pr.data),
            .new_connection_id => |nc| try conn.handleNewConnectionId(nc),
            .stop_sending => |ss| try conn_recv_stream_control_handlers.handleStopSending(conn, ss),
            .path_abandon => |pa| conn_recv_multipath_handlers.handlePathAbandon(conn, pa, now_us),
            .path_status_backup => |ps| conn_recv_multipath_handlers.handlePathStatus(conn, ps, false),
            .path_status_available => |ps| conn_recv_multipath_handlers.handlePathStatus(conn, ps, true),
            .path_new_connection_id => |nc| try conn.handlePathNewConnectionId(nc),
            .path_retire_connection_id => |rc| conn.handlePathRetireConnectionId(rc),
            .max_path_id => |mp| conn.handleMaxPathId(mp),
            .paths_blocked => |pb| conn.handlePathsBlocked(pb),
            .path_cids_blocked => |pcb| conn.handlePathCidsBlocked(pcb),
            .max_data => |md| conn.handleMaxData(md),
            .max_stream_data => |msd| conn.handleMaxStreamData(msd),
            .max_streams => |ms| conn.handleMaxStreams(ms),
            .data_blocked => |db| conn.handleDataBlocked(db),
            .stream_data_blocked => |sdb| try conn.handleStreamDataBlocked(sdb),
            .streams_blocked => |sb| conn.handleStreamsBlocked(sb),
            .connection_close => |cc| {
                conn.enterDraining(
                    .peer,
                    closeErrorSpace(cc.is_transport),
                    cc.error_code,
                    if (cc.is_transport) cc.frame_type else 0,
                    cc.reason_phrase,
                    now_us,
                );
            },
            .retire_connection_id => |rc| conn.handleRetireConnectionId(rc),
            .new_token => |nt| conn.handleNewToken(nt),
            .alternative_v4_address => |a| conn.handleAlternativeAddressV4(a),
            .alternative_v6_address => |a| conn.handleAlternativeAddressV6(a),
        }
    }
    if (debugFramesEnabled()) {
        std.debug.print("\n", .{});
    }
}

fn isMultipathFrame(f: frame_types.Frame) bool {
    return switch (f) {
        .path_ack,
        .path_abandon,
        .path_status_backup,
        .path_status_available,
        .path_new_connection_id,
        .path_retire_connection_id,
        .max_path_id,
        .paths_blocked,
        .path_cids_blocked,
        => true,
        else => false,
    };
}

/// draft-munizaga-quic-alternative-server-address-00 §6 frame
/// classifier feeding the pre-switch negotiation gate in
/// `dispatchFrames` — both families share one §4/§7 policy check.
fn isAlternativeAddressFrame(f: frame_types.Frame) bool {
    return switch (f) {
        .alternative_v4_address,
        .alternative_v6_address,
        => true,
        else => false,
    };
}

fn frameAllowedInEarlyData(f: frame_types.Frame) bool {
    return switch (f) {
        // RFC 9000 §12.4 / Table 3 marks ACK (IH_1), CRYPTO (IH_1),
        // HANDSHAKE_DONE (___1), and NEW_TOKEN (___1) as forbidden
        // in 0-RTT. PATH_RESPONSE and RETIRE_CONNECTION_ID are
        // __01 (legal in 0-RTT) and therefore fall through to the
        // allow arm below.
        .ack,
        .crypto,
        .handshake_done,
        .new_token,
        // draft-munizaga-quic-alternative-server-address-00 §4 ¶3
        // forbids remembering the `alternative_address` parameter
        // for 0-RTT, so the negotiation cannot have happened by
        // the time a 0-RTT packet is processed. Reject the frames
        // outright at the early-data gate so the diagnostic close
        // reason is "forbidden frame in 0-RTT" rather than
        // "without negotiation" — clearer for operators and
        // closes the door even if a future role-gate change
        // accidentally weakens the inner check.
        .alternative_v4_address,
        .alternative_v6_address,
        => false,
        else => true,
    };
}

/// RFC 9000 §12.4 / Table 3: frames legal at the Initial or
/// Handshake encryption level. Both levels share the same allowed
/// list — PADDING, PING, ACK, CRYPTO, and the transport-variant
/// CONNECTION_CLOSE (frame type 0x1c).
///
/// CONNECTION_CLOSE 0x1d (the application-error variant) is
/// 1-RTT-only because it carries an application-supplied error
/// code; emitting it before the handshake completes would expose
/// application semantics to an unauthenticated peer.
fn frameAllowedInInitialOrHandshake(f: frame_types.Frame) bool {
    return switch (f) {
        .padding,
        .ping,
        .ack,
        .crypto,
        => true,
        .connection_close => |cc| cc.is_transport,
        else => false,
    };
}

pub fn tokenEql(a: [16]u8, b: [16]u8) bool {
    // RFC 9000 §10.3 — stateless reset tokens MUST be compared in
    // constant time. A peer that observes timing differences across
    // mismatching prefixes can incrementally guess valid tokens.
    // Routes through `stateless_reset.eql` so the conformance
    // suite can verify the property against the same code path
    // production callers exercise.
    return stateless_reset_mod.eql(a, b);
}

fn statelessResetTokenFromDatagram(bytes: []const u8) ?[16]u8 {
    if (bytes.len < 21) return null;
    if ((bytes[0] & 0x80) != 0) return null;
    var token: [16]u8 = undefined;
    @memcpy(&token, bytes[bytes.len - 16 ..]);
    return token;
}

pub fn isKnownStatelessReset(conn: *const Connection, bytes: []const u8) bool {
    const token = statelessResetTokenFromDatagram(bytes) orelse return false;
    for (conn.peer_cids.items) |item| {
        if (tokenEql(item.stateless_reset_token, token)) return true;
    }
    return false;
}

pub fn pathIdAllowedByLocalLimit(conn: *Connection, path_id: u32) bool {
    if (path_id <= conn.local_max_path_id) return true;
    conn.close(true, transport_error_protocol_violation, "multipath path id exceeds local limit");
    return false;
}

fn validateIncomingMultipathFrame(conn: *Connection, f: frame_types.Frame) bool {
    return switch (f) {
        .path_ack => |pa| pathIdAllowedByLocalLimit(conn, pa.path_id),
        .path_abandon => |pa| pathIdAllowedByLocalLimit(conn, pa.path_id),
        .path_status_backup => |ps| pathIdAllowedByLocalLimit(conn, ps.path_id),
        .path_status_available => |ps| pathIdAllowedByLocalLimit(conn, ps.path_id),
        .path_new_connection_id => |nc| pathIdAllowedByLocalLimit(conn, nc.path_id),
        .path_retire_connection_id => |rc| pathIdAllowedByLocalLimit(conn, rc.path_id),
        .paths_blocked => |pb| pathIdAllowedByLocalLimit(conn, pb.maximum_path_id),
        .path_cids_blocked => |pcb| blk: {
            if (!pathIdAllowedByLocalLimit(conn, pcb.path_id)) break :blk false;
            break :blk conn_recv_multipath_handlers.pathCidsBlockedSeqIsValid(conn, pcb);
        },
        .max_path_id => |mp| conn_recv_multipath_handlers.maxPathIdRespectsPeerInitialLimit(conn, mp),
        else => true,
    };
}

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;

/// Lazy per-thread cache for the QUIC_ZIG_DEBUG_FRAMES trace toggle.
/// dispatchFrames consults this once per frame; previously each
/// consultation was a libc environment scan on the inbound hot path.
/// The cache reduces that to one getenv call per thread per process
/// followed by a plain boolean branch. The value is read lazily so
/// the env var can be set between process start and first packet.
threadlocal var debug_frames_enabled_cache: ?bool = null;
fn debugFramesEnabled() bool {
    if (debug_frames_enabled_cache) |v| return v;
    const v = getenv("QUIC_ZIG_DEBUG_FRAMES") != null;
    debug_frames_enabled_cache = v;
    return v;
}
