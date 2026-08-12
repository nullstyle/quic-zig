// The inbound receive path of Connection: the handle/handleWithEcn
// datagram entry points, per-datagram loop control and stateless-reset
// detection, handleOnePacket orchestration, 1-RTT packet open against
// the key epochs, frame counting/dispatch (dispatchFrames) with the
// per-level frame gates, and incoming multipath frame validation.
// Free-function siblings of `Connection`'s method-style receive
// plumbing; the methods on `Connection` are thin thunks that delegate
// here. Per-level packet handlers live in
// conn_recv_packet_handlers.zig and the frame handlers in the other
// conn_recv_*_handlers.zig siblings.

const std = @import("std");
const boringssl = @import("boringssl");
const state_mod = @import("state.zig");
const conn_qlog = @import("conn_qlog.zig");
const conn_keys = @import("conn_keys.zig");
const conn_loss = @import("conn_loss.zig");
const conn_paths = @import("conn_paths.zig");
const conn_migration = @import("conn_migration.zig");
const conn_recv_data_handlers = @import("conn_recv_data_handlers.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const ApplicationKeyEpoch = state_mod.ApplicationKeyEpoch;
const ApplicationReadKeySlot = state_mod.ApplicationReadKeySlot;
const ApplicationOpenResult = state_mod.ApplicationOpenResult;
const wire_header = state_mod.wire_header;
const frame_mod = state_mod.frame_mod;
const frame_types = state_mod.frame_types;
const rtt_mod = state_mod.rtt_mod;
const short_packet_mod = state_mod.short_packet_mod;
const socket_opts_mod = state_mod.socket_opts_mod;
const stateless_reset_mod = state_mod.stateless_reset_mod;
const _internal = state_mod._internal;
const max_recv_plaintext = state_mod.max_recv_plaintext;
const Address = state_mod.Address;
const PathState = state_mod.PathState;
const PnSpace = state_mod.PnSpace;
const closeErrorSpace = state_mod.lifecycle_mod.closeErrorSpace;
const max_supported_udp_payload_size = state_mod.max_supported_udp_payload_size;
const transport_error_frame_encoding = state_mod.transport_error_frame_encoding;
const transport_error_protocol_violation = state_mod.transport_error_protocol_violation;

// Doc comment lives on the `Connection.handle` thunk in state.zig.
pub fn handle(
    self: *Connection,
    bytes: []u8,
    from: ?Address,
    now_us: u64,
) Error!void {
    return handleWithEcn(self, bytes, from, .not_ect, now_us);
}

// Doc comment lives on the `Connection.handleWithEcn` thunk in state.zig.
pub fn handleWithEcn(
    self: *Connection,
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
    self.last_recv_ecn = if (self.ecn_enabled) ecn else .not_ect;
    defer self.last_recv_ecn = .not_ect;
    const entry_state = self.lifecycle.state();
    if (entry_state == .draining or entry_state == .closed) return;
    if (entry_state == .closing and self.lifecycle.pending_close != null) return;
    // Closing-state attribution accumulator. Cleared on entry so
    // it reflects only this datagram's observations.
    self.closing_state_attribution_observed = false;
    // Per-handle-cycle DoS gates. See `incoming_ack_range_cap` /
    // `incoming_retire_cid_cap` for the rationale.
    self.incoming_ack_range_count = 0;
    self.incoming_retire_cid_count = 0;
    if (bytes.len > localUdpPayloadLimit(
        self,
    )) {
        self.emitPacketDropped(null, @intCast(bytes.len), .payload_too_large);
        self.close(true, transport_error_protocol_violation, "udp payload exceeds local limit");
        conn_qlog.emitConnectionStateIfChanged(
            self,
        );
        return;
    }
    if (bytes.len > 0) {
        self.last_activity_us = now_us;
        self.qlog_bytes_received +|= bytes.len;
    }
    const incoming_path_id = self.incomingPathId(from);
    self.current_incoming_path_id = incoming_path_id;
    self.current_incoming_addr = from;
    const incoming_path = self.pathForId(incoming_path_id);
    const rebind_addr = self.peerAddressChangeCandidate(incoming_path_id, from);
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
        self.last_authenticated_path_id = null;
        const consumed = try handleOnePacket(self, bytes[pos..], now_us);
        if (consumed == 0) break;
        pos += consumed;
        if (!rebind_recorded) {
            if (rebind_addr) |addr| {
                if (self.last_authenticated_path_id) |path_id| {
                    try self.recordAuthenticatedDatagramAddress(path_id, addr, bytes.len, now_us);
                    rebind_recorded = true;
                }
            }
        }
        if (shouldStopDatagramLoop(
            self,
        )) break;
        if (!drain_tls_after_packet) break;
        // Drain CRYPTO into TLS BETWEEN packets, not just at
        // the end. A coalesced Initial+Handshake datagram
        // delivers the ServerHello at Initial level — we have
        // to feed it to TLS (deriving Handshake keys) before
        // we can decrypt the trailing Handshake packet.
        try conn_recv_data_handlers.drainInboxIntoTls(
            self,
        );
    }
    if (conn_recv_data_handlers.cryptoInboxQueued(
        self,
    ) and !closingAttributionOnly(
        self,
    )) try conn_recv_data_handlers.drainInboxIntoTls(
        self,
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
    if (self.received_handshake_done and !self.handshake_keys_discarded) {
        self.discardHandshakeKeys();
    }
    // RFC 9000 §10.2.1 ¶3: when in the closing state and an
    // attributed inbound packet arrived during this datagram,
    // re-arm a CONNECTION_CLOSE retransmit (subject to the SHOULD
    // rate-limit). The peer's CC, if any, would have transitioned
    // us to draining via `dispatchFrames` before we get here.
    maybeRearmClosingStateCloseRepeat(self, now_us);

    // PATH_CHALLENGE → record-and-tick; the validator will
    // either succeed (echo arrived) or time out at PTO * 3.
    for (self.paths.paths.items) |*path| {
        path.path.validator.tick(now_us);
        if (path.path.validator.status == .failed) {
            conn_paths.handlePathValidationFailure(self, path);
        }
    }
    if (self.alert) |_| return error.PeerAlerted;
}

fn localUdpPayloadLimit(self: *const Connection) usize {
    return @intCast(@min(self.local_transport_params.max_udp_payload_size, max_supported_udp_payload_size));
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
pub fn closingAttributionOnly(self: *const Connection) bool {
    return self.lifecycle.closing_deadline_us != null and self.lifecycle.pending_close == null and self.lifecycle.draining_deadline_us == null;
}

/// Decide whether the per-datagram packet loop should bail out
/// after the most recent packet. Terminal states (draining /
/// closed) and a freshly-queued local close all force a break;
/// closing-state attribution mode keeps iterating so a CC tucked
/// into a later coalesced packet still transitions us to
/// draining.
fn shouldStopDatagramLoop(self: *const Connection) bool {
    const cs = self.lifecycle.state();
    if (cs == .draining or cs == .closed) return true;
    if (cs == .closing and self.lifecycle.pending_close != null) return true;
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
    self: *Connection,
    payload: []const u8,
    now_us: u64,
) void {
    var it = frame_mod.iter(payload);
    while (it.next() catch return) |f| {
        switch (f) {
            .connection_close => |cc| {
                self.enterDraining(
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
fn maybeRearmClosingStateCloseRepeat(self: *Connection, now_us: u64) void {
    if (!self.closing_state_attribution_observed) return;
    self.closing_state_attribution_observed = false;
    if (self.lifecycle.state() != .closing) return;
    if (self.lifecycle.closing_deadline_us == null) return;
    if (self.lifecycle.pending_close != null) return;
    const base = conn_loss.basePtoDurationForLevel(self, .application);
    if (!self.lifecycle.shouldRearmCloseRepeat(now_us, base)) return;
    const stored = self.lifecycle.close_event orelse return;
    self.lifecycle.pending_close = .{
        .is_transport = stored.error_space == .transport,
        .error_code = stored.error_code,
        .frame_type = stored.frame_type,
        .reason = self.lifecycle.close_reason_buf[0..stored.reason_len],
    };
    conn_qlog.emitConnectionStateIfChanged(
        self,
    );
}

pub fn handleOnePacket(
    self: *Connection,
    bytes: []u8,
    now_us: u64,
) Error!usize {
    if (bytes.len < 1) return 0;
    const first = bytes[0];

    if (first & 0x80 == 0) {
        // Short header → 1-RTT, last in datagram.
        return try self.handleShort(bytes, now_us);
    }

    if (bytes.len < 5) return 0;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    if (version == 0) {
        return self.handleVersionNegotiation(bytes, now_us);
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
        .initial => try self.handleInitial(bytes, now_us),
        .zero_rtt => try self.handleZeroRtt(bytes, now_us),
        .handshake => try self.handleHandshake(bytes, now_us),
        .retry => try self.handleRetry(bytes, now_us),
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

pub fn packetPayloadAckEliciting(payload: []const u8) bool {
    var it = frame_mod.iter(payload);
    while (it.next() catch return true) |f| {
        if (frameAckEliciting(f)) return true;
    }
    return false;
}

pub fn packetPayloadNeedsImmediateAck(payload: []const u8) bool {
    var it = frame_mod.iter(payload);
    while (it.next() catch return true) |f| {
        switch (f) {
            .stream => |s| if (s.fin) return true,
            .reset_stream,
            .stop_sending,
            => return true,
            else => {},
        }
    }
    return false;
}

pub fn recordApplicationReceivedPacket(
    app_pn_space: *PnSpace,
    pn: u64,
    now_us: u64,
    payload: []const u8,
    delayed_ack_threshold: u8,
) void {
    const ack_eliciting = packetPayloadAckEliciting(payload);
    if (ack_eliciting and packetPayloadNeedsImmediateAck(payload)) {
        app_pn_space.recordReceivedPacket(pn, now_us / rtt_mod.ms, true);
        return;
    }
    app_pn_space.recordReceivedPacketDelayed(
        pn,
        now_us / rtt_mod.ms,
        ack_eliciting,
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

pub fn countFrames(payload: []const u8) u32 {
    var count: u32 = 0;
    var it = frame_mod.iter(payload);
    while (it.next() catch return count) |_| {
        count += 1;
    }
    return count;
}

pub fn openApplicationPacket(
    self: *Connection,
    pt_buf: *[max_recv_plaintext]u8,
    bytes: []u8,
    app_path: *const PathState,
    largest_received: u64,
    multipath_path_id: ?u32,
) Error!?ApplicationOpenResult {
    if (try tryOpenApplicationPacketWithEpoch(
        self,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        self.app_read_current,
        .current,
    )) |result| return result;
    if (try tryOpenApplicationPacketWithEpoch(
        self,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        self.app_read_previous,
        .previous,
    )) |result| return result;
    if (self.app_read_next == null) try conn_keys.refreshNextApplicationReadKey(
        self,
    );
    if (try tryOpenApplicationPacketWithEpoch(
        self,
        pt_buf,
        bytes,
        app_path,
        largest_received,
        multipath_path_id,
        self.app_read_next,
        .next,
    )) |result| return result;
    return null;
}

fn tryOpenApplicationPacketWithEpoch(
    self: *Connection,
    pt_buf: *[max_recv_plaintext]u8,
    bytes: []u8,
    app_path: *const PathState,
    largest_received: u64,
    multipath_path_id: ?u32,
    maybe_epoch: ?ApplicationKeyEpoch,
    slot: ApplicationReadKeySlot,
) Error!?ApplicationOpenResult {
    _ = self;
    const epoch = maybe_epoch orelse return null;
    const opened = short_packet_mod.open1Rtt(pt_buf, bytes, .{
        .dcid_len = app_path.path.local_cid.len,
        .keys = &epoch.keys,
        .largest_received = largest_received,
        .multipath_path_id = multipath_path_id,
    }) catch |e| switch (e) {
        boringssl.crypto.aead.Error.Auth => return null,
        else => return e,
    };
    if (opened.key_phase != epoch.key_phase) return null;
    return .{ .opened = opened, .slot = slot };
}

pub fn dispatchFrames(
    self: *Connection,
    lvl: EncryptionLevel,
    payload: []const u8,
    now_us: u64,
) Error!void {
    if (debugFrames() != null) {
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
            self.close(true, transport_error_frame_encoding, "malformed frame");
            return;
        };
        const f = maybe_frame orelse break;
        if (debugFrames() != null) {
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
            self.close(true, transport_error_protocol_violation, "forbidden frame at Initial/Handshake level");
            return;
        }
        if (lvl == .early_data and !frameAllowedInEarlyData(f)) {
            self.close(true, transport_error_protocol_violation, "forbidden frame in 0-RTT");
            return;
        }
        // RFC 9000 §19.20: HANDSHAKE_DONE is a server-only frame.
        // "A server MUST treat receipt of a HANDSHAKE_DONE frame as
        // a connection error of type PROTOCOL_VIOLATION."
        if (f == .handshake_done and self.role == .server) {
            self.close(true, transport_error_protocol_violation, "HANDSHAKE_DONE received by server");
            return;
        }
        if (lvl != .application and isMultipathFrame(f)) {
            self.close(true, transport_error_protocol_violation, "multipath frame outside 1-RTT");
            return;
        }
        if (lvl == .application and isMultipathFrame(f) and !self.multipathNegotiated()) {
            self.close(true, transport_error_protocol_violation, "multipath frame without negotiation");
            return;
        }
        if (lvl == .application and isMultipathFrame(f) and
            !validateIncomingMultipathFrame(self, f))
        {
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
                self.received_handshake_done = true;
            },
            .ack => |a| {
                if (self.exceedsIncomingAckRangeCap(a.range_count)) continue;
                try self.handleAckAtLevel(lvl, a, now_us);
            },
            .path_ack => |a| {
                if (self.exceedsIncomingAckRangeCap(a.range_count)) continue;
                try self.handlePathAck(a, now_us);
            },
            .crypto => |cr| try self.handleCrypto(lvl, cr),
            .stream => |s| try self.handleStream(lvl, s),
            .reset_stream => |rs| try self.handleResetStream(rs),
            .datagram => |dg| try self.handleDatagram(lvl, dg),
            .path_challenge => |pc| {
                self.queuePathResponseOnPath(
                    self.current_incoming_path_id,
                    pc.data,
                    self.current_incoming_addr,
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
                const path = self.pathForId(self.current_incoming_path_id);
                if (conn_migration.consumeFreshPeerCidForMigration(self, path)) |fresh_cid| {
                    path.path.peer_cid = fresh_cid;
                    if (path.id == 0) {
                        self.peer_dcid = fresh_cid;
                        self.peer_dcid_set = true;
                    }
                }
            },
            .path_response => |pr| self.recordPathResponse(self.current_incoming_path_id, pr.data),
            .new_connection_id => |nc| try self.handleNewConnectionId(nc),
            .stop_sending => |ss| try self.handleStopSending(ss),
            .path_abandon => |pa| self.handlePathAbandon(pa, now_us),
            .path_status_backup => |ps| self.handlePathStatus(ps, false),
            .path_status_available => |ps| self.handlePathStatus(ps, true),
            .path_new_connection_id => |nc| try self.handlePathNewConnectionId(nc),
            .path_retire_connection_id => |rc| self.handlePathRetireConnectionId(rc),
            .max_path_id => |mp| self.handleMaxPathId(mp),
            .paths_blocked => |pb| self.handlePathsBlocked(pb),
            .path_cids_blocked => |pcb| self.handlePathCidsBlocked(pcb),
            .max_data => |md| self.handleMaxData(md),
            .max_stream_data => |msd| self.handleMaxStreamData(msd),
            .max_streams => |ms| self.handleMaxStreams(ms),
            .data_blocked => |db| self.handleDataBlocked(db),
            .stream_data_blocked => |sdb| try self.handleStreamDataBlocked(sdb),
            .streams_blocked => |sb| self.handleStreamsBlocked(sb),
            .connection_close => |cc| {
                self.enterDraining(
                    .peer,
                    closeErrorSpace(cc.is_transport),
                    cc.error_code,
                    if (cc.is_transport) cc.frame_type else 0,
                    cc.reason_phrase,
                    now_us,
                );
            },
            .retire_connection_id => |rc| self.handleRetireConnectionId(rc),
            .new_token => |nt| self.handleNewToken(nt),
            // draft-munizaga-quic-alternative-server-address-00 §6.
            // ALTERNATIVE_V4/V6_ADDRESS frames are gated by the
            // `alternative_address` transport parameter (§4) — only
            // a server may send them, and only after the client
            // advertised support. Receipt outside that envelope is
            // a peer protocol violation.
            .alternative_v4_address => |a| {
                if (self.role != .client or
                    !self.localAdvertisedAlternativeAddress())
                {
                    self.close(
                        true,
                        transport_error_protocol_violation,
                        "alternative_address frame without negotiation",
                    );
                    return;
                }
                self.handleAlternativeAddressV4(a);
            },
            .alternative_v6_address => |a| {
                if (self.role != .client or
                    !self.localAdvertisedAlternativeAddress())
                {
                    self.close(
                        true,
                        transport_error_protocol_violation,
                        "alternative_address frame without negotiation",
                    );
                    return;
                }
                self.handleAlternativeAddressV6(a);
            },
        }
    }
    if (debugFrames() != null) {
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

fn frameAllowedInEarlyData(f: frame_types.Frame) bool {
    return switch (f) {
        .ack,
        .crypto,
        .handshake_done,
        .new_token,
        .path_response,
        .retire_connection_id,
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

pub fn isKnownStatelessReset(self: *const Connection, bytes: []const u8) bool {
    const token = statelessResetTokenFromDatagram(bytes) orelse return false;
    for (self.peer_cids.items) |item| {
        if (tokenEql(item.stateless_reset_token, token)) return true;
    }
    return false;
}

pub fn pathIdAllowedByLocalLimit(self: *Connection, path_id: u32) bool {
    if (path_id <= self.local_max_path_id) return true;
    self.close(true, transport_error_protocol_violation, "multipath path id exceeds local limit");
    return false;
}

fn validateIncomingMultipathFrame(self: *Connection, f: frame_types.Frame) bool {
    return switch (f) {
        .path_ack => |pa| pathIdAllowedByLocalLimit(self, pa.path_id),
        .path_abandon => |pa| pathIdAllowedByLocalLimit(self, pa.path_id),
        .path_status_backup => |ps| pathIdAllowedByLocalLimit(self, ps.path_id),
        .path_status_available => |ps| pathIdAllowedByLocalLimit(self, ps.path_id),
        .path_new_connection_id => |nc| pathIdAllowedByLocalLimit(self, nc.path_id),
        .path_retire_connection_id => |rc| pathIdAllowedByLocalLimit(self, rc.path_id),
        .paths_blocked => |pb| pathIdAllowedByLocalLimit(self, pb.maximum_path_id),
        .path_cids_blocked => |pcb| blk: {
            if (!pathIdAllowedByLocalLimit(self, pcb.path_id)) break :blk false;
            const next = _internal.nextLocalCidSequence(self, pcb.path_id);
            if (pcb.next_sequence_number > next) {
                self.close(true, transport_error_protocol_violation, "path cids blocked skips local cid sequence");
                break :blk false;
            }
            break :blk true;
        },
        .max_path_id => |mp| blk: {
            if (self.cached_peer_transport_params) |params| {
                if (params.initial_max_path_id) |initial_max_path_id| {
                    if (mp.maximum_path_id < initial_max_path_id) {
                        self.close(true, transport_error_protocol_violation, "max path id below peer initial limit");
                        break :blk false;
                    }
                }
            }
            break :blk true;
        },
        else => true,
    };
}

extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
fn debugFrames() ?*const anyopaque {
    return getenv("QUIC_ZIG_DEBUG_FRAMES");
}
