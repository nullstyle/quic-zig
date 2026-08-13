// 1-RTT key schedule and key updates (RFC 9001 §6), AEAD usage limits,
// and Initial/Handshake key discard. Free-function siblings of
// `Connection`'s method-style key plumbing; the methods on `Connection`
// are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_qlog = @import("conn_qlog.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const EncryptionLevel = state_mod.EncryptionLevel;
const Direction = state_mod.Direction;
const Suite = state_mod.Suite;
const PacketKeys = state_mod.PacketKeys;
const SecretMaterial = state_mod.SecretMaterial;
const ApplicationKeyEpoch = state_mod.ApplicationKeyEpoch;
const ApplicationKeyUpdateLimits = state_mod.ApplicationKeyUpdateLimits;
const ApplicationKeyUpdateStatus = state_mod.ApplicationKeyUpdateStatus;
const short_packet_mod = state_mod.short_packet_mod;
const initial_keys_mod = state_mod.initial_keys_mod;
const sent_packets_mod = state_mod.sent_packets_mod;
const transport_error_aead_limit_reached = state_mod.transport_error_aead_limit_reached;

/// Are read/write secrets installed at the given encryption level?
pub fn haveSecret(self: *const Connection, lvl: EncryptionLevel, dir: Direction) bool {
    const slot = self.levels[lvl.idx()];
    return switch (dir) {
        .read => slot.read != null,
        .write => slot.write != null,
    };
}

/// True if Initial-level packet protection keys are still installed
/// for the given direction. RFC 9001 §5.7 ¶3 requires that an
/// endpoint discard its Initial keys "when it first sends a
/// Handshake packet" (write side) and after it "first successfully
/// processes a Handshake packet" (read side); after that point
/// inbound Initial packets must be dropped and outbound Initial
/// packets cannot be sealed. Embedders shouldn't normally inspect
/// this — it's exposed primarily for conformance assertions over
/// the §5.7 lifecycle.
pub fn initialKeysActive(self: *const Connection, dir: Direction) bool {
    return switch (dir) {
        .read => self.initial_keys_read != null,
        .write => self.initial_keys_write != null,
    };
}

/// Cipher suite negotiated for the given encryption level, if
/// the secret has been installed and the protocol-id is one we
/// support. RFC 9001 only permits TLS 1.3 cipher suites; quic
/// understands the three QUIC v1 suites.
pub fn cipherSuite(
    self: *const Connection,
    lvl: EncryptionLevel,
    dir: Direction,
) ?Suite {
    const slot = self.levels[lvl.idx()];
    const material_opt = switch (dir) {
        .read => slot.read,
        .write => slot.write,
    };
    const material = material_opt orelse return null;
    return Suite.fromProtocolId(material.cipher_protocol_id);
}

/// Derive AEAD/IV/HP keys for the given (level, direction). The
/// secret was captured by the TLS bridge; HKDF-Expand-Label
/// turns it into per-packet protection material.
pub fn packetKeys(
    self: *const Connection,
    lvl: EncryptionLevel,
    dir: Direction,
) Error!?PacketKeys {
    if (lvl == .application) {
        switch (dir) {
            .read => if (self.app_read_current) |epoch| return epoch.keys,
            .write => if (self.app_write_current) |epoch| return epoch.keys,
        }
    }
    const slot = self.levels[lvl.idx()];
    const material_opt = switch (dir) {
        .read => slot.read,
        .write => slot.write,
    };
    const material = material_opt orelse return null;
    const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
        return Error.UnsupportedCipherSuite;
    const secret = material.secret[0..material.secret_len];
    return try short_packet_mod.derivePacketKeys(suite, secret);
}

fn applicationKeyEpochFromMaterial(
    material: SecretMaterial,
    key_phase: bool,
    epoch: u64,
    installed_at_us: u64,
) Error!ApplicationKeyEpoch {
    const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
        return Error.UnsupportedCipherSuite;
    const keys = try short_packet_mod.derivePacketKeys(
        suite,
        material.secret[0..material.secret_len],
    );
    return .{
        .material = material,
        .keys = keys,
        .key_phase = key_phase,
        .epoch = epoch,
        .installed_at_us = installed_at_us,
    };
}

fn nextApplicationKeyEpoch(
    current: ApplicationKeyEpoch,
    installed_at_us: u64,
) Error!ApplicationKeyEpoch {
    var material = current.material;
    const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
        return Error.UnsupportedCipherSuite;
    const next_secret = try short_packet_mod.deriveNextTrafficSecret(
        suite,
        material.secret[0..material.secret_len],
    );

    const secret_len: usize = suite.secretLen();
    @memcpy(material.secret[0..secret_len], next_secret[0..secret_len]);
    @memset(material.secret[secret_len..], 0);
    material.secret_len = @intCast(secret_len);

    var next_keys = try short_packet_mod.derivePacketKeys(
        suite,
        material.secret[0..material.secret_len],
    );
    // RFC 9001 §6: HP keys don't rotate on a key update; only the
    // AEAD key/IV change. `setHp` keeps the cached HP cipher in
    // sync with the bytes — a bare `next_keys.hp = …` would leave
    // the cache pointing at the just-derived (but unused) HP key.
    try next_keys.setHp(current.keys.hp[0..suite.hpLen()]);
    return .{
        .material = material,
        .keys = next_keys,
        .key_phase = !current.key_phase,
        .epoch = current.epoch +| 1,
        .installed_at_us = installed_at_us,
    };
}

pub fn installApplicationSecret(
    self: *Connection,
    dir: Direction,
    material: SecretMaterial,
) Error!void {
    const app_idx = EncryptionLevel.application.idx();
    const epoch = try applicationKeyEpochFromMaterial(material, false, 0, 0);
    switch (dir) {
        .read => {
            self.levels[app_idx].read = material;
            self.app_read_previous = null;
            self.app_read_current = epoch;
            self.app_read_next = try nextApplicationKeyEpoch(epoch, 0);
            self.app_failed_auth_packets = 0;
            conn_qlog.emitQlog(self, .{
                .name = .application_read_key_installed,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
            conn_qlog.emitQlog(self, .{
                .name = .key_updated,
                .level = .application,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
        },
        .write => {
            self.levels[app_idx].write = material;
            self.app_write_current = epoch;
            self.app_write_update_pending_ack = false;
            self.app_next_local_update_after_us = null;
            conn_qlog.emitQlog(self, .{
                .name = .application_write_key_installed,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
            conn_qlog.emitQlog(self, .{
                .name = .key_updated,
                .level = .application,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
        },
    }
}

pub fn refreshNextApplicationReadKey(self: *Connection) Error!void {
    const current = self.app_read_current orelse {
        self.app_read_next = null;
        return;
    };
    self.app_read_next = try nextApplicationKeyEpoch(current, current.installed_at_us);
}

pub fn promoteApplicationReadKeys(self: *Connection, now_us: u64) Error!void {
    const current = self.app_read_current orelse return Error.KeyUpdateUnavailable;
    var previous = current;
    previous.discard_deadline_us = now_us +| self.retiredPathRetentionUs();
    self.app_read_previous = previous;
    self.app_read_current = self.app_read_next orelse
        try nextApplicationKeyEpoch(current, now_us);
    self.app_read_current.?.installed_at_us = now_us;
    self.app_read_current.?.discard_deadline_us = null;
    try refreshNextApplicationReadKey(
        self,
    );
    conn_qlog.emitQlog(self, .{
        .name = .application_read_key_discard_scheduled,
        .at_us = now_us,
        .key_epoch = previous.epoch,
        .key_phase = previous.key_phase,
        .discard_deadline_us = previous.discard_deadline_us,
    });
    conn_qlog.emitQlog(self, .{
        .name = .application_read_key_updated,
        .at_us = now_us,
        .key_epoch = self.app_read_current.?.epoch,
        .key_phase = self.app_read_current.?.key_phase,
    });
    conn_qlog.emitQlog(self, .{
        .name = .key_updated,
        .at_us = now_us,
        .level = .application,
        .key_epoch = self.app_read_current.?.epoch,
        .key_phase = self.app_read_current.?.key_phase,
    });
}

fn installNextApplicationWriteKeys(
    self: *Connection,
    now_us: u64,
    pending_ack: bool,
) Error!void {
    const current = self.app_write_current orelse return Error.KeyUpdateUnavailable;
    self.app_write_current = try nextApplicationKeyEpoch(current, now_us);
    self.app_write_current.?.installed_at_us = now_us;
    self.app_write_current.?.acked = false;
    self.app_write_update_pending_ack = pending_ack;
    conn_qlog.emitQlog(self, .{
        .name = .application_write_key_updated,
        .at_us = now_us,
        .key_epoch = self.app_write_current.?.epoch,
        .key_phase = self.app_write_current.?.key_phase,
    });
    conn_qlog.emitQlog(self, .{
        .name = .key_updated,
        .at_us = now_us,
        .level = .application,
        .key_epoch = self.app_write_current.?.epoch,
        .key_phase = self.app_write_current.?.key_phase,
    });
}

pub fn maybeRespondToPeerKeyUpdate(self: *Connection, now_us: u64) Error!void {
    const read = self.app_read_current orelse return;
    const write = self.app_write_current orelse return;
    if (write.key_phase == read.key_phase) return;
    try installNextApplicationWriteKeys(self, now_us, true);
}

/// True if the embedder may call `requestKeyUpdate` right now
/// (RFC 9001 §6). Returns false while a previous update is still
/// awaiting an ACK or while the cooldown deadline is in the future.
pub fn canInitiateKeyUpdateAt(self: *const Connection, now_us: u64) bool {
    if (self.app_write_current == null) return false;
    if (self.app_write_update_pending_ack) return false;
    if (self.app_next_local_update_after_us) |deadline| {
        if (now_us < deadline) return false;
    }
    return true;
}

/// Initiate an application key update (RFC 9001 §6). Returns
/// `error.KeyUpdateBlocked` if `canInitiateKeyUpdateAt` would
/// have returned false.
pub fn requestKeyUpdate(self: *Connection, now_us: u64) Error!void {
    if (!canInitiateKeyUpdateAt(self, now_us)) return Error.KeyUpdateBlocked;
    try installNextApplicationWriteKeys(self, now_us, true);
}

/// Snapshot of the current application key-update lifecycle —
/// read/write epoch, key phase, packets protected with the
/// current write key, and whether a discard deadline is set.
pub fn keyUpdateStatus(self: *const Connection) ApplicationKeyUpdateStatus {
    var status: ApplicationKeyUpdateStatus = .{
        .write_update_pending_ack = self.app_write_update_pending_ack,
        .next_local_update_after_us = self.app_next_local_update_after_us,
        .auth_failures = self.app_failed_auth_packets,
        .next_read_epoch_ready = self.app_read_next != null,
    };
    if (self.app_read_current) |epoch| {
        status.read_epoch = epoch.epoch;
        status.read_key_phase = epoch.key_phase;
    }
    if (self.app_read_previous) |epoch| {
        status.previous_read_discard_deadline_us = epoch.discard_deadline_us;
    }
    if (self.app_write_current) |epoch| {
        status.write_epoch = epoch.epoch;
        status.write_key_phase = epoch.key_phase;
        status.write_packets_protected = epoch.packets_protected;
    }
    return status;
}

/// Override the AEAD confidentiality / integrity / proactive-update
/// thresholds. Test-only — production embedders should accept the
/// RFC 9001 §6.6 defaults.
pub fn setApplicationKeyUpdateLimitsForTesting(
    self: *Connection,
    limits: ApplicationKeyUpdateLimits,
) void {
    self.app_key_update_limits = limits;
}

/// Test-only: allocate the next outgoing PN in the application
/// (1-RTT) packet number space and bump `next_pn` so the
/// connection's own send path will pick a strictly larger PN on
/// its next outbound packet. Conformance fixtures use this to seal
/// a synthetic 1-RTT packet with a PN consistent with the
/// connection's bookkeeping — without this, an injected frame
/// elicits an ACK whose `largest_acked` would exceed the live
/// `next_pn`, which the connection (correctly) treats as an ACK
/// of an unsent packet (RFC 9000 §13.1) and closes with
/// PROTOCOL_VIOLATION. Only conformance fixtures should reach for
/// this; production code drives PN allocation through the normal
/// `pollLevel` path.
pub fn allocApplicationPacketNumberForTesting(self: *Connection) ?u64 {
    return self.primaryPath().app_pn_space.nextPn();
}

pub fn applicationWriteKeyPhase(self: *const Connection) bool {
    const current = self.app_write_current orelse return false;
    return current.key_phase;
}

pub fn prepareApplicationWriteKeys(self: *Connection, now_us: u64) Error!void {
    const current = self.app_write_current orelse return;
    if (current.packets_protected >= self.app_key_update_limits.proactive_update_threshold and
        canInitiateKeyUpdateAt(self, now_us))
    {
        try requestKeyUpdate(self, now_us);
        return;
    }
    if (current.packets_protected >= self.app_key_update_limits.confidentiality_limit) {
        conn_qlog.emitQlog(self, .{
            .name = .aead_confidentiality_limit_reached,
            .at_us = now_us,
            .key_epoch = current.epoch,
            .key_phase = current.key_phase,
        });
        self.close(true, transport_error_aead_limit_reached, "AEAD confidentiality limit reached");
    }
}

pub fn recordApplicationPacketProtected(
    self: *Connection,
    sent_packet: *sent_packets_mod.SentPacket,
) void {
    if (self.app_write_current) |*epoch| {
        epoch.packets_protected +|= 1;
        sent_packet.key_epoch = epoch.epoch;
        sent_packet.key_phase = epoch.key_phase;
    }
}

pub fn onApplicationPacketAckedForKeys(
    self: *Connection,
    packet: *const sent_packets_mod.SentPacket,
    now_us: u64,
) void {
    const epoch_id = packet.key_epoch orelse return;
    if (self.app_write_current) |*epoch| {
        if (epoch.epoch == epoch_id) {
            epoch.acked = true;
            if (self.app_write_update_pending_ack) {
                self.app_write_update_pending_ack = false;
                self.app_next_local_update_after_us = now_us +| self.retiredPathRetentionUs();
                conn_qlog.emitQlog(self, .{
                    .name = .application_write_update_acked,
                    .at_us = now_us,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                    .packet_number = packet.pn,
                    .discard_deadline_us = self.app_next_local_update_after_us,
                });
            }
        }
    }
}

pub fn noteApplicationAuthFailure(self: *Connection) void {
    self.app_failed_auth_packets +|= 1;
    if (self.app_failed_auth_packets >= self.app_key_update_limits.integrity_limit) {
        conn_qlog.emitQlog(self, .{
            .name = .aead_integrity_limit_reached,
            .key_epoch = if (self.app_read_current) |epoch| epoch.epoch else null,
            .key_phase = if (self.app_read_current) |epoch| epoch.key_phase else null,
        });
        self.close(true, transport_error_aead_limit_reached, "AEAD integrity limit reached");
    }
}

pub fn discardExpiredApplicationReadKeys(self: *Connection, now_us: u64) void {
    if (self.app_read_previous) |epoch| {
        if (epoch.discard_deadline_us) |deadline| {
            if (now_us >= deadline) {
                conn_qlog.emitQlog(self, .{
                    .name = .application_read_key_discarded,
                    .at_us = now_us,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                    .discard_deadline_us = deadline,
                });
                self.app_read_previous = null;
            }
        }
    }
}

/// RFC 9001 §5.7 ¶3: "Endpoints MUST discard their Initial keys
/// when they first send a Handshake packet." quic makes the call
/// stricter: once Handshake-level secrets are installed (which
/// means the TLS handshake has progressed past Initial) we drop
/// Initial keys outright. Any further inbound Initial packet is
/// rejected by `packetKeys` returning null, and the receiver
/// drops it as `keys_unavailable`.
///
/// Idempotent: safe to call multiple times. Securely zeroes the
/// discarded key material so it can't be recovered from a memory
/// dump after the discard point.
pub fn discardInitialKeys(self: *Connection) void {
    if (self.initial_keys_read) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
    if (self.initial_keys_write) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
    self.initial_keys_read = null;
    self.initial_keys_write = null;
    self.initial_keys_discarded = true;
}

/// RFC 9001 §4.9.2: "An endpoint MUST discard its handshake keys
/// when the TLS handshake is confirmed." Mirrors `discardInitialKeys`
/// but operates on the Handshake-level slot in `levels` and the
/// connection-level Handshake sent tracker (`sent[1]`).
///
/// The trigger differs per role: clients latch on HANDSHAKE_DONE
/// (RFC 9001 §4.1.2 ¶2), servers latch on `handshakeDone()`
/// returning true (which equals "received client Finished" — the
/// server's confirmation event). Both paths land here.
///
/// Effect:
///   - Securely zeros the read+write traffic-secret material in
///     `levels[handshake.idx()]` and clears both slots, so
///     `packetKeys(.handshake, …)` returns null. Any subsequent
///     inbound Handshake-level packet is dropped at the receiver
///     as `keys_unavailable`; no further Handshake-level packet
///     can be sealed by the send path either.
///   - Clears the connection-level Handshake sent tracker. RFC
///     9002 §6.4 ¶1: "If a packet number space is discarded, then
///     all in-flight packets in that space MUST be removed from
///     bytes_in_flight." Without this, `firePtoAtLevel(.handshake)`
///     would keep retransmitting phantom Finished CRYPTO frames
///     forever — exactly the failure mode that quiche's strict
///     `dropped invalid packet` response made fatal in the
///     `rebind-addr` interop testcase (the post-rebind 1-RTT
///     stall left no fresh ACK source, so the only thing the
///     client kept emitting was useless Handshake-PTO probes).
///   - Resets the Handshake-level `pto_count` and `pending_ping`
///     so a stale latch can't immediately re-fire.
///
/// Idempotent: the `handshake_keys_discarded` latch makes a
/// second call a no-op.
/// INTERNAL: pub for `_state_tests.zig` to drive the discard
/// directly without the surrounding `handleWithEcn` /
/// `drainInboxIntoTls` machinery. Embedders never need this —
/// the gate is purely an internal RFC 9001 §4.9.2 invariant.
pub fn discardHandshakeKeys(self: *Connection) void {
    if (self.handshake_keys_discarded) return;
    const hsk_lvl_idx = EncryptionLevel.handshake.idx();
    if (self.levels[hsk_lvl_idx].read) |*material| {
        std.crypto.secureZero(u8, &material.secret);
    }
    if (self.levels[hsk_lvl_idx].write) |*material| {
        std.crypto.secureZero(u8, &material.secret);
    }
    self.levels[hsk_lvl_idx].read = null;
    self.levels[hsk_lvl_idx].write = null;
    // Initial uses idx 0 in connPnIdx mapping; Handshake is idx 1.
    // See `connPnIdx` for the rationale (the array indices ride
    // the connection-level PN-space layout, not `EncryptionLevel.idx`).
    self.clearSentTracker(&self.sent[1]);
    self.pto_count[1] = 0;
    self.pending_ping[1] = false;
    self.handshake_keys_discarded = true;
}

pub fn ensureInitialKeys(self: *Connection) Error!void {
    // RFC 9001 §5.7 ¶3 — once the discard latch is set, never
    // re-derive. Any Initial-level packet from now on cannot be
    // sealed (poll path) or opened (handle path); the receiver
    // drops as `keys_unavailable`.
    if (self.initial_keys_discarded) return;
    if (self.initial_keys_read != null and self.initial_keys_write != null) return;
    if (!self.initial_dcid_set) return;
    const dcid_slice = self.initial_dcid.slice();
    // RFC 9001 §5.2 / RFC 9368 §3.3.1: client-direction secret
    // comes from "client in", server-direction from "server in";
    // the active version selects salt + HKDF labels.
    const client_keys_initial = try initial_keys_mod.deriveInitialKeysFor(self.version, dcid_slice, false);
    const server_keys_initial = try initial_keys_mod.deriveInitialKeysFor(self.version, dcid_slice, true);
    const client_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &client_keys_initial.secret);
    const server_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &server_keys_initial.secret);
    switch (self.role) {
        .client => {
            self.initial_keys_write = client_pkt;
            self.initial_keys_read = server_pkt;
        },
        .server => {
            self.initial_keys_write = server_pkt;
            self.initial_keys_read = client_pkt;
        },
    }
}
