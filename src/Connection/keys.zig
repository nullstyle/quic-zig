//! 1-RTT key schedule and key updates (RFC 9001 §6), AEAD usage limits,
//! and Initial/Handshake key discard. Free-function siblings of
//! `Connection`'s method-style key plumbing; the methods on `Connection`
//! are thin thunks that delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const conn_qlog = @import("qlog.zig");
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
const SentPacketTracker = state_mod.SentPacketTracker;
const transport_error_aead_limit_reached = state_mod.transport_error_aead_limit_reached;

/// Are read/write secrets installed at the given encryption level?
pub fn haveSecret(conn: *const Connection, lvl: EncryptionLevel, dir: Direction) bool {
    const slot = conn.levels[lvl.idx()];
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
pub fn initialKeysActive(conn: *const Connection, dir: Direction) bool {
    return switch (dir) {
        .read => conn.initial_keys_read != null,
        .write => conn.initial_keys_write != null,
    };
}

/// Cipher suite negotiated for the given encryption level, if
/// the secret has been installed and the protocol-id is one we
/// support. RFC 9001 only permits TLS 1.3 cipher suites; quic
/// understands the three QUIC v1 suites.
pub fn cipherSuite(
    conn: *const Connection,
    lvl: EncryptionLevel,
    dir: Direction,
) ?Suite {
    const slot = conn.levels[lvl.idx()];
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
///
/// Handshake and 0-RTT keys are derived once per secret and cached
/// in the level slot; every call returns a *borrowed copy* of the
/// cached set (the `aead` field aliases the stored heap context), so
/// callers must not `deinitAead` the result. The cache is freed when
/// the secret is replaced or discarded. Deriving per call instead
/// leaked one `EVP_AEAD_CTX` per packet on the Handshake/0-RTT seal
/// and open paths; application epochs and Initial keys were already
/// cached for the same reason.
pub fn packetKeys(
    conn: *Connection,
    lvl: EncryptionLevel,
    dir: Direction,
) Error!?*const PacketKeys {
    // A pointer into the connection, never a copy: the keys carry the
    // AES key schedules and the AEAD context, and copying them per
    // packet was 2% of the engine's CPU (the sprint "CPU per packet",
    // 2026-10-08). The pointer is good until the next key event
    // (a level's keys discarded, an epoch replaced), which never
    // happens inside one packet's seal or open.
    if (lvl == .application) {
        switch (dir) {
            .read => if (conn.app_read_current) |*epoch| return &epoch.keys,
            .write => if (conn.app_write_current) |*epoch| return &epoch.keys,
        }
    }
    const slot = &conn.levels[lvl.idx()];
    const cached = switch (dir) {
        .read => &slot.read_keys,
        .write => &slot.write_keys,
    };
    if (cached.*) |*keys| return keys;
    const material_opt = switch (dir) {
        .read => slot.read,
        .write => slot.write,
    };
    const material = material_opt orelse return null;
    const suite = Suite.fromProtocolId(material.cipher_protocol_id) orelse
        return Error.UnsupportedCipherSuite;
    const secret = material.secret[0..material.secret_len];
    cached.* = try short_packet_mod.derivePacketKeys(suite, secret);
    return &cached.*.?;
}

/// Free a level slot's cached packet keys — the heap `EVP_AEAD_CTX`
/// plus the sensitive key bytes — before its secret is replaced or
/// the slot is torn down. Call at every site that overwrites or
/// drops a non-application `PerLevelState` secret; a silent drop is
/// exactly the leak `packetKeys`'s cache exists to prevent.
pub fn freeLevelKeys(slot: *?PacketKeys) void {
    if (slot.*) |*keys| {
        keys.deinitAead();
        std.crypto.secureZero(u8, &keys.key);
        std.crypto.secureZero(u8, &keys.iv);
        std.crypto.secureZero(u8, &keys.hp);
        std.crypto.secureZero(u8, std.mem.asBytes(&keys.hp_cipher));
        slot.* = null;
    }
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
    errdefer next_keys.deinitAead();
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
    conn: *Connection,
    dir: Direction,
    material: SecretMaterial,
) Error!void {
    const app_idx = EncryptionLevel.application.idx();
    const epoch = try applicationKeyEpochFromMaterial(material, false, 0, 0);
    switch (dir) {
        .read => {
            conn.levels[app_idx].read = material;
            if (conn.app_read_previous) |*prev| prev.keys.deinitAead();
            conn.app_read_previous = null;
            if (conn.app_read_current) |*cur| cur.keys.deinitAead();
            conn.app_read_current = epoch;
            conn.app_read_next = try nextApplicationKeyEpoch(epoch, 0);
            conn.app_failed_auth_packets = 0;
            conn_qlog.emitQlog(conn, .{
                .name = .application_read_key_installed,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
            conn_qlog.emitQlog(conn, .{
                .name = .key_updated,
                .level = .application,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
        },
        .write => {
            conn.levels[app_idx].write = material;
            if (conn.app_write_current) |*cur| cur.keys.deinitAead();
            conn.app_write_current = epoch;
            conn.app_write_update_pending_ack = false;
            conn.app_next_local_update_after_us = null;
            conn_qlog.emitQlog(conn, .{
                .name = .application_write_key_installed,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
            conn_qlog.emitQlog(conn, .{
                .name = .key_updated,
                .level = .application,
                .key_epoch = epoch.epoch,
                .key_phase = epoch.key_phase,
            });
        },
    }
}

pub fn refreshNextApplicationReadKey(conn: *Connection) Error!void {
    const current = conn.app_read_current orelse {
        conn.app_read_next = null;
        return;
    };
    conn.app_read_next = try nextApplicationKeyEpoch(current, current.installed_at_us);
}

pub fn promoteApplicationReadKeys(conn: *Connection, now_us: u64) Error!void {
    const current = conn.app_read_current orelse return Error.KeyUpdateUnavailable;
    var previous = current;
    previous.discard_deadline_us = now_us +| conn.retiredPathRetentionUs();
    // `previous` (the retired current epoch) moves into the
    // app_read_previous slot; any epoch already sitting there is
    // done and its cached AEAD context must be freed.
    if (conn.app_read_previous) |*old_prev| old_prev.keys.deinitAead();
    conn.app_read_previous = previous;
    conn.app_read_current = conn.app_read_next orelse
        try nextApplicationKeyEpoch(current, now_us);
    conn.app_read_current.?.installed_at_us = now_us;
    conn.app_read_current.?.discard_deadline_us = null;
    try refreshNextApplicationReadKey(
        conn,
    );
    conn_qlog.emitQlog(conn, .{
        .name = .application_read_key_discard_scheduled,
        .at_us = now_us,
        .key_epoch = previous.epoch,
        .key_phase = previous.key_phase,
        .discard_deadline_us = previous.discard_deadline_us,
    });
    conn_qlog.emitQlog(conn, .{
        .name = .application_read_key_updated,
        .at_us = now_us,
        .key_epoch = conn.app_read_current.?.epoch,
        .key_phase = conn.app_read_current.?.key_phase,
    });
    conn_qlog.emitQlog(conn, .{
        .name = .key_updated,
        .at_us = now_us,
        .level = .application,
        .key_epoch = conn.app_read_current.?.epoch,
        .key_phase = conn.app_read_current.?.key_phase,
    });
}

fn installNextApplicationWriteKeys(
    conn: *Connection,
    now_us: u64,
    pending_ack: bool,
) Error!void {
    var current = conn.app_write_current orelse return Error.KeyUpdateUnavailable;
    current.keys.deinitAead();
    conn.app_write_current = try nextApplicationKeyEpoch(current, now_us);
    conn.app_write_current.?.installed_at_us = now_us;
    conn.app_write_current.?.acked = false;
    conn.app_write_update_pending_ack = pending_ack;
    conn_qlog.emitQlog(conn, .{
        .name = .application_write_key_updated,
        .at_us = now_us,
        .key_epoch = conn.app_write_current.?.epoch,
        .key_phase = conn.app_write_current.?.key_phase,
    });
    conn_qlog.emitQlog(conn, .{
        .name = .key_updated,
        .at_us = now_us,
        .level = .application,
        .key_epoch = conn.app_write_current.?.epoch,
        .key_phase = conn.app_write_current.?.key_phase,
    });
}

pub fn maybeRespondToPeerKeyUpdate(conn: *Connection, now_us: u64) Error!void {
    const read = conn.app_read_current orelse return;
    const write = conn.app_write_current orelse return;
    if (write.key_phase == read.key_phase) return;
    try installNextApplicationWriteKeys(conn, now_us, true);
}

/// True if the embedder may call `requestKeyUpdate` right now
/// (RFC 9001 §6). Returns false before the handshake is confirmed,
/// while a previous update is still awaiting an ACK, or while the
/// cooldown deadline is in the future.
pub fn canInitiateKeyUpdateAt(conn: *const Connection, now_us: u64) bool {
    if (conn.app_write_current == null) return false;
    // RFC 9001 §6.1 ¶2: "An endpoint MUST NOT initiate a key update
    // prior to having confirmed the handshake". 1-RTT write keys are
    // there earlier: a client has them when its handshake is COMPLETE
    // (it has the server's Finished), one flight before it is
    // CONFIRMED (HANDSHAKE_DONE, §4.1.2). `handshake_keys_discarded`
    // is the confirmation latch of both roles.
    //
    // Until v0.26.0 only the keys were asked for. MEASURED 2026-10-04
    // with the interop client, which asks "as soon as the handshake
    // completes": its very first 1-RTT packet was in key phase 1 (all
    // 2517 of a run), and the runner's `keyupdate` check against a
    // quic-go server failed 4 runs of 4.
    if (!conn.handshake_keys_discarded) return false;
    if (conn.app_write_update_pending_ack) return false;
    if (conn.app_next_local_update_after_us) |deadline| {
        if (now_us < deadline) return false;
    }
    return true;
}

/// Initiate an application key update (RFC 9001 §6). Returns
/// `error.KeyUpdateBlocked` if `canInitiateKeyUpdateAt` would
/// have returned false.
pub fn requestKeyUpdate(conn: *Connection, now_us: u64) Error!void {
    if (!canInitiateKeyUpdateAt(conn, now_us)) return Error.KeyUpdateBlocked;
    try installNextApplicationWriteKeys(conn, now_us, true);
}

/// Snapshot of the current application key-update lifecycle —
/// read/write epoch, key phase, packets protected with the
/// current write key, and whether a discard deadline is set.
pub fn keyUpdateStatus(conn: *const Connection) ApplicationKeyUpdateStatus {
    var status: ApplicationKeyUpdateStatus = .{
        .write_update_pending_ack = conn.app_write_update_pending_ack,
        .next_local_update_after_us = conn.app_next_local_update_after_us,
        .auth_failures = conn.app_failed_auth_packets,
        .next_read_epoch_ready = conn.app_read_next != null,
    };
    if (conn.app_read_current) |epoch| {
        status.read_epoch = epoch.epoch;
        status.read_key_phase = epoch.key_phase;
    }
    if (conn.app_read_previous) |epoch| {
        status.previous_read_discard_deadline_us = epoch.discard_deadline_us;
    }
    if (conn.app_write_current) |epoch| {
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
    conn: *Connection,
    limits: ApplicationKeyUpdateLimits,
) void {
    conn.app_key_update_limits = limits;
    conn.key_update_limits_override_active = true;
}

/// Effective AEAD usage limits. When no test override is active, the
/// negotiated suite's RFC 9001 §6.6 values apply (once application
/// keys exist); before that, the cross-suite conservative floor in
/// the struct defaults covers the handshake phase.
fn effectiveKeyUpdateLimits(conn: *const Connection) ApplicationKeyUpdateLimits {
    if (conn.key_update_limits_override_active) return conn.app_key_update_limits;
    const suite = if (conn.app_write_current) |epoch| epoch.keys.suite else return conn.app_key_update_limits;
    const l = suite.aeadLimits();
    return .{
        .confidentiality_limit = l.confidentiality_limit,
        .proactive_update_threshold = l.confidentiality_limit -| 1024,
        .integrity_limit = l.integrity_limit,
    };
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
pub fn allocApplicationPacketNumberForTesting(conn: *Connection) ?u64 {
    return conn.primaryPath().app_pn_space.nextPn();
}

pub fn applicationWriteKeyPhase(conn: *const Connection) bool {
    const current = conn.app_write_current orelse return false;
    return current.key_phase;
}

pub fn prepareApplicationWriteKeys(conn: *Connection, now_us: u64) Error!void {
    const current = conn.app_write_current orelse return;
    const limits = effectiveKeyUpdateLimits(conn);
    if (current.packets_protected >= limits.proactive_update_threshold and
        canInitiateKeyUpdateAt(conn, now_us))
    {
        try requestKeyUpdate(conn, now_us);
        return;
    }
    if (current.packets_protected >= limits.confidentiality_limit) {
        conn_qlog.emitQlog(conn, .{
            .name = .aead_confidentiality_limit_reached,
            .at_us = now_us,
            .key_epoch = current.epoch,
            .key_phase = current.key_phase,
        });
        conn.close(true, transport_error_aead_limit_reached, "AEAD confidentiality limit reached");
    }
}

pub fn recordApplicationPacketProtected(
    conn: *Connection,
    sent_packet: *SentPacketTracker.SentPacket,
) void {
    if (conn.app_write_current) |*epoch| {
        epoch.packets_protected +|= 1;
        sent_packet.key_epoch = epoch.epoch;
        sent_packet.key_phase = epoch.key_phase;
    }
}

pub fn onApplicationPacketAckedForKeys(
    conn: *Connection,
    packet: *const SentPacketTracker.SentPacket,
    now_us: u64,
) void {
    const epoch_id = packet.key_epoch orelse return;
    if (conn.app_write_current) |*epoch| {
        if (epoch.epoch == epoch_id) {
            epoch.acked = true;
            if (conn.app_write_update_pending_ack) {
                conn.app_write_update_pending_ack = false;
                conn.app_next_local_update_after_us = now_us +| conn.retiredPathRetentionUs();
                conn_qlog.emitQlog(conn, .{
                    .name = .application_write_update_acked,
                    .at_us = now_us,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                    .packet_number = packet.pn,
                    .discard_deadline_us = conn.app_next_local_update_after_us,
                });
            }
        }
    }
}

pub fn noteApplicationAuthFailure(conn: *Connection) void {
    conn.app_failed_auth_packets +|= 1;
    if (conn.app_failed_auth_packets >= effectiveKeyUpdateLimits(conn).integrity_limit) {
        conn_qlog.emitQlog(conn, .{
            .name = .aead_integrity_limit_reached,
            .key_epoch = if (conn.app_read_current) |epoch| epoch.epoch else null,
            .key_phase = if (conn.app_read_current) |epoch| epoch.key_phase else null,
        });
        conn.close(true, transport_error_aead_limit_reached, "AEAD integrity limit reached");
    }
}

pub fn discardExpiredApplicationReadKeys(conn: *Connection, now_us: u64) void {
    if (conn.app_read_previous) |epoch| {
        if (epoch.discard_deadline_us) |deadline| {
            if (now_us >= deadline) {
                conn_qlog.emitQlog(conn, .{
                    .name = .application_read_key_discarded,
                    .at_us = now_us,
                    .key_epoch = epoch.epoch,
                    .key_phase = epoch.key_phase,
                    .discard_deadline_us = deadline,
                });
                conn.app_read_previous.?.keys.deinitAead();
                conn.app_read_previous = null;
            }
        }
    }
}

/// RFC 9001 §4.9.1: "a client MUST discard Initial keys when it
/// first sends a Handshake packet and a server MUST discard Initial
/// keys when it first successfully processes a Handshake packet.
/// Endpoints MUST NOT send Initial packets after this point." The
/// callers are those two places and, as a backstop, the completed
/// handshake. Any further inbound Initial packet is dropped as
/// `keys_unavailable` (that packet only: the packets behind it in the
/// datagram are still processed), and the Initial space's recovery
/// state goes with the keys.
///
/// Idempotent: safe to call multiple times. Securely zeroes the
/// discarded key material so it can't be recovered from a memory
/// dump after the discard point.
pub fn discardInitialKeys(conn: *Connection) void {
    wipeInitialKeys(conn);
    conn.initial_keys_discarded = true;
    dropSpaceRecoveryState(conn, .initial, 0);
}

/// Free and zero the Initial packet keys, and nothing else. The key
/// half of `discardInitialKeys`, on its own for `Connection.deinit`:
/// teardown wipes the keys after the trackers and the CRYPTO queues
/// are already freed, so it must not run the recovery half.
pub fn wipeInitialKeys(conn: *Connection) void {
    if (conn.initial_keys_read) |*k| {
        k.deinitAead();
        std.crypto.secureZero(u8, std.mem.asBytes(k));
    }
    if (conn.initial_keys_write) |*k| {
        k.deinitAead();
        std.crypto.secureZero(u8, std.mem.asBytes(k));
    }
    conn.initial_keys_read = null;
    conn.initial_keys_write = null;
}

/// Drop what the loss recovery of a handshake space still holds when
/// its keys go: the sent packets, the CRYPTO data that waits for an
/// ACK, the CRYPTO data that waits for retransmission, and the probe
/// state. RFC 9002 §6.4: packets of a discarded space leave the bytes
/// in flight, and its timers stop.
///
/// The retransmission queue matters most. Data in it can never be
/// sent without the keys, and `canSend` counts that queue, so a chunk
/// left there made `canSend` say "yes" for the rest of the connection
/// while `poll` had nothing. A chunk gets there when a probe timeout
/// or the peer's retry (`loss.retransmitHandshakeCryptoEarly`) queues
/// the flight just before the handshake moves on.
///
/// `pn_idx` is the index of the space in the connection-level arrays
/// (`sent`, `pto_count`, `pending_ping`): 0 for Initial, 1 for
/// Handshake.
fn dropSpaceRecoveryState(conn: *Connection, lvl: EncryptionLevel, pn_idx: usize) void {
    conn.clearSentTracker(&conn.sent[pn_idx]);
    // The space is done for good: its tracker's storage goes back
    // (256 slots of 200 bytes for each of the two spaces).
    conn.sent[pn_idx].shrinkToMinimum(conn.allocator);
    conn.pto_count[pn_idx] = 0;
    conn.pending_ping[pn_idx] = false;
    const idx = lvl.idx();
    for (conn.crypto_retx[idx].items) |chunk| conn.allocator.free(chunk.data);
    conn.crypto_retx[idx].clearAndFree(conn.allocator);
    for (conn.sent_crypto[idx].items) |chunk| conn.allocator.free(chunk.data);
    conn.sent_crypto[idx].clearAndFree(conn.allocator);
    // The CRYPTO buffers of a level whose keys are gone hold nothing
    // that anyone reads again.
    conn.inbox[idx].release(conn.allocator);
    conn.outbox[idx].release(conn.allocator);
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
/// INTERNAL: pub for `_tests.zig` to drive the discard
/// directly without the surrounding `handleWithEcn` /
/// `drainInboxIntoTls` machinery. Embedders never need this —
/// the gate is purely an internal RFC 9001 §4.9.2 invariant.
pub fn discardHandshakeKeys(conn: *Connection) void {
    if (conn.handshake_keys_discarded) return;
    const hsk_lvl_idx = EncryptionLevel.handshake.idx();
    if (conn.levels[hsk_lvl_idx].read) |*material| {
        std.crypto.secureZero(u8, &material.secret);
    }
    if (conn.levels[hsk_lvl_idx].write) |*material| {
        std.crypto.secureZero(u8, &material.secret);
    }
    // The cached PacketKeys derived from those secrets hold live heap
    // AEAD contexts; freeing them is as much a part of the discard as
    // zeroing the secrets.
    freeLevelKeys(&conn.levels[hsk_lvl_idx].read_keys);
    freeLevelKeys(&conn.levels[hsk_lvl_idx].write_keys);
    conn.levels[hsk_lvl_idx].read = null;
    conn.levels[hsk_lvl_idx].write = null;
    // A Handshake packet kept for keys that are gone now has no use.
    conn.freeHeldHandshakePackets();
    // Initial uses idx 0 in connPnIdx mapping; Handshake is idx 1.
    // See `connPnIdx` for the rationale (the array indices ride
    // the connection-level PN-space layout, not `EncryptionLevel.idx`).
    dropSpaceRecoveryState(conn, .handshake, 1);
    conn.handshake_keys_discarded = true;
}

pub fn ensureInitialKeys(conn: *Connection) Error!void {
    // RFC 9001 §5.7 ¶3 — once the discard latch is set, never
    // re-derive. Any Initial-level packet from now on cannot be
    // sealed (poll path) or opened (handle path); the receiver
    // drops as `keys_unavailable`.
    if (conn.initial_keys_discarded) return;
    if (conn.initial_keys_read != null and conn.initial_keys_write != null) return;
    if (!conn.initial_dcid_set) return;
    const dcid_slice = conn.initial_dcid.slice();
    // RFC 9001 §5.2 / RFC 9368 §3.3.1: client-direction secret
    // comes from "client in", server-direction from "server in";
    // the active version selects salt + HKDF labels.
    const client_keys_initial = try initial_keys_mod.deriveInitialKeysFor(conn.version, dcid_slice, false);
    const server_keys_initial = try initial_keys_mod.deriveInitialKeysFor(conn.version, dcid_slice, true);
    const client_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &client_keys_initial.secret);
    const server_pkt = try short_packet_mod.derivePacketKeys(.aes128_gcm_sha256, &server_keys_initial.secret);
    switch (conn.role) {
        .client => {
            conn.initial_keys_write = client_pkt;
            conn.initial_keys_read = server_pkt;
        },
        .server => {
            conn.initial_keys_write = server_pkt;
            conn.initial_keys_read = client_pkt;
        },
    }
}
