//! Server version negotiation and compatible version upgrade
//! (RFC 9368/9369): accepted-version checks, ClientHello preparse for
//! the upgrade target, the pending-upgrade state machine, and VN packet
//! queueing. Split from Server.zig; the private methods on Server
//! delegate here via private thunks where hub callers remain.

const std = @import("std");
const Server = @import("../Server.zig");
const Slot = Server.Slot;
const Error = Server.Error;
const conn_mod = @import("../conn/root.zig");
const wire = @import("../wire/root.zig");
const Address = conn_mod.path.Address;
const ConnectionId = conn_mod.path.ConnectionId;
const wire_peek = @import("wire_peek.zig");
const isInitialLongHeader = wire_peek.isInitialLongHeader;
const StatelessResponse = Server.StatelessResponse;
const peekLongHeaderIds = wire_peek.peekLongHeaderIds;

/// True if `version` is one of the wire-format versions this
/// server is configured to accept. Drives the VN gate in `feed`.
pub fn versionAccepted(server: *const Server, version: u32) bool {
    for (server.versions) |v| {
        if (v == version) return true;
    }
    return false;
}

/// RFC 9368 §5/§6 server-side pre-parse: decide whether to
/// upgrade this incoming Initial from `wire_version` to a
/// different chosen version.
///
/// Decrypts a private copy of the Initial under wire-version
/// keys, walks the resulting CRYPTO frames to assemble the
/// ClientHello, looks for `quic_transport_parameters` and inside
/// that for `version_information` (codepoint 0x11). Intersects
/// the client's advertised `available_versions` with the server's
/// configured `Config.accepted_versions` and returns the first server-
/// preferred entry that also appears in the client's list.
///
/// Returns:
///   - `null` when the pre-parse failed at any step (decrypt
///     auth, malformed/fragmented ClientHello, missing extension,
///     no overlap with the client's list). The caller falls back
///     to the wire version, which is always spec-compliant.
///   - `wire_version` when the decision is "no upgrade" (the
///     wire version is the highest-priority overlap). Cheap to
///     handle as a no-op upstream.
///   - The upgrade target version when the decision is to
///     upgrade. The caller MUST advertise this as `chosen_version`
///     in the outbound transport_params and (after the first
///     wire-version Initial is processed) flip the connection's
///     active version to it for outbound packet protection.
///
/// Sets `*ch_complete` to false when the reassembled CH was
/// incomplete on this Initial (i.e. the ClientHello is fragmented
/// across multiple Initials). Callers that want to drive a
/// streaming reassembler use that signal to attach a per-slot
/// `PendingUpgradeState`.
///
/// Defensive posture: any error path returns `null`. The pre-
/// parse never closes the connection or surfaces an error to the
/// caller — it is purely advisory.
pub fn preparseUpgradeTarget(
    server: *const Server,
    bytes: []const u8,
    wire_version: u32,
    ch_complete: *bool,
) ?u32 {
    ch_complete.* = false;
    // Multi-version mode is the only case where an upgrade is
    // possible. With a single configured version there is nothing
    // to choose between.
    if (server.versions.len <= 1) return null;
    // Only Initial-key-derivable wire versions support compatible
    // version negotiation. Higher layers reject everything else
    // via `versionAccepted` upstream, but stay defensive.
    if (!wire.initial.isSupportedVersion(wire_version)) return null;

    var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
    const plaintext = decryptInitialPreparse(bytes, wire_version, &pt_buf) orelse return null;

    // Reassemble the ClientHello bytes from the decrypted payload's
    // CRYPTO frames. Single-Initial fast path; on fragmentation we
    // leave `ch_complete=false` and the caller falls into the
    // streaming `PendingUpgradeState` path.
    var ch_buf: [wire.vneg_preparse.max_client_hello_bytes]u8 = undefined;
    const ch = wire.vneg_preparse.reassembleClientHello(&ch_buf, plaintext) orelse return null;
    ch_complete.* = true;

    return upgradeTargetFromCh(server, ch);
}

/// Steps 3-5 of the §6 pre-parse: walk a contiguous ClientHello
/// looking for `quic_transport_parameters` → `version_information`,
/// then intersect the advertised `available_versions` with the
/// server's configured preference list. Shared by the single-shot
/// `preparseUpgradeTarget` and the streaming `advancePendingUpgrade`
/// paths so both produce bit-identical decisions for any given CH.
fn upgradeTargetFromCh(server: *const Server, ch: []const u8) ?u32 {
    const qtp = wire.vneg_preparse.findQuicTransportParamsExt(ch) orelse return null;
    const info = wire.vneg_preparse.findVersionInformation(qtp) orelse return null;
    return wire.vneg_preparse.chooseUpgradeVersion(server.versions, info.available());
}

/// Decrypt a single inbound Initial under the wire-version keys,
/// returning a borrowed slice into `pt_buf` that holds the
/// decrypted plaintext payload (frame stream). Stateless — the
/// caller's normal `handleInitial` flow is the source of truth for
/// `largest_received` etc.; the pre-parse just needs the
/// frame-stream bytes once. Returns null on any decrypt failure
/// (truncated header, key-derivation error, AEAD authentication
/// failure, oversize buffer); callers treat null identically to
/// "skip the upgrade".
fn decryptInitialPreparse(
    bytes: []const u8,
    wire_version: u32,
    pt_buf: *[conn_mod.state.max_recv_plaintext]u8,
) ?[]const u8 {
    const ids = peekLongHeaderIds(bytes) orelse return null;

    // Make a private copy of the inbound bytes — `openInitial`
    // strips header protection in-place, and the caller will
    // re-decrypt the same buffer through the normal
    // `handleInitial` flow.
    var pkt_copy: [conn_mod.state.max_recv_plaintext]u8 = undefined;
    if (bytes.len > pkt_copy.len) return null;
    @memcpy(pkt_copy[0..bytes.len], bytes);

    const init_keys = wire.initial.deriveInitialKeysFor(wire_version, ids.dcid, false) catch return null;
    var r_keys = wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret) catch return null;
    defer r_keys.deinitAead();

    const opened = wire.long_packet.openInitial(pt_buf, pkt_copy[0..bytes.len], .{
        .keys = &r_keys,
        .largest_received = 0,
    }) catch return null;
    return opened.payload;
}

/// Allocate and seed a `PendingUpgradeState` for a freshly-opened
/// slot whose first Initial carried only a CH prefix. Decrypts
/// the first Initial again (the cost is one AEAD open per slot
/// in the multi-Initial path; the single-Initial fast path
/// doesn't enter here) and feeds its CRYPTO bytes through the
/// reassembler so subsequent routed Initials can complete the
/// CH. Returns null on allocation failure or a malformed first-
/// Initial frame stream — in either case the slot commits to
/// the wire version.
pub fn openPendingUpgrade(
    server: *Server,
    bytes: []const u8,
    wire_version: u32,
) ?*PendingUpgradeState {
    const pu = server.allocator.create(PendingUpgradeState) catch return null;
    pu.init(wire_version);
    pu.initials_seen = 1;
    var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
    const plain = decryptInitialPreparse(bytes, wire_version, &pt_buf) orelse {
        server.allocator.destroy(pu);
        return null;
    };
    _ = pu.rc.feed(plain) catch {
        server.allocator.destroy(pu);
        return null;
    };
    return pu;
}

/// Apply a routed Initial datagram to the slot's pending §6
/// upgrade reassembler. Decrypt under the cached wire version,
/// feed the frame stream into the `ChReassembler`, and on a
/// completed CH:
///   - run the same `upgradeTargetFromCh` decision the single-
///     shot path uses,
///   - if the chosen version differs from the wire version,
///     update the connection's outbound transport_params (so the
///     EE BoringSSL is about to write advertises the upgrade)
///     and stash a pending version flip for `dispatchToSlot` to
///     apply once `handleWithEcn` returns,
///   - drop the pending state so future routed datagrams don't
///     re-decrypt this Initial.
///
/// Bounded by `PendingUpgradeState.max_initial_packets`: if the
/// CH is still not complete after that many Initials, give up and
/// commit to the wire version (same outcome as the
/// `error.Invalid` / decrypt-failure paths). The CH is also never
/// allowed to arrive on the upgrade target's keys — only the wire
/// version's — and any frame the reassembler rejects (overflow,
/// unexpected frame type, conflicting overlap) drops the pending
/// state immediately.
pub fn advancePendingUpgrade(server: *Server, slot: *Slot, bytes: []const u8) void {
    const pu = slot.pending_upgrade orelse return;

    // Only Initial-typed long-header datagrams advance the
    // reassembler. Routed Handshake / 1-RTT datagrams ride in via
    // the same path but are not part of CH reassembly. If we ever
    // see a non-Initial here it almost certainly means the peer
    // has already moved past Initial — drop pending state and
    // commit to the wire version.
    const ids = peekLongHeaderIds(bytes) orelse {
        dropPendingUpgrade(server, slot);
        return;
    };
    if (!isInitialLongHeader(bytes, ids.version) or ids.version != pu.wire_version) {
        dropPendingUpgrade(server, slot);
        return;
    }

    // Hard cap on pre-parse work per slot. A peer that keeps
    // sending fragmented Initials past this budget gets the wire-
    // version commitment (still spec-compliant) so we don't
    // accumulate unbounded decrypt CPU under their control.
    if (pu.initials_seen >= PendingUpgradeState.max_initial_packets) {
        dropPendingUpgrade(server, slot);
        return;
    }
    pu.initials_seen += 1;

    var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
    const plaintext = decryptInitialPreparse(bytes, pu.wire_version, &pt_buf) orelse {
        // Decrypt failure — likely a stale retransmit or a packet
        // the connection's normal flow will reject too. Don't
        // tear down pending state on a single failure; future
        // Initials may still drive the upgrade.
        return;
    };

    const got_or_err = pu.rc.feed(plaintext);
    const maybe_ch = got_or_err catch {
        // Malformed frame stream or oversize CH. Falls back to
        // wire version — drop pending state so we don't keep
        // re-evaluating broken inputs.
        dropPendingUpgrade(server, slot);
        return;
    };
    const ch = maybe_ch orelse return; // Still waiting for more bytes.

    // CH complete — make the §6 decision. Whether we upgrade or
    // commit to the wire version, the pending state can be
    // dropped: the decision is final.
    const upgrade_target = upgradeTargetFromCh(server, ch);
    const wire_version = pu.wire_version;
    dropPendingUpgrade(server, slot);

    const chosen = upgrade_target orelse wire_version;
    if (chosen == wire_version) return; // No upgrade.

    // Rebuild the local transport_params with the upgraded
    // chosen version listed first, then push them to BoringSSL.
    // BoringSSL serializes these only when it actually emits the
    // EE; that hasn't happened yet because the CH it has so far
    // is still fragmented (the very datagram we're about to feed
    // into `dispatchToSlot` carries the missing tail). The
    // `setTransportParams` call wins the race and the EE goes
    // out advertising chosen=upgrade.
    var params = slot.conn.localTransportParams();
    var ordered: [wire.vneg_preparse.max_versions]u32 = undefined;
    params.setCompatibleVersions(wire.vneg_preparse.orderedAvailableVersions(
        chosen,
        server.versions,
        &ordered,
    )) catch return;
    slot.conn.setTransportParams(params) catch return;
    slot.conn.setPendingVersionUpgrade(chosen);
}

/// Free and unhook the per-slot multi-Initial pre-parse buffer.
/// Idempotent. Called once the upgrade decision is final or when
/// the per-slot Initial budget is exhausted.
fn dropPendingUpgrade(server: *Server, slot: *Slot) void {
    const pu = slot.pending_upgrade orelse return;
    slot.pending_upgrade = null;
    server.allocator.destroy(pu);
}

/// Encode a Version Negotiation packet into the response queue.
/// Errors propagate from the encoder (`InsufficientBytes`) or
/// the queue allocator (`OutOfMemory`); on either, `feed` falls
/// back to `.dropped`. The supported_versions list mirrors
/// `Config.accepted_versions`; the response echoes the client's CIDs
/// swapped (RFC 8999 §6) and the unused bits are left as the
/// encoder default.
pub fn queueVersionNegotiation(
    server: *Server,
    dst_addr: Address,
    client_packet: []const u8,
) !void {
    const ids = peekLongHeaderIds(client_packet) orelse return error.InvalidVersionNegotiation;
    var entry: StatelessResponse = .{ .dst = dst_addr, .len = 0, .kind = .version_negotiation };

    // Pack our configured versions into a u32-aligned buffer; the
    // wire-level VN encoder handles the rest. Capped at 16 entries
    // so we don't overflow the inline `entry.bytes` budget.
    var versions_bytes: [16 * 4]u8 = undefined;
    const count = @min(server.versions.len, 16);
    for (server.versions[0..count], 0..) |v, i| {
        std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], v, .big);
    }

    const written = try wire.header.encode(&entry.bytes, .{ .version_negotiation = .{
        .dcid = try wire.header.ConnId.fromSlice(ids.scid),
        .scid = try wire.header.ConnId.fromSlice(ids.dcid),
        .versions_bytes = versions_bytes[0 .. count * 4],
    } });
    entry.len = written;
    try server.queueStatelessResponse(entry);
}

// -- NEW_TOKEN ------------------------------------------------------

/// RFC 9368 §6 multi-Initial pre-parse buffer. Owned by the slot;
/// dropped once the CH completes or the Initial-packet budget runs
/// out. Sized to hold the largest CH the pre-parse will accept
/// (`vneg_preparse.max_client_hello_bytes`); together with the
/// reassembler's bookkeeping that is roughly 4 KiB per pending slot.
///
/// DoS posture: the reassembler is created lazily and destroyed
/// eagerly — a flood of new Initials still pays the global slot
/// quota and the per-source rate limiter, and each pending state
/// burns at most `max_initial_packets` packets of decryption work
/// before falling back to the wire version. There is no unbounded
/// per-CID accumulation.
pub const PendingUpgradeState = struct {
    /// Maximum number of client Initials we will decrypt to drive
    /// the upgrade decision before giving up and committing to the
    /// wire version. Real CHs split across at most 2-3 Initials in
    /// practice; 4 keeps a margin without letting a peer churn the
    /// pre-parse path indefinitely.
    pub const max_initial_packets: u8 = 4;

    /// Backing storage for the assembled CH. The reassembler borrows
    /// this slice via `init`.
    ch_buf: [wire.vneg_preparse.max_client_hello_bytes]u8 = undefined,
    /// Per-slot reassembler. Holds segment bookkeeping plus a
    /// pointer back into `ch_buf`.
    rc: wire.vneg_preparse.ChReassembler,
    /// Number of Initials we've already consumed for this slot's
    /// upgrade decision. Bumps on every routed datagram fed through
    /// `advancePendingUpgrade` and on the slot-creating Initial when
    /// `openPendingUpgrade` seeds the reassembler. Bounded by
    /// `max_initial_packets`.
    initials_seen: u8 = 0,
    /// The wire version the FIRST Initial arrived under. Subsequent
    /// Initials decrypted by the pre-parse use the same Initial-key
    /// derivation; if the peer flipped versions mid-flight (which
    /// would be a peer bug), `openInitial` will fail authentication
    /// and the pre-parse falls back gracefully.
    wire_version: u32,

    fn init(self: *PendingUpgradeState, wire_version: u32) void {
        self.* = .{
            .rc = wire.vneg_preparse.ChReassembler.init(&self.ch_buf),
            .wire_version = wire_version,
        };
    }
};
