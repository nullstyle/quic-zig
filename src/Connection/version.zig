//! Server-side Initial acceptance, Version Negotiation / Retry packet
//! writing, and compatible version upgrade (RFC 9000 §6, §17.2.5; RFC
//! 9368/9369). Free-function siblings of `Connection`'s method-style
//! version plumbing; the methods on `Connection` are thin thunks that
//! delegate here.

const std = @import("std");
const state_mod = @import("../Connection.zig");
const Connection = state_mod.Connection;
const Error = state_mod.Error;
const ConnectionId = state_mod.ConnectionId;
const TransportParams = state_mod.TransportParams;
const wire_header = state_mod.wire_header;
const long_packet_mod = state_mod.long_packet_mod;
const initial_keys_mod = state_mod.initial_keys_mod;
const path_mod = state_mod.path_mod;

/// Server-side helper: peek the unprotected DCID + SCID out of
/// an incoming Initial datagram and install them along with the
/// caller-supplied transport parameters. Idempotent — safe to
/// call once before the first `handle`. Useful for plain UDP
/// servers that need to seed CID/transport-parameter state
/// from the very first datagram before TLS can advance.
pub fn acceptInitial(
    self: *Connection,
    bytes: []const u8,
    params: TransportParams,
) Error!void {
    if (self.role != .server) return Error.NotServerContext;
    if (bytes.len < 6) return Error.InsufficientBytes;
    if ((bytes[0] & 0x80) == 0) return Error.NotInitialPacket; // bit 7 clear → short header
    // RFC 9368 §3.2: the v2 long-header type rotation puts Initial
    // at 0b01 instead of 0b00. Resolve through `longTypeFromBits`
    // so a v2 ClientHello survives this gate.
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    if (wire_header.longTypeFromBits(version, long_type_bits) != .initial) {
        return Error.NotInitialPacket;
    }
    // Adopt the peer's version so subsequent Initial-key
    // derivation (`ensureInitialKeys`), header encoding, and
    // Retry-tag construction all key off the right RFC 9001 §5
    // / RFC 9368 §3.3 constants. Invalidates any pre-existing
    // Initial keys via `setVersion`.
    if (version != self.version) setVersion(self, version);
    // RFC 9368 §6 ¶6/¶7 downgrade-attack guard: snapshot the wire
    // version of the FIRST Initial we accepted, BEFORE any
    // compatible-version upgrade flips `self.version`. The client's
    // `version_information.chosen_version` (parsed later from the
    // ClientHello transport params) MUST equal this — otherwise a
    // path attacker rewrote the wire version while leaving the
    // ClientHello intact. Latched once: subsequent `acceptInitial`
    // calls (e.g. retransmits) leave the snapshot alone.
    if (self.initial_wire_version == null) {
        self.initial_wire_version = version;
    }

    const dcid_len = bytes[5];
    if (dcid_len > path_mod.max_cid_len) return Error.DcidTooLong;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return Error.InsufficientBytes;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;
    const scid_len = bytes[pos];
    if (scid_len > path_mod.max_cid_len) return Error.DcidTooLong;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return Error.InsufficientBytes;
    const scid = bytes[pos .. pos + scid_len];

    try setInitialDcid(self, dcid);
    try self.setPeerDcid(scid);
    try self.setTransportParams(params);
}

fn longHeaderCids(bytes: []const u8) Error!struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
} {
    if (bytes.len < 6) return Error.InsufficientBytes;
    if ((bytes[0] & 0x80) == 0) return Error.NotInitialPacket;
    const version = std.mem.readInt(u32, bytes[1..5], .big);

    const dcid_len = bytes[5];
    if (dcid_len > path_mod.max_cid_len) return Error.DcidTooLong;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return Error.InsufficientBytes;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;
    const scid_len = bytes[pos];
    if (scid_len > path_mod.max_cid_len) return Error.DcidTooLong;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return Error.InsufficientBytes;
    const scid = bytes[pos .. pos + scid_len];
    return .{ .version = version, .dcid = dcid, .scid = scid };
}

fn initialHeaderCids(bytes: []const u8) Error!struct {
    dcid: []const u8,
    scid: []const u8,
} {
    const cids = try longHeaderCids(bytes);
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    // RFC 9368 §3.2: the v2 long-header type rotation makes the
    // wire-bit value version-specific; resolve through
    // `longTypeFromBits` so v2 Initials don't get rejected here.
    const long_type = wire_header.longTypeFromBits(cids.version, long_type_bits);
    if (long_type != .initial) return Error.NotInitialPacket;
    return .{ .dcid = cids.dcid, .scid = cids.scid };
}

/// Server-side helper: write a Version Negotiation packet in
/// response to a client's unsupported-version long-header packet.
/// `supported_versions` is encoded in preference order.
pub fn writeVersionNegotiation(
    self: *Connection,
    dst: []u8,
    client_packet: []const u8,
    supported_versions: []const u32,
) Error!usize {
    if (self.role != .server) return error.NotServerContext;
    if (supported_versions.len == 0) return error.InvalidVersionNegotiation;
    if (supported_versions.len > 16) return error.BufferTooSmall;
    const cids = try longHeaderCids(client_packet);

    var versions_bytes: [16 * 4]u8 = undefined;
    for (supported_versions, 0..) |version, i| {
        std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], version, .big);
    }

    return try wire_header.encode(dst, .{ .version_negotiation = .{
        .dcid = try wire_header.ConnId.fromSlice(cids.scid),
        .scid = try wire_header.ConnId.fromSlice(cids.dcid),
        .versions_bytes = versions_bytes[0 .. supported_versions.len * 4],
    } });
}

/// Server-side helper: write a Retry packet in response to
/// `client_initial`. Token contents and validation remain
/// embedder-owned; quic handles the Retry header and the
/// version-keyed RFC 9001 §5.8 / RFC 9368 §3.3.3 integrity tag.
/// The Retry's version field mirrors the client's Initial so the
/// peer can validate under the matching constants.
pub fn writeRetry(
    self: *Connection,
    dst: []u8,
    client_initial: []const u8,
    retry_scid: []const u8,
    retry_token: []const u8,
) Error!usize {
    if (self.role != .server) return error.NotServerContext;
    const cids = try longHeaderCids(client_initial);
    // Make sure the leading long-header packet really is an Initial
    // under the client's chosen version (RFC 9368 §3.2 v2 layout
    // moves the Retry slot, so a v1-only check would mis-classify
    // a v2 Retry as "not an Initial").
    const long_type_bits: u2 = @intCast((client_initial[0] >> 4) & 0x03);
    const long_type = wire_header.longTypeFromBits(cids.version, long_type_bits);
    if (long_type != .initial) return Error.NotInitialPacket;
    return try long_packet_mod.sealRetry(dst, .{
        .version = cids.version,
        .original_dcid = cids.dcid,
        .dcid = cids.scid,
        .scid = retry_scid,
        .retry_token = retry_token,
    });
}

/// Set the original DCID used for Initial-key derivation
/// (RFC 9001 §5.2). On the client this is the random DCID it
/// chose for its very first Initial. On the server, it's the
/// DCID it received on the client's first Initial. Per RFC 9000
/// the initial DCID is at least 8 bytes, so `len == 0` here is
/// always "unset".
pub fn setInitialDcid(self: *Connection, dcid: []const u8) Error!void {
    if (dcid.len > path_mod.max_cid_len) return Error.DcidTooLong;
    if (!self.original_initial_dcid_set) {
        self.original_initial_dcid = ConnectionId.fromSlice(dcid);
        self.original_initial_dcid_set = true;
    }
    self.initial_dcid = ConnectionId.fromSlice(dcid);
    self.initial_dcid_set = true;
    self.initial_keys_read = null;
    self.initial_keys_write = null;
}

/// Set the active QUIC wire-format version. The Initial-keys
/// derivation depends on it (RFC 9001 §5.2 v1 / RFC 9368 §3.3.1
/// v2), so any cached Initial keys are dropped on change. Calling
/// this after Initial-level traffic has been exchanged is a
/// configuration error and bypasses the safety latch — embedders
/// MUST switch versions only at construction time or via the
/// compatible-version-negotiation upgrade path before either side
/// has emitted an Initial under the previous version.
pub fn setVersion(self: *Connection, version: u32) void {
    if (self.version == version) return;
    self.version = version;
    if (self.initial_keys_read) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
    if (self.initial_keys_write) |*k| std.crypto.secureZero(u8, std.mem.asBytes(k));
    self.initial_keys_read = null;
    self.initial_keys_write = null;
}

/// RFC 9368 §6 server-side hook: stash an upgrade target so a
/// later call to `applyPendingVersionUpgrade` can flip the active
/// version after the first wire-version Initial has been consumed
/// under its wire-version keys. The actual flip lives in the
/// server's `dispatchToSlot`, just after `handleWithEcn` returns
/// and before the embedder's `poll` would seal the EE-bearing
/// response under what would otherwise still be the wire-version
/// keys. Calling with `null` clears the pending upgrade. Idempotent.
pub fn setPendingVersionUpgrade(self: *Connection, version: ?u32) void {
    self.pending_version_upgrade = version;
}

/// Returns the currently-pending upgrade target, or `null` if
/// none was stashed via `setPendingVersionUpgrade`.
pub fn pendingVersionUpgrade(self: *const Connection) ?u32 {
    return self.pending_version_upgrade;
}

/// Apply any RFC 9368 §6 pending version upgrade. The wire-
/// version Initial keys are zeroed (via `setVersion`) so any
/// retransmitted wire-version Initial that arrives after this
/// point will be dropped at decrypt; the spec allows that —
/// once the server has chosen to upgrade, the original wire-
/// version stream is discarded. Returns `true` when a flip
/// happened (so the caller can emit observability), `false`
/// otherwise.
pub fn applyPendingVersionUpgrade(self: *Connection) bool {
    const target = self.pending_version_upgrade orelse return false;
    self.pending_version_upgrade = null;
    if (target == self.version) return false;
    setVersion(self, target);
    return true;
}

/// RFC 9368 §6 client-side hook: accept a compatible-version
/// upgrade signaled by the server's first Initial response carrying
/// a wire version that differs from the one the client put on its
/// outgoing Initial. The candidate `version` MUST appear in the
/// client's locally-advertised `version_information.available_versions`
/// (see `local_transport_params.compatibleVersions()` — entry 0 is
/// the wire/preferred version, the remaining entries are the
/// compatible set). Validates the candidate against the client's
/// list and against `wire.initial.isSupportedVersion`, then flips
/// `self.version` (which re-derives Initial keys via `setVersion`).
///
/// Returns:
///  - `true` on a successful flip; the caller should re-derive
///    Initial keys (which `setVersion` zeroes) and retry decryption
///    of the inbound Initial.
///  - `false` when the upgrade is rejected (wrong role, no
///    advertised compatible-versions list, candidate not on the
///    client's list, candidate's keys aren't derivable, or the
///    state machine has already moved past the Initial-level
///    decision window). Caller treats this as "leave version
///    alone"; the inbound packet will then fail AEAD auth and be
///    dropped, which is the spec-compliant fallback.
pub fn clientAcceptCompatibleVersion(self: *Connection, version: u32) bool {
    if (self.role != .client) return false;
    // Same-version is reported as "nothing to do" (false) so
    // callers can distinguish a real flip from a no-op.
    if (version == self.version) return false;
    // The decision window closes once Initial keys are dropped
    // (discardInitialKeys, post-handshake-confirm) — beyond that,
    // flipping `self.version` would desync the long-header type-bit
    // decoder against in-flight packets.
    if (self.initial_keys_discarded) return false;
    if (self.inner.handshakeDone()) return false;
    // Defensive: only accept versions whose Initial keys we can
    // derive. RFC 9368 §6 only defines v1↔v2; an unknown version
    // here would have been a configuration accident upstream.
    if (!initial_keys_mod.isSupportedVersion(version)) return false;
    // The candidate MUST appear in the locally-advertised
    // `available_versions` list (RFC 9368 §6 ¶6: "a server SHOULD
    // pick one of the versions" the client listed). The list
    // includes the wire version at index 0 plus every
    // compatible_version from `Client.Config`.
    const advertised = self.local_transport_params.compatibleVersions();
    if (std.mem.indexOfScalar(u32, advertised, version) == null) return false;
    setVersion(self, version);
    return true;
}
