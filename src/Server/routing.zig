// Connection routing: the CID -> slot table (lookup, resync, drop),
// QUIC-LB CID minting and live-slot rotation, and per-slot CID
// replenishment. Split from server.zig; the pub methods on Server are
// thin thunks that delegate here. The pure header-peek / CID-key
// helpers live in the wire_peek.zig leaf.

const std = @import("std");
const Server = @import("../Server.zig");
const Slot = Server.Slot;
const Error = Server.Error;
const wire_peek = @import("wire_peek.zig");
const cidKeyFromSlice = wire_peek.cidKeyFromSlice;
const cidKeyFromConnectionId = wire_peek.cidKeyFromConnectionId;
const containsConnectionId = wire_peek.containsConnectionId;
const peekDcidForServer = wire_peek.peekDcidForServer;
const conn_mod = @import("../conn/root.zig");
const lb_mod = @import("../lb/root.zig");
const ConnectionId = conn_mod.path.ConnectionId;
const Address = conn_mod.path.Address;
const max_tracked_cids_per_slot = Server.max_tracked_cids_per_slot;
const boringssl = @import("boringssl");

// Doc comment lives on the `Connection.installLbConfig` thunk in state.zig.
pub fn installLbConfig(self: *Server, new_cfg: lb_mod.LbConfig) Error!void {
    new_cfg.validate() catch return Error.InvalidConfig;
    if (self.lb_factory == null) return Error.InvalidConfig;
    if (new_cfg.cidLength() != self.local_cid_len) return Error.InvalidConfig;

    const new_factory = lb_mod.Factory.initUnchecked(new_cfg) catch |err| switch (err) {
        error.AesKeyInvalid => return Error.InvalidConfig,
        error.RandFailure => return Error.RandFailed,
        error.InvalidLbConfig => return Error.InvalidConfig,
        error.BufferTooSmall, error.NonceExhausted => unreachable,
    };
    if (self.lb_factory) |*old| old.deinit();
    self.lb_factory = new_factory;

    // Auto-push to live peers. No-op without a stateless-reset
    // key (token derivation needs one); embedders running
    // without the key drive replenishment manually via
    // `connection_ids_needed`.
    if (self.stateless_reset_key != null) {
        _ = rotateLiveSlotCids(
            self,
        );
    }
}

// Doc comment lives on the `Connection.rotateLiveSlotCids` thunk in state.zig.
pub fn rotateLiveSlotCids(self: *Server) usize {
    const factory_ptr = if (self.lb_factory) |*f| f else return 0;
    const key = self.stateless_reset_key orelse return 0;

    var rotated: usize = 0;
    for (self.slots.items) |slot| {
        if (slot.conn.isClosed()) continue;
        if (slot.conn.localConnectionIdIssueBudget(0) == 0) continue;

        var cid_buf: [20]u8 = undefined;
        const cid_slice = cid_buf[0..self.local_cid_len];
        _ = factory_ptr.mint(cid_slice) catch continue;

        const token = conn_mod.stateless_reset.derive(&key, cid_slice) catch continue;
        const next_seq = slot.conn.nextLocalConnectionIdSequence(0);
        const provision = conn_mod.ConnectionIdProvision{
            .connection_id = cid_slice,
            .stateless_reset_token = token,
            .retire_prior_to = next_seq,
        };
        _ = slot.conn.replenishConnectionIds(&[_]conn_mod.ConnectionIdProvision{provision}) catch continue;

        // Bring the routing table in line with the slot's new
        // active-CID set so the new CID becomes routable on
        // the next inbound datagram. Failures here leave the
        // CID in the connection but unreachable until the next
        // organic resync — log via the standard error path
        // by skipping the rotation count.
        resyncSlotCids(self, slot) catch continue;
        rotated += 1;
    }
    return rotated;
}

pub fn findSlotForDatagram(self: *Server, bytes: []const u8) ?*Slot {
    const dcid = peekDcidForServer(bytes, self.local_cid_len) orelse return null;
    const key = cidKeyFromSlice(dcid);
    return self.cid_table.get(key);
}

// Doc comment lives on the `Connection.mintLocalScid` thunk in state.zig.
pub fn mintLocalScid(self: *Server, dst: []u8) Error!void {
    if (self.lb_factory) |*factory| {
        const n = factory.mint(dst) catch |err| switch (err) {
            error.RandFailure => return Error.RandFailed,
            // Per draft §3 ¶3 / §3.1: when the active
            // configuration can no longer mint distinct CIDs the
            // server SHOULD switch to a new configuration or use
            // the unroutable fallback. Until the operator calls
            // `installLbConfig`, this branch keeps the server
            // alive by emitting unroutable CIDs that an LB can
            // route via its configured fallback path.
            error.NonceExhausted => {
                if (dst.len < lb_mod.min_unroutable_cid_len) {
                    return Error.RandFailed;
                }
                _ = lb_mod.mintUnroutable(dst, @intCast(dst.len)) catch {
                    return Error.RandFailed;
                };
                return;
            },
            // `Server.init` already rejected ill-sized
            // configurations, and `local_cid_len` matches
            // `Factory.cidLength()` by construction. Reaching any
            // of these would mean an invariant upstream slipped —
            // surface as the generic SCID mint-failure code
            // rather than panicking, since the network-input path
            // must remain non-fatal.
            error.BufferTooSmall,
            error.InvalidLbConfig,
            error.AesKeyInvalid,
            => return Error.RandFailed,
        };
        std.debug.assert(n == dst.len);
        return;
    }
    try boringssl.crypto.rand.fillBytes(dst);
}

/// Diff the slot's currently-tracked CIDs against the
/// connection's authoritative `localScids` list and patch
/// `cid_table` accordingly. Called after every `feed` so that
/// an SCID issued during this datagram (NEW_CONNECTION_ID) is
/// routable from the *next* datagram on, and a retired SCID
/// (RETIRE_CONNECTION_ID consumed during this datagram) stops
/// accepting traffic.
///
/// Algorithm: O(K + L) where K = current local SCID count and
/// L = previously-tracked CID count. Both are bounded by
/// `max_tracked_cids_per_slot`; in practice K ≈ L ≈ peer's
/// `active_connection_id_limit` (default 8).
pub fn resyncSlotCids(self: *Server, slot: *Slot) Error!void {
    var snapshot_buf: [max_tracked_cids_per_slot]ConnectionId = undefined;
    const total = slot.conn.localScidCount();
    // Default `active_connection_id_limit=8` keeps `total` well
    // under the bound. If an embedder lifts the limit beyond
    // `max_tracked_cids_per_slot`, the router will silently miss
    // SCIDs past the cap and the peer could lose connectivity
    // after a CID rotation. Surface the misconfiguration loudly
    // in debug builds; release builds still truncate (no
    // panic), but the configuration is broken either way.
    std.debug.assert(total <= max_tracked_cids_per_slot);
    const n = slot.conn.localScids(snapshot_buf[0..@min(total, max_tracked_cids_per_slot)]);
    const snapshot = snapshot_buf[0..n];

    // Drop tracked CIDs that are no longer in the connection's
    // active set. `tracked_cids` is small and the inner loop is
    // a byte compare, so the nominal O(K*L) is fine.
    var i: usize = 0;
    while (i < slot.tracked_cid_count) {
        const tracked = slot.tracked_cids[i];
        if (!containsConnectionId(snapshot, tracked)) {
            _ = self.cid_table.remove(cidKeyFromConnectionId(tracked));
            // Swap-remove to keep the bookkeeping O(1).
            slot.tracked_cid_count -= 1;
            slot.tracked_cids[i] = slot.tracked_cids[slot.tracked_cid_count];
            continue;
        }
        i += 1;
    }

    // Add CIDs that the connection now owns but the table
    // doesn't yet route. Skip the initial DCID — that one is
    // peer-chosen, never returned by `localScids`, and it stays
    // pinned for the lifetime of the slot.
    for (snapshot) |cid| {
        if (containsConnectionId(slot.tracked_cids[0..slot.tracked_cid_count], cid)) continue;
        const gop = try self.cid_table.getOrPut(self.allocator, cidKeyFromConnectionId(cid));
        if (gop.found_existing and gop.value_ptr.* != slot) {
            // CID collision with a different live slot (astronomically
            // unlikely given CID entropy). Do not hijack its routing
            // or claim the CID: overwriting would silently steal the
            // other slot's traffic, and reaping either slot would then
            // un-route the survivor. Leave the existing owner intact.
            continue;
        }
        gop.value_ptr.* = slot;
        // invariant: snapshot ≤ max_tracked_cids_per_slot, so
        // we always have room.
        std.debug.assert(slot.tracked_cid_count < max_tracked_cids_per_slot);
        slot.tracked_cids[slot.tracked_cid_count] = cid;
        slot.tracked_cid_count += 1;
    }
}

/// Remove every routing entry owned by `slot` from `cid_table`.
/// Called from `reap` after the slot is observed `.closed`.
pub fn dropAllCidsFromTable(self: *Server, slot: *Slot) void {
    removeCidIfOwnedBy(self, slot.initial_dcid, slot);
    for (slot.tracked_cids[0..slot.tracked_cid_count]) |cid| {
        removeCidIfOwnedBy(self, cid, slot);
    }
    slot.tracked_cid_count = 0;
}

/// Remove a CID's routing entry only if it still points at `slot`.
/// Guards against a CID collision (see `resyncSlotCids`) causing a
/// reaped slot to un-route a CID another live slot now owns.
fn removeCidIfOwnedBy(self: *Server, cid: ConnectionId, slot: *Slot) void {
    const key = cidKeyFromConnectionId(cid);
    if (self.cid_table.getPtr(key)) |vp| {
        if (vp.* == slot) _ = self.cid_table.remove(key);
    }
}

/// Mint and queue a single NEW_TOKEN on `slot`'s connection if all
/// prerequisites are satisfied:
///  - `Server.new_token_key` is non-null (feature opt-in).
///  - The slot's connection has confirmed the handshake.
///  - This slot has not already emitted its NEW_TOKEN.
///  - We have a peer address to bind into the token (no `from`,
///    no NEW_TOKEN — the embedder is in a hermetic-test path).
///
/// Called from the routed and accepted feed paths; idempotent
/// across retries via the slot's `new_token_emitted` latch.
/// Post-handshake CID inventory top-up (RFC 9000 §5.1.1 / §9).
/// Runs once per slot from the feed paths, next to
/// `maybeIssueNewToken`. Mints up to
/// `min(local issue budget, max_auto_replenish_cids)` fresh SCIDs
/// through the same `mintLocalScid` path as the handshake CID,
/// derives each one's §10.3 stateless-reset token from
/// `stateless_reset_key`, and queues NEW_CONNECTION_ID frames via
/// `replenishConnectionIds`. The post-feed `resyncSlotCids` pass
/// picks the new CIDs up into the routing table. Failures skip the
/// top-up (the latch stays set): migration then degrades to the
/// pre-replenish behavior instead of failing the connection.
pub fn maybeReplenishConnectionIds(self: *Server, slot: *Slot) void {
    if (!self.auto_replenish_connection_ids) return;
    if (slot.cids_replenished) return;
    const key = if (self.stateless_reset_key) |*k| k else return;
    if (!slot.conn.handshakeDone()) return;
    slot.cids_replenished = true;

    var cid_storage: [8][20]u8 = undefined;
    var provisions: [8]conn_mod.ConnectionIdProvision = undefined;
    const budget = @min(
        @min(
            slot.conn.localConnectionIdIssueBudget(0),
            @as(usize, self.max_auto_replenish_cids),
        ),
        provisions.len,
    );
    if (budget == 0) return;

    var n: usize = 0;
    while (n < budget) : (n += 1) {
        const cid = cid_storage[n][0..self.local_cid_len];
        mintLocalScid(self, cid) catch return;
        const token = conn_mod.stateless_reset.derive(key, cid) catch return;
        provisions[n] = .{
            .connection_id = cid,
            .stateless_reset_token = token,
        };
    }
    _ = slot.conn.replenishConnectionIds(provisions[0..n]) catch {};
}
