//! Server TLS context lifecycle: refcounted generation draining and
//! hot context replacement (Server.replaceTlsContext), plus the
//! anti-replay early-data trampoline shared with Server.init. Split
//! from Server.zig; the pub method on Server is a thin thunk that
//! delegates here.

const std = @import("std");
const boringssl = @import("boringssl");
const Server = @import("../Server.zig");
const Error = Server.Error;
const TlsReload = Server.TlsReload;
const conn_mod = @import("../conn/root.zig");
const tls_mod = @import("../tls/root.zig");

/// Decrement the refcount on the draining entry for `generation`,
/// if any. When the refcount hits zero, the entry's context is
/// torn down and the entry is dropped from
/// `draining_tls_contexts`. A `generation` matching
/// `current_generation` is a no-op (the current context isn't a
/// draining entry until the next `replaceTlsContext`).
pub fn releaseGeneration(server: *Server, generation: u32) void {
    if (generation == server.current_generation) return;
    var idx: usize = 0;
    while (idx < server.draining_tls_contexts.items.len) : (idx += 1) {
        const entry = &server.draining_tls_contexts.items[idx];
        if (entry.generation != generation) continue;
        // invariant: refcount > 0 — every live slot at this
        // generation contributed exactly one. Reaping a slot
        // can't drop to zero before all its refs are accounted.
        std.debug.assert(entry.refcount > 0);
        entry.refcount -= 1;
        if (entry.refcount == 0) {
            entry.ctx.deinit();
            _ = server.draining_tls_contexts.swapRemove(idx);
        }
        return;
    }
}

/// Bookkeeping for one TLS context that has been swapped out by
/// `Server.replaceTlsContext` but still has live slots referencing it
/// via per-connection SSL handles. The entry is `deinit`-ed and
/// dropped when `refcount` hits zero on reap.
pub const DrainingTlsEntry = struct {
    /// The swapped-out context. Owned — `refcount==0` deinit calls
    /// `Context.deinit` on this. Per-connection SSL handles created
    /// against this context already hold their own up-ref via
    /// `SSL_new`, so deiniting here only drops the Server's reference;
    /// the underlying SSL_CTX stays alive until every per-connection
    /// SSL handle is freed.
    ctx: boringssl.tls.Context,
    /// Generation tag. Slots opened against this context recorded the
    /// same value in their `tls_generation` field; reap matches on it.
    generation: u32,
    /// Number of live slots still associated with this context. Set
    /// at swap-time (= count of pre-swap slots whose generation was
    /// `current_generation`); decremented in `reap` when one of those
    /// slots is reclaimed.
    refcount: usize,
};

/// BoringSSL `allow_early_data` callback installed by `Server.init`
/// when an `AntiReplayTracker` is supplied via Config. Hashes the
/// resumed-session ticket bytes (`Conn.peerSessionId`) to a 32-byte
/// tracker `Id` and consults `tracker.consume` for a verdict.
///
/// Return contract (mirrors `boringssl.tls.AllowEarlyDataCallback`):
///   - `true`  → BoringSSL proceeds with 0-RTT for this handshake.
///   - `false` → BoringSSL toggles `early_data_enabled = false` on
///               this `SSL` so the handshake completes as 1-RTT.
///
/// Defensive defaults: any plumbing failure (null user_data, hash
/// failure, OOM in the tracker) returns `false` — denying 0-RTT
/// rather than risking a replay window where the tracker can't see
/// the attempt. Hash failures are not peer-reachable in practice.
pub fn antiReplayEarlyDataTrampoline(
    user_data: ?*anyopaque,
    ssl: *boringssl.tls.Conn,
) bool {
    const raw_ptr = user_data orelse return false;
    const tracker: *tls_mod.anti_replay.AntiReplayTracker =
        @ptrCast(@alignCast(raw_ptr));

    // No resumed session attached → no replay risk to gate on. Return
    // true; BoringSSL will refuse 0-RTT anyway because there's no
    // ticket to bind it to.
    const ticket = ssl.peerSessionId() orelse return true;

    const id_full = boringssl.crypto.hash.Sha256.hash(ticket) catch return false;
    var id: tls_mod.anti_replay.Id = undefined;
    @memcpy(&id, id_full[0..tls_mod.anti_replay.id_len]);

    // The tracker exposes an internal-clock variant of `consume` so
    // this callback (which has no path to the Server's monotonic
    // clock) can defer to the most recent `now_us` that
    // `Server.feed` cached via `bumpClock`. The age-out window then
    // tracks Server-driven time exactly the way the application-
    // layer `consume(id, now_us)` callers see.
    const verdict = tracker.consumeUsingInternalClock(id) catch return false;
    return switch (verdict) {
        .fresh => true,
        .replay => false,
    };
}

/// Build a server-mode TLS context from PEM credentials, carrying
/// the FULL TLS security posture: TLS-1.3-only version pin, ALPN
/// preference order, mTLS trust anchors (`client_ca_pem`), the
/// 0-RTT `early_data_enabled` knob, and the anti-replay early-data
/// hook (`tracker`).
///
/// This is the ONLY constructor for Server-owned contexts — both
/// `Server.init` and `replaceTlsContext({.pem = ...})` go through
/// it, deliberately: the two paths used to carry hand-mirrored
/// copies of this sequence, and commit 7fc58b6 landed the
/// anti-replay hook (RFC 9001 §5.6 / hardening §5.2) on the init
/// copy only, leaving `.pem` cert rotations silently accepting
/// replayed 0-RTT flights until 1b69f8a backfilled it. Every
/// future posture knob (ticket keys, cipher preferences, OCSP,
/// ...) must land here so a cert reload can never downgrade the
/// server's security posture again.
///
/// Empty `cert_pem`/`key_pem` is rejected as `Error.InvalidConfig`
/// (both callers share that rule). On any failure the
/// partially-built context is torn down internally; on success the
/// caller owns the returned context.
///
/// `tracker` non-null implies early data is enabled
/// (`Config.EarlyData.antiReplayTracker` only returns a tracker
/// for `.with_anti_replay`, which also enables 0-RTT); the hook is
/// installed whenever a tracker is supplied, matching the
/// historical `Server.init` behavior.
pub fn buildServerContext(
    alpn: []const []const u8,
    cert_pem: []const u8,
    key_pem: []const u8,
    client_ca_pem: ?[]const u8,
    early_data_enabled: bool,
    tracker: ?*tls_mod.anti_replay.AntiReplayTracker,
) Error!boringssl.tls.Context {
    if (cert_pem.len == 0 or key_pem.len == 0) return Error.InvalidConfig;
    var ctx = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = alpn,
        .early_data_enabled = early_data_enabled,
    });
    errdefer ctx.deinit();
    try ctx.loadCertChainAndKey(cert_pem, key_pem);
    // mTLS: require and verify a client certificate against the
    // embedder's pinned roots. On the reload path this carries the
    // init-time posture onto the replacement context — a cert
    // rotation must not silently stop verifying clients.
    if (client_ca_pem) |ca| {
        try tls_mod.pem.installTrustAnchors(ctx, ca, .require_peer_cert);
    }
    // Hardening §5.2 / RFC 9001 §5.6: when the embedder installs an
    // `AntiReplayTracker`, hook BoringSSL's pre-resumption
    // early-data callback so duplicate 0-RTT attempts are rejected
    // at the TLS layer (not just at application post-handshake). A
    // context that enables early data without it would silently
    // accept replayed 0-RTT flights.
    if (tracker) |t| {
        try ctx.setAllowEarlyDataCallback(
            antiReplayEarlyDataTrampoline,
            @ptrCast(t),
        );
    }
    return ctx;
}

// Doc comment lives on the `Server.replaceTlsContext` thunk in Server.zig.
pub fn replaceTlsContext(server: *Server, reload: TlsReload) Error!void {
    var new_ctx: boringssl.tls.Context = switch (reload) {
        // Rebuild with the same posture the original context was
        // built with — `buildServerContext` is shared with
        // `Server.init` precisely so the two can't drift.
        .pem => |pem| try buildServerContext(
            server.alpn_protocols,
            pem.cert_pem,
            pem.key_pem,
            server.client_ca_pem,
            server.enable_0rtt,
            server.early_data_anti_replay,
        ),
        // Mirror the `Server.init` rule that rejects
        // `client_ca_pem` + `tls_context_override`: an adopted
        // context owns its own verification posture, and adopting
        // one while this Server is configured for mTLS would
        // silently stop verifying clients (and flip-flop back on
        // a later `.pem` reload). mTLS servers rotate via `.pem`.
        .override => |ctx| blk: {
            if (server.client_ca_pem != null) return Error.InvalidConfig;
            break :blk ctx;
        },
    };
    // From this point on the new context is logically the
    // Server's. If the bookkeeping below fails we have to deinit
    // it ourselves to avoid leaking — the caller already
    // surrendered ownership of an `.override`, and the `.pem`
    // branch built it locally.
    errdefer new_ctx.deinit();

    // Count live slots at the current generation so we know how
    // many references the about-to-drain context still holds.
    var refs: usize = 0;
    const gen_to_drain = server.current_generation;
    for (server.slots.items) |slot| {
        if (slot.tls_generation == gen_to_drain) refs += 1;
    }

    // Reserve a draining slot up-front when the pre-swap context
    // is owned and still referenced — `appendBounded`-style call
    // would also work, but doing it now means an OOM here leaves
    // both the old context and the slot table untouched.
    if (server.owns_tls and refs > 0) {
        try server.draining_tls_contexts.append(server.allocator, .{
            .ctx = server.tls_ctx,
            .generation = gen_to_drain,
            .refcount = refs,
        });
    } else if (server.owns_tls and refs == 0) {
        // Owned but no live slots reference it — drop immediately.
        server.tls_ctx.deinit();
    }
    // If !owns_tls, the embedder retains ownership of the
    // pre-swap context — we just forget the pointer.

    server.tls_ctx = new_ctx;
    server.owns_tls = true;
    server.current_generation +%= 1;
}
