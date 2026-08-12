//! quic_zig.Server — production-grade convenience wrapper for embedding
//! quic_zig as a QUIC server.
//!
//! `Connection` is intentionally I/O-agnostic: it consumes incoming
//! UDP datagrams via `handle()` and produces outgoing ones via
//! `poll()`. Wiring that to a UDP socket, demultiplexing peers by
//! connection ID, applying transport-parameter templates, and
//! stepping the per-connection event loop is repetitive boilerplate
//! every embedder ends up writing.
//!
//! `Server` owns that boilerplate. It is still I/O-agnostic — the
//! embedder owns the UDP socket and the wall clock — but it owns the
//! `boringssl.tls.Context`, the per-connection lifecycle, and a
//! constant-time CID-to-slot routing table that follows
//! NEW_CONNECTION_ID issuance / RETIRE_CONNECTION_ID retirement
//! automatically.
//!
//! Routing
//! -------
//! After every successful `feed`, the slot's CID set is resynced
//! from `Connection.localScids` and the routing table is updated in
//! place — added SCIDs become routing keys immediately, retired
//! SCIDs stop accepting traffic. Lookup is `std.AutoHashMap`
//! O(1) on the length-prefixed CID bytes; reaping a slot drops
//! every CID it owned in one pass. RFC 9000 §5.1.1 lets peers pick
//! any issued CID at any time, and the router honors that without
//! the embedder writing CID-tracking glue.
//!
//! DoS posture
//! -----------
//! Three gates harden Initial-driven slot creation; each surfaces a
//! distinct `FeedOutcome` variant when it fires.
//!
//! 1. `Config.initial_source_rate_limit` drives a per-source-address
//!    token bucket (on by default at the recommended open-internet
//!    cap). When the cap is exceeded, fresh Initials from that
//!    source are dropped without state, so an attacker spraying
//!    Initials from a single address cannot exhaust the slot table
//!    or the TLS context.
//! 2. `Config.retry_token_key` enables stateless Retry-based source
//!    validation (RFC 9000 §8.1.2). The first Initial from a peer
//!    earns a Retry packet bound to its address; until the peer
//!    echoes a valid token in a follow-up Initial, no `Connection`
//!    is allocated. Set this to gate the 3x amplification window
//!    behind a proof-of-address round trip.
//! 3. Long-header packets carrying any version not in
//!    `Config.accepted_versions` (which defaults to QUIC v1 only) always
//!    trigger a Version Negotiation response (RFC 9000 §6 / RFC
//!    8999 §6 / RFC 9368 §6); this is unconditional and requires
//!    no further `Config` opt-in.
//!
//! Stateless responses (Retry, Version Negotiation) are queued on
//! the `Server` and surfaced via `drainStatelessResponse`. The
//! embedder's I/O loop polls for these in addition to per-slot
//! `poll` output and forwards them on the same UDP socket. The
//! queue is bounded — when full, the oldest queued response is
//! dropped to keep ingest latency bounded.
//!
//! All three gates require an embedder-supplied `from` address
//! when calling `feed`. When `from` is null (the embedder didn't
//! capture the peer 4-tuple), the gates degrade to pass-through:
//! the rate limiter does not track the source, no Retry is
//! attempted, and a Version Negotiation response cannot be queued
//! because there is no destination to send it to (the datagram is
//! `dropped` instead). Passing `from` is strongly recommended for
//! any internet-facing deployment.
//!
//! For a hand-rolled loop, see the README. Embedders that just want
//! "bind a socket and serve QUIC" should reach for
//! `quic_zig.transport.runUdpServer` instead — it owns the
//! `std.Io`-based bind / tune / receive / feed / poll / tick / reap
//! cadence. The QNS endpoint at `interop/qns_endpoint.zig` keeps its
//! own bespoke loop because it has interop-specific quirks
//! (deterministic CID prefix, per-testcase wiring); general-purpose
//! embedders should reach for `Server` (server side) or
//! `quic_zig.Client` (client side) first.

const std = @import("std");
const boringssl = @import("boringssl");

const conn_mod = @import("conn/root.zig");
const tls_mod = @import("tls/root.zig");
const wire = @import("wire/root.zig");
const lb_mod = @import("lb/root.zig");
const retry_token_mod = conn_mod.retry_token;
const new_token_mod = conn_mod.new_token;
const lifecycle = conn_mod.lifecycle;

const Connection = conn_mod.Connection;
const ConnectionError = conn_mod.state.Error;
const TransportParams = tls_mod.TransportParams;
const ConnectionId = conn_mod.path.ConnectionId;
const Address = conn_mod.path.Address;
const QlogCallback = conn_mod.QlogCallback;
const RetryTokenKey = conn_mod.RetryTokenKey;
const PreferredAddressTp = tls_mod.transport_params.PreferredAddress;

/// Maximum byte size of a single queued stateless response (Version
/// Negotiation or Retry). Both packet types fit comfortably inside
/// this bound: VN is ~16 bytes plus 4 bytes per advertised version
/// (max 16), and Retry is ~32 bytes plus the token (53 bytes).
const max_stateless_response_bytes: usize = 256;

/// Bound on the stateless-response queue. Reached only when the
/// embedder is feeding faster than they drain; on overflow the
/// oldest VN entry is evicted in preference to any Retry entry, so
/// a flood of unsupported-version probes cannot crowd out Retry
/// responses to legitimate v1 peers. If the queue is full of
/// Retry entries (no VN to evict), the oldest Retry is dropped.
const stateless_response_queue_capacity: usize = 64;

/// What kind of stateless response this entry carries. Used by the
/// queue's overflow eviction policy to prefer dropping VN over
/// Retry when both are queued, since VN traffic is cheaper for
/// peers to retry than Retry round-trips.
pub const StatelessResponseKind = enum {
    version_negotiation,
    retry,
};

const server_observability = @import("server/observability.zig");
const server_dos = @import("server/dos.zig");
const RetryStateEntry = server_dos.RetryStateEntry;
const RetryDecision = server_dos.RetryDecision;
const RetryEcho = server_dos.RetryEcho;
const SourceRateEntry = server_dos.SourceRateEntry;
const LogEventImpl = server_observability.LogEvent;
const LogCallbackImpl = server_observability.LogCallback;
const ConnectionWillCloseCallbackImpl = server_observability.ConnectionWillCloseCallback;
const MetricsSnapshotImpl = server_observability.MetricsSnapshot;
const RateLimitSnapshotImpl = server_observability.RateLimitSnapshot;

/// One queued stateless server response (VN or Retry), held by
/// value so the embedder can drain across multiple `feed` calls.
/// Re-exported as `Server.StatelessResponse`.
const StatelessResponseImpl = struct {
    /// Where to send the response. Always set — `feed` only queues
    /// stateless responses when `from` is non-null because there is
    /// no destination to send to otherwise.
    dst: Address,
    /// Length of the valid bytes prefix in `bytes`.
    len: usize,
    /// Whether this is a Version Negotiation or Retry response.
    /// Drives queue-overflow eviction policy.
    kind: StatelessResponseKind = .version_negotiation,
    bytes: [max_stateless_response_bytes]u8 = @splat(0),

    /// Borrowed view of the encoded packet. Valid until the next
    /// `drainStatelessResponse` call returns this entry by value.
    pub fn slice(self: *const StatelessResponseImpl) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Maximum number of routing CIDs a slot tracks at once. Bounded
/// by the peer's `active_connection_id_limit` (default 8 in quic_zig);
/// 32 leaves headroom for embedders that lift the limit and for
/// in-flight retires, while keeping the router a fixed, alloc-free
/// slot footprint. If a `Connection` ever issues more than this
/// many active SCIDs, `resyncSlotCids` asserts in debug builds and
/// truncates in release — bump this constant if you bump
/// `active_connection_id_limit` toward 32 or beyond.
const max_tracked_cids_per_slot: usize = 32;

/// Idle threshold (microseconds) past which a `SourceRateEntry`
/// whose three counter windows have all elapsed is also considered
/// stale on the bandwidth-bucket axis and may be pruned. Five
/// seconds is comfortably longer than the default
/// `source_rate_window_us` (one second), so a source seen recently
/// enough to keep its bucket warm survives `pruneSourceRate` even
/// when its Initial / VN / log windows have aged out. Hardening
/// guide §4.1 token-bucket.
// INTERNAL: pub for server/ sibling access; not part of the embedder API.
pub const bandwidth_idle_threshold_us: u64 = 5_000_000;

/// Length-prefixed packed CID key used as the `cid_table` HashMap
/// key. Byte 0 is the CID length (1..20); bytes 1..1+len are the
/// CID material; bytes past `len` are zeroed so the key compares
/// by value.
// INTERNAL: pub for server/ sibling access; not part of the embedder API.
pub const CidKey = [21]u8;

fn cidKeyFromSlice(cid: []const u8) CidKey {
    // Defensive: callers (peekDcidForServer, ConnectionId.slice, etc.)
    // already bound CID length to ≤ 20 via header parse and config
    // validation, but we clamp here so a future caller that forgets
    // can't reach a buffer overflow on a peer-controlled length.
    const n = @min(cid.len, 20);
    var k: CidKey = @splat(0);
    k[0] = @intCast(n);
    @memcpy(k[1 .. 1 + n], cid[0..n]);
    return k;
}

fn cidKeyFromConnectionId(cid: ConnectionId) CidKey {
    return cidKeyFromSlice(cid.bytes[0..cid.len]);
}

const server_config = @import("server/config.zig");
/// Alt-address advertisement config for `Config.preferred_address`;
/// declared in server/config.zig.
pub const PreferredAddressConfig = server_config.PreferredAddressConfig;
const RateLimitImpl = server_config.RateLimit;
const EarlyDataImpl = server_config.EarlyData;
const ConfigImpl = server_config.Config;
const TlsReloadImpl = server_config.TlsReload;

/// One slot in the server's per-connection table. The `Connection`
/// is heap-allocated so the embedder can hold stable pointers across
/// `Server.feed` / `Server.poll` calls. Re-exported as `Server.Slot`.
const SlotImpl = struct {
    /// The owned connection. Embedders may write to streams, call
    /// `sendDatagram`, or read events on this directly.
    conn: *Connection,
    /// The DCID the client picked on its very first Initial. Held
    /// in addition to `tracked_cids` because the peer may keep using
    /// it for several flights before switching to a server-issued
    /// SCID, and the router needs to recognize it from the very
    /// first datagram before `Connection.localScids` has populated.
    initial_dcid: ConnectionId,
    /// CIDs currently registered in `Server.cid_table` for this
    /// slot. Bounded — a slot's working set never exceeds the peer's
    /// `active_connection_id_limit` plus a small in-flight margin.
    /// Slots 0..tracked_cid_count are valid.
    tracked_cids: [max_tracked_cids_per_slot]ConnectionId = @splat(.{}),
    tracked_cid_count: u8 = 0,
    /// Source address most recently observed for this slot, or null
    /// if the embedder didn't pass one. Used as a routing hint for
    /// the rate limiter on connection close.
    peer_addr: ?Address = null,
    /// Last time `feed` saw any datagram for this slot. Embedders
    /// can use this to enforce idle timeouts beyond what QUIC's own
    /// idle timer covers.
    last_activity_us: u64 = 0,
    /// Server-local monotonic id assigned at slot creation. Stable
    /// for the slot's lifetime; embedders can use this as the
    /// primary key in operational logs and trace correlation
    /// without depending on peer-chosen CIDs.
    slot_id: u64,
    /// W3C traceparent trace-id (16 bytes), or null if the embedder
    /// has not associated a trace with this slot. Embedders set via
    /// `setTraceContext`; quic_zig itself never reads it.
    trace_id: ?[16]u8 = null,
    /// W3C traceparent parent-span-id (8 bytes), or null.
    parent_span_id: ?[8]u8 = null,
    /// TLS-context generation this slot was opened against. Set to
    /// `Server.current_generation` at `openSlotFromInitial` time and
    /// never mutated afterward. Drives draining-context refcount
    /// bookkeeping in `Server.reap`: when a slot is reaped, its
    /// generation tells us which draining context (if any) loses a
    /// reference.
    tls_generation: u32 = 0,
    /// True once this slot has queued its single NEW_TOKEN frame.
    /// `Server.feed` flips this on the first datagram routed to a
    /// slot whose connection has just confirmed the handshake (so
    /// every subsequent datagram skips the mint cost). Stays false
    /// for the slot's lifetime when `Server.new_token_key` is null.
    new_token_emitted: bool = false,

    /// Embedder-owned per-connection pointer; quic_zig never reads or
    /// frees it. Set it when `feed` reports `.accepted` (the new slot is
    /// at the back of `Server.slots`) to hang application state — an
    /// HTTP/3 session, routing context, metrics — off the slot without
    /// maintaining a parallel `slot_id`-keyed map. Still valid inside
    /// `Config.on_connection_will_close`, which is the last safe place
    /// to release whatever it points at.
    user_data: ?*anyopaque = null,

    /// True once the post-handshake CID auto-replenish ran for this
    /// slot (see `Config.auto_replenish_connection_ids`). Latched even
    /// when the top-up mints zero CIDs so the check is one branch per
    /// feed.
    cids_replenished: bool = false,

    /// RFC 9368 §6 multi-Initial pre-parse state. Non-null only while
    /// a multi-version server is still waiting for a fragmented
    /// ClientHello to complete so it can decide on a compatible-
    /// version upgrade. Allocated at slot-open time when
    /// `openSlotFromInitial`'s single-shot pre-parse reports the CH
    /// is incomplete; freed once the CH completes (decision applied)
    /// or the per-slot Initial budget is exhausted (fallback to wire
    /// version). Stays null for the rest of the slot's life — it is
    /// strictly a bootstrap construct.
    pending_upgrade: ?*PendingUpgradeState = null,

    /// Index into the `runUdpServer`-owned listener-socket array
    /// recording which socket most recently received an authenticated
    /// datagram for this slot. 0 = primary socket; 1+ = alt-listener
    /// sockets the loop bound from `Config.preferred_address`. The
    /// outbound drain consults this so replies follow the path the
    /// peer is currently sending on (RFC 9000 §5.1.1 server-initiated
    /// migration: pre-migration the client addresses the primary
    /// socket; post-migration it addresses the preferred-address
    /// alt-port). Embedders running their own loop ignore this
    /// field; nothing in the core transport reads it.
    last_recv_socket_idx: u8 = 0,

    /// Attach a W3C tracecontext to this slot. Embedders typically
    /// call this after `Server.feed` returns `.accepted` and the
    /// upstream service has assigned trace identifiers. quic_zig does
    /// not interpret these bytes — they are pure metadata for
    /// embedder-side correlation.
    pub fn setTraceContext(
        self: *SlotImpl,
        trace_id: [16]u8,
        parent_span_id: [8]u8,
    ) void {
        self.trace_id = trace_id;
        self.parent_span_id = parent_span_id;
    }
};

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
const PendingUpgradeState = struct {
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

/// Bookkeeping for one TLS context that has been swapped out by
/// `Server.replaceTlsContext` but still has live slots referencing it
/// via per-connection SSL handles. The entry is `deinit`-ed and
/// dropped when `refcount` hits zero on reap.
const DrainingTlsEntry = struct {
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

/// Outcome of feeding a single datagram to the server. Re-exported
/// as `Server.FeedOutcome`. The variants distinguish reasons an
/// embedder might want to alert on (`rate_limited`, `table_full`,
/// `version_negotiated`, `retry_sent`) from the generic drop bucket
/// (`dropped`).
const FeedOutcomeImpl = enum {
    /// The datagram was routed to an existing connection and
    /// processed.
    routed,
    /// The datagram opened a brand-new connection. The newly created
    /// `Slot` is at the back of `Server.slots`.
    accepted,
    /// Generic drop — empty datagram, unroutable bytes that aren't
    /// an Initial, malformed header, expired or invalid Retry token,
    /// or `openSlotFromInitial` failed (malformed header, TLS
    /// hiccup). Silently dropped per RFC 9000 §10.3.
    dropped,
    /// Per-source rate limiter rejected this Initial; the source's
    /// recent budget is exhausted within the configured window.
    /// Embedders should treat a sustained stream of these from the
    /// same source as DoS-flood evidence.
    rate_limited,
    /// `max_concurrent_connections` reached. The slot table is
    /// full; new Initials are dropped until existing slots are
    /// reaped.
    table_full,
    /// The datagram carried a long-header packet with a version
    /// that is not in `Config.accepted_versions`. A Version Negotiation
    /// response was queued for the embedder to drain via
    /// `drainStatelessResponse`. No `Connection` was created.
    /// RFC 9000 §6 / RFC 8999 §6 / RFC 9368 §6.
    version_negotiated,
    /// `Config.retry_token_key` is set and this Initial either
    /// carried no token or carried one that is not the one we
    /// would have minted for this source. A fresh Retry packet was
    /// queued for the embedder to drain. RFC 9000 §8.1.2. No
    /// `Connection` was created — the peer must echo the Retry's
    /// SCID and token in a subsequent Initial to proceed.
    retry_sent,
};

/// Errors produced by `Server.init` and `Server.feed`. `feed` only
/// returns `OutOfMemory` directly — per-connection errors are
/// suppressed so a malformed datagram from one peer cannot tear down
/// the server. Re-exported as `Server.Error`.
const ErrorImpl = error{
    OutOfMemory,
    InvalidConfig,
    RandFailed,
} || boringssl.tls.Error;

/// I/O-agnostic QUIC server. Owns the TLS context, the connection
/// table, and the CID-to-slot routing table. The embedder owns the
/// UDP socket and the clock.
///
/// Lifecycle:
///   1. `init` builds the TLS context and pre-allocates the slot +
///      routing tables.
///   2. The embedder repeatedly calls `feed(bytes, from, now_us)`
///      on every received datagram, then calls `poll(out_buf,
///      now_us)` in a loop on every live slot to drain queued
///      packets.
///   3. `tick(now_us)` drives time-based recovery. Embedders should
///      call it on every loop iteration regardless of I/O.
///   4. `reap()` reclaims closed slots periodically.
///   5. `shutdown` queues `CONNECTION_CLOSE` on every live slot;
///      `deinit` reclaims memory.
pub const Server = struct {
    /// Re-exports of the helper types so `Server.Config`,
    /// `Server.Slot`, `Server.FeedOutcome`, `Server.StatelessResponse`,
    /// `Server.TlsReload`, `Server.Error`, and the observability
    /// types all resolve from the public API surface. The top-level
    /// definitions remain authoritative.
    pub const Config = ConfigImpl;
    pub const Slot = SlotImpl;
    pub const FeedOutcome = FeedOutcomeImpl;
    pub const StatelessResponse = StatelessResponseImpl;
    pub const TlsReload = TlsReloadImpl;
    pub const RateLimit = RateLimitImpl;
    pub const EarlyData = EarlyDataImpl;
    pub const Error = ErrorImpl;
    pub const LogEvent = LogEventImpl;
    pub const LogCallback = LogCallbackImpl;
    pub const ConnectionWillCloseCallback = ConnectionWillCloseCallbackImpl;
    pub const MetricsSnapshot = MetricsSnapshotImpl;
    pub const RateLimitSnapshot = RateLimitSnapshotImpl;

    /// Idle timeout (ms) `init` substitutes when the embedder leaves
    /// `transport_params.max_idle_timeout_ms` at 0 and does not set
    /// `Config.allow_no_idle_timeout`. 30s matches every quick-start
    /// example and the README production checklist; it keeps idle /
    /// half-open connections from living forever on an internet-facing
    /// listener.
    pub const default_server_idle_timeout_ms: u64 = 30_000;

    allocator: std.mem.Allocator,
    tls_ctx: boringssl.tls.Context,
    /// True when `tls_ctx` is Server-owned and must be torn down by
    /// Server lifecycle paths.
    owns_tls: bool,
    /// Borrowed ALPN list captured from `Config.alpn_protocols` at
    /// `init` time. Used by `replaceTlsContext({.pem = ...})` to
    /// reconstruct the new context with the same ALPN preference
    /// order. Embedders that need to change the ALPN list across a
    /// reload must use the `.override` variant.
    alpn_protocols: []const []const u8,
    /// Borrowed mTLS client-CA bundle captured from
    /// `Config.client_ca_pem` at `init` time (null when mTLS is
    /// off). Used by `replaceTlsContext({.pem = ...})` to carry the
    /// verification posture onto the replacement context, so the
    /// caller must keep the bytes alive for the lifetime of the
    /// server.
    client_ca_pem: ?[]const u8,
    transport_params: TransportParams,
    max_concurrent_connections: u32,
    local_cid_len: u8,
    /// QUIC-LB factory built from `Config.quic_lb` at `init` time.
    /// Null when QUIC-LB is disabled; in that case all SCIDs are
    /// drawn directly from BoringSSL's CSPRNG (the secure-by-default
    /// path). When set, both initial-Slot SCIDs (in
    /// `openSlotFromInitial`) and Retry SCIDs (in
    /// `mintAndQueueRetry`) flow through `lb_factory.mint`.
    lb_factory: ?lb_mod.Factory,
    /// Stateless-reset HMAC key from `Config.stateless_reset_key`.
    /// `secureZero`-ed in `deinit`. When set, `installLbConfig`
    /// auto-pushes NEW_CONNECTION_ID frames to live slots; null
    /// means rotation is "lazy" (peers retain existing CIDs until
    /// they organically retire).
    stateless_reset_key: ?conn_mod.stateless_reset.Key,
    qlog_callback: ?QlogCallback,
    qlog_user_data: ?*anyopaque,
    log_callback: ?LogCallbackImpl,
    log_user_data: ?*anyopaque,
    on_connection_will_close: ?ConnectionWillCloseCallbackImpl,
    on_connection_will_close_user_data: ?*anyopaque,
    early_data_application_context: []const u8,
    auto_replenish_connection_ids: bool,
    max_auto_replenish_cids: u8,

    /// Live connection slots. Embedders may iterate this between
    /// `feed` / `poll` calls to inspect or mutate connections.
    slots: std.ArrayList(*Slot) = .empty,

    /// Routing table: every CID currently valid as a DCID for some
    /// slot maps to that slot. Updated on `openSlotFromInitial`,
    /// after every `feed` (resync), and on `reap`.
    cid_table: std.AutoHashMapUnmanaged(CidKey, *Slot) = .empty,

    /// Rate limiter state. Empty when the limiter is disabled.
    source_rate_table: std.AutoHashMapUnmanaged(Address, SourceRateEntry) = .empty,
    /// Resolved `Config.initial_source_rate_limit`. Null means the
    /// limiter is disabled.
    max_initials_per_source: ?u64,
    source_rate_window_us: u64,
    source_rate_table_capacity: u32,
    /// Resolved `Config.vn_source_rate_limit`. Null disables
    /// the per-source VN rate limit; otherwise gates VN emission via
    /// the same `source_rate_table` (separate counter pair).
    max_vn_per_source: ?u64,

    /// Per-source Retry bookkeeping. Empty when Retry is disabled.
    /// One entry per peer that earned a Retry packet, dropped once
    /// the peer either successfully validates and a Slot opens
    /// (post-Retry SCID rotates into `cid_table`) or the entry is
    /// evicted on table overflow.
    retry_state_table: std.AutoHashMapUnmanaged(Address, RetryStateEntry) = .empty,
    retry_token_key: ?RetryTokenKey,
    retry_token_lifetime_us: u64,
    retry_state_table_capacity: u32,

    /// Captured `Config.new_token_key`. Null disables NEW_TOKEN
    /// issuance. Hardening guide §4.3 / RFC 9000 §8.1.3.
    new_token_key: ?conn_mod.NewTokenKey,
    /// Captured `Config.new_token_lifetime_us`. Only consulted when
    /// `new_token_key` is non-null.
    new_token_lifetime_us: u64,

    /// Resolved from `Config.early_data` at `init`. Drives the
    /// `early_data_enabled` knob on TLS contexts auto-built by
    /// `replaceTlsContext({.pem = ...})` so reloads preserve the
    /// original 0-RTT posture without forcing the embedder to pass
    /// it again.
    enable_0rtt: bool,

    /// Resolved from `Config.early_data`. Drives the
    /// `bumpClock` call in `feed` so the BoringSSL trampoline has
    /// the latest `now_us` to consult in its
    /// `consumeUsingInternalClock` call.
    early_data_anti_replay: ?*tls_mod.anti_replay.AntiReplayTracker,

    /// Captured `Config.reveal_close_reason_on_wire` — applied to
    /// every Connection the Server creates so the close-reason
    /// redaction posture matches the embedder's choice.
    reveal_close_reason_on_wire: bool,

    /// Captured `Config.max_connection_memory` — threaded onto every
    /// Connection at slot-open time so `tryReserveResidentBytes` has
    /// a per-connection cap. Hardening guide §3.5 / §8.
    max_connection_memory: u64,

    /// Captured `Config.delayed_ack_packet_threshold` — threaded onto
    /// every Connection at slot-open time. RFC 9000 §13.2.1.
    delayed_ack_packet_threshold: u8,

    /// Captured `Config.enable_ecn` — threaded onto every Connection
    /// at slot-open time. RFC 9000 §13.4 IETF ECN signaling. Default
    /// true; flip to false in environments known to bleach ECN bits.
    ecn_enabled: bool,
    /// Captured `Config.pmtud` — applied to every Connection at
    /// slot-open time. RFC 8899 DPLPMTUD.
    pmtud_config: conn_mod.PmtudConfig,

    /// Captured `Config.preferred_address` — used by `openSlotFromInitial`
    /// to auto-build the `preferred_address` transport parameter for
    /// every accepted connection (RFC 9000 §18.2 / §5.1.1) and by
    /// `runUdpServer` to bind alt listener sockets. Null when the
    /// feature is disabled (default).
    preferred_address: ?PreferredAddressConfig,

    /// Resolved `Config.listener_datagram_rate_limit`. Null disables the
    /// listener-level packet rate limit; otherwise gates *every*
    /// inbound datagram (existing-slot routes included) at the very
    /// top of `feed`. Hardening guide §4.1.
    max_datagrams_per_window: ?u64,
    /// Resolved `Config.listener_byte_rate_limit`. Null disables the
    /// listener-level byte rate limit; otherwise gates *every* inbound
    /// datagram by total bytes accumulated within the shared window.
    /// Runs after the packet-count gate at the top of `feed`.
    /// Hardening guide §4.1.
    max_bytes_per_window: ?u64,
    /// Captured `Config.listener_rate_window_us`. Window length shared
    /// by the two listener limiters.
    listener_rate_window_us: u64,
    /// Sliding-window counters for the listener-level caps. Single
    /// global bucket per counter, sharing one window — no per-source
    /// bookkeeping, so they stay cheap even under floods from many
    /// sources.
    listener_rate_count: u32 = 0,
    bytes_in_window: u64 = 0,
    listener_rate_window_start_us: u64 = 0,
    /// Resolved `Config.source_byte_rate_limit`. Null disables
    /// the per-source bandwidth shaper; when set, every datagram that
    /// the global listener gates approve charges `bytes.len` against
    /// the source's token bucket (one second's burst capacity, refills
    /// at the configured rate). Hardening guide §4.1 token-bucket.
    max_bytes_per_source_per_second: ?u64,

    /// Resolved `Config.log_source_rate_limit`. Null
    /// disables the per-source log rate limit. Hardening guide §9.4.
    max_log_events_per_source: ?u64,

    /// Captured `Config.accepted_versions`. Drives both the Version Negotiation
    /// gate (any inbound long-header packet whose declared version is
    /// not in this list earns a VN response listing the entries here)
    /// and the per-Initial version selection in `openSlotFromInitial`
    /// (the slot's connection adopts the matching incoming version).
    versions: []const u32,

    /// Snapshot of the most recent `feed`'s `now_us` argument. Threaded
    /// to `emitLog` so the per-source log rate limit fires its sliding
    /// window against in-feed time even though `emitLog` itself takes
    /// no clock argument. Set at the top of every `feed`; reads are
    /// only valid inside the feed's call frame.
    last_feed_now_us: u64 = 0,

    /// IP-layer ECN codepoint observed on the datagram currently being
    /// processed by `feedWithEcn`. Threaded to `dispatchToSlot` so the
    /// per-Connection `handleWithEcn` call gets the right marking.
    /// `not_ect` outside an active feed; mutating outside `feed*`
    /// (e.g. via test scaffolding) is undefined behavior.
    last_feed_ecn: conn_mod.state.socket_opts_mod.EcnCodepoint = .not_ect,

    /// Bounded FIFO of stateless responses (VN, Retry) queued for
    /// the embedder to drain via `drainStatelessResponse`. Bounded
    /// at `stateless_response_queue_capacity`; on overflow the
    /// oldest entry is evicted to keep ingest latency bounded.
    stateless_responses: std.ArrayList(StatelessResponse) = .empty,

    /// Monotonic, server-local slot id. Bumped on every accepted
    /// slot; stable for the slot's lifetime. NOT a CID — it's purely
    /// a routing key for embedder logs/tracing.
    next_slot_id: u64 = 0,
    /// Monotonic counter stamping every newly-opened slot's
    /// `tls_generation`. Starts at 0 and bumps on each
    /// `replaceTlsContext` call. Slots opened against `tls_ctx` carry
    /// this exact value; slots opened before a swap retain whatever
    /// generation was current when they were created.
    current_generation: u32 = 0,
    /// Pre-swap TLS contexts that were owned by the Server and still
    /// have at least one live slot referencing them via a
    /// per-connection SSL handle. Each entry is `deinit`-ed and
    /// removed in `reap` once its `refcount` reaches zero. Pre-swap
    /// contexts that the embedder originally supplied via
    /// `tls_context_override` are NOT inserted here — the embedder
    /// retains ownership of those.
    draining_tls_contexts: std.ArrayListUnmanaged(DrainingTlsEntry) = .empty,

    // -- observability counters ---------------------------------------
    //
    // All counters are monotonic since `init` and never reset; the
    // embedder takes deltas if they want a rate. They're plain `u64`
    // (not atomic) because `Server` is single-threaded — the embedder
    // serializes their loop on a single thread, so an atomic load is
    // strictly more expensive without buying anything.
    feeds_routed: u64 = 0,
    feeds_accepted: u64 = 0,
    feeds_dropped: u64 = 0,
    feeds_rate_limited: u64 = 0,
    feeds_table_full: u64 = 0,
    feeds_version_negotiated: u64 = 0,
    feeds_retry_sent: u64 = 0,
    feeds_initial_too_small: u64 = 0,
    feeds_vn_rate_limited: u64 = 0,
    /// Datagrams dropped at the listener-level packet rate limit
    /// (`Config.listener_datagram_rate_limit`). Subset of `feeds_dropped`.
    /// Spiking values point at a flood-style attack.
    feeds_listener_rate_limited: u64 = 0,
    /// Datagrams dropped at the listener-level byte rate limit
    /// (`Config.listener_byte_rate_limit`). Subset of `feeds_dropped`.
    /// Spiking values point at a few-but-large bandwidth flood.
    feeds_listener_byte_rate_limited: u64 = 0,
    /// Datagrams dropped at the per-source bandwidth shaper
    /// (`Config.source_byte_rate_limit`). Subset of
    /// `feeds_dropped`. Spiking values point at a single-source
    /// bandwidth abuser that the global listener cap is wide enough
    /// to let through. Hardening guide §4.1 token-bucket.
    feeds_source_bandwidth_limited: u64 = 0,
    /// LogEvents dropped by the per-source log rate limiter
    /// (`Config.log_source_rate_limit`). NOT a subset
    /// of `feeds_dropped` — log emission is a separate side effect
    /// from datagram disposition.
    feeds_log_rate_limited: u64 = 0,
    retries_validated: u64 = 0,
    stateless_responses_evicted: u64 = 0,
    slots_reaped: u64 = 0,
    /// Sticky high-water mark of `stateless_responses.items.len`. Set
    /// in `queueStatelessResponse` *before* the new entry lands in
    /// the queue so it reflects the maximum depth ever observed,
    /// regardless of subsequent drains.
    stateless_queue_high_water: u64 = 0,

    pub fn init(config: Config) Error!Server {
        if (config.alpn_protocols.len == 0) return Error.InvalidConfig;
        if (config.local_cid_len == 0 or config.local_cid_len > 20) return Error.InvalidConfig;
        if (config.tls_cert_pem.len == 0 or config.tls_key_pem.len == 0) return Error.InvalidConfig;
        if (config.client_ca_pem) |ca| {
            if (ca.len == 0) return Error.InvalidConfig;
            // An override context owns its own verification posture;
            // silently ignoring the bundle would leave the embedder
            // believing mTLS is on when it is not.
            if (config.tls_context_override != null) return Error.InvalidConfig;
        }
        if (config.initial_source_rate_limit.resolve(Config.default_initial_source_rate_cap)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.vn_source_rate_limit.resolve(Config.default_vn_source_rate_cap)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.retry_token_key != null) {
            if (config.retry_token_lifetime_us == 0) return Error.InvalidConfig;
            if (config.retry_state_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.new_token_key != null) {
            // NEW_TOKEN with a zero lifetime would expire on the next
            // microsecond — the feature degenerates into "always
            // invalid" but the embedder might never notice. Treat
            // that as misconfiguration.
            if (config.new_token_lifetime_us == 0) return Error.InvalidConfig;
        }
        // Hardening guide §4.1: cap=0 is meaningless for the listener
        // rate limits — it would drop every datagram. Surface it as
        // `InvalidConfig` instead of letting it silently DoS the
        // server itself.
        if (config.listener_datagram_rate_limit.resolve(0)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.listener_rate_window_us == 0) return Error.InvalidConfig;
        }
        if (config.listener_byte_rate_limit.resolve(0)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.listener_rate_window_us == 0) return Error.InvalidConfig;
        }
        // Hardening guide §4.1 token-bucket: cap=0 is meaningless —
        // it would drop every datagram. Surface it as `InvalidConfig`
        // instead of letting it silently DoS the server. The shaper
        // shares the `source_rate_table` with `acceptSourceRate` /
        // `acceptVnRate` / `acceptLogRate`, so the same capacity bound
        // applies; explicit checks here mirror those helpers' shape.
        if (config.source_byte_rate_limit.resolve(0)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.log_source_rate_limit.resolve(Config.default_log_source_rate_cap)) |cap| {
            if (cap == 0) return Error.InvalidConfig;
            if (config.source_rate_window_us == 0) return Error.InvalidConfig;
            if (config.source_rate_table_capacity == 0) return Error.InvalidConfig;
        }
        if (config.quic_lb) |lb_cfg| {
            // Per-field and combined-length bounds from
            // draft-ietf-quic-load-balancers-21 §3 (server_id 1..15,
            // nonce 4..18, combined ≤ 19, config_id 0..6). Surface as
            // `InvalidConfig` so the failure mode matches every other
            // bad-Config case in `Server.init`. All three encoder
            // modes (§5.2 plaintext, §5.4.1 single-pass, §5.4.2
            // four-pass) are now wired — `Factory.mint` dispatches on
            // `(key, combined)` automatically.
            lb_cfg.validate() catch return Error.InvalidConfig;
        }
        // RFC 9000 §18.2 / §5.1.1: a `preferred_address` advertisement
        // requires a stateless-reset key so the seq-1 reset token in
        // the parameter matches the token a future stateless-reset on
        // the alt-CID would produce. The parameter must also point at
        // at least one address — both families null is a misconfiguration.
        if (config.preferred_address) |pa_cfg| {
            if (pa_cfg.ipv4 == null and pa_cfg.ipv6 == null) {
                return Error.InvalidConfig;
            }
            if (config.stateless_reset_key == null) {
                return Error.InvalidConfig;
            }
        }

        // Resolve the on-wire CID length and the transport parameters
        // we'll commit to. With QUIC-LB enabled, the CID length is
        // dictated by the LB configuration (1 + server_id_len +
        // nonce_len), and plaintext mode triggers the SHOULD from
        // draft §3 ¶3 to advertise `disable_active_migration` so peers
        // don't mint extra CIDs through this server (the unkeyed CIDs
        // would leak `server_id` directly on every NEW_CONNECTION_ID).
        var resolved_transport_params = config.transport_params;
        // Secure default: a server that leaves the idle timeout at 0
        // (the struct default, "no idle timer") would keep idle /
        // half-open connections alive forever. Substitute a safe
        // timeout unless the embedder explicitly opts into no-timeout.
        if (resolved_transport_params.max_idle_timeout_ms == 0 and !config.allow_no_idle_timeout) {
            resolved_transport_params.max_idle_timeout_ms = default_server_idle_timeout_ms;
        }
        const resolved_local_cid_len: u8 = if (config.quic_lb) |lb_cfg| blk: {
            if (lb_cfg.isPlaintext() and !resolved_transport_params.disable_active_migration) {
                resolved_transport_params.disable_active_migration = true;
            }
            break :blk lb_cfg.cidLength();
        } else config.local_cid_len;

        // Build the LB factory before any allocation so an AES key
        // setup or CSPRNG-seeded nonce-counter failure short-circuits
        // before we own anything that needs cleanup. Errors are mapped
        // to existing Server-level codes — `AesKeyInvalid` to
        // `InvalidConfig` (the supplied `[16]u8` was somehow refused),
        // CSPRNG draws to `RandFailed`.
        const resolved_lb_factory: ?lb_mod.Factory = if (config.quic_lb) |lb_cfg| blk: {
            const f = lb_mod.Factory.initUnchecked(lb_cfg) catch |err| switch (err) {
                error.AesKeyInvalid => return Error.InvalidConfig,
                error.RandFailure => return Error.RandFailed,
                error.InvalidLbConfig => return Error.InvalidConfig,
                error.BufferTooSmall, error.NonceExhausted => unreachable,
            };
            break :blk f;
        } else null;

        // The version list drives the VN gate and per-slot version
        // adoption; an empty list would mean the server rejects every
        // inbound Initial, which is almost never what an embedder
        // wants. Every entry must be a wire-format version we know
        // how to derive Initial keys for (RFC 9001 §5.2 v1 / RFC
        // 9368 §3.3.1 v2). Reject `version == 0` outright because
        // the wire reserves it for Version Negotiation packets.
        if (config.accepted_versions.len == 0) return Error.InvalidConfig;
        for (config.accepted_versions) |v| {
            if (v == 0) return Error.InvalidConfig;
            if (!wire.initial.isSupportedVersion(v)) return Error.InvalidConfig;
        }

        var tls_ctx: boringssl.tls.Context = undefined;
        var owns_tls = false;
        if (config.tls_context_override) |ctx| {
            tls_ctx = ctx;
        } else {
            tls_ctx = try boringssl.tls.Context.initServer(.{
                .verify = .none,
                .min_version = boringssl.raw.TLS1_3_VERSION,
                .max_version = boringssl.raw.TLS1_3_VERSION,
                .alpn = config.alpn_protocols,
                .early_data_enabled = config.early_data.enabled(),
            });
            errdefer tls_ctx.deinit();
            try tls_ctx.loadCertChainAndKey(config.tls_cert_pem, config.tls_key_pem);
            // mTLS: require and verify a client certificate against
            // the embedder's pinned roots. Rejected during validation
            // when combined with `tls_context_override`.
            if (config.client_ca_pem) |ca| {
                try tls_mod.pem.installTrustAnchors(tls_ctx, ca, .require_peer_cert);
            }
            // Hardening §5.2 / RFC 9001 §5.6: when the embedder
            // installs an `AntiReplayTracker`, hook BoringSSL's
            // pre-resumption early-data callback so duplicate 0-RTT
            // attempts are rejected at the TLS layer (not just at
            // application post-handshake). Only fires on the
            // auto-built path; override-mode embedders own the hook
            // themselves.
            if (config.early_data.antiReplayTracker()) |tracker| {
                try tls_ctx.setAllowEarlyDataCallback(
                    antiReplayEarlyDataTrampoline,
                    @ptrCast(tracker),
                );
            }
            owns_tls = true;
        }

        // SCIDs and Retry SCIDs are minted directly from BoringSSL's
        // CSPRNG — see `mintLocalCid` / `mintAndQueueRetry`. There is
        // no PRNG-from-seed cache: each ID is a fresh
        // `crypto.rand.fillBytes` call so an attacker observing
        // server-issued CIDs can't predict future ones from a finite
        // PRNG state. (Hardening guide §4.5.)

        const slots_initial_capacity: usize = @min(config.max_concurrent_connections, 64);
        var slots: std.ArrayList(*Slot) = .empty;
        slots.ensureTotalCapacity(config.allocator, slots_initial_capacity) catch |e| switch (e) {
            error.OutOfMemory => {
                if (owns_tls) tls_ctx.deinit();
                return Error.OutOfMemory;
            },
        };

        // Pre-size the CID table to roughly initial-slots * average
        // CIDs per slot; saves rehash churn on the first hundred
        // connections without committing pages we don't need.
        var cid_table: std.AutoHashMapUnmanaged(CidKey, *Slot) = .empty;
        cid_table.ensureTotalCapacity(config.allocator, @intCast(slots_initial_capacity * 2)) catch |e| switch (e) {
            error.OutOfMemory => {
                slots.deinit(config.allocator);
                if (owns_tls) tls_ctx.deinit();
                return Error.OutOfMemory;
            },
        };

        return .{
            .allocator = config.allocator,
            .tls_ctx = tls_ctx,
            .owns_tls = owns_tls,
            .alpn_protocols = config.alpn_protocols,
            .client_ca_pem = config.client_ca_pem,
            .transport_params = resolved_transport_params,
            .max_concurrent_connections = config.max_concurrent_connections,
            .local_cid_len = resolved_local_cid_len,
            .lb_factory = resolved_lb_factory,
            .stateless_reset_key = config.stateless_reset_key,
            .qlog_callback = config.qlog_callback,
            .qlog_user_data = config.qlog_user_data,
            .log_callback = config.log_callback,
            .log_user_data = config.log_user_data,
            .on_connection_will_close = config.on_connection_will_close,
            .on_connection_will_close_user_data = config.on_connection_will_close_user_data,
            .early_data_application_context = config.early_data_application_context,
            .auto_replenish_connection_ids = config.auto_replenish_connection_ids,
            .max_auto_replenish_cids = config.max_auto_replenish_cids,
            .slots = slots,
            .cid_table = cid_table,
            .source_rate_table = .empty,
            .max_initials_per_source = config.initial_source_rate_limit.resolve(
                Config.default_initial_source_rate_cap,
            ),
            .max_vn_per_source = config.vn_source_rate_limit.resolve(
                Config.default_vn_source_rate_cap,
            ),
            .source_rate_window_us = config.source_rate_window_us,
            .source_rate_table_capacity = config.source_rate_table_capacity,
            .retry_state_table = .empty,
            .retry_token_key = config.retry_token_key,
            .retry_token_lifetime_us = config.retry_token_lifetime_us,
            .retry_state_table_capacity = config.retry_state_table_capacity,
            .new_token_key = config.new_token_key,
            .new_token_lifetime_us = config.new_token_lifetime_us,
            .enable_0rtt = config.early_data.enabled(),
            .early_data_anti_replay = config.early_data.antiReplayTracker(),
            .reveal_close_reason_on_wire = config.reveal_close_reason_on_wire,
            .max_connection_memory = config.max_connection_memory,
            .delayed_ack_packet_threshold = config.delayed_ack_packet_threshold,
            .ecn_enabled = config.enable_ecn,
            // The listener and bandwidth limiters recommend "off"
            // (envelope-dependent), so `.default` resolves through a
            // zero default cap to null.
            .max_datagrams_per_window = config.listener_datagram_rate_limit.resolve(0),
            .max_bytes_per_window = config.listener_byte_rate_limit.resolve(0),
            .listener_rate_window_us = config.listener_rate_window_us,
            .max_bytes_per_source_per_second = config.source_byte_rate_limit.resolve(0),
            .max_log_events_per_source = config.log_source_rate_limit.resolve(
                Config.default_log_source_rate_cap,
            ),
            .versions = config.accepted_versions,
            .pmtud_config = config.pmtud,
            .preferred_address = config.preferred_address,
            .stateless_responses = .empty,
        };
    }

    /// Install a new QUIC-LB configuration. Subsequent SCID mints
    /// (post-Initial Slot SCIDs and Retry SCIDs) use the new
    /// configuration; the previous factory's key bytes are
    /// `secureZero`-ed before the swap.
    ///
    /// **If `Config.stateless_reset_key` was provided**, this method
    /// ALSO pushes a NEW_CONNECTION_ID frame to every live slot via
    /// `rotateLiveSlotCids`, so peers retire their old CIDs and
    /// migrate to the new-config CIDs on their next datagram. Per-
    /// slot push failures are swallowed (best-effort) — the factory
    /// swap commits regardless.
    ///
    /// **Without `stateless_reset_key`**, the swap is point-in-time
    /// and peers continue using their existing CIDs until they
    /// organically retire them via the existing `connection_ids_needed`
    /// event flow.
    ///
    /// To keep the routing key shape stable for the slot table and
    /// `peekDcidForServer`, the new configuration MUST mint CIDs of
    /// the same length as the configuration the Server was built with
    /// (`Server.local_cid_len`). Mismatched lengths surface as
    /// `Error.InvalidConfig`. This restriction matches typical
    /// rotation flows (key rotation under a fixed deployment shape).
    ///
    /// Errors:
    ///   * `InvalidConfig` — `LbConfig.validate` failed, or the
    ///     resolved `cidLength` doesn't match the server's existing
    ///     `local_cid_len`, or the previous Server was built without
    ///     a `quic_lb` configuration (no factory to rotate).
    ///   * `RandFailed` — CSPRNG nonce-counter seed failed.
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
            _ = self.rotateLiveSlotCids();
        }
    }

    /// Push a fresh NEW_CONNECTION_ID frame to every live slot using
    /// the active LB factory and the configured stateless-reset key.
    /// Each pushed frame's `retire_prior_to` invalidates every
    /// previously-issued local CID on that slot, so the peer
    /// switches to the new CID on its next datagram.
    ///
    /// Returns the number of slots that successfully received a new
    /// CID. Per-slot failures (no LB factory, no stateless-reset
    /// key, CID-issue budget exhausted, factory mint failure,
    /// HMAC error, replenishment rejected) are swallowed so a single
    /// bad slot doesn't abort the rotation. Pre-handshake slots
    /// receive the queued frame but don't transmit it until they
    /// reach 1-RTT — NEW_CONNECTION_ID is a §12.4 / §17 1-RTT-only
    /// frame.
    ///
    /// `installLbConfig` calls this automatically when
    /// `Config.stateless_reset_key` is set; embedders typically
    /// reach for it directly only when proactively pushing CIDs
    /// without a config swap.
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
            self.resyncSlotCids(slot) catch continue;
            rotated += 1;
        }
        return rotated;
    }

    pub fn deinit(self: *Server) void {
        for (self.slots.items) |slot| {
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            if (slot.pending_upgrade) |pu| self.allocator.destroy(pu);
            self.allocator.destroy(slot);
        }
        self.slots.deinit(self.allocator);
        self.cid_table.deinit(self.allocator);
        self.source_rate_table.deinit(self.allocator);
        self.retry_state_table.deinit(self.allocator);
        self.stateless_responses.deinit(self.allocator);
        // Hardening guide §3.5 / §9.4: zero the Retry-token HMAC key
        // before the `Server` struct is released. Even though the
        // memory is about to leave scope, the optimizer can't elide
        // a volatile-backed `secureZero`, so the key bytes don't
        // linger in a freed allocation that the host allocator might
        // reuse for unrelated data (or surface in a core dump).
        if (self.retry_token_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
        // Same hardening rationale for the NEW_TOKEN AES-GCM-256
        // key — a peer-mintable token's worth of crypto state must
        // not linger after the Server struct is freed.
        if (self.new_token_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
        // Same for the QUIC-LB encryption key — `Factory.deinit`
        // zeros the embedded `LbConfig.key` and the nonce counter
        // buffer. No-op for plaintext-mode factories (key was null).
        if (self.lb_factory) |*factory| {
            factory.deinit();
        }
        // And the stateless-reset HMAC key — same hardening
        // rationale as the other secret key fields.
        if (self.stateless_reset_key) |*key| {
            std.crypto.secureZero(u8, key[0..]);
        }
        // Draining contexts always represent ownership the Server
        // took on at swap-time, so they're unconditionally deinit-ed
        // here regardless of `owns_tls` (which only describes the
        // *current* context).
        for (self.draining_tls_contexts.items) |*entry| entry.ctx.deinit();
        self.draining_tls_contexts.deinit(self.allocator);
        if (self.owns_tls) self.tls_ctx.deinit();
        self.* = undefined;
    }

    /// Number of live connections currently in the table.
    pub fn connectionCount(self: *const Server) usize {
        return self.slots.items.len;
    }

    /// Number of CIDs currently registered as routing keys across
    /// all live slots. Useful for tests and metrics; production
    /// embedders rarely need this.
    pub fn routingTableSize(self: *const Server) usize {
        return self.cid_table.count();
    }

    /// Iterator over the live slots. Embedders can use this to push
    /// outgoing data, drain events, or call `Server.poll`.
    pub fn iterator(self: *Server) []*Slot {
        return self.slots.items;
    }

    /// Demultiplex `bytes` to the right connection, opening a new
    /// one for fresh long-header Initials. `now_us` is the monotonic
    /// clock in microseconds (any monotonic origin works as long as
    /// it's consistent across calls).
    ///
    /// Stateless responses (Version Negotiation, Retry) are queued
    /// internally; the embedder must drain them via
    /// `drainStatelessResponse` and forward them on the same UDP
    /// socket the datagram came in on.
    pub fn feed(
        self: *Server,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!FeedOutcome {
        return self.feedWithEcn(bytes, from, .not_ect, now_us);
    }

    /// Like `feed`, but also carries the IP-layer ECN codepoint the
    /// embedder peeled off the datagram's TOS byte. The codepoint
    /// flows down to `Connection.handleWithEcn` so per-PN-space ECN
    /// counters can be bumped on successful decrypt (RFC 9000
    /// §13.4.1). Embedders that aren't running cmsg parsing should
    /// keep using `feed` (which passes `not_ect`).
    pub fn feedWithEcn(
        self: *Server,
        bytes: []u8,
        from: ?Address,
        ecn: conn_mod.state.socket_opts_mod.EcnCodepoint,
        now_us: u64,
    ) Error!FeedOutcome {
        // Set the ingress ECN for any subsequent dispatch into a
        // slot's Connection. Stateless / pre-slot processing
        // (Version Negotiation, Retry minting, table_full) doesn't
        // care about the marking — only the per-Connection handlers
        // do. Cleared at function exit so a malformed/dropped feed
        // doesn't leave a stale codepoint visible to the next call.
        self.last_feed_ecn = ecn;
        defer self.last_feed_ecn = .not_ect;
        // Stamp the feed's `now_us` so `emitLog` can run its per-source
        // log rate limit against in-feed time without taking a separate
        // clock argument.
        self.last_feed_now_us = now_us;
        // Push the same `now_us` to the anti-replay tracker so its
        // BoringSSL `allow_early_data` trampoline (which has no other
        // path to a monotonic clock) ages entries against
        // Server-driven time. No-op when 0-RTT or anti-replay isn't
        // configured.
        if (self.early_data_anti_replay) |tracker| tracker.bumpClock(now_us);
        // Hardening guide §4.1: listener-level packet + byte rate
        // limits. Runs *before* the empty-bytes check, before the
        // 1200-byte Initial size gate, before slot lookup — every
        // datagram entering the server passes here so a flood from
        // many sources can't bleed through any of the per-source /
        // per-slot gates downstream. Single global bucket on a
        // sliding-by-reset window shared by both caps: cheap, and
        // good enough for DoS deflection (the per-source gates own
        // attribution; this owns the firehose).
        //
        // Order is packet-count first, byte-budget second so a
        // few-but-large flood that also exceeds the packet cap is
        // accounted to the packet counter (the cheaper signal to
        // alert on).
        if (self.max_datagrams_per_window != null or self.max_bytes_per_window != null) {
            const elapsed = now_us -% self.listener_rate_window_start_us;
            const window_reset =
                elapsed >= self.listener_rate_window_us or
                (self.listener_rate_count == 0 and self.bytes_in_window == 0);
            if (window_reset) {
                self.listener_rate_count = 0;
                self.bytes_in_window = 0;
                self.listener_rate_window_start_us = now_us;
            }
            if (self.max_datagrams_per_window) |cap| {
                if (self.listener_rate_count >= cap) {
                    self.feeds_listener_rate_limited += 1;
                    self.feeds_dropped += 1;
                    return .dropped;
                }
                self.listener_rate_count += 1;
            }
            if (self.max_bytes_per_window) |cap| {
                // Increment before the gate so the gate fires on the
                // byte that would push the budget over, not after.
                self.bytes_in_window += bytes.len;
                if (self.bytes_in_window > cap) {
                    self.feeds_listener_byte_rate_limited += 1;
                    self.feeds_dropped += 1;
                    return .dropped;
                }
            }
        }
        if (bytes.len == 0) {
            self.feeds_dropped += 1;
            return .dropped;
        }

        // Hardening guide §4.1 token-bucket: per-source bandwidth
        // shaper. Runs after the global listener gates (so the global
        // aggregate ceiling still bounds total bandwidth even when
        // every source has a full bucket) but before slot lookup (so
        // an in-flight handshake datagram from a misbehaving source
        // is gated too). Charge happens only when `from` is provided
        // — null-source feeds bypass the limiter for the same reason
        // as the per-source Initial / VN / log gates.
        if (self.max_bytes_per_source_per_second) |cap| {
            if (from) |addr| {
                if (!self.acceptSourceBandwidth(addr, bytes.len, cap, now_us)) {
                    self.feeds_source_bandwidth_limited += 1;
                    self.feeds_dropped += 1;
                    // Reuse `feed_rate_limited`: `recent_count` carries
                    // the dropped datagram's byte length so embedders
                    // can correlate the log with the bucket-empty
                    // condition without a new variant.
                    self.emitLog(.{ .feed_rate_limited = .{
                        .peer = addr,
                        .recent_count = std.math.lossyCast(u32, bytes.len),
                    } });
                    return .dropped;
                }
            }
        }

        // RFC 9000 §14: a server MUST discard a QUIC v1 Initial packet
        // carried in a UDP datagram with a payload smaller than 1200
        // bytes. Enforced *before* slot lookup so the rule applies
        // both to new-connection-creating Initials and to in-flight
        // handshake Initials that would otherwise route to an existing
        // slot.
        //
        // Gated on `Config.accepted_versions` membership so unsupported-version
        // probes still flow into the Version Negotiation path below
        // (whose response is governed by RFC 9000 §6, not §14). The
        // size check keys off the leading packet's long-header type
        // bits — coalesced datagrams whose first packet is Initial
        // are the typical adversarial pattern (single short Initial
        // used to mint server state cheaply); a pathological
        // inner-Initial would still ride a leading packet large
        // enough to push the datagram past 1200, so this covers the
        // practical attack surface.
        if (peekLongHeaderIds(bytes)) |ids| {
            if (isInitialLongHeader(bytes, ids.version) and
                bytes.len < conn_mod.state.min_quic_udp_payload_size and
                self.versionAccepted(ids.version))
            {
                self.feeds_initial_too_small += 1;
                self.feeds_dropped += 1;
                return .dropped;
            }
        }

        // Existing connection? Hash table lookup, O(1).
        if (self.findSlotForDatagram(bytes)) |slot| {
            slot.last_activity_us = now_us;
            // RFC 9368 §6: when a multi-Initial fragmented ClientHello
            // is in flight, the upgrade decision lands on a later
            // Initial than the slot-creating one. Try to advance the
            // pending reassembler before `dispatchToSlot` ingests this
            // datagram; if the CH completes here we update the
            // outbound transport_params (so the EE the server is about
            // to emit advertises chosen=upgrade) and stash the pending
            // version flip for `dispatchToSlot` to apply post-handle.
            //
            // Failure here is purely advisory — the pending state is
            // dropped and the connection continues under the wire
            // version, which is always spec-compliant.
            if (slot.pending_upgrade != null) {
                self.advancePendingUpgrade(slot, bytes);
            }
            try self.dispatchToSlot(slot, bytes, from, now_us);
            // Re-sync the slot's outbound routing hint from the
            // connection's active path — RFC 9000 §9 / §9.6: the
            // server MUST NOT respond to a peer-initiated migration
            // before the handshake is confirmed, and the
            // `Connection.handlePeerAddressChange` gate enforces
            // that. If the gate refused (handshake incomplete /
            // anti-replay etc.), `activePath().path.peer_addr`
            // stays at the previously-validated tuple even when
            // `from` carries a new one. Reading the slot's
            // `peer_addr` from the canonical path AFTER dispatch
            // (rather than blindly stamping `from` BEFORE dispatch)
            // means the loop's outbound drain doesn't follow a
            // peer's pre-handshake rebind that the connection
            // refused. The routing hint must keep pointing at the
            // last validated tuple until the connection's migration
            // gate accepts the new one; otherwise the next outbound
            // packet could carry ACK + STREAM data on an unvalidated
            // path instead of first proving it with PATH_CHALLENGE.
            const ap = slot.conn.activePath();
            if (ap.peer_addr_set) {
                slot.peer_addr = ap.path.peer_addr;
            } else if (from) |addr| {
                // First-ever authenticated datagram: the connection
                // hasn't latched a peer_addr yet (`peer_addr_set` is
                // false). Use the inbound source as the routing hint
                // until the next datagram makes it canonical.
                slot.peer_addr = addr;
            }
            try self.resyncSlotCids(slot);
            // RFC 9000 §8.1.3: once the handshake is confirmed, the
            // server MAY issue NEW_TOKEN frames usable on the peer's
            // future first Initial. We emit exactly one per session
            // (the simplest policy that still removes the Retry
            // round-trip for returning clients); the slot's
            // `new_token_emitted` flag latches at first issuance.
            self.maybeIssueNewToken(slot, from, now_us);
            // Same trigger as NEW_TOKEN: first post-handshake feed
            // tops up the migration CID inventory (see
            // Config.auto_replenish_connection_ids). Before the
            // resync of the NEXT feed the new CIDs are queued but not
            // yet routable; that window only delays a peer's first
            // migration by one datagram.
            self.maybeReplenishConnectionIds(slot);
            self.feeds_routed += 1;
            return .routed;
        }

        // Long-header packets reach the version-negotiation gate
        // first: any long-header packet whose declared version is
        // not in `Config.accepted_versions` earns a VN response, regardless
        // of the long-type bits. Per RFC 9000 §6 / RFC 9368 §6 this
        // catches non-Initial long-header probes (0-RTT, Handshake)
        // too.
        if (peekLongHeaderIds(bytes)) |ids| {
            if (!self.versionAccepted(ids.version)) {
                if (from) |addr| {
                    // Per-source VN-rate gate (hardening guide §4.4):
                    // legitimate clients fix their version and retry
                    // with one of our supported versions after one VN
                    // response, so even a small cap is non-disruptive.
                    // This blunts the VN-flood amplification surface
                    // where one source fills the global
                    // stateless-response queue.
                    if (self.max_vn_per_source) |cap| {
                        if (!self.acceptVnRate(addr, cap, now_us)) {
                            self.feeds_vn_rate_limited += 1;
                            self.feeds_dropped += 1;
                            self.emitLog(.{ .feed_rate_limited = .{
                                .peer = addr,
                                .recent_count = if (self.source_rate_table.get(addr)) |e|
                                    e.vn_count
                                else
                                    std.math.lossyCast(u32, cap),
                            } });
                            return .dropped;
                        }
                    }
                    self.queueVersionNegotiation(addr, bytes) catch {
                        self.feeds_dropped += 1;
                        return .dropped;
                    };
                    self.feeds_version_negotiated += 1;
                    self.emitLog(.{ .version_negotiated = .{
                        .peer = addr,
                        .requested_version = ids.version,
                    } });
                    return .version_negotiated;
                }
                // No destination address — we can't send a VN, so
                // the datagram is dropped per the documented
                // pass-through behavior.
                self.feeds_dropped += 1;
                return .dropped;
            }
        }

        // New connection candidate: must be a long-header Initial
        // under one of our supported versions. The version-list gate
        // upstream already filtered unsupported versions to VN; here
        // we just translate the long-header type bits to an abstract
        // `LongType` and require Initial. We can't use `peekLongHeaderIds`
        // here because it rejects DCID-len > 20 — the source-rate
        // gate downstream wants to charge those datagrams too.
        if (bytes.len < 5 or (bytes[0] & 0x80) == 0) {
            self.feeds_dropped += 1;
            return .dropped;
        }
        const candidate_version = std.mem.readInt(u32, bytes[1..5], .big);
        if (!isInitialLongHeader(bytes, candidate_version)) {
            self.feeds_dropped += 1;
            return .dropped;
        }
        if (self.slots.items.len >= self.max_concurrent_connections) {
            self.feeds_table_full += 1;
            self.emitLog(.{ .table_full = .{ .peer = from } });
            return .table_full;
        }

        // Source-rate gate runs *before* Retry / TLS / Connection
        // setup so an attacker spraying Initials from one address
        // can't burn server CPU minting state we'll throw away.
        if (self.max_initials_per_source) |cap| {
            if (from) |addr| {
                if (!self.acceptSourceRate(addr, cap, now_us)) {
                    self.feeds_rate_limited += 1;
                    // Surface the bucket count *after* the rejection
                    // so the embedder sees the value the gate just
                    // tripped against.
                    const recent_count = if (self.source_rate_table.get(addr)) |e|
                        e.count
                    else
                        std.math.lossyCast(u32, cap);
                    self.emitLog(.{ .feed_rate_limited = .{
                        .peer = addr,
                        .recent_count = recent_count,
                    } });
                    return .rate_limited;
                }
            }
        }

        // Retry / NEW_TOKEN gate runs before the Connection is
        // allocated. `.sent` queues a Retry; `.drop` rejects a
        // wrong-source token; `.echo` accepts a Retry-validated
        // Initial; `.new_token_skip` accepts a NEW_TOKEN-validated
        // Initial directly (no Retry round-trip). `.none` is the
        // gate-disabled fall-through.
        var retry_ctx: ?RetryEcho = null;
        if (self.retry_token_key != null or self.new_token_key != null) {
            if (from) |addr| {
                switch (try self.applyRetryGate(addr, bytes, now_us)) {
                    .sent => {
                        self.feeds_retry_sent += 1;
                        // The Retry state table now holds the per-source
                        // entry just minted. Surface its SCID length.
                        const scid_len = if (self.retry_state_table.get(addr)) |e| e.retry_scid_len else self.local_cid_len;
                        self.emitLog(.{ .retry_minted = .{
                            .peer = addr,
                            .scid_len = scid_len,
                        } });
                        return .retry_sent;
                    },
                    .drop => {
                        self.feeds_dropped += 1;
                        return .dropped;
                    },
                    .none => {},
                    .echo => |echo| retry_ctx = echo,
                    .new_token_skip => {
                        // The peer presented a valid NEW_TOKEN; treat
                        // them as already address-validated and
                        // proceed to slot creation as if no Retry was
                        // ever required. No `retry_ctx` is set —
                        // there is no Retry SCID to bind to and the
                        // initial transport parameters skip the
                        // `retry_source_connection_id` echo.
                    },
                }
            }
            // No `from`: pass-through to the legacy accept path so
            // that null-address feed still works for in-process
            // tests; production embedders are expected to pass
            // `from` to engage Retry.
        }

        const slot = self.openSlotFromInitial(bytes, from, now_us, retry_ctx) catch |err| switch (err) {
            error.OutOfMemory => return Error.OutOfMemory,
            // Anything else (TLS init, malformed Initial, Connection
            // setup) is a per-peer hiccup — drop the datagram and
            // keep the server alive. The slot was never registered,
            // so cid_table stays clean.
            else => {
                self.feeds_dropped += 1;
                return .dropped;
            },
        };
        // Successful Retry round-trip: clear the per-source bucket
        // so the next Initial from this address (e.g. a new
        // connection) starts fresh.
        if (retry_ctx != null) {
            if (from) |addr| _ = self.retry_state_table.remove(addr);
            self.retries_validated += 1;
        }
        try self.dispatchToSlot(slot, bytes, from, now_us);
        try self.resyncSlotCids(slot);
        // Same NEW_TOKEN issuance check the routed path runs — a
        // pathological 0-RTT-only handshake might confirm in the
        // very first received datagram, in which case there is no
        // later "routed" feed to trip the issuance check.
        self.maybeIssueNewToken(slot, from, now_us);
        self.maybeReplenishConnectionIds(slot);
        self.feeds_accepted += 1;
        // Emit *after* slot is fully visible in the routing table so
        // the callback can index into `slots` if it wants to.
        if (from) |addr| {
            self.emitLog(.{ .connection_accepted = .{
                .peer = addr,
                .slot_count = self.slots.items.len,
            } });
        }
        return .accepted;
    }

    /// Drain the next stateless response the server has queued, if
    /// any. The returned `StatelessResponse` carries an owned copy
    /// of the encoded bytes plus the destination address — the
    /// embedder forwards it on the same UDP socket the source
    /// datagram came in on. Returns null when the queue is empty.
    pub fn drainStatelessResponse(self: *Server) ?StatelessResponse {
        if (self.stateless_responses.items.len == 0) return null;
        return self.stateless_responses.orderedRemove(0);
    }

    /// Number of stateless responses currently queued. Useful for
    /// tests and metrics.
    pub fn statelessResponseCount(self: *const Server) usize {
        return self.stateless_responses.items.len;
    }

    /// Poll one outgoing datagram for `slot` into `dst`. Returns the
    /// number of bytes written, or null if nothing is queued. Thin
    /// wrapper around `Connection.poll` — embedders that need the
    /// full path-aware `OutgoingDatagram` should call
    /// `slot.conn.pollDatagram` directly.
    pub fn poll(
        self: *Server,
        slot: *Slot,
        dst: []u8,
        now_us: u64,
    ) ConnectionError!?usize {
        _ = self;
        return try slot.conn.poll(dst, now_us);
    }

    /// Drive time-based recovery on every live slot. Idempotent and
    /// cheap — call it on every loop iteration. Terminal-closed slots
    /// are skipped (their deadlines have already fired and there's
    /// nothing more for `tick` to do); call `reap` periodically to
    /// reclaim them. RFC 9000 §10.2.1/§10.2.2 closing- and
    /// draining-state slots stay in the loop so their deadlines fire
    /// and the connection eventually transitions to terminal closed.
    pub fn tick(self: *Server, now_us: u64) ConnectionError!void {
        for (self.slots.items) |slot| {
            if (slot.conn.closeState() == .closed) continue;
            try slot.conn.tick(now_us);
        }
    }

    /// Earliest pending timer deadline across every live slot, or null
    /// when no slot has one armed. Event loops size their socket
    /// receive timeout with this instead of a fixed tick: sleep until
    /// `min(next inbound datagram, deadline.at_us)`, then call `tick`.
    /// O(slots) per call — cheap enough per loop iteration, and it
    /// spares every embedder the slot-walk boilerplate.
    pub fn nextTimerDeadline(self: *const Server, now_us: u64) ?conn_mod.state.TimerDeadline {
        var best: ?conn_mod.state.TimerDeadline = null;
        for (self.slots.items) |slot| {
            const deadline = slot.conn.nextTimerDeadline(now_us) orelse continue;
            if (best == null or deadline.at_us < best.?.at_us) best = deadline;
        }
        return best;
    }

    /// Reap any *terminally-closed* slots from the table. Returns the
    /// number of slots reclaimed. Iterates back-to-front and uses
    /// `swapRemove`, so reaping N closed slots is O(N), not O(N²).
    /// Each reaped slot drops every CID it owned from `cid_table`.
    /// If a reaped slot was opened against a draining TLS context,
    /// its draining-entry refcount is decremented; when the count
    /// reaches zero the draining context is `deinit`-ed and removed
    /// from `draining_tls_contexts`.
    ///
    /// RFC 9000 §10.2 ¶5 mandates that closing and draining states
    /// "SHOULD persist for at least three times the current PTO
    /// interval" — slots in those states are deliberately kept alive
    /// so a peer's late CC retransmit can still find the connection.
    pub fn reap(self: *Server) usize {
        var reaped: usize = 0;
        var i: usize = self.slots.items.len;
        while (i > 0) {
            i -= 1;
            const slot = self.slots.items[i];
            if (slot.conn.closeState() != .closed) continue;
            // Ordered-teardown hook: the embedder releases anything
            // borrowing `slot.conn` (sessions, `slot.user_data`) while
            // the slot is still fully alive. Must run before any
            // teardown below.
            if (self.on_connection_will_close) |callback| {
                callback(self.on_connection_will_close_user_data, slot);
            }
            // Capture the close-event source and peer address before
            // we tear the connection down — once `slot.conn.deinit`
            // has run, both pointers are dead.
            const close_source: ?lifecycle.CloseSource =
                if (slot.conn.closeEvent()) |ev| ev.source else null;
            const close_peer: ?Address = slot.peer_addr;
            self.dropAllCidsFromTable(slot);
            const generation = slot.tls_generation;
            slot.conn.deinit();
            self.allocator.destroy(slot.conn);
            if (slot.pending_upgrade) |pu| self.allocator.destroy(pu);
            self.allocator.destroy(slot);
            _ = self.slots.swapRemove(i);
            reaped += 1;
            self.releaseGeneration(generation);
            self.emitLog(.{ .connection_closed = .{
                .peer = close_peer,
                .source = close_source,
            } });
        }
        self.slots_reaped += reaped;
        return reaped;
    }

    /// Decrement the refcount on the draining entry for `generation`,
    /// if any. When the refcount hits zero, the entry's context is
    /// torn down and the entry is dropped from
    /// `draining_tls_contexts`. A `generation` matching
    /// `current_generation` is a no-op (the current context isn't a
    /// draining entry until the next `replaceTlsContext`).
    fn releaseGeneration(self: *Server, generation: u32) void {
        if (generation == self.current_generation) return;
        var idx: usize = 0;
        while (idx < self.draining_tls_contexts.items.len) : (idx += 1) {
            const entry = &self.draining_tls_contexts.items[idx];
            if (entry.generation != generation) continue;
            // invariant: refcount > 0 — every live slot at this
            // generation contributed exactly one. Reaping a slot
            // can't drop to zero before all its refs are accounted.
            std.debug.assert(entry.refcount > 0);
            entry.refcount -= 1;
            if (entry.refcount == 0) {
                entry.ctx.deinit();
                _ = self.draining_tls_contexts.swapRemove(idx);
            }
            return;
        }
    }

    /// Queue `CONNECTION_CLOSE` on every live slot. Embedders should
    /// keep polling and ticking until each slot becomes `.closed`,
    /// then call `reap` to reclaim memory.
    pub fn shutdown(self: *Server, error_code: u64, reason: []const u8) void {
        for (self.slots.items) |slot| {
            slot.conn.close(true, error_code, reason);
        }
    }

    /// Hot-swap the TLS context used for new connections. Existing
    /// slots keep talking to their original context via the
    /// per-connection SSL handle (BoringSSL up-refs `SSL_CTX` on
    /// `SSL_new`, so the slot's TLS state survives the swap); only
    /// future `acceptInitial` calls — i.e. brand-new slots created
    /// after this returns — see the new context.
    ///
    /// The pre-swap context, if it was Server-owned, is moved into
    /// `draining_tls_contexts` with a refcount equal to the number of
    /// live slots that were opened against it. As those slots reach
    /// `.closed` and get reaped, the refcount decrements; the
    /// draining context is torn down on the reap that drops the last
    /// reference. If the pre-swap context was caller-supplied (via
    /// `Config.tls_context_override`), the embedder retains
    /// ownership: the swap simply forgets the borrowed pointer here
    /// and stops handing it to new slots. The draining list is
    /// always purely Server-owned.
    ///
    /// The new context is Server-owned after a successful swap. A
    /// `.pem` reload builds that context internally; an `.override`
    /// reload adopts the caller-supplied context, so the caller must
    /// not deinit it after handing it over.
    ///
    /// **Resumption note**: BoringSSL mints session tickets under
    /// the SSL_CTX's per-context ticket key, so a ticket issued
    /// before this swap cannot be decrypted under the new context
    /// (different key material). Embedders that need cross-reload
    /// resumption — for example to keep 0-RTT working across a hot
    /// cert rotation — must manage ticket key material themselves
    /// (`SSL_CTX_set_tlsext_ticket_keys` or its callback variants)
    /// and feed the rebuilt context in via the `.override` variant
    /// after configuring the keys explicitly. This call deliberately
    /// does not bridge ticket keys for you.
    ///
    /// Errors:
    ///   - `OutOfMemory`: appending to `draining_tls_contexts`.
    ///   - `boringssl.tls.Error.*` / `InvalidConfig`: from the
    ///     `.pem` variant — propagated from
    ///     `Context.initServer`/`loadCertChainAndKey`/the mTLS and
    ///     anti-replay re-installs carried over from `init`.
    ///   - `InvalidConfig`: from the `.override` variant when this
    ///     Server was initialized with `client_ca_pem` — mirroring
    ///     the `Server.init` rule, because an adopted context would
    ///     silently drop the required-client-cert posture. mTLS
    ///     servers rotate via `.pem`. On this error the supplied
    ///     context was NOT consumed: ownership stays with the
    ///     caller.
    ///
    /// The Server is left untouched on every error: the current
    /// context, slot table, and draining list are all unchanged.
    pub fn replaceTlsContext(self: *Server, reload: TlsReload) Error!void {
        var new_ctx: boringssl.tls.Context = switch (reload) {
            .pem => |pem| blk: {
                if (pem.cert_pem.len == 0 or pem.key_pem.len == 0) return Error.InvalidConfig;
                var ctx = try boringssl.tls.Context.initServer(.{
                    .verify = .none,
                    .min_version = boringssl.raw.TLS1_3_VERSION,
                    .max_version = boringssl.raw.TLS1_3_VERSION,
                    .alpn = self.alpn_protocols,
                    .early_data_enabled = self.enable_0rtt,
                });
                errdefer ctx.deinit();
                try ctx.loadCertChainAndKey(pem.cert_pem, pem.key_pem);
                // Carry the init-time mTLS posture onto the
                // replacement context — a cert rotation must not
                // silently stop verifying clients.
                if (self.client_ca_pem) |ca| {
                    try tls_mod.pem.installTrustAnchors(ctx, ca, .require_peer_cert);
                }
                // Same for the 0-RTT anti-replay hook: `Server.init`
                // installs it on the original context; a rotated
                // context that re-enables early data without it would
                // silently accept replayed 0-RTT flights for every
                // ticket minted after the swap (RFC 9001 §5.6 /
                // hardening §5.2).
                if (self.enable_0rtt) {
                    if (self.early_data_anti_replay) |tracker| {
                        try ctx.setAllowEarlyDataCallback(
                            antiReplayEarlyDataTrampoline,
                            @ptrCast(tracker),
                        );
                    }
                }
                break :blk ctx;
            },
            // Mirror the `Server.init` rule that rejects
            // `client_ca_pem` + `tls_context_override`: an adopted
            // context owns its own verification posture, and adopting
            // one while this Server is configured for mTLS would
            // silently stop verifying clients (and flip-flop back on
            // a later `.pem` reload). mTLS servers rotate via `.pem`.
            .override => |ctx| blk: {
                if (self.client_ca_pem != null) return Error.InvalidConfig;
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
        const gen_to_drain = self.current_generation;
        for (self.slots.items) |slot| {
            if (slot.tls_generation == gen_to_drain) refs += 1;
        }

        // Reserve a draining slot up-front when the pre-swap context
        // is owned and still referenced — `appendBounded`-style call
        // would also work, but doing it now means an OOM here leaves
        // both the old context and the slot table untouched.
        if (self.owns_tls and refs > 0) {
            try self.draining_tls_contexts.append(self.allocator, .{
                .ctx = self.tls_ctx,
                .generation = gen_to_drain,
                .refcount = refs,
            });
        } else if (self.owns_tls and refs == 0) {
            // Owned but no live slots reference it — drop immediately.
            self.tls_ctx.deinit();
        }
        // If !owns_tls, the embedder retains ownership of the
        // pre-swap context — we just forget the pointer.

        self.tls_ctx = new_ctx;
        self.owns_tls = true;
        self.current_generation +%= 1;
    }

    // -- internals ------------------------------------------------------

    fn findSlotForDatagram(self: *Server, bytes: []const u8) ?*Slot {
        const dcid = peekDcidForServer(bytes, self.local_cid_len) orelse return null;
        const key = cidKeyFromSlice(dcid);
        return self.cid_table.get(key);
    }

    /// Fill `dst` (length `self.local_cid_len`) with a freshly-minted
    /// server-side SCID. With QUIC-LB enabled (`Config.quic_lb`), the
    /// bytes are produced by the configured `lb.Factory` so an
    /// external load balancer can decode the routing identity;
    /// otherwise the bytes come straight from BoringSSL's CSPRNG.
    /// Used by both `openSlotFromInitial` (initial Slot SCID) and
    /// `mintAndQueueRetry` (Retry SCID).
    /// Mint a fresh server SCID into `dst`. Three paths, in order of
    /// preference:
    ///
    ///   1. **No LB configured** — draw `dst.len` bytes from the
    ///      BoringSSL CSPRNG. Pure entropy on the wire; no metadata.
    ///   2. **LB configured, factory accepts** — defer to
    ///      `lb.Factory.mint`, which dispatches to plaintext,
    ///      single-pass AES, or four-pass Feistel based on
    ///      `(key, combined)`.
    ///   3. **LB configured, nonce counter exhausted** — fall back
    ///      to `lb.mintUnroutable` so the server keeps minting
    ///      well-formed CIDs (config_id `0b111`, length self-encoded)
    ///      until the operator rotates to a new configuration via
    ///      `installLbConfig`. The fallback requires
    ///      `local_cid_len >= lb.min_unroutable_cid_len` (8 octets);
    ///      configurations with shorter CIDs surface
    ///      `Error.RandFailed` instead.
    ///
    /// Public so the LB-5 conformance suite can exercise path (3)
    /// directly via white-box state manipulation. Embedders rarely
    /// need to call this — the Server's existing
    /// `openSlotFromInitial` and `mintAndQueueRetry` paths route
    /// through here automatically.
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

    fn openSlotFromInitial(
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
        const upgrade_target = self.preparseUpgradeTarget(bytes, ids.version, &ch_complete);
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
            pending_upgrade = self.openPendingUpgrade(bytes, ids.version);
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
    fn slotErrorCloseCode(err: anyerror) struct { code: u64, reason: []const u8 } {
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

    fn dispatchToSlot(
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
    fn resyncSlotCids(self: *Server, slot: *Slot) Error!void {
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
    fn dropAllCidsFromTable(self: *Server, slot: *Slot) void {
        self.removeCidIfOwnedBy(slot.initial_dcid, slot);
        for (slot.tracked_cids[0..slot.tracked_cid_count]) |cid| {
            self.removeCidIfOwnedBy(cid, slot);
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

    fn acceptSourceRate(
        self: *Server,
        addr: Address,
        cap: u64,
        now_us: u64,
    ) bool {
        return server_dos.acceptSourceRate(self, addr, cap, now_us);
    }

    fn acceptVnRate(
        self: *Server,
        addr: Address,
        cap: u64,
        now_us: u64,
    ) bool {
        return server_dos.acceptVnRate(self, addr, cap, now_us);
    }

    fn acceptSourceBandwidth(
        self: *Server,
        addr: Address,
        bytes_charged: u64,
        cap_per_second: u64,
        now_us: u64,
    ) bool {
        return server_dos.acceptSourceBandwidth(self, addr, bytes_charged, cap_per_second, now_us);
    }

    pub fn pruneSourceRate(self: *Server, now_us: u64) void {
        return server_dos.pruneSourceRate(self, now_us);
    }

    pub fn evictOldestSourceRate(self: *Server) void {
        return server_dos.evictOldestSourceRate(self);
    }

    /// True if `version` is one of the wire-format versions this
    /// server is configured to accept. Drives the VN gate in `feed`.
    fn versionAccepted(self: *const Server, version: u32) bool {
        for (self.versions) |v| {
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
    fn preparseUpgradeTarget(
        self: *const Server,
        bytes: []const u8,
        wire_version: u32,
        ch_complete: *bool,
    ) ?u32 {
        ch_complete.* = false;
        // Multi-version mode is the only case where an upgrade is
        // possible. With a single configured version there is nothing
        // to choose between.
        if (self.versions.len <= 1) return null;
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

        return self.upgradeTargetFromCh(ch);
    }

    /// Steps 3-5 of the §6 pre-parse: walk a contiguous ClientHello
    /// looking for `quic_transport_parameters` → `version_information`,
    /// then intersect the advertised `available_versions` with the
    /// server's configured preference list. Shared by the single-shot
    /// `preparseUpgradeTarget` and the streaming `advancePendingUpgrade`
    /// paths so both produce bit-identical decisions for any given CH.
    fn upgradeTargetFromCh(self: *const Server, ch: []const u8) ?u32 {
        const qtp = wire.vneg_preparse.findQuicTransportParamsExt(ch) orelse return null;
        const info = wire.vneg_preparse.findVersionInformation(qtp) orelse return null;
        return wire.vneg_preparse.chooseUpgradeVersion(self.versions, info.available());
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
        const r_keys = wire.short_packet.derivePacketKeys(.aes128_gcm_sha256, &init_keys.secret) catch return null;

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
    fn openPendingUpgrade(
        self: *Server,
        bytes: []const u8,
        wire_version: u32,
    ) ?*PendingUpgradeState {
        const pu = self.allocator.create(PendingUpgradeState) catch return null;
        pu.init(wire_version);
        pu.initials_seen = 1;
        var pt_buf: [conn_mod.state.max_recv_plaintext]u8 = undefined;
        const plain = decryptInitialPreparse(bytes, wire_version, &pt_buf) orelse {
            self.allocator.destroy(pu);
            return null;
        };
        _ = pu.rc.feed(plain) catch {
            self.allocator.destroy(pu);
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
    fn advancePendingUpgrade(self: *Server, slot: *Slot, bytes: []const u8) void {
        const pu = slot.pending_upgrade orelse return;

        // Only Initial-typed long-header datagrams advance the
        // reassembler. Routed Handshake / 1-RTT datagrams ride in via
        // the same path but are not part of CH reassembly. If we ever
        // see a non-Initial here it almost certainly means the peer
        // has already moved past Initial — drop pending state and
        // commit to the wire version.
        const ids = peekLongHeaderIds(bytes) orelse {
            self.dropPendingUpgrade(slot);
            return;
        };
        if (!isInitialLongHeader(bytes, ids.version) or ids.version != pu.wire_version) {
            self.dropPendingUpgrade(slot);
            return;
        }

        // Hard cap on pre-parse work per slot. A peer that keeps
        // sending fragmented Initials past this budget gets the wire-
        // version commitment (still spec-compliant) so we don't
        // accumulate unbounded decrypt CPU under their control.
        if (pu.initials_seen >= PendingUpgradeState.max_initial_packets) {
            self.dropPendingUpgrade(slot);
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
            self.dropPendingUpgrade(slot);
            return;
        };
        const ch = maybe_ch orelse return; // Still waiting for more bytes.

        // CH complete — make the §6 decision. Whether we upgrade or
        // commit to the wire version, the pending state can be
        // dropped: the decision is final.
        const upgrade_target = self.upgradeTargetFromCh(ch);
        const wire_version = pu.wire_version;
        self.dropPendingUpgrade(slot);

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
        var ordered: [16]u32 = undefined;
        ordered[0] = chosen;
        var n: usize = 1;
        for (self.versions) |v| {
            if (v == chosen) continue;
            if (n >= ordered.len) break;
            ordered[n] = v;
            n += 1;
        }
        params.setCompatibleVersions(ordered[0..n]) catch return;
        slot.conn.setTransportParams(params) catch return;
        slot.conn.setPendingVersionUpgrade(chosen);
    }

    /// Free and unhook the per-slot multi-Initial pre-parse buffer.
    /// Idempotent. Called once the upgrade decision is final or when
    /// the per-slot Initial budget is exhausted.
    fn dropPendingUpgrade(self: *Server, slot: *Slot) void {
        const pu = slot.pending_upgrade orelse return;
        slot.pending_upgrade = null;
        self.allocator.destroy(pu);
    }

    /// Encode a Version Negotiation packet into the response queue.
    /// Errors propagate from the encoder (`InsufficientBytes`) or
    /// the queue allocator (`OutOfMemory`); on either, `feed` falls
    /// back to `.dropped`. The supported_versions list mirrors
    /// `Config.accepted_versions`; the response echoes the client's CIDs
    /// swapped (RFC 8999 §6) and the unused bits are left as the
    /// encoder default.
    fn queueVersionNegotiation(
        self: *Server,
        dst_addr: Address,
        client_packet: []const u8,
    ) !void {
        const ids = peekLongHeaderIds(client_packet) orelse return error.InvalidVersionNegotiation;
        var entry: StatelessResponse = .{ .dst = dst_addr, .len = 0, .kind = .version_negotiation };

        // Pack our configured versions into a u32-aligned buffer; the
        // wire-level VN encoder handles the rest. Capped at 16 entries
        // so we don't overflow the inline `entry.bytes` budget.
        var versions_bytes: [16 * 4]u8 = undefined;
        const count = @min(self.versions.len, 16);
        for (self.versions[0..count], 0..) |v, i| {
            std.mem.writeInt(u32, versions_bytes[i * 4 ..][0..4], v, .big);
        }

        const written = try wire.header.encode(&entry.bytes, .{ .version_negotiation = .{
            .dcid = try wire.header.ConnId.fromSlice(ids.scid),
            .scid = try wire.header.ConnId.fromSlice(ids.dcid),
            .versions_bytes = versions_bytes[0 .. count * 4],
        } });
        entry.len = written;
        try self.queueStatelessResponse(entry);
    }

    // -- NEW_TOKEN ------------------------------------------------------

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
    fn maybeReplenishConnectionIds(self: *Server, slot: *Slot) void {
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
            self.mintLocalScid(cid) catch return;
            const token = conn_mod.stateless_reset.derive(key, cid) catch return;
            provisions[n] = .{
                .connection_id = cid,
                .stateless_reset_token = token,
            };
        }
        _ = slot.conn.replenishConnectionIds(provisions[0..n]) catch {};
    }

    fn maybeIssueNewToken(
        self: *Server,
        slot: *Slot,
        from: ?Address,
        now_us: u64,
    ) void {
        return server_dos.maybeIssueNewToken(self, slot, from, now_us);
    }

    fn applyRetryGate(
        self: *Server,
        addr: Address,
        bytes: []const u8,
        now_us: u64,
    ) Error!RetryDecision {
        return server_dos.applyRetryGate(self, addr, bytes, now_us);
    }

    // INTERNAL: pub for server/ sibling access; not part of the embedder API.
    pub fn queueStatelessResponse(self: *Server, entry: StatelessResponse) Error!void {
        // Bound the queue: on overflow, prefer evicting the oldest
        // VN entry over any Retry. This stops a flood of
        // unsupported-version probes from starving Retry responses
        // to legitimate v1 peers. If no VN is queued (the queue is
        // all Retry), evict the oldest Retry — falling back to FIFO
        // is still better than refusing the new entry.
        if (self.stateless_responses.items.len >= stateless_response_queue_capacity) {
            const evict_idx: usize = blk: {
                for (self.stateless_responses.items, 0..) |*e, i| {
                    if (e.kind == .version_negotiation) break :blk i;
                }
                break :blk 0;
            };
            const evicted_kind = self.stateless_responses.items[evict_idx].kind;
            _ = self.stateless_responses.orderedRemove(evict_idx);
            self.stateless_responses_evicted += 1;
            self.emitLog(.{ .stateless_queue_evicted = .{ .kind = evicted_kind } });
        }
        try self.stateless_responses.append(self.allocator, entry);
        // Update the sticky high-water mark *after* append — it
        // captures the post-insert depth, which is the value the
        // queue actually held at this instant. The mark only ever
        // grows.
        const depth: u64 = @intCast(self.stateless_responses.items.len);
        if (depth > self.stateless_queue_high_water) {
            self.stateless_queue_high_water = depth;
        }
    }

    // -- observability -------------------------------------------------

    fn emitLog(self: *Server, ev: LogEvent) void {
        return server_observability.emitLog(self, ev);
    }

    /// Snapshot the server's instrumentation gauges and counters.
    /// The returned `MetricsSnapshot` is a flat by-value struct;
    /// reading it does not allocate, mutate the server, or invoke
    /// any user callback. Embedders typically call this on a fixed
    /// schedule and forward to their metrics pipeline (Prometheus,
    /// statsd, OpenTelemetry).
    pub fn metricsSnapshot(self: *const Server) MetricsSnapshot {
        return server_observability.metricsSnapshot(self);
    }

    /// Snapshot the rate-limiter table, returning the top
    /// `RateLimitSnapshot.top_n` (16) sources by `recent_count` in
    /// descending order. The unused tail of `top_offenders` is
    /// zero-initialized; embedders should iterate up to
    /// `top_offender_count`.
    ///
    /// The implementation is an O(N * top_n) insertion sort across
    /// the table (N = `source_rate_table` size, bounded by
    /// `Config.source_rate_table_capacity`). With the default
    /// capacity of 4096 entries and top_n=16 this is well under a
    /// millisecond on commodity hardware; the snapshot is meant for
    /// occasional polling (every few seconds), not the per-packet
    /// hot path.
    pub fn rateLimitSnapshot(self: *const Server) RateLimitSnapshot {
        return server_observability.rateLimitSnapshot(self);
    }
};

/// Project a `PreferredAddressConfig` into the on-wire transport-
/// parameter struct. The seq-1 CID + token are minted by the caller
/// (`openSlotFromInitial`); this helper just packs the address pair
/// and identity bytes into the codec's six-field shape.
///
/// RFC 9000 §18.2 lets either family be all-zero as a sentinel for
/// "no preferred address for this family". When `cfg.ipv4` /
/// `cfg.ipv6` is null, the corresponding output bytes / port stay
/// zero — clients reading the parameter see no v4 / v6 address as
/// expected.
fn buildPreferredAddressParam(
    cfg: PreferredAddressConfig,
    cid: []const u8,
    stateless_reset_token: [16]u8,
) PreferredAddressTp {
    var out: PreferredAddressTp = .{
        .connection_id = ConnectionId.fromSlice(cid),
        .stateless_reset_token = stateless_reset_token,
    };
    if (cfg.ipv4) |v4| {
        out.ipv4_address = v4.bytes;
        out.ipv4_port = v4.port;
    }
    if (cfg.ipv6) |v6| {
        out.ipv6_address = v6.bytes;
        out.ipv6_port = v6.port;
    }
    return out;
}

// -- header-peek helpers ------------------------------------------------

// INTERNAL: pub for server/ sibling access; not part of the embedder API.
pub const LongHeaderIds = struct {
    version: u32,
    dcid: []const u8,
    scid: []const u8,
};

// INTERNAL: pub for server/ sibling access; not part of the embedder API.
pub fn peekLongHeaderIds(bytes: []const u8) ?LongHeaderIds {
    if (bytes.len < 6) return null;
    if ((bytes[0] & 0x80) == 0) return null;
    const version = std.mem.readInt(u32, bytes[1..5], .big);
    const dcid_len = bytes[5];
    if (dcid_len > 20) return null;
    var pos: usize = 6;
    if (bytes.len < pos + @as(usize, dcid_len) + 1) return null;
    const dcid = bytes[pos .. pos + dcid_len];
    pos += dcid_len;

    const scid_len = bytes[pos];
    if (scid_len > 20) return null;
    pos += 1;
    if (bytes.len < pos + @as(usize, scid_len)) return null;
    const scid = bytes[pos .. pos + scid_len];

    return .{ .version = version, .dcid = dcid, .scid = scid };
}

/// True if `bytes` looks like a long-header Initial under the
/// supplied wire-format version. RFC 9368 §3.2 puts Initial at
/// 0b01 under v2 vs 0b00 under v1, so the caller has to pre-resolve
/// the version field — typically via `peekLongHeaderIds`.
fn isInitialLongHeader(bytes: []const u8, version: u32) bool {
    if (bytes.len == 0 or (bytes[0] & 0x80) == 0) return false;
    if (bytes.len < 5) return false;
    if (version == 0) return false; // version negotiation
    const long_type_bits: u2 = @intCast((bytes[0] >> 4) & 0x03);
    return wire.header.longTypeFromBits(version, long_type_bits) == .initial;
}

/// Peek the DCID from either header form. Long headers carry an
/// explicit length; short headers use the server's local-CID length.
fn peekDcidForServer(bytes: []const u8, local_cid_len: u8) ?[]const u8 {
    if (bytes.len == 0) return null;
    if ((bytes[0] & 0x80) != 0) {
        const ids = peekLongHeaderIds(bytes) orelse return null;
        return ids.dcid;
    }
    if (bytes.len < 1 + @as(usize, local_cid_len)) return null;
    return bytes[1 .. 1 + local_cid_len];
}

fn containsConnectionId(haystack: []const ConnectionId, needle: ConnectionId) bool {
    for (haystack) |cid| {
        if (ConnectionId.eql(cid, needle)) return true;
    }
    return false;
}

/// Extract the token slice from an Initial header, or null if the
/// packet didn't parse cleanly as one. The bytes returned are
/// borrowed from `bytes`.
// INTERNAL: pub for server/ sibling access; not part of the embedder API.
pub fn peekInitialToken(bytes: []const u8) ?[]const u8 {
    const parsed = wire.header.parse(bytes, 0) catch return null;
    return switch (parsed.header) {
        .initial => |initial| initial.token,
        else => null,
    };
}

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
fn antiReplayEarlyDataTrampoline(
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

// -- tests --------------------------------------------------------------
//
// The init/feed end-to-end smoke test lives in
// `tests/e2e/server_smoke.zig` because it needs real cert/key PEMs
// from `tests/data`, which sit outside this package's import path.
// The tests below only exercise pure helpers and config validation —
// neither needs a TLS context.

test "slotErrorCloseCode maps TLS failures to CRYPTO_ERROR and everything else to INTERNAL_ERROR" {
    // The live `dispatchToSlot` path is dominated by `sendAlert`,
    // which closes with the specific 0x0100+alert code before the
    // error unwinds — so this mapping is the only place the
    // alert-less decision is observable, and without this test a
    // revert to INTERNAL_ERROR passes the entire suite (it did).
    const crypto = Server.slotErrorCloseCode(error.HandshakeFailed);
    try std.testing.expectEqual(
        conn_mod.state.transport_error_crypto_handshake_failure,
        crypto.code,
    );
    // RFC 9001 §4.8: the whole 0x0100-0x01ff window means "TLS
    // rejected this connection".
    try std.testing.expect(crypto.code >= 0x0100 and crypto.code <= 0x01ff);
    try std.testing.expectEqual(
        conn_mod.state.transport_error_crypto_handshake_failure,
        Server.slotErrorCloseCode(error.PeerAlerted).code,
    );

    // Everything else keeps the RFC 9000 §20.1 catch-all.
    for ([_]anyerror{
        error.InboxOverflow,
        error.UnsupportedCipherSuite,
        error.ProtocolViolation,
    }) |err| {
        try std.testing.expectEqual(
            conn_mod.state.transport_error_internal,
            Server.slotErrorCloseCode(err).code,
        );
    }
}

test "Server.init validates configuration" {
    const protos = [_][]const u8{"hq-test"};

    // Empty cert/key.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "",
        .tls_key_pem = "",
        .alpn_protocols = &protos,
        .transport_params = .{},
    }));

    // No ALPN.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &.{},
        .transport_params = .{},
    }));

    // local_cid_len=0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 0,
        .transport_params = .{},
    }));

    // local_cid_len > 20.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .local_cid_len = 21,
        .transport_params = .{},
    }));

    // Source rate limiter enabled with an explicit cap of 0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .initial_source_rate_limit = .{ .limit = 0 },
        .transport_params = .{},
    }));

    // Source rate limiter enabled with window=0 — the default-on
    // limiter alone must be enough to trip this.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .source_rate_window_us = 0,
        .transport_params = .{},
    }));

    // VN limiter with an explicit cap of 0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .vn_source_rate_limit = .{ .limit = 0 },
        .transport_params = .{},
    }));

    // Log limiter with an explicit cap of 0.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .log_source_rate_limit = .{ .limit = 0 },
        .transport_params = .{},
    }));

    // mTLS bundle combined with a context override: the override owns
    // its own verification posture, so the bundle would be silently
    // ignored — reject instead. (A real override context is not
    // needed; validation runs before any TLS work.)
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .client_ca_pem = "stub",
        .tls_context_override = .{ .inner = undefined, .mode = .server },
        .transport_params = .{},
    }));

    // Empty mTLS bundle.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .client_ca_pem = "",
        .transport_params = .{},
    }));

    // preferred_address with neither v4 nor v6 set.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .preferred_address = .{},
        .stateless_reset_key = @splat(0x42),
    }));

    // preferred_address without stateless_reset_key.
    try std.testing.expectError(Server.Error.InvalidConfig, Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = "stub",
        .tls_key_pem = "stub",
        .alpn_protocols = &protos,
        .transport_params = .{},
        .preferred_address = .{
            .ipv6 = .{ .port = 444, .bytes = @splat(0), .flow = 0 },
        },
        // stateless_reset_key intentionally null.
    }));
}

test "buildPreferredAddressParam packs config + identity into transport-param shape" {
    // The codec auto-build path (used by `openSlotFromInitial`) projects
    // the embedder-supplied `PreferredAddressConfig` into the on-wire
    // `tls.transport_params.PreferredAddress` shape that the encoder
    // serializes. Pin the field-by-field mapping so future config
    // additions can't silently break the wire output.
    const cfg: PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = .{ 193, 167, 100, 100 }, .port = 444 },
        .ipv6 = .{ .bytes = @splat(0), .port = 445, .flow = 0 },
    };
    var alt_cid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var token: [16]u8 = @splat(0xee);
    const got = buildPreferredAddressParam(cfg, &alt_cid, token);

    try std.testing.expectEqualSlices(u8, &cfg.ipv4.?.bytes, &got.ipv4_address);
    try std.testing.expectEqual(@as(u16, 444), got.ipv4_port);
    try std.testing.expectEqualSlices(u8, &cfg.ipv6.?.bytes, &got.ipv6_address);
    try std.testing.expectEqual(@as(u16, 445), got.ipv6_port);
    try std.testing.expectEqualSlices(u8, &alt_cid, got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &token, &got.stateless_reset_token);
}

test "buildPreferredAddressParam leaves missing-family fields zero (RFC 9000 §18.2 sentinel)" {
    // §18.2 ¶2: the address pair fields are independently optional;
    // the all-zero address + zero port is the "no preferred address
    // for this family" sentinel. Verify the helper preserves that
    // when `ipv4` (or `ipv6`) is left null in the config.
    const cfg: PreferredAddressConfig = .{
        .ipv6 = .{ .bytes = .{
            0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        }, .port = 444, .flow = 0 },
    };
    const cid: [8]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2 };
    const tok: [16]u8 = @splat(0xab);
    const got = buildPreferredAddressParam(cfg, &cid, tok);

    // v4 stays at the all-zero / port-zero sentinel.
    const zero_v4: [4]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &zero_v4, &got.ipv4_address);
    try std.testing.expectEqual(@as(u16, 0), got.ipv4_port);
    // v6 is populated.
    try std.testing.expectEqualSlices(u8, &cfg.ipv6.?.bytes, &got.ipv6_address);
    try std.testing.expectEqual(@as(u16, 444), got.ipv6_port);
}

test "buildPreferredAddressParam round-trips through Params codec" {
    // End-to-end: pack a config into the transport-parameter struct,
    // encode through `Params.encode`, decode via `Params.decode`, and
    // confirm every field survives the wire format. The decoder is
    // role-aware (server-only acceptance) but `Params.decode` itself
    // is role-neutral; we use it for the codec round-trip without
    // engaging the role gate.
    const transport_params = @import("tls/root.zig").transport_params;

    const cfg: PreferredAddressConfig = .{
        .ipv4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 4433 },
        .ipv6 = .{ .bytes = .{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0,    0,    0,    0,    0, 0, 0, 1,
        }, .port = 4434, .flow = 0 },
    };
    const cid: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    const token: [16]u8 = @splat(0x77);
    const pa = buildPreferredAddressParam(cfg, &cid, token);

    const params: transport_params.Params = .{ .preferred_address = pa };
    var buf: [256]u8 = undefined;
    const n = try params.encode(&buf);
    const decoded = try transport_params.Params.decode(buf[0..n]);
    const got = decoded.preferred_address orelse return error.MissingPreferredAddress;

    try std.testing.expectEqualSlices(u8, &pa.ipv4_address, &got.ipv4_address);
    try std.testing.expectEqual(pa.ipv4_port, got.ipv4_port);
    try std.testing.expectEqualSlices(u8, &pa.ipv6_address, &got.ipv6_address);
    try std.testing.expectEqual(pa.ipv6_port, got.ipv6_port);
    try std.testing.expectEqualSlices(u8, pa.connection_id.slice(), got.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &pa.stateless_reset_token, &got.stateless_reset_token);
}

test "peekLongHeaderIds rejects too-short" {
    try std.testing.expect(peekLongHeaderIds(&.{}) == null);
    try std.testing.expect(peekLongHeaderIds(&.{0xc0}) == null);
}

test "isInitialLongHeader recognizes Initial type bits" {
    // Long header, type=0b00 (Initial under v1), version=1.
    const v1_bytes = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v1_bytes, 0x00000001));

    // Long header, type=0b01 (Initial under v2 per RFC 9368 §3.2),
    // version = 0x6b3343cf. The same bit pattern is 0-RTT under v1
    // and Initial under v2, so the helper has to consult `version`.
    const v2_bytes = [_]u8{ 0xd0, 0x6b, 0x33, 0x43, 0xcf, 0, 0 };
    try std.testing.expect(isInitialLongHeader(&v2_bytes, 0x6b3343cf));
    try std.testing.expect(!isInitialLongHeader(&v2_bytes, 0x00000001));

    // Version negotiation (version=0) is *not* an Initial under
    // either version. The caller is expected to pass `version=0`
    // here (matching the bytes' version field); the helper rejects
    // outright.
    const vn = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&vn, 0));

    // Short header.
    const sh = [_]u8{ 0x40, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(!isInitialLongHeader(&sh, 0x00000001));
}

test "cidKey round-trips identical CIDs" {
    const a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const b = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const c = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 9 };
    const d = [_]u8{ 1, 2, 3, 4, 5, 6, 7 }; // different length

    try std.testing.expectEqual(cidKeyFromSlice(&a), cidKeyFromSlice(&b));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&c)));
    try std.testing.expect(!std.mem.eql(u8, &cidKeyFromSlice(&a), &cidKeyFromSlice(&d)));
}

// -- fuzz harness --------------------------------------------------------
//
// `Server.feed` is the entry point an open-internet deployment exposes
// to arbitrary bytes; the header-peek helpers (`peekLongHeaderIds`,
// `isInitialLongHeader`, `peekDcidForServer`) gate it. None may panic
// on hostile input. We stop short of a full `Server` end-to-end fuzz
// (it would need a TLS context and an allocator-tracked
// `boringssl.tls.Context`) — the wire-level peek surface is the
// highest-yield target.

test "fuzz: peekLongHeaderIds never panics" {
    try std.testing.fuzz({}, fuzzPeekLongHeader, .{});
}

fn fuzzPeekLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];

    const ids = peekLongHeaderIds(input) orelse return;
    // Returned CID slices must point into `input`.
    try std.testing.expect(ids.dcid.len <= 20);
    try std.testing.expect(ids.scid.len <= 20);
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.dcid.ptr) + ids.dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(@intFromPtr(ids.scid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(ids.scid.ptr) + ids.scid.len <= @intFromPtr(input.ptr) + input.len);
}

test "fuzz: isInitialLongHeader never panics" {
    try std.testing.fuzz({}, fuzzIsInitialLongHeader, .{});
}

fn fuzzIsInitialLongHeader(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    // Drive the helper under both versions so the v1 and v2 long-type
    // rotations are both exercised on the same input bytes.
    _ = isInitialLongHeader(input, 0x00000001);
    _ = isInitialLongHeader(input, 0x6b3343cf);
}

test "fuzz: peekDcidForServer never panics across all CID lengths" {
    try std.testing.fuzz({}, fuzzPeekDcid, .{});
}

fn fuzzPeekDcid(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [256]u8 = undefined;
    const len = smith.slice(&input_buf);
    const input = input_buf[0..len];
    const local_cid_len = smith.valueRangeAtMost(u8, 0, 20);

    const dcid = peekDcidForServer(input, local_cid_len) orelse return;
    // The returned slice must lie inside `input`.
    try std.testing.expect(@intFromPtr(dcid.ptr) >= @intFromPtr(input.ptr));
    try std.testing.expect(@intFromPtr(dcid.ptr) + dcid.len <= @intFromPtr(input.ptr) + input.len);
    try std.testing.expect(dcid.len <= 20);
}
