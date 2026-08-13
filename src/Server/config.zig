// Server configuration surface: Config and its nested policy types
// (RateLimit, EarlyData, TlsReload) plus PreferredAddressConfig.
// Split from server.zig; server.zig re-imports these under the same
// `Server.Config` / `Server.RateLimit` / ... aliases, so the embedder
// surface is unchanged.

const Config = @This();

const std = @import("std");
const boringssl = @import("boringssl");
const server_observability = @import("observability.zig");
const conn_mod = @import("../conn/root.zig");
const tls_mod = @import("../tls/root.zig");
const lb_mod = @import("../lb/root.zig");
const state = conn_mod.state;
// Direct sibling imports: these types are declared in
// observability.zig; reaching them through server.zig's re-exports
// would put this file in the hub cycle for no reason. With only
// sibling imports, config.zig is a leaf.
const LogCallbackImpl = server_observability.LogCallback;
const ConnectionWillCloseCallbackImpl = server_observability.ConnectionWillCloseCallback;
const QlogCallback = conn_mod.QlogCallback;
const TransportParams = tls_mod.TransportParams;
const RetryTokenKey = conn_mod.RetryTokenKey;
const PreferredAddressTp = tls_mod.transport_params.PreferredAddress;

/// Configuration handed to `Server.init`. Re-exported as
/// `Server.Config`.
/// Server `preferred_address` (RFC 9000 §18.2 / §5.1.1) configuration.
/// When set on `Config.preferred_address`, the server advertises this
/// alternate IPv4/IPv6 address pair to clients during the handshake,
/// and (when used with `runUdpServer`) binds an additional listener
/// socket on each configured address. Clients that complete the
/// handshake migrate to the preferred address per RFC 9000 §5.1.1.
///
/// At least one of `ipv4` / `ipv6` must be non-null. When only one
/// family is set, the unused-family fields in the on-wire transport
/// parameter are left zero (the spec sentinel meaning "no preferred
/// address for this family"). The CID + stateless-reset token the
/// parameter advertises are derived per-connection at handshake time
/// using `Config.stateless_reset_key` and `Server.mintLocalScid`; the
/// embedder does not supply them.
///
/// **`Config.stateless_reset_key` is required** when this field is
/// set. The seq-1 stateless-reset token in the parameter must match
/// the token a future stateless-reset on the alt-CID would produce,
/// and the deterministic `conn.stateless_reset.derive` helper is the
/// only path quic surfaces for that. Setting `preferred_address`
/// without a key fails `Server.init` with `InvalidConfig`.
pub const PreferredAddressConfig = struct {
    /// Alt IPv4 address + port to advertise + bind, or null. The
    /// 4-byte address bytes are advertised verbatim; an all-zero
    /// `ipv4` is interpreted by RFC 9000 §18.2 as "no IPv4
    /// preferred address" and `runUdpServer` will skip the v4 bind.
    ipv4: ?std.Io.net.Ip4Address = null,
    /// Alt IPv6 address + port to advertise + bind, or null.
    /// Same all-zero sentinel semantics as `ipv4`.
    ipv6: ?std.Io.net.Ip6Address = null,
};

/// Three-state rate/quota configuration, re-exported as
/// `Server.RateLimit`. A tagged union instead of `?T` so
/// "I didn't configure this" (`.default` — the library-recommended
/// setting applies, which for some limiters is "off") and "turn the
/// protection off" (`.disabled`) are spelled differently: a consumer
/// mirroring a `null` default cannot silently disable a protection
/// the library turned on, and the library can change a recommended
/// default in a later release without silently overriding embedders
/// who deliberately opted out.
///
/// Every rate/quota knob on `Config` uses this one type, so the
/// idiom is learned once. Limiters whose recommended setting is a
/// real cap expose it as a `Config.default_*_cap` constant; the ones
/// whose recommendation is "off, it depends on your deployment
/// envelope" say so in their field doc.
pub const RateLimit = union(enum) {
    /// Apply this limiter's library-recommended setting (see the
    /// `Config.default_*` constants; for the listener and bandwidth
    /// limiters the recommendation is "off — depends on your
    /// deployment envelope").
    default,
    /// Explicitly disable the limiter, accepting the unbounded rate.
    disabled,
    /// Explicit cap, in the unit named by the field's doc comment.
    /// Zero fails `Server.init` with `InvalidConfig`.
    limit: u64,

    /// Resolve to the effective cap: null means the limiter is off.
    /// `default_cap` of 0 expresses "recommended off".
    pub fn resolve(self: RateLimit, default_cap: u64) ?u64 {
        return switch (self) {
            .default => if (default_cap == 0) null else default_cap,
            .disabled => null,
            .limit => |cap| cap,
        };
    }
};

/// 0-RTT (early-data) posture for `Server.Config.early_data`,
/// re-exported as `Server.EarlyData`. A union rather than a
/// `bool` + `?*AntiReplayTracker` pair because the dangerous
/// combination — early data on, tracker forgotten — was
/// representable, valid, and silent. Here it has a name.
pub const EarlyData = union(enum) {
    /// Refuse 0-RTT: the auto-built TLS context is created with
    /// early data disabled, and resumed connections complete as
    /// 1-RTT. The secure default.
    disabled,
    /// Accept 0-RTT with TLS-layer replay protection. The Server
    /// installs a BoringSSL `allow_early_data` callback that hashes
    /// the resumed-session ticket bytes (`Conn.peerSessionId`) to the
    /// tracker's 32-byte `Id` and calls `tracker.consume(id, now)`.
    /// Verdict `.fresh` lets BoringSSL accept 0-RTT; `.replay`
    /// toggles `early_data_enabled` off for that handshake (the
    /// connection then completes as 1-RTT). The tracker is owned by
    /// the embedder and must outlive the `Server`.
    with_anti_replay: *tls_mod.anti_replay.AntiReplayTracker,
    /// Accept 0-RTT with NO transport-layer replay protection.
    /// Correct only when every request the application will accept
    /// over early data is idempotent, or the application runs its own
    /// replay defense above quic (RFC 9001 §5.6 leaves the check
    /// to the application). Spelled out so that shipping unprotected
    /// 0-RTT is always a deliberate, greppable choice.
    without_replay_protection,

    /// True when either enabled variant is selected.
    pub fn enabled(self: EarlyData) bool {
        return self != .disabled;
    }

    /// The embedder's replay tracker, or null when 0-RTT is disabled
    /// or deliberately unprotected.
    pub fn antiReplayTracker(self: EarlyData) ?*tls_mod.anti_replay.AntiReplayTracker {
        return switch (self) {
            .with_anti_replay => |t| t,
            .disabled, .without_replay_protection => null,
        };
    }
};

/// Library-recommended open-internet cap backing
/// `initial_source_rate_limit = .default`.
pub const default_initial_source_rate_cap: u64 = 32;
/// Library-recommended open-internet cap backing
/// `vn_source_rate_limit = .default`.
pub const default_vn_source_rate_cap: u64 = 8;
/// Library-recommended cap backing
/// `log_source_rate_limit = .default`.
pub const default_log_source_rate_cap: u64 = 16;

/// Wall-clock allocator used for the connection table and any
/// transient per-server allocations. Each `Connection` allocates
/// from this allocator as well.
allocator: std.mem.Allocator,

/// Server certificate chain and private key, both PEM-encoded.
/// The `Server` does not take ownership; the caller must keep
/// these bytes alive for the lifetime of the server.
tls_cert_pem: []const u8,
tls_key_pem: []const u8,

/// Optional CA bundle (PEM, one or more certificates) that turns
/// on mTLS: when set, the auto-built TLS context **requires** a
/// client certificate and verifies it against exactly these
/// roots — a client that presents no certificate, or one not
/// chaining to this bundle, fails the handshake. Off by default
/// (`null`): servers do not verify clients. Only consulted when
/// `tls_context_override` is null — an override context owns its
/// own verification posture, and combining the two fails
/// `Server.init` with `InvalidConfig`. Like `tls_cert_pem`, the
/// caller must keep the bytes alive for the lifetime of the
/// server: `replaceTlsContext(.{ .pem = ... })` re-installs the
/// same bundle on the replacement context.
client_ca_pem: ?[]const u8 = null,

/// ALPN protocols the server is willing to negotiate, in
/// preference order. Required — QUIC rejects connections that do
/// not negotiate ALPN.
alpn_protocols: []const []const u8,

/// Default transport parameters applied to every accepted
/// connection. The `original_destination_connection_id` and
/// `initial_source_connection_id` fields are filled in
/// automatically per connection; everything else is taken
/// verbatim, except `max_idle_timeout_ms` — see
/// `allow_no_idle_timeout`.
transport_params: TransportParams,

/// When the supplied `transport_params.max_idle_timeout_ms` is 0
/// (the struct default, meaning "no idle timer"), `Server.init`
/// substitutes a safe `default_server_idle_timeout_ms` so an
/// inattentive embedder does not stand up a server that keeps
/// idle / half-open connections alive forever — a resource-exhaustion
/// vector on an internet-facing listener. Set this to `true` to
/// honor an explicit 0 and genuinely disable the idle timer.
allow_no_idle_timeout: bool = false,

/// Maximum number of concurrent live connections. Excess Initial
/// packets are dropped.
max_concurrent_connections: u32 = 1000,

/// Length of the locally-issued connection IDs (the SCIDs the
/// server returns to clients). Must be 1..20. Default 8 matches
/// the QNS endpoint. **Ignored when `quic_lb` is set** — the
/// QUIC-LB configuration determines the CID length
/// (`1 + server_id_len + nonce_len`) and `Server.init` overrides
/// this field with the resolved value.
local_cid_len: u8 = 8,

/// 32-byte HMAC key used to derive stateless-reset tokens
/// (RFC 9000 §10.3) for CIDs the Server auto-issues on
/// `installLbConfig` rotation. Off by default — leave null and
/// drive replenishment manually via the `connection_ids_needed`
/// event flow with embedder-supplied tokens.
///
/// When set, `installLbConfig` automatically pushes a
/// NEW_CONNECTION_ID frame to every live slot using the new LB
/// factory; tokens are derived as
/// `HMAC-SHA256(stateless_reset_key, "quic stateless reset
/// v1" || cid)` per `quic.conn.stateless_reset.derive`.
///
/// **Persist this key across server restarts.** A cold-start
/// embedder that forgets the key invalidates every previously
/// issued reset token: live connections through the restart will
/// no longer drop on stateless reset. The same hardening note in
/// the README §"Things you must wire yourself" applies.
stateless_reset_key: ?conn_mod.stateless_reset.Key = null,

/// QUIC-LB connection-ID generation
/// (draft-ietf-quic-load-balancers-21). Off by default — leave
/// null for pure-CSPRNG SCIDs. Set to opt every locally-issued
/// SCID into the routing-encoded format an external layer-4 LB
/// can decode.
///
/// **Hardening note:** this deliberately inverts the
/// "Server SCIDs are CSPRNG draws — no deployment metadata leaks
/// on the wire" default (README §"On by default"). Treat the
/// load balancer as the trust boundary; in plaintext mode (no
/// `LbConfig.key`) any on-path observer between LB and peer can
/// read `server_id` directly. Encrypted modes raise the bar to
/// "linkability without key" but do not protect against attackers
/// between LB and server. Plaintext, single-pass AES, and
/// four-pass Feistel modes are implemented.
///
/// When set in plaintext mode, `Server.init` also auto-enables
/// `transport_params.disable_active_migration` per the draft
/// §3 ¶3 SHOULD requirement, unless the embedder already set
/// it true.
quic_lb: ?lb_mod.LbConfig = null,

/// If non-null, every accepted `Connection` is wired up to this
/// qlog callback for application-key-update telemetry.
qlog_callback: ?QlogCallback = null,
qlog_user_data: ?*anyopaque = null,

/// Optional structured-logging hook. When set, the server emits
/// a `LogEvent` at every observable choice point (connection
/// open / close / reaped, rate-limited Initial, Retry minted,
/// VN response, queue eviction, table-full rejection). The
/// callback runs synchronously on the embedder's thread inside
/// `feed` / `reap` and must not call back into the server.
log_callback: ?LogCallbackImpl = null,
/// Opaque pointer passed back to `log_callback` on every event.
log_user_data: ?*anyopaque = null,

/// Ordered-teardown hook: runs inside `reap` for each closed slot
/// right before the slot and its connection are destroyed, while
/// `slot.conn` / `slot.user_data` are still valid. See
/// `ConnectionWillCloseCallback` for the contract. Null disables it.
on_connection_will_close: ?ConnectionWillCloseCallbackImpl = null,
/// Opaque pointer passed back to `on_connection_will_close`.
on_connection_will_close_user_data: ?*anyopaque = null,

/// Proactively top up each connection's local CID inventory once
/// its handshake completes. RFC 9000 §9: a client can only migrate
/// to a fresh server-issued CID, and a server that never issues
/// spares makes every `beginClientActiveMigration` against it fail
/// out of the box (the `connection_ids_needed` event only fires on
/// retirement, never proactively). Effective only when
/// `stateless_reset_key` is set — each issued CID carries a
/// derived §10.3 reset token; without the key this is a no-op
/// (advertising CIDs whose reset tokens the server cannot honor
/// across restarts would be worse than issuing none).
auto_replenish_connection_ids: bool = true,
/// Cap on spare CIDs minted per connection by the post-handshake
/// auto-replenish, further bounded by the peer's
/// `active_connection_id_limit`. Three spares (on top of the
/// handshake CID) cover a migration plus rotation headroom without
/// bloating the routing table.
max_auto_replenish_cids: u8 = 3,

/// Application bytes bound into the RFC 9001 §4.6.1 0-RTT replay
/// context, alongside the replay-relevant transport parameters and
/// the primary ALPN (`alpn_protocols[0]`). Only consulted when
/// `early_data` is enabled: the accept path installs the resulting
/// context digest on every fresh slot *before* the ClientHello is
/// processed, which is what lets BoringSSL accept early data on
/// resumption at all. Change this string across deployments whose
/// application semantics make previously-issued 0-RTT tickets
/// unsafe to replay — a changed context invalidates every
/// outstanding ticket's early-data capability (the session still
/// resumes; only 0-RTT is refused). An HTTP/3 layer would put a
/// canonicalized SETTINGS digest here.
early_data_application_context: []const u8 = "quic-zig Server wrapper v1",

/// Optional override of the underlying `boringssl.tls.Context`.
/// When null, `Server.init` constructs a TLS-1.3-only server
/// context with the supplied ALPN list and `verify=.none` —
/// unless `client_ca_pem` is set, which turns on required client
/// -certificate verification (mTLS). The auto-built context's
/// early-data posture is gated by `Config.early_data` (off by
/// default; §5.2 / §12 hardening). Pass your own to enable
/// session-ticket callbacks or any other TLS-context behavior the
/// auto-built path doesn't expose; combining an override with
/// `client_ca_pem` fails `init` with `InvalidConfig`.
tls_context_override: ?boringssl.tls.Context = null,

/// Per-source-address Initial-acceptance cap (was
/// `max_initials_per_source_per_window: ?u32` before 0.10.0 —
/// renamed so the `null`-disables sentinel could not silently
/// switch off a default-on protection). `.default` applies
/// `default_initial_source_rate_cap` (32, the recommended
/// open-internet value): fresh Initials from a source whose
/// recent count is at or above the cap within
/// `source_rate_window_us` are rejected before any Retry / TLS /
/// Connection setup, bounding a per-source Initial flood that
/// would otherwise allocate connection state. Datagrams to
/// existing slots are unaffected. Set `.disabled` to opt out —
/// e.g. behind a trusted front-end that already polices source
/// rate, or when the embedder supplies `from = null`
/// (unattributed) datagrams, for which the gate is a no-op
/// anyway. `.{ .limit = 0 }` fails `Server.init` with
/// `InvalidConfig`.
initial_source_rate_limit: RateLimit = .default,

/// Sliding-window size for `initial_source_rate_limit`,
/// in microseconds. Default is one second. Shared by the VN
/// rate-limit window (`vn_source_rate_limit`).
source_rate_window_us: u64 = 1_000_000,

/// Maximum number of distinct source addresses the rate limiter
/// tracks at once. Excess sources rotate out the oldest entry.
/// Only consulted when the limiter is enabled.
source_rate_table_capacity: u32 = 4096,

/// Per-source-address Version-Negotiation-emission cap (was
/// `max_vn_per_source_per_window: ?u32` before 0.10.0; renamed
/// for the same reason as `initial_source_rate_limit`).
/// `.disabled` turns the limiter off (every non-v1 long-header
/// packet earns a VN response, subject only to the bounded
/// global stateless queue). Hardening guide §4.4: a peer
/// flooding non-v1 long-header probes from a single address can
/// otherwise force up to `stateless_response_queue_capacity`
/// outbound bytes per drain cycle. `.default` applies
/// `default_vn_source_rate_cap` (8, the open-internet
/// recommendation) — legitimate clients fix their version after
/// one VN response and retry with v1.
vn_source_rate_limit: RateLimit = .default,

/// 32-byte HMAC key used to mint and validate stateless Retry
/// tokens (RFC 9000 §8.1.2). When null, Retry is disabled and
/// every well-formed Initial is accepted directly. When set,
/// the first Initial from a peer is answered with a Retry
/// packet; the connection is only allocated once the peer
/// echoes back a valid token in a follow-up Initial.
///
/// The key must be stable across the token lifetime so a Retry
/// minted on one packet can be validated on the next. Embedders
/// fronting multiple servers behind a load balancer should
/// share one key across the pool.
retry_token_key: ?RetryTokenKey = null,
/// Lifetime of a minted Retry token in microseconds. Tokens
/// older than this validate as `expired` and are dropped.
/// Default is 10 seconds — the QNS-recommended ceiling, large
/// enough to absorb a slow-handshake client and small enough
/// that a stolen token expires before it can be replayed.
retry_token_lifetime_us: u64 = 10_000_000,
/// Maximum number of distinct source addresses for which the
/// server holds Retry-pending state at once. Excess sources
/// evict the oldest entry. Only consulted when
/// `retry_token_key` is non-null.
retry_state_table_capacity: u32 = 4096,

/// AES-GCM-256 key used to mint and validate NEW_TOKEN frames
/// (RFC 9000 §8.1.3). When null, NEW_TOKEN issuance is disabled
/// and Initial-token validation falls through to the Retry
/// token gate. When set, the server emits one NEW_TOKEN per
/// successfully-handshake-confirmed connection, and accepts
/// returning clients presenting a valid NEW_TOKEN as already
/// address-validated (no Retry round-trip).
///
/// This key is **distinct from `retry_token_key`** by design:
/// NEW_TOKENs typically outlive Retry tokens by orders of
/// magnitude (hours/days vs. seconds), so they need their own
/// rotation policy. Sharing the key would force NEW_TOKEN
/// rotation every time the operator rotated the Retry key.
new_token_key: ?conn_mod.NewTokenKey = null,
/// Lifetime of a minted NEW_TOKEN in microseconds. Returning
/// clients presenting a token older than this fall through to
/// the Retry gate (or the no-validation accept path, if Retry
/// is also disabled). Default 24 hours — long enough that a
/// returning user a day later still skips Retry, short enough
/// that a stolen token's window of misuse is bounded.
new_token_lifetime_us: u64 = 24 * 3600 * 1_000_000,

/// QUIC 0-RTT (early data) posture on the auto-built TLS context
/// (replaces `enable_0rtt: bool` + `early_data_anti_replay: ?*T`
/// as of 0.10.0 — see `EarlyData`). `.disabled` by default to
/// satisfy the §5.2 / §12 hardening posture: 0-RTT is replayable
/// and unsuitable for state-changing requests without an
/// anti-replay mechanism (RFC 9001 §5.6 / RFC 8446 §8).
///
/// The two enabled variants differ only in replay protection, and
/// the unprotected one has to be named explicitly — the old pair
/// let `enable_0rtt = true` with a forgotten tracker ship
/// replay-exposed 0-RTT with no error and no log line.
///
/// Override-mode embedders must set this too. Supplying your own
/// `tls_context_override` means you own that context's
/// `early_data_enabled` flag — but this field additionally drives
/// the RFC 9001 §4.6.1 early-data *context* install on every fresh
/// slot (`setEarlyDataContextForParams`, without which BoringSSL
/// refuses 0-RTT and issued tickets are never 0-RTT-capable), the
/// anti-replay tracker's clock, and the posture carried across
/// `replaceTlsContext`. Leaving it `.disabled` while enabling early
/// data on your own context yields a server where 0-RTT silently
/// never works.
early_data: EarlyData = .disabled,

/// Whether to encode the locally-recorded close-reason string into
/// outgoing CONNECTION_CLOSE frames. Default `false` (redact) per
/// secure-by-default redaction: internal parser-error strings reveal
/// implementation detail to the peer (parser fingerprinting,
/// internal state names). Local introspection is unaffected; the
/// embedder still sees the reason via close events.
///
/// Threaded onto every Connection the Server creates. Embedders
/// can also set `Connection.reveal_close_reason_on_wire` directly
/// for finer-grained control (e.g. dev/debug builds).
reveal_close_reason_on_wire: bool = false,

/// Per-Connection cap on bytes resident in peer-controlled
/// reassembly / queue buffers (CRYPTO, DATAGRAM, stream send /
/// recv). See `conn.state.default_max_connection_memory` and
/// `Connection.max_connection_memory` for the per-buffer
/// rationale. Threaded onto every accepted slot at
/// `openSlotFromInitial` time. 32 MiB by default — a healthy
/// upper bound that still leaves headroom for the per-buffer
/// caps to do their job before this aggregate cap fires.
max_connection_memory: u64 = conn_mod.state.default_max_connection_memory,

/// Number of ack-eliciting application packets the server requires
/// before forcing an immediate ACK (RFC 9000 §13.2.1 ¶2). Default
/// matches `quic.conn.state.application_ack_eliciting_threshold`.
/// Lower this to 1 for low-RTT links where every packet should be
/// ACKed; raise it to amortize ACK overhead at the cost of more
/// peer PTOs. Threaded onto every Connection at slot-open time.
delayed_ack_packet_threshold: u8 = conn_mod.state.application_ack_eliciting_threshold,

/// Enable IETF ECN signaling (RFC 9000 §13.4 / RFC 3168) on every
/// Connection the Server creates. Default `true` — production
/// QUIC reaps modest goodput wins by reacting to router-driven
/// CE marks. Flip to `false` only in environments known to
/// bleach ECN bits (some legacy NATs / firewalls). Threaded onto
/// every Connection's `ecn_enabled` field at slot-open time.
enable_ecn: bool = true,

/// Listener-level packet rate limit (global DoS backstop; was
/// `max_datagrams_per_window: ?u32` before 0.10.0 — retyped onto
/// the shared `RateLimit` union with its siblings): drop incoming
/// UDP datagrams when the global per-window count exceeds this
/// cap, in datagrams per window. `.default` is off — the right
/// value depends on your deployment envelope, so production opts
/// in with `.{ .limit = n }`. The window length is
/// `listener_rate_window_us`; the bucket is single-global (no
/// per-source bookkeeping) so it shares state with nothing and
/// triggers cheaply on a flood from many spoofed sources.
///
/// Recommended: scale to ~2x peak observed packets-per-window,
/// then alert on `MetricsSnapshot.feeds_listener_rate_limited`
/// growing. `.{ .limit = 0 }` fails `Server.init` with
/// `InvalidConfig`.
listener_datagram_rate_limit: RateLimit = .default,

/// Listener-level byte rate limit (global DoS backstop; was
/// `max_bytes_per_window: ?u64` before 0.10.0): drop incoming UDP
/// datagrams when the global per-window byte total exceeds this
/// cap, in bytes per window. `.default` is off — production opts
/// in with `.{ .limit = n }`. Shares
/// `listener_rate_window_us` with the packet-count cap; the
/// bucket is single-global (no per-source bookkeeping) so a
/// flood of few-but-large datagrams from any number of sources
/// is gated even when the per-packet cap is generous.
///
/// Recommended: scale to ~2x peak observed bytes-per-window,
/// then alert on `MetricsSnapshot.feeds_listener_byte_rate_limited`
/// growing. `.{ .limit = 0 }` fails `Server.init` with
/// `InvalidConfig`.
listener_byte_rate_limit: RateLimit = .default,

/// Window length for `listener_datagram_rate_limit` /
/// `listener_byte_rate_limit` in microseconds. Default 1 second.
/// Smaller windows make the caps more responsive at the cost of
/// more reset jitter; larger windows smooth bursty traffic. Both
/// listener-level caps share this single window.
listener_rate_window_us: u64 = 1_000_000,

/// Per-source bandwidth shaping (hardening §4.1 token-bucket; was
/// `max_bytes_per_source_per_second: ?u64` before 0.10.0). The cap
/// is in **bytes per second**: every accepted datagram from a given
/// source charges `bytes.len` against a token bucket that refills
/// at that rate, up to the same value as a hard cap (one second's
/// burst). When the bucket is empty the datagram is dropped and
/// `feeds_source_bandwidth_limited` ticks.
///
/// `.default` is off — production opts in with
/// `.{ .limit = bytes_per_second }`. Distinct from the global
/// sliding-window `listener_byte_rate_limit`: this gates per
/// source, the global cap gates aggregate. Charging happens AFTER
/// the global gates approve, so the global caps still bound
/// aggregate bandwidth even when every individual source has full
/// buckets. `.{ .limit = 0 }` fails `Server.init` with
/// `InvalidConfig`.
source_byte_rate_limit: RateLimit = .default,

/// Per-source cap on `LogEvent` emissions per window (hardening
/// guide §9.4; was `max_log_events_per_source_per_window: ?u32`
/// before 0.10.0 — renamed and retyped alongside its two sibling
/// limiters so `null` could not silently switch off a
/// default-on protection). When the cap fires, the log is
/// dropped silently — no nested log about the dropped log.
/// `.default` applies `default_log_source_rate_cap` (16 events
/// per window per source); `.disabled` opts out, accepting an
/// unbounded log-event rate. Reuses `source_rate_window_us` (so
/// the Initial / VN / log windows all share one knob).
///
/// Log events with `from = null` (no source attribution) bypass
/// the limiter — see `acceptLogRate`. Embedders that want a
/// global ceiling on null-source events should put one in their
/// own log_callback.
log_source_rate_limit: RateLimit = .default,

/// QUIC wire-format versions this server accepts on inbound
/// Initials. RFC 9000 §6 / RFC 8999 §6: any long-header packet
/// whose declared version isn't in this list earns a Version
/// Negotiation response listing the configured set. Must be
/// non-empty.
///
/// Defaults to `&.{ 0x00000001 }` (QUIC v1 only) so v0.x embedders
/// keep the same wire posture they had before RFC 9368 v2 support
/// landed. Adding `0x6b3343cf` (`quic.QUIC_VERSION_2`) opts
/// the server into v2: incoming v2 Initials are accepted under
/// the §3.3.1 salt + §3.3.2 labels, outgoing Retries / VN frames
/// echo the negotiated version, and the optional
/// `version_information` (codepoint 0x11) transport parameter
/// advertises the full list to the peer for compatible-version
/// upgrade.
accepted_versions: []const u32 = &.{0x00000001},

/// RFC 8899 DPLPMTUD configuration applied to every accepted
/// connection. The default config (1200 floor, 1452 ceiling,
/// 64-byte step, 3-strike threshold, enabled) matches the
/// QUIC v1 minimum-MTU floor and the typical 1500-byte internet
/// MTU. Set `enable = false` to keep the static-MTU behaviour
/// (PMTU stays at `initial_mtu`).
pmtud: conn_mod.PmtudConfig = .{},

/// Congestion-control algorithm for every accepted connection:
/// `.cubic` (RFC 9438, the default as of 0.11.0), `.new_reno`
/// (RFC 9002, the historical default — the one-line rollback), or
/// `.bbr` (BBRv3, draft-ietf-ccwg-bbr-06, opt-in: model-based;
/// ignores `enable_hystart` and expects `enable_pacing = true`,
/// without which it degrades to window-limited bursts).
congestion_control: conn_mod.CongestionAlgorithm = .cubic,

/// RFC 9002 §7.7 packet pacing for every accepted connection (on
/// by default): spreads sends at gain x cwnd/RTT instead of
/// bursting a full window. `false` restores the pre-0.11 emission
/// timing exactly.
enable_pacing: bool = true,

/// RFC 9406 HyStart++ for every accepted connection (on by
/// default): leaves slow start on sustained RTT inflation instead
/// of waiting for the loss that overshooting the bottleneck
/// causes. `false` restores plain RFC 9002 slow start.
enable_hystart: bool = true,

/// RFC 9000 §18.2 / §5.1.1 server preferred-address advertisement.
/// Null disables the feature (default — no `preferred_address`
/// transport parameter is sent and clients have no server-driven
/// post-handshake migration target).
///
/// When set, every accepted connection's outbound transport
/// parameters carry a `preferred_address` value pointing at the
/// configured IPv4 / IPv6 address pair. The seq-1 server CID +
/// stateless reset token the parameter embeds is minted per-
/// connection through `mintLocalScid` + `conn.stateless_reset.derive`,
/// and queued on the connection as a NEW_CONNECTION_ID(seq=1)
/// equivalent so post-migration packets the client addresses
/// to the alt-CID authenticate. **Requires
/// `Config.stateless_reset_key`**; without it `Server.init`
/// returns `InvalidConfig` (the deterministic token derivation
/// is the only path quic surfaces for the seq-1 token).
///
/// `runUdpServer` consults this field to also bind alt listener
/// socket(s) on the configured port(s), poll all bound sockets
/// per iteration, and route outbound replies through the socket
/// the slot most recently received on. Embedders driving their
/// own loop are responsible for the multi-socket plumbing —
/// the codec auto-build still applies.
preferred_address: ?PreferredAddressConfig = null,

/// Argument to `Server.replaceTlsContext`. Either fresh PEM bytes
/// (the server rebuilds an internally-owned context with the same
/// shape `Server.init` produces) or a caller-built context the
/// embedder hands over wholesale. Re-exported as `Server.TlsReload`.
pub const TlsReload = union(enum) {
    /// Rebuild a fresh server context from PEM-encoded cert chain
    /// and private key. The new context is configured identically to
    /// `Server.init`'s default path: TLS-1.3 only, `verify=.none`,
    /// the server's currently-cached ALPN list, and the early-data
    /// posture the Server was originally initialized with via
    /// `Config.early_data`. The Server takes ownership of the
    /// resulting context and `deinit`s it (after refcounted draining)
    /// on `Server.deinit` or on a subsequent `replaceTlsContext`.
    pem: struct {
        /// PEM-encoded certificate chain (leaf first, then any
        /// intermediates). Must outlive only this call — the new
        /// `boringssl.tls.Context` parses the bytes during construction
        /// and copies what it needs.
        cert_pem: []const u8,
        /// PEM-encoded private key matching the leaf in `cert_pem`.
        /// Same lifetime constraint as `cert_pem`.
        key_pem: []const u8,
    },
    /// A caller-built context the Server should adopt as the new
    /// current context. Use this to wire up bespoke options the
    /// `pem` variant doesn't expose (custom verify modes, session
    /// ticket callbacks, ALPN protocols different from the
    /// init-time list, etc.). The Server takes ownership and will
    /// `deinit` the override when it eventually drains.
    override: boringssl.tls.Context,
};
