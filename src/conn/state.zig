//! quic.Connection — per-connection state machine root.
//!
//! The Connection wraps a `boringssl.tls.Conn` (the SSL object),
//! installs quic's `tls.quic.Method` callbacks, and exposes a
//! deterministic `advance` driver that pulls peer-provided CRYPTO
//! bytes through `provideQuicData` + `SSL_do_handshake` until the
//! handshake completes. Once handshake is done it owns packet number
//! spaces, ACK tracking, congestion control, flow control, the
//! stream layer, the multipath `PathSet`, key updates, and the
//! close/draining lifecycle.
//!
//! This file is the hub: the struct definition (fields), construction,
//! negotiated transport-parameter config, the close/draining
//! lifecycle, per-level dispatch shims, `tick`/`nextTimerDeadline`,
//! the TLS handshake driver + `tls.quic.Method` trampolines, and thin
//! delegating methods. The method bodies live in free-function
//! sibling files, each taking `*Connection` as its first argument:
//!
//!  - conn_send.zig          — canSend/poll*; the packet assembler
//!  - conn_recv_dispatch.zig — handle/handleWithEcn, packet open,
//!                             frame dispatch + gates, stateless reset
//!  - conn_recv_data_handlers.zig    — CRYPTO / STREAM / DATAGRAM
//!  - conn_recv_packet_handlers.zig  — per-level packet handlers
//!  - conn_recv_ack_handlers.zig     — inbound ACK processing
//!  - conn_recv_flow_handlers.zig    — MAX_* / *_BLOCKED frames
//!  - conn_recv_cid_token_handlers.zig / conn_recv_multipath_handlers.zig
//!  - conn_recv_stream_control_handlers.zig — STOP_SENDING/RESET_STREAM
//!  - conn_streams.zig       — stream open/id algebra/limits/GC + API
//!  - conn_flow.zig          — flow-control credit + blocked state
//!  - conn_datagram.zig      — RFC 9221 datagram API + events
//!  - conn_cids.zig          — local + peer CID registries/budgets
//!  - conn_keys.zig          — key schedule, 1-RTT key update, discard
//!  - conn_version.zig       — Initial accept, VN/Retry, version upgrade
//!  - conn_paths.zig         — multipath lifecycle, PATH_CHALLENGE, probes
//!  - conn_migration.zig     — RFC 9000 §9 migration + alt-address
//!  - conn_loss.zig          — RFC 9002 loss detection, PTO, deadlines
//!  - conn_qlog.zig          — qlog event types + emitters
//!  - path_frame_queue.zig / _internal.zig — multipath queueing + shared
//!                             CID helpers (pre-existing)
//!
//! Tests live in _state_tests_<area>.zig (aggregated by
//! _state_tests.zig); shared fixtures in _test_util.zig. Methods and
//! decls annotated `// INTERNAL:` are pub only for these sibling
//! files — they are not embedder API.

const std = @import("std");
const boringssl = @import("boringssl");
const c = boringssl.raw;

pub const level_mod = @import("../tls/level.zig");
pub const wire_header = @import("../wire/header.zig");
pub const short_packet_mod = @import("../wire/short_packet.zig");
pub const long_packet_mod = @import("../wire/long_packet.zig");
pub const initial_keys_mod = @import("../wire/initial.zig");
pub const transport_params_mod = @import("../tls/transport_params.zig");
pub const early_data_context_mod = @import("../tls/early_data_context.zig");
pub const varint = @import("../wire/varint.zig");
pub const frame_mod = @import("../frame/root.zig");
pub const frame_types = @import("../frame/types.zig");
pub const ack_range_mod = @import("../frame/ack_range.zig");
pub const ack_tracker_mod = @import("ack_tracker.zig");
pub const send_stream_mod = @import("send_stream.zig");
pub const recv_stream_mod = @import("recv_stream.zig");
pub const pn_space_mod = @import("pn_space.zig");
pub const sent_packets_mod = @import("sent_packets.zig");
pub const loss_recovery_mod = @import("loss_recovery.zig");
pub const path_mod = @import("path.zig");
pub const congestion_mod = @import("congestion.zig");
pub const rtt_mod = @import("rtt.zig");
pub const flow_control_mod = @import("flow_control.zig");
pub const event_queue_mod = @import("event_queue.zig");
pub const pending_frames_mod = @import("pending_frames.zig");
pub const lifecycle_mod = @import("lifecycle.zig");
pub const stateless_reset_mod = @import("stateless_reset.zig");
pub const path_frame_queue = @import("path_frame_queue.zig");
pub const pacing_mod = @import("pacing.zig");
pub const socket_opts_mod = @import("../transport/socket_opts.zig");
pub const _internal = @import("_internal.zig");
const conn_recv_flow_handlers = @import("conn_recv_flow_handlers.zig");
const conn_recv_cid_token_handlers = @import("conn_recv_cid_token_handlers.zig");
const conn_recv_multipath_handlers = @import("conn_recv_multipath_handlers.zig");
const conn_recv_stream_control_handlers = @import("conn_recv_stream_control_handlers.zig");
const conn_recv_packet_handlers = @import("conn_recv_packet_handlers.zig");
const conn_recv_ack_handlers = @import("conn_recv_ack_handlers.zig");
const conn_qlog = @import("conn_qlog.zig");
const conn_keys = @import("conn_keys.zig");
const conn_version = @import("conn_version.zig");
const conn_cids = @import("conn_cids.zig");
const conn_streams = @import("conn_streams.zig");
const conn_datagram = @import("conn_datagram.zig");
const conn_flow = @import("conn_flow.zig");
const conn_paths = @import("conn_paths.zig");
const conn_migration = @import("conn_migration.zig");
const conn_loss = @import("conn_loss.zig");
const conn_recv_data_handlers = @import("conn_recv_data_handlers.zig");
const conn_recv_dispatch = @import("conn_recv_dispatch.zig");
const conn_send = @import("conn_send.zig");
const conn_stats = @import("conn_stats.zig");

/// Encryption level (Initial / Handshake / 0-RTT / 1-RTT) — RFC 9001 §2.1.
pub const EncryptionLevel = level_mod.EncryptionLevel;
/// Read or write half-direction selector for keying material.
pub const Direction = level_mod.Direction;
/// Derived AEAD packet protection keys for a single direction.
pub const PacketKeys = short_packet_mod.PacketKeys;
/// Negotiated TLS cipher suite mapped to QUIC AEAD parameters.
pub const Suite = short_packet_mod.Suite;
/// Send half of a QUIC stream (RFC 9000 §3) — owns offset, flow credit, retransmit queue.
pub const SendStream = send_stream_mod.SendStream;
/// Receive half of a QUIC stream — owns reassembly buffer and flow-control window.
pub const RecvStream = recv_stream_mod.RecvStream;
/// Per-encryption-level packet number space (RFC 9000 §12.3).
pub const PnSpace = pn_space_mod.PnSpace;
/// In-flight packet bookkeeping for ACK processing and loss recovery.
pub const SentPacketTracker = sent_packets_mod.SentPacketTracker;
/// One network path (4-tuple plus DCID/SCID) — RFC 9000 §9 / multipath draft-21.
pub const Path = path_mod.Path;
/// Container holding all paths a connection currently knows about.
pub const PathSet = path_mod.PathSet;
/// Per-path validation/availability state machine.
pub const PathState = path_mod.PathState;
/// Per-path counters (datagrams sent/received, loss, RTT inputs).
pub const PathStats = path_mod.PathStats;
/// Whole-connection observability snapshot returned by `Connection.stats()`.
pub const ConnectionStats = conn_stats.ConnectionStats;
/// RFC 8899 DPLPMTUD probe-state-machine phase (re-export).
pub const PmtudState = path_mod.PmtudState;
/// RFC 8899 DPLPMTUD embedder configuration (re-export).
pub const PmtudConfig = path_mod.PmtudConfig;
/// Multipath scheduler that picks which path an outgoing datagram uses.
pub const Scheduler = path_mod.Scheduler;
/// QUIC connection ID — variable-length opaque identifier (RFC 9000 §5.1).
pub const ConnectionId = path_mod.ConnectionId;
/// IP address + port pair used as a path endpoint.
pub const Address = path_mod.Address;
/// PATH_CHALLENGE / PATH_RESPONSE state machine (RFC 9000 §8.2).
pub const PathValidator = path_mod.PathValidator;
/// Smoothed RTT / RTT-variance estimator (RFC 9002 §5).
pub const RttEstimator = rtt_mod.RttEstimator;
/// Decoded peer transport parameters from the TLS handshake (RFC 9000 §18).
pub const TransportParams = transport_params_mod.Params;
/// Default congestion controller — NewReno from RFC 9002 §7.
pub const NewReno = congestion_mod.NewReno;
/// Algorithm-dispatching congestion controller each path holds.
pub const CongestionController = congestion_mod.CongestionController;
/// Selectable congestion-control algorithm.
pub const CongestionAlgorithm = congestion_mod.Algorithm;
/// BoringSSL TLS session ticket handle, used for 0-RTT resumption.
pub const Session = boringssl.tls.Session;
/// 0-RTT acceptance/rejection status reported by BoringSSL.
pub const EarlyDataStatus = boringssl.tls.Conn.EarlyDataStatus;

/// Whether this Connection is the QUIC client or server endpoint.
pub const Role = enum { client, server };

/// Wire version code for QUIC v1 (RFC 9000 §15).
pub const quic_version_1: u32 = 0x00000001;

/// Aggregate error set returned from any Connection operation.
pub const Error = error{
    OutOfMemory,
    HandshakeFailed,
    InboxOverflow,
    PeerAlerted,
    UnsupportedCipherSuite,
    StreamAlreadyOpen,
    StreamNotFound,
    PnSpaceExhausted,
    PeerDcidNotSet,
    PathNotFound,
    PathLimitExceeded,
    /// `beginClientActiveMigration` before the handshake confirmed
    /// (RFC 9000 §9.6 forbids it). Retry after `handshake_established`.
    MigrationPreHandshake,
    /// `beginClientActiveMigration` while a path validation is already
    /// in flight. Retry once the current validation settles.
    MigrationValidationPending,
    /// `beginClientActiveMigration` found no fresh (unused) peer CID to
    /// rotate to (RFC 9000 §5.1.2 ¶1). Retry after the peer issues one
    /// via NEW_CONNECTION_ID; servers running quic-zig with a
    /// `stateless_reset_key` provision spares automatically post-
    /// handshake.
    MigrationNoFreshPeerCid,
    ConnectionIdLimitExceeded,
    ConnectionIdRequired,
    ConnectionIdAlreadyInUse,
    EmptyEarlyDataContext,
    KeyUpdateUnavailable,
    KeyUpdateBlocked,
    DatagramUnavailable,
    DatagramTooLarge,
    DatagramQueueFull,
    DatagramIdExhausted,
    InvalidStreamId,
    StreamLimitExceeded,
    /// A local stream open was refused because the connection is in
    /// graceful shutdown (`beginGracefulShutdown`): no new streams are
    /// created while in-flight streams drain. RFC 9000 has no GOAWAY, so
    /// this is a local-only signal paired with withheld MAX_STREAMS credit.
    ShuttingDown,
    /// `tryReserveResidentBytes` would push the connection past
    /// `max_connection_memory`. Hardening guide §3.5 / §8: peer-driven
    /// allocations (CRYPTO reassembly, DATAGRAM queues, stream
    /// reassembly / send queues) collectively must not exceed the
    /// per-Connection budget. Returned from any handler that detects
    /// an over-cap reservation; callers close the connection with
    /// `transport_error_excessive_load` and a redacted reason before
    /// the over-cap allocation lands.
    ExcessiveLoad,
    /// `Connection.setNewTokenCallback` /
    /// `Connection.queueNewToken` / `Connection.setInitialToken` were
    /// called on a connection in the wrong role (e.g. queueing a
    /// NEW_TOKEN on a client). Embedder-side misuse — peer input
    /// can never produce this.
    NotServerContext,
    NotClientContext,
    /// `Connection.queueNewToken` was called with a zero-length
    /// token, which RFC 9000 §19.7 forbids.
    ZeroLengthNewToken,
    /// `Connection.queueNewToken` was called with a token longer
    /// than `pending_frames.NewTokenItem.max_len`. quic mints
    /// fixed-shape 96-byte tokens via `conn.new_token.mint`; only
    /// custom embedder formats can hit this.
    NewTokenTooLong,
    /// `Connection.advertiseAlternativeV4Address` /
    /// `Connection.advertiseAlternativeV6Address` was called before
    /// the peer advertised support via the `alternative_address`
    /// transport parameter (draft-munizaga-quic-alternative-server-address-00 §4).
    /// Embedder-side misuse — advertising an alternative address to
    /// a peer that doesn't expect the frame would force a peer
    /// PROTOCOL_VIOLATION close.
    AlternativeAddressNotNegotiated,
    /// `Connection.advertiseAlternativeV4Address` /
    /// `Connection.advertiseAlternativeV6Address` ran out of fresh
    /// Status Sequence Numbers
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5).
    /// Saturating the counter and reusing the maximum value would
    /// silently violate the §6 ¶5 monotonically-increasing
    /// requirement — the receiver would dedupe the second emission
    /// as a retransmit and drop a real update on the floor.
    /// Embedders that hit this should restart the connection (or
    /// use a different connection for further advertisements);
    /// reaching 2^64 advertise calls on one connection without a
    /// teardown is functionally impossible, but failing closed is
    /// the right behavior at the boundary.
    AlternativeAddressSequenceExhausted,
    /// `Connection.noteServerLocalAddressChanged` was called on a
    /// connection whose `local_transport_params.preferred_address` is
    /// null. RFC 9000 §5.1.1 / §18.2: the server-initiated migration
    /// the API models is only meaningful when the server has advertised
    /// a `preferred_address` in its handshake transport parameters —
    /// without one, the client has no signal to migrate to and no
    /// remote 4-tuple can be authenticated against the advertised
    /// pair. Embedders hit this when wiring up the API on a server
    /// that never set `Server.Config.preferred_address`; the fix is
    /// either to configure a preferred address or to skip the call.
    PreferredAddressNotAdvertised,
} || boringssl.tls.Error ||
    boringssl.crypto.rand.Error ||
    short_packet_mod.Error ||
    long_packet_mod.Error ||
    send_stream_mod.Error ||
    recv_stream_mod.Error ||
    sent_packets_mod.Error ||
    flow_control_mod.Error ||
    frame_mod.EncodeError ||
    frame_mod.DecodeError ||
    ack_range_mod.Error ||
    ack_tracker_mod.Error ||
    transport_params_mod.Error;

/// Per-level secret bookkeeping. The TLS bridge stores the BoringSSL
/// cipher protocol-id plus raw traffic secret; packet-protection keys
/// are derived on demand from the negotiated suite.
pub const SecretMaterial = struct {
    cipher_protocol_id: u16,
    secret: [64]u8 = @splat(0),
    secret_len: u8 = 0,
};

/// Read+write traffic-secret material for one TLS encryption level.
/// Either half can be `null` until BoringSSL installs that direction.
pub const PerLevelState = struct {
    read: ?SecretMaterial = null,
    write: ?SecretMaterial = null,
};

/// RFC 9218 (Extensible Priorities) per-stream send priority — the minimal
/// two-parameter model, no RFC 7540 dependency tree. `urgency` 0 is most
/// urgent … 7 least (default 3); `incremental` is a hint that a response may
/// be delivered in interleaved chunks. The application-data send scheduler
/// orders ready streams by urgency then stream id (see `streamSetPriority`,
/// `streamPriority`, and `docs/stream-priority.md`).
pub const StreamPriority = struct {
    urgency: u3 = 3,
    incremental: bool = false,
};

/// One QUIC stream — bundles the send and receive halves with a
/// stable `id`. Bidi or uni is a property of the id (RFC 9000 §2.1
/// stream IDs encode direction in the low two bits); `streamIsUni` /
/// `streamIsBidi` decode the direction.
pub const Stream = struct {
    id: u64,
    send: SendStream,
    recv: RecvStream,
    /// Current stream-level receive limit we have advertised for this
    /// stream via transport params / MAX_STREAM_DATA.
    recv_max_data: u64 = 0,
    /// Current stream-level send limit the peer has advertised via
    /// transport params / MAX_STREAM_DATA.
    send_max_data: u64 = std.math.maxInt(u64),
    /// One past the highest stream byte we have ever put on the wire.
    /// Retransmissions below this floor do not consume flow control.
    send_flow_highest: u64 = 0,
    /// True once any byte for this stream arrived in a 0-RTT packet.
    arrived_in_early_data: bool = false,
    /// True once this peer-initiated stream has returned one stream
    /// count credit through MAX_STREAMS.
    stream_count_credit_returned: bool = false,

    /// RFC 9218 send priority. Default urgency 3 / non-incremental, so a
    /// connection with no explicit priorities schedules ready streams in
    /// stream-id order (unchanged from the pre-priority behavior).
    priority: StreamPriority = .{},

    /// True if the recv side has reached one of the four "no further
    /// peer bytes will land" states. Mirrors `maybeReturnPeerStreamCredit`'s
    /// definition: FIN-with-bytes-drained (data_recvd / data_read) or
    /// peer RESET (reset_recvd / reset_read). Used by the connection-
    /// level stream GC to decide whether the receive half is structurally
    /// dead.
    pub fn recvFullyTerminated(self: *const Stream) bool {
        return self.recv.state == .data_recvd or
            self.recv.state == .data_read or
            self.recv.state == .reset_recvd or
            self.recv.state == .reset_read;
    }
};

/// Default datagram budget for outgoing 1-RTT packets. RFC 9000 §14
/// mandates at least 1200 bytes path MTU; DPLPMTUD (RFC 8899) can
/// lift this per path.
pub const default_mtu: usize = 1200;
/// RFC 9000 §20.1 INTERNAL_ERROR (0x01): the endpoint hit an internal
/// problem and cannot continue. quic uses it as the catch-all for
/// failures with no more specific code — never for a TLS rejection,
/// which gets RFC 9001 §4.8's CRYPTO_ERROR window instead. Note the
/// bucket is not purely local-side today: a peer-driven resource
/// failure that reaches `Server`'s per-connection catch without
/// having closed itself first lands here too, where EXCESSIVE_LOAD
/// (0x09) would be more precise.
pub const transport_error_internal: u64 = 0x01;
pub const transport_error_protocol_violation: u64 = 0x0a;
pub const transport_error_flow_control: u64 = 0x03;
pub const transport_error_stream_limit: u64 = 0x04;
pub const transport_error_stream_state: u64 = 0x05;
pub const transport_error_final_size: u64 = 0x06;
pub const transport_error_frame_encoding: u64 = 0x07;
pub const transport_error_transport_parameter: u64 = 0x08;
/// RFC 9000 §20.1 / §3.5: a server that runs out of resource budget for
/// peer-controlled state (CRYPTO reassembly, DATAGRAM queues, stream
/// buffers) closes the connection with EXCESSIVE_LOAD (0x09) rather
/// than spilling unbounded peer input into the host allocator. The
/// This is the connection-wide "memory cap" DoS backstop.
pub const transport_error_excessive_load: u64 = 0x09;
pub const transport_error_aead_limit_reached: u64 = 0x0f;
/// RFC 9000 §20.1 / §10.2.3: the generic transport-error code used when
/// converting an application-variant CONNECTION_CLOSE (0x1d) to the
/// transport variant (0x1c) for emission at Initial/Handshake levels —
/// "the application or application protocol caused the connection to
/// be closed."
pub const transport_error_application_error: u64 = 0x0c;

/// RFC 9001 §4.8 CRYPTO_ERROR base. "The alert description is added to
/// 0x0100 to produce a QUIC error code from the range reserved for
/// CRYPTO_ERROR" — so the whole 0x0100-0x01ff window means "TLS
/// rejected this connection". `sendAlert` performs the addition.
pub const transport_error_crypto_base: u64 = 0x0100;

/// RFC 9001 §4.8's generic stand-in: CRYPTO_ERROR carrying the TLS
/// `handshake_failure` alert (40 / 0x28). §4.8 explicitly permits
/// "replacing any alert with a generic alert, such as
/// handshake_failure (0x0128 in QUIC)". Used when the handshake failed
/// but the TLS stack raised no alert of its own, so an alert-less TLS
/// failure still lands in the CRYPTO_ERROR window a peer or embedder
/// can classify — instead of being mislabeled INTERNAL_ERROR.
pub const transport_error_crypto_handshake_failure: u64 =
    transport_error_crypto_base + 0x28;

/// Default per-Connection cap on bytes resident in peer-controlled
/// reassembly buffers (CRYPTO, DATAGRAM, stream send/recv). Hits at
/// 32 MiB — comfortably above the per-stream / per-CRYPTO-level
/// budgets the per-buffer caps already enforce, so legitimate
/// traffic stays inside it, but well below the host RSS that a
/// flood of orthogonal buffers could otherwise push us into.
/// Tuneable per `Connection` via `max_connection_memory`; the
/// `Server.Config` default threads through to every accepted slot.
pub const default_max_connection_memory: u64 = 32 * 1024 * 1024;

/// Upper bound on AEAD plaintext for a single received packet. This
/// implementation deliberately advertises and enforces the same 4 KiB
/// UDP payload budget so packet protection can stay stack-backed.
pub const max_recv_plaintext: usize = 4096;
/// Largest UDP payload size we will advertise to the peer in transport params.
pub const max_supported_udp_payload_size: usize = max_recv_plaintext;
/// Wire-mandated minimum UDP payload size for Initial packets (RFC 9000 §14).
pub const min_quic_udp_payload_size: usize = default_mtu;

/// Bounded queue budgets for RFC 9221 DATAGRAM payloads.
pub const max_outbound_datagram_payload_size: usize = default_mtu - 9;
/// Maximum number of unsent outbound DATAGRAM frames buffered at once.
pub const max_pending_datagram_count: usize = 64;
/// Maximum total byte volume of unsent outbound DATAGRAM frames buffered at once.
pub const max_pending_datagram_bytes: usize = 64 * 1024;

/// Bounded reassembly budgets for peer-controlled CRYPTO gaps.
pub const max_pending_crypto_bytes_per_level: usize = 64 * 1024;
/// Maximum number of out-of-order CRYPTO fragments buffered per level.
/// The byte cap alone does not bound the *fragment count*: a peer could
/// flood tens of thousands of 1-byte out-of-order fragments (all within
/// the byte budget), and `drainPendingCrypto`'s linear-scan-and-remove
/// loop is O(n²) in the fragment count — a CPU-exhaustion vector. A
/// legitimate handshake flight fragments into at most a handful of
/// packets per level, so this cap is generous; overflow is a peer
/// protocol violation. Mirrors `max_pending_datagram_count`.
pub const max_pending_crypto_fragments_per_level: usize = 128;
/// Largest gap (in bytes) we will tolerate between in-order CRYPTO data and a
/// future fragment before treating the peer's stream as malicious.
pub const max_crypto_reassembly_gap: u64 = 64 * 1024;
/// Number of ack-eliciting application packets we accept before forcing an
/// ACK frame (RFC 9000 §13.2.2).
pub const application_ack_eliciting_threshold: u8 = 1;
/// Hard cap on total bytes spent on ACK ranges in any single application packet.
///
/// These caps are deliberately SINGLE-TIER. A two-tier variant — keep
/// this budget for packets that also carry STREAM data, spend a wider
/// one (256 B / 64 ranges) on standalone ACKs where no payload is
/// being crowded out — has been built and measured twice and rejected
/// both times:
///   * 2026-05 (`5b9a4f6`): regressed multiplexing completion under a
///     bursty 10 Mbps simulator.
///   * 2026-08: re-measured against the bottleneck impairment cells,
///     including the 8-stream multiplexed one, with pacing enabled
///     (pacing was the hypothesis for why it should matter now, since
///     pacing-blocked polls emit standalone ACKs). Every cell came out
///     bit-identical — no regression, but no benefit either: during a
///     bulk transfer the range cap simply does not bind.
/// It is not free: a wider standalone ACK is a bigger packet on the
/// return path, which matters on asymmetric links. Re-open only with a
/// workload that demonstrably makes the 16-range cap bind (bursty or
/// correlated loss producing many disjoint gaps) — not on the
/// principle alone.
pub const max_application_ack_ranges_bytes: usize = 128;
/// Hard cap on the number of additional (non-largest) ACK ranges per application packet.
pub const max_application_ack_lower_ranges: u64 = 16;
/// Per-`handle`-cycle ceiling on cumulative ACK ranges drained from
/// inbound ACK / PATH_ACK frames. Sized at 4× the per-frame decoder
/// cap (`frame.decode.max_incoming_ack_ranges = 256`) so well-behaved
/// multipath peers can ACK across roughly 4 active paths in one
/// datagram before tripping the gate. Beyond that, additional frames
/// are skipped (see RFC 9000 §19.3 — ACK is not ack-eliciting and
/// dropping does not affect connection liveness).
pub const incoming_ack_range_cap: u64 = 4 * @import("../frame/decode.zig").max_incoming_ack_ranges;
/// Per-`handle`-cycle ceiling on RETIRE_CONNECTION_ID frames. The
/// `active_connection_id_limit` hard cap is 16 (transport_params.zig);
/// 4× that gives steady-state churn headroom for a legitimate peer
/// rotating CIDs aggressively without enabling a flood attack.
pub const incoming_retire_cid_cap: u64 = 64;

/// Default per-stream receive credit advertised in transport params.
pub const default_stream_receive_window: u64 = 1024 * 1024;
/// Default connection-level receive credit advertised in transport params.
pub const default_connection_receive_window: u64 = 16 * 1024 * 1024;
/// Hard ceiling on `initial_max_streams_*` we will ever advertise.
pub const max_stream_count_limit: u64 = @as(u64, 1) << 60;
/// Minimum number of stream credits to accumulate before sending MAX_STREAMS.
pub const min_stream_credit_return_batch: u64 = 16;
/// Divisor controlling the watermark at which MAX_STREAMS replenishment fires.
pub const stream_credit_return_divisor: u64 = 1;

/// Minimum interval between path-validation probes (PATH_CHALLENGE
/// emissions) for the same path. Hardens against a peer that
/// repeatedly switches source addresses to force fresh validator
/// state and burn server CPU minting tokens. 100 ms is short enough
/// that a real NAT rebinding-then-immediate-keepalive sequence still
/// validates within one RTT, and long enough to stop any
/// adversarial probe-flood. Surfaced in qlog as
/// `migration_fail_reason = .rate_limited`.
pub const min_path_challenge_interval_us: u64 = 100_000;

/// Implementation allocation policy. QUIC's wire limits are intentionally
/// enormous; quic caps the resources it advertises and tracks so peer input
/// cannot force unbounded stream/path/CID state.
pub const max_streams_per_connection: u64 = 4096;
/// Largest QUIC multipath path identifier we accept (draft-ietf-quic-multipath-21).
pub const max_supported_path_id: u32 = 255;
/// Hard cap on the `active_connection_id_limit` we honour from the peer.
pub const max_supported_active_connection_id_limit: u64 = 16;
/// Maximum unique (stream_id, offset) pairs we remember for STREAM_DATA_BLOCKED
/// dedupe before refusing to track more.
pub const max_tracked_stream_data_blocked: usize = 8192;
/// Upper bound on `initial_max_data` we accept from peer transport params.
pub const max_initial_connection_receive_window: u64 = default_connection_receive_window;
/// Upper bound on `initial_max_stream_data_*` we accept from peer transport params.
pub const max_initial_stream_receive_window: u64 = recv_stream_mod.default_max_buffered_span;

/// One out-of-order CRYPTO fragment held in `crypto_pending[lvl]`
/// until enough lower-offset bytes have arrived for it to be
/// delivered to TLS via `provideQuicData`.
pub const CryptoChunk = struct {
    offset: u64,
    /// Allocator-owned bytes. Freed when delivered or on `deinit`.
    data: []u8,
};

/// One CRYPTO fragment that has been written into a sent packet and is
/// awaiting acknowledgement. Tracks the packet number it rode in so the
/// ACK / loss path can match it back to a retransmission queue.
pub const SentCryptoChunk = struct {
    pn: u64,
    offset: u64,
    /// Allocator-owned bytes. Freed on ACK or moved back to
    /// `crypto_retx` on loss.
    data: []u8,
};

/// One peer-issued connection ID stashed from a NEW_CONNECTION_ID
/// frame (RFC 9000 §19.15).
pub const IssuedCid = struct {
    path_id: u32 = 0,
    sequence_number: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [16]u8,
};

/// Outgoing CONNECTION_CLOSE intent.
pub const ConnectionCloseInfo = lifecycle_mod.ConnectionCloseInfo;

/// Origin of a connection-close event surfaced through `nextEvent`.
pub const CloseSource = lifecycle_mod.CloseSource;

/// QUIC distinguishes transport-level (RFC 9000 §20.1) from application-level
/// (RFC 9000 §20.2) errors; this enum tags which space `error_code` lives in.
pub const CloseErrorSpace = lifecycle_mod.CloseErrorSpace;

/// High-level connection lifecycle state — RFC 9000 §10 (closing/draining).
pub const CloseState = lifecycle_mod.CloseState;

/// Maximum length of a CONNECTION_CLOSE reason phrase we will record/emit.
pub const max_close_reason_len: usize = lifecycle_mod.max_close_reason_len;

/// Snapshot of a close event delivered to the embedder via `nextEvent`.
/// Captures source, error space/code and (optionally) the wire-level frame
/// type that triggered the close. RFC 9000 §10.
pub const CloseEvent = lifecycle_mod.CloseEvent;

/// Pure close/draining state extracted from `Connection` — re-exported
/// for tests that want to assert on it directly.
pub const LifecycleState = lifecycle_mod.LifecycleState;

/// The (initiator, directionality) class encoded in the low two bits of a
/// stream id (RFC 9000 §2.1): bit 0 is the initiator (0 = client, 1 =
/// server), bit 1 is directionality (0 = bidirectional, 1 = unidirectional).
/// Provided so embedders (notably an HTTP/3 layer classifying the control
/// stream and QPACK encoder/decoder streams) don't hand-roll the bit math.
pub const StreamType = enum(u2) {
    client_bidi = 0b00,
    server_bidi = 0b01,
    client_uni = 0b10,
    server_uni = 0b11,

    /// The stream type encoded in the low two bits of `id` (RFC 9000 §2.1).
    pub fn fromId(id: u64) StreamType {
        return @fromBackingInt(@intCast(@as(u2, @truncate(id))));
    }

    /// Compose the stream id for this type at 0-based per-type sequence
    /// `index`: `id = (index << 2) | type`. Asserts `index` fits the
    /// 62-bit stream-id space.
    pub fn streamId(self: StreamType, index: u64) u64 {
        std.debug.assert(index <= (std.math.maxInt(u64) >> 2));
        return (index << 2) | @backingInt(self);
    }

    pub fn isBidi(self: StreamType) bool {
        return (@backingInt(self) & 0b10) == 0;
    }

    pub fn isUni(self: StreamType) bool {
        return !self.isBidi();
    }

    pub fn initiatedByClient(self: StreamType) bool {
        return (@backingInt(self) & 0b01) == 0;
    }

    pub fn initiatedByServer(self: StreamType) bool {
        return !self.initiatedByClient();
    }
};

/// Coarse connection lifecycle phase for embedder state machines (e.g. an
/// HTTP/3 layer gating stream creation and shutdown). Composes the
/// handshake epoch with the RFC 9000 §10 close states so embedders don't
/// have to infer them from `handshakeDone()` / `closeState()` / `haveSecret`
/// by hand. See `Connection.phase`.
pub const ConnectionPhase = enum {
    /// Only Initial keys installed — still in the Initial exchange.
    initial,
    /// Handshake keys installed; TLS handshake not yet complete.
    handshake,
    /// 1-RTT (application) keys installed — the application-data phase.
    established,
    /// Local CONNECTION_CLOSE sent; draining output (RFC 9000 §10.2.1).
    closing,
    /// Peer CONNECTION_CLOSE received / stateless reset; draining (§10.2.2).
    draining,
    /// Terminal: fully closed, no further packets flow.
    closed,
};

/// Tagged-union of all connection-level events the embedder polls via `nextEvent`.
/// Each variant carries enough context for the embedder to react without re-querying
/// Connection state.
/// Point-in-time send-side flow-control view for one stream
/// (RFC 9000 §4, the sender's half). All figures are NEW-data bytes:
/// retransmissions below the wire high-water mark consume no credit
/// and are invisible here. Congestion control and pacing are
/// deliberately excluded — this answers "what would the peer's
/// windows accept", the input backpressure needs; `sendAllowance`
/// on the congestion side answers "what may leave right now".
pub const SendWindow = struct {
    /// Connection-level credit remaining: peer `max_data` minus new
    /// stream bytes already sent. Shared across all streams — two
    /// streams both reporting 10 KB here are drawing on the same 10 KB.
    connection: u64,
    /// Stream-level credit remaining: peer `max_stream_data` minus
    /// this stream's wire high-water mark.
    stream: u64,
    /// This stream's queued-but-unsent NEW bytes (accepted by
    /// `streamWrite`, not yet on the wire). They will consume credit
    /// when they go out, so they are already subtracted from
    /// `writable`.
    queued: u64,
    /// `min(connection, stream) -| queued`: bytes a further
    /// `streamWrite` could accept AND eventually transmit as new data
    /// under the current peer windows, ignoring other streams' queues.
    /// The number a `canWrite`-style backpressure gate wants.
    writable: u64,
};

pub const ConnectionEvent = union(enum) {
    close: CloseEvent,
    /// The TLS handshake just completed (`handshakeDone()` latched true):
    /// 1-RTT application traffic is fully usable in both directions.
    /// Emitted exactly once per connection, lazily, on the first
    /// `pollEvent` after completion. Note a server accepting 0-RTT can
    /// surface `stream_opened` events *before* this one.
    handshake_established,
    /// The 0-RTT outcome resolved: emitted exactly once, lazily on
    /// `pollEvent`, carrying `.accepted` or `.rejected` — connections
    /// that never attempt 0-RTT get no event. `.rejected` is
    /// deliberately withheld until the rejected early-data packets
    /// have been requeued verbatim for 1-RTT (the CONTRACT in
    /// `requeueRejectedEarlyData`), so a reactor observes the
    /// post-requeue state; note that by then the client-side
    /// `earlyDataStatus()` may already read `.not_offered` again (the
    /// rejection handler restarts the TLS handshake), which is why
    /// this event, not that poll, is the reliable rejection signal.
    /// Replaces per-drain status polling for embedders driving
    /// remembered-settings replay.
    early_data: EarlyDataStatus,
    /// A peer-initiated stream was opened, explicitly or implicitly
    /// (RFC 9000 §3.2). Delivery is lossless and in per-type index order
    /// — see `StreamOpenedInfo` for the watermark semantics and the
    /// already-terminal caveat.
    stream_opened: StreamOpenedInfo,
    flow_blocked: FlowBlockedInfo,
    connection_ids_needed: ConnectionIdReplenishInfo,
    datagram_acked: DatagramSendEvent,
    datagram_lost: DatagramSendEvent,
    /// One ALTERNATIVE_V4/V6_ADDRESS update received from the peer
    /// (draft-munizaga-quic-alternative-server-address-00 §6). Only
    /// surfaced when the local endpoint advertised support via the
    /// §4 `alternative_address` transport parameter and the peer's
    /// Status Sequence Number is strictly greater than every previous
    /// update — see `AlternativeServerAddressEvent` for the dedup /
    /// reorder rules.
    alternative_server_address: AlternativeServerAddressEvent,
};

/// Whether a flow-control block was hit on the local side or reported by the peer.
pub const FlowBlockedSource = event_queue_mod.FlowBlockedSource;
/// Which flow-control axis ran out of credit — connection data, per-stream data,
/// or stream-count (RFC 9000 §4 / §19.12-§19.14).
pub const FlowBlockedKind = event_queue_mod.FlowBlockedKind;
/// One flow-control block event delivered to the embedder via `nextEvent`. Carries
/// the limit that was hit and (for stream-data) which stream tripped it.
pub const FlowBlockedInfo = event_queue_mod.FlowBlockedInfo;
/// Maximum buffered FlowBlockedInfo events before older entries are dropped.
pub const max_flow_blocked_events: usize = event_queue_mod.max_flow_blocked_events;
/// Why the connection is asking the embedder to issue more local connection IDs.
pub const ConnectionIdReplenishReason = event_queue_mod.ConnectionIdReplenishReason;
/// Embedder-visible snapshot of CID-issuance state when the active count drops
/// below the peer's `active_connection_id_limit` (RFC 9000 §5.1.1).
pub const ConnectionIdReplenishInfo = event_queue_mod.ConnectionIdReplenishInfo;
/// Maximum buffered CID replenish events before older entries are dropped.
pub const max_connection_id_events: usize = event_queue_mod.max_connection_id_events;
/// One ACK or loss event for a previously-sent RFC 9221 DATAGRAM frame, returned
/// to the embedder so it can reconcile its outbound queue.
pub const DatagramSendEvent = event_queue_mod.DatagramSendEvent;
/// Maximum buffered datagram ack/loss events before older entries are dropped.
pub const max_datagram_send_events: usize = event_queue_mod.max_datagram_send_events;
/// One §6 update surfaced via `Connection.pollEvent`.
pub const AlternativeServerAddressEvent = event_queue_mod.AlternativeServerAddressEvent;
/// One IPv4 update — payload of `AlternativeServerAddressEvent.v4`.
pub const AlternativeServerAddressV4Event = event_queue_mod.AlternativeServerAddressV4Event;
/// One IPv6 update — payload of `AlternativeServerAddressEvent.v6`.
pub const AlternativeServerAddressV6Event = event_queue_mod.AlternativeServerAddressV6Event;
/// Maximum buffered alt-address events before older entries are dropped.
pub const max_alternative_address_events: usize = event_queue_mod.max_alternative_address_events;

const StoredDatagramSendEvent = event_queue_mod.StoredDatagramSendEvent;

const StoredCloseEvent = lifecycle_mod.StoredCloseEvent;

/// One newly-opened peer-initiated stream — payload of
/// `ConnectionEvent.stream_opened`.
pub const StreamOpenedInfo = event_queue_mod.StreamOpenedInfo;

/// One queued STOP_SENDING frame (RFC 9000 §19.5) with its application error code.
pub const StopSendingItem = pending_frames_mod.StopSendingItem;

/// One queued MAX_STREAM_DATA frame (RFC 9000 §19.10) with the new credit value.
pub const MaxStreamDataItem = pending_frames_mod.MaxStreamDataItem;

/// One queued NEW_CONNECTION_ID frame (RFC 9000 §19.15) the embedder has handed
/// to the connection and is awaiting transmission.
pub const PendingNewConnectionId = pending_frames_mod.PendingNewConnectionId;

/// Embedder-supplied bundle when calling `provideConnectionId`/`provisionPathConnectionId`
/// to install a fresh local CID and its stateless reset token.
pub const ConnectionIdProvision = struct {
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
    retire_prior_to: u64 = 0,
};

/// Snapshot reported when peer-issued CIDs for a path run dry — used to drive
/// PATH_CIDS_BLOCKED frames on the multipath extension.
pub const PathCidsBlockedInfo = struct {
    path_id: u32,
    next_sequence_number: u64,
};

/// One queued PATH_AVAILABLE / PATH_BACKUP frame from draft-ietf-quic-multipath-21.
pub const PendingPathStatus = pending_frames_mod.PendingPathStatus;

/// Header-only descriptor returned from `pollDatagram` — paired with the bytes
/// the caller wrote into the supplied buffer.
pub const OutgoingDatagram = struct {
    len: usize,
    to: ?Address = null,
    path_id: u32 = 0,
};

/// Embedder-visible descriptor for a peer datagram received via `handleDatagram`.
/// `arrived_in_early_data` propagates the 0-RTT-vs-1-RTT distinction up to the app.
pub const IncomingDatagram = struct {
    len: usize,
    arrived_in_early_data: bool = false,
};

/// Read-only snapshot of a stream's send half, returned by
/// `Connection.streamSendStats`. `buffered` (`written - acked`) is the
/// resident send-buffer volume — the value an embedder watches for
/// application-level write backpressure.
pub const StreamSendStats = struct {
    /// Total bytes the app has queued via `streamWrite` (the write offset).
    written: u64,
    /// Bytes contiguously acknowledged from offset 0.
    acked: u64,
    /// Bytes written but not yet acknowledged (`written - acked`).
    buffered: u64,
    /// Whether any bytes — or a queued FIN / RESET — are ready to send now.
    has_pending: bool,
};

/// Result of `Connection.streamReadFin`: the bytes read, plus whether the
/// peer's FIN has been observed for the stream.
pub const StreamReadResult = struct {
    /// Bytes copied into the caller's buffer (0 when empty or drained).
    n: usize,
    /// True once a STREAM frame carrying the FIN bit has been accepted for
    /// this stream — no more data will arrive. Surfaced inline with the read
    /// that drains the final bytes, so a caller need not inspect the receive
    /// half separately (which the stream GC reaps the moment it goes terminal).
    fin: bool,
};

/// Read-only recv-half status of a stream, from `Connection.streamRecvState`.
pub const StreamRecvState = struct {
    /// A STREAM frame with the FIN bit has been accepted (clean end).
    fin_seen: bool,
    /// A RESET_STREAM has been received (abortive end) — the counterpart to
    /// `fin_seen` that `recvFullyTerminated` otherwise collapses together.
    reset_seen: bool,
    /// The receive half has structurally terminated: FIN drained to EOF or a
    /// RESET was received, so no further peer bytes will be delivered
    /// (RFC 9000 §3.2).
    terminal: bool,
};

const PendingRecvDatagram = pending_frames_mod.PendingRecvDatagram;
const PendingSendDatagram = pending_frames_mod.PendingSendDatagram;

/// Distinct timers the Connection drives. The embedder only ever sees one at
/// a time via `nextTimer` — the earliest pending — but the kind disambiguates
/// what `tick` will do when it fires.
pub const TimerKind = enum {
    ack_delay,
    loss_detection,
    pto,
    idle,
    /// RFC 9002 §7.7 pacing: application data is waiting on send
    /// credit; `at_us` is when the pacer's token bucket next covers a
    /// full datagram. `tick` does nothing for this kind — waking and
    /// draining the outbox (the loop's normal post-tick step) is the
    /// action.
    pacing,
    /// RFC 9000 §10.2.1 closing-state expiry. The connection has sent
    /// a CONNECTION_CLOSE; this timer fires at `now + 3 * PTO` after
    /// the first emit and transitions the connection to terminal
    /// closed (skipping draining if the peer's CC never arrives).
    closing,
    /// RFC 9000 §10.2.2 draining-state expiry. The connection has
    /// received the peer's CONNECTION_CLOSE (or hit idle timeout /
    /// stateless reset); this timer fires after the
    /// `lifecycle.draining_deadline_us` interval and transitions the
    /// connection to terminal closed.
    draining,
    path_retirement,
    key_discard,
};

/// One pending timer expiry returned from `nextTimer`. `level` and `path_id`
/// are populated for kinds that are scoped (e.g. key_discard / path_retirement);
/// the embedder treats them as opaque and just feeds `at_us` back into `tick`.
pub const TimerDeadline = struct {
    kind: TimerKind,
    at_us: u64,
    level: ?EncryptionLevel = null,
    path_id: u32 = 0,
};

// INTERNAL: pub for _state_tests.zig access; not part of embedder API.
pub const LossStats = struct {
    count: u32 = 0,
    bytes_lost: u64 = 0,
    in_flight_bytes_lost: u64 = 0,
    earliest_lost_sent_time_us: ?u64 = null,
    largest_lost_sent_time_us: u64 = 0,
    /// RFC 9002 §7.6.1 mandates that persistent congestion be
    /// determined only from ack-eliciting packets. We therefore
    /// track the time bounds of the *ack-eliciting* lost subset
    /// separately so the unfiltered counters above stay usable
    /// for cwnd reduction (which doesn't need the filter).
    ack_eliciting_count: u32 = 0,
    earliest_ack_eliciting_lost_sent_time_us: ?u64 = null,
    largest_ack_eliciting_lost_sent_time_us: u64 = 0,

    pub fn add(self: *LossStats, packet: sent_packets_mod.SentPacket) void {
        self.count += 1;
        self.bytes_lost += packet.bytes;
        if (packet.in_flight) self.in_flight_bytes_lost += packet.bytes;
        if (self.earliest_lost_sent_time_us == null or
            packet.sent_time_us < self.earliest_lost_sent_time_us.?)
        {
            self.earliest_lost_sent_time_us = packet.sent_time_us;
        }
        if (packet.sent_time_us > self.largest_lost_sent_time_us) {
            self.largest_lost_sent_time_us = packet.sent_time_us;
        }
        if (packet.ack_eliciting) {
            self.ack_eliciting_count += 1;
            if (self.earliest_ack_eliciting_lost_sent_time_us == null or
                packet.sent_time_us < self.earliest_ack_eliciting_lost_sent_time_us.?)
            {
                self.earliest_ack_eliciting_lost_sent_time_us = packet.sent_time_us;
            }
            if (packet.sent_time_us > self.largest_ack_eliciting_lost_sent_time_us) {
                self.largest_ack_eliciting_lost_sent_time_us = packet.sent_time_us;
            }
        }
    }
};

/// Tunables governing automatic 1-RTT key updates. Defaults follow the
/// RFC 9001 §6.6 confidentiality / integrity limits and an early proactive
/// rotation point so the connection never has to spend its last legal packet
/// on CONNECTION_CLOSE.
pub const ApplicationKeyUpdateLimits = struct {
    /// RFC 9001 §6.6 gives AES-GCM a 2^23 packet confidentiality limit.
    /// ChaCha20-Poly1305 does not force a lower update point, so the
    /// default uses the cross-suite conservative floor.
    confidentiality_limit: u64 = @as(u64, 1) << 23,
    /// Update slightly before the hard limit so we don't need to spend
    /// the last legal packet on CONNECTION_CLOSE.
    proactive_update_threshold: u64 = (@as(u64, 1) << 23) - 1024,
    /// RFC 9001 §6.6 gives ChaCha20-Poly1305 the strictest invalid-
    /// packet integrity limit among the supported QUIC v1 suites.
    integrity_limit: u64 = @as(u64, 1) << 36,
};

/// Read-only snapshot of 1-RTT key update bookkeeping returned from
/// `applicationKeyUpdateStatus()`. Useful for tests, qlog, and embedders
/// that want to surface key-rotation telemetry.
pub const ApplicationKeyUpdateStatus = struct {
    read_epoch: ?u64 = null,
    read_key_phase: bool = false,
    previous_read_discard_deadline_us: ?u64 = null,
    next_read_epoch_ready: bool = false,
    write_epoch: ?u64 = null,
    write_key_phase: bool = false,
    write_packets_protected: u64 = 0,
    write_update_pending_ack: bool = false,
    next_local_update_after_us: ?u64 = null,
    auth_failures: u64 = 0,
};

/// Tag identifying a qlog event (modeled on draft-ietf-quic-qlog-quic-events);
/// declared in conn_qlog.zig.
pub const QlogEventName = conn_qlog.QlogEventName;
/// QUIC packet type as it appears in qlog packet events; declared in conn_qlog.zig.
pub const QlogPacketKind = conn_qlog.QlogPacketKind;
/// Why a packet was dropped before frame dispatch; declared in conn_qlog.zig.
pub const QlogPacketDropReason = conn_qlog.QlogPacketDropReason;
/// Packet number space tag carried in qlog packet/loss events; declared in conn_qlog.zig.
pub const QlogPnSpace = conn_qlog.QlogPnSpace;
/// Stream lifecycle state reported via qlog `stream_state_updated`; declared in conn_qlog.zig.
pub const QlogStreamState = conn_qlog.QlogStreamState;
/// Congestion-controller phase reported via qlog `congestion_state_updated`;
/// declared in conn_qlog.zig.
pub const QlogCongestionState = conn_qlog.QlogCongestionState;
/// Why a packet was declared lost (RFC 9002 §6); declared in conn_qlog.zig.
pub const QlogLossReason = conn_qlog.QlogLossReason;
/// Why a candidate path failed to validate; declared in conn_qlog.zig.
pub const QlogMigrationFailReason = conn_qlog.QlogMigrationFailReason;
/// Qlog event payload delivered to the embedder's `QlogCallback`; declared in conn_qlog.zig.
pub const QlogEvent = conn_qlog.QlogEvent;
/// Embedder-supplied qlog sink callback; declared in conn_qlog.zig.
pub const QlogCallback = conn_qlog.QlogCallback;

/// Allow / deny verdict returned by a `MigrationCallback`; declared in conn_migration.zig.
pub const MigrationDecision = conn_migration.MigrationDecision;
/// Embedder policy hook consulted on peer migration candidates (RFC 9000 §9);
/// declared in conn_migration.zig.
pub const MigrationCallback = conn_migration.MigrationCallback;
/// Callback fired when a client receives a NEW_TOKEN frame (RFC 9000 §8.1.3);
/// declared in conn_migration.zig.
pub const NewTokenCallback = conn_migration.NewTokenCallback;

// INTERNAL: pub for conn_keys.zig access; not part of the embedder API.
pub const ApplicationKeyEpoch = struct {
    material: SecretMaterial,
    keys: PacketKeys,
    key_phase: bool = false,
    epoch: u64 = 0,
    installed_at_us: u64 = 0,
    packets_protected: u64 = 0,
    discard_deadline_us: ?u64 = null,
    acked: bool = false,
};

// INTERNAL: pub for conn_recv_dispatch.zig access; not part of the embedder API.
pub const ApplicationReadKeySlot = enum {
    current,
    previous,
    next,
};

// INTERNAL: pub for conn_recv_dispatch.zig access; not part of the embedder API.
pub const ApplicationOpenResult = struct {
    opened: short_packet_mod.Open1RttResult,
    slot: ApplicationReadKeySlot,
};

/// Default per-encryption-level CRYPTO inbox bound. BoringSSL's
/// `SSL_quic_max_handshake_flight_len` returns this 16 KiB constant
/// for the Initial and Application levels and as the floor for
/// Handshake; see `ssl/ssl_lib.cc:SSL_quic_max_handshake_flight_len`.
/// We size `CryptoBuffer.buf` to match that floor — small enough to
/// fit four buffers per Connection on the stack budget, large enough
/// for every flight that does not carry a peer certificate chain.
///
/// **Known gap**: at the Handshake level BoringSSL may raise the
/// bound to `2 * max_cert_list` when the peer ships a large cert
/// chain (clients can receive Certificate + CertificateRequest),
/// which exceeds our fixed buffer. Wiring `SSL_quic_max_handshake_flight_len`
/// through the boringssl-zig wrapper (it has no method binding today)
/// would let us size per-level dynamically; until then, peers with
/// >16 KiB Handshake flights surface as `error.InboxOverflow`.
pub const crypto_buffer_default_len: usize = 16384;

pub const CryptoBuffer = struct {
    buf: [crypto_buffer_default_len]u8 = undefined,
    len: usize = 0,

    /// Append bytes BoringSSL produced via `add_handshake_data`.
    /// Returns `error.InboxOverflow` if the fixed-size buffer is full.
    pub fn append(self: *CryptoBuffer, data: []const u8) !void {
        if (self.len + data.len > self.buf.len) return error.InboxOverflow;
        @memcpy(self.buf[self.len .. self.len + data.len], data);
        self.len += data.len;
    }

    /// Returns the buffered bytes and resets the buffer to empty. The
    /// returned slice aliases the internal storage and is valid only
    /// until the next `append`.
    pub fn drain(self: *CryptoBuffer) []const u8 {
        const out = self.buf[0..self.len];
        self.len = 0;
        return out;
    }
};

/// Per-QUIC-connection state machine and embedder-facing API.
///
/// The Connection owns the TLS handshake (`inner`), packet number spaces,
/// flow-control accounting, the stream table, path set, congestion controller,
/// loss detector, and timers. Embedders feed peer datagrams in through
/// `handleDatagram` / `handleClientInitial` / `handleStatelessReset`, drive
/// time forward with `tick`, pull outgoing datagrams via `pollDatagram`, and
/// observe lifecycle changes through `nextEvent` / `nextTimer`.
pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    /// Owned SSL handle from the caller-provided `boringssl.tls.Context`.
    /// The Context outlives the Connection (caller-managed).
    inner: boringssl.tls.Conn,

    /// Inbox of CRYPTO frame bytes received from the peer at each
    /// encryption level. The peer's `add_handshake_data` callback
    /// appends here; `advance` drains via `provideQuicData`.
    inbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },

    /// Per-level secret bookkeeping. Updated by the
    /// `set_read_secret` / `set_write_secret` callbacks.
    levels: [4]PerLevelState = .{ .{}, .{}, .{}, .{} },

    /// Peer pointer for the in-process mock transport tests; real
    /// deployments don't set this (they ship CRYPTO bytes via QUIC
    /// packets through a `transport.Transport` — see `src/transport/`).
    peer: ?*Connection = null,

    /// Last alert byte received via the `send_alert` callback, if
    /// any. Non-null = handshake should be torn down.
    alert: ?u8 = null,

    /// **Test-only.** When set, the migration gate in
    /// `recordAuthenticatedDatagramAddress` bypasses its
    /// `handshakeDone()` check so peer-address-change tests can fire
    /// migration without driving a full TLS handshake. Production
    /// code MUST NOT set this — it disables RFC 9000 §9.6 / hardening
    /// guide §4.8 enforcement.
    test_only_force_handshake_for_migration: bool = false,

    /// Whether to encode the locally-recorded close-reason string into
    /// outgoing CONNECTION_CLOSE frames. Default `false` (redact) per
    /// secure-by-default redaction: internal parser-error strings like
    /// "ack of unsent packet" or "connection id reused across paths"
    /// are useful telemetry for the embedder but reveal implementation
    /// detail to the peer (parser fingerprinting, internal state
    /// names). Local introspection is unaffected — `lifecycle.record`
    /// always captures the reason for embedder-side observability,
    /// and `nextEvent` surfaces it via `CloseEvent.reason`.
    ///
    /// Embedders that want the reason on the wire (debug builds,
    /// internal load tests, etc.) can flip this to `true`.
    reveal_close_reason_on_wire: bool = false,

    /// Hard ceiling on `bytes_resident` (per-connection memory DoS cap).
    /// Sums every byte sitting in peer-controlled reassembly /
    /// queue buffers — CRYPTO `crypto_pending`, RFC 9221 inbound
    /// DATAGRAMs, and per-stream send/recv reassembly buffers. When
    /// a fresh allocation would push the running total past this
    /// cap, the handler closes the connection with
    /// `transport_error_excessive_load` instead of letting the
    /// allocation land. Defaults to `default_max_connection_memory`
    /// (32 MiB); `Server.Config.max_connection_memory` threads onto
    /// every accepted slot.
    ///
    /// Tuning note: per-buffer caps already exist
    /// (`max_pending_crypto_bytes_per_level = 64 KiB`,
    /// `max_pending_datagram_bytes = 64 KiB`,
    /// `max_initial_stream_receive_window = 16 MiB`,
    /// `default_max_buffered_send = 1 MiB`). This is the *aggregate*
    /// guard that prevents a peer from opening many streams at once
    /// and inflating the connection's host RSS even when each
    /// individual buffer stays under its own cap.
    max_connection_memory: u64 = default_max_connection_memory,

    /// Number of ack-eliciting application packets received before
    /// forcing an immediate ACK (RFC 9000 §13.2.1 ¶2: "An endpoint
    /// MUST acknowledge ack-eliciting packets within its advertised
    /// max_ack_delay, with the following exception: it MUST send an
    /// immediate ACK for ack-eliciting packets that are received after
    /// receiving at least 2 ack-eliciting packets without sending an
    /// ACK..."). RFC 9000 §13.2.2 lets implementations tune this
    /// threshold; 2 is the RFC-recommended starting point.
    /// Set lower (e.g. 1) to ACK every ack-eliciting packet
    /// immediately — useful in low-RTT environments where the
    /// `max_ack_delay` deadline rarely fires. Set higher to amortize
    /// ACK overhead at the cost of triggering more peer PTOs.
    /// `Server.Config` and `Client.Config` thread the chosen value
    /// onto every Connection at construction time.
    delayed_ack_packet_threshold: u8 = application_ack_eliciting_threshold,

    /// Enable IETF ECN signaling (RFC 9000 §13.4 / RFC 3168). When
    /// `true` (the default), quic will:
    ///   * count incoming `EcnCodepoint` markings into per-PN-space
    ///     `recv_ect0` / `recv_ect1` / `recv_ce` counters,
    ///   * emit `0x03` ACK frames carrying those counts whenever any
    ///     received packet at that level was ECN-marked,
    ///   * validate peer-reported counts on incoming ACKs per
    ///     §13.4.2 and react to CE bumps via the NewReno
    ///     congestion controller.
    ///
    /// When `false`, the codec is otherwise unchanged but no marking
    /// signal is propagated either way; outgoing ACKs stay at type
    /// `0x02`. Embedders flip this off only on environments known to
    /// bleach ECN bits (some legacy NATs / firewalls), or when
    /// running tests that need a deterministic congestion control
    /// path.
    ecn_enabled: bool = true,
    /// IP-layer ECN codepoint observed on the most recently received
    /// (and decrypted) datagram. Set by `handle` from the cmsg the
    /// embedder plumbs in; consumed by the per-packet handlers when
    /// they record received PNs into the level's `PnSpace`.
    /// `not_ect` is the conservative default — the embedder
    /// hasn't surfaced any TOS byte for this datagram.
    last_recv_ecn: socket_opts_mod.EcnCodepoint = .not_ect,

    /// Running total of bytes currently resident in peer-controlled
    /// buffers — see `max_connection_memory`. Mutated by
    /// `tryReserveResidentBytes` / `releaseResidentBytes` at every
    /// allocation / free site that holds peer-supplied bytes.
    /// Monotonically non-negative — any release that would underflow
    /// the counter clamps at zero and asserts in debug builds.
    bytes_resident: u64 = 0,

    /// Connection-level packet-number bookkeeping for Initial and
    /// Handshake (RFC 9000 §12.3). Application PN spaces live in
    /// `paths` so multipath can allocate one space per active path.
    pn_spaces: [2]PnSpace = .{ .{}, .{} },
    /// Sent-packet tracker for connection-level PN spaces. Application
    /// packets live in `paths.primary().sent`; Initial/Handshake stay
    /// here because QUIC multipath only widens the Application space.
    /// Initial + Handshake sent-packet trackers, one heap slab owned
    /// by the Connection (created in `initClient`/`initServer`, freed
    /// in `deinit`). Kept off the struct because two 4096-slot
    /// trackers inline would put ~1.5 MB on every stack frame that
    /// constructs or moves a Connection by value — the by-value
    /// `init*` return became a stack overflow the moment SentPacket
    /// grew its delivery-rate stamps. The application-level tracker
    /// lives on each PathState (heap via PathSet).
    sent: *[2]SentPacketTracker,
    /// Multipath-capable Application path set. Path id 0 is always the
    /// initial path and owns Application PN/ACK/sent/RTT/congestion.
    paths: PathSet = .{},
    multipath_enabled: bool = false,
    local_max_path_id: u32 = 0,
    peer_max_path_id: u32 = 0,
    peer_paths_blocked_at: ?u32 = null,
    peer_path_cids_blocked_path_id: ?u32 = null,
    peer_path_cids_blocked_next_sequence: u64 = 0,
    current_incoming_path_id: u32 = 0,
    current_incoming_addr: ?Address = null,
    last_authenticated_path_id: ?u32 = null,
    poll_addr_override: ?Address = null,
    /// PTO backoff count for Initial and Handshake. Application PTO
    /// backoff is per-path in `PathState.pto_count`. Reset when an
    /// ACK newly acknowledges ack-eliciting data in that space.
    pto_count: [2]u32 = .{ 0, 0 },
    /// PING probes requested by PTO for Initial and Handshake when no
    /// retransmittable data is immediately available.
    pending_ping: [2]bool = .{ false, false },

    /// Per-encryption-level outbox of CRYPTO bytes the TLS bridge
    /// has handed us via `add_handshake_data`. `poll` packs these
    /// into outgoing CRYPTO frames at the matching level.
    outbox: [4]CryptoBuffer = .{ .{}, .{}, .{}, .{} },
    /// Highest CRYPTO offset we've handed to the peer at each level.
    /// Used to set the `offset` field on the next CRYPTO frame.
    crypto_send_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Highest CRYPTO offset we've fed back to BoringSSL at each
    /// level (one past the last byte of in-order data delivered via
    /// `provideQuicData`).
    crypto_recv_offset: [4]u64 = .{ 0, 0, 0, 0 },
    /// Per-level reassembly queue for CRYPTO frames received out
    /// of order. Each entry holds bytes whose `offset` is strictly
    /// greater than `crypto_recv_offset[lvl]`. Drained whenever
    /// `crypto_recv_offset` catches up to the lowest entry.
    /// quic-go (and many real stacks) routinely fragment the
    /// ClientHello into out-of-order CRYPTO frames inside a single
    /// Initial; without reassembly the handshake stalls.
    crypto_pending: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    crypto_pending_bytes: [4]usize = .{ 0, 0, 0, 0 },
    /// CRYPTO bytes that were sent in lost packets and need to be
    /// retransmitted at their original offsets.
    crypto_retx: [4]std.ArrayList(CryptoChunk) = .{ .empty, .empty, .empty, .empty },
    /// CRYPTO bytes currently in sent packets awaiting ACK/loss.
    sent_crypto: [4]std.ArrayList(SentCryptoChunk) = .{ .empty, .empty, .empty, .empty },

    /// Per-stream state, keyed by stream id.
    streams: std.AutoHashMapUnmanaged(u64, *Stream) = .empty,
    /// Monotonic connection-local key for STREAM send bookkeeping.
    /// Wire packet numbers are scoped by packet-number space/path;
    /// SendStream needs one global key to avoid multipath PN collisions.
    next_stream_packet_key: u64 = 0,

    next_datagram_id: u64 = 0,

    /// Next Status Sequence Number to mint for an
    /// `ALTERNATIVE_V4/V6_ADDRESS` frame
    /// (draft-munizaga-quic-alternative-server-address-00 §6 ¶5).
    /// Both frame types share one monotonically-increasing space.
    next_alternative_address_sequence: u64 = 0,

    /// DCID we put on outgoing packets (the peer chose this; client
    /// learns it from the server's first Initial SCID, or
    /// NEW_CONNECTION_ID). Zero-length CIDs are valid — `peer_dcid_set`
    /// distinguishes "explicitly empty" from "never set".
    peer_dcid: ConnectionId = .{},
    peer_dcid_set: bool = false,
    /// SCID we identify ourselves with — appears as SCID on outgoing
    /// long-header packets, and the peer puts it (or another CID we
    /// issued) as DCID on every incoming packet. Zero-length is valid.
    local_scid: ConnectionId = .{},
    local_scid_set: bool = false,
    /// Stable Source CID used on Initial, Handshake, and 0-RTT long
    /// headers. Peers can retire CID sequence 0 before the Initial or
    /// Handshake packet spaces are fully quiet, but the long-header SCID
    /// still has to remain the one advertised by the handshake transport
    /// parameter.
    initial_source_cid: ConnectionId = .{},
    initial_source_cid_set: bool = false,
    /// Original DCID used for Initial-key derivation (RFC 9001 §5.2).
    /// Active QUIC wire-format version for this connection. Drives
    /// the Initial-key salt + HKDF labels (RFC 9001 §5.2 / RFC 9368
    /// §3.3.1, §3.3.2), the long-header packet-type bit layout
    /// (RFC 9000 §17.2 / RFC 9368 §3.2), and the Retry integrity
    /// constants (RFC 9001 §5.8 / RFC 9368 §3.3.3). Defaults to
    /// QUIC v1; embedders that opt in to v2 set this via
    /// `setVersion` after `initClient` / `initServer`. Once an
    /// Initial is sealed or opened the value is effectively
    /// immutable (changing it would re-derive Initial keys against
    /// a different salt).
    version: u32 = quic_version_1,

    /// RFC 9368 §6 compatible-version-negotiation upgrade target,
    /// stashed by the server's `Server.preparseUpgradeTarget` and
    /// applied by the server's `dispatchToSlot` after the first
    /// `handleWithEcn` consumes the wire-version Initial under
    /// wire-version keys. `null` means no upgrade is pending.
    /// Server-side only; clients leave this null. See
    /// `setPendingVersionUpgrade` / `applyPendingVersionUpgrade`.
    pending_version_upgrade: ?u32 = null,

    /// RFC 9368 §6 ¶6/¶7 downgrade-attack guard: wire version on the
    /// FIRST Initial we observed. Captured BEFORE any compatible-
    /// version-negotiation upgrade flips `self.version`, so the
    /// server-side check in `validatePeerTransportRole` can compare
    /// the client's advertised `version_information.chosen_version`
    /// against the actual on-wire version of the client's Initial,
    /// even after `applyPendingVersionUpgrade` has retargeted
    /// `self.version` to the upgrade target. Set by `acceptInitial`
    /// on the server side; left `null` on the client side (the client
    /// only ever sends a single wire version on its first Initial,
    /// which equals `self.version` at the time the params are
    /// validated, so the simpler `advertised_versions[0] !=
    /// self.version` check in the client branch is sufficient).
    initial_wire_version: ?u32 = null,

    /// Client side: the random DCID it sent on the very first Initial.
    /// Server side: same value, recovered from that incoming Initial.
    initial_dcid: ConnectionId = .{},
    initial_dcid_set: bool = false,
    /// Stable copy of the client's first Initial DCID. If Retry is
    /// accepted, `initial_dcid` changes to the Retry SCID for key
    /// derivation, while this value remains the Original DCID used for
    /// Retry integrity and transport-parameter validation.
    original_initial_dcid: ConnectionId = .{},
    original_initial_dcid_set: bool = false,
    retry_source_cid: ConnectionId = .{},
    retry_source_cid_set: bool = false,
    retry_accepted: bool = false,
    retry_token: std.ArrayList(u8) = .empty,

    /// Cached Initial-level packet keys. Derived once `initial_dcid`
    /// is set; cleared if `initial_dcid` is rotated (e.g. after
    /// receiving a Retry, RFC 9001 §5.2). Direction-specific (server
    /// uses `is_server=true` derivation for write).
    initial_keys_read: ?short_packet_mod.PacketKeys = null,
    initial_keys_write: ?short_packet_mod.PacketKeys = null,
    /// Latched true the first time `discardInitialKeys` fires (i.e.
    /// when Handshake or higher secrets are installed). Once set,
    /// `ensureInitialKeys` is a no-op — the discard is one-way and
    /// any subsequent Initial-level packet can't be sealed/opened
    /// with re-derived keys. RFC 9001 §5.7 ¶3.
    initial_keys_discarded: bool = false,
    /// Latched true when `discardHandshakeKeys` fires. RFC 9001 §4.9.2:
    /// "An endpoint MUST discard its handshake keys when the TLS
    /// handshake is confirmed (Section 4.1.2)." For the client, that
    /// confirmation event is receipt of HANDSHAKE_DONE (RFC 9001
    /// §4.1.2 ¶2); for the server, it is delivery of the client's
    /// Finished message (which equals `handshakeDone()` returning
    /// true). Once latched, `pnSpaceForLevel(.handshake)` and
    /// `sentForLevel(.handshake)` are dead — `tick` skips them and
    /// `packetKeys(.handshake, ...)` returns null because the
    /// per-level secret material has been zeroed.
    handshake_keys_discarded: bool = false,
    /// Latched true on the client when a HANDSHAKE_DONE frame is
    /// processed (RFC 9001 §4.1.2 ¶2). Drives `discardHandshakeKeys`
    /// in `applyPostFrameProcessing` and short-circuits any further
    /// Handshake-level activity (PTO, loss detection, retransmit).
    /// Server-side this stays false — the equivalent latch is
    /// `inner.handshakeDone()`, which already covers the §4.9.2
    /// "TLS handshake is confirmed" trigger for the server role.
    received_handshake_done: bool = false,
    /// Sequence number of the locally-issued CID the next-handled
    /// datagram was addressed to, or `null` when unknown. Set by
    /// `Server` from its routing table before each `Connection.handle`
    /// invocation; consumed by `handleRetireConnectionId` to enforce
    /// RFC 9000 §19.16 ¶3 (a peer MUST NOT retire the CID it just
    /// used to send to us — PROTOCOL_VIOLATION).
    current_incoming_local_cid_seq: ?u64 = null,

    /// Cumulative count of ACK ranges processed across every ACK /
    /// PATH_ACK frame in the current `handle` cycle. Reset on entry to
    /// `handle`. Incremented by `range_count + 1` per frame (the +1
    /// accounts for `first_range`, which is real but encoded out of
    /// the gap-list). The decoder already caps each individual frame
    /// at `frame.decode.max_incoming_ack_ranges = 256`; without a
    /// per-cycle ceiling, an attacker on N paths could submit
    /// N × 256 ranges per datagram and force unbounded
    /// loss-detection walks. We cap at `incoming_ack_range_cap` —
    /// enough headroom for legitimate multipath aggregation across
    /// ~4 active paths in one datagram, not enough to amplify.
    incoming_ack_range_count: u64 = 0,
    /// Cumulative count of RETIRE_CONNECTION_ID frames processed in
    /// the current `handle` cycle. Reset on entry to `handle`.
    /// Bounded at `incoming_retire_cid_cap` so a peer flooding
    /// retires inside one datagram is treated as adversarial and
    /// closed with PROTOCOL_VIOLATION rather than allowed to spend
    /// CPU walking `local_cids` once per frame.
    incoming_retire_cid_count: u64 = 0,

    /// Application key-update lifecycle. QUIC key updates derive new
    /// packet-protection key/IV from "quic ku" while retaining the
    /// original header-protection key. Read side keeps previous/current/next
    /// epochs so delayed old-phase packets survive until the 3x-PTO discard
    /// timer; write side tracks ACK-gating and AEAD packet limits.
    app_read_previous: ?ApplicationKeyEpoch = null,
    app_read_current: ?ApplicationKeyEpoch = null,
    app_read_next: ?ApplicationKeyEpoch = null,
    app_write_current: ?ApplicationKeyEpoch = null,
    app_write_update_pending_ack: bool = false,
    app_next_local_update_after_us: ?u64 = null,
    app_failed_auth_packets: u64 = 0,
    app_key_update_limits: ApplicationKeyUpdateLimits = .{},
    qlog_callback: ?QlogCallback = null,
    qlog_user_data: ?*anyopaque = null,
    /// Optional embedder policy that gates peer migrations to a new
    /// 4-tuple (RFC 9000 §9). When `null`, every authenticated
    /// migration candidate is accepted and validated. See
    /// `setMigrationCallback`.
    migration_callback: ?MigrationCallback = null,
    migration_user_data: ?*anyopaque = null,
    /// Opt-in for high-volume per-packet qlog events
    /// (`packet_sent`, `packet_received`, `packet_lost`). Disabled by
    /// default so production callers don't pay for every packet
    /// crossing the boundary.
    qlog_packet_events: bool = false,
    /// Whether `connection_started` has fired yet. Single-shot.
    qlog_started: bool = false,
    /// Last close-state we emitted for `connection_state_updated`.
    qlog_last_state: CloseState = .open,
    /// Whether `parameters_set` fired.
    qlog_params_emitted: bool = false,
    /// Last congestion controller phase emitted (so we don't spam
    /// transitions). `null` means no snapshot has been taken yet.
    qlog_last_congestion_state: ?QlogCongestionState = null,

    // -- cheap aggregate counters used by PathStats --
    /// Total packets we've sent (across all paths/levels).
    qlog_packets_sent: u64 = 0,
    /// Total packets we've successfully received (post-AEAD).
    qlog_packets_received: u64 = 0,
    /// Total packets declared lost.
    qlog_packets_lost: u64 = 0,
    /// Total UDP payload bytes we've sent.
    qlog_bytes_sent: u64 = 0,
    /// Total UDP payload bytes the peer has sent us.
    qlog_bytes_received: u64 = 0,

    /// Local datagram budget for outgoing packets. Functions as the
    /// connection-wide ceiling: per-path PMTU values discovered via
    /// RFC 8899 DPLPMTUD must not exceed this. Negotiated peer
    /// `max_udp_payload_size` lowers this in `validatePeerTransportLimits`.
    mtu: usize = default_mtu,

    /// RFC 8899 DPLPMTUD configuration. Threaded onto every
    /// `PathState` at creation time. The Connection-level field
    /// defaults to `enable = false` so direct `Connection.createClient
    /// / initServer` callers (mainly internal test fixtures) keep the
    /// static-MTU behaviour. The public `Server.Config
    /// .pmtud` and `Client.Config.pmtud` wrappers default to enabled
    /// (`PmtudConfig{}` with `enable = true`) and call
    /// `setPmtudConfig` after `initClient` / `initServer`, so
    /// production embedders get DPLPMTUD without any extra wiring.
    pmtud_config: path_mod.PmtudConfig = .{ .enable = false },

    /// Congestion-control algorithm used by every path's controller.
    /// A mutable posture switch like `ecn_enabled`: wrappers thread
    /// `Config.congestion_control` through `setCongestionAlgorithm`
    /// right after `initClient`/`initServer`; paths created later
    /// (multipath, migration) inherit it at construction.
    cc_algorithm: congestion_mod.Algorithm = .cubic,

    /// RFC 9406 HyStart++ configuration for every path's controller.
    /// A posture switch like `cc_algorithm`; wrappers thread
    /// `Config.enable_hystart` here right after init.
    cc_hystart: congestion_mod.HyStartConfig = .{},

    /// RFC 9002 §7.7 packet pacing. On by default; `false` restores
    /// the pre-0.11 burst-a-full-cwnd emission timing exactly (the
    /// rollback lever). Wrappers thread `Config.enable_pacing` here.
    pacing_enabled: bool = true,

    /// Local parameters handed to BoringSSL. Kept here too so ACK
    /// delay and idle timers can use the negotiated local values.
    local_transport_params: TransportParams = .{},
    /// True once `setTransportParams` has encoded and pushed the local
    /// parameters. Guards the `setLocalScid` ordering contract: the first
    /// SCID latch must happen before this, so its Initial Source Connection
    /// ID (RFC 9000 §7.3) makes it into the advertised parameters.
    local_transport_params_set: bool = false,
    /// Receive-side connection flow-control limit we have advertised
    /// through transport parameters / MAX_DATA.
    local_max_data: u64 = 0,
    /// Sum of per-stream receive high-water marks the peer has forced.
    peer_sent_stream_data: u64 = 0,
    /// Send-side connection flow-control limit advertised by the peer.
    peer_max_data: u64 = std.math.maxInt(u64),
    /// Sum of new stream bytes we have put on the wire.
    we_sent_stream_data: u64 = 0,
    /// Stream-count limits. `local_*` governs peer-created streams;
    /// `peer_*` governs streams opened through the public API. Unknown
    /// peer limits are permissive until peer transport params arrive.
    local_max_streams_bidi: u64 = 0,
    local_max_streams_uni: u64 = 0,
    peer_max_streams_bidi: u64 = std.math.maxInt(u64),
    peer_max_streams_uni: u64 = std.math.maxInt(u64),
    peer_opened_streams_bidi: u64 = 0,
    peer_opened_streams_uni: u64 = 0,
    local_opened_streams_bidi: u64 = 0,
    local_opened_streams_uni: u64 = 0,
    /// `pollEvent` watermarks for `stream_opened` emission: peer-opened
    /// stream indices in [surfaced, peer_opened_streams_*) have not been
    /// surfaced to the embedder yet. Peer indices open contiguously
    /// (RFC 9000 §3.2), so chasing the count is lossless — no queue, no
    /// overflow, O(1) state.
    surfaced_peer_streams_bidi: u64 = 0,
    surfaced_peer_streams_uni: u64 = 0,
    /// One-shot latch for `ConnectionEvent.handshake_established`.
    handshake_established_surfaced: bool = false,
    /// Latch for the one-shot `ConnectionEvent.early_data`: set once
    /// the 0-RTT outcome has been surfaced (or, for connections that
    /// never attempted 0-RTT, once the handshake finishes with
    /// `.not_offered` — after which the status can never change and
    /// `pollEvent` stops consulting BoringSSL).
    early_data_surfaced: bool = false,
    /// Rotating cursor for the RFC 9218 send scheduler's round-robin among
    /// equal-urgency *incremental* streams: each application packet advances it
    /// past the incremental stream that led, so a different one leads next
    /// packet (non-incremental streams are unaffected — they keep strict
    /// stream-id order). See `collectSendableStreamsByPriority`.
    priority_rr_cursor: u64 = 0,
    // Contiguous "reaped" watermark per peer-initiated direction: the
    // count k such that every peer stream index in [0, k) was created
    // and reaped (RFC 9000 §3.2). A STREAM/RESET_STREAM for an absent
    // peer stream with index < the watermark is a post-terminal frame
    // and is ignored rather than resurrecting the stream (which would
    // forget its locked final size / reset state). The bitset records
    // reaped-but-not-yet-coalesced indices in the bounded window
    // [peer_reaped_below_*, peer_opened_streams_*); the watermark only
    // ever advances across a contiguous run of reaped indices from the
    // bottom, so an implicitly-opened-but-never-created lower index
    // (whose bit is never set) permanently halts the run and its later
    // first data still flows to the normal create path. Bounded: every
    // creatable peer index is < local_max_streams_* <=
    // max_streams_per_connection (4096), so the fixed bitset is always
    // in range and adds a constant 2×512 B per connection.
    peer_reaped_below_bidi: u64 = 0,
    peer_reaped_below_uni: u64 = 0,
    peer_reaped_bits_bidi: std.StaticBitSet(max_streams_per_connection) = std.StaticBitSet(max_streams_per_connection).empty,
    peer_reaped_bits_uni: std.StaticBitSet(max_streams_per_connection) = std.StaticBitSet(max_streams_per_connection).empty,
    /// Decoded peer parameters once BoringSSL exposes them.
    cached_peer_transport_params: ?TransportParams = null,
    /// The peer's transport parameters as REMEMBERED from a prior
    /// connection, supplied by the embedder for a 0-RTT resumption
    /// (BoringSSL does not carry peer transport params across resumption,
    /// and they can't be recovered from the one-way early-data context
    /// digest). Used only to bound early-data (0-RTT) sends *before* the
    /// real `cached_peer_transport_params` arrive on this connection. RFC
    /// 9001 §4.6.1 guarantees the server MUST NOT lower these on
    /// resumption, so seeding limits from them can only under-grant vs
    /// the real params, never over-grant.
    remembered_peer_transport_params: ?TransportParams = null,
    /// The peer's transport-parameter stateless reset token is bound
    /// to its initial source CID. Register it once; later peer DCID
    /// rotation is driven by NEW_CONNECTION_ID metadata.
    peer_transport_reset_token_installed: bool = false,
    /// Per-connection opt-in for sending queued application bytes in
    /// 0-RTT packets. Session resumption can still happen when this is
    /// false; quic just waits for 1-RTT before emitting app data.
    early_data_send_enabled: bool = false,
    /// Once BoringSSL reports rejection, every tracked 0-RTT packet is
    /// removed from flight and its STREAM bytes are put back on the
    /// send queue exactly once.
    early_data_rejection_processed: bool = false,

    /// Last send/receive activity on this connection, in the same
    /// microsecond clock the embedder passes to `handle` / `poll` /
    /// `tick`. Zero means no packet activity has been observed yet.
    ///
    /// Stable, embedder-readable observation point: layers above
    /// (e.g. an HTTP/3 session enforcing request deadlines) read this
    /// directly as the connection clock rather than threading their
    /// own timestamp through every call. Read-only for embedders —
    /// quic maintains it.
    last_activity_us: u64 = 0,

    /// Close/draining lifecycle: pending CONNECTION_CLOSE, closing/
    /// draining deadlines, rate-limit bookkeeping, sticky close event,
    /// and the reason-phrase buffer. See `lifecycle.zig`.
    lifecycle: LifecycleState = .{},
    /// Set whenever an inbound packet authenticates under our keys
    /// while the connection is in RFC 9000 §10.2.1's closing state.
    /// `handle` consumes this flag after the per-datagram loop and
    /// re-arms `pending_close` if the §10.2.1 ¶3 rate-limit allows,
    /// so the peer gets a fresh CONNECTION_CLOSE. Cleared on every
    /// `handle` entry so the signal only reflects the current
    /// datagram.
    closing_state_attribution_observed: bool = false,

    /// Peer-issued connection IDs we've stashed via NEW_CONNECTION_ID.
    /// `consumeFreshPeerCidForMigration` draws from this set; it is
    /// also where a peer's `active_connection_id_limit` violation
    /// surfaces (§5.1.1).
    peer_cids: std.ArrayList(IssuedCid) = .empty,
    /// Locally-issued connection IDs, keyed by path, used to map
    /// incoming short-header DCIDs back to draft multipath path IDs.
    local_cids: std.ArrayList(IssuedCid) = .empty,
    /// Server-only HANDSHAKE_DONE delivery. The frame is ack-eliciting
    /// and must be retransmitted on loss until the client confirms the
    /// handshake.
    pending_handshake_done: bool = false,
    handshake_done_queued_once: bool = false,
    /// Graceful-shutdown latch (`beginGracefulShutdown`). While set, local
    /// stream opens are refused with `Error.ShuttingDown` and no further
    /// MAX_STREAMS credit is granted (the peer's stream limit freezes at
    /// its current value), so both sides quiesce new-stream creation while
    /// in-flight streams complete. Independent of the RFC 9000 §10 close
    /// state — the connection stays open until the embedder calls `close`.
    graceful_shutdown: bool = false,
    flow_blocked_events: event_queue_mod.EventQueue(FlowBlockedInfo, max_flow_blocked_events) = .{},
    connection_id_events: event_queue_mod.EventQueue(ConnectionIdReplenishInfo, max_connection_id_events) = .{},
    datagram_send_events: event_queue_mod.EventQueue(StoredDatagramSendEvent, max_datagram_send_events) = .{},
    /// Received `ALTERNATIVE_V4/V6_ADDRESS` events
    /// (draft-munizaga-quic-alternative-server-address-00 §6) the
    /// embedder hasn't drained via `pollEvent` yet. Bounded at
    /// `max_alternative_address_events` (16) with drop-oldest
    /// eviction. Eviction is semantically safe under §6 ¶5
    /// monotonicity — the latest update always supersedes older
    /// ones — but a sluggish embedder polling on a chatty peer can
    /// miss intermediate state. The high-watermark is preserved on
    /// `highest_alternative_address_sequence_seen` so the embedder
    /// can detect that updates were dropped (sequence gap between
    /// the latest polled event and `highestAlternativeAddressSequenceSeen()`).
    alternative_server_address_events: event_queue_mod.EventQueue(AlternativeServerAddressEvent, max_alternative_address_events) = .{},
    /// Highest §6 ¶5 Status Sequence Number we've already observed.
    /// `null` until the first frame arrives. Drives the receive-side
    /// monotonicity gate: equal-or-lower numbers are absorbed silently
    /// (idempotent retransmit / out-of-order delivery).
    highest_alternative_address_sequence_seen: ?u64 = null,
    local_data_blocked_at: ?u64 = null,
    local_stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    local_streams_blocked_bidi: ?u64 = null,
    local_streams_blocked_uni: ?u64 = null,
    peer_data_blocked_at: ?u64 = null,
    peer_stream_data_blocked: std.ArrayList(frame_types.StreamDataBlocked) = .empty,
    peer_streams_blocked_bidi: ?u64 = null,
    peer_streams_blocked_uni: ?u64 = null,
    /// Bytes the application has drained from all receive streams.
    recv_stream_bytes_read: u64 = 0,

    /// All control-frame backlog the connection owes the peer at the
    /// application encryption level — flow-control window updates,
    /// STOP_SENDING, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID, the
    /// PATH_CHALLENGE/PATH_RESPONSE pair, multipath draft-21
    /// bookkeeping, and queued DATAGRAMs in both directions. The
    /// hot-path drain in `pollLevel` walks each subqueue in order.
    pending_frames: pending_frames_mod.PendingFrameQueues = .empty,

    /// Client-side callback fired when a NEW_TOKEN frame arrives at
    /// application encryption level (RFC 9000 §8.1.3). Embedders
    /// stash the bytes for use as the long-header Token on a future
    /// connection's first Initial. Server-side connections never
    /// fire this — peers MUST NOT send NEW_TOKEN to a server.
    new_token_callback: ?NewTokenCallback = null,
    new_token_user_data: ?*anyopaque = null,

    /// Construct a client-side `Connection` in place at `conn` and
    /// wire it to its TLS state immediately — `conn` must already sit
    /// at its final, stable address (the TLS callbacks keep
    /// `*Connection` in SSL ex-data, and completion-style transports
    /// hand Connection-owned buffers to the kernel; a Connection
    /// NEVER moves after this call). Most embedders want
    /// `createClient`, which pairs this with heap placement; this
    /// entry point exists for caller-owned storage (arenas, pools,
    /// static slots) and pairs with `deinit`.
    ///
    /// `tls_ctx` must be a client-mode `boringssl.tls.Context` and
    /// stays caller-owned; `server_name` becomes the SNI hostname
    /// (copied by BoringSSL — the slice does not need to outlive this
    /// call).
    pub fn initClientAt(
        conn: *Connection,
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
        server_name: [:0]const u8,
    ) !void {
        const sent_slab = try allocator.create([2]SentPacketTracker);
        errdefer allocator.destroy(sent_slab);
        sent_slab.* = .{ .{}, .{} };
        conn.* = .{
            .allocator = allocator,
            .role = .client,
            .inner = try tls_ctx.newQuicClient(),
            .sent = sent_slab,
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{
            .max_datagram_size = default_mtu,
            .algorithm = conn.cc_algorithm,
            .hystart = conn.cc_hystart,
        });
        // Client picked the destination address itself, so the §8.1
        // anti-amplification cap doesn't apply on its outbound. Primary
        // path starts validated. (See `PathSet.ensurePrimary` for the
        // matching server policy: the server leaves it unvalidated and
        // flips it on the first authenticated Handshake from peer.)
        conn.primaryPath().path.markValidated();
        // RFC 8899 DPLPMTUD: install the default config on the primary
        // path. Embedders that supply a non-default config must call
        // `setPmtudConfig` after construction (the wrapper helpers
        // `Server.Config.pmtud` / `Client.Config.pmtud` thread it
        // automatically). `setPmtudConfig` does the matching lift on
        // `self.mtu` for us.
        conn.setPmtudConfig(conn.pmtud_config);
        try conn.installTls(server_name);
    }

    /// Construct a server-side `Connection` in place at `conn` — the
    /// caller-owned-storage twin of `createServer`; see `initClientAt`
    /// for the stable-address contract. `tls_ctx` must be a
    /// server-mode `boringssl.tls.Context` and stays caller-owned.
    pub fn initServerAt(
        conn: *Connection,
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
    ) !void {
        const sent_slab = try allocator.create([2]SentPacketTracker);
        errdefer allocator.destroy(sent_slab);
        sent_slab.* = .{ .{}, .{} };
        conn.* = .{
            .allocator = allocator,
            .role = .server,
            .inner = try tls_ctx.newQuicServer(),
            .sent = sent_slab,
        };
        errdefer conn.inner.deinit();
        try conn.paths.ensurePrimary(allocator, .{
            .max_datagram_size = default_mtu,
            .algorithm = conn.cc_algorithm,
            .hystart = conn.cc_hystart,
        });
        // RFC 8899 DPLPMTUD on the primary path. See `initClientAt`
        // for the embedder-config plumbing path.
        conn.setPmtudConfig(conn.pmtud_config);
        try conn.installTls(null);
    }

    /// Build a client-side `Connection` on the heap and return its
    /// stable address, fully wired to TLS and ready to `advance`.
    /// Pair with `destroy`. This replaces the old
    /// initClient-then-move-then-bind() dance — a Connection now has
    /// one address for its whole life, so there is no window where a
    /// move silently dangles the SSL ex-data pointer.
    pub fn createClient(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
        server_name: [:0]const u8,
    ) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);
        try initClientAt(conn, allocator, tls_ctx, server_name);
        return conn;
    }

    /// Build a server-side `Connection` on the heap and return its
    /// stable address. Pair with `destroy`. See `createClient`.
    pub fn createServer(
        allocator: std.mem.Allocator,
        tls_ctx: boringssl.tls.Context,
    ) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);
        try initServerAt(conn, allocator, tls_ctx);
        return conn;
    }

    /// Replace the connection-wide `PmtudConfig` and re-initialise the
    /// PMTUD state on every existing path. Embedders pass a config via
    /// `Server.Config.pmtud` / `Client.Config.pmtud`; this entry point
    /// is reachable directly for tests and for embedders that want to
    /// retune at runtime.
    ///
    /// `Connection.mtu` is left untouched: it stays the connection-
    /// wide static ceiling (the QUIC v1 floor unless an embedder
    /// raised it explicitly, then potentially lowered by the peer's
    /// `max_udp_payload_size`). DPLPMTUD's own ceiling lives on
    /// `pmtud_config.max_mtu` and is consulted directly by the probe
    /// scheduler. Per-path `pmtu` floats inside that range as probes
    /// succeed or fail.
    pub fn setPmtudConfig(self: *Connection, cfg: path_mod.PmtudConfig) void {
        self.pmtud_config = cfg;
        for (self.paths.paths.items) |*p| {
            p.pmtudInit(cfg);
        }
    }

    /// Select the congestion-control algorithm and re-initialise the
    /// controller on every existing path (each keeps its own
    /// `max_datagram_size`). Wrappers call this right after
    /// `initClient`/`initServer`, mirroring `setPmtudConfig`; calling
    /// it mid-connection is legal but resets all congestion state —
    /// cwnd returns to the initial window on every path.
    pub fn setCongestionAlgorithm(self: *Connection, algo: congestion_mod.Algorithm) void {
        self.cc_algorithm = algo;
        for (self.paths.paths.items) |*p| {
            var cfg = p.path.cc.config();
            cfg.algorithm = algo;
            cfg.hystart = self.cc_hystart;
            p.path.cc = congestion_mod.CongestionController.init(cfg);
        }
    }

    /// Enable or disable RFC 9406 HyStart++ on every path's
    /// controller. Like `setCongestionAlgorithm`, this re-initialises
    /// the controllers, so call it during setup rather than
    /// mid-connection.
    pub fn setHyStartEnabled(self: *Connection, enabled: bool) void {
        self.cc_hystart.enabled = enabled;
        for (self.paths.paths.items) |*p| {
            var cfg = p.path.cc.config();
            cfg.hystart = self.cc_hystart;
            p.path.cc = congestion_mod.CongestionController.init(cfg);
        }
    }

    /// RFC 8899 DPLPMTUD: current PMTU floor (in bytes) for the active
    /// application-data path. The send path consults this when sizing
    /// outbound 1-RTT packets; embedders surface it via observability.
    pub fn pmtu(self: *const Connection) usize {
        return self.paths.activeConst().pmtu;
    }

    /// Wire this Connection to its underlying SSL: install the
    /// `tls.quic.Method` callbacks and stash `*Connection` in SSL
    /// ex-data so the callbacks can recover the right state. Runs as
    /// the last step of `init*At` — the address is final at
    /// construction, so there is no bind-later window. (qlog's
    /// `connection_started` is emitted by `setQlogCallback`, the
    /// first moment a sink exists to receive it.)
    fn installTls(self: *Connection, hostname: ?[:0]const u8) !void {
        try self.inner.setUserData(self);
        try self.inner.setQuicMethod(&method);
        if (hostname) |h| try self.inner.setHostname(h);
    }

    /// Tear down a Connection built by `createClient`/`createServer`:
    /// `deinit` plus freeing the heap slot. Connections constructed
    /// with `init*At` into caller-owned storage call `deinit` instead.
    pub fn destroy(self: *Connection) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    /// Free all per-connection allocations, including stream
    /// buffers, queued frames, packet-number space state, and the
    /// underlying `boringssl.tls.Conn`. After this call the
    /// `Connection` is `undefined` and must not be reused.
    pub fn deinit(self: *Connection) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.send.deinit();
            s.recv.deinit();
            self.allocator.destroy(s);
        }
        self.streams.deinit(self.allocator);
        self.pending_frames.deinit(self.allocator);
        for (self.sent) |*tracker| {
            var i: u32 = 0;
            while (i < tracker.count) : (i += 1) {
                // Tombstones own nothing; deinit would double-free.
                if (tracker.packets[i].dead) continue;
                tracker.packets[i].deinit(self.allocator);
            }
        }
        self.allocator.destroy(self.sent);
        self.paths.deinit(self.allocator);
        for (&self.crypto_pending) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.crypto_retx) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }
        for (&self.sent_crypto) |*list| {
            for (list.items) |chunk| self.allocator.free(chunk.data);
            list.deinit(self.allocator);
        }

        // Hardening guide §3.5 / §9.4: zero sensitive packet
        // protection material before the buffers go back to the
        // allocator. `secureZero` is volatile-backed so the optimizer
        // can't elide it on the dead-store path where the struct is
        // about to be `undefined`-poisoned. We zero in place — the
        // surrounding ArrayLists and structs will be deinit-ed below.
        for (&self.levels) |*level| {
            if (level.read) |*material| std.crypto.secureZero(u8, &material.secret);
            if (level.write) |*material| std.crypto.secureZero(u8, &material.secret);
        }
        zeroAppKeyEpoch(&self.app_read_previous);
        zeroAppKeyEpoch(&self.app_read_current);
        zeroAppKeyEpoch(&self.app_read_next);
        zeroAppKeyEpoch(&self.app_write_current);
        // Stateless-reset tokens — both directions. Peer-supplied
        // ones are the ones we'd compare incoming traffic against;
        // local ones are the ones we minted and may have shipped over
        // the wire. Either way they shouldn't linger in freed memory.
        for (self.peer_cids.items) |*item| std.crypto.secureZero(u8, &item.stateless_reset_token);
        for (self.local_cids.items) |*item| std.crypto.secureZero(u8, &item.stateless_reset_token);

        self.peer_cids.deinit(self.allocator);
        self.local_cids.deinit(self.allocator);
        self.retry_token.deinit(self.allocator);
        self.local_stream_data_blocked.deinit(self.allocator);
        self.peer_stream_data_blocked.deinit(self.allocator);
        self.inner.deinit();
        self.* = undefined;
    }

    /// Helper used by `deinit` to zero the secret + derived packet
    /// keys held inside an `ApplicationKeyEpoch` slot.
    fn zeroAppKeyEpoch(slot: *?ApplicationKeyEpoch) void {
        if (slot.*) |*epoch| {
            std.crypto.secureZero(u8, &epoch.material.secret);
            std.crypto.secureZero(u8, &epoch.keys.key);
            std.crypto.secureZero(u8, &epoch.keys.iv);
            std.crypto.secureZero(u8, &epoch.keys.hp);
            // The cached HP cipher holds an AES key schedule derived
            // from `hp`; zero its raw bytes too.
            std.crypto.secureZero(u8, std.mem.asBytes(&epoch.keys.hp_cipher));
        }
    }

    /// Snapshot of the parameters most recently passed to
    /// `setTransportParams`. Useful for callers (e.g. RFC 9368 §6
    /// multi-Initial pre-parse) that need to mutate one or two
    /// fields and re-push without rebuilding the full struct.
    pub fn localTransportParams(self: *const Connection) TransportParams {
        return self.local_transport_params;
    }

    /// Encode `params` (RFC 9000 §18 + RFC 9221) and hand the blob
    /// to BoringSSL for transmission inside CRYPTO frames during the
    /// handshake. Must be called before the first `advance`.
    ///
    /// Initial Source Connection ID (RFC 9000 §7.3): if the local SCID has
    /// already been latched (`setLocalScid`), fold it into the advertised
    /// parameters here. If not, `setLocalScid` back-fills and re-pushes it when
    /// it runs, so the two calls may happen in either order. A caller may also
    /// set `params.initial_source_connection_id` directly, or omit it entirely
    /// when talking only to lenient peers.
    pub fn setTransportParams(self: *Connection, params: TransportParams) !void {
        var local = try normalizeLocalTransportParams(params);
        // RFC 9000 §7.3: every endpoint MUST advertise
        // `initial_source_connection_id`, set to the Source Connection ID it
        // put on its Initial packet. The connection already owns that value
        // (`initial_source_cid`, latched from `setLocalScid`), so fill it in
        // for callers of this low-level API rather than making every embedder
        // duplicate it. A missing ISCID is a hard handshake rejection on
        // strict peers (e.g. quic-go closes with TRANSPORT_PARAMETER_ERROR).
        if (self.initial_source_cid_set) {
            local.initial_source_connection_id = self.initial_source_cid;
        }
        var buf: [1024]u8 = undefined;
        const n = try local.encode(&buf);
        self.local_transport_params = local;
        self.local_transport_params_set = true;
        self.applyLocalFlowTransportParams();
        if (local.initial_max_path_id) |max_path_id| {
            self.local_max_path_id = max_path_id;
            self.multipath_enabled = true;
        } else {
            self.local_max_path_id = 0;
        }
        try self.inner.setQuicTransportParams(buf[0..n]);
    }

    fn normalizeLocalTransportParams(params: TransportParams) transport_params_mod.Error!TransportParams {
        var local = params;
        if (local.max_udp_payload_size < min_quic_udp_payload_size) return error.InvalidValue;
        if (local.initial_max_streams_bidi > max_stream_count_limit or
            local.initial_max_streams_uni > max_stream_count_limit)
        {
            return error.InvalidValue;
        }
        if (local.initial_max_streams_bidi > max_streams_per_connection or
            local.initial_max_streams_uni > max_streams_per_connection)
        {
            return error.InvalidValue;
        }
        if (local.active_connection_id_limit > max_supported_active_connection_id_limit) {
            return error.InvalidValue;
        }
        if (local.initial_max_path_id) |max_path_id| {
            if (max_path_id > max_supported_path_id) return error.InvalidValue;
        }
        if (local.initial_max_data > max_initial_connection_receive_window) {
            return error.InvalidValue;
        }
        if (local.initial_max_stream_data_bidi_local > max_initial_stream_receive_window or
            local.initial_max_stream_data_bidi_remote > max_initial_stream_receive_window or
            local.initial_max_stream_data_uni > max_initial_stream_receive_window)
        {
            return error.InvalidValue;
        }
        if (local.max_udp_payload_size > max_supported_udp_payload_size) {
            local.max_udp_payload_size = max_supported_udp_payload_size;
        }
        if (local.max_datagram_frame_size > max_supported_udp_payload_size) {
            local.max_datagram_frame_size = max_supported_udp_payload_size;
        }
        return local;
    }

    fn applyLocalFlowTransportParams(self: *Connection) void {
        const params = self.local_transport_params;
        self.local_max_data = params.initial_max_data;
        self.local_max_streams_bidi = params.initial_max_streams_bidi;
        self.local_max_streams_uni = params.initial_max_streams_uni;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            s.recv_max_data = self.initialRecvStreamLimit(s.id);
        }
    }

    /// Escape hatch: set already-encoded transport-parameter bytes.
    /// Useful for testing the decoder against fixtures.
    pub fn setRawTransportParams(self: *Connection, params: []const u8) !void {
        try self.inner.setQuicTransportParams(params);
    }

    /// Decode the peer's transport parameters once the handshake has
    /// produced them (typically available right after Initial keys
    /// are derived on the peer's first flight). Returns null until
    /// the peer's blob is available.
    pub fn peerTransportParams(self: *Connection) !?TransportParams {
        const blob = self.inner.peerQuicTransportParams() orelse return null;
        const params = try transport_params_mod.Params.decode(blob);
        self.cached_peer_transport_params = params;
        if (params.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = @min(max_path_id, max_supported_path_id);
            self.multipath_enabled = true;
        }
        self.validatePeerTransportLimits();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return params;
        self.validatePeerTransportRole();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return params;
        try self.installPeerTransportStatelessResetToken();
        self.validatePeerTransportConnectionIds();
        return params;
    }

    /// Client-only: install a previously-captured TLS session before
    /// the first handshake step so BoringSSL can attempt resumption.
    pub fn setSession(self: *Connection, session: Session) !void {
        if (self.role != .client) return error.NotClientContext;
        try self.inner.setSession(session);
    }

    /// Install a callback fired when the (client-side) connection
    /// receives a NEW_TOKEN frame (RFC 9000 §8.1.3). The embedder
    /// typically stashes the bytes alongside their session ticket so
    /// the next connection to the same server can present the token
    /// in its long-header Token field and skip the server's Retry
    /// round trip.
    ///
    /// `cb` may be null to clear an existing callback. Server-side
    /// connections never fire the callback (NEW_TOKEN from a peer is
    /// a client-only event).
    pub fn setNewTokenCallback(
        self: *Connection,
        cb: ?NewTokenCallback,
        user_data: ?*anyopaque,
    ) void {
        self.new_token_callback = cb;
        self.new_token_user_data = user_data;
    }

    /// Server-side helper: pre-load the client's first Initial Token
    /// field with `token` (a Retry token or a NEW_TOKEN from a prior
    /// connection). Idempotent. Used by `Client` to wire up
    /// `Client.Config.new_token` ahead of the first `advance`.
    pub fn setInitialToken(self: *Connection, token: []const u8) Error!void {
        if (self.role != .client) return Error.NotClientContext;
        try self.retry_token.resize(self.allocator, token.len);
        @memcpy(self.retry_token.items, token);
    }

    /// Server-side helper: queue a NEW_TOKEN frame for transmission at
    /// application encryption level (RFC 9000 §19.7). Idempotent — a
    /// second call before the first one drains overwrites the queued
    /// payload (we only ever owe one NEW_TOKEN per session by
    /// default). The bytes are copied into the per-connection
    /// pending-frames slot, so `token` does not need to outlive this
    /// call.
    pub fn queueNewToken(self: *Connection, token: []const u8) Error!void {
        if (self.role != .server) return Error.NotServerContext;
        // RFC 9000 §19.7: NEW_TOKEN MUST NOT carry a zero-length token
        // (a peer that received one would close with FRAME_ENCODING).
        // We also bound the upper end to the inline-buffer capacity;
        // server callers fed by `new_token.mint` always emit exactly
        // `new_token.max_token_len = 96`, which fits.
        if (token.len == 0) return Error.ZeroLengthNewToken;
        if (token.len > pending_frames_mod.NewTokenItem.max_len) return Error.NewTokenTooLong;
        var item: pending_frames_mod.NewTokenItem = .{};
        @memcpy(item.bytes[0..token.len], token);
        item.len = @intCast(token.len);
        self.pending_frames.new_token = item;
    }

    /// Per-connection 0-RTT toggle. This deliberately gates quic's
    /// packet scheduler as well as BoringSSL, so early application data
    /// is only sent after the caller opts in for this connection.
    pub fn setEarlyDataEnabled(self: *Connection, enabled: bool) void {
        self.early_data_send_enabled = enabled;
        self.inner.setEarlyDataEnabled(enabled);
    }

    /// Snapshot of BoringSSL's 0-RTT state machine: whether early
    /// data was attempted, accepted, or rejected, plus the rejection
    /// reason if any. Useful after the handshake finishes for
    /// metrics and assertions.
    pub fn earlyDataStatus(self: *Connection) EarlyDataStatus {
        return self.inner.earlyDataStatus();
    }

    /// Free-form reason string from BoringSSL describing why 0-RTT
    /// was rejected. Empty when 0-RTT was accepted or not attempted.
    pub fn earlyDataReason(self: *Connection) []const u8 {
        return self.inner.earlyDataReason();
    }

    /// The ALPN protocol negotiated during the handshake, or null
    /// before selection happens (or when the peer offered none). A
    /// server configured with several `alpn_protocols` uses this to
    /// learn which protocol a given connection actually speaks. The
    /// bytes are owned by BoringSSL and valid for the connection's
    /// lifetime.
    pub fn negotiatedAlpn(self: *Connection) ?[]const u8 {
        return self.inner.alpnSelected();
    }

    /// Server-only: install the QUIC 0-RTT replay context (RFC 9001
    /// §4.6.1). Required when 0-RTT is enabled on the server.
    pub fn setEarlyDataContext(self: *Connection, ctx: []const u8) !void {
        if (self.role != .server) return error.NotServerContext;
        if (ctx.len == 0) return Error.EmptyEarlyDataContext;
        try self.inner.setQuicEarlyDataContext(ctx);
    }

    /// Server convenience: build and install quic's canonical replay
    /// context from current transport parameters plus app-owned bytes.
    /// The returned digest is what callers should remember beside the
    /// issued ticket if they keep their own ticket metadata.
    pub fn setEarlyDataContextForParams(
        self: *Connection,
        params: TransportParams,
        alpn: []const u8,
        application_context: []const u8,
    ) !early_data_context_mod.Digest {
        const digest = try early_data_context_mod.build(.{
            .transport_params = params,
            .alpn = alpn,
            .application_context = application_context,
        });
        try self.setEarlyDataContext(&digest);
        return digest;
    }

    /// True once the TLS-1.3 handshake has emitted Finished and
    /// the server has issued HANDSHAKE_DONE. Streams and DATAGRAMs
    /// queued before this can still flow at 0-RTT level if early
    /// data was negotiated; everything else waits.
    pub fn handshakeDone(self: *Connection) bool {
        return self.inner.handshakeDone();
    }

    // INTERNAL: pub for conn_recv_data_handlers.zig access; not part of the embedder API.
    pub fn queueHandshakeDoneIfReady(self: *Connection) void {
        if (self.role != .server) return;
        if (!self.inner.handshakeDone()) return;
        if (self.handshake_done_queued_once) return;
        self.pending_handshake_done = true;
        self.handshake_done_queued_once = true;
    }

    /// True if BoringSSL is in QUIC mode (i.e. `tls.quic.Method`
    /// callbacks are wired up). Should always be true after `init*`.
    /// Useful as a sanity check during embedder bring-up.
    pub fn isQuic(self: *Connection) bool {
        return self.inner.isQuic();
    }

    /// Install an opt-in qlog-style callback for security/lifecycle
    /// diagnostics. quic never writes logs on its own; embedders can
    /// translate these events into qlog JSON, metrics, or test probes.
    pub fn setQlogCallback(self: *Connection, callback: ?QlogCallback, user_data: ?*anyopaque) void {
        return conn_qlog.setQlogCallback(self, callback, user_data);
    }

    /// Install an embedder-policy hook that gates peer migrations to
    /// a new 4-tuple (RFC 9000 §9). The callback fires synchronously
    /// **before** PATH_CHALLENGE / PATH_RESPONSE — i.e. as soon as the
    /// triggering datagram authenticates on the existing path's keys
    /// and we identify a different peer address. Most embedders only
    /// want an IP allowlist, which doesn't justify paying for a
    /// validation round-trip.
    ///
    /// Returning `.deny` from the callback drops the migration
    /// attempt: PATH_CHALLENGE is not queued, the existing path keeps
    /// its address (and its anti-amp credit grows from the triggering
    /// datagram), and the connection stays open. A
    /// `migration_path_failed` qlog event with reason `policy_denied`
    /// is emitted for observability.
    ///
    /// The callback receives `*const Connection` so it can read state
    /// but not mutate it. Pass `null` (with any user data) to remove
    /// a previously-installed callback.
    pub fn setMigrationCallback(
        self: *Connection,
        callback: ?MigrationCallback,
        user_data: ?*anyopaque,
    ) void {
        return conn_migration.setMigrationCallback(self, callback, user_data);
    }

    /// Enable or disable per-packet qlog events
    /// (`packet_sent`, `packet_received`, `packet_lost`). High-volume —
    /// keep off in production unless actively debugging.
    pub fn setQlogPacketEvents(self: *Connection, enabled: bool) void {
        return conn_qlog.setQlogPacketEvents(self, enabled);
    }

    fn emitConnectionStateIfChanged(self: *Connection) void {
        return conn_qlog.emitConnectionStateIfChanged(self);
    }

    pub fn emitPeerParametersSet(self: *Connection) void {
        return conn_qlog.emitPeerParametersSet(self);
    }

    fn emitPacketSent(self: *Connection, lvl: EncryptionLevel, pn: u64, size: u32, frames_count: u32) void {
        return conn_qlog.emitPacketSent(self, lvl, pn, size, frames_count);
    }

    fn emitLossDetected(self: *Connection, lvl: EncryptionLevel, loss_stats: LossStats, reason: QlogLossReason) void {
        return conn_qlog.emitLossDetected(self, lvl, loss_stats, reason);
    }

    fn emitPacketLost(self: *Connection, lvl: EncryptionLevel, pn: u64, bytes: u32, reason: QlogLossReason) void {
        return conn_qlog.emitPacketLost(self, lvl, pn, bytes, reason);
    }

    pub fn haveSecret(self: *const Connection, lvl: EncryptionLevel, dir: Direction) bool {
        return conn_keys.haveSecret(self, lvl, dir);
    }

    pub fn initialKeysActive(self: *const Connection, dir: Direction) bool {
        return conn_keys.initialKeysActive(self, dir);
    }

    pub fn cipherSuite(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) ?Suite {
        return conn_keys.cipherSuite(self, lvl, dir);
    }

    pub fn packetKeys(
        self: *const Connection,
        lvl: EncryptionLevel,
        dir: Direction,
    ) Error!?PacketKeys {
        return conn_keys.packetKeys(self, lvl, dir);
    }

    pub fn installApplicationSecret(
        self: *Connection,
        dir: Direction,
        material: SecretMaterial,
    ) Error!void {
        return conn_keys.installApplicationSecret(self, dir, material);
    }

    fn refreshNextApplicationReadKey(self: *Connection) Error!void {
        return conn_keys.refreshNextApplicationReadKey(self);
    }

    pub fn promoteApplicationReadKeys(self: *Connection, now_us: u64) Error!void {
        return conn_keys.promoteApplicationReadKeys(self, now_us);
    }

    pub fn canInitiateKeyUpdateAt(self: *const Connection, now_us: u64) bool {
        return conn_keys.canInitiateKeyUpdateAt(self, now_us);
    }

    pub fn requestKeyUpdate(self: *Connection, now_us: u64) Error!void {
        return conn_keys.requestKeyUpdate(self, now_us);
    }

    pub fn keyUpdateStatus(self: *const Connection) ApplicationKeyUpdateStatus {
        return conn_keys.keyUpdateStatus(self);
    }

    pub fn setApplicationKeyUpdateLimitsForTesting(
        self: *Connection,
        limits: ApplicationKeyUpdateLimits,
    ) void {
        return conn_keys.setApplicationKeyUpdateLimitsForTesting(self, limits);
    }

    pub fn allocApplicationPacketNumberForTesting(self: *Connection) ?u64 {
        return conn_keys.allocApplicationPacketNumberForTesting(self);
    }

    fn applicationWriteKeyPhase(self: *const Connection) bool {
        return conn_keys.applicationWriteKeyPhase(self);
    }

    fn prepareApplicationWriteKeys(self: *Connection, now_us: u64) Error!void {
        return conn_keys.prepareApplicationWriteKeys(self, now_us);
    }

    fn recordApplicationPacketProtected(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
    ) void {
        return conn_keys.recordApplicationPacketProtected(self, sent_packet);
    }

    pub fn onApplicationPacketAckedForKeys(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
        now_us: u64,
    ) void {
        return conn_keys.onApplicationPacketAckedForKeys(self, packet, now_us);
    }

    fn discardExpiredApplicationReadKeys(self: *Connection, now_us: u64) void {
        return conn_keys.discardExpiredApplicationReadKeys(self, now_us);
    }

    pub fn setPeerDcid(self: *Connection, cid: []const u8) !void {
        return conn_cids.setPeerDcid(self, cid);
    }

    pub fn setLocalScid(self: *Connection, cid: []const u8) !void {
        return conn_cids.setLocalScid(self, cid);
    }

    pub fn localDcidLen(self: *const Connection) u8 {
        return conn_cids.localDcidLen(self);
    }

    pub fn longHeaderScid(self: *const Connection) ConnectionId {
        return conn_cids.longHeaderScid(self);
    }

    pub fn smallestLiveLocalCidSeq(self: *const Connection, path_id: u32) ?u64 {
        return conn_cids.smallestLiveLocalCidSeq(self, path_id);
    }

    pub fn nextLocalConnectionIdSequence(self: *const Connection, path_id: u32) u64 {
        return conn_cids.nextLocalConnectionIdSequence(self, path_id);
    }

    pub fn localScidCount(self: *const Connection) usize {
        return conn_cids.localScidCount(self);
    }

    pub fn localScids(self: *const Connection, dst: []ConnectionId) usize {
        return conn_cids.localScids(self, dst);
    }

    pub fn ownsLocalCid(self: *const Connection, dcid: []const u8) bool {
        return conn_cids.ownsLocalCid(self, dcid);
    }

    pub fn findLocalCidSequence(self: *const Connection, dcid: []const u8) ?u64 {
        return conn_cids.findLocalCidSequence(self, dcid);
    }

    pub fn setIncomingLocalCidSeq(self: *Connection, seq: ?u64) void {
        return conn_cids.setIncomingLocalCidSeq(self, seq);
    }

    pub fn peerActiveConnectionIdLimit(self: *const Connection) u64 {
        return conn_cids.peerActiveConnectionIdLimit(self);
    }

    pub fn localConnectionIdIssueBudget(self: *const Connection, path_id: u32) usize {
        return conn_cids.localConnectionIdIssueBudget(self, path_id);
    }

    pub fn acceptInitial(
        self: *Connection,
        bytes: []const u8,
        params: TransportParams,
    ) Error!void {
        return conn_version.acceptInitial(self, bytes, params);
    }

    pub fn writeVersionNegotiation(
        self: *Connection,
        dst: []u8,
        client_packet: []const u8,
        supported_versions: []const u32,
    ) Error!usize {
        return conn_version.writeVersionNegotiation(self, dst, client_packet, supported_versions);
    }

    pub fn writeRetry(
        self: *Connection,
        dst: []u8,
        client_initial: []const u8,
        retry_scid: []const u8,
        retry_token: []const u8,
    ) Error!usize {
        return conn_version.writeRetry(self, dst, client_initial, retry_scid, retry_token);
    }

    pub fn setInitialDcid(self: *Connection, dcid: []const u8) Error!void {
        return conn_version.setInitialDcid(self, dcid);
    }

    fn discardInitialKeys(self: *Connection) void {
        return conn_keys.discardInitialKeys(self);
    }

    pub fn discardHandshakeKeys(self: *Connection) void {
        return conn_keys.discardHandshakeKeys(self);
    }

    pub fn setVersion(self: *Connection, version: u32) void {
        return conn_version.setVersion(self, version);
    }

    pub fn setPendingVersionUpgrade(self: *Connection, version: ?u32) void {
        return conn_version.setPendingVersionUpgrade(self, version);
    }

    pub fn applyPendingVersionUpgrade(self: *Connection) bool {
        return conn_version.applyPendingVersionUpgrade(self);
    }

    pub fn clientAcceptCompatibleVersion(self: *Connection, version: u32) bool {
        return conn_version.clientAcceptCompatibleVersion(self, version);
    }

    /// Open a new bidirectional stream with the given id. The id
    /// is caller-supplied. RFC 9000 §2.1 says the low two bits of
    /// a stream id encode (initiator, direction):
    ///   0 = client-initiated bidi, 1 = server-initiated bidi
    ///   2 = client-initiated uni,  3 = server-initiated uni
    pub fn openBidi(self: *Connection, id: u64) Error!*Stream {
        return conn_streams.openBidi(self, id);
    }

    /// Open a new unidirectional stream. The caller is responsible
    /// for choosing an id with the right low bits per §2.1.
    pub fn openUni(self: *Connection, id: u64) Error!*Stream {
        return conn_streams.openUni(self, id);
    }

    /// The `StreamType` this endpoint uses when it initiates a stream of the
    /// given directionality — client-{bidi,uni} for a client, server-{...}
    /// for a server.
    pub fn localStreamType(self: *const Connection, uni: bool) StreamType {
        return conn_streams.localStreamType(self, uni);
    }

    /// Open the next bidirectional stream initiated by this endpoint,
    /// choosing the id automatically (no manual RFC 9000 §2.1 bit math).
    /// Returns `StreamLimitExceeded` if the peer's bidi stream limit is
    /// reached; the id is not consumed in that case, so a later retry after
    /// the peer raises the limit reuses it.
    pub fn openNextBidi(self: *Connection) Error!*Stream {
        return conn_streams.openNextBidi(self);
    }

    /// Open the next unidirectional stream initiated by this endpoint —
    /// e.g. an HTTP/3 control or QPACK encoder/decoder stream — choosing the
    /// id automatically. Same limit/retry semantics as `openNextBidi`.
    pub fn openNextUni(self: *Connection) Error!*Stream {
        return conn_streams.openNextUni(self);
    }

    pub fn peekNextBidi(self: *const Connection) u64 {
        return conn_streams.peekNextBidi(self);
    }

    pub fn peekNextUni(self: *const Connection) u64 {
        return conn_streams.peekNextUni(self);
    }

    pub fn streamIndex(id: u64) u64 {
        return conn_streams.streamIndex(id);
    }

    pub fn initialRecvStreamLimit(self: *const Connection, id: u64) u64 {
        return conn_streams.initialRecvStreamLimit(self, id);
    }

    pub fn initialSendStreamLimit(self: *const Connection, id: u64) u64 {
        return conn_streams.initialSendStreamLimit(self, id);
    }

    /// Install the peer's transport parameters remembered from a prior
    /// connection, for a 0-RTT resumption. Bounds early-data (0-RTT)
    /// sends before the real peer params arrive — per-stream (via
    /// `initialSendStreamLimit`) and connection-level (by tightening
    /// `peer_max_data`). No-op-ish once the real params are cached:
    /// `applyPeerFlowTransportParams` overwrites `peer_max_data` and
    /// `@max`-raises each stream's window to the true (>= remembered)
    /// limits. Intended to be called at connection setup by the client
    /// wrapper when it also installs the resumption session ticket.
    pub fn setRememberedPeerTransportParams(self: *Connection, params: TransportParams) void {
        self.remembered_peer_transport_params = params;
        if (self.cached_peer_transport_params == null) {
            self.peer_max_data = @min(self.peer_max_data, params.initial_max_data);
        }
    }

    pub fn recordPeerStreamOpenOrClose(self: *Connection, id: u64) bool {
        return conn_streams.recordPeerStreamOpenOrClose(self, id);
    }

    /// Connection-level send flow credit: new stream bytes the peer's
    /// MAX_DATA window accepts right now. See `streamSendWindow` for
    /// the per-stream composite view.
    pub fn sendWindow(self: *const Connection) u64 {
        return conn_streams.connectionSendWindow(self);
    }

    /// Send-side flow-control snapshot for one stream: connection and
    /// stream credit, queued-but-unsent backlog, and the net
    /// `writable` figure a backpressure gate wants (see `SendWindow`).
    /// Null for unknown streams and peer-initiated uni streams.
    /// Reflects peer flow-control windows only — congestion control
    /// and pacing intentionally excluded.
    pub fn streamSendWindow(self: *const Connection, id: u64) ?SendWindow {
        return conn_streams.streamSendWindow(self, id);
    }

    pub fn limitChunkToSendFlow(
        self: *Connection,
        s: *const Stream,
        chunk: send_stream_mod.Chunk,
    ) Error!?send_stream_mod.Chunk {
        return conn_streams.limitChunkToSendFlow(self, s, chunk);
    }

    fn limitChunkToSendFlowAfterPlanned(
        self: *Connection,
        s: *const Stream,
        chunk: send_stream_mod.Chunk,
        planned_conn_new_bytes: u64,
    ) Error!?send_stream_mod.Chunk {
        return conn_streams.limitChunkToSendFlowAfterPlanned(self, s, chunk, planned_conn_new_bytes);
    }

    fn streamFlowNewBytes(s: *const Stream, chunk: send_stream_mod.Chunk) u64 {
        return conn_streams.streamFlowNewBytes(s, chunk);
    }

    pub fn recordStreamFlowSent(self: *Connection, s: *Stream, chunk: send_stream_mod.Chunk) void {
        return conn_streams.recordStreamFlowSent(self, s, chunk);
    }

    /// Iterate over every open stream. The yielded pointer is
    /// invalidated by `openBidi` / `openUni` (HashMap rehash) and
    /// by stream removal — finish iteration before mutating the
    /// stream set.
    pub fn streamIterator(self: *Connection) std.AutoHashMapUnmanaged(u64, *Stream).Iterator {
        return conn_streams.streamIterator(self);
    }

    pub fn streamCount(self: *const Connection) usize {
        return conn_streams.streamCount(self);
    }

    fn gcClosedStreams(self: *Connection) void {
        return conn_streams.gcClosedStreams(self);
    }

    /// Look up a stream by id. Returns null if no stream is open
    /// at that id.
    pub fn stream(self: *const Connection, id: u64) ?*Stream {
        return conn_streams.stream(self, id);
    }

    /// Snapshot of stream `id`'s send-half progress (bytes written, acked,
    /// buffered, and whether anything is ready to send), or `null` if the
    /// stream is not in the live table — either never opened or already
    /// reaped after both halves reached a terminal state (RFC 9000 §3.2).
    /// Lets an embedder track send backpressure without reaching into
    /// `SendStream`'s internals; snapshot a terminal stream's stats before
    /// the reaping GC removes it if you need them post-close.
    pub fn streamSendStats(self: *const Connection, id: u64) ?StreamSendStats {
        return conn_streams.streamSendStats(self, id);
    }

    /// Set the RFC 9218 send priority of stream `id` (see `StreamPriority`).
    /// The application-data send scheduler emits ready streams in urgency
    /// order (then stream id), so a higher-urgency stream's bytes lead. An
    /// embedder (e.g. an HTTP/3 layer honoring the `priority` header /
    /// PRIORITY_UPDATE) can update this at any time; it takes effect on the
    /// next packet built. Returns `StreamNotFound` for an unknown/reaped id.
    pub fn streamSetPriority(self: *Connection, id: u64, p: StreamPriority) Error!void {
        return conn_streams.streamSetPriority(self, id, p);
    }

    /// The current RFC 9218 send priority of stream `id`, or `null` if the
    /// stream is not in the live table (never opened, or already reaped).
    pub fn streamPriority(self: *const Connection, id: u64) ?StreamPriority {
        return conn_streams.streamPriority(self, id);
    }

    pub fn collectSendableStreamsByPriority(self: *Connection, buf: []*Stream) []*Stream {
        return conn_streams.collectSendableStreamsByPriority(self, buf);
    }

    /// Read-only recv-half status of stream `id`: whether the peer's FIN or
    /// RESET_STREAM has been seen, and whether the receive side has reached a
    /// terminal state (RFC 9000 §3.2). Returns `null` if the stream is not in
    /// the live table (never opened, or already reaped). Unlike
    /// `recvFullyTerminated`, it distinguishes a clean FIN from an abortive
    /// RESET, and holds no `*Stream` the caller must keep valid across a reap.
    pub fn streamRecvState(self: *const Connection, id: u64) ?StreamRecvState {
        return conn_streams.streamRecvState(self, id);
    }

    /// Convenience: write `data` to the send half of stream `id`.
    pub fn streamWrite(self: *Connection, id: u64, data: []const u8) Error!usize {
        return conn_streams.streamWrite(self, id, data);
    }

    /// Convenience: read from the receive half of stream `id`.
    pub fn streamRead(self: *Connection, id: u64, dst: []u8) Error!usize {
        return conn_streams.streamRead(self, id, dst);
    }

    /// Like `streamRead`, but also reports whether the peer's FIN has been
    /// seen — so a caller captures end-of-stream inline with the last read
    /// rather than inspecting the receive half separately, which the stream
    /// GC reaps the moment the recv side goes terminal. Prefer this over
    /// `streamRead` when you need to detect clean stream completion.
    pub fn streamReadFin(self: *Connection, id: u64, dst: []u8) Error!StreamReadResult {
        return conn_streams.streamReadFin(self, id, dst);
    }

    pub fn streamArrivedInEarlyData(self: *const Connection, id: u64) ?bool {
        return conn_streams.streamArrivedInEarlyData(self, id);
    }

    pub fn localDataBlockedAt(self: *const Connection) ?u64 {
        return conn_flow.localDataBlockedAt(self);
    }

    pub fn localStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
        return conn_flow.localStreamDataBlockedAt(self, stream_id);
    }

    pub fn localStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
        return conn_flow.localStreamsBlockedAt(self, bidi);
    }

    pub fn peerDataBlockedAt(self: *const Connection) ?u64 {
        return conn_flow.peerDataBlockedAt(self);
    }

    pub fn peerStreamDataBlockedAt(self: *const Connection, stream_id: u64) ?u64 {
        return conn_flow.peerStreamDataBlockedAt(self, stream_id);
    }

    pub fn peerStreamsBlockedAt(self: *const Connection, bidi: bool) ?u64 {
        return conn_flow.peerStreamsBlockedAt(self, bidi);
    }

    pub fn shouldQueueReceiveCredit(consumed: u64, advertised: u64, window: u64) bool {
        return conn_flow.shouldQueueReceiveCredit(consumed, advertised, window);
    }

    pub fn queueMaxStreams(self: *Connection, bidi: bool, maximum_streams: u64) void {
        return conn_flow.queueMaxStreams(self, bidi, maximum_streams);
    }

    pub fn connectionIdReplenishInfo(
        self: *const Connection,
        path_id: u32,
    ) ?ConnectionIdReplenishInfo {
        return conn_cids.connectionIdReplenishInfo(self, path_id);
    }

    fn recordDatagramLost(self: *Connection, packet: *const sent_packets_mod.SentPacket) void {
        return conn_datagram.recordDatagramLost(self, packet);
    }

    pub fn upsertStreamBlocked(
        list: *std.ArrayList(frame_types.StreamDataBlocked),
        allocator: std.mem.Allocator,
        item: frame_types.StreamDataBlocked,
    ) Error!bool {
        return conn_flow.upsertStreamBlocked(list, allocator, item);
    }

    pub fn noteDataBlocked(self: *Connection, maximum_data: u64) void {
        return conn_flow.noteDataBlocked(self, maximum_data);
    }

    fn requeueDataBlocked(self: *Connection, maximum_data: u64) bool {
        return conn_flow.requeueDataBlocked(self, maximum_data);
    }

    pub fn clearLocalDataBlocked(self: *Connection, new_limit: u64) void {
        return conn_flow.clearLocalDataBlocked(self, new_limit);
    }

    pub fn noteStreamDataBlocked(
        self: *Connection,
        stream_id: u64,
        maximum_stream_data: u64,
    ) Error!void {
        return conn_flow.noteStreamDataBlocked(self, stream_id, maximum_stream_data);
    }

    fn requeueStreamDataBlocked(
        self: *Connection,
        item: frame_types.StreamDataBlocked,
    ) Error!bool {
        return conn_flow.requeueStreamDataBlocked(self, item);
    }

    pub fn clearLocalStreamDataBlocked(
        self: *Connection,
        stream_id: u64,
        new_limit: u64,
    ) void {
        return conn_flow.clearLocalStreamDataBlocked(self, stream_id, new_limit);
    }

    pub fn noteStreamsBlocked(self: *Connection, bidi: bool, maximum_streams: u64) void {
        return conn_flow.noteStreamsBlocked(self, bidi, maximum_streams);
    }

    fn requeueStreamsBlocked(self: *Connection, item: frame_types.StreamsBlocked) bool {
        return conn_flow.requeueStreamsBlocked(self, item);
    }

    pub fn clearLocalStreamsBlocked(self: *Connection, bidi: bool, new_limit: u64) void {
        return conn_flow.clearLocalStreamsBlocked(self, bidi, new_limit);
    }

    /// Convenience: close the send half of stream `id` (queues FIN).
    pub fn streamFinish(self: *Connection, id: u64) Error!void {
        return conn_streams.streamFinish(self, id);
    }

    /// Convenience: abort the send half of stream `id` with
    /// RESET_STREAM (RFC 9000 §19.4). Any queued but unsent STREAM data
    /// is discarded; the final size is the number of bytes already
    /// accepted by `streamWrite`.
    pub fn streamReset(
        self: *Connection,
        id: u64,
        application_error_code: u64,
    ) Error!void {
        return conn_streams.streamReset(self, id, application_error_code);
    }

    /// Queue an RFC 9221 DATAGRAM payload for transmission. The next
    /// 1-RTT packet that fits the bytes ships them. Queueing is capped
    /// by the implementation's UDP packet budget and, once known, the
    /// peer's `max_datagram_frame_size` transport parameter.
    pub fn sendDatagram(self: *Connection, payload: []const u8) Error!void {
        return conn_datagram.sendDatagram(self, payload);
    }

    /// Queue a DATAGRAM and return a connection-local id that will be
    /// echoed in `datagram_acked` / `datagram_lost` events. QUIC never
    /// retransmits DATAGRAM frames; this id is only for app retry policy.
    pub fn sendDatagramTracked(self: *Connection, payload: []const u8) Error!u64 {
        return conn_datagram.sendDatagramTracked(self, payload);
    }

    /// The largest RFC 9221 DATAGRAM payload (in bytes) that `sendDatagram`
    /// / `sendDatagramTracked` will accept right now.
    ///
    /// It tracks the live path: it grows as DPLPMTUD validates a larger PMTU
    /// and shrinks after a PMTU black-hole, and is further bounded by the
    /// peer's `max_datagram_frame_size` transport parameter once the handshake
    /// supplies it. Returns `Error.DatagramUnavailable` when the peer did not
    /// enable DATAGRAM (advertised `max_datagram_frame_size == 0`).
    ///
    /// The value is a snapshot — a later black-hole event can lower it and
    /// `sendDatagram` re-validates at send time — so treat it as "safe to send
    /// now," not a standing guarantee. RFC 9221 §5 forbids fragmenting a
    /// DATAGRAM; the send path only emits one that fits the current packet, so
    /// a payload sized to this value is carried whole.
    pub fn maxDatagramPayload(self: *const Connection) Error!usize {
        return conn_datagram.maxDatagramPayload(self);
    }

    pub fn queueNewConnectionId(
        self: *Connection,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        return conn_cids.queueNewConnectionId(self, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn queueRetireConnectionId(
        self: *Connection,
        sequence_number: u64,
    ) Error!void {
        return conn_cids.queueRetireConnectionId(self, sequence_number);
    }

    /// True if the peer advertised the §4 `alternative_address`
    /// transport parameter on its handshake. Returns false when peer
    /// transport parameters haven't been received yet, when the peer
    /// is a server (servers MUST NOT send the parameter), or when the
    /// peer simply omitted it. Drives the negotiation gate on
    /// `advertiseAlternative*Address`.
    /// Optional flags for `advertiseAlternative*Address`; declared in conn_migration.zig.
    pub const AdvertiseAlternativeAddressOptions = conn_migration.AdvertiseAlternativeAddressOptions;

    pub fn peerSupportsAlternativeAddress(self: *const Connection) bool {
        return conn_migration.peerSupportsAlternativeAddress(self);
    }

    pub fn localAdvertisedAlternativeAddress(self: *const Connection) bool {
        return conn_migration.localAdvertisedAlternativeAddress(self);
    }

    pub fn advertiseAlternativeV4Address(
        self: *Connection,
        address: [4]u8,
        port: u16,
        opts: AdvertiseAlternativeAddressOptions,
    ) Error!u64 {
        return conn_migration.advertiseAlternativeV4Address(self, address, port, opts);
    }

    pub fn advertiseAlternativeV6Address(
        self: *Connection,
        address: [16]u8,
        port: u16,
        opts: AdvertiseAlternativeAddressOptions,
    ) Error!u64 {
        return conn_migration.advertiseAlternativeV6Address(self, address, port, opts);
    }

    /// Pop the oldest received DATAGRAM into `dst`. Returns the
    /// number of bytes written, or null if none pending. The
    /// payload is dropped from the queue regardless of whether it
    /// fit — caller must size `dst` to the peer's advertised
    /// `max_datagram_frame_size`.
    pub fn receiveDatagram(self: *Connection, dst: []u8) ?usize {
        return conn_datagram.receiveDatagram(self, dst);
    }

    /// Pop the oldest received DATAGRAM and include whether it arrived
    /// in 0-RTT. The payload is dropped from the queue regardless of
    /// whether it fit.
    pub fn receiveDatagramInfo(self: *Connection, dst: []u8) ?IncomingDatagram {
        return conn_datagram.receiveDatagramInfo(self, dst);
    }

    pub fn pendingDatagrams(self: *const Connection) usize {
        return conn_datagram.pendingDatagrams(self);
    }

    pub fn enableMultipath(self: *Connection, enabled: bool) void {
        return conn_paths.enableMultipath(self, enabled);
    }

    pub fn multipathEnabled(self: *const Connection) bool {
        return conn_paths.multipathEnabled(self);
    }

    pub fn multipathNegotiated(self: *const Connection) bool {
        return conn_paths.multipathNegotiated(self);
    }

    pub fn peerSupportsGreaseQuicBit(self: *const Connection) bool {
        return conn_paths.peerSupportsGreaseQuicBit(self);
    }

    fn nextQuicBit(self: *const Connection) u1 {
        return conn_paths.nextQuicBit(self);
    }

    pub fn openPath(
        self: *Connection,
        peer_addr: Address,
        local_addr: Address,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
    ) Error!u32 {
        return conn_paths.openPath(self, peer_addr, local_addr, local_cid, peer_cid);
    }

    pub fn setActivePath(self: *Connection, path_id: u32) bool {
        return conn_paths.setActivePath(self, path_id);
    }

    pub fn abandonPath(self: *Connection, path_id: u32) bool {
        return conn_paths.abandonPath(self, path_id);
    }

    pub fn abandonPathAt(
        self: *Connection,
        path_id: u32,
        error_code: u64,
        now_us: u64,
    ) bool {
        return conn_paths.abandonPathAt(self, path_id, error_code, now_us);
    }

    pub fn setPathBackup(self: *Connection, path_id: u32, backup: bool) bool {
        return conn_paths.setPathBackup(self, path_id, backup);
    }

    pub fn markPathValidated(self: *Connection, path_id: u32) bool {
        return conn_paths.markPathValidated(self, path_id);
    }

    pub fn setScheduler(self: *Connection, scheduler: Scheduler) void {
        return conn_paths.setScheduler(self, scheduler);
    }

    pub fn activePathId(self: *const Connection) u32 {
        return conn_paths.activePathId(self);
    }

    pub fn pathStats(self: *const Connection, path_id: u32) ?PathStats {
        return conn_paths.pathStats(self, path_id);
    }

    /// One-call observability snapshot (Unstable tier): whole-connection
    /// byte/packet counters, an active-path cwnd/RTT/PMTU snapshot, and
    /// the open-stream/close-state gauges — the connection-level mirror
    /// of `Server.metricsSnapshot`. Everything is copied by value, so
    /// the result is safe to hold across ticks and reaps. Per-path
    /// detail stays on `pathStats(path_id)`.
    pub fn stats(self: *const Connection) ConnectionStats {
        return conn_stats.stats(self);
    }

    pub fn queuePathAbandon(self: *Connection, path_id: u32, error_code: u64) Error!void {
        return path_frame_queue.queuePathAbandon(self, path_id, error_code);
    }

    pub fn queuePathStatus(self: *Connection, path_id: u32, available: bool, sequence_number: u64) Error!void {
        return path_frame_queue.queuePathStatus(self, path_id, available, sequence_number);
    }

    pub fn queuePathNewConnectionId(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: []const u8,
        stateless_reset_token: [16]u8,
    ) Error!void {
        return path_frame_queue.queuePathNewConnectionId(self, path_id, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn queuePathRetireConnectionId(self: *Connection, path_id: u32, sequence_number: u64) Error!void {
        return path_frame_queue.queuePathRetireConnectionId(self, path_id, sequence_number);
    }

    pub fn queueMaxPathId(self: *Connection, maximum_path_id: u32) void {
        return path_frame_queue.queueMaxPathId(self, maximum_path_id);
    }

    pub fn queuePathsBlocked(self: *Connection, maximum_path_id: u32) void {
        return path_frame_queue.queuePathsBlocked(self, maximum_path_id);
    }

    pub fn queuePathCidsBlocked(self: *Connection, path_id: u32, next_sequence_number: u64) void {
        return path_frame_queue.queuePathCidsBlocked(self, path_id, next_sequence_number);
    }

    pub fn pendingPathCidsBlocked(self: *const Connection) ?PathCidsBlockedInfo {
        return path_frame_queue.pendingPathCidsBlocked(self);
    }

    pub fn clearPendingPathCidsBlocked(self: *Connection, path_id: u32, next_sequence_number: u64) void {
        return path_frame_queue.clearPendingPathCidsBlocked(self, path_id, next_sequence_number);
    }

    pub fn replenishConnectionIds(
        self: *Connection,
        provisions: []const ConnectionIdProvision,
    ) Error!usize {
        return conn_cids.replenishConnectionIds(self, provisions);
    }

    pub fn replenishPathConnectionIds(
        self: *Connection,
        path_id: u32,
        provisions: []const ConnectionIdProvision,
    ) Error!usize {
        return conn_cids.replenishPathConnectionIds(self, path_id, provisions);
    }

    // INTERNAL: pub for conn_recv_data_handlers.zig access; not part of the embedder API.
    pub fn cachePeerTransportParams(self: *Connection) Error!void {
        if (self.cached_peer_transport_params != null) return;
        const blob = self.inner.peerQuicTransportParams() orelse return;
        self.cached_peer_transport_params = try transport_params_mod.Params.decode(blob);
        if (self.cached_peer_transport_params.?.initial_max_path_id) |max_path_id| {
            self.peer_max_path_id = @min(max_path_id, max_supported_path_id);
            self.multipath_enabled = true;
        }
        self.validatePeerTransportLimits();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        self.validatePeerTransportRole();
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) {
            self.emitConnectionStateIfChanged();
            return;
        }
        try self.installPeerTransportStatelessResetToken();
        try self.installPreferredAddressConnectionId();
        self.validatePeerTransportConnectionIds();
        // Successfully accepted — fire `parameters_set` once.
        self.emitPeerParametersSet();
    }

    /// RFC 9000 §5.1.1 / §18.2: a server's `preferred_address` transport
    /// parameter carries a `connection_id` field that the client SHOULD
    /// register as if it had arrived in a NEW_CONNECTION_ID frame with
    /// sequence number 1. Some servers (notably ngtcp2) only ever
    /// advertise CIDs through this channel — they never proactively
    /// emit a NEW_CONNECTION_ID frame after the handshake, so missing
    /// this registration leaves the client with exactly one peer CID
    /// (the initial DCID) and a client-initiated active migration
    /// fails to satisfy the §5.1.2 ¶1 rotation requirement.
    ///
    /// Server-only operation: clients are forbidden from sending
    /// `preferred_address`; that's enforced upstream in
    /// `validatePeerTransportRole`.
    fn installPreferredAddressConnectionId(self: *Connection) Error!void {
        if (self.role != .client) return;
        const params = self.cached_peer_transport_params orelse return;
        const pref = params.preferred_address orelse return;
        if (pref.connection_id.len == 0) return;
        // Idempotent: skip if the CID is already registered (e.g. a
        // peer that also sends NEW_CONNECTION_ID for the same value).
        for (self.peer_cids.items) |item| {
            if (ConnectionId.eql(item.cid, pref.connection_id)) return;
        }
        try self.registerPeerCid(0, 1, 0, pref.connection_id, pref.stateless_reset_token);
    }

    pub fn validatePeerTransportLimits(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        if (params.max_udp_payload_size < min_quic_udp_payload_size) {
            self.close(true, transport_error_transport_parameter, "peer max udp payload below minimum");
            return;
        }
        if (params.initial_max_streams_bidi > max_stream_count_limit or
            params.initial_max_streams_uni > max_stream_count_limit)
        {
            self.close(true, transport_error_transport_parameter, "peer stream count exceeds maximum");
            return;
        }
        const peer_udp_limit: usize = @intCast(@min(params.max_udp_payload_size, max_supported_udp_payload_size));
        self.mtu = @min(self.mtu, peer_udp_limit);
        for (self.paths.paths.items) |*path| {
            path.pmtu = @min(path.pmtu, peer_udp_limit);
        }
        self.applyPeerFlowTransportParams(params);
    }

    pub fn validatePeerTransportRole(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        switch (self.role) {
            .server => {
                if (params.original_destination_connection_id != null) {
                    self.close(true, transport_error_transport_parameter, "client sent original destination cid");
                    return;
                }
                if (params.stateless_reset_token != null) {
                    self.close(true, transport_error_transport_parameter, "client sent stateless reset token");
                    return;
                }
                if (params.preferred_address != null) {
                    self.close(true, transport_error_transport_parameter, "client sent preferred address");
                    return;
                }
                if (params.retry_source_connection_id != null) {
                    self.close(true, transport_error_transport_parameter, "client sent retry source cid");
                    return;
                }
                // RFC 9368 §6 ¶6/¶7 downgrade-attack guard (symmetric
                // server-side counterpart to the client-side check
                // below): the client's `version_information.chosen_version`
                // MUST equal the wire version of the FIRST Initial we
                // observed. We can't compare against `self.version`
                // directly because, when an RFC 9368 §6 compatible-
                // version upgrade has been applied, `self.version` has
                // already been flipped to the upgrade target by
                // `applyPendingVersionUpgrade` — the original wire
                // version was snapshotted into `initial_wire_version`
                // by `acceptInitial` before that flip. A mismatch
                // means a path attacker rewrote the wire version on
                // the client's Initial while leaving the encrypted
                // ClientHello intact (which would otherwise steer the
                // server onto a weaker version). Graceful fallback:
                // when `advertised_versions` is empty (a peer that
                // never sent `version_information`) or
                // `initial_wire_version` is null (handshake started
                // before this code was active), we ignore the check.
                const advertised_versions = params.compatibleVersions();
                if (advertised_versions.len > 0) {
                    if (self.initial_wire_version) |wire_version| {
                        if (advertised_versions[0] != wire_version) {
                            self.close(
                                true,
                                transport_error_transport_parameter,
                                "client chosen_version mismatches wire version",
                            );
                            return;
                        }
                    }
                }
            },
            .client => {
                // draft-munizaga-quic-alternative-server-address-00 §4 ¶2:
                // "Servers MUST NOT send this transport parameter. A
                // client that supports this extension and receives this
                // transport parameter MUST abort the connection with a
                // TRANSPORT_PARAMETER_ERROR."
                //
                // The MUST is explicitly conditioned on the client
                // supporting the extension; a non-supporting client
                // is technically free to ignore the parameter (RFC
                // 9000 §18 forward-compat would treat an unrecognized
                // parameter as a no-op). quic deliberately picks
                // the strict close instead: a server that emits the
                // parameter is broken regardless of whether *this*
                // client happens to support the extension, and
                // surfacing the violation forces the operator to
                // notice and fix it rather than papering over the
                // bug. Both behaviors are spec-conformant; this is
                // the safer of the two.
                if (params.alternative_address) {
                    self.close(true, transport_error_transport_parameter, "server sent alternative_address");
                    return;
                }
                // RFC 9368 §6 ¶6/¶7 downgrade-attack guard: when the
                // server advertises `version_information`, the first
                // entry (the server's `chosen_version`) MUST equal
                // the wire version we currently see on the response
                // carrying it — otherwise a path attacker could
                // splice a v1 ClientHello into a v2 Initial response
                // and steer the client onto a weaker version. Since
                // these transport parameters are surfaced through TLS
                // EncryptedExtensions only after our active
                // `self.version` has been adopted (see the
                // compatible-version upgrade hook in
                // `handleInitial`), the check is just `chosen ==
                // self.version`.
                const advertised_versions = params.compatibleVersions();
                if (advertised_versions.len > 0 and advertised_versions[0] != self.version) {
                    self.close(
                        true,
                        transport_error_transport_parameter,
                        "server chosen_version mismatches wire version",
                    );
                    return;
                }
            },
        }
    }

    fn applyPeerFlowTransportParams(self: *Connection, params: TransportParams) void {
        self.peer_max_data = params.initial_max_data;
        self.peer_max_streams_bidi = @min(params.initial_max_streams_bidi, max_streams_per_connection);
        self.peer_max_streams_uni = @min(params.initial_max_streams_uni, max_streams_per_connection);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.*;
            const current = if (s.send_max_data == std.math.maxInt(u64)) 0 else s.send_max_data;
            s.send_max_data = @max(current, self.initialSendStreamLimit(s.id));
        }
    }

    pub fn peerAckDelayExponent(self: *const Connection) u6 {
        const params = self.cached_peer_transport_params orelse return 3;
        return @intCast(@min(params.ack_delay_exponent, 20));
    }

    pub fn peerMaxAckDelayUs(self: *const Connection) u64 {
        const params = self.cached_peer_transport_params orelse return 25 * rtt_mod.ms;
        return params.max_ack_delay_ms * rtt_mod.ms;
    }

    fn localMaxAckDelayUs(self: *const Connection) u64 {
        return self.local_transport_params.max_ack_delay_ms * rtt_mod.ms;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn ackDelayScaled(
        self: *const Connection,
        tracker: *const ack_tracker_mod.AckTracker,
        now_us: u64,
    ) u64 {
        const largest_at_us = tracker.largest_at_ms * rtt_mod.ms;
        if (now_us <= largest_at_us) return 0;
        const shift: u6 = @intCast(@min(self.local_transport_params.ack_delay_exponent, 20));
        return (now_us - largest_at_us) >> shift;
    }

    fn ackDelayDeadlineUs(
        self: *const Connection,
        tracker: *const ack_tracker_mod.AckTracker,
    ) ?u64 {
        const base_ms = tracker.ackDelayBaseMs() orelse return null;
        return base_ms * rtt_mod.ms +| self.localMaxAckDelayUs();
    }

    fn promoteDueAckDelay(self: *Connection, tracker: *ack_tracker_mod.AckTracker, now_us: u64) void {
        _ = tracker.promoteDelayedAck(
            now_us / rtt_mod.ms,
            self.local_transport_params.max_ack_delay_ms,
        );
    }

    // INTERNAL: pub for conn_loss.zig access; not part of the embedder API.
    pub fn idleTimeoutUs(self: *const Connection) ?u64 {
        // RFC 9000 §10.1 ¶2: "An idle timeout value of 0 is equivalent
        // to no timeout." The effective value is the minimum of local
        // and peer; if either is 0 the connection has no idle timeout.
        // We treat "peer params not yet cached" the same as "peer
        // advertised 0" — pre-handshake there is no negotiated value
        // so no idle deadline applies.
        const local = self.local_transport_params.max_idle_timeout_ms;
        if (local == 0) return null;
        const params = self.cached_peer_transport_params orelse return null;
        if (params.max_idle_timeout_ms == 0) return null;
        return @min(local, params.max_idle_timeout_ms) * rtt_mod.ms;
    }

    pub fn primaryPath(self: *Connection) *PathState {
        return conn_paths.primaryPath(self);
    }

    pub fn primaryPathConst(self: *const Connection) *const PathState {
        return conn_paths.primaryPathConst(self);
    }

    pub fn activePath(self: *Connection) *PathState {
        return conn_paths.activePath(self);
    }

    fn applicationPathForPoll(self: *Connection) *PathState {
        return conn_paths.applicationPathForPoll(self);
    }

    pub fn incomingPathId(self: *Connection, from: ?Address) u32 {
        return conn_paths.incomingPathId(self, from);
    }

    pub fn peerAddressChangeCandidate(
        self: *Connection,
        path_id: u32,
        from: ?Address,
    ) ?Address {
        return conn_paths.peerAddressChangeCandidate(self, path_id, from);
    }

    pub fn queuePathResponseOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
        addr: ?Address,
    ) void {
        return conn_paths.queuePathResponseOnPath(self, path_id, token, addr);
    }

    fn queuePathChallengeOnPath(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) void {
        return conn_paths.queuePathChallengeOnPath(self, path_id, token);
    }

    fn handlePathValidationFailure(
        self: *Connection,
        path: *PathState,
    ) void {
        return conn_paths.handlePathValidationFailure(self, path);
    }

    pub fn recordPathResponse(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) void {
        return conn_paths.recordPathResponse(self, path_id, token);
    }

    fn shouldRequeuePathChallenge(
        self: *Connection,
        path_id: u32,
        token: [8]u8,
    ) bool {
        return conn_paths.shouldRequeuePathChallenge(self, path_id, token);
    }

    pub fn handlePeerAddressChange(
        self: *Connection,
        path: *PathState,
        addr: Address,
        datagram_len: usize,
        now_us: u64,
    ) Error!void {
        return conn_migration.handlePeerAddressChange(self, path, addr, datagram_len, now_us);
    }

    fn consumeFreshPeerCidForMigration(
        self: *Connection,
        path: *PathState,
    ) ?ConnectionId {
        return conn_migration.consumeFreshPeerCidForMigration(self, path);
    }

    pub fn beginClientActiveMigration(
        self: *Connection,
        new_local_addr: Address,
        now_us: u64,
    ) Error!void {
        return conn_migration.beginClientActiveMigration(self, new_local_addr, now_us);
    }

    pub fn noteServerLocalAddressChanged(
        self: *Connection,
        new_local_addr: Address,
        now_us: u64,
    ) Error!void {
        return conn_migration.noteServerLocalAddressChanged(self, new_local_addr, now_us);
    }

    pub fn recordAuthenticatedDatagramAddress(
        self: *Connection,
        path_id: u32,
        addr: Address,
        datagram_len: usize,
        now_us: u64,
    ) Error!void {
        return conn_migration.recordAuthenticatedDatagramAddress(self, path_id, addr, datagram_len, now_us);
    }

    pub fn incomingShortPath(self: *Connection, bytes: []const u8) ?*PathState {
        return conn_migration.incomingShortPath(self, bytes);
    }

    fn connPnIdx(lvl: EncryptionLevel) ?usize {
        return switch (lvl) {
            .initial => 0,
            .handshake => 1,
            .early_data, .application => null,
        };
    }

    pub fn pnSpaceForLevel(self: *Connection, lvl: EncryptionLevel) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPath().app_pn_space;
    }

    // INTERNAL: pub for conn_loss.zig access; not part of the embedder API.
    pub fn pnSpaceForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &self.primaryPathConst().app_pn_space;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn pnSpaceForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *PnSpace {
        if (connPnIdx(lvl)) |idx| return &self.pn_spaces[idx];
        return &app_path.app_pn_space;
    }

    pub fn sentForLevel(self: *Connection, lvl: EncryptionLevel) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPath().sent;
    }

    // INTERNAL: pub for conn_loss.zig access; not part of the embedder API.
    pub fn sentForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &self.primaryPathConst().sent;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn sentForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *SentPacketTracker {
        if (connPnIdx(lvl)) |idx| return &self.sent[idx];
        return &app_path.sent;
    }

    pub fn rttForLevel(self: *Connection, lvl: EncryptionLevel) *RttEstimator {
        _ = lvl;
        return &self.primaryPath().path.rtt;
    }

    // INTERNAL: pub for conn_loss.zig access; not part of the embedder API.
    pub fn rttForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const RttEstimator {
        _ = lvl;
        return &self.primaryPathConst().path.rtt;
    }

    fn rttForLevelOnPathConst(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) *const RttEstimator {
        if (lvl == .application) return &app_path.path.rtt;
        return &self.primaryPathConst().path.rtt;
    }

    pub fn ccForApplication(self: *Connection) *CongestionController {
        return &self.primaryPath().path.cc;
    }

    fn ccForApplicationConst(self: *const Connection) *const CongestionController {
        return &self.primaryPathConst().path.cc;
    }

    pub fn ptoCountForLevel(self: *Connection, lvl: EncryptionLevel) *u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPath().pto_count;
    }

    // INTERNAL: pub for conn_loss.zig access; not part of the embedder API.
    pub fn ptoCountForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const u32 {
        if (connPnIdx(lvl)) |idx| return &self.pto_count[idx];
        return &self.primaryPathConst().pto_count;
    }

    pub fn pendingPingForLevel(self: *Connection, lvl: EncryptionLevel) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPath().pending_ping;
    }

    fn pendingPingForLevelConst(self: *const Connection, lvl: EncryptionLevel) *const bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &self.primaryPathConst().pending_ping;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn pendingPingForLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
    ) *bool {
        if (connPnIdx(lvl)) |idx| return &self.pending_ping[idx];
        return &app_path.pending_ping;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn anyPendingPing(self: *const Connection) bool {
        for (self.pending_ping) |ping| {
            if (ping) return true;
        }
        for (self.paths.paths.items) |*p| {
            if (p.path.state == .failed) continue;
            if (p.pending_ping) return true;
        }
        return false;
    }

    fn clearPendingPings(self: *Connection) void {
        self.pending_ping = .{ false, false };
        for (self.paths.paths.items) |*p| {
            p.pending_ping = false;
            p.pto_probe_count = 0;
        }
    }

    // INTERNAL: pub for conn_keys.zig access; not part of the embedder API.
    pub fn clearSentTracker(self: *Connection, tracker: *SentPacketTracker) void {
        var i: u32 = 0;
        while (i < tracker.count) : (i += 1) {
            // Tombstones own nothing; deinit would double-free.
            if (tracker.packets[i].dead) continue;
            tracker.packets[i].deinit(self.allocator);
        }
        tracker.count = 0;
        tracker.dead_count = 0;
        tracker.bytes_in_flight = 0;
        tracker.ack_eliciting_in_flight = 0;
    }

    fn clearRecoveryState(self: *Connection) void {
        for (self.sent) |*tracker| self.clearSentTracker(tracker);
        for (self.paths.paths.items) |*path| {
            self.clearSentTracker(&path.sent);
            path.pending_ping = false;
            path.pto_probe_count = 0;
            path.pto_count = 0;
        }
        self.clearPendingPings();
    }

    pub fn resetInitialRecoveryForRetry(self: *Connection) Error!void {
        const idx = EncryptionLevel.initial.idx();
        try self.crypto_retx[idx].ensureUnusedCapacity(
            self.allocator,
            self.sent_crypto[idx].items.len,
        );
        for (self.sent_crypto[idx].items) |chunk| {
            self.crypto_retx[idx].appendAssumeCapacity(.{
                .offset = chunk.offset,
                .data = chunk.data,
            });
        }
        self.sent_crypto[idx].clearRetainingCapacity();
        self.clearSentTracker(&self.sent[0]);
        self.pto_count[0] = 0;
        self.pending_ping[0] = false;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn canSendEarlyData(self: *Connection) bool {
        if (self.role != .client) return false;
        if (!self.early_data_send_enabled) return false;
        if (self.inner.handshakeDone()) return false;
        if (self.inner.earlyDataStatus() == .rejected) return false;
        return self.haveSecret(.early_data, .write);
    }

    // INTERNAL: pub for conn_cids.zig access; not part of the embedder API.
    pub fn installPeerTransportStatelessResetToken(self: *Connection) Error!void {
        if (self.peer_transport_reset_token_installed) return;
        const params = self.cached_peer_transport_params orelse return;
        const token = params.stateless_reset_token orelse return;
        if (!self.peer_dcid_set or self.peer_dcid.len == 0) return;
        try self.registerPeerCid(0, 0, 0, self.peer_dcid, token);
        self.peer_transport_reset_token_installed = true;
    }

    pub fn validatePeerTransportConnectionIds(self: *Connection) void {
        const params = self.cached_peer_transport_params orelse return;
        if (params.original_destination_connection_id) |odcid| {
            if (self.original_initial_dcid_set and
                !ConnectionId.eql(odcid, self.original_initial_dcid))
            {
                self.close(true, transport_error_transport_parameter, "original destination cid mismatch");
                return;
            }
        }
        if (self.retry_accepted) {
            const retry_source = params.retry_source_connection_id orelse {
                self.close(true, transport_error_transport_parameter, "missing retry source cid");
                return;
            };
            if (!ConnectionId.eql(retry_source, self.retry_source_cid)) {
                self.close(true, transport_error_transport_parameter, "retry source cid mismatch");
                return;
            }
        } else if (params.retry_source_connection_id != null) {
            self.close(true, transport_error_transport_parameter, "unexpected retry source cid");
        }
    }

    // INTERNAL: pub for conn_recv_data_handlers.zig access; not part of the embedder API.
    pub fn refreshEarlyDataStatus(self: *Connection) Error!void {
        if (self.early_data_rejection_processed) return;
        if (self.inner.earlyDataStatus() != .rejected) return;
        try self.requeueRejectedEarlyData();
        self.early_data_rejection_processed = true;
    }

    /// RFC 9001 §4.6.2: the server rejected 0-RTT, so everything sent
    /// under early-data keys must be re-sent under 1-RTT keys.
    ///
    /// CONTRACT — load-bearing downstream, do not weaken silently:
    /// rejection requeues the SAME stream bytes and control frames
    /// VERBATIM for 1-RTT retransmission. No stream is reset, no data
    /// is dropped, and nothing is reordered beyond normal retransmit
    /// scheduling; the packets are explicitly NOT congestion losses.
    /// http3-zig builds its HTTP/3 early-data guarantees (RFC 9114
    /// §7.2.4.2 remembered-settings replay) directly on this verbatim
    /// behavior. If a reset-streams-on-rejection policy is ever
    /// wanted, add it as a second explicit mode beside this one —
    /// changing this default breaks a consumer contract.
    pub fn requeueRejectedEarlyData(self: *Connection) Error!void {
        for (self.paths.paths.items) |*path| {
            var i: u32 = 0;
            while (i < path.sent.count) {
                const packet = path.sent.packets[i];
                if (!packet.is_early_data) {
                    i += 1;
                    continue;
                }

                var removed = path.sent.removeAt(i);
                defer removed.deinit(self.allocator);
                self.recordDatagramLost(&removed);
                _ = try self.dispatchLostPacketToStreams(&removed);
                _ = try self.dispatchLostControlFramesOnPath(&removed, path.id);
                conn_loss.discardSentCryptoForPacket(self, .early_data, removed.pn);
            }
        }
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn nextStreamPacketKey(self: *Connection) u64 {
        const key = self.next_stream_packet_key;
        self.next_stream_packet_key +|= 1;
        return key;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn drainingDurationUs(self: *const Connection) u64 {
        return 3 * self.primaryPathConst().path.rtt.pto(self.peerMaxAckDelayUs());
    }

    // INTERNAL: pub for conn_migration.zig access; not part of the embedder API.
    pub fn saturatingMul(a: u64, b: u64) u64 {
        return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn u64ToUsizeClamped(value: u64) usize {
        const max_usize_as_u64: u64 = @intCast(std.math.maxInt(usize));
        if (value > max_usize_as_u64) return std.math.maxInt(usize);
        return @intCast(value);
    }

    fn basePtoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        return conn_loss.basePtoDurationForLevel(self, lvl);
    }

    pub fn ptoDurationForLevel(self: *const Connection, lvl: EncryptionLevel) u64 {
        return conn_loss.ptoDurationForLevel(self, lvl);
    }

    pub fn ptoDurationForApplicationPath(self: *const Connection, path: *const PathState) u64 {
        return conn_loss.ptoDurationForApplicationPath(self, path);
    }

    pub fn largestApplicationPtoDurationUs(self: *const Connection) u64 {
        return conn_loss.largestApplicationPtoDurationUs(self);
    }

    pub fn retiredPathRetentionUs(self: *const Connection) u64 {
        return conn_loss.retiredPathRetentionUs(self);
    }

    fn expireRetiringPaths(self: *Connection, now_us: u64) void {
        return conn_paths.expireRetiringPaths(self, now_us);
    }

    fn considerDeadline(best: *?TimerDeadline, candidate: TimerDeadline) void {
        return conn_loss.considerDeadline(best, candidate);
    }

    fn lossDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        return conn_loss.lossDeadlineForLevel(self, lvl);
    }

    fn lossDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        return conn_loss.lossDeadlineForApplicationPath(self, path);
    }

    fn ptoDeadlineForLevel(self: *const Connection, lvl: EncryptionLevel) ?u64 {
        return conn_loss.ptoDeadlineForLevel(self, lvl);
    }

    fn ptoDeadlineForApplicationPath(self: *const Connection, path: *const PathState) ?u64 {
        return conn_loss.ptoDeadlineForApplicationPath(self, path);
    }

    fn idleDeadline(self: *const Connection) ?u64 {
        return conn_loss.idleDeadline(self);
    }

    fn bytesInFlight(self: *const Connection) u64 {
        var total: u64 = 0;
        for (self.sent) |*tracker| total += tracker.bytes_in_flight;
        for (self.paths.paths.items) |*p| total += p.sent.bytes_in_flight;
        return total;
    }

    /// Current NewReno congestion window in bytes for the active
    /// application-data path. Diagnostic only; there is no setter.
    pub fn congestionWindow(self: *const Connection) u64 {
        return self.ccForApplicationConst().cwndBytes();
    }

    /// Total bytes currently in flight across all packet-number
    /// spaces and paths. Useful for back-pressure decisions.
    pub fn congestionBytesInFlight(self: *const Connection) u64 {
        return self.bytesInFlight();
    }

    /// Current PTO duration in microseconds for the primary
    /// application path, with the §6.2.1 exponential backoff already
    /// applied (i.e. `base_pto << pto_count`). Test-only diagnostic so
    /// conformance tests can pin the §6.2.1 doubling invariant; there
    /// is no production reason an embedder would need this.
    pub fn ptoMicros(self: *const Connection) u64 {
        return self.ptoDurationForApplicationPath(self.primaryPathConst());
    }

    /// Current PTO backoff count for the primary application path.
    /// Reset to 0 by an ACK that newly acknowledges an ack-eliciting
    /// packet (§6.2.1). Test-only diagnostic — same justification as
    /// `ptoMicros`.
    pub fn ptoCount(self: *const Connection) u32 {
        return self.primaryPathConst().pto_count;
    }

    pub fn congestionBlocked(self: *const Connection, lvl: EncryptionLevel) bool {
        if (lvl != .application and lvl != .early_data) return false;
        const path = self.primaryPathConst();
        if (path.pending_ping) return false;
        if (path.pto_probe_count > 0) return false;
        return path.path.cc.sendAllowance(path.sent.bytes_in_flight) == 0;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    pub fn congestionBlockedOnPath(
        self: *const Connection,
        lvl: EncryptionLevel,
        app_path: *const PathState,
    ) bool {
        _ = self;
        if (lvl != .application and lvl != .early_data) return false;
        if (app_path.pending_ping) return false;
        if (app_path.pto_probe_count > 0) return false;
        return app_path.path.cc.sendAllowance(app_path.sent.bytes_in_flight) == 0;
    }

    // INTERNAL: pub for conn_send.zig access; not part of the embedder API.
    // Pacing twin of `congestionBlockedOnPath`, sharing its exemption
    // structure exactly: non-application levels, PTO probes, and
    // pending PINGs are never paced (RFC 9002 §7.7 applies to normal
    // data emission; probes and handshake latency stay untouched).
    // Refills the path's bucket lazily as a side effect.
    pub fn pacingBlockedOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path: *PathState,
        now_us: u64,
        datagram_bytes: u64,
    ) bool {
        if (!self.pacing_enabled) return false;
        if (lvl != .application and lvl != .early_data) return false;
        if (app_path.pending_ping) return false;
        if (app_path.pto_probe_count > 0) return false;
        const cc = &app_path.path.cc;
        app_path.path.pacer.refill(
            now_us,
            cc.pacingRateBps(app_path.path.rtt.smoothed_rtt_us),
            cc.config().max_datagram_size,
        );
        return !app_path.path.pacer.canSend(datagram_bytes);
    }

    /// Soonest timer deadline among ack-delay, loss detection, PTO,
    /// idle, draining, path retirement, and key-discard. Embedders
    /// can park their event loop on this until `tick` should fire.
    /// Returns null when no timer is currently armed.
    pub fn nextTimerDeadline(self: *const Connection, now_us: u64) ?TimerDeadline {
        var best: ?TimerDeadline = null;

        if (self.lifecycle.draining_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .draining, .at_us = at_us });
            return best;
        }
        // RFC 9000 §10.2.1 closing-state expiry: even though `closed`
        // is already latched, surface the deadline so embedders can
        // park their event loop on it.
        if (self.lifecycle.closing_deadline_us) |at_us| {
            considerDeadline(&best, .{ .kind = .closing, .at_us = at_us });
            return best;
        }
        if (self.lifecycle.closed) return null;

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            // Twin of the `tick` gate: a discarded space contributes
            // no scheduling deadlines. Without this, `nextDeadline`
            // would surface a stale Handshake PTO timestamp from the
            // last unACKed Finished CRYPTO and an embedder polling
            // loop would wake repeatedly for a no-op `tick`.
            const space_active = switch (lvl) {
                .initial => !self.initial_keys_discarded,
                .handshake => !self.handshake_keys_discarded,
                else => false,
            };
            if (space_active) {
                const tracker = &self.pnSpaceForLevelConst(lvl).received;
                if (self.ackDelayDeadlineUs(tracker)) |at_us| {
                    considerDeadline(&best, .{
                        .kind = .ack_delay,
                        .at_us = at_us,
                        .level = lvl,
                    });
                }
                if (self.lossDeadlineForLevel(lvl)) |at_us| {
                    considerDeadline(&best, .{
                        .kind = .loss_detection,
                        .at_us = at_us,
                        .level = lvl,
                    });
                }
                if (self.ptoDeadlineForLevel(lvl)) |at_us| {
                    considerDeadline(&best, .{
                        .kind = .pto,
                        .at_us = at_us,
                        .level = lvl,
                    });
                }
            }
        }
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            if (path.path.state == .retiring) {
                if (path.retire_deadline_us) |at_us| {
                    considerDeadline(&best, .{
                        .kind = .path_retirement,
                        .at_us = at_us,
                        .level = .application,
                        .path_id = path.id,
                    });
                }
            }
            const tracker = &path.app_pn_space.received;
            if (self.ackDelayDeadlineUs(tracker)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .ack_delay,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.lossDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .loss_detection,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            if (self.ptoDeadlineForApplicationPath(path)) |at_us| {
                considerDeadline(&best, .{
                    .kind = .pto,
                    .at_us = at_us,
                    .level = .application,
                    .path_id = path.id,
                });
            }
            // RFC 9002 §7.7: surface "send credit at T" only when a
            // wake would actually unblock a send — the path must not
            // be cwnd-blocked (only an ACK arrival clears that, an fd
            // event, not a timer) and data must be pending. Checks
            // ordered cheap-first; `canSend` (a bounded field sweep)
            // runs last and only when the pacer is actually short.
            if (self.pacing_enabled and path.path.state != .retiring) {
                const cc = &path.path.cc;
                if (cc.sendAllowance(path.sent.bytes_in_flight) > 0) {
                    if (path.path.pacer.nextReadyUs(
                        now_us,
                        @min(@as(u64, @intCast(path.pmtu)), default_mtu),
                        cc.pacingRateBps(path.path.rtt.smoothed_rtt_us),
                        cc.config().max_datagram_size,
                    )) |at_us| {
                        if (self.canSend()) {
                            considerDeadline(&best, .{
                                .kind = .pacing,
                                .at_us = at_us,
                                .level = .application,
                                .path_id = path.id,
                            });
                        }
                    }
                }
            }
        }
        if (self.app_read_previous) |epoch| {
            if (epoch.discard_deadline_us) |at_us| {
                considerDeadline(&best, .{
                    .kind = .key_discard,
                    .at_us = at_us,
                    .level = .application,
                });
            }
        }

        if (self.idleDeadline()) |at_us| {
            considerDeadline(&best, .{ .kind = .idle, .at_us = at_us });
        }
        return best;
    }

    /// True if `poll` would produce an outgoing packet right now.
    pub fn canSend(self: *const Connection) bool {
        return conn_send.canSend(self);
    }

    /// One outgoing-datagram step. Walks Initial → Handshake →
    /// Application encryption levels in order, packing whatever is
    /// pending at each (CRYPTO, ACK, STREAM) into a coalesced
    /// short/long-header datagram per RFC 9000 §12.2. Returns the
    /// total bytes written, or null if nothing was ready.
    pub fn poll(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        return conn_send.poll(self, dst, now_us);
    }

    /// Path-aware outgoing-datagram step. Single-path callers can
    /// keep using `poll`; multipath-aware embedders can inspect the
    /// destination address and path id once `PathSet` lands.
    pub fn pollDatagram(
        self: *Connection,
        dst: []u8,
        now_us: u64,
    ) Error!?OutgoingDatagram {
        return conn_send.pollDatagram(self, dst, now_us);
    }

    /// Emit one packet at the given level, if there's anything to
    /// send and we have keys. Internal helper of `poll` — exposed
    /// for tests that want fine-grained control.
    pub fn pollLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        return conn_send.pollLevel(self, lvl, dst, now_us);
    }

    pub fn pollLevelOnPath(
        self: *Connection,
        lvl: EncryptionLevel,
        app_path_id: u32,
        dst: []u8,
        now_us: u64,
    ) Error!?usize {
        return conn_send.pollLevelOnPath(self, lvl, app_path_id, dst, now_us);
    }

    pub fn emitOnePendingMultipathFrame(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[max_recv_plaintext]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        return conn_send.emitOnePendingMultipathFrame(self, sent_packet, pl_buf, pl_pos, max_payload);
    }

    pub fn emitPendingMultipathFrames(
        self: *Connection,
        sent_packet: *sent_packets_mod.SentPacket,
        pl_buf: *[max_recv_plaintext]u8,
        pl_pos: *usize,
        max_payload: usize,
    ) Error!bool {
        return conn_send.emitPendingMultipathFrames(self, sent_packet, pl_buf, pl_pos, max_payload);
    }

    /// Process an incoming UDP datagram. Splits coalesced packets
    /// (RFC 9000 §12.2) and routes each through the matching
    /// per-level decrypt + frame-dispatch path.
    ///
    /// Lifecycle gates per RFC 9000 §10.2:
    ///   - draining / closed (§10.2.2 ¶1): silently drop.
    ///   - pre-emit closing  (`pending_close != null`): drop here;
    ///     the next `poll` will emit the queued CC.
    ///   - post-emit closing (§10.2.1): keep processing the datagram
    ///     so we can attribute it (and re-arm a CC retransmit per
    ///     §10.2.1 ¶3) and so a peer's CC moves us to draining.
    ///     `dispatchFrames` is suppressed for non-CONNECTION_CLOSE
    ///     frames in this state via `closingAttributionOnly`.
    pub fn handle(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        now_us: u64,
    ) Error!void {
        return conn_recv_dispatch.handle(self, bytes, from, now_us);
    }

    /// Same as `handle` but also accepts the IP-layer ECN codepoint
    /// the embedder peeled off the datagram's TOS byte (RFC 3168 §5).
    /// Plumbed through from `Server.feedWithEcn` /
    /// `runUdpServer`'s recvmsg cmsg parser; per-packet handlers read
    /// `last_recv_ecn` to bump the receiving PN-space's counters
    /// (RFC 9000 §13.4.1).
    pub fn handleWithEcn(
        self: *Connection,
        bytes: []u8,
        from: ?Address,
        ecn: socket_opts_mod.EcnCodepoint,
        now_us: u64,
    ) Error!void {
        return conn_recv_dispatch.handleWithEcn(self, bytes, from, ecn, now_us);
    }

    pub fn probePath(
        self: *Connection,
        token: [8]u8,
        now_us: u64,
        timeout_us: u64,
    ) Error!void {
        return conn_paths.probePath(self, token, now_us, timeout_us);
    }

    pub fn requestPing(self: *Connection) void {
        return conn_paths.requestPing(self);
    }

    pub fn requestPathPing(self: *Connection, path_id: u32) Error!void {
        return conn_paths.requestPathPing(self, path_id);
    }

    pub fn isPathValidated(self: *const Connection) bool {
        return conn_paths.isPathValidated(self);
    }

    /// Current public shutdown state.
    pub fn closeState(self: *const Connection) CloseState {
        return self.lifecycle.state();
    }

    /// The coarse `ConnectionPhase`. A non-open close state (closing /
    /// draining / closed) always wins; otherwise the handshake epoch is
    /// reported from the highest installed write keys: application →
    /// `.established`, handshake → `.handshake`, else `.initial`. Composes
    /// `closeState()` with `haveSecret()` so embedders (notably an HTTP/3
    /// layer) needn't infer the epoch themselves.
    pub fn phase(self: *const Connection) ConnectionPhase {
        switch (self.closeState()) {
            .closing => return .closing,
            .draining => return .draining,
            .closed => return .closed,
            .open => {},
        }
        if (self.haveSecret(.application, .write)) return .established;
        if (self.haveSecret(.handshake, .write)) return .handshake;
        return .initial;
    }

    /// Begin a graceful shutdown: refuse new local stream opens with
    /// `Error.ShuttingDown` and stop granting MAX_STREAMS credit so the peer
    /// quiesces new-stream creation, while in-flight streams keep draining.
    /// The connection stays open (no CONNECTION_CLOSE) until the embedder
    /// calls `close` — typically once the remaining streams complete or a
    /// shutdown deadline elapses. Idempotent. RFC 9000 defines no GOAWAY
    /// frame, so this is a local policy paired with withheld credit rather
    /// than a wire signal; a layer like HTTP/3 sends its own GOAWAY on top.
    pub fn beginGracefulShutdown(self: *Connection) void {
        self.graceful_shutdown = true;
    }

    /// True after `beginGracefulShutdown` has been called (until close).
    pub fn gracefulShutdownActive(self: *const Connection) bool {
        return self.graceful_shutdown;
    }

    /// True after we've sent or received CONNECTION_CLOSE, received a
    /// stateless reset, or timed out. Use `closeState` to distinguish
    /// closing, draining, and terminal closed states.
    pub fn isClosed(self: *const Connection) bool {
        return self.lifecycle.closed;
    }

    const closeErrorSpace = lifecycle_mod.closeErrorSpace;

    // INTERNAL: pub for conn_recv_dispatch.zig access; not part of the embedder API.
    pub fn enterDraining(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        const draining_deadline = now_us +| self.drainingDurationUs();
        self.lifecycle.enterDraining(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
            draining_deadline,
        );
        self.clearPendingPings();
        self.emitConnectionStateIfChanged();
    }

    fn finishDraining(self: *Connection) void {
        self.lifecycle.finishDraining();
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    pub fn enterClosed(
        self: *Connection,
        source: CloseSource,
        error_space: CloseErrorSpace,
        error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_us: u64,
    ) void {
        self.lifecycle.enterClosed(
            source,
            error_space,
            error_code,
            frame_type,
            reason,
            now_us,
        );
        self.clearRecoveryState();
        self.emitConnectionStateIfChanged();
    }

    pub fn enterStatelessReset(self: *Connection, now_us: u64) void {
        self.enterDraining(
            .stateless_reset,
            .transport,
            0,
            0,
            "stateless reset",
            now_us,
        );
    }

    /// Sticky close/error status for embedders. This remains available
    /// after `pollEvent` consumes the event notification.
    pub fn closeEvent(self: *const Connection) ?CloseEvent {
        return self.lifecycle.event();
    }

    /// Poll the next connection-level event.
    pub fn pollEvent(self: *Connection) ?ConnectionEvent {
        if (self.lifecycle.close_event) |*event| {
            if (!event.delivered) {
                const out = self.lifecycle.eventFromStored(event.*);
                event.delivered = true;
                return .{ .close = out };
            }
        }
        if (!self.handshake_established_surfaced and self.inner.handshakeDone()) {
            self.handshake_established_surfaced = true;
            return .handshake_established;
        }
        // 0-RTT outcome, one-shot. Gated so connections that never
        // participate in early data pay no per-poll TLS query: clients
        // after opting in via setEarlyDataEnabled (or after a
        // processed rejection — the rejection handler deliberately
        // clears the opt-in flag), servers always (they cannot know a
        // 0-RTT attempt is coming). A `.not_offered` read after
        // handshake completion is terminal and latches the watch off
        // without emitting.
        if (!self.early_data_surfaced and
            (self.early_data_send_enabled or
                self.early_data_rejection_processed or
                self.role == .server))
        {
            if (self.early_data_rejection_processed) {
                // quic's own latch is authoritative for rejection: it
                // is set in the same breath as the verbatim requeue
                // (the variant's ordering promise), and the TLS-side
                // reason is wiped when resetEarlyDataReject restarts
                // the handshake, so the inner status cannot be
                // consulted for this case.
                self.early_data_surfaced = true;
                return .{ .early_data = .rejected };
            }
            switch (self.inner.earlyDataStatus()) {
                .accepted => {
                    self.early_data_surfaced = true;
                    return .{ .early_data = .accepted };
                },
                // A raw `.rejected` read before the latch means the
                // requeue has not run yet — hold the event for it.
                .rejected => {},
                .not_offered => if (self.inner.handshakeDone()) {
                    self.early_data_surfaced = true;
                },
            }
        }
        if (self.surfaced_peer_streams_bidi < self.peer_opened_streams_bidi) {
            const stream_type: StreamType = if (self.role == .client) .server_bidi else .client_bidi;
            const id = stream_type.streamId(self.surfaced_peer_streams_bidi);
            self.surfaced_peer_streams_bidi += 1;
            return .{ .stream_opened = .{ .stream_id = id, .bidi = true } };
        }
        if (self.surfaced_peer_streams_uni < self.peer_opened_streams_uni) {
            const stream_type: StreamType = if (self.role == .client) .server_uni else .client_uni;
            const id = stream_type.streamId(self.surfaced_peer_streams_uni);
            self.surfaced_peer_streams_uni += 1;
            return .{ .stream_opened = .{ .stream_id = id, .bidi = false } };
        }
        if (self.flow_blocked_events.pop()) |out| {
            return .{ .flow_blocked = out };
        }
        if (self.connection_id_events.pop()) |out| {
            return .{ .connection_ids_needed = out };
        }
        if (self.datagram_send_events.pop()) |out| {
            return switch (out) {
                .acked => |event| .{ .datagram_acked = event },
                .lost => |event| .{ .datagram_lost = event },
            };
        }
        if (self.alternative_server_address_events.pop()) |out| {
            return .{ .alternative_server_address = out };
        }
        return null;
    }

    /// Queue a CONNECTION_CLOSE frame (RFC 9000 §19.19) for the
    /// next outgoing packet. `is_transport` selects between
    /// transport (0x1c) and application (0x1d) error spaces.
    pub fn close(
        self: *Connection,
        is_transport: bool,
        error_code: u64,
        reason: []const u8,
    ) void {
        if (self.lifecycle.pending_close != null or self.lifecycle.closed) return;
        self.lifecycle.record(
            .local,
            closeErrorSpace(is_transport),
            error_code,
            0,
            reason,
            null,
            null,
        );
        self.lifecycle.pending_close = .{
            .is_transport = is_transport,
            .error_code = error_code,
            .reason = reason,
        };
        self.emitConnectionStateIfChanged();
    }

    /// Try to reserve `n` bytes of resident-memory budget. Returns
    /// `error.ExcessiveLoad` when the reservation would push
    /// `bytes_resident` past `max_connection_memory` — callers should
    /// then `close(true, transport_error_excessive_load, "...")` and
    /// abandon the in-flight allocation rather than allow it to land.
    /// The reason string is the wire reason: keep it generic
    /// (`"excessive resource use"`) — secure-by-default redaction
    /// to avoid leaking which buffer tripped the cap.
    ///
    /// Pair every successful `tryReserveResidentBytes(n)` with a
    /// `releaseResidentBytes(n)` when the underlying bytes are freed.
    /// The helper has no awareness of which buffer the bytes live in —
    /// the call sites (handleCrypto / handleDatagram / handleStream /
    /// streamRead / dispatchAckedToStreams) own the pairing.
    pub fn tryReserveResidentBytes(self: *Connection, n: usize) Error!void {
        if (n == 0) return;
        const add: u64 = @intCast(n);
        const cap = self.max_connection_memory;
        // Saturating-add semantics: an attacker can't underflow the
        // budget by exceeding u64::MAX, but the cap check below still
        // fires once the running total overshoots `cap`.
        if (self.bytes_resident > cap or add > cap - self.bytes_resident) {
            return Error.ExcessiveLoad;
        }
        self.bytes_resident += add;
    }

    /// Release `n` bytes of resident-memory budget. Pairs with
    /// `tryReserveResidentBytes`. Underflow is clamped at zero in
    /// release builds (an unbalanced free is a bug, not a security
    /// issue — the cap stays honored), and asserts in debug.
    pub fn releaseResidentBytes(self: *Connection, n: usize) void {
        if (n == 0) return;
        const sub: u64 = @intCast(n);
        std.debug.assert(self.bytes_resident >= sub);
        self.bytes_resident -|= sub;
    }

    /// Queue a STOP_SENDING for `stream_id` with the given app
    /// error code (RFC 9000 §19.5). Tells the peer to stop
    /// sending on the receiving half of the stream.
    pub fn streamStopSending(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        return conn_streams.streamStopSending(self, stream_id, application_error_code);
    }

    fn queueStopSending(
        self: *Connection,
        item: StopSendingItem,
    ) Error!void {
        return conn_streams.queueStopSending(self, item);
    }

    pub fn peerCidsCount(self: *const Connection) usize {
        return conn_cids.peerCidsCount(self);
    }

    pub fn peerDcid(self: *const Connection) ConnectionId {
        return conn_cids.peerDcid(self);
    }

    pub fn registerPeerCidForTesting(
        self: *Connection,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        return conn_cids.registerPeerCidForTesting(self, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn handleOnePacket(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        return conn_recv_dispatch.handleOnePacket(self, bytes, now_us);
    }

    pub fn packetPayloadAckEliciting(payload: []const u8) bool {
        return conn_recv_dispatch.packetPayloadAckEliciting(payload);
    }

    pub fn packetPayloadNeedsImmediateAck(payload: []const u8) bool {
        return conn_recv_dispatch.packetPayloadNeedsImmediateAck(payload);
    }

    pub fn handleShort(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        return conn_recv_packet_handlers.handleShort(self, bytes, now_us);
    }

    pub fn handleInitial(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        return conn_recv_packet_handlers.handleInitial(self, bytes, now_us);
    }

    pub fn handleRetry(
        self: *Connection,
        bytes: []u8,
        now_us: u64,
    ) Error!usize {
        return conn_recv_packet_handlers.handleRetry(self, bytes, now_us);
    }

    pub fn dispatchFrames(
        self: *Connection,
        lvl: EncryptionLevel,
        payload: []const u8,
        now_us: u64,
    ) Error!void {
        return conn_recv_dispatch.dispatchFrames(self, lvl, payload, now_us);
    }

    pub fn tokenEql(a: [16]u8, b: [16]u8) bool {
        return conn_recv_dispatch.tokenEql(a, b);
    }

    pub fn isKnownStatelessReset(self: *const Connection, bytes: []const u8) bool {
        return conn_recv_dispatch.isKnownStatelessReset(self, bytes);
    }

    pub fn peerCidActiveCountForPath(self: *const Connection, path_id: u32) usize {
        return conn_cids.peerCidActiveCountForPath(self, path_id);
    }

    pub fn registerPeerCid(
        self: *Connection,
        path_id: u32,
        sequence_number: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        stateless_reset_token: [16]u8,
    ) Error!void {
        return conn_cids.registerPeerCid(self, path_id, sequence_number, retire_prior_to, cid, stateless_reset_token);
    }

    pub fn handleNewConnectionId(
        self: *Connection,
        nc: frame_types.NewConnectionId,
    ) Error!void {
        return conn_recv_cid_token_handlers.handleNewConnectionId(self, nc);
    }

    /// Returns true (and increments the per-cycle counter) when the
    /// cumulative ACK range count for this `handle` cycle would exceed
    /// `incoming_ack_range_cap`. Skipping rather than closing is RFC
    /// 9000 §19.3-aligned: ACK is not ack-eliciting, dropping it
    /// re-issues no liveness obligation, and the peer's loss-recovery
    /// will retransmit anything we miss.
    pub fn exceedsIncomingAckRangeCap(self: *Connection, range_count: u64) bool {
        const next = self.incoming_ack_range_count +| range_count +| 1;
        if (next > incoming_ack_range_cap) return true;
        self.incoming_ack_range_count = next;
        return false;
    }

    pub fn handleRetireConnectionId(
        self: *Connection,
        rc: frame_types.RetireConnectionId,
    ) void {
        return conn_recv_cid_token_handlers.handleRetireConnectionId(self, rc);
    }

    /// RFC 9000 §19.7 — server-issued NEW_TOKEN. The frame is only
    /// legal at application encryption level (filtered upstream by
    /// the level-allowed-frames check). Servers MUST NOT receive
    /// NEW_TOKEN; if a peer-acting-as-server sends it to us we
    /// raise PROTOCOL_VIOLATION. Clients hand the borrowed slice
    /// straight to the embedder callback if one is installed.
    pub fn handleNewToken(self: *Connection, nt: frame_types.NewToken) void {
        return conn_recv_cid_token_handlers.handleNewToken(self, nt);
    }

    pub fn handlePathAck(
        self: *Connection,
        pa: frame_types.PathAck,
        now_us: u64,
    ) Error!void {
        return conn_recv_multipath_handlers.handlePathAck(self, pa, now_us);
    }

    pub fn handlePathNewConnectionId(
        self: *Connection,
        nc: frame_types.PathNewConnectionId,
    ) Error!void {
        return conn_recv_multipath_handlers.handlePathNewConnectionId(self, nc);
    }

    pub fn handlePathRetireConnectionId(
        self: *Connection,
        rc: frame_types.PathRetireConnectionId,
    ) void {
        return conn_recv_multipath_handlers.handlePathRetireConnectionId(self, rc);
    }

    pub fn handleMaxPathId(self: *Connection, mp: frame_types.MaxPathId) void {
        return conn_recv_multipath_handlers.handleMaxPathId(self, mp);
    }

    pub fn handlePathsBlocked(self: *Connection, pb: frame_types.PathsBlocked) void {
        return conn_recv_multipath_handlers.handlePathsBlocked(self, pb);
    }

    pub fn handlePathCidsBlocked(self: *Connection, pcb: frame_types.PathCidsBlocked) void {
        return conn_recv_multipath_handlers.handlePathCidsBlocked(self, pcb);
    }

    pub fn handleAlternativeAddressV4(
        self: *Connection,
        a: frame_types.AlternativeV4Address,
    ) void {
        return conn_migration.handleAlternativeAddressV4(self, a);
    }

    pub fn handleAlternativeAddressV6(
        self: *Connection,
        a: frame_types.AlternativeV6Address,
    ) void {
        return conn_migration.handleAlternativeAddressV6(self, a);
    }

    pub fn highestAlternativeAddressSequenceSeen(self: *const Connection) ?u64 {
        return conn_migration.highestAlternativeAddressSequenceSeen(self);
    }

    pub fn handleMaxData(self: *Connection, md: frame_types.MaxData) void {
        return conn_recv_flow_handlers.handleMaxData(self, md);
    }

    pub fn handleMaxStreamData(self: *Connection, msd: frame_types.MaxStreamData) void {
        return conn_recv_flow_handlers.handleMaxStreamData(self, msd);
    }

    pub fn handleMaxStreams(self: *Connection, ms: frame_types.MaxStreams) void {
        return conn_recv_flow_handlers.handleMaxStreams(self, ms);
    }

    pub fn handleDataBlocked(self: *Connection, db: frame_types.DataBlocked) void {
        return conn_recv_flow_handlers.handleDataBlocked(self, db);
    }

    pub fn handleStreamDataBlocked(self: *Connection, sdb: frame_types.StreamDataBlocked) Error!void {
        return conn_recv_flow_handlers.handleStreamDataBlocked(self, sdb);
    }

    pub fn handleStreamsBlocked(self: *Connection, sb: frame_types.StreamsBlocked) void {
        return conn_recv_flow_handlers.handleStreamsBlocked(self, sb);
    }

    pub fn handleDatagram(
        self: *Connection,
        lvl: EncryptionLevel,
        dg: frame_types.Datagram,
    ) Error!void {
        return conn_recv_data_handlers.handleDatagram(self, lvl, dg);
    }

    pub fn handleCrypto(
        self: *Connection,
        lvl: EncryptionLevel,
        cr: frame_types.Crypto,
    ) Error!void {
        return conn_recv_data_handlers.handleCrypto(self, lvl, cr);
    }

    fn cryptoInboxQueued(self: *const Connection) bool {
        return conn_recv_data_handlers.cryptoInboxQueued(self);
    }

    fn drainInboxIntoTls(self: *Connection) Error!void {
        return conn_recv_data_handlers.drainInboxIntoTls(self);
    }

    pub fn handleStream(
        self: *Connection,
        lvl: EncryptionLevel,
        s: frame_types.Stream,
    ) Error!void {
        return conn_recv_data_handlers.handleStream(self, lvl, s);
    }

    pub fn handleResetStream(self: *Connection, rs: frame_types.ResetStream) Error!void {
        return conn_recv_stream_control_handlers.handleResetStream(self, rs);
    }

    pub fn handleAckAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        a: frame_types.Ack,
        now_us: u64,
    ) Error!void {
        return conn_recv_ack_handlers.handleAckAtLevel(self, lvl, a, now_us);
    }

    fn dispatchLostPacketToStreams(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        return conn_loss.dispatchLostPacketToStreams(self, packet);
    }

    pub fn dispatchLostControlFrames(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        return conn_recv_ack_handlers.dispatchLostControlFrames(self, packet);
    }

    pub fn dispatchLostControlFramesOnPath(
        self: *Connection,
        packet: *const sent_packets_mod.SentPacket,
        path_id: u32,
    ) Error!bool {
        return conn_loss.dispatchLostControlFramesOnPath(self, packet, path_id);
    }

    pub fn requeueLostPacket(
        self: *Connection,
        lvl: EncryptionLevel,
        packet: *const sent_packets_mod.SentPacket,
    ) Error!bool {
        return conn_loss.requeueLostPacket(self, lvl, packet);
    }

    pub fn isPersistentCongestionFromBasePto(base_pto_us: u64, loss_stats: LossStats) bool {
        return conn_loss.isPersistentCongestionFromBasePto(base_pto_us, loss_stats);
    }

    pub fn detectLossesByPacketThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
    ) Error!void {
        return conn_loss.detectLossesByPacketThresholdOnApplicationPath(self, path);
    }

    fn detectLossesByTimeThresholdAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        return conn_loss.detectLossesByTimeThresholdAtLevel(self, lvl, now_us);
    }

    fn detectLossesByTimeThresholdOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        return conn_loss.detectLossesByTimeThresholdOnApplicationPath(self, path, now_us);
    }

    fn fireDuePtoAtLevel(
        self: *Connection,
        lvl: EncryptionLevel,
        now_us: u64,
    ) Error!void {
        return conn_loss.fireDuePtoAtLevel(self, lvl, now_us);
    }

    fn fireDuePtoOnApplicationPath(
        self: *Connection,
        path: *PathState,
        now_us: u64,
    ) Error!void {
        return conn_loss.fireDuePtoOnApplicationPath(self, path, now_us);
    }

    /// Periodic tick — drives time-based loss detection, PTO,
    /// idle timeout, and draining deadlines. The caller passes the
    /// current monotonic time in microseconds. Safe to call any time.
    pub fn tick(self: *Connection, now_us: u64) Error!void {
        for (self.paths.paths.items) |*p| {
            p.path.validator.tick(now_us);
            if (p.path.validator.status == .failed) {
                self.handlePathValidationFailure(p);
            }
        }
        self.expireRetiringPaths(now_us);
        self.discardExpiredApplicationReadKeys(now_us);

        if (self.lifecycle.draining_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.finishDraining();
            }
            return;
        }
        // RFC 9000 §10.2.1 closing-state expiry. The deadline fires at
        // `first_close_emit + 3 * PTO`. If the peer's CC never came
        // back (otherwise we'd already be in draining), fall straight
        // to terminal closed — §10.2 ¶7: "Once its closing or
        // draining state ends, an endpoint SHOULD discard all
        // connection state."
        if (self.lifecycle.closing_deadline_us) |deadline| {
            if (now_us >= deadline) {
                self.finishDraining();
            }
            return;
        }

        if (self.lifecycle.closed) return;

        if (!self.lifecycle.closed) {
            if (self.idleDeadline()) |deadline| {
                if (now_us >= deadline) {
                    self.enterDraining(
                        .idle_timeout,
                        .transport,
                        0,
                        0,
                        "idle timeout",
                        now_us,
                    );
                    return;
                }
            }
        }

        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |lvl| {
            // RFC 9001 §4.9.2: a discarded packet number space MUST
            // NOT continue to drive timers. The Initial latch lives
            // in `initial_keys_discarded`; the Handshake latch in
            // `handshake_keys_discarded`. Both are one-way, so the
            // gates below stay consistent with the corresponding
            // `levels[…]` and `sent[…]` shutdown.
            const space_active = switch (lvl) {
                .initial => !self.initial_keys_discarded,
                .handshake => !self.handshake_keys_discarded,
                else => false,
            };
            if (space_active) {
                self.promoteDueAckDelay(&self.pnSpaceForLevel(lvl).received, now_us);
            }
        }
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            self.promoteDueAckDelay(&path.app_pn_space.received, now_us);
        }

        if (!self.initial_keys_discarded) try self.detectLossesByTimeThresholdAtLevel(.initial, now_us);
        if (!self.handshake_keys_discarded) try self.detectLossesByTimeThresholdAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            try self.detectLossesByTimeThresholdOnApplicationPath(path, now_us);
        }

        if (!self.initial_keys_discarded) try self.fireDuePtoAtLevel(.initial, now_us);
        if (!self.handshake_keys_discarded) try self.fireDuePtoAtLevel(.handshake, now_us);
        for (self.paths.paths.items) |*path| {
            if (path.path.state == .failed) continue;
            try self.fireDuePtoOnApplicationPath(path, now_us);
        }

        // Reclaim fully-terminated streams. Done at the tail of `tick`
        // rather than inside `handle` / `pollDatagram` because those
        // are reentered with stream pointers held — the GC removes
        // entries from `self.streams`, which would invalidate any
        // outstanding `*Stream` borrowed from `streams.get`. `tick`
        // holds no such borrows.
        self.gcClosedStreams();
    }

    /// One handshake driver step:
    /// 1. For each encryption level (low → high), if there are
    ///    queued bytes from the peer, feed them in via
    ///    `provideQuicData` and advance the handshake. (Per-level
    ///    feeding is required because keys for level N+1 are
    ///    derived during processing of level N.)
    /// 2. After all queued levels are drained, make one more
    ///    handshake call in case there's outgoing-only progress
    ///    (e.g. the very first client step that emits ClientHello).
    /// 3. If the handshake is done and `application`-level bytes
    ///    are pending (post-handshake messages such as
    ///    NewSessionTicket), call `processQuicPostHandshake`.
    pub fn advance(self: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const idx = lvl.idx();
            if (self.inbox[idx].len > 0) {
                const bytes = self.inbox[idx].drain();
                try self.inner.provideQuicData(lvl.toBoringssl(), bytes);
                if (self.inner.handshakeDone()) {
                    try self.cachePeerTransportParams();
                    try self.inner.processQuicPostHandshake();
                } else {
                    try self.advanceHandshake();
                }
            }
        }
        if (!self.inner.handshakeDone()) try self.advanceHandshake();
        if (self.inner.handshakeDone()) try self.cachePeerTransportParams();
        self.queueHandshakeDoneIfReady();
        try self.refreshEarlyDataStatus();
        // In-process test shim: shuttle outbox→peer.inbox so mock-
        // transport handshake tests can run without a UDP socket.
        // Active only when `peer` is set (production paths leave it
        // null and go through the datagram-driven transport).
        if (self.peer) |peer| try self.shuttleOutboxToPeer(peer);
        if (self.alert) |_| return error.PeerAlerted;
    }

    fn shuttleOutboxToPeer(self: *Connection, peer: *Connection) Error!void {
        inline for (level_mod.all) |lvl| {
            const i = lvl.idx();
            if (self.outbox[i].len > 0) {
                const bytes = self.outbox[i].drain();
                try peer.inbox[i].append(bytes);
                self.crypto_send_offset[i] += bytes.len;
            }
        }
    }

    // INTERNAL: pub for conn_recv_data_handlers.zig access; not part of the embedder API.
    pub fn advanceHandshake(self: *Connection) Error!void {
        self.inner.handshake() catch |e| switch (e) {
            error.WantRead, error.WantWrite => {},
            // RFC 9001 §4.6.2: the server declined our 0-RTT — a routine
            // protocol event (ticket expiry, server restart, changed
            // config), not a connection failure. Recover in-library so
            // no embedder ever needs the Internal-tier reset call:
            // reset BoringSSL's handshake state so it proceeds as a
            // full 1-RTT handshake, stop scheduling early-data packets,
            // and requeue every staged 0-RTT packet's frames for
            // retransmission once application keys exist. The embedder
            // observes the outcome via `earlyDataStatus()` /
            // `earlyDataReason()`; data written before `advance` still
            // arrives, just one round trip later.
            error.EarlyDataRejected => {
                self.inner.resetEarlyDataReject();
                self.early_data_send_enabled = false;
                if (!self.early_data_rejection_processed) {
                    try self.requeueRejectedEarlyData();
                    self.early_data_rejection_processed = true;
                }
                // Drive the reset handshake forward so this call still
                // makes progress; a second rejection would violate the
                // BoringSSL contract, so a repeat propagates.
                self.inner.handshake() catch |e2| switch (e2) {
                    error.WantRead, error.WantWrite => {},
                    else => return e2,
                };
            },
            else => return e,
        };
    }
};

// -- tls.quic.Method bridge ---------------------------------------------
//
// Each callback recovers the *Connection from the SSL via ex-data,
// then writes into quic state. The trampolines stay in this module
// because they reach into Connection's private fields directly.

fn setReadSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .read);
}

fn setWriteSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
) callconv(.c) c_int {
    return setSecret(ssl, level, cipher, secret, secret_len, .write);
}

fn setSecret(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    cipher: ?*const c.SSL_CIPHER,
    secret: [*c]const u8,
    secret_len: usize,
    dir: Direction,
) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    if (secret_len > 64) return 0;
    const cipher_id: u16 = blk: {
        if (cipher) |cph| {
            break :blk c.zbssl_SSL_CIPHER_get_protocol_id(cph);
        } else {
            break :blk 0;
        }
    };

    var material: SecretMaterial = .{ .cipher_protocol_id = cipher_id };
    @memcpy(material.secret[0..secret_len], secret[0..secret_len]);
    material.secret_len = @intCast(secret_len);

    const lvl = EncryptionLevel.fromBoringssl(@fromBackingInt(@intCast(level)));
    if (lvl == .application) {
        conn.installApplicationSecret(dir, material) catch return 0;
    } else switch (dir) {
        .read => conn.levels[lvl.idx()].read = material,
        .write => conn.levels[lvl.idx()].write = material,
    }
    if (lvl != .application) {
        conn_qlog.emitQlog(conn, .{ .name = .key_updated, .level = lvl });
    }
    return 1;
}

fn addHandshakeData(
    ssl: ?*c.SSL,
    level: c.ssl_encryption_level_t,
    data: [*c]const u8,
    len: usize,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    const lvl = EncryptionLevel.fromBoringssl(@fromBackingInt(@intCast(level)));
    // Buffer outgoing CRYPTO bytes per level. `poll` packs them into
    // CRYPTO frames inside Initial/Handshake/1-RTT packets — that's
    // the wire-level handshake path. The in-process mock-transport
    // shim additionally has `advance` shuttle outbox→peer.inbox when
    // `peer` is set.
    conn.outbox[lvl.idx()].append(data[0..len]) catch return 0;
    return 1;
}

fn flushFlight(_: ?*c.SSL) callconv(.c) c_int {
    return 1;
}

fn sendAlert(
    ssl: ?*c.SSL,
    _: c.ssl_encryption_level_t,
    alert: u8,
) callconv(.c) c_int {
    const conn = connFromSsl(ssl) orelse return 0;
    conn.alert = alert;
    // RFC 9001 §4.8: "A TLS alert is turned into a QUIC connection
    // error by converting the one-byte alert description into a QUIC
    // error code. The alert description is added to 0x0100 to produce
    // a QUIC error code from the range reserved for CRYPTO_ERROR."
    //
    // Examples: no_application_protocol (0x78) → 0x178,
    // bad_certificate (0x2a) → 0x12a, unknown_ca (0x30) → 0x130.
    //
    // Idempotent: if the connection has already started closing
    // (e.g. from another simultaneous error path), `close` no-ops.
    const quic_error_code: u64 = transport_error_crypto_base + @as(u64, alert);
    conn.close(true, quic_error_code, "tls alert");
    return 1;
}

fn connFromSsl(ssl: ?*c.SSL) ?*Connection {
    const ssl_ptr = ssl orelse return null;
    const raw_ptr = boringssl.tls.Conn.userDataFromSsl(ssl_ptr) orelse return null;
    return @ptrCast(@alignCast(raw_ptr));
}

const method: boringssl.tls.quic.Method = .{
    .set_read_secret = setReadSecret,
    .set_write_secret = setWriteSecret,
    .add_handshake_data = addHandshakeData,
    .flush_flight = flushFlight,
    .send_alert = sendAlert,
};

// -- tests ---------------------------------------------------------------
//
// All inline tests for state.zig live in src/conn/_state_tests.zig.
// The leading underscore signals "internal to conn/". Including the
// import here ensures the compiler walks the file for `test` blocks
// when this module is compiled in test mode.
comptime {
    _ = @import("_state_tests.zig");
}
