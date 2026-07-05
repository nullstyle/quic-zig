# Changelog

All notable changes to quic-zig are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [Unreleased]

### Fixed

- Replayed STREAM / RESET_STREAM frames for an out-of-order reaped peer
  stream (one above the contiguous reaped watermark, when a lower peer
  stream is still live) no longer resurrect the stream. `peerStreamAlreadyReaped`
  now consults the per-index reaped bitset in addition to the watermark, so
  such post-terminal frames are ignored per RFC 9000 §3.2.

## [0.6.0] - 2026-07-04

RFC 9218 (Extensible Priorities) stream-priority scheduling. See
`docs/stream-priority.md`. Additive — no breaking upgrade actions.

### Added

- `quic_zig.StreamPriority` (`urgency` 0–7, default 3; `incremental`) and
  `Connection.streamSetPriority(id, p)` / `streamPriority(id)`. The
  application-data send scheduler emits ready streams by RFC 9218 §10
  priority: **urgency** first, then within a band **non-incremental** streams
  lead in stream-id order (head-of-line) and **incremental** streams are
  round-robined so no one monopolizes the band. A higher-urgency stream's
  bytes therefore lead each packet. With no explicit priorities every stream
  is non-incremental urgency 3, so the order is deterministic stream-id
  ascending — a no-op in observable behavior for non-prioritizing embedders.
  Cross-path priority interactions with multipath remain out of scope (see
  `docs/stream-priority.md`).

## [0.5.0] - 2026-07-04

Additive, reap-robust public accessors and re-exports so an HTTP/3-class
embedder can observe the
transport's FIN / stream-id / datagram-size / send-stats / event-payload
truth without reaching into internal modules or reimplementing bookkeeping
the transport already owns. All changes are additive — no breaking upgrade
actions.

### Added

- Top-level re-exports for the types carried through `ConnectionEvent`
  (`DatagramSendEvent`, `FlowBlockedInfo` / `FlowBlockedKind` /
  `FlowBlockedSource`, `ConnectionIdReplenishInfo`) plus `path.Address`
  (the peer-address type used by `handle` / `pollDatagram`), so an embedder
  can name the payloads it destructures out of `ConnectionEvent` without
  reaching into `conn.*` / `conn.state.*` / `conn.path.*`.
- `Connection.peekNextBidi` / `peekNextUni`: return the id `openNextBidi` /
  `openNextUni` would use next, without consuming it or advancing the
  counter — so an embedder can run a stream-limit / GOAWAY gate keyed on
  the id *before* opening, then open.
- `Connection.streamSendStats(id)` → `StreamSendStats { written, acked,
  buffered, has_pending }`: a send-half backpressure snapshot that doesn't
  reach through `stream(id).?.send` into `SendStream`. Returns `null` for a
  stream not in the live table (never opened or already reaped).
- `Connection.streamReadFin(id, dst)` → `StreamReadResult { n, fin }`: like
  `streamRead` but reports the peer's FIN inline with the read that drains
  it, so an embedder detects end-of-stream without inspecting the receive
  half (which the stream GC reaps the moment it goes terminal).
  `streamRead` keeps its `Error!usize` signature.
- `Connection.streamRecvState(id)` → `?StreamRecvState { fin_seen,
  reset_seen, terminal }`: a non-consuming recv-half query that
  distinguishes a clean FIN from an abortive RESET (which
  `recvFullyTerminated` collapses) and returns `null` for a reaped/unknown
  stream — no `*Stream` to keep valid across a reap.
- `Connection.maxDatagramPayload()`: the current maximum RFC 9221 DATAGRAM
  payload, now public and PMTU-aware. It tracks the active path's validated
  PMTU (grows on a validated larger path, shrinks after a black-hole)
  rather than the static 1200-byte floor, still bounded by the peer's
  `max_datagram_frame_size`. Behavior at the 1200-byte floor is unchanged,
  and RFC 9221 §5 no-fragmentation is preserved by the existing send-time
  build guard.

### Changed

- The QUIC interop endpoint now accepts the `ecn` testcase — it was missing
  from `run_endpoint.sh`'s allow-list (so the runner's `ecn` cell hit the
  catch-all `exit 127`) despite the endpoint always marking ECT(0) on
  egress and parsing the TOS cmsg on ingress. The QNS Docker image and the
  external-interop tool now pin Zig `0.17.0-dev.1158` to match
  `build.zig.zon` instead of the stale `dev.269`.

## [0.4.0] - 2026-07-04

Downstream-enablement release: transport-layer primitives an HTTP/3-class
layer needs on day one, so it binds against a stable, ergonomic surface
instead of reimplementing stream-id math and shutdown logic, plus 1.0
API-stability documentation and toolchain fixes.

All changes are additive — no breaking upgrade actions are required. One
note: `Connection.Error` gains a `ShuttingDown` variant; per the new
stability contract (see `docs/API_STABILITY.md`), handle the error set with
an `else` branch so added variants don't break an exhaustive switch.

### Added

- `quic_zig.StreamType` (`client_bidi` / `server_bidi` / `client_uni` /
  `server_uni`) with `fromId`, `streamId(index)`, and
  `isBidi`/`isUni`/`initiatedBy*` helpers, plus role-aware
  `Connection.openNextBidi` / `openNextUni` (and `localStreamType`) that
  choose the next local-initiated id automatically — so an embedder needn't
  hand-roll the RFC 9000 §2.1 low-two-bit encoding for the HTTP/3 control
  stream (3) and QPACK streams (4, 5). On `StreamLimitExceeded` the id is
  not consumed, so a retry after the peer raises the limit reuses it.
- `Connection.phase()` returning `quic_zig.ConnectionPhase`
  (`initial` / `handshake` / `established` / `closing` / `draining` /
  `closed`), composing the handshake epoch with the existing RFC 9000 §10
  close states so embedders can gate stream creation and shutdown without
  inferring the epoch from `handshakeDone` / `closeState` / `haveSecret`.
- `Connection.beginGracefulShutdown()` / `gracefulShutdownActive()`: an
  orderly-shutdown primitive (a transport-level GOAWAY substitute — QUIC
  has no GOAWAY frame). While active, new local stream opens are refused
  with the new `Error.ShuttingDown` and no further MAX_STREAMS credit is
  granted, so the peer's stream limit freezes and both sides quiesce
  new-stream creation while in-flight streams drain to completion. The
  connection stays open until the embedder calls `close`.

### Changed

- Documented API stability tiers in `docs/API_STABILITY.md`: which surfaces
  are stable (1.0 semver target) vs evolving vs internal, the
  `ConnectionEvent` forward-compatibility contract, and the sunset path for
  the draft-based extensions (QUIC-LB draft-21, alt-addr draft-00).
- Added `docs/stream-priority.md`, documenting the RFC 9218 (urgency +
  incremental) stream-priority model.
- The QUIC interop endpoint now initiates an RFC 9001 §6 key update from the
  server role too (previously client-only), so the `keyupdate` testcase
  exercises both directions.
- Fuzzing workflow: removed the filtered-binary parallel fuzz steps
  (`zig build fuzz` and the per-site targets). Deep coverage-guided fuzzing
  is the unfiltered `zig build test --fuzz`, matching CI. The committed
  regression corpus (inline `.corpus` seeds, run by every `zig build test`)
  and the workflow are documented in `CONTRIBUTING.md`.

### Fixed

- `version()` returned a hardcoded `"0.2.0"` while the package manifest
  declared `0.3.0`. It is now single-sourced from `build.zig.zon` through a
  `build_options` module, so it can never drift from the manifest again.

## [0.3.0] - 2026-07-03

Hardening release from a full security & robustness review: closes a
remote-crash DoS and a set of untrusted-input / DoS / correctness issues,
and flips several server and client defaults to be secure by default.

**Upgrade notes — behavior changes that may require action:**

- **Client TLS now verifies by default.** `Client.connect` verifies the
  server certificate against the system trust store. Clients talking to
  self-signed or test peers must now set
  `Client.Config.insecure_skip_verify = true`. A non-null `ca_pem` is
  rejected with `InvalidConfig` (it was previously ignored); pin a private
  CA with a fully configured `tls_context_override`.
- **Server idle timeout defaults to 30s.** `Server.init` substitutes
  `Server.default_server_idle_timeout_ms` when
  `transport_params.max_idle_timeout_ms` is `0`; set
  `Server.Config.allow_no_idle_timeout = true` to keep no idle timer.
- **Per-source Initial-flood limiter is on** at 32/window
  (`Server.Config.max_initials_per_source_per_window`); set it to `null`
  to disable (enforcement is a no-op for unattributed `from == null`
  datagrams).

### Added

- End-to-end loss-recovery test: drops one 1-RTT data packet through the
  mock transport and asserts the lost frames are retransmitted (all data
  + FIN still arrive) and the client's congestion window shrinks below its
  drop-time value — exercising the Connection-level loss → retransmit →
  NewReno response chain that was previously only unit-tested against
  hand-built primitives.
- Coverage-guided fuzz targets for the remaining untrusted-facing
  crypto/parse paths: the QUIC-LB CID decoder (`lb-decode`), the 1-RTT
  decrypt entry point (`open-1rtt`), and Initial key derivation
  (`initial-derive`). Validated via the `zig build test` smoke run. Deep
  coverage-guided `zig build fuzz` aborts with "reached unreachable code"
  on macOS — a `std.testing.fuzz` fuzzer-runtime platform gap that
  reproduces with a trivial standalone fuzz test and affects every fuzz
  target — so run deep fuzzing on Linux, as CI does.

### Security

- The server per-source Initial-flood limiter is now on by default
  (`Config.max_initials_per_source_per_window = 32`, the previously
  recommended value); set it to `null` to disable. Enforcement applies
  only to attributed (`from != null`) datagrams.
- `Server.init` now substitutes a safe 30s idle timeout when
  `transport_params.max_idle_timeout_ms` is left at 0, instead of
  standing up a server with no idle timer. Set the new
  `Config.allow_no_idle_timeout = true` to genuinely disable it.
- Client TLS is now secure by default: `Client.connect` verifies the
  server certificate against the system trust store unless the new
  `Client.Config.insecure_skip_verify` opt-out is set. The previous
  default performed no verification. A non-null `ca_pem` (not yet wired
  into the auto-built context) is now rejected with `InvalidConfig`
  rather than silently downgrading to system-store verification.

### Fixed

- Prevent a remote-triggerable panic in `RttEstimator.update`: a
  peer-controlled ACK `ack_delay` (unclamped before handshake
  confirmation) could overflow `min_rtt + ack_delay` in ReleaseSafe.
  The ACK-delay scaling now saturates and the estimator uses a
  saturating add.
- Restore Retry / NEW_TOKEN issuance for IPv6 peers: the token address
  cap (22) was smaller than a full IPv6 address context (23), so every
  IPv6 client was denied a token. The cap now tracks
  `path.Address.context_max_len` and is guarded by a comptime assert.
- Convert frame-decode errors (unknown type, truncation) into a
  FRAME_ENCODING_ERROR connection close at the dispatch boundary instead
  of propagating them out — a single malformed frame from an
  authenticated peer no longer tears down the transport loop, and the
  server no longer mislabels the close as INTERNAL_ERROR.
- Bound the out-of-order CRYPTO reassembly queue by fragment count (not
  just byte volume) to stop a tiny-fragment flood from driving the
  O(n²) drain into CPU exhaustion.
- `alt_addr.recommendedMigrationDelayMs` no longer overflows (a
  ReleaseSafe panic) when the requested delay window spans the whole
  `u64` range; it now draws over the full range instead.
- Retry and NEW_TOKEN now bind the connection's negotiated / the inbound
  Initial's QUIC version instead of a hardcoded v1, restoring real
  cross-version token separation for v2-capable servers. No behavior
  change for the default single-version (v1) server.
- Server `cid_table` collision handling: `resyncSlotCids` no longer
  overwrites a CID routed to a different live slot, and slot reaping only
  removes routing entries it still owns — so an (astronomically unlikely)
  CID collision can no longer silently re-route or un-route a peer.
- Suppress frame re-processing on a duplicate application packet number:
  a replayed authenticated 1-RTT packet is still acknowledged but no
  longer re-delivers its (non-idempotent) DATAGRAM frame or double-charges
  the resident-bytes budget (RFC 9000 §12.3 / §13.1).
- Reject post-terminal frames for a reaped peer stream: a STREAM or
  RESET_STREAM for a peer-initiated stream that already reached a terminal
  state and was reclaimed is now ignored (RFC 9000 §3.2) instead of
  resurrecting the stream with fresh state (losing its locked final size /
  reset state). Uses a bounded per-direction contiguous "reaped" watermark
  that correctly distinguishes reaped streams from implicitly-opened,
  never-yet-used lower-numbered streams.
- Bound the pre-transport-parameters per-stream send window. It previously
  defaulted to `maxInt` before the peer's parameters were known; it is now
  bounded by embedder-supplied remembered session parameters during a
  0-RTT resumption (new `Client.Config.resumption_peer_transport_params`
  and `Connection.setRememberedPeerTransportParams`), and is 0 for a plain
  connection (which never sends application data before its parameters
  arrive). 0-RTT without remembered parameters keeps its prior behavior.

### Changed

- Documented the `runUdpClient` / `runUdpServer` threading contract:
  `Connection` is single-threaded with no internal locking, so all
  access (loop and application work) must be serialized onto one thread.
- Bumped `minimum_zig_version` to the verified `0.17.0-dev.1158+1d1193aa7`
  and recorded the last-verified master build in `mise.toml`.

- Updated to Zig `0.17.0-dev.813+2153f8143` (configure/maker build
  split): forwarded `zig build ... -- <args>` now use
  `Step.Run.addPassthruArgs()` instead of the removed `b.args`, and
  `minimum_zig_version` reflects the verified master build.
- Bumped `boringssl_zig` to 0.6.1 for the same Zig master
  compatibility fixes.
- Reworked the public README and usage docs around stable embedding,
  interop, benchmark, and conformance workflows.

## [0.2.0]

### Added

- High-level `Server` and `Client` wrappers around the raw
  `Connection` state machine.
- `transport.runUdpServer` and `transport.runUdpClient` for simple
  `std.Io` UDP loops.
- QUIC v2 compatible Version Negotiation support.
- Retry, NEW_TOKEN, stateless reset token helpers, and key logging
  surfaces.
- 0-RTT session support with anti-replay integration hooks.
- ECN, DPLPMTUD, migration, preferred address, DATAGRAM, and qlog-style
  event surfaces.
- QUIC-LB draft 21 helpers, including plaintext, single-pass AES, and
  four-pass Feistel CID modes plus decode support.
- Alternative Server Address draft 00 codec, emit, receive event, and
  embedder example support.
- RFC-traceable conformance suites and a microbenchmark harness.
- Official QUIC interop-runner endpoint and wrapper.

### Changed

- Public module name is `quic_zig`.
- Production guidance requires `-Doptimize=ReleaseSafe` for
  internet-facing builds.
- Generated interop outputs are ignored under `interop/logs*` and
  `interop/results`.

## [0.1.0]

### Added

- QUIC v1 packet, frame, transport-parameter, stream, loss-recovery,
  and TLS glue foundations.
- BoringSSL-backed TLS 1.3, AEAD, HKDF, and header protection.
- Initial unit and end-to-end smoke tests.

## [0.0.0]

### Added

- Initial repository scaffold.
