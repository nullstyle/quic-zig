# Changelog

All notable changes to quic-zig are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [Unreleased]

The deduplication series: a repo-wide audit found 50 verified
copy-paste families (41 worth extracting), and this series collapses
them onto shared implementations. Internal-only in behavior except for
the fixes noted below, all of which were latent defects the duplication
had been hiding. Deterministic impairment cells stay byte-identical
throughout.

### Fixed

- **Per-source rate limiting reset unrelated budgets.** On Initial
  window rollover, `acceptSourceRate` assigned a whole fresh
  `SourceRateEntry` instead of just its own (count, window_start) pair,
  silently zeroing the VN, log, and bandwidth axes that were added to
  the struct later. One Initial per window handed a peer a fresh
  Version-Negotiation budget (2× the configured VN amplification cap)
  and a full token bucket (up to 2× the configured per-source byte
  rate). Both consequences now have regression tests.
- **qlog congestion-state events were stamped `at_us = 0`.** The
  packet-threshold loss sweeps passed `0` where the time-threshold
  sweeps passed `now_us`; that forced the `.recovery` branch whenever a
  recovery period had ever started, and — because the event latches
  before the ACK handler's correctly-timestamped call — suppressed the
  good event and produced a spurious recovery→congestion_avoidance flap
  on lossless ACKs. `now_us` is now a required parameter.
- **Inbound ACK side effects ran in opposite orders** on the per-level
  and per-path paths (key-epoch confirmation vs stream dispatch). The
  two are independent, so this was observable only on the error path;
  it is now one order, with a comment recording that the order is free.

### Changed

- Internal: ~1,600 lines of verified duplication collapsed onto shared
  implementations across loss detection (four sweeps → one
  `sweepLosses` over a `LossTarget`), inbound ACK application (two
  handlers → one applier over an `AckTarget`), the 1-RTT control drain
  (ten hand-rolled length computations → the file's existing
  `encodeFrameIfFits`), the NEW_TOKEN/Retry AEAD codecs (→ one
  `token_envelope.Envelope`), the Server rate limiters, transport-param
  encode/encodedLen, the frame codecs, the wire long-header walk, the
  UDP loops, CID registries, migration checks, flow control, Feistel,
  and more. Public API and Internal-tier paths unchanged.
- Both token wire formats are now pinned by known-answer `validate`
  tests, so a refactor can no longer silently invalidate tokens already
  issued in the field.

## [0.13.1] - 2026-08-13

The restyle release: internal-only. The whole codebase now reads like
the zig compiler's (file-as-struct, Sema-style spokes, decl-alias
method re-exports) with zero embedder-visible change — same API, same
wire behavior, byte-identical deterministic cells. Downstreams: a pin
bump should require no code changes at all.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

### Changed

- **Internal: the codebase adopts the zig compiler's layout
  conventions** (ziglang file-as-struct). `Connection`, `Server`,
  `Client`, `Server.Config`, and 14 support types are now TitleCase
  files that ARE their structs (`src/Connection.zig` with
  `Connection/` spokes, `src/Server.zig` with `Server/`, Compilation.zig
  anatomy: @This alias, imports, fields, then types and methods).
  The 20 `conn_*` method files became `Connection/<x>.zig`; 244 pure
  pass-through hub thunks became decl-alias re-exports (Sema.zig
  mechanism, −851 lines); spoke receivers are `conn:`/`server:`; the
  `*Impl` alias pattern is retired. **Zero embedder-visible change**:
  every public name and every Internal-tier path
  (`quic.conn.state.*`, `quic.conn.path.*`, …) resolves exactly as
  before, enforced per-commit by the new
  `tests/e2e/internal_surface_smoke.zig`; wire behavior byte-identical
  (deterministic impairment cells) at every phase boundary. Mechanical
  commits are listed in `.git-blame-ignore-revs`.
- Internal: the `src/server/` import seam was cleaned — pure
  header-peek/CID-key helpers moved to a new `wire_peek.zig` leaf,
  siblings now import siblings directly instead of round-tripping
  `server.zig`, and the hub-and-spokes layout rules are codified in
  `CONTRIBUTING.md`. No embedder-visible change.

### Fixed

- Test discovery: `pacing`/`hystart`/`delivery_rate` submodule tests
  were only reachable transitively; making the discovery block
  explicit recovered two silently-undiscovered tests.

## [0.13.0] - 2026-08-13

The integration release. Everything in it exists because a downstream
shipped v0.12.0 and reported back within the day: the three surfaces
the first HTTP/3 embedder asked for — a one-shot
`ConnectionEvent.early_data` (replacing a status poll that the
rejection path makes unreliable by design), send-window introspection
for real backpressure, and the 0-RTT surface promoted to the Stable
tier — plus a 1.35 MiB-per-connection memory return from right-sizing
the Initial/Handshake sent-packet trackers, closing out the warm-up
footprint growth that same downstream measured across
v0.10.1 → v0.12.0. No wire-behavior changes; defaults unchanged.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

### Added

- **`ConnectionEvent.early_data`** — one-shot event carrying the
  `EarlyDataStatus` when the 0-RTT outcome resolves (`.accepted` /
  `.rejected`; connections that never attempt 0-RTT get no event).
  Rejection is surfaced only after the verbatim 1-RTT requeue has
  run, so reactors observe post-requeue state. Replaces per-drain
  `earlyDataStatus()` polling. Additive variant under the
  `ConnectionEvent` forward-compatibility contract: exhaustive
  switches gain a compile error, which is the documented signal.
- **Send-window introspection** — `Connection.sendWindow()`
  (connection-level flow credit remaining) and
  `Connection.streamSendWindow(id) ?SendWindow`, a per-stream snapshot
  carrying the connection credit, stream credit, queued-but-unsent
  backlog, and the net `writable` figure a `canWrite`-style
  backpressure gate wants. Mirrors the send gate's own accounting
  (new-data bytes only; retransmissions are invisible; congestion
  control deliberately excluded — `sendAllowance` answers that side).
  Requested by http3-zig, whose backpressure previously could only
  consult its own buffer cap and the binary blocked events. Newly
  added surface: Unstable tier until it soaks, per policy.

### Changed

- **The 0-RTT / early-data surface is Stable tier** —
  `earlyDataStatus` (+ `EarlyDataStatus`), `earlyDataReason`,
  `setEarlyDataEnabled`, `streamArrivedInEarlyData`, and
  `setEarlyDataContextForParams` join the compile-checked Stable list
  (`tests/e2e/public_api_smoke.zig`), promoted at the request of the
  first downstream shipping HTTP/3 early data on them. The verbatim
  requeue-on-rejection behavior is documented as part of the surface.
- **Per-connection memory: −1.35 MiB** — sent-packet tracker capacity
  became an init-time choice, and the Initial/Handshake spaces are
  right-sized 4096 → 256 slots (they peak at single-digit live
  packets across the whole test/impairment corpus and sit idle after
  the handshake; 256 still covers a 100 KiB certificate-chain flight
  ~2.8×, with the sizing evidence recorded at
  `sent_packets.initial_handshake_max_tracked`). Addresses the
  v0.10.1 → v0.12.0 warm-up footprint growth measured downstream
  (~6.2 → ~3.5 MB per connection pair expected). The ACK-churn
  microbench got ~20% faster in the bargain (tracker counters now sit
  adjacent to the slots they govern).

## [0.12.0] - 2026-08-12

The shape release. BBRv3 lands as the third congestion controller —
opt-in, on a new per-packet delivery-rate measurement spine — and the
two long-standing API-shape debts close while the pre-release breaking
window is open: a `Connection` now has one address for its whole life,
and the package sheds its redundant `_zig` suffix. One migration for
downstreams covers all of it, plus the two availability fixes below
(a peer could end either bundled UDP loop).

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

Headline numbers (m5max dev machine; impairment cells are in-process
deterministic virtual time — identical seeds, machine-independent;
the goodput figure is wall-clock in-process; every BBR number is
measured OPT-IN via `congestion_control = .bbr`, the shipped default
is still CUBIC):

- BBR vs CUBIC on the 10 Mbit bottleneck cells: line-rate parity
  (9.71 vMbps) with peak queueing delay **85.6 ms → 16.7 ms (5.1×
  shorter queue)**; on the new shallow 25 ms buffer cell, tail drops
  **15 → 0**.
- BBR vs CUBIC, 64 MiB wall-clock bulk transfer: **249.9 → 266.5 MB/s
  (+6.7%)** — pacing at the modeled bandwidth beats window bursts
  even without a bottleneck.
- BBR vs CUBIC on the fixed-delay 1% loss cell: **53.6 → 1252 vMbps
  (23×)** — regime-specific (that cell has no bandwidth constraint;
  the bottleneck+loss cell shows parity, not fireworks), but it is
  the loss-tolerance BBR exists to provide.
- `Connection` is **~1.2 MB smaller** than 0.11.0 (the two
  Initial/Handshake trackers moved to one heap slab) at
  `@sizeOf(Connection)` = 152,224 bytes, and its address is now
  stable for life.
- Honest cost, measured and rebaselined: the sent-packet-tracker
  churn micro pays for the 40 bytes of per-packet delivery-rate
  stamps, **46.9 → 61.5 ns/op** (still ~113× better than the
  pre-0.11.0 cliff); end-to-end goodput impact −1%.

### Changed (BREAKING)

- **The package is named `quic` now, not `quic_zig`.** The `_zig`
  suffix was redundant in a Zig package name. This changes every
  consumer-facing identifier at once: `build.zig.zon` dependency key
  (`.quic = .{ ... }`), `b.dependency("quic", ...)`,
  `dep.module("quic")`, and `@import("quic")`. The manifest
  `.name`/`.fingerprint` pair changed with it, which is a new package
  identity as far as the Zig package manager is concerned — re-fetch
  rather than expecting hash continuity. The project (repo, docs,
  issue tracker) is still called quic-zig; only the package/module
  identifier shrank. Bench report metadata follows: suites are
  `quic.microbench` / `quic.bench_e2e` and the version key is
  `quic_version` (committed baselines updated in-commit, header-only).
  Historical CHANGELOG entries below keep the names that were true
  when they shipped. Migration note from the first downstream to take
  this bump: with the conventional `const quic = @import("quic")`,
  any local variable or parameter already named `quic` becomes a
  shadowing error under Zig's no-shadowing rule — rename those locals
  first (http3-zig hit 7 of them; the compile errors point at every
  one).
- **A `Connection` now has one address for its whole life** — the
  init-then-move-then-`bind()` dance is gone, and with it the window
  where moving a bound Connection silently dangled the `*Connection`
  stashed in SSL ex-data. Construction wires TLS immediately:
  - `Connection.initClient(alloc, ctx, name) !Connection` + `bind()`
    → `Connection.createClient(alloc, ctx, name) !*Connection`,
    paired with `conn.destroy()` (replaces `deinit()` + freeing your
    own box).
  - `Connection.initServer(alloc, ctx)` + `bind()` →
    `Connection.createServer(alloc, ctx) !*Connection` + `destroy()`.
  - Caller-owned storage (arenas, pools, embedding a Connection in a
    heap-allocated parent) uses `Connection.initClientAt(&slot, ...)`
    / `initServerAt(&slot, ...)`, which construct in place at the
    final address and pair with `deinit()`.
  - `bind()` no longer exists; delete the call. Migration is
    mechanical: both wrappers already heap-boxed their Connection and
    are unchanged (`Client`/`Server` APIs are not affected).
  - qlog's `connection_started` now fires from `setQlogCallback` (the
    first moment a sink exists). Previously the client-side event was
    emitted during `bind()`, which ran before wrapper users installed
    their callback — it was silently dropped for them.
  This is the structural counterpart of 0.10.0's naming shakeout:
  the last known API-shape debt closed before new surface (multipath
  productization, completion-based transports — both of which need
  pinned addresses) is built on top. `@sizeOf(Connection)` is 152,224
  bytes; it was never a by-value type in practice, and now the type
  system says so.

### Added

- **BBRv3 congestion control (opt-in)** — `congestion_control = .bbr`
  on both `Client.Config` and `Server.Config` selects a model-based
  controller per draft-ietf-ccwg-bbr-06: it paces at the estimated
  bottleneck bandwidth (windowed max delivery rate) and bounds data in
  flight to a small multiple of the estimated BDP (windowed min RTT),
  cycling Startup/Drain/ProbeBW/ProbeRTT with loss-driven short- and
  long-term inflight bounds. The default remains CUBIC — flipping it
  is gated on a multi-flow fairness cell and an interop battery (see
  the `congestion_bbr.zig` header). Built on new per-packet
  delivery-rate sampling (draft-cheng-iccrg-delivery-rate-estimation,
  as embedded in the BBR draft), a controller-owned pacing-rate
  outlet, and per-lost-packet controller inlets, each of which landed
  as its own zero-consumer/zero-delta commit. Conformance:
  `tests/conformance/bbr_draft06.zig` (26 draft-cited claims + 2
  visible-debt skips) and `draft_cheng_delivery_rate_02.zig`.
  Observability: `CongestionController.bbrSnapshot()`. On the
  deterministic impairment battery vs CUBIC (identical seeds), BBR
  holds link-limited goodput while cutting bottleneck queueing —
  full A/B table in the landing commit message.
- **`MetricsSnapshot.egress_local_faults`** — counts send attempts
  abandoned on a *local* socket fault (`NetworkDown`,
  `SystemResources`, `AccessDenied`) inside `runUdpServer`. The server
  loop deliberately does not exit on egress failure, but until now it
  also never mentioned one, so a host with no interface or no socket
  buffers served nothing while reporting perfect health. Peer-provoked
  failures are excluded by design — they are routine on the open
  internet and would bury the signal. Any sustained nonzero rate here
  means the host, not the peers.

### Fixed

- **A peer could end the bundled UDP loops.** `runUdpServer` /
  `runUdpClient` treated every non-timeout receive error as fatal,
  including three that the remote side influences: `PortUnreachable`
  and `ConnectionResetByPeer` (ICMP feedback queued against the bound
  socket and reported at the next receive — so a peer that goes away,
  or an off-path packet that provokes an ICMP, could stop a server
  from serving everyone else) and `MessageOversize` (a datagram larger
  than the per-message buffer, which the sender chooses). These are
  now tolerated and the datagram discarded, which is what
  `examples/foreign_loop_embedder.zig` already did — the bundled loops
  were the inconsistent ones. Local faults still propagate.
  Classification is pinned by `transport.classifyReceiveError` and its
  test. Thanks to the capnp-zig team, who hit the Windows half of this
  in their own receive bridge and flagged the pattern.
- **The same hole existed on the send path**, and the client loop was
  the exposed one: a peer that stops listening provokes an ICMP
  port-unreachable, which the kernel reports as `ConnectionRefused` on
  the *next send* — and the client propagated it, so any peer could
  end the loop. Now `ConnectionRefused`, `ConnectionResetByPeer`,
  `HostUnreachable`, `NetworkUnreachable`, and `MessageOversize` are
  tolerated on both loops (the datagram is lost; loss recovery
  retransmits, and a peer that is genuinely gone is closed out by the
  idle timeout, which is the clean path). Local faults still reach the
  embedder on the client and are counted on the server. All client
  egress, including the GSO path, now routes through one policy,
  pinned by `transport.classifySendError` and its test.

### Changed

- The Windows limitation of the bundled event loops is now documented
  at both `RunError` sets and in `EMBEDDING.md`, and asserted by the
  three real-socket smoke tests rather than skipped: `runUdpServer` /
  `runUdpClient` fail with `error.ConcurrencyUnavailable` on native
  Windows because std has no overlapped-I/O `net_receive` there, so no
  timed receive — the loops' heartbeat — is possible. The protocol
  engine is unaffected and remains tier-1 on Windows; embedders there
  drive their own loop. Applies equally to v0.10.x and v0.11.0.

## [0.11.0] - 2026-08-12

The performance release, measured. Three long-deferred datapath levers
land together — modern congestion control with pacing, a batched UDP
datapath, and an O(1) sent-packet-tracker fix — each backed by a new
end-to-end benchmark tier (goodput, handshakes/sec, deterministic
impairment) with committed baselines and a regression-compare tool, so
every claim below has a number behind it. All changes are additive:
the Stable API surface is unchanged and no `Config` field was renamed.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b (moved up from
0.17.0-dev.1252 during the release — see Changed).

Headline numbers (m5max dev machine; loopback for the real-socket
figure, in-process virtual time for impairment — deterministic per
seed and machine-independent):

- Slow-start overshoot on a 10 Mbit bottleneck: HyStart++ takes
  buffer-overflow drops from **111 to 0** and peak queueing delay from
  **99.7 ms to 85.6 ms** (to **33.6 ms**, −52%, with 1% background
  loss) — identically on the 8-stream multiplexed variant.

- Real-socket upload goodput **10.8 → 48.9 MB/s (4.5×)** from the
  batched datapath (batched ingress, cross-peer `sendmmsg`, Linux
  GSO/GRO).
- Sent-packet-tracker removal at high occupancy **6941 → 46.9 ns/op
  (~148×)**; the old full-tail memmove was a quadratic ACK-processing
  cliff (~590 KB moved per cumulative ACK at 4096 in flight).
- Goodput under 1% loss **44.2 → 53.6 vMbps (+21%)** from CUBIC +
  pacing combined; ~1852 handshakes/sec at 5 allocations each.

### Added

- **CUBIC congestion control (RFC 9438)** — now the default, selectable
  back to NewReno with `Server.Config` / `Client.Config`
  `congestion_control = .new_reno` (a one-line rollback; both ship
  compiled in). Congestion control is now pluggable behind a
  by-value tagged union (no allocation, no vtable). New
  `tests/conformance/rfc9438_cubic.zig`.
- **Packet pacing (RFC 9002 §7.7)** — on by default
  (`enable_pacing = false` restores the pre-0.11 burst timing exactly).
  A per-path token bucket that spreads sends at gain × cwnd/RTT;
  surfaced to foreign event loops as a new `TimerKind.pacing` deadline.
  New `tests/conformance/rfc9002_pacing.zig`.
- **RFC 9002 §7.8 application-limited gate** — the window no longer
  grows off ACKs from an unfilled pipe (both controllers).
- **HyStart++ (RFC 9406)** — on by default
  (`enable_hystart = false` restores plain RFC 9002 slow start).
  Standard slow start only stops once it overruns the bottleneck and
  loses packets; HyStart++ watches for sustained RTT inflation across
  a round and leaves slow start before the overshoot. Shared by both
  controllers (CUBIC + HyStart++ is the pairing Linux and quiche
  ship). New `tests/conformance/rfc9406_hystart.zig`.
- **Batched UDP datapath** in `runUdpServer` / `runUdpClient`: batched
  ingress (`RunUdpOptions.max_datagrams_per_iteration`, default 16),
  cross-peer egress via one `sendMany`/`sendmmsg`
  (`max_send_batch_datagrams`, default 64), and Linux UDP GSO/GRO
  (`enable_gso` / `enable_gro`, default on, probe-gated with runtime
  fallback; no effect off Linux). New public `transport.fillGsoBatch`
  + GSO cmsg helpers for foreign-loop embedders.
- **`Connection.stats()`** (`ConnectionStats`, Unstable tier) — a
  by-value observability snapshot: whole-connection byte/packet
  counters plus an active-path cwnd/RTT/PMTU snapshot and
  open-stream/close-state gauges.
- **`quic_zig.qlog`** — a real JSON Text Sequences (`.sqlog`) qlog
  writer (qlog_version 0.4) that qvis loads directly; the QNS endpoint
  emits it in place of the prior ad-hoc JSONL. The `metrics_updated`
  event now carries the (previously dead) pacing rate.
- **End-to-end benchmark tier** (`zig build bench-e2e`): in-process
  goodput, handshakes/sec, and a deterministic loss/reorder impairment
  matrix, with allocation counts and per-poll latency percentiles.
  Microbenchmarks (`zig build bench`) now report median ± MAD over N
  samples. New `zig build bench-compare` regression tool + committed
  `baselines/bench/`, and a real-socket `zig build run-goodput-smoke`.
  The impairment simulator gained a rate-limited **bottleneck link
  with a finite tail-drop buffer** and a **multi-stream transfer
  mode**, so congestion-control behavior that only appears when a
  queue builds — slow-start overshoot above all — is finally
  measurable in-tree rather than only in interop.

### Changed

- **CUBIC, pacing, and HyStart++ are the defaults** (see Added for the
  per-feature opt-outs) — the deliberate wire-behavior changes in this
  release, each landed separately and measured on its own so a
  regression bisects to one of them. Validated by the blocking
  quic-go interop gate and the weekly matrix.
- `TimerKind` gains a `pacing` variant; embedders with exhaustive
  switches over it get a compile error (the documented forward-compat
  signal) — handle unknown kinds generically (wake, tick, drain).
- `SentPacketTracker` removal is now O(1) tombstoning with amortized
  compaction; `count` includes tombstones, `liveCount()` is the
  tracked-packet count (internal API).
- The undocumented `max_datagrams_per_loop_iteration` transport
  constant (always 1) is replaced by the configurable
  `max_datagrams_per_iteration` option.
- CI: the weekly deep-fuzz budget is corrected to 1M/target (the
  documented 10M was never runnable under GitHub's job cap); a Linux
  aarch64 test leg is added; the weekly interop matrix gains goodput
  and loss-conditioned cells with a job-summary readout.
- **Toolchain moved to `0.17.0-dev.1683+5ceec001b`** (from
  `0.17.0-dev.1252`), and `minimum_zig_version` with it. The previous
  pin had been garbage-collected from ziglang.org — which keeps only
  the current master tarball — so it was no longer installable from
  its nominal source. Embedders must move up: the tree now uses
  `std.lang.Optimize`'s lowercase field names, which do not exist on
  the old pin.
- The QNS interop image no longer depends on ziglang.org retaining a
  dev tarball. It tries the Zig project's community mirrors in order
  and pins the exact SHA-256 per architecture (digests verified
  against Zig's minisign key), so the build fails closed on a bad
  mirror instead of failing open on a missing one.

### Fixed

- Quadratic ACK-processing cost at high bytes-in-flight (the tracker
  memmove cliff, above).
- A new version-negotiation-preparse fuzz harness (the 38th fuzz site)
  covers the multi-Initial ClientHello reassembler + transport-param /
  version-selection walk — the most complex parser reached before any
  TLS state exists.
- Documentation truth-up: the boringssl-zig pin box in
  `RELEASE_READINESS.md` now matches the actual SHA pin (with a new
  cross-repo pin-lint workflow), the platform tier table matches CI,
  the `EMBEDDING.md` Windows clause reflects its tier-1 status, and 27
  code comments that cited a nonexistent "hardening guide" are
  repointed to the governing RFC sections.

## [0.10.1] - 2026-08-12

Patch release over v0.10.0 so downstreams can pin a tag instead of a
raw SHA for the native-Windows build fix. Library code is byte-identical
to v0.10.0 — the only functional change is the dependency pin.

Cut on a short-lived `release/0.10.x` line off `e00d449` and merged back
into the trunk, so `v0.10.1` is an ancestor of `main` and development
stays on one thread. The tag itself is immutable and unaffected by that
merge.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19 (unchanged).

### Fixed

- **Native Windows builds no longer fail in the linker configuration
  step.** The `boringssl-zig` pin moves from tag `v0.6.4` to `0.6.5`
  (`292c70a2`), which stops `ws2_32` from being resolved through
  `pkg-config`: Git Bash can expose a `pkg-config.BAT` shim that cannot
  describe Windows SDK libraries, failing an otherwise healthy native
  build. This is a *build-configuration* fix; no runtime behavior
  changed on any platform.

  Note the pin is a commit SHA rather than a tag, because the fix
  landed upstream before boringssl-zig cut a release; see the
  cross-repo pin note in `docs/RELEASE_READINESS.md`.

## [0.10.0] - 2026-07-29

Consumer-feedback release (thanks to the capnp-zig team for a detailed
downstream audit): the private-CA / mTLS gap is closed, the build is
lighter to consume, and the release/versioning discipline consumers
asked for is now written down in CONTRIBUTING.md ("Releases"). The
`Server.Config` field names are frozen from here to 1.0.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19 — and as of this
release that is *enforced*, not just recorded: `mise.toml` pins the exact
master build instead of resolving `master` at install time.

### Added

- **Private-CA and mTLS support through the wrappers, no BoringSSL
  types required.** `Client.Config.ca_pem` is now wired: it pins the
  supplied PEM bundle as the only trust anchors (replacing, not
  augmenting, the system store) while keeping hostname/identity
  verification against `server_name`. New `Client.Config.client_cert_pem`
  / `client_key_pem` present a client certificate when the server
  requests one, and new `Server.Config.client_ca_pem` makes the server
  require and verify client certificates against a pinned bundle
  (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`), including
  across `replaceTlsContext(.{ .pem = ... })` rotations. Backed by the
  new `tls.pem` module (`installTrustAnchors` / `installClientIdentity`)
  and covered end-to-end by `tests/e2e/tls_verify_e2e.zig` — the first
  wrapper handshakes in the suite that run with verification ON.
  Negative coverage includes SAN mismatch, a server chaining to a
  different root, a missing client cert, an *untrusted* client cert
  (verification, not just presence), rotation carry-over, and the
  malformed-PEM error paths. Hardening details: pinned clients set
  `SSL_CTX_set_reverify_on_resume` so resumed sessions cannot inherit
  a different trust posture; a PEM bundle with a malformed block
  after valid certificates fails with `InvalidPem` instead of
  silently installing a prefix of the roots
  (`PEM_R_NO_START_LINE`-based end-of-input detection); and
  `replaceTlsContext(.{ .override = ... })` is rejected with
  `InvalidConfig` while `client_ca_pem` is configured, because an
  adopted context would silently drop the required-client-cert
  posture (mTLS servers rotate via `.pem`).
- `build.zig` now forwards boringssl-zig's `-Dboringssl-source` and
  `-Dboringssl-target` options (with `-Dboringssl-target` rejected
  unless `-Dboringssl-source=cmake`, instead of being silently
  ignored). Caveat: the boringssl-zig package archive quic-zig pins
  does not ship the `vendor/` prebuilt archives, so cmake mode
  currently requires a boringssl-zig checkout with the prebuilts
  populated (`just boringssl-cmake` upstream) wired in as a path
  dependency; the forwarding makes quic-zig transparent to that
  setup rather than the blocker.
- **`examples/foreign_loop_embedder.zig`** — a worked, tested
  integration of the caller-drives (no-I/O) path into a hand-rolled
  `std.posix.poll` reactor, plus a new
  `## Foreign Event Loops` section in EMBEDDING.md. Driving
  `feed`/`handle`, `drainStatelessResponse`, `pollDatagram`, `tick`,
  `pollEvent`, and `reap` from your own loop has always been supported;
  it was not discoverable, and a downstream consumer hand-rolled ~450
  lines of wake-pipe and timer plumbing before finding it. The example
  isolates the parts that are easy to get wrong — deadline→timeout
  conversion (past-due must clamp to 0, sub-millisecond must round up
  to 1) and the queue+wake handoff for cross-thread application work —
  as pure, separately tested units, and its in-memory test completes a
  real TLS 1.3 handshake plus stream and datagram echo through the
  pumps with no socket involved. Builds as
  `foreign-loop-embedder-example` under `zig build examples`; its
  inline tests run under `zig build test` on every tier-1 platform
  (the socket/poll group skips on Windows, where `std.posix.poll` is a
  compile error).
- `quic_zig.ConnectionError` (and `conn.Error`) re-export the error set
  `Connection`'s methods return, so embedders composing their own error
  sets stop reaching through the `conn.state` submodule path.
  `Connection.last_activity_us` is documented as a stable,
  embedder-readable connection clock — http3-zig already reads it that
  way for request-deadline enforcement.
- `build.zig` enforces `minimum_zig_version` with a `comptime` assert
  (Zig's build runner parses the field but never checks it). An
  out-of-floor toolchain now gets a one-line diagnostic naming both
  versions — in dependency builds too — instead of an unexplained
  compile error inside the tree.

### Changed (BREAKING)

- **`Server.Config` naming/semantics normalization.** This is the one
  pre-1.0 `Config` churn `docs/API_STABILITY.md` has always reserved,
  batched into this release so consumers migrate once. `Config` field
  names are frozen from here to 1.0.

  Every rate and quota knob now shares one three-state type,
  `Server.RateLimit` — `.default` (the library's recommendation),
  `.disabled` (opt out), `.{ .limit = n }` (explicit cap). `null` is no
  longer spellable for these, which is the point: when 0.3.0 turned the
  Initial-flood limiter on by default, `null` silently inverted from
  "harmless unset" to "explicitly disable a DoS mitigation", and a
  downstream consumer mirroring the old default shipped exactly that
  misconfiguration with no compile error and no failing test. Every
  stale caller is now a compile error.

  | old field | new field | migration |
  | --- | --- | --- |
  | `max_initials_per_source_per_window: ?u32 = 32` | `initial_source_rate_limit: RateLimit = .default` | `null` → `.disabled`; `n` → `.{ .limit = n }` |
  | `max_vn_per_source_per_window: ?u32 = 8` | `vn_source_rate_limit: RateLimit = .default` | same |
  | `max_log_events_per_source_per_window: ?u32 = 16` | `log_source_rate_limit: RateLimit = .default` | same |
  | `max_datagrams_per_window: ?u32 = null` | `listener_datagram_rate_limit: RateLimit = .default` | same (`.default` is off) |
  | `max_bytes_per_window: ?u64 = null` | `listener_byte_rate_limit: RateLimit = .default` | same (`.default` is off) |
  | `max_bytes_per_source_per_second: ?u64 = null` | `source_byte_rate_limit: RateLimit = .default` | same; cap is still bytes/second |
  | `enable_0rtt: bool` + `early_data_anti_replay: ?*T` | `early_data: EarlyData = .disabled` | see below |
  | `versions: []const u32` | `accepted_versions: []const u32` | rename only |
  | `max_auto_replenish_cids: usize` | `max_auto_replenish_cids: u8` | literals unchanged |

  The recommended caps are exposed as `Config.default_initial_source_rate_cap`
  (32), `default_vn_source_rate_cap` (8), and
  `default_log_source_rate_cap` (16). The listener and bandwidth
  limiters recommend "off" — the right ceiling is deployment-specific —
  so `.default` resolves to no limit for those three.

  `enable_0rtt: bool` + `early_data_anti_replay: ?*AntiReplayTracker`
  collapse into `early_data: Server.EarlyData`, a union of `.disabled`,
  `.{ .with_anti_replay = &tracker }`, and
  `.without_replay_protection`. The old pair let `enable_0rtt = true`
  with a forgotten tracker ship replay-exposed 0-RTT as a perfectly
  valid config, with no error and no log line; shipping unprotected
  0-RTT is now a deliberate, greppable choice. Migration:
  `.enable_0rtt = true` + `.early_data_anti_replay = &t` →
  `.early_data = .{ .with_anti_replay = &t }`; `.enable_0rtt = true`
  alone → `.early_data = .without_replay_protection`; omit the field to
  keep 0-RTT off.

  `usize` was the only platform-width integer in either `Config`, which
  would have frozen a field whose size differs between a 32- and
  64-bit build of the same consumer.
- The published package archive no longer ships the `bench/`, `docs/`,
  `interop/`, `tests/`, and `tools/` trees, and `build.zig` registers
  its development steps (tests, QNS endpoint, examples, docs, bench,
  interop tooling) only when quic-zig is the root package. Consumers
  fetch and configure just the module graph. Building the dev steps
  requires a git checkout — which is where they were run anyway.

### Fixed (examples)

- The canonical echo example pair silently truncated any stream larger
  than one read chunk and panicked on the documented backpressure path.
  `streamReadFin`'s `fin` reports that the FIN *frame arrived*, not that
  the application has drained the stream, so honouring it before a read
  returns zero bytes abandoned whatever was still buffered; and
  `streamWrite` short-writes by design when the send buffer is near
  `max_buffered`, which an `assert(written == n)` turned into a crash.
  Both are fixed in `examples/echo_server.zig` and
  `examples/echo_client.zig`, and `zig build run-echo-smoke` now runs a
  second leg with a payload larger than one chunk as a permanent
  regression gate. These are the examples embedders copy first, so the
  wrong pattern was the most costly part of the bug.

### Changed

- **Wire-visible close code for TLS handshake failures.** When a
  connection dies inside `Server.feed` because TLS rejected it, the
  CONNECTION_CLOSE the peer sees now carries RFC 9001 §4.8's generic
  CRYPTO_ERROR `handshake_failure` (0x0128) instead of RFC 9000 §20.1
  INTERNAL_ERROR (0x01), so a TLS rejection is no longer reported as
  "the server broke". Most rejections already carried the *specific*
  0x0100+alert code — BoringSSL's `send_alert` closes first and
  `close` is first-wins — so this only moves the alert-less handshake
  failure, but it moves it into the window a peer can classify. Three
  new public constants name the codes:
  `conn.state.transport_error_internal`,
  `transport_error_crypto_base`, and
  `transport_error_crypto_handshake_failure`. The e2e TLS suite now
  asserts rejection close codes land in 0x0100-0x01ff on both sides.
- **The pinned Zig toolchain is now reproducible.** `mise.toml` pinned
  `zig = "master"`, which resolves at install time, so every CI job
  silently ran whatever master shipped that morning rather than the
  compiler the release was verified against. It now pins the exact build
  (`0.17.0-dev.1252+e4b325c19`). This is a development-tooling change —
  it does not affect the published module — but it is what makes the
  "Verified toolchain" line above meaningful, and it is worth copying if
  you also track Zig master.

### Fixed

- `Client.Config.ca_pem` no longer rejects every non-null value with
  `error.InvalidConfig` (the 0.3.0 "trap field"). The only remaining
  `InvalidConfig` cases are genuinely contradictory configs: `ca_pem`
  with `insecure_skip_verify`, credential fields combined with
  `tls_context_override`, an empty bundle, or a cert/key half-pair.
  (An unparseable non-empty bundle fails with `InvalidPem`.)
- `Server.replaceTlsContext(.{ .pem = ... })` re-installs the 0-RTT
  anti-replay callback (`Config.early_data`'s tracker) on the
  replacement context. Previously a hot cert rotation on a 0-RTT
  server silently disconnected TLS-layer replay protection for every
  ticket minted after the swap (RFC 9001 §5.6).
- **CONTRIBUTING.md's fuzzing guidance was wrong in two ways**, both
  corrected against the pinned toolchain. macOS *can* deep-fuzz
  (`zig build test --fuzz=1000` completes on aarch64-macOS with real
  coverage; the old note described 0.17.0-dev.1158 behaviour). And
  adding `-ffuzz` / `Module.fuzz` by hand is actively harmful: `--fuzz`
  already instruments the root module, where every fuzz target lives, so
  setting the per-module flag only instruments `quic_zig` where it is a
  non-root dependency and breaks the link with seven undefined
  `runner_*` symbols on every platform. There is now also a documented
  way to check a deep-fuzz run actually collected coverage, because exit
  status alone is not sufficient evidence.
- The `quic-go-interop` and `interop` workflows had been failing since
  2026-07-09: both check the repo out into a `quic-zig/` subdirectory,
  but the dependency-prefetch step ran at the workspace root (`no
  build.zig file found`, exhausting all retries) and the package-cache
  path and key resolved one level too high, so the cache never hit and
  its key could never invalidate.

## [0.9.0] - 2026-07-09

The application-readiness release: every gap between "protocol-complete"
and "an application can be built on this" identified by the 2026-07
embedding audit is closed. Applications get stream/handshake lifecycle
events, hostable packaged UDP loops, ordered connection teardown,
working 0-RTT and client migration through the wrappers, a canonical
echo example pair exercised in CI over real sockets, generated API
docs, and out-of-tree consumption checks.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19.

### Added

- `ConnectionEvent.handshake_established`: one-shot event surfaced on the
  first `pollEvent` after `handshakeDone()` latches, so embedders no longer
  poll `phase()` to learn 1-RTT is usable.
- `ConnectionEvent.stream_opened` (`StreamOpenedInfo`): lossless, in-order
  notification of peer-initiated stream opens — including RFC 9000 §3.2
  implicit creation — via a watermark chase over the opened-stream counters
  instead of an overflowable queue. Removes the per-tick
  `streamIterator` diff-scan every application previously hand-rolled.
- `Server.Slot.user_data`: embedder-owned per-connection pointer, so
  application state hangs off the slot instead of a parallel
  `slot_id`-keyed map.
- `Server.Config.on_connection_will_close`: ordered-teardown hook invoked
  inside `reap` while the slot and its `Connection` are still valid —
  closes the use-after-free window between reap and application-side
  session cleanup (the http3-zig integration seam).
- `Server.nextTimerDeadline`: aggregate earliest timer deadline across all
  live slots, for event loops that sleep until the next deadline instead
  of fixed-tick polling.
- `RunUdpOptions.on_iteration` / `RunUdpClientOptions.on_iteration`:
  per-iteration application hooks on the packaged UDP loops, making them
  hostable for interactive applications. The hooks run on the loop thread
  (the loops' single-threaded contract is unchanged); hook errors
  propagate out, so both run functions now return `anyerror!void`.

- 0-RTT now works end-to-end through the wrappers. `Server` installs the
  RFC 9001 §4.6.1 replay context on every fresh slot before the
  ClientHello is processed (`Config.enable_0rtt` is now a complete
  recipe; `Config.early_data_application_context` binds app semantics
  into the digest), and the client recovers from 0-RTT rejection
  in-library — the handshake continues as 1-RTT and staged early data
  is requeued automatically, with the outcome observable via
  `earlyDataStatus()`. Previously the server wrapper could never accept
  early data and a rejected client needed an Internal-tier call to
  survive.
- `Client.Config.new_session_callback`: session-ticket capture that
  hands the application ready-to-persist `tls.resumption_state`
  envelope bytes (ticket + remembered peer transport parameters) —
  the persistence half that `Config.resumption_state` always assumed
  existed.
- `Server.Config.auto_replenish_connection_ids` (on by default when
  `stateless_reset_key` is set): proactive post-handshake
  NEW_CONNECTION_ID top-up so client active migration works against a
  default-configured server. Migration refusals are now typed
  (`MigrationPreHandshake` / `MigrationValidationPending` /
  `MigrationNoFreshPeerCid`) instead of all conflating into
  `PathLimitExceeded`.
- `Connection.negotiatedAlpn()`: the ALPN protocol selected during the
  handshake, for multi-protocol servers.
- Canonical echo examples over real UDP sockets: `examples/echo_server.zig`
  (Server + `runUdpServer` + `on_iteration` event loop, `Slot.user_data`
  per-connection state freed in `on_connection_will_close`, SIGINT
  shutdown) and `examples/echo_client.zig` (Client + `runUdpClient` hook
  state machine), plus `zig build run-echo-smoke` — a one-process binary
  that runs the full stream+DATAGRAM echo round trip on loopback and
  gates CI, so the hostability surface is exercised end-to-end on every
  push.
- `zig build docs`: Zig autodocs for the `quic_zig` module, emitted to
  `zig-out/docs`.
- Exported the shared `boringssl` module instance from build.zig
  (`dep.module("boringssl")`) so consumers can construct
  `tls_context_override` values (private-CA pinning) with correct type
  identity, and added an out-of-tree consumer package
  (`tools/consumer-smoke/`, CI-checked) proving tag consumers can wire
  both modules.

### Fixed

- EMBEDDING.md's raw connection cycle example now compiles and works
  against a real network: it includes the mandatory `conn.advance()`
  handshake kick after `Client.connect`, an `else` arm on the `pollEvent`
  switch (as the forward-compatibility contract requires), the current
  std random API, and the real `resumption_state` config field name.
- Documented the previously-invisible operational contracts: DATAGRAM
  support requires a nonzero `max_datagram_frame_size` transport param,
  local transport-parameter caps (16 MiB windows, 4096 streams, 16 CIDs)
  reject with `error.InvalidValue`, and `handle`/`feed` need a mutable
  buffer. Replaced the data-racing "cooperating task" threading advice
  with the real single-threaded serialization contract, and fixed the
  dangling doc cross-references in EMBEDDING.md/README.md.
- README gained a "Consuming this package" section (exact `zig fetch`
  pin, module wiring, toolchain floor, macOS `COPYFILE_DISABLE=1`) and
  the quick-start now shows the stream write path
  (`openNextBidi`/`streamWrite`/`streamFinish`/`streamReadFin`).

## [0.8.0] - 2026-07-05

### Added

- Added a public API smoke test for the documented 1.0 Stable tier. The test
  compiles against the wrapper/config types, transport helpers, core
  `Connection` loop, lifecycle, stream, DATAGRAM, event payload, and top-level
  re-export surface without introducing a breaking namespace split.
- Added a manual `rc-fuzz` workflow for pre-release gates. It runs unfiltered
  `zig build test --fuzz=1M` by default, uploads the fuzzer cache/crash
  artifacts, and is blocking by design; the weekly fuzz workflow remains
  advisory.

### Changed

- Marked the 1.0 API partition gate satisfied by the audited
  `docs/API_STABILITY.md` tiering plus compile-time smoke coverage. The final
  curated `1.0.0` changelog remains open for the actual RC/final release.

## [0.7.6] - 2026-07-05

### Changed

- Promoted the native `windows-latest` CI leg from advisory to blocking after
  the v0.7.5 release line proved green, and reconciled the 1.0 release
  readiness checklist with the verified quic-go interop and sanitizer state.

## [0.7.5] - 2026-07-05

### Fixed

- Fixed the native Windows CI leg by making interop-helper path tests
  separator-neutral, accepting BoringSSL's platform-specific TLS 1.3 cipher
  preference, skipping std.Io loopback smoke tests that currently hit
  `ConcurrencyUnavailable` on Windows, and keeping ReleaseSafe benchmark
  fixtures out of the default Windows `zig build test` path.

## [0.7.4] - 2026-07-05

### Fixed

- The pinned quic-go hard interop gate now lets the runner own and create its
  log directory, writes the JSON result outside that log tree, and uploads
  both directories from the correct GitHub workspace path.

## [0.7.3] - 2026-07-05

### Fixed

- The pinned quic-go hard interop gate can assume compliance for the pinned
  quic-go peer so the stale runner unknown-testcase preflight does not skip
  the real `H,D` client tests.
- The QNS image workflow now keeps image-build validation blocking while
  gating GHCR publication behind the `QNS_IMAGE_PUBLISH` repository variable,
  avoiding red CI when the package does not grant this repository write access.

## [0.7.2] - 2026-07-05

### Changed

- Repointed `boringssl_zig` to the `v0.6.4` release tag, which keeps the
  GitHub mirror source fetch and adds Windows SDK macro hygiene, no-asm
  fallback, and Winsock linking for BoringSSL native Windows builds.

### Fixed

- Socket-option and ECN helper code now gates POSIX-only cmsg /
  `setsockopt` paths on Windows so `qns-endpoint` reaches the link step on
  Windows instead of failing during Zig source analysis.

## [0.7.1] - 2026-07-05

### Changed

- Repointed `boringssl_zig` to the `v0.6.2` release tag, which keeps the
  sanitizer propagation from v0.6.1 while switching BoringSSL source fetches
  to the GitHub mirror and fixing the standalone consumer build under current
  Zig master.

## [0.7.0] - 2026-07-05

### Added

- Versioned persisted 0-RTT state formats. `quic_zig.tls.resumption_state`
  encodes a strict `QZRS` envelope around BoringSSL session bytes plus the
  remembered peer transport parameters, and `tls.AntiReplayTracker` can now
  `encode` / `restore` a `QZAR` anti-replay snapshot while preserving replay
  and FIFO behavior.
- `-Dsanitize-c=off|trap|full` build option for quic-zig-owned modules, plus
  a Linux CI job that runs `zig build test -Dsanitize-c=full`.
- Blocking quic-go interop workflow for QNS client `H,D`, using a pinned
  quic-interop-runner ref and pinned quic-go image digest. The broader
  advisory interop matrix uses the same pins.

### Changed (BREAKING)

- `Client.Config.session_ticket` and
  `Client.Config.resumption_peer_transport_params` were replaced by
  `Client.Config.resumption_state`. Use `tls.resumption_state.encode` /
  `encodeAlloc` to build the envelope; passing raw BoringSSL session-ticket
  bytes is rejected as `InvalidConfig`.
- `boringssl_zig` is now pinned to the `v0.6.1` release tag instead of a
  bare commit tarball, and quic-zig forwards `-Dsanitize-c` into that
  dependency so the BoringSSL C/C++ libraries are instrumented consistently
  with the Zig wrapper modules.

### Fixed

- `setLocalScid` and `setTransportParams` are now order-independent for the
  Initial Source Connection ID (RFC 9000 §7.3). A low-level caller that sets
  transport parameters before latching its SCID (as the e2e harness and some
  embedders do) previously shipped without an ISCID; the first `setLocalScid`
  now back-fills the ISCID into the already-encoded parameters and re-pushes
  them, so strict peers see it regardless of call order. A caller-supplied
  ISCID is left untouched. `setLocalScid`'s error set is now inferred (it may
  surface the re-push's errors); this only affects code that exhaustively
  switched on its previous `Error` set.

## [0.6.1] - 2026-07-05

### Fixed

- `setTransportParams` now advertises `initial_source_connection_id`
  (RFC 9000 §7.3), filled from the connection's own SCID, so callers of the
  low-level `Connection` API don't have to. Omitting it is a hard handshake
  rejection on strict peers (quic-go closes with TRANSPORT_PARAMETER_ERROR),
  which is why in-tree loopback interop passed while every real foreign peer
  failed. Validated live against webtransport-go.
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
