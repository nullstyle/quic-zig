# Changelog

All notable changes to quic-zig are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [Unreleased]

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
- Removed tracked investigation/status notes that duplicated local
  scratch output or stale matrix history.

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
