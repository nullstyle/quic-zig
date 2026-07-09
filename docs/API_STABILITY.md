# API Stability

quic-zig is pre-1.0. Per semver, **any 0.x release may include breaking
changes.** This document exists so a downstream project (notably an
HTTP/3-class layer built on the transport) can judge *which* surfaces are
load-bearing versus volatile, and what the path to 1.0 looks like — not to
promise that nothing moves before then.

At 1.0 the **Stable** tier below graduates to a semver guarantee: no
breaking changes to it without a major version bump. The other tiers carry
no such promise even after 1.0.

## Tiers

### Stable — depend on these freely

These are the intended long-term embedding surface. They may still be
refined before 1.0, but changes will be deliberate, called out in
`CHANGELOG.md`, and kept minimal.

- **Wrappers:** `Server`, `Client`, their `Config` structs, and
  `transport.runUdpServer` / `transport.runUdpClient` — including the
  loops' `on_iteration` application hooks, `Server.Slot.user_data`,
  `Server.Config.on_connection_will_close` (pre-reap ordered-teardown
  hook), and the `Server.nextTimerDeadline` aggregate.
- **Raw connection cycle:** `Connection.handle` / `handleWithEcn`,
  `pollDatagram`, `tick`, `pollEvent`, `nextTimerDeadline`, `isClosed`,
  `closeState`, `phase`.
- **Streams:** `openBidi` / `openUni`, `openNextBidi` / `openNextUni`,
  `localStreamType`, `streamRead`, `streamWrite`, `streamFinish`,
  `streamStopSending`, `streamIterator`, and the `StreamType` classifier.
- **Lifecycle:** `beginGracefulShutdown` / `gracefulShutdownActive`,
  `close`, `ConnectionPhase`, `CloseState`, `CloseEvent`.
- **Datagrams:** `sendDatagram` / `sendDatagramTracked`, `receiveDatagram`.
- **Flow-control introspection** and the qlog-style event callbacks.
- **`ConnectionEvent`** — subject to the forward-compatibility contract
  below.
- **Error set:** the `Error` variants a public method documents it can
  return. New variants may be added (handle errors exhaustively with an
  `else`); existing ones will not be silently repurposed.

`tests/e2e/public_api_smoke.zig` compile-checks the Stable tier above so an
accidental removal of a wrapper, config, lifecycle method, stream/datagram
entry point, event payload, or key top-level re-export fails the normal test
suite.

### Unstable / evolving — usable, but expect movement

- **Draft / evolving extensions:** `quic_zig.lb` (QUIC-LB draft-21),
  multipath (draft-21), `quic_zig.alt_addr` (Alternative Server Address
  draft-00), and the qlog event surface. Each carries an explicit
  disposition (Track-to-RFC vs Experimental/Unstable-with-SLA) — see
  *Draft-extension policy*. Preferred address (RFC 9000 §9.6) and the QUIC v2
  negotiation knobs (RFC 9369) are RFC-anchored on the wire but their
  surface here is still maturing, so they also sit in this tier.
- **Newly added surfaces** may see minor signature or naming refinement
  as they are exercised for the first time.
- **Config naming** follows a settled convention: on/off feature toggles use
  `enable_` (`enable_ecn`), permission grants use `allow_`
  (`allow_no_idle_timeout`), and `null`-to-disable is reserved for caps and
  quotas. A few fields keep intentional semantic prefixes —
  `insecure_skip_verify` (matching common TLS-config naming) and
  `reveal_close_reason_on_wire` (privacy-signalling). New `Config` fields
  follow the same convention and are added with production-safe defaults.

### Internal — do not depend on

- Anything named `_internal`, any file or decl prefixed with `_`, and
  `Connection`'s non-`pub` fields.
- The low-level `frame` and `wire` codecs are exported for tests and
  advanced use, but are **not** covered by the stability guarantee.
- Test-only helpers and fixtures.

## `ConnectionEvent` forward-compatibility contract

`ConnectionEvent` is a tagged union that embedders `switch` over. The
contract, which 1.0 will keep:

- **New variants may be added in a minor release.** Handle unknown
  variants with an `else` branch — a `switch` without one will fail to
  compile against a newer quic-zig, which is the intended signal to review
  it.
- **Existing variant tags will not be removed or repurposed** within a
  release series. A tag's payload shape is stable; if a variant needs an
  incompatible payload it will be introduced as a new tag.

## Config forward-compatibility

New `Config` fields are additive and default to safe, backward-compatible
behavior (the 0.3.0 secure-by-default flips were the deliberate exception,
and were called out as breaking). Existing fields will not silently change
meaning. The naming/semantics normalization noted above is the one planned
pre-1.0 churn to this surface.

## Draft-extension policy

The draft-based extensions are pinned to a specific revision via
compile-time constants. Each carries one of two dispositions so an embedder
knows what kind of change to expect:

- **Track-to-RFC** — actively converging on a standard. The wire is pinned
  to a named draft revision, the API is expected to *graduate to Stable* when
  the RFC publishes, and revision bumps follow the sunset mechanics below.
- **Experimental (Unstable-with-SLA)** — kept in the surface but not
  converging on a near-term RFC. The SLA is narrow: the pinned wire constants
  are correct and tested, but the *API shape may change at any minor release*
  and the surface may be withdrawn. Do not build load-bearing product on it
  without pinning the exact quic-zig version.

| Extension | Wire anchor | Disposition |
| --- | --- | --- |
| QUIC-LB (`quic_zig.lb`) | draft-ietf-quic-load-balancers-21 | Track-to-RFC |
| Multipath | draft-ietf-quic-multipath-21 | Experimental (Unstable-with-SLA) |
| Alternative Server Address (`quic_zig.alt_addr`) | draft-…-00 | Experimental (Unstable-with-SLA) |
| qlog events | qlog event schema | Stable **API** (callback signatures), draft-tracked **schema** (emitted field shape follows the qlog draft) |

Preferred address (RFC 9000 §9.6) and QUIC v2 negotiation (RFC 9369) are
RFC-anchored on the wire; they are listed in the Unstable tier for API
maturity, not draft volatility, and are not part of this table.

### Sunset mechanics (revision bumps)

When a tracked draft moves to a new revision or its RFC publishes:

1. The implementation moves to the new revision.
2. The superseded draft's code path is kept for **one minor release** with
   a deprecation note in `CHANGELOG.md`, then removed.
3. If a wire format changes incompatibly, the new format is introduced
   under a new namespaced entry rather than silently altering the existing
   one, so a deployment can migrate deliberately.

Enabling a draft extension embeds draft-versioned behavior in your
deployment on purpose; treat a draft bump as a coordinated upgrade event,
the same as rotating Retry / NEW_TOKEN / stateless-reset keys.
