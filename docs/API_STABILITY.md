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
- **0-RTT / early data:** `earlyDataStatus` (and the `EarlyDataStatus`
  enum), `earlyDataReason`, `setEarlyDataEnabled`,
  `streamArrivedInEarlyData`, `setEarlyDataContextForParams`, plus the
  wrapper knobs already covered above (`Client.Config.resumption_state`,
  `Server.Config.early_data`, `Server.Config.early_data_application_context`).
  The rejection contract is part of the surface: rejected early data is
  requeued VERBATIM for 1-RTT (see `requeueRejectedEarlyData`'s CONTRACT
  block) — downstream HTTP/3 early-data support builds on it.
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

- **Draft / evolving extensions:** `quic.lb` (QUIC-LB draft-21),
  multipath (draft-21), `quic.alt_addr` (Alternative Server Address
  draft-00), and the qlog event surface. Each carries an explicit
  disposition (Track-to-RFC vs Experimental/Unstable-with-SLA) — see
  *Draft-extension policy*. Preferred address (RFC 9000 §9.6) and the QUIC v2
  negotiation knobs (RFC 9369) are RFC-anchored on the wire but their
  surface here is still maturing, so they also sit in this tier.
- **Newly added surfaces** may see minor signature or naming refinement
  as they are exercised for the first time.
- **`Connection.stats()` / `ConnectionStats`** (added 0.11.0): the
  whole-connection observability snapshot. Fields may be *added* in any
  minor; existing fields keep their meaning. Promotion to Stable is
  planned once the field set survives one release unchanged.
- **Config naming** follows a settled convention: on/off feature toggles use
  `enable_` (`enable_ecn`) and permission grants use `allow_`
  (`allow_no_idle_timeout`). A few fields keep intentional semantic prefixes —
  `insecure_skip_verify` (matching common TLS-config naming) and
  `reveal_close_reason_on_wire` (privacy-signalling). New `Config` fields
  follow the same convention and are added with production-safe defaults.

- **`?T` is for "no payload supplied", never for "feature off".** A
  nullable field is the right spelling when the feature *is* the payload
  and has no payload-free enabled state: a key (`retry_token_key`), a PEM
  bundle (`client_ca_pem`), a callback (`log_callback`), a context
  override, an optional sub-config (`preferred_address`). There, `null`
  reads unambiguously as "I didn't supply one".

  It is the wrong spelling for anything with a library-recommended
  setting, because `null` then has to mean both "I didn't configure
  this" and "turn it off" — and when the library later changes the
  recommendation, every consumer that mirrored `null` silently loses the
  new behavior. That is exactly what happened when 0.3.0 turned the
  Initial-flood limiter on by default. Such settings use a three-state
  union instead: `Server.RateLimit` (`.default` / `.disabled` /
  `.{ .limit = n }`) for every rate and quota knob, and
  `Server.EarlyData` for the 0-RTT posture, where the unprotected
  variant has to be named rather than reached by forgetting a field.
  Prefer making a dangerous configuration *unrepresentable* over
  catching it with an `InvalidConfig` check.

### Internal — do not depend on

- Anything named `_internal`, and any file or decl prefixed with `_`.
- `Connection`'s fields, with the documented exceptions below. Zig has
  no field-level privacy, so reachability is not permission: treat a
  field as internal unless its own doc comment says otherwise. The
  fields that *are* stable observation points say so explicitly —
  today that is `Connection.last_activity_us` (the connection clock, in
  the same microsecond origin you pass to `handle` / `poll` / `tick`)
  and the mutable posture switches the wrappers thread onto each
  connection (`ecn_enabled`, `reveal_close_reason_on_wire`,
  `delayed_ack_packet_threshold`), which `Server`/`Client` set from
  `Config` and a raw-`Connection` embedder sets directly.
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
meaning.

The naming/semantics normalization that this section previously listed as
planned pre-1.0 churn **landed in 0.10.0** and is now complete: the rate
and quota knobs moved onto `Server.RateLimit`, the 0-RTT pair became
`Server.EarlyData`, `Server.Config.versions` became `accepted_versions`,
and `max_auto_replenish_cids` dropped its platform-width `usize`. See the
0.10.0 CHANGELOG entry for the field-by-field migration. **No further
`Config` renames are planned before 1.0**; from here the surface grows
additively, and a field whose meaning genuinely has to change gets a new
name alongside the old one rather than a redefinition.

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
| QUIC-LB (`quic.lb`) | draft-ietf-quic-load-balancers-21 | Track-to-RFC |
| Multipath | draft-ietf-quic-multipath-21 | Experimental (Unstable-with-SLA) |
| Alternative Server Address (`quic.alt_addr`) | draft-…-00 | Experimental (Unstable-with-SLA) |
| BBRv3 congestion control (`congestion_control = .bbr`) | draft-ietf-ccwg-bbr-06 (behavior only — no wire format, so revision bumps are behavior/API changes and the sunset mechanics below do not apply) | Track-to-RFC (adopted CCWG deliverable; the draft's own intended status is Experimental, and API graduation additionally follows the `CongestionAlgorithm` Unstable-tier soak) |
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
