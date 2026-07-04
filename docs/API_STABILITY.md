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
  `transport.runUdpServer` / `transport.runUdpClient`.
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

### Unstable / evolving — usable, but expect movement

- **Draft extensions:** `quic_zig.lb` (QUIC-LB draft-21),
  `quic_zig.alt_addr` (Alternative Server Address draft-00), multipath
  (draft-21), preferred address, and the QUIC v2 negotiation knobs. These
  track IETF drafts and will change with the draft or on RFC publication —
  see *Draft-extension sunset path*.
- **Recently added surfaces** may see minor signature or naming refinement
  as the downstream layer exercises them for the first time.
- **Config naming** is a known pre-1.0 cleanup target: field names and the
  `null`-to-disable vs `bool` conventions will be normalized before 1.0.
  New `Config` fields are always added with production-safe defaults.

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

## Draft-extension sunset path

The draft-based extensions are pinned to a specific revision via
compile-time constants (`quic_zig.lb`, `quic_zig.alt_addr`). When the
corresponding RFC — or a newer draft — is published:

1. The implementation moves to the new revision.
2. The superseded draft's code path is kept for **one minor release** with
   a deprecation note in `CHANGELOG.md`, then removed.
3. If a wire format changes incompatibly, the new format is introduced
   under a new namespaced entry rather than silently altering the existing
   one, so a deployment can migrate deliberately.

Enabling a draft extension embeds draft-versioned behavior in your
deployment on purpose; treat a draft bump as a coordinated upgrade event,
the same as rotating Retry / NEW_TOKEN / stateless-reset keys.
