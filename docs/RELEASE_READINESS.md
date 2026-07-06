# Release readiness: platform tiers & 1.0 graduation checklist

This document defines what "supported" means per platform and tracks the
concrete gates quic-zig must clear before a 1.0 tag. It is the companion
to [API_STABILITY.md](API_STABILITY.md) (which governs the API surface)
and [SECURITY.md](../SECURITY.md) (which governs vulnerability handling).

## Platform tiers

**Tier 1 — release-gating.** The full `zig build test` suite (Debug +
ReleaseSafe) must pass in CI on every push; a red tier-1 job blocks a
release.

| Platform | Arch | CI | Status |
| --- | --- | --- | --- |
| Linux | x86-64 | `ubuntu-latest` | Gating |
| Linux | aarch64 | (via `ubuntu-24.04-arm` downstream) | Gating |
| macOS | aarch64 | `macos-latest` | Gating |
| Windows | x86-64 | `windows-latest` | Gating |

**Tier 2 — best-effort.** Builds are expected to work but are not
CI-gated. Bug reports accepted; regressions do not block a release.
Other architectures and BSDs fall here.

Windows has been promoted to tier-1 after the native `windows-latest`
`zig build` and `zig build test` leg passed on the v0.7.5 release line.
Real-socket std.Io loopback smoke tests that currently hit
`ConcurrencyUnavailable` on native Windows stay skipped in-tree, but the
package build/test gate itself is blocking.

## 1.0 graduation checklist

A 1.0 tag asserts the API surface is frozen under semver and the library
is safe to embed in production. The gates:

### Correctness & interop
- [x] Foreign-peer interop is a **hard** CI gate, not advisory: the
      `quic-go-interop` workflow is authored and blocking on push / PR,
      using a pinned quic-interop-runner ref and pinned quic-go image for
      QNS client `H,D`. Verified green on `main` at commit
      `6bbc43280383df2f901528a426d6698e78446308`.
- [x] RFC 9000 §10.2 closing/draining edge-case coverage audited and
      backfilled (roadmap H1 #16). Audited; all 7 verified gaps are now
      covered in `tests/conformance/rfc9000_streams_flow.zig`: closing→draining
      on a peer CONNECTION_CLOSE; draining suppresses a queued ACK; draining
      suppresses queued STREAM data; draining sheds keepalive PING; Handshake
      level application close converts 0x1d→0x1c/APPLICATION_ERROR; close
      emission defers to 1-RTT when application write keys exist; and successive
      closing-state CONNECTION_CLOSE retransmits preserve error_code/frame_type.

### Memory safety
- [x] Sanitizer CI scaffold is in place: `-Dsanitize-c=off|trap|full`
      is accepted by quic-zig-owned build modules and Linux CI runs
      `zig build test -Dsanitize-c=full`. The option is forwarded into
      `boringssl-zig` v0.6.4 so the BoringSSL C/C++ libraries are
      instrumented consistently with quic-zig's wrapper modules.
- [x] Deep fuzzing has an explicit pre-release gate. Plain
      `zig build test` runs every `std.testing.fuzz` seed as a deterministic
      smoke test on each push; `.github/workflows/fuzz.yml` remains weekly
      advisory coverage. Before tagging v0.8.0 or a later RC/final release,
      `.github/workflows/rc-fuzz.yml` must pass unfiltered
      `zig build test --fuzz=1M` (or a larger requested budget) and upload
      `.zig-cache/v` for replay. No open crashers are tracked in-tree.

### API surface
- [x] The `Connection` surface is partitioned into Stable / Unstable so
      the semver promise covers only what is meant to be stable (roadmap
      H1 #4). For v0.8.0 this is satisfied by the audited
      `API_STABILITY.md` tiering plus compile-time smoke coverage of the
      documented Stable surface; no breaking namespace split is planned for
      1.0.
- [x] The low-level init-ordering contract is documented and enforced
      (roadmap H1 #9).
- [x] Serialized resumption / anti-replay state format is versioned and
      frozen (roadmap H1 #14): client 0-RTT state uses the strict `QZRS`
      envelope and `AntiReplayTracker` persistence uses `QZAR`.

### Cross-repo hygiene
- [x] `boringssl-zig` is pinned to a tag (not a bare SHA) and a CI lint
      asserts quic-zig and http3-zig pin it byte-for-byte identically
      (roadmap H1 #3).

### Platforms
- [x] Windows `windows-latest` job is green and `continue-on-error` is
      removed (promotes Windows to a hard tier-1 gate). Verified green on
      `main` at commit `6bbc43280383df2f901528a426d6698e78446308`.

### Docs & policy
- [x] `SECURITY.md` present with a disclosure process.
- [x] Draft-extension sunset/tracking policy documented for every pinned
      draft (roadmap H1 #7).
- [ ] `CHANGELOG.md` has a curated `1.0.0` section summarizing the frozen
      surface and any final breaking renames.

## v0.8.0 RC-prep release

v0.8.0 is the final pre-RC hardening release. It validates the API-stability
partition, adds the manual release-blocking fuzz gate, and keeps the actual
`1.0.0` changelog curation open for the RC/final release.

The v0.8.0 code/docs are staged on `main`, but the tag must wait for a
completed external/manual `rc-fuzz` pass. Do not treat a cancelled or
in-harness fuzz run as release evidence.

Check items off as they land; the list is the definition of done for the
1.0 tag.
