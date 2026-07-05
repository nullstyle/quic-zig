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
| Windows | x86-64 | `windows-latest` | **Advisory today; tier-1 target for 1.0** |

**Tier 2 — best-effort.** Builds are expected to work but are not
CI-gated. Bug reports accepted; regressions do not block a release.
Other architectures and BSDs fall here.

Windows is the one platform mid-promotion. The decision for 1.0 is that
Windows is tier-1: the `windows-latest` job runs today with
`continue-on-error: true` so we get signal without gating on a surface
that still has known gaps (socket abstraction, path MTU probing, and the
BoringSSL FFI build under MSVC). Graduating it means removing
`continue-on-error` — tracked as a checklist item below.

## 1.0 graduation checklist

A 1.0 tag asserts the API surface is frozen under semver and the library
is safe to embed in production. The gates:

### Correctness & interop
- [ ] Foreign-peer interop is a **hard** CI gate, not advisory: the
      `quic-go-interop` workflow is authored and blocking on push / PR,
      using a pinned quic-interop-runner ref and pinned quic-go image for
      QNS client `H,D`. This remains open until the first GitHub run proves
      the external runner path.
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
      `zig build test -Dsanitize-c=full`. Full dependency-level sanitizer
      propagation has landed in the sibling `boringssl-zig` workspace and
      can be pinned here after the user publishes a real boringssl-zig tag.
- [ ] Deep fuzzing is scheduled/advisory today, not a release-gating
      corpus job. Plain `zig build test` runs every `std.testing.fuzz`
      seed as a deterministic smoke test on each push; `.github/workflows/fuzz.yml`
      runs unfiltered coverage-guided `zig build test --fuzz=100K` weekly
      with `continue-on-error: true` and uploads `.zig-cache/v` for replay.
      No open crashers are tracked in-tree.

### API surface
- [ ] The `Connection` surface is partitioned into Stable / Unstable so
      the semver promise covers only what is meant to be stable (roadmap
      H1 #4).
- [x] The low-level init-ordering contract is documented and enforced
      (roadmap H1 #9).
- [x] Serialized resumption / anti-replay state format is versioned and
      frozen (roadmap H1 #14): client 0-RTT state uses the strict `QZRS`
      envelope and `AntiReplayTracker` persistence uses `QZAR`.

### Cross-repo hygiene
- [ ] `boringssl-zig` is pinned to a tag (not a bare SHA) and a CI lint
      asserts quic-zig and http3-zig pin it byte-for-byte identically
      (roadmap H1 #3). Do not replace the current bare SHA with another
      bare SHA; this waits for a real boringssl-zig tag.

### Platforms
- [ ] Windows `windows-latest` job is green and `continue-on-error` is
      removed (promotes Windows to a hard tier-1 gate).

### Docs & policy
- [x] `SECURITY.md` present with a disclosure process.
- [x] Draft-extension sunset/tracking policy documented for every pinned
      draft (roadmap H1 #7).
- [ ] `CHANGELOG.md` has a curated `1.0.0` section summarizing the frozen
      surface and any final breaking renames.

Check items off as they land; the list is the definition of done for the
1.0 tag.
