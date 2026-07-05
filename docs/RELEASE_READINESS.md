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
      handshake + a request complete against a pinned quic-go server image
      on every push (roadmap H1 #8).
- [~] RFC 9000 §10.2 closing/draining edge-case coverage audited and
      backfilled (roadmap H1 #16). Audited; 4 of 7 verified gaps backfilled
      in `tests/conformance/rfc9000_streams_flow.zig` (closing→draining on a
      peer CONNECTION_CLOSE; draining suppresses a queued ACK; draining
      suppresses queued STREAM data; draining sheds keepalive PING). Three
      remain, each needing more test infrastructure:
      - §10.2.3: an application close (`close(false, …)`) emitted at
        Initial/Handshake level must convert 0x1d→0x1c/APPLICATION_ERROR.
        Needs a connection with Handshake write keys but no application keys.
      - §10.2.1/§10.2.3: with both Handshake and application keys, the close
        emission defers to the application space and preserves the 0x1d
        application variant. Needs the narrow post-1-RTT-key / pre-confirm
        window (handshake keys are discarded at confirmation).
      - §10.2.1 ¶2: successive closing-state CONNECTION_CLOSE retransmits
        carry a byte-identical error_code/frame_type. Needs `open1Rtt` +
        frame-decode of the sealed retransmits to compare.

### Memory safety
- [ ] ASan/UBSan run over the BoringSSL FFI boundary in CI (roadmap
      H1 #1) — the highest-severity untested surface.
- [ ] Fuzz corpus for packet/frame/transport-parameter parsing runs in
      CI with no open crashers.

### API surface
- [ ] The `Connection` surface is partitioned into Stable / Unstable so
      the semver promise covers only what is meant to be stable (roadmap
      H1 #4).
- [ ] The low-level init-ordering contract is documented and enforced
      (roadmap H1 #9 — **done**).
- [ ] Serialized resumption / anti-replay state format is versioned and
      frozen (roadmap H1 #14).

### Cross-repo hygiene
- [ ] `boringssl-zig` is pinned to a tag (not a bare SHA) and a CI lint
      asserts quic-zig and http3-zig pin it byte-for-byte identically
      (roadmap H1 #3).

### Platforms
- [ ] Windows `windows-latest` job is green and `continue-on-error` is
      removed (promotes Windows to a hard tier-1 gate).

### Docs & policy
- [x] `SECURITY.md` present with a disclosure process.
- [ ] Draft-extension sunset/tracking policy documented for every pinned
      draft (roadmap H1 #7).
- [ ] `CHANGELOG.md` has a curated `1.0.0` section summarizing the frozen
      surface and any final breaking renames.

Check items off as they land; the list is the definition of done for the
1.0 tag.
