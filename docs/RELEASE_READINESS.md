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
| Linux | aarch64 | `ubuntu-24.04-arm` | Gating |
| macOS | aarch64 | `macos-15` (`macos-26` advisory) | Gating |
| Windows | x86-64 | `windows-latest` | Gating |

**Tier 2 — best-effort.** Builds are expected to work but are not
CI-gated. Bug reports accepted; regressions do not block a release.
Other architectures and BSDs fall here.

Windows has been promoted to tier-1 after the native `windows-latest`
`zig build` and `zig build test` leg passed on the v0.7.5 release line.
The protocol engine, wire codecs, conformance suite, and in-memory TLS
handshakes therefore genuinely execute on native Windows — this is not
a cross-compile-only claim.

Three real-socket loopback smoke tests are the exception (two in
`tests/e2e/server_loop_smoke.zig`, one in `client_loop_smoke.zig`):
the ones that enter `runUdpServer` / `runUdpClient`. They carry an
unconditional `builtin.os.tag == .windows` skip, so **native Windows
real-socket operation is untested, not known-broken.**

The skip predates the current toolchain pin and its recorded cause no
longer holds: it was attributed to `error.ConcurrencyUnavailable` from
std's `batchAwaitConcurrent`, but at 0.17.0-dev.1683 that function
takes a dedicated Windows branch (`batchDrainSubmittedWindows` +
`NtDelayExecution`) that never returns it — the `ConcurrencyUnavailable`
path is reachable only on wasi and on platforms without `poll`. Note
also that a timed receive needs the same machinery whether it asks for
one datagram or many: `receiveTimeout` and `receiveManyTimeout` both
lower to `Io.operateTimeout`, which is `batch.awaitConcurrent`. So
`enable_ecn = false` was never a Windows escape hatch, and 0.11.0's
move to an always-batched receive did not remove one.

Resolving this means deleting the three skips and reading the
`windows-latest` leg. It is deliberately not bundled into a release
commit, since it can only turn red in CI.

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
      the pinned `boringssl-zig` revision so the BoringSSL C/C++ libraries
      are instrumented consistently with quic-zig's wrapper modules.
- [x] Deep fuzzing has an explicit pre-release gate. Plain
      `zig build test` runs every `std.testing.fuzz` seed as a deterministic
      smoke test on each push; `.github/workflows/fuzz.yml` remains weekly
      advisory coverage. Before tagging v0.8.0 or a later RC/final release,
      `.github/workflows/rc-fuzz.yml` must pass unfiltered
      `zig build test --fuzz` at its default budget of 50000 per target
      (~1.85M executions; raise it for an RC/1.0), assert the coverage
      file's `pcs_len` is non-zero (an uninstrumented run looks green),
      and upload `.zig-cache/v` for replay. No open crashers are tracked
      in-tree.

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
- [ ] `boringssl-zig` is pinned to a tag (not a bare SHA) in both quic-zig
      and http3-zig, byte-for-byte identically (roadmap H1 #3). Current
      reality (2026-08-11): quic-zig deliberately pins bare SHA
      `292c70a2…` — unreleased 0.6.5 carrying the Windows socket link
      fix — while http3-zig pins tag `v0.6.4`. The CI lint half of this
      gate now exists: `.github/workflows/pin-lint.yml` compares the two
      pins on push/PR and weekly, tolerating exactly this known pair (with
      a warning) and failing on any other divergence. Re-check this box
      when boringssl-zig tags v0.6.5, both repos repin to the tag, and the
      known pair is deleted from the lint.

- [ ] **The pinned toolchain is durably obtainable.** It is obtainable
      today but not durably, because the pin tracks Zig *master* and
      ziglang.org garbage-collects older master dev tarballs. Retention
      is finite but not one-deep — measured 2026-08-12, `dev.1683`
      (then current) and `dev.1509` (174 commits back) both returned
      200 while `dev.1252` and `dev.1158` were 404 — so a pin does not
      die the instant master advances; it has a shelf life of some
      hundreds of commits.

      `0.17.0-dev.1252` outlived its. When it went missing the Docker
      jobs (which have no toolchain cache) went red, and every other
      leg kept passing only because `jdx/mise-action` restores a warm
      cache and never re-downloads — meaning an Actions cache eviction
      would have taken all of CI red with no in-repo remedy.

      Two mitigations are in place. The pin moved up to
      `0.17.0-dev.1683+5ceec001b`, which ziglang.org currently serves,
      and `interop/qns/Dockerfile` now walks Zig's community mirror
      list with per-architecture SHA-256 pins so it survives the source
      disappearing again. Neither makes the pin permanent: moving up
      only restarts the same clock.

      Close this properly by pinning a *tagged* Zig release once one
      exists that quic-zig can build against (0.16.0 cannot — HEAD uses
      0.17-only forms), or by vendoring the tarball somewhere the
      project controls. Tagged releases are retained indefinitely,
      which is the only version of this that stays true.

### Platforms
- [x] Windows `windows-latest` job is green and `continue-on-error` is
      removed (promotes Windows to a hard tier-1 gate). Verified green on
      `main` at commit `6bbc43280383df2f901528a426d6698e78446308`.
      Regressed during 0.11.0 (the GSO/GRO cmsg helpers do not compile
      where `std.c.cmsghdr` is `void`) and was fixed in `53c84be`, which
      also added `just check-windows` — the local gate that would have
      caught it, since `zig build -Dtarget=…` alone never compiles the
      test binaries.

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

**Disposition (2026-07-24): shipped untagged, closed.** The v0.8.0
code/docs landed on `main` (`4d295d4`) but the rc-fuzz gate was never
run for that commit, and it has since been superseded by 0.9.0 and the
0.10.0 line. No retroactive tag is planned; the tag-every-release
policy (CONTRIBUTING.md "Releases") applies from v0.10.0 onward. This
item is not awaiting any action.

## v0.9.0 application-readiness release

v0.9.0 closes the 2026-07 embedding-audit gaps (lifecycle events,
hostable loops, ordered teardown, wrapper 0-RTT, default-config client
migration, echo reference examples, autodocs, out-of-tree consumption
checks — see the CHANGELOG entry).

**Disposition (2026-07-24): shipped untagged, closed.** Same as
v0.8.0 — the gate was never run for `2aa11ad` and the release is
superseded. Not awaiting any action.

## v0.10.0 consumer-adoption release

v0.10.0 is the first release cut under the CONTRIBUTING.md "Releases"
policy, and the first to be tagged since v0.7.6. It closes the
private-CA / mTLS gap the capnp-zig downstream audit identified, and
lands the one pre-1.0 `Server.Config` naming/semantics normalization
that `docs/API_STABILITY.md` had reserved — so `Config` field names are
frozen from here to 1.0.

**Tagged 2026-07-29 at `a113cd9`, all four gates green on that commit:**
rc-fuzz, `test` (Linux, macOS, Windows + `-Dsanitize-c=full`),
quic-go-interop, and the QNS image build.

The rc-fuzz pass is worth recording precisely, because it is the first
one this project has ever had that measured anything:
`n_runs=1,858,230 unique_runs=7,830 pcs_len=34,268`, coverage
3182/34268 (9.29%), no crash. `unique_runs` being non-zero is the part
that matters — it means coverage feedback was actually steering input
generation.

It had been failing since 2026-07-09 for a reason that took six
hypotheses to pin down: **coverage-guided fuzzing needs the LLVM
backend.** Zig's fuzzer reads its program-counter range from the
linker-provided `__sancov_pcs*` / `__sancov_cntrs` sections, and only
LLVM emits them (measured on 0.17.0-dev.1252: an x86_64 test binary
built with `-ffuzz` has 0 sancov sections on the self-hosted backend and
2 totalling 89,460 bytes with `-fllvm`). Zig 0.17 defaults x86_64 to
`stage2_x86_64` and aarch64 to `stage2_llvm`, so the gate collected real
coverage on every aarch64 machine we tested and none on x86_64 CI, while
still executing the full budget — so it looked like a real run and then
died reporting `corrupted coverage file ... pcs_len was zero`. `build.zig`
now takes `-Duse-llvm=true` (applied to the unit-test binary only, since
that is where every fuzz target lives) and both fuzz workflows pass it.

Two process notes worth keeping, since the failure was diagnosed wrong
five times first:

- The thing that finally worked was making the gate report its own
  numbers unconditionally (`if: always()` on the coverage check). One
  line of `pcs_len=0` beat weeks of inference from a 24-byte artifact.
- One of those wrong turns was a *bad measurement*, not a missing one:
  `strings | grep sancov` counts the fuzzer runtime's own symbol names
  and so shows a similar count either way, which "refuted" the correct
  hypothesis. Section sizes were the right instrument. A weak
  measurement yields confident wrong conclusions as efficiently as no
  measurement at all.

0.10.0 also re-scoped that gate. It was a `1M` budget (~5 hours) which
made tagging a half-day commitment and is a large part of why v0.8.0 and
v0.9.0 shipped untagged; it is now `50000` (~10 minutes), justified by the
measurement that the long run adds 0.67 percentage points of coverage
over a short one. The gate additionally verifies the coverage file
reports non-zero `pcs_len`, so an uninstrumented run can no longer pass
silently. Deep fuzzing moved to the weekly advisory job, which is the
right home for it: it runs whether or not anyone is cutting a release.

### RC/soak criterion toward 1.0

Between v0.9.0 and the 1.0 RC, the explicit soak gate is: http3-zig
consumes the tag as its pin, ships its socket-backed examples on it, and
one release cycle passes without a Stable-tier breaking-change request.
That makes "distance to 1.0" measurable from this document instead of
implied.

Check items off as they land; the list is the definition of done for the
1.0 tag.
