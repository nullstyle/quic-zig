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

The one documented exception is the **bundled convenience event loop**:
`transport.runUdpServer` / `runUdpClient` cannot run on native Windows
at the pinned toolchain. This was measured, not inferred — the skips
that used to hide it were deleted and the `windows-latest` leg was
read (2026-08-12). The Zig 0.17.0 release still has the gap: the std
source cited below is unchanged, and the asserting tests still pass on
`windows-latest`.

Cause: every timed receive lowers to `Io.operateTimeout` ->
`Batch.awaitConcurrent`, and std's Windows `net_receive` arm has no
overlapped-I/O path — `Io/Threaded.zig` carries a literal *"TODO
integrate with overlapped I/O or equivalent to avoid this error"* and
returns `error.ConcurrencyUnavailable` instead. Untimed `receive`
does work on Windows, but blocks indefinitely, which would strand
`tick` and with it PTO, the idle timeout, pacing, and `shutdown_flag`.
A timed receive *is* the loop's heartbeat, so there is nothing to
degrade to; the error propagates. Every readiness-wait alternative is
also closed at this pin: `std.posix.poll` is a `@compileError` on
Windows and `ws2_32.pollfd` / `WSAPoll` are not defined (see
`examples/foreign_loop_embedder.zig`).

`enable_ecn = false` is not a workaround — `receiveTimeout` and
`receiveManyTimeout` share the same lowering, so both receive paths
fail identically, and have since before batched receive landed. v0.10.x
is affected the same way.

This is a std gap rather than a quic-zig defect, and it is narrow: the
protocol engine, wire codecs, conformance suite, and TLS handshakes all
genuinely execute on Windows. Windows embedders drive their own loop,
which is the library's primary supported pattern anyway (`EMBEDDING.md`,
`examples/foreign_loop_embedder.zig`). The three tests now **assert**
the documented failure instead of skipping, so if std implements
overlapped `net_receive` the assertion fails and tells us to re-enable
the loop there.

## 1.0 graduation checklist

A 1.0 tag asserts the API surface is frozen under semver and the library
is safe to embed in production. The gates:

### Correctness & interop
- [x] Foreign-peer interop is a **hard** CI gate, not advisory: the
      `quic-go-interop` workflow is authored and blocking on push / PR,
      using a pinned quic-interop-runner ref and pinned quic-go image for
      QNS client `H,D`. This box was first checked on 2026-07-05 against
      a green run at `6bbc432` that had run zero tests, as had every run
      of the gate until 2026-10-03 (see "v0.23.0 toolchain release").
      It is checked now on evidence: the first real pass is run
      37114532615 at `fe6b5b8` (`interop evidence: pairs=1 cells=2
      succeeded=2 failed=0 unsupported=0 skipped=0`), and the wrapper
      fails the gate when that line shows a skipped or failed cell.
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
      `.github/workflows/rc-fuzz.yml` must pass `tools/fuzz-gate.sh`
      (unfiltered `zig build test --fuzz`) at its default budget of 50000
      per site (~2M executions; raise it for an RC/1.0). The script fails
      on a failing site, on a run below 90% of sites x budget, and on a
      missing or zero-`pcs_len` coverage file — the exit status of
      `zig build test --fuzz` reports none of the three — and the
      workflow uploads `.zig-cache/f` and `.zig-cache/v` for replay. No
      open crashers are tracked in-tree. (The gate was blind to a failing
      site from v0.14.0 through v0.22.0; see the v0.23.0 section below.)

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
- [ ] `boringssl` is pinned to a tag (not a bare SHA) in both quic-zig
      and http3-zig, byte-for-byte identically (roadmap H1 #3). Current
      reality (2026-10): the pins have diverged. quic-zig pins bare SHA
      `ff30fe9…` (boringssl 0.6.7, since v0.21.2); http3-zig's main
      still pins `87d15bf…` (0.6.6) beside quic v0.19.0.
      `.github/workflows/pin-lint.yml` is a ratchet: identical pins
      pass, exactly that dated pair passes with a warning, anything
      else fails. Re-check this box when boringssl-zig tags the release,
      both repos repin to the tag (delete the known pair then), and
      http3-zig's `tools/check-boringssl-pin.sh` again lints a tag pin.

- [x] **Toolchain pinning policy is decided and executed.** quic-zig
      tracked Zig master while 0.17 was in development and **pins the
      tagged `0.17.0` release as of v0.23.0**. It stays on tagged
      releases from here; tagged tarballs are retained upstream, so
      the pin no longer has a shelf life.

      The toolchain is named in four places that must agree:
      `mise.toml`, `build.zig.zon` `minimum_zig_version`,
      `tools/consumer-smoke/build.zig.zon`, and the version + per-arch
      SHA-256 in `interop/qns/Dockerfile`. `just check-pins` and the
      `zig-pin` job in `.github/workflows/pin-lint.yml` fail when they
      disagree. That lint exists because they did: in 2026-09 `main`
      sat red for eleven days on a pin that had moved in one place and
      not the others.

      History worth keeping from the master-pin era: ziglang.org
      garbage-collects older master tarballs, and an expired pin
      presents misleadingly — the Docker jobs go red first because
      they have no toolchain cache, while every other leg keeps
      passing off `jdx/mise-action`'s warm cache. If CI ever looks
      broken *only* in containers, check the pin and its digests
      before debugging the container. `interop/qns/Dockerfile` still
      walks Zig's community mirror list, so it tolerates one source
      being down.

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

## v0.23.0 toolchain release

v0.23.0 moves the project off Zig master pins onto the tagged Zig
0.17.0 release, and repairs the release gates it found broken on the
way.

**What the gates had been missing.** From v0.14.0 through v0.22.0 the
pre-release fuzz gate could not fail on a failing fuzz site:
`zig build test --fuzz` exits 0 when a site fails and ends the run
there, and the gate asked only for a non-zero coverage header. All
eight gate runs in that window (v0.14.0, v0.15.0, v0.15.1, v0.16.0,
v0.16.1, v0.17.0, v0.20.0, v0.21.1) logged the same failing site — a
stale close-code invariant in the CID-lifecycle harness, a test defect
and not a protocol one — ran between 1% and 60% of their budget
(18,503 to 1,119,215 executions of about 2M), and passed. v0.18.0,
v0.19.0, v0.21.0, v0.21.2, and v0.22.0 were tagged with no gate run at
all, and v0.22.0 with `test` red on its own commit, because the
toolchain pin had moved in one of its four places and not the others.
No protocol defect is known in any of those tags and none is
withdrawn, but none of them carries the fuzz evidence a tag is
supposed to imply. The last gate run that was what it claimed to be
was v0.13.1's (1,923,878 executions, no failing site).

From v0.23.0: `tools/fuzz-gate.sh` judges a fuzz run on its log and
its coverage header instead of its exit status (failing site, run
count below 90% of sites x budget, missing or uninstrumented coverage
file); `tools/check-zig-pins.sh` fails when the four pin sites
disagree; and the weekly fuzz job no longer reports a failed step as a
green run. Both scripts were mutation-checked before they were
trusted.

The first full-budget gate run since v0.13.1, on the tagged toolchain:
`n_runs=2,075,711 unique_runs=9,326 pcs_len=40,982` across 40 sites,
coverage 3546/40982 (8.65%), no failing site (Linux x86_64, Zig
0.17.0).

**Tagged 2026-10-03 at `d4ba4d9`.** Four of the five gates were real
on that commit: `test` (Linux x86-64 and aarch64, macOS 15 and 26,
Windows, `-Dsanitize-c=full`), rc-fuzz (`n_runs=2,249,381
unique_runs=9,268 pcs_len=40,969`, no failing site), the QNS image
build, and pin-lint. A fresh project then consumed the release tarball
on Zig 0.17.0.

**The fifth gate was empty, and always had been.** `quic-go-interop`
showed green on `d4ba4d9` and had run zero tests. Its log says
"quic-zig client not compliant", then "Not compliant, skipping". Of
its 111 runs since the gate was added on 2026-07-05, 96 reached the
runner, every one of those skipped its only pair, and 93 showed green.
The advisory weekly matrix (`interop.yml`, quic-zig as server) never
had a green job: each of its 21 scheduled runs since the first on
2026-05-10 failed at the matrix step or before it, and
`continue-on-error` showed every one as a green run. Every run whose
log still exists (2026-07-12 on) ran zero tests; that includes the
dispatched run on the commit that made BBRv3 the default (v0.16.0).

The cause is one line in the runner's log bundle: `interface_name
requires Docker Engine v28.1 or later`. The pinned runner's compose
file names the simulator's interfaces. GitHub's ubuntu image carries
Engine 28.0.4. So no container ever started in CI, the runner's
compliance preflight reported that as "not compliant", skipped the
pair, and exited 0. The runner's own workflow installs a newer Engine
for this reason; ours never did. Local runs were real all along,
because the local Engine was newer.

So no tag made since the gate was added carries a real result from
it, v0.23.0 included, and the advisory matrix never passed. Two
release notes cite a CI interop result and are wrong as written: 0.11.0 (CUBIC,
pacing, and HyStart++ as defaults, "validated by the blocking quic-go
interop gate and the weekly matrix") and 0.16.0 (BBRv3 as the default,
"plus the full cross-implementation interop matrix"). 0.7.3 added
`--assume-compliant quic-go` for what it called a stale preflight; the
preflight was not stale. No tag is withdrawn: the code of the v0.23.0
tag is the code the repaired gates then ran on (only CI files, the
wrapper tool, and docs differ), and the results are below.

Repaired after the tag (`fe6b5b8` and the commits that follow it):
both workflows install a current Engine and a host `tshark`; the
wrapper refuses an Engine that is too old, prints what
`docker compose` said when a preflight fails, and reads the runner's
result file after the run, so a skipped cell, a failed cell, or a run
in which nothing succeeded is a failed step. Its tests use the v0.23.0
gate's own result file and the first real matrix result, and 17
mutants of its rules all die. The first attempt at this (`06f3354`)
added a guard that counted cells; a skipped pair is written as cells
with a null result, so that guard could not fail either, and it had
not been mutation-checked.

**The first real results, on the code of the tag.** The release gate
passed in CI for the first time (run 37114532615): quic-zig as client
against the pinned quic-go, handshake and transfer, with the real
preflight. The first real matrix in CI (run 37115312707, quic-zig as
server): quic-go and ngtcp2 passed handshake, transfer, chacha20,
multiplexing, transferloss, and blackhole; quiche passed four, does
not support chacha20, and failed multiplexing (`pairs=3 cells=21
succeeded=19 failed=1 unsupported=1 skipped=0`); goodput was 9.30,
9.16, and 9.11 Mbps on the runner's 10 Mbps link. A local run gave
the same cells. The one failure is old (it is the
same against server images built in May and in August) and its cause
is known: quiche's test client cuts a request short when its send
window is full, and this library's doubling stream credit lets it
burst into that state. The CHANGELOG entry after 0.23.0 has the
detail. The weekly matrix lists that cell as a known failure, in a
list that fails the job when a listed cell passes.

The pattern across all four (the fuzz gate, the weekly fuzz job, the
interop matrix, the interop hard gate) is the same, and it is the rule
this project now applies to its own gates: a run's conclusion is not
evidence. Read the line that counts what ran.

### RC/soak criterion toward 1.0

Between v0.9.0 and the 1.0 RC, the explicit soak gate is: http3-zig
consumes the tag as its pin, ships its socket-backed examples on it, and
one release cycle passes without a Stable-tier breaking-change request.
That makes "distance to 1.0" measurable from this document instead of
implied.

Check items off as they land; the list is the definition of done for the
1.0 tag.
