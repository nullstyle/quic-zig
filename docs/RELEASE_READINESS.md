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
      reality (2026-10-04): the pins are identical again, and both are
      the bare SHA `ff30fe9…` (boringssl 0.6.7; quic-zig since v0.21.2,
      http3-zig since its commit `f2c3805`; it is on quic v0.26.0).
      `.github/workflows/pin-lint.yml` is strict again: identical pins
      pass, anything else fails (the one dated pair that passed with a
      warning while http3-zig was on 0.6.6 is deleted). Check this box
      when boringssl-zig tags the release, both repos repin to the tag,
      and http3-zig's `tools/check-boringssl-pin.sh` again lints a tag
      pin.

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

Measured after that paragraph was written: the cell says little about
quic-zig. With no quic-zig in the pair, the same quiche client fails
the same test against a quic-go server in 4 of 8 runs and against an
ngtcp2 server in 2 of 8, and a trial of "credit returned as streams
close" on our side still failed 8 of 9. A server only changes the
odds. The first version of this record named our stream credit as the
cause and its change as the fix, before the control run (the same test
without quic-zig) had been made. The control comes first.

The pattern across all four (the fuzz gate, the weekly fuzz job, the
interop matrix, the interop hard gate) is the same, and it is the rule
this project now applies to its own gates: a run's conclusion is not
evidence. Read the line that counts what ran.

## v0.24.0 stream-window release

v0.24.0 removes the lifetime stream cap and makes the stream limit a
window. Through v0.23.0 a connection could open 4096 streams of each
type over its whole life, and `initial_max_streams_*` did not bound
how many were open at once, because the limit doubled as it was used.
From v0.24.0 the parameter is the number of streams a peer may have
open at once, an id comes back when a stream is fully closed, and a
connection carries any number of streams. It is a breaking release: in
wire behaviour, in what the two parameters mean, and in two names. The
CHANGELOG has the list, and EMBEDDING.md ("Stream limits are a
window") has what an embedder must do.

**Criteria written before the first change, and what was measured.**

- One connection completes 20,000 bidirectional and 20,000
  unidirectional streams in each direction, with no re-dial: through
  `quic.app.ConnectionDriver` and on bare connections, with late
  replies for streams that are already reaped, in Debug and in
  ReleaseSafe.
- The live peer streams never pass a window of 1, 2, 16 or 100, in
  either direction, for either type, while a greedy peer still fills
  the window (end to end; and a fuzz harness checks "no credit is
  owed" after every operation).
- With the first copy of every MAX_STREAMS frame lost, 2,000 streams
  through a window of 1 still finish.
- `@sizeOf(Connection)` is 154,680 bytes (Debug); it was 156,040.
- The id-space model fuzz ran 1,000,336 executions with no
  disagreement, and every rule of the module has a compiling mutant
  that dies.
- 13 of the 14 virtual-time cells of v0.23.0 are byte-identical. The
  14th (`impairment_bottleneck_10mbit_mux8`) is one datagram shorter:
  the old rule sent two MAX_STREAMS frames for eight streams that were
  never closed.
- A request/reply stream gives its id back two round trips after it
  opens, so a window of W carries about W / (2 x RTT) such streams per
  second: 16.6, 66.2 and 221.5 per second for windows of 1, 4 and 16
  on a 30 ms round trip (the new `churn` bench cells).

**Eight stream faults were fixed on the way**, none of them new in
this release: a lost MAX_STREAMS frame was never sent again; `openUni`
could re-open a finished id; a stream the application stopped reading
never ended; the app driver refused a stream by half; bytes of a reset
stream never went back to the connection window (a long-lived
connection stalled at `initial_max_data`); STOP_SENDING and
MAX_STREAM_DATA were not checked against the stream they name; a reset
after the last acknowledgement left the terminal state; and a local
stream at index 4096 or above was never reclaimed. Ten RFC conformance
tests had been testing bookkeeping types that no connection ran; they
now drive a real connection pair, and for three mutants of the real
flow-control code they are the only tests that fail.

**Interop.** The quic-go and ngtcp2 clients pass `multiplexing`
(2000 streams) against the release's interop server 5 runs of 5 each.
`server x quiche x multiplexing`, which had failed in every run on
record, passes 6 runs of 10 (13 of 20, with ten more runs made after
the release commit). "Every run" had one cause: the stream
window of our interop server was 1000, and the other two servers use
100. quiche's test client drops what a short request write did not
take, its send window starts at its first congestion window (13,500
bytes), and a first flight of 1000 requests crosses that near request
486: in each of 10 runs at a window of 1000, the first request cut was
the one that crossed byte 13,500. It took both changes of this release
to move the cell (window 100 with the old doubling rule: 0 of 3; window
1000 with credit on close: 0 of 10). What is left is the client's own
failure rate, which it shows against the other servers too (4 of 8
against quic-go, 2 of 8 against ngtcp2, with no quic-zig in the pair).
So the cell is in a new class of the wrapper, `--flaky`: it is run,
counted (`flaky_passed` / `flaky_failed` on the evidence line) and
named, and it cannot decide a run in either direction. No cell is a
known failure now. As a client, the release passes the same 18 of 21
cells against quic-go, ngtcp2 and quiche servers as v0.23.0 did; the
`zerortt` cell fails against each (see "On record"). The CI
matrix results are with the gates, below.

**The gates on the release commit.** Tagged 2026-10-03 at
`1d34b32`. All five gates ran on that commit, and each was read at its
evidence line, not at the colour of its run.

- `test`: six jobs (Linux x86-64 and aarch64, macOS 15 and 26, Windows,
  `-Dsanitize-c=full`), every step green. The four Unix jobs ran
  1,811 tests in Debug (16 skipped) and 1,771 in ReleaseSafe; the
  Windows job ran 1,748 in each mode (39 skipped); the sanitizer job
  ran the 1,811.
- rc-fuzz: `n_runs=2,068,452 unique_runs=10,655 pcs_len=41,855` across
  41 sites (floor 1,845,000), coverage 4110/41855 (9.82%), no failing
  site.
- `quic-go-interop` (quic-zig as client against the pinned quic-go,
  handshake and transfer, `--strict`): `interop evidence: pairs=1
  cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0 skipped=0
  flaky_passed=0 flaky_failed=0`.
- QNS image: built from that commit (a real build, not a cache hit).
- pin-lint: `zig pins agree: 0.17.0`; the boringssl pin differs from
  http3-zig's main by the one dated pair the lint tolerates.

The matrix dispatched on the same commit (run 37149749367; quic-zig as
server; handshake, transfer, chacha20, multiplexing, transferloss,
blackhole, and the goodput measurement; quic-go, quiche and ngtcp2
clients) ended with `interop evidence: pairs=3 cells=21 succeeded=19
failed=0 known_failed=0 unsupported=1 skipped=0 flaky_passed=1
flaky_failed=0`. quic-go and ngtcp2 passed all six tests. quiche
passed five and does not support chacha20; its `multiplexing` pass is
the flaky cell, and the first time that cell passed in CI. Goodput on
the runner's 10 Mbps link: 9.30 Mbps to quic-go, 9.12 to quiche, 9.18
to ngtcp2 (v0.23.0: 9.30, 9.11, 9.16). A wider matrix on the commit before
the version line (run 37149418254 on `cf5bf7c`: 16 tests, 48 cells)
ended with `interop evidence: pairs=3 cells=48 succeeded=43 failed=0
known_failed=0 unsupported=4 skipped=0 flaky_passed=1 flaky_failed=0`.
It is the first run of that matrix with no failed cell. On the v0.23.0
code the same matrix (run 37137087184) had `succeeded=42 failed=1
known_failed=1`. Two cells changed: `quiche:multiplexing` (a pass
now), and `quic-go:retry` (it failed that once, passes now, and passes
5 runs of 5 on a developer machine with either code: not reproduced).

**On record, not done.** The loss and reorder bench cells have a long
tail (`impairment_reorder10pct` took more than a second in 4 of 24
seeded runs, with no loss in the cell). The QNS client sends no 0-RTT
data in the `zerortt` test against any of three servers. The interop
server answers one datagram at a time, so it sends one response per
packet to a client that sends one request per packet. The bench
harness makes its handshake without packets. Each is a candidate for
the next sprint; none is new in this release.

Found after the tag, and also not new: `server x quic-go x
handshakecorruption` fails about 2 runs in 5. A second run of the wide
matrix on the release's server code (run 37155539640) had that one
failed cell (`succeeded=42 failed=1`), where the first had none. On a
developer machine the cell failed 2 runs of 5 on the v0.24.0 code and
2 of 5 on the v0.23.0 code: quic-go's client gives up on one of the 50
handshakes the test makes through 30% packet corruption. One green run
of the wide matrix was read as "no failed cell", which was true of the
run and not of the code. It is the same kind of fault as the long tail
above, with a cheaper way to see it. Also after the tag, a stream
window of 20 for the interop server was tried and taken back the same
day: it made the quiche cell pass 15 runs of 15 and made `zerortt`
fail for every client (the CHANGELOG has both stories).

## v0.24.1 build-option release

v0.24.1 changes no library code: `src/` is the same as in v0.24.0. It
makes the package accept the `optimize` build option, which its own
documentation had told consumers to pass.

**What was wrong, and for how long.** The package builds in Debug or
in ReleaseSafe and nothing else, so its mode option was the boolean
`release`. README.md and EMBEDDING.md showed
`b.dependency("quic", .{ .target = target, .optimize = optimize })`.
Zig reports an unknown dependency option
(`error: invalid option: "optimize"`), goes on, and exits 0; quic-zig
then built in its default mode. Measured on the v0.24.0 tarball with
`zig build --verbose -Doptimize=ReleaseSafe` in a fresh consumer:
`-Osafe` for the application, `-Odebug` for `quic` and for
`boringssl`. A consumer that followed the docs, or passed no mode,
shipped a Debug QUIC stack and a Debug BoringSSL inside its release
build, unless it was built with `zig build --release`. Every
downstream checkout read on 2026-10-03 does one or the other. This is
as old as the build-mode policy; any performance number a consumer
took that way is a Debug number.

**Why nothing caught it.** The in-tree consumer smoke had the same
wrong line. CI ran it in Debug only and read its last line
(`consumer-smoke ok`), and the step printed the `error:` line above in
every run and passed. It was found the day v0.24.0 shipped, by
building a fresh consumer of the published tarball and reading all of
its output. That is the fifth green signal in this record that said
nothing (the fuzz gate, the weekly fuzz job, the interop matrix, the
interop hard gate, and this step).

**What v0.24.1 does.** `optimize` is an option: Debug gives Debug,
ReleaseSafe gives ReleaseSafe, ReleaseFast and ReleaseSmall stop the
build with the build-mode message. `release` works as before, and a
release asked for by either option is a release.
`tools/consumer-smoke/check-modes.sh` is the contract as a consumer
sees it (both spellings, three application modes, nothing compiled;
it fails on any `invalid option` line), and CI runs it. Five mutants
of the mode rule, the v0.24.0 behaviour among them, each fail the case
they should.

**The gates on the release commit.** Tagged 2026-10-03 at `4564995`,
each gate read at its evidence line.

- `test`: six jobs, every step green; 1,811 tests in Debug and 1,771
  in ReleaseSafe on the four Unix jobs, 1,748 on Windows; in the
  consumer-smoke step, `check-modes: 6 of 6 as expected` and no
  `invalid option` line.
- rc-fuzz: `n_runs=2,066,947 unique_runs=10,204 pcs_len=41,855` across
  41 sites (floor 1,845,000), no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0 skipped=0 flaky_passed=0
  flaky_failed=0`.
- QNS image: built from that commit.
- pin-lint: `zig pins agree: 0.17.0`.

The matrix dispatched on the same commit (run 37165403359; quic-zig as
server; 7 tests; quic-go, quiche and ngtcp2 clients): `interop
evidence: pairs=3 cells=21 succeeded=19 failed=0 known_failed=0
unsupported=1 skipped=0 flaky_passed=1 flaky_failed=0`.

A fresh consumer outside the repository, with the `optimize` spelling
and `-Doptimize=ReleaseSafe`: built from the
published tag tarball (hash
`quic-0.24.1-DnSYvRqMNADDwuJG9qlOxfaaUIGacBiERjfZ5DINt3RH`), it
compiled with `-Osafe` for the application, for `quic` and for
`boringssl`, printed no `invalid option` line, and ran
(`consumer-smoke ok: quic-zig 0.24.1`). The same consumer passes the
six build-mode checks.

## v0.25.0 no-stalls release

v0.25.0 is about one sentence: a connection must not stall, and must
not die, because packets were lost, damaged or many. It has a
security fix that every older release needs, six fixes for the
handshake under loss, and one for a large window. It records five
faults and limits that it found and did not fix, and one fix that it
tried and took back.

**The security fix, and why nothing had found it.** `Connection.handle`
returned an error for a packet whose header did not parse, and an
error from `handle` ends the connection (`Server.feed` closes it; the
bundled client loop returns). Nothing had authenticated those bytes. A
datagram of 12 bytes with a connection ID in it closed an open
connection. The code is in every tag. Three things should have found
it and did not:

- The fuzz harness for the receive path seals its packets, and takes
  every error but `OutOfMemory` as fine.
- The interop runner's `handshakecorruption` test changes one byte in
  the first 51 bytes of a datagram. The changed datagram does not
  reach the endpoint: in a local run with 336 corrupted datagrams
  neither end saw one packet that failed to decrypt. The UDP checksum
  removes them. To the endpoints that test is a loss test.
- No test gave a damaged datagram to `handle`.

It was found by writing the test that `handshakecorruption` means to
be: one changed byte, or a cut, in each of the first datagrams of a
handshake, with a real server and client in memory. 75 of 2448 cases
ended the connection. The same sweep then found that the server kept a
client connection ID that it had read from a datagram that did not
authenticate. There is now a fuzz harness for bytes that do not
authenticate (the gate counts 43 sites). Those are the sixth and the
seventh green signal in this record that said nothing: a fuzz harness
that takes every error as fine, and a corruption test whose corruption
does not arrive.

**How the handshake faults were found.** One was measured before the
sprint (`server x quic-go x handshakecorruption` failed about 2 runs
in 5). The others were found one failed run at a time. A run that
failed after a fix was not taken as "the remaining failure rate": its
capture was read (the simulator's verdict for each datagram, the
client's log, the packets). Three times it showed a stall of ours, and
each became a fix: a lost HANDSHAKE_DONE that the server sent again
only at 2, 10 and 43 s; a 1-RTT probe before the handshake was done,
which took the one datagram the network let through; and Initial
packets sent long after RFC 9001 section 4.9.1 says to stop, which a
quiche client answers by dropping the whole datagram.

**One fix was wrong, and the same method found that too.** A failed
run suggested that a handshake probe should repeat its ACK. It was
built, passed its unit tests and 8 mutants, made one e2e scenario
faster, and left the bench cells as they were. One CI matrix run on
it was green. The local batch on it passed 1 run of 4: for a peer
whose first copy of the ACK was lost, the repeat is the first
acknowledgement, and a first round-trip sample is not corrected for
ACK delay (RFC 9002 section 5.3). A quiche client's estimate went to
1048 ms on a 38 ms path, and its close took 10.5 s. The change was
taken back the same day, and the reason is written where the change
would go (`firePtoAtLevel` in `src/Connection/loss.zig`). A fix that
comes from one failed run of an intermittent cell is not a fix until
the batch has run on it, and one green matrix run is not that batch.

**Old faults that the reading turned up, not fixed here.** The Retry
token has no room for a first connection ID of 19 or 20 bytes (the
`retry` cell with a quic-go client failed in exactly those runs: 2 of
6 on this release, 2 of 14 on v0.24.1). The interop client fails
`keyupdate` against quic-go (4 runs of 4, on v0.24.1 too) and does
not implement the two handshake-loss cells. All are in the CHANGELOG
under "Measured, not changed" or in its test notes.

**The pass criteria, as written before the work, and what happened.**

- S1 (quic-go x `handshakecorruption` and x `handshakeloss`, local,
  20 runs of each, all pass): met. 20 of 20 and 20 of 20 on the
  release code (13 and 12 of 20 on v0.24.1), and a passing run takes
  40 to 41 s where it took 75 to 78 s (medians). It is not a property
  the test can promise: on the code two fixes earlier it was 19 and
  18 of 20, and each of those three failed runs was the network
  losing every copy of a flight inside the 5 s that quic-go gives a
  handshake. With an ngtcp2 client: 5 of 5 and 5 of 5 (v0.24.1: 5 of
  5 and 4 of 5).
- Not a criterion, and not as good: with a quiche client the two
  cells passed 14 of 15 and 16 of 20 runs (v0.24.1: 5 of 5 and 4 of
  5). This release is not shown to be better with quiche. The five
  failed runs on the release code were read. In one the server never
  got a ClientHello (all five copies lost). In one every Handshake
  packet of the client was lost. In three the client's Finished was
  lost three times in 42 s, and each probe of the client in between
  was lost or the server's ACK for it was; one ACK more would have
  told the client at once that its Finished was lost. That is the
  repeat that was tried and taken back (above), so this is open. The
  one failed run on v0.24.1 was the stall that this release removes
  (an ACK alone for each retry of the client).
- S2 (flight lost 5 times, done before the server's second probe
  timeout): met. Done at 36 ms; the code before never finished.
- S3 (never more than 3 times the bytes received from an unvalidated
  address): met; every run of `tests/e2e/handshake_loss.zig` checks it
  from the outside.
- S4 (10,000 small packets with no ACKs: no error, the connection
  stays open, and it finishes when ACKs come): met.
- S5 (no run of the reorder or 5% loss cell more than 3 times the
  cell's median): NOT met for the reorder cell, and not attempted.
  The cause was found: the cell reorders by more than the fixed loss
  thresholds allow, so 10% of the packets are declared lost although
  all arrive, and every controller slows down as for real loss. The
  cure is a feature. By the rule set before the sprint, that track
  stopped there.
- S6 (the other virtual-time cells byte-identical or explained): met.
  The 17 older cells print the same line as on v0.24.1.
- S7 (five gates real on the release commit; the wide matrix, both
  roles): the five gates are real. The matrix ran in both roles and
  was read; it is not all green. Both are below.

**The gates on the release commit.** Tagged 2026-10-04 at `67f0fea`,
each gate read at its evidence line.

- `test`: six jobs, every step green; 1,859 tests in Debug and 1,819
  in ReleaseSafe on the four Unix jobs, 1,796 on Windows; in the
  consumer-smoke step, `check-modes: 6 of 6 as expected` and no
  `invalid option` line.
- rc-fuzz: `n_runs=2,164,314 unique_runs=13,100 pcs_len=42,647` across
  43 sites (floor 1,935,000), no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0 skipped=0 flaky_passed=0
  flaky_failed=0`.
- QNS image: built from that commit.
- pin-lint: `zig pins agree: 0.17.0`.

The wide matrix, quic-zig as server, 16 tests, quic-go, quiche and
ngtcp2 clients. Two runs on the release commit:

- Run 37192405690: `interop evidence: pairs=3 cells=48 succeeded=43
  failed=0 known_failed=0 unsupported=4 skipped=0 flaky_passed=0
  flaky_failed=1`.
- Run 37192403891: `interop evidence: pairs=3 cells=48 succeeded=42
  failed=1 known_failed=0 unsupported=4 skipped=0 flaky_passed=1
  flaky_failed=0`.

The failed cell of the second run is `quiche:handshakeloss`. Its
capture is in the run's artifact and was not read (this session
downloads nothing). The same cell on the same code has 20 local runs
(8 of them made after that CI run), and each failed one was read: see
"Not a criterion" above. The cell that the first run names as flaky is
`quiche:multiplexing`, as in every release since v0.24.0.

Two runs on the same code a few commits earlier: run 37187540007
(`6a2426b`), `interop evidence: pairs=3 cells=48 succeeded=43 failed=0
known_failed=0 unsupported=4 skipped=0 flaky_passed=1 flaky_failed=0`;
and run 37184022357 (`729e54e`), `succeeded=42 failed=1` with
`quic-go:retry` (the Retry token, above).

The same tests with quic-zig as the client, local, against the three
servers: `interop evidence: pairs=3 cells=45 succeeded=33 failed=4
known_failed=0 unsupported=8 skipped=0 flaky_passed=0 flaky_failed=0`.
The four are `zerortt` against each server and `keyupdate` against
quic-go, and both fail the same way with the v0.24.1 image.

A fresh consumer outside the repository, built from an archive of the
tag (`git archive`, the files of the tag tarball; hash
`quic-0.25.0-DnSYvcRANgAnmiJVo3UPd3XOuezmr8Ia1mXeqXgow4vw`), with
`.optimize = optimize` and `-Doptimize=ReleaseSafe`: it compiled with
`-Osafe` for the application, for `quic` and for `boringssl`, printed
no `invalid option` line, and ran (`consumer-smoke ok: quic-zig
0.25.0`).

## v0.26.0 small-repairs release

v0.26.0 is about one sentence: a connection that a correct peer starts
must come up, and a close in the handshake must reach the peer. It
has no security fix. It repairs five rules of RFC 9000 and RFC 9001
that were missing or wrong, and it records five faults and limits
that it found and did not fix.

**What was repaired, and how each was found.**

- The Retry token had room for 45 bytes of client address and
  connection IDs. An IPv6 client with a first connection ID above 14
  bytes got no Retry. Known since v0.25.0 (the `retry` cell with a
  quic-go client failed in exactly the runs with a 19 or 20 byte ID).
  A test through `Server.feed` for every legal length was red for 6
  of 26 cases, and the larger token (114 bytes) made a second,
  hand-written copy of the old size panic in the send path. There is
  one constant now.
- A handshake datagram could be longer than 1200 bytes (1353 and 1310
  measured), a server's first flight was never padded, and a client's
  Initial packet with only an ACK came out at 1201 bytes. A size check
  at the end of every run of `tests/e2e/handshake_loss.zig` was red
  for 19 of its 20 tests. An older test in the repository recorded a
  real path that lost the 1353-byte datagram; it held the recovery,
  not the cause.
- Three connection-ID checks of RFC 9000 section 7.3 were missing,
  and a client took the Source Connection ID of every Initial packet
  that authenticated. Found by reading; each has a red-first test.
  The first version of the check closed 22 e2e tests of ours: a
  server built on a bare `Connection` never sent
  `original_destination_connection_id`, and our own client had not
  looked. The library fills it in now.
- A CONNECTION_CLOSE during the handshake went at one level, and a
  peer in the middle of the handshake could not read it. Found by a
  test written for it (`tests/e2e/handshake_close.zig`).
- A key update was allowed one flight before the handshake was
  confirmed. This was the cause of an interop failure that had no
  known cause (the client role, `keyupdate` against quic-go, 4 runs
  of 4 on two releases): the interop client asked that early, its
  first 1-RTT packet was in key phase 1, and the runner could not
  read the capture after that.

**What the interop client could not do before.** It could not run
`multiconnect`, so the two handshake-loss tests never ran in the
client role. They run now, and the first run under 30% loss found a
fault in the library within 39 downloads (a lost NEW_CONNECTION_ID
for a retired ID was issued again and ended the connection). The
client's `zerortt` test failed against every server because the
client did not keep the server's transport parameters with the
session; that is in the interop program, and the library gap behind
it (the number of 0-RTT streams is not bounded) is recorded.

**Found and not fixed.** All are in the CHANGELOG under "Measured,
not changed", with their numbers.

- A client retries a silent handshake with one datagram for each
  probe timeout (1, 3, 7, 15 s). Against a quic-go server, which
  gives up after 5 s of silence, the client role passed
  `handshakeloss` in 5 runs of 10 and `handshakecorruption` in 2 of
  10. All 13 failed cells were read and are this one cause.
- Against a quiche server (8 of 10 and 8 of 10): three failed cells
  are a ServerHello that quiche sends again only at 1, 5 and 21 s,
  whatever the client sends; one is a Handshake packet that arrived
  before its keys and was dropped.
- A lost CONNECTION_CLOSE is in practice not sent again.
- Remembered transport parameters do not bound the number of 0-RTT
  streams.

**The pass criteria, as written before the work, and what happened.**

- S1 (Retry for all 26 cases; quic-go x `retry` 20 of 20; the interop
  endpoint never exits on client input): met. 20 of 20, with a 19 or
  20 byte ID in 4 of the runs.
- S2 (no handshake datagram above 1200 bytes; a server datagram with
  an ack-eliciting Initial packet is 1200; at most 3 times the bytes
  received): met, checked in every run of the handshake-loss tests.
  A no-loss flight is 1 datagram of 1200 bytes with the small
  certificate (was 831), 3 with the wide one, 6 with the largest.
- S3 (quic-go x `handshakecorruption` and x `handshakeloss`, 20 local
  runs each, at least 19 of 20, a median of at most 45 s, no failed
  run a stall of ours): met on the release code. 20 of 20 at 37.3 s
  and 19 of 20 at 42.1 s. The failed run: the simulator dropped all
  six datagrams of the server for one connection inside the 5 s that
  the quic-go client waits. A batch on the code after the
  datagram-size change had the same counts and the same reading.
- S4 (the connection-ID tests pass for both roles; the wide matrix in
  both roles has no cell that passed on v0.25.0 and fails now): met.
- S5 (the peer has the error code of a handshake close within one
  round trip, each phase, each role): met.
- S6 (the gated experiment, an ACK repeat in the Handshake space
  alone): not met, and the change is not in the code. It was
  built on its own branch after the release commit (4 unit tests, 7
  mutants killed). The plan asked for four numbers on a batch with a
  quiche client; one is "no round-trip estimate above 1 s in any quiche
  log". Run 3 broke it: the repeat was the client's first sample,
  2.137 s on a 30 ms path, its probe timer went to 6.4, 12.9 and
  25.7 s, and its connection timed out with no file. The batch was
  stopped at 9 runs (7 passed; the second failed run lost all five
  copies of its ClientHello). The idea was that a peer in the
  Handshake space has a sample from the Initial space. It has none
  when the datagram with the one Initial ACK was lost. The note is at
  `firePtoAtLevel` in `src/Connection/loss.zig`, and the CHANGELOG has
  it under "Unreleased".
- S7 (the client role runs the two handshake-loss tests against three
  servers, 5 runs each, every failed run read; `zerortt` passes or
  the cause is written down; the cause of `keyupdate` against quic-go
  is written down): met. Both now pass (3 runs of 3 against each
  server).
- S8 (the 18 virtual-time bench cells print the same lines, or each
  difference is explained): met. The same lines as on v0.25.0 after
  the datagram-size change, after the connection-ID change, after the
  close change, and on the release code.
- S9 (five gates real on the tag commit; the wide matrix in both
  roles, two runs of the server role; a mutant for every new guard;
  the fuzz gate counts at least 43 sites):
  met. The gates and the matrix are below. 51 mutants
  for the release, each killed by a test (one lived at first and got
  its test), and 7 more for the experiment. The fuzz gate counts 43
  sites.

**The gates on the release commit.** Tagged 2026-10-04 at `6c1dc5b`,
each gate read at its evidence line.

- `test`: six jobs, every step green; 1,903 tests in Debug and 1,863
  in ReleaseSafe on the four Unix jobs, 1,840 on Windows; in the
  consumer-smoke step, `check-modes: 6 of 6 as expected` and no
  `invalid option` line.
- rc-fuzz: `n_runs=2,224,649 unique_runs=11,985 pcs_len=43,417` across
  43 sites (floor 1,935,000), no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0 skipped=0 flaky_passed=0
  flaky_failed=0`.
- QNS image: built from that commit.
- pin-lint: `zig pins agree: 0.17.0`.

The wide matrix, quic-zig as server, 16 tests, quic-go, quiche and
ngtcp2 clients, in CI:

- Run 37242740162, on the release commit: `interop evidence: pairs=3
  cells=48 succeeded=43 failed=0 known_failed=0 unsupported=4
  skipped=0 flaky_passed=0 flaky_failed=1`.
- Run 37240916279, on `3a9f95d` (the commit before; the same source):
  the same line.

The cell that both runs name as flaky is `quiche:multiplexing`: it
failed in both, as it does in a part of the runs of every release
since v0.24.0 (the record of v0.24.0 has the cause). Its captures are
in the artifacts of the runs and were not read (this session
downloads nothing); the same cell passed in the local run below. No
other cell failed.

The same tests without the goodput measurement, local, on the image
of the release code (`3a9f95d`). quic-zig as the server: `interop
evidence: pairs=3 cells=45 succeeded=41 failed=0 known_failed=0
unsupported=4 skipped=0 flaky_passed=0 flaky_failed=0`. quic-zig as
the client against the three servers: `interop evidence: pairs=3
cells=45 succeeded=43 failed=0 known_failed=0 unsupported=2 skipped=0
flaky_passed=0 flaky_failed=0` (v0.25.0: 33 passed, 4 failed, 8 not
supported). One run of each; the client role's two handshake-loss
cells passed in that run and do not pass every time (above).

A fresh consumer outside the repository, built from an archive of the
tag (`git archive`, the files of the tag tarball; hash
`quic-0.26.0-DnSYvXvxNwDWO2vGjU5Puuv1FlpgAmBahRmUxawCD_KE`), with
`.optimize = optimize` and `-Doptimize=ReleaseSafe`: it compiled with
`-Osafe` for the application, for `quic` and for `boringssl`, printed
no `invalid option` line, and ran (`consumer-smoke ok: quic-zig
0.26.0`).

## v0.27.0 ticket-keys release

v0.27.0 is about one sentence: a server that restarts, or reloads its
certificate, must still accept the session tickets that it gave out,
and a client's early data must go early also when the server answers
with a Retry. It has no security fix, and it removes nothing. Every
item was asked for by a downstream (the handoff of capnp-zig, five
asks) or was found in the sprint before (the number of 0-RTT
streams).

**Measured before it was planned.** A probe at the public wrappers: a
first connection earns a ticket, a second one resumes with 11 bytes
of early data, and the probe looks at WHEN the server can read them.

    same server                         before its handshake is done
    a new server ("restart")            after  (0-RTT rejected)
    a new server, the same ticket key   before
    a new server, another key           after
    a .pem reload                       after
    a .pem reload, the key set again    before
    a resumed dial behind a Retry       after  (client: "accepted")

So a restart and a certificate reload cost every client one full
handshake and its 0-RTT, one 48-byte key was all that was missing, and
the client's word "accepted" does not say that its early data went
early. That last line is why every test of this release looks at the
moment at which the server can read, and not at the client's status
alone.

**What was built.**

- `Server.Config.session_ticket_key`, installed where the Server
  builds a TLS context, so a `.pem` reload cannot lose it. Three
  pairs are refused: a zero key, a key with a context of the
  embedder, and a key with the replay tracker (the tracker is process
  memory; after a crash a recorded 0-RTT flight would be fresh again
  for the 60 s that BoringSSL allows a ticket age to be off).
- `Server.rotateSessionTicketKey`: the Server keeps two keys and
  gives BoringSSL its ticket-key callback. One question was open in
  the plan ("not measured, and it matters"): does a ticket that is
  opened with the PREVIOUS key through the callback keep its 0-RTT?
  It was measured before the Server was touched: yes, and tickets
  sealed by the callback open with BoringSSL's own key setter and the
  other way round. The old key is cleared one ticket lifetime after
  the rotation. That is not tidiness: whoever has a ticket key can
  make tickets, and with client certificates that is a session for
  any client identity.
- `Server.Config.session_ticket_lifetime_s`.
- A client sends its 0-RTT data again after a Retry, and
  `Connection.retryAccepted()`.
- Remembered transport parameters also limit the number of 0-RTT
  streams. This one broke 21 unit tests of our own: seven test
  helpers gave a hand-built connection its send credit through
  remembered parameters with flow limits only. An embedder that calls
  the function by hand can meet the same; it is the one "can need a
  change" item of the release.
- Three doc repairs. One of them was advice of ours that would have
  cost a follower the server's TLS posture (use `.override` to carry
  ticket keys).

No change in boringssl-zig was needed (the raw layer has every
function), so no pin moved and http3-zig was not touched.

**What the mutants found.** 54 mutants, all killed in the end, and
the first runs earned their cost:

- Three mutants that took the wrong 16 bytes of the key for the HMAC
  or for AES passed every test. The end-to-end test keys were 48
  equal bytes, so every part of a key was the same. A callback with
  the key parts swapped would have shipped green. The keys have three
  different parts now, and a comptime check holds that.
- A mutant with a fixed IV passed: no test looked at the IV.
- Two guards could not be made to fail by any test (a read-back of
  what was just set). One became a function with its own test; the
  other was removed.
- Two "survivors" were the mutant runner: it did not count a leaked
  allocation as a failed test.

The first point is the eighth green signal in this record that said
nothing: a test of a structured secret with a key that has no
structure.

**The pass criteria, as written before the work, and what happened.**

- S1 (a ticket of server A is taken by a new server B with the same
  key, with 0-RTT; not with another key or none; the same across a
  `.pem` reload; the three refusals): met.
- S2 (a ticket older than the lifetime is not resumed, a younger one
  is; the TLS clock moved in the test): met. With a lifetime of 10 s:
  taken at 9 s, refused at 10 s; with none set, taken at 10 s.
- S3 (after one rotation a ticket of the old key resumes; a second
  rotation, or one lifetime, ends that; a `.pem` reload keeps both
  keys; what the previous key gives is measured): met. It gives
  0-RTT.
- S4 (behind a Retry the server reads the early data before its
  handshake is done; nothing is counted as lost; packet numbers do
  not go back): met.
- S5 (a resumed client cannot open more early streams than it
  remembers; after the handshake the real limits hold): met.
- S6 (no setting = no change: the 18 bench cells print the same
  lines as on v0.26.0; the resumption and zerortt interop cells pass
  in both roles): met.
- S7 (capnp-zig's own suite on the branch): NOT met at
  the tag. The capnp-zig session was asked to run its suite against
  an archive of the branch and had not answered when the gates were
  green. What stands in for its answer, and is less than it:
  capnp-zig's sources (its commit `e416dd3`) were read against the
  changes. It does not call `setRememberedPeerTransportParams`. Its
  bridge sets the key with BoringSSL's plain setter on
  `server.tls_ctx.inner` and reads the field `retry_accepted`; both
  names are unchanged, and a Server touches the ticket keys of its
  context only when the new setting is used. Tests of this release
  run that bridge form against the setting, in both directions. One
  test of capnp-zig that holds "late after a Retry" will go red; it
  was told, and that is the wanted result. Its answer goes into the
  sprint log when it comes. **It came the same day, after the tag:
  met, late.** See "After the tag" at the end of this section.
- S8 (a mutant for every new guard; the fuzz gate counts at least 43
  sites; five gates real on the tag commit; the wide matrix in both
  roles with every failed cell read): met; the gates and the matrix
  are below.

**The gates on the release commit.** Tagged 2026-10-05 at `9d2ab6e`,
each gate read at its evidence line.

- `test`: six jobs, every step green; 1,942 tests in Debug and 1,902
  in ReleaseSafe on the four Unix jobs, 1,879 on Windows; in the
  consumer-smoke step, `check-modes: 6 of 6 as expected` and no
  `invalid option` line.
- rc-fuzz: `n_runs=2,163,963 unique_runs=12,974 pcs_len=43,766` across
  43 sites (floor 1,935,000), no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0 skipped=0 flaky_passed=0
  flaky_failed=0`.
- QNS image: built from that commit.
- pin-lint: `zig pins agree: 0.17.0`, and the boringssl pins of
  quic-zig and http3-zig are identical (the lint is strict again
  since `6684116`).

The wide matrix, quic-zig as server, 16 tests, quic-go, quiche and
ngtcp2 clients, in CI on the release commit (run 37354596734):
`interop evidence: pairs=3 cells=48 succeeded=43 failed=0
known_failed=0 unsupported=4 skipped=0 flaky_passed=0
flaky_failed=1`. The flaky cell is `quiche:multiplexing`, as in every
release since v0.24.0.

The same tests without the goodput measurement, local, on the code of
the release (the image was built one commit before the release
commit, which changes the version and the docs only). One run for
each role, and every failed cell read in its capture:

- quic-zig as the client against the three servers: `interop
  evidence: pairs=3 cells=45 succeeded=42 failed=1 known_failed=0
  unsupported=2 skipped=0 flaky_passed=0 flaky_failed=0`. The failed
  cell is `handshakeloss` against quic-go, which passes 5 runs of 10
  on v0.26.0 (the client's slow retry of a silent handshake). In the
  capture the server heard nothing from the client for 7.0 s; it
  waits 5 s. Nothing in this release touches that.
- quic-zig as the server against the three clients: `interop
  evidence: pairs=3 cells=45 succeeded=40 failed=1 known_failed=0
  unsupported=4 skipped=0 flaky_passed=0 flaky_failed=0`. The failed
  cell is `quiche:multiplexing` (the local run has no flaky list). In
  the quiche client's log 4 of its 1999 requests are cut short on the
  wire with no FIN, and it logged "failed to send request Done" 4
  times: the signature of every earlier capture of that cell.
- The client's `zerortt` and `keyupdate` cells in a batch of their
  own: 3 runs of 3 against each server. The 0-RTT sizes at the runner
  are 10413, 10414 and 10417 bytes, as on v0.26.0, now with the
  library holding the stream count.

The `resumption` and `zerortt` cells pass in both roles against all
three peers. None of them uses the new settings: the interop endpoint
sets no ticket key, so what they show is that nothing changed for a
server without one.

A fresh consumer outside the repository, built from an archive of the
tag (`git archive`, the files of the tag tarball; hash
`quic-0.27.0-DnSYvdkEOQDHm_pJQOp6Vo47gQ1Cm7-0c2sgVV0M6Xht`), with
`.optimize = optimize` and `-Doptimize=ReleaseSafe`: it compiled with
`-Osafe` for the application, for `quic` and for `boringssl`, printed
no `invalid option` line, and ran (`consumer-smoke ok: quic-zig
0.27.0`).

**After the tag: what the downstreams ran.** Both answers came the
same day, after the tag was pushed. The numbers are theirs.

- capnp-zig ran its own suite, first on the archive of the branch,
  then on the tag (built from a `git archive` of `9d2ab6e`; the hash
  matched). So S7 is met, late. With its tests unchanged:
  `test-rpc-quic` 144 of 149, and exactly the 5 failures it expected.
  Three tests held "late after a Retry" (the fix of this release;
  each new value was the one its handoff predicted). Two held
  `.handshake_timeout` where v0.26.0 gives `.peer_close` (it was on
  v0.25.0). With those five flipped, its scratch tests for the new
  settings, and its dial counter moved to `retryAccepted()`: 169 of
  169, in Debug and in ReleaseSafe. It checked the config field, its
  bridge and the field on one server (the field wins), tickets read
  both ways, rotation (the old key ends on the `feed` clock), every
  refusal, and the lifetime range. A build without its bridge passes
  too. Its words: "No v0.27.1 needed from our side."
- One result it did not expect: the stream-count change of this
  release repaired a hidden failure of its own. A resumed dial that
  staged 5 large frames against a remembered limit of 2 streams was
  closed by the server on v0.26.0 (0 of 5 arrived). Now the client
  stops at the limit, and all 5 arrive in order.
- http3-zig moved to v0.27.0 (its commit `9920527`): core 16 of 16,
  interop 6 of 6, allocation counts as on v0.26.0. It does not call
  `setRememberedPeerTransportParams`.

What capnp-zig found, and where each thing went:

- Docs, repaired on `main` after the tag (the changelog has them
  under "Unreleased"). The doc of `rotateSessionTicketKey` did not
  say plainly that the lifetime counts from its `now_us` argument on
  the clock of `feed`, and that the Server does not check the thread.
  Nothing said what a process must do when it restarts less than one
  ticket lifetime after a rotation: start with the old key and rotate
  again (a test holds that now). Nothing said that the caller's own
  copies of the key are not cleared, that a lifetime above 2 days
  needs the client too (a BoringSSL client keeps a ticket for 2 days
  at most by default), and that the bundled UDP loop feeds a clock
  that starts at zero, so with it a `new_token_key` from the process
  before does not save the Retry.
- Not built, for a later sprint: a setting for the previous ticket
  key at start; a debug check of the thread rule; and three asks of
  its handoff about the NEW_TOKEN clock that this sprint answered
  with docs only (the bundled loop's clock, a wall clock of its own
  for NEW_TOKEN times, an allowed clock skew).

## v0.28.0 stream-end release and the v0.28.1 build fix

v0.28.0 (tag `a9078d8`, 2026-10-05) is "the end of a stream that
cannot be lost": `Connection.streamRecvEnd` and a bounded note of how
reclaimed streams ended, `reset_code` on the read results, the hook of
`runUdpClient` before `tick`. It was made by another session; its
record is the sprint file in the project's handoff notes
(`SPRINT-2026-10-05-stream-end.md`), with its gates read at evidence
level (rc-fuzz 2.2 M executions, 0 failing; test six jobs; quic-go
2 of 2; the wide matrix 19 of 21 with 0 failed).

**v0.28.0 did not compile for a 32-bit target.** http3-zig's CI leg
for `x86-linux-musl` found it the same day: `src/conn/RecvEndRing.zig`
asserted at comptime that a `Record` is 40 bytes, which holds only
where a u64 aligns to 8 (it is 36 where a u64 aligns to 4). No leg of
ours built for a 32-bit target, so none could see it. http3-zig went
back to v0.27.0 and waited.

**v0.28.1** (tag `21d05d1`, 2026-10-05) is the fix: the assert is on
the layout; five u64-to-usize casts in tests and examples that the
32-bit build refused; a size pin in one test that is per pointer size
now; a 32-bit leg in the `test` workflow that compiles AND runs the
suite (an x86-64 Linux runner runs 32-bit static binaries); `just
check-x86` as the compile-only form. Nothing changed for a 64-bit
target.

The first run of the 32-bit leg found one more thing, recorded and not
changed: with the C sanitizer in its default trap mode, nine
bench-harness handshakes trap inside BoringSSL's P-256 field code
(fiat `p256_32.h`, `fiat_p256_mul`, under ECDSA verify) on
`x86-linux-musl`, while the other handshake tests with the same P-256
key pass. The leg runs with `-Dsanitize-c=off`; the x86-64 `sanitizer`
job keeps the UB check on the C code. It is a finding for
boringssl-zig (`FINDING-2026-10-05-boringssl-p256-ubsan-32-bit.md` in
the handoff notes).

**The gates on `21d05d1`**, each read at its evidence line.

- `test`: seven jobs, every step green; 1,960 tests in Debug and
  1,920 in ReleaseSafe on the Unix jobs, 1,897 on Windows, 1,960 on
  the 32-bit leg (the same count as 64-bit); `check-modes: 6 of 6 as
  expected`; `consumer-smoke ok: quic-zig 0.28.1`.
- rc-fuzz: `n_runs=2,168,624 unique_runs=12,461 pcs_len=44,392`
  across 43 sites (floor 1,935,000), no failing site.
- `quic-go-interop`: `pairs=1 cells=2 succeeded=2 failed=0`.
- QNS image: built and pushed from that commit.
- pin-lint: `pin-lint: OK`, `zig pins agree: 0.17.0`, the boringssl
  pins of quic-zig and http3-zig identical.
- A fresh consumer from an archive of the tag (hash
  `quic-0.28.1-DnSYvacDOgCPlHPHQWufNaG2XMoKtnwwHJPVcIUuAmqB`):
  `-Osafe` for the application, `quic` and `boringssl`, no `invalid
  option` line, `consumer-smoke ok: quic-zig 0.28.1`.

The wide interop matrix was not run again for v0.28.1: no code on the
wire changed after v0.28.0 (an assert, casts in tests, a CI job).

### RC/soak criterion toward 1.0

Between v0.9.0 and the 1.0 RC, the explicit soak gate is: http3-zig
consumes the tag as its pin, ships its socket-backed examples on it, and
one release cycle passes without a Stable-tier breaking-change request.
That makes "distance to 1.0" measurable from this document instead of
implied.

Check items off as they land; the list is the definition of done for the
1.0 tag.

## v0.29.0: the open-items release

v0.29.0 (tag `b9a15e6`, 2026-10-06) is the seven items that were open
after v0.28.1, done in one sprint in the "Zig 0.17.0 upgrade" session
between 2026-10-05, 20:30 and 2026-10-06, 05:00 AKDT (its record:
`SPRINT-2026-10-05-open-items.md` in the handoff notes). No
wire-format change. Each item is its own commit on `main` and its own
entry in the changelog:

- `3c9bb9c` the client connects through loss: a two-datagram handshake
  probe while there is no RTT sample, a Handshake packet before its
  keys held and read when they come, a lost CONNECTION_CLOSE sent
  again at the peer's next packet.
- `bd1a63f` a `Server` makes no connection for a datagram of which no
  packet opens (`feed` says `.dropped`); NEW_TOKEN times on a clock of
  their own; a previous ticket key at start; a client's own ticket
  lifetime; the ticket lifetime of an envelope; a thread check for
  `rotateSessionTicketKey`.
- `6bc069f` a connection costs 91 KB on the Zig heap, not 1.09 MB
  (the tracker grows on demand, the CRYPTO buffers live on the heap).
- `489462c` the 32-bit CI leg by hand (a sanitizer mode and a test
  filter as dispatch inputs).
- `30a40a3` a late packet is not a lost packet: the loss thresholds
  widen on a spurious loss and a reduction is taken back when every
  "lost" packet of its episode arrived; the recovery period is
  anchored at the detection (RFC 9002 B.6), not the lost packet's
  send time. MEASURED (12 seeds): a 20 ms round trip, 100 Mbit link
  with 10% of the packets 1 ms late: bbr 1376 -> 773 ms (the link's
  floor), cubic 9937 -> 790, new_reno 18357 -> 790. The anchor moves
  the fairness cells where CUBIC is in them (deep-buffer BBR-vs-CUBIC
  bbr share 31.1% -> 22.3%); the BBR-only cells are identical.

**The gates on `b9a15e6`**, each read at its evidence line.

- `test`: seven jobs, every step green; 1,997 of 2,013 tests in Debug
  (16 skipped) on the Unix jobs and on the 32-bit leg, 1,957 of 1,973
  in ReleaseSafe, 1,934 of 1,973 on Windows (39 skipped);
  `check-modes: 6 of 6 as expected`; `consumer-smoke ok: quic-zig
  0.29.0`.
- rc-fuzz (run 37435918383): `n_runs=2,231,001 unique_runs=11,423
  pcs_len=45,034`, `coverage verified: instrumented, 2,231,001
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0`.
- QNS image: built and pushed from that commit (digest `6c755a67…`).
- pin-lint: `pin-lint: OK`, `zig pins agree: 0.17.0`, the boringssl
  pins of quic-zig and http3-zig byte-for-byte identical.
- A fresh consumer from an archive of the tag (hash
  `quic-0.29.0-DnSYvahYOwAdaHX-Ct3_iZGZycF387GmpAbI9G9wjFGg`):
  `consumer-smoke ok: quic-zig 0.29.0`.
- The wide interop matrix (advisory, both roles, three peers, one run
  on the image of the tag): client `cells=45 succeeded=42 failed=1
  unsupported=2`, server `cells=45 succeeded=40 failed=1
  unsupported=4`. The two failures are the quiche handshake chance
  cells, run 10 times each on the same image: server x quiche x
  handshakeloss 9 of 10 (7 of 9 on 2026-10-04), client x quiche x
  handshakecorruption 7 of 10, against 8 of 10 on the image of the
  commit before the loss-recovery change (the control). Pre-existing;
  the first candidate of the next sprint (the sprint record has it).

## v0.30.0 and v0.30.1: the probes release

v0.30.0 (tag `abc5f12`, 2026-10-06) is the "probes" sprint after
v0.29.0 (record: `SPRINT-2026-10-06-probes.md` in the handoff notes):

- `5519b02` the probe timeout of the Initial and Handshake spaces is
  bounded at the no-sample probe timeout (about 1 s,
  `max_handshake_pto_us`) and anchored on the last ack-eliciting send
  (RFC 9002 A.8). A bound alone cascaded with the oldest anchor (2, 4,
  8 datagrams per timeout); the two rules go together.
- `1cbccd3` a probe timeout is not a loss (RFC 9002 section 6.2.4, a
  MUST NOT): the Application path's timeout keeps the oldest packet
  in flight, sends its frames again, tells no controller; the
  thresholds decide after the probe's ACK; a full tracker keeps the
  old expiry. The deadline runs from the last send there too.
- `46ebae6` three repairs found by downstreams on v0.29.0:
  `quic.unixWallClockUs` did not compile on Zig 0.17.0 (no test
  referenced it), `Server.adoptLoopThread()` for a thread handoff,
  and `Server.feed`'s in-place contract in its doc.

**v0.30.0 did not compile on Windows**: `unixWallClockUs` through
libc's `clock_gettime`, which Windows' libc has not (`std.c.timespec`
is `void` there), and the new test that keeps the function compiled
took the Windows test binary down. The `test` workflow's Windows job
said so on the tag; `just check-windows` was not run before it. A
tag is a tag: **v0.30.1** (tag `ccf6ae2`, the same day) is v0.30.0
with `RtlGetSystemTimePrecise` on Windows and a ticket-lifetime
test's tolerance (599 for 600 on the Windows runner in Debug:
BoringSSL counts a ticket's lifetime down from its making). Nothing
else differs. Lesson, now in the sprint rules: `mise exec -- just
check-windows` before every tag.

MEASURED for the sprint (12 or 10 runs each, before -> after): client
x quiche x handshakecorruption 7 and 8 of 10 (two control images) ->
9, then 7 of 10 (no signal at N = 10: every failed handshake is
quiche's own server backoff, which doubles while our Initial probes
only get ACKs); client x quic-go handshakeloss + handshakecorruption
10 of 10 -> 10 of 10; server x quiche handshakeloss 9 of 10 -> 9 of
10; the wide matrix on the release code client 43/0/2 and server
40/1/4 (quiche x multiplexing, the known flaky cell); 18 bench cells
byte-identical, the two-CUBIC fairness cell Jain 0.9823 -> 0.9640
(one deterministic trajectory: the old rule's spurious cuts were an
accidental equalizer), the BBR cells identical; a ClientHello lost
eight times in a row completes at 4 s (8 s before).

**The gates on `ccf6ae2`**, each read at its evidence line.

- `test`: seven jobs green, the Windows one included; 2,005 of 2,021
  tests in Debug (16 skipped) on the Unix jobs and the 32-bit leg,
  1,965 of 1,981 in ReleaseSafe, 1,942 of 1,981 on Windows (39
  skipped); `check-modes: 6 of 6 as expected`; `consumer-smoke ok:
  quic-zig 0.30.1`.
- rc-fuzz (run 37528416253): `n_runs=2,200,545 unique_runs=11,959
  pcs_len=45,166`, `coverage verified: instrumented, 2,200,545
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop`: `interop evidence: pairs=1 cells=2 succeeded=2
  failed=0 known_failed=0 unsupported=0`.
- QNS image: built and pushed from that commit (digest `1f698440…`).
- pin-lint: `pin-lint: OK`, `zig pins agree: 0.17.0`, the boringssl
  pins of quic-zig and http3-zig byte-for-byte identical.
- A fresh consumer from an archive of the tag (hash
  `quic-0.30.1-DnSYvVnOOwBfpDxHQWI41E6YxM1RqqkCuven5bK46jXR`):
  `consumer-smoke ok: quic-zig 0.30.1`.

## v0.31.0: the feed-and-confirm release

v0.31.0 (tag `35b3983`, 2026-10-06) is the "feed and confirm" sprint after
v0.30.1 (record: `SPRINT-2026-10-06-feed-confirm.md` in the handoff
notes): two small repairs, behavior only, no wire-format change, no API
an embedder must change, the same option map, the same boringssl-zig.

- `37f1dd0` a client confirms its handshake on an ACK of a 1-RTT
  packet of its own (RFC 9001 section 4.1.2 paragraph 2, a MAY): the
  server can only have opened such a packet after it processed the
  client's Finished. `one_rtt_acked`, latched in
  `recv_ack_handlers.dispatchAcked` for the client and never for a
  0-RTT packet; the discard at the end of the datagram keys on either
  latch. A client whose HANDSHAKE_DONE was lost sends no Finished
  again once any 1-RTT packet of its own is acknowledged.
- `86fc86d` `Server.feed` leaves a `.dropped` datagram as it was: the
  new-connection path copies the datagram before it opens it (a
  2048-byte stack buffer, the heap above) and puts it back on the
  stillborn branch. A datagram that comes back anything but `.routed`
  or `.accepted` is as it came.

MEASURED for the sprint, on the image of the release code, v0.30.1 as
the control: client x quiche x handshakecorruption 9 of 10 (control 7
of 10; 7, 8, 9 of 10 in earlier batches: no signal at N = 10, the
failures are quiche's own server backoff); client x quiche x
handshakeloss 5 of 5 (new); client x quic-go x handshakeloss +
handshakecorruption 10 of 10 cells (control 10 of 10); server x quiche
x handshakeloss 9 of 10 (control 9 of 10); the wide matrix client
43/0/2 (control 43/0/2) and server `cells=45 succeeded=40 failed=1 unsupported=4` (control 40/1/4; the one failure is quiche x handshakeloss, the chance cell the dedicated run puts at 9 of 10; the first attempt died in the runner's TShark capture on the host and was run again); 20 of 20 bench
cells byte-identical to v0.30.1; six mutants killed, each by the test
written for it; `just check-windows` clean before the tag.

**The gates on `35b3983`**, each read at its evidence line.

- `test`: seven jobs green, the Windows one included; 2,011 of 2,027 tests in Debug (16 skipped) on the Unix jobs, the 32-bit leg and the sanitizer job, 1,971 of 1,987 in ReleaseSafe, 1,948 of 1,987 on Windows (39 skipped); `check-modes: 6 of 6 as expected`; `consumer-smoke ok: quic-zig 0.31.0` (run 37560064112).
- rc-fuzz: (run 37560066071) `n_runs=2,179,774 unique_runs=11,560 pcs_len=45,224`, `coverage verified: instrumented, 2,179,774 executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop`: (run 37560064085) `interop evidence: pairs=1 cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image: (run 37560064076) built and pushed from that commit (`Build and push QNS image: success`; the longest build step 208.9 s).
- pin-lint: (run 37560064089) `pin-lint: OK`, `zig pins agree: 0.17.0`, the boringssl pins of quic-zig and http3-zig byte-for-byte identical.
- The package hash of the tag's archive: `quic-0.31.0-DnSYvcIFPAAlKQ7WKeI6Sbd7DfxLy-zoJa9qMUNI5iok`.

## v0.31.1: the idle-timer fix

v0.31.1 (tag `a32dcba`, 2026-10-06) fixes a regression of v0.30.1 found
by the qmsg session: a dead peer's connection lived about three times
the idle timeout (qmsg's measurement: a 2 s timeout noticed a dead
peer after 5.9 to 6.0 s on v0.30.1 and v0.31.0, after 2.2 s on
v0.29.0). Every datagram sent restarted the timer, and v0.30.1's probe
timeout probes on to a dead peer; every datagram received restarted it
before its packet was opened. The rule now, RFC 9000 section 10.1: one
send restart per receipt (the first ack-eliciting packet since the
last packet that opened), a received packet counts once it opened,
and the timeout is at least three times the PTO (paragraph 4, a MUST
that was missing; the PTO without its backoff). No wire change, no
API change, the same option map. Four conformance tests in
`tests/conformance/rfc9000_streams_flow.zig`, red before the fix;
five mutants killed by them; 20 of 20 bench cells byte-identical to
v0.31.0; `just check-windows` clean.

**The gates on `a32dcba`**, each read at its evidence line.

- `test`: seven jobs green, the Windows one included; 2,015 of 2,031 tests in Debug (16 skipped) on the Unix jobs, the 32-bit leg and the sanitizer job, 1,975 of 1,991 in ReleaseSafe, 1,952 of 1,991 on Windows (39 skipped); `check-modes: 6 of 6 as expected`; `consumer-smoke ok: quic-zig 0.31.1` (run 37564393998).
- rc-fuzz: (run 37564395744) `n_runs=2,187,187 unique_runs=12,394 pcs_len=45,231`, `coverage verified: instrumented, 2,187,187 executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop`: (run 37564394025) `interop evidence: pairs=1 cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image: (run 37564394022) built and pushed from that commit (`Build and push QNS image: success`).
- pin-lint: (run 37564394049) `pin-lint: OK`, `zig pins agree: 0.17.0`, the boringssl pins of quic-zig and http3-zig byte-for-byte identical.
- The package hash of the tag's archive: `quic-0.31.1-DnSYvW4iPABrXhGsw_q3ZbQUaoDirSODEPybR5kXQ1CB`.

## v0.35.0: the reordering release

v0.35.0 (tag `a6fa45f`, 2026-10-08) is sprint B ("CUBIC after a
standing loss + the adaptive ACK policy"), the second of the three the
owner ordered before any downstream move. On
`impairment_reorder_gaps_1gbit_defaults` (8 MiB on 1 Gbit/s, 20 ms
RTT, 10% of the packets 20 ms late, nothing dropped; 12 seeds) CUBIC
took 511 ms median against BBR's 371. A trace showed 85 spurious loss
episodes in one run, all undone, each cutting the window and holding
slow start for a round trip; none of the three causes was CUBIC. The
packet-threshold rule grew to the distance a late packet trailed by
and chased the rate as it doubled: once reordering is seen the rule is
off and the time rule alone declares losses (RFC 8985's shape); cubic
524 -> 447 ms. The widest time threshold stopped at exactly twice the
RTT, where a packet late by one round trip sits: it carries a jitter
margin now (the larger of four variances and a quarter RTT), as does
the reach the window settles by; 447 -> 422. The receive window tuned
itself on the bytes read and stalled at 2 MiB under head-of-line
blocking with the sender out of credit: when the reader has read
everything deliverable, the pace is the bytes received, holes included;
cubic 422 -> 378, bbr 367 -> 311. Then the ACK policy: every second
packet of a burst (RFC 9000 13.2.2's threshold of two) with a quiet
rule (`ack_quick_gap_us`, 1 ms) that acknowledges a lone packet at
once: the in-process goodput bench 988 -> 1,088 MB/s (twice v0.33.0's),
a quarter fewer datagrams in bulk, the strict ping-pong churn cells
byte-identical, the single-stream 1 Gbit cells about 1% slower. One
new knob, no API change, the same option map.

Local before the tag (`tools/release.sh 0.35.0` on 4df6184): the full
suite 2,026 of 2,042 (16 skipped), `just check-windows` 15/15, `just
check-x86` 15/15, eleven mutants of the new rules (eight killed on the
first run; the settle reach got a test and the quiet rule's
first-packet clause was dropped as redundant, then ten killed, one
removed), every bench cell against v0.34.0's (the bottleneck cells
the same time with 22% fewer datagrams, the single-stream 1 Gbit cells
220 -> 222 ms and 234 -> 235, loss1pct 28 -> 26, the light reorder
cells 37 -> 33 and 26 -> 25, `impairment_reorder_gaps_1gbit` with a
4 MiB window 294 -> 311 ms, the one cell slower: the packet rule's
early spurious copies used to fill the holes before the originals; the
fairness cells inside their noise; churn byte-identical).

**The gates on `a6fa45f`**, each read at its evidence line.

- `test` (run 37740389985): seven jobs; the sanitizer job 2,041 of
  2,057 (16 skipped); macos-26, macos-15, ubuntu x86 and ubuntu arm
  2,041 of 2,057 in Debug and 2,001 of 2,017 in ReleaseSafe;
  windows-latest 1,978 of 2,017 (39 skipped) in both modes;
  x86-linux-musl 2,041 of 2,057.
- rc-fuzz (run 37740392653): `n_runs=2,903,363 unique_runs=9,259
  pcs_len=45788`, `coverage verified: instrumented, 2,903,363
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop` (run 37740389965): `interop evidence: pairs=1
  cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image (run 37740389907): built and pushed from that commit.
- pin-lint (run 37740389813): `pin-lint: OK`, `zig pins agree: 0.17.0`.
- The wide local interop matrix on the tag's image (an ACK-policy
  change on the wire), after the tag: client role
  `pairs=3 cells=45 succeeded=42 failed=1 unsupported=2` (the one
  failed is the known quiche handshakeloss chance cell, 3 of 5 on a
  rerun against 4 of 5 on the v0.33.0 image; the two ECN cells
  unsupported); server role `pairs=3 cells=45 succeeded=39 failed=2
  unsupported=4` (the known quiche chance cells, multiplexing 5 of 5
  and handshakecorruption 5 of 5 on a rerun; unsupported: quiche
  chacha20 and keyupdate, the two ECN cells). The same counts as
  v0.33.0's matrix.

- The package hash of the tag's archive:
  `quic-0.35.0-DnSYvWTcPQAoe5kcHRRLjUyHrgz9-lgddJvdRj8kFflF`.
- NOT a downstream move (owner decision 2026-10-08: three sprints
  first); the draft note is in the handoff dir.

## v0.34.0: the CPU-per-packet release

v0.34.0 (tag `76c9296`, 2026-10-08) is the "CPU per packet" sprint,
the first of three the owner ordered before any downstream move. The
engine moves the same bytes in a little over half the CPU: the
in-process goodput bench (64 MiB on one stream, both endpoints in one
thread, no sockets, ReleaseSafe) went from 547.8 MB/s to 988.0 MB/s
(+80%), the loopback smoke (real UDP on macOS, one datagram per
syscall) from 122.8 to 133.4 MB/s. A `sample` profile found 35% of
the CPU in copies and fills: Zig 0.17 fills an `undefined` local with
0xAA in ReleaseSafe as well as in Debug, and three 4 KB locals on the
packet paths were 13% of the CPU on their own; a struct with a 4 KB
array inline made every `.{}` a template copy (4.5%); the send buffer
moved its live bytes to the front of its allocation on nearly every
write (12%); the keys were copied per packet (2%). The packet paths
use a `threadlocal` scratch (about 21 KB per thread, nothing per
connection), the send buffer is a ring with packetization unchanged,
a packet's keys go by pointer, the pacer computes in 64 bits when the
product fits, and the receive stream zeroes only a gap. No wire
change, no knob; the 27 bench cells are byte-identical to v0.33.0.
Two signature changes for raw-`Connection` embedders (`packetKeys`
returns a pointer; `SendStream.bytes` is a ring). Measured and not
shipped: acknowledging every second packet (+10% in bulk, 25% more
datagrams in strict ping-pong) and a cached sendable-stream list
(nothing measurable).

Local before the tag (`tools/release.sh 0.34.0` on c02fe0b): the full
suite 2,022 of 2,038 (16 skipped), `just check-windows` 15/15, `just
check-x86` 15/15, eight mutants of the new rules (five killed on the
first run; the ring's growth while its bytes wrap and the pacer's
128-bit fallback survived and got tests, then killed; the receive
gap's zeroing is unobservable by design: no read returns a gap byte),
the 27 bench cells byte-identical to v0.33.0.

**The gates on `76c9296`**, each read at its evidence line.

- `test` (run 37734236463): seven jobs; the sanitizer job 2,037 of
  2,053 (16 skipped); macos-26, macos-15, ubuntu x86 and ubuntu arm
  2,037 of 2,053 in Debug and 1,997 of 2,013 in ReleaseSafe;
  windows-latest 1,974 of 2,013 (39 skipped) in both modes;
  x86-linux-musl 2,037 of 2,053.
- rc-fuzz (run 37734238708): `n_runs=2,318,073 unique_runs=11,478
  pcs_len=45732`, `coverage verified: instrumented, 2,318,073
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop` (run 37734236536): `interop evidence: pairs=1
  cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image (run 37734236442): built and pushed from that commit.
- pin-lint (run 37734236443): `pin-lint: OK`, `zig pins agree: 0.17.0`.
- The wide interop matrix: not run for this tag (no wire or
  flow-control change; the 27 bench cells are byte-identical to
  v0.33.0, whose matrix stands).

- The package hash of the tag's archive:
  `quic-0.34.0-DnSYvV-RPQDWpFMKpVCpvBE9bvdzDxb-vwMLwRFWtdix`.
- NOT a downstream move (owner decision 2026-10-08: three sprints
  first); the draft note is in the handoff dir.

## v0.33.0: the line-rate release

v0.33.0 (tag `712ac23`, 2026-10-08) is the "line rate by default"
sprint: a single stream reaches the path's rate on the engine's
defaults. The receive windows tune themselves (quic-go's and
Chromium's rule: a reader that consumed the last half window in under
two round trips gets a window twice as big, up to 8 MiB per stream and
16 MiB per connection, the connection's cap never more than half of
`max_connection_memory`), the send buffer follows the peer's credit
(`max_buffered_send` is the floor, `max_buffered_send_cap` 16 MiB the
cap), the sent-packet tracker holds 16384 packets (the slab grows on
demand), a write past the memory budget returns short instead of
`ExcessiveLoad`, and the previous loss episode stays undoable. The
sprint's finding was not on its plan: CUBIC stayed at ~1.5 s on the
reorder cell whatever the windows because the sender wrote packet
numbers in one byte while fewer than 128 packets were out, and a
packet 20 ms late at 1 Gbit/s arrives after ~2000 newer ones; the
receiver recovered the wrong number (RFC 9000 A.3), the tag failed,
the packet was dropped without a trace, and the loss it had been
declared was never taken back. A packet number is never one byte now
(quic-go's choice). Measured on the defaults, 8 MiB at 1 Gbit/s with
a 20 ms round trip, bbr, 12 seeds: clean 410 -> 234 ms (the floor
~220), 10% of the packets 20 ms late 924 -> 371 ms median (cubic
~1540 -> 511), 16 streams x 256 MiB at 100 ms 7334 -> 4138 ms. Five
knobs, all on by default; the same option map.

Local before the tag (`tools/release.sh 0.33.0` on c833970): the full
suite 2,019 of 2,035 (16 skipped; four tests adapted: three tracker
tests had the 4096 count written in, one borrowed-driver test pins a
3-byte buffer that the follow rule would lift), `just check-windows`
15/15, `just check-x86` 15/15, fifteen mutants of the new rules (14
killed, 1 equivalent: the window's cap is enforced in the doubling as
well as in the guard; two survived a first run and were closed by
tests, CUBIC's full restore of a previous episode and the tracker
number stated as a number), the bench cells against main (the four
bottleneck cells within one queue microsecond, the packet-number
byte; the three churn cells byte-identical; every window-bound cell
faster, the light impairment cells among them; the six fairness
cells inside noise or better, 2f mixed Jain 0.80 -> 0.86).

**The gates on `712ac23`**, each read at its evidence line.

- `test` (run 37715271918): seven jobs; the sanitizer job 2,034 of
  2,050 (16 skipped); macos-26, macos-15, ubuntu x86 and ubuntu arm
  2,034 of 2,050 in Debug and 1,994 of 2,010 in ReleaseSafe;
  windows-latest 1,971 of 2,010 (39 skipped) in both modes;
  x86-linux-musl 2,034 of 2,050.
- rc-fuzz (run 37715273154): `n_runs=2,220,035 unique_runs=11,859
  pcs_len=45627`, `coverage verified: instrumented, 2,220,035
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop` (run 37715271900): `interop evidence: pairs=1
  cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image (run 37715271932): built and pushed from that commit.
- pin-lint (run 37715271906): `pin-lint: OK`, `zig pins agree: 0.17.0`.
- The wide local interop matrix on the tag's image (a flow-control
  change), after the tag: client role `pairs=3 cells=45 succeeded=43
  failed=0 unsupported=2` (the two ECN cells; v0.32.0 had 42 with the
  quiche handshakeloss chance cell failing once); server role
  `pairs=3 cells=45 succeeded=39 failed=2 unsupported=4` (unsupported: quiche chacha20 and keyupdate, the two ECN cells; the two failed are the known quiche chance cells: multiplexing, which failed in the v0.27-era and v0.30-era matrices too and passed in v0.32.0's, 2 of 5 on a rerun against 13 of 20 historically, and handshakeloss, 5 of 5 on a rerun; v0.32.0's server role was 41 with none failed).

- The package hash of the tag's archive:
  `quic-0.33.0-DnSYvfk6PQAwBH4pHnhv97zhZeAoJ_0JZRjDIPu_jG8u`.

## v0.32.0: the single-stream limits release

v0.32.0 (tag `ffdb251`, 2026-10-07) is the "reorder follow-ups" sprint:
the owner asked for loss thresholds that shrink back, the BBR
mechanism behind a slow reordering cell, and a decision on the ACK
range cap. The measurement answered a different question. BBR was
never the brake under reordering (a trace showed it in Startup with a
2 MB window and a 110 MB/s pacing rate while the bytes in flight fell
to 20 to 80 KB at every hole); two fixed sizes were: the receive
credit the engine gave after the initial window (1 MiB per stream and
16 MiB per connection, whatever the transport parameters announced)
and the 1 MiB send buffer with no knob. Now the window an endpoint
keeps open is the one it announced (the defaults announce exactly the
old constants, so a default embedder sees no change; the QNS endpoint
announces 16 MiB and keeps it), `max_buffered_send` exists on
Connection, Client.Config and Server.Config (default 1 MiB), the ACK
frame carries 64 lower ranges (was 16), and the thresholds shrink
back after 16 clean round trips by send time (RFC 8985's shape; not
the controller's loss episodes, which BBR never closes under steady
loss). Measured, 8 MiB on one stream over 1 Gbit with a 20 ms round
trip, bbr: 361 -> 220 ms clean, 768 -> 294 ms with 10% of the packets
20 ms late (279 with the wider ACK). CUBIC stays at 1527 ms there in
every setting: its own response to spurious losses, the first
candidate of the next sprint. No wire-format change, no API an
embedder must change, the same option map.

Local before the tag: the full suite (1,357 in the e2e and
conformance binaries, one e2e threshold re-measured: the answering
side of the 20,000-stream test no longer sends a MAX_STREAM_DATA frame
on the first read of every stream, which its 1 MiB running window over
the 256 KiB it announced made it do), `just check-windows` clean, ten
mutants killed, the bench cells (the four bottleneck and three churn
cells byte-identical; every cell the old running window had capped
faster, since the harness announces 4 MiB; the six fairness cells
inside their noise). After the tag: the wide local interop matrix on
the tag's image, client role 42 of 45 (the one failure the known
quiche handshakeloss chance cell, two ECN cells unsupported), server
role 41 of 45 with no failure (four unsupported): 83 of 90, against
42 and 40 at v0.30.1.

**The gates on `ffdb251`**, each read at its evidence line.

- `test` (run 37692543374): seven jobs; the sanitizer job 2,022 of
  2,038 (16 skipped); macos-26, macos-15, ubuntu arm and ubuntu x86
  2,022 of 2,038 in Debug and 1,982 of 1,998 in ReleaseSafe;
  windows-latest 1,959 of 1,998 (39 skipped) in both modes;
  x86-linux-musl 2,022 of 2,038.
- rc-fuzz (run 37692566750): `n_runs=2,179,373 unique_runs=12,580
  pcs_len=45384`, `coverage verified: instrumented, 2,179,373
  executions across 43 sites (floor 1,935,000)`, no failing site.
- `quic-go-interop` (run 37692543362): `interop evidence: pairs=1
  cells=2 succeeded=2 failed=0 known_failed=0 unsupported=0`.
- QNS image (run 37692543357): built and pushed from that commit.
- pin-lint (run 37692543364): `pin-lint: OK`, `zig pins agree: 0.17.0`.
- The package hash of the tag's archive:
  `quic-0.32.0-DnSYvcGOPADCEZMispvPbD9RznRtyIGq77zHIgmS8iVl`.

**Two rules changed the same day (owner decision, 2026-10-07; the
text is in CONTRIBUTING.md "Releases").** A tag used to cost about an
hour of serial gates and six downstreams waited on it, while the
suite itself takes minutes. From here: a tag goes out on the fast
local gates (the full suite, `just check-windows`, `just check-x86`;
`tools/release.sh X.Y.Z` runs them and does the rest), and the five
CI gates prove it within the hour, read at the evidence line; a red
gate is answered with a patch tag. And the consumers move per
cluster, not in lockstep: cluster A (nest, qmsg, qmesh-zig,
mruby-quic, one binary) with one script, cluster B (http3-zig,
capnp-zig) by its own sessions, the option map the same for all.
Cluster A moved to v0.32.0 the same afternoon (qmsg v0.8.2).
