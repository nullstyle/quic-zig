# Sprint 1: transport baseline and local candidate

This is local qualification of main `b0d7d7892690da62e259815226903a8c92c08328`
plus the ring-capacity fix below. The released pin remains v0.42.2
(`2aa5bae31b7eab42cf95a654ab9717248d6f2498`); no release version, consumer
pin, default compiler or backend is changed. The branch is
`codex/sprint-1-baseline`, with reviewable uncommitted changes.

## Source review and reproduced repair

The Oct 13 commits `021591e` and `b0d7d78` are absent from v0.42.2. Review
covered PTO/late-ACK range ownership, fallible packet construction, ring
capacity/lookup/compaction, RTT sampling and ACK-delay precision, active-path
recovery, parser bounds and input restoration. They retain the current
borrowing connection driver and bounded outbox interfaces. The parser's
actual total-parameter cap is **64**, as enforced by its regression test.
No performance gain follows from this qualification.

The in-flight ring replacement underflowed when `ensureTotalCapacity` was
called with a requested minimum below the existing live count. A real-source
regression inserting three entries then requesting capacity one failed with
`integer overflow` at `SendStream.zig:155`. Saturating the additional-slot
subtraction makes lower/equal requests preserve entries and storage. Both
ring tests pass after the change. Logs preserve the failing and passing
commands; no unrelated transport refactor was made.

## Local evidence

Evidence is retained under ignored
`benchmark-reports/sprint-1-2026-10-26/`. Every gate has a JSON record with
its exact command, working directory, timestamps, duration, exit status and
log path. `manifest.json` records final package/source/compiler hashes,
per-file digests, configuration, gate/log hashes and remaining limits.
`source.patch` records the tracked patch over the named HEAD.

Host: Darwin arm64, macOS 27.0.1. Toolchain: mise-pinned **stock Zig 0.17.0**,
compiler SHA256 `1c5f706db0ed6d55451940f31dc05a6177d05696bc1fa5d853696d04c718b523`.
Builds use `COPYFILE_DISABLE=1`, at most `-j2`, Debug/ReleaseSafe and the
existing BoringSSL pin. The ignored `tools-bin/zig` wrapper adds `-j2` to
the existing cross-check and fuzz recipes without modifying those recipes.

The initial unmodified main Debug baseline passed 37/37 steps,
2088/2104 tests with 16 skips. The final Debug summary reports 37/37 steps,
2074/2090 tests with 16 skips plus 15 cached tests. Final ReleaseSafe reports
30/30 steps, 2045/2061 tests with 16 skips plus 44 cached benchmark fixtures.
Cached counts are stated separately rather than presented as newly executed
cases. All 16 skips are the existing visible conformance-debt tests.

| Gate | Evidence |
|---|---|
| Ring regression | `ring-source-red`: expected integer-overflow failure; `ring-source-green`: 2/2 pass. |
| Full Debug / ReleaseSafe | Final source passes the counts above; baseline and final logs are separate. |
| Full C sanitizer | `sanitize-full`: 37/37 steps, 2089/2105 tests, 16 existing skips. |
| Bench fixtures / examples | `bench-examples`: passes; 44 benchmark fixtures already executed in final Debug. |
| Native UDP | `echo`: exact stream/datagram payloads 24 and 4172 bytes; `goodput`: exact 16 MiB and clean FIN. |
| Consumer module identity / options | Debug and ReleaseSafe binaries pass; both `optimize` build-mode guards pass. |
| Cross compilation | Existing Windows x86-64 and Linux x86-musl recipes pass, including test-binary compilation; neither runs natively on this Mac. |
| Bounded fuzz preflight | 43 sites, budget 1000/site, 51,304 executions, 2709 unique runs, 47,958 PCs; gate verifies instrumentation. |
| Release-budget fuzz | `fuzz-50000.json` and log record the exact outcome, execution/coverage counts and budget 50,000/site. |
| Virtual workload control | Candidate and clean v0.42.2 each complete 31 cells; 20 deterministic results unchanged, 11 changed. |
| Strict external interop | Local Docker: client H,D 2/2 and server H,D 2/2 against pinned quic-go; no failed, skipped or unsupported cells. |
| Additional Linux execution | `root-qns/linux-evidence.json` records actual Linux arm64 Debug/ReleaseSafe outcomes and image/source identity, separately from the interop tests. |
| Final archive smoke | Copied out-of-tree consumer outcomes are recorded after packaging in the final manifest. |

The release-budget fuzz, delegated Linux and final archive outcomes live in
the final manifest and their named records so this packaged report can remain
identical to the tested archive. No gate is inferred from a command being
launched. Fuzz corpus and coverage snapshots are retained separately.

The deterministic control preserves main-only behavior changes explicitly.
`virtual-comparison.json` contains every differing field, excluding wall
measurements. The fat-window cell changes 518.07 → 507.81 virtual Mbit/s;
mixed BBR/CUBIC fairness changes Jain index 0.8914 → 0.8233, and shallow
mixed fairness changes 0.9691 → 0.9236. These differences are qualification
caveats, not passing claims of performance equivalence. No default congestion
controller or timing policy is changed by this sprint.

Performance disposition: **integration candidate; hold promotion pending
review of the main-only fairness change**. `bench-compare` defaults to a
10% tolerance for supported headline metrics; its metric table does not
include Jain fairness. The fairness machinery asserts nonzero progress,
utilization > 0.5 and Jain > 0.5, and its historical default-controller
record requires no starvation rather than a maintained numeric Jain floor.
The measured six fairness cells retain progress, utilization about 0.971
and Jain > 0.82. Thus no existing executable numeric gate fails, but that
alone does not explain or accept the mixed-share regression. The exact
main-only cause is not established by this report. Candidate testing may
continue; publication or default-policy endorsement is not implied.

## Candidate consumption and evidence limits

The local archive is `candidate/quic-zig-sprint-1.tar.gz`; its SHA256 and
Zig package hash are in `manifest.json`. It contains exactly the manifest's
consumer `.paths`, built from the final source snapshot including this
report. It is an unpublished candidate retaining package version 0.42.2;
identify it by its hashes, not that version string. The manifest verifies
that archive members match the final worktree files.

For coordinated testing, pass the archive and its Zig package hash to
qmesh's composition wrapper (`--quic-archive` and `--quic-hash`). Every
parent must use that same quic source/options and its exported BoringSSL
module. Installed qmsg/qmesh pins are not changed by this qualification.

Native macOS execution, cross compilation, Docker interop and virtual-time
workloads are distinct evidence. Native Windows execution, hosted tier-1 CI and physical-network behavior
are not inferred from these local gates. Evented activation, hardened-fork publication and a QUIC
release remain separate work.
