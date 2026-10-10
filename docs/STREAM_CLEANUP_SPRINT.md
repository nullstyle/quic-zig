# Stream cleanup sprint — 2026-10-10

Cleanup now visits a bounded list of streams named by lifecycle transitions.
Six interleaved trials on m3studio-001 reduce tick time per stream by 48% at
window 1,024 and 79% at 4,096. A same-binary walk/candidate control confirms
the cause. Poll and bulk engine/UDP rates remain within noise. This is a
many-stream tick improvement; no physical link line rate or overall request
throughput gain is claimed.

Implementation: `371d6e16c7fa01979b4166423aea2df24ca1387e`, on main in the
main checkout. Baseline: `da5475b2521b863438e538bf05bac016ec79fe29`, the
verified v0.41.0 implementation plus its evidence commit. v0.42.0 is planned;
local gates pass and exact-tag CI proof is pending. The single maintained
[integrator brief](DOWNSTREAM_INTEGRATION.md) owns the current verified pin.

## Measurement and diagnosis

Machine: **m3studio-001**, site **Hoth**; SSH endpoint
`admin@hoth-m3studio-001.local`. Darwin 25.6.0, arm64, 32 logical CPUs,
512 GiB RAM. Zig 0.17.0 via mise, ReleaseSafe, BBR and fixed benchmark
settings. Source archives, not worktrees/checkouts, are under
`/Users/admin/.cache/quic-zig/stream-cleanup-2026-10-10/`.

M3 builds finished before timing. Binaries were warmed, then six pairs ran
serially, alternating which version ran first. Each bulk trial contains
nine 64 MiB samples. Churn runs all six windows once per trial. The measured
sources match the implementation above; benchmark version strings are
0.41.0 because timing preceded the release bump. CPU snapshots were 99.1%
idle before engine pairs and 99.29% after; native bulk 99.20% and 99.32%.
The final latency snapshot was 96.35% idle. Small changes remain noisy.

The fresh baseline gave tick 3.565 us/stream at window 4,096 against 0.965
at 256. The narrowed feedback loop was:

```sh
mise exec -- zig build bench-e2e -- --scenario churn --cell churn_window4096_rtt30ms --json churn.json
```

The target was ≥20% lower wide-window tick cost, without changing virtual
behavior. Ranked falsifiable hypotheses were: (1) full-map cleanup scans
cause the scaling; (2) stream destruction dominates; (3) sendable-list
removal dominates; (4) other timer work dominates. Three direct baseline
Time Profiler captures yielded 1,724 usable Running samples of 1 ms, plus
two excluded stackless markers. Cleanup appeared in 81; iterator/header/
capacity leaves accounted for 65. Destruction accounted for four. Scanning
was the focused cause.

Three production-candidate captures yielded 1,790 usable samples, plus two
excluded markers. Cleanup appeared in four samples, all destruction/free
work, with no map-walk leaves under cleanup. These short captures corroborate
the timings; they are not precise per-function percentage estimates.

## Focused change and preserved behavior

A fixed list holds up to 128 `*Stream` candidates, with an in-list bit to
merge duplicate notices. Existing ACK, FIN/data, RESET_STREAM, read/consume,
and STOP_SENDING cleanup notices name the stream. Stopped receive halves
are drained at tick, preserving the callback's borrowed-buffer lifetime.
Candidates are reconsidered then, rather than presumed terminal.

Stream pointers survive map growth. At GC, current key-slot addresses are
resolved once and sorted before mutation, preserving the map iterator's
retirement and stopped-read order. That ordering relies on the pinned Zig
HashMap implementation; Debug independently compares IDs and order against
the actual walk. Revalidate it on toolchain changes. Debug also checks stopped
buffers before the diagnostic walk can mask a missed notice.

Overflow uses the authoritative full walk. `markStreamsGc()` keeps its
existing contract for fixtures/raw callers and requests that walk. A full
128-stream retirement batch schedules a full walk on the next tick, exactly
as before. There is no candidate-list allocation or OOM path. The 128-stream
retirement cap, 256-record end-evidence ring, stream credit, tombstones,
resident-byte accounting and late-reply handling stay unchanged. No new
public operation or toolchain migration is required.

The inline pointer array costs 1 KiB per 64-bit Connection, plus its count/
flag; the per-stream membership bit is bounded state. Bulk transfer allocation
counts remain 58 in every measured trial. No per-stream heap queue is added.
A post-timing compiler-size probe confirms Connection 11,480 → 12,512 bytes
(+1,032, 9.0%) and Stream 440 → 440 bytes on aarch64 macOS. This is a fixed
per-connection memory tradeoff, including idle connections. The temporary
compileLog intentionally fails compilation to emit sizes and is restored;
it is not part of the gates or measured production binaries.

## Engine results

Median of six paired trials, microseconds per stream:

| Window | Baseline tick | Candidate tick | Tick change | Poll baseline → candidate |
|---|---|---|---|---|
| 1 | 33.802 | 33.424 | -1.1% | 55.370 → 55.705 |
| 4 | 8.965 | 8.845 | -1.3% | 14.056 → 14.133 |
| 16 | 3.067 | 3.061 | -0.2% | 4.429 → 4.404 |
| 256 | 0.963 | 0.790 | -18.0% | 0.731 → 0.743 |
| 1,024 | 1.414 | 0.729 | -48.5% | 0.620 → 0.621 |
| 4,096 | 3.548 | 0.735 | -79.3% | 1.060 → 1.055 |

Same executable, forced walk versus candidates (scratch-only control):

| Window | Forced walk tick | Candidate tick | Change |
|---|---|---|---|
| 256 | 0.963 | 0.826 | -14.2% |
| 1,024 | 1.433 | 0.744 | -48.1% |
| 4,096 | 3.489 | 0.734 | -79.0% |

Bulk engine: 997.484 → 1001.432 MiB/s
(+0.4%, below the 5% threshold). All production/control trials retain 87,876
datagrams and 58 transfer allocations. The full probe patch and raw reports
are in the [portable record](stream-cleanup-2026-10-10.json); no probe field,
flag or logging ships. At window 4,096 the first candidate control reports
six fallback walks among 1,915 GC calls, so the bounded fallback is exercised.

The full harness wall result is a limitation: production baseline
69.521 → candidate 72.101 us/stream (**+3.7%**), whereas the same-binary
control is 71.934 → 68.294 (**−5.1%**). Sorting in
`bench/e2e/harness.zig.collectStreamIds` dominates these runs. Its merge leaves
appear more often in candidate captures (mergeInto 491 versus 431;
mergeExternal 166 versus 109), offsetting cleanup savings. This is consistent
with binary-layout effects, but does not prove their exact mechanism. The
same-binary result isolates the benefit of skipping scans. Neither full-wall
comparison is advertised as a general application throughput gain.

## Native UDP and tails

Six paired 512 MiB uploads, default receive/send batches 16/64, buffer reuse,
socket tuning off and existing offloads on:

| Metric | Baseline | Candidate |
|---|---|---|
| Bulk MiB/s | 173.935 | 173.534 |
| CPU ms/MiB | 9.352 | 9.297 |
| Single-peer echo p50/p99 us | 32 / 95.5 | 32 / 95 |
| Four-client bulk MiB/s | 451.599 | 458.274 |
| Four-client echo p50/p99 us | 46.5 / 115.5 | 47 / 119 |

Each latency trial has five single-peer samples of 2,000 pongs, and three
multi-peer samples with four clients over two server loops. Every bulk sample
delivers exactly 512 MiB and one clean stream, or 256 MiB and four clean
streams. Multi-peer echo completes 4,000 pongs/sample. Paired p99 trial medians
span 89–121 versus 93–96 us for single-peer, and 100–128 versus 106–161 for
multi-peer. Tails overlap; no repeatable gain or clear regression is claimed.
Darwin reuseport again routes the four loopback flows to one server socket.
These results do not validate real NIC line rate or new Linux/backend gains.

## Correctness and gates

Four new tests were run against the old implementation before the change
(their preservation checks passed), then strengthened with candidate-list
invariants. They cover duplicate notices and map growth, exact map retirement
order, overflow with the exact 128-stream batch, end records surviving the
next tick, stopped reads with FIN gaps, late frames, and allocation failure.
Existing FIN/reset ACK, read/consume, implicit-ID and reordered-reply tests
remain in the full suite. All 31 virtual impairment/fairness/churn lines are
byte-identical to fresh baseline runs.

Three deliberate ReleaseSafe mutants fail: dropping overflow work,
removing map-order sorting, and omitting the STOP_SENDING cleanup notice.
They fail behavioral assertions, not compilation. Production source is
restored; tagged scratch diagnostics are absent from the shipped tree.

Full Debug: 37/37 build steps; final emitted count 1,500/1,500 with other
targets cached. Full ReleaseSafe: 30/30, emitted 2,062/2,078 (16 skips;
cached targets omitted from counts). Windows and x86-linux-musl default
builds are 15/15 and compile-only tests are clean. Default, test-app (50 tests),
conformance, qns-endpoint, examples, bench-test and threaded bench-io-build
all pass. The external wide matrix is not repeated: retirement order/batching,
flow-credit order and all virtual lines are preserved. Exact-tag quic-go
interop and the other four mandatory CI gates still must prove the release.

## Reproduction and evidence

```sh
mise exec -- zig build bench-e2e -- --scenario churn --json churn.json
mise exec -- zig build bench-e2e -- --scenario goodput --samples 9 --json bulk.json
mise exec -- zig build bench-io-build -Dbench-io-threaded-only
./zig-out/bin/quic-zig-bench-io --io threaded --scenario goodput \
  --mib 512 --samples 1 --receive-batch 16 --send-batch 64 \
  --buffers reuse --socket-tuning off --offloads on --json udp.json
```

Build and warm each archive before alternating six pairs. Keep builds,
profiles and other M3 load outside timings. Raw reports, capture XML, traces,
logs and scripts are retained in `benchmark-reports/stream-cleanup-2026-10-10/`
and the M3 scratch root above. The tracked JSON contains measured reports,
binary/source identities, profiles, CPU snapshots, mutants and the control
patch. The maintained integrator brief is ready for owner relay; no downstream
checkout or pin was changed and delivery to unavailable sessions is not claimed.

## Next sprint proposals

Start after the owner's choice. Goals below are proposals, not measured gains.

| Option | Problem and proposed work | Goal | Scope and risk | Acceptance |
|---|---|---|---|---|
| **Evented backend compatibility — recommended** | The measured native UDP ceiling remains about 174 MiB/s, with the prior line-rate profile dominated by syscalls/readiness. Stock Zig 0.17 Dispatch/Uring fail the I/O vtable contract. Repair and release a compatible compiler/std fork, then compare valid backends on m3studio-001. | Obtain a valid comparison; seek ≥10% UDP throughput or a clear CPU/MiB improvement. | Separate compiler/std sprint plus fork release; timer, cancellation, shutdown and platform risk. Any toolchain-floor move needs explicit migration evidence. | Focused std tests and fork CI/artifacts; paired M3 native/VM UDP, echo and multi-peer runs with byte/FIN checks, idle/cancel/shutdown cases, then full/cross/virtual/interop gates. |
| Receive-side servicing profile | Harness sorting dominates the wide-window profile, but that alone does not prove a production library bottleneck. Profile real Client/Server/app or RPC receive servicing; consider a ready-stream API only if application map sweeps dominate there too. | Establish real CPU per completed reply; seek ≥20% reduction at ≥1,024 live streams if the hypothesis holds. | One diagnostic sprint before an interface change. Readiness deduplication, FIN/reset delivery, implicit lower IDs, late replies and bounded memory are the main risks. | Paired M3 real-message workloads, harness/library CPU attribution, exactly-once end notifications and backpressure, reordered stream cases, all 31 cells and release gates for any resulting change. |
