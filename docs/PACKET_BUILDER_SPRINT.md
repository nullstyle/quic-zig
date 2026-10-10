# Packet-builder sprint — 2026-10-10

The no-reset 1-RTT path now uses the existing sendable list to avoid walking
all open streams. On m3studio-001, six paired runs reduce poll cost per stream
by 62%, 73%, and 80% at windows 256, 1,024, and 4,096. A same-binary control
confirms the cause. Bulk engine and native UDP results remain within about 1%.
This is a many-stream CPU improvement; it does not establish link line rate.

Implementation: `791acdc6448019814ab1d4ba433bf45443b4fe0f`, on main in the main
checkout. Baseline: `89953ff887143e3feca018daf60cd53b8ddcd595` (verified v0.40.1
plus its evidence commit). The release is planned as v0.41.0; it is not yet
tagged. Local gates pass. Post-tag verification will be recorded here and in
[release readiness](RELEASE_READINESS.md). The single maintained
[integrator brief](DOWNSTREAM_INTEGRATION.md) owns the verified pin.

## Measurement and diagnosis

Machine: **m3studio-001**, at site **Hoth**. SSH endpoint:
`admin@hoth-m3studio-001.local`. Darwin 25.6.0, arm64, 32 logical CPUs,
512 GiB RAM, Zig 0.17.0 through mise. All measured binaries use ReleaseSafe;
BBR and the existing default benchmark settings stay fixed.

Sources were exported to scratch directories under
`/Users/admin/.cache/quic-zig/packet-builder-2026-10-10/`. These are archives,
not Git checkouts or worktrees. Builds, profiles, and timed trials ran
serially on that machine. Every executable was warmed before the pairs.
Odd pairs run baseline first; even pairs run candidate first. All six pairs
are retained, including the slower third baseline bulk trial.
The settled CPU snapshots were 94.9% idle before the engine pairs and 99.1%
after; native bulk snapshots were 99.4% before and 98.75% after. Background
macOS activity still limits small wall-clock conclusions.

The feedback loop was the existing churn benchmark, including its timed
`Connection.poll` calls. A fresh baseline gave 5.16 us per stream at window
4,096 and 1.89 us at 256. The fresh nine-sample bulk baseline was 987.9 MiB/s,
consistent with the [earlier engine profile](LINE_RATE_PROFILE.md).

The ranked hypotheses were: (1) the reset walk grows with open streams;
(2) repeated control checks dominate even with one stream; (3) code placement
explains small gains. Three direct Time Profiler captures of the 4,096-window
baseline gave 1,822 usable Running samples of 1 ms, plus two excluded
stackless markers. Of 129 samples with the packet builder on the stack,
95 landed in stream-map iterator/header/capacity work. That walk occurs even
when no reset exists. The scan became the focused change; the other cold
control checks were left for separate evidence.

Three candidate captures gave 1,720 usable samples, plus one excluded marker.
Only 13 had the builder on the stack; none of those landed in the map walk.
This corroborates the timing, but the captures are too short to give precise
per-function percentages. Harness sorting itself accounts for much of the
whole-cell profile (`collectStreamIds` sorts each gathered id set). Thus the
poll column is more specific than total benchmark wall time. A trial that
launched a shell captured only its six startup samples, not its children;
that capture is excluded. Initial post-build runs are warm-up evidence only.

## Change and invariants

`src/Connection/send.zig` searches the **full** existing sendable list for an
unqueued reset. When none exists, it skips the map. When a reset exists, it
uses the original map walk to pick it, preserving reset frame order and the
one-reset-per-packet budget. After a failed list insertion, it uses the map
unconditionally. Debug compares all pending resets against list membership
and count. No new queue, allocation, public API, or lifecycle notice is added.

Using the STREAM chunk array would be wrong: it holds only 32 streams and
can hide a lower-priority reset. The list already tracks resets through
`streamReset`, STOP_SENDING, emission, loss, ACK, and GC. Direct send-half
mutations in test fixtures still require `noteSendable`, as before.

## Paired engine results

Medians of six trial results. Each bulk trial contains nine 64 MiB samples.
Churn uses 2,048 / 4,096 / 8,192 requests for the three wide windows.
Times below are microseconds per completed stream.

| Window | Baseline poll | Candidate poll | Reduction | Baseline tick | Candidate tick |
|---|---:|---:|---:|---:|---:|
| 256 | 1.921 | 0.736 | 61.7% | 0.932 | 0.958 |
| 1,024 | 2.347 | 0.631 | 73.1% | 1.433 | 1.427 |
| 4,096 | 5.298 | 1.067 | 79.9% | 3.836 | 3.569 |

A scratch-only binary adds a runtime `--reset-walk-probe` switch that forces
only the old reset walk. The rest of its code and Connection layout are
identical between modes. Its walk/list poll results are 1.919/0.742,
2.356/0.628, and 5.968/1.053 us per stream: reductions of 61.3%, 73.3%, and
82.4%. That switch, its Connection field, and harness plumbing are not shipped.
The complete probe patch and all five measured executable SHA-256s are in
[the portable record](packet-builder-2026-10-10.json).

Bulk medians of medians: 983.89 → 994.75 MiB/s (+1.1%); same-binary control
983.13 → 992.95 (+1.0%). Both are below the 5% bulk goal and the established
code-placement caution. No bulk speedup is advertised. All bulk samples have
87,876 datagrams and 58 transfer allocations. At window 4,096 the whole-cell
wall time is 75.18 → 69.80 us per stream, but that includes the simulated
network, reads, and harness sorting. Tick differences are incidental; this
change only targets polling. Peak live streams remain 3,750.

## Native UDP checks

Six alternating pairs of 512 MiB uploads, using Threaded I/O, 16/64 receive/
send batches, reused buffers, offloads enabled, socket tuning disabled, and a
5 ms receive timeout. Exact delivery and one clean completion are required.

| Metric | Baseline | Candidate |
|---|---:|---:|
| Bulk MiB/s | 173.311 | 173.499 |
| Process CPU ms/MiB | 9.335 | 9.360 |
| Single-peer echo p50, us | 32 | 32 |
| Single-peer echo p99, us | 93.5 | 91 |
| Four-client/two-loop bulk MiB/s | 451.70 | 460.08 |
| Four-client/two-loop echo p50, us | 46 | 45.5 |
| Four-client/two-loop echo p99, us | 128 | 91 |

Echo and multi-peer rows are medians of six paired trials: five samples of
2,000 pings for single echo, and three samples of four 64 MiB uploads / 4,000
pongs for multi-peer. Every multi upload delivered 256 MiB and four clean
completions. The first sequential echo/multi check showed a small worse tail;
the alternating follow-up did not repeat it. Paired single-peer p99 ranges
are 68–95 and 65–109 us; multi-peer ranges are 94–161 and 79–130 us. They
overlap, so the apparent multi-peer tail win is not advertised.

Native UDP bulk and CPU/MiB are neutral within noise. These loopback checks
are not a physical-link or stream-heavy UDP line-rate test. Darwin reuseport
continues to direct the four flows to one of the two server sockets. Linux
UDP was not remeasured this sprint; the preceding [UDP sprint](UDP_IO_SPRINT.md)
contains its separate offload and libc evidence.

## Validation

- All **31** impairment, fairness, and churn virtual-time output lines are
  byte-identical to fresh baseline runs. Frame count, credit, live-stream
  counts, and deterministic delivery times agree.
- Three new builder tests cover a reset behind 64 data streams, a packet too
  small for it, final-size preservation, retransmission, an ACK of an earlier
  copy, GC and late loss, actual failed list insertion, and multiple-reset
  map order with one reset per packet.
- Three ReleaseSafe mutants are caught: a 32-entry scan, omitted degraded
  fallback, and omitted loss-side `noteSendable`. The first and third fail the
  reset retry test; the second fails the allocation-fallback test.
- Debug full suite: 37/37 steps, 2,058/2,074 tests, 16 skips. ReleaseSafe:
  30/30 steps, 2,016/2,032 tests, 16 skips. The 42 benchmark fixture tests ran
  in the Debug invocation using their ReleaseSafe build and are cached in
  the following Safe invocation.
- Default build, test-app (50/50), conformance, qns-endpoint, examples,
  bench-test, and threaded-only bench-io-build all pass. Windows and
  x86-linux-musl default builds are 15/15 steps; test binaries compile clean.
- The wide external interop matrix is not repeated: reset order, packet
  budget, wire data, flow credit, and virtual-time behavior are preserved.
  The exact-tag quic-go interop and other mandatory CI gates remain required.

## Reproduction and evidence

```sh
mise exec -- zig build bench-e2e -- --scenario churn --json churn.json
mise exec -- zig build bench-e2e -- --scenario goodput --samples 9 --json bulk.json
mise exec -- zig build bench-io-build -Dbench-io-threaded-only
./zig-out/bin/quic-zig-bench-io --io threaded --scenario goodput \
  --mib 512 --samples 1 --receive-batch 16 --send-batch 64 \
  --buffers reuse --socket-tuning off --offloads on --json udp.json
```

Build each exported source before the measurement phase. Warm both binaries,
alternate order for six pairs, then repeat with both modes of the scratch
probe from the portable record. Do not profile or build during timing.
Raw reports, captures, logs, scripts, and prototypes are retained locally in
`benchmark-reports/packet-builder-2026-10-10/` and on m3studio-001 in the scratch
root above. The tracked JSON contains raw measured reports, CPU snapshots,
probe patch, binary identities, virtual lines, and summaries. No downstream
checkout or pin was changed. The integrator brief is ready for owner relay;
delivery to the unavailable Claude sessions is not claimed.

## Next sprint proposals

Start after the owner's choice. Goals below are proposals, not measured gains.

| Option | Problem and proposed work | Goal | Scope and risk | Acceptance |
|---|---|---|---|---|
| **Many-stream GC — recommended** | After this change, the 4,096-window tick still costs 3.57 us/stream versus 1.07 for poll. Profile actual cleanup work, then consider a bounded candidate queue if full-map cleanup scans dominate. Preserve the existing retirement batch and end-evidence contract. | Seek ≥20% lower wide-window tick cost; keep memory and virtual behavior stable. | One focused portable sprint, contingent on measurement. Missed terminal transitions can leak streams; premature removal can lose late replies or end evidence. | Interleaved M3 runs, Debug agreement with the walk, FIN/reset/STOP_SENDING/ACK/read/late-reply and allocation-failure cases, batch/evidence survival checks, all 31 cells, full/cross gates, UDP completion and tails. |
| Zig evented backend compatibility | Stock Dispatch/Uring currently fail the I/O vtable contract, and the available fork is below the project floor. Repair and release a compatible fork, then measure native/VM UDP with it. | Obtain a valid backend comparison; seek ≥10% UDP or a clear CPU/MiB win. | Separate compiler/std sprint and fork release. Timer, cancellation, shutdown, and cross-platform risk; a project toolchain migration requires its own evidence. | Focused std tests and fork CI/artifacts; paired quiet M3 UDP/echo/multi-peer runs with byte/FIN checks, idle/cancellation/shutdown tests, then QUIC full/cross/virtual/interop gates. |
