# UDP I/O sprint — 2026-10-10

The native macOS probes did **not** produce a repeatable throughput gain.
v0.40.1 fixes benchmark/example completion and adds reproducible controls.
It keeps the UDP driver, protocol code, public API, default batch limits,
and Zig 0.17.0 pin unchanged. Existing Linux GSO/GRO help bulk uploads;
this is a measurement of released behavior, not a new transport speedup.

The machine is **m3studio-001**, at the **Hoth** site. SSH uses
`admin@hoth-m3studio-001.local`. Tests ran on its M3 Ultra, 32 logical CPUs,
512 GiB RAM, native Darwin 25.6.0 arm64. Linux results ran in its existing
OrbStack VM (Linux 6.13.7, Ubuntu 24.04 container, Docker 27.5.1, 32 VM CPUs and about 16 GiB VM memory). Native
and VM absolute rates are different environments and are not an A/B test.
The Linux container digest and executable hashes are in the
[compact evidence](udp-io-2026-10-10.json).

## Method and integrity

Source base: `4f746137c6087a388b7931c97152e8502feb5c34`; implementation:
`5dd1e5c63b27cc830e8b14941322761aff865153`. Source exports have no Git
worktrees. Changes were made in the main checkout on main. All measurements
are ReleaseSafe and IPv4 UDP loopback; none measures a physical link.

Builds, timing batches, CPU captures, and syscall tracing ran serially on
m3studio-001. Native host snapshots were 92.89% idle before the final
matrix and 93.0% after; Spotlight used about one core. Small effects are
therefore treated conservatively. Pairs alternate order; the batch matrix
rotates order. Each bulk pair transfers 512 MiB. Buffer and sendto probes
have six pairs, receive-drain four, and batch limits three trials per setting.
Echo uses five 2,000-ping samples per setting. Multi-peer checks use four
clients, three samples, 64 MiB and 1,000 pings per client.

Every final upload requires the exact delivered byte count and one clean
FIN per client. A reset or missing end evidence fails. The sender waits for
`SendStream.State.data_recvd`: ACKing the FIN packet alone can precede
ACKs/retransmission of earlier bytes. The FIN-before-data regression test
fails when restored to the old `fin_acked` rule (41/42 tests pass); the fixed
benchmark passes 42/42. An acknowledged reset also fails completion.

JSON schema `quic-zig-bench-io/3` records receive/send batch limits, timeout,
socket tuning, offloads, buffer mode, delivered bytes, and clean stream
count. Invalid/unsupported arguments fail with a nonzero exit status.

## Native macOS results

Medians; CPU is process user+system time over the transfer window, divided
by delivered MiB. Both endpoint loops count. Reused/per-pass controls use
one binary; their emitted code need not reproduce the old archive layout.

| Configuration | MiB/s | CPU ms/MiB |
|---|---:|---:|
| Per-pass buffers | 171.1 | 9.451 |
| Reused buffers | 170.7 | 9.476 |
| Receive 1 / send 64 | 152.7 | 11.469 |
| Receive 16 / send 64 (defaults) | 174.4 | 9.395 |
| Receive 64 / send 64 | 172.4 | 9.375 |
| Receive 16 / send 1 | 162.8 | 10.459 |

No same-binary buffer benefit is supported. An earlier separate-binary probe
suggested a small CPU reduction, but the stronger control did not confirm
it. Scratch reuse is retained as example/application cleanup; no transport
performance claim depends on it. Keep receive 16 / send 64: lowering either
limit hurts bulk throughput, and receive 64 does not help. Single-client
echo medians are 32–33 µs p50 and 78–92 µs p99 across these batch settings.

With four clients, one server loop delivers 461.1 MiB/s aggregate and two
loops 455.7 MiB/s (three samples each). All 256 MiB and four clean FINs
arrive in every upload; all 4,000 pongs arrive in every echo sample.
On Darwin the per-server counters show all traffic reaches one reuse-port
socket. This verifies concurrent completion and shutdown, not a physical
network fairness guarantee. Existing idle/timer coverage and the full
suite remain the timer checks; no receive-drain change was landed.

Two separate 512 MiB Time Profiler captures contain 4,853
(per-pass) and 4,909 (reuse) usable Running samples,
all weighted 1 ms. Their sendmsg + recvmsg + poll shares are 73.3% and
74.1%. Fills contribute 1.2% and 1.1%; no material reduction appears.
Three and five stackless Running markers are excluded respectively.
Captures include setup/teardown and are not timing runs. These are sampled
CPU shares, not syscall counts. Native exact syscall counting was not
available without additional privileges (`sudo -n` failed).

### Backend feasibility probes — not shipped

- **Ready receive drain:** stock Threaded's timed receive drains queued
  messages on its first nonblocking attempt, but its post-poll path returns
  one datagram. A bounded zero-time receive of the remaining slots cut
  median server iterations from 333,939 to
  197,251. Throughput moved only
  173.9 → 174.8 MiB/s.
  Iterations are not syscalls. The probe adds an empty-queue attempt and
  lacks evented/error-policy validation; it does not justify a driver patch.
- **Public sendto:** in an isolated copy of Zig's stock library,
  `netSendOnePosix` uses `sendto` only on Darwin when `message.control.len == 0`;
  messages with ancillary data still use `sendmsg`. Destination conversion,
  cancellation, and error handling are retained. Six paired trials give
  172.1 → 172.4 MiB/s,
  with CPU 9.416 →
  9.351 ms/MiB. No meaningful gain.
  The exact patch is retained in the JSON. The installed compiler and fork
  checkout were unchanged.
- **Evented:** stock Dispatch/Kqueue on Darwin and Uring on Linux fail to
  compile against the current I/O vtable (including `processReplacePath`).
  The latest published personal fork is a 0.17.0-dev build below this
  project's 0.17.0 floor. No compatible evented timing is claimed. Repair
  and release of that fork is separate work.

Darwin private multi-message APIs do not solve mixed-peer/ancillary sends;
the primary-source limits are linked in the [preceding profile](LINE_RATE_PROFILE.md).

## Linux VM results

Both libc builds use the same benchmark and baseline CPU target. Offloads
mean the existing GSO and GRO controls together. Defaults already enable
them. Six alternating 512 MiB pairs per libc:

| Configuration | MiB/s | CPU ms/MiB |
|---|---:|---:|
| musl, offloads off | 153.2 | 6.563 |
| musl, offloads on | 200.5 | 5.016 |
| GNU libc, offloads off | 154.3 | 6.487 |
| GNU libc, offloads on | 200.1 | 5.019 |

The musl result is +30.9% bulk throughput and −23.6% CPU/MiB with offloads.
GNU libc gives +29.7% and −22.6%. Neither libc is a proven throughput win
over the other in this single-client workload; cross-libc runs were not
interleaved. GNU four-client bulk is 504.2 → 710.4 MiB/s across three
samples per setting, with CPU 4.988 → 3.769 ms/MiB; treat that smaller
batch as supporting evidence, not an equivalent six-pair comparison.
Four-client musl bulk is 559.4 → 589.3 MiB/s with CPU 4.635 → 3.704 ms/MiB.
Single-client echo is about 9 µs p50 with either setting. A six-pair,
16,000-pong concurrent echo recheck gives 193,316 → 172,005 round trips/s
and p99 47.5 → 52 µs. Individual rates vary widely (some pairs reverse), so
this does not establish a stable latency regression or justify disabling
offloads. Separate GSO and GRO experiments are needed before changing policy.

Dedicated 64 MiB `strace -f -c` passes include handshake, ACKs, error returns,
and teardown; their slowed transfer rates are excluded. Musl reports
54,137 → 27,983 sendmsg calls, 58,740 → 30,789 recvmsg calls, and 522 → 154
ppoll calls with offloads. On 64-bit targets, Zig's bundled musl
`src/network/sendmmsg.c` loops over `sendmsg` because libc/kernel header
layouts differ. Thus a sendmmsg call in source does not prove kernel batching.
GNU libc emits real sendmmsg syscalls: 6,275 off / 27,655 on, alongside
56,468 / 29,994 recvmsg and 2,965 / 157 ppoll calls in its separate traced
64 MiB passes. Offload egress and ordinary batching take different paths;
tracing also changes pacing and batch occupancy. These counts do not show
a universal reduction in send calls with GSO and cannot predict untraced
throughput. Both libc diagnostics are preserved separately in the JSON.
Counts describe these traced transfers, not packet counts or stable
calls-per-packet ratios. No privileged native trace or physical-NIC capture
was obtained. ECN/path metadata handling is unchanged; these probes are not
an independent ECN/path validation.

## Validation and release

Local default build and named steps pass (`test-app`, conformance,
qns-endpoint, examples, bench-test, threaded bench-io-build). ReleaseSafe
full suite: 2,055/2,071 pass, 16 skipped. The 31 impairment/fairness/churn
virtual lines match the archived base byte-for-byte. CLI negative checks
fail for zero limits/timeouts, missing values, invalid buffer mode, and an
unavailable evented backend. The release fast gates and five exact-commit
CI gates are recorded in [release readiness](RELEASE_READINESS.md).

Wide interop is not repeated: protocol sources/tests are unchanged from
v0.40.0, as are UDP timers, batching, metadata, congestion, and loss behavior.
The standard release interop gate still applies. Integrators need no API,
option-map, or toolchain migration; the maintained
[downstream brief](DOWNSTREAM_INTEGRATION.md) owns the verified pin and CI.

## Reproduction

On the selected source export, use the pinned toolchain, build once, then
run the executable directly. Do not overlap builds/profilers and timings.

```sh
mise exec -- zig build bench-io-build -Dbench-io-threaded-only
./zig-out/bin/quic-zig-bench-io --io threaded --scenario goodput \
  --mib 512 --samples 1 --receive-batch 16 --send-batch 64 \
  --buffers reuse --socket-tuning off --offloads on --json trial.json
./zig-out/bin/quic-zig-bench-io --io threaded --scenario echo \
  --pings 2000 --samples 5 --json echo.json
./zig-out/bin/quic-zig-bench-io --io threaded --scenario all \
  --loops 2 --clients 4 --mib 64 --pings 1000 --samples 3 --json multi.json
```

Alternate paired order for six trials. Change only the control being tested.
For Linux, cross-build with `-Dtarget=aarch64-linux-musl` or
`-Dtarget=aarch64-linux-gnu`, copy each executable to m3studio-001, and run
it in the recorded Ubuntu container. Use `--network none` for measured
loopback runs. The standard threaded-only flag is needed on both targets.
For the sendto probe, pass `zig build --zig-lib=<isolated-stock-lib-copy>`
with that flag first; retain and alternate stock/probe executables.

Raw JSON/logs/traces, syscall summaries, archive sources, and driver/std
prototypes are retained locally under
`benchmark-reports/udp-io-2026-10-10/` and remotely under
`/Users/admin/.cache/quic-zig/udp-io-2026-10-10/`. The portable metrics,
configuration, full probe patch, and exact completion evidence are in the
tracked JSON. This directory is scratch evidence, not another checkout.

## Next sprint proposals

Start after the owner's choice. Proposals are not measured gains.

| Option | Problem and proposed work | Goal | Scope and risk | Acceptance |
|---|---|---|---|---|
| **Packet-builder common path — recommended** | Native UDP probes did not produce a useful patch. The prior engine profile attributes 8.5% to builder work. Measure and simplify recurring 1-RTT control checks; investigate a pending-reset list only if the scan has measurable cost. | Seek ≥5% engine benefit or a clear many-stream improvement; keep real UDP neutral. | Portable, about one sprint. Reset/loss/GC invalidation can lose required work; retain a Debug comparison against the walk. | Interleaved archived M3 baselines and same-layout controls, reset/loss/retry/GC tests, all 31 virtual cells, full suite and cross checks. Do not ship for a noise-sized gain. |
| Zig evented backend compatibility | Current stock evented code cannot compile and the available fork is below the version floor. Align the fork's Dispatch/Uring I/O vtables, prove cancellation/timer behavior, then repeat native UDP/echo/multi-peer measurements. | Obtain a valid backend comparison; seek ≥10% UDP or a clear CPU/MiB win without promising it. | Compiler/std work and a fork release, likely a separate sprint. Broader platform/toolchain compatibility risk; keep the project pin until results justify a deliberate migration. | Focused std tests, fork CI/artifacts, exact byte/FIN and metadata checks, idle deadlines/shutdown, paired M3 timing and CPU traces, quic full/cross/virtual and interop gates before any consumer migration. |
