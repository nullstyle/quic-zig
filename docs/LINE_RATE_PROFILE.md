# Bulk-transfer CPU profile — 2026-10-10

On the quiet M3 Ultra, v0.40.0 sustains **985.8 MiB/s** in the in-memory
engine benchmark. Real UDP loopback sustains **137.0 MiB/s** for the stock
16 MiB upload and **173.8 MiB/s** for a 512 MiB upload. The UDP profile places
72.8% of sampled running CPU time in send, receive, and readiness syscalls.
The next substantial bulk-transfer opportunity is the UDP I/O path.

This sprint establishes a baseline and ranks work; it ships no transport
change and creates no release tag. The verified integrator pin remains
[v0.40.0](DOWNSTREAM_INTEGRATION.md). These are IPv4 loopback and in-memory
measurements, not physical-NIC line-rate measurements.

## Provenance and method

- Source: exact tag `v0.40.0`, commit
  `5796be0f8989a081bb563b96fcc6a856f43eb11d`, exported with `git archive`.
- Machine: `m3studio-001` at the Hoth site (SSH `hoth-m3studio-001.local`),
  Apple M3 Ultra, 32 logical/physical CPUs,
  512 GiB memory, Darwin 25.6.0 arm64; Xcode 16.3 (16E140).
- Zig 0.17.0 through mise; native ReleaseSafe with BoringSSL. The in-memory
  benchmark reports the `apple_m3` CPU target and BBR.
- Builds, throughput runs, and CPU profiles ran serially. Cached executables
  were used for timing. No unrelated host process was stopped. Process
  snapshots are retained. Final timing snapshots show 99.32% idle before and
  99.9% after; individual profile snapshots show 97.73–99.32% idle. UDP
  results still vary with OS scheduling.
- Throughput executables print `MB/s` while dividing bytes by 1024². All
  rates here use the correct unit, MiB/s. CPU profiling and throughput
  measurements are separate runs; profiler overhead is not a speed result.
- [Machine-readable evidence](line-rate-2026-10-10.json) preserves every
  timing sample, profile totals/top symbols, and XML/executable SHA-256 hashes.
  Raw logs, cached executables, XML, and Instruments traces are retained in
  ignored `benchmark-reports/line-rate-v041/remote/`, also at
  `/Users/admin/.cache/quic-zig/line-rate-v041/evidence/` on the remote host.
  `v041` is a scratch-directory label, not a release.

Early local M5 runs overlapped a background Ghidra job. An Apple CoreSimulator
cache rebuild was found in the first remote UDP timing batch's process
snapshots. All throughput batches and CPU captures were repeated after it
finished. Only that final set is used here; the earlier raw files are
retained as exploratory evidence. M3/M5 rate differences are not before/after
results.

## Throughput baseline

| Workload | Samples | Median MiB/s | Dispersion / completion |
|---|---:|---:|---|
| In-memory 64 MiB, batch 1 | 9 | 980.708 | MAD 1.204; range 944.454–984.888 |
| In-memory 64 MiB, batch 2 | 9 | 986.163 | MAD 0.989 |
| In-memory 64 MiB, batch 3 | 9 | 985.798 | MAD 2.227 |
| Real UDP, stock 16 MiB smoke | 9 | 137.0 | Range 132.3–169.4; all bytes and clean FIN |
| Real UDP, 512 MiB smoke variant | 3 | 173.8 | Range 171.3–178.5; all bytes and clean FIN |

The reported in-memory baseline is the median of the three batch medians.
Every sample in the final batches is retained. Each 64 MiB transfer emits 87,876
datagrams. The JSON records 58 allocations for the reported transfer in
each batch; per-sample logs show 57–58. The smoke example uses
`std.Io.Threaded`, sends through the real Client/Server wrappers, and validates
the byte count and FIN acknowledgment. Its client and server explicitly set
`tune_socket=false`; library defaults are true.

The 512 MiB variant changes only the example's `total_bytes` from 16 MiB to
512 MiB. It amortizes startup/congestion-window growth and lengthens the CPU
profile. Its rate cannot be treated as an improvement over the 16 MiB case.

### Existing socket-tuning probe

The tuned variant additionally sets `tune_socket=true` on both endpoints;
the library is unchanged. Six paired trials alternate which executable runs
first, with no concurrent build or profile.

| Variant | Median MiB/s | Range | Result |
|---|---:|---:|---|
| 512 MiB, tuning off | 174.30 | 172.4–178.1 | All six uploads complete, FIN acknowledged |
| 512 MiB, tuning on | 174.25 | 171.5–176.5 | All six uploads complete, FIN acknowledged |

The median difference is −0.03%, inside run variation. This loopback test
does not demonstrate a tuning gain. It does not evaluate tuning under
physical-link bursts, loss, or multiple connections.

## In-memory engine CPU

Two Time Profiler captures contain 2,153 and 2,152 usable running samples, 4,305
total. Every sample has weight 1 ms. The table gives flat/self sample shares,
with counts combined across both captures. Inclusive caller shares must not
be added to these shares.

The second capture also exports one stackless sentinel marker, excluded
from CPU attribution. The JSON records both export-row and usable-sample
counts.

| Leaf or group | Samples | Share | Interpretation |
|---|---:|---:|---|
| AES-GCM encryption/decryption kernels | 777 | 18.0% | Dominant individual compute group |
| Copies and fills | 379 | 8.8% | Mostly write ownership, receive/read copies, frame encoding, allocator fills |
| `Connection.send.pollLevelOnPath` | 364 | 8.5% | Packet-builder bookkeeping and control branches |
| `zbssl_CRYPTO_memcmp` | 191 | 4.4% | Required AEAD authentication-tag validation |
| Clock (`mach_absolute_time`) | 88 | 2.0% | Includes benchmark timing; not all engine overhead |
| GCM associated-data processing | 108 | 2.5% | Packet-protection setup |
| `SentPacketTracker.record` | 62 | 1.4% | Recovery bookkeeping |
| Stream-map iterator | 41 | 1.0% | Includes RESET_STREAM scan in the builder |

The remaining copies do not reproduce the large redundant-copy opportunity
removed in v0.34.0. In-memory `CRYPTO_memcmp` is authentication work, not a
removable stateless-reset check. No authentication or memory-accounting rule
was weakened during profiling.

The packet builder still scans the stream map for RESET_STREAM in
`src/Connection/send.zig`. A pending-reset collection is a plausible future
optimization, especially with many live streams, but its bulk share is
small. `collectSendableStreamsByPriority` already uses the sendable list in
ReleaseSafe; only the Debug agreement check walks all streams.

The in-memory harness establishes TLS through its direct peer shortcut and
retains handshake-level state differently from the packet-driven wrappers.
Optimizing repeated empty long-header polls solely for this harness could
inflate its speed without improving real UDP. Any engine proposal must be
checked against both workloads.

## Real UDP CPU

One 512 MiB upload capture contains 4,838 usable running samples, all weighted 1 ms,
including client, server, and short setup/teardown activity. It excludes
waiting-thread samples. The result describes sampled running CPU, not wall
time spent waiting or a syscall count. Two stackless sentinel markers are
excluded from CPU attribution and recorded separately in the JSON.

| Leaf or group | Samples | Share | Main caller / implication |
|---|---:|---:|---|
| `__sendmsg` | 2,505 | 51.8% | `Io.Threaded.netSendOnePosix`; one send per datagram on this platform |
| `__recvmsg` | 689 | 14.2% | `Io.Threaded.netReceivePosix` |
| `poll` | 326 | 6.7% | `Io.Threaded.batchAwaitConcurrent` |
| Fills (`_platform_memset`) | 301 | 6.2% | 246 samples (5.1% overall) under smoke `SinkApp.onIteration` |
| Stream-map lookup | 152 | 3.1% | Wrapper/application access and stream handling |
| Send-chunk map insertion | 129 | 2.7% | Upload buffering |
| AES-GCM encryption/decryption kernels | 121 | 2.5% | Much smaller share when real UDP I/O dominates |
| Payload randomization | 54 | 1.1% | Example setup, outside the timed transfer |
| Copies (`_platform_memmove`) | 36 | 0.7% | Data movement |
| Packet builder | 42 | 0.9% | Engine builder is not the main UDP cost here |

The smoke callback creates a 64 KiB `undefined` read buffer on each pass;
ReleaseSafe emits a fill. Moving reusable scratch to application state is
worth measuring in a future benchmark/application cleanup. It would be an
example change, not evidence of faster transport code by itself.

Do not filter samples by the presence of a `transport.udp_*` frame: inlining
and tail calls erase that frame on the main send path. Such a filter drops
the 2,505 send samples and produces a misleading distribution.

The library already batches up to 64 outgoing and 16 incoming datagrams per
loop pass. The pinned `std.Io.Threaded` uses `sendmmsg` only on Linux; macOS
loops over `netSendOnePosix`. Its POSIX receive path uses `recvmsg`. Linux
GSO/GRO are also already implemented and enabled by default in this library;
their effect was not measured on this macOS host.

Darwin's `sendmsg_x`/`recvmsg_x` declarations are explicitly private.
`sendmsg_x` does not support address or ancillary data, which blocks a direct
replacement for the server's mixed-peer/ECN sends. This needs a bounded
backend feasibility check, not an assumed universal batching patch.
[Apple XNU socket_private.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/socket_private.h).
Apple's SwiftNIO Darwin `sendmmsg` shim also loops over `sendmsg`; its name
does not imply kernel batching.
[SwiftNIO Darwin shim](https://github.com/apple/swift-nio/blob/main/Sources/CNIODarwin/shim.c).

## Proposals at the end of the profiling sprint

The owner selected the UDP I/O path. Its results and current recommendations
are in [UDP_IO_SPRINT.md](UDP_IO_SPRINT.md). The table below records the
proposals made at the end of this earlier sprint. These were not measured
improvements. Estimated scope assumes the current platform/toolchain limitations.

| Proposal | Evidence / concrete work | Measurement goal | Scope and risks | Acceptance |
|---|---|---|---|---|
| **UDP I/O path — recommended** | 72.8% syscall/readiness share. Establish a reusable 512 MiB real-UDP benchmark, reuse sink scratch, then compare Threaded with a supported evented/backend path and Linux's existing batching/offloads. Count calls per delivered packet before selecting a patch. | Lower CPU per delivered MiB and reduce syscall/wakeup cost; seek a repeatable ≥10% real-UDP gain, without promising it. | One sprint for benchmark/backend feasibility; implementation may need another sprint or Zig fork work. Stock evented builds currently have I/O-vtable mismatches. Darwin private batching cannot simply serve mixed peers/ECN. | Interleaved timing and CPU profiles, complete byte count/FIN, idle timers/shutdown, multi-peer fairness, ECN/path metadata, full suite and Windows/x86 checks. Repeat 31 virtual cells; wide interop if timing or wire behavior changes. |
| Packet-builder bookkeeping | Builder 8.5%, stream iterator 1.0% in-memory. Profile and simplify the common 1-RTT control checks; measure a pending-reset collection or cheap no-reset gate, preserving retransmission and ordering. Add many-stream and real-UDP comparisons. | Stable ≥5% engine CPU/goodput benefit or a clear many-stream scheduling win; the reset scan alone is too small to promise the bulk goal. | Roughly one sprint, portable and narrower. Smaller real-UDP upside on this host; new invalidation/queue state can lose resets if incomplete. | Reset/loss/retry/GC invariants, Debug agreement, full suite and cross checks, all 31 virtual cells, interleaved archived baselines and code-layout controls for small gains. |

## Reproduction

Use an archive export of the tag in a scratch directory; it needs no git
worktree. Repository changes belong in the main checkout on main.

```sh
profile_root="$(mktemp -d "${TMPDIR:-/tmp}/quic-profile.XXXXXX")"
mkdir -p "$profile_root/source" "$profile_root/evidence"
git archive v0.40.0 | tar -x -C "$profile_root/source"
cd "$profile_root/source"
mise trust mise.toml
mise exec -- zig build bench-e2e -Drelease=true -- --scenario goodput --samples 9 --json ../evidence/baseline.json
mise exec -- zig build run-goodput-smoke -Drelease=true --summary all
```

After the first build, invoke its cached executable directly. Run three
9-sample goodput batches serially. For long real-UDP runs, change only
`const total_bytes: usize = 16 << 20` to `512 << 20` in the exported example,
build once, and run the cached executable. For the tuning probe change only
its two `tune_socket=false` fields to true; retain the untuned executable and
alternate pair order for six trials. Require success, 536,870,912 bytes at
the sink, and `fin drained: true` for every long upload.

On the remote host, use `/Users/admin/.local/bin/mise` if its non-login SSH
PATH does not include mise. Capture CPU separately:

```sh
xcrun xctrace record --template 'Time Profiler' --time-limit 8s --no-prompt \
  --output engine.trace --launch -- "$engine_exe" --scenario goodput --samples 32
xcrun xctrace record --template 'Time Profiler' --time-limit 20s --no-prompt \
  --output udp.trace --launch -- "$udp_exe"
xcrun xctrace export --input engine.trace --toc --output engine-toc.xml
xcrun xctrace export --input engine.trace \
  --xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]' \
  --output engine-samples.xml
```

Use the same export for `udp.trace`. Both targets exit before the time limit;
recording stops on exit. Resolve XML `id`/`ref` nodes for stacks, frames,
states, and weights before counting. This host exports `backtrace`; newer
Xcode can export `tagged-backtrace`. Count the first frame for flat shares
and retain all process threads. Preserve raw traces and metadata so a future
result can be compared on the same machine, mode, and workload.
