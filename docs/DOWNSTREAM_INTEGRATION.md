# Downstream integration

This is the maintained brief for quic-zig integrators. Update this file in
place after each sprint; do not create another file for each tag. The current
verified pin is at the top. Migration guidance is cumulative. Main-only work
must be labelled separately from released behavior. For post-tag verification,
read the [latest maintained brief](https://github.com/nullstyle/quic-zig/blob/main/docs/DOWNSTREAM_INTEGRATION.md);
a tagged archive contains the brief as it stood when tagged.

Last updated: 2026-10-10. Current release: **v0.42.2, verified**.
v0.42.2 keeps benchmark fixture tests independent of the optional evented
benchmark, correcting the stock Zig 0.17 Linux compile failure in v0.42.1.
**Do not pin v0.42.1.** The current release keeps Threaded as the default and
requires no API or toolchain migration. The matching evented fork was
published after its blocking LLVM assertion was repaired at source
(`0.17.0+fork.3bfc1a3ab`, 2026-10-11); its adoption has separate gates —
see the evented section below.

The preceding v0.42.0 stream cleanup sprint is complete. Lifecycle transitions
name up to 128 cleanup candidates, avoiding most full-map scans; overflow and explicit marking
keep the authoritative walk. Six paired m3studio-001 trials, at site Hoth,
reduce tick time per stream 48–79% at windows 1,024–4,096. A same-binary control
confirms the scan cost. Retirement/credit order, the batch/end-evidence contract
and late replies are preserved. No API/toolchain migration is required.

The fixed list adds 1,032 bytes per M3 Connection (11,480 → 12,512, including
idle connections); Stream stays 440 bytes and the list never allocates. Bulk
and native UDP are within noise. Production harness wall time rises 3.7% while
the same-binary control falls 5.1%; no general application-throughput gain is
claimed. See [stream cleanup evidence](STREAM_CLEANUP_SPRINT.md). The preceding
[packet-builder sprint](PACKET_BUILDER_SPRINT.md), [UDP sprint](UDP_IO_SPRINT.md)
and [line-rate profile](LINE_RATE_PROFILE.md) remain dated evidence.

## Current pin and build options

Tag `v0.42.2` = `2aa5bae31b7eab42cf95a654ab9717248d6f2498`.
Package hash: `quic-0.42.2-DnSYvVJRZQDaf9LFsqj9k1cFzPeYCNwb3HgKBDn8s07g`.
Toolchain: Zig 0.17.0, pinned by mise. Use ReleaseSafe for deployed code.

```sh
mise exec -- zig fetch --save https://github.com/nullstyle/quic-zig/archive/refs/tags/v0.42.2.tar.gz
```

Every parent in one binary must pass the same dependency options:

```zig
const quic_dep = b.dependency("quic", .{
    .target = target,
    .release = optimize != .debug,
    .@"sanitize-c" = @as([]const u8, "trap"),
});
exe.root_module.addImport("quic", quic_dep.module("quic"));
exe.root_module.addImport("boringssl", quic_dep.module("boringssl"));
```

Take both modules from that dependency to preserve type identity, including
TLS-context overrides. The package supports Debug and ReleaseSafe. For the
full setup and public surface, see [Embedding](../EMBEDDING.md) and
[API stability](API_STABILITY.md).

## What an integrator needs to know

### Benchmark and smoke-example consumers

v0.40.1 waits for all stream bytes and FIN to be ACKed; `fin_acked` alone
can precede earlier data ACKs/retransmission. The receive-side benchmark
requires exact delivered bytes and clean completion. If you copied the
bulk-smoke or benchmark upload loop, take the corrected example logic.
Library API, UDP defaults, and the coordinated option map are unchanged.

Benchmark report readers should accept `quic-zig-bench-io/3`, which adds
batch/tuning/offload/buffer settings and delivered-byte/clean-FIN evidence.
The development benchmark is not part of the consumer archive. Existing
Linux offloads are already enabled by default; native macOS probes yielded
no repeatable speedup, so this release advertises no transport gain.

### Writes and memory windows

`streamWrite` can return a short count or zero as backpressure. Retry the
unaccepted tail after the connection makes progress. Since v0.38.0, writes
leave a receive reserve within `max_connection_memory`; application-side
workarounds that capped writes at half the budget are no longer needed.
A slow reader's unread data reduces the writer's remaining share.

The receive share is the larger of the announced connection window and the
configured receive-window cap, with that cap limited to half the connection
memory budget. Announcing `initial_max_data` above half the budget reduces
write capacity; at or above the whole budget it leaves zero capacity. Raise
the budget or lower the announced window. Wrapper defaults are consistent:
16 MiB connection window and 32 MiB memory budget.

Since v0.40.0, `Server.init` and `Client.connect` emit `config_warning` when
`initial_max_data > max_connection_memory / 2`. Warnings do not reject or
rewrite the configuration. Client adds optional `Config.log_callback` and
`log_user_data`, with `Client.LogEvent` and `Client.LogCallback`. Server uses
its existing log callback.

Since v0.39.0, `Connection.streamWriteCapacity(id)` reports what the next
write could accept: the smaller of stream-buffer room and free writer budget.
It returns zero for a finished or reset send half. The answer can change after
a write, read, ACK, or frame from the peer; it is not flow credit alone.
Use it when a frame header and payload must be written together.

### Closure and stream cleanup

`Connection.isClosed()` becomes true when CONNECTION_CLOSE is sent or
received, including closing and draining. Use `closeState()` to distinguish
those phases from terminal closure. v0.40.0 corrects the documentation;
the behavior is unchanged.

Since v0.37.2, a connection at rest reclaims ended streams at its next tick.
`TimerKind.stream_gc` makes that tick due immediately. Integrators using
`nextTimerDeadline` or `Server.tickDue` receive that deadline. Workarounds
that touched each connection before every tick are no longer needed.
In v0.40.0, busy ticks skip the cleanup walk when no stream needs cleanup;
cleanup timing and retirement evidence are unchanged. Since v0.42.0, named
lifecycle transitions use a bounded candidate list; overflow and raw
`markStreamsGc()` callers request the authoritative map walk. Retirement
order, the 128-stream batch and 256-record end-evidence survival remain
unchanged. The fixed Connection memory cost is documented above.

A test fixture that writes directly to a send half must call
`conn.noteSendable(s)`. Fixtures that set terminal or ACK state directly
must also simulate its cleanup notice (`markStreamsGc`). Prefer real public
operations. In invariant tests, `bytes_resident` must equal
`Connection.residentBytesSum()` after each operation.

### Custom event loops and connection memory

Use `Server.takeReady`, drain each returned slot, then `slotDrained(slot, now)`;
use `tickDue(now)` and `nextDeadline(now)` to avoid sweeping idle connections.
Do not reap slots while a `takeReady` slice is in use. The bundled UDP loop
already uses this API. The [foreign-loop example](../examples/foreign_loop_embedder.zig)
shows the integration.

The sendable list allocates on first stream output. The server's ready list
and timer heap allocate when the first connection arrives. Sent-packet
tracking grows from a small allocation and returns capacity when idle.
These allocations preserve the lower idle-memory cost; they are intentional.
The packet scratch is thread-local, about 21 KiB per engine thread, not per
connection. A `Connection` must live in writable memory because its const
`nextTimerDeadline` accessor updates a cache.

### Evented backend adoption — experimental, main-only

The [evented sprint report](EVENTED_BACKEND_SPRINT.md) records repairs in the
stable Zig 0.17 fork and completed native measurements. Threaded remains the
default: Dispatch and shared Kqueue establish no native throughput gain, and
both lose four-client goodput. The fork release that was held on a compiler
LLVM assertion is now published: the assertion was repaired at the LLVM
source seam (see the [sprint report](EVENTED_BACKEND_SPRINT.md) and
zigfork's `llvm-v3i8-mmo-fix-2026-10-10.md`), and the stable fork
`0.17.0+fork.3bfc1a3ab` passed the rebuilt-compiler gates — including full
QUIC ReleaseSafe under an assertions-enabled patched LLVM — before
publication. The verified QUIC pin above covers the stock-toolchain
Threaded release; experimental fork adoption remains separate owner work
that must validate backend-specific paths on the matching compiler/library.
No default toolchain or consumer pin was changed.

Use a verified, matching compiler/library built from the fork's tagged-0.17
stable assembly. September's `0.17.0-dev` release is below current 0.17.0
floors; do not relax those floors or relabel an older compiler. Preserve the
same BoringSSL revision and coordinated dependency options shown above.
Stock-compiler checks against a replacement `lib` are limited source evidence,
not a substitute for the rebuilt fork gate.

QUIC continues accepting `std.Io`; selecting a backend changes its scheduling
and lifetime obligations. Keep one active backend context per participating
OS thread, use managed fibers/registered threads, drain groups/futures before
deinit, and finish/cancel socket operations before closing through the same
owning `Io`. Foreign-thread calls, nested active instances and concurrent
socket close are unsupported. Existing raw-thread examples need an explicit
evented context design. Synchronous file/process fallbacks can block workers.

Dispatch/Kqueue provide reviewed UDP and stream paths; Uring remains UDP-only
and unsupported stream operations return errors. Backend allocation/stack and
timer limitations are in the sprint report. Native macOS, BSD semantic-only,
Linux cross-build and native Linux results must be read separately.

`capnp-zig` still has `evented_available=false`. Its owner must revise its
expected-failure canary and validate actual TCP/Unix/SCM_RIGHTS, cancellation
and shutdown paths before activation. Inherited Unix-address bounds/encoding
and truncated ancillary descriptor ownership remain blockers; successful QUIC
UDP or complete-control tests do not resolve them. The maintained
[fork audit ledger](/Users/nullstyle/prj/zig/zigfork/docs/io-audit-followup.md)
records wider platform/tooling findings. No downstream checkout was edited,
and no external handoff delivery is claimed.

### ACK policy and earlier raw API changes

Bulk bursts normally get one ACK per two packets; a packet after a quiet gap
gets an immediate ACK. `ack_quick_gap_us` defaults to 1 ms; zero disables the
quiet-gap rule. `ack_frequency_policy` defaults to `.auto`; `.off` stops
outgoing extension requests. Unsupported peers see no extension frame.
Manual `requestAckFrequency` and `requestImmediateAck` calls can return
`AckFrequencyNotNegotiated`. The extension still uses provisional codepoints;
see [API stability](API_STABILITY.md) before relying on them.

Raw-Connection embedders moving from before v0.34.0 must account for two
changes: `packetKeys` returns a borrowed pointer, and `SendStream.bytes` is a
ring (`len`, `chunkBytes`, `chunkBytesContiguous` replace `bytes.items`).
Client, Server, and quic.app wrappers did not require those migrations.

## Released change history

| Release | Integrator effect | Required action |
|---|---|---|
| v0.42.2 | Benchmark fixtures use their own Threaded-only options, restoring stock Zig 0.17 Linux test/fuzz builds. Five exact-tag gates and a fresh URL consumer pass. | Use this verified pin instead of v0.42.1. No library API, toolchain floor or default-backend migration. |
| v0.42.1 — do not pin | Linux test/sanitizer/fuzz builds instantiate stock Uring's incompatible vtable through the newly imported benchmark fixtures. | Keep the tag rejected; use v0.42.2 or the preceding verified release. Passing other jobs does not repair this tag. |
| v0.42.0 | Bounded cleanup candidates cut wide-window tick time 48–79%; retirement/credit/evidence order is preserved. | No API/toolchain migration. Budget +1,032 bytes per M3 Connection, including idle; no bulk/UDP or application-throughput gain promised. |
| v0.41.0 | Packet-builder no-reset scans cost less: wide-window poll time falls 62–80%; reset ordering and virtual behavior agree. | No API/toolchain migration. No bulk or UDP speedup claimed. |
| v0.40.1 | Correct bulk smoke/benchmark completion; reproducible I/O controls and report schema 3. | No library/API/toolchain migration. Update copied example loops or benchmark report readers. |
| v0.40.0 | Busy ticks cost 51–54% less in churn; memory-window warnings; corrected closure docs. | Optional warning callback on Client; check small-budget window settings. |
| v0.39.0 | Sendable-list poll check; `streamWriteCapacity`; stronger Debug invariants. | Optional capacity check before indivisible writes. |
| v0.38.0 | Writes preserve receive reserve and release consumed prefixes under pressure. | Handle short writes; remove redundant half-budget write cap when ready. |
| v0.37.2 | Stream cleanup runs at rest; rest-cache invalidation fixes. | Prefer this or newer over v0.37.1; remove touch-before-tick workaround. |
| v0.37.1 | Every PTO probe retransmits stream data to a silent peer. | Supersedes v0.37.0, whose test gate was red. Do not newly pin v0.37.0. |
| v0.37.0 | Larger ACK-range coverage and ACK-frequency extension. | Optional policy configuration; use a later verified tag. |
| v0.36.0 | Ready/timer API and much lower idle memory. | Optional custom-loop migration to O(active connections). |
| v0.35.0 | Bulk ACK reduction, reordering recovery, receive-window tuning. | Optional ACK quiet-gap configuration. |
| v0.34.0 | CPU-per-packet reduction; two raw API changes above. | Update raw key/buffer access if moving from an earlier release. |

Older migration details and per-release measurements remain in
[CHANGELOG](../CHANGELOG.md) and [release evidence](RELEASE_READINESS.md).
Historical per-tag handoff notes are archived context, not the maintained
integrator brief.

## Validation of the current pin

All five gates were read at the exact tag commit,
**2aa5bae31b7eab42cf95a654ab9717248d6f2498**, at
**2026-10-10 22:34:26 UTC**, within 15 minutes of tagging at 22:19:29 UTC.

- [test 38090992546](https://github.com/nullstyle/quic-zig/actions/runs/38090992546): all seven jobs pass, including advisory macOS 26. Unix Debug, full sanitizer and 32-bit musl report 2,079/2,095 tests (16 skips). Unix ReleaseSafe reports 2,035/2,051 (16 skips; 44 benchmark fixtures cached after Debug). Windows Debug and ReleaseSafe report 2,012/2,051 (39 skips; benchmark fixtures excluded by the existing platform condition). Consumer-smoke loads quic-zig 0.42.2; check-modes validates 6 of 6. The 32-bit job executes with `-Dsanitize-c=off`; it is not a 32-bit ReleaseSafe claim.
- [rc-fuzz 38090994221](https://github.com/nullstyle/quic-zig/actions/runs/38090994221): `coverage verified: instrumented, 2,235,928 executions across 43 sites (floor 1,935,000)`; `n_runs=2,235,928 unique_runs=12,808 pcs_len=47781`. No actual failure markers; echoed scripts are excluded from that check.
- [quic-go-interop 38090992547](https://github.com/nullstyle/quic-zig/actions/runs/38090992547): pairs=1, cells=2, succeeded=2; failure, known-failure, unsupported, skipped and flaky counters are zero. Both cells executed.
- [QNS Image 38090992545](https://github.com/nullstyle/quic-zig/actions/runs/38090992545): the image build passes, with publish_image:false and push:false. The actual build command labels the exact tag commit and has no `--push`; publication remains disabled.
- [pin-lint 38090992586](https://github.com/nullstyle/quic-zig/actions/runs/38090992586): BoringSSL pin-lint OK and byte-identical typed pin; all four Zig pins and the two published Docker toolchain digests agree at 0.17.0.

A fresh-cache URL consumer fetched the advertised archive and hash with stock
Zig 0.17.0, then executed `zig build run -Doptimize=ReleaseSafe --summary all`:
11/11 steps succeeded and `consumer-smoke ok: quic-zig 0.42.2`. It uses the
coordinated release/sanitizer options and both exported modules shown above.
The URL fetch and consumer run completed at 22:21:18 and 22:22:09 UTC.

v0.42.1 remains rejected: [test 38090194012](https://github.com/nullstyle/quic-zig/actions/runs/38090194012)
has three failing Linux jobs, and [rc-fuzz 38090196055](https://github.com/nullstyle/quic-zig/actions/runs/38090196055)
fails on the same stock Uring `processReplacePath` vtable compile error. The
fuzz execution floor was met, but its build exited 1. This is not a sanitizer
finding or saved crashing input. The tag was not moved or rerun to hide the
failure. Earlier verified release evidence and the rejection are retained in
[release readiness](RELEASE_READINESS.md).

## Delivery and pin ownership

Each downstream session moves its own pin. Repositories linked into one
binary move together: cluster A is nest, qmsg, qmesh-zig, and mruby-quic;
http3-zig and capnp-zig move on their own cadence. A release is information,
not a forced cluster move. No downstream checkout or pin was changed here.

This file is ready for owner relay. The Claude downstream sessions in the
original handoff are unavailable to this chat's message tools. Delivery is
not claimed. Do not infer current consumer pins from old sprint notes.

## Unreleased fork correctness follow-up, 2026-10-11 UTC

Fork feature source through `017b3e4966a2` repairs Unix SCM_RIGHTS ownership,
ancillary bounds/errors/CLOEXEC, native Unix address encoding and Dispatch
timed-futex allocation failure. Native Darwin/Linux correctness cases and
the QUIC gates pass; the [report](UNIX_FD_HARDENING.md) records exact
compiler/library identities and limits. These fixes are absent from the
published `0.17.0+fork.3bfc1a3ab` artifact.

Owners adopting a future matching release must validate their actual
descriptor, cancellation and transport paths; expanded std networking
error sets may require exhaustive-switch changes. Darwin CLOEXEC is set
after receive and is not atomic with unrelated exec. Raw Unix datagram
Uring tests do not enable its public Unix/stream APIs or a public Unix pair
API. Threaded, stock Zig 0.17.0, QUIC v0.42.2 and downstream pins remain
unchanged. No downstream delivery or activation is claimed.
