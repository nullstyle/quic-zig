# Sprint 3: application workloads and stream-limit readiness

Sprint 3 starts from committed Sprint 2
`c74110a94667dd155068b862cb7a966aadbe7697` on
`codex/sprint-3-application-profiles`. Its scope is real application profiling
and repairs supported by reproduced correctness or performance failures.

## Reproduced transport defect

The public qmsg snapshot-recovery workload exposed an inherited idle-cache
defect. After an application timeout, another request can reach the peer's
stream limit. `openNextBidi` / `openNextUni` queue a
`STREAMS_BLOCKED` notification through `noteStreamsBlocked`, but that change
did not invalidate the connection's cached idle state. Debug's full-builder
cross-check then produces a packet where the cached path expected none and
asserts. An optimized build can delay the notification until another change
invalidates the cache.

The paused-server application uses valid nondecreasing owner timestamps,
relative request deadlines, canonical event ownership and immediate re-pumping
after queued work. Adding a sleep changes reproduction timing without fixing
the transport. The defect also reproduces on released QUIC v0.37.2; it is not a
new candidate-only regression. A copied native recovery binary reproduced it
in two of three initial runs.

The focused regression primes a confirmed connection's idle cache, exhausts
the bidi and uni stream limits through public open-next calls, and requires
the blocked notification to reach the wire. It also checks duplicate
suppression. The existing idle-cache table also reproduced the same assertion
after a public bidi/uni `queueMaxStreams` grant. The two-line repair invalidates
cached idle state when either `STREAMS_BLOCKED` or `MAX_STREAMS` is newly queued;
duplicate suppression and transport policy stay intact.

## Measured workloads

`tools/profile-applications.py` builds one public qmsg Req/Rep consumer against
the native QUIC pin and an explicitly selected source. It freezes source
copies, uses one QUIC module and the established
`{target, release, sanitize-c = "trap"}` options, installs exact binaries, and
alternates their timed execution order. Compiler/binary/source hashes, commands,
child CPU and RSS, application timings, completion, queue and allocation
counters accompany the results. Build time is outside timed runs.

The initial pre-repair baseline used three samples per lane, each with 50,000
1 KiB requests, concurrency and stream window eight, 128 warm-up exchanges and
200 ms idle observation. All 300,000 measured replies matched their requests,
with zero drops and zero counted Zig-owned live bytes after teardown. The warm
CPU medians were 1.364 s native and 1.397 s selected; wall medians were 1.924 s
and 2.044 s. The sample ranges overlap, so this baseline does not establish a
transport performance regression. These are dated observations on this Mac
while other producer work was active.

The counting allocator observes roughly 36 Zig-owned allocations per exchange;
it does not include BoringSSL/libc allocations. Whole-process RSS is recorded
separately. One bounded Time Profiler capture of the selected binary completed
the exact workload. Across 1,248 weighted Running ms, flat leaf shares were
39.26% `__sendmsg`, 13.78% `__recvmsg`, 5.61% `poll` and 6.17% connection-stream
hash lookup. One stackless marker was excluded. These are sampled CPU shares,
not syscall counts or evidence that a particular optimization would help.

`tools/profile-composition.py` uses the existing parent composition graph to
build and time the reliable-publication and snapshot-recovery examples. Their
machine-readable reports must pass application delivery, filtering, queue,
timeout and convergence checks. The publication environment guard's no-op
output cannot qualify as a workload run. Cold setup, warm work and intentional
outage time remain separate from whole-process timing.

## Qualification and limits

Exact diagnostics and profile records are retained under
`benchmark-reports/sprint-3-2026-10-26/`; the final coordinated matrix and its
source identities live in qmesh's `evidence/sprint-3-2026-10-26/` index. Initial
development failures, timing-dependent non-reproductions and deterministic
regression evidence remain distinguishable.

The fixed candidate requires fresh runtime qualification; Sprint 2's
runtime-equality claim no longer describes it. Public dependency pins and
versions remain unchanged. Released v0.37.2 remains an immutable negative
control for the idle-cache defect. The inherited mixed-fairness promotion hold
also remains. These local application measurements establish no hosted CI,
native Windows, physical-network performance or release approval.
