# Evented backend sprint — 2026-10-10

The stable Zig 0.17 fork has evented I/O contract and lifetime repairs, and
the native comparison is complete. **Threaded remains the default:** neither
Dispatch nor shared Kqueue improves native throughput in these runs. Final
Linux/rebuilt-release proof remains pending below. The maintained
[integrator brief](DOWNSTREAM_INTEGRATION.md) owns the verified QUIC pin;
QUIC release verification and experimental fork adoption are separate facts.

The prior [UDP sprint](UDP_IO_SPRINT.md) could not compare evented backends:
stock 0.17 referenced removed I/O vtable fields, and September's published
`0.17.0-dev` fork was below the projects' stable-0.17 floor. Native loopback
profiles placed most sampled CPU in socket/readiness syscalls. This sprint
first makes the comparison valid and reviews the fork's wider integration
surface. It does not establish physical-NIC line rate.

## Compatibility and source identity

Use the fork's **stable** assembly, based on tagged Zig `0.17.0`
(`7647adab80`), with feature `evented-0.17`. The candidate is developed in
`ziglang` on `feat/evented-0.17`. The separate master assembly declares a
0.18 development line; passing stable checks does not validate master.
The intended stable identity is `0.17.0+fork.<buildsha9>`, tied to its actual
source manifest. An older development compiler must not be relabelled or
accepted by weakening consumer version floors.

The matching compiler, selected `lib` directory, source checkout and project
mise pin are separate facts. Focused checks using stock 0.17 with the candidate
library prove that source pairing, not compiler/code-generation changes or a
released fork. Deployment and the final gate require the rebuilt compiler and
its matching library. This sprint does not alter the default mise toolchain,
BoringSSL revision or downstream pins.

The maintained [fork audit ledger](/Users/nullstyle/prj/zig/zigfork/docs/io-audit-followup.md)
contains the capability inventory, inherited handoffs and developer backlog.
It is a local developer link, outside a fetched quic-zig archive. The fork's
release manifest must supply portable source identities before publication.

## Concrete repairs

| Area | Resulting behavior | Why it matters |
|---|---|---|
| Stable I/O contract | Remove obsolete `processReplacePath`/`processSpawnPath` entries; honor 0.17's executable union and required inherited-parent-handle entries. | Executable selection and working directory are independent; adapters receive correctly typed backend-owned userdata. |
| Owned fallbacks | Dispatch, Kqueue and Uring own `Threaded.init_single_threaded` state; Uring gives it the existing synchronized allocator wrapper. | Adapter state has the right allocator/environment and avoids unrelated process-global signal-handler installation or teardown. |
| Stream/control results | Shared `Stream.read` handles `ReadResult`; supported backends preserve data length, control length and truncation metadata. Operation userdata keeps full slice metadata. | Ancillary buffers survive direct, async and timed paths without narrowing lengths. Pending userdata grows from seven to nine machine words. On aarch64 macOS the union layout grows each batch Storage from 88 to 96 bytes (+8). |
| Dispatch batch ownership | Operations retain their own registrations, buffers and source teardown until completion/cancellation releases them. Separate batches sharing a socket stay independent. | Returned stack/buffer storage and recycled descriptors must not be accessed by a late handler. |
| Receive accounting | Kqueue and Uring stop draining after the first packet exhausts caller data space; Kqueue hard errors preserve the consumed-message count. | A following queued datagram must not be consumed into a zero-length tail or disappear from the reported count. |
| Deadlines and timers | Shared timeout logic keeps one original deadline. Uring timed batches use an independent timer plus original-timer/cancel completion barriers; the unsafe linked single-request batch path is removed. Kqueue timer-arm failure is handled explicitly. | Spurious wakeups must not extend a duration; late timer completions must not write into reused stack/storage. |
| Child ownership | Dispatch/Uring canceled waits preserve a live child and its pipes; observed termination permits cleanup. Kill uses forced termination before reaping. | A canceled wait must not abandon an unreaped child, and ignored TERM must not strand shutdown. Final-source runtime evidence is pending. |
| Benchmark startup | Multi-loop teardown is installed before launch and joins/cancels started workers before freeing task/application state. | Partial server/client startup and error exits must obey the same lifetimes as successful measurements. |

Unsupported Uring stream operations now return explicit errors instead of
TODO panics. **Uring remains UDP-only**: its TCP/Unix listen/connect and stream
operations do not provide a Linux RPC transport. Successful UDP timings cannot
be used to enable general evented TCP consumers.

## Experimental operating contract

Keep one active backend context per participating OS thread. Call through its
managed fibers or registered threads; foreign-thread calls and nested active
backend instances are unsupported. The process initializer still supplies
Threaded I/O by default. An example sharing `init.io` through raw `std.Thread`s
needs an explicit evented context design before switching backends.

Keep batches, data/control buffers and socket descriptors alive until their
completion or cancellation barrier returns. Finish/cancel socket operations
before closing through the same owning `Io`. Drain groups/futures before
deinitializing the backend. Concurrent close is outside this contract.
Kqueue requires a thread-safe allocator. Fixed fiber result/context capacities
and large virtual stack reservations remain implementation limits.

Owned Threaded file/process adapters are synchronous and can occupy a worker.
Cancellation can be checked before entry without promising prompt interruption
of the blocking call. Kqueue's exceptional finite timer-arm failure uses a
Threaded wait against the original deadline and can delay cancellation.
Darwin zero-length UDP receives may return success without consuming a packet
or waiting for readiness; zero-capacity coverage does not promise consumption.

## Focused evidence and its boundaries

The [portable evidence record](EVENTED_BACKEND_EVIDENCE.json) embeds stock
canary sources/logs, focused commands, source/binary hashes, corrected initial
test assumptions, handoff inventory, native benchmark inputs and analysis.
Its full fork ledger is readable in the same file. Scratch paths describe
provenance; consumers do not need those paths to read the captured evidence.
Recorded snapshots remain distinct from later source changes and final
rebuilt-compiler checks.

| Check | Recorded result | Boundary |
|---|---|---|
| Kqueue network, adapters, stream/control and cancellation cases | Four programs × Debug/ReleaseSafe: 8 builds and 8 native macOS runs pass, including the reopened receive fix. | Local correctness checks with stock compiler plus candidate library; no M3 performance claim. |
| Kqueue BSD checks | Four programs × aarch64 FreeBSD/x86_64 OpenBSD, ReleaseSafe: 8 semantic checks pass. | No BSD linking or native execution proof. |
| Uring network/cancellation cases | Two programs × two Linux targets × Debug/ReleaseSafe: 8 cross-builds pass at their captured source. | aarch64-musl/x86_64-gnu build evidence; subsequent ownership fixes need the final Linux gate. |
| Final Uring scheduler review | Future/group completion must publish only after leaving the finished stack; migrated main fibers return to their original thread before teardown joins workers. | A final reuse/migration stress case is required in Debug and ReleaseSafe. The earlier `ef58f0204f` snapshot has the reviewed race and is not a multiworker release candidate. |
| Dispatch ownership/process and shared deadline cases | Candidate focused cases are named in the fork ledger. | **Pending — attach final-source case matrix and native results.** |
| Matching rebuilt fork compiler | **Pending — compiler/library hashes, version, source manifest and full gate.** | Stock compiler/library pairing cannot establish compiler changes. |
| Final native Linux cases | **Pending — kernel/container identities, commands, exact binaries and results.** | Cross-compilation is insufficient. |
| QUIC local/cross gates | Stock Debug 37/37, ReleaseSafe 30/30, default 15/15 and named steps 46/46 (94/94 tests) pass. Windows and 32-bit compile checks each pass 15/15. | QUIC source `6a7f30761e3e`; named benchmark build selects Threaded-only for stock 0.17. No wire/flow/CC library change, so the 31 virtual cells and wide external matrix are not repeated. Exact-tag interop is required below. |

The stock canaries independently reproduce removed vtable fields and the
obsolete stream-result destructure. They are expected stock failures, not fork
regressions. The audit also reproduces Darwin Unix-address size mismatch,
unnamed errno 102 formatting, truncated SCM_RIGHTS descriptor loss and send
panics, an iOS vtable compile failure, and wrapped-fetch archive-root retention.
Windows canceled-accept and Linux abstract Unix encoding findings are
source-only. These are wider inherited defects, not evidence that evented UDP
has repaired them.

`capnp-zig/src/io_backend.zig` still sets `evented_available=false`. Its owner
must update the expected-failure canary and validate real TCP, Unix, descriptor
passing, cancellation and shutdown using the exact fork before activation.
Complete ancillary delivery tests do not solve truncated descriptor cleanup,
Unix path bounds/encoding or general FD ownership. No consumer checkout was
edited, and no external handoff delivery is claimed.

## Quiet-machine comparison

Use **m3studio-001**, at site **Hoth**, via
`admin@hoth-m3studio-001.local`. Native Darwin and its existing Linux VM are
separate environments; compare Threaded and evented within each environment.
Export source archives rather than creating remote development worktrees.
Build and warm before timing; keep builds, profiles and measurements serial.
The first bulk preflight reports 90.85% idle; subsequent settled echo/multi-peer
snapshots report 98.78–99.23% idle. Background airport activity is retained in
the raw snapshots. User applications were not stopped.

Keep the same QUIC source, congestion control, payload, batch sizes, buffer
policy, socket tuning, offloads, receive timeout and Dispatch timer leeway in
each comparison. Record backend/thread layout: shared workers, one backend per
loop thread and explicit Kqueue are different experiments. Alternate pair
order and retain idle snapshots, every sample and dispersion. Every upload
must deliver exact bytes and clean FIN evidence; echo must deliver every pong.

Native measurements use QUIC `6a7f30761e3ed84cc188cd4806787f9f6f0b098e` and
fork library `ef58f0204f1f49843d50161958a187ab1d850484`, built by stock Zig
0.17.0. The shared overlay executable supplies the same-binary Threaded,
Dispatch and Kqueue comparison; a separate stock executable is retained as a
control. These timings do not prove the rebuilt compiler or a later Linux-only
repair. Six alternating, serial trials per workload use ReleaseSafe, receive/
send batches 16/64, reusable buffers, tuning off, offloads on, 5 ms receive
timeout and zero Dispatch leeway. Values below are medians of trial medians;
MAD and full ranges are retained in the portable record.

| Native workload | Overlay Threaded | Dispatch | Shared Kqueue |
|---|---:|---:|---:|
| Single 512 MiB upload, MiB/s | 174.45 | 170.56 | 171.93 |
| Upload CPU ms/MiB | 9.282 | 11.789 | 10.110 |
| Single echo p50 / p99, µs | 31.5 / 86 | 51 / 83 | 33 / 87.5 |
| Single echo CPU µs/pong | 26.07 | 56.75 | 37.40 |
| Four-client aggregate upload, MiB/s | 444.22 | 323.30 | 338.54 |
| Four-client upload CPU ms/MiB | 10.078 | 14.821 | 9.047 |
| Four-client echo p50 / p99, µs | 42 / 149 | 54.5 / 155 | 53 / 190 |

All 96 timed reports / 288 samples pass independent integrity checks: exactly
30 GiB delivered, 312 clean streams and 528,000 pongs. Eight warmup samples
separately complete 64 MiB, four clean streams and 128 pongs. Every command
exits zero and timestamped commands do not overlap. Echo tail cells are
medians of sample p99s, not pooled percentiles. All 144 multi-peer samples
route application traffic to one of the two server sockets, so these runs do
not validate load balancing across loops.

Every Dispatch single-bulk pair loses rate; its median paired CPU/MiB increase
is 27.0%. Four-client Dispatch loses 27.2% rate and adds 46.6% CPU/MiB.
Shared Kqueue loses 25.6% four-client rate while reducing CPU/MiB 10.5% in
every pair; this is a tradeoff, not a throughput gain. Kqueue multi-peer p99
worsens in every pair (median paired increase 30.1%). A low single-bulk Kqueue
CPU sample (6.084 ms/MiB, versus 10.04–10.16 for the other five) is retained;
no selective exclusion or robust single-bulk CPU gain is claimed. Single-peer
p99 ranges overlap and paired directions are mixed.

**Keep Threaded as the default.** No backend establishes the proposed ≥5%
native throughput improvement. Physical-link line rate, general application
RPC performance and Linux gains do not follow from native Darwin loopback.
Linux VM measurements and profile evidence are recorded separately below.

## Native profiles

Time Profiler resolves XML frame/weight references and retains Running samples
with a nonempty stack. Stock Threaded, overlay Threaded and Dispatch use a
20-second cap; the cap may kill the launched benchmark, so completed unprofiled
trials establish byte/FIN correctness. Kqueue's capped recording stalled while
saving and failed export after interruption; it is not counted as a valid
trace. A replacement four-upload recording exits naturally under a 30-second
cap. Different profile exposures do not prove normalized CPU differences.

| Native profile | Usable weighted CPU samples | sendmsg / recvmsg / readiness leaf shares |
|---|---:|---:|
| Overlay Threaded | 31,205 ms | 53.43% / 15.06% / 8.44% (`poll`) |
| Dispatch | 37,291 ms | 42.66% / 12.80% / 4.47% (`kevent_qos`) |
| Shared Kqueue, natural exit | 16,264 ms | 54.57% / 13.26% / 8.37% (`kevent`) |

Dispatch also attributes 17.55% to `start_wqthread`; workqueue entry/unwind
limitations mean the trace alone cannot identify the cause of its CPU penalty.
Socket/readiness calls remain the dominant sampled native cost. These are
sampled weights, not syscall counts, and include startup/transfer/teardown.
Inclusive/group shares overlap; the portable profile summary retains their
method, TOCs, raw XML hashes and the unsuccessful recording boundary.

## Release proof — LLVM repair and fork publication, 2026-10-10/11

The LLVM memory-operand defect that held the fork release was confirmed and
repaired at its source seam. `combineV3I8LoadExt`
(`AArch64ISelLowering.cpp`, LLVM 22.1.4) lowered `<3 x i8>` loads into an
i16+i8 pair but handed the i16 load the original three-byte
MachineMemOperand. SelectionDAG load CSE against a scalar i16 load from the
same pointer then aborted `MachineMemOperand::refineAlignment`
("Size mismatch!", MachineOperand.cpp:1154) — the exact abort behind the
full QUIC ReleaseSafe failure. The fix resizes the operand
(`MF.getMachineMemOperand(MMO, 0, 2)`), mirroring the existing i8 sibling.
The full record — patch, hashes, lit regression, runtime check, six-engine
provenance — is the zigfork repository's
`docs/llvm-v3i8-mmo-fix-2026-10-10.md`, with portable artifacts in its
`docs/llvm-fix-2026-10-10/` directory. Publication then surfaced one more
fork defect on x86_64-linux — a fiber-switch inline-asm clobber bug, also
repaired this sprint — before the release went out at
`0.17.0+fork.3bfc1a3ab`.

| Identity/gate | Final record |
|---|---|
| LLVM repair proof | Unpatched asserting llc: reproducer exit 134, new lit regression exit 134, i32 control exit 0. Patched llc: all exit 0; regression FileCheck passes (single `ldrh` CSE, `ldrb #2`, `orr lsl 16`); existing `vec3-loads-ext-trunc-stores` passes both LE and BE RUN lines; native runtime check (8 patterns incl. 0x00/0xFF) exits 0. Canonical diff SHA256 `d7159f1d…c5844c`. |
| First publication attempt and what it caught | `build/stable` pushed `c94b4041… → 2328a3a5f2` with an explicit lease; zig release run 38097275401 **failed and published nothing**. Two independent root causes: (1) the 3-vCPU macOS runner needs ~117s for the timer-heavy `evented_dispatch_group_reuse` Debug regression (26s on an 18-core workstation) and the 120s watchdog killed a healthy ReleaseSafe run — a capacity limit, fixed by zigfork `5b6cefe` (`ZIGFORK_TEST_TIMEOUT=600` for release builds); (2) the x86_64-linux `udp_reuse_port_load_balance` ReleaseSafe run segfaulted in `Io.fiber.contextSwitch` — a real fork defect on the first-ever native x86_64-linux execution of the Uring fiber path (the earlier 18-check Linux battery ran on aarch64 only). |
| Fiber switch clobber fix | `Io.fiber.contextSwitch` passed the SwitchMessage as a tied in/out register operand (x1/a1/rsi) while also naming that register in the clobber lists. The contradictory LLVM constraints (`"={rsi},{rsi},…,~{rsi},…"`) let ReleaseSafe x86_64 allocation skip materializing the message pointer; the switch then read contexts from a stale register (faulting store through a null base). Minimal repro `Uring.init(thread_limit=0)+sleep+sleep+deinit` on x86_64-linux: ReleaseSafe+LLVM crashed 3/3; ReleaseFast+LLVM and self-hosted ReleaseSafe passed 3/3 each; after dropping `.x1`/`.x11`/`.rsi` from the three arch clobber lists (`feat/evented-0.17` `ab6fa8873f`) the nine-run matrix passes and the emitted code materializes `rsi` immediately before the asm. Record: zigfork `docs/fiber-switch-clobber-fix-2026-10-11.md`. |
| Rebuilt stable fork compiler (final) | `0.17.0+fork.3bfc1a3ab` from `build/stable` 3bfc1a3abc (= 0.17.0 `7647adab80` + feat/evented-0.17 `ab6fa8873f` incl. the fiber fix + zigfork workflow `5b6cefe`), built by `build-release.sh aarch64-macos` against the patched LLVM 22.1.4 overlay (assertions ON). zig SHA256 `00fb11b33d9a…c65579f`, tarball `c76a4203…3fdcbe96`. (The intermediate `2328a3a5f` build passed every local gate identically and first proved the QUIC ReleaseSafe repair; its lib predates the fiber fix.) |
| Focused backend gates | `test-feature.sh aarch64-macos` passed inside both release builds, Debug and ReleaseSafe: 21 evented/kqueue/threaded cases, translate-c signedness, self-hosted vector partitions, and the 73-test std gate including the Dispatch deadline/readiness unit — re-run again with the fixed lib paired to the 2328 compiler before the fix landed on the branch. |
| QUIC gates under the patched compiler | v0.42.2 source (2aa5bae), fresh caches, 3bfc compiler with its packaged (fixed) lib: `test` 37/37 steps, 2035/2051 (16 skipped); `test -Drelease=true` **30/30 steps, 2079/2095 (16 skipped, fresh-cache accounting)** — zero `Size mismatch` hits, the pre-fix abort is gone; `bench-test` 12/12; `bench-io-build` 12/12. Gate manifests: `/tmp/quic-llvmfix-gates{,-3bfc}/manifest.json` (2328-era manifest copied in `zigfork/docs/llvm-fix-2026-10-10/`). |
| Fork publication (final) | `build/stable` pushed `2328a3a5f2… → 3bfc1a3abc` with `--force-with-lease` after manifest review (a first attempt with a mistyped lease value was correctly rejected by the lease itself). Zig release run 38104948470 rebuilt all three platform assets at `0.17.0+fork.3bfc1a3ab`. |
| Three-platform CI assets and staged install | See run 38104948470: aarch64-macos, x86_64-linux and aarch64-linux jobs at version `0.17.0+fork.3bfc1a3ab`; asset checksums and the staged `zigfork install stable` (under `~/.zvm/fork-stable`, without `--use`) are recorded in the zigfork audit ledger. The default toolchain is untouched. |
| QUIC release/tag/package hash and five exact-tag gates | v0.42.2 = `2aa5bae31b7eab42cf95a654ab9717248d6f2498`, package `quic-0.42.2-DnSYvVJRZQDaf9LFsqj9k1cFzPeYCNwb3HgKBDn8s07g`; all five exact-tag workflows verified 2026-10-10 22:34:26 UTC (see [RELEASE_READINESS.md](RELEASE_READINESS.md)). No new QUIC release was needed for this fork work. |

Identity boundaries: the patched-LLVM compiler is the local audit
instrument that proved the invariant repair; the CI-published three-platform
assets are built by the standard zigfork workflow from stock ziglang.org
bundles (assertions off) and carry the fork standard library, not the LLVM
patch — the upstream defect stays dormant there exactly as in stock Zig
0.17.0, which the verified v0.42.2 gates already exercise. Upstreaming the
LLVM fix is recommended follow-up; nothing was sent externally.

The maintained integrator brief advertises only a verified QUIC tag.
Evented activation still requires a matching compiler/library and actual
application checks by each integrator. Integrators move their own pins; no
default compiler or consumer checkout is changed here.

## Final-binary measurements — fork 0.17.0+fork.3bfc1a3ab, 2026-10-11

Final binaries (QUIC 2aa5bae + the published fork lib, ReleaseSafe, patched
audit engine; stock control built with stock Zig 0.17.0) replaced the
7dfa-era candidate set. After four-variant preflight, the full serial
comparison ran on m3studio-001: warm 4/4, bulk 24/24, echo 24/24,
multi-bulk 24/24, multi-echo 24/24 — every command exit zero, with
independent integrity checks exact (30,720 MiB, 312 clean streams, 528,000
pongs). Four Time Profiler recordings (stock/overlay Threaded, Dispatch,
shared Kqueue; 20 s cap, capped termination boundary documented) exported
TOC+XML. Raw data and per-run commands:
`benchmark-reports/evented-2026-10-10/final-v0.42.2-3bfc1a3ab/`.

| macOS medians | stock Threaded | overlay Threaded | Dispatch | shared Kqueue |
|---|---:|---:|---:|---:|
| Single-bulk MiB/s | 180.2 | 181.2 | 176.6 | 181.0 |
| Single-bulk CPU ms/MiB | 9.07 | 8.98 | 11.44 | 9.68 |
| Four-client aggregate MiB/s | 485.8 | 490.6 | 306.2 | 345.9 |
| Four-client CPU ms/MiB | 9.41 | 9.13 | 15.50 | 8.81 |
| Echo p50 / p99, µs | 31 / 92 | 31 / 88 | 45 / 82 | 34 / 90 |
| Four-client echo p50 / p99, µs | 43 / 138 | 43 / 134 | 53 / 131 | 53 / 155 |

The original conclusion is unchanged: no evented backend establishes a
native Darwin throughput gain; Dispatch loses single-bulk rate and
four-client goodput; shared Kqueue trades four-client rate for CPU/MiB.
**Threaded remains the default.**

Linux (OrbStack Ubuntu 24.04 AArch64 VM, `network none`, seccomp
unconfined, binary mounted read-only; Uring = the `evented` backend on
Linux; six paired trials per shape, Threaded then Uring within each trial;
VM restored to Stopped afterward): 24/24 zero exits.

| Linux VM medians | Threaded | Uring (evented) |
|---|---:|---:|
| Bulk MiB/s | 201.2 | **294.0** |
| Bulk CPU ms/MiB | 5.00 | 5.22 |
| Echo rtt p50 / p99, µs | 16 / 50 | 17 / 54 |
| Echo round-trips/s | 52,974 | 48,947 |

Paired per-trial Uring bulk deltas: +37.6%, +39.0%, +42.9%, +46.3%,
+50.1%, +129.9% — all six positive (median ≈ +46%) at essentially equal
CPU per MiB. Echo is a near-tie slightly favoring Threaded. This is the
first completed Linux perf comparison for the fork; it is loopback
container evidence only — no physical-NIC line-rate or general
application-RPC claim follows. ev-thread remains untested here
(multi-loop/client workloads only, per its scope).

## Next sprint proposals

These are proposals after the current release/measurement gate, not predicted
gains. Threaded remains the measured default; correctness blockers lead the ranking.

| Proposal | Concrete work | Goal | Scope/risk | Acceptance |
|---|---|---|---|---|
| **Unix/descriptor ownership hardening — recommended** | Reproduce truncated SCM_RIGHTS with FD accounting; bound ancillary lengths, close undelivered descriptors, test CLOEXEC and Unix address boundaries/abstract encoding. | Make supported Unix/FD transports safe enough for owner-led integration. | Separate std/API work; descriptor leaks, malformed control buffers and platform differences. Uring TCP remains a separate feature. | Native Darwin/Linux FD-count and cancellation cases; boundary-length/byte-encoding tests; capnp owner validates its actual transport before activation. |
| Measured wake/scheduler follow-up | Profile the backend and worker layout that loses the paired comparison; isolate wake/timer/syscall cost with same-binary controls before altering scheduling. | Reduce demonstrated CPU/MiB or tail cost without changing QUIC behavior. | Measurement-first sprint; timer slack, work stealing, fairness and cancellation can trade throughput for latency. | Quiet M3 paired bulk/echo/multi-peer evidence, exact completion, idle/cancel/shutdown checks and full release gates for any resulting change. |
