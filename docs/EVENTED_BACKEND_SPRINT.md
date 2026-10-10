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

## Release proof — pending

| Identity/gate | Final record |
|---|---|
| QUIC implementation on main | **Pending — commit and source archive identity.** |
| Stable fork feature/build/tooling commits | **Pending — exact assembly manifest.** |
| Three native fork builds and focused/full gates | **Pending — exact-source CI URLs, versions and artifact hashes.** |
| Verified fork release and staged install | **Pending — tag, manifest, checksums and exact-binary version; no default-tool switch implied.** |
| QUIC release/tag/package hash and five exact-tag gates | **Pending — fill after publication and verification.** |

The maintained integrator brief advertises only a verified QUIC tag. A
stock-gated benchmark/docs patch can be verified independently of the fork;
evented activation still requires its matching compiler/library and actual
application checks. Integrators move their own pins; no default compiler or
consumer checkout is changed here.

## Next sprint proposals

These are proposals after the current release/measurement gate, not predicted
gains. Threaded remains the measured default; correctness blockers lead the ranking.

| Proposal | Concrete work | Goal | Scope/risk | Acceptance |
|---|---|---|---|---|
| **Unix/descriptor ownership hardening — recommended** | Reproduce truncated SCM_RIGHTS with FD accounting; bound ancillary lengths, close undelivered descriptors, test CLOEXEC and Unix address boundaries/abstract encoding. | Make supported Unix/FD transports safe enough for owner-led integration. | Separate std/API work; descriptor leaks, malformed control buffers and platform differences. Uring TCP remains a separate feature. | Native Darwin/Linux FD-count and cancellation cases; boundary-length/byte-encoding tests; capnp owner validates its actual transport before activation. |
| Measured wake/scheduler follow-up | Profile the backend and worker layout that loses the paired comparison; isolate wake/timer/syscall cost with same-binary controls before altering scheduling. | Reduce demonstrated CPU/MiB or tail cost without changing QUIC behavior. | Measurement-first sprint; timer slack, work stealing, fairness and cancellation can trade throughput for latency. | Quiet M3 paired bulk/echo/multi-peer evidence, exact completion, idle/cancel/shutdown checks and full release gates for any resulting change. |
