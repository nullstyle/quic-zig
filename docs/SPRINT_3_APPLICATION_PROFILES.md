# Sprint 3: application workload profiles

This note preserves the pre-repair Req/Rep baseline and measurement method.
The [current Sprint 3 handoff](SPRINT_3_APPLICATION_WORKLOADS.md) records the
subsequent idle-cache repair and coordinated qualification.

Sprint 3 starts from locally committed Sprint 2
`c74110a94667dd155068b862cb7a966aadbe7697`. Its QUIC scope is to profile
actual application workloads and investigate demonstrated transport costs or
regressions. It changes no transport policy, toolchain, version, or dependency
pin. The inherited fairness promotion hold remains separate.

## Repeatable public Req/Rep workload

`tools/profile-applications.py` snapshots explicit qmsg and QUIC source trees
before building a small real IPv4 UDP consumer. Both lanes use the same qmsg
snapshot, workload source, TLS fixtures, compiler, and ReleaseSafe options:

- `native` uses qmsg's existing immutable QUIC v0.37.2 dependency pin;
- `selected` injects the requested QUIC module with the same
  `{target, release, sanitize-c}` option map;
- a compile-time check requires the harness and qmsg to expose the same
  `quic.Connection` type.

The workload calls only public `QuicSocket(.req/.rep)` methods. One application
thread drives both sockets, consumes canonical events, replies on each
request's handle, and waits on borrowed UDP descriptors plus both timer
deadlines after quiet iterations. Each reply must match its request ID, wire
message ID, and exact payload. Every event batch is freed on early returns.

TLS setup is reported separately from an untimed warmup and the warm request
phase. The initial comparison uses 50,000 requests per process, 1,024-byte
bodies in both directions, eight concurrent requests, an eight-stream window,
128 warmup requests, and a 200 ms idle tail. Each warm request has a 10-second
deadline; setup and each active phase have a 30-second total bound. Workload
counts, body size, window, concurrency, warmup and time bounds are configurable
within explicit limits. Three samples alternate native/selected order.

```sh
mise exec -- python3 tools/profile-applications.py \
  --qmsg-path /absolute/path/to/frozen/qmsg \
  --quic-path /absolute/path/to/quic-zig \
  --requests 50000 --samples 3 --jobs 2 \
  --output-dir benchmark-reports/my-application-profile
```

The script copies tracked and nonignored source files, checks that they did
not change during copying, and hashes every copied file. Source snapshots,
staged build, compiler and executable hashes, exact commands, raw logs and
per-sample process snapshots remain in the output directory. Public manifests
are not edited. Builds run before the measured child processes.

## What the measurements mean

- Warm wall time and process CPU time cover public request admission through
  consumption of all reply events. Per-request p50/p99 includes application
  queueing, owner-loop service and peer handling; it is not a network RTT.
- The counting allocator measures **Zig-owned allocations** through the
  allocator passed into qmsg/QUIC. BoringSSL and libc allocations outside that
  allocator are excluded. Counts and allocated bytes are phase deltas;
  live/peak bytes are carried process-lifetime gauges. Counted live bytes must
  return to zero after both socket owners are destroyed.
- Whole-child user/system CPU and peak RSS are separate operating-system
  measurements covering setup, warmup, warm traffic, idle and teardown. Darwin
  reports RSS bytes; Linux's KiB value is converted to bytes.
- Request completion, unique correlation, exact bodies, no dropped events or
  messages, configured outstanding limits, and zero counted live bytes after
  teardown are correctness gates. Timing is local comparative evidence.
- Host process snapshots expose concurrent work. Profiler captures are
  separate from timing samples, and timing variation alone does not justify a
  transport change.

## Consumer scenarios

The coordinated parent composition build supplies two additional public
workloads with the same native/selected QUIC module choice:

1. qmsg reliable publication with source filtering, a paused subscriber,
   bounded pending output and reconnect/resubscribe;
2. qmesh missed-announcement recovery, where bounded qmsg requests retrieve a
   snapshot after a partition outlasts the gossip hint retention.

Their producer reports define delivery, refusal/drop, retention, deadline and
convergence gates. Their cached executable timings and CPU/RSS are recorded
separately from the Req/Rep baseline; intentional pause and outage time is not
transport work. Dynamic endpoint advertisements, live CREDIT, the evented
backend, physical-network claims and release promotion are outside this sprint.

## Evidence status

The first fixture check and paired baseline are retained under
`benchmark-reports/sprint-3-2026-10-26/`. They use the clean qmsg Sprint 2 source
`941eef6b65deb250d2e5ee56637523be9eec5527`, snapshotted before Sprint 3 edits.
All six initial 50,000-request runs complete with exact replies, no message or
event drops, and zero counted live bytes after teardown. Native warm CPU has
a 1.364 s median versus selected 1.397 s; warm wall medians are 1.924 s and
2.044 s. Their ranges overlap. Concurrent producer work and a later warmup
argument-bound correction make these exploratory measurements, not final
promotion evidence. No transport change is justified by this comparison.

Final consumer snapshots, serial paired measurements and the bounded profile
capture are indexed separately under `benchmark-reports/sprint-3-2026-10-26/`
and the coordinated qmesh evidence directory. This preliminary comparison is
kept with its original input and measurement limits.
