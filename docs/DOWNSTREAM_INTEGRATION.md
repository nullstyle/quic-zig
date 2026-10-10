# Downstream integration

This is the maintained brief for quic-zig integrators. Update this file in
place after each sprint; do not create another file for each tag. The current
verified pin is at the top. Migration guidance is cumulative. Main-only work
must be labelled separately from released behavior.

Last updated: 2026-10-10. Current release: **v0.40.0, verified**.
The line-rate profiling sprint is complete. It changed documentation only;
there is no new release or integrator API migration. Its
[CPU profile and next proposals](LINE_RATE_PROFILE.md) are main-only evidence.

## Current pin and build options

Tag `v0.40.0` = `5796be0f8989a081bb563b96fcc6a856f43eb11d`.
Package hash: `quic-0.40.0-DnSYvSs1QADqzgHFcxff2HzBAezXWXpCJD2BCKJEemBu`.
Toolchain: Zig 0.17.0, pinned by mise. Use ReleaseSafe for deployed code.

```sh
mise exec -- zig fetch --save https://github.com/nullstyle/quic-zig/archive/refs/tags/v0.40.0.tar.gz
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
cleanup timing and retirement evidence are unchanged.

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

All five CI gates verified on the tag commit by 2026-10-10 18:38:21 UTC,
within 21 minutes of release. Evidence:

- [test 38075222309](https://github.com/nullstyle/quic-zig/actions/runs/38075222309):
  seven jobs succeeded. Unix Debug 2068/2084 and ReleaseSafe 2028/2044
  (16 skipped each); Windows Debug and ReleaseSafe each 2005/2044
  (39 skipped). Full sanitizer and 32-bit Linux musl suites passed.
  consumer-smoke ok: quic-zig 0.40.0; check-modes: 6 of 6 as expected.
- [rc-fuzz 38075224074](https://github.com/nullstyle/quic-zig/actions/runs/38075224074):
  2,637,540 instrumented executions across 43 sites, above the 1,935,000
  floor; pcs_len=47345, unique_runs=10,277. No failing inputs.
- [quic-go-interop 38075222415](https://github.com/nullstyle/quic-zig/actions/runs/38075222415):
  pairs=1 cells=2 succeeded=2; zero failed, known_failed, unsupported,
  skipped, or flaky cells.
- [QNS Image 38075222433](https://github.com/nullstyle/quic-zig/actions/runs/38075222433):
  image build succeeded. Publication is disabled (publish_image:false,
  push:false); this gate proves the build only.
- [pin-lint 38075222408](https://github.com/nullstyle/quic-zig/actions/runs/38075222408):
  pin-lint OK; Zig pins agree at 0.17.0.

## Delivery and pin ownership

Each downstream session moves its own pin. Repositories linked into one
binary move together: cluster A is nest, qmsg, qmesh-zig, and mruby-quic;
http3-zig and capnp-zig move on their own cadence. A release is information,
not a forced cluster move. No downstream checkout or pin was changed here.

This file is ready for owner relay. The Claude downstream sessions in the
original handoff are unavailable to this chat's message tools. Delivery is
not claimed. Do not infer current consumer pins from old sprint notes.
