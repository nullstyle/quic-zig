# Embedding quic-zig

This guide covers the stable embedding surfaces:

- `quic.Server` for accepting QUIC connections.
- `quic.Client` for dialing QUIC peers.
- `quic.transport.runUdpServer` and `runUdpClient` for simple
  `std.Io` UDP loops.
- `quic.Connection` for custom event loops, batched I/O, qlog
  routing, and application-specific scheduling.

quic-zig is pre-1.0, so APIs may change between 0.x releases. The
module name in Zig code is `quic`.

## Package Setup

In a consuming `build.zig`, import the module from the package
dependency:

```zig
const quic_dep = b.dependency("quic", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("quic", quic_dep.module("quic"));
```

Application code then uses:

```zig
const quic = @import("quic");
```

## Server Wrapper

`Server` owns TLS context setup, per-connection state, CID routing, Retry
validation, Version Negotiation, and the connection table. The embedder
chooses the socket model and application protocol behavior.

Transport-parameters note: `transport_params = .{}` compiles and
handshakes, but its all-zero flow-control / stream-count defaults admit
no streams and no bytes — every peer request then stalls with no error
on either side. Pass `Server.Config.defaultTransportParams()` for the
blessed working set (DATAGRAM stays opt-in), or set the fields
explicitly. A server whose params admit nothing also earns a
`config_warning` log event at init (see `Server.LogEvent`).

```zig
const std = @import("std");
const quic = @import("quic");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_pem: []const u8,
    key_pem: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"h3"};

    // DEMO ONLY: this mints a fresh Retry key on every start, which
    // invalidates every outstanding Retry/NEW_TOKEN across a restart
    // (see the key-persistence note under "Required Configuration"
    // below). A real deployment loads this key from durable storage
    // and only generates+stores it on first run.
    var retry_key: quic.RetryTokenKey = undefined;
    io.random(&retry_key);

    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = cert_pem,
        .tls_key_pem = key_pem,
        .alpn_protocols = &protos,
        .transport_params = .{
            .max_idle_timeout_ms = 30_000,
            .initial_max_data = 16 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1 << 20,
            .initial_max_stream_data_bidi_remote = 1 << 20,
            .initial_max_stream_data_uni = 1 << 20,
            .initial_max_streams_bidi = 1000,
            .initial_max_streams_uni = 64,
            .active_connection_id_limit = 4,
        },
        .max_concurrent_connections = 10_000,
        .initial_source_rate_limit = .{ .limit = 32 },
        .retry_token_key = retry_key,
    });
    defer server.deinit();

    try quic.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:4433",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

`runUdpServer` binds the UDP socket, applies socket tuning, receives
datagrams, feeds the server, drains outbound packets, ticks connection
timers, and exits after the shutdown flag flips. `Server` and
`Connection` have no internal locking and are single-threaded by
contract: while the loop runs, nothing else may touch the server or its
connections — including walking `server.iterator()` — except from the
loop's own thread or behind the embedder's own mutex around every
access. The shipped loops call `RunUdpOptions.on_iteration` (and the
client's equivalent) once per iteration on the loop's own thread, which
is where application stream and datagram work belongs — the packaged
echo example pair is built on exactly that hook. When your process
already has an event loop of its own, drive the caller-drives path
directly instead: see "Foreign Event Loops" below.

### Scaling across cores

There is no built-in multi-worker mode: one `Server` is one
single-threaded instance. To use more than one core, run N independent
`Server` instances (each on its own thread or process) sharing the
same port via `SO_REUSEPORT` — set it on the socket before handing
control to `runUdpServer` (bind the socket yourself and pass the
address through `RunUdpOptions.listen` once reuse is enabled), or
drive each instance caller-drives. No shared state exists between
instances, so no locks are needed; connection CIDs and stateless-reset
tokens must be minted from per-instance configurations (QUIC-LB or
random SCIDs) so peers route to the instance that owns their
connection.

## Writing Your Application Layer

`Server` + `runUdpServer` own the transport; your protocol logic is
the layer above. There are two supported shapes — start with the
first, drop to the second when you need the control.

### The `quic.app.Driver` (recommended first pass)

`quic.app.Driver(App)` is an opt-in dispatcher that owns the three
state machines every custom server otherwise hand-rolls: per-stream
tracking (`app.StreamTable`), short-write staging (`app.Outbox`), and
sound end-of-stream detection. It walks the slots, drains each
connection's event queue, pumps reads, delivers DATAGRAMs, and calls
*typed* callbacks — no `?*anyopaque` contexts, no `@ptrCast` dance, no
slot-diffing to discover connections.

```zig
const D = quic.app.Driver(EchoApp);

const EchoApp = struct {
    // Required decls (use `void` when unused) — the Driver allocates
    // and frees this storage per connection / stream:
    pub const StreamState = void;
    pub const ConnState = struct { streams_echoed: u32 = 0 };

    fn onStreamData(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        try s.outbox.push(s.conn, e.id, chunk); // stages short writes
    }

    fn onStreamEnd(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        // Fires exactly once, only when the stream is really done —
        // never on "empty read + FIN seen".
        if (end == .fin) {
            try s.outbox.finish(s.conn, e.id);
            s.app.streams_echoed += 1;
        }
    }

    fn onDisconnect(_: *EchoApp, s: *D.Session) void { /* free nothing: driver owns it */ }
};
```

Wiring — hooks are an explicit registration list (there is no method
detection, on purpose; see `quic.app`'s docs for the comptime-quirk
rationale):

```zig
var app: EchoApp = .{};
var driver = try D.init(.{
    .allocator = allocator,
    .app = &app,
    .hooks = .{
        .on_stream_data = EchoApp.onStreamData,
        .on_stream_end = EchoApp.onStreamEnd,
        .on_disconnect = EchoApp.onDisconnect,
    },
    // Sized to what you advertise, so a conforming peer can never
    // overflow the table (overflow is refused via STOP_SENDING):
    .max_tracked_streams = tp.initial_max_streams_bidi + tp.initial_max_streams_uni,
    .datagram_buf_bytes = tp.max_datagram_frame_size, // if you use DATAGRAM
});
defer driver.deinit();

var server = try quic.Server.init(.{
    ...,
    .on_connection_will_close = D.willCloseHook,
    .on_connection_will_close_user_data = &driver,
});
try quic.transport.runUdpServer(&server, .{
    ...,
    .on_iteration = D.iterationHook,
    .on_iteration_ctx = &driver,
});
```

Ordering guarantees (the traps this removes): events drain before
data from the same stream is pumped; `onStreamEnd` fires on
`streamRecvState().terminal` / reset / reaped — never early under
reordering; `Outbox.push` accepts what the connection takes and
retries the rest, so short writes disappear; the whole pass runs
before `Connection.tick`, which is what keeps the stream GC from
reaping streams with unread bytes. A hand-rolled loop must preserve
the same order: `driver.service(&server)` before any `conn.tick`.

Teardown is covered too: when a connection goes away, the will-close
hook first delivers `onStreamEnd` (`.reaped`) for every stream still
tracked, then `onDisconnect` — so per-stream state freed in
`onStreamEnd` is freed on abrupt disconnects as well, with no
app-side sweep. This holds on BOTH teardown paths: a normal
close→tick→reap cycle, and `Server.deinit` called with connections
still live (it fires the same hook per slot before destroying it).
You do not need a drain loop before `deinit` just to avoid leaking
Driver sessions.

Worked examples: `examples/echo_server.zig` (streaming echo),
`examples/request_response_server.zig` (length-prefixed
request/response — the pattern most protocols build on).

### Raw: the `on_iteration` switch

Everything the Driver does is expressible directly; the callback
inventory is `Server.Config.on_connection_will_close` plus
`RunUdpOptions.on_iteration`. The explicit pattern (slot walk,
`pollEvent` switch with a mandatory `else => {}` arm for
forward-compat, per-stream state by hand) is documented in
`examples/echo_server_raw.zig` — the teaching artifact. Use it when
you want full control over event ordering or per-stream state layout.

### Testing your server in-process

`quic.testing.Loopback` ships in the package for embedder tests: a
real `Server`/`Client` pair over in-memory datagram exchange — real
TLS and packet protection, no sockets, no threads, no ports.

```zig
var lb = try quic.testing.Loopback.init(.{
    .allocator = allocator, .server = &server, .client = &client,
});
defer lb.deinit();
try lb.handshake(&driver);
// ... drive streams ...
try lb.step(&driver); // one runUdpServer-shaped iteration
```

`tests/e2e/testing_loopback.zig` in the repository is the worked
example (it is also this harness's own regression test).

## Client Wrapper

`Client.connect` owns the client-side TLS setup and initial connection
ID generation. The returned `client.conn` is the full
`*quic.Connection`.

```zig
const std = @import("std");
const quic = @import("quic");

pub fn dial(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    server_name: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"h3"};

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = server_name,
        .alpn_protocols = &protos,
        .transport_params = .{
            .max_idle_timeout_ms = 30_000,
            .initial_max_data = 16 * 1024 * 1024,
            .initial_max_stream_data_bidi_local = 1 << 20,
            .initial_max_stream_data_bidi_remote = 1 << 20,
            .initial_max_stream_data_uni = 1 << 20,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 64,
            .active_connection_id_limit = 4,
        },
    });
    defer client.deinit();

    try quic.transport.runUdpClient(&client, .{
        .target = target,
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

`runUdpClient` binds an ephemeral UDP socket by default, applies socket
tuning, advances the handshake, polls outbound packets, receives inbound
packets, and ticks timers until the connection closes or the shutdown
flag flips. If you need DNS resolution, fixed source tuples, custom
packet pacing, or single-threaded application logic, use the raw
connection cycle below.

The wrapper-built TLS context verifies the server certificate against
the system trust store by default. To pin a private CA instead —
the internal-service-mesh posture — pass the PEM bundle as
`.ca_pem`: the client then trusts exactly those roots (they replace
the system store) and still checks the certificate's identity
against `server_name`. For mTLS, additionally set
`.client_cert_pem` / `.client_key_pem` (the certificate presented
when the server requests one) and, on the server, set
`Server.Config.client_ca_pem` to require and verify client
certificates. For self-signed or test peers, set
`.insecure_skip_verify = true` in the `Client.connect` config — it turns
off impersonation protection, so keep it out of production.

## Raw Connection Cycle

`Connection` is the I/O-agnostic state machine under both wrappers. A
custom loop repeats four operations:

1. Feed inbound datagrams with `conn.handle` or `conn.handleWithEcn`.
2. Drain outbound datagrams with `conn.pollDatagram`.
3. Drive timers with `conn.tick`.
4. Sleep until `conn.nextTimerDeadline(now_us)` or the next socket event.

"Foreign Event Loops" below covers where the sleep and the wake come
from when the wait belongs to a runtime you don't control.

Both feed paths (`conn.handle` / `Server.feed`) take the datagram as a
mutable `[]u8` — header unprotection rewrites the bytes in place — so
receive into a mutable buffer, never a `[]const u8` slice.

```zig
// Client bootstrap: `Client.connect` deliberately does NOT call
// `advance`, so 0-RTT data can be staged before the first flight.
// Call it once after `connect`, before the first loop iteration;
// without it the ClientHello never hits the wire and the loop
// waits forever. (Server-accepted connections need no equivalent —
// `Server.feed` drives them.)
try conn.advance();

while (!conn.isClosed()) {
    const now_us = monotonicNowUs();

    if (try sock.recvNonBlocking(&rx)) |msg| {
        try conn.handle(msg.bytes, msg.from, now_us);
    }

    while (try conn.pollDatagram(&tx, now_us)) |out| {
        const dst = out.to orelse peer_addr;
        try sock.send(dst, tx[0..out.len]);
    }

    try conn.tick(now_us);

    while (conn.pollEvent()) |ev| switch (ev) {
        .close => |c| handleClose(c),
        .flow_blocked => handleFlowBlocked(),
        .connection_ids_needed => |info| provideConnectionIds(info),
        .datagram_acked, .datagram_lost => |info| updateDatagramState(info),
        // Covers the variants this app ignores (e.g.
        // `alternative_server_address`) and any added in a minor
        // release — always keep an `else` arm (docs/API_STABILITY.md).
        else => {},
    };

    var it = conn.streamIterator();
    while (it.next()) |entry| {
        const stream_id = entry.key_ptr.*;
        var buf: [4096]u8 = undefined;
        const n = try conn.streamRead(stream_id, &buf);
        if (n > 0) handleAppData(stream_id, buf[0..n]);
    }

    parkUntil(conn.nextTimerDeadline(now_us));
}
```

Servers using the raw loop should also drain stateless responses queued
by `Server.feed`:

```zig
while (server.drainStatelessResponse()) |resp| {
    try sock.send(resp.dst, resp.slice());
}
```

## Foreign Event Loops

If your process already owns a wait — an existing reactor, a runtime's
scheduler, a `poll`/`epoll`/`kqueue` set you multiplex yourself — you do
not need `transport.runUdp*` at all. The caller-drives path above **is**
the supported integration for that case, and
`examples/foreign_loop_embedder.zig` is a worked, tested implementation
of it: a hand-rolled `std.posix.poll` reactor driving a `Server` and a
`Client` in one loop, with cross-thread application work arriving
through a queue and a wake socket.

### What you take on

Everything the packaged loop was doing for you:

- **Bind and tune the socket.** `socket_opts.applyServerTuning` raises
  `SO_RCVBUF`/`SO_SNDBUF` to 4 MiB; kernel defaults (~200 KiB on Linux,
  ~9 KiB on macOS) drop datagrams, and to QUIC a drop is loss.
- **Refresh the clock *after* the blocking wait.** Reusing the
  pre-wait timestamp makes PTO and loss-detection timers fire late.
- **Bound ingress per iteration.** The packaged loop reads one datagram
  per iteration so a hot receive queue cannot starve tick-driven
  recovery work. Batch if you like, but budget it.
- **Drain stateless responses separately.** Version Negotiation and
  Retry belong to no connection, so `drainStatelessResponse` is its own
  step alongside the per-slot outbox.
- **Pick destinations per datagram.** `out.to orelse slot.peer_addr` —
  not a single cached peer address — or migration, multipath, and
  VN/Retry peers get the wrong destination.
- **Contain per-connection errors.** A malformed peer must not tear
  down the loop; the packaged loop swallows per-slot failures.
- **Skip terminal slots, keep closing ones.** `closeState() == .closed`
  slots are done, but closing/draining ones still need `tick` so
  CONNECTION_CLOSE retransmits (RFC 9000 §10.2.1).
- **`reap` periodically.** `reap` is what invokes
  `Config.on_connection_will_close` while the slot is still valid.
- **Honour a shutdown grace window** so peers get a CONNECTION_CLOSE.

### One iteration, in order

Compute the timeout, wait, then: receive → `feed`/`handle` →
`drainStatelessResponse` → per-slot `pollEvent` and application I/O →
`pollDatagram` → `tick` → periodic `reap`. The invariant that matters:
**drain the outbox after every state change and before you sleep.**

### Deciding how long to sleep

`Server.nextTimerDeadline(now_us)` (or `Connection.nextTimerDeadline`)
returns the soonest armed deadline as an absolute `at_us` on your own
clock origin. Convert it to your wait's units, and mind two traps the
example isolates into a tested pure function:

- A **past-due** deadline must clamp to zero. A negative timeout means
  "block forever" to `poll`, and the PTO never fires.
- A **sub-millisecond** deadline must round *up* to 1 ms, or the loop
  spins hot on a 300 µs ACK-delay timer.

Since 0.11.0 the deadline can also be `TimerKind.pacing` (RFC 9002
§7.7, on by default): application data is waiting on send credit, and
`pollDatagram` will return null until roughly `at_us`. Treat it like
any other kind — wake, `tick`, drain the outbox. Two contract notes:
`pollDatagram` returning null while you still have data queued has
always been a legal state (flow control, anti-amplification, cwnd);
pacing just adds one more cause, so loops keyed on the deadline (not on
"poll returned something") need no changes. Loops that ignore
`nextTimerDeadline` and wake on a fixed interval still work — each wake
releases up to one interval's worth of credit (the bucket scales with
wake granularity) — and `enable_pacing = false` on either `Config`
restores the pre-0.11 burst behavior exactly. New `TimerKind` variants
may appear in minors; handle unknown kinds generically (waking and
draining is always correct).

A null deadline means nothing is armed: block until an fd is readable
if you have a wake channel, otherwise cap the sleep.

### Waking the loop from application threads

`Server` and `Connection` have no internal locking. In a foreign loop
*you* are the serializer: no thread but the loop thread may call into
quic. The pattern is a queue plus a wake fd — producers push work
under a mutex and nudge the loop; the loop thread drains the queue and
is the only caller. A wake means "check the queue", not "one item", so
N pushes may coalesce into one wake; drain until empty.

## Stream Conventions, Lifecycle, and Shutdown

For layers that build their own framing on top of the transport (HTTP/3,
WebTransport, custom protocols), a few helpers remove common boilerplate.

Stream ids encode `(initiator, direction)` in their low two bits (RFC 9000
§2.1). Rather than compute them by hand, classify with
`quic.StreamType.fromId(id)` and open the next local-initiated stream
with the role-aware helpers:

```zig
// e.g. an HTTP/3 endpoint's control + QPACK encoder/decoder streams:
const control = try conn.openNextUni();   // next local unidirectional id
const qpack_enc = try conn.openNextUni();
const qpack_dec = try conn.openNextUni();

// classify a peer-initiated stream seen via streamIterator:
switch (quic.StreamType.fromId(id)) {
    .client_bidi, .server_bidi => {},
    .client_uni, .server_uni => {},
}
```

`openNextBidi` / `openNextUni` pick the id automatically and return
`Error.StreamLimitExceeded` when the peer's limit is reached without
consuming the id (a later retry reuses it). When a layer must know the id
*before* opening — e.g. to run a GOAWAY / stream-limit gate keyed on it —
`peekNextBidi()` / `peekNextUni()` return the id the matching `openNext*`
would use next, without consuming it:

```zig
const id = conn.peekNextBidi();
if (!localGoawayGate(id)) return error.RequestBlocked;
const s = try conn.openNextBidi();   // reuses the peeked id
```

To observe stream completion and backpressure without reaching into the
stream internals — which the transport's stream GC reclaims the moment a
stream goes terminal — use the connection-level accessors:

- `streamReadFin(id, dst)` reads like `streamRead` but also returns whether
  the peer's FIN has been seen, captured inline with the read that drains
  the stream (so you never have to re-inspect a soon-reaped stream).
- `streamRecvState(id)` reports `fin_seen` / `reset_seen` / `terminal`,
  distinguishing a clean FIN from an abortive RESET, or `null` once the
  stream has been reaped or was never opened.
- `streamSendStats(id)` snapshots `written` / `acked` / `buffered` /
  `has_pending` for write backpressure, or `null` for a reaped stream.

### Ending a receive stream

**Use `streamRecvState(id).terminal`, and nothing else.** Every wrong
version of this test fails *silently*: the application truncates the
stream, and neither endpoint reports an error.

- A read that returns 0 bytes means "nothing readable **right now**".
  `streamRead` also returns 0 when the next in-order byte has not arrived
  yet, so an empty read is not a drained stream.
- `StreamReadResult.fin` (and `streamRecvState().fin_seen`) means the
  FIN-carrying frame was accepted, at whatever offset it named. A FIN at a
  high offset can arrive before a lower chunk does.
- The two together are therefore **not** an end-of-stream test either.
  "Empty read + FIN seen" is exactly the state of a stream with a hole in
  it: a peer that sends `0..99`, then `200..299` with the FIN, with
  `100..199` reordered behind them, puts the receiver in that state with
  two thirds of the stream still to come.

`terminal` is true only once the FIN arrived **and** every byte was
delivered and read, or the peer sent RESET_STREAM — `reset_seen` tells an
abort apart from a clean EOF. `null` means the stream was already reaped,
which is terminal too:

```zig
while (true) {
    const n = conn.streamRead(id, &buf) catch |err| switch (err) {
        error.StreamNotFound => break, // already reaped
        else => return err,
    };
    if (n == 0) break;                 // nothing readable RIGHT NOW
    handle(buf[0..n]);
}
const st = conn.streamRecvState(id) orelse return true; // reaped => done
if (!st.terminal) return false;                         // more coming, or a gap
if (st.reset_seen) return true;                         // peer aborted
// clean EOF: every byte arrived and was read
```

A receiver that knows the message length in advance (a fixed-size reply, a
length-prefixed frame) may end on the byte count instead — that is what
`examples/echo_client.zig` does. Everything else ends on `terminal`.
`examples/echo_server.zig`, `examples/foreign_loop_embedder.zig`, and
`examples/goodput_smoke.zig` all follow this rule, and the reordering
regression test that pins it lives in `examples/foreign_loop_embedder.zig`.

RFC 9221 DATAGRAM support is off by default:
`transport_params.max_datagram_frame_size` defaults to `0`, which
advertises no DATAGRAM support. Set it to a nonzero value on your own
transport params to receive DATAGRAM frames — and expect
`Error.DatagramUnavailable` from `sendDatagram` until the *peer*
advertises a nonzero value of its own. Once enabled,
`maxDatagramPayload()` returns the largest payload `sendDatagram` will
currently accept — PMTU-aware and bounded by the peer's
`max_datagram_frame_size` — so a caller can size buffers up front instead
of probing for `Error.DatagramTooLarge`.

`Connection.phase()` reports a coarse `quic.ConnectionPhase` —
`initial` → `handshake` → `established`, or `closing` / `draining` /
`closed` — so an embedder can gate its own state machine without inferring
the epoch from `handshakeDone` and `closeState`.

For orderly shutdown, `Connection.beginGracefulShutdown()` refuses new
local stream opens (`Error.ShuttingDown`) and stops granting MAX_STREAMS
credit so the peer quiesces new-stream creation, while in-flight streams
drain to completion. QUIC has no GOAWAY frame, so this is the transport
building block a higher layer pairs with its own GOAWAY signal. The
connection stays open until you call `close`:

```zig
conn.beginGracefulShutdown();     // stop taking new streams
// ... let existing streams finish, or apply a shutdown deadline ...
conn.close(true, 0x0, "done");    // then close for real
```

## Required Configuration

Set these deliberately for any deployed server:

- `tls_cert_pem` and `tls_key_pem`: PEM leaf certificate chain and
  matching private key.
- `alpn_protocols`: required by QUIC. For HTTP/3, pass `&.{"h3"}`.
- `transport_params.max_idle_timeout_ms`: `Server.init` substitutes a
  safe 30s timeout when this is left at `0`; set it explicitly to match
  your deployment, or set `Server.Config.allow_no_idle_timeout = true` to
  genuinely run with no idle timer.
- `transport_params.initial_max_*`: stream and connection flow-control
  limits for your application workload.
- `max_concurrent_connections`: slot-table cap.
- `max_connection_memory`: aggregate per-connection cap for peer-driven
  buffers.
- Rate/quota knobs all share one three-state type,
  `Server.RateLimit`: `.default` takes the library's recommendation,
  `.disabled` opts out, `.{ .limit = n }` sets an explicit cap.
  `null` is deliberately not spellable, so mirroring an unset field
  can never silently switch a protection off.
  - `initial_source_rate_limit` (recommended 32) and
    `vn_source_rate_limit` (recommended 8): per-source Initial and
    Version-Negotiation flood limiters. `.disabled` suits a trusted
    front-end that already polices source rate.
  - `log_source_rate_limit` (recommended 16): per-source cap on
    `LogEvent` emissions, so a peer cannot flood your log pipeline.
  - `listener_datagram_rate_limit` / `listener_byte_rate_limit`
    (global, per `listener_rate_window_us`) and
    `source_byte_rate_limit` (per-source bytes/second): recommended
    off, because the right ceiling is your deployment envelope. Set
    them in production.
- `retry_token_key`: enables stateless Retry before allocating a
  connection slot.
- `new_token_key`: enables NEW_TOKEN issuance for returning clients.
- `stateless_reset_key`: required when the server auto-issues CIDs that
  need reset tokens, including preferred-address and QUIC-LB rotation.

Implementation limits: quic-zig caps what `transport_params` may
advertise, and values above the caps are rejected with
`error.InvalidValue` (at `Client.connect`, or when the server installs
the parameters on an accepted connection) rather than clamped:
`initial_max_data` and each `initial_max_stream_data_*` cap at 16 MiB,
`initial_max_streams_bidi` / `initial_max_streams_uni` at 4096, and
`active_connection_id_limit` at 16. Peer-advertised stream-count and
CID limits above those caps are clamped instead.

Persist Retry, NEW_TOKEN, and stateless-reset keys across graceful
restarts when continuity matters. Rotating them is a deployment event:
old Retry and NEW_TOKEN values stop validating, and old stateless-reset
tokens stop matching previously issued CIDs.

## 0-RTT

0-RTT is off by default. To enable it safely:

- Allocate a `quic.tls.AntiReplayTracker` (it must outlive the
  `Server`) and set `Server.Config.early_data` to
  `.{ .with_anti_replay = &tracker }`. The union carries the tracker,
  so there is no separate field to remember — which is the point: the
  only way to run early data without replay protection is to name
  `.without_replay_protection`, and that is correct only when every
  request reachable over early data is idempotent.
- Bind tickets to replay-relevant transport and application settings
  with `Connection.setEarlyDataContextForParams`.
- Size a restore payload before you stage it: `Client.earlyDataSendWindow()`
  (null when the client is not resuming) returns the early-data
  flow-control budget from the remembered session — `max_data` in
  total plus the per-stream ceilings — so an embedder staging 0-RTT
  bytes before `advance()` can check they fit rather than discovering
  the limit mid-flight.
- Treat bytes where `Connection.streamArrivedInEarlyData(id)` is true as
  replayable. Only idempotent application actions should be accepted.

Client session tickets are re-exported as `quic.Session`:

```zig
var resumed = try quic.Session.fromBytes(client_ctx, ticket_bytes);
defer resumed.deinit();
try conn.setSession(resumed);
conn.setEarlyDataEnabled(true);
```

On a resuming client, also supply the server's transport parameters as
observed on the ticket-issuing connection, so early-data sends are bounded
by the resumed session's flow-control limits. BoringSSL does not carry
peer transport parameters across resumption, so quic-zig persists both in
one versioned envelope: encode the ticket together with the observed
parameters via `quic.tls.resumption_state.encode` / `encodeAlloc`,
and feed the bytes back through `Client.Config.resumption_state` — the
wrapper decodes the envelope (`tls.resumption_state.decode`), installs
the session, enables early data, and remembers the peer parameters. On a
raw `Connection`, call `conn.setRememberedPeerTransportParams(...)` next
to `setSession`. Without the remembered parameters, early-data streams
keep an unbounded (client-self-limited) send window until the server's
real parameters arrive.

## Diagnostics

TLS key logging is available through `boringssl-zig` and re-exported as
`quic.KeylogCallback`:

```zig
try tls_ctx.setKeylogCallback(onKeylogLine);
```

Connection lifecycle, packet, congestion, migration, loss, and key-update
events are surfaced through the qlog-style callback:

```zig
conn.setQlogCallback(onQlogEvent, app_state);
conn.setQlogPacketEvents(true);

fn onQlogEvent(user_data: ?*anyopaque, event: quic.QlogEvent) void {
    _ = user_data;
    recordEvent(event);
}
```

Packet sent/received events are opt-in through
`setQlogPacketEvents(true)` so embedders can keep high-volume telemetry
off in low-overhead deployments.

## Extension Surfaces

- QUIC v2 is available through `Server.Config.accepted_versions`,
  `Client.Config.preferred_version`, and
  `Client.Config.compatible_versions`.
- Multipath tracks draft 21 through `initial_max_path_id`,
  path-specific CID provisioning, and `Connection.pollDatagram`.
- Preferred Address is configured with `Server.Config.preferred_address`;
  `runUdpServer` binds the alternate listener sockets for that config.
- QUIC-LB draft 21 is exposed as `quic.lb` and
  `Server.Config.quic_lb`. Plaintext, single-pass AES, and four-pass
  Feistel modes are implemented. Enabling it intentionally embeds routing
  information in server-issued CIDs.
- Alternative Server Address draft 00 exposes codec support, server emit,
  typed receive events, and helper functions through `quic.alt_addr`
  and `examples/alt_addr_embedder.zig`.

## Out Of Scope

quic-zig does not implement HTTP/3, QPACK, WebTransport, MASQUE, or FIPS
validation. (Windows used to be listed here; it has since been promoted
to a tier-1 release-gating platform — see `docs/RELEASE_READINESS.md`.
BBR also used to be listed here; BBRv3 landed as an opt-in
`congestion_control = .bbr`, pinned to draft-ietf-ccwg-bbr-06 — the
default stays CUBIC.)

One Windows caveat, and it is about the *bundled* loop only: the
convenience helpers `transport.runUdpServer` / `runUdpClient` fail
with `error.WindowsBundledLoopUnsupported` on native Windows, because std has
no overlapped-I/O `net_receive` there and so cannot perform the timed
receive those loops use as their heartbeat. This is not a limitation
of the protocol engine, which is fully supported on Windows. Drive the
connection yourself with the caller-drives API described above — the
pattern in `examples/foreign_loop_embedder.zig`, which already handles
this exact error by falling back to a blocking read. If std gains an
overlapped `net_receive`, the bundled loops will work unchanged and
the tests pinning this behavior will fail to tell us so.
