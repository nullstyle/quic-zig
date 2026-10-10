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

For the current verified pin, coordinated dependency options, and cumulative
migration guidance, see the maintained
[downstream integration brief](docs/DOWNSTREAM_INTEGRATION.md).

## Package Setup

In a consuming `build.zig`, import the module from the package
dependency:

```zig
const quic_dep = b.dependency("quic", .{
    .target = target,
    .release = optimize != .debug,
});
exe.root_module.addImport("quic", quic_dep.module("quic"));
```

The package builds in Debug or in ReleaseSafe and in nothing else.
`.release = optimize != .debug` selects ReleaseSafe for an application
in any release mode, with every release of quic-zig. From 0.24.1
`.optimize = optimize` is accepted too (Debug and ReleaseSafe;
ReleaseFast and ReleaseSmall stop the build). Through 0.24.0 an
`optimize` option was reported as `error: invalid option: "optimize"`
and then ignored, which left quic-zig and its BoringSSL in Debug
inside a release build, and this guide showed that line. `zig build
--verbose` shows the mode each module gets: read the `-O` flag in
front of `-Mquic=`. Every package in one build that depends on
quic-zig must pass the same options with the same values, or the
build makes two `quic` modules.

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

#### Discovering fully-authenticated connections

A slot becomes a fully authenticated peer the moment its TLS handshake
completes — mid-`feed`, on the datagram that carried the client's
Finished. `Server.Config.on_handshake_complete` (or the post-init
`setOnHandshakeCompleteHook`) fires there, exactly once per slot, with
the slot's connection established and open: negotiated ALPN, transport
parameters, and the client's authenticated identity
(`conn.peerCertSpkiDigest()`) are all readable, and it is the right
place to allocate per-connection application state onto
`slot.user_data`. This replaces the diff-`iterator()`-and-poll-
`handshakeDone()` pattern embedders otherwise need at the accept
boundary. The callback runs synchronously inside `feed` on the loop
thread; per-slot mutation is the intended use, but do not call back
into the server from it.

#### Loop thread or loop fiber

What "the loop's own thread" means depends on the `std.Io` backend
driving the loop. Under `std.Io.Threaded` the loop is an ordinary
thread: run it on a `std.Thread`, or in a `std.Io.Group` task, and stop
it either way. Under an Evented backend (`std.Io.Dispatch` on macOS,
`std.Io.Uring` on Linux) the loop is a fiber on one of the backend's
worker threads — `Io.Group` tasks and `Io.async` fibers both work, and
on Linux prefer one Evented instance per loop thread (see the bench's
`--io ev-thread` mode; a shared instance's work stealing costs group
goodput).

The stop mechanism differs with it. The shutdown flag — checked every
`receive_timeout_ms` — is the only stop path that works on every
backend today: Evented network waits are not cancellation points
(`Io.Dispatch` has none yet), so a `Group` cancellation cannot
interrupt a parked receive; it lands on the next in-flight call at
best, which the loops treat as a clean exit (`error.Canceled` from a
send is its own send disposition, neither a fault nor a peer event).
Set the flag, then await the loop task, and expect the exit to take up
to one receive timeout.

### Scaling across cores

There is no built-in multi-worker mode: one `Server` is one
single-threaded instance. To use more than one core, run N independent
`Server` instances (each on its own thread or process) sharing the
same port: pass the same `listen` string to every instance and set
`RunUdpOptions.reuse_port = true`, which applies `SO_REUSEPORT` to
every listener the loop binds before the bind. (Binding a socket of
your own for a caller-driven instance? When
`quic.transport.std_bind_has_reuse_port` is true, pass
`.reuse_port = true` to `std.Io.net.IpAddress.bind` and stay on your
`Io` backend. On an older std, bind through
`quic.transport.bindUdpSocket(&addr, .{ .reuse_port = true })`, a
POSIX-direct fallback whose socket is blocking and therefore suits
`std.Io.Threaded` and `std.Io.Uring` but not `std.Io.Dispatch`.) No
shared state exists between
instances, so no locks are needed; connection CIDs and stateless-reset
tokens must be minted from per-instance configurations (QUIC-LB or
random SCIDs) so peers route to the instance that owns their
connection.

What the kernel does with N sockets on one port is platform behavior,
not library behavior, and it differs:

- **Linux** (kernel ≥ 3.9) hash-balances flows across the socket group
  by 4-tuple, so each connection stays on one worker for as long as
  the client's address and port AND the group's membership are stable.
  The kernel picks `socks[hash * N >> 32]` over its array of N sockets;
  a worker leaving shrinks N and drops the last-bound socket into the
  vacated slot, a worker joining appends. Either re-homes a share of
  the flows that were on the OTHER workers (none to most of them,
  depending on which slot the departing worker held), and a sibling
  that receives such a packet answers it with a stateless reset when
  the shared `stateless_reset_key` is pinned, so those connections
  die. Rolling restarts therefore need CID routing just as migration
  does (below); `SO_REUSEPORT` alone only lets the replacement bind
  while the old worker still holds the port. Every socket in the group
  must be owned by one UID (the uid it was created under); any process
  under that UID can join the port and receive its traffic. That is
  inherent to `SO_REUSEPORT`, which is why the option is opt-in.
- **macOS / BSD** permit the shared bind but do not balance: one
  socket receives every unicast datagram — the most recently bound one
  when the workers bind a specific address, the OLDEST one when they
  bind the wildcard address (`0.0.0.0` / `[::]`, the usual server
  shape). When that socket closes, the next in line takes over. A
  macOS fleet therefore behaves active/passive, not load-balanced —
  fine for bind-sharing and failover, not a scaling story — and with
  wildcard binds a newly spawned worker receives nothing until every
  older one has exited.
- A client whose 4-tuple changes — connection migration, NAT
  rebinding, a `preferred_address` — can land on an instance that does
  not own its connection. Deployments that need migration resilience
  or disruption-free worker restarts must route by CID (QUIC-LB, an eBPF reuseport program, or an
  external load balancer) rather than rely on the kernel hash. The
  loop applies `reuse_port` to `preferred_address` alt listeners too,
  so all workers can boot, but migration across them has this same
  routing caveat.
- Windows sockets have no `SO_REUSEPORT`, and the bundled loop does
  not run on Windows at all (`RunError.WindowsBundledLoopUnsupported`).
  On any other POSIX target whose sockets lack the option, the loop
  refuses up front with `RunError.ReusePortUnsupported` instead of
  letting a fleet die one `AddressInUse` at a time.

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
data from the same stream is pumped; `onStreamEnd` fires once the
receive half has ended (`streamRecvEnd`), never early under
reordering, as `.fin` or `.reset` even if a `tick` reaped the stream
first (`.reaped` is left for teardown and "how unknown");
`Outbox.push` accepts what the connection takes and
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
Driver sessions. `deinit` itself is silent — no CONNECTION_CLOSE is
sent — so peers of live connections see a drop, not a close. When the
close must be wire-visible, call `server.shutdown(code, reason)` first
and keep servicing until the slots reach `.closed` (then `reap`),
calling `deinit` last.

Worked examples: `examples/echo_server.zig` (streaming echo),
`examples/request_response_server.zig` (length-prefixed
request/response — the pattern most protocols build on).

### Borrowing accepted and dialed connections

`quic.app.ConnectionDriver(App)` runs the same stream/event machinery for
one borrowed `Connection`. It works with either `Server.Slot.conn` or
`Client.conn`, without taking ownership of the socket, connection, timers,
or application protocol. One driver consumes each connection's events.

```zig
const Pump = quic.app.ConnectionDriver(MyApp);
var pump = try Pump.init(.{
    .allocator = allocator,
    .app = &app,
    .conn = conn,
    .max_tracked_streams = 128,
    .outbox_limits = .{ .max_streams = 16, .max_bytes = 1 << 20 },
    .hooks = .{
        .on_stream_data = MyApp.onData,
        .on_stream_end = MyApp.onEnd,
    },
});
// MyApp declares ConnState and StreamState; pump.state is its ConnState.
// Call pump.deinit() BEFORE the owner destroys conn.
try pump.service(); // after inbound packets, before conn.tick(now_us)
```

The data hook has type
`fn (*MyApp, *Pump, *Pump.StreamEntry, []const u8) anyerror!usize`.
Return the number of bytes accepted. Zero pauses the stream until the next
service pass; partial consumption also yields. Unconsumed bytes stay in
QUIC's receive buffer and retain their flow-control charge. A successful
hook must not consume, reset, or otherwise mutate that same receive half.
It may open other streams or queue responses. Returning an error consumes
nothing, so commit application side effects only with successful progress.

Peer streams are discovered automatically. After opening a local bidi
stream, call `pump.trackStream(id)` to receive its response. `refusedStreams()`
counts incoming streams rejected because the table is full or no data hook
is installed; rejection sends STOP_SENDING, and RESET_STREAM too on a
bidirectional stream (so the stream ends on both sides and gives its
place in the stream window back). FIN is delivered
only after all bytes have been consumed; RESET and teardown deliver a single
terminal hook. `deinit` is idempotent and delivers remaining stream ends
before `on_disconnect`, without destroying the borrowed connection.
`on_handshake` also works when an owner delegates an already-established
connection after consuming its original handshake event.

Both drivers' outboxes have bounded pending stream and byte limits. A push
reserves capacity for the complete payload before writing any prefix;
`error.QueueFull` or allocation failure therefore accepts no bytes and is
safe to retry. Check `pendingBytes()` and `pendingStreams()` for pressure.
The defaults are 128 pending streams and 16 MiB. The legacy server Driver
retains its `!void` data callback, which accepts the entire supplied chunk.
To apply the same pause contract on that adapter, provide
`on_stream_data_consumed` with a `!usize` result; it takes precedence over
`on_stream_data`.

Server `Driver.service` attaches teardown automatically. Explicit `attach`
is still supported and chains the server's previous will-close hook after
driver cleanup. `slot.user_data` remains available to the embedder; retrieve
driver state through `driver.sessionOn(slot)`. Destroy the server before the
driver so every accepted session receives its terminal callbacks.

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

### Peer identity: who did the handshake authenticate?

Once a connection's handshake completes, `conn.peerCertSpkiDigest()`
returns the SHA-256 fingerprint of the peer's leaf-certificate
SubjectPublicKeyInfo — the same value
`openssl x509 -pubkey | openssl pkey -pubin -outform DER |
openssl dgst -sha256` prints for that certificate. It is null before
the handshake completes, when the peer presented no certificate (a
server that verifies but does not require client certs), or once the
connection leaves its open phase. The digest is stable across
certificate re-issuance as long as the keypair is retained, works on
resumed sessions, and reads the other role's certificate — a server
sees the client's key, a client the server's — so it is the natural
embedder-side peer id ("who am I talking to?") for mTLS meshes:

```zig
// Inside your per-connection accept path (e.g. on_handshake_complete):
if (conn.peerCertSpkiDigest()) |digest| {
    // Bind application session state to the authenticated key.
    sessions.put(digest, makeSession(conn));
}
```

### Dialing by address: skipping the name check under a pinned CA

A mesh client dials addresses learned out-of-band; the peer
certificate's identity is its cluster membership, not the name dialed.
`.identity_verification = .none` sends SNI as usual but skips the
SAN/CN-vs-`server_name` check while chain validation against `ca_pem`
stays mandatory. It requires `ca_pem` (combining it with
`insecure_skip_verify`, `tls_context_override`, or no pinned roots at
all fails `connect` with `InvalidConfig` — it must never silently
downgrade to no verification):

```zig
var client = try quic.Client.connect(.{
    .allocator = allocator,
    .server_name = "mesh-node-7.internal", // SNI only; not identity
    .alpn_protocols = &protos,
    .transport_params = params,
    .ca_pem = cluster_ca_pem,
    .identity_verification = .none,
});
```

Read the peer's `peerCertSpkiDigest()` after the handshake to learn
which cluster member actually answered.

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

The send buffer you give to `poll` / `pollDatagram` must be at least
1200 bytes. A handshake datagram (one that holds an Initial or a
Handshake packet) is never longer than 1200 bytes, whatever the buffer
holds, and it is exactly 1200 when RFC 9000 section 14.1 wants it
padded. Only a datagram with a 1-RTT packet alone can be longer: up to
the path's MTU, and a DPLPMTUD probe up to `pmtud_config.max_mtu`. Size
the buffer for that (1500 is enough for the defaults). With a buffer
under 1200 bytes a client gets `error.OutputTooSmall` for a datagram
with an Initial packet, and a server sends no ServerHello.

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
  down the loop; the packaged loop swallows per-slot failures. An
  error from `Connection.handle` (or from `Server.feed` for one slot)
  is fatal for that connection and for nothing else: close it and go
  on. A datagram that does not authenticate is never such an error.
  Since 0.25.0 `handle` drops it; before that it returned an error
  for a header that did not parse, and a loop that closed the
  connection on that error could be made to close it by anyone who
  saw one of its packets.
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
consuming the id (a later retry reuses it; see "Stream limits are a
window" below). When a layer must know the id
*before* opening — e.g. to run a GOAWAY / stream-limit gate keyed on it —
`peekNextBidi()` / `peekNextUni()` return the id the matching `openNext*`
would use next, without consuming it:

```zig
const id = conn.peekNextBidi();
if (!localGoawayGate(id)) return error.RequestBlocked;
const s = try conn.openNextBidi();   // reuses the peeked id
```

### Stream limits are a window

`initial_max_streams_bidi` and `initial_max_streams_uni` say how many
streams of each type the peer may have open **at once**. They do not
limit how many streams a connection carries over its life: a
connection can go on for as long as it lives (the only ceiling is the
wire's own, 2^60 streams of each type).

quic-zig gives a stream id back when a stream of the peer is fully
closed, and sends the MAX_STREAMS frame for you. The limit it has
advertised is always `window + streams closed`. Things to know:

- **A stream holds its place until both directions are finished.** For
  a bidirectional stream the peer opened, that means its data is read
  to the end, and your side is finished and acknowledged (or reset).
  A request you never answer and never finish holds one place in the
  window for the life of the connection. Finish (`streamFinish`) or
  reset (`streamReset`) every stream you do not need.
- **To refuse a stream, end both halves.** `streamStopSending(id, code)`
  ends the half the peer sends on: the peer is asked to stop, and the
  connection reads and drops what still arrives, so you need not read
  the stream again. On a bidirectional stream also call
  `streamReset(id, code)` for your own half. STOP_SENDING alone leaves
  a bidirectional stream half open, and a peer whose bytes were all
  acknowledged answers it with nothing, so the RESET_STREAM is also
  what tells the peer it was refused. (`quic.app.Driver` does both when
  its table is full.)
- **`Error.StreamLimitExceeded` is always temporary.** The id is not
  consumed. Try again when the peer has raised its limit; a
  `flow_blocked` event with `kind == .streams` tells you that you were
  blocked, and the peer is told too (STREAMS_BLOCKED). How fast a peer
  gives ids back is the peer's own rule.
- **An id you skip is a stream the peer keeps open.** Opening stream
  12 first also opens 0, 4 and 8 on the peer (RFC 9000 §2.1), and each
  holds a place in its window until you use and finish it. Open
  streams in order (`openNextBidi` / `openNextUni` do), or use the ids
  you skipped.
- **Size your window from round trips, not from the request count.** An
  id comes back two round trips after its stream opens: one for the
  request and the reply, one for the acknowledgement and the credit.
  A window of `W` therefore carries about `W / (2 x RTT)`
  request/reply streams per second. Measured (`zig build bench-e2e --
  --scenario churn`, 30 ms round trip): 16.6, 66.2 and 221.5 per
  second for windows of 1, 4 and 16.
- **A table sized to your windows cannot overflow.** A conforming peer
  never has more than `initial_max_streams_bidi +
  initial_max_streams_uni` streams open, so a stream table of that
  size (see `quic.app.Driver`'s `max_tracked_streams`) never has to
  refuse one.
- The largest window you may configure is
  `Connection.max_concurrent_streams_per_kind` (4096); a larger value
  is `error.InvalidValue`. A limit the PEER grants you is taken as
  sent.

Releases through 0.23.0 worked differently, and code written for them
may still plan for it: the limit DOUBLED when streams ended (so it did
not bound concurrency), and it stopped for good at 4096 streams of each
type over the life of the connection
(`Connection.max_streams_per_connection`, removed). If you counted
streams and retired a connection before stream 4096, you can delete
that.

To observe stream completion and backpressure without reaching into the
stream internals — which the transport's stream GC reclaims the moment a
stream goes terminal — use the connection-level accessors:

- `streamReadFin(id, dst)` reads like `streamRead` but also returns `fin`
  (a FIN arrived and no reset followed) and `reset_code` (the peer reset
  the stream), captured inline with the read. `fin` is NOT an end-of-stream
  test on its own — see "Ending a receive stream" below. (Since 0.28.0
  `fin` is false for a stream the peer reset after its FIN: the reset threw
  unread bytes away, so it is cut, not complete.)
- `streamRecvState(id)` reports `fin_seen` / `reset_seen` / `terminal` /
  `reset_code` for a LIVE stream, or `null` once the stream has been reaped
  or was never opened. Non-null means "still in the table".
- `streamRecvEnd(id)` reports how the receive half ENDED — `fin_seen`,
  `reset_code`, `final_size`, `read_offset`, and `isClean()` — and gives
  the same answer before and after the `tick` that reaps the stream (see
  "Ending a receive stream" below).
- `streamSendStats(id)` snapshots `written` / `acked` / `buffered` /
  `has_pending` for write backpressure, or `null` for a reaped stream.

### Ending a receive stream

**Use `streamRecvEnd(id)`, and nothing else.** Every wrong version of
this test fails *silently*: the application truncates the stream, and
neither endpoint reports an error.

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

- "The stream is gone" is not an end-of-stream test either. `tick` reaps a
  stream the moment its receive half ends, so `StreamNotFound` (or
  `streamRecvState` == null) after a reap looks the same for a clean FIN
  and for a reset. Before 0.28.0 an end that arrived with nothing left to
  read (a bare FIN after your last read, or a RESET_STREAM) could be
  reaped before you looked, and its kind was lost.

`streamRecvEnd` is non-null only once the receive half has ENDED — the FIN
arrived **and** every byte was delivered and read, or the peer sent
RESET_STREAM — and it says which. It answers the same whether you ask
before or after the `tick` that reaps the stream, at least through the
tick after the reaping one. Past that, a reaped stream's end note may be
overwritten — and if the connection could not allocate the note at all
(out of memory), there is none. In both cases `null` with
`streamRecvWasReaped(id)` true means "ended, how unknown". Treat that as
cut, never as complete:

```zig
while (true) {
    const n = conn.streamRead(id, &buf) catch |err| switch (err) {
        error.StreamNotFound => break, // already reaped: see below
        else => return err,
    };
    if (n == 0) break;                 // nothing readable RIGHT NOW
    handle(buf[0..n]);
}
const end = conn.streamRecvEnd(id) orelse {
    if (conn.streamRecvWasReaped(id)) return .cut; // ended, how unknown
    return .more_coming;                           // not ended, or a gap
};
if (end.isClean()) return .clean; // FIN, every byte arrived and was read
return .cut;                      // reset (end.reset_code) or stopped
```

Read every stream at least once between two calls of `tick` and you meet
the "how unknown" case only if the note could not be allocated: you see
each end while the stream is still live. The bundled loops do this:
`runUdpServer` and (since 0.28.0) `runUdpClient` run their hook before
`tick`.

A receiver that knows the message length in advance (a fixed-size reply, a
length-prefixed frame) may end on the byte count instead — that is what
`examples/echo_client.zig` does, and it still asks `streamRecvEnd` when the
stream is gone, because a reset is a cut reply whatever the count says.
Everything else ends on `streamRecvEnd`. `examples/echo_server.zig` gets
it through `quic.app` (its `onStreamEnd` sees `.fin` / `.reset`), and
`examples/goodput_smoke.zig` asks `streamRecvEnd` directly.
`examples/foreign_loop_embedder.zig` ends on a live stream's `terminal` and
takes a stream that is already gone as abandoned (cut), which keeps the
same rule — gone is never complete — and its reordering regression test
pins the "empty read + FIN" trap above.

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
  genuinely run with no idle timer. Note the idle timer only governs a
  connection once its handshake is CONFIRMED — before that there may be
  no negotiated idle value at all (the peer's parameters haven't
  arrived, or either side advertised 0), which is what the next knob
  covers. The timer also cannot observe a peer that dies while this
  side's ack-eliciting data is unacked: loss recovery keeps PTO-probing,
  every outbound probe refreshes the connection's activity clock, and
  the idle deadline moves with it — such connections are structurally
  immortal at the connection layer. That failure mode is answered by
  stateless resets (`stateless_reset_key` below), not by the idle
  timeout; sizing the timeout smaller does not close it.
- `handshake_timeout_ms` (server default 10s, client default 30s, `0`
  disables): bounds how long a connection may live without completing
  its handshake. Without it, a dial to a server that drops every packet
  retransmits its Initial budget and then sits silently forever, and a
  server receiving abandoned dials accumulates half-open slots until
  `max_concurrent_connections` is exhausted and the endpoint mutes —
  the QUIC analog of a SYN flood. On expiry the connection drains (no
  CONNECTION_CLOSE is sent; the peer is unresponsive by definition)
  and `pollEvent` reports `CloseSource.handshake_timeout`, so "never
  became viable" stays distinguishable from "went quiet after
  establishing". The timer disarms at handshake confirmation and hands
  liveness back to the idle timeout; 0-RTT resumption attempts get the
  same bound. If you run with the idle timeout opted out AND a
  confirmed connection goes silent, that connection lives until your
  embedder-level guards act — by then it is your policy, not a gap.
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
- `stateless_reset_key`: set it on any deployed server. It is not a
  per-feature prerequisite — it gates the whole RFC 9000 §10.3
  mechanism. Without it: no reset emission; no §18.2 token advertised,
  so peers cannot detect a reset and a client of a crashed-and-restarted
  server waits out its idle timeout instead of learning the connection
  died; `auto_replenish_connection_ids` silently no-ops, leaving each
  connection on its single handshake CID, which in turn makes
  client-initiated migration fail (`MigrationNoFreshPeerCid`) and skips
  CID rotation on NAT rebinding. It is additionally *required* for
  preferred-address and QUIC-LB rotation, which `Server.init` enforces.
  Do not hand-set `transport_params.stateless_reset_token` in its
  place — that advertises one fixed token to every peer.

Implementation limits: quic-zig caps what `transport_params` may
advertise, and values above the caps are rejected with
`error.InvalidValue` (at `Client.connect`, or when the server installs
the parameters on an accepted connection) rather than clamped:
`initial_max_data` and each `initial_max_stream_data_*` cap at 16 MiB,
`initial_max_streams_bidi` / `initial_max_streams_uni` at 4096
(`Connection.max_concurrent_streams_per_kind`: streams open at once,
not streams over the connection's life), and
`active_connection_id_limit` at 16. A peer-advertised CID limit above
the cap is clamped instead. A peer-advertised stream limit is taken as
sent.

Persist Retry, NEW_TOKEN, and stateless-reset keys across graceful
restarts when continuity matters. Rotating them is a deployment event:
old Retry and NEW_TOKEN values stop validating, and old stateless-reset
tokens stop matching previously issued CIDs.

For the stateless-reset key the requirement is stronger than "survive
graceful restarts": reset tokens are derived per-CID from the key, so a
*replacement* listener — a restarted instance, or a sibling instance
behind the same port — can only reset a dead instance's orphaned
connections if it holds the SAME key. Pin one stateless-reset key
across every instance and restart of a deployment; with per-instance
keys, orphan cleanup degrades to waiting out each peer's idle timeout
(or forever, per the `max_idle_timeout_ms` note above).

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
real parameters arrive. Pass the server's parameters whole: since
0.27.0 the remembered `initial_max_streams_bidi` and
`initial_max_streams_uni` are also the number of streams that can be
opened before the handshake, so a struct with flow-control limits
only allows none.

### Session tickets across restarts

A resumed handshake needs a ticket that the server can open. BoringSSL
seals tickets under a key that is random for each TLS context and
lives in memory only. So by default a restarted process, and the
context that `replaceTlsContext(.{ .pem = ... })` builds, cannot open
the tickets that are out: every client pays one full handshake and
loses its 0-RTT.

Give the server a key of its own to keep them:

```zig
// 48 bytes from a CSPRNG, made once and kept where the next process
// (and every server of the pool) finds them. A secret of the same
// rank as the private key: not in the repository, not in a log.
const ticket_key: quic.SessionTicketKey = loadTicketKey();

var server = try quic.Server.init(.{
    // ...
    .early_data = .without_replay_protection, // see "the refused pair"
    .session_ticket_key = ticket_key,
    .session_ticket_lifetime_s = 6 * 60 * 60,
});
```

- **What survives.** With the same key, a ticket from before the
  restart resumes. 0-RTT survives too when the ALPN,
  `transport_params` and `early_data_application_context` are the same
  as before (a server must not lower the limits that a ticket
  remembers). A certificate reload with `.pem` keeps the key and the
  lifetime.
- **What a stolen key gives.** Not recorded 1-RTT traffic: TLS 1.3
  resumes with a fresh key exchange. It does open recorded 0-RTT data,
  it lets its holder answer as your server to a client that offers a
  ticket, and it lets its holder make tickets (with client
  certificates in use, a session for any client identity). All three
  end when the key is no longer accepted.
- **Change the key on a schedule.** `server.rotateSessionTicketKey(new_key, now_us)`,
  on the thread that calls `feed`. New tickets are sealed under the
  new key at once. The old key still opens tickets for one ticket
  lifetime, so no client loses its session, and every client that
  comes back leaves with a ticket of the new key. Then the old key is
  cleared. BoringSSL changes its own key every 2 days; a period of
  hours to a few days is reasonable here, and never more than 7 days.
  Give the new key to the other servers of the pool the same way, and
  to the next process as `session_ticket_key`. A process that STARTS
  with the new key does not have the old one.
  `now_us` must be on the clock that you give `feed` and `tick`: the
  old key is cleared when that clock reaches `now_us` plus one
  lifetime. A second rotation before that drops the old key at once.
  The Server does not check the thread.
- **A restart soon after a key change.** A process that restarts less
  than one ticket lifetime after the rotation, and starts with the new
  key, loses the tickets of the old key that are still out. To keep
  them, start it with the OLD key as `session_ticket_key` and call
  `rotateSessionTicketKey(new_key, t)` before the first datagram. If
  your `now_us` goes on across the restart, `t` is the `now_us` of the
  first rotation, and the old key ends when it would have ended. If it
  does not, `t` is the present `now_us`, and the old key lives one more
  lifetime from the restart.
- **The lifetime** (`session_ticket_lifetime_s`, 1 second to 7 days,
  default 2 days) is how long a ticket is good for, and so how long an
  old key is of use after a rotation. TLS measures it on the wall
  clock. More than 2 days needs the client too: a BoringSSL client (a
  quic-zig client is one) keeps a ticket for 2 days at most unless
  that limit was raised on its own TLS context.
- **Your copies of the key.** The Server clears its own copy at
  `deinit`. The `Config` that you built and the buffer that you loaded
  the key into are yours to clear (`std.crypto.secureZero`).
- **The refused pair.** `session_ticket_key` together with
  `early_data = .with_anti_replay` is `InvalidConfig`. The replay
  tracker is process memory; after a crash it is empty, and a 0-RTT
  flight that was recorded before the crash would be "fresh" again for
  about a minute. Use `.without_replay_protection` with a replay
  defense of your own (accept only idempotent requests as early data),
  or `.disabled`, which keeps resumption and drops 0-RTT.
- **Source validation after a restart.** A `new_token_key` that is
  the same after the restart lets a returning client skip the Retry,
  but only if the clock that stamps and checks the tokens goes on
  across the restart: set `new_token_clock = quic.unixWallClockUs`
  (microseconds since the Unix epoch) and a
  `new_token_max_clock_skew_us` of a few seconds. Without it the
  tokens use the `now_us` of `feed`, and a clock that starts at zero
  in each process (the bundled loop's does) reads the tokens of the
  process before it as not yet valid, and after that as younger than
  they are (it takes them for one token lifetime of its own clock).
  `now_us` stays your timer clock: a wall clock can jump, and the
  timers must not. When the server does answer with a Retry, the
  client sends
  its 0-RTT data again after it (since 0.27.0), so the data still
  arrives before the handshake is done, one round trip later.
  `Connection.retryAccepted()` tells a client that this happened.
- **A context of your own** (`tls_context_override`) takes neither
  setting. Set the key on that context yourself, before the first
  datagram: `quic.tls.session_ticket.install(ctx, &key)` for one key,
  or `quic.tls.session_ticket.installRing(ctx, &ring)` for a pair of
  keys that you rotate.

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
BBR also used to be listed here; BBRv3 landed pinned to
draft-ietf-ccwg-bbr-06 and, as of 0.16.0, IS the default —
`congestion_control = .cubic` is the one-line rollback.)

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
