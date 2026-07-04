# Embedding quic-zig

This guide covers the stable embedding surfaces:

- `quic_zig.Server` for accepting QUIC connections.
- `quic_zig.Client` for dialing QUIC peers.
- `quic_zig.transport.runUdpServer` and `runUdpClient` for simple
  `std.Io` UDP loops.
- `quic_zig.Connection` for custom event loops, batched I/O, qlog
  routing, and application-specific scheduling.

quic-zig is pre-1.0, so APIs may change between 0.x releases. The
module name in Zig code is `quic_zig`.

## Package Setup

In a consuming `build.zig`, import the module from the package
dependency:

```zig
const quic_zig_dep = b.dependency("quic_zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("quic_zig", quic_zig_dep.module("quic_zig"));
```

Application code then uses:

```zig
const quic_zig = @import("quic_zig");
```

## Server Wrapper

`Server` owns TLS context setup, per-connection state, CID routing, Retry
validation, Version Negotiation, and the connection table. The embedder
chooses the socket model and application protocol behavior.

```zig
const std = @import("std");
const quic_zig = @import("quic_zig");

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
    // (see "Persist keys across restarts" below). A real deployment
    // loads this key from durable storage and only generates+stores it
    // on first run.
    var retry_key: quic_zig.RetryTokenKey = undefined;
    std.crypto.random.bytes(&retry_key);

    var server = try quic_zig.Server.init(.{
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
        .max_initials_per_source_per_window = 32,
        .retry_token_key = retry_key,
    });
    defer server.deinit();

    try quic_zig.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:4433",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

`runUdpServer` binds the UDP socket, applies socket tuning, receives
datagrams, feeds the server, drains outbound packets, ticks connection
timers, and exits after the shutdown flag flips. Per-stream application
work can run in a cooperating task that walks `server.iterator()`, or you
can use a custom loop.

## Client Wrapper

`Client.connect` owns the client-side TLS setup and initial connection
ID generation. The returned `client.conn` is the full
`*quic_zig.Connection`.

```zig
const std = @import("std");
const quic_zig = @import("quic_zig");

pub fn dial(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    server_name: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"h3"};

    var client = try quic_zig.Client.connect(.{
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

    try quic_zig.transport.runUdpClient(&client, .{
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
the system trust store by default. For self-signed or test peers, set
`.insecure_skip_verify = true` in the `Client.connect` config — it turns
off impersonation protection, so keep it out of production. Pinning a
private CA to the wrapper-built context is not yet supported (a non-null
`ca_pem` is rejected, not silently ignored); supply a fully configured
`tls_context_override` to verify against your own roots.

## Raw Connection Cycle

`Connection` is the I/O-agnostic state machine under both wrappers. A
custom loop repeats four operations:

1. Feed inbound datagrams with `conn.handle` or `conn.handleWithEcn`.
2. Drain outbound datagrams with `conn.pollDatagram`.
3. Drive timers with `conn.tick`.
4. Sleep until `conn.nextTimerDeadline(now_us)` or the next socket event.

```zig
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
        .alternative_server_address => |addr| scheduleAltAddress(addr),
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

## Stream Conventions, Lifecycle, and Shutdown

For layers that build their own framing on top of the transport (HTTP/3,
WebTransport, custom protocols), a few helpers remove common boilerplate.

Stream ids encode `(initiator, direction)` in their low two bits (RFC 9000
§2.1). Rather than compute them by hand, classify with
`quic_zig.StreamType.fromId(id)` and open the next local-initiated stream
with the role-aware helpers:

```zig
// e.g. an HTTP/3 endpoint's control + QPACK encoder/decoder streams:
const control = try conn.openNextUni();   // next local unidirectional id
const qpack_enc = try conn.openNextUni();
const qpack_dec = try conn.openNextUni();

// classify a peer-initiated stream seen via streamIterator:
switch (quic_zig.StreamType.fromId(id)) {
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

For RFC 9221 DATAGRAMs, `maxDatagramPayload()` returns the largest payload
`sendDatagram` will currently accept — PMTU-aware and bounded by the peer's
`max_datagram_frame_size` — so a caller can size buffers up front instead of
probing for `Error.DatagramTooLarge`.

`Connection.phase()` reports a coarse `quic_zig.ConnectionPhase` —
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
- `max_initials_per_source_per_window` (on by default at 32) and
  `max_vn_per_source_per_window` (on by default at 8): per-source Initial
  and Version-Negotiation flood limiters; set to `null` to disable, e.g.
  behind a trusted front-end that already polices source rate.
  `max_datagrams_per_window` and `max_bytes_per_window` are off by
  default — tune to your deployment envelope.
- `retry_token_key`: enables stateless Retry before allocating a
  connection slot.
- `new_token_key`: enables NEW_TOKEN issuance for returning clients.
- `stateless_reset_key`: required when the server auto-issues CIDs that
  need reset tokens, including preferred-address and QUIC-LB rotation.

Persist Retry, NEW_TOKEN, and stateless-reset keys across graceful
restarts when continuity matters. Rotating them is a deployment event:
old Retry and NEW_TOKEN values stop validating, and old stateless-reset
tokens stop matching previously issued CIDs.

## 0-RTT

0-RTT is off by default. To enable it safely:

- Set `Server.Config.enable_0rtt = true`.
- Allocate `quic_zig.tls.AntiReplayTracker` and pass it through
  `Server.Config.early_data_anti_replay`.
- Bind tickets to replay-relevant transport and application settings
  with `Connection.setEarlyDataContextForParams`.
- Treat bytes where `Connection.streamArrivedInEarlyData(id)` is true as
  replayable. Only idempotent application actions should be accepted.

Client session tickets are re-exported as `quic_zig.Session`:

```zig
var resumed = try quic_zig.Session.fromBytes(client_ctx, ticket_bytes);
defer resumed.deinit();
try conn.setSession(resumed);
conn.setEarlyDataEnabled(true);
```

On a resuming client, also supply the server's transport parameters as
observed on the ticket-issuing connection, so early-data sends are bounded
by the resumed session's flow-control limits. BoringSSL does not carry
peer transport parameters across resumption, so persist them alongside the
ticket and feed them back: with the wrapper set
`Client.Config.resumption_peer_transport_params`, or on a raw `Connection`
call `conn.setRememberedPeerTransportParams(...)` next to `setSession`.
Without them, early-data streams keep an unbounded (client-self-limited)
send window until the server's real parameters arrive.

## Diagnostics

TLS key logging is available through `boringssl-zig` and re-exported as
`quic_zig.KeylogCallback`:

```zig
try tls_ctx.setKeylogCallback(onKeylogLine);
```

Connection lifecycle, packet, congestion, migration, loss, and key-update
events are surfaced through the qlog-style callback:

```zig
conn.setQlogCallback(onQlogEvent, app_state);
conn.setQlogPacketEvents(true);

fn onQlogEvent(user_data: ?*anyopaque, event: quic_zig.QlogEvent) void {
    _ = user_data;
    recordEvent(event);
}
```

Packet sent/received events are opt-in through
`setQlogPacketEvents(true)` so embedders can keep high-volume telemetry
off in low-overhead deployments.

## Extension Surfaces

- QUIC v2 is available through `Server.Config.versions`,
  `Client.Config.preferred_version`, and
  `Client.Config.compatible_versions`.
- Multipath tracks draft 21 through `initial_max_path_id`,
  path-specific CID provisioning, and `Connection.pollDatagram`.
- Preferred Address is configured with `Server.Config.preferred_address`;
  `runUdpServer` binds the alternate listener sockets for that config.
- QUIC-LB draft 21 is exposed as `quic_zig.lb` and
  `Server.Config.quic_lb`. Plaintext, single-pass AES, and four-pass
  Feistel modes are implemented. Enabling it intentionally embeds routing
  information in server-issued CIDs.
- Alternative Server Address draft 00 exposes codec support, server emit,
  typed receive events, and helper functions through `quic_zig.alt_addr`
  and `examples/alt_addr_embedder.zig`.

## Out Of Scope

quic-zig does not implement HTTP/3, QPACK, WebTransport, MASQUE, FIPS
validation, BBR, or a platform support guarantee for Windows.
