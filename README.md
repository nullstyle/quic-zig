# quic-zig

quic-zig is a Zig-first QUIC transport library. It implements the core
IETF QUIC stack around RFC 8999, RFC 9000, RFC 9001, and RFC 9002, with
TLS 1.3 and packet protection provided by
[`boringssl-zig`](../boringssl-zig).

The project is pre-1.0. It is suitable for experiments, embedding work,
interop testing, and implementation research. Treat public APIs as
subject to change until a 1.0 release, and do not expose it to untrusted
internet traffic without the production checklist in
[EMBEDDING.md](EMBEDDING.md).

## What It Includes

- QUIC v1 connection state, packet protection, streams, DATAGRAM,
  loss recovery, NewReno congestion feedback, ECN, and DPLPMTUD.
- High-level `Server` and `Client` wrappers for embedders that want
  quic-zig to own TLS context setup and connection state.
- Basic `std.Io` loop helpers in `quic_zig.transport.runUdpServer`
  and `quic_zig.transport.runUdpClient`, allowing integrators to avoid
  rolling their own UDP loop.
- Stateless Retry, NEW_TOKEN, stateless reset token helpers, 0-RTT with
  anti-replay hooks, qlog-style callbacks, and key logging support.
- Version Negotiation, Retry validation, QUIC v2 compatible version
  negotiation, connection migration, preferred address support, and
  draft multipath plumbing.
- Optional extension surfaces for QUIC-LB draft 21 and Alternative
  Server Address draft 00.

quic-zig is transport-only. HTTP/3, QPACK, WebTransport, and application
protocol policy belong in a layer above this package.

## Build And Test

The repository pins its toolchain with `mise`.

```sh
mise install
zig build test
zig build conformance
zig build bench-test
zig build bench
```

`zig build test` runs unit, integration, conformance, QNS endpoint, and
deterministic fuzz-smoke tests. `zig build conformance` runs only the
RFC-traceable conformance corpus. `zig build bench` runs microbenchmarks
under `ReleaseSafe` in a separate benchmark-only build. Use
`zig build bench -Dbench-unsafe-release-fast=true` only for explicit
unsafe `ReleaseFast` measurements. `zig build bench-test` runs the
benchmark fixture tests through the same build graph, including BoringSSL
C-module wiring.

Production or internet-facing builds must use:

```sh
zig build -Doptimize=ReleaseSafe
```

`ReleaseFast` and `ReleaseSmall` are intentionally not supported for the
network-input parser surface because Zig removes runtime safety checks in
those modes.

## Importing

The public Zig module name is `quic_zig`.

```zig
const quic_zig_dep = b.dependency("quic_zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("quic_zig", quic_zig_dep.module("quic_zig"));
```

Application code imports it as:

```zig
const quic_zig = @import("quic_zig");
```

## Server Quick Start

`Server` owns TLS context setup and the connection table. The embedder
still owns application policy, shutdown, and any per-stream work.

```zig
const std = @import("std");
const quic_zig = @import("quic_zig");

pub fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_pem: []const u8,
    key_pem: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"hq-interop"};

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
    });
    defer server.deinit();

    try quic_zig.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:4433",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

For custom socket ownership, Retry or Version Negotiation policy,
batched I/O, qlog rotation, or deterministic CIDs, drive
`Server.feed`, `server.drainStatelessResponse`, `slot.conn.pollDatagram`,
and `slot.conn.tick` directly. See [EMBEDDING.md](EMBEDDING.md) for the
full event-loop shape.

## Client Quick Start

`Client.connect` builds a client-mode TLS context, creates the first
DCID/SCID pair, wires transport parameters, and returns a ready
`*Connection`.

```zig
const std = @import("std");
const quic_zig = @import("quic_zig");

pub fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    server_name: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"hq-interop"};

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

`runUdpClient` owns the UDP socket and the receive/poll/tick loop.
Application code still drives streams, DATAGRAMs, and events through
`client.conn`. Embedders that want a single-threaded application loop can
use the raw `Connection` cycle described in [EMBEDDING.md](EMBEDDING.md).

`Client.connect` verifies the server certificate against the system
trust store by default. To talk to a server with a self-signed or
otherwise untrusted certificate (test and interop setups), set
`insecure_skip_verify = true` — this disables impersonation protection,
so never enable it against untrusted networks. Pinning a private CA for
a wrapper-built context is not yet supplied; build your own
`tls_context_override` for that (a non-null `ca_pem` is rejected rather
than silently ignored).

## Production Checklist

Before exposing a server to arbitrary peers:

- Build with `-Doptimize=ReleaseSafe`.
- Set ALPN, certificate chain, private key, stream limits, and
  connection memory budgets explicitly. The idle timeout defaults to a
  safe 30s on the server when left unset (`allow_no_idle_timeout` opts
  out); set it explicitly to match your deployment.
- The per-source Initial-flood limiter is on by default (32/window) and
  Version Negotiation flood limiting is on; tune the datagram, byte-rate,
  and logging limits for your deployment. Set the per-source Initial cap
  to `null` only behind a trusted front-end that polices source rate.
- Use `retry_token_key` and `new_token_key` when clients should prove
  source address ownership before allocation.
- Persist `stateless_reset_key`, Retry token keys, and NEW_TOKEN keys
  across graceful restarts when those features are enabled.
- Keep 0-RTT off unless `tls.AntiReplayTracker` is wired and the
  application rejects non-idempotent early requests.
- Use `Connection.setMigrationCallback` if peer migration needs
  application-level allowlisting.
- Enable packet-level qlog events with
  `Connection.setQlogPacketEvents(true)` when packet sent/received
  telemetry is needed.

The detailed configuration guide is [EMBEDDING.md](EMBEDDING.md).

## Usage Docs

- [EMBEDDING.md](EMBEDDING.md): server, client, raw `Connection`, and
  production configuration.
- [docs/API_STABILITY.md](docs/API_STABILITY.md): which surfaces are
  stable vs evolving vs internal, the `ConnectionEvent` forward-compat
  contract, and the per-draft extension policy (Track-to-RFC vs
  Experimental) with its sunset mechanics.
- [interop/README.md](interop/README.md): QUIC interop-runner endpoint
  and wrapper commands.
- [tests/conformance/README.md](tests/conformance/README.md):
  RFC-traceable conformance test style and filters.
- [bench/README.md](bench/README.md): microbenchmark scope and command.
- [CONTRIBUTING.md](CONTRIBUTING.md): local workflow and contribution
  expectations.

## Current Boundaries

- No HTTP/3, QPACK, WebTransport, or MASQUE implementation in this
  package.
- No FIPS validation.
- Windows is a **tier-1 target for 1.0** but not yet a hard CI gate: it
  runs advisory (non-blocking) in CI today. See
  [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md) for the platform
  tiers and the graduation checklist that flips it to blocking.
- BBR and large-scale performance tuning remain future work.

## License

See [LICENSE](LICENSE).
