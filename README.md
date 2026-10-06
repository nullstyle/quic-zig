# quic-zig

quic-zig is a Zig-first QUIC transport library. It implements the core
IETF QUIC stack around RFC 8999, RFC 9000, RFC 9001, and RFC 9002, with
TLS 1.3 and packet protection provided by
[`boringssl-zig`](https://github.com/nullstyle/boringssl-zig).

The project is pre-1.0. It is suitable for experiments, embedding work,
interop testing, and implementation research. Treat public APIs as
subject to change until a 1.0 release, and do not expose it to untrusted
internet traffic without working through the production checklist below
and the configuration guide in [EMBEDDING.md](EMBEDDING.md).

## What It Includes

- QUIC v1 connection state, packet protection, streams, DATAGRAM,
  loss recovery, BBRv3 congestion control (draft-ietf-ccwg-bbr-06;
  CUBIC and NewReno selectable) with RFC 9002 packet pacing, ECN,
  and DPLPMTUD.
- High-level `Server` and `Client` wrappers for embedders that want
  quic-zig to own TLS context setup and connection state.
- An opt-in application layer (`quic.app`) for connection and server builders:
  typed callbacks over the polled event/stream surface, per-stream
  tracking, short-write staging, and reordering-safe end-of-stream
  detection — plus `quic.testing`, an in-memory loopback harness
  shipped for embedder integration tests.
- Basic `std.Io` loop helpers in `quic.transport.runUdpServer`
  and `quic.transport.runUdpClient`, allowing integrators to avoid
  rolling their own UDP loop.
- Stateless Retry, NEW_TOKEN, stateless reset token helpers, versioned
  0-RTT resumption state with anti-replay persistence hooks,
  qlog-style callbacks, and key logging support.
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
zig build -Drelease
```

`ReleaseFast` and `ReleaseSmall` are intentionally not supported for the
network-input parser surface because Zig removes runtime safety checks in
those modes.

## Importing

The public Zig module name is `quic`.

### Consuming this package

Fetch a tagged release into your `build.zig.zon` — substitute the
current tag (`v0.28.1` as of this writing):

```sh
zig fetch --save https://github.com/nullstyle/quic-zig/archive/refs/tags/v0.28.1.tar.gz
```

Pin the **archive tarball URL** as above; it is the form every release
is verified with. On Zig 0.17.0 a `git+https://…#v0.28.1` reference
resolves to the same package hash. (On the 0.17.0-dev builds it did
not: release tags here are annotated tag objects, and those builds
gave them a different, unnamed `N-V` fingerprint.)

One Zig 0.17.0 field note. A standalone `zig fetch <url>` — without
`--save` — rewrites the package's entry in the global cache in a form
that a later `zig build` rejects with an unrelated-looking `N-V` hash
mismatch; `zig fetch --save` and `zig build --fetch` do not. If you
see that mismatch despite the correct URL and hash, delete the
package's `<hash>.tar.gz` from the `p/` directory of the Zig global
cache and build again.

Then wire the module in `build.zig`:

```zig
const quic_dep = b.dependency("quic", .{
    .target = target,
    .release = optimize != .debug,
});
exe.root_module.addImport("quic", quic_dep.module("quic"));
```

quic-zig has two build modes, Debug and ReleaseSafe. It refuses
ReleaseFast and ReleaseSmall: they remove the safety checks on the
code that parses network input. `.release = optimize != .debug` gives
it ReleaseSafe inside an application built in any release mode, and
works with every release of quic-zig.

From 0.24.1 the usual `.optimize = optimize` works too, for Debug and
ReleaseSafe (ReleaseFast and ReleaseSmall stop the build with a message
that says what to pass). **Through 0.24.0 it did not work, and this
page said to use it.** The package had no `optimize` option, so the
build printed `error: invalid option: "optimize"` and went on, and
quic-zig and its BoringSSL were compiled in **Debug** inside a release
build of the application. If you pin 0.24.0 or older, pass `release`.

To check what you get, run `zig build --verbose` and read the `-O`
flag in front of `-Mquic=`. When several packages in one build depend
on quic-zig, each must pass the same options with the same values, or
the build makes two `quic` modules whose types do not match.

Application code imports it as:

```zig
const quic = @import("quic");
```

quic-zig also exports its shared BoringSSL module instance as
`dep.module("boringssl")` — import it when you need to construct a
`boringssl.tls.Context` that type-unifies with quic's API, e.g.
for `Client.Config.tls_context_override` (custom session-ticket
capture, keylog wiring, or any posture the PEM config fields don't
express — private-CA pinning and mTLS themselves need only
`ca_pem` / `client_cert_pem` / `client_ca_pem`, no BoringSSL types).

**Toolchain**: quic-zig requires the tagged Zig `0.17.0` release.
[`mise.toml`](https://github.com/nullstyle/quic-zig/blob/main/mise.toml)
is the source of truth for the verified toolchain, and
`minimum_zig_version` in `build.zig.zon` records the same version as
the floor — `0.17.0-dev` master builds are below it and are refused
with a clear message. On macOS, run `zig` commands with `COPYFILE_DISABLE=1` in
the environment so AppleDouble (`._*`) metadata files stay out of
archives and cache hashes.

## Server Quick Start

`Server` owns TLS context setup and the connection table. The embedder
still owns application policy, shutdown, and any per-stream work.

```zig
const std = @import("std");
const quic = @import("quic");

pub fn runServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_pem: []const u8,
    key_pem: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"hq-interop"};

    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = cert_pem,
        .tls_key_pem = key_pem,
        .alpn_protocols = &protos,
        // The blessed working set — all flow-control / stream-count
        // knobs nonzero. (`.{}` compiles but admits no streams.)
        .transport_params = quic.Server.Config.defaultTransportParams(),
    });
    defer server.deinit();

    try quic.transport.runUdpServer(&server, .{
        .listen = "0.0.0.0:4433",
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

Application logic — accepting connections, tracking streams,
echoing or answering — belongs to `quic.app.Driver(App)`: typed
callbacks (`onStreamData`, `onStreamEnd`, `onDatagram`, ...) wired
into the loop's `on_iteration` hook, with short-write staging and
sound end-of-stream handling owned for you. The examples below are
built on it; EMBEDDING.md's "Writing Your Application Layer" is the
guide. For custom socket ownership, Retry or Version Negotiation
policy, batched I/O, qlog rotation, or deterministic CIDs, drive
`Server.feed`, `server.drainStatelessResponse`, `slot.conn.pollDatagram`,
and `slot.conn.tick` directly. See [EMBEDDING.md](EMBEDDING.md) for the
full event-loop shape.

## Client Quick Start

`Client.connect` builds a client-mode TLS context, creates the first
DCID/SCID pair, wires transport parameters, and returns a ready
`*Connection`.

```zig
const std = @import("std");
const quic = @import("quic");

pub fn runClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    server_name: []const u8,
    shutdown: *const std.atomic.Value(bool),
) !void {
    const protos = [_][]const u8{"hq-interop"};

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = server_name,
        .alpn_protocols = &protos,
        // The blessed working set — nonzero flow-control / stream
        // windows so the client can receive the server's response.
        // (`.{}` compiles but advertises a zero receive window.)
        .transport_params = quic.Client.Config.defaultTransportParams(),
    });
    defer client.deinit();

    try quic.transport.runUdpClient(&client, .{
        .target = target,
        .io = io,
        .shutdown_flag = shutdown,
    });
}
```

`runUdpClient` owns the UDP socket and the receive/poll/tick loop.
Application code still drives streams, DATAGRAMs, and events through
`client.conn` — serialized with the loop, since `Connection` is
single-threaded. The application-data path in miniature:

```zig
const stream = try client.conn.openNextBidi();
_ = try client.conn.streamWrite(stream.id, "GET /index.html\r\n");
try client.conn.streamFinish(stream.id); // send FIN
// ... later, as response data arrives:
var buf: [4096]u8 = undefined;
const r = try client.conn.streamReadFin(stream.id, &buf);
// r.n bytes of payload in buf; r.fin is true once the peer's FIN is seen.
```

Embedders that want a single-threaded application loop can
use the raw `Connection` cycle described in [EMBEDDING.md](EMBEDDING.md).

`Client.connect` verifies the server certificate against the system
trust store by default. To pin a private CA, pass the PEM bundle as
`ca_pem` — the client then trusts exactly those roots. For mTLS, set
`client_cert_pem` / `client_key_pem` on the client and
`Server.Config.client_ca_pem` on the server. To talk to a server with
a self-signed or otherwise untrusted certificate (test and interop
setups), set `insecure_skip_verify = true` — this disables
impersonation protection, so never enable it against untrusted
networks.

## Production Checklist

Before exposing a server to arbitrary peers:

- Build with `-Drelease` (resolves to ReleaseSafe — build.zig sets
  it as the preferred release mode and rejects fast/small outright).
- Set ALPN, certificate chain, private key, stream limits, and
  connection memory budgets explicitly. The idle timeout defaults to a
  safe 30s on the server when left unset (`allow_no_idle_timeout` opts
  out); set it explicitly to match your deployment.
- The per-source Initial-flood limiter is on by default (32/window) and
  Version Negotiation flood limiting is on; tune the datagram, byte-rate,
  and logging limits for your deployment. Set
  `.initial_source_rate_limit = .disabled` (and
  `.vn_source_rate_limit = .disabled`) only behind a trusted front-end
  that polices source rate — the three-state `RateLimit` union makes
  the dangerous "unset" state unspellable.
- Use `retry_token_key` and `new_token_key` when clients should prove
  source address ownership before allocation.
- Set `stateless_reset_key` on any deployed server. It gates the whole
  RFC 9000 §10.3 mechanism — emission, the §18.2 token peers need to
  *detect* a reset (without it, clients of a crashed server idle out
  instead of failing fast), spare-CID replenishment, and migration.
  See its `Server.Config` docstring for the full list.
- Persist `stateless_reset_key`, Retry token keys, and NEW_TOKEN keys
  across graceful restarts when those features are enabled. A forgotten
  reset key invalidates every token it ever issued, which defeats
  precisely the crash-restart detection the key exists for.
- Keep 0-RTT off unless `tls.AntiReplayTracker` is wired, its versioned
  state is persisted across restarts, and the application rejects
  non-idempotent early requests. Persist client resumption via
  `tls.resumption_state`; raw BoringSSL session-ticket bytes are not a
  supported quic-zig state format.
- Use `Connection.setMigrationCallback` if peer migration needs
  application-level allowlisting.
- Enable packet-level qlog events with
  `Connection.setQlogPacketEvents(true)` when packet sent/received
  telemetry is needed.

The detailed configuration guide is [EMBEDDING.md](EMBEDDING.md).

## Usage Docs

The published package archive ships this file, `EMBEDDING.md`,
`docs/`, and `examples/` — links into those are relative. Links into
`interop/`, `tests/`, and `bench/` are absolute because those trees
live only in the git repository.

- [EMBEDDING.md](EMBEDDING.md): server, client, application layer
  (`quic.app`), raw `Connection`, and production configuration.
- [docs/ERROR_CODES.md](docs/ERROR_CODES.md): what each error means
  and its typical cause.
- [docs/API_STABILITY.md](docs/API_STABILITY.md):
  which surfaces are stable vs evolving vs internal, the
  `ConnectionEvent` forward-compat contract, and the per-draft
  extension policy (Track-to-RFC vs Experimental) with its sunset
  mechanics.
- [interop/README.md](https://github.com/nullstyle/quic-zig/blob/main/interop/README.md):
  QUIC interop-runner endpoint and wrapper commands.
- [tests/conformance/README.md](https://github.com/nullstyle/quic-zig/blob/main/tests/conformance/README.md):
  RFC-traceable conformance test style and filters.
- [bench/README.md](https://github.com/nullstyle/quic-zig/blob/main/bench/README.md):
  microbenchmark scope and command.
- [examples/foreign_loop_embedder.zig](examples/foreign_loop_embedder.zig):
  worked integration of the caller-drives (no-I/O) path into a
  hand-rolled `poll` reactor — the supported shape when your runtime
  already owns the wait.
- [CONTRIBUTING.md](CONTRIBUTING.md): local workflow and contribution
  expectations.

## Current Boundaries

- No HTTP/3, QPACK, WebTransport, or MASQUE implementation in this
  package.
- No FIPS validation.
- Windows is a **tier-1 CI gate for 1.0**: `windows-latest` is blocking on
  every push / PR. See
  [docs/RELEASE_READINESS.md](docs/RELEASE_READINESS.md)
  for the platform tiers and graduation checklist.
- BBRv3 congestion control (draft-ietf-ccwg-bbr-06) is the default as
  of 0.16.0, gated on the in-tree multi-flow fairness cells;
  `congestion_control = .cubic` is the one-line rollback. The interop
  battery cited for that change had not run in CI; the first real
  cross-implementation matrix ran on 2026-10-03 (see the CHANGELOG).
  Large-scale performance tuning remains future work.

## License

See [LICENSE](LICENSE).
