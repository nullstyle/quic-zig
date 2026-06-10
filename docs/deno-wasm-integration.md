# Deno WASM UDP Integration

Design status: proposal.

Last checked against the Deno API docs on 2026-05-11. `Deno.listenDatagram`
is currently marked unstable and requires the unstable net flag plus network
permission for UDP use.

## Goal

Expose quic-zig to Deno as a freestanding WebAssembly module while Deno owns
all native UDP socket work through `Deno.listenDatagram`.

The boundary should be:

- Deno opens, receives from, sends on, and closes UDP sockets.
- WebAssembly owns QUIC endpoint state, TLS state, timers, streams, DATAGRAM
  queues, connection IDs, retry tokens, loss recovery, and packet protection.
- The TypeScript host is a pump: copy an inbound UDP payload and source address
  into wasm, call one export, drain outbound QUIC datagrams, then sleep until
  either UDP input or the next quic-zig timer.

This avoids WASI sockets, native Deno plugins, and JS callbacks from the QUIC
core. Deno remains the capability boundary; quic-zig remains transport
agnostic.

## Deno UDP Surface

The required Deno API is small:

- `Deno.listenDatagram({ transport: "udp", hostname, port, reuseAddress })`
  returns a `Deno.DatagramConn`.
- `DatagramConn.receive(p?)` resolves to `[Uint8Array, Deno.Addr]`.
- `DatagramConn.send(p, addr)` sends a UDP payload to a `Deno.Addr`.
- `DatagramConn.addr` reports the local address.
- `DatagramConn.close()` closes the socket and rejects pending receives.
- UDP peer addresses use `Deno.NetAddr`: `{ transport: "udp", hostname, port }`.

Run commands need `--unstable-net` and `--allow-net` or `-N`.

## quic-zig Surfaces To Reuse

The current library already has the right embedder hooks:

- Server side:
  - `Server.feed` / `Server.feedWithEcn`
  - `Server.drainStatelessResponse`
  - `Server.iterator`
  - `slot.conn.pollDatagram`
  - `Server.tick`
  - `Server.reap`
  - `Server.metricsSnapshot`
- Client side:
  - `Client.connect`
  - `client.conn.handle` / `handleWithEcn`
  - `client.conn.pollDatagram`
  - `client.conn.tick`
  - `client.conn.nextTimerDeadline`
  - `client.conn.pollEvent`
- Application I/O:
  - `Connection.streamWrite`, `streamRead`, `streamFinish`, `streamReset`
  - `Connection.sendDatagram`, `receiveDatagramInfo`
  - `Connection.pollEvent`

No quic-zig socket abstraction should be ported into wasm for the first
integration. The wasm adapter should sit above these I/O-agnostic APIs.

## Architecture

```text
+----------------------------------------------------------------+
| Deno TypeScript                                                |
|                                                                |
|  Deno.listenDatagram -- receive/send -- native UDP socket       |
|          |                                                     |
|          | binary payload + NetAddr                            |
|          v                                                     |
|  QuicEndpointHost:                                             |
|    - address encode/decode                                     |
|    - monotonic clock                                           |
|    - wasm memory view refresh                                  |
|    - UDP receive/timer race                                    |
|    - bounded send drain                                        |
+----------+-----------------------------------------------------+
           | wasm C ABI exports
+----------v-----------------------------------------------------+
| quic-zig-deno.wasm                                             |
|                                                                |
|  adapter/deno_wasm.zig                                         |
|    - handle table                                              |
|    - config decode                                             |
|    - Deno address struct <-> quic_zig.conn.path.Address         |
|    - server/client entrypoints                                 |
|                                                                |
|  quic_zig.Server / quic_zig.Client / quic_zig.Connection        |
|  boringssl-zig TLS and packet protection                       |
+----------------------------------------------------------------+
```

## WASM Build Shape

Add a separate adapter root rather than changing `src/root.zig`:

- `src/deno_wasm/root.zig`: exported ABI and handle table.
- `src/deno_wasm/address.zig`: compact binary address codec.
- `src/deno_wasm/config.zig`: versioned config decoder.
- `src/deno_wasm/errors.zig`: stable integer error/status mapping.
- `deno/mod.ts`: host wrapper around the wasm ABI.

Build target:

- `wasm32-freestanding`
- `ReleaseSafe`
- no WASI socket imports
- exported memory
- no `_start`; instantiate as a library module

Keep quic-zig's existing production policy: do not ship network-input builds
with `ReleaseFast` or `ReleaseSmall`.

### TLS/Crypto Build Blocker

The major non-UDP blocker is `boringssl-zig`. Today it is verified for macOS
and linux-musl native targets, uses C/C++ translation, links libc/libc++, and
wraps BoringSSL's RNG/TLS APIs. A true `wasm32-freestanding` artifact needs an
explicit BoringSSL wasm port plan:

1. Prove `boringssl-zig` can compile `libcrypto` and `libssl` for
   `wasm32-freestanding` without accidental host syscalls.
2. Provide entropy through a small host import backed by
   `crypto.getRandomValues`, then route BoringSSL RAND and quic-zig token
   generation through it.
3. Route BoringSSL allocation to wasm-local allocation. Deno should never own
   BoringSSL pointers.
4. Disable or stub file, fd, and certificate-store behavior that cannot exist
   in freestanding wasm. Certificates and keys enter as config bytes.
5. Keep the existing BoringSSL QUIC method bridge inside wasm, so Deno never
   sees TLS handshake internals.

If this is too large for the first milestone, a temporary `wasm32-wasi` proof
can validate the UDP pump and ABI, but that is not the final freestanding
design.

## ABI

Use a stable C-like ABI with integer handles. Do not expose Zig pointers as
durable JS objects. JS may hold numeric handles; wasm owns the pointed-to state.

All pointer/length pairs refer to wasm linear memory. All times are monotonic
microseconds as unsigned 64-bit values; JS passes them as `BigInt`.

### Common Exports

```c
uint32_t qzd_abi_version(void);
uint32_t qzd_alloc(uint32_t len, uint32_t align);
void     qzd_free(uint32_t ptr, uint32_t len, uint32_t align);
uint32_t qzd_last_error(uint32_t out_ptr, uint32_t out_cap);
```

`qzd_last_error` writes a short diagnostic string for development. Program
logic should use status codes, not parse this string.

### Address ABI

Use a fixed little-endian struct. TypeScript converts between this and
`Deno.NetAddr`.

```c
struct QzdAddr {
  uint8_t  family;      // 4 or 6
  uint8_t  reserved0;
  uint16_t port;        // host endian in wasm memory; TS DataView reads LE
  uint8_t  ip[16];      // IPv4 uses first 4 bytes, rest zero
  uint32_t scope_id;    // initially 0; reserved for future IPv6 zones
};
```

Deno's UDP address only exposes `hostname` and `port`, so the initial adapter
should accept numeric IPv4/IPv6 host strings and reject unresolved names at the
wasm boundary. DNS belongs in the TypeScript host before calling client
construction.

### Packet ABI

```c
struct QzdPacketMeta {
  QzdAddr  addr;
  uint32_t path_id;
  uint32_t conn_id;
  uint32_t flags;
};
```

`flags` starts with:

- `1 << 0`: stateless response
- `1 << 1`: connection-scoped response
- `1 << 2`: has explicit destination address

### Server Exports

```c
uint32_t qzd_server_new(uint32_t config_ptr, uint32_t config_len);
void     qzd_server_free(uint32_t server);

uint32_t qzd_server_recv(
  uint32_t server,
  uint32_t packet_ptr,
  uint32_t packet_len,
  uint32_t addr_ptr,
  uint64_t now_us
);

int32_t qzd_server_next_packet(
  uint32_t server,
  uint32_t out_ptr,
  uint32_t out_cap,
  uint32_t meta_ptr,
  uint64_t now_us
);

uint32_t qzd_server_tick(uint32_t server, uint64_t now_us);
uint64_t qzd_server_next_deadline(uint32_t server, uint64_t now_us);
uint32_t qzd_server_reap(uint32_t server);
uint32_t qzd_server_next_event(uint32_t server, uint32_t out_ptr, uint32_t out_cap);
```

`qzd_server_next_packet` drains in this order:

1. `Server.drainStatelessResponse`
2. per-slot `slot.conn.pollDatagram`

For per-slot packets, destination selection is:

1. `OutgoingDatagram.to`, when present
2. `slot.peer_addr`, as maintained by `Server.feed`
3. no packet if neither address is available

Return values:

- positive: byte length written into `out_ptr`
- `0`: no packet available
- negative: stable error code

`qzd_server_next_deadline` iterates every live slot and returns the minimum
`conn.nextTimerDeadline(now_us).at_us`, or `0` when no timer is armed.

### Client Exports

```c
uint32_t qzd_client_new(uint32_t config_ptr, uint32_t config_len);
void     qzd_client_free(uint32_t client);

uint32_t qzd_client_recv(
  uint32_t client,
  uint32_t packet_ptr,
  uint32_t packet_len,
  uint32_t addr_ptr,
  uint64_t now_us
);

int32_t qzd_client_next_packet(
  uint32_t client,
  uint32_t out_ptr,
  uint32_t out_cap,
  uint32_t meta_ptr,
  uint64_t now_us
);

uint32_t qzd_client_tick(uint32_t client, uint64_t now_us);
uint64_t qzd_client_next_deadline(uint32_t client, uint64_t now_us);
uint32_t qzd_client_next_event(uint32_t client, uint32_t out_ptr, uint32_t out_cap);
```

The client config includes a required remote `QzdAddr`. `qzd_client_next_packet`
uses `OutgoingDatagram.to` when present, otherwise the configured remote.

### Application I/O Exports

Start narrow. Add stream lifecycle richness only after handshake and packet I/O
are proven.

```c
int64_t  qzd_conn_open_bidi(uint32_t endpoint, uint32_t conn_id);
int32_t  qzd_conn_stream_write(uint32_t endpoint, uint32_t conn_id, uint64_t stream_id,
                               uint32_t ptr, uint32_t len);
int32_t  qzd_conn_stream_read(uint32_t endpoint, uint32_t conn_id, uint64_t stream_id,
                              uint32_t out_ptr, uint32_t out_cap);
uint32_t qzd_conn_stream_finish(uint32_t endpoint, uint32_t conn_id, uint64_t stream_id);

int32_t  qzd_conn_send_datagram(uint32_t endpoint, uint32_t conn_id,
                                uint32_t ptr, uint32_t len);
int32_t  qzd_conn_recv_datagram(uint32_t endpoint, uint32_t conn_id,
                                uint32_t out_ptr, uint32_t out_cap,
                                uint32_t info_ptr);
```

For the server, `conn_id` is the adapter's stable slot handle, not a QUIC
connection ID. Events tell the host when a new connection is accepted and which
slot handle to use.

## TypeScript Pump

The host wrapper should be single-threaded per endpoint. Avoid re-entrant wasm
calls for the same server/client handle.

```ts
const socket = Deno.listenDatagram({
  transport: "udp",
  hostname: "0.0.0.0",
  port: 4433,
  reuseAddress: true,
});

while (!closed) {
  drainOutgoing();

  const deadline = wasm.serverNextDeadline(server, nowUs());
  const rxView = memoryView(rxPtr, rxCap); // recreate after every export
  const receive = socket.receive(rxView).then(([data, addr]) => ({
    kind: "rx" as const,
    len: data.byteLength,
    addr,
  }));
  const timer = sleepUntil(deadline).then(() => ({ kind: "timer" as const }));

  const event = await Promise.race([receive, timer]);
  const now = nowUs();

  if (event.kind === "rx") {
    writeQzdAddr(addrPtr, event.addr);
    wasm.serverRecv(server, rxPtr, event.len, addrPtr, now);
  }

  wasm.serverTick(server, now);
  drainEvents();
  drainOutgoing();
  wasm.serverReap(server);
}
```

Important host rules:

- Recreate `Uint8Array(memory.buffer, ptr, len)` after each wasm export because
  memory growth can replace the backing buffer.
- It is acceptable to receive directly into wasm memory, but do not keep the
  returned `data` view after calling back into wasm.
- Copy outbound bytes before awaiting `DatagramConn.send`, because the same
  wasm TX buffer will be reused.
- Send sequentially per endpoint unless and until packet batching is designed.
  This keeps packet order unsurprising.
- Cap work per loop, for example drain at most 64 outbound packets before
  returning to receive/timer wait, so one busy connection does not starve input.

## Config Format

Do not use raw Zig structs as the public config format. Use a small versioned
binary format or JSON copied into wasm and parsed by the adapter.

For MVP, JSON is acceptable because endpoint construction is cold path:

```json
{
  "role": "server",
  "alpn": ["h3"],
  "certPem": "...",
  "keyPem": "...",
  "transportParams": {
    "maxIdleTimeoutMs": 30000,
    "initialMaxData": 16777216,
    "initialMaxStreamDataBidiLocal": 1048576,
    "initialMaxStreamDataBidiRemote": 1048576,
    "initialMaxStreamDataUni": 1048576,
    "initialMaxStreamsBidi": 1000,
    "initialMaxStreamsUni": 64,
    "activeConnectionIdLimit": 4,
    "maxDatagramFrameSize": 1200
  },
  "limits": {
    "maxConcurrentConnections": 10000,
    "maxConnectionMemory": 16777216,
    "maxInitialsPerSourcePerWindow": 32
  }
}
```

Later, replace JSON with a binary config once the option set settles.

## ECN And Socket Options

Deno's `DatagramConn` API exposes payload and address, not IP control messages.
Therefore the MVP calls `feed`/`handle`, not `feedWithEcn`/`handleWithEcn`, and
outbound ECN marking is unavailable.

Socket buffer tuning from `quic_zig.transport.socket_opts` also stays native
only. Deno's public UDP API does not expose `SO_RCVBUF`, `SO_SNDBUF`, GSO,
`recvmmsg`, or cmsg parsing. If those become necessary, add optional native
Deno capabilities in the host wrapper rather than expanding the wasm ABI first.

## Error And Event Model

Every export returns either a non-negative success value or a stable negative
error code. The adapter stores the last diagnostic string for developer logs.

Connection and server events should be serialized as compact tagged records:

- connection accepted
- connection closed
- flow blocked
- connection IDs needed
- DATAGRAM acked/lost
- stream readable
- stream writable
- incoming DATAGRAM available
- metrics snapshot requested

The host should surface these as async iterables or callbacks, but the wasm side
should remain polling-based.

## Milestones

1. Adapter skeleton:
   - build a tiny `wasm32-freestanding` module that exports memory, alloc/free,
     address encode/decode tests, and status/error mapping.
2. Crypto feasibility:
   - compile `boringssl-zig` for wasm or document the required porting patches.
   - wire entropy import from Deno.
3. QUIC client MVP:
   - `qzd_client_new`, `recv`, `next_packet`, `tick`, `next_deadline`.
   - Deno host connects to a known QUIC peer over UDP.
4. QUIC server MVP:
   - `qzd_server_new`, `recv`, stateless response drain, slot packet drain,
     `tick`, `reap`.
   - loopback handshake against a native quic-zig or Go QUIC client.
5. Application data:
   - streams, FIN/reset, connection events.
   - RFC 9221 DATAGRAM send/receive.
6. Hardening:
   - memory ceilings surfaced in config.
   - bounded host send queue.
   - fuzz ABI decoders.
   - interop runner target using Deno as the UDP host.

## Open Questions

- Can `boringssl-zig` be made truly freestanding without a large fork, or should
  the project introduce a crypto/TLS provider seam before the Deno work lands?
- Should the Deno host expose one UDP socket per endpoint only, or also support
  preferred-address and future multipath sockets?
- Do we need DNS inside the host wrapper, or should all configs require numeric
  IP addresses after caller-side resolution?
- Should `Deno.QuicEndpoint` be used as a reference oracle in tests even though
  this integration deliberately uses UDP instead of Deno's QUIC stack?

## References

- Deno `listenDatagram`: https://docs.deno.com/api/deno/~/Deno.listenDatagram
- Deno `DatagramConn`: https://docs.deno.com/api/deno/~/Deno.DatagramConn
- Deno unstable net flag: https://docs.deno.com/runtime/reference/cli/unstable_flags/
- quic-zig embedding guide: ../EMBEDDING.md
