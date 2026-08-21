# Error Reference

One page for the errors a quic-zig embedder actually meets, what each
means, and the typical cause. The authoritative definitions live in
`src/Connection.zig` (`Connection.Error`), `src/Server.zig`
(`Server.Error`), and `src/transport/udp_server.zig`
(`transport.RunError`); per-function doc comments carry the precise
contract. The error sets are additive-only across minor releases
(API_STABILITY.md) — always leave an `else` arm.

## Application-stream misuse (your code, not the peer)

| Error | Meaning | Typical cause |
|---|---|---|
| `StreamNotWritable` | Send-side op on a stream with no send half here. | `streamWrite` / `streamFinish` / `streamReset` on a peer-initiated unidirectional stream. The call fails instead of silently black-holing the bytes into a send half the scheduler never transmits. |
| `StreamNotReadable` | Read on a stream with no receive half here. | `streamRead` / `streamReadFin` on a locally-initiated unidirectional stream. The call fails instead of returning 0 forever ("nothing readable right now") on a half that can never produce bytes. |
| `InvalidStreamId` | The id cannot name a stream this endpoint may open. | Manual `openBidi`/`openUni` with wrong low bits or direction; use `openNextBidi` / `openNextUni`. |
| `StreamAlreadyOpen` | Open for an id that is already live. | Re-opening after `peekNext*`; track your opens. |
| `StreamNotFound` | The id is not in the live stream table. | Normal completion signal: the stream reached terminal and the GC reaped it. Also genuinely-unknown ids. |
| `StreamLimitExceeded` | Peer's MAX_STREAMS window is full. | Retryable; the id is not consumed. |
| `ShuttingDown` | Local graceful shutdown refuses new streams. | After `beginGracefulShutdown`. |
| `StreamClosed` (SendStream) | Wrote after FIN or RESET on that stream. | App-side sequencing bug. |

## Backpressure and capacity (retry later, never fatal)

| Error | Meaning | Typical cause |
|---|---|---|
| `DatagramTooLarge` | Payload exceeds `maxDatagramPayload()` right now. | Shrink the payload; the limit tracks PMTU + the peer's `max_datagram_frame_size`. |
| `DatagramUnavailable` | Peer did not enable RFC 9221 DATAGRAM. | Advertise `max_datagram_frame_size` or stop sending datagrams. |
| `DatagramQueueFull` | Outbound DATAGRAM queue at capacity. | Retry on a later iteration; QUIC never retransmits DATAGRAM frames. |
| `ExcessiveLoad` | An allocation would exceed `max_connection_memory`. | Peer-driven buffer pressure; the handler closes with `excessive_load`. |
| `InboxOverflow` | The fixed-size CRYPTO reorder inbox is full. | Oversized (>16 KiB) handshake flight; usually a broken or hostile peer. |

## Transport / peer-induced (usually means the connection is closing)

`HandshakeFailed`, `PeerAlerted`, `UnsupportedCipherSuite`,
`PnSpaceExhausted`, and the frame-decode family (`FinalSizeChanged`,
`BeyondFinalSize`, `BufferLimitExceeded`) indicate the peer sent
something the protocol layer refused; the connection is closed or
about to be — observe `ConnectionEvent.close` for the sticky
`CloseEvent` and stop issuing work for that connection.

## Migration (`Connection.beginClientActiveMigration`)

| Error | Meaning |
|---|---|
| `MigrationPreHandshake` | Called before the handshake confirmed; retry after `handshake_established`. |
| `MigrationValidationPending` | A path validation is already in flight. |
| `MigrationNoFreshPeerCid` | No unused peer CID to rotate to; retry after the peer issues one. |

## Server configuration (`Server.init` → `InvalidConfig`)

Every cross-field misconfiguration — empty ALPN/certs, cid length
bounds, zero-valued rate limits, `preferred_address` without
`stateless_reset_key`, QUIC-LB field violations, unsupported versions
— collapses to `InvalidConfig`. See `Server/Config.zig` field docs for
the full rule list. `RandFailed` covers CSPRNG exhaustion at init.

Not a fatal misconfiguration but close: a `config_warning` log event
at init means `transport_params` admit no streams, bytes, or
datagrams — see `Server.Config.defaultTransportParams()`.

## The bundled loops (`transport.RunError`)

`InvalidListenAddress`, `InvalidBufferSize`, `SocketTuningFailed`,
`WindowsBundledLoopUnsupported` (native Windows has no
`std.Io` overlapped UDP receive; drive the caller-drives path there),
plus socket-level failures from bind/send. `runUdpServer` returns
`anyerror!void` only because `on_iteration` hook errors propagate
verbatim — an error from your application code is the supported way
to stop the loop.
