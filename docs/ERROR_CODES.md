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
| `StreamNotReadable` | Read on a stream with no receive half here. | `streamRead` / `streamReadFin` on a locally-initiated unidirectional stream. The call fails instead of returning 0 forever ("nothing readable right now") on a half that can never produce bytes. Also `streamStopSending` on such a stream: the peer has no sending half to stop, and the frame would be a STREAM_STATE_ERROR on its side, so none is sent. |
| `InvalidStreamId` | The id cannot name a stream this endpoint may open. | Manual `openBidi`/`openUni` with wrong low bits or direction; use `openNextBidi` / `openNextUni`. |
| `StreamAlreadyOpen` | Open for an id that is live, or that was used before. | Re-opening after `peekNext*`; track your opens. A stream id is used once: an id whose stream finished and was reaped is not free again (RFC 9000 §2.1), for `openBidi` and `openUni` alike. |
| `TooManySkippedStreamIds` | `openBidi(id)` / `openUni(id)` named an id too far out of order. | Each run of lower ids you skip is remembered until you open it; the connection keeps at most `Connection.max_local_skipped_stream_ranges` (64) runs. Not a retry-later error: open the ids you skipped, or open in order with `openNextBidi` / `openNextUni`, which never skip. |
| `StreamNotFound` | The id is not in the live stream table. | Normal completion signal: the stream reached terminal and the GC reaped it. Also genuinely-unknown ids. `streamStopSending` returns it for a stream the peer has not opened or that is already closed (no frame is sent for either). |
| `StreamLimitExceeded` | Peer's MAX_STREAMS window is full. | Always temporary, and the id is not consumed: try again when the peer has raised its limit, which it does as your streams close on its side (EMBEDDING.md, "Stream limits are a window"). There is no lifetime cap (0.23.0 and earlier stopped for good at 4096 streams of each type). |
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
