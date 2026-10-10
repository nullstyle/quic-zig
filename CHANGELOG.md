# Changelog

All notable changes to quic-zig are documented in this file.

The project is pre-1.0. Any 0.x release may include breaking API
changes.

## [0.40.0] - 2026-10-10

### Added

- `Server.init` and `Client.connect` emit `config_warning` when
  `initial_max_data` exceeds `max_connection_memory / 2`. The receive
  reserve reduces stream write capacity; a window at or above the full
  budget leaves zero write space. Raise the budget or lower the window.
  Client adds optional `Config.log_callback` and `log_user_data`, with
  `Client.LogEvent` and `Client.LogCallback` for configuration warnings.

### Fixed

- `Connection.isClosed` documentation now matches the code: true when
  CONNECTION_CLOSE is sent or received, including closing and draining.
  Use `closeState` to distinguish those states from terminal closure.

## [0.39.0] - 2026-10-09

The tail of the many-connections work (0.36.0), and its guards.

### Added

- `Connection.streamWriteCapacity(id)`: how many bytes the next
  `streamWrite` on that stream would take, computed as the write
  computes it (the send buffer's room, following the peer's credit up
  to the cap; the writer's share of the memory budget still free; the
  smaller). An embedder that frames its data (a header and a payload
  that must go out together) asks before a write that must not be cut.
  `SendWindow.writable` counts flow credit alone. Asked by http3-zig
  (a frame written as header + payload in two calls was cut mid-frame
  by a short write). Two tests.

### Changed

- `canSend` answers "a stream has something to send" from the sendable
  list (0.36.0) instead of walking every stream on every poll of a
  connection not at rest; the walk stays for a degraded list, and a
  Debug build checks the two agree. The churn cell with 3,750 live
  streams: 6.82 -> 5.73 us of poll per stream (-16%), the virtual-time
  results byte-identical.

### Guards (tests only)

- `tests/e2e/rest_cache_table.zig`: a client/server pair at rest with
  the rest cache primed, then one public call (19 of them: pings,
  stream writes, finishes, resets, priorities, a stop, the PMTU and
  congestion knobs, a datagram, a token, a path probe, a graceful
  shutdown, a close), then every reader of the cache on both sides: a
  call that forgot to drop the cache asserts. The two defects of
  2026-10-08 were missing touches.
- `Connection.residentBytesSum` against `bytes_resident` (the memory
  budget's charge equals the sum of the buffers it covers): held by
  the stream-window fuzz harness after every operation and by the
  budget tests. Green on the first run.
- The allocations per connection since 0.36.0, named (http3-zig
  measured +2 per side): one for the sendable list's first insert on
  every connection that sends stream data; the sent-packet tracker's
  growth from 16 slots on larger transfers (a `realloc` per doubling);
  the Server's ready list and timer heap, per server, paid by its
  first connection. Each kept: the shape the idle-memory win needs.

## [0.38.0] - 2026-10-09

### Changed

- The memory budget (`max_connection_memory`) keeps a receive reserve.
  One budget holds what the application writes (send buffers), what
  the peer sends (receive reassembly), CRYPTO and DATAGRAM queues.
  Since 0.33.0 `streamWrite` took what the budget left and returned
  short, but it could take ALL of it; then a STREAM byte from the peer,
  inside the window it was given, failed the budget and the connection
  closed with "excessive resource use" (`transport_error_excessive_load`),
  a fault the peer did not cause and the application never saw at its
  own write (found by capnp-zig: a 256 KiB budget, a 1 MiB reply, a
  client frame every millisecond, closed within 7 ms). Now:
  - `streamWrite` stops short of the receive side's share, the
    connection window (as announced, never below the window cap: half
    the budget by default), so a frame inside the window always has
    room. With the defaults the writes stop at 16 MiB of resident bytes
    instead of 32. A slow reader whose unread bytes sit in the budget
    leaves the writer less, until the application reads: a short write,
    not a fault. Announce a window larger than half the budget and the
    writer gets nothing; raise the budget with the window.
  - Under pressure the receive buffers give back the charge of their
    consumed prefixes (bytes the application read that the sliding
    window keeps until the prefix reaches half the buffer) before a
    frame or a DATAGRAM is refused. After that the receive side holds
    its unread bytes and nothing more, so with the writer at its share
    the sum fits the budget: an honest peer never meets the fault.
  - Nothing else changes: a DATAGRAM over the budget is still shed (RFC
    9221), CRYPTO over its 64 KiB caps still closes, the window cap
    stays half the budget.
  Three tests (capnp-zig's shape; a slow reader; the pressure with two
  streams); every bench cell measured. An embedder that capped its own
  writes at half the budget to work around this can stop.

## [0.37.2] - 2026-10-08

### Fixed

- A connection at rest reclaims its ended streams. Since 0.36.0 a
  connection at rest answered `tick` from its cached deadline, and
  `atRest` did not look at the stream table: a stream whose halves had
  ended (the ACK of our FIN; the peer's FIN or RESET_STREAM received;
  a stop) was work for the next `tick`, the one that reclaims it,
  gives its id back to the peer and records its end for
  `streamRecvEnd`, and that tick never ran. A Debug build asserted in
  `tick`'s self-check; a release build kept the stream until something
  else touched the connection, and a sender ran out of stream ids
  (found by capnp-zig on its move to v0.37.1: two transfers of 10,240
  frames over uni streams stopped at 10,185 and 10,177, both sides at
  rest; 19 of its 202 QUIC tests asserted in Debug). Now every
  transition that can end a stream marks the connection, the mark
  keeps it off rest, its timer is due at once (`TimerKind.stream_gc`,
  new) so a host on the ready API ticks it too, and the GC clears the
  mark. Two tests at the public wrappers (feed, drain, tick; a stopped
  stream). An embedder that touched every connection before every
  tick to work around this can stop.
- A server comes to rest. Its Handshake packet-number space kept a
  pending ACK after the keys were discarded (the server discards them
  the moment the client's Finished is processed, before any poll), and
  that flag made `canSend` true for the life of every server
  connection: since 0.36.0 no server connection ever used the rest
  cache. A key discard now drops the space's pending ACK (RFC 9001
  section 4.9: it could never be sent).
- With servers at rest, the Debug self-checks found four state changes
  that did not drop a cached rest deadline, so a release build would
  have answered "nothing to send" until the next datagram or timer:
  `requestPing` / `requestPathPing`, `setPmtudConfig` (a search with a
  probe to send), `setActivePath` / `setPathStatus` /
  `markPathValidated`, and the AEAD limits of the write keys (a key
  update or a close), which are now checked before the rest shortcut
  instead of inside the builder. Each touches now.

## [0.37.1] - 2026-10-08

The v0.37.0 tag's `test` gate was red on its `zig fmt --check` step
(`bench/loss_ack.zig`, a bench file, was not formatted; every test
passed on every job). This tag formats the file, and carries one fix
the tag's wide interop matrix found. The move goes to this tag.

### Fixed

- A probe timeout to a silent peer carries previously sent stream
  data every time. Since 0.30.0 a probe re-sends the frames of the
  oldest ack-eliciting packet in flight, and the packet stays in
  flight (RFC 9002 section 6.2.4). A stream chunk sent again moves to
  the copy's packet (the key goes with the copy), so the SECOND probe
  found the oldest packet's data gone and re-sent its control frames
  alone, or a PING; the copy's packet, never the oldest, was never
  probed. The probe now walks on to the oldest packet that still owns
  stream or CRYPTO data. Found in the handshake-corruption interop
  cell (a quic-zig client, a quic-go server, 30% of the bytes
  corrupted): the request's packet and the first probe's copy lost,
  every ACK the server sent corrupted, and one NEW_CONNECTION_ID went
  out per probe for 30 s, until the idle timeout. Any ACK that
  arrives ends it in either version (the thresholds find the loss);
  a peer silent through several probes is the case. One test.

## [0.37.0] - 2026-10-08

The protocol-polish release: an ACK frame describes every gap the
receiver knows, and the Acknowledgement Frequency extension is in.
Two changes on the wire, one new knob, two new calls, one new
transport-parameter field, the same option map. Verified toolchain:
0.17.0.

MEASURED (`impairment_reorder_gaps_1gbit_defaults`: 8 MiB on
1 Gbit/s, 20 ms RTT, 10% of the packets 20 ms late, nothing dropped;
12 seeds, median / min):

| | v0.36.0 | v0.37.0 |
| --- | --- | --- |
| cubic | 374 / 334 ms | 346 / 314 ms |
| bbr | 311 / 309 ms | 314 / 291 ms |
| the same transfer with nothing reordered | cubic 242, bbr 222 ms | the same |
| `impairment_reorder_gaps_1gbit` (4 MiB window, bbr) | 311 ms | 272 ms |
| `impairment_clean_1gbit_rtt20ms` (bbr) | 222 ms, 8,449 datagrams | 222 ms, 7,607 datagrams |
| `impairment_loss5pct` / `impairment_reorder10pct` (bbr) | 31 / 33 ms, 9,106 / 11,012 datagrams | 32 / 33 ms, 7,854 / 8,338 datagrams |

### Added

- **The Acknowledgement Frequency extension**
  (draft-ietf-quic-ack-frequency, the draft's provisional codepoints:
  ACK_FREQUENCY 0xaf, IMMEDIATE_ACK 0x1f, `min_ack_delay`
  0xff04de1b). A connection advertises `min_ack_delay` (1 ms unless
  `TransportParams.min_ack_delay_us` says otherwise; never above its
  max_ack_delay), honors a peer's ACK_FREQUENCY (the largest sequence
  number wins; the threshold, the delay and the reordering rule feed
  the ACK policy; a requested delay below our min_ack_delay is a
  PROTOCOL_VIOLATION; the frames only in 1-RTT) and IMMEDIATE_ACK (an
  acknowledgment at once). It asks a peer that advertised the
  parameter for fewer ACKs when its window is large
  (`ack_frequency_policy = .auto`, the default on `Client.Config`,
  `Server.Config` and `Connection`; `.off` never asks): one ACK per
  sixteenth of the window, 2 packets at least and 64 at most, again
  when that doubled or halved, once per round trip at most.
  `Connection.requestAckFrequency(threshold, max_ack_delay_us,
  reordering_threshold)` and `requestImmediateAck()` for an embedder
  with its own policy (`error.AckFrequencyNotNegotiated` without the
  peer's parameter; a manual request takes the policy over). A lost
  ACK_FREQUENCY is sent again while it is still the latest. The caps
  16, 32 and 64 were measured on the reorder cells over 12 seeds
  (bbr 314 / 316 / 314 ms against 315 without): the cap costs
  nothing there; a 1 Gbit bulk transfer sends 10% fewer datagrams.

### Fixed

- **An application ACK frame carries up to 255 lower ranges**, the
  receiver's own cap (was 64, raised from 16 on 2026-10-07 and
  measured then while the sender's buffer and the receiver's window
  still bound the transfer). With 10% of the packets 20 ms late the
  receiver holds 72 to 90 ranges at once and every frame carried 64,
  so a late packet that filled a LOW gap stayed unacknowledged until
  the gaps above it closed, past any threshold: the sender declared
  it lost and cut its window (312 truncated frames in one run; three
  to six loss episodes per run, one now, the first reorder event).
  The byte budget stays 512 (255 small ranges fit; no frame truncated
  on that cell now). The alternatives measured first (a wider time
  threshold, a re-grown or an earlier undo, a reaction deferred one
  round trip on a reordering path) gained nothing on top; the sprint
  log in the handoff dir has the table.

## [0.36.0] - 2026-10-08

The many-connections release: a server with thousands of mostly idle
connections pays for the ones that have work, not for all of them,
on every loop pass and in memory. One new Server API (the ready list
and the timer heap, which the bundled `runUdpServer` now runs on),
one new Connection function (`touch`), no change on the wire: every
bench cell is byte-identical to v0.35.0. The same option map.
Verified toolchain: 0.17.0.

MEASURED (`zig build bench-e2e -- --scenario connections`, N server
connections in memory, 10 of them active; ReleaseSafe; one run each,
about 10% noise between runs):

| | v0.35.0 | v0.36.0, the sweep | v0.36.0, the ready API |
| --- | --- | --- | --- |
| Zig heap per idle server connection | 91,186 B | 20,974 B | 20,974 B |
| the handshake's peak, one connection | 196,568 B | 30,232 B | 30,232 B |
| one idle loop pass, 1,000 connections | 429 us | 356 us | 0 us |
| one idle loop pass, 4,000 connections | 3,488 us | 2,221 us | 0 us |
| one request among 1,000 idle connections | 131 us | 125 us | 15 us |
| one request among 4,000 idle connections | 1,233 us | 671 us | 69 us |
| churn, 4,096 requests open on one connection: engine poll per stream | 16.2 us | 6.9 us | |
| churn, 1,024 open | 5.6 us | 2.4 us | |

### Added

- **The ready list and the timer heap** (`Server.takeReady`,
  `peekReady`, `slotDrained`, `tickDue`, `nextDeadline`;
  `Connection.touch`). A slot joins the ready list when its
  connection is touched: a datagram fed to it, a timer that fired, an
  application call that queued output, a close. `tickDue` ticks the
  slots whose deadline passed (a heap of deadlines, stale entries by
  generation) and marks them ready; `nextDeadline` is the heap's top.
  Each is O(what has work). `tick` and `nextTimerDeadline` (the
  sweeps) stay and may be mixed in. The bundled `runUdpServer` uses
  the ready API; an embedder with its own loop (qmsg's
  `drainOutbound` scans from slot 0 for every datagram) can adopt it
  at its own pace. A test (`tests/e2e/server_ready.zig`) runs a
  handshake, a write, the idle timeout and a reap through it.
- **The `connections` bench scenario** (`bench/e2e/connections.zig`):
  N connections on one Server, an idle pass split into tick / timer
  scan / empty poll per connection, the heap per connection, and a
  request's cost among the idle ones in the three loop shapes (one
  sweep per pass, a scan from slot 0 per datagram, the ready API).
  Three churn cells with 256, 1,024 and 4,096 requests open at once,
  with the engine's own poll and tick time on a second line.

### Changed

- **Memory per idle server connection: 92,468 -> 22,132 bytes on
  the Zig heap** (`tests/e2e/memory_per_connection.zig`'s stage
  print; BoringSSL's heap apart), the handshake's peak 196,568 ->
  30,232. The sent-packet tracker starts at 16 slots, not 256 (51 KB
  of the 92 were slots for 0 to 3 packets in flight), and gives a
  storage above 64 slots back when nothing is tracked
  (`SentPacketTracker.shrinkIdle`, from the connection's tick): a
  connection that idles after a bulk transfer no longer holds 3.2 MB.
  The ACK tracker holds eight ranges inline and moves to a heap block
  of 255 only when a path reorders or loses (12 KB across the three
  trackers, for one range in use; the drop-the-lowest rule beyond 255
  is unchanged). The path list holds exactly one path until a second
  opens (5.4 KB). The four embedder-event queues are one heap block
  made at the first event (5.2 KB).
- **A connection at rest answers from a cache.** With the handshake
  confirmed, nothing to send, no ACK owed or armed, no path
  validating, retiring or probing its MTU, the connection keeps its
  next deadline until something changes (`touch`): `tick` and
  `nextTimerDeadline` cost a comparison, `pollDatagram` returns at
  once. A Debug build runs the full path as well and asserts the
  shortcut, on every call. `nextTimerDeadline` keeps its `*const
  Connection` signature (the cache is written through it). The
  server's handshake-done check runs behind its latch now, not before
  it: one BoringSSL call fewer per empty poll.
- **The sendable streams are a list kept in priority order**
  (`Connection.sendable`, by urgency, non-incremental first, then id),
  maintained at every transition of a send half; the packet builder
  takes its first 32 with the round-robin rotation applied per
  urgency group instead of walking every stream of the connection for
  every packet. A Debug build runs the old walk too and asserts the
  same streams in the same order. A test fixture that writes into a
  send half directly calls `Connection.noteSendable`.

## [0.35.0] - 2026-10-08

The reordering release: a path that reorders by a round trip no longer
holds CUBIC back, and the receiver acknowledges every second packet
of a burst while a lone packet still gets its ACK at once. One new
knob (`ack_quick_gap_us`), one ACK-policy change on the wire (fewer
ACK datagrams in bulk, none fewer in ping-pong), no API change. The
same option map. Verified toolchain: 0.17.0.

MEASURED (12 seeds, median / max; `impairment_reorder_gaps_1gbit_defaults`:
8 MiB on 1 Gbit/s, 20 ms RTT, 10% of the packets 20 ms late, nothing
dropped):

| | v0.34.0 | v0.35.0 |
| --- | --- | --- |
| cubic | 511 / 626 ms | 378 / 405 ms |
| bbr | 371 / 414 ms | 311 / 380 ms |
| in-process goodput (64 MiB, no sockets) | 988 MB/s, 117,120 datagrams | 1,088 MB/s, 87,852 datagrams |
| churn, strict ping-pong (2,000 streams) | 8,000 datagrams | 8,000 datagrams |

### Fixed

- **The packet-threshold rule is off once reordering is seen**
  (`conn/ReorderWindow.zig`). The threshold grew to the distance a
  late packet trailed by, one spurious loss at a time; on a path
  whose rate doubles every round trip the distance doubles too, and
  every doubling opened loss episodes until the threshold caught up:
  85 spurious episodes in one 8 MiB transfer, each cutting CUBIC's
  window and holding slow start for a round trip. Now a spurious loss
  puts the packet threshold at its maximum and the time rule alone
  declares losses, as RFC 8985 (RACK) stops using DupThresh once
  reordering is observed. MEASURED: cubic 524 -> 447 ms.
- **The widest time threshold carries a jitter margin.** It stopped
  at exactly twice the RTT, and a packet late by one round trip sat
  on that cliff: its queueing delay decided whether it was declared
  lost. The widest threshold, and the reach the window settles by, is
  twice the RTT plus the larger of four times the RTT variance (the
  probe timeout's margin) and a quarter of the RTT. MEASURED: cubic
  447 -> 422 ms, bbr 371 -> 367.
- **The receive window grows on the bytes received when the reader
  keeps up** (`Connection/streams.zig`). The tune counted only the
  bytes the application read; under reordering the application is
  held by the network, not slow, and the window stalled at 2 MiB for
  a 2.5 MB bandwidth-delay product plus a 20 ms hole, with the sender
  out of credit half the time. When the application has read
  everything deliverable, the pace is the bytes received, holes
  included; a reader that leaves deliverable bytes is slow, hole or
  not, and keeps the old rule. MEASURED: cubic 422 -> 378 ms, bbr
  367 -> 311.

### Changed

- **The receiver acknowledges every second packet of a burst, and a
  lone packet at once.** `application_ack_eliciting_threshold` is
  RFC 9000 13.2.2's two (one through v0.34.0), with a quiet rule: an
  ack-eliciting packet that arrives `ack_quick_gap_us` (1 ms by
  default; `Connection`, `Client.Config`, `Server.Config`; 0 turns it
  off) or more after the previous one is acknowledged at once. A
  burst on any path faster than ~10 Mbit/s shares one ACK between two
  packets; a request, a reply or a keepalive, a round trip apart, gets
  its ACK now instead of after the max_ack_delay timer. Initial and
  Handshake packets, and packets with a FIN, a RESET_STREAM or a
  STOP_SENDING, are acknowledged at once as before. MEASURED: the
  in-process goodput bench 988 -> 1,088 MB/s (+10%, twice v0.33.0's),
  a quarter fewer datagrams in bulk; the churn cells (strict
  ping-pong) byte-identical to v0.34.0's. The cost: ACK clocking every
  second packet makes the single-stream 1 Gbit cells about 2% slower
  (the release record has every cell).
- **The reorder ring stays at 256 records**: 1,024 was measured and
  changed no reorder cell by a millisecond.

## [0.34.0] - 2026-10-08

The CPU-per-packet release: the engine moves the same bytes in a
little over half the CPU. No wire change, no knob, every bench cell
byte-identical in virtual time (no decision moved). Two signature
changes for embedders of the raw `Connection` (BREAKING, below).
Verified toolchain: 0.17.0.

MEASURED (`zig build bench-e2e -- --scenario goodput`: 64 MiB on one
stream, both endpoints in one thread, no sockets, ReleaseSafe; the
number that isolates the stack's CPU from syscalls):

| step | goodput |
| --- | --- |
| v0.33.0 | 547.8 MB/s |
| scratch buffers instead of 4 KB locals | 716.2 (+31%) |
| the send buffer is a ring | 894.0 (+25%) |
| keys by pointer | 968.4 (+8%) |
| the pacer in 64 bits | +1.4% (back to back) |
| the last two per-packet fills | +2.7% (back to back) |
| v0.34.0 | 988.0 MB/s (+80%) |

The loopback smoke (`zig build run-goodput-smoke --release=safe`,
real UDP, one datagram per syscall on macOS) is syscall-bound and
moves little: see the release record.

### Changed

- **No large `undefined` local on a per-packet path.** Zig 0.17 fills
  an `undefined` local with 0xAA in ReleaseSafe as well as in Debug (the
  disassembly: `memset(x, 0xaa, 4096)` at the top of
  `pollLevelOnPath`, `handleShort`, `seal1Rtt`), and every downstream
  builds ReleaseSafe. A `sample` profile of the goodput bench put 14%
  of the engine's CPU in those fills and 4.5% more in a 4 KB template
  copy (`var initial: InitialInDatagram = .{}` with the Initial
  payload inline). The packet paths use `Connection.Scratch`, one per
  thread (`Connection.scratch()`, about 21 KB, a `threadlocal`; nothing
  in it lives past the engine call that fills it); `seal1Rtt` takes an
  optional staging buffer and declares its own only for a padded
  packet, in a function of its own.
- **The send buffer is a ring** (`conn/SendStream.zig`). The buffer
  slid a slice within its allocation and moved the live tail to the
  front whenever a write needed room: an application that keeps the
  buffer full moved its bytes about three times per byte written, 12%
  of the engine's CPU. Now the ACKed prefix is discarded by moving the
  head, a write lands at the tail, and the only copy left is into a
  bigger ring when it grows. Packetization is unchanged: a chunk that
  crosses the wrap is handed to the frame encoder through the scratch
  (`chunkBytesContiguous`), once per turn of the ring.
- **A packet's keys by pointer.** `packetKeys` returned the keys by
  value (the AES key schedules and the AEAD context, about a
  kilobyte) once per packet sent, and the open path copied each key
  epoch, up to three per packet received: 2% of the CPU.
- **The pacer computes in 64 bits** when the product fits, which is
  every realistic rate, window and interval, and in 128 bits
  otherwise; the result is the same (a 128-bit division per poll was
  1.2%).
- **The receive stream zeroes only a gap** before a frame's bytes
  when it grows its buffer; it zeroed the whole grown region and then
  copied the frame over it, writing every in-order byte twice.

### Changed (BREAKING, raw `Connection` embedders only)

- `Connection.packetKeys` returns `Error!?*const PacketKeys` (was
  `Error!?PacketKeys`): pass the pointer on where `&keys` was passed.
  The pointer is good until the next key event, which never happens
  inside one packet's seal or open.
- `SendStream.bytes` is a ring: the `items` slice is gone. `bytes.len()`
  is the live byte count (what `bytes.items.len` was); `chunkBytes`
  serves a chunk that lies before the wrap, `chunkBytesContiguous(c,
  scratch)` any chunk.

### Measured and not shipped

- `application_ack_eliciting_threshold` 1 -> 2 (RFC 9000 13.2.2's
  recommendation): goodput +10% and a quarter fewer datagrams in bulk,
  but the single-stream 1 Gbit cells 2% slower (ACK clocking every
  second packet), and strict ping-pong (churn window 1, 30 ms RTT)
  sent 25% MORE datagrams: a lone packet is acknowledged by the
  max_ack_delay timer instead of at once. The downstreams are
  message-oriented, so the threshold stays at 1; an adaptive policy
  (an immediate ACK after a quiet round trip, every second packet in a
  burst) is a later sprint's, with these numbers as its baseline.
- A cached sendable-stream list: nothing measurable with one stream,
  and with several the round-robin cursor reorders the list every
  packet. For many streams the per-packet insertion sort is O(n^2); a
  priority structure kept across packets is a later sprint's.

## [0.33.0] - 2026-10-07

The line-rate release: a single stream reaches the path's rate on the
engine's defaults, with no configuration. The receive windows tune
themselves, the send buffer follows the peer's credit, the sent-packet
tracker holds four times as many packets, a packet number is never one
byte, and a spurious loss is taken back even when its last packet
comes after the next episode. Five new knobs, all on by default, and
one behavior change for an application that writes past the
connection's memory budget. On the wire, a packet number is one byte
longer while fewer than 128 packets are out; every peer decodes it.
The same option map. Verified toolchain: 0.17.0.

MEASURED, 1 Gbit/s with a 20 ms round trip, 8 MiB on one stream, the
engine's defaults, 12 seeds (bbr unless said; v0.32.0 -> v0.33.0):

| cell | v0.32.0 | v0.33.0 |
| --- | --- | --- |
| `impairment_clean_1gbit_rtt20ms_defaults` | 410 ms | 234 ms |
| `impairment_reorder_gaps_1gbit_defaults` (min / median / max) | 790 / 924 / 1045 ms | 359 / 371 / 414 ms |
| the same, cubic (median) | ~1540 ms | 511 ms |
| `impairment_clean_1gbit_rtt20ms` (the harness announces 4 MiB) | 285 ms | 220 ms |
| `impairment_fat_window_1gbit_rtt100ms` (16 streams x 256 MiB, 100 ms) | 7334 ms | 4138 ms |

The clean link's floor for 8 MiB at 1 Gbit/s with a 20 ms handshake
is ~220 ms; the defaults are now within 7% of it.

### Fixed

- **A packet number is never one byte** (`wire/packet_number.zig`,
  `chooseLength` returns 2..4). The receiver recovers a packet number
  against the largest it has decrypted (RFC 9000 A.3): a packet that
  arrives after more than half a window of newer packets decodes to
  the wrong number, fails to open, and is dropped without a trace.
  One byte is a window of 256, so 128 newer packets (150 KB) are
  enough. The sender's rule (room for twice the unacknowledged range,
  17.1) covers reordering by about one RTT; a reorder of 20 ms at
  1 Gbit/s is ~2000 packets, which a sender with 100 packets in
  flight met with one byte. Found by the reorder bench cell with the
  new episode instrument: about 7 of every 100 late packets in a run
  were never in the receiver's ACK tracker although the simulated
  network dropped nothing, so their loss episodes were never taken
  back; CUBIC, which regrows one packet per RTT after a reduction
  that stands, ran the cell at ~1.5 s. quic-go made the same choice.
  MEASURED (`impairment_reorder_gaps_1gbit_defaults`, median / max):
  cubic 1544 / 2100 ms -> 523 / 626 ms; bbr 438 / 716 ms -> 371 /
  414 ms. Two tests: a packet sealed with 10 out opens after 2000
  newer ones (it failed the tag with one byte), and the decode
  arithmetic.
- **A spurious loss whose last packet arrives after the next episode
  opened is still taken back** (`conn/congestion.zig`,
  `LossEpisodes`). The controllers kept one undo slot, and only the
  current episode's packets counted. They keep the previous episode
  too, with its own pending count and saved state (NewReno, CUBIC);
  a complete previous episode restores its state in full when the
  current one was already taken back, and otherwise only up to what
  the current reduction was taken from. BBR keeps no window to
  restore, so it only extends the current episode, as before.
  MEASURED (the same cell, median): cubic 523 ms -> 511 ms; bbr
  unchanged.

### Added

- **The receive windows tune themselves**
  (`Connection.auto_tune_receive_windows`, default on;
  `max_stream_receive_window`, 8 MiB; `max_connection_receive_window`,
  16 MiB; the same three on `Client.Config` and `Server.Config`). The
  rule quic-go and Chromium use: when a credit is due and the
  application read the last half window in less than two round trips
  (4 x the fraction read x srtt), the window doubles, up to the cap;
  the connection's window stays at least one and a half times any
  stream's. A reader that keeps up on a fat path gets the path's rate
  with no configuration; a slow reader's window never grows. Off, the
  window an endpoint announced is the one it keeps (v0.32.0's
  behavior). The caps are the memory safety: a peer may fill a window
  the endpoint opened, so the connection's cap is never more than
  half of `max_connection_memory` (32 MiB by default) whatever the
  knob says. MEASURED (bbr): `impairment_clean_1gbit_rtt20ms_defaults`
  410 ms -> 290 ms; `impairment_fat_window_1gbit_rtt100ms` 4775 ms ->
  3203 ms with the windows unbounded.
- **The send buffer follows the peer's credit**
  (`Connection.send_buffer_follows_credit`, default on;
  `max_buffered_send_cap`, 16 MiB; the same on `Client.Config` and
  `Server.Config`). A stream's send buffer (`max_buffered_send`, 1 MiB,
  now the floor) grows to what the peer still accepts beyond the
  acknowledged floor, up to the cap, at the application's writes; a
  limit once raised stays. With the receive windows above, one stream
  on a fat path has the buffer the path needs, from both ends, with no
  configuration. Off, `max_buffered_send` is the limit exactly
  (v0.32.0's behavior). MEASURED (bbr):
  `impairment_clean_1gbit_rtt20ms_defaults` 290 ms -> 234 ms;
  `impairment_reorder_gaps_1gbit_defaults` 750 ms -> 438 ms (median);
  `impairment_clean_1gbit_rtt20ms` 285 ms -> 220 ms.
- **Two bench cells on the engine's defaults**
  (`impairment_clean_1gbit_rtt20ms_defaults`,
  `impairment_reorder_gaps_1gbit_defaults`): the harness announces
  nothing and sets no buffer, so they measure what an embedder gets.
  The impairment cells take `--cc cubic` as well as `bbr`, and their
  loss line prints the loss episodes and how many were taken back.
  The cell comment of the reorder cell records the finding that
  neither controller was the brake under reordering until the packet
  number fix above.

### Changed

- **The sent-packet tracker holds 16384 packets**
  (`conn/SentPacketTracker.max_tracked`, was 4096): ~19 MB in flight
  at 1200 bytes, enough for 1 Gbit/s at 150 ms. The slab grows on
  demand, so only a connection that fills the slots pays for them
  (40 bytes a slot). The reorder window's packet threshold keeps its
  own cap of 4096. MEASURED (bbr): `impairment_fat_window_1gbit_rtt100ms`
  7334 ms -> 4775 ms.
- **A write past the connection's memory budget returns short.** An
  application whose own writes reach `max_connection_memory` got
  `error.ExcessiveLoad`, the fault meant for what a peer puts in
  buffers; now `streamWrite` takes what the budget leaves and returns
  the count, as it does at the stream's limit (zero when nothing
  fits). With the windows and buffers above, a writer with many
  streams on a fat path reached the budget where it never could
  before; the budget is back-pressure for the application and a
  fault for the peer. Embedders that treated `ExcessiveLoad` from
  `streamWrite` as the signal to stop writing should read the count.

## [0.32.0] - 2026-10-07

The single-stream limits release: a stream can now go as fast as the
windows its endpoints announce, and the loss thresholds that widened
for reordering shrink back when the reordering stops. One behavior
change for embedders who announce flow-control windows other than the
defaults (the window they announce now stays the window), two new
knobs, a wider ACK frame under heavy reordering. No wire-format
change, no API an embedder must change, the same option map. Verified
toolchain: 0.17.0.

### Fixed

- **The receive window an endpoint keeps open is the one it
  announced.** Through v0.31.1 the credit given after the initial
  window was a fixed 1 MiB per stream and 16 MiB per connection,
  whatever the transport parameters said: an embedder announcing
  4 MiB per stream got 4 MiB for the first 4 MiB of a stream and
  1 MiB after; one announcing 64 KiB got 1 MiB. Now the credit stays
  one announced window ahead of what the application read. The
  defaults (`Client.Config.defaultTransportParams`,
  `Server.Config.defaultTransportParams`) announce exactly the old
  constants, so an embedder on them sees no change. MEASURED
  (`impairment_clean_1gbit_rtt20ms`, 8 MiB on 1 Gbit with a 20 ms
  round trip, bbr, the harness announcing 4 MiB): 361 ms -> 285 ms;
  with the send buffer below as well, 220 ms.

### Added

- **`Connection.max_buffered_send`, `Client.Config.max_buffered_send`,
  `Server.Config.max_buffered_send`**: the send buffer of every stream
  the connection opens from then on (`SendStream.max_buffered`,
  default `Connection.default_max_buffered_send` = 1 MiB, as before).
  The buffer holds every byte written and not yet acknowledged in
  order, so it is the window a stream's sender has: on a path whose
  bandwidth-delay product is larger, or under reordering (a hole
  holds the oldest byte until its repair is acknowledged), a single
  stream cannot go faster than this buffer per round trip of repair.
  MEASURED (`impairment_reorder_gaps_1gbit`, 8 MiB on 1 Gbit with a
  20 ms round trip and 10% of the packets 20 ms late, bbr): 768 ms
  with the default, 294 ms with an 8 MiB buffer and a 4 MiB announced
  receive window (the clean link: 220 ms). The congestion controller
  was never the brake there: BBR sat in Startup with a 2 MB window
  and a 110 MB/s pacing rate.
- **The loss thresholds shrink back** (`conn/ReorderWindow.zig`,
  after RFC 8985's rule for RACK's reordering window): a remembered
  loss whose packet is older than twice the round trip can never
  widen the thresholds again, so it is a real loss; a round trip with
  such losses counts once, a spurious hit restarts the count and its
  own round counts for nothing, and after 16 clean rounds in a row
  the thresholds go back to RFC 9002's (3 packets, 9/8 of the round
  trip). Nothing moves on a path that keeps reordering or never
  loses. The rounds are the window's own, by send time, not the
  controller's loss episodes: BBR extends one recovery period at
  every later loss, so under steady loss its episode never ends.
  MEASURED (`impairment_reorder_then_loss_20ms`, 24 MiB: a 15 ms
  reordering burst on a 20 ms path, then 0.5% loss; 12 seeds): with
  the rule the loss detection delay, averaged over the run, fell
  about 20% (bbr 36 to 49 ms -> 28 to 43; the phase after the decay
  finds a loss at the RFC's 9/8 round trip instead of two), the
  transfer time unchanged for BBR (median 2325 -> 2331 ms) and 4.7%
  longer for CUBIC (19.7 -> 20.6 s: random loss found a round trip
  sooner cuts its window a round trip sooner; its seeds spread 17 to
  23 s either way). The 8 MiB version of the cell, about 26 round
  trips of loss, never reached 16 clean rounds.
- Bench cells `impairment_clean_1gbit_rtt20ms` (the gaps cell's link
  with nothing late), `impairment_clean_1gbit_rtt20ms_buf8m` and
  `impairment_reorder_gaps_1gbit_buf8m` (an 8 MiB send buffer through
  the new `ImpairmentOptions.send_buffer_bytes`); the bench's loss
  line prints the decay's counters.

### Changed

- **The ACK frame carries up to 64 ranges below the largest (512
  bytes), from 16 (128).** Under heavy reordering (hundreds of gaps
  open at once) the 16-range frame left received packets unseen by
  the sender until they fell out of the receiver's tracker: declared
  lost, sent again, and counted as losses. MEASURED
  (`impairment_reorder_gaps_1gbit`, 12 seeds, bbr): 455 to 620
  packets declared lost at 16 ranges, 117 to 299 at 64; 254 adds
  nothing over 64; the time 5% (once the windows above no longer
  bind: 294 -> 279 ms, one seed). Cost: an ACK frame of up to 512
  bytes of ranges only when that many gaps are open.
- `impairment_reorder_then_loss_20ms` transfers 24 MiB (was 8): long
  enough for the decay to fire well before the end.
- The bench cells moved with the window fix: the harness announces
  4 MiB per stream, which the engine ran at 1 MiB after the first
  4 MiB through v0.31.1. Every cell the old running window had capped
  is faster (8 MiB on the 2 ms link: 38 -> 30 ms with nothing lost,
  54 -> 46 with 1% lost, 93 -> 56 with 5%; the 2 ms reorder cells 114
  -> 102 and 74 -> 72; the fat-window cell 7.9 -> 7.3 s); the four
  bottleneck cells and the three churn cells are byte-identical; the
  six fairness cells moved inside their noise (Jain 0.964 -> 0.982 for
  two CUBIC flows, 0.764 -> 0.802 for a BBR and a CUBIC flow).

## [0.31.1] - 2026-10-06

The idle-timer fix: a dead peer's connection ends one idle timeout
after the first probe, not three (a regression of v0.30.1, found by
the qmsg session). No wire change, no API change, the same option
map. Every downstream on v0.30.1 or v0.31.0 wants this one: qmsg's
dead-peer gate failed about 2 runs in 5 there. Verified toolchain:
0.17.0.

### Fixed

- **A dead peer's connection ends one idle timeout after the first
  probe, not three.** RFC 9000 section 10.1: a send restarts the idle
  timer only for the first ack-eliciting packet since the last packet
  received and processed, and a received packet restarts it only when
  it is processed (it opened). Through v0.31.0 every datagram sent
  restarted it, so the backed-off probes to a dead peer (v0.30.1's
  probe timeout probes on instead of declaring a loss) kept the
  connection alive until one probe gap was longer than the timeout:
  about three times the timeout (MEASURED by the qmsg session,
  2026-10-06: a 2 s timeout noticed a dead peer after 5.9 to 6.0 s on
  v0.30.1 and v0.31.0, after 2.2 s on v0.29.0; qmsg's dead-peer test
  failed about 2 runs in 5). And every datagram received restarted
  it, before its packet was opened, so a spoofed datagram to a known
  connection kept it alive. (History, from capnp-zig's review on
  2026-10-07: that second restart is older than v0.30.1, in every
  release before this one since at least v0.24.1; the send restart is
  old too, and v0.30.0's probe timeout that is not a loss is what made
  it a regression. Only the dead-peer lifetime is a regression of
  v0.30.1; the unopened-datagram restart is a fix of long standing.)
  Also: the idle timeout is at least three
  times the PTO (section 10.1 paragraph 4, a MUST that was missing),
  the PTO without its backoff. Three conformance tests. No wire
  change, no API change.

## [0.31.0] - 2026-10-06

The "feed and confirm" release: two small repairs, behavior only, no
wire-format change, no API an embedder must change, the same option
map and the same boringssl-zig (0.6.7). A client confirms its
handshake on an ACK of a 1-RTT packet of its own (RFC 9001 section
4.1.2, a MAY), and `Server.feed` leaves a `.dropped` datagram as it
was. Verified toolchain: 0.17.0.

### Changed

- **A client confirms its handshake on an ACK of a 1-RTT packet of its
  own (RFC 9001 section 4.1.2, a MAY).** It confirmed on HANDSHAKE_DONE
  alone; until that frame came, it kept its Handshake keys and probed
  its Finished at the handshake probe timeout. The server can only
  have opened a 1-RTT packet of the client after it processed the
  client's Finished, so such an ACK says the handshake is complete
  there. An ACK of a 0-RTT packet does not count (a server
  acknowledges those before it has the Finished), and the server
  never confirms on an ACK. What you may see: a client whose
  HANDSHAKE_DONE was lost sends no Finished again once any 1-RTT
  packet of its own is acknowledged (quiche sends HANDSHAKE_DONE again
  only at its own backed-off timeout; in the probes sprint's client x
  quiche x handshakecorruption runs, two of three failed handshakes
  had such an ACK at about 24 s). Key updates and migration become
  legal at that point too. Unit, conformance and loss-harness tests;
  the loss harness gained `client_pings` and `drop_server_short`.
- **`Server.feed` leaves a `.dropped` datagram as it was.** The datagram
  that makes a new connection is opened where it lies; a connection
  that could open no packet of it is stillborn (another server's first
  flight on a shared socket, junk behind a long header), and `feed`
  said `.dropped` with the first byte and packet-number bytes already
  changed, so an embedder that routed it to its own dials had to copy
  before `feed` (found by the bugnest session in qmesh-zig,
  2026-10-06). `feed` now copies the datagram before it opens it on
  that path (on the stack up to 2048 bytes, the heap above) and puts
  it back: a datagram that comes back anything but `.routed` or
  `.accepted` is as it came. A copy before `feed` stays correct and
  can go. Test: `tests/e2e/server_stillborn.zig`.

## [0.30.1] - 2026-10-06

A build fix for 0.30.0: it did not compile on Windows. No change for
any other target beyond a test's tolerance. Verified toolchain:
0.17.0.

### Fixed

- **0.30.0 did not compile on Windows.** `quic.unixWallClockUs`
  called libc's `clock_gettime`, and Windows' libc has none:
  `std.c.timespec` is `void` there, and the test that keeps the
  function compiled (new in 0.30.0) took the Windows test binary down
  with it. On Windows it reads `RtlGetSystemTimePrecise` now (100 ns
  intervals since 1601, rebased to the Unix epoch). `just
  check-windows` sees it; the `test` workflow's Windows job did, on
  the tag. Do not pin 0.30.0 for a Windows build.
- A ticket-lifetime test read 599 for 600 on the Windows runner in
  Debug: BoringSSL counts a ticket's lifetime down from the moment it
  was made, and a slow handshake crosses a second. The three
  lifetime checks allow 5 s under the value set.

## [0.30.0] - 2026-10-06

The probes release. A probe timeout is not a loss (RFC 9002 section
6.2.4: the Application space's timeout no longer declares the oldest
packet lost nor cuts the window; the probe carries its frames again
and the thresholds decide); the handshake spaces' probe timeout is
bounded at about a second and runs from the last send (RFC 9002 A.8),
so a client waiting for a lost server flight probes every second
instead of 1, 2, 4, 8 s. Plus three repairs found by downstreams on
0.29.0: `quic.unixWallClockUs` compiles on Zig 0.17.0,
`Server.adoptLoopThread()`, and `Server.feed`'s in-place contract in
its doc. Behavior only: no wire-format change, no API an embedder
must change, the same option map. Verified toolchain: 0.17.0.

### Fixed

- **`quic.unixWallClockUs` compiles on Zig 0.17.0.** v0.29.0's new
  function called `std.time.microTimestamp`, which 0.17.0 does not
  have (its `std.time` reads clocks through `std.Io`); no test
  referenced the function, so no gate compiled it. It reads libc's
  `clock_gettime(CLOCK_REALTIME)` now, and a test keeps it compiled.
  Found by capnp-zig.
- **`Server.feed` says that it changes `bytes` in place, whatever the
  outcome.** A datagram that comes back `.dropped` may already have
  its first byte and packet-number bytes changed (header protection
  is removed where the packet lies). An embedder that routes a
  `.dropped` datagram to its own dials on one socket must hand them a
  copy taken before `feed`. Found by the bugnest session in qmesh-zig
  (a dial given the bytes after `feed` stalled in its handshake);
  0.29.0's note said "route on `.dropped`" without the copy.
- **`Server.adoptLoopThread()`**: makes the calling thread the loop
  thread of the Server, for an embedder that hands a Server to another
  thread at a quiescent point. v0.29.0's Debug tripwire
  (`checkLoopThread`, which `feed`, `tick` and
  `rotateSessionTicketKey` run) latched the first thread and tripped
  on the first step of the new one, which broke capnp-zig's documented
  `adoptOwnerThread` handoff for a server-side connection in Debug
  builds (release builds were never affected). Found by capnp-zig.
- **A probe timeout is not a loss (RFC 9002 section 6.2.4).** "A PTO
  timer expiration event does not indicate packet loss and MUST NOT
  cause prior unacknowledged packets to be marked as lost." The
  Application space's probe timeout took the oldest ack-eliciting
  packet out as lost, sent its frames again, and told the controller:
  NewReno and CUBIC cut the window by 0.5 / 0.7, BBR entered recovery
  with a loss event. A real loss got two reactions; a late ACK got one
  for nothing. Now the packet stays in flight, the probe carries its
  retransmittable frames again (a PING when it has none; DATAGRAM
  frames are not sent again), nothing is declared lost, and when the
  probe's ACK comes the packet and time thresholds find what was
  lost. The deadline runs from the last ack-eliciting packet sent
  (RFC 9002 A.8), not the oldest. A full tracker keeps the old expiry
  (a probe needs a slot). The handshake spaces are unchanged: their
  expiry is how a lost flight is sent again. MEASURED: the 18
  impairment and churn bench cells are byte-identical (the thresholds
  find every loss there first); the two-CUBIC fairness cell moves
  from Jain 0.9823 to 0.9640 over its 20 s (the old rule's spurious
  cuts, for a timeout whose ACK was only late in the 100 ms queue,
  were an accidental equalizer); the BBR cells are identical.
- **The probe timeout of the handshake spaces is bounded at about a
  second, and runs from the last packet sent.** RFC 9002 section
  6.2.1 doubles the timeout at every expiry without bound. A client
  that waited for the rest of a server's flight under 31% corruption
  (interop `handshakecorruption`, a quiche server) probed at gaps of
  0.4, 0.7, 1.2, 2.3, 4.4 and 8.7 s: ten probes in the 30 s the
  handshake had, and the flight never got through. Now the gap in the
  Initial and Handshake spaces never grows past the probe timeout of
  an endpoint with no RTT sample (`max_handshake_pto_us`, about 1 s),
  so a client with a sample never probes less often than one without;
  below that every probe is where the RFC puts it. A deviation,
  recorded at the constant; the Application space keeps the doubling.
  And the deadline runs from the LAST ack-eliciting packet sent (RFC
  9002 A.8), not from the oldest: with the bound, the oldest anchor
  cascaded (the expiry of the oldest packet left the next-oldest past
  its deadline, and one probe timeout sent 2, 4, then 8 datagrams).
  MEASURED, 10 runs each: client x quiche x handshakecorruption 7 of
  10 -> 9 of 10; client x quic-go x handshakeloss + handshakecorruption
  10 of 10 -> 10 of 10; server x quiche x handshakeloss 9 of 10 -> 9
  of 10; a ClientHello lost eight times in a row completes the
  handshake at 4 s (8 s before). The bench cells are byte-identical.

## [0.29.0] - 2026-10-06

The open-items release: the seven items that were open after 0.28.1.
A client that connects through loss (two-datagram probes, a held
Handshake packet, a CONNECTION_CLOSE sent again); a late packet is
not a lost packet (loss thresholds that widen on a spurious loss, a
reduction taken back when every "lost" packet arrived, and the
recovery period anchored at the detection as RFC 9002 says); a
connection costs 91 KB on the heap, not 1.09 MB; a `Server` makes no
connection for a datagram of which no packet opens; the NEW_TOKEN
times on a clock of their own; the rest of capnp-zig's ticket asks;
and the 32-bit CI leg by hand. No wire-format change. The congestion
controllers' loss hooks take the detection time (internal surface).
Verified toolchain: 0.17.0.

### Fixed

- **A late packet is not a lost packet: the loss thresholds widen when
  a declared loss turns out spurious, and a reduction made for one is
  taken back (RFC 9002 section 6.1).** The thresholds were fixed at 3
  packets and 9/8 of the RTT, so a path that reorders declared packets
  lost that arrived, and every controller saw loss. Now each space
  remembers the packets it declared lost (`conn/ReorderWindow.zig`, a
  ring of 256 records, allocated at the first loss); an ACK that covers
  one of them is a spurious loss. The packet threshold grows to one
  past the distance the packet trailed the largest acknowledged
  packet, and the time threshold grows (9/8, 5/4, 3/2, then 2 times
  the RTT) until it covers how late the packet was. Only for a packet
  the widest thresholds could have covered: a packet later than twice
  the RTT is lost at any width, and widening for it would only send
  its copy later. The thresholds only grow, for the life of the
  connection (Chromium's `GeneralLossAlgorithm` does the same with its
  packet threshold). The controller counts the packets declared lost in
  each loss episode; when every one of them has arrived, there was no
  congestion, and the reduction is taken back: NewReno and CUBIC
  restore the window, the threshold and W_max (Linux's
  `tcp_undo_cwnd_reduction`), BBR restores its model bounds (the
  draft's section 5.5.11, SaveStateUponLoss, until now a documented
  deviation). A probe timeout's expired packet counts the same way.
  MEASURED (`bench-e2e`, 12 seeds, before -> after):
  `impairment_reorder10pct_1ms_rtt20ms_100mbit` (a 20 ms round trip,
  100 Mbit/s, 10% of the packets 1 ms late; new): bbr median 1376 ->
  773 ms (the link's floor), cubic 9937 -> 790, new_reno 18357 -> 790;
  600 to 800 packets declared lost per run, all spurious, now 4 to 8.
  `impairment_reorder10pct_1ms` (2 ms round trip; new): bbr median
  199 -> 82 ms and max 2442 -> 94, cubic 3472 -> 87, new_reno 3609 ->
  120. `impairment_reorder10pct` (5 ms late on a 2 ms path, 2.5 round
  trips, past any width): bbr 137 -> 137, max 2480 -> 2078; cubic
  4462 -> 3004; new_reno 4512 -> 3264. The 17 other cells are
  unchanged. `ConnectionStats.packets_spuriously_lost` counts them.
- **The recovery period starts at the detection of the loss, not at
  the lost packet's send time (RFC 9002 section B.6,
  `congestion_recovery_start_time = now()`).** NewReno, CUBIC and
  BBR anchored the period at the send time of the newest lost packet,
  so it ended at the next ACK (of any packet sent after that one), and
  every loss found inside one round trip was a new reduction: 0.7 of
  0.7 of 0.7 of the window for one congestion event, where the RFC
  reduces once. Now a loss of a packet sent before the detection is
  inside the period, and the period ends with the ACK of a packet sent
  after the detection, as in TCP's fast recovery. MEASURED: the
  fairness cells change where CUBIC is in them, since a CUBIC that
  reduces once per round trip takes more: `fairness_10mbit_2f_mixed`
  (bbr against cubic, deep buffer) bbr share 31.1% -> 22.3%, the
  shallow one 61.3% -> 62.5%, `fairness_10mbit_2f_cubic` Jain 0.9996
  -> 0.9823 (56.7% / 43.3% over 20 s); the BBR-only cells are
  byte-identical. The controllers' `onPacketLost` and
  `onCongestionEvent` take the detection time as a third / second
  argument (internal; `quic.CongestionController` is not an embedder
  surface).
- **A handshake probe is two datagrams while there is no RTT sample
  (RFC 9002 section 6.2.4).** A client whose Initial datagram was lost
  sent it again after 1 s, 3 s, 7 s and 15 s, one datagram each time
  (the first probe timeout is 1 s with no sample, and it doubles). A
  quic-go server forgets a half-open connection after 5 s, so the
  handshake failed whenever the datagrams at 0, 1 and 3 s were all
  lost. MEASURED (interop `handshakeloss` and `handshakecorruption`,
  quic-zig as the client against quic-go, 10 runs each on 0.28.1):
  5 and 6 passes of 10. Now the CRYPTO data of the expired packet is
  queued twice, so the probe leaves in two datagrams; a network that
  loses up to three datagrams in a row cannot hold the client off past
  3 s. Only the Initial and Handshake spaces, and only while the
  connection has no RTT sample: with a sample the retries are quick,
  and a second datagram would only double the cues that the peer
  answers with a copy of its flight (measured in the handshake-loss
  tests: it used up the peer's eight early copies in a 100 ms outage).
  A server with no sample does the same with its flight.
- **A Handshake packet that arrives before its keys is kept and read
  when the keys come (RFC 9000 section 12.2).** The datagram with the
  ServerHello is lost or late, the datagram with the rest of the
  flight is not: the client had no Handshake keys and dropped it, and
  the server sent it again after its own loss detection. Now the
  client keeps up to two such packets (`max_held_handshake_packets`)
  and reads them as soon as the ServerHello gives it the keys; they
  are freed when the Handshake keys are discarded. In the
  handshake-loss tests, a flight of three datagrams with the second
  delivered before the first is done with no copy of anything.
- **A lost CONNECTION_CLOSE is sent again at the peer's next packet.**
  The rate limit of RFC 9000 section 10.2.1 was time: not before two
  probe timeouts since the last close, while the closing state ends
  at three. So a peer that did not get the close, and probes on its
  own timer, got the repeat only by luck (measured: probes at 100 ms to
  9 s after the close, no answer to any). The limit counts the peer's
  packets now: the first packet after the close earns the close again,
  then two more, then four, and so on, so a flood of N packets gets
  log2(N) closes.

- **A `Server` makes no connection for a datagram of which no packet
  opens.** `feed` built a whole connection from the long header of a
  1200-byte datagram before any packet was authenticated, and said
  `.accepted` also when none was: the connection stayed, half open,
  until the handshake timeout. An embedder with ONE socket for a
  `Server` and its own dials, which gave each datagram to the Server
  first and to a dial on `.dropped`, lost the answers to its dials
  since 0.26.0 (a server's first flight is 1200 bytes since then;
  qmesh-zig, found by the bugnest session; measured: `.accepted`, one
  connection, gone 11 to 30 s later). Now a connection that opened no
  packet of the datagram that made it is taken down at once and
  `feed` says `.dropped`, as it did before 0.26.0 for that datagram.
  A client whose Initial opens and then fails in TLS is not this case.

### Added

- **`Server.Config.new_token_clock` and `new_token_max_clock_skew_us`:
  a clock of their own for NEW_TOKEN times.** A token holds the time
  it was made at. Stamped with the `now_us` of `feed` (a timer clock,
  which starts at zero in each process), a `new_token_key` that the
  next process is given too did not let returning clients skip the
  Retry, and let old tokens through after their lifetime. Now the
  tokens can be stamped and checked with a clock that goes on across
  a restart (`quic.unixWallClockUs`, microseconds since the Unix
  epoch, is one), with an allowed skew for the jumps of a wall clock,
  and the timers keep their clock. Three asks of capnp-zig's handoff
  (2026-10-04) that 0.27.0 answered with docs only. The bundled loop
  needs nothing else.
- **`Server.Config.previous_session_ticket_key` (and
  `previous_session_ticket_key_until_us`)**: a process that starts
  less than one ticket lifetime after a key change still opens the
  tickets of the key before, as a running process does after
  `rotateSessionTicketKey`. Refused: with no `session_ticket_key`, 48
  zero bytes, or the 16-byte name of the current key. Asked for by
  capnp-zig after it ran 0.27.0 (its way out was to start with the old
  key and rotate at once).
- **`Client.Config.session_ticket_lifetime_s`**: the client's own
  limit on how long it keeps a ticket. A BoringSSL client keeps a
  ticket for the smaller of the server's lifetime and 2 days, so a
  server lifetime above 2 days had no effect on a quic-zig client.
  1 to 604800; refused with `tls_context_override`.
- **`Client.resumptionTicketLifetimeSeconds(envelope)`**: the lifetime
  of the ticket in a saved resumption envelope, as the client keeps
  it. capnp-zig read it through `boringssl.raw` for this.
- **`Server.rotateSessionTicketKey` checks the thread in a Debug
  build**: a call from a thread that is not the one of `feed` and
  `tick` trips an assert (the keys it changes are read by the
  handshakes on that thread). Asked for by capnp-zig.

### Measured

- `bench-e2e`: two new reorder cells, `impairment_reorder10pct_1ms`
  and `impairment_reorder10pct_1ms_rtt20ms_100mbit` (the impairment
  options take `reorder_extra_us`), and a loss line under each run of
  a sweep: packets declared lost, how many arrived late, the
  thresholds at the end.
- The ACK frame's range cap (16 lower ranges, 128 bytes) re-measured
  with the reorder cells at 64 / 512 and 254 / 1024: more of the late
  packets are seen acknowledged, the transfers are no faster. Kept.
- `tests/e2e/handshake_loss.zig`, 30% loss each way, 300 seeds, a
  ClientHello of two packets, a 10 s budget: 0 handshakes not done
  (4 before), 79 at 900 ms or more (79 before: the client's own first
  second when it never heard anything). 30% toward the client only: 0
  not done and 23 slow, as before.

## [0.28.1] - 2026-10-05

A build fix for 0.28.0: it did not compile for a 32-bit target. No
change for a 64-bit target beyond five casts in tests and examples.
A 32-bit leg in CI from now on. Verified toolchain: 0.17.0.

### Fixed

- **0.28.0 did not compile for a 32-bit target** (`x86-linux-musl`).
  `src/conn/RecvEndRing.zig` asserted at comptime that a `Record` is
  40 bytes. It is 40 where a u64 aligns to 8, and 36 where it aligns to
  4, so every build that uses `Connection` failed on that target with
  "reached unreachable code". The check is on the layout now (four u64
  and the flags byte, padded to the alignment of u64), and the module
  doc says both sizes. Found by http3-zig's CI (its
  `x86-linux-musl` leg), which went back to 0.27.0 for it.
- Five places in tests and examples put a u64 (a transport parameter)
  where a usize is wanted, which a 32-bit target refuses
  (`examples/request_response_server.zig`, `tests/e2e/app_driver.zig`,
  `tests/e2e/testing_loopback.zig`, `src/Connection/_tests_fuzz.zig`,
  a test in `src/conn/RecvStream.zig`). The library itself compiled;
  the suite did not.

### CI and tests

- A 32-bit leg in the `test` workflow: `build-test (ubuntu-latest,
  x86-linux-musl)` compiles and RUNS the suite (an x86-64 Linux
  runner runs 32-bit static binaries). No leg here could see the
  0.28.0 break. `just check-x86` is the compile-only form for a host
  that cannot run the binaries, beside `just check-windows`.
- The first run of that leg found two more things. (1) The test that
  pins `@sizeOf(SentPacket)` at 200 bytes: on a 32-bit target it is
  152 (pointers and usize are 4 bytes, a u64 aligns to 4); the pin is
  per pointer size now. (2) Nine tests of the bench harness
  (`bench/e2e/harness.zig`, `bench/e2e/fairness.zig`) crashed: a UBSan
  trap ("Alignment, null, or object-size") in BoringSSL's P-256 field
  code (`third_party/fiat/p256_32.h`, `fiat_p256_mul`) during ECDSA
  verify in the TLS handshake. The other tests that run a handshake
  with the same P-256 key passed on the same build, so what sets the
  nine apart is not known yet (they build their TLS contexts with
  `boringssl.tls.Context` and `Connection.initClientAt`, not with
  `Client.connect`). The trap is inside BoringSSL as built for x86
  with the C sanitizer in trap mode; it is recorded for boringssl-zig
  and not changed here. The leg runs the suite with
  `-Dsanitize-c=off`; the x86-64 `sanitizer` job keeps the UB check on
  the C code.

## [0.28.0] - 2026-10-05

"The end of a stream that cannot be lost". An application now learns
how a stream ended — a clean FIN, or a reset with its code — whatever
the order of its read and `tick`. New: `Connection.streamRecvEnd`,
`StreamRecvEnd`, `reset_code` on `StreamRecvState` and
`StreamReadResult`. Fixed: `streamReadFin` called a stream that was
reset after its FIN complete. Changed: `runUdpClient` runs its hook
before `tick`; `quic.app` reports the true end of a stream that a
`tick` reclaimed first. No wire change: when streams are reclaimed and
when stream credit returns do not move. Also the doc repairs that
capnp-zig's run of 0.27.0 asked for. No security fix; nothing removed
or renamed.

### Documentation

- **What capnp-zig found when it ran its own suite on 0.27.0.** The
  suite passed. These are the things that the docs did not say:
  - `Server.rotateSessionTicketKey`: the time of the old key counts
    from the `now_us` argument, on the clock of `feed` and `tick`.
    The Server does not check the calling thread.
  - A process that restarts less than one ticket lifetime after a
    rotation, and starts with the new key, loses the tickets of the
    old key that are still out. The way to keep them: start with the
    OLD key and call `rotateSessionTicketKey` again before the first
    datagram (with the `now_us` of the first rotation, if the clock
    goes on across the restart). It is in the doc of the function and
    in EMBEDDING.md. This corrects the 0.27.0 entry "A process that
    starts with a new ticket key does not have the old one", which
    named no way out.
  - `Config.session_ticket_key` holds the key by value. The Server
    clears its own copy; the caller clears the `Config` and the
    buffer that the key was loaded into.
  - `Config.session_ticket_lifetime_s` above 2 days needs the client
    too: a BoringSSL client keeps a ticket for 2 days at most, unless
    that limit was raised on its own TLS context.
  - The bundled loop (`transport.runUdpServer`) feeds a clock that
    starts at zero each time it starts. With it, a `new_token_key`
    from the process before does not save the Retry: the new process
    reads the old tokens as not yet valid until its uptime passes
    their issue time. Read in the token check, and now in the docs
    too: from then on it takes such a token for one token lifetime of
    its own clock, however old the token is. So a key that outlives
    the process needs a clock that goes on, and the bundled loop has
    none.

### Fixed

- **`streamReadFin` called a stream reset after its FIN complete.**
  When a peer sent data and a FIN, then RESET_STREAM before the
  application read, the reset threw the unread bytes away but
  `streamReadFin` still said `fin = true` with `n = 0`: a cut stream
  passed for a complete one, with the right read order. Now `fin` is
  false once the peer reset the stream, and the result carries
  `reset_code`. (`RecvStream.resetStream` keeps `fin_seen`;
  `streamReadFin` did not look at the reset.) `fin` is still not an
  end-of-stream test on its own (a FIN at a high offset can arrive
  while lower bytes are missing); `streamRecvEnd` is that test.
- **The end of a stream was lost when `tick` ran before the
  application read.** `tick` reclaims a stream as soon as its receive
  half has ended. When the end came with nothing left to read (a FIN
  in a frame of its own after the last read, or a RESET_STREAM) and
  `tick` ran first, a clean end and a reset gave the same answers and
  the reset code was gone. Reported by http3-zig (it lost the end of
  its WebTransport CONNECT streams) and measured by two more
  downstreams. Three changes, below: `streamRecvEnd` answers after the
  reclaim, `runUdpClient` reads before `tick`, and `quic.app` reports
  the true end. Old behavior, not from 0.27.0.

### Added

- **`Connection.streamRecvEnd(id) ?StreamRecvEnd`** (Evolving): how the
  receive half of a stream ended — `fin_seen`, `reset_code`,
  `final_size`, `read_offset`, `stopped`, `arrived_in_early_data`, and
  `isClean()`. It gives the same answer before and after the `tick`
  that reclaims the stream, at least through the tick after that one.
  Behind it is a small note per connection (a ring of 256 ends, about
  10 KiB, allocated on the first reclaim). `null` together with
  `streamRecvWasReaped(id) == true` means "ended, how not known": treat
  it as cut, never as complete. If the note cannot be allocated, the
  stream is still reclaimed as before and the answer is "not known".
- **`reset_code`** on `StreamRecvState` (live streams) and on
  `StreamReadResult`. Before this, the code of a peer's RESET_STREAM
  could be read only from the internal field `Stream.recv.reset` of a
  live stream, and was gone once `tick` reclaimed it.

### Changed

- **`runUdpClient` calls its `on_iteration` hook BEFORE `tick`** (it was
  after), the order `runUdpServer` already uses. A stream whose end came
  in this iteration is still in the table when the hook reads it. When
  that `tick` closes the connection (an idle timeout, for example), the
  hook runs once more right after it, so it still sees the close before
  the loop returns, as it did with the old order.
- **`quic.app`**: for a stream that a `tick` reclaimed before the Driver
  serviced it, `on_stream_end` now gets `.fin` or `.reset` (it got
  `.reaped`). A stream the application itself stopped
  (`streamStopSending`) is now `.reaped`, also while it is live (it was
  `.fin`, which says every byte reached `on_stream_data`; the bytes after
  the stop were dropped). `.reaped` now means "no clean end the Driver can
  vouch for: teardown, a stopped stream, or a reclaimed stream whose end
  is not known". Note: such a stopped stream can be `.reaped` while still
  live, so `streamRecvWasReaped(id)` is false for it; that alone does not
  mean teardown. `streamRecvEnd(id).?.stopped` says it directly. The
  reset code is
  `conn.streamRecvEnd(entry.id).?.reset_code`. `StreamEnd` keeps its
  shape (no payload). *Correction (2026-10-06, found by capnp-zig):
  the USUAL end of a stopped stream is `.reset`, not `.reaped`: a peer
  answers STOP_SENDING with RESET_STREAM (RFC 9000 §3.5) and the reset
  is checked first; `.reaped` is the stopped stream whose RESET_STREAM
  has not arrived. And `.?` is safe only inside `on_stream_end`, where
  the answer is never null; anywhere else (the Driver's teardown pass
  included) read it as `if (conn.streamRecvEnd(id)) |e| e.stopped`.*
- **`Outbox.finish` cannot stop the server any more.** It now treats as
  "nothing left to finish": `StreamNotFound` for a stream that really
  was reclaimed (its send half was already done), and `StreamClosed`, a
  send half the peer already stopped with STOP_SENDING. The second one
  is an old fault: a peer that sent STOP_SENDING and then its FIN made
  the usual `.fin => outbox.finish(...)` reply return `StreamClosed`
  out of the service pass, which stops `runUdpServer` for every
  connection. An id that was never opened still returns
  `StreamNotFound`.
- EMBEDDING.md "Ending a receive stream" is rewritten around
  `streamRecvEnd`. Its old snippet took `streamRecvState(id) == null`
  as "done", which is the trap itself. `examples/echo_client.zig` asks
  `streamRecvEnd` when its stream is gone, and `examples/goodput_smoke.zig`
  ends its upload on `streamRecvEnd` (a cut upload now fails the smoke;
  it took "gone" as "done").

### Not changed (on purpose)

- WHEN a stream is reclaimed, and WHEN its stream credit goes back to
  the peer. A per-tick oracle in the stream-window fuzz test pins it.
- `streamRecvState` returns null once a stream is reclaimed, as before:
  qmsg and `quic.app` use "not null" to mean "still in the table".
- The field `Stream.recv.final_size` (capnp-zig reads it directly).
- The shape of `quic.app.StreamEnd`.

### Tools and tests

- `tests/e2e/stream_end_after_tick.zig`: four kinds of end (FIN, RESET,
  FIN then RESET, unread data + FIN then RESET) on a uni and a bidi
  stream, asked before and after the reclaiming `tick`: the same
  `streamRecvEnd` both ways; `streamReadFin` for the reset cases; the
  null contract of `streamRecvState`; the `runUdpClient` order through
  its iteration tail; and `quic.app` with the tick first.
- The stream-window fuzz test checks, at every `tick`, that exactly the
  streams of today's reclaim rule leave the table and that each one's
  note equals its live answer from just before.
- Unit tests: the ring's bound and survival, an overwritten note that
  answers "not known" (never "clean"), and a refused allocation that
  still reclaims and gives credit at the same tick.
- `tests/e2e/session_tickets.zig`: a process that restarts before the
  old key's time is over, starts with the old key and rotates again
  with the time of the first rotation. It takes the tickets of both
  keys, and the old key ends when it would have ended.
- `tests/e2e/new_token_smoke.zig`: a server whose clock starts again
  reads a token of the process before at the wrong age (a Retry
  before its uptime passes the issue time; taken for one lifetime of
  its own clock after that). Measured, not wanted.

## [0.27.0] - 2026-10-05

"Tickets that live through a restart". A server can now keep its
session tickets, and with them resumption and 0-RTT, across a
restart, a certificate reload and a change of the ticket key; and a
client's early data goes early also when the server answers with a
Retry. New: `Server.Config.session_ticket_key`,
`Server.Config.session_ticket_lifetime_s`,
`Server.rotateSessionTicketKey`, `Connection.retryAccepted()`.
Nothing is removed or renamed. **One thing can need a change in an
embedder:** a direct caller of
`Connection.setRememberedPeerTransportParams` must pass the two
stream counts too (under "Changed"). A server that uses none of the
new settings behaves as before: the 18 virtual-time bench cells print
the same lines as on 0.26.0. The work was asked for by capnp-zig,
whose handoff named each item. Verified toolchain: 0.17.0.

### Added

- **`Server.Config.session_ticket_key`: session tickets that live
  through a restart and a certificate reload.** BoringSSL seals
  tickets under a key that is random for each TLS context and lives
  in memory only. So a new process could not open the tickets of the
  one before it, and neither could the context that
  `replaceTlsContext(.{ .pem = ... })` builds: every client paid one
  full handshake and lost its 0-RTT. Measured at the public wrappers
  before this: after a restart, and after a `.pem` reload, a resumed
  client's early data was rejected; with the same 48-byte key on both
  contexts it was accepted and the server read it before its
  handshake was done. The new setting (`quic.SessionTicketKey`, 48
  bytes) is installed on the context that `init` builds and on every
  context that a `.pem` reload builds. `init` refuses, with
  `InvalidConfig`, a key of 48 zero bytes, a key together with
  `tls_context_override`, and a key together with
  `early_data = .with_anti_replay` (the replay tracker is process
  memory: after a crash a recorded 0-RTT flight would be fresh
  again). The field's doc comment says what a stolen key gives and
  what else must stay the same for 0-RTT to survive. Asked for by
  capnp-zig, which installed the key through the raw TLS layer.
- **`Server.rotateSessionTicketKey(new_key, now_us)`: a key change
  that loses no ticket.** BoringSSL's own key setter holds one key
  and drops the one before it, so a change through it costs every
  client one full handshake. The Server now keeps two keys and gives
  BoringSSL a callback: new tickets are sealed under the new key, and
  the key before it still opens the tickets that are out. A client
  that comes back with one resumes, with 0-RTT, and leaves with a
  ticket of the new key (measured before it was built, and held by
  tests). The old key is cleared one ticket lifetime after the
  rotation, by the clock of `feed` and `tick`, or at once by a second
  rotation. A `.pem` reload keeps both keys. Refused: a server with
  no `session_ticket_key`, a zero key, and a key with the 16-byte
  name of the current one. The ticket format is BoringSSL's own, so a
  server with the setting and a server whose key was set on the TLS
  context by hand read each other's tickets; a pool can move one
  server at a time. For an embedder with a TLS context of its own:
  `quic.tls.session_ticket.Ring` and `installRing`.
- **`Server.Config.session_ticket_lifetime_s`.** How long a session
  ticket is good for: 1 second to 7 days (the limit of RFC 8446
  section 4.6.1); null leaves BoringSSL's 2 days. A `.pem` reload
  keeps it. With a ticket key that outlives the process, the
  lifetime is how long a stolen key is of use after the key is
  changed, so an operator wants to be able to shorten it. TLS reads
  the wall clock for it, not the `now_us` of the QUIC loop. Tested
  with a TLS clock that the test moves: with a lifetime of 10 s a
  ticket is taken at 9 s and refused at 10 s; with no lifetime set
  it is taken at 10 s.
- **`Connection.retryAccepted()`.** True once a client has taken a
  Retry packet. A client that counts "dials that saved the round
  trip" needs it: after a Retry the handshake costs one round trip
  more, and `earlyDataStatus()` still says `.accepted`. (capnp-zig
  read the field `retry_accepted` for this; the field stays.)

### Changed

- **Remembered transport parameters also limit the NUMBER of 0-RTT
  streams.** Until the server's new parameters arrive, a resumed
  client may open at most the remembered `initial_max_streams_bidi`
  and `initial_max_streams_uni` streams (RFC 9000 section 7.4.1); one
  more is `error.StreamLimitExceeded`, as at the real limit. Only the
  bytes were bounded before, so a client could open and fill more
  early streams than the server had allowed, and a server that checks
  closes the connection for it. With `Client.Config.resumption_state`
  nothing is to do: the envelope holds the server's parameters. **A
  caller of `Connection.setRememberedPeerTransportParams` that passes
  flow-control limits only must now pass the two stream counts too**
  (a count of 0 means no early stream). Seven test helpers of this
  repository did that and were changed.

### Fixed

- **A client sends its 0-RTT data again after a Retry.** A server
  that answers the first flight with a Retry has no connection for
  it, so the 0-RTT packets of that flight are gone. The client kept
  them as "in flight". Nothing acknowledges them, and there is no
  1-RTT probe timer before the handshake is confirmed, so the data
  came back through loss recovery after the handshake, as 1-RTT
  data, while TLS reported the early data as accepted. Now the Retry
  queues the stream bytes and control frames of those packets again,
  and they go out as 0-RTT with the next Initial packet, to the
  connection ID of the Retry (RFC 9000 section 17.2.5.3). Packet
  numbers go on; the keys are the same; it is not a loss for the
  congestion controller or the loss counters. A DATAGRAM frame in
  such a packet is reported as lost, as on a rejection. Measured at
  the public wrappers before and after: with a Retry in the way, the
  server could read the early bytes only after its handshake was
  done; now it reads them before. Found by the capnp-zig session,
  whose patched client proved the cure.

### Documentation

- **The "Resumption note" of `replaceTlsContext` gave advice that
  loses the server's TLS posture.** It told embedders who want
  tickets to live through a certificate reload to set ticket keys on
  a context of their own and pass it as `.override`. A context that
  the embedder builds has only what the embedder puts on it: not the
  TLS 1.3 pin, the ALPN list, the early-data flag or the anti-replay
  hook of the Server's own contexts (and `.override` is refused with
  `client_ca_pem`). The note now points at `session_ticket_key` with
  a `.pem` reload, and `TlsReload.override` lists what it leaves to
  the embedder. Reported by capnp-zig.
- **`Server.feed`: "any monotonic origin works" is true inside one
  process only.** A NEW_TOKEN holds the `now_us` it was made at. With
  a `new_token_key` that the next process is given too, a clock that
  starts at zero in each process makes the new process read the
  tokens of the one before it as not yet valid, and those clients get
  a Retry. The doc of `feed` and of `new_token_key` say so now, and
  what clock does not have the problem. Reported by capnp-zig, which
  met it.
- **EMBEDDING.md, "Session tickets across restarts"**: the key, what
  a stolen key gives, rotation, lifetime, the pair that is refused,
  source validation after a restart, and what to do with a TLS
  context of your own.

### Measured, not changed

- **The ACK repeat in the Handshake space alone was tried and is not
  in the code.** 0.25.0 took back a repeat of the handshake ACK in
  both spaces: for a peer whose first copy was lost, a late ACK is a
  wrong first round-trip sample. The same change for the Handshake
  space alone was built after 0.26.0 (a probe timeout there, and a
  1-RTT packet that arrives before its keys, owe the Handshake ACK
  again; 4 unit tests, 7 mutants killed), on the idea that a peer in
  the Handshake space has a sample from the Initial space. It has
  none when the datagram with the one Initial ACK was lost. Measured
  with a quiche client under 30% loss, in run 3 of 9: the repeat made
  the client send its lost Finished again at once, and it was the
  client's first sample, 2.137 s on a 30 ms path (the ACK carried the
  true delay of 2.10 s; RFC 9002 section 5.3 does not correct a first
  sample). The client's probe timer went to 6.4, 12.9 and 25.7 s, and
  the connection timed out with no file. The rule set before the test
  was "no round-trip estimate above 1 s in any run", so the batch
  stopped there: 7 runs of 9 passed (the other failed run lost all
  five copies of its ClientHello). A repeat is safe only for a peer
  that is known to have a sample; the note is at `firePtoAtLevel` in
  `src/Connection/loss.zig`.
- **A ticket key together with the replay tracker is refused, not
  made safe.** `session_ticket_key` with
  `early_data = .with_anti_replay` is `InvalidConfig`, because the
  tracker is empty after a crash. The pair can be made safe: a server
  that takes no 0-RTT for the first 61 s after its start (BoringSSL
  accepts a ticket age that is off by 60 s; RFC 8446 section 8.2
  asks for this). It is not built.
- **A process that starts with a new ticket key does not have the
  old one.** `rotateSessionTicketKey` keeps the previous key in the
  process that is running. `Config.session_ticket_key` is one key, so
  after a restart the tickets of the key before it are lost.
- **Still open from 0.26.0, as written there:** a client retries a
  silent handshake with one datagram for each probe timeout; a
  Handshake packet that arrives before its keys is dropped; a
  CONNECTION_CLOSE that is lost is in practice not sent again.

### Tools and tests

- `tests/e2e/session_tickets.zig` (25 tests), at the public wrappers:
  a first connection earns a ticket, a second one resumes with early
  data. Each test looks at what the client says and at WHEN the
  server could read the bytes (before its handshake was done, or
  after). The second is the one that counts: a client says "accepted"
  also when its early data came late.
- `src/tls/session_ticket.zig` (13 unit tests): the pair of keys, the
  lifetime range, and BoringSSL's ticket callback called directly.
- The ticket lifetime is tested with a TLS clock that the test moves
  (TLS ages a ticket on the wall clock, not on the clock of the QUIC
  loop).
- 54 mutants of the new code, all killed in the end. The first runs
  found real gaps, and each has a test now. Three mutants that took
  the wrong 16 bytes of the key for the HMAC or for AES passed every
  test, because the test keys were 48 equal bytes; the keys now have
  three different parts. A mutant with a fixed IV passed, because no
  test looked at the IV. Two guards that no test could make fail were
  rewritten or removed.
- Interop, local, on the code of this release, both roles against
  quic-go, ngtcp2 and quiche. As the client, `zerortt` and
  `keyupdate` passed 3 runs of 3 against each server; the 0-RTT sizes
  at the runner are what they were (10413 to 10417 bytes), now with
  the library holding the stream count. The wide matrix (15 tests),
  one run for each role. As the client: 42 cells passed, 1 failed, 2
  not supported by the peer. As the server: 40 passed, 1 failed, 4
  not supported by the peer. Both failed cells are known ones, and
  both were read: `handshakeloss` against a quic-go server (the first
  "Measured, not changed" entry of 0.26.0; the server heard nothing
  from the client for 7 s), and `multiplexing` with a quiche client
  (the flaky cell of every release since 0.24.0; 4 of its 1999
  requests were cut short by the client). The `resumption` and
  `zerortt` cells pass in both roles against all three peers.

## [0.26.0] - 2026-10-04

"Every legal peer connects": small repairs, each a rule of RFC 9000
or RFC 9001 that was missing or wrong. A server with Retry on answers
every legal client. No handshake datagram is longer than 1200 bytes,
and those that must be 1200 bytes are. The connection IDs of the
handshake are checked. A close during the handshake reaches the peer.
A key update waits for the handshake to be confirmed. **Three things
can need a change in an embedder:** the token types are 114 bytes
(were 96); a peer that leaves a connection ID out of its transport
parameters is refused; `requestKeyUpdate` returns
`error.KeyUpdateBlocked` until the handshake is confirmed. All three
are under "Changed" or "Fixed". On the wire, a server's first flight
is padded to 1200 bytes. The 18 virtual-time bench cells print the
same lines as on 0.25.0. Five more faults and limits were found and
measured and are not fixed here: they are under "Measured, not
changed". Verified toolchain: 0.17.0.

### Changed

- **Address-validation tokens are 114 bytes (were 96).**
  `quic.RetryToken`, `quic.conn.NewTokenBlob`,
  `retry_token.max_token_len` and `new_token.max_token_len` change
  size. A buffer written as `[96]u8` for a token must use the type or
  the constant. The formats have new versions (Retry v3, NEW_TOKEN
  v2). A token made by an older release fails `validate` as
  `.malformed`, which a server treats as "no token": it sends a fresh
  Retry, or accepts the client without one when Retry is off. Tests
  hold both. `retry_token.mint` and `new_token.mint` no longer return
  `OutputTooSmall` for fields within their limits (only for an output
  buffer that is too short).
- **A server's first flight is padded.** A datagram of a server that
  holds an ack-eliciting Initial packet (the ServerHello, a copy of
  it, a probe) is now 1200 bytes, as RFC 9000 section 14.1 says it
  MUST be. It was never padded: with a small certificate the whole
  flight was one datagram of 831 bytes. Every padded byte counts
  against the anti-amplification limit, so a server that may not send
  1200 bytes yet sends no ServerHello yet (an ACK still goes). In
  numbers, for that small certificate: before the client's address is
  validated, its 1200 bytes pay for three copies of the flight (3 x
  1200), where four fitted before (4 x 831).
- **`sealInitial`'s `pad_to` is exact.** It was a floor that could
  come out one byte over. A padded Initial packet may now have a
  Length field of two bytes for a value that fits one (RFC 9000
  section 16 allows it).
- **A peer that leaves a connection ID out of its transport
  parameters is refused.** From the checks under "Fixed": a peer with
  no `initial_source_connection_id`, and a server with no
  `original_destination_connection_id`, now get
  TRANSPORT_PARAMETER_ERROR. This library's own endpoints always sent
  the first one. A server made from a bare `Connection` (no `Server`
  wrapper) sent no `original_destination_connection_id` unless the
  embedder set it; it is filled in now (see "Fixed"), so such a
  server needs no change. One that answers with a Retry itself must
  set it, with `retry_source_connection_id`, as RFC 9000 always
  wanted.

### Fixed

- **The connection-ID rules of RFC 9000 sections 7.2, 7.3 and
  17.2.5.2.** Four checks were missing. (1) A later Initial packet
  with another Source Connection ID is now dropped, at both ends. The
  client took the ID of every Initial packet that authenticated, and
  anyone who saw the ClientHello can make one (the Initial keys come
  from an ID that is on the wire): one such packet, and the client
  sent the rest of its handshake to an ID the server did not know.
  (2) The peer's `initial_source_connection_id` must be there and
  must be the ID of its Initial packets. It was not looked at. (3) A
  server's `original_destination_connection_id` must be there; only a
  wrong value closed. (4) A Retry that comes after an Initial packet
  of the server is discarded; only a second Retry was. The transport
  parameters are inside the TLS handshake and the first packet
  headers are not, so checks 2 and 3 are how an endpoint knows that
  nobody changed the IDs, or put a Retry in, on the way.
- **A key update waits for the handshake to be confirmed.** RFC 9001
  section 6.1: an endpoint MUST NOT start a key update before that.
  `requestKeyUpdate` asked only for 1-RTT write keys, and a client
  has those one flight earlier (it is confirmed by HANDSHAKE_DONE).
  It now returns `error.KeyUpdateBlocked` until the handshake is
  confirmed, and `canInitiateKeyUpdateAt` says false. An embedder
  that asks "as soon as the handshake is done" and treats
  `KeyUpdateBlocked` as "try again" needs no change. Found with the
  interop client, which asked that early: its very first 1-RTT packet
  was in key phase 1, and the runner's `keyupdate` test against a
  quic-go server failed 4 runs of 4.
- **A close during the handshake reaches the peer.** A
  CONNECTION_CLOSE went at one encryption level, and when 1-RTT write
  keys were there, that level was 1-RTT. A server has those keys as
  soon as its flight is built, and the client can read 1-RTT only
  with the whole flight: a client in the middle of the handshake could
  not read the server's close. It learned no error code and waited
  for its own timeout. The same for a server that did not have the
  client's Finished. Now the close goes into one datagram at every
  level the endpoint has write keys for (RFC 9000 section 10.2.3),
  and the close that is sent again in the closing state too. After
  the handshake is confirmed there is only 1-RTT, as before.
- **An application close in an Initial or Handshake packet carries no
  reason.** Such a close is sent as a transport close with
  APPLICATION_ERROR, and RFC 9000 section 10.2.3 says its Reason
  Phrase MUST be cleared. It went along when
  `reveal_close_reason_on_wire` was on.
- **A server made from a bare `Connection` sends
  `original_destination_connection_id`.** `setTransportParams` and
  `setInitialDcid` fill it in from the client's first Initial packet,
  in either order of the calls, when the embedder left it null. A
  client that follows RFC 9000 closes a handshake without it (this
  library's own did not check).
- **A handshake datagram is 1200 bytes at most.** Each packet of a
  coalesced datagram was capped at 1200 on its own, so the datagram
  could be much longer. Measured with 4096-byte send buffers: client
  Initial + Handshake + 1-RTT 1353 bytes, server Initial + Handshake
  1310, a Handshake packet with a DPLPMTUD probe behind it 2427. A
  path that carries less dropped them (an IPv6 path of the minimum
  MTU carries 1232 bytes), and an older test in this repository
  records a real path that did. The bundled loops use 1500-byte
  buffers, so they sent the 1353 and the 1310. Now the budget is for
  the datagram (RFC 9000 section 14.2): each packet gets what the
  ones in front of it left, of the size and of the
  anti-amplification allowance. A DPLPMTUD probe is alone in its
  datagram. On a path that carries 1252 bytes the server now has the
  handshake and the first stream data within 3 ms and nothing but
  probes is lost; before, the datagram with the client's Finished and
  that data was lost there, and each probe-sized copy of the data
  behind it.
- **A client's datagram with an Initial packet is exactly 1200
  bytes.** The padding was in the Initial packet, so a Handshake
  packet behind it made the datagram longer; and an Initial packet
  with only an ACK or a PING came out at 1201 bytes, which `poll`
  could not write into a 1200-byte buffer (it returned an error). The
  padding now belongs to the datagram.
- **A client's CONNECTION_CLOSE in an Initial packet reaches the
  server.** That packet was not padded (a server drops a datagram
  that begins with an Initial packet and is shorter than 1200 bytes)
  and did not carry the token of a Retry (RFC 9000 section 8.1.2:
  all Initial packets do).
- **Lost handshake data is sent again also when it does not fit
  whole.** A CRYPTO chunk in the retransmission queue was sent only
  if all of it fitted the packet, and nothing behind it was sent
  either. It is now cut to what fits.
- **A server with Retry on answers every legal client.** The Retry
  token had room for 45 bytes of client address and connection IDs.
  The client picks the length of its first Destination Connection ID
  (8 to 20 bytes), and an IPv6 address takes 23 bytes: with the
  default 8-byte server IDs an IPv6 client with a first ID above 14
  bytes got no Retry. The server dropped its Initial packets, and the
  client timed out. A server with 20-byte IDs could not answer an IPv6
  client at all. The token now holds a full address and two IDs of
  full length, and a compile-time check keeps it so. Test: a Retry
  round trip through `Server.feed` for each first ID length from 8 to
  20, with an IPv4 and an IPv6 client (6 of the 26 cases failed
  before), and one with 20-byte IDs on both ends.
- **A NEW_CONNECTION_ID frame that was lost is not issued again when
  the peer has retired that ID.** The loss path queued it again
  without a check. The ID was no longer ours, so the frame counted as
  a new issuance: with the peer's limit used up, that was
  `error.ConnectionIdLimitExceeded` out of `tick` or `handle`, and
  that ends a connection. Found the first time the interop client ran
  under 30% loss. The same for PATH_NEW_CONNECTION_ID.
- **A connection ID sequence number is used once.** The next number
  came from the IDs still in use, so after the peer retired the
  newest ID, the next ID got its number again (RFC 9000 section
  5.1.1; a peer may close for it, section 19.15).

### Measured, not changed

The first three come from the interop client, which ran the runner's
two handshake-loss tests for the first time in this release (30% loss
each way, 50 connections a run; two batches of 5 runs for each
server, so N = 10; there is no older number). Against an ngtcp2
server both tests passed 10 runs of 10. Every failed run was read in
its capture.

- **A client retries a silent handshake slowly, one datagram at a
  time.** A client that hears nothing sends again at 1, 3, 7 and 15 s:
  the first probe timeout of RFC 9002 (1 s), doubled each time, and
  one datagram for each (section 6.2.4 allows two). A quic-go server
  sends three datagrams, then waits for the client, and gives the
  connection up when 5 s pass with no packet from it (measured). So
  three lost datagrams in a row can end a handshake there. Against a
  quic-go server `handshakeloss` passed 5 runs of 10 and
  `handshakecorruption` 2 of 10. All 13 failed cells are this: the
  server heard nothing from the client for 6 to 15 s, or never again.
  In 9 the client's handshake then timed out. In 4 the server took
  the late ClientHello for a new connection, the download was good,
  and the runner counted 51 handshakes for 50 requests. A quic-go
  endpoint probes with two datagrams and starts at 200 ms (the same
  captures). This library's server answers each retry of a client at
  once, and it passes these tests (see "Tools and tests"). The cure
  for the client changes when every connection sends; it is not in
  this release.
- **A client whose ClientHello is acknowledged, and whose ServerHello
  is lost, can only wait.** It has nothing to send again, so its
  probe is a PING. A quiche server answers a PING with an ACK and
  nothing else, and a second copy of the ClientHello the same way
  (measured); it sends its ServerHello again on its own timer only,
  1, 5 and 21 s after the first. When those copies are lost too, the
  client's handshake timeout (30 s) comes first. Against a quiche
  server the two tests passed 8 runs of 10 and 8 of 10, and 3 of the
  4 failed cells are this. Nothing that this client could send would
  have changed them. (This library's own server takes such a PING as
  the peer's retry and sends its flight again, since 0.25.0.)
- **A Handshake packet that arrives before its keys is dropped.** The
  fourth failed cell with quiche. The server's Handshake packets
  arrived before its ServerHello (the copies of the ServerHello were
  lost until the one of 5 s). The client could not read them and did
  not keep them (RFC 9000 section 12.2 allows a receiver to keep such
  a packet), so at 5 s it had the keys and nothing to read with them.
  quiche's next copy (10 s) was lost, and the client's own probes
  came late: its first round-trip sample was 2 s on a 30 ms path,
  because the ACK that it got for its ClientHello was a copy sent 2 s
  after the first, and RFC 9002 section 5.3 does not correct a first
  sample. Its probes went at 11 s (lost) and 23 s (answered with an
  ACK only), and its handshake timed out at 30 s. (A late copy of an
  ACK is what made 0.25.0 take its own ACK repeat back; here a peer
  does it to us.)
- **A CONNECTION_CLOSE that is lost is in practice not sent again.**
  In the closing state a packet from the peer is answered with the
  close again only if two probe timeouts have passed since the last
  one, and the closing state ends after three. So one copy goes, and
  a second one only for a packet that arrives in the last third of
  the closing state. A peer that misses the copy waits for its own
  timeout. RFC 9000 section 10.2.1 asks for a limit on these answers
  and leaves the rate open. Found with a test of this release
  (`tests/e2e/handshake_close.zig`): it saw a second copy only when
  it gave the peer's packet inside that window. The policy is in
  `shouldRearmCloseRepeat` in `src/conn/lifecycle.zig`.
- **Remembered transport parameters limit the bytes of 0-RTT data,
  not the number of streams.** `setRememberedPeerTransportParams`
  gives the early streams their flow-control credit. The count of
  streams a client may open is not bounded by the remembered
  `initial_max_streams_bidi` and `initial_max_streams_uni` until the
  server's new parameters arrive (RFC 9000 section 7.4.1 wants the
  remembered limits kept). The interop client counts by hand. An
  embedder that opens 0-RTT streams must do the same.
- **Still open from 0.25.0, as written there:** the sent-packet
  tracker limits a fast, long path; reordering beyond the fixed
  thresholds is loss to every controller; an ACK in the handshake is
  said once (the repeat in the Handshake space alone, an experiment
  that the plan for this release allowed, is not in it); a probe
  timeout sends again what was in the oldest packet only.

### Tools and tests

- `tests/e2e/handshake_loss.zig`: every run now also checks the size
  of each datagram of both ends (none above 1200 bytes in the
  handshake but a DPLPMTUD probe, a probe alone, and exactly 1200
  where RFC 9000 section 14.1 wants it). The flight of a server with
  no loss, in datagrams: 1 of 1200 bytes with the small certificate
  (was 1 of 831), 3 of 1200, 1166 and 336 bytes with the wide one
  (was 1310, 1166 and 190), 6 with the largest.
- `tests/e2e/handshake_close.zig` (7 tests): a close in each phase of
  the handshake, from each end; the peer has the error code within one
  round trip.
- A Retry round trip through `Server.feed` for 26 cases (each first
  ID length from 8 to 20, an IPv4 and an IPv6 client); conformance
  tests for RFC 9000 sections 14.1 and 14.2 and for RFC 9001 section
  6.1; unit tests for the connection-ID rules at both ends.
- 51 mutants of the new rules, each killed by a test. One lived at
  first (the packets of one datagram did not share the
  anti-amplification allowance, and no test saw it); it has its test
  now.
- The interop client program runs `multiconnect`, so the runner's
  `handshakeloss` and `handshakecorruption` tests run in the client
  role for the first time; it sends its 0-RTT requests within the
  limits it remembers from the first connection; and the interop
  server drops a datagram that its Retry path cannot answer (it
  exited).
- Interop, local, quic-zig as the server, a quic-go client. `retry`:
  20 runs of 20 (4 of them with a first ID of 19 or 20 bytes; on
  0.25.0 exactly those runs failed). `handshakecorruption` and
  `handshakeloss`, 30% each way, 50 connections a run: 20 runs of 20
  and 19 of 20 on the code of this release, and a passing run takes
  37 and 42 s (medians; 0.25.0: 20 of 20 and 20 of 20, 40 and 41 s).
  A batch earlier in the work (after the change of the datagram
  size) had the same counts. Both failed runs were read, and neither
  is a stall: the simulator dropped every datagram of the server for
  one connection (its flight four times in 2.4 s in one run, seven
  times in 3.3 s in the other) inside the 5 s that a quic-go client
  waits.
- Interop, local, the wide matrix (15 tests) on the code of this
  release. quic-zig as the client against quic-go, ngtcp2 and quiche
  servers: 43 cells passed, none failed, 2 are not supported by the
  peer (0.25.0: 33 passed, 4 failed, 8 not supported, 6 of them by
  our client). `zerortt` now passes against all three (the runner saw
  0 bytes of 0-RTT data before, 10413 to 10417 now) and `keyupdate`
  against quic-go (see "A key update waits ..."); in a batch of their
  own the two tests passed 3 runs of 3 against each server. quic-zig
  as the server against the three clients: 41 passed, none failed, 4
  not supported by the peer.
- The numbers of the client role under loss are under "Measured, not
  changed". The interop simulator's rule "at most 3 losses in a row"
  is for a direction, not for a connection: datagrams of other
  connections take the turns that pass (measured; it matters when a
  failed run is read).

## [0.25.0] - 2026-10-04

"No stalls under stress": a connection must not stall, and must not
die, because packets were lost, damaged or many. **It has a security
fix: on every release before this one, one small datagram from anyone
who saw a packet of a connection ended that connection.** Six faults
in the handshake under loss are fixed (each is a rule of RFC 9002,
RFC 9001 or RFC 9000 that was missing), and more than 4096 packets in
flight no longer ends a connection. No API is removed or renamed, and
nothing changes on a path with no loss. Five more faults and limits
were found and measured and are not fixed here: they are under
"Measured, not changed", with one fix that was tried and taken back.
Verified toolchain: 0.17.0.

### Security

- **One datagram could end a connection.** `Connection.handle`
  returned an error for a packet whose header did not parse
  (`error.ConnIdTooLong`, `error.DeclaredLengthExceedsInput`,
  `error.PayloadTooShort`, `error.InsufficientBytes`,
  `error.InsufficientCiphertext`). An error from `handle` is fatal:
  `Server.feed` closes the connection with INTERNAL_ERROR, and the
  bundled client loop returns. Nothing had authenticated the bytes
  those errors were about. So a datagram of 12 bytes (the first byte
  of a short header, the connection ID, three more bytes) from anyone
  who saw one packet of a connection ended it. So did a datagram that
  a small receive buffer cut short, and one changed bit in a length
  field. **Every release before this one has it** (the code is from
  2026-05-04, before v0.1.0-pre.1). Now every failure of an open is a
  dropped packet (qlog `packet_dropped`, `header_decode_failure` or
  `decryption_failure`). A datagram too short to reach the AEAD is not
  counted against the integrity limit. Found by a sweep in
  `tests/e2e/handshake_loss.zig` (one changed byte in the first 51
  bytes, or a cut, in each of the first four datagrams of each end):
  75 of 2448 cases with a changed byte ended the connection before.
  The interop runner's `handshakecorruption` test could not find it:
  the datagrams it corrupts do not reach the endpoints (measured: no
  packet that failed to decrypt, at either end, in a run with 336
  corrupted datagrams; the UDP checksum removes them).
- **A server took the client's connection ID from a datagram that did
  not authenticate.** It read the ID from the header of the first
  datagram and kept it. A ClientHello with a damaged Source
  Connection ID Length was dropped, as it must be, but the server then
  sent every packet to the wrong ID, and the client could read none
  of the 1-RTT packets (found by the same sweep). The server now takes
  the ID from the first Initial packet that authenticates (RFC 9000
  section 7.2), and from no later one.

### Fixed

- **A server sends its handshake flight again when the client
  retries.** (RFC 9002 section 6.2.3.) A flight that nobody
  acknowledged gives no RTT sample, so the server's probe timeout was
  1 s and then doubled: the flight went out at 0, 1, 3, 7 and 15 s. A
  client that asked again in between (its ClientHello once more, or a
  PING) got an ACK and nothing else. Measured with a quic-go client
  through the interop runner's 30% loss: the client asked seven times
  and gave up at 10 s. Now an Initial or Handshake packet that asks
  for an answer and brings no new CRYPTO data is taken for what it is,
  the peer's retry: every unacknowledged CRYPTO byte of both handshake
  spaces goes out again at once. Both roles do it. It is bounded by
  the anti-amplification limit (unchanged), by 8 copies for one
  connection (`loss.max_early_handshake_retransmits`; measured: the
  gain ends at 3 in a network that never loses 4 in a row, and an
  outage of 100 ms needs 7), and by one copy for each received
  datagram. A packet with a number we already have is the network's
  duplicate, not a retry. It is not a loss and not a probe timeout:
  no loss counter, no qlog loss event, the backoff untouched.
- **A client with nothing in flight keeps probing.** (RFC 9002
  sections 6.2.2.1 and 6.2.1.) A server may send 3 times what it
  received until it has validated the client's address. With a
  certificate of 5.4 KB it is at that limit with a part of its flight
  unsent. If the client's ACKs were then lost, the server could send
  nothing, the client had nothing in flight and so no timer, and both
  ends were silent until the handshake timeout. Reproduced in
  `tests/e2e/handshake_loss.zig`. The client now keeps a probe timer
  until an ACK arrives in a Handshake packet; the probe is a PING in a
  Handshake packet if it has the keys, else in an Initial packet. And
  a client no longer resets its backoff on an ACK in an Initial
  packet, so the probes come each twice as late as the one before.
- **A client that still sends its Finished gets HANDSHAKE_DONE again
  at once.** A server discards its Handshake keys the moment the
  handshake completes, so it can neither open nor acknowledge the
  client's later Handshake packets: the client learns that the
  handshake is confirmed from HANDSHAKE_DONE alone. When that frame
  was lost, the server ignored the client's repeated Finished and
  sent HANDSHAKE_DONE again only at its own probe timeout (measured:
  at 2, 10 and 43 s, all lost; the client gave up at 53 s). A
  Handshake packet that arrives after the discard now queues the
  frame again: at most 8 times, and never after the client
  acknowledged one.
- **No probe timer for 1-RTT data until the handshake is confirmed.**
  (RFC 9002 section 6.2.1, a MUST.) A server with 1-RTT data in its
  first flight (the interop server sends NEW_CONNECTION_ID there)
  probed it a second later, while the client still had no 1-RTT keys.
  Measured in a failed `handshakecorruption` run: twice that useless
  probe was the one datagram the network let through between two runs
  of three corrupted ones. "Confirmed" is the moment the Handshake
  keys are discarded (a server: when the handshake completes; a
  client: at HANDSHAKE_DONE). A connection whose handshake does not
  run over packets (keys installed by hand) is not affected.
- **Initial keys go when the standard says.** (RFC 9001 section
  4.9.1, a MUST for both ends.) Both ends kept their Initial keys, and
  sent Initial packets, until the handshake was done. Now the server
  discards them when a Handshake packet from the client authenticates,
  and the client when it first sends a Handshake packet. This matters
  because each end puts its Initial packet first in a datagram, and a
  peer that cannot open the first packet may drop the whole datagram.
  Measured with a quiche client through the interop runner's 30%
  loss, on the code with the first fix above and without this one: 3
  runs of 5 passed, and the cell failed in CI. In the failed runs,
  every answer of the server to the client's Handshake PING began
  with a ServerHello that the client could not read any more; the
  client dropped each datagram whole and gave up after 32 and 38 s.
- **A packet that is not opened no longer hides the packets behind
  it.** (RFC 9000 section 12.2, a MUST.) A long-header packet with no
  keys for its level, or with a tag that did not verify, took the
  rest of its datagram with it: a Handshake packet behind an Initial
  packet, a 1-RTT packet behind a Handshake packet. The receiver now
  skips that one packet (its length is in the unprotected part of the
  header) and reads the next.
- **More than 4096 packets in flight no longer ends the connection.**
  The sent-packet tracker of a path holds 4096 packets. When it was
  full, `poll` returned `error.TooManyInFlight`, after the packet was
  built and its frames had left their queues, and an embedder's loop
  ends a connection on a `poll` error. 4096 packets is a window of
  4.9 MB in 1200-byte packets and of 0.4 MB in 100-byte packets.
  Reproduced two ways: 10,000 small packets with no ACKs, and a bench
  cell at 1 Gbit/s with a 100 ms round trip. A full tracker is now
  back-pressure, like a full congestion window: no ack-eliciting
  packet is built (probes included) until an ACK, a loss or a probe
  timeout frees a slot. ACKs and CONNECTION_CLOSE still go, and
  `nextTimerDeadline` gives no pacing deadline in that state. The
  capacity is unchanged, and it is now the most packets a path keeps
  in flight; see "Measured, not changed" below.
- **Discarding the keys of a handshake space drops what the space
  still held.** CRYPTO data that waited for retransmission when its
  keys went stayed in the queue for the life of the connection, and
  `canSend` then said "yes" while `poll` had nothing. The Initial
  space also kept its sent packets (they counted in
  `congestionBytesInFlight`). Both spaces now drop their sent packets,
  their unacknowledged and their queued CRYPTO data, and their probe
  state at the discard.

### Measured, not changed

- **The sent-packet tracker limits a fast, long path.** New bench cell
  `impairment_fat_window_1gbit_rtt100ms` (1 Gbit/s, 100 ms round trip,
  16 streams): 272 vMbps with the shipped 4096 slots, 448 with 8192,
  479 with 16384, 157 with 2048. More slots cost memory for every
  connection; that is its own decision. Until this release the cell
  did not finish (`error: TooManyInFlight`).
- **Reordering beyond the fixed loss thresholds is loss to every
  controller.** The bench cell `impairment_reorder10pct` drops
  nothing; it holds 10% of the packets back by 5 ms on a 2 ms path.
  The thresholds of RFC 9002 (3 packets, 9/8 of the RTT) declare each
  of them lost: 10.4% of the packets, all of which arrived. Over 24
  seeds: CUBIC 4.2 to 4.6 s and NewReno 4.1 to 4.4 s in every run; BBR
  0.1 to 3.4 s (median 0.15 s), fast only while its startup lasts.
  With thresholds wide enough for that reordering (a temporary edit)
  the same seeds take 0.2 to 0.3 s with BBR and 0.4 to 0.5 s with
  CUBIC. The cell's one committed seed (106 ms) hid this. The cure is
  a feature (find out that a "lost" packet arrived, widen the
  thresholds, take back the controller's reaction); it is not in this
  release. The notes are at the cell in `bench/e2e_main.zig` and at
  `packet_threshold` in `src/conn/loss_recovery.zig`.
- **An ACK in the handshake is said once, and it stays that way.** A
  peer whose copy of our ACK was lost does not learn what we have
  until it sends something new. Repeating the ACK with each probe
  looked like the cure, was built, and was taken back the same day:
  for that peer the repeat is the first acknowledgement of its
  packet, it takes its round-trip sample from it, and the first
  sample is not corrected for the ACK delay (RFC 9002 section 5.3).
  Measured with a quiche client: its estimate went to 1048 ms on a
  38 ms path, its close took 10.5 s, and 1 run of 4 passed where 9 of
  10 pass without the repeat. The note is at `firePtoAtLevel` in
  `src/Connection/loss.zig`.
- **A Retry token has no room for a long first connection ID.** The
  token is 96 bytes, and its three bound fields (client address,
  original Destination Connection ID, retry Source Connection ID)
  share 45 of them. For a client with an IPv6 address and a server
  with the default 8-byte connection ID, the client's first
  Destination Connection ID may be 14 bytes at most; RFC 9000 allows
  20, and quic-go picks 8 to 20 at random. A `Server` with
  `retry_token_key` set drops the Initial packet of such a client (no
  Retry, no error), and the client times out. Read in
  `src/Server/dos.zig`; measured through the interop endpoint, which
  has its own copy of the logic and room for 18 bytes: the `retry`
  cell with a quic-go client fails exactly in the runs with a 19 or
  20 byte ID (2 of 6 on this release, 2 of 14 on 0.24.1). The fix is
  a larger token, which changes the size of `quic.RetryToken`; it is
  not in this release.
- **One handshake datagram can be larger than 1200 bytes.** Each
  coalesced packet is capped at the MTU on its own, so Initial +
  Handshake together reached 1310 bytes in a test with a wide
  certificate (the bundled loops pass 1500-byte buffers). And a
  server does not pad a datagram with an ack-eliciting Initial packet
  to 1200 bytes (RFC 9000 section 14.1 says it must). Both are
  recorded, not changed.
- **A probe timeout sends again what was in the oldest packet only.**
  RFC 9002 section 6.2.4 allows two packets. With two small packets
  in flight the probes take turns.

### Tools and tests

- `zig build test -Dtest-filter='text'` runs only the tests whose name
  contains the text (a development option; CI does not pass it).
- `zig build bench-e2e -- --cell NAME --seed N --sweep K`: one cell,
  a chosen seed, or K seeds with the minimum, the median and the
  maximum. One seed is one draw.
- `tests/e2e/handshake_loss.zig`: a real server and client over a
  network that the test controls one datagram at a time (18 tests).
  It can lose a datagram, deliver it twice, change one byte of it or
  cut it short. Every run also checks, from the outside, that the
  server sends at most 3 times what it was given before it validates
  the address.
- `tests/e2e/unauthenticated_datagram.zig` (3 tests): damaged copies
  of real packets, and packets that no key opens, given to both ends
  of an open connection.
- `src/Connection/_tests_handshake_recovery.zig` (17 unit tests); two
  new fuzz harnesses (the send path with a tracker of 4 to 12 slots;
  `handle` with bytes that do not authenticate), so `rc-fuzz` now
  counts 43 sites; and 67 mutants of the new rules, each killed by a
  test.
- Interop, local, quic-zig as the server, 30% loss or corruption each
  way, 50 connections a run. A quic-go client: `handshakecorruption`
  passed 13 runs of 20 and `handshakeloss` 12 of 20 on 0.24.1; 20 of
  20 and 20 of 20 on this release, and a passing run takes 40 to 41 s
  where it took 75 to 78 s (medians). An ngtcp2 client: 5 of 5 and 5
  of 5, at 55 to 57 s (0.24.1: 5 of 5 and 4 of 5, at 80 to 86 s). A
  quiche client: 14 of 15 and 16 of 20 (0.24.1: 5 of 5 and 4 of 5).
  With quiche this release is not shown to be better. (The tagged
  text said "11 of 12" for the second cell: 8 more runs after the tag
  had 3 failures.)
- Every failed run on the way was read in its capture (the
  simulator's verdict for each datagram, the client's log). Three
  times it showed a stall of ours, and each became a fix above. Once
  it showed that a fix of ours was wrong, and that fix is gone (see
  "An ACK in the handshake is said once"). The five quiche runs that
  still failed were read too. In one the server never got a
  ClientHello (all five copies lost). In one every Handshake packet
  of the client was lost. In three the client's Finished was lost
  three times in 42 s, and each probe of the client in between was
  lost or the server's ACK for it was; one ACK more would have told
  the client at once that its Finished was lost, and that is the
  repeat that was tried and taken back. A run can always fail in the
  first two ways. The third is open.
- Interop in CI, the wide matrix (16 tests, three clients, quic-zig
  as the server) on the code of this release, four runs: every cell
  that the peers support passed in two; one failed `retry` with
  quic-go (see "A Retry token has no room ..." above); one failed
  `handshakeloss` with quiche.
- Interop, local, quic-zig as the client, the same tests against
  three servers: 33 cells passed. `zerortt` fails against all three
  and `keyupdate` against quic-go, both the same on 0.24.1 (measured
  for `keyupdate`: 4 runs of 4 on each). The interop client program
  does not implement the two handshake-loss cells, so the client's
  handshake under loss is held by `tests/e2e/handshake_loss.zig`
  alone.

## [0.24.1] - 2026-10-03

A build fix, with no change to the library code: `src/` is the same as
in 0.24.0. The package now accepts the `optimize` build option that
its own documentation told consumers to pass. Without it, an
application that followed the docs got quic-zig and BoringSSL compiled
in Debug inside its release build. **If you depend on quic-zig, at any
version, check your build**: `zig build --verbose`, and read the `-O`
flag in front of `-Mquic=`. Verified toolchain: 0.17.0.

### Fixed

- **The package accepts `optimize`.** `b.dependency("quic", .{ .target
  = target, .optimize = optimize })` now builds quic-zig in Debug for
  Debug and in ReleaseSafe for ReleaseSafe. ReleaseFast and
  ReleaseSmall stop the build, with a message that says what to pass
  (this package does not compile its network parser without safety
  checks). `release` works as before, and a release asked for by
  either option is a release. `tools/consumer-smoke/check-modes.sh`
  is the contract: both spellings, three application modes, no
  compilation; CI runs it. Five mutants of the mode logic, the 0.24.0
  behaviour among them, each fail the case they should.
- **The documented way to depend on this package built it in Debug.**
  README.md and EMBEDDING.md told consumers to pass
  `.optimize = optimize` to `b.dependency("quic", ...)`. Through
  0.24.0 the package had no `optimize` option: it builds in Debug or
  in ReleaseSafe, so its option was the boolean `release` alone. Zig
  reports the unknown option
  (`error: invalid option: "optimize"`, with a stack trace) and goes
  on, and quic-zig then takes its default. Measured on the 0.24.0
  tarball with `zig build --verbose -Doptimize=ReleaseSafe` in a fresh
  consumer: `-Osafe` for the application's module, `-Odebug` for
  `quic` and for `boringssl`. So an application that followed the
  docs shipped a Debug QUIC stack and Debug BoringSSL inside its
  release build, unless it was built with `zig build --release`. The
  snippet in the docs is `.release = optimize != .debug` (`-Osafe` for
  all three, no error, and right for every release of quic-zig and
  every application mode). The in-tree consumer smoke had the wrong
  line too, and printed that error in every CI run of its step, which
  passed; it now stops the build when the `quic` or the `boringssl`
  module is not in the mode the build asked for. Found by building a
  fresh consumer of the published 0.24.0 tarball and reading its
  whole output, not its last line. If you depend on quic-zig, check
  your own build: `zig build --verbose`, and read the `-O` flag in
  front of `-Mquic=`.

### CI and tests

- **Measured and taken back: an interop server stream window of 20.**
  0.24.0 took that window from 1000 to 100 and `server x quiche x
  multiplexing` from 0 of 10 runs to 13 of 20. What is left at 100 is
  loss: quiche's test client sends one request per packet, a burst of
  up to 100 of them overflows the 25-packet queue of the runner's
  network simulator (3 to 6% of the client's packets lost), its
  congestion window shrinks, and it drops what a short request write
  did not take. With a window of 20 a burst fits the queue: 15 local
  runs of 15 passed, and in each one every packet the client sent
  arrived. That was committed (`4017b1c`), and the wide matrix on it
  failed: `zerortt` for all three clients, "Client sent too much data
  in 1-RTT packets" (`pairs=3 cells=48 succeeded=40 failed=3`). The
  runner's 0-RTT test sends 40 requests before the handshake is done,
  and a client can open only as many 0-RTT streams as the window it
  remembers. The window is 100 again, where that matrix has no failed
  cell (`succeeded=43 failed=0`). The runs that made 20 look right
  were multiplexing runs only; the matrix was the check, and `main`
  did not move before it was read. `interop/qns_endpoint.zig`
  (`endpoint_bidi_stream_limit`) has the three windows side by side,
  and what could serve both tests (a window per test case, or 40):
  not measured.
- **`server x quic-go x handshakecorruption` fails about 2 runs in 5,
  and did so before this release.** The wide matrix (16 tests) ran
  green on the 0.24.0 code once (run 37149418254). A second run on the
  same server code (run 37155539640) had one failed cell, this one:
  `succeeded=42 failed=1`. The test makes 50 connections through a
  link that damages 30% of the packets in each direction, in bursts of
  three, and quic-go's client gives up on one of them ("handshake did
  not complete in time", or "no recent network activity"). On a
  developer machine the cell failed 2 runs of 5 on the 0.24.0 code and
  2 runs of 5 on the 0.23.0 code, with the same two messages. So the
  release did not cause it, and one green run of that matrix did not
  mean the cell was sound. It belongs with the long tail the loss and
  reorder bench cells show (recovery that sometimes takes far too
  long), and it is the cheapest way to see that fault: 75 s per run,
  2 failures in 5. It is not put in the wrapper's `--flaky` class: that
  class is for a fault that is not ours, and this one may be. The
  weekly matrix does not run this test.
- **Measured and not adopted: an interop server loop that empties its
  socket before it sends.** The loop reads one datagram per pass, so
  it answers a client that sends one request per packet with one
  response per packet (2021 datagrams for 2000 responses). A scratch
  build that reads up to 64 datagrams per pass sent 160, and 289 in
  place of 915 to the quic-go client. It made no clear difference to
  the quiche cell at a window of 100 (16 of 20 runs against 13 of 20).
  The library's own `runUdpServer` already receives in batches. Every
  server-role cell runs this loop, so the change waits for a wide
  matrix run of its own.

## [0.24.0] - 2026-10-03

The stream-window release. A connection could carry 4096 streams of
each type over its whole life; now it carries any number, a window at
a time. `initial_max_streams_bidi` / `_uni` is the number of streams
the peer may have open at once, and an id comes back when a stream is
fully closed. It is a breaking release: in wire behaviour (when
MAX_STREAMS is sent and how far it goes), in what the two parameters
mean, and in two names (`Connection.max_streams_per_connection` is
removed; `streamStopSending` can refuse). Read "Stream limits are a
window" in EMBEDDING.md before you move a pin. Three kinds of code need
a change: code that opens more streams than the window in one burst
and does not retry, code that leaves a peer's stream unanswered and
unfinished, and code that refuses a stream with STOP_SENDING alone.
Eight stream faults are fixed on the way, and the interop cell that
had failed in every run for months (`server x quiche x multiplexing`)
now passes 6 runs in 10, which is what that client does against the
other servers. Verified toolchain: 0.17.0 (Linux x86-64 and aarch64,
macOS, and Windows in CI; macOS locally).

### Fixed

- **A lost MAX_STREAMS frame was never sent again.** RFC 9000 §13.3
  says the current stream limit is sent again when the packet with the
  most recent MAX_STREAMS is lost. The loss path asked
  `queueMaxStreams` to queue the lost value, and that function ignores
  a value that does not raise the limit, which the lost value never
  does: the limit was raised when the frame was first queued. The path
  also reported a requeue that had not happened, so a PTO whose only
  content was that frame sent no probe at all. The next grant usually
  hid the loss, because the limit doubled as the peer opened streams;
  the last grant before the 4096 cap could not be recovered. Found by
  reading the code on the way to "credit on close", where the same
  loss would stop a peer that is out of stream credit for good.
- **`openUni` could re-open the id of a stream that had finished.**
  `openBidi` refused a reaped id; `openUni` had no such check and made
  a fresh stream at offset 0. A peer drops frames for a stream it has
  closed (RFC 9000 §3.2), so data written there was lost with no
  error. Both now return `StreamAlreadyOpen`.
- **A local bidirectional stream at index 4096 or above was never
  reclaimed.** Its closed state was one bit in a 4096-bit set, so an id
  past the set kept its terminal `Stream` until the connection ended.
  Reachable only before the peer's transport parameters arrived (the
  negotiated limit was capped at 4096 then).
- **A stream the application stopped reading never ended on our
  side.** `streamStopSending` queued the frame and did nothing else. A
  peer answers STOP_SENDING with RESET_STREAM only while it still has
  bytes to send; a peer whose bytes are all acknowledged answers with
  nothing (RFC 9000 §3.1). So a refused stream whose request was small
  stayed open here for the life of the connection, with its unread
  bytes charged to the connection window. Now the connection reads
  such a stream to its end and drops the bytes (from the next `tick`,
  and as data arrives), so its receive half ends by itself. Under the
  window rule this is not optional: a stream that never ends keeps its
  place in the stream window. See "Changed" for what the call refuses
  now.
- **`quic.app.Driver` refused a bidirectional stream by half.** A full
  table (or no stream hooks) sent STOP_SENDING and left our own half of
  the stream open. The Driver now also sends RESET_STREAM, which ends
  the stream on both sides and is the refusal the peer is sure to see.
  Measured with the refusal test: with STOP_SENDING alone, forty
  refused requests through a window of four never finish.
- **Bytes of a stream the peer reset were never given back to the
  connection window.** MAX_DATA moved forward only as the application
  read. What the peer had sent on a stream it then reset (read or not,
  arrived or not: the final size counts) stayed charged for good, so
  every such stream made the connection window smaller, and a
  connection that lived long enough stalled at `initial_max_data`. The
  unread part of the final size is now credited when the RESET_STREAM
  arrives.
- **STOP_SENDING and MAX_STREAM_DATA were not checked against the
  stream they name** (RFC 9000 §19.5, §19.10, §3.2).
  - For a receive-only stream (a unidirectional stream of the peer),
    STOP_SENDING reset a send half that does not exist, which queued a
    RESET_STREAM on a stream we cannot send on. It is
    STREAM_STATE_ERROR now, as §19.5 requires.
  - For a stream of ours that was never opened, both frames were
    dropped. Both are STREAM_STATE_ERROR now.
  - For a bidirectional stream of the peer that had not been seen yet,
    both frames were dropped: the STOP_SENDING was never answered, and
    the credit of the MAX_STREAM_DATA was lost. Both create the stream
    now (§3.2), under the stream limit.
- **RESET_STREAM for a stream that was already finished.** A reset
  (the application's, or the one a late STOP_SENDING asks for) after
  every byte and the FIN were acknowledged took the send half out of
  its terminal state, sent a RESET_STREAM for a stream the peer had
  finished with, and made the stream wait for one more acknowledgement
  before it could be reaped. "Data Recvd" is terminal (§3.1): the
  reset is a no-op there.

### Changed (BREAKING)

- **No lifetime stream cap.** A connection carried at most 4096
  streams of each type over its whole life: our MAX_STREAMS never rose
  past 4096, and a larger limit from the peer was clamped to 4096.
  From stream 4097 on, every open returned `StreamLimitExceeded`, for
  good, on a connection that otherwise looked healthy. That cap is
  gone. Together with the window rule below, a connection now carries
  any number of streams (up to the wire's 2^60), a window's worth at a
  time.
  - `Connection.max_streams_per_connection` is REMOVED, not given a new
    meaning. Code that names it stops compiling, and that is the
    signal: logic built on it (count the streams, retire the
    connection before 4096) is no longer needed and should be deleted.
  - `Connection.max_concurrent_streams_per_kind` (4096) is the new
    name for what the number still bounds: the largest
    `initial_max_streams_bidi` / `initial_max_streams_uni` you may
    configure, which is the most streams of one type a peer can have
    open at once. A larger value is still `error.InvalidValue`.
  - A limit the PEER grants, in its transport parameters or in
    MAX_STREAMS, is taken as sent (the only ceiling is the stream id
    space).
  - `Connection.queueMaxStreams` (a manual grant; nothing needs it)
    is bounded to `max_concurrent_streams_per_kind` ahead of the
    streams that have closed.
  - `StreamLimitExceeded` is always temporary now.
  - EMBEDDING.md: "Stream limits are lifetime limits" is replaced by
    "Stream limits are a window".
- **The stream limit is a window, and stream credit comes back when a
  stream is closed (wire behaviour).** `initial_max_streams_bidi` /
  `_uni` is now the number of streams the peer may have open AT ONCE.
  The limit we advertise is that window plus the number of the peer's
  streams that are fully closed here. MAX_STREAMS goes out when half a
  window of credit has built up, and at once when the peer has used
  every id it has or says STREAMS_BLOCKED (RFC 9000 §4.6).
  - Before, the limit DOUBLED. When the receive side of a peer stream
    ended and the peer had used a quarter of its ids, the limit grew by
    `max(16, limit)`. A limit of 1 was 17 after the first stream, so
    the parameter did not bound concurrency, and a stream table sized
    to it could overflow.
  - "Closed" means reaped. For a bidirectional stream both directions
    are finished: the peer's data is read to its end, and our side is
    finished and acknowledged (or reset). A peer-opened bidirectional
    stream that the application never answers and never finishes keeps
    its place in the window for the life of the connection.
  - The cost: a request/reply stream gives its id back two round trips
    after it opens (request and reply, then the acknowledgement and
    the credit). A window of W carries about W / (2 x RTT) such streams
    per second. Measured with the new `churn` bench cells on a 30 ms
    round trip: 16.6, 66.2 and 221.5 per second for windows of 1, 4
    and 16.
  - Removed with the old rule: the public constants
    `Connection.min_stream_credit_return_batch` and
    `Connection.stream_credit_return_divisor`, and the field
    `Stream.stream_count_credit_returned`.

### Changed

- **`Connection.streamStopSending` can refuse.** It always returned
  success and queued a frame, for any id. It now returns
  `StreamNotReadable` for a unidirectional stream of ours and
  `StreamNotFound` for a stream the peer has not opened or that is
  already closed, and queues nothing: each of those frames would be a
  STREAM_STATE_ERROR on the peer's side, which closes the connection.
  It is a no-op for a receive half that has already ended. For a stream
  the peer opened by skipping it (open, reported, no data yet) the call
  records the refusal, so data that arrives later is dropped. Callers
  that use `catch {}` need no change.
- **`Connection.handleMaxStreamData` returns `Error!void`** (it can
  create a stream now).
- **Removed: the `quic.conn.flow_control` bookkeeping types**
  (`DataWindow`, `ConnectionData`, `StreamData`, `StreamCount`), their
  fuzz harness, and the `flow_control_credit_update` microbenchmark.
  `Connection` never used them; see "CI and tests". The namespace and
  its `Error` set stay (the set is part of `Connection.Error`).
- **Closed-stream memory is no longer indexed by stream id.** The three
  fixed 4096-bit sets that recorded which streams had been reaped are
  gone. Each of the four stream-id spaces (peer or local, bidi or uni)
  is now a `conn.stream_id_space.StreamIdSpace`: the highest id used,
  plus a short list of the lower ids that were skipped and not used
  yet. An id below the high-water mark that is not live and was not
  skipped is closed, at any index. `Connection` is 1,360 bytes smaller
  (156,040 to 154,680 in Debug). This is what let the lifetime stream
  cap go.
- **New error `TooManySkippedStreamIds`.** `openBidi(id)` /
  `openUni(id)` may name ids out of order. Each separate run of
  skipped lower ids is remembered until it is opened, and the
  connection keeps at most `Connection.max_local_skipped_stream_ranges`
  (64) runs; one more out-of-order open fails with this error.
  `openNextBidi` / `openNextUni` never skip. Before, any number of
  scattered ids below 4096 could be opened.
- Removed the `Connection.recordPeerStreamOpenOrClose` thunk
  (internal scaffolding with no caller outside the library). The
  fields `local_max_streams_*`, `peer_max_streams_*`,
  `peer_opened_streams_*`, `local_opened_streams_*` are now
  `peer_*_ids.limit`, `local_*_ids.limit`, `peer_*_ids.opened`,
  `local_*_ids.opened`.

### CI and tests

- **Ten RFC conformance tests tested code that no connection runs.**
  The §4.1, §4.2 and §4.6 tests in
  `tests/conformance/rfc9000_streams_flow.zig` drove
  `quic.conn.flow_control`, a set of bookkeeping types with the right
  names and the right rules that `Connection` never called (it keeps
  its own counters). Their comments said `Connection` used them. They
  now drive a real `Connection` pair: frames are sealed and injected,
  and the assertions read the connection's counters and close events.
  Seven mutants of the real flow-control code are each killed by the
  rewritten test for their rule. For three of them (a stale MAX_DATA,
  MAX_STREAM_DATA or MAX_STREAMS that LOWERS a limit) that test is the
  only one in `zig build test` that fails: before, nothing did.
  Six new conformance tests cover §19.5, §19.10, §3.2 and the terminal
  state of §3.1.
- **One connection, 20,000 streams of each type, each way.** The test
  that pinned the lifetime cap (4096 requests, then a refusal that
  waiting did not cure) is now the test that there is none:
  `tests/e2e/app_driver.zig` runs 20,000 requests and 20,000 one-way
  streams on one connection through the app driver, asked by the
  client and then by the server; `tests/e2e/stream_window.zig` does
  the same on bare `Connection`s through a window of 100, with every
  7th datagram from the answering side delivered 40 iterations late,
  so that replies arrive for streams that are finished and reaped
  (6,678 late datagrams, all ignored as RFC 9000 §3.2 says). Every
  build mode runs those counts. At first a Debug build needed 24 s for
  the end-to-end suite (4 s before), and a profile showed why:
  `std.testing.allocator` records a stack trace for each allocation,
  and in a Debug build that cost about 100 times everything else these
  loops do. The stream tests now count leaks with
  `tests/e2e/common.zig` `LeakCounter` (no traces; mutation-checked,
  with a library that leaks every reaped stream among the mutants), and
  keep one short run of the same paths on `std.testing.allocator` for
  what a counter cannot see. The Debug suite takes 8.4 s, the release
  suite 0.8 s.
- **Stream-window tests at three levels.** End to end
  (`tests/e2e/stream_window.zig`, a real `Server` / `Client` pair):
  the live peer streams never pass a window of 1, 2, 16 or 100, in
  either direction, for either stream type, while a greedy peer still
  fills it; and with the first copy of every MAX_STREAMS frame lost,
  2,000 streams through a window of 1 still finish. Through the app
  driver: a stream table the size of the window never refuses a
  stream. And a fuzz harness (`fuzz: Connection stream window ...`),
  the first one that calls `tick`: frames in any order, reads, replies
  and ticks, with "no credit is owed" checked after every operation.
  Writing that invariant down found a gap before the harness had run
  once: credit held back for batching was not sent when the peer then
  used its last id.
- **Bench: `churn` cells, and two faults in the bench harness.**
  `zig build bench-e2e -- --scenario churn` runs 2,000 request/reply
  streams through windows of 1, 4 and 16 in virtual time
  (`bench-compare` knows the new kind). They were the first cells where
  the server sends more than it receives, and the first to run longer
  than 30 virtual seconds, and each property exposed a fault in
  `bench/e2e/harness.zig`, whose handshake is a shortcut without
  packets: the server stayed under the anti-amplification limit for
  the whole run (3 bytes out for each byte in), and its handshake was
  never confirmed, so the 30 s handshake backstop closed it. Neither
  touched the older cells, where the client sends the data; all 14 are
  byte-identical except `impairment_bottleneck_10mbit_mux8`, which no
  longer carries the two MAX_STREAMS frames the old rule sent for its
  eight streams (they are never answered, so under the window rule no
  credit is due): one datagram fewer.
- **Two things the benchmarks cannot say, now written where they are
  run.** `goodput_bulk_64mib` moves by about 4% with code position
  alone (no-op instructions in a branch that never runs; note in
  `bench/e2e_main.zig`). And the loss and reorder cells have a long
  tail that one seed cannot show: over 12 seeds
  `impairment_reorder10pct` took about 100 to 280 ms, but more than a
  second in 4 of 24 runs (note on `PairOptions.server_path_validated`).
  `bench-compare` also no longer reports every `fairness` cell as
  absent from the new report.
- **Both interop workflows ran zero tests in CI and showed green — the
  quic-go release gate from its first run.** The pinned
  quic-interop-runner names the simulator's interfaces with
  `interface_name` in its `docker-compose.yml`, which needs Docker
  Engine 28.1 or later. GitHub's ubuntu image carries 28.0.4, so in CI
  no container ever started. The runner's compliance preflight
  reported that as "not compliant", skipped the pair, and exited 0.
  - `quic-go-interop.yml`, one of the five release gates: 111 runs
    from 2026-07-05 to 2026-10-03. 96 reached the runner, every one of
    those skipped its only pair, and 93 showed green. Every release
    tagged in that window counted this gate as passed, 0.23.0
    included.
  - `interop.yml`, the advisory weekly matrix: its job failed in each
    of its 21 scheduled runs since 2026-05-10, and `continue-on-error`
    showed each as a green run. Every run whose log still exists
    (2026-07-12 on) ran zero tests, including the run dispatched on
    the commit that made BBRv3 the default.

  Two earlier entries in this file cite a CI interop result and are
  wrong as written: 0.11.0 ("validated by the blocking quic-go interop
  gate and the weekly matrix", for CUBIC, pacing, and HyStart++ as
  defaults) and 0.16.0 ("plus the full cross-implementation interop
  matrix", for BBRv3 as the default). 0.7.3 added
  `--assume-compliant quic-go` for what it called a stale preflight;
  the preflight was not stale, the Engine was too old. Interop runs on
  a developer machine were real all along, because the Engine there
  was newer.

  The repair has three parts. Both workflows install a current Engine,
  as the runner's own workflow does, and no longer skip the preflight.
  `tools/external_interop.zig` refuses to start the runner on an
  Engine that is too old, and prints what `docker compose` said when a
  preflight fails. And it reads the runner's result file after the run
  and prints one `interop evidence:` line: a skipped cell, a failed
  cell (a failed measurement too, which the runner's exit code does
  not count), or a run in which nothing succeeded fails the step, and
  `--strict` (the release gate) also refuses `unsupported`.
  `continue-on-error` is gone from the matrix. The first repair
  attempt added a guard that counted result cells; the runner writes a
  skipped pair as cells with a null result, so that guard could not
  fail either. The rules now in the wrapper are tested against the
  0.23.0 gate's own result file and the first real matrix result, and
  17 mutants of them all die (a mutant that does not compile is not
  counted as killed).

  Once tests ran in CI, two more things showed. The CI machine has no
  `tshark`, so the wrapper used its fallback, `tshark` in a Docker
  image; the runner's Python library then loses track of the
  `docker run` process and the runner stops with
  `TSharkCrashException`. Both workflows now install a host `tshark`
  (4.5 or later, from the Wireshark PPA), as the runner's own workflow
  does. And the wrapper now deletes an old result file before a run,
  and checks that the runner's exit code and the result file agree.

- **First real interop results, on the code of the 0.23.0 tag** (only
  CI files, the wrapper tool, docs, and comments differ from the tag):
  - Release gate (quic-zig client against the pinned quic-go server),
    in CI for the first time (run 37114532615): handshake and transfer
    passed, with the real preflight. `interop evidence: pairs=1 cells=2
    succeeded=2 failed=0 unsupported=0 skipped=0`.
  - Matrix in CI (run 37115312707; quic-zig server; handshake,
    transfer, chacha20, multiplexing, transferloss, blackhole, and the
    goodput measurement): quic-go and ngtcp2 passed all six tests.
    quiche passed four, does not support chacha20, and failed
    multiplexing. `interop evidence: pairs=3 cells=21 succeeded=19
    failed=1 unsupported=1 skipped=0`. Goodput on the runner's 10 Mbps
    link, with BBRv3 as the default: 9.30 Mbps to quic-go, 9.16 to
    ngtcp2, 9.11 to quiche. A run on a developer machine, with peer
    images five months older, gave the same cells and 9.29, 9.10, and
    9.07 Mbps.
- **`server x quiche x multiplexing` failed, every time, for months;
  now it passes 6 runs of 10.** The story is in the order it was
  found; the last paragraph is what it was. It failed the same way
  against server images built on
  2026-05-11 and 2026-08-12, so it comes from neither Zig 0.17.0, nor
  0.23.0, nor the BBRv3 default; the blind matrix just never showed
  it. quiche's HTTP/0.9 test client ignores how many bytes a request
  write accepted, so a request that meets a full send window is cut
  short, sent without FIN, and never finished: 12 to 25 of the 1999
  requests in each run whose log was read. Its window fills because
  quic-zig returns stream credit when a quarter of the limit has been
  opened, and doubles it (1000, 2000, 4000, 4096): quiche then sends
  one request per packet in large bursts, the simulator's 25-packet
  queue drops about 8% of them, and its congestion window collapses
  mid-burst. A
  lower initial limit on the test endpoint does not help (the credit
  still doubles).

  Corrected after this entry was first written, which said that
  returning credit as streams close would fix the cell. It does not,
  and the cell is not only ours. A trial of that rule (limit = initial
  + closed, window 100) cut 4 requests in place of 12 to 25 and still
  failed 8 of 9 runs. With no quic-zig in the pair, the same quiche
  client fails the same test against a quic-go server in 4 of 8 runs
  and against an ngtcp2 server in 2 of 8, on the same machine with the
  same runner and simulator; quic-zig 0.23.0 fails 8 of 8. quiche
  puts exactly one STREAM frame in each packet, so every burst of
  requests is a burst of small packets, and the simulator's 25-packet
  queue drops 4 to 8% of them whatever the server does. A server only
  changes the odds, and ours were the worst of the three. So this
  cell cannot be a pass/fail signal for quic-zig. The endpoint's
  "stalled-peer keepalive" for this cell rests on a theory the logs
  do not support (nothing is parked on the quiche side); the
  measurement is recorded next to it in `interop/qns_endpoint.zig`.

  What made ours the worst, measured with the finished library: the
  stream window of the interop SERVER. Ours was 1000 (the most the
  runner allows); quic-go's and ngtcp2's are 100. quiche's send
  window starts at its first congestion window, 13,500 bytes, and a
  request is about 28 bytes, so a first flight of 1000 requests runs
  past it near request 486. In each of 10 runs at a window of 1000
  the first request cut was the one that crossed byte 13,500 (stream
  index 481 to 488). So at 1000 the cell could not pass under any
  credit rule: 0 of 10 with credit on close, 18 to 31 requests cut.
  At a window of 100, where the first flight is under 3,000 bytes:

  | interop server window | credit rule | runs passed | requests cut per run |
  | --- | --- | --- | --- |
  | 1000 | limit doubles (0.23.0) | 0 of 10 | 12 to 25 |
  | 100 | limit doubles (0.23.0) | 0 of 3 | 25 to 36 |
  | 1000 | credit on close (0.24.0) | 0 of 10 | 18 to 31 |
  | 100 | credit on close (0.24.0) | 6 of 10 | 0, or 1 to 4 in a failed run |

  It took both changes. The interop endpoint's window is 100 now
  (`endpoint_bidi_stream_limit` in `interop/qns_endpoint.zig`, with
  the measurements). The quic-go and ngtcp2 clients pass the test at
  either window, 5 of 5 each.
- **Interop wrapper: `--flaky peer:test`.** 6 of 10 is the same class
  as the other servers (4 of 8, 6 of 8), and the fault is in the
  client, so the cell fits neither class the wrapper had: as a plain
  cell it fails the matrix 4 runs in 10 for no fault of ours, and as
  a `--known-failures` cell it fails the matrix the 6 runs in 10 it
  passes (that list is a ratchet, right only for a cell that fails
  every time). A `--flaky` cell is run, counted on the evidence line
  (`flaky_passed=N flaky_failed=N`, two new fields at its end) and
  named. It decides nothing: a failure does not fail the run, a pass
  is not counted as a success, and a run in which only flaky cells
  passed is still "no cell succeeded". The runner's exit code is
  checked against known failures plus flaky failures. A cell on both
  lists is an error. The weekly matrix lists `quiche:multiplexing`
  there; `--known-failures` stays, with no cell on it. Unit-tested on
  the real result file of the first matrix; 7 mutants, all killed.
- **`quic-go x retry` (server role) failed once in CI and is not
  reproduced.** The wide matrix dispatched on the 0.23.0 code
  (16 tests x 3 clients, run 37137087184: `pairs=3 cells=48
  succeeded=42 failed=1 known_failed=1 unsupported=4 skipped=0`) had
  that one new failure. On a developer machine the same cell passes 5
  of 5 on the 0.23.0 code and 5 of 5 on this code.

## [0.23.0] - 2026-10-03

The tagged-toolchain release. quic-zig now builds on the tagged Zig
0.17.0 release instead of a pinned master build: a breaking floor move
for consumers, with no API change and no wire-behavior change against
0.22.0. Moving the pin also showed that the release gates had gone
blind in August — the fuzz gate could not fail on a failing fuzz site
and had been running a fraction of its budget, and the toolchain was
pinned four different ways — so this release repairs them, and it is
the first since 0.13.1 to carry a full-budget fuzz run. Consumers move
their toolchain pin to 0.17.0; anyone who keeps a connection open
across thousands of streams should read the new note on lifetime
stream limits. Verified toolchain: 0.17.0 (Linux x86-64 and aarch64,
macOS, and Windows in CI; macOS locally).

### Changed (BREAKING)

- **The toolchain floor is the tagged Zig `0.17.0` release.**
  `minimum_zig_version` moves from the `0.17.0-dev` master builds this
  project tracked while 0.17 was in development to `0.17.0`, and
  `mise.toml` and the QNS Dockerfile pin the same release. Every
  `0.17.0-dev.*` build orders below `0.17.0`, so a consumer still on a
  master build gets the floor diagnostic from `build.zig` instead of a
  build. Migration: pin Zig `0.17.0` (`zig = "0.17.0"` in `mise.toml`).
  quic-zig itself needed no source change for the move — the tree as
  it stood at the previous pin (`0.17.0-dev.1978+c961124d9`) builds and
  passes unmodified on the release — so a consumer already on a late
  0.17-dev build should need none either; the 0.17.0 release notes
  list what changed for older ones. This supersedes the never-released
  dev.1978 pin move (the toolchain the 0.22.0 test re-baseline was
  verified under; the SentPacket size pin and the e2e suite cannot
  pass under the older dev.1683 pin).

### Changed

- **Bulk transfer is about 19% faster, from retiring one deprecated
  call.** `std.mem.copyForwards` — an element-wise loop that LLVM does
  not turn into a memmove — sat on the stream hot paths: receive-buffer
  compaction, send-buffer compaction, the CRYPTO outbox shift, and the
  application Outbox tails. Zig 0.17.0 deprecates it in favor of the
  `@memmove` builtin, and the swap moves `goodput_bulk_64mib` from 412
  to 492 MB/s (ReleaseSafe, same machine and session, 9 samples; three
  pairs measured +19.0%, +19.5%, +21.7%) and handshakes per second by
  about +3%. The attribution is measured, not assumed: the same tree
  one commit earlier, with every other deprecation already renamed,
  still runs at 412 MB/s. The toolchain move by itself is
  performance-neutral (0.22.0 built with 0.17.0 instead of
  0.17.0-dev.1978: -1.6% goodput, inside the noise), no microbenchmark
  moved beyond the compare tolerance (the largest were -7.3% and
  +6.0%, on a loaded machine), and all 14 deterministic
  virtual-time cells (impairment and fairness) are byte-identical
  across 0.22.0 on the old compiler, 0.22.0 on the new one, and this
  release — so nothing about transport behavior changed. The committed
  bench baselines are not refreshed in this release: the machine was
  not quiet enough for a baseline capture, and the numbers above are
  same-session comparisons.

- **Deprecated std forms retired (internal; no behavior or API
  change).** Zig 0.17.0 marks a set of std names deprecated — only in
  doc comments, the compiler does not warn — and removes some of them
  in 0.18.0. The list was built from the release's own `lib/std`
  `Deprecated` comments rather than from memory, and every use in the
  tree is migrated: `builtin.os` / `builtin.cpu` to `builtin.target.*`
  and `Target.Os.Tag.isBSD` to explicit tags (both removed in 0.18.0),
  `std.builtin.OptimizeMode` to `std.lang.Optimize`,
  `std.ArrayListUnmanaged` to `std.ArrayList`, `std.StaticBitSet` to
  `std.bit_set.Static`, `std.mem.indexOf*` to `std.mem.find*`,
  `std.fmt.bufPrint` to `std.mem.print`, `std.fmt.allocPrint` to
  `Allocator.print`, `std.fs.path` to `std.Io.Dir.path`,
  `std.meta.fieldInfo` / `fieldNames` to `@FieldType` / `@typeInfo`,
  and `std.mem.copyForwards` to `@memmove`. Two deprecated names stay
  on purpose, because their replacements are not renames:
  `Socket.sendMany` (the replacement reports partial sends and takes a
  different lowering — a send-path change that deserves its own
  measurement) and `std.heap.DebugAllocator` in the `bench-io`
  `HEAPDEBUG` aid.

### Documentation

- **Stream limits are lifetime limits, and now say so.** A connection
  can open at most 4096 streams of each kind over its whole life: the
  cumulative MAX_STREAMS quic-zig grants stops at
  `Connection.max_streams_per_connection`, and a larger grant from a
  peer is clamped to it, no matter how many earlier streams finished.
  This is not new — every release with the cap behaves this way — but
  the docs described `StreamLimitExceeded` only as retryable
  backpressure, and a one-stream-per-request protocol on a long-lived
  connection reaches the cap after 4096 requests and then sees every
  later request time out. EMBEDDING.md ("Stream limits are lifetime
  limits") and docs/ERROR_CODES.md now state the limit and what to do
  about it (retire the connection with headroom, or carry more
  requests per stream), and `tests/e2e/app_driver.zig` pins it
  end to end: 4096 request/reply streams complete, the 4097th open
  fails, and waiting does not help. Recycling stream credit, so that a
  connection is bounded by live streams rather than lifetime indices,
  is planned work.

- **Compiler notes re-measured on Zig 0.17.0.** Every in-tree note that
  cited a 0.17-dev build was re-tested against the release and either
  re-stamped or corrected. The one correction that matters to
  embedders: the `quic.app` Driver docs blamed "`@hasDecl` unreliable
  on 0.17-dev" for explicit hook registration. It is a language rule,
  not a quirk — `@hasDecl` sees only `pub` declarations (and as of
  0.17.0 that holds for a probe written in the declaring file too), so
  method detection would silently skip every callback an embedder did
  not mark `pub`. The design is unchanged; the stated reason is now the
  real one. Still true on the release and re-stamped: the Windows
  bundled-loop gap (std has no overlapped `net_receive`), x86_64
  needing the LLVM backend for fuzz coverage, the `SentPacket` size
  pin (`std.ArrayList` carries a `pointer_stability` lock in the safe
  optimize modes: 200 bytes there, 184 in ReleaseFast/ReleaseSmall),
  and `bench-io`'s evented backends needing the fork std (stock
  0.17.0's `Io.Dispatch` and `Io.Kqueue` do not compile). No longer
  true: a filtered test binary fuzzes cleanly again.

### CI and tests

- **A long-lived connection test for the application drivers.** Every
  existing `ConnectionDriver` / `Driver` test used a fresh connection
  for a handful of streams, so nothing covered what a session that
  stays up depends on: stream-table entries being released and stream
  credit being returned. "ConnectionDriver: a long-lived connection
  keeps answering requests" runs 300 request/reply streams over one
  connection with eight-entry stream tables and the default credit of
  100. It was written to chase a downstream report that 0.22.0 broke
  long-lived request/reply sessions, and it passes. So do, against the
  0.22.0 tag itself, qmsg's two-node tests extended to 200 rounds in
  each direction, and nest's unit tests and its whole kill suite (714
  scenarios) with every quic pin moved to 0.22.0. No 0.22.0 defect was
  found behind that report; the one hard limit a long-lived session
  does hit is the lifetime stream cap documented above, which predates
  0.22.0.

- **The CID-lifecycle fuzz harness had a stale close-code invariant.**
  `registerPeerCid` has closed with CONNECTION_ID_LIMIT_ERROR (RFC 9000
  §5.1.1) since 0.14.0, but the harness's close-code set still expected
  PROTOCOL_VIOLATION for that path, so the deep fuzzer failed on it in
  every run — the fuzz gates just did not notice (next entry). No
  protocol behavior was wrong and none changes. The invariant now
  admits the code, and the harness carries a seed that walks past the
  limit, so the next close-code move fails `zig build test` on the
  commit that makes it instead of waiting for a deep run.

- **The fuzz gates could not fail on a failing site.**
  `zig build test --fuzz` exits 0 when a fuzz site fails; the only
  trace is a log line, and the run stops at that site, so the sites
  after it get no budget. Every weekly fuzz run since 2026-08-16 and
  all eight pre-release gate runs from v0.14.0 through v0.21.1 logged
  the failing site above, stopped at a fraction of their budget
  (between 18,503 and 1,119,215 of ~2M executions), and reported
  success; v0.18.0, v0.19.0, v0.21.0, v0.21.2, and v0.22.0 were tagged
  with no gate run at all. So for seven weeks most fuzz sites got
  little or no deep fuzzing, and no release in that window has the
  fuzz evidence its tag implied. `tools/fuzz-gate.sh` now
  defines a clean run for the release gate (`rc-fuzz.yml`), the weekly
  job (`fuzz.yml`), and `just fuzz` / `mise run fuzz` alike: it fails on
  the failing-site log line, on a run count below 90% of sites x budget,
  and on a missing or uninstrumented coverage file, and it prints the
  coverage numbers either way. The weekly job also lost its
  `continue-on-error` (a failed fuzz step showed as a green run), now
  persists the corpus (`.zig-cache/f`; it had been caching the coverage
  file, so every run started cold), and both jobs upload the failing
  input. Verified by mutation: with the CID invariant re-broken the
  gate exits 1; on the fixed tree it passes.

- **Toolchain pin agreement lint.** The Zig toolchain is named in four
  places — `mise.toml`, `build.zig.zon`, `tools/consumer-smoke/build.zig.zon`,
  and `interop/qns/Dockerfile` — and they had drifted apart: `main`
  tested against one compiler, declared another as its floor, and built
  the QNS image with a third. `tools/check-zig-pins.sh` (`just
  check-pins`) fails on any disagreement; `test.yml` runs it on every
  push, and the new `zig-pin` job in `pin-lint.yml` additionally checks
  the Dockerfile's per-arch SHA-256 against the digests ziglang.org
  publishes.

- **The cross-repo boringssl pin lint is a ratchet again.** quic-zig
  has pinned boringssl 0.6.7 since 0.21.2 while http3-zig's main still
  pins 0.6.6, so the strict lint had been red on every run since that
  release — and a lint that is always red reports nothing. It now
  passes identical pins, tolerates exactly that dated pair with a
  warning, and fails on anything else. The pair is deleted when
  http3-zig repins.

## [0.22.0] - 2026-09-20

The stream-lifecycle hardening release. Two correctness fixes in the
application stream machinery — reordered stream opens no longer tear
down live requests, and late replies after local stream reclamation no
longer reset the connection — plus the bounded application stream
drivers those fixes motivated, an Outbox that bounds what it accepts,
and a test-suite re-baseline onto current 0.17-dev toolchains. Anyone
running request/reply workloads over connections with reordering or
aggressive stream GC should upgrade. Verified toolchain:
0.17.0-dev.1978+c961124d9 and zvm master 0.17.0-dev.2151+2ec5523d5
(macOS); also exercised end-to-end downstream via nest's 658-scenario
kill suite.


- Test suites (`test`, `test-app`) run green under 0.17.0-dev.1978 and
  current master, closing the toolchain drift that kept main red: the
  e2e comptime `@hasDecl` canary on Driver-entangled App types reported
  false negatives on 0.17-dev (the reason Driver bans decl probes), so
  the guard is now the runtime `driver.streamsServiced()` assertion the
  Driver docs prescribe; and the SentPacket size pin re-baselines
  184 -> 200 — the field inventory is unchanged, `std.ArrayList` grew
  24 -> 32 in std and SentPacket holds two (tracker 736 -> 800 KB, raw
  churn +8.7% by memcpy ratio).

- Application drivers keep implicitly opened lower stream IDs pending until
  their first receive state arrives. Reordering a higher stream ahead of a
  lower stream no longer causes a false teardown and lost request delivery.
- Fixed a connection reset when reordered or retransmitted replies arrived
  after local bidirectional stream state was reclaimed. GC now remembers
  actual local stream reaps in a fixed-size bitmap, so late STREAM and
  RESET_STREAM frames are ignored without accepting genuinely unopened IDs.
  Live stream final-size checks remain intact; reaped IDs cannot be reopened.
- Added `app.ConnectionDriver(App)`, borrowing either an accepted or dialed
  connection. Its data hook reports consumed bytes; zero or partial progress
  pauses the stream without releasing credit for unread bytes. Local bidi
  streams can register for response delivery with `trackStream`.
- The existing server `app.Driver` shares that pump, attaches teardown
  automatically, preserves embedder `slot.user_data`, and chains the previous
  will-close hook. Use `sessionOn(slot)` for driver state and destroy the
  server before the driver. Its optional `on_stream_data_consumed` callback
  adds the same pause contract without changing the existing void callback.
  Both drivers expose `refusedStreams()` for stream admission metrics.
- `app.Outbox` now bounds pending stream count and bytes (defaults 128 and
  16 MiB), reserves complete pushes before accepting any prefix, and exposes
  pending counts. `QueueFull` accepts no bytes. Flushing visits every queued
  stream, including those beyond a blocked first 128 entries.
- Exposed `Connection.streamInitiatedByLocal` and `streamIsBidi`. Added the
  socket-free `zig build test-app` contract suite, including real TLS pairs.

## [0.21.2] - 2026-09-20

A dependency release: no quic code changes. The boringssl-zig pin
moves 0.6.6 -> 0.6.7, which adds `crypto.pkey`, `crypto.x509`, and
`crypto.pem` — key generation, a certificate builder for self-signed
CAs and the leaves they sign, and PEM encode/decode through memory
BIOs. Consumers that mint development PKIs (nest's mesh identity, for
one) now do it through the wrapper instead of hand-written externs;
quic itself does not touch the new modules and behaves exactly as
0.21.1. The stream-driver work on main stays unreleased for a future
0.22.0. Verified toolchain: 0.17.0-dev.1683+5ceec001b (macOS); also
exercised end-to-end downstream under 0.17.0-dev.1978 via nest's
658-scenario kill suite.

## [0.21.1] - 2026-09-07

The packet-key leak fix. Every Handshake and 0-RTT key derivation
allocated a fresh BoringSSL AEAD context and dropped it on the floor —
on the receive path once per packet and on the send path once per poll —
so a long-lived process holding QUIC sessions grew at a steady ~10 KB/s
at two sessions per second, reported by `leaks` as root leaks. Anyone
embedding quic-zig in a durable process should upgrade; behavior is
otherwise unchanged. Verified toolchain:
0.17.0-dev.1683+5ceec001b (macOS).

- **Fixed: every Handshake and 0-RTT packet-key derivation leaked its
  BoringSSL AEAD context.** `Connection.packetKeys` derived a fresh
  `PacketKeys` — whose `aead` field owns a heap `EVP_AEAD_CTX` — on
  every call at the `.handshake` and `.early_data` levels, and both
  callers dropped it: the send path (`send.pollLevelOnPath` derives
  on every poll at those levels, even when no packet leaves) and the
  receive handlers (`recv_packet_handlers.handleHandshake` /
  `handleZeroRtt`). Application epochs and Initial keys were already
  cached; Handshake and 0-RTT keys now are too: derived once per
  secret, stored in `PerLevelState.read_keys`/`write_keys`, and freed
  when the secret is replaced (`setSecret`), discarded
  (`discardHandshakeKeys`), or the connection is destroyed. Callers
  receive a borrowed copy and must not `deinitAead` it — the same
  semantics Application and Initial keys already had — and
  `packetKeys` accordingly takes `*Connection` to install the cache.
  Two more members of the same class are fixed alongside:
  `setInitialDcid` and `setVersion` dropped the Initial keys without
  freeing their contexts (every Retry leaked the pair), and
  `Connection.deinit` now frees Initial and per-level cached keys on
  a mid-handshake teardown. Pre-fix, measured with
  `MallocStackLogging` on an embedded member at two QUIC sessions
  per second: 7,661 live 640-byte contexts after ten idle minutes
  (~5,600 under the send path, ~2,060 under the receive path), about
  10 KB/s of steady growth. Pinned by new derive-once identity tests
  (the cached context's address is stable across calls, per
  direction) and a discard-frees-the-cache test.


## [0.21.0] - 2026-09-06

The mTLS peer-identity release. An embedder building a cluster on
mutual TLS had no way to learn *which* peer a connection actually
authenticated as: the certificate was validated, but its identity was
not readable, so application peer ids had to be taken on trust from
inside the channel. This release exposes that identity
(`Connection.peerCertSpkiDigest`), makes private-cluster dials by
address practical without weakening chain validation
(`Client.Config.identity_verification`), and gives servers a precise
moment at which a connection is authenticated and its identity
readable (`Server.Config.on_handshake_complete`). Together they let a
mesh, a replication link, or a message bus bind its own peer id to the
key that signed the handshake. Verified toolchain:
0.17.0-dev.1683+5ceec001b (macOS).

- **`Connection.peerCertSpkiDigest()`: the authenticated peer
  identity.** Returns SHA-256 over the DER-encoded SubjectPublicKeyInfo
  of the peer's leaf certificate once the handshake completed and the
  peer presented a certificate — the preimage of the standard
  `openssl x509 -pubkey | openssl pkey -pubin -outform DER |
  openssl dgst -sha256` fingerprint pipeline, so expected values can
  be computed with any toolchain. Null otherwise (handshake
  incomplete, no peer certificate, connection past its open phase).
  Role-agnostic (a server reads the client cert, a client the server
  cert), stable across certificate re-issuance while the keypair is
  retained, and correct on resumed sessions (BoringSSL keeps the
  session's peer certificate). Backed by new `boringssl.tls.Conn`
  accessors in the 0.6.6 boringssl pin (`SSL_get_peer_certificate` +
  SPKI DER + SHA-256); the pin moves byte-identically in quic-zig and
  http3-zig per the pin-lint contract. mTLS embedders (service meshes,
  replication, message buses) bind application peer ids to this digest
  instead of announced ids inside the channel. New e2e suite
  `tests/e2e/peer_identity.zig` pins the digest against
  openssl-computed KAT constants for both fixtures, both roles, null
  gating pre-handshake and under optional client certs, and
  resumption.

- **`Client.Config.identity_verification`: pinned-CA dials without the
  name check.** `.server_name` (default) keeps today's behavior — SNI
  plus SAN/CN verification against `server_name`. `.none` sends SNI
  but skips the name check while chain validation against `ca_pem`
  remains mandatory — the posture for private-cluster peers dialed by
  address whose certificate identity is cluster membership, not the
  dialed name. `.none` without `ca_pem` (including via
  `insecure_skip_verify` or `tls_context_override` combinations) fails
  `connect` with `InvalidConfig` so the posture can never silently
  downgrade to no verification. Plumbing: `Connection.createClientWithPolicy`
  / `initClientAtWithPolicy` (additive; the existing constructors keep
  the `.server_name` default) on top of a new
  `boringssl.tls.Conn.setSni` that installs SNI without the
  `X509_VERIFY_PARAM_set1_host` binding. e2e: a name outside the SAN
  completes under `.none` + pinned roots, an untrusted chain is still
  rejected, and the configuration matrix is unit-pinned.

- **`Server.Config.on_handshake_complete`: per-slot
  discovery of fully-authenticated connections.** Fires exactly once
  per slot, from inside `feed`, on the datagram whose processing
  completed the TLS handshake — replacing the
  diff-`iterator()`-and-poll-`handshakeDone()` accept-boundary pattern
  embedders needed. Inside the callback the connection is established
  and open: ALPN, transport parameters, and
  `conn.peerCertSpkiDigest()` are readable and `slot.user_data` can be
  installed. `Server.setOnHandshakeCompleteHook` is the post-init
  twin. e2e-pinned in `tests/e2e/server_lifecycle_hooks.zig` including
  the once-per-slot latch and identity readability inside the
  callback.

## [0.20.0] - 2026-09-06

The padded-Initial release. A client padded only ack-eliciting Initial
packets, so its ACK-only Initial left as a ~100-byte datagram that every
RFC-conformant server drops; against a real network peer the server then
waited for two probe timeouts before it could finish the handshake, about
two seconds per connection, while loopback never showed it. Verified
toolchain: 0.17.0-dev.1683+5ceec001b (macOS, and the fleet-revisions
consumer on 0.17.0-dev.1978+c961124d9 on macOS and aarch64 Linux).

- **Clients pad every Initial-leading datagram to 1200 bytes.** RFC 9000
  §14.1 requires a client to expand every UDP datagram that carries an
  Initial packet, not only ack-eliciting ones; the ack-eliciting condition
  belongs to the server side of that rule. `Server.feed` drops
  Initial-leading datagrams under 1200 bytes, so a client's unpadded
  ACK-only Initial was silently discarded and the server retransmitted its
  first flight at every probe timeout before finishing the handshake: about
  two seconds per connection against a real network peer, invisible on
  loopback where the client's next Initial coalesces with ack-eliciting
  Handshake data. The e2e test `initial_padding.zig` inspects every client
  datagram of a loopback handshake before the server sees it.

- **`error.Canceled` from a send is its own send disposition.**
  `transport.classifySendError` now classifies it as `.canceled`
  instead of `.fatal`: a bundled loop whose task was cancelled
  mid-send returns so the cancelled thread or fiber exits, instead of
  counting an egress local fault and continuing (after cancellation
  every I/O call fails this way, so the loop would spin). The client
  loop exits cleanly — no error surfaces to the embedder, since the
  cancellation was requested, not suffered.
- **`bench-io` builds on stock Zig with `-Dbench-io-threaded-only`.**
  The evented backends compile out under the option, giving a
  Threaded-only bench on upstream std (whose `Io.Dispatch` does not
  compile on the batch path); the header documents which fork
  releases the evented modes need.
- **New bench mode `--io ev-thread`** (Linux): one loop per thread on
  its own single-threaded Evented instance — the evented placement
  experiment. At 8 servers x 16 clients it overtakes Threaded on
  group goodput (1011.7 vs 869.7 MiB/s) where a shared instance
  trails it (665.9), with echo latency at parity and the best tail
  latency. Embedders on Linux should prefer one Evented instance per
  thread; EMBEDDING.md says so.
- **Docs: loop thread or loop fiber.** EMBEDDING.md now states what
  "the loop's own thread" means per backend, that the shutdown flag
  is the only stop mechanism that works everywhere today (Evented
  network waits are not cancellation points), and what to expect from
  `error.Canceled` on the way out.

- **`RunUdpOptions.reuse_port` binds through std when std can.** When
  `std.Io.net.IpAddress.BindOptions` has a `reuse_port` field, every
  listener the bundled loop binds goes through the `Io` vtable, so a
  custom backend sees the bind and `std.Io.Dispatch` gets the O_NONBLOCK
  socket its receive path depends on. Before, `reuse_port = true` always
  took the POSIX-direct `transport.bindUdpSocket` path, whose blocking
  socket makes `receiveManyTimeout` on `std.Io.Dispatch` ignore its
  timeout and block until the whole batch (`max_datagrams_per_iteration`,
  default 16) is full, stalling timers and the first datagram of every
  batch (`std.Io.Threaded` and `std.Io.Uring` were unaffected). Older std
  versions keep the old path unchanged; `transport.std_bind_has_reuse_port`
  says which one is in effect. `bindUdpSocket` stays for those std
  versions and its docs now say the socket is blocking.
- **Docs: what `SO_REUSEPORT` does and does not give you.** Linux
  re-hashes flows across the group whenever a socket joins or leaves, so
  a worker restart moves a share of the *other* workers' connections onto
  instances that do not own them (which stateless-reset them when the
  shared key is pinned); `reuse_port` alone does not make restarts
  seamless — CID routing does. On macOS the one socket that receives
  everything is the newest for a specific-address bind but the oldest
  for a wildcard bind. EMBEDDING.md and the option docs said otherwise.
- **`bench-io --loops N --clients M`**: N server loops on one port via
  `reuse_port` and M concurrent clients, aggregate rates plus the
  per-server split; `--loops 1 --clients M` is the one-server control.

## [0.19.0] - 2026-08-27

The handshake-liveness release. A `Connection` whose handshake never
completed, whose peer then went quiet, NEVER died: RFC 9000 §10.1's
idle timeout is the min of both endpoints' advertised values, which
pre-confirmation either hasn't arrived (a dropped-server dial) or is 0
(idle opted out) — so the client-side shape was an eternal dial
(Initial retransmission budget, then silence forever, no CloseEvent)
and the server-side shape was the QUIC SYN-flood analog (abandoned
dials parking every `max_concurrent_connections` slot `.open` until
the endpoint mutes). Measured downstream in capnp-zig's fanout soak
(2026-08-27) and reproduced against pre-fix quic-zig in what is now
`tests/e2e/handshake_timeout.zig` (600 simulated seconds, both
endpoints `.open`, zero close events).

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b (CI pin; also
built on dev.1786 locally).

### Added

- **Handshake-liveness backstop, on by default** —
  `Client.Config.handshake_timeout_ms` (default 30s),
  `Server.Config.handshake_timeout_ms` (default 10s, the scarcer and
  floodable side), and the raw-cycle
  `Connection.handshake_timeout_us` they thread onto
  `Connection.Tunables`. The deadline anchors at the connection's
  first `tick` (≈ `connect` / slot-open), surfaces as the new
  `TimerKind.handshake_timeout` through `nextTimerDeadline` (often
  the only park target a stalled dial offers), and on expiry tears
  the connection down through draining to terminal `.closed`, where
  `Server.reap` reclaims the slot. Posture on expiry mirrors the
  idle timeout exactly: silent draining, no CONNECTION_CLOSE — a
  peer this timer describes is unresponsive by definition, so a CC
  would be pure amplification (a queued-CC close via
  `Connection.close` was considered and rejected on that ground).
- **`CloseSource.handshake_timeout`** (additive enum variant): the
  sticky `CloseEvent` and `pollEvent`'s close event carry it, so
  "never became viable" stays distinguishable from
  `idle_timeout`'s "went quiet after establishing". Downstream
  first-write-wins cause latches (capnp-zig's
  `disconnectCauseFor`) can map it exactly; the variant is safe for
  non-exhaustive consumers per the `ConnectionEvent` forward-compat
  contract in docs/API_STABILITY.md.

### Design decisions worth knowing

- **The disarm boundary is handshake CONFIRMATION, not TLS
  completion.** The timer stays armed through the mid-confirmation
  stall — server flight delivered, client's Finished lost — where
  both sides have application write keys and a "done" TLS state
  machine yet the connection is not viable and (with the idle
  timeout opted out) otherwise immortal. The latch it consults is
  `handshake_keys_discarded` (RFC 9001 §4.1.2 / §4.9.2), which this
  codebase already maintains symmetrically: server-side on
  processing the client's Finished, client-side on receiving
  HANDSHAKE_DONE. 0-RTT resumption dials walk the same paths and get
  the same bound — a stalled resumption occupies a slot exactly like
  a stalled full handshake.
- **Defaults are on, not opt-in** (the silent default was the
  hazard). 30s client / 10s server mirror what the downstream embed
  chose for its own guards, which remain useful defense in depth;
  equal-value windows are fine either way since the downstream cause
  latch is first-write-wins. `0` restores the pre-0.19.0 unbounded
  behavior for embedders that want their own guard to be the only
  one.
- One embedder-visible behavior change beyond the knob: a fresh
  client's `nextTimerDeadline` now reports the handshake backstop at
  bootstrap, where it previously reported null ("nothing armed"). The
  foreign-loop example's drain-before-park lesson test was updated
  accordingly — the park is now bounded from above, which is the
  improvement the lesson always wanted.

## [0.18.0] - 2026-08-27

The multi-process port-sharing release. EMBEDDING.md's "Scaling
across cores" guidance told embedders to bind their own `SO_REUSEPORT`
socket and hand it to `runUdpServer` — an instruction the shipped loop
could not accept (it binds from `RunUdpOptions.listen` itself, and a
second process on the same `ip:port` died with `AddressInUse`;
reproduced against 0.17.0). Evaluated against a downstream
suggestions doc from mruby-quic, whose `--workers N` supervisor
design is the first consumer; the platform semantics it assumed were
measured rather than trusted and are pinned by test.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b (CI pin; also
built on dev.1786 locally).

### Added

- **`RunUdpOptions.reuse_port`** (default `false`): sets
  `SO_REUSEPORT` on every listener the loop binds — primary and
  `preferred_address` alt listeners alike — so N independent
  processes share one `ip:port`. Off means byte-identical behavior:
  the bind still goes through the `std.Io` `netBindIp` vtable, so
  custom Io backends keep seeing every bind. Platform posture is
  explicit rather than defaulted: Linux gets kernel 4-tuple hash
  balancing (the intended multi-worker path; same-effective-UID group
  joining per socket(7) is the documented tradeoff); macOS/BSD permit
  the shared bind but deliver to the most recently bound socket
  (measured on darwin 25.6: 32 flows, 0/32 split; survivors take over
  when the newest closes) — bind-sharing and failover, not balancing;
  targets without the option fail fast with the new
  `RunError.ReusePortUnsupported` instead of a fleet dying one
  `AddressInUse` at a time. Windows keeps refusing the whole loop up
  front (`WindowsBundledLoopUnsupported` fires first).
- **`transport.bindUdpSocket(&addr, .{ .reuse_port = true })`** and
  `transport.BindUdpOptions`: a POSIX-direct UDP bind that applies
  pre-bind socket options std's atomic `IpAddress.bind` leaves no
  window for. This is the supported way for ANY std-based embedder —
  foreign-loop ones included — to obtain a `SO_REUSEPORT` socket; the
  loop's flag routes through it. Returns a normal `Net.Socket` usable
  with any `std.Io` (POSIX sockets are plain `{handle, address}`
  values there); the errno mapping lands in
  `Net.IpAddress.BindError` so existing error handling transfers.
  Mirrors std's own backend behavior for `SOCK_CLOEXEC` (Darwin/Haiku
  reject it inside `socket()`'s type argument with `EPROTOTYPE`;
  plain type + `fcntl(F_SETFD)` after, per the same predicate std's
  backends consult).

### Rejected alternatives

- **A `prebound`-socket option on `RunUdpOptions`** (embedder binds,
  loop adopts): rejected. It buys socket-activation / fd-passing
  scenarios with no consumer behind them, at the cost of an ownership
  model (who closes), a `listen`-plus-`prebound` conflict policy, and
  socket-type validation — each answer a doc line and a test.
  `SO_REUSEPORT` group joins already make worker restarts seamless on
  Linux, which is what the actual downstream design (spawn-and-reexec
  supervisor) needs. Revisit with a concrete socket-activation
  requirement; the composable `bindUdpSocket` helper is where extra
  pre-bind options should land first.
- **Silently ignoring `reuse_port` on platforms without the option**:
  rejected in favor of the loud `RunError.ReusePortUnsupported`. A
  silently-ignored flag would resurface as per-worker `AddressInUse`
  deaths — the exact failure the flag exists to remove, one step
  removed from its cause.

## [0.17.0] - 2026-08-26

The receive-side DATAGRAM release. Inbound queue overflow now sheds
datagrams (RFC 9221 §5.3) instead of closing the connection — before
this, one conforming packet packed with tiny DATAGRAM frames could
kill its own connection, which a new downstream embedding (mruby-quic,
fed by a quinn-based client) hit live. Plus a receive-drop counter,
honest inbound-queue accounting, and a comment-anchor lint. Wire
defaults and encodings are unchanged.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b (CI pin; also
built on dev.1786 locally).

### Changed

- **Inbound DATAGRAM overflow sheds instead of closing.** RFC 9221
  §5.3: datagrams "MAY be dropped by the receiver if the receiver
  cannot process them"; nothing in the RFC calls for a close, and
  closing converted recoverable loss into an unrecoverable fault.
  `handleDatagram` queue pressure — and, on this path only, an
  over-cap `max_connection_memory` reservation — now drops the
  arriving datagram and counts it. The two RFC 9221 §3
  negotiated-parameter closes stay (frame above the advertised
  `max_datagram_frame_size`; any DATAGRAM when support was not
  advertised). CRYPTO and STREAM overflow still closes, deliberately:
  reliable bytes cannot be shed after the carrying packet is ACKed,
  while a datagram ACK explicitly does not promise app delivery
  (§5.2). Send-side `DatagramQueueFull` backpressure is unchanged.
- **The inbound queue's 64-item count cap is retired.** A single
  ~1200-byte packet can legally carry hundreds of minimal DATAGRAM
  frames (~3 bytes each), so any small fixed count was trippable by
  one conforming packet; it effectively bounded "datagrams per
  event-loop iteration", which nothing documented. Admission now
  charges `payload + recv_datagram_item_overhead` (new const, 48
  bytes, comptime-checked against the queue-slot size) against
  `max_pending_datagram_bytes`, so tiny/empty datagrams cannot
  occupy unbounded slots and the worst-case queue length (~1365)
  keeps `popRecvDatagram`'s O(n) head removal bounded.
  `max_pending_datagram_count` remains as the send-side cap it always
  documented. Capacity check: ~10-byte payloads now queue ≈1130 deep
  (was 64).
- **New `ConnectionStats.datagrams_dropped_recv`** (additive,
  monotonic): inbound datagrams shed under queue/memory pressure, so
  an application can tell "peer never sent it" from "we shed it".
  The `receiveDatagram` docs now state the drain contract: drain to
  empty each service iteration — one pop per event-loop tick cannot
  keep up with packed frames (`quic.app` already drains in a loop).
  Two alternatives were considered and rejected, with rationale in
  the code and commit: a per-drop hook (fires exactly under drop
  storms; the counter carries the signal at O(1)) and a batch-drain
  API (fatality gone, cost unmeasured — reopen with a profile).

### Documentation

- **The ghost "hardening guide" citations are gone again, and a lint
  now keeps them out.** Commit `4a3ecdd` (0.10.x) removed 27 comments
  citing section numbers of an internal security guide that was never
  written; later work reintroduced ~45 more, plus two pointers to
  README sections that do not exist. All are repointed to the
  governing RFC section or a self-contained mechanism name, keeping
  every rationale. `tests/lint_comment_anchors.zig` (part of
  `zig build test`, mutation-checked) fails on any comment matching
  the ghost citation style, so the third wave cannot land.

## [0.16.1] - 2026-08-21

Patch release: closes a stateless-reset configuration hole reported by
a downstream embedder, and collects the documentation for what a null
`stateless_reset_key` silently disables. No wire behavior changes.

### Changed

- **`Server.init` now refuses a hand-set
  `transport_params.stateless_reset_token` when `stateless_reset_key`
  is null** (`error.InvalidConfig`). RFC 9000 §18.2's token belongs to
  the handshake CID and therefore differs per connection, so a value
  in per-server config cannot be correct for more than one peer:
  `transport_params` is copied verbatim onto every accepted connection
  and the accept path only *overwrites* this field when a key is set.
  Keyless, the same token reached every peer — so any peer that ever
  completed a handshake could reset any other peer's connection — and
  it could never be honored, since the emitter derives from the absent
  key. Set `stateless_reset_key` and let per-CID tokens be derived.
  A hand-set token alongside a real key is still accepted (the accept
  path overwrites it, making it inert).

### Documentation

- The `Server.Config.stateless_reset_key` docstring is now the single
  place collecting everything a null key silently disables: reset
  emission, the §18.2 advertisement peers need to *detect* a reset
  (without it a client of a crashed-and-restarted server idles out
  rather than failing fast), auto CID replenishment (whose flag
  defaults to true), client-initiated migration, and peer CID
  rotation on NAT rebinding. EMBEDDING.md and the README hardening
  checklist are reframed from "required for preferred-address /
  QUIC-LB" to "set it on any deployed server"; the README previously
  told readers to *persist* the key but never to *set* it. Reported
  by a downstream embedder (capnp-zig).

## [0.16.0] - 2026-08-21

The "fairness and the flip" release. BBRv3 is now the DEFAULT
congestion controller, gated on a new multi-flow fairness battery
that promptly caught (and this release fixes) a three-defect
transport deadlock plus a sub-millisecond bandwidth-measurement bug.
Also: a zero-copy stream read path, the qmsg-derived `quic.app`
refinement, and the last two silent-failure traps closed.

**Default behavior changes.** BBRv3 replaces CUBIC as the default;
`congestion_control = .cubic` is the one-line rollback at any layer.
NOTE for wrappers: if your transport snapshot-copied `.cubic` as its
own config-field default (rather than deferring to quic-zig's), the
flip does NOT reach your consumers until you update that default.

### Changed

- **BBRv3 (draft-ietf-ccwg-bbr-06) is the default congestion
  controller.** The flip gate recorded in `congestion/Bbr.zig` was
  built and passed on pre-registered criteria: 2-flow BBR Jain
  1.0000 at 97.1% link utilization (CUBIC reference 0.9996), 4-flow
  0.9970, a 5 s late joiner converging to 1.0000, no starvation
  against CUBIC in either buffer regime (31.1% share deep / 61.3%
  shallow) — with peak queue delay 43 ms vs CUBIC's 100 ms and zero
  drops in the BBR-only cells — plus the full cross-implementation
  interop matrix (quic-go / quiche / ngtcp2, loss cells included).
  CUBIC and NewReno remain compiled-in (`.cubic`, `.new_reno`).
- **BREAKING: `receiveDatagram` no longer truncates silently.** An
  undersized `dst` now returns `Error.DatagramBufferTooSmall` and
  consumes nothing (retry after `nextDatagramSize`); the signature
  is `Error!?usize`. `receiveDatagramInfo` keeps truncate-and-report
  for fixed-buffer callers. Closes the silent-failure family.
- **BREAKING (Evolving tier): `quic.app.Driver` refinements from the
  qmsg port.** `on_datagram` now receives a `Driver.Datagram`
  (`bytes` + `arrived_in_early_data`); `Options.read_chunk_bytes`
  is gone (the pump is zero-copy, see Added); `quic.app` promotion
  re-targets 0.17.

### Added

- **Multi-flow fairness cells** (`zig build bench-e2e -- --scenario
  fairness`): N connection pairs share ONE simulated bottleneck;
  per-flow goodput, shares, and the Jain index, deterministic per
  seed. Six recorded cells (BBR/CUBIC/mixed matchups, staggered
  start, shallow buffer) now ride the e2e baseline.
- **Zero-copy stream reads.** `Connection.streamPeek` /
  `streamConsume` (Evolving): borrow the readable prefix straight
  from the reassembly buffer, then consume with the exact
  flow-control bookkeeping `streamRead` runs. The `quic.app.Driver`
  stream pump uses it: hooks receive whole contiguous runs with no
  intermediate copy, and a failing hook redelivers its chunk instead
  of losing it.
- **`quic.app` friction list, resolved**: optional `ConnState` /
  `StreamState` types (incl. `?*T`, defaulting to null);
  `StreamRecvState.read_offset` + `.final_size`;
  `Server.setConnectionWillCloseHook` + `Driver.attach(server)` for
  post-init teardown wiring in wrapper stacks; a loud lifetime note
  on `StreamEnd` (entry state must be consumed inside the hook).
- **RFC 9000 §7.4.1 enforcement**: a client whose 0-RTT was accepted
  now closes with PROTOCOL_VIOLATION if the server's fresh transport
  parameters reduce any of the seven early-data-load-bearing limits
  below the remembered values.

### Fixed

- **Pacer refill quantization starvation** (also in v0.15.1). The
  refill clock advanced even when integer division floored the
  accrual to zero, so any rate below one byte per poll interval
  froze the token bucket permanently.
- **Flow-control credit starved behind the pacing gate** (also in
  v0.15.1). Exempt ACK sends debit the pacer; a receive-mostly
  endpoint in permanent pacer debt never sent its queued
  MAX_STREAM_DATA / MAX_DATA — the RFC 9000 §4.2 deadlock, observed
  as two BBR flows wedging at exactly `initial_max_stream_data`.
  Credit and blocked-signal frames are now exempt from the pacing
  half of the gate (cwnd still applies).
- **BBR pacing floor.** A receive-mostly endpoint latched a
  garbage-low rate (~5 KB/s) from its post-handshake control-tail
  sample and parked in Startup forever, pacing everything it owed at
  that rate. Until the pipe has been observed full, the pacing rate
  never drops below InitPacingRate (documented DEVIATION).
- **Delivery-rate reliability floor is min_rtt once primed, not a
  permanent 1 ms.** Every sub-millisecond path (loopback, LAN,
  datacenter) was systematically underestimated under BBR — Startup
  latched full_bw ~2x below the path; the real-socket goodput smoke
  ran 7-20 MB/s vs CUBIC's 49, and reads 42-46 MB/s with the fix.
  Paths with min_rtt >= 1 ms are byte-identical.

## [0.15.1] - 2026-08-21

Patch release: the two congestion-independent transport-liveness
fixes above (Pacer refill quantization starvation; flow-control
credit starved behind the pacing gate), cherry-picked onto v0.15.0
for downstreams that want them without 0.16.0's behavior changes.
No API or default changes.

## [0.15.0] - 2026-08-21

The "serve the downstreams" release: RFC 9000 §10.3 Stateless Reset
emission (the death certificate a peer of a crashed server needs), a
0-RTT restore-budget query, the last silent-failure traps closed, an
undrained-`Server.deinit` session leak fixed, and two observability
surfaces promoted to Stable. No default wire behavior changed.

### Added

- **RFC 9000 §10.3 Stateless Reset EMISSION.** With
  `Config.stateless_reset_key` set, `Server.feed` now answers an
  unroutable short-header datagram with a spec-shaped Stateless
  Reset — the death certificate that lets a peer of a crashed or
  restarted server abandon the connection immediately instead of
  grinding out its idle timeout. Emission follows the §10.3 rules:
  trigger must be ≥ 22 bytes and carry a complete DCID; the reset is
  always smaller than its trigger (the §10.3.3 loop rule — a
  reset-vs-reset exchange shrinks to death, pinned by test), one
  byte shorter for small triggers, randomized 41–63 bytes for large
  ones; the token tail is the same HMAC committed when issuing CIDs.
  Per-source budget via the new
  `Config.stateless_reset_source_rate_limit` (default cap 8).
  Resets ride the existing stateless-response queue
  (`StatelessResponseKind.stateless_reset`; evicted first on
  overflow) and drain through the bundled loops unchanged.
- **`FeedOutcome.stateless_reset_sent`** (additive enum variant —
  keep an `else` arm when switching) and
  **`LogEvent.unroutable_dcid`** carrying the stale DCID and a
  `reset_queued` flag: it fires for every full-DCID unroutable
  short-header datagram, whether or not a reset ships, so
  DCID-routing front ends can observe stale-CID traffic. Metrics:
  `feeds_stateless_reset`, `feeds_reset_rate_limited`.
- **The handshake SCID's reset token is now advertised** via the
  RFC 9000 §18.2 `stateless_reset_token` transport parameter.
  Previously tokens reached the peer only with
  NEW_CONNECTION_ID-provided spares and the preferred-address CID,
  so a reset aimed at the PRIMARY connection ID could not be
  recognized. The death-certificate e2e (client handshakes against
  server #1, a key-sharing stateless server #2 resets it, client
  enters draining with `CloseSource.stateless_reset`) pins the full
  chain and fails if the advertise is removed.
- **`Client.earlyDataSendWindow()` / `Connection.earlyDataSendWindow()`**
  (Evolving): the 0-RTT early-data flow-control budget derived from
  the resumed session's remembered transport parameters —
  connection-level `max_data` plus the per-stream ceilings. Returns
  null when the client is not resuming. Lets an embedder size a
  restore payload to fit the early-data window before staging it
  pre-`advance()` (RFC 9001 §4.5), instead of discovering the limit
  mid-flight.
- **`Client.Config.defaultTransportParams()`**: the client-side
  mirror of the server helper — a non-zero flow-control / stream
  working set so a client dialing with it can receive a response
  instead of advertising a zero window with `.{}` and stalling.

### Changed

- **Promoted to the Stable tier:** `Connection.stats()` /
  `ConnectionStats` (its 16-field set is byte-identical across
  0.11.0→0.14.0, four releases) and the send-side snapshots
  `Connection.sendWindow` / `streamSendWindow` (with `SendWindow`,
  soaked unchanged in the http3-zig downstream since 0.13.0). All
  three are now compile-pinned in `public_api_smoke.zig`, so a future
  signature change fails CI. `ConnectionStats` fields may still be
  *added* under the forward-compat expectation; existing fields keep
  their name, type, and meaning.
- **`streamRecvState` on a locally-initiated unidirectional stream
  now returns `null`** (like an unknown stream) instead of a
  fabricated non-terminal state. Such a stream has no receive half,
  so a caller polling it for completion would wait forever — the
  last member of the silent-failure family the 0.14.0 sprint hunted
  (the twin of `streamRead`'s `StreamNotReadable`). Embedder-side
  misuse only; peer input can never produce it.

### Fixed

- **`Server.deinit` now fires `on_connection_will_close` per live
  slot** before destroying it (same ordered-teardown hook `reap`
  runs). Destroying a server with connections still live previously
  skipped the hook — the only place a `quic.app.Driver` session
  frees — so every such session (and its per-stream app state)
  leaked. The pre-`deinit` drain loop is no longer a leak-safety
  requirement (it still matters for graceful on-wire close).
  Mutation-checked by a new no-drain-deinit leak test.
- Four doc comments referenced a `provideConnectionId` method that
  does not exist (the real API is `replenishConnectionIds`); a
  downstream integration audit tripped on it. Corrected, including
  the runnable example in `conn/stateless_reset.zig`.

The application-layer sprint: closing the silent-failure traps and
adding `quic.app` / `quic.testing`, so a custom server is a
typed-callback exercise instead of a hand-rolled state-machine
porting exercise. No wire-protocol behavior changed.

### Added

- **`Client.Config.initial_dcid` — dictated initial DCID (Stable
  surface).** Optional 8..20-byte value used verbatim on the very
  first Initial instead of the random mint; `initial_dcid_len` is
  ignored (and not validated) when it is set. This is the
  rendezvous mechanic for pre-arranged dials: a server that handed
  the bytes out out-of-band can route the handshake from the first
  datagram via the RFC 8999 §5.1 header peek, before any
  decryption. The field's doc comment carries the security
  contract (bytes must be CSPRNG-unpredictable; routing, never
  authorization; Retry rewrites the wire DCID). Demonstrated
  end-to-end — including single-use claim semantics,
  nonce-confirmation, and the pinned Retry limitation — in
  `tests/e2e/rendezvous_frontend.zig`.
- **`quic.app` — opt-in application layer for server embedders.**
  `app.Driver(App)` walks the server's slots, drains each
  connection's event queue, tracks peer streams, pumps reads,
  delivers DATAGRAMs, and flushes staged writes through *typed*
  callbacks — no `?*anyopaque` contexts, no `@ptrCast` dance, no
  slot-diffing. Companion pieces usable alone: `app.StreamTable`
  (typed per-stream registry; overflow answered with STOP_SENDING,
  never a silent hang), `app.Outbox` (iteration-resumable stream
  writes that hide `streamWrite`'s short-write backpressure), and
  `app.StreamEnd` (fin / reset / reaped — the sound completion
  classification). Hooks are an explicit registration list
  (`.hooks = .{ .on_stream_data = ... }`); there is no
  `@hasDecl`-based detection anywhere in the module — comptime
  callback probing against App types from dependent modules was
  observed (0.17-dev) to answer false regardless of evaluation
  site, and a silently-missing callback is precisely the bug class
  this module exists to prevent. Per-stream state is airtight on
  every path: entries are default-constructed when first tracked,
  and connection teardown delivers the `on_stream_end` (`.reaped`)
  still owed to any mid-request stream before `on_disconnect` — so
  state freed in `on_stream_end` never leaks on abrupt disconnects.
- **`quic.testing` — shipped in-memory loopback harness.**
  `testing.Loopback` pumps a real `Server`/`Client` pair (real TLS,
  real packet protection) over in-memory datagram exchange in the
  `runUdpServer` iteration order, so downstream servers get
  in-process integration tests with no sockets, threads, or ports.
- **`Server.Config.defaultTransportParams()`**: the blessed
  non-zero flow-control / stream-count working set.
  `transport_params = .{}` compiles and handshakes but admits no
  streams — the classic first-hour footgun; a server whose params
  admit nothing now also earns a `config_warning` log event at
  init.
- **`Server.Config.mintKey()`**: CSPRNG key material for the
  32-byte key fields (`stateless_reset_key`, `retry_token_key`,
  `new_token_key`).
- **`Connection.nextDatagramSize()`**: the queued head DATAGRAM's
  full size without popping, for sizing read buffers.
- **`IncomingDatagram.payload_len`**: full on-wire payload length;
  `payload_len > len` marks truncation. Surfaced by
  `receiveDatagramInfo` only — plain `receiveDatagram` still
  truncates silently, so switch to the info variant (or size with
  `nextDatagramSize`) where truncation matters.
- Examples: `echo_server.zig` rewritten on `quic.app` (the raw
  variant preserved as `echo_server_raw.zig`, the teaching
  artifact); new `request_response_server.zig` (length-prefixed
  request/response — the pattern most protocols build on).
- `docs/ERROR_CODES.md`: one-page error reference (meaning + typical
  cause per error family). The package archive now ships the whole
  `docs/` directory (error reference, API stability, release
  readiness, stream-priority notes) — previously GitHub-URL-only,
  which broke offline consumers.

### Changed

- **`streamWrite` / `streamFinish` / `streamReset` on a
  receive-only stream now return `error.StreamNotWritable`** instead
  of accepting the data into a send half the scheduler never
  transmits — the silent stream black hole is gone. Peer input can
  never produce this; it is embedder-misuse-only.
- **`streamRead` / `streamReadFin` on a send-only stream now return
  `error.StreamNotReadable`** — the receive-side mirror. Reading a
  locally-initiated unidirectional stream used to return 0 forever,
  indistinguishable from "nothing readable right now". Same
  embedder-misuse-only contract.
- The raw echo example (`echo_server_raw.zig`) pins its buffer/limit
  couplings with `comptime` asserts (tracker size ≥ advertised stream
  limits; DATAGRAM buffer ≥ advertised frame size), mirroring the
  pattern `foreign_loop_embedder.zig` already enforced; the app-layer
  examples get the same couplings from Driver options wired to their
  advertised transport params.
- Doc drift: prose references to `nextEvent` now name `pollEvent`.

### The deduplication series

A repo-wide audit found 50 verified copy-paste families (41 worth
extracting), and this series collapses them onto shared
implementations. Internal-only in behavior except for the fixes
noted below, all of which were latent defects the duplication had
been hiding. Deterministic impairment cells stay byte-identical
throughout.

#### Fixed

- **The Windows fail-fast gate jumped ahead of argument validation.**
  The series' `WindowsBundledLoopUnsupported` up-front gate in
  `runUdpServer` / `runUdpClient` fired before buffer/address
  validation, so on native Windows a typo'd address reported as a
  platform limit — and it broke the Windows CI leg's validation and
  early-return pins (red since 2026-08-16). Validation now runs
  first on every platform; the gate fires after it, before any
  socket is bound, and the smoke tests pin the gate's own error.
- **Per-source rate limiting reset unrelated budgets.** On Initial
  window rollover, `acceptSourceRate` assigned a whole fresh
  `SourceRateEntry` instead of just its own (count, window_start) pair,
  silently zeroing the VN, log, and bandwidth axes that were added to
  the struct later. One Initial per window handed a peer a fresh
  Version-Negotiation budget (2× the configured VN amplification cap)
  and a full token bucket (up to 2× the configured per-source byte
  rate). Both consequences now have regression tests.
- **qlog congestion-state events were stamped `at_us = 0`.** The
  packet-threshold loss sweeps passed `0` where the time-threshold
  sweeps passed `now_us`; that forced the `.recovery` branch whenever a
  recovery period had ever started, and — because the event latches
  before the ACK handler's correctly-timestamped call — suppressed the
  good event and produced a spurious recovery→congestion_avoidance flap
  on lossless ACKs. `now_us` is now a required parameter.
- **Inbound ACK side effects ran in opposite orders** on the per-level
  and per-path paths (key-epoch confirmation vs stream dispatch). The
  two are independent, so this was observable only on the error path;
  it is now one order, with a comment recording that the order is free.
- **Three shipped examples ended a receive stream on "empty read + FIN
  seen", which truncates under reordering.** `streamRead` returns 0
  whenever the next in-order byte is missing, and `fin_seen` flips as
  soon as the FIN-carrying frame is accepted at any offset, so the pair
  is also the state of a stream with a hole below the FIN — a peer that
  sends `0..99`, then `200..299` with the FIN, with `100..199`
  reordered behind them, got a third of its stream echoed back and
  FIN'd, silently. `examples/echo_server.zig`,
  `examples/foreign_loop_embedder.zig`, and `examples/goodput_smoke.zig`
  now end on `Connection.streamRecvState(id).terminal` (with `null`,
  meaning reaped, treated as terminal). Library behavior is unchanged —
  the transport always reassembled correctly — but embedders who copied
  the example loop inherited the bug. EMBEDDING.md now states the rule
  under "Ending a receive stream", and a reordering regression test
  (one client datagram held back until the server is observed with the
  FIN seen and the recv half non-terminal) pins it in
  `examples/foreign_loop_embedder.zig`.

#### Changed

- `RecvStream.read` uses a sliding-window consumed prefix with a
  half-buffer compaction policy (amortized O(1) per read instead of
  O(n²)-total small-read memmoves); the resident-bytes budget now
  explicitly keys on the physical buffer, with the consumed prefix
  keeping its charge until compaction.
- Peer ECN reports are reconciled against the packets this endpoint
  actually sent with an ECT codepoint (RFC 9000 §13.4.2.2 post-errata
  bound) — monotonic-count fabrication is now rejected and flips the
  space to validation-failed.
- Breaking (Internal-tier re-exports): `Connection.wire_header` and
  `Connection.varint` are renamed to `wire_header_mod` and
  `varint_mod` to match the `_mod` namespace-alias convention
  (`short_packet_mod`, `frame_mod`, …). Consumers reaching the wire
  namespace should use `quic.wire` (unchanged); the
  `quic.conn.state.*` spellings changed.
- The bundled UDP loops allocate `max_datagrams_per_iteration ×
  rx_buffer_bytes` for the ingress batch (one jumbo datagram can no
  longer truncate its batch-mates), fail up front with
  `error.WindowsBundledLoopUnsupported` on Windows instead of deep
  inside the first timed receive, and document the tx-buffer clamp
  failure mode. EMBEDDING.md documents the SO_REUSEPORT multi-core
  pattern.
- Security audit follow-ups (full-spectrum repo audit, 2026-08):
  oversized unauthenticated datagrams are now silently discarded
  instead of closing the connection (off-path DoS); ReleaseFast and
  ReleaseSmall are rejected at build time with `--release` defaulting
  to ReleaseSafe; NEW_CONNECTION_ID receive-path closes use the
  correct FRAME_ENCODING_ERROR / CONNECTION_ID_LIMIT_ERROR codepoints
  (and the resource-exhaustion close no longer squats on 0x09);
  0-RTT now admits PATH_RESPONSE and RETIRE_CONNECTION_ID per RFC 9000
  §12.4; STREAM data beyond a locked final size surfaces
  FINAL_SIZE_ERROR even on completed streams; mTLS servers deny early
  data until the resumed handshake re-verifies identity (RFC 9001
  §4.6.4); key-update limits follow the negotiated suite's RFC 9001
  §6.6 values; AEAD contexts are cached per key set; the receive path
  classifies each payload once; and the CI matrix gained a ReleaseSafe
  test leg, a format gate, an examples leg, a job timeout, and
  SHA-pinned actions.
- Internal: ~1,600 lines of verified duplication collapsed onto shared
  implementations across loss detection (four sweeps → one
  `sweepLosses` over a `LossTarget`), inbound ACK application (two
  handlers → one applier over an `AckTarget`), the 1-RTT control drain
  (ten hand-rolled length computations → the file's existing
  `encodeFrameIfFits`), the NEW_TOKEN/Retry AEAD codecs (→ one
  `token_envelope.Envelope`), the Server rate limiters, transport-param
  encode/encodedLen, the frame codecs, the wire long-header walk, the
  UDP loops, CID registries, migration checks, flow control, Feistel,
  and more. Public API and Internal-tier paths unchanged.
- Both token wire formats are now pinned by known-answer `validate`
  tests, so a refactor can no longer silently invalidate tokens already
  issued in the field.

## [0.13.1] - 2026-08-13

The restyle release: internal-only. The whole codebase now reads like
the zig compiler's (file-as-struct, Sema-style spokes, decl-alias
method re-exports) with zero embedder-visible change — same API, same
wire behavior, byte-identical deterministic cells. Downstreams: a pin
bump should require no code changes at all.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

### Changed

- **Internal: the codebase adopts the zig compiler's layout
  conventions** (ziglang file-as-struct). `Connection`, `Server`,
  `Client`, `Server.Config`, and 14 support types are now TitleCase
  files that ARE their structs (`src/Connection.zig` with
  `Connection/` spokes, `src/Server.zig` with `Server/`, Compilation.zig
  anatomy: @This alias, imports, fields, then types and methods).
  The 20 `conn_*` method files became `Connection/<x>.zig`; 244 pure
  pass-through hub thunks became decl-alias re-exports (Sema.zig
  mechanism, −851 lines); spoke receivers are `conn:`/`server:`; the
  `*Impl` alias pattern is retired. **Zero embedder-visible change**:
  every public name and every Internal-tier path
  (`quic.conn.state.*`, `quic.conn.path.*`, …) resolves exactly as
  before, enforced per-commit by the new
  `tests/e2e/internal_surface_smoke.zig`; wire behavior byte-identical
  (deterministic impairment cells) at every phase boundary. Mechanical
  commits are listed in `.git-blame-ignore-revs`.
- Internal: the `src/server/` import seam was cleaned — pure
  header-peek/CID-key helpers moved to a new `wire_peek.zig` leaf,
  siblings now import siblings directly instead of round-tripping
  `server.zig`, and the hub-and-spokes layout rules are codified in
  `CONTRIBUTING.md`. No embedder-visible change.

### Fixed

- Test discovery: `pacing`/`hystart`/`delivery_rate` submodule tests
  were only reachable transitively; making the discovery block
  explicit recovered two silently-undiscovered tests.

## [0.13.0] - 2026-08-13

The integration release. Everything in it exists because a downstream
shipped v0.12.0 and reported back within the day: the three surfaces
the first HTTP/3 embedder asked for — a one-shot
`ConnectionEvent.early_data` (replacing a status poll that the
rejection path makes unreliable by design), send-window introspection
for real backpressure, and the 0-RTT surface promoted to the Stable
tier — plus a 1.35 MiB-per-connection memory return from right-sizing
the Initial/Handshake sent-packet trackers, closing out the warm-up
footprint growth that same downstream measured across
v0.10.1 → v0.12.0. No wire-behavior changes; defaults unchanged.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

### Added

- **`ConnectionEvent.early_data`** — one-shot event carrying the
  `EarlyDataStatus` when the 0-RTT outcome resolves (`.accepted` /
  `.rejected`; connections that never attempt 0-RTT get no event).
  Rejection is surfaced only after the verbatim 1-RTT requeue has
  run, so reactors observe post-requeue state. Replaces per-drain
  `earlyDataStatus()` polling. Additive variant under the
  `ConnectionEvent` forward-compatibility contract: exhaustive
  switches gain a compile error, which is the documented signal.
- **Send-window introspection** — `Connection.sendWindow()`
  (connection-level flow credit remaining) and
  `Connection.streamSendWindow(id) ?SendWindow`, a per-stream snapshot
  carrying the connection credit, stream credit, queued-but-unsent
  backlog, and the net `writable` figure a `canWrite`-style
  backpressure gate wants. Mirrors the send gate's own accounting
  (new-data bytes only; retransmissions are invisible; congestion
  control deliberately excluded — `sendAllowance` answers that side).
  Requested by http3-zig, whose backpressure previously could only
  consult its own buffer cap and the binary blocked events. Newly
  added surface: Unstable tier until it soaks, per policy.

### Changed

- **The 0-RTT / early-data surface is Stable tier** —
  `earlyDataStatus` (+ `EarlyDataStatus`), `earlyDataReason`,
  `setEarlyDataEnabled`, `streamArrivedInEarlyData`, and
  `setEarlyDataContextForParams` join the compile-checked Stable list
  (`tests/e2e/public_api_smoke.zig`), promoted at the request of the
  first downstream shipping HTTP/3 early data on them. The verbatim
  requeue-on-rejection behavior is documented as part of the surface.
- **Per-connection memory: −1.35 MiB** — sent-packet tracker capacity
  became an init-time choice, and the Initial/Handshake spaces are
  right-sized 4096 → 256 slots (they peak at single-digit live
  packets across the whole test/impairment corpus and sit idle after
  the handshake; 256 still covers a 100 KiB certificate-chain flight
  ~2.8×, with the sizing evidence recorded at
  `sent_packets.initial_handshake_max_tracked`). Addresses the
  v0.10.1 → v0.12.0 warm-up footprint growth measured downstream
  (~6.2 → ~3.5 MB per connection pair expected). The ACK-churn
  microbench got ~20% faster in the bargain (tracker counters now sit
  adjacent to the slots they govern).

## [0.12.0] - 2026-08-12

The shape release. BBRv3 lands as the third congestion controller —
opt-in, on a new per-packet delivery-rate measurement spine — and the
two long-standing API-shape debts close while the pre-release breaking
window is open: a `Connection` now has one address for its whole life,
and the package sheds its redundant `_zig` suffix. One migration for
downstreams covers all of it, plus the two availability fixes below
(a peer could end either bundled UDP loop).

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b.

Headline numbers (m5max dev machine; impairment cells are in-process
deterministic virtual time — identical seeds, machine-independent;
the goodput figure is wall-clock in-process; every BBR number is
measured OPT-IN via `congestion_control = .bbr`, the shipped default
is still CUBIC):

- BBR vs CUBIC on the 10 Mbit bottleneck cells: line-rate parity
  (9.71 vMbps) with peak queueing delay **85.6 ms → 16.7 ms (5.1×
  shorter queue)**; on the new shallow 25 ms buffer cell, tail drops
  **15 → 0**.
- BBR vs CUBIC, 64 MiB wall-clock bulk transfer: **249.9 → 266.5 MB/s
  (+6.7%)** — pacing at the modeled bandwidth beats window bursts
  even without a bottleneck.
- BBR vs CUBIC on the fixed-delay 1% loss cell: **53.6 → 1252 vMbps
  (23×)** — regime-specific (that cell has no bandwidth constraint;
  the bottleneck+loss cell shows parity, not fireworks), but it is
  the loss-tolerance BBR exists to provide.
- `Connection` is **~1.2 MB smaller** than 0.11.0 (the two
  Initial/Handshake trackers moved to one heap slab) at
  `@sizeOf(Connection)` = 152,224 bytes, and its address is now
  stable for life.
- Honest cost, measured and rebaselined: the sent-packet-tracker
  churn micro pays for the 40 bytes of per-packet delivery-rate
  stamps, **46.9 → 61.5 ns/op** (still ~113× better than the
  pre-0.11.0 cliff); end-to-end goodput impact −1%.

### Changed (BREAKING)

- **The package is named `quic` now, not `quic_zig`.** The `_zig`
  suffix was redundant in a Zig package name. This changes every
  consumer-facing identifier at once: `build.zig.zon` dependency key
  (`.quic = .{ ... }`), `b.dependency("quic", ...)`,
  `dep.module("quic")`, and `@import("quic")`. The manifest
  `.name`/`.fingerprint` pair changed with it, which is a new package
  identity as far as the Zig package manager is concerned — re-fetch
  rather than expecting hash continuity. The project (repo, docs,
  issue tracker) is still called quic-zig; only the package/module
  identifier shrank. Bench report metadata follows: suites are
  `quic.microbench` / `quic.bench_e2e` and the version key is
  `quic_version` (committed baselines updated in-commit, header-only).
  Historical CHANGELOG entries below keep the names that were true
  when they shipped. Migration note from the first downstream to take
  this bump: with the conventional `const quic = @import("quic")`,
  any local variable or parameter already named `quic` becomes a
  shadowing error under Zig's no-shadowing rule — rename those locals
  first (http3-zig hit 7 of them; the compile errors point at every
  one).
- **A `Connection` now has one address for its whole life** — the
  init-then-move-then-`bind()` dance is gone, and with it the window
  where moving a bound Connection silently dangled the `*Connection`
  stashed in SSL ex-data. Construction wires TLS immediately:
  - `Connection.initClient(alloc, ctx, name) !Connection` + `bind()`
    → `Connection.createClient(alloc, ctx, name) !*Connection`,
    paired with `conn.destroy()` (replaces `deinit()` + freeing your
    own box).
  - `Connection.initServer(alloc, ctx)` + `bind()` →
    `Connection.createServer(alloc, ctx) !*Connection` + `destroy()`.
  - Caller-owned storage (arenas, pools, embedding a Connection in a
    heap-allocated parent) uses `Connection.initClientAt(&slot, ...)`
    / `initServerAt(&slot, ...)`, which construct in place at the
    final address and pair with `deinit()`.
  - `bind()` no longer exists; delete the call. Migration is
    mechanical: both wrappers already heap-boxed their Connection and
    are unchanged (`Client`/`Server` APIs are not affected).
  - qlog's `connection_started` now fires from `setQlogCallback` (the
    first moment a sink exists). Previously the client-side event was
    emitted during `bind()`, which ran before wrapper users installed
    their callback — it was silently dropped for them.
  This is the structural counterpart of 0.10.0's naming shakeout:
  the last known API-shape debt closed before new surface (multipath
  productization, completion-based transports — both of which need
  pinned addresses) is built on top. `@sizeOf(Connection)` is 152,224
  bytes; it was never a by-value type in practice, and now the type
  system says so.

### Added

- **BBRv3 congestion control (opt-in)** — `congestion_control = .bbr`
  on both `Client.Config` and `Server.Config` selects a model-based
  controller per draft-ietf-ccwg-bbr-06: it paces at the estimated
  bottleneck bandwidth (windowed max delivery rate) and bounds data in
  flight to a small multiple of the estimated BDP (windowed min RTT),
  cycling Startup/Drain/ProbeBW/ProbeRTT with loss-driven short- and
  long-term inflight bounds. The default remains CUBIC — flipping it
  is gated on a multi-flow fairness cell and an interop battery (see
  the `congestion_bbr.zig` header). Built on new per-packet
  delivery-rate sampling (draft-cheng-iccrg-delivery-rate-estimation,
  as embedded in the BBR draft), a controller-owned pacing-rate
  outlet, and per-lost-packet controller inlets, each of which landed
  as its own zero-consumer/zero-delta commit. Conformance:
  `tests/conformance/bbr_draft06.zig` (26 draft-cited claims + 2
  visible-debt skips) and `draft_cheng_delivery_rate_02.zig`.
  Observability: `CongestionController.bbrSnapshot()`. On the
  deterministic impairment battery vs CUBIC (identical seeds), BBR
  holds link-limited goodput while cutting bottleneck queueing —
  full A/B table in the landing commit message.
- **`MetricsSnapshot.egress_local_faults`** — counts send attempts
  abandoned on a *local* socket fault (`NetworkDown`,
  `SystemResources`, `AccessDenied`) inside `runUdpServer`. The server
  loop deliberately does not exit on egress failure, but until now it
  also never mentioned one, so a host with no interface or no socket
  buffers served nothing while reporting perfect health. Peer-provoked
  failures are excluded by design — they are routine on the open
  internet and would bury the signal. Any sustained nonzero rate here
  means the host, not the peers.

### Fixed

- **A peer could end the bundled UDP loops.** `runUdpServer` /
  `runUdpClient` treated every non-timeout receive error as fatal,
  including three that the remote side influences: `PortUnreachable`
  and `ConnectionResetByPeer` (ICMP feedback queued against the bound
  socket and reported at the next receive — so a peer that goes away,
  or an off-path packet that provokes an ICMP, could stop a server
  from serving everyone else) and `MessageOversize` (a datagram larger
  than the per-message buffer, which the sender chooses). These are
  now tolerated and the datagram discarded, which is what
  `examples/foreign_loop_embedder.zig` already did — the bundled loops
  were the inconsistent ones. Local faults still propagate.
  Classification is pinned by `transport.classifyReceiveError` and its
  test. Thanks to the capnp-zig team, who hit the Windows half of this
  in their own receive bridge and flagged the pattern.
- **The same hole existed on the send path**, and the client loop was
  the exposed one: a peer that stops listening provokes an ICMP
  port-unreachable, which the kernel reports as `ConnectionRefused` on
  the *next send* — and the client propagated it, so any peer could
  end the loop. Now `ConnectionRefused`, `ConnectionResetByPeer`,
  `HostUnreachable`, `NetworkUnreachable`, and `MessageOversize` are
  tolerated on both loops (the datagram is lost; loss recovery
  retransmits, and a peer that is genuinely gone is closed out by the
  idle timeout, which is the clean path). Local faults still reach the
  embedder on the client and are counted on the server. All client
  egress, including the GSO path, now routes through one policy,
  pinned by `transport.classifySendError` and its test.

### Changed

- The Windows limitation of the bundled event loops is now documented
  at both `RunError` sets and in `EMBEDDING.md`, and asserted by the
  three real-socket smoke tests rather than skipped: `runUdpServer` /
  `runUdpClient` fail with `error.ConcurrencyUnavailable` on native
  Windows because std has no overlapped-I/O `net_receive` there, so no
  timed receive — the loops' heartbeat — is possible. The protocol
  engine is unaffected and remains tier-1 on Windows; embedders there
  drive their own loop. Applies equally to v0.10.x and v0.11.0.

## [0.11.0] - 2026-08-12

The performance release, measured. Three long-deferred datapath levers
land together — modern congestion control with pacing, a batched UDP
datapath, and an O(1) sent-packet-tracker fix — each backed by a new
end-to-end benchmark tier (goodput, handshakes/sec, deterministic
impairment) with committed baselines and a regression-compare tool, so
every claim below has a number behind it. All changes are additive:
the Stable API surface is unchanged and no `Config` field was renamed.

Verified toolchain: zig 0.17.0-dev.1683+5ceec001b (moved up from
0.17.0-dev.1252 during the release — see Changed).

Headline numbers (m5max dev machine; loopback for the real-socket
figure, in-process virtual time for impairment — deterministic per
seed and machine-independent):

- Slow-start overshoot on a 10 Mbit bottleneck: HyStart++ takes
  buffer-overflow drops from **111 to 0** and peak queueing delay from
  **99.7 ms to 85.6 ms** (to **33.6 ms**, −52%, with 1% background
  loss) — identically on the 8-stream multiplexed variant.

- Real-socket upload goodput **10.8 → 48.9 MB/s (4.5×)** from the
  batched datapath (batched ingress, cross-peer `sendmmsg`, Linux
  GSO/GRO).
- Sent-packet-tracker removal at high occupancy **6941 → 46.9 ns/op
  (~148×)**; the old full-tail memmove was a quadratic ACK-processing
  cliff (~590 KB moved per cumulative ACK at 4096 in flight).
- Goodput under 1% loss **44.2 → 53.6 vMbps (+21%)** from CUBIC +
  pacing combined; ~1852 handshakes/sec at 5 allocations each.

### Added

- **CUBIC congestion control (RFC 9438)** — now the default, selectable
  back to NewReno with `Server.Config` / `Client.Config`
  `congestion_control = .new_reno` (a one-line rollback; both ship
  compiled in). Congestion control is now pluggable behind a
  by-value tagged union (no allocation, no vtable). New
  `tests/conformance/rfc9438_cubic.zig`.
- **Packet pacing (RFC 9002 §7.7)** — on by default
  (`enable_pacing = false` restores the pre-0.11 burst timing exactly).
  A per-path token bucket that spreads sends at gain × cwnd/RTT;
  surfaced to foreign event loops as a new `TimerKind.pacing` deadline.
  New `tests/conformance/rfc9002_pacing.zig`.
- **RFC 9002 §7.8 application-limited gate** — the window no longer
  grows off ACKs from an unfilled pipe (both controllers).
- **HyStart++ (RFC 9406)** — on by default
  (`enable_hystart = false` restores plain RFC 9002 slow start).
  Standard slow start only stops once it overruns the bottleneck and
  loses packets; HyStart++ watches for sustained RTT inflation across
  a round and leaves slow start before the overshoot. Shared by both
  controllers (CUBIC + HyStart++ is the pairing Linux and quiche
  ship). New `tests/conformance/rfc9406_hystart.zig`.
- **Batched UDP datapath** in `runUdpServer` / `runUdpClient`: batched
  ingress (`RunUdpOptions.max_datagrams_per_iteration`, default 16),
  cross-peer egress via one `sendMany`/`sendmmsg`
  (`max_send_batch_datagrams`, default 64), and Linux UDP GSO/GRO
  (`enable_gso` / `enable_gro`, default on, probe-gated with runtime
  fallback; no effect off Linux). New public `transport.fillGsoBatch`
  + GSO cmsg helpers for foreign-loop embedders.
- **`Connection.stats()`** (`ConnectionStats`, Unstable tier) — a
  by-value observability snapshot: whole-connection byte/packet
  counters plus an active-path cwnd/RTT/PMTU snapshot and
  open-stream/close-state gauges.
- **`quic_zig.qlog`** — a real JSON Text Sequences (`.sqlog`) qlog
  writer (qlog_version 0.4) that qvis loads directly; the QNS endpoint
  emits it in place of the prior ad-hoc JSONL. The `metrics_updated`
  event now carries the (previously dead) pacing rate.
- **End-to-end benchmark tier** (`zig build bench-e2e`): in-process
  goodput, handshakes/sec, and a deterministic loss/reorder impairment
  matrix, with allocation counts and per-poll latency percentiles.
  Microbenchmarks (`zig build bench`) now report median ± MAD over N
  samples. New `zig build bench-compare` regression tool + committed
  `baselines/bench/`, and a real-socket `zig build run-goodput-smoke`.
  The impairment simulator gained a rate-limited **bottleneck link
  with a finite tail-drop buffer** and a **multi-stream transfer
  mode**, so congestion-control behavior that only appears when a
  queue builds — slow-start overshoot above all — is finally
  measurable in-tree rather than only in interop.

### Changed

- **CUBIC, pacing, and HyStart++ are the defaults** (see Added for the
  per-feature opt-outs) — the deliberate wire-behavior changes in this
  release, each landed separately and measured on its own so a
  regression bisects to one of them. Validated by the blocking
  quic-go interop gate and the weekly matrix.
- `TimerKind` gains a `pacing` variant; embedders with exhaustive
  switches over it get a compile error (the documented forward-compat
  signal) — handle unknown kinds generically (wake, tick, drain).
- `SentPacketTracker` removal is now O(1) tombstoning with amortized
  compaction; `count` includes tombstones, `liveCount()` is the
  tracked-packet count (internal API).
- The undocumented `max_datagrams_per_loop_iteration` transport
  constant (always 1) is replaced by the configurable
  `max_datagrams_per_iteration` option.
- CI: the weekly deep-fuzz budget is corrected to 1M/target (the
  documented 10M was never runnable under GitHub's job cap); a Linux
  aarch64 test leg is added; the weekly interop matrix gains goodput
  and loss-conditioned cells with a job-summary readout.
- **Toolchain moved to `0.17.0-dev.1683+5ceec001b`** (from
  `0.17.0-dev.1252`), and `minimum_zig_version` with it. The previous
  pin had been garbage-collected from ziglang.org — which keeps only
  the current master tarball — so it was no longer installable from
  its nominal source. Embedders must move up: the tree now uses
  `std.lang.Optimize`'s lowercase field names, which do not exist on
  the old pin.
- The QNS interop image no longer depends on ziglang.org retaining a
  dev tarball. It tries the Zig project's community mirrors in order
  and pins the exact SHA-256 per architecture (digests verified
  against Zig's minisign key), so the build fails closed on a bad
  mirror instead of failing open on a missing one.

### Fixed

- Quadratic ACK-processing cost at high bytes-in-flight (the tracker
  memmove cliff, above).
- A new version-negotiation-preparse fuzz harness (the 38th fuzz site)
  covers the multi-Initial ClientHello reassembler + transport-param /
  version-selection walk — the most complex parser reached before any
  TLS state exists.
- Documentation truth-up: the boringssl-zig pin box in
  `RELEASE_READINESS.md` now matches the actual SHA pin (with a new
  cross-repo pin-lint workflow), the platform tier table matches CI,
  the `EMBEDDING.md` Windows clause reflects its tier-1 status, and 27
  code comments that cited a nonexistent "hardening guide" are
  repointed to the governing RFC sections.

## [0.10.1] - 2026-08-12

Patch release over v0.10.0 so downstreams can pin a tag instead of a
raw SHA for the native-Windows build fix. Library code is byte-identical
to v0.10.0 — the only functional change is the dependency pin.

Cut on a short-lived `release/0.10.x` line off `e00d449` and merged back
into the trunk, so `v0.10.1` is an ancestor of `main` and development
stays on one thread. The tag itself is immutable and unaffected by that
merge.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19 (unchanged).

### Fixed

- **Native Windows builds no longer fail in the linker configuration
  step.** The `boringssl-zig` pin moves from tag `v0.6.4` to `0.6.5`
  (`292c70a2`), which stops `ws2_32` from being resolved through
  `pkg-config`: Git Bash can expose a `pkg-config.BAT` shim that cannot
  describe Windows SDK libraries, failing an otherwise healthy native
  build. This is a *build-configuration* fix; no runtime behavior
  changed on any platform.

  Note the pin is a commit SHA rather than a tag, because the fix
  landed upstream before boringssl-zig cut a release; see the
  cross-repo pin note in `docs/RELEASE_READINESS.md`.

## [0.10.0] - 2026-07-29

Consumer-feedback release (thanks to the capnp-zig team for a detailed
downstream audit): the private-CA / mTLS gap is closed, the build is
lighter to consume, and the release/versioning discipline consumers
asked for is now written down in CONTRIBUTING.md ("Releases"). The
`Server.Config` field names are frozen from here to 1.0.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19 — and as of this
release that is *enforced*, not just recorded: `mise.toml` pins the exact
master build instead of resolving `master` at install time.

### Added

- **Private-CA and mTLS support through the wrappers, no BoringSSL
  types required.** `Client.Config.ca_pem` is now wired: it pins the
  supplied PEM bundle as the only trust anchors (replacing, not
  augmenting, the system store) while keeping hostname/identity
  verification against `server_name`. New `Client.Config.client_cert_pem`
  / `client_key_pem` present a client certificate when the server
  requests one, and new `Server.Config.client_ca_pem` makes the server
  require and verify client certificates against a pinned bundle
  (`SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`), including
  across `replaceTlsContext(.{ .pem = ... })` rotations. Backed by the
  new `tls.pem` module (`installTrustAnchors` / `installClientIdentity`)
  and covered end-to-end by `tests/e2e/tls_verify_e2e.zig` — the first
  wrapper handshakes in the suite that run with verification ON.
  Negative coverage includes SAN mismatch, a server chaining to a
  different root, a missing client cert, an *untrusted* client cert
  (verification, not just presence), rotation carry-over, and the
  malformed-PEM error paths. Hardening details: pinned clients set
  `SSL_CTX_set_reverify_on_resume` so resumed sessions cannot inherit
  a different trust posture; a PEM bundle with a malformed block
  after valid certificates fails with `InvalidPem` instead of
  silently installing a prefix of the roots
  (`PEM_R_NO_START_LINE`-based end-of-input detection); and
  `replaceTlsContext(.{ .override = ... })` is rejected with
  `InvalidConfig` while `client_ca_pem` is configured, because an
  adopted context would silently drop the required-client-cert
  posture (mTLS servers rotate via `.pem`).
- `build.zig` now forwards boringssl-zig's `-Dboringssl-source` and
  `-Dboringssl-target` options (with `-Dboringssl-target` rejected
  unless `-Dboringssl-source=cmake`, instead of being silently
  ignored). Caveat: the boringssl-zig package archive quic-zig pins
  does not ship the `vendor/` prebuilt archives, so cmake mode
  currently requires a boringssl-zig checkout with the prebuilts
  populated (`just boringssl-cmake` upstream) wired in as a path
  dependency; the forwarding makes quic-zig transparent to that
  setup rather than the blocker.
- **`examples/foreign_loop_embedder.zig`** — a worked, tested
  integration of the caller-drives (no-I/O) path into a hand-rolled
  `std.posix.poll` reactor, plus a new
  `## Foreign Event Loops` section in EMBEDDING.md. Driving
  `feed`/`handle`, `drainStatelessResponse`, `pollDatagram`, `tick`,
  `pollEvent`, and `reap` from your own loop has always been supported;
  it was not discoverable, and a downstream consumer hand-rolled ~450
  lines of wake-pipe and timer plumbing before finding it. The example
  isolates the parts that are easy to get wrong — deadline→timeout
  conversion (past-due must clamp to 0, sub-millisecond must round up
  to 1) and the queue+wake handoff for cross-thread application work —
  as pure, separately tested units, and its in-memory test completes a
  real TLS 1.3 handshake plus stream and datagram echo through the
  pumps with no socket involved. Builds as
  `foreign-loop-embedder-example` under `zig build examples`; its
  inline tests run under `zig build test` on every tier-1 platform
  (the socket/poll group skips on Windows, where `std.posix.poll` is a
  compile error).
- `quic_zig.ConnectionError` (and `conn.Error`) re-export the error set
  `Connection`'s methods return, so embedders composing their own error
  sets stop reaching through the `conn.state` submodule path.
  `Connection.last_activity_us` is documented as a stable,
  embedder-readable connection clock — http3-zig already reads it that
  way for request-deadline enforcement.
- `build.zig` enforces `minimum_zig_version` with a `comptime` assert
  (Zig's build runner parses the field but never checks it). An
  out-of-floor toolchain now gets a one-line diagnostic naming both
  versions — in dependency builds too — instead of an unexplained
  compile error inside the tree.

### Changed (BREAKING)

- **`Server.Config` naming/semantics normalization.** This is the one
  pre-1.0 `Config` churn `docs/API_STABILITY.md` has always reserved,
  batched into this release so consumers migrate once. `Config` field
  names are frozen from here to 1.0.

  Every rate and quota knob now shares one three-state type,
  `Server.RateLimit` — `.default` (the library's recommendation),
  `.disabled` (opt out), `.{ .limit = n }` (explicit cap). `null` is no
  longer spellable for these, which is the point: when 0.3.0 turned the
  Initial-flood limiter on by default, `null` silently inverted from
  "harmless unset" to "explicitly disable a DoS mitigation", and a
  downstream consumer mirroring the old default shipped exactly that
  misconfiguration with no compile error and no failing test. Every
  stale caller is now a compile error.

  | old field | new field | migration |
  | --- | --- | --- |
  | `max_initials_per_source_per_window: ?u32 = 32` | `initial_source_rate_limit: RateLimit = .default` | `null` → `.disabled`; `n` → `.{ .limit = n }` |
  | `max_vn_per_source_per_window: ?u32 = 8` | `vn_source_rate_limit: RateLimit = .default` | same |
  | `max_log_events_per_source_per_window: ?u32 = 16` | `log_source_rate_limit: RateLimit = .default` | same |
  | `max_datagrams_per_window: ?u32 = null` | `listener_datagram_rate_limit: RateLimit = .default` | same (`.default` is off) |
  | `max_bytes_per_window: ?u64 = null` | `listener_byte_rate_limit: RateLimit = .default` | same (`.default` is off) |
  | `max_bytes_per_source_per_second: ?u64 = null` | `source_byte_rate_limit: RateLimit = .default` | same; cap is still bytes/second |
  | `enable_0rtt: bool` + `early_data_anti_replay: ?*T` | `early_data: EarlyData = .disabled` | see below |
  | `versions: []const u32` | `accepted_versions: []const u32` | rename only |
  | `max_auto_replenish_cids: usize` | `max_auto_replenish_cids: u8` | literals unchanged |

  The recommended caps are exposed as `Config.default_initial_source_rate_cap`
  (32), `default_vn_source_rate_cap` (8), and
  `default_log_source_rate_cap` (16). The listener and bandwidth
  limiters recommend "off" — the right ceiling is deployment-specific —
  so `.default` resolves to no limit for those three.

  `enable_0rtt: bool` + `early_data_anti_replay: ?*AntiReplayTracker`
  collapse into `early_data: Server.EarlyData`, a union of `.disabled`,
  `.{ .with_anti_replay = &tracker }`, and
  `.without_replay_protection`. The old pair let `enable_0rtt = true`
  with a forgotten tracker ship replay-exposed 0-RTT as a perfectly
  valid config, with no error and no log line; shipping unprotected
  0-RTT is now a deliberate, greppable choice. Migration:
  `.enable_0rtt = true` + `.early_data_anti_replay = &t` →
  `.early_data = .{ .with_anti_replay = &t }`; `.enable_0rtt = true`
  alone → `.early_data = .without_replay_protection`; omit the field to
  keep 0-RTT off.

  `usize` was the only platform-width integer in either `Config`, which
  would have frozen a field whose size differs between a 32- and
  64-bit build of the same consumer.
- The published package archive no longer ships the `bench/`, `docs/`,
  `interop/`, `tests/`, and `tools/` trees, and `build.zig` registers
  its development steps (tests, QNS endpoint, examples, docs, bench,
  interop tooling) only when quic-zig is the root package. Consumers
  fetch and configure just the module graph. Building the dev steps
  requires a git checkout — which is where they were run anyway.

### Fixed (examples)

- The canonical echo example pair silently truncated any stream larger
  than one read chunk and panicked on the documented backpressure path.
  `streamReadFin`'s `fin` reports that the FIN *frame arrived*, not that
  the application has drained the stream, so honouring it before a read
  returns zero bytes abandoned whatever was still buffered; and
  `streamWrite` short-writes by design when the send buffer is near
  `max_buffered`, which an `assert(written == n)` turned into a crash.
  Both are fixed in `examples/echo_server.zig` and
  `examples/echo_client.zig`, and `zig build run-echo-smoke` now runs a
  second leg with a payload larger than one chunk as a permanent
  regression gate. These are the examples embedders copy first, so the
  wrong pattern was the most costly part of the bug.

### Changed

- **Wire-visible close code for TLS handshake failures.** When a
  connection dies inside `Server.feed` because TLS rejected it, the
  CONNECTION_CLOSE the peer sees now carries RFC 9001 §4.8's generic
  CRYPTO_ERROR `handshake_failure` (0x0128) instead of RFC 9000 §20.1
  INTERNAL_ERROR (0x01), so a TLS rejection is no longer reported as
  "the server broke". Most rejections already carried the *specific*
  0x0100+alert code — BoringSSL's `send_alert` closes first and
  `close` is first-wins — so this only moves the alert-less handshake
  failure, but it moves it into the window a peer can classify. Three
  new public constants name the codes:
  `conn.state.transport_error_internal`,
  `transport_error_crypto_base`, and
  `transport_error_crypto_handshake_failure`. The e2e TLS suite now
  asserts rejection close codes land in 0x0100-0x01ff on both sides.
- **The pinned Zig toolchain is now reproducible.** `mise.toml` pinned
  `zig = "master"`, which resolves at install time, so every CI job
  silently ran whatever master shipped that morning rather than the
  compiler the release was verified against. It now pins the exact build
  (`0.17.0-dev.1252+e4b325c19`). This is a development-tooling change —
  it does not affect the published module — but it is what makes the
  "Verified toolchain" line above meaningful, and it is worth copying if
  you also track Zig master.

### Fixed

- `Client.Config.ca_pem` no longer rejects every non-null value with
  `error.InvalidConfig` (the 0.3.0 "trap field"). The only remaining
  `InvalidConfig` cases are genuinely contradictory configs: `ca_pem`
  with `insecure_skip_verify`, credential fields combined with
  `tls_context_override`, an empty bundle, or a cert/key half-pair.
  (An unparseable non-empty bundle fails with `InvalidPem`.)
- `Server.replaceTlsContext(.{ .pem = ... })` re-installs the 0-RTT
  anti-replay callback (`Config.early_data`'s tracker) on the
  replacement context. Previously a hot cert rotation on a 0-RTT
  server silently disconnected TLS-layer replay protection for every
  ticket minted after the swap (RFC 9001 §5.6).
- **CONTRIBUTING.md's fuzzing guidance was wrong in two ways**, both
  corrected against the pinned toolchain. macOS *can* deep-fuzz
  (`zig build test --fuzz=1000` completes on aarch64-macOS with real
  coverage; the old note described 0.17.0-dev.1158 behaviour). And
  adding `-ffuzz` / `Module.fuzz` by hand is actively harmful: `--fuzz`
  already instruments the root module, where every fuzz target lives, so
  setting the per-module flag only instruments `quic_zig` where it is a
  non-root dependency and breaks the link with seven undefined
  `runner_*` symbols on every platform. There is now also a documented
  way to check a deep-fuzz run actually collected coverage, because exit
  status alone is not sufficient evidence.
- The `quic-go-interop` and `interop` workflows had been failing since
  2026-07-09: both check the repo out into a `quic-zig/` subdirectory,
  but the dependency-prefetch step ran at the workspace root (`no
  build.zig file found`, exhausting all retries) and the package-cache
  path and key resolved one level too high, so the cache never hit and
  its key could never invalidate.

## [0.9.0] - 2026-07-09

The application-readiness release: every gap between "protocol-complete"
and "an application can be built on this" identified by the 2026-07
embedding audit is closed. Applications get stream/handshake lifecycle
events, hostable packaged UDP loops, ordered connection teardown,
working 0-RTT and client migration through the wrappers, a canonical
echo example pair exercised in CI over real sockets, generated API
docs, and out-of-tree consumption checks.

Verified toolchain: zig 0.17.0-dev.1252+e4b325c19.

### Added

- `ConnectionEvent.handshake_established`: one-shot event surfaced on the
  first `pollEvent` after `handshakeDone()` latches, so embedders no longer
  poll `phase()` to learn 1-RTT is usable.
- `ConnectionEvent.stream_opened` (`StreamOpenedInfo`): lossless, in-order
  notification of peer-initiated stream opens — including RFC 9000 §3.2
  implicit creation — via a watermark chase over the opened-stream counters
  instead of an overflowable queue. Removes the per-tick
  `streamIterator` diff-scan every application previously hand-rolled.
- `Server.Slot.user_data`: embedder-owned per-connection pointer, so
  application state hangs off the slot instead of a parallel
  `slot_id`-keyed map.
- `Server.Config.on_connection_will_close`: ordered-teardown hook invoked
  inside `reap` while the slot and its `Connection` are still valid —
  closes the use-after-free window between reap and application-side
  session cleanup (the http3-zig integration seam).
- `Server.nextTimerDeadline`: aggregate earliest timer deadline across all
  live slots, for event loops that sleep until the next deadline instead
  of fixed-tick polling.
- `RunUdpOptions.on_iteration` / `RunUdpClientOptions.on_iteration`:
  per-iteration application hooks on the packaged UDP loops, making them
  hostable for interactive applications. The hooks run on the loop thread
  (the loops' single-threaded contract is unchanged); hook errors
  propagate out, so both run functions now return `anyerror!void`.

- 0-RTT now works end-to-end through the wrappers. `Server` installs the
  RFC 9001 §4.6.1 replay context on every fresh slot before the
  ClientHello is processed (`Config.enable_0rtt` is now a complete
  recipe; `Config.early_data_application_context` binds app semantics
  into the digest), and the client recovers from 0-RTT rejection
  in-library — the handshake continues as 1-RTT and staged early data
  is requeued automatically, with the outcome observable via
  `earlyDataStatus()`. Previously the server wrapper could never accept
  early data and a rejected client needed an Internal-tier call to
  survive.
- `Client.Config.new_session_callback`: session-ticket capture that
  hands the application ready-to-persist `tls.resumption_state`
  envelope bytes (ticket + remembered peer transport parameters) —
  the persistence half that `Config.resumption_state` always assumed
  existed.
- `Server.Config.auto_replenish_connection_ids` (on by default when
  `stateless_reset_key` is set): proactive post-handshake
  NEW_CONNECTION_ID top-up so client active migration works against a
  default-configured server. Migration refusals are now typed
  (`MigrationPreHandshake` / `MigrationValidationPending` /
  `MigrationNoFreshPeerCid`) instead of all conflating into
  `PathLimitExceeded`.
- `Connection.negotiatedAlpn()`: the ALPN protocol selected during the
  handshake, for multi-protocol servers.
- Canonical echo examples over real UDP sockets: `examples/echo_server.zig`
  (Server + `runUdpServer` + `on_iteration` event loop, `Slot.user_data`
  per-connection state freed in `on_connection_will_close`, SIGINT
  shutdown) and `examples/echo_client.zig` (Client + `runUdpClient` hook
  state machine), plus `zig build run-echo-smoke` — a one-process binary
  that runs the full stream+DATAGRAM echo round trip on loopback and
  gates CI, so the hostability surface is exercised end-to-end on every
  push.
- `zig build docs`: Zig autodocs for the `quic_zig` module, emitted to
  `zig-out/docs`.
- Exported the shared `boringssl` module instance from build.zig
  (`dep.module("boringssl")`) so consumers can construct
  `tls_context_override` values (private-CA pinning) with correct type
  identity, and added an out-of-tree consumer package
  (`tools/consumer-smoke/`, CI-checked) proving tag consumers can wire
  both modules.

### Fixed

- EMBEDDING.md's raw connection cycle example now compiles and works
  against a real network: it includes the mandatory `conn.advance()`
  handshake kick after `Client.connect`, an `else` arm on the `pollEvent`
  switch (as the forward-compatibility contract requires), the current
  std random API, and the real `resumption_state` config field name.
- Documented the previously-invisible operational contracts: DATAGRAM
  support requires a nonzero `max_datagram_frame_size` transport param,
  local transport-parameter caps (16 MiB windows, 4096 streams, 16 CIDs)
  reject with `error.InvalidValue`, and `handle`/`feed` need a mutable
  buffer. Replaced the data-racing "cooperating task" threading advice
  with the real single-threaded serialization contract, and fixed the
  dangling doc cross-references in EMBEDDING.md/README.md.
- README gained a "Consuming this package" section (exact `zig fetch`
  pin, module wiring, toolchain floor, macOS `COPYFILE_DISABLE=1`) and
  the quick-start now shows the stream write path
  (`openNextBidi`/`streamWrite`/`streamFinish`/`streamReadFin`).

## [0.8.0] - 2026-07-05

### Added

- Added a public API smoke test for the documented 1.0 Stable tier. The test
  compiles against the wrapper/config types, transport helpers, core
  `Connection` loop, lifecycle, stream, DATAGRAM, event payload, and top-level
  re-export surface without introducing a breaking namespace split.
- Added a manual `rc-fuzz` workflow for pre-release gates. It runs unfiltered
  `zig build test --fuzz=1M` by default, uploads the fuzzer cache/crash
  artifacts, and is blocking by design; the weekly fuzz workflow remains
  advisory.

### Changed

- Marked the 1.0 API partition gate satisfied by the audited
  `docs/API_STABILITY.md` tiering plus compile-time smoke coverage. The final
  curated `1.0.0` changelog remains open for the actual RC/final release.

## [0.7.6] - 2026-07-05

### Changed

- Promoted the native `windows-latest` CI leg from advisory to blocking after
  the v0.7.5 release line proved green, and reconciled the 1.0 release
  readiness checklist with the verified quic-go interop and sanitizer state.

## [0.7.5] - 2026-07-05

### Fixed

- Fixed the native Windows CI leg by making interop-helper path tests
  separator-neutral, accepting BoringSSL's platform-specific TLS 1.3 cipher
  preference, skipping std.Io loopback smoke tests that currently hit
  `ConcurrencyUnavailable` on Windows, and keeping ReleaseSafe benchmark
  fixtures out of the default Windows `zig build test` path.

## [0.7.4] - 2026-07-05

### Fixed

- The pinned quic-go hard interop gate now lets the runner own and create its
  log directory, writes the JSON result outside that log tree, and uploads
  both directories from the correct GitHub workspace path.

## [0.7.3] - 2026-07-05

### Fixed

- The pinned quic-go hard interop gate can assume compliance for the pinned
  quic-go peer so the stale runner unknown-testcase preflight does not skip
  the real `H,D` client tests.
- The QNS image workflow now keeps image-build validation blocking while
  gating GHCR publication behind the `QNS_IMAGE_PUBLISH` repository variable,
  avoiding red CI when the package does not grant this repository write access.

## [0.7.2] - 2026-07-05

### Changed

- Repointed `boringssl_zig` to the `v0.6.4` release tag, which keeps the
  GitHub mirror source fetch and adds Windows SDK macro hygiene, no-asm
  fallback, and Winsock linking for BoringSSL native Windows builds.

### Fixed

- Socket-option and ECN helper code now gates POSIX-only cmsg /
  `setsockopt` paths on Windows so `qns-endpoint` reaches the link step on
  Windows instead of failing during Zig source analysis.

## [0.7.1] - 2026-07-05

### Changed

- Repointed `boringssl_zig` to the `v0.6.2` release tag, which keeps the
  sanitizer propagation from v0.6.1 while switching BoringSSL source fetches
  to the GitHub mirror and fixing the standalone consumer build under current
  Zig master.

## [0.7.0] - 2026-07-05

### Added

- Versioned persisted 0-RTT state formats. `quic_zig.tls.resumption_state`
  encodes a strict `QZRS` envelope around BoringSSL session bytes plus the
  remembered peer transport parameters, and `tls.AntiReplayTracker` can now
  `encode` / `restore` a `QZAR` anti-replay snapshot while preserving replay
  and FIFO behavior.
- `-Dsanitize-c=off|trap|full` build option for quic-zig-owned modules, plus
  a Linux CI job that runs `zig build test -Dsanitize-c=full`.
- Blocking quic-go interop workflow for QNS client `H,D`, using a pinned
  quic-interop-runner ref and pinned quic-go image digest. The broader
  advisory interop matrix uses the same pins.

### Changed (BREAKING)

- `Client.Config.session_ticket` and
  `Client.Config.resumption_peer_transport_params` were replaced by
  `Client.Config.resumption_state`. Use `tls.resumption_state.encode` /
  `encodeAlloc` to build the envelope; passing raw BoringSSL session-ticket
  bytes is rejected as `InvalidConfig`.
- `boringssl_zig` is now pinned to the `v0.6.1` release tag instead of a
  bare commit tarball, and quic-zig forwards `-Dsanitize-c` into that
  dependency so the BoringSSL C/C++ libraries are instrumented consistently
  with the Zig wrapper modules.

### Fixed

- `setLocalScid` and `setTransportParams` are now order-independent for the
  Initial Source Connection ID (RFC 9000 §7.3). A low-level caller that sets
  transport parameters before latching its SCID (as the e2e harness and some
  embedders do) previously shipped without an ISCID; the first `setLocalScid`
  now back-fills the ISCID into the already-encoded parameters and re-pushes
  them, so strict peers see it regardless of call order. A caller-supplied
  ISCID is left untouched. `setLocalScid`'s error set is now inferred (it may
  surface the re-push's errors); this only affects code that exhaustively
  switched on its previous `Error` set.

## [0.6.1] - 2026-07-05

### Fixed

- `setTransportParams` now advertises `initial_source_connection_id`
  (RFC 9000 §7.3), filled from the connection's own SCID, so callers of the
  low-level `Connection` API don't have to. Omitting it is a hard handshake
  rejection on strict peers (quic-go closes with TRANSPORT_PARAMETER_ERROR),
  which is why in-tree loopback interop passed while every real foreign peer
  failed. Validated live against webtransport-go.
- Replayed STREAM / RESET_STREAM frames for an out-of-order reaped peer
  stream (one above the contiguous reaped watermark, when a lower peer
  stream is still live) no longer resurrect the stream. `peerStreamAlreadyReaped`
  now consults the per-index reaped bitset in addition to the watermark, so
  such post-terminal frames are ignored per RFC 9000 §3.2.

## [0.6.0] - 2026-07-04

RFC 9218 (Extensible Priorities) stream-priority scheduling. See
`docs/stream-priority.md`. Additive — no breaking upgrade actions.

### Added

- `quic_zig.StreamPriority` (`urgency` 0–7, default 3; `incremental`) and
  `Connection.streamSetPriority(id, p)` / `streamPriority(id)`. The
  application-data send scheduler emits ready streams by RFC 9218 §10
  priority: **urgency** first, then within a band **non-incremental** streams
  lead in stream-id order (head-of-line) and **incremental** streams are
  round-robined so no one monopolizes the band. A higher-urgency stream's
  bytes therefore lead each packet. With no explicit priorities every stream
  is non-incremental urgency 3, so the order is deterministic stream-id
  ascending — a no-op in observable behavior for non-prioritizing embedders.
  Cross-path priority interactions with multipath remain out of scope (see
  `docs/stream-priority.md`).

## [0.5.0] - 2026-07-04

Additive, reap-robust public accessors and re-exports so an HTTP/3-class
embedder can observe the
transport's FIN / stream-id / datagram-size / send-stats / event-payload
truth without reaching into internal modules or reimplementing bookkeeping
the transport already owns. All changes are additive — no breaking upgrade
actions.

### Added

- Top-level re-exports for the types carried through `ConnectionEvent`
  (`DatagramSendEvent`, `FlowBlockedInfo` / `FlowBlockedKind` /
  `FlowBlockedSource`, `ConnectionIdReplenishInfo`) plus `path.Address`
  (the peer-address type used by `handle` / `pollDatagram`), so an embedder
  can name the payloads it destructures out of `ConnectionEvent` without
  reaching into `conn.*` / `conn.state.*` / `conn.path.*`.
- `Connection.peekNextBidi` / `peekNextUni`: return the id `openNextBidi` /
  `openNextUni` would use next, without consuming it or advancing the
  counter — so an embedder can run a stream-limit / GOAWAY gate keyed on
  the id *before* opening, then open.
- `Connection.streamSendStats(id)` → `StreamSendStats { written, acked,
  buffered, has_pending }`: a send-half backpressure snapshot that doesn't
  reach through `stream(id).?.send` into `SendStream`. Returns `null` for a
  stream not in the live table (never opened or already reaped).
- `Connection.streamReadFin(id, dst)` → `StreamReadResult { n, fin }`: like
  `streamRead` but reports the peer's FIN inline with the read that drains
  it, so an embedder detects end-of-stream without inspecting the receive
  half (which the stream GC reaps the moment it goes terminal).
  `streamRead` keeps its `Error!usize` signature.
- `Connection.streamRecvState(id)` → `?StreamRecvState { fin_seen,
  reset_seen, terminal }`: a non-consuming recv-half query that
  distinguishes a clean FIN from an abortive RESET (which
  `recvFullyTerminated` collapses) and returns `null` for a reaped/unknown
  stream — no `*Stream` to keep valid across a reap.
- `Connection.maxDatagramPayload()`: the current maximum RFC 9221 DATAGRAM
  payload, now public and PMTU-aware. It tracks the active path's validated
  PMTU (grows on a validated larger path, shrinks after a black-hole)
  rather than the static 1200-byte floor, still bounded by the peer's
  `max_datagram_frame_size`. Behavior at the 1200-byte floor is unchanged,
  and RFC 9221 §5 no-fragmentation is preserved by the existing send-time
  build guard.

### Changed

- The QUIC interop endpoint now accepts the `ecn` testcase — it was missing
  from `run_endpoint.sh`'s allow-list (so the runner's `ecn` cell hit the
  catch-all `exit 127`) despite the endpoint always marking ECT(0) on
  egress and parsing the TOS cmsg on ingress. The QNS Docker image and the
  external-interop tool now pin Zig `0.17.0-dev.1158` to match
  `build.zig.zon` instead of the stale `dev.269`.

## [0.4.0] - 2026-07-04

Downstream-enablement release: transport-layer primitives an HTTP/3-class
layer needs on day one, so it binds against a stable, ergonomic surface
instead of reimplementing stream-id math and shutdown logic, plus 1.0
API-stability documentation and toolchain fixes.

All changes are additive — no breaking upgrade actions are required. One
note: `Connection.Error` gains a `ShuttingDown` variant; per the new
stability contract (see `docs/API_STABILITY.md`), handle the error set with
an `else` branch so added variants don't break an exhaustive switch.

### Added

- `quic_zig.StreamType` (`client_bidi` / `server_bidi` / `client_uni` /
  `server_uni`) with `fromId`, `streamId(index)`, and
  `isBidi`/`isUni`/`initiatedBy*` helpers, plus role-aware
  `Connection.openNextBidi` / `openNextUni` (and `localStreamType`) that
  choose the next local-initiated id automatically — so an embedder needn't
  hand-roll the RFC 9000 §2.1 low-two-bit encoding for the HTTP/3 control
  stream (3) and QPACK streams (4, 5). On `StreamLimitExceeded` the id is
  not consumed, so a retry after the peer raises the limit reuses it.
- `Connection.phase()` returning `quic_zig.ConnectionPhase`
  (`initial` / `handshake` / `established` / `closing` / `draining` /
  `closed`), composing the handshake epoch with the existing RFC 9000 §10
  close states so embedders can gate stream creation and shutdown without
  inferring the epoch from `handshakeDone` / `closeState` / `haveSecret`.
- `Connection.beginGracefulShutdown()` / `gracefulShutdownActive()`: an
  orderly-shutdown primitive (a transport-level GOAWAY substitute — QUIC
  has no GOAWAY frame). While active, new local stream opens are refused
  with the new `Error.ShuttingDown` and no further MAX_STREAMS credit is
  granted, so the peer's stream limit freezes and both sides quiesce
  new-stream creation while in-flight streams drain to completion. The
  connection stays open until the embedder calls `close`.

### Changed

- Documented API stability tiers in `docs/API_STABILITY.md`: which surfaces
  are stable (1.0 semver target) vs evolving vs internal, the
  `ConnectionEvent` forward-compatibility contract, and the sunset path for
  the draft-based extensions (QUIC-LB draft-21, alt-addr draft-00).
- Added `docs/stream-priority.md`, documenting the RFC 9218 (urgency +
  incremental) stream-priority model.
- The QUIC interop endpoint now initiates an RFC 9001 §6 key update from the
  server role too (previously client-only), so the `keyupdate` testcase
  exercises both directions.
- Fuzzing workflow: removed the filtered-binary parallel fuzz steps
  (`zig build fuzz` and the per-site targets). Deep coverage-guided fuzzing
  is the unfiltered `zig build test --fuzz`, matching CI. The committed
  regression corpus (inline `.corpus` seeds, run by every `zig build test`)
  and the workflow are documented in `CONTRIBUTING.md`.

### Fixed

- `version()` returned a hardcoded `"0.2.0"` while the package manifest
  declared `0.3.0`. It is now single-sourced from `build.zig.zon` through a
  `build_options` module, so it can never drift from the manifest again.

## [0.3.0] - 2026-07-03

Hardening release from a full security & robustness review: closes a
remote-crash DoS and a set of untrusted-input / DoS / correctness issues,
and flips several server and client defaults to be secure by default.

**Upgrade notes — behavior changes that may require action:**

- **Client TLS now verifies by default.** `Client.connect` verifies the
  server certificate against the system trust store. Clients talking to
  self-signed or test peers must now set
  `Client.Config.insecure_skip_verify = true`. A non-null `ca_pem` is
  rejected with `InvalidConfig` (it was previously ignored); pin a private
  CA with a fully configured `tls_context_override`.
- **Server idle timeout defaults to 30s.** `Server.init` substitutes
  `Server.default_server_idle_timeout_ms` when
  `transport_params.max_idle_timeout_ms` is `0`; set
  `Server.Config.allow_no_idle_timeout = true` to keep no idle timer.
- **Per-source Initial-flood limiter is on** at 32/window
  (`Server.Config.max_initials_per_source_per_window`); set it to `null`
  to disable (enforcement is a no-op for unattributed `from == null`
  datagrams).

### Added

- End-to-end loss-recovery test: drops one 1-RTT data packet through the
  mock transport and asserts the lost frames are retransmitted (all data
  + FIN still arrive) and the client's congestion window shrinks below its
  drop-time value — exercising the Connection-level loss → retransmit →
  NewReno response chain that was previously only unit-tested against
  hand-built primitives.
- Coverage-guided fuzz targets for the remaining untrusted-facing
  crypto/parse paths: the QUIC-LB CID decoder (`lb-decode`), the 1-RTT
  decrypt entry point (`open-1rtt`), and Initial key derivation
  (`initial-derive`). Validated via the `zig build test` smoke run. Deep
  coverage-guided `zig build fuzz` aborts with "reached unreachable code"
  on macOS — a `std.testing.fuzz` fuzzer-runtime platform gap that
  reproduces with a trivial standalone fuzz test and affects every fuzz
  target — so run deep fuzzing on Linux, as CI does.

### Security

- The server per-source Initial-flood limiter is now on by default
  (`Config.max_initials_per_source_per_window = 32`, the previously
  recommended value); set it to `null` to disable. Enforcement applies
  only to attributed (`from != null`) datagrams.
- `Server.init` now substitutes a safe 30s idle timeout when
  `transport_params.max_idle_timeout_ms` is left at 0, instead of
  standing up a server with no idle timer. Set the new
  `Config.allow_no_idle_timeout = true` to genuinely disable it.
- Client TLS is now secure by default: `Client.connect` verifies the
  server certificate against the system trust store unless the new
  `Client.Config.insecure_skip_verify` opt-out is set. The previous
  default performed no verification. A non-null `ca_pem` (not yet wired
  into the auto-built context) is now rejected with `InvalidConfig`
  rather than silently downgrading to system-store verification.

### Fixed

- Prevent a remote-triggerable panic in `RttEstimator.update`: a
  peer-controlled ACK `ack_delay` (unclamped before handshake
  confirmation) could overflow `min_rtt + ack_delay` in ReleaseSafe.
  The ACK-delay scaling now saturates and the estimator uses a
  saturating add.
- Restore Retry / NEW_TOKEN issuance for IPv6 peers: the token address
  cap (22) was smaller than a full IPv6 address context (23), so every
  IPv6 client was denied a token. The cap now tracks
  `path.Address.context_max_len` and is guarded by a comptime assert.
- Convert frame-decode errors (unknown type, truncation) into a
  FRAME_ENCODING_ERROR connection close at the dispatch boundary instead
  of propagating them out — a single malformed frame from an
  authenticated peer no longer tears down the transport loop, and the
  server no longer mislabels the close as INTERNAL_ERROR.
- Bound the out-of-order CRYPTO reassembly queue by fragment count (not
  just byte volume) to stop a tiny-fragment flood from driving the
  O(n²) drain into CPU exhaustion.
- `alt_addr.recommendedMigrationDelayMs` no longer overflows (a
  ReleaseSafe panic) when the requested delay window spans the whole
  `u64` range; it now draws over the full range instead.
- Retry and NEW_TOKEN now bind the connection's negotiated / the inbound
  Initial's QUIC version instead of a hardcoded v1, restoring real
  cross-version token separation for v2-capable servers. No behavior
  change for the default single-version (v1) server.
- Server `cid_table` collision handling: `resyncSlotCids` no longer
  overwrites a CID routed to a different live slot, and slot reaping only
  removes routing entries it still owns — so an (astronomically unlikely)
  CID collision can no longer silently re-route or un-route a peer.
- Suppress frame re-processing on a duplicate application packet number:
  a replayed authenticated 1-RTT packet is still acknowledged but no
  longer re-delivers its (non-idempotent) DATAGRAM frame or double-charges
  the resident-bytes budget (RFC 9000 §12.3 / §13.1).
- Reject post-terminal frames for a reaped peer stream: a STREAM or
  RESET_STREAM for a peer-initiated stream that already reached a terminal
  state and was reclaimed is now ignored (RFC 9000 §3.2) instead of
  resurrecting the stream with fresh state (losing its locked final size /
  reset state). Uses a bounded per-direction contiguous "reaped" watermark
  that correctly distinguishes reaped streams from implicitly-opened,
  never-yet-used lower-numbered streams.
- Bound the pre-transport-parameters per-stream send window. It previously
  defaulted to `maxInt` before the peer's parameters were known; it is now
  bounded by embedder-supplied remembered session parameters during a
  0-RTT resumption (new `Client.Config.resumption_peer_transport_params`
  and `Connection.setRememberedPeerTransportParams`), and is 0 for a plain
  connection (which never sends application data before its parameters
  arrive). 0-RTT without remembered parameters keeps its prior behavior.

### Changed

- Documented the `runUdpClient` / `runUdpServer` threading contract:
  `Connection` is single-threaded with no internal locking, so all
  access (loop and application work) must be serialized onto one thread.
- Bumped `minimum_zig_version` to the verified `0.17.0-dev.1158+1d1193aa7`
  and recorded the last-verified master build in `mise.toml`.

- Updated to Zig `0.17.0-dev.813+2153f8143` (configure/maker build
  split): forwarded `zig build ... -- <args>` now use
  `Step.Run.addPassthruArgs()` instead of the removed `b.args`, and
  `minimum_zig_version` reflects the verified master build.
- Bumped `boringssl_zig` to 0.6.1 for the same Zig master
  compatibility fixes.
- Reworked the public README and usage docs around stable embedding,
  interop, benchmark, and conformance workflows.

## [0.2.0]

### Added

- High-level `Server` and `Client` wrappers around the raw
  `Connection` state machine.
- `transport.runUdpServer` and `transport.runUdpClient` for simple
  `std.Io` UDP loops.
- QUIC v2 compatible Version Negotiation support.
- Retry, NEW_TOKEN, stateless reset token helpers, and key logging
  surfaces.
- 0-RTT session support with anti-replay integration hooks.
- ECN, DPLPMTUD, migration, preferred address, DATAGRAM, and qlog-style
  event surfaces.
- QUIC-LB draft 21 helpers, including plaintext, single-pass AES, and
  four-pass Feistel CID modes plus decode support.
- Alternative Server Address draft 00 codec, emit, receive event, and
  embedder example support.
- RFC-traceable conformance suites and a microbenchmark harness.
- Official QUIC interop-runner endpoint and wrapper.

### Changed

- Public module name is `quic_zig`.
- Production guidance requires `-Doptimize=ReleaseSafe` for
  internet-facing builds.
- Generated interop outputs are ignored under `interop/logs*` and
  `interop/results`.

## [0.1.0]

### Added

- QUIC v1 packet, frame, transport-parameter, stream, loss-recovery,
  and TLS glue foundations.
- BoringSSL-backed TLS 1.3, AEAD, HKDF, and header protection.
- Initial unit and end-to-end smoke tests.

## [0.0.0]

### Added

- Initial repository scaffold.
