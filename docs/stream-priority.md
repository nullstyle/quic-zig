# Stream priority

quic-zig schedules application-data sends by stream priority, following
RFC 9218 (Extensible Priorities). Each stream carries an urgency and an
incremental hint; the send scheduler uses them to decide which ready
stream's bytes go on the wire next.

Priority is a transport-side primitive. The RFC 9218 `priority` request
header and `PRIORITY_UPDATE` frame — and any reprioritization policy — are
parsed and mapped onto this primitive by the HTTP/3 layer above.

## Model: RFC 9218 (Extensible Priorities)

RFC 9218 is intentionally small — two parameters, no priority tree (unlike
the withdrawn RFC 7540 model):

- **urgency** `u`: integer `0`–`7`, lower is more urgent, default `3`.
- **incremental** `i`: boolean, default `false`. `true` means the response
  can be delivered in interleaved chunks; `false` means deliver one such
  stream to completion before the next of equal urgency.

The transport primitive carries exactly these two values and nothing more.

## API

```zig
pub const StreamPriority = struct {
    urgency: u3 = 3,        // 0 = most urgent … 7 = least; RFC 9218 default 3
    incremental: bool = false,
};

// On Connection:
pub fn streamSetPriority(self: *Connection, id: u64, p: StreamPriority) Error!void;
pub fn streamPriority(self: *const Connection, id: u64) ?StreamPriority;
```

Each `Stream` carries a `priority: StreamPriority` field (default `.{}`), set
at open time or updated later. With no explicit priority every stream is
non-incremental at urgency 3, so ordering reduces to stream-id ascending.

## Scheduling

When choosing which stream's bytes to emit next, the connection yields
send-ready streams in priority order:

- **urgency** ascending — a higher-urgency stream's bytes lead each packet.
- Within one urgency band:
  - **Non-incremental** streams lead, in ascending stream-id order —
    head-of-line, each served toward completion before the next. They are
    ordered ahead of incremental streams in the same band.
  - **Incremental** streams are round-robined: a per-connection cursor
    advances past the incremental stream that led each packet, so a
    different one leads the next and no single incremental stream
    monopolizes the band's bandwidth.

## Scope

Out of scope:

- Any RFC 7540-style dependency tree or weights.
- Cross-path priority interactions with multipath scheduling.
