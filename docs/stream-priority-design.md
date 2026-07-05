# Stream priority — design spike

**Status: implemented in 0.6.0.** `StreamPriority` (urgency + incremental),
`Connection.streamSetPriority` / `streamPriority`, and the urgency-ordered
application-data send scheduler (`collectSendableStreamsByPriority`, driving
the STREAM-drain loop in `pollLevelOnPath`) landed together with http3-zig's
first prioritized workload, which validates the ordering. The `incremental`
hint is stored but not yet used to interleave equal-urgency streams — that
refinement is deferred until a consumer needs it (see below).

This spike records the intended shape of a stream-priority API so the
downstream HTTP/3 layer can be built against a known target, while
*deliberately* deferring the implementation until that layer exists to
validate the ordering semantics. Shipping an unvalidated priority field
now would bake a guess into the 1.0 surface — exactly the churn we want to
avoid.

## Why it's deferred, not built

- The transport today exposes a `Scheduler` enum for **path** selection
  (`primary` / `round_robin` / `lowest_rtt_cwnd`), but nothing for
  **per-stream** ordering. `streamIterator` yields streams in hash-map
  order.
- HTTP/3 prioritization (RFC 9218) is a *client signal* the server *may*
  honor. The transport can't know the right ordering policy until the H3
  layer defines how it maps requests to streams and consumes the ordering.
- A minimal `streamSetPriority` field added now becomes public 1.0 surface.
  If the H3 layer then wants different granularity (e.g. per-frame vs
  per-stream, or a distinct default), we'd break it. Better to co-design
  the field with the first real consumer.

## Target model: RFC 9218 (Extensible Priorities)

RFC 9218 is intentionally small — two parameters, no priority tree
(unlike the withdrawn RFC 7540 model):

- **urgency** `u`: integer `0`–`7`, lower is more urgent, default `3`.
- **incremental** `i`: boolean, default `false`. `true` means the response
  can be delivered in interleaved chunks; `false` means deliver one such
  stream to completion before the next of equal urgency.

The transport-side primitive should carry exactly these two values and no
more — the tree logic, header/frame parsing (`priority` request header,
`PRIORITY_UPDATE` frame), and reprioritization policy all belong in the H3
layer.

## Proposed API (for when we build it)

```zig
pub const StreamPriority = struct {
    urgency: u3 = 3,        // 0 = most urgent … 7 = least; RFC 9218 default 3
    incremental: bool = false,
};

// On Connection:
pub fn streamSetPriority(self: *Connection, id: u64, p: StreamPriority) Error!void;
pub fn streamPriority(self: *const Connection, id: u64) ?StreamPriority;
```

Ordering hook: `streamIterator` (or a new `streamSendIterator`) yields
send-ready streams ordered by `(urgency asc, then a round-robin rotation
among equal-urgency incremental streams, then stream-id asc for
non-incremental)`. The scheduler in `pollLevelOnPath`'s STREAM-drain loop
consults this order when choosing which stream's bytes to emit next.

Storage: a `priority: StreamPriority` field on `Stream` (default
`.{}`), set at open time or updated later. Default behavior with no
explicit priority is unchanged from today (all streams equal urgency,
non-incremental → effectively stream-id order).

## Scope boundary

Explicitly **out of scope** for the eventual first implementation:

- RFC 9218 header / `PRIORITY_UPDATE` frame parsing (H3 layer).
- Any RFC 7540-style dependency tree or weights.
- Cross-path priority interactions with multipath scheduling.

## What shipped vs. what's deferred

Shipped in 0.6.0: the `StreamPriority` field, `streamSetPriority` /
`streamPriority`, and strict **urgency** ordering in the send scheduler (ties
broken by stream id) — the primary RFC 9218 mechanism, validated by
http3-zig honoring the `priority` header / `PRIORITY_UPDATE`.

Deferred (add when a consumer needs it): the `incremental` round-robin
rotation among equal-urgency incremental streams. Today equal-urgency streams
are served in stream-id order regardless of `incremental`, which is a valid
(if not fully RFC-9218-optimal) policy. The stored `incremental` flag is the
hook for that refinement. Still explicitly out of scope: any RFC 7540-style
dependency tree, and cross-path priority interactions with multipath.
