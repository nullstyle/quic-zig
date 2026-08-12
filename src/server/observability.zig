// Server observability: the LogEvent / LogCallback surface, metrics
// and rate-limit snapshots, the log-event rate limiter, and the emit
// plumbing. Split from server.zig; server.zig re-imports the types
// under their original private aliases and keeps thin method thunks,
// so the embedder surface (Server.LogEvent, Server.metricsSnapshot,
// ...) is unchanged.

const std = @import("std");
const server_mod = @import("../server.zig");
const Server = server_mod.Server;
const SlotImpl = server_mod.Server.Slot;
const StatelessResponseKind = server_mod.StatelessResponseKind;
const conn_mod = @import("../conn/root.zig");
const Address = conn_mod.path.Address;
const ConnectionId = conn_mod.path.ConnectionId;
const lifecycle = conn_mod.lifecycle;

/// Structured observability events emitted by the `Server` at
/// well-defined choice points. Embedders install a `LogCallback` via
/// `Config.log_callback` to forward these to their logger of choice;
/// the server emits them synchronously and never holds any internal
/// lock while the callback runs. Re-exported as `Server.LogEvent`.
///
/// The variants are intentionally narrow — one struct per choice
/// point — so the embedder can pattern-match on the discriminator and
/// pick out only the fields they care about. Adding a new variant is
/// a non-breaking change at the source level (existing callers'
/// `else =>` arms still type-check) but is a wire/behavior change for
/// any embedder logging the variants verbatim, so each addition
/// should land in a CHANGELOG entry.
pub const LogEvent = union(enum) {
    /// A new connection slot was opened from an Initial datagram. The
    /// `slot_count` field is the live-slot count *after* this accept,
    /// which embedders can use to alert on saturation.
    connection_accepted: struct { peer: Address, slot_count: usize },
    /// A previously-live slot was reaped. `peer` is the last source
    /// address observed for that slot (or null if the embedder never
    /// passed `from` on `feed`); `source` is the close reason from
    /// the connection's sticky `closeEvent` (or null for slots torn
    /// down before they ever transitioned through the close pipeline).
    connection_closed: struct { peer: ?Address, source: ?lifecycle.CloseSource },
    /// The per-source rate limiter rejected an Initial. `recent_count`
    /// is the source's tally inside the current window at the moment
    /// of rejection, surfaced so embedders can tune
    /// `initial_source_rate_limit`.
    feed_rate_limited: struct { peer: Address, recent_count: u32 },
    /// A Retry packet was successfully minted and queued for `peer`.
    /// `scid_len` is the length of the server-issued SCID embedded in
    /// the Retry — currently always equal to `Config.local_cid_len`.
    retry_minted: struct { peer: Address, scid_len: u8 },
    /// A long-header packet declared an unsupported version and a
    /// Version Negotiation response was queued. `requested_version` is
    /// the version field the peer asked for; embedders can correlate
    /// this with their version-deployment posture.
    version_negotiated: struct { peer: Address, requested_version: u32 },
    /// The bounded stateless-response queue was full when a fresh
    /// response (VN or Retry) arrived; the indicated entry was
    /// evicted to make room. `kind` is the kind of the *evicted*
    /// entry, not the new one.
    stateless_queue_evicted: struct { kind: StatelessResponseKind },
    /// `feed` rejected an Initial because the slot table was at
    /// `max_concurrent_connections`. `peer` is the source address (or
    /// null when the embedder didn't pass `from`).
    table_full: struct { peer: ?Address },
};

/// Embedder-supplied logging hook. The `user_data` pointer is the
/// `Config.log_user_data` the server stashed at init time and is
/// passed back verbatim. Re-exported as `Server.LogCallback`.
///
/// The callback is invoked synchronously from inside `feed` / `reap` /
/// `queueStatelessResponse` and must not call back into the server it
/// was registered with (no `feed`, no `drainStatelessResponse`,
/// nothing else that mutates server state). Returning an error is not
/// supported — the callback's job is to push the event into a buffer,
/// log line, or counter and return.
pub const LogCallback = *const fn (user_data: ?*anyopaque, ev: LogEvent) void;

/// Callback invoked from `Server.reap` for each slot whose connection
/// reached `.closed`, immediately *before* the connection and slot are
/// destroyed. Inside the callback the slot — including `slot.conn` and
/// `slot.user_data` — is still fully valid; the moment it returns, both
/// are dead. This is the ordered-teardown hook for per-connection
/// application state that borrows `slot.conn` (an HTTP/3 session, an
/// app-side context keyed by `slot.slot_id`): tear it down here and the
/// use-after-free window between reap and app-side cleanup disappears.
/// Runs synchronously on the embedder's thread inside `reap` and must
/// not call back into the Server (same re-entrancy rule as
/// `log_callback`).
pub const ConnectionWillCloseCallback = *const fn (user_data: ?*anyopaque, slot: *SlotImpl) void;

/// By-value snapshot of the server's instrumentation counters and
/// gauges. Returned from `Server.metricsSnapshot`; the snapshot is
/// taken atomically (no mutation between fields) because all reads
/// run on the embedder's thread. Re-exported as
/// `Server.MetricsSnapshot`.
///
/// Fields divide into two groups:
///   * Gauges describe *current* state — table sizes, queue depth,
///     the post-init high-water mark for the stateless queue.
///   * Counters monotonically increase from `init` to `deinit` and
///     cover every lifecycle event the embedder might want to chart.
///
/// Counters wrap at `u64` overflow, which is decades of traffic on
/// any realistic deployment. The embedder is responsible for
/// computing per-second rates if they want a flow chart.
pub const MetricsSnapshot = struct {
    // Gauges (current state).
    /// Current number of live connection slots. Mirrors
    /// `Server.connectionCount`.
    live_connections: u64,
    /// Current number of routing CIDs across all live slots. Mirrors
    /// `Server.routingTableSize`.
    routing_table_size: u64,
    /// Number of distinct sources the rate limiter currently tracks.
    /// Zero when the limiter is disabled.
    source_rate_table_size: u64,
    /// Number of distinct peers with Retry-pending state. Zero when
    /// Retry is disabled.
    retry_state_table_size: u64,
    /// Current depth of the stateless-response (VN/Retry) queue.
    /// Mirrors `Server.statelessResponseCount`.
    stateless_queue_depth: u64,
    /// All-time maximum value of `stateless_queue_depth` since
    /// `init`. Sticky — it does not decrease when the queue drains.
    /// Useful for sizing the queue capacity for production load.
    stateless_queue_high_water: u64,

    // Counters (monotonic since init).
    /// Datagrams routed to an existing slot.
    feeds_routed: u64,
    /// Initials that opened a new slot (`.accepted`).
    feeds_accepted: u64,
    /// Datagrams rejected with `.dropped` for any reason — empty,
    /// malformed, slot creation failed, expired token, etc.
    feeds_dropped: u64,
    /// Initials rejected by the per-source rate limiter
    /// (`.rate_limited`).
    feeds_rate_limited: u64,
    /// Initials rejected because `max_concurrent_connections` was
    /// reached (`.table_full`).
    feeds_table_full: u64,
    /// Long-header packets that triggered a Version Negotiation
    /// response (`.version_negotiated`).
    feeds_version_negotiated: u64,
    /// Initials that triggered a Retry packet (`.retry_sent`).
    feeds_retry_sent: u64,
    /// Initial-bearing UDP datagrams discarded because the datagram
    /// payload was smaller than the RFC 9000 §14 minimum (1200
    /// bytes). A subset of `feeds_dropped` — incremented in addition
    /// to it. Spiking values point at amplification probes.
    feeds_initial_too_small: u64,
    /// Non-v1 long-header datagrams that would have triggered a
    /// Version Negotiation response but were dropped because the
    /// per-source VN rate limit (`vn_source_rate_limit`)
    /// fired. A subset of `feeds_dropped`. Spiking values point at
    /// VN-flood probes.
    feeds_vn_rate_limited: u64,
    /// Datagrams dropped at the listener-level packet rate limit
    /// (`Config.listener_datagram_rate_limit`). Subset of `feeds_dropped`.
    /// Hardening guide §4.1.
    feeds_listener_rate_limited: u64,
    /// Datagrams dropped at the listener-level byte rate limit
    /// (`Config.listener_byte_rate_limit`). Subset of `feeds_dropped`.
    /// Tracks bandwidth-flavored floods that the packet-count cap
    /// would let through (few-but-large datagrams). Hardening guide §4.1.
    feeds_listener_byte_rate_limited: u64,
    /// Datagrams dropped at the per-source bandwidth shaper
    /// (`Config.source_byte_rate_limit`). Subset of
    /// `feeds_dropped`. Distinct from `feeds_listener_byte_rate_limited`:
    /// the listener cap protects the aggregate firehose, this protects
    /// against any single source consuming more than its fair share.
    /// Hardening guide §4.1 token-bucket.
    feeds_source_bandwidth_limited: u64,
    /// LogEvents the server dropped under the per-source log rate
    /// limit (`Config.log_source_rate_limit`).
    /// Distinct from `feeds_dropped` — feeding a datagram and emitting
    /// a log are separate side effects. Hardening guide §9.4.
    feeds_log_rate_limited: u64,
    /// Echoed Retry tokens that successfully validated and led to a
    /// post-Retry `.accepted`. Always less than or equal to
    /// `feeds_retry_sent`.
    retries_validated: u64,
    /// Stateless responses dropped on queue overflow.
    stateless_responses_evicted: u64,
    /// Slots reclaimed by `reap()` (one per closed connection).
    slots_reaped: u64,
};

/// By-value snapshot of the per-source rate limiter, ranked by
/// recent activity. Returned from `Server.rateLimitSnapshot`; the
/// top-N list is sorted in descending order by `recent_count`. When
/// the rate limiter is disabled, the snapshot is all-zero.
/// Re-exported as `Server.RateLimitSnapshot`.
pub const RateLimitSnapshot = struct {
    /// One row in the top-N table.
    pub const SourceRow = struct {
        addr: Address,
        recent_count: u32,
        window_start_us: u64,
    };

    /// Maximum number of top-offender rows the snapshot returns.
    pub const top_n: usize = 16;

    /// Total number of distinct sources currently tracked. May be
    /// larger than `top_offender_count` when the table holds more
    /// than `top_n` sources.
    table_size: usize,
    /// Cumulative count of `.rate_limited` returns since `init`.
    /// Mirrors `MetricsSnapshot.feeds_rate_limited`.
    cumulative_rejections: u64,
    /// Top offenders, sorted descending by `recent_count`. Slots
    /// past `top_offender_count` are zero-initialized and should be
    /// ignored.
    top_offenders: [top_n]SourceRow,
    /// Number of valid rows in `top_offenders`.
    top_offender_count: usize,
};

/// Per-source log-emission rate gate. Mirrors `acceptSourceRate`
/// and `acceptVnRate` but uses the entry's tertiary
/// `log_count` / `log_window_start_us` pair so log floods don't
/// burn the Initial / VN budgets and vice versa. Returns `true`
/// when emission is permitted.
///
/// Hardening guide §9.4: a peer that triggers many feed-rate-limit
/// or table-full or VN-rate-limit events from a single address
/// would otherwise let the attacker flood the embedder's log
/// pipeline (disk, stdout, structured-logging dependency, etc.).
/// On a denial of `false`, the caller drops the LogEvent silently
/// — there is no nested log about the dropped log.
fn acceptLogRate(
    self: *Server,
    addr: Address,
    cap: u64,
    now_us: u64,
) bool {
    // Lazy eviction shared with `acceptSourceRate` / `acceptVnRate`.
    if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
        self.pruneSourceRate(now_us);
        if (self.source_rate_table.count() >= self.source_rate_table_capacity) {
            self.evictOldestSourceRate();
        }
    }

    const gop = self.source_rate_table.getOrPut(self.allocator, addr) catch {
        // OOM on the rate table: deny the log rather than risk
        // unbounded emission. Mirrors `acceptSourceRate`.
        return false;
    };
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .count = 0,
            .window_start_us = 0,
            .log_count = 1,
            .log_window_start_us = now_us,
        };
        return true;
    }

    const elapsed = now_us -% gop.value_ptr.log_window_start_us;
    if (elapsed >= self.source_rate_window_us) {
        gop.value_ptr.log_count = 1;
        gop.value_ptr.log_window_start_us = now_us;
        return true;
    }

    if (gop.value_ptr.log_count >= cap) return false;
    gop.value_ptr.log_count += 1;
    return true;
}

/// Internal helper: invoke `log_callback` if installed. Mediated
/// by the per-source log rate limit (hardening guide §9.4) when
/// the event carries a source address — events with `from = null`
/// (or a variant that doesn't bind to a peer) bypass the gate.
pub fn emitLog(self: *Server, ev: LogEvent) void {
    if (self.log_callback == null) return;
    if (self.max_log_events_per_source) |cap| {
        if (logEventSource(ev)) |addr| {
            // `acceptLogRate` allocates on first hit per source —
            // OOM there denies the log rather than crash. We pass
            // the most recent timestamp the caller surfaced via
            // the in-flight feed; emitLog doesn't take a clock so
            // we use the limiter's own `log_window_start_us`
            // semantics where the comparison is against `now_us`
            // captured at call time. Callers that want strict
            // timing pass `now_us` to whichever feed-side gate
            // upstream of this; here we use the source's most
            // recent log-window start as a stand-in for "now".
            //
            // The simplest correct implementation: hand
            // `acceptLogRate` an in-feed `now_us` via a ledger
            // captured at feed entry. We do that via
            // `last_feed_now_us`, set at the top of every `feed`.
            if (!acceptLogRate(self, addr, cap, self.last_feed_now_us)) {
                self.feeds_log_rate_limited += 1;
                return;
            }
        }
    }
    self.log_callback.?(self.log_user_data, ev);
}

/// Snapshot the server's instrumentation gauges and counters.
/// The returned `MetricsSnapshot` is a flat by-value struct;
/// reading it does not allocate, mutate the server, or invoke
/// any user callback. Embedders typically call this on a fixed
/// schedule and forward to their metrics pipeline (Prometheus,
/// statsd, OpenTelemetry).
pub fn metricsSnapshot(self: *const Server) MetricsSnapshot {
    return .{
        .live_connections = @intCast(self.slots.items.len),
        .routing_table_size = @intCast(self.cid_table.count()),
        .source_rate_table_size = @intCast(self.source_rate_table.count()),
        .retry_state_table_size = @intCast(self.retry_state_table.count()),
        .stateless_queue_depth = @intCast(self.stateless_responses.items.len),
        .stateless_queue_high_water = self.stateless_queue_high_water,
        .feeds_routed = self.feeds_routed,
        .feeds_accepted = self.feeds_accepted,
        .feeds_dropped = self.feeds_dropped,
        .feeds_rate_limited = self.feeds_rate_limited,
        .feeds_table_full = self.feeds_table_full,
        .feeds_version_negotiated = self.feeds_version_negotiated,
        .feeds_retry_sent = self.feeds_retry_sent,
        .feeds_initial_too_small = self.feeds_initial_too_small,
        .feeds_vn_rate_limited = self.feeds_vn_rate_limited,
        .feeds_listener_rate_limited = self.feeds_listener_rate_limited,
        .feeds_listener_byte_rate_limited = self.feeds_listener_byte_rate_limited,
        .feeds_source_bandwidth_limited = self.feeds_source_bandwidth_limited,
        .feeds_log_rate_limited = self.feeds_log_rate_limited,
        .retries_validated = self.retries_validated,
        .stateless_responses_evicted = self.stateless_responses_evicted,
        .slots_reaped = self.slots_reaped,
    };
}

/// Snapshot the rate-limiter table, returning the top
/// `RateLimitSnapshot.top_n` (16) sources by `recent_count` in
/// descending order. The unused tail of `top_offenders` is
/// zero-initialized; embedders should iterate up to
/// `top_offender_count`.
///
/// The implementation is an O(N * top_n) insertion sort across
/// the table (N = `source_rate_table` size, bounded by
/// `Config.source_rate_table_capacity`). With the default
/// capacity of 4096 entries and top_n=16 this is well under a
/// millisecond on commodity hardware; the snapshot is meant for
/// occasional polling (every few seconds), not the per-packet
/// hot path.
pub fn rateLimitSnapshot(self: *const Server) RateLimitSnapshot {
    var snap: RateLimitSnapshot = .{
        .table_size = self.source_rate_table.count(),
        .cumulative_rejections = self.feeds_rate_limited,
        .top_offenders = @splat(.{ .addr = .unspecified, .recent_count = 0, .window_start_us = 0 }),
        .top_offender_count = 0,
    };

    // Insertion-sort across the live table. For each entry, find
    // the first position whose count is below ours and shift
    // everything after it down by one. Bounded scan because the
    // top-N array is fixed at 16.
    var it = self.source_rate_table.iterator();
    while (it.next()) |entry| {
        const row: RateLimitSnapshot.SourceRow = .{
            .addr = entry.key_ptr.*,
            .recent_count = entry.value_ptr.count,
            .window_start_us = entry.value_ptr.window_start_us,
        };

        // Find insertion point in the descending-by-count list.
        var insert_idx: usize = snap.top_offender_count;
        for (0..snap.top_offender_count) |i| {
            if (row.recent_count > snap.top_offenders[i].recent_count) {
                insert_idx = i;
                break;
            }
        }
        if (insert_idx >= RateLimitSnapshot.top_n) continue;

        // Shift down to make room. If the array is already at
        // capacity, the last entry falls off the bottom.
        const last = @min(snap.top_offender_count, RateLimitSnapshot.top_n - 1);
        var j: usize = last;
        while (j > insert_idx) : (j -= 1) {
            snap.top_offenders[j] = snap.top_offenders[j - 1];
        }
        snap.top_offenders[insert_idx] = row;
        if (snap.top_offender_count < RateLimitSnapshot.top_n) {
            snap.top_offender_count += 1;
        }
    }
    return snap;
}

/// Extract the source address from a `LogEvent` for the per-source log
/// rate limit. Returns null when the event has no source attribution
/// (e.g. `stateless_queue_evicted`) or the source is itself null
/// (`connection_closed` / `table_full` paths where the embedder
/// didn't pass `from`). Hardening guide §9.4: events with no source
/// bypass the limiter.
fn logEventSource(ev: LogEvent) ?Address {
    return switch (ev) {
        .connection_accepted => |e| e.peer,
        .connection_closed => |e| e.peer,
        .feed_rate_limited => |e| e.peer,
        .retry_minted => |e| e.peer,
        .version_negotiated => |e| e.peer,
        .stateless_queue_evicted => null,
        .table_full => |e| e.peer,
    };
}
