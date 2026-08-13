//! Server DoS gates: per-source Initial rate limiting, version
//! negotiation rate limiting, per-source bandwidth accounting, and the
//! Retry / NEW_TOKEN address-validation gate (mint, echo-validate,
//! bounded state table). Split from Server.zig; the private methods on
//! Server delegate here via private thunks where hub callers remain.

const std = @import("std");
const Server = @import("../Server.zig");
const conn_mod = @import("../conn/root.zig");
const Address = conn_mod.path.Address;
const ConnectionId = conn_mod.path.ConnectionId;
const retry_token_mod = conn_mod.retry_token;
const new_token_mod = conn_mod.new_token;
const wire_peek = @import("wire_peek.zig");
const peekLongHeaderIds = wire_peek.peekLongHeaderIds;
const peekInitialToken = wire_peek.peekInitialToken;
const wire = @import("../wire/root.zig");

/// Idle threshold (microseconds) past which a `SourceRateEntry`
/// whose three counter windows have all elapsed is also considered
/// stale on the bandwidth-bucket axis and may be pruned. Five
/// seconds is comfortably longer than the default
/// `source_rate_window_us` (one second), so a source seen recently
/// enough to keep its bucket warm survives `pruneSourceRate` even
/// when its Initial / VN / log windows have aged out. Hardening
/// guide §4.1 token-bucket. Declared here (not on the hub): this
/// file owns the source-rate table and is the constant's only user.
pub const bandwidth_idle_threshold_us: u64 = 5_000_000;
const StatelessResponse = Server.StatelessResponse;
const RetryTokenKey = conn_mod.RetryTokenKey;
const Error = Server.Error;
const LongHeaderIds = wire_peek.LongHeaderIds;
const Slot = Server.Slot;

/// Token-bucket gate for per-source Initial acceptance. Returns
/// true if `addr` is under its cap and the caller may proceed
/// with slot creation; in that case, the source's count is
/// incremented. Returns false if the cap is exceeded — caller
/// should drop the datagram.
///
/// The window is sliding-by-reset: when an entry's
/// `window_start_us` is older than `source_rate_window_us`, the
/// count resets. This is cheaper than a true sliding window and
/// good enough for DoS-deflecting purposes; it allows up to 2x
/// the cap across two adjacent windows in pathological timing.
pub fn acceptSourceRate(
    server: *Server,
    addr: Address,
    cap: u64,
    now_us: u64,
) bool {
    // Lazy eviction when the table is at capacity. Pruning
    // every call is wasteful; only pay the O(table) cost when
    // we're about to add an entry that would overflow.
    if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
        pruneSourceRate(server, now_us);
        // If pruning didn't make room, drop the most stale
        // entry to guarantee progress.
        if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
            evictOldestSourceRate(
                server,
            );
        }
    }

    const gop = server.source_rate_table.getOrPut(server.allocator, addr) catch {
        // OOM on the rate table is a cheap soft fail: deny the
        // accept rather than continue without protection.
        return false;
    };
    if (!gop.found_existing) {
        gop.value_ptr.* = .{ .count = 1, .window_start_us = now_us };
        return true;
    }

    const elapsed = now_us -% gop.value_ptr.window_start_us;
    if (elapsed >= server.source_rate_window_us) {
        gop.value_ptr.* = .{ .count = 1, .window_start_us = now_us };
        return true;
    }

    if (gop.value_ptr.count >= cap) return false;
    gop.value_ptr.count += 1;
    return true;
}

/// Per-source VN-emission rate gate. Mirrors `acceptSourceRate`
/// but uses the entry's secondary `vn_count` / `vn_window_start_us`
/// pair so VN floods don't burn the per-source Initial budget
/// (and vice versa). Returns `true` when emission is permitted.
pub fn acceptVnRate(
    server: *Server,
    addr: Address,
    cap: u64,
    now_us: u64,
) bool {
    // Lazy eviction shared with `acceptSourceRate`.
    if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
        pruneSourceRate(server, now_us);
        if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
            evictOldestSourceRate(
                server,
            );
        }
    }

    const gop = server.source_rate_table.getOrPut(server.allocator, addr) catch {
        // OOM on the rate table: deny the VN rather than continue
        // unprotected. Mirrors `acceptSourceRate` policy.
        return false;
    };
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .count = 0,
            .window_start_us = 0,
            .vn_count = 1,
            .vn_window_start_us = now_us,
        };
        return true;
    }

    const elapsed = now_us -% gop.value_ptr.vn_window_start_us;
    if (elapsed >= server.source_rate_window_us) {
        gop.value_ptr.vn_count = 1;
        gop.value_ptr.vn_window_start_us = now_us;
        return true;
    }

    if (gop.value_ptr.vn_count >= cap) return false;
    gop.value_ptr.vn_count += 1;
    return true;
}

/// Per-source bandwidth gate (token-bucket). Returns true when the
/// `bytes_charged`-byte datagram is permitted; false when the
/// bucket is empty. Mirrors `acceptSourceRate` / `acceptVnRate` /
/// `acceptLogRate` in shape (lazy eviction, OOM-fail-closed) and
/// shares the `source_rate_table`.
///
/// The bucket is sized to one second of `cap_per_second`, refills
/// at `cap_per_second` bytes/s up to that ceiling, and debits
/// `bytes_charged` per accepted datagram. Hardening guide §4.1
/// token-bucket: this is the per-source companion to the global
/// sliding-window byte-rate cap. The shaper sits AFTER the global
/// listener gates so the global aggregate ceiling still bounds
/// total bandwidth even with every source's bucket full.
pub fn acceptSourceBandwidth(
    server: *Server,
    addr: Address,
    bytes_charged: u64,
    cap_per_second: u64,
    now_us: u64,
) bool {
    // Lazy eviction shared with the rest of the per-source helpers.
    if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
        pruneSourceRate(server, now_us);
        if (server.source_rate_table.count() >= server.source_rate_table_capacity) {
            evictOldestSourceRate(
                server,
            );
        }
    }

    const gop = server.source_rate_table.getOrPut(server.allocator, addr) catch {
        // OOM on the rate table: deny the datagram rather than
        // continue unprotected. Mirrors `acceptSourceRate` policy.
        return false;
    };
    if (!gop.found_existing) {
        // Bootstrap: full bucket, charge immediately. A first
        // datagram larger than one full second's burst is dropped
        // here (the bucket starts at `cap_per_second`, not at
        // `cap_per_second + bytes_charged`).
        const tokens_after_charge: u64 = if (cap_per_second >= bytes_charged)
            cap_per_second - bytes_charged
        else
            0;
        gop.value_ptr.* = .{
            .count = 0,
            .window_start_us = 0,
            .vn_count = 0,
            .vn_window_start_us = 0,
            .log_count = 0,
            .log_window_start_us = 0,
            .bandwidth_tokens = tokens_after_charge,
            .bandwidth_last_refill_us = now_us,
        };
        return cap_per_second >= bytes_charged;
    }

    // Refill: tokens += elapsed_us * cap / 1_000_000, capped at cap.
    // `mulWide` keeps the intermediate product in u128 so a long
    // idle gap on a high cap can't overflow u64 mid-divide.
    const elapsed = now_us -% gop.value_ptr.bandwidth_last_refill_us;
    const refill: u64 = @intCast(std.math.mulWide(u64, elapsed, cap_per_second) / std.time.us_per_s);
    const refilled = std.math.add(u64, gop.value_ptr.bandwidth_tokens, refill) catch cap_per_second;
    gop.value_ptr.bandwidth_tokens = @min(refilled, cap_per_second);
    gop.value_ptr.bandwidth_last_refill_us = now_us;

    if (gop.value_ptr.bandwidth_tokens < bytes_charged) return false;
    gop.value_ptr.bandwidth_tokens -= bytes_charged;
    return true;
}

// INTERNAL: pub for direct sibling import (server/observability.zig);
// not part of the embedder API. The Server method thunk was demoted.
pub fn pruneSourceRate(server: *Server, now_us: u64) void {
    var it = server.source_rate_table.iterator();
    while (it.next()) |entry| {
        const init_elapsed = now_us -% entry.value_ptr.window_start_us;
        const vn_elapsed = now_us -% entry.value_ptr.vn_window_start_us;
        const log_elapsed = now_us -% entry.value_ptr.log_window_start_us;
        const bandwidth_elapsed = now_us -% entry.value_ptr.bandwidth_last_refill_us;
        // Only prune when *all four* per-counter / per-bucket axes
        // have gone idle — otherwise an entry that's only stale on
        // one axis would lose its still-active counters on the
        // others. The bandwidth-bucket survival threshold is held
        // separately so a long-idle source still pays the
        // refill-from-empty bootstrap rather than getting a free
        // full-bucket reset on its next packet.
        if (init_elapsed >= server.source_rate_window_us and
            vn_elapsed >= server.source_rate_window_us and
            log_elapsed >= server.source_rate_window_us and
            bandwidth_elapsed >= bandwidth_idle_threshold_us)
        {
            _ = server.source_rate_table.remove(entry.key_ptr.*);
        }
    }
}

// INTERNAL: pub for direct sibling import (server/observability.zig);
// not part of the embedder API. The Server method thunk was demoted.
pub fn evictOldestSourceRate(server: *Server) void {
    var it = server.source_rate_table.iterator();
    var oldest_addr: ?Address = null;
    var oldest_start: u64 = std.math.maxInt(u64);
    while (it.next()) |entry| {
        if (entry.value_ptr.window_start_us < oldest_start) {
            oldest_start = entry.value_ptr.window_start_us;
            oldest_addr = entry.key_ptr.*;
        }
    }
    if (oldest_addr) |addr| _ = server.source_rate_table.remove(addr);
}

// -- Version Negotiation -------------------------------------------

pub fn maybeIssueNewToken(
    server: *Server,
    slot: *Slot,
    from: ?Address,
    now_us: u64,
) void {
    const key_ptr = if (server.new_token_key) |*k| k else return;
    if (slot.new_token_emitted) return;
    if (!slot.conn.handshakeDone()) return;
    const addr = from orelse return;

    var addr_buf: [Address.context_max_len]u8 = undefined;
    const ctx = addressContext(&addr_buf, addr);
    var token: new_token_mod.Token = undefined;
    _ = new_token_mod.mint(&token, .{
        .key = key_ptr,
        .now_us = now_us,
        .lifetime_us = server.new_token_lifetime_us,
        .client_address = ctx,
        // Bind the connection's negotiated version. Validation on a
        // returning Initial checks against that Initial's wire
        // version; for a single-version deployment both are v1, so
        // this is a no-op there and provides real cross-version
        // separation once a v2-capable server is configured.
        .quic_version = slot.conn.version,
    }) catch {
        // Mint can only fail on a BoringSSL CSPRNG hiccup here: the
        // output buffer is fixed-size, and `new_token.max_address_len`
        // is comptime-coupled to `Address.context_max_len`, so the
        // address context (IPv6 included) can no longer exceed the
        // field cap — the ContextTooLong path that silently denied
        // every IPv6 peer a NEW_TOKEN is closed. Skip issuance for
        // this slot; the slot stays usable, and future Initials from
        // the same address fall through to the Retry gate as if
        // NEW_TOKEN was never issued.
        return;
    };

    slot.conn.queueNewToken(&token) catch {
        // Same not-peer-reachable rationale; the queue holds at
        // most one entry, the bytes are fixed-size, and the
        // role check has already passed (we minted on a
        // server-role slot).
        return;
    };
    slot.new_token_emitted = true;
}

// -- Retry ----------------------------------------------------------

/// What `applyRetryGate` decided. `none` means proceed with the
/// normal accept path (this Initial carried no token and Retry
/// is disabled, or the source already passed validation in a
/// prior datagram). `sent` means we queued a Retry. `drop` means
/// the echoed token was malformed/expired/wrong-source. `echo`
/// means the Retry token validated and the caller should accept
/// this Initial as the post-Retry continuation.
/// `new_token_skip` means a valid NEW_TOKEN was presented, so
/// the source is treated as already address-validated and the
/// caller skips the Retry round-trip (RFC 9000 §8.1.3).
pub const RetryDecision = union(enum) {
    none,
    sent,
    drop,
    echo: RetryEcho,
    new_token_skip,
};

/// Captured server-side context for an Initial that successfully
/// echoed a Retry token. The slot opener uses these to set the
/// post-Retry transport parameters.
pub const RetryEcho = struct {
    retry_scid: [20]u8,
    retry_scid_len: u8,
    original_dcid: ConnectionId,
};

/// Run the Retry / NEW_TOKEN gate for an Initial from `addr`.
/// Either queues a Retry (`.sent`), validates an echoed Retry
/// token (`.echo`), validates an echoed NEW_TOKEN
/// (`.new_token_skip`, accept directly), or returns `.drop` for
/// a malformed/expired/wrong-source token. Returns `.none` only
/// if both gates are disabled (caller checks before invoking).
///
/// Token-disambiguation: if `new_token_key` is set, NEW_TOKEN
/// validation runs first; on `.valid` we skip Retry. On
/// `.malformed` (also covers a Retry-token blob in a fresh
/// session — distinct domain separator), we fall through to
/// Retry. Other NEW_TOKEN failures (`.expired`, `.invalid`,
/// etc.) ALSO fall through so a stale stored token sends the
/// peer through a fresh Retry round-trip rather than dropping
/// the connection.
pub fn applyRetryGate(
    server: *Server,
    addr: Address,
    bytes: []const u8,
    now_us: u64,
) Error!RetryDecision {
    const retry_key = if (server.retry_token_key) |*k| k else null;
    const new_token_key = if (server.new_token_key) |*k| k else null;
    if (retry_key == null and new_token_key == null) return .none;

    const ids = peekLongHeaderIds(bytes) orelse return .drop;
    const token = peekInitialToken(bytes);

    // NEW_TOKEN check first — if a returning client presents a
    // valid NEW_TOKEN, we want to accept it directly without
    // burning a Retry round-trip. On any failure we fall
    // through; a stale or wrong-address NEW_TOKEN should never
    // close the connection (the peer expected to be accepted
    // and would re-handshake gracefully on a Retry).
    if (token != null and token.?.len > 0) {
        if (new_token_key) |nt_key| {
            var addr_buf: [Address.context_max_len]u8 = undefined;
            const ctx = addressContext(&addr_buf, addr);
            const result = new_token_mod.validate(token.?, .{
                .key = nt_key,
                .now_us = now_us,
                .client_address = ctx,
                .quic_version = ids.version,
            });
            if (result == .valid) return .new_token_skip;
            // Fall through to Retry validation on malformed,
            // expired, invalid, etc.
        }
    }

    // Retry-token path. If Retry is disabled, an Initial
    // carrying a non-NEW_TOKEN token is treated as if no token
    // were present (we can't validate it; falling back to
    // accept-without-validation is the only safe move when the
    // operator opted out of Retry).
    const key_ptr = retry_key orelse return .none;

    const existing = server.retry_state_table.get(addr);

    // No echoed token: the peer is on its first Initial. Mint a
    // Retry, queue it, and require the next Initial to echo.
    if (token == null or token.?.len == 0) {
        mintAndQueueRetry(server, addr, ids, now_us, key_ptr) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .drop,
        };
        return .sent;
    }

    // Echoed token but no per-source state: stale (we evicted on
    // overflow, restarted, etc.). Re-mint a fresh Retry; the peer
    // will retry with a new round-trip.
    const state = existing orelse {
        mintAndQueueRetry(server, addr, ids, now_us, key_ptr) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return .drop,
        };
        return .sent;
    };

    // Echoed token: validate against the per-source retry_scid
    // we minted. The SCID binding ties the token to a specific
    // Retry round-trip — a token minted for some other peer
    // can't be replayed here even if the source IP collides.
    var addr_buf: [Address.context_max_len]u8 = undefined;
    const ctx = addressContext(&addr_buf, addr);
    const result = retry_token_mod.validate(token.?, .{
        .key = key_ptr,
        .now_us = now_us,
        .client_address = ctx,
        .original_dcid = state.original_dcid.slice(),
        .retry_scid = state.retry_scid[0..state.retry_scid_len],
        // Bind the inbound Initial's wire version; the peer echoes
        // the same version on the follow-up Initial the Retry token
        // rides in, so mint and validate stay consistent.
        .quic_version = ids.version,
    });
    if (result != .valid) return .drop;

    // Validated: bubble up the per-source context so the slot
    // opener knows which SCID to bind and which odcid to set in
    // transport params.
    return .{ .echo = .{
        .retry_scid = state.retry_scid,
        .retry_scid_len = state.retry_scid_len,
        .original_dcid = state.original_dcid,
    } };
}

/// Sentinel returned from `mintAndQueueRetry` when token mint or
/// Retry seal fails for a reason that isn't peer-induced (DCID
/// length already bounded by `peekLongHeaderIds`, address ctx
/// is fixed-size, dst buf is fixed-size). Any peer-reachable
/// path that lands here means an invariant slipped, so the
/// caller drops the datagram silently.
const RetryMintError = Error || error{RetryEncodeFailed};

fn mintAndQueueRetry(
    server: *Server,
    addr: Address,
    ids: LongHeaderIds,
    now_us: u64,
    key_ptr: *const RetryTokenKey,
) RetryMintError!void {
    // Bound the table without letting forged-source floods
    // evict legitimate-peer Retry round-trips. First sweep
    // anything older than the token lifetime — those entries
    // are already useless because their tokens won't validate.
    // Only fall back to oldest-eviction if the table is still
    // at capacity (i.e., every entry is within its lifetime).
    if (server.retry_state_table.count() >= server.retry_state_table_capacity) {
        pruneExpiredRetryState(server, now_us);
        if (server.retry_state_table.count() >= server.retry_state_table_capacity) {
            evictOldestRetryState(
                server,
            );
        }
    }

    // Pick a fresh server-issued SCID for this Retry. The peer
    // will echo this DCID in its post-Retry Initial, and the
    // token HMAC binds to it so a replayed Retry can't authorize
    // a different connection.
    var retry_scid: [20]u8 = @splat(0);
    const retry_scid_len = server.local_cid_len;
    try server.mintLocalScid(retry_scid[0..retry_scid_len]);

    var addr_buf: [Address.context_max_len]u8 = undefined;
    const ctx = addressContext(&addr_buf, addr);
    var token: retry_token_mod.Token = undefined;
    _ = retry_token_mod.mint(&token, .{
        .key = key_ptr,
        .now_us = now_us,
        .lifetime_us = server.retry_token_lifetime_us,
        .client_address = ctx,
        .original_dcid = ids.dcid,
        .retry_scid = retry_scid[0..retry_scid_len],
        // Bind the inbound Initial's wire version (see the matching
        // validate call). v1 for the default single-version server.
        .quic_version = ids.version,
    }) catch return error.RetryEncodeFailed;

    var entry: StatelessResponse = .{ .dst = addr, .len = 0, .kind = .retry };
    const written = wire.long_packet.sealRetry(&entry.bytes, .{
        .original_dcid = ids.dcid,
        .dcid = ids.scid,
        .scid = retry_scid[0..retry_scid_len],
        .retry_token = &token,
    }) catch return error.RetryEncodeFailed;
    entry.len = written;

    try server.queueStatelessResponse(entry);

    // Record the retry state so we can validate the echoed
    // token in the peer's next Initial.
    const gop = try server.retry_state_table.getOrPut(server.allocator, addr);
    gop.value_ptr.* = .{
        .retry_scid = retry_scid,
        .retry_scid_len = retry_scid_len,
        .original_dcid = ConnectionId.fromSlice(ids.dcid),
        .minted_at_us = now_us,
    };
}

fn evictOldestRetryState(server: *Server) void {
    var it = server.retry_state_table.iterator();
    var oldest_addr: ?Address = null;
    var oldest_us: u64 = std.math.maxInt(u64);
    while (it.next()) |entry| {
        if (entry.value_ptr.minted_at_us < oldest_us) {
            oldest_us = entry.value_ptr.minted_at_us;
            oldest_addr = entry.key_ptr.*;
        }
    }
    if (oldest_addr) |a| _ = server.retry_state_table.remove(a);
}

/// Drop every retry-state entry whose token has expired
/// (`now_us - minted_at_us > retry_token_lifetime_us`).
/// Expired entries can never validate a peer's echoed token,
/// so freeing their slot is always safe and means the table
/// fills with usable round-trips before any eviction policy
/// has to fire.
fn pruneExpiredRetryState(server: *Server, now_us: u64) void {
    const lifetime = server.retry_token_lifetime_us;
    var stale_buf: [32]Address = undefined;
    while (true) {
        var n: usize = 0;
        var it = server.retry_state_table.iterator();
        while (it.next()) |entry| {
            if (n >= stale_buf.len) break;
            const age = now_us -% entry.value_ptr.minted_at_us;
            if (age > lifetime) {
                stale_buf[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        if (n == 0) return;
        for (stale_buf[0..n]) |addr| _ = server.retry_state_table.remove(addr);
        // If we evicted a full batch there may be more — loop
        // to keep sweeping. Bounded by the table size, so
        // this terminates.
        if (n < stale_buf.len) return;
    }
}

// -- stateless response queue --------------------------------------

/// Per-source Retry bookkeeping. Created when the server queues a
/// Retry packet for a source; consulted on the next Initial from
/// that source to decide whether to validate the echoed token or
/// re-send Retry. Bound on the table size mirrors the rate-limit
/// table so a flood of distinct addresses cannot grow this
/// unbounded.
pub const RetryStateEntry = struct {
    /// Server-issued SCID embedded in the Retry packet — the peer
    /// must echo this DCID in subsequent Initials and the token
    /// HMAC binds it.
    retry_scid: [20]u8 = @splat(0),
    retry_scid_len: u8 = 0,
    /// The DCID from the client's first Initial — the
    /// `original_destination_connection_id` transport parameter
    /// must reflect this on the post-Retry connection.
    original_dcid: ConnectionId = .{},
    /// Wall-clock microseconds when the Retry was minted; used to
    /// evict stale entries on overflow.
    minted_at_us: u64 = 0,
};

/// Per-source rate-limit bookkeeping. One entry per active source
/// address; entries older than `source_rate_window_us` are pruned
/// lazily on each `feed`. Three independent (count, window_start)
/// pairs track Initial-eligible, Version-Negotiation-eligible, and
/// LogEvent-eligible traffic separately — a peer that spams VN
/// probes shouldn't burn the per-source Initial budget, a peer that
/// gets rate-limited shouldn't free up its VN budget, and so on.
pub const SourceRateEntry = struct {
    /// Initial-driven slot creations attributed to this source
    /// within the current window.
    count: u32,
    /// Wall-clock microseconds when the current Initial window started.
    window_start_us: u64,
    /// Version-Negotiation responses attributed to this source within
    /// the current VN window. Gated by
    /// `Config.vn_source_rate_limit`.
    vn_count: u32 = 0,
    /// Wall-clock microseconds when the current VN window started.
    vn_window_start_us: u64 = 0,
    /// LogEvents emitted on behalf of this source within the current
    /// log window. Gated by `Config.log_source_rate_limit`.
    /// Hardening guide §9.4: a flood of feed-rate-limited /
    /// table-full / VN-rate-limited / etc. log events from one
    /// address would otherwise let the peer flood the embedder's
    /// log pipeline; this counter caps that.
    log_count: u32 = 0,
    /// Wall-clock microseconds when the current log window started.
    log_window_start_us: u64 = 0,
    /// Token-bucket level (in bytes) for per-source bandwidth shaping.
    /// Gated by `Config.source_byte_rate_limit`. Refilled at
    /// the configured rate up to a one-second burst cap; each accepted
    /// datagram debits `bytes.len`. Hardening guide §4.1 token-bucket.
    bandwidth_tokens: u64 = 0,
    /// Wall-clock microseconds at the most recent token-bucket refill.
    /// Driven by the per-feed `now_us` so the shaper reads the
    /// embedder's monotonic clock rather than a separate timebase.
    bandwidth_last_refill_us: u64 = 0,
};

/// Canonicalize an `Address` into the byte string the Retry-token
/// HMAC binds against. Delegates to `Address.writeContext`, which
/// produces a length-tagged form (family byte + variant fields in
/// network byte order). The binding stays tight as long as both
/// peers project the same client tuple into the same canonical
/// bytes.
pub fn addressContext(dst: []u8, addr: Address) []const u8 {
    return addr.writeContext(dst);
}
