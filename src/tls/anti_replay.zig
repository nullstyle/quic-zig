//! Bounded single-use cache for 0-RTT replay protection
//! (RFC 9001 §5.6, RFC 8446 §8 / §E.5).
//!
//! Per the hardening guide §5.2: enabling 0-RTT requires "an
//! anti-replay mechanism" — without it, an attacker who captures a
//! 0-RTT request can replay it for the lifetime of the resumed
//! session ticket. BoringSSL's QUIC integration deliberately delegates
//! this to the application: the server-side session cache can pin
//! tickets, but the "has this exact early-data already been seen?"
//! check has to live at a layer that knows the ticket's identity.
//!
//! `AntiReplayTracker` is the data structure that check needs.
//! Embedders that opt in to 0-RTT (`Server.Config.enable_0rtt = true`)
//! follow this workflow on every connection that 0-RTT accepts:
//!
//! ```zig
//! var tracker = try AntiReplayTracker.init(allocator, .{
//!     .max_entries = 4096,
//!     .max_age_us = 10 * 60 * std.time.us_per_s, // 10 minutes
//! });
//! defer tracker.deinit();
//!
//! // After Connection.handshakeDone() and earlyDataStatus() == .accepted:
//! const id = computeTicketIdentity(session, transport_params, ...);
//! switch (tracker.consume(id, now_us)) {
//!     .fresh => { /* OK to act on the 0-RTT request */ },
//!     .replay => { /* MUST reject — treat the early-data bytes as
//!                  unauthenticated and serve any response only at
//!                  1-RTT (i.e. after handshake completion). */ },
//! }
//! ```
//!
//! What "identity" means is up to the embedder — see "Identity
//! choice" below — but it must be stable across replays of the same
//! 0-RTT message and unique per legitimate connection attempt.
//!
//! ## Properties
//!
//! - **Bounded.** The tracker holds at most `max_entries` IDs at any
//!   moment; insertion past the cap evicts the oldest entry. A peer
//!   that sprays unique 0-RTT attempts can't grow our memory.
//! - **Time-windowed.** Entries older than `max_age_us` are pruned on
//!   insertion and on explicit `prune` calls. This ensures the cache
//!   only retains IDs for the window during which a replay is
//!   actually feasible (typically the session-ticket lifetime — 1-3
//!   ticket lifetimes is plenty of slack).
//! - **No allocator pressure on the hot path.** `consume` does at
//!   most one HashMap put + one ArrayList swap-remove. Pruning is
//!   batched on insert when the cap is reached.
//!
//! ## Identity choice
//!
//! The identity (a `[32]u8` opaque key) must:
//!
//! - **Stay constant across replays of the same 0-RTT message.** The
//!   replayed bytes will produce the same ID.
//! - **Differ across distinct legitimate 0-RTT attempts.** Two
//!   genuine clients resuming the same ticket (which shouldn't
//!   happen for single-use tickets, but can if the server issued
//!   multi-use tickets) must produce distinct IDs.
//!
//! Sensible constructions:
//!
//! 1. **Session ticket bytes**: SHA-256 of the resumed session's
//!    ticket bytes. Bound to the ticket exactly. (Requires extracting
//!    the ticket from BoringSSL's `SSL_SESSION`.)
//! 2. **Early-data digest + ClientHello random**: SHA-256 over the
//!    `early_data_context` (already computed for QUIC's
//!    `quic_early_data_context`) plus the 32-byte client random from
//!    the ClientHello. Stable for replays; differs across genuine
//!    attempts because client_random is fresh per attempt.
//! 3. **Initial DCID + early-data digest**: cheap and stable, but
//!    weaker — an attacker who can replay both the DCID and the
//!    early-data bytes captures a "same DCID + same early data"
//!    pair, which the tracker would correctly mark `.replay`. Good
//!    enough for many threat models.

const std = @import("std");

/// Opaque single-use identifier. Embedders pick the construction
/// (see module docstring); `AntiReplayTracker` treats the value as
/// an opaque key. SHA-256 width is the natural choice — it's
/// collision-resistant for any of the recommended derivations.
pub const id_len: usize = 32;
pub const Id = [id_len]u8;

/// Tracker construction options. All fields have sensible defaults.
pub const Options = struct {
    /// Maximum live entries the tracker holds. When the cap is hit,
    /// the next insertion evicts the oldest entry. 4096 is enough to
    /// cover a few ticket-lifetimes' worth of legitimate 0-RTT
    /// attempts on a moderately-loaded server; deployments expecting
    /// higher 0-RTT volume should raise this.
    max_entries: usize = 4096,
    /// Maximum age of an entry, in microseconds. After this, the
    /// entry is removed (on the next prune sweep) — the assumption
    /// being that any replay arriving past this window is no longer
    /// useful to the attacker because the underlying session ticket
    /// has aged out at the TLS layer too. Default: 10 minutes.
    max_age_us: u64 = 10 * std.time.us_per_min,
};

/// Outcome of `consume`. The hardening posture is "fresh = OK",
/// "replay = REJECT". There is no third variant — every input gets
/// one of these two answers (the tracker never returns errors except
/// for OOM, which propagates separately).
pub const Verdict = enum {
    /// First time this identity has been seen within the active
    /// window. Embedder MAY honor the associated 0-RTT request.
    fresh,
    /// Identity has already been consumed; this is a replay.
    /// Embedder MUST reject the 0-RTT request — treat the early-data
    /// bytes as unauthenticated and serve any response only after
    /// handshake completion.
    replay,
};

pub const PersistenceError = error{
    BufferTooSmall,
    InvalidFormat,
    UnsupportedVersion,
    InvalidFlags,
    ValueTooLarge,
    TrailingBytes,
    DuplicateEntry,
    InvalidOptions,
};

const persistence_magic = "QZAR".*;
const persistence_version: u8 = 1;
const persistence_flags: u8 = 0;
const persistence_header_len: usize = 4 + 1 + 1 + 8 + 8 + 8 + 8;
const persistence_entry_len: usize = id_len + 8;

const Entry = struct {
    id: Id,
    inserted_at_us: u64,
};

/// Bounded single-use cache. Not thread-safe — callers serialize on
/// their own (typical: the same thread that runs the QUIC server
/// loop also calls `consume`).
pub const AntiReplayTracker = struct {
    allocator: std.mem.Allocator,
    options: Options,
    /// Insertion-ordered ring of entries. Index 0 = oldest, last =
    /// newest. Used for FIFO eviction and bulk pruning.
    entries: std.ArrayList(Entry) = .empty,
    /// Membership index. Maps Id → insertion timestamp; we track the
    /// timestamp here too so `consume` can verify a hit isn't stale
    /// without scanning `entries`.
    seen: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    /// Monotonic-non-decreasing clock cache, set via `bumpClock`.
    /// Used by `consumeUsingInternalClock` so callers without an
    /// explicit `now_us` (such as the BoringSSL `allow_early_data`
    /// callback hook) can still drive the tracker. The application-
    /// layer `consume(id, now_us)` API is unchanged and ignores this
    /// field.
    last_observed_now_us: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, options: Options) !AntiReplayTracker {
        if (options.max_entries == 0) return error.InvalidOptions;
        if (options.max_age_us == 0) return error.InvalidOptions;
        var tracker: AntiReplayTracker = .{
            .allocator = allocator,
            .options = options,
        };
        try tracker.entries.ensureTotalCapacity(allocator, @min(options.max_entries, 64));
        try tracker.seen.ensureTotalCapacity(allocator, @intCast(@min(options.max_entries, 64)));
        return tracker;
    }

    pub fn deinit(self: *AntiReplayTracker) void {
        self.entries.deinit(self.allocator);
        self.seen.deinit(self.allocator);
        self.* = undefined;
    }

    /// Look up `id`, and if it's not already in the active window,
    /// insert it. Returns `.fresh` on first sight, `.replay` if the
    /// id has been seen within the active window.
    ///
    /// `now_us` is a monotonic-clock microsecond timestamp; the
    /// tracker uses it for both insertion bookkeeping and to age out
    /// stale entries on the prune path.
    pub fn consume(self: *AntiReplayTracker, id: Id, now_us: u64) error{OutOfMemory}!Verdict {
        // Stale-aware membership check. An entry that's older than
        // `max_age_us` is about to be pruned; treat it as gone for
        // verdict purposes — the replay window has expired so the
        // identity is effectively fresh again.
        if (self.seen.get(id)) |inserted_at_us| {
            if (now_us -| inserted_at_us < self.options.max_age_us) {
                return .replay;
            }
            // Old hit — fall through to refresh. We'll rewrite the
            // entry's timestamp below so its slot in the ring stays
            // correct.
        }

        // Insertion path. Prune stale entries first (cheap when most
        // of the cache is fresh — the loop exits on the first
        // non-stale entry because they're insertion-ordered). Then
        // evict the oldest if the cap is reached.
        self.pruneStale(now_us);
        if (self.entries.items.len >= self.options.max_entries) {
            self.evictOldest();
        }

        try self.entries.append(self.allocator, .{ .id = id, .inserted_at_us = now_us });
        try self.seen.put(self.allocator, id, now_us);
        return .fresh;
    }

    /// Prune all entries older than `max_age_us`. Normally `consume`
    /// does this implicitly; embedders can call it explicitly during
    /// idle ticks if they want to keep memory tighter.
    pub fn prune(self: *AntiReplayTracker, now_us: u64) void {
        self.pruneStale(now_us);
    }

    /// Update the cached internal clock. Called by `Server.feed` so
    /// the BoringSSL `allow_early_data` trampoline (which has no
    /// other path to a monotonic clock) has a sensible `now_us` to
    /// pass into `consumeUsingInternalClock`. Monotonic-non-decreasing
    /// — older `now_us` values are clamped up to the cached value.
    pub fn bumpClock(self: *AntiReplayTracker, now_us: u64) void {
        if (now_us > self.last_observed_now_us) {
            self.last_observed_now_us = now_us;
        }
    }

    /// `consume` variant for callers that can't pipe in `now_us`
    /// directly — uses the cached clock from `bumpClock`. Returns
    /// the same `.fresh`/`.replay` verdicts.
    pub fn consumeUsingInternalClock(
        self: *AntiReplayTracker,
        id: Id,
    ) error{OutOfMemory}!Verdict {
        return self.consume(id, self.last_observed_now_us);
    }

    /// How many entries the tracker currently holds. Useful for
    /// metrics / observability.
    pub fn size(self: *const AntiReplayTracker) usize {
        return self.entries.items.len;
    }

    /// Exact byte length `encode` will emit for this tracker's
    /// versioned persisted state.
    pub fn encodedLen(self: *const AntiReplayTracker) PersistenceError!usize {
        const entries_bytes = std.math.mul(usize, self.entries.items.len, persistence_entry_len) catch
            return PersistenceError.ValueTooLarge;
        return std.math.add(usize, persistence_header_len, entries_bytes) catch
            return PersistenceError.ValueTooLarge;
    }

    /// Serialize the replay cache as a versioned, architecture-neutral
    /// envelope. Entries retain insertion order so FIFO eviction
    /// behavior is preserved after restore.
    pub fn encode(self: *const AntiReplayTracker, dst: []u8) PersistenceError!usize {
        const needed = try self.encodedLen();
        if (dst.len < needed) return PersistenceError.BufferTooSmall;
        const max_entries_u64 = std.math.cast(u64, self.options.max_entries) orelse
            return PersistenceError.ValueTooLarge;
        const count_u64 = std.math.cast(u64, self.entries.items.len) orelse
            return PersistenceError.ValueTooLarge;

        @memcpy(dst[0..4], &persistence_magic);
        dst[4] = persistence_version;
        dst[5] = persistence_flags;
        var pos: usize = 6;
        writeU64(dst, &pos, max_entries_u64);
        writeU64(dst, &pos, self.options.max_age_us);
        writeU64(dst, &pos, self.last_observed_now_us);
        writeU64(dst, &pos, count_u64);
        for (self.entries.items) |entry| {
            @memcpy(dst[pos .. pos + id_len], &entry.id);
            pos += id_len;
            writeU64(dst, &pos, entry.inserted_at_us);
        }
        std.debug.assert(pos == needed);
        return needed;
    }

    pub fn encodeAlloc(
        self: *const AntiReplayTracker,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || PersistenceError)![]u8 {
        const len = try self.encodedLen();
        const out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        const written = try self.encode(out);
        std.debug.assert(written == len);
        return out;
    }

    /// Restore a tracker from `encode` bytes.
    pub fn restore(
        allocator: std.mem.Allocator,
        src: []const u8,
    ) (std.mem.Allocator.Error || PersistenceError)!AntiReplayTracker {
        return decode(allocator, src);
    }

    /// Decode a persisted tracker envelope. Unknown versions and
    /// non-zero flags are rejected so future formats can evolve
    /// without silently changing replay semantics.
    pub fn decode(
        allocator: std.mem.Allocator,
        src: []const u8,
    ) (std.mem.Allocator.Error || PersistenceError)!AntiReplayTracker {
        if (src.len < persistence_header_len) return PersistenceError.InvalidFormat;
        if (!std.mem.eql(u8, src[0..4], &persistence_magic)) return PersistenceError.InvalidFormat;
        if (src[4] != persistence_version) return PersistenceError.UnsupportedVersion;
        if (src[5] != persistence_flags) return PersistenceError.InvalidFlags;

        var pos: usize = 6;
        const max_entries_u64 = readU64(src, &pos);
        const max_age_us = readU64(src, &pos);
        const last_observed_now_us = readU64(src, &pos);
        const entry_count_u64 = readU64(src, &pos);
        const max_entries = std.math.cast(usize, max_entries_u64) orelse
            return PersistenceError.ValueTooLarge;
        const entry_count = std.math.cast(usize, entry_count_u64) orelse
            return PersistenceError.ValueTooLarge;
        if (max_entries == 0 or max_age_us == 0) return PersistenceError.InvalidOptions;
        if (entry_count > max_entries) return PersistenceError.InvalidFormat;
        const entries_bytes = std.math.mul(usize, entry_count, persistence_entry_len) catch
            return PersistenceError.ValueTooLarge;
        const total = std.math.add(usize, persistence_header_len, entries_bytes) catch
            return PersistenceError.ValueTooLarge;
        if (src.len < total) return PersistenceError.InvalidFormat;
        if (src.len > total) return PersistenceError.TrailingBytes;

        var tracker = AntiReplayTracker.init(allocator, .{
            .max_entries = max_entries,
            .max_age_us = max_age_us,
        }) catch |err| switch (err) {
            error.InvalidOptions => return PersistenceError.InvalidOptions,
            error.OutOfMemory => return error.OutOfMemory,
        };
        errdefer tracker.deinit();
        tracker.last_observed_now_us = last_observed_now_us;

        var i: usize = 0;
        while (i < entry_count) : (i += 1) {
            var id: Id = undefined;
            @memcpy(&id, src[pos .. pos + id_len]);
            pos += id_len;
            const inserted_at_us = readU64(src, &pos);
            if (tracker.seen.get(id) != null) return PersistenceError.DuplicateEntry;
            try tracker.entries.append(allocator, .{ .id = id, .inserted_at_us = inserted_at_us });
            try tracker.seen.put(allocator, id, inserted_at_us);
        }
        std.debug.assert(pos == total);
        return tracker;
    }

    fn pruneStale(self: *AntiReplayTracker, now_us: u64) void {
        var drop: usize = 0;
        while (drop < self.entries.items.len) : (drop += 1) {
            const e = self.entries.items[drop];
            if (now_us -| e.inserted_at_us < self.options.max_age_us) break;
        }
        if (drop == 0) return;

        // Drop the prefix from `entries` and clear matching `seen`
        // entries. The map removals only fire if the timestamp still
        // matches — if `consume` re-inserted the same id with a
        // fresher timestamp before this prune ran, we mustn't drop it
        // from the membership index.
        for (self.entries.items[0..drop]) |e| {
            if (self.seen.get(e.id)) |ts| {
                if (ts == e.inserted_at_us) _ = self.seen.remove(e.id);
            }
        }
        const remaining = self.entries.items.len - drop;
        std.mem.copyForwards(Entry, self.entries.items[0..remaining], self.entries.items[drop..]);
        self.entries.shrinkRetainingCapacity(remaining);
    }

    fn evictOldest(self: *AntiReplayTracker) void {
        if (self.entries.items.len == 0) return;
        const oldest = self.entries.items[0];
        if (self.seen.get(oldest.id)) |ts| {
            if (ts == oldest.inserted_at_us) _ = self.seen.remove(oldest.id);
        }
        std.mem.copyForwards(
            Entry,
            self.entries.items[0 .. self.entries.items.len - 1],
            self.entries.items[1..],
        );
        self.entries.shrinkRetainingCapacity(self.entries.items.len - 1);
    }
};

fn writeU64(dst: []u8, pos: *usize, value: u64) void {
    std.mem.writeInt(u64, dst[pos.*..][0..8], value, .big);
    pos.* += 8;
}

fn readU64(src: []const u8, pos: *usize) u64 {
    const value = std.mem.readInt(u64, src[pos.*..][0..8], .big);
    pos.* += 8;
    return value;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn idOf(b: u8) Id {
    var id: Id = @splat(0);
    id[0] = b;
    return id;
}

test "first sight of an id is fresh; second sight within the window is replay" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{});
    defer tracker.deinit();

    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x01), 1_000));
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0x01), 2_000));
    try testing.expectEqual(@as(usize, 1), tracker.size());
}

test "different ids are independent" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{});
    defer tracker.deinit();

    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xaa), 1_000));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xbb), 1_500));
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0xaa), 2_000));
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0xbb), 2_500));
}

test "an id past max_age_us becomes fresh again" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{ .max_age_us = 1_000 });
    defer tracker.deinit();

    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x42), 1_000));
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0x42), 1_500));
    // 1_000 us past insert: aged out.
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x42), 2_000));
    try testing.expectEqual(@as(usize, 1), tracker.size());
}

test "max_entries cap evicts the oldest entry" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{ .max_entries = 3 });
    defer tracker.deinit();

    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x01), 1));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x02), 2));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x03), 3));
    // Inserting a 4th evicts id 0x01.
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x04), 4));
    try testing.expectEqual(@as(usize, 3), tracker.size());
    // 0x01 is now fresh-able because it was evicted.
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x01), 5));
    // 0x02..0x04 are still replays.
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0x03), 6));
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0x04), 7));
}

test "explicit prune drops aged-out entries without inserting" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{ .max_age_us = 1_000 });
    defer tracker.deinit();

    _ = try tracker.consume(idOf(0xa1), 1_000);
    _ = try tracker.consume(idOf(0xa2), 1_500);
    try testing.expectEqual(@as(usize, 2), tracker.size());

    // Window passes, then prune.
    tracker.prune(3_000);
    try testing.expectEqual(@as(usize, 0), tracker.size());

    // Both ids are now fresh again.
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xa1), 3_500));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xa2), 3_500));
}

test "init rejects zero max_entries / max_age_us" {
    try testing.expectError(error.InvalidOptions, AntiReplayTracker.init(
        testing.allocator,
        .{ .max_entries = 0 },
    ));
    try testing.expectError(error.InvalidOptions, AntiReplayTracker.init(
        testing.allocator,
        .{ .max_age_us = 0 },
    ));
}

test "consume re-insertion after age-out preserves single-shot semantics" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{ .max_age_us = 1_000 });
    defer tracker.deinit();

    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xff), 1_000));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xff), 3_000)); // aged out
    // Same id within the new window: replay again.
    try testing.expectEqual(Verdict.replay, try tracker.consume(idOf(0xff), 3_500));
}

test "persistence round-trips options, clock, replay verdicts, and FIFO order" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{
        .max_entries = 3,
        .max_age_us = 10_000,
    });
    defer tracker.deinit();

    tracker.bumpClock(2_000);
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x01), 1_000));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0x02), 1_500));
    const bytes = try tracker.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(try tracker.encodedLen(), bytes.len);

    var restored = try AntiReplayTracker.restore(testing.allocator, bytes);
    defer restored.deinit();

    try testing.expectEqual(@as(usize, 3), restored.options.max_entries);
    try testing.expectEqual(@as(u64, 10_000), restored.options.max_age_us);
    try testing.expectEqual(@as(u64, 2_000), restored.last_observed_now_us);
    try testing.expectEqual(@as(usize, 2), restored.size());
    try testing.expectEqual(Verdict.replay, try restored.consume(idOf(0x01), 2_100));
    try testing.expectEqual(Verdict.replay, try restored.consumeUsingInternalClock(idOf(0x02)));

    // FIFO order survived the restore: inserting two new IDs evicts
    // 0x01 then 0x02 in that order under max_entries=3.
    try testing.expectEqual(Verdict.fresh, try restored.consume(idOf(0x03), 3_000));
    try testing.expectEqual(Verdict.fresh, try restored.consume(idOf(0x04), 4_000));
    try testing.expectEqual(Verdict.fresh, try restored.consume(idOf(0x01), 4_500));
    try testing.expectEqual(Verdict.fresh, try restored.consume(idOf(0x02), 5_000));
}

test "persistence rejects unknown version, flags, malformed lengths, and duplicates" {
    var tracker = try AntiReplayTracker.init(testing.allocator, .{ .max_entries = 4 });
    defer tracker.deinit();
    try testing.expectEqual(Verdict.fresh, try tracker.consume(idOf(0xaa), 1));
    const bytes = try tracker.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);

    var mutated = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(mutated);
    mutated[4] = persistence_version + 1;
    try testing.expectError(PersistenceError.UnsupportedVersion, AntiReplayTracker.restore(testing.allocator, mutated));
    mutated[4] = persistence_version;
    mutated[5] = 1;
    try testing.expectError(PersistenceError.InvalidFlags, AntiReplayTracker.restore(testing.allocator, mutated));
    mutated[5] = persistence_flags;

    std.mem.writeInt(u64, mutated[30..38], @as(u64, 2), .big);
    try testing.expectError(PersistenceError.InvalidFormat, AntiReplayTracker.restore(testing.allocator, mutated));

    const dup_len = bytes.len + persistence_entry_len;
    var dup = try testing.allocator.alloc(u8, dup_len);
    defer testing.allocator.free(dup);
    @memcpy(dup[0..bytes.len], bytes);
    @memcpy(dup[bytes.len..dup_len], bytes[persistence_header_len..bytes.len]);
    std.mem.writeInt(u64, dup[30..38], @as(u64, 2), .big);
    try testing.expectError(PersistenceError.DuplicateEntry, AntiReplayTracker.restore(testing.allocator, dup));

    var trailing = try testing.allocator.alloc(u8, bytes.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0xff;
    try testing.expectError(PersistenceError.TrailingBytes, AntiReplayTracker.restore(
        testing.allocator,
        trailing,
    ));
}

// -- fuzz harness --------------------------------------------------------
//
// Drive `consume` / `prune` / `consumeUsingInternalClock` /
// `bumpClock` with corpus-derived ids and timestamps under tight
// `max_entries` and `max_age_us` to exercise the eviction and
// pruning paths. Properties:
//
// - No panic, no leak (testing allocator catches leaks at deinit).
// - `size() <= max_entries` always.
// - First `consume(id, t)` returns `.fresh`; second call with the
//   same id at any t' where (t' - t) < max_age_us returns `.replay`,
//   provided the id has not been evicted by a cap-overflow in between.
// - `prune(t)` and `consume` keep the tracker structurally consistent:
//   `entries.items.len == seen.count()` only invariantly when no
//   re-insertion-after-aged-out interleaves. We assert the weaker
//   `size() == entries.items.len` (the intended public meaning).

test "fuzz: anti_replay tracker invariants" {
    try std.testing.fuzz({}, fuzzAntiReplay, .{});
}

fn fuzzAntiReplay(_: void, smith: *std.testing.Smith) anyerror!void {
    const max_entries: usize = 8;
    const max_age_us: u64 = 1_000_000;
    var tracker = try AntiReplayTracker.init(testing.allocator, .{
        .max_entries = max_entries,
        .max_age_us = max_age_us,
    });
    defer tracker.deinit();

    // Track a small id pool so consume hits real replays often.
    const pool_size: u8 = 32;

    var steps: u32 = 0;
    while (steps < 256 and !smith.eos()) : (steps += 1) {
        const op = smith.valueRangeAtMost(u8, 0, 4);
        switch (op) {
            0, 1, 2 => {
                // consume — biased 3/5 so the tracker actually sees traffic.
                var id: Id = @splat(0);
                id[0] = smith.valueRangeAtMost(u8, 0, pool_size - 1);
                const now_us = smith.value(u32);
                _ = tracker.consume(id, now_us) catch |e| switch (e) {
                    error.OutOfMemory => return,
                };
            },
            3 => {
                const now_us = smith.value(u32);
                tracker.prune(now_us);
            },
            4 => {
                const now_us = smith.value(u32);
                tracker.bumpClock(now_us);
                var id: Id = @splat(0);
                id[0] = smith.valueRangeAtMost(u8, 0, pool_size - 1);
                _ = tracker.consumeUsingInternalClock(id) catch |e| switch (e) {
                    error.OutOfMemory => return,
                };
            },
            else => unreachable,
        }

        // Bound is never exceeded.
        try testing.expect(tracker.size() <= max_entries);
        try testing.expectEqual(tracker.entries.items.len, tracker.size());
    }

    // Cross-cutting: the freshness contract for a *fresh* id must
    // hold within a stable time window. Pick a `now_us` past every
    // entry's max_age_us so prune empties the cache regardless of
    // whatever the fuzzer steered the internal clock to.
    const t0: u64 = std.math.maxInt(u32) + max_age_us + 1;
    tracker.prune(t0);
    try testing.expectEqual(@as(usize, 0), tracker.size());

    var probe_id: Id = @splat(0);
    probe_id[0] = pool_size; // not in the fuzzer's pool
    try testing.expectEqual(Verdict.fresh, try tracker.consume(probe_id, t0));
    try testing.expectEqual(Verdict.replay, try tracker.consume(probe_id, t0 + 1));
    try testing.expectEqual(Verdict.fresh, try tracker.consume(probe_id, t0 + max_age_us));
}
