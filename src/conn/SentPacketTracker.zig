//! Sent-packet tracker (RFC 9002 §A.1).
//!
//! Per packet number space, records each sent packet's metadata
//! until it's acknowledged or declared lost. Loss recovery walks
//! this set when an ACK arrives to compute newly-acked PNs and
//! detect lost ones.

// Consumers spell `<module>.SentPacketTracker`; the pub self-alias keeps
// that path resolving now that the file IS the type.
pub const SentPacketTracker = @This();

const std = @import("std");
const frame_types = @import("../frame/types.zig");

/// Maximum number of control frames a single tracked packet can carry
/// for retransmission bookkeeping.
pub const max_retransmit_frames: usize = 16;
/// Maximum number of STREAM keys a single tracked packet can reference
/// (one per coalesced STREAM frame inside the packet).
pub const max_stream_keys_per_packet: usize = 32;

/// Tagged union of control frames the connection may need to
/// retransmit when the carrying packet is lost.
pub const RetransmitFrame = union(enum) {
    max_data: frame_types.MaxData,
    max_stream_data: frame_types.MaxStreamData,
    max_streams: frame_types.MaxStreams,
    data_blocked: frame_types.DataBlocked,
    stream_data_blocked: frame_types.StreamDataBlocked,
    streams_blocked: frame_types.StreamsBlocked,
    new_connection_id: frame_types.NewConnectionId,
    retire_connection_id: frame_types.RetireConnectionId,
    handshake_done: frame_types.HandshakeDone,
    stop_sending: frame_types.StopSending,
    path_response: frame_types.PathResponse,
    path_challenge: frame_types.PathChallenge,
    reset_stream: frame_types.ResetStream,
    path_abandon: frame_types.PathAbandon,
    path_status_backup: frame_types.PathStatus,
    path_status_available: frame_types.PathStatus,
    path_new_connection_id: frame_types.PathNewConnectionId,
    path_retire_connection_id: frame_types.PathRetireConnectionId,
    max_path_id: frame_types.MaxPathId,
    paths_blocked: frame_types.PathsBlocked,
    path_cids_blocked: frame_types.PathCidsBlocked,
    /// NEW_TOKEN retransmit slot. Stores the token by value (max 96
    /// bytes) so the loss-recovery requeue path doesn't need to
    /// chase a borrowed slice that may have been overwritten when
    /// `pending_frames.new_token` was cleared on first emit.
    new_token: NewTokenRetransmit,
    /// ALTERNATIVE_V4_ADDRESS retransmit slot
    /// (draft-munizaga-quic-alternative-server-address-00 §6).
    alternative_v4_address: frame_types.AlternativeV4Address,
    /// ALTERNATIVE_V6_ADDRESS retransmit slot.
    alternative_v6_address: frame_types.AlternativeV6Address,
};

/// Inline NEW_TOKEN payload for `RetransmitFrame.new_token`. Mirrors
/// `pending_frames.NewTokenItem` so the requeue path can stamp the
/// bytes back into the pending slot byte-for-byte. Kept here (instead
/// of importing the queue type) to avoid a circular import between
/// `sent_packets` and `pending_frames`.
pub const NewTokenRetransmit = struct {
    pub const max_len: usize = 96;
    bytes: [max_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const NewTokenRetransmit) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Reference to a DATAGRAM frame the application owns. Surfaces
/// ack/loss outcomes so the app can run its own retry policy
/// (RFC 9221 §3).
pub const SentDatagram = struct {
    id: u64,
    len: usize,
    path_id: u32 = 0,
};

/// Routing handle for one STREAM-frame chunk on a sent packet:
/// `stream_id` picks the SendStream out of `Connection.streams`,
/// `stream_key` picks the chunk out of that stream's in-flight map.
///
/// QUIC stream IDs are 62-bit varints (RFC 9000 §16), so `maxInt(u64)`
/// is unambiguously outside the valid range and serves as an
/// "unoccupied" sentinel — letting us store the primary ref inline as
/// a non-optional struct without the 8-byte Optional bookkeeping, so
/// `SentPacket`'s footprint inside the 4096-slot tracker doesn't grow.
pub const StreamRef = struct {
    stream_id: u64,
    stream_key: u64,

    pub const empty: StreamRef = .{
        .stream_id = std.math.maxInt(u64),
        .stream_key = 0,
    };

    pub fn isEmpty(self: StreamRef) bool {
        return self.stream_id == std.math.maxInt(u64);
    }
};

/// Metadata for one packet the connection has put on the wire and
/// is awaiting an ACK or loss outcome for.
pub const SentPacket = struct {
    pn: u64,
    /// Send time in microseconds (monotonic clock the caller manages).
    sent_time_us: u64,
    /// Wire size of the encoded packet (header + ciphertext + tag).
    /// Used for in-flight bookkeeping and congestion-controller updates.
    bytes: u64,
    /// -- Delivery-rate sampler stamps (draft-cheng-iccrg-delivery-rate-
    /// estimation-02 §3.1.2, as embedded/updated by draft-ietf-ccwg-bbr-06
    /// §4.1.2.1.2). Written by `delivery_rate.Estimator.onPacketSent` for
    /// in-flight application/0-RTT packets; zero for Initial/Handshake
    /// and non-in-flight packets, which are never sampled.
    ///
    /// `C.delivered` at send time (bytes delivered so far on this path).
    delivered: u64 = 0,
    /// `C.delivered_time` at send time (µs).
    delivered_time_us: u64 = 0,
    /// `C.first_sent_time` at send time (µs) — the start of the send
    /// interval a future rate sample over this packet will measure.
    first_sent_time_us: u64 = 0,
    /// Bytes in flight immediately after this transmission, INCLUDING
    /// this packet (ccwg-bbr-06 §4.1.2.1.2 `P.tx_in_flight`).
    tx_in_flight: u64 = 0,
    /// `C.lost` at send time (bytes). BBR's loss response computes
    /// `rs.lost = C.lost - P.lost` from it (ccwg-bbr-06 §5.5.10.2).
    lost_at_send: u64 = 0,
    /// Did this packet contain at least one ack-eliciting frame?
    /// (Almost any frame except PADDING/ACK/CONNECTION_CLOSE.)
    ack_eliciting: bool,
    /// Did this packet contribute to bytes-in-flight? Most packets
    /// do; ACK-only packets and pure PADDING runs do not.
    in_flight: bool,
    /// Ack-eliciting control frames that need explicit ACK/loss
    /// handling. STREAM frames are tracked by SendStream; DATAGRAM,
    /// ACK, PADDING, and CONNECTION_CLOSE are intentionally absent.
    ///
    /// Heap-backed on purpose: an inline [max_retransmit_frames]
    /// array would put ~16 x @sizeOf(RetransmitFrame) (the union's
    /// NEW_TOKEN arm alone carries 96 token bytes inline) inside
    /// every one of the 4096 tracker slots, ballooning SentPacket
    /// from its pinned 184 bytes to ~2.3 KB and the tracker to
    /// ~9.5 MB per connection. The array is allocated only for the
    /// small fraction of packets that actually carry retransmittable
    /// control frames; bulk-transfer packets (one inline stream_ref)
    /// pay zero allocations.
    retransmit_frames: std.ArrayList(RetransmitFrame) = .empty,
    /// DATAGRAM frames are not retransmitted by QUIC, but apps need
    /// ack/loss visibility to implement their own retry policy.
    datagram: ?SentDatagram = null,
    /// Routing handle for the first STREAM chunk on this packet. The
    /// `stream_id` lets ACK/loss dispatch look up the owning SendStream
    /// in O(1); `stream_key` then picks the chunk out of that stream's
    /// in-flight map. Application PNs are per-path under multipath so
    /// the wire PN alone is not globally unique — hence the side-table.
    /// `StreamRef.empty` (stream_id = maxInt(u64)) means "no STREAM
    /// frame on this packet"; using a sentinel instead of `?StreamRef`
    /// keeps SentPacket compact inside the 4096-slot tracker.
    stream_ref: StreamRef = StreamRef.empty,
    /// Additional refs when multiple STREAM frames are packed into one
    /// QUIC packet. Allocated only for coalesced STREAM packets; the
    /// primary `stream_ref` is the first entry so the common
    /// single-frame case stays compact.
    extra_stream_refs: std.ArrayList(StreamRef) = .empty,
    /// True when this Application-space packet was sent under 0-RTT
    /// keys. If TLS rejects early data, callers can requeue STREAM
    /// bytes without treating the packet as congestion loss.
    is_early_data: bool = false,
    /// 1-RTT application key epoch used to protect this packet.
    /// Null for Initial, Handshake, and 0-RTT packets.
    key_epoch: ?u64 = null,
    /// Key Phase bit used on the wire for a 1-RTT application packet.
    key_phase: ?bool = null,
    /// `C.app_limited != 0` at send time (draft-cheng-02 §3.2): a rate
    /// sample over this packet must not be taken as evidence of the
    /// path's full bandwidth.
    is_app_limited: bool = false,
    /// Tombstone: this slot was removed (acked / lost / PTO-expired)
    /// and awaits compaction inside `record`. Dead slots keep their
    /// field values (so PN-ordered scans and binary search stay
    /// correct) but own nothing — ownership of the heap-backed arrays
    /// transferred to whoever removed the packet. Every content-driven
    /// walk outside this file must skip dead entries; the removal APIs
    /// here skip them internally.
    dead: bool = false,

    /// Append a control frame so loss recovery can re-queue it if the
    /// packet is declared lost. Errors with `TooManyRetransmittableFrames`
    /// when capacity is reached.
    pub fn addRetransmitFrame(
        self: *SentPacket,
        allocator: std.mem.Allocator,
        frame: RetransmitFrame,
    ) Error!void {
        if (self.retransmit_frames.items.len >= max_retransmit_frames) {
            return Error.TooManyRetransmittableFrames;
        }
        try self.retransmit_frames.append(allocator, frame);
    }

    /// Record a STREAM-frame routing ref so ack/loss callbacks can
    /// reach the right `SendStream` directly. Sets `stream_ref` on the
    /// first call, then appends to `extra_stream_refs`.
    pub fn addStreamRef(self: *SentPacket, allocator: std.mem.Allocator, ref: StreamRef) Error!void {
        if (self.stream_ref.isEmpty()) {
            self.stream_ref = ref;
            return;
        }
        if (self.extra_stream_refs.items.len >= max_stream_keys_per_packet - 1) {
            return Error.TooManyStreamFrames;
        }
        try self.extra_stream_refs.append(allocator, ref);
    }

    /// Iterator over every STREAM ref carried by a `SentPacket`
    /// (the primary `stream_ref` first, then `extra_stream_refs`).
    pub const StreamRefIterator = struct {
        packet: *const SentPacket,
        index: usize = 0,

        /// Yield the next StreamRef, or null when exhausted.
        pub fn next(self: *StreamRefIterator) ?StreamRef {
            if (self.index == 0) {
                self.index = 1;
                if (!self.packet.stream_ref.isEmpty()) return self.packet.stream_ref;
            }
            const extra_index = self.index - 1;
            if (extra_index >= self.packet.extra_stream_refs.items.len) return null;
            self.index += 1;
            return self.packet.extra_stream_refs.items[extra_index];
        }
    };

    /// Build an iterator over every STREAM ref referenced by this packet.
    pub fn streamRefs(self: *const SentPacket) StreamRefIterator {
        return .{ .packet = self };
    }

    /// Release the heap-backed retransmit-frame and stream-ref arrays.
    pub fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
        self.retransmit_frames.deinit(allocator);
        self.extra_stream_refs.deinit(allocator);
        self.* = undefined;
    }
};

/// Application-space tracker capacity. Real connections rarely hold
/// more than a few hundred live packets; 4096 gives high-BDP headroom
/// (the highest observed across this repo's full test + impairment +
/// smoke corpus is 915). Capacity is a per-tracker choice made at
/// `init`, so a PN space that provably needs less pays for less. When
/// a tracker is live-full, `record` returns `Error.TooManyInFlight` —
/// a connection-fatal condition the caller should map to a
/// CONNECTION_CLOSE.
pub const max_tracked: usize = 4096;

/// Initial/Handshake-space tracker capacity. Those spaces carry the
/// handshake flights and then sit idle for the connection's remaining
/// lifetime, so they get 256 slots instead of the Application space's
/// 4096 — returning ~1.35 MiB per connection. Sizing evidence, both
/// directions:
///
/// - Measured: across 591 connections spanning the unit/integration
///   suites, all eight deterministic impairment cells (including 5%
///   loss, which exercises handshake PTO retransmission), and both
///   wall-clock smokes, peak live occupancy was 3 (Initial) and 1
///   (Handshake) — 256 is ~85x the observed worst case.
/// - Bounded: the largest legitimate Handshake flight is a
///   certificate chain, and BoringSSL peers reject chains above
///   SSL_MAX_CERT_LIST_DEFAULT (100 KiB) by default, making that the
///   de-facto interop ceiling for what anyone ships. 100 KiB of
///   CRYPTO is ~90 packets; holding even that many live at once needs
///   cwnd > ~300 KiB DURING the handshake, which slow start reaches
///   only after ~288 KiB of the flight was already acknowledged —
///   i.e. a chain well past 0.5 MiB.
///
/// Failure mode if exceeded anyway: `record` returns
/// `Error.TooManyInFlight` and the connection closes. The one traffic
/// shape that can approach the cap — a peer soliciting ACK-carrying
/// Initial packets indefinitely while acknowledging none of them — is
/// a flood, and closing on it is the intended defense outcome (the
/// crypto-flood limiter throttles it long before this backstop).
pub const initial_handshake_max_tracked: usize = 256;

/// Errors raised by the sent-packet tracker.
pub const Error = error{
    /// `record` was called when the per-PN-space cap was reached.
    TooManyInFlight,
    /// `addRetransmitFrame` exceeded `max_retransmit_frames`.
    TooManyRetransmittableFrames,
    /// `addStreamRef` exceeded `max_stream_keys_per_packet`.
    TooManyStreamFrames,
} || std.mem.Allocator.Error;

/// Tombstone density that triggers compaction on the next `record`,
/// as a fraction of capacity: one sweep per `capacity / 4` removals.
/// High enough to amortize the sweep (each removed slot is scanned at
/// most 4 extra times), low enough that dead slots never crowd out
/// live capacity for long. `compact_threshold` is the resulting value
/// for a `max_tracked`-capacity (application-space) tracker.
pub const compact_threshold: u32 = max_tracked / 4;

/// RFC 9002 §A.1 sent-packet tracker. Indexed by PN, sorted ascending,
/// with running totals for in-flight bookkeeping.
///
/// Capacity is chosen at `init` and fixed for the tracker's lifetime —
/// per-PN-space sizing is the point (the Application space needs
/// high-BDP headroom; Initial/Handshake carry a handful of packets and
/// then sit idle for the rest of the connection).
///
/// Removal is O(1) tombstoning: removed slots stay in place (marked
/// `dead`) and are swept out in one pass inside `record` once
/// `compactThreshold()` accumulate. Compaction therefore never runs
/// while an ACK/loss walk holds indices — `record` is only called from
/// the send path. `count` includes tombstones (walks iterate physical
/// slots and skip `dead`); `liveCount()` is the tracked-packet count.
/// Slot storage, sorted ascending by PN (tombstones keep their PN,
/// preserving order for binary search). Sent packets are appended
/// at the high end; ACKs/loss tombstone anywhere. Length is the
/// tracker's capacity. Normally allocated via `init`; constructing
/// directly over caller-managed storage is allowed when the
/// lifetime is externally guaranteed (see bench/loss_ack.zig).
packets: []SentPacket,
/// Physical entries, INCLUDING tombstones. Loop bound for walks;
/// not the number of tracked packets — that is `liveCount()`.
count: u32 = 0,
/// Tombstones currently awaiting compaction.
dead_count: u32 = 0,
/// Sum of bytes for in-flight packets currently tracked.
bytes_in_flight: u64 = 0,
/// Sum of bytes for ack-eliciting packets currently tracked.
/// Used for some loss-recovery state; tracked separately so
/// we don't have to walk the array.
ack_eliciting_in_flight: u64 = 0,

/// Allocate a tracker with room for `cap` live packets. The
/// storage is exactly `cap * @sizeOf(SentPacket)` — capacity is
/// the whole per-space memory story, so size it to the space.
pub fn init(allocator: std.mem.Allocator, cap: usize) std.mem.Allocator.Error!SentPacketTracker {
    // Compaction math (capacity / 4) and the MinPipeCwnd-style
    // floor below it need a few slots to be meaningful.
    std.debug.assert(cap >= 4);
    return .{ .packets = try allocator.alloc(SentPacket, cap) };
}

/// Release every live packet's owned per-packet arrays, then the
/// slot storage itself. Tombstones own nothing (their remover took
/// ownership) — deinit'ing them would double-free.
pub fn deinit(self: *SentPacketTracker, allocator: std.mem.Allocator) void {
    self.clear(allocator);
    allocator.free(self.packets);
    self.* = undefined;
}

/// Drop every tracked packet (releasing owned per-packet arrays)
/// and zero the running totals, keeping the slot storage for
/// reuse. The key-drop / recovery-reset primitive.
pub fn clear(self: *SentPacketTracker, allocator: std.mem.Allocator) void {
    var i: u32 = 0;
    while (i < self.count) : (i += 1) {
        // Tombstones own nothing; deinit would double-free.
        if (self.packets[i].dead) continue;
        self.packets[i].deinit(allocator);
    }
    self.resetRetainingCapacity();
}

/// Forget every tracked packet WITHOUT releasing per-packet owned
/// arrays. Only correct when no live packet owns heap data (none
/// was given retransmit frames or extra stream refs) — the
/// bench/test fast-reset path. Production resets want `clear`.
pub fn resetRetainingCapacity(self: *SentPacketTracker) void {
    self.count = 0;
    self.dead_count = 0;
    self.bytes_in_flight = 0;
    self.ack_eliciting_in_flight = 0;
}

/// Live-packet capacity (the storage length fixed at init).
pub fn capacity(self: *const SentPacketTracker) u32 {
    return @intCast(self.packets.len);
}

/// Tombstone count that triggers a sweep: capacity / 4, so the
/// amortization ratio is the same at every tracker size.
fn compactThreshold(self: *const SentPacketTracker) u32 {
    return self.capacity() / 4;
}

/// Packets currently tracked (excludes tombstones).
pub fn liveCount(self: *const SentPacketTracker) u32 {
    return self.count - self.dead_count;
}

/// Record a newly-sent packet. PNs must be strictly increasing.
pub fn record(self: *SentPacketTracker, p: SentPacket) Error!void {
    if (self.liveCount() >= self.capacity()) return Error.TooManyInFlight;
    if (self.count >= self.capacity() or self.dead_count >= self.compactThreshold()) {
        // liveCount < capacity, so compaction always frees a slot.
        self.compact();
    }
    if (self.count > 0) {
        // invariant: caller is the send path, which draws PNs
        // from a monotonically-incrementing nextPn() and never
        // reuses one. Not peer-controlled; pure local data.
        // (Tombstones keep their PN, so comparing against the last
        // physical slot is still the highest PN ever recorded.)
        std.debug.assert(p.pn > self.packets[self.count - 1].pn);
    }
    self.packets[self.count] = p;
    self.count += 1;
    self.addInFlight(p);
}

/// Overwrite a removed slot with a canonical, fully-defined
/// tombstone. Only the PN survives: PN-ordered scans, binary
/// search, and the record-monotonicity assert all read dead slots'
/// PNs, and removal callbacks are allowed to `deinit` the packet
/// through the pointer they receive (which sets it to `undefined`)
/// — so the slot must be re-stamped after the callback returns.
fn tombstone(slot: *SentPacket, pn: u64) void {
    slot.* = .{
        .pn = pn,
        .sent_time_us = 0,
        .bytes = 0,
        .ack_eliciting = false,
        .in_flight = false,
        .dead = true,
    };
}

/// One-pass tombstone sweep preserving PN order. Dead slots own
/// nothing (ownership left with their remover), so this is a pure
/// move of the survivors.
fn compact(self: *SentPacketTracker) void {
    if (self.dead_count == 0) return;
    var w: u32 = 0;
    var r: u32 = 0;
    while (r < self.count) : (r += 1) {
        if (self.packets[r].dead) continue;
        if (w != r) self.packets[w] = self.packets[r];
        w += 1;
    }
    self.count = w;
    self.dead_count = 0;
}

/// Remove a tracked packet by index: O(1) tombstone, no memmove.
/// Returns the removed entry (ownership of its heap-backed arrays
/// transfers to the caller). `idx` must reference a live packet.
pub fn removeAt(self: *SentPacketTracker, idx: u32) SentPacket {
    // invariant: callers walk via indexOf/lowerBound/forward
    // scan, all of which yield indices already < count, and skip
    // dead entries before removing.
    std.debug.assert(idx < self.count);
    std.debug.assert(!self.packets[idx].dead);
    const p = self.packets[idx];
    tombstone(&self.packets[idx], p.pn);
    self.dead_count += 1;
    self.subInFlight(p);
    return p;
}

/// Credit an in-flight packet's bytes to the tracker's counters, and
/// its inverse. Every add/remove path goes through this pair so the
/// two counters can never fall out of step — the accounting block was
/// open-coded at four sites with two different orderings relative to
/// the tombstone.
fn addInFlight(self: *SentPacketTracker, p: SentPacket) void {
    if (!p.in_flight) return;
    self.bytes_in_flight += p.bytes;
    if (p.ack_eliciting) self.ack_eliciting_in_flight += p.bytes;
}

fn subInFlight(self: *SentPacketTracker, p: SentPacket) void {
    if (!p.in_flight) return;
    self.bytes_in_flight -= p.bytes;
    if (p.ack_eliciting) self.ack_eliciting_in_flight -= p.bytes;
}

/// Remove every live packet in the half-open index range
/// `[start, end)`, calling `on_remove` for each before its slot is
/// tombstoned. Packet ownership is transferred to the callback.
/// Tombstones already inside the range are skipped.
pub fn removeRangeWith(
    self: *SentPacketTracker,
    start: u32,
    end: u32,
    context: anytype,
    comptime on_remove: fn (@TypeOf(context), *SentPacket) void,
) void {
    // One walk, shared with the error-aware variant below: adapt the
    // infallible callback to the fallible signature over an
    // uninhabited error set, which makes the error branch dead and
    // the generated code identical to an open-coded infallible loop.
    // The typed `on_remove` parameter is kept so infallible callers
    // keep their stricter compile-time signature check.
    const Infallible = struct {
        fn call(c: @TypeOf(context), p: *SentPacket) error{}!void {
            on_remove(c, p);
        }
    };
    self.removeRangeWithError(start, end, context, Infallible.call) catch |err| switch (err) {};
}

/// Error-aware sibling of `removeRangeWith`. If `on_remove` fails,
/// packets already handed to the callback (including the failing
/// packet) are removed; remaining live packets in `[start, end)`
/// stay tracked.
pub fn removeRangeWithError(
    self: *SentPacketTracker,
    start: u32,
    end: u32,
    context: anytype,
    comptime on_remove: anytype,
) !void {
    std.debug.assert(start <= end);
    std.debug.assert(end <= self.count);

    var i = start;
    while (i < end) : (i += 1) {
        const packet = &self.packets[i];
        if (packet.dead) continue;
        self.subInFlight(packet.*);
        const pn = packet.pn;
        const result = on_remove(context, packet);
        tombstone(packet, pn);
        self.dead_count += 1;
        result catch |err| return err;
    }
}

/// Find the index of the tracked packet with the given PN.
/// Returns null if no match. O(log N) binary search.
pub fn indexOf(self: *const SentPacketTracker, pn: u64) ?u32 {
    var lo: u32 = 0;
    var hi: u32 = self.count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const p = self.packets[mid];
        if (p.pn == pn) return mid;
        if (p.pn < pn) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return null;
}

/// Find the first tracked packet whose PN is >= `pn`.
/// Returns null if all tracked PNs are smaller.
pub fn lowerBound(self: *const SentPacketTracker, pn: u64) ?u32 {
    var lo: u32 = 0;
    var hi: u32 = self.count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (self.packets[mid].pn < pn) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo >= self.count) return null;
    return lo;
}

// -- tests ---------------------------------------------------------------

/// Live PNs in tracker order — the observable "what is tracked" view
/// the tests assert on (physical slots include tombstones).
fn livePns(t: *const SentPacketTracker, buf: []u64) []const u64 {
    var n: usize = 0;
    var i: u32 = 0;
    while (i < t.count) : (i += 1) {
        if (t.packets[i].dead) continue;
        buf[n] = t.packets[i].pn;
        n += 1;
    }
    return buf[0..n];
}

test "record + remove + bytes_in_flight bookkeeping" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    try t.record(.{ .pn = 0, .sent_time_us = 100, .bytes = 1200, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 1, .sent_time_us = 110, .bytes = 800, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 2, .sent_time_us = 120, .bytes = 60, .ack_eliciting = false, .in_flight = false });

    try std.testing.expectEqual(@as(u32, 3), t.liveCount());
    try std.testing.expectEqual(@as(u64, 2000), t.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 2000), t.ack_eliciting_in_flight);

    const idx = t.indexOf(1) orelse unreachable;
    const removed = t.removeAt(idx);
    try std.testing.expectEqual(@as(u64, 1), removed.pn);
    try std.testing.expectEqual(@as(u32, 2), t.liveCount());
    try std.testing.expectEqual(@as(u64, 1200), t.bytes_in_flight);
    var pn_buf: [8]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{ 0, 2 }, livePns(&t, &pn_buf));
}

test "indexOf returns null for missing PNs" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    try t.record(.{ .pn = 5, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(?u32, 0), t.indexOf(5));
    try std.testing.expectEqual(@as(?u32, null), t.indexOf(4));
    try std.testing.expectEqual(@as(?u32, null), t.indexOf(6));
}

test "lowerBound finds the first PN >= target" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    try t.record(.{ .pn = 1, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 3, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try t.record(.{ .pn = 7, .sent_time_us = 0, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(?u32, 0), t.lowerBound(0));
    try std.testing.expectEqual(@as(?u32, 0), t.lowerBound(1));
    try std.testing.expectEqual(@as(?u32, 1), t.lowerBound(2));
    try std.testing.expectEqual(@as(?u32, 1), t.lowerBound(3));
    try std.testing.expectEqual(@as(?u32, 2), t.lowerBound(4));
    try std.testing.expectEqual(@as(?u32, 2), t.lowerBound(7));
    try std.testing.expectEqual(@as(?u32, null), t.lowerBound(8));
}

test "non-in-flight packets don't update bytes_in_flight" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    try t.record(.{ .pn = 0, .sent_time_us = 0, .bytes = 50, .ack_eliciting = false, .in_flight = false });
    try std.testing.expectEqual(@as(u64, 0), t.bytes_in_flight);
    _ = t.removeAt(0);
    try std.testing.expectEqual(@as(u64, 0), t.bytes_in_flight);
    try std.testing.expectEqual(@as(u32, 0), t.liveCount());
}

const RemovedRangeStats = struct {
    count: u32 = 0,
    pn_sum: u64 = 0,
    bytes: u64 = 0,
};

fn recordRemovedPacket(stats: *RemovedRangeStats, packet: *SentPacket) void {
    stats.count += 1;
    stats.pn_sum += packet.pn;
    stats.bytes += packet.bytes;
}

test "removeRangeWith tombstones the range and preserves sorted survivors" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var pn: u64 = 0;
    while (pn < 6) : (pn += 1) {
        try t.record(.{
            .pn = pn,
            .sent_time_us = pn,
            .bytes = 100 + pn,
            .ack_eliciting = pn != 2,
            .in_flight = pn != 3,
        });
    }

    var stats: RemovedRangeStats = .{};
    t.removeRangeWith(1, 5, &stats, recordRemovedPacket);

    try std.testing.expectEqual(@as(u32, 4), stats.count);
    try std.testing.expectEqual(@as(u64, 10), stats.pn_sum);
    try std.testing.expectEqual(@as(u64, 410), stats.bytes);
    try std.testing.expectEqual(@as(u32, 2), t.liveCount());
    var pn_buf: [8]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{ 0, 5 }, livePns(&t, &pn_buf));
    try std.testing.expectEqual(@as(u64, 205), t.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 205), t.ack_eliciting_in_flight);

    // Re-running the same range is a no-op: everything inside is dead.
    t.removeRangeWith(1, 5, &stats, recordRemovedPacket);
    try std.testing.expectEqual(@as(u32, 4), stats.count);
    try std.testing.expectEqual(@as(u32, 2), t.liveCount());
}

fn deinitRemovedPacket(allocator: std.mem.Allocator, packet: *SentPacket) void {
    packet.deinit(allocator);
}

test "removeRangeWith transfers owned packet fields to callback" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var packet: SentPacket = .{
        .pn = 0,
        .sent_time_us = 0,
        .bytes = 100,
        .ack_eliciting = true,
        .in_flight = true,
    };
    try packet.addRetransmitFrame(std.testing.allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try packet.addStreamRef(std.testing.allocator, .{ .stream_id = 0, .stream_key = 42 });
    try packet.addStreamRef(std.testing.allocator, .{ .stream_id = 4, .stream_key = 43 });
    try t.record(packet);

    t.removeRangeWith(0, 1, std.testing.allocator, deinitRemovedPacket);
    try std.testing.expectEqual(@as(u32, 0), t.liveCount());
    try std.testing.expectEqual(@as(u64, 0), t.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), t.ack_eliciting_in_flight);
}

const FallibleRemovedRangeStats = struct {
    fail_on_pn: u64,
    count: u32 = 0,
    pn_sum: u64 = 0,
};

fn recordRemovedPacketFallible(
    stats: *FallibleRemovedRangeStats,
    packet: *SentPacket,
) error{StopHere}!void {
    stats.count += 1;
    stats.pn_sum += packet.pn;
    if (packet.pn == stats.fail_on_pn) return error.StopHere;
}

test "removeRangeWithError keeps packets after failing callback" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var pn: u64 = 0;
    while (pn < 6) : (pn += 1) {
        try t.record(.{
            .pn = pn,
            .sent_time_us = pn,
            .bytes = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    var stats: FallibleRemovedRangeStats = .{ .fail_on_pn = 3 };
    try std.testing.expectError(
        error.StopHere,
        t.removeRangeWithError(1, 5, &stats, recordRemovedPacketFallible),
    );

    try std.testing.expectEqual(@as(u32, 3), stats.count);
    try std.testing.expectEqual(@as(u64, 1 + 2 + 3), stats.pn_sum);
    try std.testing.expectEqual(@as(u32, 3), t.liveCount());
    var pn_buf: [8]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{ 0, 4, 5 }, livePns(&t, &pn_buf));
    try std.testing.expectEqual(@as(u64, 300), t.bytes_in_flight);
}

test "SentPacket stores retransmittable control frames" {
    var p: SentPacket = .{
        .pn = 1,
        .sent_time_us = 10,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);
    try p.addRetransmitFrame(std.testing.allocator, .{ .max_data = .{ .maximum_data = 4096 } });
    try p.addRetransmitFrame(std.testing.allocator, .{ .path_challenge = .{ .data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } } });

    try std.testing.expectEqual(@as(usize, 2), p.retransmit_frames.items.len);
    try std.testing.expect(p.retransmit_frames.items[0] == .max_data);
    try std.testing.expectEqual(@as(u64, 4096), p.retransmit_frames.items[0].max_data.maximum_data);
    try std.testing.expect(p.retransmit_frames.items[1] == .path_challenge);
}

test "SentPacket stores multiple STREAM refs" {
    var p: SentPacket = .{
        .pn = 1,
        .sent_time_us = 10,
        .bytes = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    defer p.deinit(std.testing.allocator);

    try p.addStreamRef(std.testing.allocator, .{ .stream_id = 0, .stream_key = 11 });
    try p.addStreamRef(std.testing.allocator, .{ .stream_id = 4, .stream_key = 12 });
    try p.addStreamRef(std.testing.allocator, .{ .stream_id = 8, .stream_key = 13 });

    var it = p.streamRefs();
    try std.testing.expectEqual(@as(?StreamRef, .{ .stream_id = 0, .stream_key = 11 }), it.next());
    try std.testing.expectEqual(@as(?StreamRef, .{ .stream_id = 4, .stream_key = 12 }), it.next());
    try std.testing.expectEqual(@as(?StreamRef, .{ .stream_id = 8, .stream_key = 13 }), it.next());
    try std.testing.expectEqual(@as(?StreamRef, null), it.next());
}

test "SentPacket.stream_ref defaults to empty sentinel" {
    const p: SentPacket = .{
        .pn = 1,
        .sent_time_us = 10,
        .bytes = 1200,
        .ack_eliciting = false,
        .in_flight = false,
    };
    try std.testing.expect(p.stream_ref.isEmpty());
    var it = p.streamRefs();
    try std.testing.expectEqual(@as(?StreamRef, null), it.next());
}

test "SentPacket size stays pinned (tracker footprint = 4096 of these)" {
    // 184 = 176 bytes of 8-aligned fields (including the five u64
    // delivery-rate stamps added for rate-based congestion control)
    // + 7 one-byte tail fields (`is_app_limited` and `dead` ride in
    // tail padding) + 1 pad byte. Every +8 here costs 32 KB per
    // tracker (4096 slots) and struct-copy time in the ACK-churn hot
    // path — grow consciously, and re-run the
    // `sent_tracker_churn_3500_occupancy` A/B (baselines/bench/README.md)
    // before accepting. The 144 -> 184 growth for the stamps was
    // measured in-commit: raw churn +33% (pure 184/144 memcpy ratio),
    // end-to-end goodput -1% (crypto dominates). Rejected then, and
    // not worth re-litigating without new numbers: a compressed
    // u32-delta layout (alignment gives back only 8 of the 40 bytes)
    // and a PN-keyed side ring for the stamps (returns this micro to
    // its old number but keeps the ack-path stamping cost, and adds
    // collision semantics once a live PN span exceeds the slot
    // count — silent sample corruption traded for a synthetic win).
    try std.testing.expectEqual(@as(usize, 184), @sizeOf(SentPacket));
}

test "compaction triggers inside record and preserves order + search" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var pn: u64 = 0;
    while (pn < 2 * compact_threshold) : (pn += 1) {
        try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    }
    // Tombstone every even PN (compact_threshold of them, exactly at
    // the trigger), scanning physical slots like real callers do.
    var i: u32 = 0;
    while (i < t.count) : (i += 1) {
        if (t.packets[i].dead) continue;
        if (t.packets[i].pn % 2 == 0) _ = t.removeAt(i);
    }
    try std.testing.expectEqual(compact_threshold, t.dead_count);
    const live_before = t.liveCount();

    // The next record sweeps: physical count collapses to live+1.
    try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 100, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(u32, 0), t.dead_count);
    try std.testing.expectEqual(live_before + 1, t.count);
    try std.testing.expectEqual(live_before + 1, t.liveCount());

    // Order preserved, binary search still lands.
    var k: u32 = 1;
    while (k < t.count) : (k += 1) {
        try std.testing.expect(t.packets[k - 1].pn < t.packets[k].pn);
    }
    try std.testing.expectEqual(@as(?u32, null), t.indexOf(0)); // even: removed
    try std.testing.expect(t.indexOf(1) != null);
    try std.testing.expect(t.indexOf(2 * compact_threshold - 1) != null);
    try std.testing.expectEqual(
        @as(u64, 100 * @as(u64, t.liveCount())),
        t.bytes_in_flight,
    );
}

test "capacity is live capacity: physical-full compacts instead of failing" {
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var pn: u64 = 0;
    while (pn < max_tracked) : (pn += 1) {
        try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    }
    // Live-full: record must fail.
    try std.testing.expectError(Error.TooManyInFlight, t.record(.{
        .pn = pn,
        .sent_time_us = pn,
        .bytes = 10,
        .ack_eliciting = true,
        .in_flight = true,
    }));
    // One removal frees one live slot even though the array is
    // physically full — record compacts and succeeds.
    _ = t.removeAt(17);
    try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(u32, max_tracked), t.liveCount());
    try std.testing.expectEqual(@as(u32, 0), t.dead_count);
}

/// Reference model for the equivalence property test: a plain
/// ArrayList that removes by copy — the semantics the tombstone
/// implementation must be indistinguishable from.
const ReferenceTracker = struct {
    entries: std.ArrayList(SentPacket) = .empty,
    bytes_in_flight: u64 = 0,
    ack_eliciting_in_flight: u64 = 0,

    fn record(self: *ReferenceTracker, allocator: std.mem.Allocator, p: SentPacket) !void {
        try self.entries.append(allocator, p);
        if (p.in_flight) {
            self.bytes_in_flight += p.bytes;
            if (p.ack_eliciting) self.ack_eliciting_in_flight += p.bytes;
        }
    }

    fn removePn(self: *ReferenceTracker, pn: u64) ?SentPacket {
        for (self.entries.items, 0..) |p, i| {
            if (p.pn == pn) {
                if (p.in_flight) {
                    self.bytes_in_flight -= p.bytes;
                    if (p.ack_eliciting) self.ack_eliciting_in_flight -= p.bytes;
                }
                return self.entries.orderedRemove(i);
            }
        }
        return null;
    }
};

test "property: tombstone tracker is observably identical to the reference model" {
    const allocator = std.testing.allocator;
    var t = try SentPacketTracker.init(std.testing.allocator, max_tracked);
    defer t.deinit(std.testing.allocator);
    var ref: ReferenceTracker = .{};
    defer ref.entries.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(0x5e9d);
    const random = prng.random();

    var next_pn: u64 = 0;
    var op: u32 = 0;
    while (op < 20_000) : (op += 1) {
        const roll = random.uintLessThan(u8, 100);
        if (roll < 55 or ref.entries.items.len == 0) {
            // Record (drives the compaction trigger organically).
            const p: SentPacket = .{
                .pn = next_pn,
                .sent_time_us = next_pn * 7,
                .bytes = 1 + random.uintLessThan(u64, 1500),
                .ack_eliciting = random.boolean(),
                .in_flight = random.boolean(),
            };
            next_pn += 1;
            try t.record(p);
            try ref.record(allocator, p);
        } else if (roll < 85) {
            // Remove one random live packet by PN via removeAt.
            const pick = ref.entries.items[random.uintLessThan(usize, ref.entries.items.len)].pn;
            const idx = t.indexOf(pick).?;
            try std.testing.expect(!t.packets[idx].dead);
            const got = t.removeAt(idx);
            const want = ref.removePn(pick).?;
            try std.testing.expectEqual(want.pn, got.pn);
            try std.testing.expectEqual(want.bytes, got.bytes);
        } else {
            // Remove a contiguous PN span via removeRangeWith (the ACK
            // path shape): pick a random live packet, span up to 8 PNs.
            const anchor = ref.entries.items[random.uintLessThan(usize, ref.entries.items.len)].pn;
            const span: u64 = 1 + random.uintLessThan(u64, 8);
            const start = t.lowerBound(anchor) orelse continue;
            var end = start;
            while (end < t.count and t.packets[end].pn < anchor + span) : (end += 1) {}
            const Sink = struct {
                // Mirror what real ACK/loss dispatch is allowed to do:
                // consume the packet through the pointer and leave the
                // slot `undefined`. The tracker must re-stamp the
                // tombstone afterwards (this pinned a real bug: a wiped
                // slot's 0xAA-pattern PN broke the record assert and
                // binary-search ordering).
                fn drop(_: *u32, packet: *SentPacket) void {
                    packet.* = undefined;
                }
            };
            var sink: u32 = 0;
            t.removeRangeWith(start, end, &sink, Sink.drop);
            var pn_walk = anchor;
            while (pn_walk < anchor + span) : (pn_walk += 1) {
                _ = ref.removePn(pn_walk);
            }
        }

        // Observable equivalence after every operation.
        try std.testing.expectEqual(@as(u32, @intCast(ref.entries.items.len)), t.liveCount());
        try std.testing.expectEqual(ref.bytes_in_flight, t.bytes_in_flight);
        try std.testing.expectEqual(ref.ack_eliciting_in_flight, t.ack_eliciting_in_flight);
        // Full live-sequence check periodically (O(n) — not every op).
        if (op % 512 == 0) {
            var live_i: usize = 0;
            var phys: u32 = 0;
            var recomputed_in_flight: u64 = 0;
            while (phys < t.count) : (phys += 1) {
                const p = t.packets[phys];
                if (p.dead) continue;
                try std.testing.expectEqual(ref.entries.items[live_i].pn, p.pn);
                if (p.in_flight) recomputed_in_flight += p.bytes;
                live_i += 1;
            }
            try std.testing.expectEqual(ref.entries.items.len, live_i);
            try std.testing.expectEqual(t.bytes_in_flight, recomputed_in_flight);
        }
    }
}

test "capacity is a per-tracker init choice, enforced at the chosen size" {
    var t = try SentPacketTracker.init(std.testing.allocator, 8);
    defer t.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 8), t.capacity());

    var pn: u64 = 0;
    while (pn < 8) : (pn += 1) {
        try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    }
    try std.testing.expectError(Error.TooManyInFlight, t.record(.{
        .pn = pn,
        .sent_time_us = pn,
        .bytes = 10,
        .ack_eliciting = true,
        .in_flight = true,
    }));
    // Live capacity, not physical: freeing one slot lets record
    // compact-and-succeed exactly as at the full size.
    _ = t.removeAt(3);
    try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(u32, 8), t.liveCount());
}

test "compaction threshold scales with capacity (capacity / 4)" {
    var t = try SentPacketTracker.init(std.testing.allocator, 64);
    defer t.deinit(std.testing.allocator);

    var pn: u64 = 0;
    while (pn < 32) : (pn += 1) {
        try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    }
    // Tombstone exactly capacity/4 = 16 packets: the trigger level.
    var i: u32 = 0;
    var removed: u32 = 0;
    while (i < t.count and removed < 16) : (i += 1) {
        if (t.packets[i].dead) continue;
        _ = t.removeAt(i);
        removed += 1;
    }
    try std.testing.expectEqual(@as(u32, 16), t.dead_count);

    // The next record sweeps: physical count collapses to live+1.
    try t.record(.{ .pn = pn, .sent_time_us = pn, .bytes = 10, .ack_eliciting = true, .in_flight = true });
    try std.testing.expectEqual(@as(u32, 0), t.dead_count);
    try std.testing.expectEqual(@as(u32, 17), t.count);
    try std.testing.expectEqual(@as(u32, 17), t.liveCount());
}
