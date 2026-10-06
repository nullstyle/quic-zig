//! A bounded note of how recently reclaimed streams' receive halves
//! ended, so an application that reads after `tick` reclaimed a
//! stream can still tell a clean end from a reset
//! (`Connection.streamRecvEnd`).
//!
//! Why it exists: `tick` reclaims a stream the moment its receive half
//! is terminal, and an end that arrives with nothing left to read (a
//! bare FIN after the last read, or a RESET_STREAM) can therefore be
//! reclaimed before the application looks. Without this note, a clean
//! end and a reset look the same afterwards, and the reset code is
//! gone. The note changes nothing about WHEN a stream is reclaimed or
//! when its stream credit returns to the peer.
//!
//! A FIFO of `capacity` records. `gcClosedStreams` reclaims at most
//! `gc_batch` streams per call and runs once per `tick`, and
//! `capacity = 2 * gc_batch`, so the record a tick writes survives at
//! least through the end of the NEXT tick. After that it can be
//! overwritten; the answer for that stream is then "ended, outcome
//! unknown", which callers must treat as a cut stream.
//!
//! Records are a lossless encoding of `Connection.StreamRecvEnd`,
//! packed to 40 bytes (36 on a 32-bit target, where a u64 aligns to
//! 4) so the whole ring stays near 10 KiB. It is heap-allocated once
//! per connection, on the first reclaim that needs it.

const RecvEndRing = @This();

const std = @import("std");

/// The most streams `gcClosedStreams` reclaims in one call. Owned here
/// so the ring's survival guarantee and the GC batch cannot drift apart.
pub const gc_batch: usize = 128;

/// Two GC batches: a record survives the tick after the one that wrote it.
pub const capacity: usize = 2 * gc_batch;

pub const Flags = packed struct(u8) {
    fin_seen: bool = false,
    reset: bool = false,
    stopped: bool = false,
    arrived_in_early_data: bool = false,
    _pad: u4 = 0,
};

/// One reclaimed stream's receive-half end. `reset_code` is meaningful
/// only when `flags.reset` is set.
pub const Record = struct {
    id: u64,
    final_size: u64,
    read_offset: u64,
    reset_code: u64,
    flags: Flags,
};

records: [capacity]Record = undefined,
/// Valid records, at most `capacity`.
len: usize = 0,
/// The slot the next `push` writes (it holds the oldest record once full).
next: usize = 0,

/// Append a record, overwriting the oldest one when full.
pub fn push(self: *RecvEndRing, rec: Record) void {
    self.records[self.next] = rec;
    self.next = (self.next + 1) % capacity;
    if (self.len < capacity) self.len += 1;
}

/// The record for `id`, or null if it was never written or has been
/// overwritten. Stream ids are never reused, so at most one matches.
pub fn find(self: *const RecvEndRing, id: u64) ?Record {
    var i: usize = 0;
    while (i < self.len) : (i += 1) {
        // Newest first: the stream most likely asked about is the one
        // the last tick reclaimed.
        const slot = (self.next + capacity - 1 - i) % capacity;
        if (self.records[slot].id == id) return self.records[slot];
    }
    return null;
}

comptime {
    // The size the module doc promises: four u64 and the flags byte,
    // padded to the alignment of u64. That is 40 bytes where a u64
    // aligns to 8 and 36 where it aligns to 4 (x86-linux-musl), so the
    // check is on the layout, not on a number: a field added without
    // packing shows up here instead of as silent per-connection
    // growth, and a 32-bit target still compiles. v0.28.0 asserted
    // `== 40` and did not compile for x86-linux-musl.
    std.debug.assert(@sizeOf(Record) == 4 * @sizeOf(u64) + @alignOf(u64));
}

const testing = std.testing;

fn sample(id: u64) Record {
    return .{ .id = id, .final_size = id * 10, .read_offset = id, .reset_code = 0, .flags = .{ .fin_seen = true } };
}

test "find returns the record for an id and null for one never written" {
    var ring: RecvEndRing = .{};
    ring.push(sample(4));
    ring.push(sample(8));
    try testing.expectEqual(@as(u64, 40), ring.find(4).?.final_size);
    try testing.expectEqual(@as(u64, 80), ring.find(8).?.final_size);
    try testing.expectEqual(@as(?Record, null), ring.find(12));
}

test "a full ring overwrites the oldest record first" {
    var ring: RecvEndRing = .{};
    var id: u64 = 0;
    while (id < capacity) : (id += 1) ring.push(sample(id));
    try testing.expectEqual(capacity, ring.len);
    try testing.expect(ring.find(0) != null);
    // One more push overwrites id 0 and only id 0.
    ring.push(sample(capacity));
    try testing.expectEqual(capacity, ring.len);
    try testing.expectEqual(@as(?Record, null), ring.find(0));
    try testing.expect(ring.find(1) != null);
    try testing.expect(ring.find(capacity) != null);
}

test "two GC batches of pushes keep the earlier batch" {
    // The survival guarantee in the module doc: a batch written by one
    // tick is still present after the next tick writes a full batch.
    var ring: RecvEndRing = .{};
    var id: u64 = 0;
    while (id < gc_batch) : (id += 1) ring.push(sample(id));
    while (id < 2 * gc_batch) : (id += 1) ring.push(sample(id));
    var first: u64 = 0;
    while (first < gc_batch) : (first += 1) try testing.expect(ring.find(first) != null);
}
