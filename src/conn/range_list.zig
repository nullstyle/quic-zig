//! Sorted-disjoint byte-range bookkeeping shared by the two stream
//! halves. `SendStream` keeps its `pending` / `acked_above` lists and
//! `RecvStream` its reassembly `ranges` in exactly this shape: a
//! sorted list of disjoint half-open `[offset, end)` intervals over
//! stream bytes, where inserting a range merges it with any interval
//! it overlaps or abuts, and `items[0]` answers the contiguous-prefix
//! query both sides depend on (`readableBytes` / the ACK-floor
//! absorption loop).
//!
//! `wire/vneg_preparse.zig`'s `ChReassembler.insertSegment` implements
//! the same merge over a fixed-capacity array because that module must
//! never allocate; a fix to the merge predicates here (the scan's
//! `end < offset` and the swallow's `offset <= end`) likely applies
//! there too.

const std = @import("std");

/// Half-open interval `[offset, end)` of stream bytes.
pub const Range = struct {
    offset: u64,
    /// One past the last byte (half-open). A 0-length range cannot be
    /// represented; `insertMerge` drops empty ranges instead of
    /// storing them, so an empty list is the only "nothing" state.
    end: u64,

    /// Length of the range in bytes.
    pub fn len(self: Range) u64 {
        return self.end - self.offset;
    }
};

/// Insert `new` into a sorted-disjoint range list, merging with any
/// adjacent or overlapping existing range. The list grows by at
/// most one slot.
pub fn insertMerge(
    list: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    new: Range,
) std.mem.Allocator.Error!void {
    if (new.offset >= new.end) return;

    // Find the first range whose end >= new.offset (i.e., the first
    // range that could overlap or touch `new` from below or itself).
    var i: usize = 0;
    while (i < list.items.len and list.items[i].end < new.offset) : (i += 1) {}

    // No overlap on either side: pure insert.
    if (i == list.items.len or list.items[i].offset > new.end) {
        try list.insert(allocator, i, new);
        return;
    }

    // Merge with list.items[i] and any further ranges it now connects to.
    var merged: Range = .{
        .offset = @min(list.items[i].offset, new.offset),
        .end = @max(list.items[i].end, new.end),
    };
    var j: usize = i + 1;
    while (j < list.items.len and list.items[j].offset <= merged.end) : (j += 1) {
        merged.end = @max(merged.end, list.items[j].end);
    }
    // Replace [i, j) with the single merged range.
    list.replaceRangeAssumeCapacity(i, j - i, &.{merged});
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const test_alloc = std.testing.allocator;

fn expectRanges(list: *const std.ArrayList(Range), expected: []const Range) !void {
    try testing.expectEqual(expected.len, list.items.len);
    for (expected, list.items) |want, got| {
        try testing.expectEqual(want.offset, got.offset);
        try testing.expectEqual(want.end, got.end);
    }
}

test "empty range is dropped" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);

    try insertMerge(&list, test_alloc, .{ .offset = 5, .end = 5 });
    try insertMerge(&list, test_alloc, .{ .offset = 7, .end = 3 });
    try expectRanges(&list, &.{});
}

test "pure inserts keep the list sorted and disjoint" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);

    try insertMerge(&list, test_alloc, .{ .offset = 10, .end = 12 });
    try insertMerge(&list, test_alloc, .{ .offset = 0, .end = 2 });
    try insertMerge(&list, test_alloc, .{ .offset = 5, .end = 7 });
    try expectRanges(&list, &.{
        .{ .offset = 0, .end = 2 },
        .{ .offset = 5, .end = 7 },
        .{ .offset = 10, .end = 12 },
    });
}

test "abutting ranges merge (touch counts as adjacency)" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);

    try insertMerge(&list, test_alloc, .{ .offset = 0, .end = 4 });
    try insertMerge(&list, test_alloc, .{ .offset = 8, .end = 12 });
    // Touches the first from above and the second from below.
    try insertMerge(&list, test_alloc, .{ .offset = 4, .end = 8 });
    try expectRanges(&list, &.{.{ .offset = 0, .end = 12 }});
}

test "overlapping insert swallows every connected range" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);

    try insertMerge(&list, test_alloc, .{ .offset = 2, .end = 4 });
    try insertMerge(&list, test_alloc, .{ .offset = 6, .end = 8 });
    try insertMerge(&list, test_alloc, .{ .offset = 10, .end = 12 });
    try insertMerge(&list, test_alloc, .{ .offset = 20, .end = 22 });
    // Overlaps the first three; the fourth stays disjoint.
    try insertMerge(&list, test_alloc, .{ .offset = 3, .end = 11 });
    try expectRanges(&list, &.{
        .{ .offset = 2, .end = 12 },
        .{ .offset = 20, .end = 22 },
    });
}

test "containment: an inner range is absorbed without growth" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);

    try insertMerge(&list, test_alloc, .{ .offset = 0, .end = 10 });
    try insertMerge(&list, test_alloc, .{ .offset = 3, .end = 5 });
    try expectRanges(&list, &.{.{ .offset = 0, .end = 10 }});
}

test "len is end minus offset" {
    const r: Range = .{ .offset = 3, .end = 9 };
    try testing.expectEqual(@as(u64, 6), r.len());
}
