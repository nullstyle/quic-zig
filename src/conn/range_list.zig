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

/// Index of the range that contains `point`, or null. Binary search
/// over a sorted-disjoint list.
pub fn findPoint(list: []const Range, point: u64) ?usize {
    var lo: usize = 0;
    var hi: usize = list.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const r = list[mid];
        if (point < r.offset) {
            hi = mid;
        } else if (point >= r.end) {
            lo = mid + 1;
        } else return mid;
    }
    return null;
}

/// True iff a range of the sorted-disjoint list contains `point`.
pub fn containsPoint(list: []const Range, point: u64) bool {
    return findPoint(list, point) != null;
}

/// True iff taking `point` out would cut a range in two, so that
/// `removePoint` grows the list by one slot.
pub fn removalSplits(list: []const Range, point: u64) bool {
    const i = findPoint(list, point) orelse return false;
    return point != list[i].offset and point != list[i].end - 1;
}

/// Take the single value `point` out of a sorted-disjoint range list.
/// Returns false, with the list unchanged, when no range contains it.
/// Taking a point out of the middle of a range splits the range; that
/// is the only case that allocates, and on failure the list is
/// unchanged.
pub fn removePoint(
    list: *std.ArrayList(Range),
    allocator: std.mem.Allocator,
    point: u64,
) std.mem.Allocator.Error!bool {
    const i = findPoint(list.items, point) orelse return false;
    const r = list.items[i];
    if (r.len() == 1) {
        _ = list.orderedRemove(i);
    } else if (point == r.offset) {
        list.items[i].offset = point + 1;
    } else if (point == r.end - 1) {
        list.items[i].end = point;
    } else {
        try list.insert(allocator, i + 1, .{ .offset = point + 1, .end = r.end });
        list.items[i].end = point;
    }
    return true;
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

test "findPoint and containsPoint: every point of every range, and the gaps" {
    const list = [_]Range{
        .{ .offset = 2, .end = 5 },
        .{ .offset = 7, .end = 8 },
        .{ .offset = 20, .end = 23 },
    };
    const inside = [_]struct { u64, usize }{
        .{ 2, 0 }, .{ 3, 0 }, .{ 4, 0 }, .{ 7, 1 }, .{ 20, 2 }, .{ 21, 2 }, .{ 22, 2 },
    };
    for (inside) |case| {
        try testing.expectEqual(@as(?usize, case[1]), findPoint(&list, case[0]));
        try testing.expect(containsPoint(&list, case[0]));
    }
    // Below the list, each end (half-open), the gaps, and above.
    for ([_]u64{ 0, 1, 5, 6, 8, 19, 23, 24, std.math.maxInt(u64) }) |point| {
        try testing.expectEqual(@as(?usize, null), findPoint(&list, point));
        try testing.expect(!containsPoint(&list, point));
    }
    try testing.expect(!containsPoint(&.{}, 0));
}

test "removePoint: the four shapes, and a miss changes nothing" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);
    try insertMerge(&list, test_alloc, .{ .offset = 10, .end = 20 });
    try insertMerge(&list, test_alloc, .{ .offset = 30, .end = 31 });

    // A miss: below, in the gap, at a half-open end, above.
    for ([_]u64{ 9, 20, 25, 31, 32 }) |point| {
        try testing.expect(!removalSplits(list.items, point));
        try testing.expect(!try removePoint(&list, test_alloc, point));
    }
    try expectRanges(&list, &.{ .{ .offset = 10, .end = 20 }, .{ .offset = 30, .end = 31 } });

    // The low end of a range: it shrinks from below, no split.
    try testing.expect(!removalSplits(list.items, 10));
    try testing.expect(try removePoint(&list, test_alloc, 10));
    try expectRanges(&list, &.{ .{ .offset = 11, .end = 20 }, .{ .offset = 30, .end = 31 } });

    // The high end: it shrinks from above, no split.
    try testing.expect(!removalSplits(list.items, 19));
    try testing.expect(try removePoint(&list, test_alloc, 19));
    try expectRanges(&list, &.{ .{ .offset = 11, .end = 19 }, .{ .offset = 30, .end = 31 } });

    // The middle: the range splits and the list grows by one.
    try testing.expect(removalSplits(list.items, 15));
    try testing.expect(try removePoint(&list, test_alloc, 15));
    try expectRanges(&list, &.{
        .{ .offset = 11, .end = 15 },
        .{ .offset = 16, .end = 19 },
        .{ .offset = 30, .end = 31 },
    });

    // A one-value range disappears.
    try testing.expect(!removalSplits(list.items, 30));
    try testing.expect(try removePoint(&list, test_alloc, 30));
    try expectRanges(&list, &.{ .{ .offset = 11, .end = 15 }, .{ .offset = 16, .end = 19 } });

    // Removed points are gone; their neighbours are not.
    for ([_]u64{ 10, 15, 19, 30 }) |point| try testing.expect(!containsPoint(list.items, point));
    for ([_]u64{ 11, 14, 16, 18 }) |point| try testing.expect(containsPoint(list.items, point));
}

test "removePoint: a failed split leaves the list unchanged" {
    var list: std.ArrayList(Range) = .empty;
    defer list.deinit(test_alloc);
    try insertMerge(&list, test_alloc, .{ .offset = 0, .end = 9 });

    // No spare capacity, and an allocator that refuses both a new
    // block and growth in place: the split has nowhere to go.
    list.shrinkAndFree(test_alloc, list.items.len);
    var failing = std.testing.FailingAllocator.init(test_alloc, .{ .fail_index = 0, .resize_fail_index = 0 });
    try testing.expectError(error.OutOfMemory, removePoint(&list, failing.allocator(), 4));
    try expectRanges(&list, &.{.{ .offset = 0, .end = 9 }});
    try testing.expect(containsPoint(list.items, 4));
}
