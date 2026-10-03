//! Stream-id accounting for ONE stream-id space (RFC 9000 §2.1, §3.2,
//! §4.6).
//!
//! A connection has four spaces: streams the peer opens and streams
//! we open, each bidirectional or unidirectional. A space counts
//! stream INDICES (`stream_id >> 2`), which start at 0 and may be used
//! in any order.
//!
//! This type answers two questions for the connection, and holds no
//! per-stream state that lasts longer than the stream:
//!
//!  1. What happened to an id that has no live stream? `classify`
//!     says `not_opened` (nothing yet), `hole` (a lower id that was
//!     skipped when a higher one was used: RFC 9000 §2.1 opens it
//!     implicitly, and its first frame may still come), or `used` (it
//!     had a stream; with no live stream, that stream was closed, and
//!     a late frame for it is ignored, RFC 9000 §3.2).
//!  2. How many streams may be open? `limit` is the bound in force.
//!     For a space whose limit WE advertise, the bound is a
//!     CONCURRENCY window: `limit = window + closed`, so the peer gets
//!     one id back for each stream that is fully closed (RFC 9000
//!     §4.6: "increase limits as streams are closed").
//!
//! The memory argument. The only growing state is `holes`, a sorted
//! list of skipped index ranges.
//!  - Advertised space: an id below `opened` is live, a hole, or
//!    closed, so `live + holes = opened - closed <= limit - closed <=
//!    window`. A hole is never closed, so each hole holds one unit of
//!    the window for good. So there are at most `window` holes, and at
//!    most that many ranges.
//!  - Granted space (the peer advertises the limit): holes come only
//!    from the embedder opening its own ids out of order. `open` takes
//!    a cap on the number of ranges and refuses with
//!    `TooManySkippedIds` past it.
//!
//! Pure bookkeeping: no I/O, no clock, no connection. The connection
//! owns the table of live streams and calls `noteClosed` when it reaps
//! one.

// Consumers spell `<module>.StreamIdSpace`; the pub self-alias keeps
// that path resolving now that the file IS the type.
pub const StreamIdSpace = @This();

const std = @import("std");
const range_list = @import("range_list.zig");

const Range = range_list.Range;

/// Largest stream count the wire can express (RFC 9000 §4.6): a
/// stream id is a 62-bit integer whose low two bits are the type.
pub const max_stream_count: u64 = @as(u64, 1) << 60;

/// Errors `open` can return.
pub const Error = error{
    /// The index is at or above the limit in force.
    LimitExceeded,
    /// The index was used before: it is live, or it was closed.
    AlreadyUsed,
    /// Opening this index would leave more skipped ranges than the
    /// caller allows this space to remember.
    TooManySkippedIds,
} || std.mem.Allocator.Error;

/// What is known about an index.
pub const State = enum {
    /// At or above every index used so far.
    not_opened,
    /// Below a used index, and never used itself. Open (RFC 9000
    /// §2.1), with no stream object yet.
    hole,
    /// It has, or it had, a stream object.
    used,
};

/// Indices in `[0, opened)` are used or skipped. One more than the
/// highest index used.
opened: u64 = 0,
/// The skipped indices below `opened`: sorted, disjoint ranges.
holes: std.ArrayList(Range) = .empty,
/// How many streams of this space were fully closed.
closed: u64 = 0,
/// An index at or above `limit` may not be opened.
limit: u64 = 0,
/// The concurrency window of an advertised space: `limit` follows
/// `window + closed`. Zero for a granted space.
window: u64 = 0,

/// A space whose limit we advertise (streams the peer opens).
/// `window` is our `initial_max_streams_*` transport parameter.
pub fn initAdvertised(window: u64) StreamIdSpace {
    const bounded = @min(window, max_stream_count);
    return .{ .limit = bounded, .window = bounded };
}

/// A space whose limit the peer advertises (streams we open).
/// `limit` is the limit known so far.
pub fn initGranted(limit: u64) StreamIdSpace {
    return .{ .limit = @min(limit, max_stream_count) };
}

/// Release the hole list.
pub fn deinit(self: *StreamIdSpace, allocator: std.mem.Allocator) void {
    self.holes.deinit(allocator);
    self.* = undefined;
}

/// What is known about `index`.
pub fn classify(self: *const StreamIdSpace, index: u64) State {
    if (index >= self.opened) return .not_opened;
    if (range_list.containsPoint(self.holes.items, index)) return .hole;
    return .used;
}

/// Mark `index` as used: the caller is about to create its stream.
/// Every lower index that was not used yet becomes a hole.
///
/// `max_hole_ranges` bounds the hole list. On any error the space is
/// unchanged.
pub fn open(
    self: *StreamIdSpace,
    allocator: std.mem.Allocator,
    index: u64,
    max_hole_ranges: usize,
) Error!void {
    if (index >= self.limit) return Error.LimitExceeded;
    if (index < self.opened) {
        if (!range_list.containsPoint(self.holes.items, index)) return Error.AlreadyUsed;
        if (range_list.removalSplits(self.holes.items, index) and
            self.holes.items.len >= max_hole_ranges) return Error.TooManySkippedIds;
        _ = try range_list.removePoint(&self.holes, allocator, index);
        return;
    }
    if (index > self.opened) {
        // The highest used index is never a hole, so this range cannot
        // touch the last one: a plain append keeps the list sorted and
        // disjoint.
        if (self.holes.items.len >= max_hole_ranges) return Error.TooManySkippedIds;
        try self.holes.append(allocator, .{ .offset = self.opened, .end = index });
    }
    self.opened = index + 1;
}

/// One stream of this space was fully closed and its stream object is
/// gone.
pub fn noteClosed(self: *StreamIdSpace) void {
    self.closed += 1;
}

/// How many ids below `opened` were skipped and never used.
pub fn holeCount(self: *const StreamIdSpace) u64 {
    var total: u64 = 0;
    for (self.holes.items) |r| total += r.len();
    return total;
}

/// Ids that count against the window now: live streams plus holes.
pub fn inUse(self: *const StreamIdSpace) u64 {
    return self.opened - self.closed;
}

/// The limit an advertised space is entitled to: its window, plus one
/// id for each stream that closed.
pub fn target(self: *const StreamIdSpace) u64 {
    return @min(self.window +| self.closed, max_stream_count);
}

/// The limit to advertise NOW (a MAX_STREAMS frame), or null.
///
/// There is credit to give when `target() > limit`. It is given:
///  - when half a window of it has built up (one frame returns many
///    ids, and the peer is never short by more than half a window);
///  - or at once when the peer has used every id it was given, or
///    says so (`peer_blocked_at`, the value of a STREAMS_BLOCKED frame
///    it sent). RFC 9000 §4.6: do not wait for STREAMS_BLOCKED; this
///    rule does not.
pub fn creditToAdvertise(self: *const StreamIdSpace, peer_blocked_at: ?u64) ?u64 {
    const entitled = self.target();
    if (entitled <= self.limit) return null;
    if (entitled - self.limit >= @max(1, self.window / 2)) return entitled;
    if (self.opened >= self.limit) return entitled;
    if (peer_blocked_at) |at| {
        if (at >= self.limit) return entitled;
    }
    return null;
}

/// Raise the limit: we advertised `new_limit` (advertised space), or
/// the peer granted it (granted space). A limit never goes down
/// (RFC 9000 §4.6), and never above the wire's maximum.
pub fn raiseLimit(self: *StreamIdSpace, new_limit: u64) void {
    const bounded = @min(new_limit, max_stream_count);
    if (bounded > self.limit) self.limit = bounded;
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;
const test_alloc = std.testing.allocator;

/// No practical bound: these tests are about the rules, not the cap.
const no_cap = std.math.maxInt(usize);

fn expectHoles(space: *const StreamIdSpace, expected: []const Range) !void {
    try testing.expectEqual(expected.len, space.holes.items.len);
    for (expected, space.holes.items) |want, got| {
        try testing.expectEqual(want.offset, got.offset);
        try testing.expectEqual(want.end, got.end);
    }
}

test "in-order opens leave no holes" {
    var space = StreamIdSpace.initAdvertised(4);
    defer space.deinit(test_alloc);

    for (0..4) |i| {
        try testing.expectEqual(State.not_opened, space.classify(i));
        try space.open(test_alloc, i, no_cap);
        try testing.expectEqual(State.used, space.classify(i));
    }
    try testing.expectEqual(@as(u64, 4), space.opened);
    try expectHoles(&space, &.{});
    try testing.expectEqual(@as(u64, 0), space.holeCount());
    try testing.expectEqual(@as(u64, 4), space.inUse());
}

test "a jump opens the lower ids as holes; using a hole fills it" {
    var space = StreamIdSpace.initAdvertised(16);
    defer space.deinit(test_alloc);

    try space.open(test_alloc, 5, no_cap);
    try testing.expectEqual(@as(u64, 6), space.opened);
    try expectHoles(&space, &.{.{ .offset = 0, .end = 5 }});
    for (0..5) |i| try testing.expectEqual(State.hole, space.classify(i));
    try testing.expectEqual(State.used, space.classify(5));
    try testing.expectEqual(State.not_opened, space.classify(6));
    // A hole counts against the window like a live stream.
    try testing.expectEqual(@as(u64, 6), space.inUse());
    try testing.expectEqual(@as(u64, 5), space.holeCount());

    // The first frame for a skipped id arrives late: middle, then ends.
    try space.open(test_alloc, 2, no_cap);
    try expectHoles(&space, &.{ .{ .offset = 0, .end = 2 }, .{ .offset = 3, .end = 5 } });
    try space.open(test_alloc, 0, no_cap);
    try space.open(test_alloc, 4, no_cap);
    try expectHoles(&space, &.{ .{ .offset = 1, .end = 2 }, .{ .offset = 3, .end = 4 } });
    try space.open(test_alloc, 1, no_cap);
    try space.open(test_alloc, 3, no_cap);
    try expectHoles(&space, &.{});
    try testing.expectEqual(@as(u64, 6), space.opened);
    try testing.expectEqual(@as(u64, 6), space.inUse());

    // A second jump starts a new range above the first.
    try space.open(test_alloc, 9, no_cap);
    try expectHoles(&space, &.{.{ .offset = 6, .end = 9 }});
}

test "an id cannot be used twice, and a closed id stays used" {
    var space = StreamIdSpace.initAdvertised(8);
    defer space.deinit(test_alloc);

    try space.open(test_alloc, 0, no_cap);
    try testing.expectError(Error.AlreadyUsed, space.open(test_alloc, 0, no_cap));
    space.noteClosed();
    // Closed, and its stream object is gone: still `used`, never
    // `not_opened` and never a hole. This is what stops a late frame
    // from bringing a closed stream back.
    try testing.expectEqual(State.used, space.classify(0));
    try testing.expectError(Error.AlreadyUsed, space.open(test_alloc, 0, no_cap));
    try testing.expectEqual(@as(u64, 1), space.opened);
    try testing.expectEqual(@as(u64, 0), space.inUse());
}

test "the limit is exclusive, and a refused open changes nothing" {
    var space = StreamIdSpace.initAdvertised(2);
    defer space.deinit(test_alloc);

    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, 2, no_cap));
    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, std.math.maxInt(u64), no_cap));
    try testing.expectEqual(@as(u64, 0), space.opened);
    try expectHoles(&space, &.{});

    try space.open(test_alloc, 1, no_cap);
    try space.open(test_alloc, 0, no_cap);
    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, 2, no_cap));

    var none = StreamIdSpace.initAdvertised(0);
    defer none.deinit(test_alloc);
    try testing.expectError(Error.LimitExceeded, none.open(test_alloc, 0, no_cap));
}

test "the hole cap refuses a jump or a split past it, and changes nothing" {
    var space = StreamIdSpace.initGranted(1000);
    defer space.deinit(test_alloc);

    // One range: [0, 9).
    try space.open(test_alloc, 9, 2);
    // A second range: [10, 19). The list is at the cap of 2.
    try space.open(test_alloc, 19, 2);
    try expectHoles(&space, &.{ .{ .offset = 0, .end = 9 }, .{ .offset = 10, .end = 19 } });

    // A third range is refused.
    try testing.expectError(Error.TooManySkippedIds, space.open(test_alloc, 29, 2));
    // A split is refused.
    try testing.expectError(Error.TooManySkippedIds, space.open(test_alloc, 4, 2));
    try testing.expectEqual(@as(u64, 20), space.opened);
    try expectHoles(&space, &.{ .{ .offset = 0, .end = 9 }, .{ .offset = 10, .end = 19 } });

    // Uses that do not grow the list are fine at the cap: the next id
    // in order, and an end of a range.
    try space.open(test_alloc, 20, 2);
    try space.open(test_alloc, 0, 2);
    try space.open(test_alloc, 18, 2);
    try expectHoles(&space, &.{ .{ .offset = 1, .end = 9 }, .{ .offset = 10, .end = 18 } });
}

test "credit: the limit is the window plus the closed streams" {
    var space = StreamIdSpace.initAdvertised(1);
    defer space.deinit(test_alloc);

    // A window of 1: one stream at a time, for as long as you like.
    // (The rule this replaces turned a limit of 1 into 17 after one
    // close.)
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));
    for (0..50) |i| {
        try space.open(test_alloc, i, no_cap);
        try testing.expectEqual(@as(u64, 1), space.inUse());
        try testing.expectError(Error.LimitExceeded, space.open(test_alloc, i + 1, no_cap));
        try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));
        space.noteClosed();
        try testing.expectEqual(@as(?u64, i + 2), space.creditToAdvertise(null));
        space.raiseLimit(space.creditToAdvertise(null).?);
        try testing.expectEqual(@as(u64, i + 2), space.limit);
    }
}

test "credit: half a window at a time, or at once when the peer is out" {
    var space = StreamIdSpace.initAdvertised(8);
    defer space.deinit(test_alloc);

    // The peer uses 4 of 8 and closes 3: 3 ids of credit, less than
    // half a window, and the peer still has 4 unused. Wait.
    for (0..4) |i| try space.open(test_alloc, i, no_cap);
    for (0..3) |_| space.noteClosed();
    try testing.expectEqual(@as(u64, 11), space.target());
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));
    // A STREAMS_BLOCKED below the limit is stale. One at the limit
    // means the peer wants the credit now.
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(7));
    try testing.expectEqual(@as(?u64, 11), space.creditToAdvertise(8));

    // A fourth close makes half a window: give it.
    space.noteClosed();
    try testing.expectEqual(@as(?u64, 12), space.creditToAdvertise(null));
    space.raiseLimit(12);
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));

    // The peer uses every id it has (4..11) and one closes: one id of
    // credit, far less than half a window, but the peer is out. Give
    // it at once.
    for (4..12) |i| try space.open(test_alloc, i, no_cap);
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));
    space.noteClosed();
    try testing.expectEqual(@as(?u64, 13), space.creditToAdvertise(null));
}

test "credit: a hole holds its unit of the window" {
    var space = StreamIdSpace.initAdvertised(4);
    defer space.deinit(test_alloc);

    // The peer skips 0..2 and uses 3: all four units are taken.
    try space.open(test_alloc, 3, no_cap);
    try testing.expectEqual(@as(u64, 4), space.inUse());
    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, 4, no_cap));
    // Stream 3 closes: one unit comes back. The three holes keep theirs.
    space.noteClosed();
    try testing.expectEqual(@as(?u64, 5), space.creditToAdvertise(null));
    space.raiseLimit(5);
    try space.open(test_alloc, 4, no_cap);
    try testing.expectEqual(@as(u64, 4), space.inUse());
    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, 5, no_cap));
}

test "raiseLimit never lowers the limit and never passes the wire maximum" {
    var space = StreamIdSpace.initGranted(10);
    defer space.deinit(test_alloc);

    space.raiseLimit(5);
    try testing.expectEqual(@as(u64, 10), space.limit);
    space.raiseLimit(4097);
    try testing.expectEqual(@as(u64, 4097), space.limit);
    space.raiseLimit(std.math.maxInt(u64));
    try testing.expectEqual(max_stream_count, space.limit);

    try testing.expectEqual(max_stream_count, StreamIdSpace.initGranted(std.math.maxInt(u64)).limit);
    const wide = StreamIdSpace.initAdvertised(std.math.maxInt(u64));
    try testing.expectEqual(max_stream_count, wide.limit);
    try testing.expectEqual(max_stream_count, wide.target());
}

test "a granted space has no window of its own" {
    var space = StreamIdSpace.initGranted(3);
    defer space.deinit(test_alloc);

    for (0..3) |i| try space.open(test_alloc, i, no_cap);
    for (0..3) |_| space.noteClosed();
    // The peer decides when we get more; closing our streams does not
    // raise our own limit.
    try testing.expectEqual(@as(?u64, null), space.creditToAdvertise(null));
    try testing.expectError(Error.LimitExceeded, space.open(test_alloc, 3, no_cap));
    space.raiseLimit(6);
    try space.open(test_alloc, 3, no_cap);
}

// -- fuzz harness --------------------------------------------------------
//
// Drive a space and a NAIVE MODEL of it with the same operations, and
// require them to agree. The model remembers every index it ever saw
// in a hash map, which is exactly what the real type must not do; the
// two can only agree if the range list says the same thing.
//
// Checked after every step:
//  - `classify` agrees with the model for every index near the
//    frontier, and for every index the model knows;
//  - `open` returns what the model predicts, and changes nothing when
//    it refuses;
//  - the hole list is sorted, disjoint, non-empty ranges, all below
//    `opened`, and never touching (a touch means a missed merge);
//  - `holeCount`, `inUse`, `opened`, `closed` match the model;
//  - an advertised space keeps `live + holes <= window`, and its
//    limit never exceeds `window + closed`.

const Model = struct {
    const Seen = enum { hole, live, closed };

    seen: std.AutoHashMapUnmanaged(u64, Seen) = .empty,
    opened: u64 = 0,
    closed: u64 = 0,
    limit: u64,
    window: u64,

    fn deinit(self: *Model) void {
        self.seen.deinit(test_alloc);
    }

    fn classify(self: *const Model, index: u64) State {
        if (index >= self.opened) return .not_opened;
        return switch (self.seen.get(index).?) {
            .hole => .hole,
            .live, .closed => .used,
        };
    }

    fn holeRanges(self: *const Model) usize {
        var ranges: usize = 0;
        var in_range = false;
        var i: u64 = 0;
        while (i < self.opened) : (i += 1) {
            const is_hole = self.seen.get(i).? == .hole;
            if (is_hole and !in_range) ranges += 1;
            in_range = is_hole;
        }
        return ranges;
    }

    /// What `open` must do, without doing it.
    fn predict(self: *const Model, index: u64, cap: usize) ?Error {
        if (index >= self.limit) return Error.LimitExceeded;
        if (index < self.opened) {
            if (self.seen.get(index).? != .hole) return Error.AlreadyUsed;
            const splits = index > 0 and index + 1 < self.opened and
                self.seen.get(index - 1).? == .hole and self.seen.get(index + 1).? == .hole;
            if (splits and self.holeRanges() >= cap) return Error.TooManySkippedIds;
            return null;
        }
        if (index > self.opened and self.holeRanges() >= cap) return Error.TooManySkippedIds;
        return null;
    }

    fn open(self: *Model, index: u64) !void {
        var i = self.opened;
        while (i < index) : (i += 1) try self.seen.put(test_alloc, i, .hole);
        try self.seen.put(test_alloc, index, .live);
        if (index >= self.opened) self.opened = index + 1;
    }

    fn count(self: *const Model, what: Seen) u64 {
        var n: u64 = 0;
        var it = self.seen.valueIterator();
        while (it.next()) |v| {
            if (v.* == what) n += 1;
        }
        return n;
    }

    /// The `nth` live index in ascending order, if there are that many.
    fn nthLive(self: *const Model, nth: u64) ?u64 {
        var left = nth;
        var i: u64 = 0;
        while (i < self.opened) : (i += 1) {
            if (self.seen.get(i).? != .live) continue;
            if (left == 0) return i;
            left -= 1;
        }
        return null;
    }
};

test "fuzz: StreamIdSpace agrees with a model that remembers every id" {
    try std.testing.fuzz({}, fuzzAgainstModel, .{});
}

fn fuzzAgainstModel(_: void, smith: *std.testing.Smith) anyerror!void {
    const advertised = smith.value(bool);
    // Small numbers on purpose: collisions, full windows, and the cap
    // must all be reached within a few hundred steps.
    const initial = smith.valueRangeAtMost(u64, 0, 12);
    const cap: usize = smith.valueRangeAtMost(u8, 0, 6);

    var space = if (advertised) StreamIdSpace.initAdvertised(initial) else StreamIdSpace.initGranted(initial);
    defer space.deinit(test_alloc);
    var model: Model = .{ .limit = initial, .window = if (advertised) initial else 0 };
    defer model.deinit();

    // The model is checked in full after every step, and that check is
    // linear in the ids used so far: keep one input short.
    var steps: u32 = 0;
    while (steps < 128 and !smith.eos()) : (steps += 1) {
        switch (smith.valueRangeAtMost(u8, 0, 9)) {
            // Open: mostly at or just past the frontier, sometimes
            // below it (a hole, or a used id), sometimes far off.
            0...5 => {
                const index = switch (smith.valueRangeAtMost(u8, 0, 7)) {
                    0...3 => model.opened +| smith.valueRangeAtMost(u64, 0, 3),
                    4...6 => if (model.opened == 0) 0 else smith.valueRangeAtMost(u64, 0, model.opened - 1),
                    else => smith.value(u64),
                };
                const before_opened = space.opened;
                const before_ranges = space.holes.items.len;
                const before_holes = space.holeCount();
                const predicted = model.predict(index, cap);
                if (space.open(test_alloc, index, cap)) |_| {
                    try testing.expectEqual(@as(?Error, null), predicted);
                    try model.open(index);
                } else |err| {
                    try testing.expectEqual(predicted, @as(?Error, err));
                    try testing.expectEqual(before_opened, space.opened);
                    try testing.expectEqual(before_ranges, space.holes.items.len);
                    try testing.expectEqual(before_holes, space.holeCount());
                }
            },
            // Close one live stream.
            6, 7 => {
                const live = model.count(.live);
                if (live != 0) {
                    const index = model.nthLive(smith.valueRangeAtMost(u64, 0, live - 1)).?;
                    try model.seen.put(test_alloc, index, .closed);
                    model.closed += 1;
                    space.noteClosed();
                }
            },
            // Advertised space: give the credit the rule allows.
            // Granted space: the peer grants some amount.
            else => {
                if (advertised) {
                    const blocked: ?u64 = if (smith.value(bool)) smith.valueRangeAtMost(u64, 0, space.limit +| 1) else null;
                    if (space.creditToAdvertise(blocked)) |new_limit| {
                        try testing.expect(new_limit > space.limit);
                        try testing.expectEqual(model.window + model.closed, new_limit);
                        space.raiseLimit(new_limit);
                        model.limit = new_limit;
                    } else if (blocked == null) {
                        // No credit was given. Then either there is
                        // none, or it is less than half a window and
                        // the peer still has ids left.
                        const entitled = model.window + model.closed;
                        if (entitled > space.limit) {
                            try testing.expect(entitled - space.limit < @max(1, model.window / 2));
                            try testing.expect(space.opened < space.limit);
                        }
                    }
                } else {
                    const grant = model.limit +| smith.valueRangeAtMost(u64, 0, 4);
                    space.raiseLimit(grant);
                    model.limit = @max(model.limit, @min(grant, max_stream_count));
                    // A stale, lower grant is ignored.
                    space.raiseLimit(smith.valueRangeAtMost(u64, 0, model.limit));
                }
            },
        }

        // The two agree on everything the model knows, and just past it.
        try testing.expectEqual(model.opened, space.opened);
        try testing.expectEqual(model.closed, space.closed);
        try testing.expectEqual(model.limit, space.limit);
        var i: u64 = 0;
        while (i < model.opened + 3) : (i += 1) {
            try testing.expectEqual(model.classify(i), space.classify(i));
        }
        try testing.expectEqual(State.not_opened, space.classify(std.math.maxInt(u64)));
        try testing.expectEqual(model.count(.hole), space.holeCount());
        try testing.expectEqual(model.count(.hole) + model.count(.live), space.inUse());
        try testing.expectEqual(model.holeRanges(), space.holes.items.len);
        try testing.expect(space.holes.items.len <= cap);

        // The list is well formed.
        var previous_end: u64 = 0;
        for (space.holes.items, 0..) |r, n| {
            try testing.expect(r.offset < r.end);
            try testing.expect(r.end <= space.opened);
            // Sorted, disjoint, and not touching.
            if (n != 0) try testing.expect(r.offset > previous_end);
            previous_end = r.end;
        }
        // The highest used index is never a hole.
        if (space.opened != 0) try testing.expectEqual(State.used, space.classify(space.opened - 1));

        // The window holds.
        try testing.expect(space.opened <= space.limit);
        if (advertised) {
            try testing.expect(space.inUse() <= space.window);
            try testing.expect(space.limit <= space.window + space.closed);
            try testing.expect(space.holes.items.len <= space.window);
        }
    }
}
