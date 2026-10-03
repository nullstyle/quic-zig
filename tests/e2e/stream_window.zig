//! End-to-end pins for the stream limit as a WINDOW (RFC 9000 §4.6):
//! a peer may have `initial_max_streams_*` streams open at once, and
//! gets one id back for each stream that is fully closed.
//!
//!  - the number of live peer streams never passes the window, in
//!    either direction, for either stream type, while a peer that opens
//!    streams as fast as it may still fills the window;
//!  - one connection completes many more streams than the window holds;
//!  - a lost MAX_STREAMS frame does not stall the connection (§13.3).
//!
//! A real `Server` / `Client` pair over `quic.testing.Loopback`. The
//! two `Connection`s are driven directly, with no application layer,
//! so the counters asserted here are the connection's own.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const Side = enum { client, server };

/// The largest `Options.window` a run can be given (scratch for the
/// live stream ids of one type).
const max_window = 1024;

const Options = struct {
    /// `initial_max_streams_bidi` and `_uni` of the ANSWERING side: how
    /// many streams of each type the opening side may have open at once.
    window: u64,
    /// Streams of each type the opening side completes.
    streams: u64,
    /// Which endpoint opens the streams. The other one answers.
    opener: Side,
    /// Lose the first copy of every MAX_STREAMS frame the answering
    /// side sends.
    drop_each_credit_once: bool = false,
    /// The run fails when it needs more loop iterations than this.
    budget_steps: usize,
};

const Result = struct {
    /// Most streams of the opener that were live on the answering side
    /// at one moment.
    peak_bidi: usize = 0,
    peak_uni: usize = 0,
    /// Loop iterations in which the opener was refused a new stream.
    blocked_steps: usize = 0,
    credits_dropped: usize = 0,
    steps: usize = 0,
};

const Run = struct {
    o: Options,
    loop: *quic.testing.Loopback,
    opener: *quic.Connection,
    answerer: *quic.Connection,
    result: Result = .{},
    /// Highest MAX_STREAMS value already lost once, per stream type.
    dropped_bidi: u64 = 0,
    dropped_uni: u64 = 0,

    fn openerOwns(self: *const Run, id: u64) bool {
        const server_initiated = (id & 1) == 1;
        return server_initiated == (self.o.opener == .server);
    }

    /// Streams of the opener that have a live `Stream` on `conn`.
    fn collect(self: *const Run, conn: *quic.Connection, bidi: bool, out: []u64) usize {
        var n: usize = 0;
        var it = conn.streams.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            if (!self.openerOwns(id)) continue;
            if (((id & 2) == 0) != bidi) continue;
            if (n < out.len) out[n] = id;
            n += 1;
        }
        return n;
    }

    /// The window holds on the answering side, right now.
    fn checkWindow(self: *Run) !void {
        var scratch: [1]u64 = undefined;
        inline for (.{ true, false }) |bidi| {
            const live = self.collect(self.answerer, bidi, &scratch);
            const ids = if (bidi) &self.answerer.peer_bidi_ids else &self.answerer.peer_uni_ids;
            const peak = if (bidi) &self.result.peak_bidi else &self.result.peak_uni;
            peak.* = @max(peak.*, live);
            if (live > self.o.window or
                ids.inUse() > self.o.window or
                ids.limit > ids.window + ids.closed)
            {
                std.debug.print(
                    "step {d}, bidi={}: {d} live peer streams, {d} in use, limit {d}, closed {d}; window {d}\n",
                    .{ self.result.steps, bidi, live, ids.inUse(), ids.limit, ids.closed, self.o.window },
                );
                return error.StreamWindowExceeded;
            }
        }
    }

    /// The opening side: a whole request on every stream the peer
    /// allows, then read whatever came back.
    fn openAndRead(self: *Run) !void {
        var blocked = false;
        while (self.opener.local_bidi_ids.opened < self.o.streams) {
            const s = self.opener.openNextBidi() catch |err| switch (err) {
                error.StreamLimitExceeded => {
                    blocked = true;
                    break;
                },
                else => return err,
            };
            _ = try self.opener.streamWrite(s.id, "ping");
            try self.opener.streamFinish(s.id);
        }
        while (self.opener.local_uni_ids.opened < self.o.streams) {
            const s = self.opener.openNextUni() catch |err| switch (err) {
                error.StreamLimitExceeded => {
                    blocked = true;
                    break;
                },
                else => return err,
            };
            _ = try self.opener.streamWrite(s.id, "note");
            try self.opener.streamFinish(s.id);
        }
        if (blocked) self.result.blocked_steps += 1;

        var ids: [max_window]u64 = undefined;
        const n = @min(self.collect(self.opener, true, &ids), ids.len);
        var buf: [64]u8 = undefined;
        for (ids[0..n]) |id| {
            while (try self.opener.streamRead(id, &buf) != 0) {}
        }
    }

    /// The answering side: read every stream to its end, and answer a
    /// bidirectional one when its request has ended.
    fn answer(self: *Run) !void {
        var ids: [max_window]u64 = undefined;
        var buf: [64]u8 = undefined;
        inline for (.{ true, false }) |bidi| {
            const n = @min(self.collect(self.answerer, bidi, &ids), ids.len);
            for (ids[0..n]) |id| {
                while (try self.answerer.streamRead(id, &buf) != 0) {}
                const st = self.answerer.streamRecvState(id) orelse continue;
                if (!bidi or !st.terminal) continue;
                if (self.answerer.stream(id).?.send.fin_marked) continue;
                _ = try self.answerer.streamWrite(id, "pong");
                try self.answerer.streamFinish(id);
            }
        }
    }

    fn deliver(self: *Run, to: *quic.Connection, bytes: []u8) !void {
        if (to == self.loop.client.conn) {
            try to.handle(bytes, null, self.loop.now_us);
        } else {
            _ = try self.loop.server.feed(bytes, quic.testing.loopback_addr, self.loop.now_us);
        }
    }

    fn pump(self: *Run, from: *quic.Connection, to: *quic.Connection) !void {
        while (true) {
            const bidi_before = from.pending_frames.max_streams_bidi;
            const uni_before = from.pending_frames.max_streams_uni;
            const len = (try from.poll(self.loop.rx, self.loop.now_us)) orelse break;
            if (self.o.drop_each_credit_once and from == self.answerer) {
                // A pending value that this poll cleared went out in this
                // datagram (one MAX_STREAMS frame per packet at most).
                var lose = false;
                if (bidi_before) |v| {
                    if (from.pending_frames.max_streams_bidi == null and v > self.dropped_bidi) {
                        self.dropped_bidi = v;
                        lose = true;
                    }
                }
                if (uni_before) |v| {
                    if (from.pending_frames.max_streams_uni == null and v > self.dropped_uni) {
                        self.dropped_uni = v;
                        lose = true;
                    }
                }
                if (lose) {
                    self.result.credits_dropped += 1;
                    continue;
                }
            }
            try self.deliver(to, self.loop.rx[0..len]);
        }
    }

    fn done(self: *const Run) bool {
        const n = self.o.streams;
        return self.opener.local_bidi_ids.closed == n and
            self.opener.local_uni_ids.closed == n and
            self.answerer.peer_bidi_ids.closed == n and
            self.answerer.peer_uni_ids.closed == n;
    }

    fn drive(self: *Run) !void {
        while (!self.done()) : (self.result.steps += 1) {
            if (self.result.steps == self.o.budget_steps) {
                std.debug.print(
                    "stalled: opener closed {d} bidi / {d} uni of {d}; answerer limit {d} / {d}, closed {d} / {d}\n",
                    .{
                        self.opener.local_bidi_ids.closed, self.opener.local_uni_ids.closed, self.o.streams,
                        self.answerer.peer_bidi_ids.limit, self.answerer.peer_uni_ids.limit, self.answerer.peer_bidi_ids.closed,
                        self.answerer.peer_uni_ids.closed,
                    },
                );
                return error.StreamWindowStalled;
            }
            try self.openAndRead();
            try self.pump(self.opener, self.answerer);
            // The most streams are live here: new ones have arrived and
            // `tick` has not reaped the finished ones yet.
            try self.checkWindow();
            try self.answer();
            try self.pump(self.answerer, self.opener);
            try self.loop.server.tick(self.loop.now_us);
            try self.loop.client.conn.tick(self.loop.now_us);
            try self.checkWindow();
            self.loop.now_us += 1_000;
        }
    }
};

fn runWindow(o: Options) !Result {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"stream-window"};
    var windowed = common.defaultParams();
    windowed.initial_max_streams_bidi = o.window;
    windowed.initial_max_streams_uni = o.window;
    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = if (o.opener == .client) windowed else common.defaultParams(),
    });
    defer server.deinit();
    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = if (o.opener == .server) windowed else common.defaultParams(),
        .insecure_skip_verify = true,
    });
    defer client.deinit();
    var loop = try quic.testing.Loopback.init(.{ .allocator = allocator, .server = &server, .client = &client });
    defer loop.deinit();
    try loop.handshake(&quic.testing.NullDriver{});

    const server_conn = server.iterator()[0].conn;
    var run: Run = .{
        .o = o,
        .loop = &loop,
        .opener = if (o.opener == .client) client.conn else server_conn,
        .answerer = if (o.opener == .client) server_conn else client.conn,
    };
    try run.drive();

    // Nothing was refused, reset, or closed on the way.
    try std.testing.expect(client.conn.closeEvent() == null);
    try std.testing.expect(server_conn.closeEvent() == null);
    try std.testing.expectEqual(@as(usize, 0), run.opener.streams.count());
    try std.testing.expectEqual(@as(usize, 0), run.answerer.streams.count());
    return run.result;
}

test "stream window: live peer streams never pass the window, and the peer can fill it" {
    // Many windows' worth of streams of each type through windows of 1,
    // 2, 16 and 100, in both directions. The opener is greedy: it opens
    // a stream whenever it is allowed to. A credit rule that gives more
    // than `window + closed` (the old rule doubled the limit) fails the
    // window check; one that gives less, or never gives it, stalls.
    for ([_]u64{ 1, 2, 16, 100 }) |window| {
        const streams = @max(200, 6 * window);
        for ([_]Side{ .client, .server }) |opener| {
            const r = try runWindow(.{
                .window = window,
                .streams = streams,
                .opener = opener,
                // Measured: 3 iterations per stream at a window of 1.
                .budget_steps = @intCast(10 * streams),
            });
            try std.testing.expectEqual(@as(usize, @intCast(window)), r.peak_bidi);
            try std.testing.expectEqual(@as(usize, @intCast(window)), r.peak_uni);
            // The limit is what held the opener back.
            try std.testing.expect(r.blocked_steps > 0);
        }
    }
}

test "stream window: the default window of 1000 holds, and credit does not wait behind the reap batch" {
    // `tick` reaps at most 128 streams in one pass, and with ids to
    // spare the credit goes out half a window (500) at a time. A
    // credit that waited for the wrong one of those would stall here.
    // The peak is not checked for equality: a thousand requests do not
    // arrive in one flight, so the first are closed before the last
    // arrive.
    const r = try runWindow(.{
        .window = 1000,
        .streams = 2_500,
        .opener = .client,
        // Measured: 47 iterations for 3,000 streams.
        .budget_steps = 500,
    });
    try std.testing.expect(r.peak_bidi <= 1000 and r.peak_bidi > 128);
    try std.testing.expect(r.peak_uni <= 1000 and r.peak_uni > 128);
    try std.testing.expect(r.blocked_steps > 0);
}

test "stream window: every MAX_STREAMS frame is lost once and the connection still finishes" {
    // The opener is blocked on stream credit again and again, and the
    // first copy of every credit frame is lost. Nothing but the resend
    // (RFC 9000 §13.3) can unblock it: the answering side already
    // raised its limit, so a STREAMS_BLOCKED from the opener asks for
    // nothing new. At a window of 1 every stream needs its own credit
    // frame, so 2,000 streams of each type lose about 4,000 frames.
    const cases = [_]struct { window: u64, streams: u64 }{
        .{ .window = 1, .streams = 2_000 },
        .{ .window = 16, .streams = 600 },
    };
    for (cases) |case| {
        const r = try runWindow(.{
            .window = case.window,
            .streams = case.streams,
            .opener = .client,
            .drop_each_credit_once = true,
            // Measured: 31 iterations per stream at a window of 1 (the
            // loss is found by the probe timer).
            .budget_steps = @intCast(100 * case.streams),
        });
        try std.testing.expect(r.credits_dropped >= 2 * (case.streams / case.window - 1));
        try std.testing.expect(r.peak_bidi <= case.window);
        try std.testing.expect(r.peak_uni <= case.window);
    }
}
