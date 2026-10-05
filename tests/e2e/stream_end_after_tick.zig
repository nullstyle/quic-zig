//! Pins for the 0.28.0 stream-end repair: an application learns how a
//! stream ended — a clean FIN, or a reset with its code — whatever the
//! order of its read and `tick`.
//!
//! The defect (found by http3-zig, 2026-10-05): `tick` reclaims a stream
//! the moment its receive half ends. An end that arrives with nothing
//! left to read (a bare FIN after the last read, or a RESET_STREAM) was
//! then lost if `tick` ran before the read: a clean end and a reset gave
//! the same answers, and the reset code was gone. `runUdpClient` ran its
//! hook after `tick`, so our own loop walked into it.
//!
//! What is pinned here, at the public wrappers (`quic.Server` +
//! `quic.Client`, in memory, real TLS):
//!  - `streamRecvEnd` answers the same before and after the reclaiming
//!    `tick`, for a uni and a bidi stream, for four kinds of end;
//!  - `streamReadFin` calls a stream reset after its FIN cut, not clean;
//!  - `streamRecvState` keeps its contract: null once reclaimed;
//!  - `runUdpClient`'s hook runs before `tick`;
//!  - `quic.app.Driver` reports `.fin` / `.reset` (with the code) for a
//!    stream that a `tick` reclaimed before the Driver serviced it.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe1), .port = 7 } };

fn c2s(cli: *quic.Client, srv: *quic.Server, now_us: u64) !void {
    var rx: [4096]u8 = undefined;
    while (try cli.conn.poll(&rx, now_us)) |len| _ = try srv.feed(rx[0..len], addr, now_us);
}

fn s2c(srv: *quic.Server, cli: *quic.Client, now_us: u64) !void {
    var rx: [4096]u8 = undefined;
    for (srv.iterator()) |slot| {
        while (try slot.conn.poll(&rx, now_us)) |len| try cli.conn.handle(rx[0..len], null, now_us);
    }
}

fn handshake(srv: *quic.Server, cli: *quic.Client, now_us: *u64) !void {
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        try c2s(cli, srv, now_us.*);
        try s2c(srv, cli, now_us.*);
        try srv.tick(now_us.*);
        try cli.conn.tick(now_us.*);
        now_us.* += 1_000;
        if (cli.conn.handshakeDone() and srv.iterator().len > 0 and srv.iterator()[0].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
}

fn serverInit() !quic.Server {
    return quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

fn clientConnect() !quic.Client {
    return quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

/// How the client ends its stream after the server has read "abc".
const End = enum {
    /// A bare FIN, alone in its datagram.
    fin,
    /// RESET_STREAM(77) after the 3 bytes the server read.
    reset,
    /// A bare FIN, then RESET_STREAM(79): the reset wins.
    fin_then_reset,
    /// "xyz" + FIN that the server never reads, then RESET_STREAM(80):
    /// the reset throws the 3 unread bytes away.
    unread_then_reset,
};

const Order = enum { read_then_tick, tick_then_read };

const Seen = struct {
    end: ?quic.StreamRecvEnd,
    read: union(enum) { ok: quic.StreamReadResult, err: anyerror },
    state_null: bool,
    /// `streamRecvState(..).reset_code`, when the stream was live.
    state_reset_code: ?u64,
    was_reaped: bool,
};

/// A client stream to the server: the server reads "abc" (and, for a
/// bidi stream, answers and finishes its own half so the stream is
/// reclaimable), then the client ends the stream; the server is asked
/// how it ended either before or after the `tick` that reclaims it.
fn run(end: End, order: Order, stream_id: u64) !Seen {
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    if (stream_id & 2 != 0) {
        _ = try cli.conn.openUni(stream_id);
    } else {
        _ = try cli.conn.openBidi(stream_id);
    }
    _ = try cli.conn.streamWrite(stream_id, "abc");
    var buf: [16]u8 = undefined;
    var got: usize = 0;
    var step: u32 = 0;
    while (step < 8 and got < 3) : (step += 1) {
        try c2s(&cli, &srv, now_us);
        const r = try sconn.streamReadFin(stream_id, buf[got..]);
        try std.testing.expect(!r.fin);
        got += r.n;
        try s2c(&srv, &cli, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
    }
    try std.testing.expectEqualStrings("abc", buf[0..3]);

    // A bidi stream is reclaimed only when the server's send half is
    // done too: the server answers and finishes, the client acknowledges.
    if (stream_id & 2 == 0) {
        _ = try sconn.streamWrite(stream_id, "ok");
        try sconn.streamFinish(stream_id);
        step = 0;
        while (step < 8) : (step += 1) {
            try s2c(&srv, &cli, now_us);
            var cb: [8]u8 = undefined;
            _ = cli.conn.streamReadFin(stream_id, &cb) catch {};
            try c2s(&cli, &srv, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 30_000;
        }
    }

    // The end. Each piece goes to the server with no `tick` in between,
    // so nothing is reclaimed until the order below says so.
    switch (end) {
        .fin => {
            try cli.conn.streamFinish(stream_id);
            try c2s(&cli, &srv, now_us);
        },
        .reset => {
            try cli.conn.streamReset(stream_id, 77);
            try c2s(&cli, &srv, now_us);
        },
        .fin_then_reset => {
            try cli.conn.streamFinish(stream_id);
            try c2s(&cli, &srv, now_us);
            try cli.conn.streamReset(stream_id, 79);
            try c2s(&cli, &srv, now_us);
        },
        .unread_then_reset => {
            _ = try cli.conn.streamWrite(stream_id, "xyz");
            try cli.conn.streamFinish(stream_id);
            try c2s(&cli, &srv, now_us);
            try cli.conn.streamReset(stream_id, 80);
            try c2s(&cli, &srv, now_us);
        },
    }

    if (order == .tick_then_read) try srv.tick(now_us);

    const state = sconn.streamRecvState(stream_id);
    var seen: Seen = .{
        .end = sconn.streamRecvEnd(stream_id),
        .read = undefined,
        .state_null = state == null,
        .state_reset_code = if (state) |st| st.reset_code else null,
        .was_reaped = sconn.streamRecvWasReaped(stream_id),
    };
    if (sconn.streamReadFin(stream_id, &buf)) |r| {
        seen.read = .{ .ok = r };
    } else |e| {
        seen.read = .{ .err = e };
    }
    return seen;
}

fn expectedEnd(end: End) quic.StreamRecvEnd {
    return switch (end) {
        .fin => .{ .fin_seen = true, .reset_code = null, .final_size = 3, .read_offset = 3, .stopped = false, .arrived_in_early_data = false },
        .reset => .{ .fin_seen = false, .reset_code = 77, .final_size = 3, .read_offset = 3, .stopped = false, .arrived_in_early_data = false },
        .fin_then_reset => .{ .fin_seen = true, .reset_code = 79, .final_size = 3, .read_offset = 3, .stopped = false, .arrived_in_early_data = false },
        .unread_then_reset => .{ .fin_seen = true, .reset_code = 80, .final_size = 6, .read_offset = 3, .stopped = false, .arrived_in_early_data = false },
    };
}

test "streamRecvEnd answers the same before and after the tick that reclaims the stream" {
    for ([_]u64{ 2, 0 }) |stream_id| { // a client uni and a client bidi stream
        for (std.enums.values(End)) |end| {
            const before = try run(end, .read_then_tick, stream_id);
            const after = try run(end, .tick_then_read, stream_id);

            // The tick really reclaimed the stream: this is the path the
            // note exists for, not a no-op tick.
            try std.testing.expect(!before.was_reaped);
            try std.testing.expect(after.was_reaped);

            // The answer is the expected one, and the same in both orders.
            try std.testing.expectEqualDeep(@as(?quic.StreamRecvEnd, expectedEnd(end)), before.end);
            try std.testing.expectEqualDeep(before.end, after.end);
            try std.testing.expectEqual(end == .fin, after.end.?.isClean());
        }
    }
}

test "streamReadFin calls a stream reset after its FIN cut, with the code" {
    for ([_]u64{ 2, 0 }) |stream_id| {
        for (std.enums.values(End)) |end| {
            const seen = try run(end, .read_then_tick, stream_id);
            const r = seen.read.ok;
            try std.testing.expectEqual(@as(usize, 0), r.n);
            // `fin` only for the clean end. Before 0.28.0 the two
            // reset-after-FIN cases read `fin = true` here: a cut stream
            // passed for a complete one even with the right read order.
            try std.testing.expectEqual(end == .fin, r.fin);
            try std.testing.expectEqual(expectedEnd(end).reset_code, r.reset_code);
            // The live `streamRecvState` carries the same code.
            try std.testing.expect(!seen.state_null);
            try std.testing.expectEqual(expectedEnd(end).reset_code, seen.state_reset_code);
        }
    }
}

test "after the reclaiming tick: reads say gone, streamRecvState stays null" {
    // The null-once-reclaimed contract of `streamRecvState` is relied on
    // as a liveness test (qmsg, quic.app trackStream); the repair answers
    // through `streamRecvEnd` instead and must leave it unchanged.
    for ([_]u64{ 2, 0 }) |stream_id| {
        for (std.enums.values(End)) |end| {
            const seen = try run(end, .tick_then_read, stream_id);
            try std.testing.expect(seen.state_null);
            try std.testing.expectEqual(@as(anyerror, error.StreamNotFound), seen.read.err);
        }
    }
}

// -- runUdpClient: the hook runs before `tick` --------------------------

const HookSaw = struct {
    calls: u32 = 0,
    read: ?quic.StreamReadResult = null,
    read_err: ?anyerror = null,
    stream_id: u64 = 0,

    fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        _ = now_us;
        const self: *HookSaw = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        var buf: [16]u8 = undefined;
        // Deliberately NOT `streamRecvEnd`: a hook that only reads must
        // see the end, which is what the order protects.
        if (client.conn.streamReadFin(self.stream_id, &buf)) |r| {
            self.read = r;
        } else |e| {
            self.read_err = e;
        }
    }
};

test "runUdpClient: the hook sees a bare FIN before tick reclaims the stream" {
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    // The server opens a uni stream and sends "abc"; the client reads it.
    const sid = (try sconn.openNextUni()).id;
    _ = try sconn.streamWrite(sid, "abc");
    var buf: [16]u8 = undefined;
    var got: usize = 0;
    var step: u32 = 0;
    while (step < 16) : (step += 1) {
        try s2c(&srv, &cli, now_us);
        if (got < 3) got += (cli.conn.streamReadFin(sid, buf[got..]) catch |e| switch (e) {
            error.StreamNotFound => quic.StreamReadResult{ .n = 0, .fin = false },
            else => return e,
        }).n;
        try c2s(&cli, &srv, now_us);
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 30_000;
    }
    try std.testing.expectEqualStrings("abc", buf[0..3]);

    // Then the bare FIN, alone in its datagram, handled the way the loop
    // handles ingress; then the loop's iteration tail.
    try sconn.streamFinish(sid);
    try s2c(&srv, &cli, now_us);
    var saw: HookSaw = .{ .stream_id = sid };
    try quic.transport.udp_client.finishIteration(&cli, .{
        .target = "127.0.0.1:4433",
        .io = undefined, // not touched by the iteration tail
        .on_iteration = HookSaw.onIteration,
        .on_iteration_ctx = &saw,
    }, now_us);

    try std.testing.expectEqual(@as(u32, 1), saw.calls);
    // Before 0.28.0 the hook ran after `tick` and got StreamNotFound here.
    try std.testing.expectEqual(@as(?anyerror, null), saw.read_err);
    try std.testing.expectEqual(true, saw.read.?.fin);
    // And the tick did run, after the hook: the stream is reclaimed now.
    try std.testing.expect(cli.conn.stream(sid) == null);
}

const CloseSaw = struct {
    calls: u32 = 0,
    saw_closed: bool = false,

    fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        _ = now_us;
        const self: *CloseSaw = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        if (client.conn.isClosed()) self.saw_closed = true;
    }
};

test "runUdpClient: a close that tick causes still reaches the hook" {
    // With the hook before `tick`, a close that `tick` itself causes (an
    // idle timeout here) would never reach the hook: the loop returns at
    // the top of the next iteration once the connection is closed. The
    // iteration tail runs the hook once more after such a tick.
    var srv = try serverInit();
    defer srv.deinit();
    var cli = try clientConnect();
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);

    var saw: CloseSaw = .{};
    const opts: quic.transport.RunUdpClientOptions = .{
        .target = "127.0.0.1:4433",
        .io = undefined, // not touched by the iteration tail
        .on_iteration = CloseSaw.onIteration,
        .on_iteration_ctx = &saw,
    };
    // An ordinary iteration: one hook call, still open.
    try quic.transport.udp_client.finishIteration(&cli, opts, now_us);
    try std.testing.expectEqual(@as(u32, 1), saw.calls);
    try std.testing.expect(!saw.saw_closed);

    // Past the 30 s idle timeout with no traffic: this tick closes it.
    now_us += 31 * std.time.us_per_s;
    try quic.transport.udp_client.finishIteration(&cli, opts, now_us);
    try std.testing.expect(cli.conn.isClosed());
    try std.testing.expectEqual(@as(u32, 3), saw.calls);
    try std.testing.expect(saw.saw_closed);
}

// -- quic.app: a stream reclaimed before the Driver serviced it ----------

const EndApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;

    ends: u32 = 0,
    last: ?quic.app.StreamEnd = null,
    last_code: ?u64 = null,

    fn onStreamData(_: *EndApp, _: *D.Session, _: *D.StreamEntry, _: []const u8) anyerror!void {}

    fn onStreamEnd(app: *EndApp, session: *D.Session, entry: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        app.ends += 1;
        app.last = end;
        // The documented way to get the code: it answers inside the hook
        // even for a stream the connection has already reclaimed.
        app.last_code = if (session.conn.streamRecvEnd(entry.id)) |e| e.reset_code else null;
    }
};

const D = quic.app.Driver(EndApp);

test "quic.app: a stream reclaimed by tick before service ends as .fin or .reset, not .reaped" {
    // `.fin`, `.reset`, and a FIN followed by a reset — which must map to
    // `.reset`: the reset threw bytes away, so the stream is cut.
    for ([_]enum { fin, reset, fin_then_reset }{ .fin, .reset, .fin_then_reset }) |kind| {
        // The Driver is declared first so it outlives the Server: the
        // Server's teardown fires the Driver's will-close hook.
        var app: EndApp = .{};
        var driver = try D.init(.{
            .allocator = std.testing.allocator,
            .app = &app,
            .hooks = .{ .on_stream_data = EndApp.onStreamData, .on_stream_end = EndApp.onStreamEnd },
        });
        defer driver.deinit();
        var srv = try serverInit();
        defer srv.deinit();
        driver.attach(&srv);
        var cli = try clientConnect();
        defer cli.deinit();
        var now_us: u64 = 1_000;
        try handshake(&srv, &cli, &now_us);

        // The client sends "abc" on a uni stream; the Driver reads it all.
        const sid = (try cli.conn.openNextUni()).id;
        _ = try cli.conn.streamWrite(sid, "abc");
        var step: u32 = 0;
        while (step < 4) : (step += 1) {
            try c2s(&cli, &srv, now_us);
            try driver.service(&srv);
            try s2c(&srv, &cli, now_us);
            try srv.tick(now_us);
            try cli.conn.tick(now_us);
            now_us += 1_000;
        }
        try std.testing.expectEqual(@as(u32, 0), app.ends);

        // The end arrives, and the server ticks BEFORE the Driver runs:
        // the stream is reclaimed first.
        switch (kind) {
            .fin => try cli.conn.streamFinish(sid),
            .reset => try cli.conn.streamReset(sid, 77),
            .fin_then_reset => {
                try cli.conn.streamFinish(sid);
                try c2s(&cli, &srv, now_us);
                try cli.conn.streamReset(sid, 79);
            },
        }
        try c2s(&cli, &srv, now_us);
        try srv.tick(now_us);
        try std.testing.expect(srv.iterator()[0].conn.stream(sid) == null);
        try driver.service(&srv);

        try std.testing.expectEqual(@as(u32, 1), app.ends);
        const want: quic.app.StreamEnd = if (kind == .fin) .fin else .reset;
        try std.testing.expectEqual(want, app.last.?);
        const want_code: ?u64 = switch (kind) {
            .fin => null,
            .reset => 77,
            .fin_then_reset => 79,
        };
        try std.testing.expectEqual(want_code, app.last_code);
    }
}
