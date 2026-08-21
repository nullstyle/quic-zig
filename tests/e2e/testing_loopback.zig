//! End-to-end pin for `quic.testing.Loopback` — the shipped in-memory
//! harness downstream embedders use for their own integration tests.
//! This file doubles as the usage example: a real `Server`/`Client`
//! pair, a `quic.app.Driver` echo application, handshake + stream
//! exchange driven entirely through the `Loopback` API.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const D = quic.app.Driver(EchoApp);

const EchoApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;

    fn onStreamData(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        try s.outbox.push(s.conn, e.id, chunk);
    }

    fn onStreamEnd(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        if (end == .fin) try s.outbox.finish(s.conn, e.id);
    }
};

test "Loopback drives a full echo exchange in memory" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var app: EchoApp = .{};
    var driver = try D.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = EchoApp.onStreamData,
            .on_stream_end = EchoApp.onStreamEnd,
        },
        .max_tracked_streams = common.defaultParams().initial_max_streams_bidi,
    });
    defer driver.deinit();
    try std.testing.expect(driver.streamsServiced());

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .on_connection_will_close = D.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    try lb.handshake(&driver);
    try std.testing.expect(cli.conn.handshakeDone());

    // Echo 32 KiB through a bidi stream.
    const total: usize = 32 * 1024;
    const payload = try allocator.alloc(u8, total);
    defer allocator.free(payload);
    @memset(payload, 0x5a);

    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, payload);
    try cli.conn.streamFinish(stream.id);

    var echo: std.ArrayListUnmanaged(u8) = .empty;
    defer echo.deinit(allocator);

    // Drive until the echoed stream is terminal and fully read.
    var steps: usize = 0;
    while (steps < 50_000) : (steps += 1) {
        var rbuf: [4096]u8 = undefined;
        const n = lb.client.conn.streamRead(stream.id, &rbuf) catch |err| switch (err) {
            error.StreamNotFound => 0,
            else => return err,
        };
        if (n > 0) try echo.appendSlice(allocator, rbuf[0..n]);
        const st = lb.client.conn.streamRecvState(stream.id);
        const done = (st == null or st.?.terminal) and echo.items.len == total;
        if (done) break;
        try lb.step(&driver);
    }

    try std.testing.expectEqualSlices(u8, payload, echo.items);

    // Teardown through the loop: close, fast-forward the clock past
    // draining, reap — the Driver session must free via will-close.
    lb.client.conn.close(false, 0, "done");
    var td: usize = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try lb.step(&driver);
        lb.now_us += 10_000;
        try srv.tick(lb.now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}

var drive_target_us: u64 = 0;

fn untilTarget(lb: *quic.testing.Loopback) bool {
    return lb.now_us >= drive_target_us;
}

fn untilNever(lb: *quic.testing.Loopback) bool {
    _ = lb;
    return false;
}

test "Loopback: NullDriver handshake, drive() predicate/budget, sub-ms step_us" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    var lb = try quic.testing.Loopback.init(.{
        .allocator = allocator,
        .server = &srv,
        .client = &cli,
    });
    defer lb.deinit();

    // A datagram-less, stream-less embedder needs no application
    // layer: the NullDriver pumps the handshake to completion.
    var nd: quic.testing.NullDriver = .{};
    try lb.handshake(&nd);
    try std.testing.expect(cli.conn.handshakeDone());

    // drive() with a sub-millisecond step: the clock must advance by
    // exactly step_us net per step (this used to underflow u64 and
    // crash for any step_us < 1_000). Ten 250 µs steps reach a target
    // 2.5 ms out, landing on it exactly.
    drive_target_us = lb.now_us + 2_500;
    try lb.drive(&nd, .{ .until = untilTarget, .step_us = 250 });
    try std.testing.expectEqual(drive_target_us, lb.now_us);

    // A predicate that never answers burns the whole budget and says so.
    try std.testing.expectError(
        error.DriveBudgetExhausted,
        lb.drive(&nd, .{ .until = untilNever, .budget_steps = 3 }),
    );

    // Teardown: no Driver sessions to free here (no will-close hook
    // was registered) — close and let the deinits reclaim the rest.
    lb.client.conn.close(false, 0, "done");
    var td: usize = 0;
    while (td < 400 and srv.iterator().len > 0) : (td += 1) {
        try lb.step(&nd);
        lb.now_us += 10_000;
        try srv.tick(lb.now_us);
        _ = srv.reap();
    }
    try std.testing.expectEqual(@as(usize, 0), srv.iterator().len);
}
