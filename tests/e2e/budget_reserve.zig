//! Pin for 0.38.0: the memory budget keeps a receive reserve, at the
//! public wrappers, in capnp-zig's shape (2026-10-08): a server with a
//! 256 KiB budget answers one request with a 1 MiB reply while the
//! client keeps sending a small frame every millisecond. Through
//! v0.37.x the server's first write took the whole budget and the
//! client's next frame closed the connection with "excessive resource
//! use" within milliseconds; now the write stops at the writer's share
//! (the budget less the connection window), the client's frames land,
//! and the whole reply arrives, in order.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe3), .port = 7 } };
const budget: u64 = 256 * 1024;
const reply_len: usize = 1024 * 1024;

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

/// The server's parameters: the connection window is the receive
/// side's share of its budget (half), as the budget's doc asks.
fn serverParams() quic.tls.TransportParams {
    var p = common.defaultParams();
    p.initial_max_data = budget / 2;
    return p;
}

test "a 1 MiB reply under a 256 KiB budget while the client sends a frame every millisecond: no fault, the reply arrives" {
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = serverParams(),
        .max_connection_memory = budget,
    });
    defer srv.deinit();
    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = std.testing.allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();
    var now_us: u64 = 1_000;
    try handshake(&srv, &cli, &now_us);
    const sconn = srv.iterator()[0].conn;

    // The request.
    const id: u64 = 0;
    _ = try cli.conn.openBidi(id);
    _ = try cli.conn.streamWrite(id, "GET");
    try c2s(&cli, &srv, now_us);
    var rbuf: [4096]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try sconn.streamRead(id, &rbuf));

    // The reply, written as the budget allows (a short write is retried
    // on the next iteration), while the client sends a byte every
    // millisecond on the same stream and reads what arrives; the server
    // reads the client's bytes too (a reader that keeps up).
    const reply = try std.testing.allocator.alloc(u8, reply_len);
    defer std.testing.allocator.free(reply);
    for (reply, 0..) |*b, i| b.* = @truncate(i);
    var written: usize = 0;
    var received: usize = 0;
    var chatter: usize = 0;
    var next: u8 = 0;
    var cbuf: [64 * 1024]u8 = undefined;
    var step: u32 = 0;
    while (received < reply_len and step < 4_000) : (step += 1) {
        if (written < reply_len) {
            written += try sconn.streamWrite(id, reply[written..]);
            if (written == reply_len) try sconn.streamFinish(id);
        }
        // The server never holds more than its budget.
        try std.testing.expect(sconn.bytes_resident <= budget);
        _ = try cli.conn.streamWrite(id, "x");
        try c2s(&cli, &srv, now_us);
        try s2c(&srv, &cli, now_us);
        while (true) {
            const n = try sconn.streamRead(id, &rbuf);
            if (n == 0) break;
            chatter += n;
        }
        while (true) {
            const n = try cli.conn.streamRead(id, &cbuf);
            if (n == 0) break;
            for (cbuf[0..n]) |b| {
                try std.testing.expectEqual(next, b);
                next +%= 1;
            }
            received += n;
        }
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
        try std.testing.expectEqual(quic.CloseState.open, sconn.closeState());
        try std.testing.expectEqual(quic.CloseState.open, cli.conn.closeState());
    }
    try std.testing.expectEqual(reply_len, received);
    try std.testing.expectEqual(reply_len, written);
    try std.testing.expect(chatter > 0);
    try std.testing.expectEqual(sconn.residentBytesSum(), sconn.bytes_resident);
    try std.testing.expectEqual(cli.conn.residentBytesSum(), cli.conn.bytes_resident);
}
