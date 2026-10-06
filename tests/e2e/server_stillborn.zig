//! A `Server` makes no connection for a datagram of which no packet
//! opens: another server's first flight on a shared socket, or junk
//! with a long header. `feed` says `.dropped`, as it did for such a
//! datagram before v0.26.0 (when a server's first flight was shorter
//! than 1200 bytes and the Initial size gate dropped it).
//!
//! MEASURED 2026-10-05 on v0.27.0 and v0.28.1: `.accepted`, one
//! connection, gone 11 to 30 s later; qmesh-zig's dials on a shared
//! socket never saw their answers (found by the bugnest session).

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

fn newServer(allocator: std.mem.Allocator) !quic.Server {
    return quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

fn newClient(allocator: std.mem.Allocator) !quic.Client {
    return quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test certificate
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
}

const dial_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe1), .port = 7 } };
const remote_addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe2), .port = 9 } };

test "stillborn: another server's first flight makes no connection, and the control: a client's Initial does" {
    const allocator = std.testing.allocator;
    var remote = try newServer(allocator);
    defer remote.deinit();
    var local = try newServer(allocator);
    defer local.deinit();
    var cli = try newClient(allocator);
    defer cli.deinit();
    try cli.conn.advance();
    var rx: [4096]u8 = undefined;

    // Our dial's first Initial goes to the remote server (the control:
    // a client's Initial opens, and a Server takes it).
    const first = (try cli.conn.poll(&rx, 1_000)).?;
    try std.testing.expectEqual(@as(usize, 1200), first);
    try std.testing.expectEqual(quic.Server.FeedOutcome.accepted, try remote.feed(rx[0..first], dial_addr, 1_000));
    try std.testing.expectEqual(@as(usize, 1), remote.connectionCount());

    // The remote server's answer comes back on the shared socket, and
    // the embedder gives it to its own Server first.
    var answers: usize = 0;
    for (remote.iterator()) |slot| {
        while (try slot.conn.poll(&rx, 2_000)) |len| {
            answers += 1;
            try std.testing.expectEqual(quic.Server.FeedOutcome.dropped, try local.feed(rx[0..len], remote_addr, 2_000));
            try std.testing.expectEqual(@as(usize, 0), local.connectionCount());
        }
    }
    try std.testing.expect(answers >= 1);
    while (local.drainStatelessResponse()) |_| {}
    try std.testing.expectEqual(@as(usize, 0), local.statelessResponseCount());
    try std.testing.expectEqual(@as(u64, answers), local.metricsSnapshot().feeds_dropped);
}

test "stillborn: 1200 bytes of junk behind a long header make no connection" {
    const allocator = std.testing.allocator;
    var srv = try newServer(allocator);
    defer srv.deinit();

    var junk: [1200]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.random().bytes(&junk);
    // A long header: Initial, version 1, an 8-byte DCID, an 8-byte
    // SCID, no token, and the rest is the "packet".
    junk[0] = 0xc0;
    junk[1] = 0;
    junk[2] = 0;
    junk[3] = 0;
    junk[4] = 1;
    junk[5] = 8;
    junk[14] = 8;
    junk[23] = 0;
    try std.testing.expectEqual(quic.Server.FeedOutcome.dropped, try srv.feed(&junk, dial_addr, 1_000));
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), srv.routingTableSize());
}
