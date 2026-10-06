//! `Server.adoptLoopThread`: an embedder hands a Server from one
//! thread to another at a quiescent point. The Debug tripwire
//! (`checkLoopThread`, which `feed`, `tick` and
//! `rotateSessionTicketKey` run) latches the first thread that ran the
//! Server; the handoff moves the latch. v0.29.0 had the tripwire and
//! no way to move it, which broke capnp-zig's `adoptOwnerThread` for a
//! server-side connection in Debug builds (found by capnp-zig).

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

fn tickOnThisThread(server: *quic.Server) void {
    server.tick(1_000) catch unreachable;
}

test "a Server handed to another thread at a quiescent point runs there after adoptLoopThread" {
    var server = try newServer(std.testing.allocator);
    defer server.deinit();

    // The first tick, on another thread: that thread is the loop
    // thread now.
    const t = try std.Thread.spawn(.{}, tickOnThisThread, .{&server});
    t.join();

    // The handoff: this thread takes the Server over, and its ticks
    // run (without `adoptLoopThread` the first one trips the Debug
    // tripwire).
    server.adoptLoopThread();
    try server.tick(2_000);
    try server.tick(3_000);
}
