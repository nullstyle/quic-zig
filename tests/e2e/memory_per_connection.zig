//! What one server connection costs on the Zig heap, measured with a
//! counting allocator at the public wrappers: a `Server` with `n`
//! clients through the handshake, in memory, no sockets. The number
//! is a guard here (it must not grow past `max_bytes_per_connection`
//! without someone deciding that) and a measurement for the record
//! (`print_memory` prints the stages).
//!
//! BoringSSL's heap is not in this number: it allocates through
//! malloc, not through the Zig allocator (its SSL object, the TLS
//! buffers). http3-zig measured that part as flat over 2000
//! connections on macOS.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};

/// Set to true to print the stages (a measuring aid).
const print_memory = false;

const Counting = std.heap.DebugAllocator(.{ .enable_memory_limit = true, .safety = false });

fn runHandshake(allocator: std.mem.Allocator, srv: *quic.Server, port: u16) !void {
    const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0x33), .port = port } };
    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true, // self-signed test certificate
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();
    try cli.conn.advance();
    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    var step: u32 = 0;
    var slot_index: ?usize = null;
    while (step < 64) : (step += 1) {
        while (try cli.conn.poll(&rx, now_us)) |len| {
            _ = try srv.feed(rx[0..len], addr, now_us);
        }
        while (srv.drainStatelessResponse()) |_| {}
        if (slot_index == null and srv.iterator().len > 0) slot_index = srv.iterator().len - 1;
        if (slot_index) |i| {
            const slot = srv.iterator()[i];
            while (try slot.conn.poll(&rx, now_us)) |len| try cli.conn.handle(rx[0..len], null, now_us);
        }
        try srv.tick(now_us);
        try cli.conn.tick(now_us);
        now_us += 1_000;
        if (cli.conn.handshakeDone() and slot_index != null and srv.iterator()[slot_index.?].conn.handshakeDone()) break;
    }
    try std.testing.expect(cli.conn.handshakeDone());
    // Leave the server's connection open: the client just goes away
    // (the server keeps the connection until its idle timeout).
}

/// The upper bound this test holds for one live server connection on
/// the Zig heap, after the handshake, with nothing sent yet.
/// MEASURED 2026-10-06: 1,088,857 bytes on v0.28.1 (the Application
/// tracker's 4096 slots were 819,200 of it, the eight 16 KiB CRYPTO
/// buffers 131,072); 91,257 after the tracker grew on demand and the
/// buffers moved to the heap (`@sizeOf(Connection)` 154,800 ->
/// 23,904). The bound leaves room for a little growth, not for a
/// slab.
pub const max_bytes_per_connection: usize = 131_072;

test "memory: one live server connection on the Zig heap" {
    var counting: Counting = .{};
    defer _ = counting.deinit();
    const allocator = counting.allocator();
    const client_allocator = std.testing.allocator;

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer srv.deinit();
    const after_server = counting.total_requested_bytes;

    const n: usize = 8;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try runHandshake(client_allocator, &srv, @intCast(4000 + i));
    }
    try std.testing.expectEqual(n, srv.connectionCount());
    const after_connections = counting.total_requested_bytes;
    const per_connection = (after_connections - after_server) / n;

    if (print_memory) {
        std.debug.print("[memory] @sizeOf(Connection)={d} @sizeOf(Server.Slot)={d}\n", .{ @sizeOf(quic.Connection), @sizeOf(quic.Server.Slot) });
        std.debug.print("[memory] the Server alone: {d} bytes; {d} connections: {d} bytes; per connection: {d} bytes\n", .{ after_server, n, after_connections - after_server, per_connection });
    }
    try std.testing.expect(per_connection <= max_bytes_per_connection);
}
