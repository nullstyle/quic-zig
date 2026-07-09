//! End-to-end pins for the embedder-facing `ConnectionEvent` additions:
//! `handshake_established` (one-shot, lazily surfaced on the first
//! `pollEvent` after `handshakeDone()` latches) and `stream_opened`
//! (lossless watermark-chased emission of peer-initiated stream opens,
//! including RFC 9000 §3.2 implicit creation of lower same-type indices).

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;

const ClientCid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
const ServerCid = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xc0, 0xc9 };

fn buildContexts(
    server_tls: *boringssl.tls.Context,
    client_tls: *boringssl.tls.Context,
) !void {
    const protos = [_][]const u8{"hq-test"};
    server_tls.* = try boringssl.tls.Context.initServer(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
    try server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);
    client_tls.* = try boringssl.tls.Context.initClient(.{
        .verify = .none,
        .min_version = boringssl.raw.TLS1_3_VERSION,
        .max_version = boringssl.raw.TLS1_3_VERSION,
        .alpn = &protos,
    });
}

fn handshake(client: *quic_zig.Connection, server: *quic_zig.Connection) !void {
    var step: u32 = 0;
    while (step < 50) : (step += 1) {
        if (client.handshakeDone() and server.handshakeDone()) break;
        try client.advance();
        try server.advance();
    }
    try std.testing.expect(client.handshakeDone());
    try std.testing.expect(server.handshakeDone());
}

const Pair = struct {
    client: quic_zig.Connection,
    server: quic_zig.Connection,

    fn deinit(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
    }
};

/// Initializes `pair` in place: the two connections wire `peer` pointers
/// at their final addresses, so the caller must give the Pair its
/// permanent storage before calling (returning a Pair by value would
/// dangle those pointers).
fn establishPair(
    pair: *Pair,
    allocator: std.mem.Allocator,
    server_tls: boringssl.tls.Context,
    client_tls: boringssl.tls.Context,
) !void {
    pair.client = try quic_zig.Connection.initClient(allocator, client_tls, "localhost");
    errdefer pair.client.deinit();
    pair.server = try quic_zig.Connection.initServer(allocator, server_tls);
    errdefer pair.server.deinit();

    try pair.client.bind();
    try pair.server.bind();
    pair.client.peer = &pair.server;
    pair.server.peer = &pair.client;

    const tp: quic_zig.tls.TransportParams = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 20,
        .initial_max_stream_data_uni = 1 << 20,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
    };
    try pair.client.setTransportParams(tp);
    try pair.server.setTransportParams(tp);

    try handshake(&pair.client, &pair.server);

    try pair.client.setPeerDcid(&ServerCid);
    try pair.client.setLocalScid(&ClientCid);
    try pair.server.setPeerDcid(&ClientCid);
    try pair.server.setLocalScid(&ServerCid);
}

fn pump(pair: *Pair, iterations: u32) !void {
    var pkt: [2048]u8 = undefined;
    var now_us: u64 = 1_000_000;
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        try pair.client.tick(now_us);
        try pair.server.tick(now_us);
        if (try pair.client.poll(&pkt, now_us)) |n| {
            try pair.server.handle(pkt[0..n], null, now_us);
        }
        if (try pair.server.poll(&pkt, now_us)) |n| {
            try pair.client.handle(pkt[0..n], null, now_us);
        }
        now_us += 1_000;
    }
}

test "handshake_established surfaces exactly once per side" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var pair: Pair = undefined;
    try establishPair(&pair, allocator, server_tls, client_tls);
    defer pair.deinit();

    // First poll after completion yields the one-shot, on both roles.
    const client_ev = pair.client.pollEvent() orelse return error.MissingEvent;
    try std.testing.expectEqual(
        quic_zig.ConnectionEvent.handshake_established,
        std.meta.activeTag(client_ev),
    );
    const server_ev = pair.server.pollEvent() orelse return error.MissingEvent;
    try std.testing.expectEqual(
        quic_zig.ConnectionEvent.handshake_established,
        std.meta.activeTag(server_ev),
    );

    // Draining the remaining queues never repeats it.
    while (pair.client.pollEvent()) |ev| {
        try std.testing.expect(std.meta.activeTag(ev) != .handshake_established);
    }
    while (pair.server.pollEvent()) |ev| {
        try std.testing.expect(std.meta.activeTag(ev) != .handshake_established);
    }
}

test "stream_opened surfaces peer streams in order, including implicit opens" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var pair: Pair = undefined;
    try establishPair(&pair, allocator, server_tls, client_tls);
    defer pair.deinit();

    // Client opens bidi index 0 (id 0) and bidi index 2 (id 8) and writes
    // only on those. Receiving id 8 implicitly opens index 1 (id 4) on the
    // server (RFC 9000 §3.2), so the server must surface 0, 4, 8 — in
    // index order — even though id 4 never carried a frame. A client uni
    // stream (id 2) checks the per-type id math.
    _ = try pair.client.openBidi(0);
    _ = try pair.client.streamWrite(0, "first");
    _ = try pair.client.openBidi(8);
    _ = try pair.client.streamWrite(8, "third");
    _ = try pair.client.openUni(2);
    _ = try pair.client.streamWrite(2, "uni");

    try pump(&pair, 10);

    var opened_bidi: std.ArrayList(u64) = .empty;
    defer opened_bidi.deinit(allocator);
    var opened_uni: std.ArrayList(u64) = .empty;
    defer opened_uni.deinit(allocator);
    var saw_handshake = false;

    while (pair.server.pollEvent()) |ev| switch (ev) {
        .handshake_established => saw_handshake = true,
        .stream_opened => |info| {
            try std.testing.expectEqual(
                info.bidi,
                quic_zig.StreamType.fromId(info.stream_id).isBidi(),
            );
            if (info.bidi) {
                try opened_bidi.append(allocator, info.stream_id);
            } else {
                try opened_uni.append(allocator, info.stream_id);
            }
        },
        else => {},
    };

    try std.testing.expect(saw_handshake);
    try std.testing.expectEqualSlices(u64, &.{ 0, 4, 8 }, opened_bidi.items);
    try std.testing.expectEqualSlices(u64, &.{2}, opened_uni.items);

    // The watermark is monotonic: nothing is re-surfaced on later polls.
    try pump(&pair, 4);
    while (pair.server.pollEvent()) |ev| {
        try std.testing.expect(std.meta.activeTag(ev) != .stream_opened);
    }
}

test "stream_opened uses server-initiated ids on the client side" {
    const allocator = std.testing.allocator;

    var server_tls: boringssl.tls.Context = undefined;
    var client_tls: boringssl.tls.Context = undefined;
    try buildContexts(&server_tls, &client_tls);
    defer server_tls.deinit();
    defer client_tls.deinit();

    var pair: Pair = undefined;
    try establishPair(&pair, allocator, server_tls, client_tls);
    defer pair.deinit();

    // The mock-shim handshake counts no path bytes, so the server starts
    // anti-amplification-blocked (3x of 0). Have the client speak first —
    // as any real client does — to fund the server's send budget. This
    // also pins that the client's own outbound stream never surfaces as a
    // client-side stream_opened event.
    _ = try pair.client.openBidi(0);
    _ = try pair.client.streamWrite(0, "ping");

    // Server-initiated bidi index 0 is id 1; server uni index 0 is id 3.
    _ = try pair.server.openBidi(1);
    _ = try pair.server.streamWrite(1, "hello");
    _ = try pair.server.openUni(3);
    _ = try pair.server.streamWrite(3, "uni");

    try pump(&pair, 10);


    var opened: std.ArrayList(u64) = .empty;
    defer opened.deinit(allocator);
    while (pair.client.pollEvent()) |ev| switch (ev) {
        .stream_opened => |info| try opened.append(allocator, info.stream_id),
        else => {},
    };
    try std.testing.expectEqualSlices(u64, &.{ 1, 3 }, opened.items);
}
