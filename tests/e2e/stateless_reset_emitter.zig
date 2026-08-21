//! RFC 9000 §10.3 stateless-reset EMISSION pins. Two layers:
//!
//!  1. Wire-shape and policy tests against `Server.feed` with crafted
//!     unroutable short-header datagrams: spec-shaped packets (first
//!     byte 0b01xxxxxx, ≥ 21 bytes, token tail = the same HMAC the
//!     server commits to when issuing CIDs), the smaller-than-trigger
//!     loop rule (§10.3.3, including the shrink-to-death property when
//!     a reset is fed back), the 22-byte trigger floor, the
//!     key-required and fixed-bit gates, the per-source rate limit,
//!     and the `unroutable_dcid` observation event that fires whether
//!     or not a reset ships.
//!
//!  2. The death certificate end-to-end: a real client handshakes
//!     against server #1 (which now advertises the handshake-SCID
//!     reset token via the §18.2 transport parameter), a key-sharing
//!     server #2 with no connection state answers the client's next
//!     datagram with a stateless reset, and the client's connection
//!     detects it and enters draining with `CloseSource.stateless_reset`
//!     — instead of grinding through its idle timeout.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const reset_key: quic.conn.stateless_reset.Key = @splat(0x5c);

const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = .{ 10, 0, 0, 7 }, .port = 4433 } };

fn testServer(allocator: std.mem.Allocator, config_mut: anytype) !quic.Server {
    const protos = [_][]const u8{"hq-test"};
    var config: quic.Server.Config = .{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
        .stateless_reset_key = reset_key,
    };
    config_mut(&config);
    return quic.Server.init(config);
}

fn noConfigChange(_: *quic.Server.Config) void {}

/// A crafted unroutable short-header datagram: fixed bit set, a
/// distinctive DCID at the server's CID length, deterministic filler.
fn craftShortHeader(buf: []u8, cid_len: usize) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    buf[0] = 0x4a; // 0b01001010: short-header form + fixed bit
    for (buf[1 .. 1 + cid_len], 0..) |*b, i| b.* = @intCast(0xc0 + i);
}

test "emitter: unroutable short-header datagram earns a spec-shaped reset" {
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, noConfigChange);
    defer srv.deinit();
    const cid_len: usize = srv.local_cid_len;

    var dgram: [50]u8 = undefined;
    craftShortHeader(&dgram, cid_len);
    const outcome = try srv.feed(&dgram, addr, 1_000);
    try std.testing.expectEqual(quic.Server.FeedOutcome.stateless_reset_sent, outcome);

    const entry = srv.drainStatelessResponse() orelse return error.ResetMissing;
    try std.testing.expectEqual(quic.Server.StatelessResponseKind.stateless_reset, entry.kind);
    // §10.3.3: strictly smaller than the trigger; policy floor 41 for
    // large triggers, capped at trigger-1.
    try std.testing.expect(entry.len < dgram.len);
    try std.testing.expect(entry.len >= 41);
    // First byte: short-header form (0x80 clear) + fixed bit (0x40).
    try std.testing.expect(entry.bytes[0] & 0x80 == 0);
    try std.testing.expect(entry.bytes[0] & 0x40 != 0);
    // The token tail is the committed HMAC for the addressed DCID —
    // the exact bytes a peer holding the CID's token can match.
    const expect_token = try quic.conn.stateless_reset.derive(&reset_key, dgram[1 .. 1 + cid_len]);
    try std.testing.expectEqualSlices(
        u8,
        &expect_token,
        entry.bytes[entry.len - 16 .. entry.len],
    );
    try std.testing.expect(srv.drainStatelessResponse() == null);
}

test "emitter: 22-byte trigger earns a 21-byte reset; 21-byte trigger earns nothing" {
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, noConfigChange);
    defer srv.deinit();
    const cid_len: usize = srv.local_cid_len;

    var small: [22]u8 = undefined;
    craftShortHeader(&small, cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.stateless_reset_sent,
        try srv.feed(&small, addr, 1_000),
    );
    const entry = srv.drainStatelessResponse() orelse return error.ResetMissing;
    try std.testing.expectEqual(@as(usize, 21), entry.len);

    var too_small: [21]u8 = undefined;
    craftShortHeader(&too_small, cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.dropped,
        try srv.feed(&too_small, addr, 2_000),
    );
    try std.testing.expect(srv.drainStatelessResponse() == null);
}

test "emitter: no key, no fixed bit, or truncated DCID means no reset" {
    const allocator = std.testing.allocator;

    // Without a stateless_reset_key nothing can be derived: drop.
    var keyless = try testServer(allocator, struct {
        fn f(config: *quic.Server.Config) void {
            config.stateless_reset_key = null;
        }
    }.f);
    defer keyless.deinit();
    var dgram: [50]u8 = undefined;
    craftShortHeader(&dgram, keyless.local_cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.dropped,
        try keyless.feed(&dgram, addr, 1_000),
    );
    try std.testing.expect(keyless.drainStatelessResponse() == null);

    var srv = try testServer(allocator, noConfigChange);
    defer srv.deinit();
    // Fixed bit clear: not a valid v1 packet shape — plain drop.
    var no_fixed: [50]u8 = undefined;
    craftShortHeader(&no_fixed, srv.local_cid_len);
    no_fixed[0] = 0x0a;
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.dropped,
        try srv.feed(&no_fixed, addr, 1_000),
    );
    // Shorter than 1 + cid_len: no complete DCID to derive from.
    var stub: [6]u8 = undefined;
    craftShortHeader(&stub, 4);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.dropped,
        try srv.feed(&stub, addr, 2_000),
    );
    try std.testing.expect(srv.drainStatelessResponse() == null);
}

test "emitter: per-source rate limit suppresses the third reset in a window" {
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, struct {
        fn f(config: *quic.Server.Config) void {
            config.stateless_reset_source_rate_limit = .{ .limit = 2 };
        }
    }.f);
    defer srv.deinit();

    var dgram: [50]u8 = undefined;
    craftShortHeader(&dgram, srv.local_cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.stateless_reset_sent,
        try srv.feed(&dgram, addr, 1_000),
    );
    craftShortHeader(&dgram, srv.local_cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.stateless_reset_sent,
        try srv.feed(&dgram, addr, 2_000),
    );
    craftShortHeader(&dgram, srv.local_cid_len);
    try std.testing.expectEqual(
        quic.Server.FeedOutcome.dropped,
        try srv.feed(&dgram, addr, 3_000),
    );

    const metrics = srv.metricsSnapshot();
    try std.testing.expectEqual(@as(u64, 2), metrics.feeds_stateless_reset);
    try std.testing.expectEqual(@as(u64, 1), metrics.feeds_reset_rate_limited);
}

test "emitter: feeding resets back shrinks them to death (loop rule)" {
    const allocator = std.testing.allocator;
    var srv = try testServer(allocator, struct {
        fn f(config: *quic.Server.Config) void {
            // The loop-shrink walk needs more budget than the
            // default per-source cap.
            config.stateless_reset_source_rate_limit = .disabled;
        }
    }.f);
    defer srv.deinit();

    // Start from a large unroutable datagram and keep feeding the
    // server its own reset. §10.3.3's smaller-than-trigger rule must
    // strictly shrink each round until the trigger is too small to
    // answer — a reset-vs-reset exchange between two servers dies
    // instead of looping forever.
    var buf: [128]u8 = undefined;
    craftShortHeader(&buf, srv.local_cid_len);
    var len: usize = buf.len;
    var rounds: usize = 0;
    var now_us: u64 = 1_000;
    while (rounds < 200) : (rounds += 1) {
        now_us += 1_000;
        const outcome = try srv.feed(buf[0..len], addr, now_us);
        if (outcome == .dropped) break;
        try std.testing.expectEqual(quic.Server.FeedOutcome.stateless_reset_sent, outcome);
        const entry = srv.drainStatelessResponse() orelse return error.ResetMissing;
        try std.testing.expect(entry.len < len);
        @memcpy(buf[0..entry.len], entry.slice());
        len = entry.len;
    }
    try std.testing.expect(rounds < 200); // terminated, never looped
    try std.testing.expect(len <= 21 or len < 1 + @as(usize, srv.local_cid_len));
}

const LogCapture = struct {
    var events: [8]struct { dcid: [20]u8, dcid_len: u8, reset_queued: bool } = undefined;
    var count: usize = 0;

    fn callback(_: ?*anyopaque, event: quic.Server.LogEvent) void {
        switch (event) {
            .unroutable_dcid => |e| {
                if (count < events.len) {
                    events[count] = .{
                        .dcid = e.dcid,
                        .dcid_len = e.dcid_len,
                        .reset_queued = e.reset_queued,
                    };
                    count += 1;
                }
            },
            else => {},
        }
    }
};

test "emitter: unroutable_dcid observation fires with and without a reset" {
    const allocator = std.testing.allocator;
    LogCapture.count = 0;
    var srv = try testServer(allocator, struct {
        fn f(config: *quic.Server.Config) void {
            config.stateless_reset_source_rate_limit = .{ .limit = 1 };
            config.log_callback = LogCapture.callback;
        }
    }.f);
    defer srv.deinit();
    const cid_len: usize = srv.local_cid_len;

    var dgram: [50]u8 = undefined;
    craftShortHeader(&dgram, cid_len);
    _ = try srv.feed(&dgram, addr, 1_000); // reset ships
    craftShortHeader(&dgram, cid_len);
    _ = try srv.feed(&dgram, addr, 2_000); // rate-limited: observation only

    try std.testing.expectEqual(@as(usize, 2), LogCapture.count);
    try std.testing.expect(LogCapture.events[0].reset_queued);
    try std.testing.expect(!LogCapture.events[1].reset_queued);
    for (LogCapture.events[0..2]) |ev| {
        try std.testing.expectEqual(@as(u8, @intCast(cid_len)), ev.dcid_len);
        try std.testing.expectEqualSlices(u8, dgram[1 .. 1 + cid_len], ev.dcid[0..cid_len]);
    }
}

test "death certificate: a key-sharing stateless server resets a live client" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var srv1 = try testServer(allocator, noConfigChange);
    defer srv1.deinit();

    var cli = try quic.Client.connect(.{
        .insecure_skip_verify = true,
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.defaultParams(),
    });
    defer cli.deinit();

    // Handshake against server #1 (which advertises the
    // handshake-SCID reset token via the §18.2 transport parameter).
    var rx: [4096]u8 = undefined;
    var now_us: u64 = 1_000;
    try cli.conn.advance();
    var step: u32 = 0;
    while (step < 64) : (step += 1) {
        while (try cli.conn.poll(&rx, now_us)) |len| {
            _ = try srv1.feed(rx[0..len], addr, now_us);
        }
        while (srv1.drainStatelessResponse()) |_| {}
        for (srv1.iterator()) |slot| {
            while (try slot.conn.poll(&rx, now_us)) |len| {
                try cli.conn.handle(rx[0..len], null, now_us);
            }
        }
        try srv1.tick(now_us);
        try cli.conn.tick(now_us);
        if (cli.conn.handshakeDone() and srv1.iterator().len > 0 and
            srv1.iterator()[0].conn.handshakeDone()) break;
        now_us += 1_000;
    }
    try std.testing.expect(cli.conn.handshakeDone());

    // Server #2: same key, zero connection state — the post-crash
    // restart. The client's next 1-RTT datagram cannot route there.
    var srv2 = try testServer(allocator, noConfigChange);
    defer srv2.deinit();

    const stream = try cli.conn.openNextBidi();
    _ = try cli.conn.streamWrite(stream.id, "are you still there?");
    var got_reset = false;
    var iters: u32 = 0;
    while (iters < 200 and !got_reset) : (iters += 1) {
        now_us += 1_000;
        while (try cli.conn.poll(&rx, now_us)) |len| {
            const outcome = try srv2.feed(rx[0..len], addr, now_us);
            if (outcome == .stateless_reset_sent) {
                const entry = srv2.drainStatelessResponse() orelse return error.ResetMissing;
                var reset_buf: [256]u8 = undefined;
                @memcpy(reset_buf[0..entry.len], entry.slice());
                try cli.conn.handle(reset_buf[0..entry.len], null, now_us);
                got_reset = true;
                break;
            }
        }
        try cli.conn.tick(now_us);
    }
    try std.testing.expect(got_reset);

    // The client recognized the death certificate: draining, with
    // the stateless_reset close source — no idle-timeout grind.
    try std.testing.expect(cli.conn.closeState() == .draining);
    const close_event = cli.conn.closeEvent() orelse return error.CloseEventMissing;
    try std.testing.expectEqual(quic.conn.lifecycle.CloseSource.stateless_reset, close_event.source);
}
