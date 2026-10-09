//! The rest cache (0.36.0) against every public call that changes
//! state, at the public wrappers: a connection at rest with its cached
//! deadline primed, one call, then the three places that read the
//! cache in a Debug build check it against a fresh computation
//! (`nextTimerDeadline`: fresh equals cached; `pollDatagram`: the
//! builder emits nothing when the shortcut says rest; `tick`: the full
//! tick fires nothing when the shortcut says not due). A call that
//! changes what the connection sends or when its timer is due must
//! `touch`; one that forgot asserts here.
//!
//! Why this exists: the two defects of 2026-10-08 (capnp-zig's find and
//! what its fix uncovered) were missing touches, and the self-checks
//! caught them only on flows that reached rest and then read the cache.
//! This test puts every call in that position, once, on both sides.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const protos = [_][]const u8{"hq-test"};
const addr: quic.conn.path.Address = .{ .ipv4 = .{ .addr = @splat(0xe4), .port = 7 } };

const Pair = struct {
    srv: quic.Server,
    cli: quic.Client,
    now_us: u64,

    fn init() !Pair {
        var p: Pair = .{
            .srv = try quic.Server.init(.{
                .allocator = std.testing.allocator,
                .tls_cert_pem = common.test_cert_pem,
                .tls_key_pem = common.test_key_pem,
                .alpn_protocols = &protos,
                .transport_params = common.defaultParams(),
            }),
            .cli = undefined,
            .now_us = 1_000,
        };
        errdefer p.srv.deinit();
        p.cli = try quic.Client.connect(.{
            .insecure_skip_verify = true,
            .allocator = std.testing.allocator,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = common.defaultParams(),
        });
        return p;
    }

    fn deinit(p: *Pair) void {
        p.cli.deinit();
        p.srv.deinit();
    }

    fn pump(p: *Pair) !void {
        var rx: [4096]u8 = undefined;
        while (try p.cli.conn.poll(&rx, p.now_us)) |len| _ = try p.srv.feed(rx[0..len], addr, p.now_us);
        while (p.srv.drainStatelessResponse()) |_| {}
        for (p.srv.iterator()) |slot| {
            while (try slot.conn.poll(&rx, p.now_us)) |len| try p.cli.conn.handle(rx[0..len], null, p.now_us);
        }
    }

    fn cycle(p: *Pair, advance_us: u64) !void {
        try p.pump();
        try p.srv.tick(p.now_us);
        try p.cli.conn.tick(p.now_us);
        p.now_us += advance_us;
    }

    fn sconn(p: *Pair) *quic.Connection {
        return p.srv.iterator()[0].conn;
    }

    /// Handshake, then settle until both sides are at rest with their
    /// caches primed.
    fn toRest(p: *Pair) !void {
        try p.cli.conn.advance();
        var step: u32 = 0;
        while (step < 64) : (step += 1) {
            try p.cycle(1_000);
            if (p.cli.conn.handshakeDone() and p.srv.iterator().len > 0 and p.sconn().handshakeDone()) break;
        }
        try std.testing.expect(p.cli.conn.handshakeDone());
        step = 0;
        while (step < 10) : (step += 1) try p.cycle(30_000);
        try p.prime();
    }

    /// Both caches primed: the shortcut answers from now on.
    fn prime(p: *Pair) !void {
        var rx: [4096]u8 = undefined;
        try std.testing.expect((try p.cli.conn.pollDatagram(&rx, p.now_us)) == null);
        try std.testing.expect((try p.sconn().pollDatagram(&rx, p.now_us)) == null);
        _ = p.cli.conn.nextTimerDeadline(p.now_us);
        _ = p.sconn().nextTimerDeadline(p.now_us);
        try std.testing.expect(p.cli.conn.atRest());
        try std.testing.expect(p.sconn().atRest());
    }

    /// After the call: every reader of the cache runs on both sides (the
    /// Debug checks fire for a stale cache), then both sides are pumped
    /// so that whatever the call queued goes out, and the cycle ends
    /// with both at rest again or with the connection closed, as the
    /// case says.
    fn after(p: *Pair) !void {
        _ = p.cli.conn.nextTimerDeadline(p.now_us);
        _ = p.sconn().nextTimerDeadline(p.now_us);
        var step: u32 = 0;
        while (step < 6) : (step += 1) try p.cycle(30_000);
    }
};

const Case = struct {
    name: []const u8,
    call: *const fn (p: *Pair) anyerror!void,
    /// The connection is expected closed afterwards (a close call).
    closes: bool = false,
    /// Closed or open afterwards, either is fine (a graceful shutdown
    /// with no stream to wait for may close at once or later).
    may_close: bool = false,
};

fn clientPing(p: *Pair) !void {
    p.cli.conn.requestPing();
}
fn serverPing(p: *Pair) !void {
    p.sconn().requestPing();
}
fn clientPathPing(p: *Pair) !void {
    try p.cli.conn.requestPathPing(0);
}
fn clientOpenAndWrite(p: *Pair) !void {
    _ = try p.cli.conn.openBidi(0);
    _ = try p.cli.conn.streamWrite(0, "hello");
}
fn clientOpenOnly(p: *Pair) !void {
    _ = try p.cli.conn.openBidi(0);
}
fn clientWriteFinish(p: *Pair) !void {
    _ = try p.cli.conn.openUni(2);
    _ = try p.cli.conn.streamWrite(2, "bye");
    try p.cli.conn.streamFinish(2);
}
fn clientReset(p: *Pair) !void {
    _ = try p.cli.conn.openUni(2);
    _ = try p.cli.conn.streamWrite(2, "x");
    try p.cli.conn.streamReset(2, 7);
}
fn clientPriority(p: *Pair) !void {
    _ = try p.cli.conn.openBidi(0);
    _ = try p.cli.conn.streamWrite(0, "hello");
    try p.cli.conn.streamSetPriority(0, .{ .urgency = 1, .incremental = true });
}
fn serverStopSending(p: *Pair) !void {
    // The client opens and writes; the server stops the stream.
    _ = try p.cli.conn.openBidi(0);
    _ = try p.cli.conn.streamWrite(0, "hello");
    try p.cycle(1_000);
    try p.prime();
    try p.sconn().streamStopSending(0, 9);
}
fn clientPmtud(p: *Pair) !void {
    p.cli.conn.setPmtudConfig(.{ .initial_mtu = 1200, .max_mtu = 1452, .probe_step = 64, .probe_threshold = 3, .enable = true });
}
fn clientCongestion(p: *Pair) !void {
    p.cli.conn.setCongestionAlgorithm(.cubic);
}
fn clientHyStart(p: *Pair) !void {
    p.cli.conn.setHyStartEnabled(false);
}
fn clientDatagram(p: *Pair) !void {
    // The peer may not take datagrams (the wrappers' defaults do not
    // announce them): then there is nothing to queue, and that is fine.
    p.cli.conn.sendDatagram("dg") catch return;
}
fn serverNewToken(p: *Pair) !void {
    try p.sconn().queueNewToken("token-bytes-for-the-client");
}
fn clientProbePath(p: *Pair) !void {
    try p.cli.conn.probePath(.{ 1, 2, 3, 4, 5, 6, 7, 8 }, p.now_us, 2_000_000);
}
fn clientGraceful(p: *Pair) !void {
    p.cli.conn.beginGracefulShutdown();
}
fn clientClose(p: *Pair) !void {
    p.cli.conn.close(false, 0, "done");
}
fn serverClose(p: *Pair) !void {
    p.sconn().close(false, 0, "done");
}
fn clientTouchOnly(p: *Pair) !void {
    p.cli.conn.touch();
}

const cases = [_]Case{
    .{ .name = "requestPing (client)", .call = clientPing },
    .{ .name = "requestPing (server)", .call = serverPing },
    .{ .name = "requestPathPing", .call = clientPathPing },
    .{ .name = "openBidi + streamWrite", .call = clientOpenAndWrite },
    .{ .name = "openBidi alone", .call = clientOpenOnly },
    .{ .name = "streamWrite + streamFinish", .call = clientWriteFinish },
    .{ .name = "streamReset", .call = clientReset },
    .{ .name = "streamSetPriority", .call = clientPriority },
    .{ .name = "streamStopSending (server)", .call = serverStopSending },
    .{ .name = "setPmtudConfig", .call = clientPmtud },
    .{ .name = "setCongestionAlgorithm", .call = clientCongestion },
    .{ .name = "setHyStartEnabled", .call = clientHyStart },
    .{ .name = "sendDatagram", .call = clientDatagram },
    .{ .name = "queueNewToken (server)", .call = serverNewToken },
    .{ .name = "probePath", .call = clientProbePath },
    .{ .name = "touch alone", .call = clientTouchOnly },
    .{ .name = "beginGracefulShutdown", .call = clientGraceful, .may_close = true },
    .{ .name = "close (client)", .call = clientClose, .closes = true },
    .{ .name = "close (server)", .call = serverClose, .closes = true },
};

test "the rest cache against every public call that changes state: each one touches, or leaves the cache true" {
    for (cases) |c| {
        var p = try Pair.init();
        defer p.deinit();
        try p.toRest();
        c.call(&p) catch |err| {
            std.debug.print("case '{s}': {s}\n", .{ c.name, @errorName(err) });
            return err;
        };
        p.after() catch |err| {
            std.debug.print("case '{s}' (after): {s}\n", .{ c.name, @errorName(err) });
            return err;
        };
        if (c.may_close) {
            // Either way; the point was the touch, checked in `after`.
        } else if (c.closes) {
            try std.testing.expect(p.cli.conn.closeState() != .open or p.sconn().closeState() != .open);
        } else if (p.cli.conn.closeState() != .open or p.sconn().closeState() != .open) {
            std.debug.print("case '{s}': closed afterwards (client {s}, server {s}; client reason {?s}, server reason {?s})\n", .{
                c.name,
                @tagName(p.cli.conn.closeState()),
                @tagName(p.sconn().closeState()),
                if (p.cli.conn.closeEvent()) |e| e.reason else null,
                if (p.sconn().closeEvent()) |e| e.reason else null,
            });
            return error.CaseClosedTheConnection;
        }
    }
}
