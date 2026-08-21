//! Request/response server — the pattern real protocols build on,
//! on top of `quic.app.Driver`.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/request-response-example 127.0.0.1:4433
//! ```
//!
//! Framing: one request per bidi stream, `u32` little-endian length
//! prefix + payload; the response uses the same framing. The handler
//! here uppercases the payload — swap `handleRequest` for your
//! protocol and this file is your server. (`echo_server.zig` is the
//! streaming counterpart; `echo_server_raw.zig` shows the same
//! machinery without the Driver.)
//!
//! The `Driver` contract doing the heavy lifting: `StreamState`
//! accumulates request bytes per stream, `onStreamEnd(.fin)` is the
//! one place a request is parsed and answered (it fires only when
//! every byte actually arrived — a reordering hole below the FIN
//! holds it back), and the `Outbox` stages the response for
//! retry across iterations while the peer's flow control catches up.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const common = @import("echo_common.zig");

const D = quic.app.Driver(App);

/// Per-request accumulation cap. Refuse absurd requests instead of
/// buffering the peer's imagination — a real protocol makes this
/// explicit in its framing; here it guards the demo. `pub` so the
/// inline smoke test below can push exactly one byte past it.
pub const max_request_bytes: usize = 1 << 20;

const App = struct {
    pub const StreamState = struct {
        /// Request bytes accumulated so far (length-prefixed frame).
        req: std.ArrayListUnmanaged(u8) = .empty,
        /// Set once the request overflowed `max_request_bytes` and was
        /// refused on the wire. Later chunks are dropped and the end
        /// of the stream is not answered.
        refused: bool = false,

        fn deinit(self: *StreamState, allocator: std.mem.Allocator) void {
            self.req.deinit(allocator);
        }
    };
    pub const ConnState = struct {
        requests: u32 = 0,
    };

    allocator: std.mem.Allocator,

    /// Accumulate request bytes as they arrive.
    fn onStreamData(app: *App, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        if (e.state.refused) return; // refusal already on the wire
        if (!e.bidi) {
            // A request on a UNI stream can never be answered (no
            // send half here) — refuse it instead of buffering it.
            e.state.refused = true;
            s.conn.streamStopSending(e.id, 0x46) catch {}; // FRAME_ERROR
            return;
        }
        if (e.state.req.items.len + chunk.len > max_request_bytes) {
            e.state.refused = true;
            // Free the oversized accumulation now (the list stays
            // valid and empty — `onStreamEnd`'s deinit still runs
            // exactly once), abort our response half, and tell the
            // peer to stop sending the rest.
            e.state.req.clearAndFree(app.allocator);
            try s.outbox.reset(s.conn, e.id, 0x54); // TRUNCATE
            s.conn.streamStopSending(e.id, 0x54) catch {};
            return;
        }
        try e.state.req.appendSlice(app.allocator, chunk);
    }

    /// The peer's request is complete: parse the frame, answer, FIN.
    fn onStreamEnd(app: *App, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        defer e.state.deinit(app.allocator);
        if (e.state.refused) return; // refused mid-request: no answer
        if (!e.bidi) return; // uni: no send half to answer on
        switch (end) {
            .fin => {},
            // Aborted or reaped mid-request: nothing to answer.
            .reset, .reaped => return,
        }

        const req = e.state.req.items;
        if (req.len < 4) {
            try s.outbox.reset(s.conn, e.id, 0x46); // FRAME_ERROR
            return;
        }
        const body = req[4..];

        var response: std.ArrayListUnmanaged(u8) = .empty;
        defer response.deinit(app.allocator);
        var prefix: [4]u8 = undefined;
        std.mem.writeInt(u32, &prefix, @intCast(body.len), .little);
        try response.appendSlice(app.allocator, &prefix);
        for (body) |b| try response.append(app.allocator, std.ascii.toUpper(b));

        try s.outbox.push(s.conn, e.id, response.items);
        try s.outbox.finish(s.conn, e.id);
        s.app.requests += 1;
        std.debug.print(
            "[rr] conn {d}: answered request {d} ({d} bytes -> {d} bytes)\n",
            .{ s.slot.slot_id, s.app.requests, req.len, response.items.len },
        );
    }

    fn onDisconnect(app: *App, s: *D.Session) void {
        _ = app;
        std.debug.print("[rr] conn {d}: closed after {d} request(s)\n", .{ s.slot.slot_id, s.app.requests });
    }
};

pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown_flag: *const std.atomic.Value(bool),
) !void {
    var app: App = .{ .allocator = allocator };
    var driver = try D.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = App.onStreamData,
            .on_stream_end = App.onStreamEnd,
            .on_disconnect = App.onDisconnect,
        },
        .max_tracked_streams = common.transportParams().initial_max_streams_bidi +
            common.transportParams().initial_max_streams_uni,
    });
    defer driver.deinit();

    const protos = [_][]const u8{"rr/1"};
    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = D.willCloseHook,
        .on_connection_will_close_user_data = &driver,
    });
    defer server.deinit();

    std.debug.print("[rr] request/response server listening on {s} (ALPN rr/1)\n", .{listen});

    try quic.transport.runUdpServer(&server, .{
        .listen = listen,
        .io = io,
        .shutdown_flag = shutdown_flag,
        .tune_socket = false,
        .on_iteration = D.iterationHook,
        .on_iteration_ctx = &driver,
    });

    std.debug.print("[rr] shut down cleanly\n", .{});
}

// -- SIGINT -> shutdown flag ------------------------------------------------

var sigint_flag = std.atomic.Value(bool).init(false);

fn onSigInt(_: std.posix.SIG) callconv(.c) void {
    sigint_flag.store(true, .release);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // program name
    const listen = args.next() orelse common.default_addr;

    if (builtin.os.tag != .windows) {
        const act: std.posix.Sigaction = .{
            .handler = .{ .handler = onSigInt },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(.INT, &act, null);
        std.debug.print("[rr] Ctrl-C to shut down gracefully\n", .{});
    }

    try serve(allocator, io, listen, &sigint_flag);
}

// -- Inline smoke tests (`zig build test` walks these) ----------------------
//
// The server half of `serve` — the App, its hooks, and the Driver
// wiring — driven over `quic.testing.Loopback` instead of a UDP
// socket. What the tests pin, in order: the happy request/response
// path; per-stream state across TABLE SLOT REUSE (a second request on
// the same connection lands in the released slot of the first — stale
// state there answers with garbage or crashes); and the
// `max_request_bytes` refusal, which must abort loudly on the wire
// and leave the connection healthy for the next request.

const TestPeers = struct {
    app: App,
    driver: D,
    server: quic.Server,
    client: quic.Client,
    lb: quic.testing.Loopback,

    const test_protos = [_][]const u8{"rr/1"};

    fn init(self: *TestPeers, allocator: std.mem.Allocator) !void {
        self.app = .{ .allocator = allocator };
        self.driver = try D.init(.{
            .allocator = allocator,
            .app = &self.app,
            .hooks = .{
                .on_stream_data = App.onStreamData,
                .on_stream_end = App.onStreamEnd,
                .on_disconnect = App.onDisconnect,
            },
            .max_tracked_streams = common.transportParams().initial_max_streams_bidi +
                common.transportParams().initial_max_streams_uni,
        });
        errdefer self.driver.deinit();
        self.server = try quic.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = common.cert_pem,
            .tls_key_pem = common.key_pem,
            .alpn_protocols = &test_protos,
            .transport_params = common.transportParams(),
            .on_connection_will_close = D.willCloseHook,
            .on_connection_will_close_user_data = &self.driver,
        });
        errdefer self.server.deinit();
        self.client = try quic.Client.connect(.{
            .insecure_skip_verify = true,
            .allocator = allocator,
            .server_name = "localhost",
            .alpn_protocols = &test_protos,
            .transport_params = common.transportParams(),
        });
        errdefer self.client.deinit();
        self.lb = try quic.testing.Loopback.init(.{
            .allocator = allocator,
            .server = &self.server,
            .client = &self.client,
        });
        errdefer self.lb.deinit();
        try self.lb.handshake(&self.driver);
    }

    fn deinit(self: *TestPeers) void {
        // Close and reap through the loop so the Driver session frees
        // via the will-close hook (leak-check hygiene).
        self.client.conn.close(false, 0, "done");
        var td: usize = 0;
        while (td < 400 and self.server.iterator().len > 0) : (td += 1) {
            self.lb.step(&self.driver) catch break;
            self.lb.now_us += 10_000;
            self.server.tick(self.lb.now_us) catch break;
            _ = self.server.reap();
        }
        self.lb.deinit();
        self.client.deinit();
        self.server.deinit();
        self.driver.deinit();
    }

    /// One framed request on a fresh stream; returns the framed
    /// response bytes once the response stream is terminal.
    fn roundTrip(
        self: *TestPeers,
        allocator: std.mem.Allocator,
        body: []const u8,
        out: *std.ArrayListUnmanaged(u8),
    ) !void {
        const stream = try self.client.conn.openNextBidi();
        var prefix: [4]u8 = undefined;
        std.mem.writeInt(u32, &prefix, @intCast(body.len), .little);
        _ = try self.client.conn.streamWrite(stream.id, &prefix);
        _ = try self.client.conn.streamWrite(stream.id, body);
        try self.client.conn.streamFinish(stream.id);

        var steps: usize = 0;
        while (steps < 10_000) : (steps += 1) {
            var buf: [4096]u8 = undefined;
            const n = self.client.conn.streamRead(stream.id, &buf) catch |err| switch (err) {
                error.StreamNotFound => return, // reaped: fully done
                else => return err,
            };
            if (n > 0) {
                try out.appendSlice(allocator, buf[0..n]);
                continue;
            }
            const st = self.client.conn.streamRecvState(stream.id) orelse return;
            if (st.terminal) return;
            try self.lb.step(&self.driver);
        }
        return error.ResponseStalled;
    }
};

test "request/response over Loopback: framed answer, and state survives slot reuse" {
    const allocator = std.testing.allocator;
    var p: TestPeers = undefined;
    try p.init(allocator);
    defer p.deinit();

    // Two sequential requests on one connection. The second stream
    // lands in the table slot the first released, exercising the
    // Driver's fresh-state init on slot reuse (without it the entry
    // holds whatever the released slot held — undefined behavior,
    // which this test cannot deterministically observe but does walk).
    const legs = [_]struct { body: []const u8, want: []const u8 }{
        .{ .body = "hello world", .want = "HELLO WORLD" },
        .{ .body = "zig", .want = "ZIG" },
    };
    for (legs) |leg| {
        var resp: std.ArrayListUnmanaged(u8) = .empty;
        defer resp.deinit(allocator);
        try p.roundTrip(allocator, leg.body, &resp);
        try std.testing.expect(resp.items.len >= 4);
        const framed_len = std.mem.readInt(u32, resp.items[0..4], .little);
        try std.testing.expectEqual(@as(u32, @intCast(leg.want.len)), framed_len);
        try std.testing.expectEqualStrings(leg.want, resp.items[4..]);
    }
}

test "request/response over Loopback: oversized request is refused, connection survives" {
    const allocator = std.testing.allocator;
    var p: TestPeers = undefined;
    try p.init(allocator);
    defer p.deinit();

    // Push one byte past the cap, in blocks, letting flow control
    // breathe between steps. No FIN — the refusal must come from the
    // accumulation cap, not end-of-stream handling.
    const stream = try p.client.conn.openNextBidi();
    const target: usize = max_request_bytes + 1;
    var block: [16 * 1024]u8 = undefined;
    @memset(&block, 'x');

    var sent: usize = 0;
    var writable = true;
    var refused = false;
    var steps: usize = 0;
    while (steps < 50_000) : (steps += 1) {
        if (writable and sent < target) {
            const want = @min(block.len, target - sent);
            if (p.client.conn.streamWrite(stream.id, block[0..want])) |n| {
                sent += n;
            } else |_| {
                // STOP_SENDING landed: the send half aborted.
                writable = false;
            }
        }
        try p.lb.step(&p.driver);
        const st = p.client.conn.streamRecvState(stream.id) orelse {
            refused = true; // reaped after the abort: also done
            break;
        };
        if (st.reset_seen) {
            refused = true; // server RESET its response half (0x54)
            break;
        }
    }
    try std.testing.expect(refused);

    // The connection is still healthy: a well-behaved request on a
    // fresh stream (reusing the refused stream's table slot) still
    // gets its answer.
    var resp: std.ArrayListUnmanaged(u8) = .empty;
    defer resp.deinit(allocator);
    try p.roundTrip(allocator, "still alive", &resp);
    try std.testing.expect(resp.items.len >= 4);
    try std.testing.expectEqualStrings("STILL ALIVE", resp.items[4..]);
}

test "request/response over Loopback: uni-stream request is refused, connection survives" {
    const allocator = std.testing.allocator;
    var p: TestPeers = undefined;
    try p.init(allocator);
    defer p.deinit();

    // A request on a UNI stream can never be answered — the server
    // must refuse it on the wire (STOP_SENDING), not crash trying to
    // write a response into a send half it does not have.
    const uni = try p.client.conn.openNextUni();
    var refused = false;
    var steps: usize = 0;
    while (steps < 10_000) : (steps += 1) {
        // Keep offering bytes; once the STOP_SENDING lands, the send
        // half aborts and the write fails — that is the refusal.
        if (p.client.conn.streamWrite(uni.id, "x")) |_| {} else |_| {
            refused = true;
            break;
        }
        try p.lb.step(&p.driver);
    }
    try std.testing.expect(refused);

    // And a proper bidi request afterwards still gets its answer.
    var resp: std.ArrayListUnmanaged(u8) = .empty;
    defer resp.deinit(allocator);
    try p.roundTrip(allocator, "still here", &resp);
    try std.testing.expect(resp.items.len >= 4);
    try std.testing.expectEqualStrings("STILL HERE", resp.items[4..]);
}
