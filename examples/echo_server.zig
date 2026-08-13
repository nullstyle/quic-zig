//! Echo server — the canonical first-hour quic hosting example.
//!
//! One process, one UDP socket, real loopback traffic:
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/echo-server-example              # listens on 127.0.0.1:4433
//! ./zig-out/bin/echo-client-example              # round-trips against it
//! ```
//!
//! The shape to copy for your own server:
//!
//!  1. `quic.Server.init` owns TLS + the connection table.
//!  2. `quic.transport.runUdpServer` owns the socket and the
//!     receive/tick/drain loop.
//!  3. ALL application logic lives in the `on_iteration` hook — the
//!     one place where touching a loop-owned `Server` is safe
//!     (`Server`/`Connection` have no internal locking; the hook runs
//!     on the loop thread, after ingest and before the outbox drain,
//!     so replies ship the same iteration).
//!  4. Per-connection app state hangs off `Slot.user_data` and is
//!     released in `Config.on_connection_will_close`, which `reap`
//!     invokes while the slot is still fully valid. The auto-reap
//!     runs on the loop thread too, so the two hooks never race.
//!  5. Shutdown is a `std.atomic.Value(bool)` flipped from a SIGINT
//!     handler; the loop queues CONNECTION_CLOSE on every slot and
//!     drains for a grace window before returning.
//!
//! Echo semantics: every peer-opened bidi stream is drained and the
//! bytes written back (FIN'd once the peer's FIN has been *read*, not
//! merely seen arriving); every RFC 9221 DATAGRAM is echoed verbatim.
//! One line is printed per connection event so a human can watch the
//! flow.
//!
//! Two stream-API details `echoStream` below exists to get right,
//! because both fail silently on any payload bigger than one read:
//! `StreamReadResult.fin` reports that the FIN *frame arrived*, not
//! that you have drained the stream, and `Connection.streamWrite`
//! short-writes by design when the send buffer is full. Neither is an
//! error condition; both need a loop.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const common = @import("echo_common.zig");

/// Max concurrently-tracked peer bidi streams per connection. An
/// echo demo never needs many; a full application would size this
/// to its `initial_max_streams_bidi`.
const max_tracked_streams: usize = 16;

/// Bytes of one stream staged per echo pass. Every tracked stream
/// owns one of these (16 KiB per connection at the numbers here),
/// because the write-back may not accept everything we just read.
/// `echo_smoke.zig` reads this to size the payload that forces the
/// multi-chunk path.
pub const stream_chunk_bytes: usize = 1024;

/// Read buffer for inbound DATAGRAMs. Must be at least the
/// `max_datagram_frame_size` we advertise (1200, see
/// `echo_common.transportParams`): `receiveDatagram` pops the payload
/// from the queue whether or not it fit, so a short buffer loses the
/// tail with no error.
const datagram_chunk_bytes: usize = 2048;

/// One peer bidi stream mid-echo. `buf[off..len]` is the tail
/// `streamWrite` has not accepted yet: it clamps to the stream's
/// remaining send-buffer room and returns what it took, so a short
/// write is backpressure to resume from — never an error, and never
/// something to assert on. The tail waits here and ships on a later
/// iteration, which is what keeps the echo byte-exact and in order.
const StreamEcho = struct {
    id: u64 = 0,
    active: bool = false,
    buf: [stream_chunk_bytes]u8 = undefined,
    off: usize = 0,
    len: usize = 0,
    /// The peer's FIN *frame has arrived*. Strictly weaker than "we
    /// have read everything": `StreamReadResult.fin` mirrors
    /// `recv.fin_seen`, which flips when the FIN-carrying frame is
    /// accepted regardless of how much the application has drained.
    /// Act on it only after a read comes back empty.
    fin_seen: bool = false,
};

/// Per-connection application state, allocated on the first event
/// from a connection, hung off `Slot.user_data`, and freed in
/// `onConnectionWillClose`. This is the pattern to copy: quic
/// never reads or frees `user_data`; the will-close hook is the last
/// safe place to release it.
const ConnState = struct {
    /// Peer bidi streams currently being echoed.
    streams: [max_tracked_streams]StreamEcho = @splat(.{}),
    /// Tiny per-connection counters, reported at close.
    streams_echoed: u32 = 0,
    datagrams_echoed: u32 = 0,

    fn track(self: *ConnState, id: u64) void {
        for (&self.streams) |*e| {
            if (e.active) continue;
            e.* = .{ .id = id, .active = true };
            return;
        }
        // Demo cap. A real server sizes this to the
        // `initial_max_streams_bidi` it advertises, so a conforming
        // peer can never open a stream it will not service.
    }
};

/// Application context threaded through both hooks as an opaque
/// pointer.
pub const EchoApp = struct {
    allocator: std.mem.Allocator,

    /// `transport.RunUdpOptions.on_iteration` — fires once per loop
    /// iteration on the loop thread. Drains each slot's event queue,
    /// then does the actual echo work.
    pub fn onIteration(ctx: ?*anyopaque, server: *quic.Server, now_us: u64) anyerror!void {
        _ = now_us;
        const app: *EchoApp = @ptrCast(@alignCast(ctx.?));
        for (server.iterator()) |slot| {
            // 1. Events first: they establish per-connection state.
            while (slot.conn.pollEvent()) |event| switch (event) {
                .handshake_established => {
                    _ = try app.ensureState(slot);
                    std.debug.print("[server] conn {d}: handshake established\n", .{slot.slot_id});
                },
                .stream_opened => |info| {
                    std.debug.print(
                        "[server] conn {d}: peer opened stream {d} ({s})\n",
                        .{ slot.slot_id, info.stream_id, if (info.bidi) "bidi" else "uni" },
                    );
                    // Only bidi streams can be echoed; uni streams have
                    // no return direction.
                    if (info.bidi) {
                        const state = try app.ensureState(slot);
                        state.track(info.stream_id);
                    }
                },
                .close => |close_ev| {
                    std.debug.print(
                        "[server] conn {d}: close observed (source={s} code={d})\n",
                        .{ slot.slot_id, @tagName(close_ev.source), close_ev.error_code },
                    );
                },
                else => {},
            };

            // 2. Echo work. Slots that never produced state (still
            // handshaking) are skipped.
            const state = connState(slot) orelse continue;
            try echoStreams(slot, state);
            try echoDatagrams(slot, state);
        }
    }

    /// `Server.Config.on_connection_will_close` — runs inside `reap`
    /// for each closed slot while `slot.conn` / `slot.user_data` are
    /// still valid. Free per-connection state here and nowhere else.
    pub fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
        const app: *EchoApp = @ptrCast(@alignCast(ctx.?));
        const state = connState(slot) orelse return;
        std.debug.print(
            "[server] conn {d}: reaped after echoing {d} stream(s), {d} datagram(s)\n",
            .{ slot.slot_id, state.streams_echoed, state.datagrams_echoed },
        );
        app.allocator.destroy(state);
        slot.user_data = null;
    }

    fn ensureState(app: *EchoApp, slot: *quic.Server.Slot) !*ConnState {
        if (connState(slot)) |state| return state;
        const state = try app.allocator.create(ConnState);
        state.* = .{};
        slot.user_data = state;
        return state;
    }
};

fn connState(slot: *quic.Server.Slot) ?*ConnState {
    const ptr = slot.user_data orelse return null;
    return @ptrCast(@alignCast(ptr));
}

/// Pump every tracked bidi stream one pass.
fn echoStreams(slot: *quic.Server.Slot, state: *ConnState) !void {
    for (&state.streams) |*e| {
        if (!e.active) continue;
        const finished = echoStream(slot.conn, e) catch |err| switch (err) {
            // Peer reset the stream and the GC already reaped it —
            // nothing left to echo.
            error.StreamNotFound => true,
            else => return err,
        };
        if (!finished) continue; // more to do on a later iteration
        if (e.fin_seen) {
            state.streams_echoed += 1;
            std.debug.print(
                "[server] conn {d}: stream {d} fully echoed (fin)\n",
                .{ slot.slot_id, e.id },
            );
        }
        e.* = .{};
    }
}

/// One echo pass over `e`: flush whatever the connection refused last
/// time, then read and write back until the peer's buffer is dry, then
/// FIN our half. Returns true when the stream is finished with.
///
/// Both loops here are load-bearing. Stopping at the first `res.fin`
/// would truncate any stream longer than `stream_chunk_bytes` — the
/// FIN frame can arrive while chunks are still queued for us — and
/// stopping at the first short `streamWrite` would drop the tail.
fn echoStream(conn: *quic.Connection, e: *StreamEcho) !bool {
    if (!try flushEcho(conn, e)) return false;
    while (true) {
        const res = try conn.streamReadFin(e.id, &e.buf);
        if (res.fin) e.fin_seen = true;
        e.off = 0;
        e.len = res.n;
        if (!try flushEcho(conn, e)) return false;
        // A read that came back empty is the only reliable "drained"
        // signal; `res.fin` alone is not one.
        if (res.n == 0) break;
    }
    if (!e.fin_seen) return false; // peer hasn't finished sending
    try conn.streamFinish(e.id);
    return true;
}

/// Hand `e`'s staged bytes to the connection, keeping whatever it
/// refuses. False means `streamWrite` short-wrote (the send buffer is
/// full) and the tail is still staged.
fn flushEcho(conn: *quic.Connection, e: *StreamEcho) !bool {
    while (e.off < e.len) {
        const accepted = try conn.streamWrite(e.id, e.buf[e.off..e.len]);
        if (accepted == 0) return false;
        e.off += accepted;
    }
    e.off = 0;
    e.len = 0;
    return true;
}

/// Echo every queued inbound DATAGRAM verbatim.
fn echoDatagrams(slot: *quic.Server.Slot, state: *ConnState) !void {
    var buf: [datagram_chunk_bytes]u8 = undefined;
    while (slot.conn.receiveDatagram(&buf)) |n| {
        slot.conn.sendDatagram(buf[0..n]) catch |err| switch (err) {
            // Peer didn't advertise datagram support, or shrank the
            // limit below what it just sent us — drop, don't kill the
            // connection.
            error.DatagramUnavailable, error.DatagramTooLarge => continue,
            else => return err,
        };
        state.datagrams_echoed += 1;
        std.debug.print(
            "[server] conn {d}: echoed {d}-byte datagram\n",
            .{ slot.slot_id, n },
        );
    }
}

/// Run the echo server until `shutdown_flag` flips (or the loop
/// fails). Factored out of `main` so `echo_smoke.zig` can drive the
/// identical loop on a background thread.
pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown_flag: *const std.atomic.Value(bool),
) !void {
    var app: EchoApp = .{ .allocator = allocator };
    const protos = [_][]const u8{common.alpn};

    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = EchoApp.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
    });
    defer server.deinit();

    std.debug.print("[server] echo server listening on {s} (ALPN {s})\n", .{ listen, common.alpn });

    try quic.transport.runUdpServer(&server, .{
        .listen = listen,
        .io = io,
        .shutdown_flag = shutdown_flag,
        // Demo posture: skip the SO_RCVBUF/SO_SNDBUF bump so the
        // example runs unprivileged everywhere. Production servers
        // should leave `tune_socket = true` (the default).
        .tune_socket = false,
        .on_iteration = EchoApp.onIteration,
        .on_iteration_ctx = &app,
    });

    std.debug.print("[server] shut down cleanly\n", .{});
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
        std.debug.print("[server] Ctrl-C to shut down gracefully\n", .{});
    }

    try serve(allocator, io, listen, &sigint_flag);
}
