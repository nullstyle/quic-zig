//! Echo server — the canonical first-hour quic_zig hosting example.
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
//!  1. `quic_zig.Server.init` owns TLS + the connection table.
//!  2. `quic_zig.transport.runUdpServer` owns the socket and the
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
//! Echo semantics: every peer-opened bidi stream is read to FIN and
//! the bytes written back (FIN'd once the peer's FIN is seen); every
//! RFC 9221 DATAGRAM is echoed verbatim. One line is printed per
//! connection event so a human can watch the flow.

const std = @import("std");
const builtin = @import("builtin");
const quic_zig = @import("quic_zig");
const common = @import("echo_common.zig");

/// Max concurrently-tracked peer bidi streams per connection. An
/// echo demo never needs many; a full application would size this
/// to its `initial_max_streams_bidi`.
const max_tracked_streams: usize = 16;

/// Scratch sizing for stream/datagram echo reads.
const read_chunk_bytes: usize = 4096;

/// Per-connection application state, allocated on the first event
/// from a connection, hung off `Slot.user_data`, and freed in
/// `onConnectionWillClose`. This is the pattern to copy: quic_zig
/// never reads or frees `user_data`; the will-close hook is the last
/// safe place to release it.
const ConnState = struct {
    /// Peer bidi streams currently being echoed (id list).
    streams: [max_tracked_streams]u64 = undefined,
    stream_count: usize = 0,
    /// Tiny per-connection counters, reported at close.
    streams_echoed: u32 = 0,
    datagrams_echoed: u32 = 0,

    fn track(self: *ConnState, id: u64) void {
        if (self.stream_count == max_tracked_streams) return; // demo cap
        self.streams[self.stream_count] = id;
        self.stream_count += 1;
    }

    fn removeAt(self: *ConnState, idx: usize) void {
        self.stream_count -= 1;
        self.streams[idx] = self.streams[self.stream_count];
    }
};

/// Application context threaded through both hooks as an opaque
/// pointer.
pub const EchoApp = struct {
    allocator: std.mem.Allocator,

    /// `transport.RunUdpOptions.on_iteration` — fires once per loop
    /// iteration on the loop thread. Drains each slot's event queue,
    /// then does the actual echo work.
    pub fn onIteration(ctx: ?*anyopaque, server: *quic_zig.Server, now_us: u64) anyerror!void {
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
    pub fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic_zig.Server.Slot) void {
        const app: *EchoApp = @ptrCast(@alignCast(ctx.?));
        const state = connState(slot) orelse return;
        std.debug.print(
            "[server] conn {d}: reaped after echoing {d} stream(s), {d} datagram(s)\n",
            .{ slot.slot_id, state.streams_echoed, state.datagrams_echoed },
        );
        app.allocator.destroy(state);
        slot.user_data = null;
    }

    fn ensureState(app: *EchoApp, slot: *quic_zig.Server.Slot) !*ConnState {
        if (connState(slot)) |state| return state;
        const state = try app.allocator.create(ConnState);
        state.* = .{};
        slot.user_data = state;
        return state;
    }
};

fn connState(slot: *quic_zig.Server.Slot) ?*ConnState {
    const ptr = slot.user_data orelse return null;
    return @ptrCast(@alignCast(ptr));
}

/// Pump every tracked bidi stream: read whatever the peer has
/// buffered, write it straight back, and FIN our half once the
/// peer's FIN is seen (`streamReadFin` reports it inline with the
/// draining read).
fn echoStreams(slot: *quic_zig.Server.Slot, state: *ConnState) !void {
    var buf: [read_chunk_bytes]u8 = undefined;
    var i: usize = 0;
    while (i < state.stream_count) {
        const id = state.streams[i];
        var finished = false;
        while (true) {
            const res = slot.conn.streamReadFin(id, &buf) catch |err| switch (err) {
                // Peer reset the stream and the GC already reaped it —
                // nothing left to echo.
                error.StreamNotFound => {
                    finished = true;
                    break;
                },
                else => return err,
            };
            if (res.n > 0) {
                // The demo windows (256 KiB per stream) are far larger
                // than a read chunk, so the echo write always fits.
                const written = try slot.conn.streamWrite(id, buf[0..res.n]);
                std.debug.assert(written == res.n);
            }
            if (res.fin) {
                try slot.conn.streamFinish(id);
                state.streams_echoed += 1;
                std.debug.print(
                    "[server] conn {d}: stream {d} fully echoed (fin)\n",
                    .{ slot.slot_id, id },
                );
                finished = true;
                break;
            }
            if (res.n == 0) break; // nothing more buffered this iteration
        }
        if (finished) state.removeAt(i) else i += 1;
    }
}

/// Echo every queued inbound DATAGRAM verbatim.
fn echoDatagrams(slot: *quic_zig.Server.Slot, state: *ConnState) !void {
    var buf: [read_chunk_bytes]u8 = undefined;
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

    var server = try quic_zig.Server.init(.{
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

    try quic_zig.transport.runUdpServer(&server, .{
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
