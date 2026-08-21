//! Echo server — the canonical first-hour quic hosting example,
//! built on the `quic.app` application layer.
//!
//! One process, one UDP socket, real loopback traffic:
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/echo-server-example              # listens on 127.0.0.1:4433
//! ./zig-out/bin/echo-client-example              # round-trips against it
//! ```
//!
//! The whole application is the three callbacks on `EchoApp` below:
//! stream chunks are pushed back through the session's `Outbox`
//! (which stages whatever the connection refuses and retries it on a
//! later pass), the stream's FIN is mirrored only when the peer's
//! receive half is *terminal* — never when its FIN frame was merely
//! seen — and DATAGRAMs are echoed verbatim. Everything that used to
//! be hand-rolled here (connection discovery, per-stream state
//! arrays, event-queue switches, `@ptrCast` context plumbing,
//! short-write staging) lives in `quic.app.Driver`.
//!
//! The byte-level mechanics — why `fin` is not EOF, why a short
//! write is backpressure, and what the Driver's ordering guarantees
//! are — are documented in `quic.app` and demonstrated the explicit
//! way in `echo_server_raw.zig`, the same server written directly
//! against `Server`/`Connection`. Read that one when you need to see
//! under the abstraction; copy this one when you need a server.
//!
//! `echo_smoke.zig` drives this exact `serve` on a background thread.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const common = @import("echo_common.zig");

/// Sizing anchor for the smoke test's large payload (it sends this
/// + 76 so the transfer always spans multiple packets/passes). The
/// Driver itself now pumps zero-copy whole runs — there is no fixed
/// read-chunk size anymore.
pub const stream_chunk_bytes: usize = 4096;

const D = quic.app.Driver(EchoApp);

/// The echo application: every peer-opened stream is drained and the
/// bytes written back; every RFC 9221 DATAGRAM is echoed verbatim.
/// Counters live on typed per-connection state (`ConnState`) and are
/// printed at disconnect.
const EchoApp = struct {
    pub const StreamState = void;
    pub const ConnState = struct {
        streams_echoed: u32 = 0,
        datagrams_echoed: u32 = 0,
    };

    fn onStreamData(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        // A peer-initiated UNI stream has no send half on this side:
        // pushing the echo would fail with StreamNotWritable and stop
        // the server. Drain-only for those; echo the bidi ones.
        if (!e.bidi) return;
        try s.outbox.push(s.conn, e.id, chunk);
    }

    fn onStreamEnd(_: *EchoApp, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        if (!e.bidi) return; // nothing was echoed; nothing to finish
        switch (end) {
            // Clean EOF: everything arrived and was drained — mirror
            // the peer's FIN. A reset (or an already-reaped stream)
            // has no clean EOF to mirror.
            .fin => {
                try s.outbox.finish(s.conn, e.id);
                s.app.streams_echoed += 1;
                std.debug.print(
                    "[server] conn {d}: stream {d} fully echoed (fin)\n",
                    .{ s.slot.slot_id, e.id },
                );
            },
            .reset, .reaped => {},
        }
    }

    fn onDatagram(_: *EchoApp, s: *D.Session, dg: D.Datagram) anyerror!void {
        const data = dg.bytes;
        s.conn.sendDatagram(data) catch |err| switch (err) {
            // Peer didn't advertise datagram support, or shrank the
            // limit below what it just sent us — drop, don't kill the
            // connection.
            error.DatagramUnavailable, error.DatagramTooLarge => {},
            else => return err,
        };
        s.app.datagrams_echoed += 1;
    }

    fn onDisconnect(_: *EchoApp, s: *D.Session) void {
        std.debug.print(
            "[server] conn {d}: closed after echoing {d} stream(s), {d} datagram(s)\n",
            .{ s.slot.slot_id, s.app.streams_echoed, s.app.datagrams_echoed },
        );
    }
};

/// Run the echo server until `shutdown_flag` flips (or the loop
/// fails). Factored out of `main` so `echo_smoke.zig` can drive the
/// identical loop on a background thread.
pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown_flag: *const std.atomic.Value(bool),
) !void {
    var app: EchoApp = .{};
    var driver = try D.init(.{
        .allocator = allocator,
        .app = &app,
        .hooks = .{
            .on_stream_data = EchoApp.onStreamData,
            .on_stream_end = EchoApp.onStreamEnd,
            .on_datagram = EchoApp.onDatagram,
            .on_disconnect = EchoApp.onDisconnect,
        },
        // Sized to what we advertise (see echo_common.transportParams)
        // so a conforming peer can never open a stream the table
        // cannot track, and the datagram buffer can never truncate.
        .max_tracked_streams = blk: {
            const tp = common.transportParams();
            break :blk tp.initial_max_streams_bidi + tp.initial_max_streams_uni;
        },
        .datagram_buf_bytes = common.transportParams().max_datagram_frame_size,
    });
    defer driver.deinit();

    const protos = [_][]const u8{common.alpn};
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

    std.debug.print("[server] echo server listening on {s} (ALPN {s})\n", .{ listen, common.alpn });

    try quic.transport.runUdpServer(&server, .{
        .listen = listen,
        .io = io,
        .shutdown_flag = shutdown_flag,
        // Demo posture: skip the SO_RCVBUF/SO_SNDBUF bump so the
        // example runs unprivileged everywhere. Production servers
        // should leave `tune_socket = true` (the default).
        .tune_socket = false,
        .on_iteration = D.iterationHook,
        .on_iteration_ctx = &driver,
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
