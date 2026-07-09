//! Echo client — the canonical first-hour quic_zig client example,
//! paired with `echo_server.zig`.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/echo-server-example &
//! ./zig-out/bin/echo-client-example [server-addr]   # default 127.0.0.1:4433
//! ```
//!
//! The shape to copy for your own client:
//!
//!  1. `quic_zig.Client.connect` builds the TLS context + a
//!     ready-to-tick `Connection` (here with `insecure_skip_verify`
//!     because the demo server uses a self-signed test cert — drop
//!     that for anything real).
//!  2. `quic_zig.transport.runUdpClient` owns the socket and the
//!     advance/receive/tick loop; it returns when the connection
//!     closes.
//!  3. ALL application logic lives in the `on_iteration` hook — a
//!     tiny state machine driven by `pollEvent` + stream/datagram
//!     reads, all on the loop thread.
//!
//! Round-trip exercised: open a bidi stream after
//! `handshake_established`, write one message + FIN, read the echo
//! back to FIN, then send one DATAGRAM and wait for its echo, then
//! close cleanly (which exits the loop).

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("echo_common.zig");

/// Payload for the stream leg of the round-trip.
pub const stream_message = "hello over a QUIC stream";
/// Payload for the RFC 9221 DATAGRAM leg.
pub const datagram_message = "hello over a QUIC datagram";

/// The client's whole application: a four-stage state machine
/// advanced once per loop iteration by `onIteration`.
pub const EchoFlow = struct {
    stage: Stage = .awaiting_handshake,
    stream_id: u64 = 0,
    /// Echo bytes accumulated so far (streams can deliver in chunks).
    reply: [stream_message.len]u8 = undefined,
    reply_len: usize = 0,
    /// Give-up deadline on the loop's monotonic clock (microseconds
    /// since loop start). `onIteration` errors out past this, which
    /// stops `runUdpClient` and propagates to the caller.
    deadline_us: u64,

    pub const Stage = enum {
        awaiting_handshake,
        awaiting_stream_echo,
        awaiting_datagram_echo,
        done,
    };

    /// `transport.RunUdpClientOptions.on_iteration` — fires once per
    /// loop iteration on the loop thread, after inbound datagrams are
    /// handled and the clock ticked; anything queued here ships on
    /// the very next outbox drain.
    pub fn onIteration(ctx: ?*anyopaque, client: *quic_zig.Client, now_us: u64) anyerror!void {
        const flow: *EchoFlow = @ptrCast(@alignCast(ctx.?));
        if (flow.stage == .done) return;
        if (now_us > flow.deadline_us) return error.EchoTimedOut;

        // Drain connection events. `handshake_established` (a
        // one-shot) kicks off the stream leg.
        while (client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                const stream = try client.conn.openNextBidi();
                flow.stream_id = stream.id;
                const written = try client.conn.streamWrite(flow.stream_id, stream_message);
                std.debug.assert(written == stream_message.len);
                try client.conn.streamFinish(flow.stream_id);
                flow.stage = .awaiting_stream_echo;
                std.debug.print(
                    "[client] handshake established; sent {d} bytes + FIN on stream {d}\n",
                    .{ stream_message.len, flow.stream_id },
                );
            },
            .close => |close_ev| {
                std.debug.print(
                    "[client] close observed (source={s} code={d})\n",
                    .{ @tagName(close_ev.source), close_ev.error_code },
                );
            },
            else => {},
        };

        switch (flow.stage) {
            .awaiting_handshake, .done => {},
            .awaiting_stream_echo => {
                const res = try client.conn.streamReadFin(
                    flow.stream_id,
                    flow.reply[flow.reply_len..],
                );
                flow.reply_len += res.n;
                if (!res.fin) return; // echo still in flight
                if (!std.mem.eql(u8, flow.reply[0..flow.reply_len], stream_message)) {
                    return error.EchoMismatch;
                }
                std.debug.print(
                    "[client] stream echo verified ({d} bytes); sending datagram\n",
                    .{flow.reply_len},
                );
                try client.conn.sendDatagram(datagram_message);
                flow.stage = .awaiting_datagram_echo;
            },
            .awaiting_datagram_echo => {
                var buf: [2048]u8 = undefined;
                const n = client.conn.receiveDatagram(&buf) orelse return;
                if (!std.mem.eql(u8, buf[0..n], datagram_message)) {
                    return error.EchoMismatch;
                }
                std.debug.print("[client] datagram echo verified; closing\n", .{});
                // Clean application close. The connection transitions
                // through closing -> closed, and `runUdpClient` exits
                // on its own once `isClosed()` latches.
                client.conn.close(false, 0, "echo done");
                flow.stage = .done;
            },
        }
    }
};

/// Run the full echo round-trip against `target`. Returns an error
/// if any leg fails or `timeout_us` elapses. Factored out of `main`
/// so `echo_smoke.zig` can drive the identical flow in-process.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    timeout_us: u64,
) !void {
    const protos = [_][]const u8{common.alpn};

    var client = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        // The demo server presents a self-signed test certificate.
        // Never set this against an untrusted network — verify
        // against the system store (the default) or pin roots via
        // `tls_context_override`.
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    std.debug.print("[client] connecting to {s} (ALPN {s})\n", .{ target, common.alpn });

    var flow: EchoFlow = .{ .deadline_us = timeout_us };
    try quic_zig.transport.runUdpClient(&client, .{
        .target = target,
        .io = io,
        // Demo posture, same as the server: run unprivileged.
        .tune_socket = false,
        .on_iteration = EchoFlow.onIteration,
        .on_iteration_ctx = &flow,
    });

    // The loop can also exit on handshake failure or a server-initiated
    // close — only a `done` stage means the round-trip happened.
    if (flow.stage != .done) return error.EchoIncomplete;

    std.debug.print("[client] echo round-trip complete\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // program name
    const target = args.next() orelse common.default_addr;

    try run(allocator, io, target, 15 * std.time.us_per_s);
}
