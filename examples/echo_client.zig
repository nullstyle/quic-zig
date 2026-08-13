//! Echo client — the canonical first-hour quic client example,
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
//!  1. `quic.Client.connect` builds the TLS context + a
//!     ready-to-tick `Connection` (here with `insecure_skip_verify`
//!     because the demo server uses a self-signed test cert — drop
//!     that for anything real).
//!  2. `quic.transport.runUdpClient` owns the socket and the
//!     advance/receive/tick loop; it returns when the connection
//!     closes.
//!  3. ALL application logic lives in the `on_iteration` hook — a
//!     tiny state machine driven by `pollEvent` + stream/datagram
//!     reads, all on the loop thread.
//!
//! Round-trip exercised: open a bidi stream after
//! `handshake_established`, write the message + FIN, read the echo
//! back in full, then send one DATAGRAM and wait for its echo, then
//! close cleanly (which exits the loop).
//!
//! Both stream legs are loops, not single calls, and that is the point
//! worth copying: `Connection.streamWrite` short-writes when the send
//! buffer is full, and `StreamReadResult.fin` reports that the FIN
//! *frame arrived* rather than that the stream is drained. Neither is
//! an error condition.

const std = @import("std");
const quic = @import("quic");
const common = @import("echo_common.zig");

/// Payload for the stream leg of the round-trip.
pub const stream_message = "hello over a QUIC stream";
/// Payload for the RFC 9221 DATAGRAM leg.
pub const datagram_message = "hello over a QUIC datagram";

/// The client's whole application: a five-stage state machine
/// advanced once per loop iteration by `onIteration`.
pub const EchoFlow = struct {
    stage: Stage = .awaiting_handshake,
    stream_id: u64 = 0,
    /// Bytes to write on the stream. Caller-supplied so `run` can send
    /// the demo message and `runPayload` can send something longer.
    payload: []const u8 = stream_message,
    /// Payload bytes `streamWrite` has *accepted* so far — not the same
    /// as bytes offered, since it short-writes when the send buffer is
    /// full.
    sent: usize = 0,
    /// Echo accumulator, exactly `payload.len` bytes. Caller-owned.
    reply: []u8,
    /// Echo bytes received so far (streams can deliver in chunks).
    reply_len: usize = 0,
    /// Give-up deadline on the loop's monotonic clock (microseconds
    /// since loop start). `onIteration` errors out past this, which
    /// stops `runUdpClient` and propagates to the caller.
    deadline_us: u64,

    pub const Stage = enum {
        awaiting_handshake,
        sending_request,
        awaiting_stream_echo,
        awaiting_datagram_echo,
        done,
    };

    /// `transport.RunUdpClientOptions.on_iteration` — fires once per
    /// loop iteration on the loop thread, after inbound datagrams are
    /// handled and the clock ticked; anything queued here ships on
    /// the very next outbox drain.
    pub fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        const flow: *EchoFlow = @ptrCast(@alignCast(ctx.?));
        if (flow.stage == .done) return;
        if (now_us > flow.deadline_us) return error.EchoTimedOut;

        // Drain connection events. `handshake_established` (a
        // one-shot) kicks off the stream leg.
        while (client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                const stream = try client.conn.openNextBidi();
                flow.stream_id = stream.id;
                flow.stage = .sending_request;
                std.debug.print(
                    "[client] handshake established; opened stream {d}\n",
                    .{flow.stream_id},
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
            .sending_request => {
                // `streamWrite` clamps to the stream's remaining
                // send-buffer room and returns what it accepted, so a
                // short write is backpressure to resume from — never an
                // error, and never something to assert on.
                while (flow.sent < flow.payload.len) {
                    const accepted = try client.conn.streamWrite(
                        flow.stream_id,
                        flow.payload[flow.sent..],
                    );
                    if (accepted == 0) return; // buffer full; resume next iteration
                    flow.sent += accepted;
                }
                try client.conn.streamFinish(flow.stream_id);
                flow.stage = .awaiting_stream_echo;
                std.debug.print(
                    "[client] sent {d} bytes + FIN on stream {d}\n",
                    .{ flow.sent, flow.stream_id },
                );
            },
            .awaiting_stream_echo => {
                // Read until the peer's buffer is dry. Note what this
                // does NOT key off: `res.fin` reports that the FIN
                // *frame arrived*, not that the stream is drained, so
                // for a reply of known length the byte count is the
                // reliable completion signal. (A protocol whose reply
                // length is unknown waits for a read that returns zero
                // bytes with `fin` set — that is what the server side
                // of this pair does in `echoStream`.)
                while (flow.reply_len < flow.reply.len) {
                    const res = client.conn.streamReadFin(
                        flow.stream_id,
                        flow.reply[flow.reply_len..],
                    ) catch |err| switch (err) {
                        // The stream has left the live table. The GC
                        // reaps a bidi stream once both halves are
                        // terminal, and "recv terminal" means the
                        // peer's FIN arrived — so missing bytes here
                        // mean the peer FIN'd early and shorted us,
                        // not that the echo is still in flight.
                        error.StreamNotFound => {
                            if (flow.reply_len < flow.reply.len) return error.EchoTruncated;
                            break;
                        },
                        else => return err,
                    };
                    flow.reply_len += res.n;
                    if (res.n == 0) break;
                }
                if (flow.reply_len < flow.reply.len) return; // echo still in flight
                if (!std.mem.eql(u8, flow.reply, flow.payload)) {
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
                // At least the `max_datagram_frame_size` we advertise
                // (1200): `receiveDatagram` pops the payload whether or
                // not it fit, so a short buffer loses the tail silently.
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

/// Run the full echo round-trip against `target` with the demo
/// message. Returns an error if any leg fails or `timeout_us` elapses.
/// Factored out of `main` so `echo_smoke.zig` can drive the identical
/// flow in-process.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    timeout_us: u64,
) !void {
    return runPayload(allocator, io, target, timeout_us, stream_message);
}

/// As `run`, but with a caller-chosen stream payload. `echo_smoke.zig`
/// uses this to round-trip something several times the server's
/// per-stream read chunk — the case where an echo loop that stops at
/// the first `fin` (or at the first short write) silently truncates.
pub fn runPayload(
    allocator: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    timeout_us: u64,
    payload: []const u8,
) !void {
    const protos = [_][]const u8{common.alpn};

    // The echo accumulator is exactly as long as what we sent, so
    // "every byte is back" is a length comparison.
    const reply = try allocator.alloc(u8, payload.len);
    defer allocator.free(reply);

    var client = try quic.Client.connect(.{
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

    std.debug.print(
        "[client] connecting to {s} (ALPN {s}, {d}-byte stream payload)\n",
        .{ target, common.alpn, payload.len },
    );

    var flow: EchoFlow = .{
        .deadline_us = timeout_us,
        .payload = payload,
        .reply = reply,
    };
    try quic.transport.runUdpClient(&client, .{
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
