//! One-process smoke harness for the echo example pair: runs the
//! `echo_server.zig` loop on a background thread, drives the
//! `echo_client.zig` round-trip against it over real loopback UDP,
//! and exits non-zero unless the full stream + datagram echo
//! actually happened.
//!
//! ```sh
//! zig build run-echo-smoke
//! ```
//!
//! Two legs run against the same server: the canonical demo message,
//! then a payload several times the server's per-stream read chunk.
//! The second one is the regression gate for the multi-chunk echo path
//! — an echo loop that treats `StreamReadResult.fin` as "all data
//! read", or that assumes `streamWrite` accepts everything, returns a
//! truncated stream and fails here.
//!
//! What neither leg can gate is a *gap*. Loopback delivers in order,
//! and both payloads fit one datagram, so a chunk below the read offset
//! is never missing here — and "empty read + FIN seen" (the other way
//! to truncate a stream, see `echo_server_raw.echoStream`) needs
//! exactly that. The reordering regression test for it is the in-memory one in
//! `foreign_loop_embedder.zig`, which holds a datagram back on purpose.
//!
//! This is a standalone binary (not a `zig build test` target) so it
//! can exercise real sockets, threads, and both `runUdp*` loops
//! end-to-end without dragging network flakiness into the unit-test
//! suite. CI runs it on the Linux leg.

const std = @import("std");
const echo_server = @import("echo_server.zig");
const echo_client = @import("echo_client.zig");

/// Overall give-up budget for the client round-trip. Generous: it
/// covers a lost first flight (recovered by PTO retransmit if the
/// client's Initial beats the server thread to the socket) with a
/// wide margin for slow CI runners.
const client_timeout_us: u64 = 30 * std.time.us_per_s;

/// Payload length for the second round-trip. Chosen so the multi-chunk
/// path is not just exercised but *unavoidable and deterministic*:
/// larger than the server's per-stream read chunk, yet small enough to
/// still arrive in a single QUIC datagram. The server's first read
/// therefore always comes back full with the peer's FIN already seen —
/// exactly the shape an echo loop truncates if it honours `fin` before
/// draining. A payload spanning several datagrams walks the same loops,
/// but which read sees the FIN then depends on packetization, so it
/// makes a weaker gate.
const large_payload_len: usize = echo_server.stream_chunk_bytes + 76;

const ServerTask = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown: *const std.atomic.Value(bool),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(task: *ServerTask) void {
        echo_server.serve(task.allocator, task.io, task.listen, task.shutdown) catch |err| {
            std.debug.print("echo-smoke: server loop failed: {s}\n", .{@errorName(err)});
            task.failed.store(true, .release);
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // Pick a free loopback UDP port: bind :0, read the resolved
    // ephemeral port back off the socket, release it. (The tiny
    // close-to-rebind race is acceptable for a smoke harness;
    // `runUdpServer` owns its socket, so we can't bind-and-hand-off.)
    const port: u16 = blk: {
        const probe_addr = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
        const probe = try std.Io.net.IpAddress.bind(&probe_addr, io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        defer probe.close(io);
        break :blk probe.address.getPort();
    };
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port});

    var shutdown = std.atomic.Value(bool).init(false);
    var task: ServerTask = .{
        .allocator = allocator,
        .io = io,
        .listen = addr,
        .shutdown = &shutdown,
    };

    const server_thread = try std.Thread.spawn(.{}, ServerTask.run, .{&task});
    // Deferred in reverse order: flip the flag first, then join, so
    // the server thread always winds down — including on the error
    // paths below.
    defer server_thread.join();
    defer shutdown.store(true, .release);

    // Let the server thread reach its bind before the client's first
    // Initial. Not load-bearing (a lost first flight is retransmitted
    // on PTO); it just keeps the happy path fast.
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake);

    // Leg 1: the canonical demo message. The client's `run` only
    // returns cleanly when the stream echo AND the datagram echo both
    // round-tripped (`EchoIncomplete` otherwise, `EchoTimedOut` past
    // the deadline) — that is the smoke assertion.
    echo_client.run(allocator, io, addr, client_timeout_us) catch |err| {
        std.debug.print("echo-smoke: FAIL (small payload: {s})\n", .{@errorName(err)});
        return err;
    };

    // Leg 2: a payload longer than one server read chunk, on a fresh
    // connection. Same assertion, but it exercises the multi-chunk
    // drain and the staged write-back; the client compares the echo
    // byte-for-byte, so a truncated or reordered echo fails here.
    const large = try allocator.alloc(u8, large_payload_len);
    defer allocator.free(large);
    for (large, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    echo_client.runPayload(allocator, io, addr, client_timeout_us, large) catch |err| {
        std.debug.print("echo-smoke: FAIL (large payload: {s})\n", .{@errorName(err)});
        return err;
    };

    if (task.failed.load(.acquire)) {
        std.debug.print("echo-smoke: FAIL (server loop error)\n", .{});
        return error.ServerLoopFailed;
    }

    std.debug.print(
        "echo-smoke: PASS (stream + datagram echo round-tripped on {s}; " ++
            "payloads {d} and {d} bytes)\n",
        .{ addr, echo_client.stream_message.len, large_payload_len },
    );
}
