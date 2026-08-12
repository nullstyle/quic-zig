//! One-process goodput smoke over real loopback UDP: the
//! `echo_smoke.zig` shape (server loop on a background thread, client
//! loop to completion), but the server is a byte sink and the client
//! measures how fast a bulk upload lands.
//!
//! ```sh
//! zig build run-goodput-smoke
//! ```
//!
//! This is the wrapper-loop counterpart to `zig build bench-e2e
//! --scenario goodput`: the in-process bench isolates stack CPU cost,
//! while this binary pays for real sockets, syscalls-per-datagram, and
//! loop wakeups — exactly the costs the batched-datapath work targets,
//! so its MB/s line is the number that shows the before/after.
//!
//! Pass/fail is COMPLETION ONLY (every byte delivered, FIN acked,
//! clean close, inside the deadline). The measured rate is printed for
//! humans and CI logs but never asserted — loopback throughput on a
//! shared runner is far too noisy to gate on.

const std = @import("std");
const quic_zig = @import("quic_zig");
const common = @import("echo_common.zig");

/// Bulk payload pushed client -> server.
const total_bytes: usize = 16 << 20;

/// Slice size per streamWrite offer.
const write_chunk_bytes: usize = 64 << 10;

/// Server-side per-pass read buffer.
const read_chunk_bytes: usize = 64 << 10;

/// Give-up budget for the whole upload; generous for slow CI runners.
const deadline_us: u64 = 120 * std.time.us_per_s;

// -- server: a stream byte sink ---------------------------------------------

const SinkState = struct {
    stream_id: u64 = 0,
    have_stream: bool = false,
    consumed: u64 = 0,
    fin_drained: bool = false,
};

const SinkApp = struct {
    allocator: std.mem.Allocator,

    pub fn onIteration(ctx: ?*anyopaque, server: *quic_zig.Server, now_us: u64) anyerror!void {
        _ = now_us;
        const app: *SinkApp = @ptrCast(@alignCast(ctx.?));
        for (server.iterator()) |slot| {
            while (slot.conn.pollEvent()) |event| switch (event) {
                .stream_opened => |info| {
                    if (!info.bidi) continue;
                    const state = try app.ensureState(slot);
                    state.stream_id = info.stream_id;
                    state.have_stream = true;
                },
                else => {},
            };

            const state = sinkState(slot) orelse continue;
            if (!state.have_stream or state.fin_drained) continue;

            var buf: [read_chunk_bytes]u8 = undefined;
            while (true) {
                const res = slot.conn.streamReadFin(state.stream_id, &buf) catch |err| switch (err) {
                    // Reaped after both halves went terminal — everything
                    // was already drained.
                    error.StreamNotFound => {
                        state.fin_drained = true;
                        break;
                    },
                    else => return err,
                };
                state.consumed += res.n;
                if (res.n == 0) {
                    if (res.fin) state.fin_drained = true;
                    break;
                }
            }
        }
    }

    pub fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic_zig.Server.Slot) void {
        const app: *SinkApp = @ptrCast(@alignCast(ctx.?));
        const state = sinkState(slot) orelse return;
        std.debug.print(
            "[server] conn {d}: sank {d} bytes (fin drained: {})\n",
            .{ slot.slot_id, state.consumed, state.fin_drained },
        );
        app.allocator.destroy(state);
        slot.user_data = null;
    }

    fn ensureState(app: *SinkApp, slot: *quic_zig.Server.Slot) !*SinkState {
        if (sinkState(slot)) |state| return state;
        const state = try app.allocator.create(SinkState);
        state.* = .{};
        slot.user_data = state;
        return state;
    }
};

fn sinkState(slot: *quic_zig.Server.Slot) ?*SinkState {
    const ptr = slot.user_data orelse return null;
    return @ptrCast(@alignCast(ptr));
}

fn serveSink(
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown_flag: *const std.atomic.Value(bool),
) !void {
    var app: SinkApp = .{ .allocator = allocator };
    const protos = [_][]const u8{common.alpn};

    var server = try quic_zig.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = SinkApp.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
    });
    defer server.deinit();

    try quic_zig.transport.runUdpServer(&server, .{
        .listen = listen,
        .io = io,
        .shutdown_flag = shutdown_flag,
        .tune_socket = false,
        .on_iteration = SinkApp.onIteration,
        .on_iteration_ctx = &app,
    });
}

const ServerTask = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listen: []const u8,
    shutdown: *const std.atomic.Value(bool),
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(task: *ServerTask) void {
        serveSink(task.allocator, task.io, task.listen, task.shutdown) catch |err| {
            std.debug.print("goodput-smoke: server loop failed: {s}\n", .{@errorName(err)});
            task.failed.store(true, .release);
        };
    }
};

// -- client: timed bulk upload ------------------------------------------------

const UploadFlow = struct {
    payload: []const u8,
    stream_id: u64 = 0,
    stage: Stage = .awaiting_handshake,
    sent: usize = 0,
    fin_sent: bool = false,
    start_us: ?u64 = null,
    finish_us: ?u64 = null,

    const Stage = enum { awaiting_handshake, uploading, awaiting_acks, done };

    pub fn onIteration(ctx: ?*anyopaque, client: *quic_zig.Client, now_us: u64) anyerror!void {
        const flow: *UploadFlow = @ptrCast(@alignCast(ctx.?));
        if (flow.stage == .done) return;
        if (now_us > deadline_us) return error.GoodputTimedOut;

        while (client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                const stream = try client.conn.openNextBidi();
                flow.stream_id = stream.id;
                flow.stage = .uploading;
                flow.start_us = now_us;
                std.debug.print("[client] handshake established; uploading {d} MiB\n", .{total_bytes >> 20});
            },
            else => {},
        };

        switch (flow.stage) {
            .awaiting_handshake, .done => {},
            .uploading => {
                while (flow.sent < flow.payload.len) {
                    const end = @min(flow.sent + write_chunk_bytes, flow.payload.len);
                    const accepted = try client.conn.streamWrite(
                        flow.stream_id,
                        flow.payload[flow.sent..end],
                    );
                    if (accepted == 0) return; // backpressure; resume next iteration
                    flow.sent += accepted;
                }
                try client.conn.streamFinish(flow.stream_id);
                flow.fin_sent = true;
                flow.stage = .awaiting_acks;
            },
            .awaiting_acks => {
                // Complete once the FIN is acked (which implies every
                // byte before it was delivered and acked) — or once the
                // stream was reaped, which requires exactly that.
                const complete = if (client.conn.stream(flow.stream_id)) |s|
                    s.send.fin_acked
                else
                    true;
                if (!complete) return;
                flow.finish_us = now_us;
                flow.stage = .done;
                client.conn.close(false, 0, "goodput done");
            },
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // Same free-port dance as echo_smoke: bind :0, read the port back,
    // release it and hand the address to the real loops.
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
    defer server_thread.join();
    defer shutdown.store(true, .release);

    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake);

    const payload = try allocator.alloc(u8, total_bytes);
    defer allocator.free(payload);
    var prng = std.Random.DefaultPrng.init(0x900d);
    prng.random().bytes(payload);

    const protos = [_][]const u8{common.alpn};
    var client = try quic_zig.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        // Demo posture: the sink server presents the self-signed test
        // certificate.
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    var flow: UploadFlow = .{ .payload = payload };
    try quic_zig.transport.runUdpClient(&client, .{
        .target = addr,
        .io = io,
        .tune_socket = false,
        .on_iteration = UploadFlow.onIteration,
        .on_iteration_ctx = &flow,
    });

    if (flow.stage != .done) {
        std.debug.print("goodput-smoke: FAIL (stage {s} at loop exit)\n", .{@tagName(flow.stage)});
        return error.GoodputIncomplete;
    }
    if (task.failed.load(.acquire)) {
        std.debug.print("goodput-smoke: FAIL (server loop error)\n", .{});
        return error.ServerLoopFailed;
    }

    const elapsed_us = flow.finish_us.? - flow.start_us.?;
    const secs = @as(f64, @floatFromInt(elapsed_us)) / 1e6;
    const mb_per_sec = if (secs <= 0) 0 else @as(f64, @floatFromInt(total_bytes)) / (1024.0 * 1024.0) / secs;
    std.debug.print(
        "goodput-smoke: PASS ({d} MiB uploaded + FIN-acked over {s} in {d} ms -> {d:.1} MB/s; informational, not asserted)\n",
        .{ total_bytes >> 20, addr, elapsed_us / std.time.us_per_ms, mb_per_sec },
    );
}
