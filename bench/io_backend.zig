//! Cross-backend socket benchmark: the SAME quic-zig server and client
//! loops (`transport.runUdpServer` / `transport.runUdpClient`) driven
//! by `std.Io.Threaded` and by `std.Io.Evented` (libdispatch + fibers
//! on macOS), selected at runtime. Real loopback UDP, one process: the
//! server loop runs as an `Io.Group` task, the client loop in the
//! caller, so each backend schedules the two loops its own way (a
//! thread under Threaded, a fiber on a GCD worker under Evented).
//!
//! Scenarios:
//!  - goodput: bulk upload client -> server on one stream. MB/s from
//!    `handshake_established` to FIN-acked, handshake latency, loop
//!    iterations, and process CPU time (user+sys, both loops) per MiB.
//!  - echo: RFC 9221 DATAGRAM ping-pong with one ping in flight.
//!    Round-trip latency percentiles and round trips per second. This
//!    is the backend's wake path (timed receive -> handle -> hook ->
//!    send) measured on its own, with almost no protocol work.
//!
//! ```sh
//! zig build bench-io -- --io both --scenario all --samples 5 --json report.json
//! ```
//!
//! `--io evented` needs a std where `std.Io.Evented` is not `void`
//! (on macOS: a fork checkout passed via `--zig-lib-dir`). `--leeway-ms`
//! sets `std.Io.Evented.InitOptions.leeway` (std default 10 ms), the
//! timer slack libdispatch is allowed on every timed wait.
//!
//! Pass/fail is completion only; rates are printed for humans and JSON.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");

const cert_pem = @embedFile("e2e/support/test_cert.pem");
const key_pem = @embedFile("e2e/support/test_key.pem");
const alpn = "bench-io/1";

const Backend = enum { threaded, evented };
const Scenario = enum { goodput, echo };

const Options = struct {
    backends: []const Backend = &.{ .threaded, .evented },
    scenarios: []const Scenario = &.{ .goodput, .echo },
    samples: usize = 5,
    mib: usize = 32,
    pings: usize = 1000,
    /// `std.Io.Evented.InitOptions.leeway` in ms; std default is 10.
    leeway_ms: i64 = 10,
    /// `RunUdpOptions.receive_timeout` / `RunUdpClientOptions.receive_timeout`.
    receive_timeout_ms: i64 = 5,
    json_path: ?[]const u8 = null,
};

const goodput_deadline_us: u64 = 180 * std.time.us_per_s;
const echo_deadline_us: u64 = 120 * std.time.us_per_s;
/// A lost ping would hang the echo flow; datagrams are not retransmitted.
const ping_stall_us: u64 = 2 * std.time.us_per_s;
const write_chunk_bytes: usize = 64 << 10;

fn transportParams() quic.tls.TransportParams {
    return .{
        .max_idle_timeout_ms = 30_000,
        .initial_max_data = 1 << 24,
        .initial_max_stream_data_bidi_local = 1 << 22,
        .initial_max_stream_data_bidi_remote = 1 << 22,
        .initial_max_stream_data_uni = 1 << 22,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 1200,
    };
}

// -- server: stream byte sink + datagram echo --------------------------------

const ServerApp = struct {
    allocator: std.mem.Allocator,
    ready: *std.atomic.Value(bool),
    iterations: u64 = 0,
    bytes_sunk: u64 = 0,
    datagrams_echoed: u64 = 0,

    const ConnState = struct {
        stream_id: u64 = 0,
        have_stream: bool = false,
        fin_drained: bool = false,
    };

    fn onIteration(ctx: ?*anyopaque, server: *quic.Server, now_us: u64) anyerror!void {
        _ = now_us;
        const app: *ServerApp = @ptrCast(@alignCast(ctx.?));
        app.iterations += 1;
        // First hook call: the socket is bound; the client may dial.
        app.ready.store(true, .release);
        for (server.iterator()) |slot| {
            while (slot.conn.pollEvent()) |event| switch (event) {
                .stream_opened => |info| {
                    if (!info.bidi) continue;
                    const st = try app.ensureState(slot);
                    st.stream_id = info.stream_id;
                    st.have_stream = true;
                },
                else => {},
            };

            // Echo every DATAGRAM verbatim.
            var dbuf: [2048]u8 = undefined;
            while (try slot.conn.receiveDatagram(&dbuf)) |n| {
                slot.conn.sendDatagram(dbuf[0..n]) catch |err| switch (err) {
                    error.DatagramUnavailable, error.DatagramTooLarge => {},
                    else => return err,
                };
                app.datagrams_echoed += 1;
            }

            // Sink stream bytes (same shape as examples/goodput_smoke.zig).
            const st = connState(slot) orelse continue;
            if (!st.have_stream or st.fin_drained) continue;
            var buf: [64 * 1024]u8 = undefined;
            while (true) {
                const n = slot.conn.streamRead(st.stream_id, &buf) catch |err| switch (err) {
                    error.StreamNotFound => {
                        st.fin_drained = true;
                        break;
                    },
                    else => return err,
                };
                app.bytes_sunk += n;
                if (n == 0) break;
            }
            if (!st.fin_drained) {
                if (slot.conn.streamRecvState(st.stream_id)) |rs| {
                    st.fin_drained = rs.terminal;
                } else {
                    st.fin_drained = true;
                }
            }
        }
    }

    fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
        const app: *ServerApp = @ptrCast(@alignCast(ctx.?));
        const st = connState(slot) orelse return;
        app.allocator.destroy(st);
        slot.user_data = null;
    }

    fn ensureState(app: *ServerApp, slot: *quic.Server.Slot) !*ConnState {
        if (connState(slot)) |st| return st;
        const st = try app.allocator.create(ConnState);
        st.* = .{};
        slot.user_data = st;
        return st;
    }

    fn connState(slot: *quic.Server.Slot) ?*ConnState {
        const ptr = slot.user_data orelse return null;
        return @ptrCast(@alignCast(ptr));
    }
};

const ServerTask = struct {
    app: *ServerApp,
    io: std.Io,
    listen: []const u8,
    shutdown: *const std.atomic.Value(bool),
    receive_timeout_ms: i64,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(task: *ServerTask) void {
        task.serve() catch |err| {
            std.debug.print("bench-io: server loop failed: {s}\n", .{@errorName(err)});
            task.failed.store(true, .release);
        };
    }

    fn serve(task: *ServerTask) !void {
        const protos = [_][]const u8{alpn};
        var server = try quic.Server.init(.{
            .allocator = task.app.allocator,
            .tls_cert_pem = cert_pem,
            .tls_key_pem = key_pem,
            .alpn_protocols = &protos,
            .transport_params = transportParams(),
            .on_connection_will_close = ServerApp.onConnectionWillClose,
            .on_connection_will_close_user_data = task.app,
        });
        defer server.deinit();
        try quic.transport.runUdpServer(&server, .{
            .listen = task.listen,
            .io = task.io,
            .shutdown_flag = task.shutdown,
            .shutdown_grace_us = 100_000,
            .receive_timeout = std.Io.Duration.fromMilliseconds(task.receive_timeout_ms),
            .tune_socket = false,
            .on_iteration = ServerApp.onIteration,
            .on_iteration_ctx = task.app,
        });
    }
};

// -- client flows --------------------------------------------------------------

const UploadFlow = struct {
    payload: []const u8,
    stream_id: u64 = 0,
    stage: enum { awaiting_handshake, uploading, awaiting_acks, done } = .awaiting_handshake,
    sent: usize = 0,
    handshake_us: ?u64 = null,
    start_us: ?u64 = null,
    finish_us: ?u64 = null,
    /// Process CPU time at `start_us` / `finish_us`, so the CPU number
    /// brackets exactly the same window as the rate.
    cpu_start_us: u64 = 0,
    cpu_finish_us: u64 = 0,
    iterations: u64 = 0,

    fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        const flow: *UploadFlow = @ptrCast(@alignCast(ctx.?));
        flow.iterations += 1;
        if (flow.stage == .done) return;
        if (now_us > goodput_deadline_us) return error.BenchTimedOut;

        while (client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                const stream = try client.conn.openNextBidi();
                flow.stream_id = stream.id;
                flow.stage = .uploading;
                flow.handshake_us = now_us;
                flow.start_us = now_us;
                flow.cpu_start_us = cpuTimeUs();
            },
            else => {},
        };

        switch (flow.stage) {
            .awaiting_handshake, .done => {},
            .uploading => {
                while (flow.sent < flow.payload.len) {
                    const end = @min(flow.sent + write_chunk_bytes, flow.payload.len);
                    const accepted = try client.conn.streamWrite(flow.stream_id, flow.payload[flow.sent..end]);
                    if (accepted == 0) return; // backpressure; resume next iteration
                    flow.sent += accepted;
                }
                try client.conn.streamFinish(flow.stream_id);
                flow.stage = .awaiting_acks;
            },
            .awaiting_acks => {
                const complete = if (client.conn.stream(flow.stream_id)) |s| s.send.fin_acked else true;
                if (!complete) return;
                flow.finish_us = now_us;
                flow.cpu_finish_us = cpuTimeUs();
                flow.stage = .done;
                client.conn.close(false, 0, "bench done");
            },
        }
    }
};

const EchoFlow = struct {
    rtts_us: []u64,
    done_count: usize = 0,
    stage: enum { awaiting_handshake, pinging, done } = .awaiting_handshake,
    seq: u64 = 0,
    in_flight_sent_us: ?u64 = null,
    handshake_us: ?u64 = null,
    first_ping_us: ?u64 = null,
    last_pong_us: ?u64 = null,
    cpu_start_us: u64 = 0,
    cpu_finish_us: u64 = 0,
    iterations: u64 = 0,

    fn onIteration(ctx: ?*anyopaque, client: *quic.Client, now_us: u64) anyerror!void {
        const flow: *EchoFlow = @ptrCast(@alignCast(ctx.?));
        flow.iterations += 1;
        if (flow.stage == .done) return;
        if (now_us > echo_deadline_us) return error.BenchTimedOut;

        while (client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                flow.stage = .pinging;
                flow.handshake_us = now_us;
            },
            else => {},
        };
        if (flow.stage != .pinging) return;

        if (flow.in_flight_sent_us) |sent_us| {
            var buf: [64]u8 = undefined;
            const n = (try client.conn.receiveDatagram(&buf)) orelse {
                if (now_us - sent_us > ping_stall_us) return error.PingLost;
                return; // echo still in flight
            };
            if (n != 16) return error.EchoMismatch;
            if (std.mem.readInt(u64, buf[0..8], .little) != flow.seq) return error.EchoMismatch;
            flow.rtts_us[flow.done_count] = now_us - sent_us;
            flow.done_count += 1;
            flow.seq += 1;
            flow.in_flight_sent_us = null;
            flow.last_pong_us = now_us;
            if (flow.done_count == flow.rtts_us.len) {
                flow.cpu_finish_us = cpuTimeUs();
                flow.stage = .done;
                client.conn.close(false, 0, "bench done");
                return;
            }
        }

        var payload: [16]u8 = undefined;
        std.mem.writeInt(u64, payload[0..8], flow.seq, .little);
        std.mem.writeInt(u64, payload[8..16], now_us, .little);
        try client.conn.sendDatagram(&payload);
        if (flow.first_ping_us == null) {
            flow.first_ping_us = now_us;
            flow.cpu_start_us = cpuTimeUs();
        }
        flow.in_flight_sent_us = now_us;
    }
};

const ClientTask = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    target: []const u8,
    receive_timeout_ms: i64,
    scenario: Scenario,
    payload: []const u8,
    rtts: []u64,
    upload: UploadFlow = undefined,
    echo: EchoFlow = undefined,
    err: ?anyerror = null,

    fn run(task: *ClientTask) void {
        task.drive() catch |err| {
            task.err = err;
        };
    }

    fn drive(task: *ClientTask) !void {
        const protos = [_][]const u8{alpn};
        var client = try quic.Client.connect(.{
            .allocator = task.gpa,
            .server_name = "localhost",
            .alpn_protocols = &protos,
            .transport_params = transportParams(),
            .insecure_skip_verify = true,
        });
        defer client.deinit();
        switch (task.scenario) {
            .goodput => {
                task.upload = .{ .payload = task.payload };
                try quic.transport.runUdpClient(&client, .{
                    .target = task.target,
                    .io = task.io,
                    .tune_socket = false,
                    .receive_timeout = std.Io.Duration.fromMilliseconds(task.receive_timeout_ms),
                    .on_iteration = UploadFlow.onIteration,
                    .on_iteration_ctx = &task.upload,
                });
            },
            .echo => {
                task.echo = .{ .rtts_us = task.rtts };
                try quic.transport.runUdpClient(&client, .{
                    .target = task.target,
                    .io = task.io,
                    .tune_socket = false,
                    .receive_timeout = std.Io.Duration.fromMilliseconds(task.receive_timeout_ms),
                    .on_iteration = EchoFlow.onIteration,
                    .on_iteration_ctx = &task.echo,
                });
            },
        }
    }
};

// -- measurement ----------------------------------------------------------------

const Sample = struct {
    backend: []const u8,
    scenario: []const u8,
    /// Whole sample: connect through the client loop's return (includes the
    /// handshake and the closing period; excludes server teardown).
    wall_ms: f64,
    cpu_total_ms: f64,
    /// Process CPU over exactly the measured window (transfer, or first
    /// ping to last pong). Both loops and the backend's workers count.
    cpu_ms: f64,
    handshake_ms: f64,
    client_iterations: u64,
    server_iterations: u64,
    // goodput
    mib: usize = 0,
    mib_per_sec: f64 = 0,
    cpu_ms_per_mib: f64 = 0,
    // echo
    pings: usize = 0,
    rtt_p50_us: f64 = 0,
    rtt_p90_us: f64 = 0,
    rtt_p99_us: f64 = 0,
    rtt_max_us: f64 = 0,
    round_trips_per_sec: f64 = 0,
};

const Summary = struct {
    backend: []const u8,
    scenario: []const u8,
    samples: usize,
    /// goodput: MiB/s; echo: round trips per second.
    rate_median: f64,
    rate_mad: f64,
    cpu_ms_median: f64,
    handshake_ms_median: f64,
    rtt_p50_us_median: f64,
    rtt_p99_us_median: f64,
};

const Report = struct {
    schema: []const u8 = "quic-zig-bench-io/2",
    zig_version: []const u8,
    os: []const u8,
    arch: []const u8,
    optimize: []const u8,
    cpu_count: usize,
    leeway_ms: i64,
    receive_timeout_ms: i64,
    mib: usize,
    pings: usize,
    summaries: []const Summary,
    samples: []const Sample,
};

fn cpuTimeUs() u64 {
    const ru = std.posix.getrusage(std.posix.rusage.SELF);
    return timevalUs(ru.utime) + timevalUs(ru.stime);
}

fn timevalUs(tv: anytype) u64 {
    const sec: u64 = @intCast(@max(0, tv.sec));
    const usec: u64 = @intCast(@max(0, tv.usec));
    return sec * std.time.us_per_s + usec;
}

fn elapsedUs(io: std.Io, start: std.Io.Timestamp) u64 {
    return quic.transport.udp_server.monotonicNowUs(io, start);
}

fn pickLoopbackPort(io: std.Io) !u16 {
    const probe_addr = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    const probe = try std.Io.net.IpAddress.bind(&probe_addr, io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    return probe.address.getPort();
}

fn runSample(
    gpa: std.mem.Allocator,
    io: std.Io,
    backend: Backend,
    scenario: Scenario,
    opts: Options,
    payload: []const u8,
    rtts: []u64,
) !Sample {
    const port = try pickLoopbackPort(io);
    var addr_buf: [32]u8 = undefined;
    const addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{port});

    var shutdown = std.atomic.Value(bool).init(false);
    var ready = std.atomic.Value(bool).init(false);
    var app: ServerApp = .{ .allocator = gpa, .ready = &ready };
    var task: ServerTask = .{
        .app = &app,
        .io = io,
        .listen = addr,
        .shutdown = &shutdown,
        .receive_timeout_ms = opts.receive_timeout_ms,
    };

    // The server loop is a Group task: a thread under Threaded, a fiber
    // on a dispatch worker under Evented. Defers run in reverse: flip
    // the flag, then wait for the loop to drain and return.
    var group: std.Io.Group = .init;
    try group.concurrent(io, ServerTask.run, .{&task});
    defer group.await(io) catch {};
    defer shutdown.store(true, .release);

    var waited: usize = 0;
    while (!ready.load(.acquire)) : (waited += 1) {
        if (task.failed.load(.acquire)) return error.ServerLoopFailed;
        if (waited > 10_000) return error.ServerNotReady;
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }

    const cpu_before = cpuTimeUs();
    const t0 = std.Io.Timestamp.now(io, .awake);
    var sample: Sample = .{
        .backend = @tagName(backend),
        .scenario = @tagName(scenario),
        .wall_ms = 0,
        .cpu_total_ms = 0,
        .cpu_ms = 0,
        .handshake_ms = 0,
        .client_iterations = 0,
        .server_iterations = 0,
    };
    // The client loop is a Group task as well, so under Threaded neither loop
    // sits on the process main thread (which has a higher scheduling class
    // on macOS than the pthread the server task gets).
    var client_task: ClientTask = .{
        .gpa = gpa,
        .io = io,
        .target = addr,
        .receive_timeout_ms = opts.receive_timeout_ms,
        .scenario = scenario,
        .payload = payload,
        .rtts = rtts,
    };
    var client_group: std.Io.Group = .init;
    try client_group.concurrent(io, ClientTask.run, .{&client_task});
    try client_group.await(io);
    if (client_task.err) |err| return err;
    switch (scenario) {
        .goodput => {
            const flow = &client_task.upload;
            if (flow.stage != .done) return error.GoodputIncomplete;
            const transfer_us = flow.finish_us.? - flow.start_us.?;
            const secs = @as(f64, @floatFromInt(transfer_us)) / 1e6;
            sample.mib = payload.len >> 20;
            sample.mib_per_sec = if (secs <= 0) 0 else @as(f64, @floatFromInt(payload.len)) / (1024.0 * 1024.0) / secs;
            sample.handshake_ms = @as(f64, @floatFromInt(flow.handshake_us.?)) / 1e3;
            sample.client_iterations = flow.iterations;
            sample.cpu_ms = @as(f64, @floatFromInt(flow.cpu_finish_us - flow.cpu_start_us)) / 1e3;
        },
        .echo => {
            const flow = &client_task.echo;
            if (flow.stage != .done) return error.EchoIncomplete;
            std.mem.sort(u64, rtts, {}, std.sort.asc(u64));
            sample.pings = rtts.len;
            sample.rtt_p50_us = @floatFromInt(percentile(rtts, 50));
            sample.rtt_p90_us = @floatFromInt(percentile(rtts, 90));
            sample.rtt_p99_us = @floatFromInt(percentile(rtts, 99));
            sample.rtt_max_us = @floatFromInt(rtts[rtts.len - 1]);
            const span_us = flow.last_pong_us.? - flow.first_ping_us.?;
            sample.round_trips_per_sec = if (span_us == 0) 0 else @as(f64, @floatFromInt(rtts.len)) * 1e6 / @as(f64, @floatFromInt(span_us));
            sample.handshake_ms = @as(f64, @floatFromInt(flow.handshake_us.?)) / 1e3;
            sample.client_iterations = flow.iterations;
            sample.cpu_ms = @as(f64, @floatFromInt(flow.cpu_finish_us - flow.cpu_start_us)) / 1e3;
        },
    }
    const wall_us = elapsedUs(io, t0);
    const cpu_us = cpuTimeUs() - cpu_before;
    sample.wall_ms = @as(f64, @floatFromInt(wall_us)) / 1e3;
    sample.cpu_total_ms = @as(f64, @floatFromInt(cpu_us)) / 1e3;
    if (scenario == .goodput and sample.mib > 0) {
        sample.cpu_ms_per_mib = sample.cpu_ms / @as(f64, @floatFromInt(sample.mib));
    }

    // Stop the server before reading its counters.
    shutdown.store(true, .release);
    try group.await(io);
    if (task.failed.load(.acquire)) return error.ServerLoopFailed;
    sample.server_iterations = app.iterations;
    return sample;
}

fn percentile(sorted: []const u64, p: usize) u64 {
    if (sorted.len == 0) return 0;
    const idx = (sorted.len - 1) * p / 100;
    return sorted[idx];
}

fn medianF(values: []f64) f64 {
    std.mem.sort(f64, values, {}, std.sort.asc(f64));
    const n = values.len;
    if (n == 0) return 0;
    return if (n % 2 == 1) values[n / 2] else (values[n / 2 - 1] + values[n / 2]) / 2.0;
}

fn madF(values: []const f64, median: f64, scratch: []f64) f64 {
    for (values, 0..) |v, i| scratch[i] = @abs(v - median);
    return medianF(scratch[0..values.len]);
}

fn runBackend(
    gpa: std.mem.Allocator,
    io: std.Io,
    backend: Backend,
    opts: Options,
    payload: []const u8,
    rtts: []u64,
    samples: *std.ArrayList(Sample),
) !void {
    for (opts.scenarios) |scenario| {
        for (0..opts.samples) |i| {
            const s = try runSample(gpa, io, backend, scenario, opts, payload, rtts);
            switch (scenario) {
                .goodput => std.debug.print(
                    "{s}/{s} sample {d}/{d}: {d:.1} MiB/s ({d} MiB; sample {d:.0} ms; handshake {d:.2} ms; cpu {d:.0} ms in window, {d:.0} ms total; client iters {d}, server iters {d})\n",
                    .{ @tagName(backend), @tagName(scenario), i + 1, opts.samples, s.mib_per_sec, s.mib, s.wall_ms, s.handshake_ms, s.cpu_ms, s.cpu_total_ms, s.client_iterations, s.server_iterations },
                ),
                .echo => std.debug.print(
                    "{s}/{s} sample {d}/{d}: {d:.0} rt/s (p50 {d:.0} us, p90 {d:.0} us, p99 {d:.0} us, max {d:.0} us; handshake {d:.2} ms; cpu {d:.0} ms in window, {d:.0} ms total)\n",
                    .{ @tagName(backend), @tagName(scenario), i + 1, opts.samples, s.round_trips_per_sec, s.rtt_p50_us, s.rtt_p90_us, s.rtt_p99_us, s.rtt_max_us, s.handshake_ms, s.cpu_ms, s.cpu_total_ms },
                ),
            }
            try samples.append(gpa, s);
        }
    }
}

fn summarize(gpa: std.mem.Allocator, opts: Options, samples: []const Sample) ![]Summary {
    var out: std.ArrayList(Summary) = .empty;
    const vals = try gpa.alloc(f64, opts.samples);
    defer gpa.free(vals);
    const scratch = try gpa.alloc(f64, opts.samples);
    defer gpa.free(scratch);
    for (opts.backends) |backend| for (opts.scenarios) |scenario| {
        var n: usize = 0;
        for (samples) |s| {
            if (!std.mem.eql(u8, s.backend, @tagName(backend)) or !std.mem.eql(u8, s.scenario, @tagName(scenario))) continue;
            vals[n] = if (scenario == .goodput) s.mib_per_sec else s.round_trips_per_sec;
            n += 1;
        }
        if (n == 0) continue;
        const rate_median = medianF(vals[0..n]);
        const rate_mad = madF(vals[0..n], rate_median, scratch);
        var k: usize = 0;
        for (samples) |s| {
            if (!std.mem.eql(u8, s.backend, @tagName(backend)) or !std.mem.eql(u8, s.scenario, @tagName(scenario))) continue;
            vals[k] = s.cpu_ms;
            k += 1;
        }
        const cpu_median = medianF(vals[0..k]);
        k = 0;
        for (samples) |s| {
            if (!std.mem.eql(u8, s.backend, @tagName(backend)) or !std.mem.eql(u8, s.scenario, @tagName(scenario))) continue;
            vals[k] = s.handshake_ms;
            k += 1;
        }
        const hs_median = medianF(vals[0..k]);
        k = 0;
        for (samples) |s| {
            if (!std.mem.eql(u8, s.backend, @tagName(backend)) or !std.mem.eql(u8, s.scenario, @tagName(scenario))) continue;
            vals[k] = s.rtt_p50_us;
            k += 1;
        }
        const p50_median = medianF(vals[0..k]);
        k = 0;
        for (samples) |s| {
            if (!std.mem.eql(u8, s.backend, @tagName(backend)) or !std.mem.eql(u8, s.scenario, @tagName(scenario))) continue;
            vals[k] = s.rtt_p99_us;
            k += 1;
        }
        const p99_median = medianF(vals[0..k]);
        try out.append(gpa, .{
            .backend = @tagName(backend),
            .scenario = @tagName(scenario),
            .samples = n,
            .rate_median = rate_median,
            .rate_mad = rate_mad,
            .cpu_ms_median = cpu_median,
            .handshake_ms_median = hs_median,
            .rtt_p50_us_median = p50_median,
            .rtt_p99_us_median = p99_median,
        });
    };
    return out.toOwnedSlice(gpa);
}

fn usage() void {
    std.debug.print(
        \\usage: quic-zig-bench-io [--io threaded|evented|both] [--scenario goodput|echo|all]
        \\                         [--samples N] [--mib N] [--pings N] [--leeway-ms N]
        \\                         [--receive-timeout-ms N] [--json PATH]
        \\
    , .{});
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    var opts: Options = .{};

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--io")) {
            const v = args.next() orelse return usage();
            opts.backends = if (std.mem.eql(u8, v, "threaded")) &.{.threaded} else if (std.mem.eql(u8, v, "evented")) &.{.evented} else if (std.mem.eql(u8, v, "both")) &.{ .threaded, .evented } else return usage();
        } else if (std.mem.eql(u8, arg, "--scenario")) {
            const v = args.next() orelse return usage();
            opts.scenarios = if (std.mem.eql(u8, v, "goodput")) &.{.goodput} else if (std.mem.eql(u8, v, "echo")) &.{.echo} else if (std.mem.eql(u8, v, "all")) &.{ .goodput, .echo } else return usage();
        } else if (std.mem.eql(u8, arg, "--samples")) {
            opts.samples = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        } else if (std.mem.eql(u8, arg, "--mib")) {
            opts.mib = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        } else if (std.mem.eql(u8, arg, "--pings")) {
            opts.pings = try std.fmt.parseInt(usize, args.next() orelse return usage(), 10);
        } else if (std.mem.eql(u8, arg, "--leeway-ms")) {
            opts.leeway_ms = try std.fmt.parseInt(i64, args.next() orelse return usage(), 10);
        } else if (std.mem.eql(u8, arg, "--receive-timeout-ms")) {
            opts.receive_timeout_ms = try std.fmt.parseInt(i64, args.next() orelse return usage(), 10);
        } else if (std.mem.eql(u8, arg, "--json")) {
            opts.json_path = args.next() orelse return usage();
        } else {
            usage();
            return error.InvalidArgument;
        }
    }
    if (opts.samples == 0 or opts.samples > 64) return error.InvalidArgument;

    const payload = try gpa.alloc(u8, opts.mib << 20);
    defer gpa.free(payload);
    var prng = std.Random.DefaultPrng.init(0x10b3);
    prng.random().bytes(payload);
    const rtts = try gpa.alloc(u64, opts.pings);
    defer gpa.free(rtts);

    var samples: std.ArrayList(Sample) = .empty;
    defer samples.deinit(gpa);

    for (opts.backends) |backend| switch (backend) {
        .threaded => {
            var threaded: std.Io.Threaded = .init(gpa, .{});
            defer threaded.deinit();
            try runBackend(gpa, threaded.io(), backend, opts, payload, rtts, &samples);
        },
        .evented => {
            const Evented = std.Io.Evented;
            if (Evented == void) {
                std.debug.print("bench-io: std.Io.Evented is void on {s}-{s} with this std; skipping evented\n", .{ @tagName(builtin.cpu.arch), @tagName(builtin.os.tag) });
            } else {
                var evented: Evented = undefined;
                // `leeway` (timer slack) exists only on the libdispatch
                // backend; the io_uring and kqueue backends take defaults.
                const evented_options: Evented.InitOptions = if (Evented == std.Io.Dispatch) .{
                    .leeway = std.Io.Duration.fromMilliseconds(opts.leeway_ms),
                } else .{};
                try Evented.init(&evented, gpa, evented_options);
                defer evented.deinit();
                try runBackend(gpa, evented.io(), backend, opts, payload, rtts, &samples);
            }
        },
    };

    const summaries = try summarize(gpa, opts, samples.items);
    defer gpa.free(summaries);
    std.debug.print("\n== summary (median of {d} samples, +/- MAD) ==\n", .{opts.samples});
    for (summaries) |s| {
        if (std.mem.eql(u8, s.scenario, "goodput")) {
            std.debug.print("{s:<9} goodput: {d:8.1} +/- {d:5.1} MiB/s  cpu {d:7.0} ms   handshake {d:6.2} ms\n", .{ s.backend, s.rate_median, s.rate_mad, s.cpu_ms_median, s.handshake_ms_median });
        } else {
            std.debug.print("{s:<9} echo:    {d:8.0} +/- {d:5.0} rt/s   p50 {d:6.0} us   p99 {d:6.0} us   cpu {d:6.0} ms\n", .{ s.backend, s.rate_median, s.rate_mad, s.rtt_p50_us_median, s.rtt_p99_us_median, s.cpu_ms_median });
        }
    }

    if (opts.json_path) |path| {
        const report: Report = .{
            .zig_version = builtin.zig_version_string,
            .os = @tagName(builtin.os.tag),
            .arch = @tagName(builtin.cpu.arch),
            .optimize = @tagName(builtin.mode),
            .cpu_count = std.Thread.getCpuCount() catch 0,
            .leeway_ms = opts.leeway_ms,
            .receive_timeout_ms = opts.receive_timeout_ms,
            .mib = opts.mib,
            .pings = opts.pings,
            .summaries = summaries,
            .samples = samples.items,
        };
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try aw.writer.print("{f}\n", .{std.json.fmt(report, .{ .whitespace = .indent_2 })});
        const io = init.io;
        const file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, aw.written());
        std.debug.print("wrote {s}\n", .{path});
    }
}
