//! Multi-flow fairness cells: N independent client/server Connection
//! pairs whose data directions share ONE SimNet bottleneck link, each
//! sender greedy (always more to write, never finishing), measured
//! over a fixed virtual window after a warmup. This is the instrument
//! the DEFAULT-FLIP GATE in src/conn/congestion/Bbr.zig demands: the
//! single-flow impairment cells cannot observe inter-flow dynamics
//! (§5.3.3.8 Reno/CUBIC coexistence) at all.
//!
//! Everything is virtual-time deterministic for a fixed seed and
//! option set, like the impairment cells: per-flow goodput and the
//! Jain index are exact numbers, not samples.

const std = @import("std");
const quic = @import("quic");
const sim_net = @import("sim_net.zig");
const harness = @import("harness.zig");

pub const max_flows = 8;

pub const FlowSpec = struct {
    congestion_control: quic.CongestionAlgorithm = .cubic,
    /// Server-side override; null = same as the client. Diagnosis
    /// lever only.
    server_congestion_control: ?quic.CongestionAlgorithm = null,
    hystart: bool = true,
    /// Virtual sending-start offset from the run origin. The pair is
    /// created (and TLS-handshaked in memory) up front either way;
    /// this delays the first byte of data, modelling a late joiner.
    start_us: u64 = 0,
};

pub const FairnessOptions = struct {
    name: []const u8,
    flows: []const FlowSpec,
    seed: u64 = 0xbe9c4,
    tick_us: u64 = 100,
    chunk_bytes: usize = 64 << 10,
    /// Shared bottleneck. Unlike ImpairmentOptions this has no
    /// unlimited default: a fairness cell without a contended link
    /// measures nothing.
    bottleneck_bytes_per_s: u64 = 1_250_000,
    max_queue_delay_us: u64 = 100_000,
    loss_permille: u16 = 0,
    reorder_permille: u16 = 0,
    base_delay_us: u64 = 1_000,
    /// Startup transient excluded from measurement, counted from the
    /// LAST flow's start_us — a staggered joiner gets its own warmup.
    warmup_us: u64 = 5 * std.time.us_per_s,
    /// Measurement window; per-flow goodput and the Jain index are
    /// computed over exactly this span.
    measure_us: u64 = 20 * std.time.us_per_s,
    /// Non-zero: print a per-flow sender timeline (delta bytes, cwnd,
    /// inflight, RTTs, sent/lost) every this many virtual us. A
    /// diagnosis aid, off for the recorded cells.
    timeline_every_us: u64 = 0,
    /// Flow-control ceilings, threaded to every pair (harness
    /// defaults; a diagnosis lever for separating congestion behavior
    /// from flow-control credit behavior).
    initial_max_data: u64 = 1 << 24,
    initial_max_stream_data: u64 = 1 << 22,
};

pub const FairnessResult = struct {
    name: []const u8,
    flow_count: u32,
    /// Bytes each flow's server consumed inside the measure window.
    measured_bytes: [max_flows]u64,
    /// Measured goodput per flow, Mbit/s (bits per virtual us).
    goodput_mbps: [max_flows]f64,
    /// Fraction of the measured aggregate, 0..1.
    share: [max_flows]f64,
    cc: [max_flows]quic.CongestionAlgorithm,
    start_us: [max_flows]u64,
    /// Jain fairness index over measured bytes: (sum x)^2 / (n * sum x^2).
    /// 1.0 = perfectly even, 1/n = one flow took everything.
    jain_index: f64,
    aggregate_mbps: f64,
    /// Measured aggregate as a fraction of the link rate.
    utilization: f64,
    measure_window_us: u64,
    virtual_us: u64,
    seed: u64,
    enqueued: u64,
    dropped: u64,
    queue_dropped: u64,
    peak_queue_delay_us: u64,
};

/// One fairness cell through the shared-bottleneck net, measured in
/// VIRTUAL time — deterministic for a given seed and option set.
pub fn runFairnessOnce(allocator: std.mem.Allocator, opts: FairnessOptions) !FairnessResult {
    const flow_count: u32 = @intCast(opts.flows.len);
    std.debug.assert(flow_count >= 2 and flow_count <= max_flows);
    std.debug.assert(opts.bottleneck_bytes_per_s != 0);

    var pairs: [max_flows]*harness.Pair = undefined;
    var created: u32 = 0;
    defer {
        var i: u32 = 0;
        while (i < created) : (i += 1) pairs[i].destroy(allocator);
    }
    for (opts.flows, 0..) |spec, i| {
        pairs[i] = try harness.Pair.create(allocator, .{
            .congestion_control = spec.congestion_control,
            .server_congestion_control = spec.server_congestion_control,
            .hystart = spec.hystart,
            .initial_max_data = opts.initial_max_data,
            .initial_max_stream_data = opts.initial_max_stream_data,
        });
        created += 1;
    }

    var net = sim_net.SimNet.init(allocator, .{
        .seed = opts.seed,
        .loss_permille = opts.loss_permille,
        .reorder_permille = opts.reorder_permille,
        .base_delay_us = opts.base_delay_us,
        .bottleneck_bytes_per_s = opts.bottleneck_bytes_per_s,
        .max_queue_delay_us = opts.max_queue_delay_us,
    });
    defer net.deinit();

    var endpoints: [max_flows]sim_net.Endpoints = undefined;
    for (0..flow_count) |i| {
        endpoints[i] = .{ .client = &pairs[i].client, .server = &pairs[i].server };
    }

    const data = try allocator.alloc(u8, opts.chunk_bytes);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(opts.seed);
    prng.random().bytes(data);

    var rbuf: [64 << 10]u8 = undefined;
    var pkt: [2048]u8 = undefined;

    for (0..flow_count) |i| _ = try pairs[i].client.openBidi(0);

    var last_start: u64 = 0;
    for (opts.flows) |spec| last_start = @max(last_start, spec.start_us);

    const virtual_start: u64 = 1_000_000;
    const measure_start_abs = virtual_start + last_start + opts.warmup_us;
    const measure_end_abs = measure_start_abs + opts.measure_us;

    var consumed: [max_flows]u64 = @splat(0);
    var consumed_at_snap: [max_flows]u64 = @splat(0);
    var snap_at_us: u64 = 0;
    var snapped = false;

    var next_sample_us: u64 = virtual_start;
    var prev_consumed: [max_flows]u64 = @splat(0);

    var now_us: u64 = virtual_start;
    while (now_us < measure_end_abs) {
        if (opts.timeline_every_us != 0 and now_us >= next_sample_us) {
            for (0..flow_count) |i| {
                const st = pairs[i].client.stats();
                std.debug.print(
                    "  t={d:>3}s f{d}({s}): +{d:>6} B cwnd={d:>6} inflight={d:>6} srtt={d:>6}us minrtt={d:>5}us sent={d:>6} lost={d}\n",
                    .{
                        (now_us - virtual_start) / std.time.us_per_s,
                        i,
                        @tagName(opts.flows[i].congestion_control),
                        consumed[i] - prev_consumed[i],
                        st.cwnd,
                        st.bytes_in_flight,
                        st.smoothed_rtt_us,
                        st.min_rtt_us,
                        st.packets_sent,
                        st.packets_lost,
                    },
                );
                prev_consumed[i] = consumed[i];
                // Server-side (receiver) send machinery: the pacer
                // bucket and the controller's rate/cwnd. A receiver
                // that owes flow-control credit but cannot pass the
                // send gate shows up here as negative tokens or a
                // degenerate rate.
                const spath = &pairs[i].server.paths.paths.items[0].path;
                const srate = spath.cc.pacingRateBps(spath.rtt.smoothed_rtt_us);
                std.debug.print(
                    "         srv: tokens={d} rate={d}B/s cwnd={d} inflight={d} srtt={d}us bbr={?}\n",
                    .{
                        spath.pacer.tokens,
                        srate,
                        spath.cc.cwndBytes(),
                        pairs[i].server.stats().bytes_in_flight,
                        spath.rtt.smoothed_rtt_us,
                        if (spath.cc.bbrSnapshot()) |s| s.state else null,
                    },
                );
                // Flow-control forensics: the server's queued grants
                // and per-stream recv offsets vs what the client
                // believes its send limit is.
                const srv_stream = pairs[i].server.stream(0);
                const cli_stream = pairs[i].client.stream(0);
                std.debug.print(
                    "         fc:  srv pend_msd={d} pend_md={?} read_off={?} adv={?} | cli send_lim={?} blocked_at={?}\n",
                    .{
                        pairs[i].server.pending_frames.max_stream_data.items.len,
                        pairs[i].server.pending_frames.max_data,
                        if (srv_stream) |s| s.recv.read_offset else null,
                        if (srv_stream) |s| s.recv_max_data else null,
                        if (cli_stream) |s| s.send_max_data else null,
                        pairs[i].client.localStreamDataBlockedAt(0),
                    },
                );
                // The actual send gates, evaluated read-only (the
                // pacing gate mutates its bucket, so infer it from
                // the token/rate columns instead of calling it).
                const srv_ps = &pairs[i].server.paths.paths.items[0];
                std.debug.print(
                    "         gate: canSend={} cong_blocked={} tracker_inflight={d}\n",
                    .{
                        pairs[i].server.canSend(),
                        pairs[i].server.congestionBlockedOnPath(.application, srv_ps),
                        srv_ps.sent.bytes_in_flight,
                    },
                );
            }
            next_sample_us += opts.timeline_every_us;
        }
        if (!snapped and now_us >= measure_start_abs) {
            consumed_at_snap = consumed;
            snap_at_us = now_us;
            snapped = true;
        }

        // Greedy offer: every active flow always has a chunk ready;
        // the send window, not the application, is the limiter.
        for (opts.flows, 0..) |spec, i| {
            if (now_us - virtual_start < spec.start_us) continue;
            while (true) {
                const accepted = try pairs[i].client.streamWrite(0, data);
                if (accepted < data.len) break;
            }
        }

        // Drain every pending datagram from every flow into the
        // shared net; cwnd bounds each flow's burst.
        var progressed = true;
        while (progressed) {
            progressed = false;
            for (0..flow_count) |i| {
                if (try pairs[i].client.poll(&pkt, now_us)) |n| {
                    try net.enqueueFor(@intCast(i), true, pkt[0..n], now_us);
                    progressed = true;
                }
                if (try pairs[i].server.poll(&pkt, now_us)) |n| {
                    try net.enqueueFor(@intCast(i), false, pkt[0..n], now_us);
                    progressed = true;
                }
            }
        }

        try net.deliverDueMulti(endpoints[0..flow_count], now_us);

        // Continuous consumption keeps flow-control credit flowing so
        // the congestion controller, never the receive window, is the
        // binding constraint.
        for (0..flow_count) |i| {
            while (true) {
                const got = pairs[i].server.streamRead(0, &rbuf) catch |err| switch (err) {
                    error.StreamNotFound => break,
                    else => return err,
                };
                if (got == 0) break;
                consumed[i] += got;
            }
        }

        now_us += opts.tick_us;
        for (0..flow_count) |i| {
            try pairs[i].client.tick(now_us);
            try pairs[i].server.tick(now_us);
        }
    }

    if (!snapped) return error.FairnessWindowNeverOpened;
    const window_us = measure_end_abs - snap_at_us;

    var result: FairnessResult = .{
        .name = opts.name,
        .flow_count = flow_count,
        .measured_bytes = @splat(0),
        .goodput_mbps = @splat(0),
        .share = @splat(0),
        .cc = @splat(.cubic),
        .start_us = @splat(0),
        .jain_index = 0,
        .aggregate_mbps = 0,
        .utilization = 0,
        .measure_window_us = window_us,
        .virtual_us = now_us - virtual_start,
        .seed = opts.seed,
        .enqueued = net.enqueued,
        .dropped = net.dropped,
        .queue_dropped = net.queue_dropped,
        .peak_queue_delay_us = net.peak_queue_delay_us,
    };

    var sum: f64 = 0;
    var sum_sq: f64 = 0;
    var total_bytes: u64 = 0;
    for (0..flow_count) |i| {
        const bytes = consumed[i] - consumed_at_snap[i];
        result.measured_bytes[i] = bytes;
        result.cc[i] = opts.flows[i].congestion_control;
        result.start_us[i] = opts.flows[i].start_us;
        result.goodput_mbps[i] = @as(f64, @floatFromInt(bytes)) * 8.0 / @as(f64, @floatFromInt(window_us));
        const x: f64 = @floatFromInt(bytes);
        sum += x;
        sum_sq += x * x;
        total_bytes += bytes;
    }
    for (0..flow_count) |i| {
        result.share[i] = if (total_bytes == 0)
            0
        else
            @as(f64, @floatFromInt(result.measured_bytes[i])) / @as(f64, @floatFromInt(total_bytes));
    }
    result.jain_index = if (sum_sq == 0)
        0
    else
        (sum * sum) / (@as(f64, @floatFromInt(flow_count)) * sum_sq);
    result.aggregate_mbps = sum * 8.0 / @as(f64, @floatFromInt(window_us));
    const link_mbps = @as(f64, @floatFromInt(opts.bottleneck_bytes_per_s)) * 8.0 / 1e6;
    result.utilization = result.aggregate_mbps / link_mbps;
    return result;
}

// -- tests -------------------------------------------------------------------

const test_opts: FairnessOptions = .{
    .name = "fairness-machinery",
    .flows = &.{ .{}, .{} },
    // Small windows: these pin the machinery, not the measurement —
    // the real cells live in e2e_main.zig.
    .warmup_us = 500 * std.time.us_per_ms,
    .measure_us = 1500 * std.time.us_per_ms,
};

test "fairness run is deterministic in virtual time for a fixed seed" {
    var first: ?FairnessResult = null;
    for (0..2) |_| {
        const result = try runFairnessOnce(std.testing.allocator, test_opts);
        if (first) |f| {
            try std.testing.expectEqual(f.measured_bytes, result.measured_bytes);
            try std.testing.expectEqual(f.enqueued, result.enqueued);
            try std.testing.expectEqual(f.dropped, result.dropped);
            try std.testing.expectEqual(f.jain_index, result.jain_index);
        } else {
            first = result;
        }
    }
}

test "two identical CUBIC flows share a clean bottleneck without starvation" {
    const result = try runFairnessOnce(std.testing.allocator, test_opts);
    try std.testing.expectEqual(@as(u32, 2), result.flow_count);
    // Machinery floor, deliberately looser than any flip criterion:
    // both flows move data, the link is actually used, and the index
    // is in-range.
    try std.testing.expect(result.measured_bytes[0] > 0);
    try std.testing.expect(result.measured_bytes[1] > 0);
    try std.testing.expect(result.utilization > 0.5);
    try std.testing.expect(result.jain_index > 0.5 and result.jain_index <= 1.0);
}

test "staggered joiner opens the measure window after its own warmup" {
    var opts = test_opts;
    opts.name = "fairness-stagger-machinery";
    opts.flows = &.{ .{}, .{ .start_us = 300 * std.time.us_per_ms } };
    const result = try runFairnessOnce(std.testing.allocator, opts);
    // Window = warmup after the LATE start, so even the joiner has
    // measured bytes.
    try std.testing.expect(result.measured_bytes[1] > 0);
    try std.testing.expectEqual(@as(u64, 300 * std.time.us_per_ms), result.start_us[1]);
}
