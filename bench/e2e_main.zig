//! quic end-to-end benchmarks: whole-Connection numbers the
//! microbenchmarks in `main.zig` deliberately leave out.
//!
//!  - goodput:    in-process bulk stream transfer (client -> server
//!                over a memory shuttle); wall-clock MB/s = stack CPU
//!                efficiency, plus allocation counts and per-poll
//!                latency percentiles.
//!                MEASURED 2026-10-03 (M5 Max, Zig 0.17.0): this cell
//!                moves by about 4% with code POSITION alone. Sixteen
//!                no-op instructions in a branch that never runs
//!                during the transfer took one tree from 497.7 to
//!                476.1 MB/s; 32 of them took a tree that looked "4%
//!                slower" from 477.6 back to 497.9. Same datagram
//!                count, same allocations, runs interleaved. So a
//!                wall-clock delta under about 5% between two commits
//!                proves nothing until a padding control (the same
//!                change plus no-ops) agrees. The virtual-time
//!                impairment cells are the exact instrument.
//!  - handshakes: full TLS 1.3 handshakes per second + allocations
//!                per handshake.
//!  - impairment: goodput through a seeded loss/reorder net measured
//!                in VIRTUAL time — deterministic for a given seed, so
//!                congestion-control changes show up as exact deltas.
//!
//!  - fairness:   N flows sharing ONE bottleneck link — per-flow
//!                goodput, shares, and the Jain index. The
//!                DEFAULT-FLIP GATE instrument (see
//!                src/conn/congestion/Bbr.zig).
//!
//!  - churn:      many short request/reply streams through a small
//!                stream window, in VIRTUAL time: requests per second
//!                as a function of `initial_max_streams_bidi` and the
//!                round-trip time. The number an embedder sizes its
//!                stream window from (docs/EMBEDDING.md).
//!
//! Run with `zig build bench-e2e` (`-- --scenario goodput|handshakes|
//! impairment|fairness|churn|all`, `--samples N`, `--json path` /
//! `--json-dir dir`).
//!
//! One seed is one draw. A virtual-time cell is exact for its seed, and
//! a different seed can give a very different time (MEASURED 2026-10-03:
//! `impairment_reorder10pct` over 24 seeds: median 151 ms, and six
//! seeds between 0.9 and 3.4 s; see the note at that cell for why). So
//! before a conclusion is drawn from one cell:
//!
//!  - `--cell NAME`  run only that impairment, fairness or churn cell;
//!  - `--seed N`     give the impairment cells this seed;
//!  - `--sweep K`    run each impairment cell over K seeds (N, N + 1,
//!                   ...) and print the minimum, the median and the
//!                   maximum. A sweep writes no JSON report.
//! Same ReleaseSafe default and `-Dbench-unsafe-release-fast` escape
//! hatch as `zig build bench`; reports share the schema-v3 envelope
//! (report.zig) so `zig build bench-compare` reads them.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const report_mod = @import("report.zig");
const harness = @import("e2e/harness.zig");
const fairness = @import("e2e/fairness.zig");

const default_samples: usize = 5;
const max_samples: usize = 32;

const GoodputEntry = struct {
    samples_mb_per_sec: [max_samples]f64,
    sample_count: usize,
    median_mb_per_sec: f64,
    mad_mb_per_sec: f64,
    last: harness.GoodputResult,
};

const HandshakesEntry = struct {
    samples_handshakes_per_sec: [max_samples]f64,
    sample_count: usize,
    median_handshakes_per_sec: f64,
    mad_handshakes_per_sec: f64,
    last: harness.HandshakeResult,
};

const Entries = struct {
    goodput: ?GoodputEntry = null,
    handshakes: ?HandshakesEntry = null,
    impairment: std.ArrayList(harness.ImpairmentResult) = .empty,
    fairness: std.ArrayList(fairness.FairnessResult) = .empty,
    churn: std.ArrayList(harness.ChurnResult) = .empty,
};

fn stats(samples: []const f64) struct { median: f64, mad: f64 } {
    var sorted: [max_samples]f64 = undefined;
    @memcpy(sorted[0..samples.len], samples);
    const median = report_mod.medianInPlace(sorted[0..samples.len]);
    var scratch: [max_samples]f64 = undefined;
    const mad = report_mod.medianAbsoluteDeviation(samples, median, &scratch);
    return .{ .median = median, .mad = mad };
}

fn runGoodput(allocator: std.mem.Allocator, samples: usize, cc: quic.CongestionAlgorithm) !GoodputEntry {
    var entry: GoodputEntry = undefined;
    entry.sample_count = samples;
    var last: harness.GoodputResult = undefined;
    for (0..samples) |i| {
        var counting = harness.CountingAllocator.init(allocator);
        last = try harness.runGoodputOnce(allocator, &counting, .{ .congestion_control = cc });
        entry.samples_mb_per_sec[i] = last.mb_per_sec;
        std.debug.print("goodput sample {d}/{d}: {d:.1} MB/s ({d} datagrams, {d} transfer allocs)\n", .{
            i + 1, samples, last.mb_per_sec, last.datagrams, last.transfer_allocs,
        });
    }
    const s = stats(entry.samples_mb_per_sec[0..samples]);
    entry.median_mb_per_sec = s.median;
    entry.mad_mb_per_sec = s.mad;
    entry.last = last;
    std.debug.print("goodput: {d:.1} MB/s \u{b1}{d:.1} (poll p50 {d} ns, p99 {d} ns)\n", .{
        s.median, s.mad, last.poll_p50_ns, last.poll_p99_ns,
    });
    return entry;
}

fn runHandshakes(allocator: std.mem.Allocator, samples: usize) !HandshakesEntry {
    var entry: HandshakesEntry = undefined;
    entry.sample_count = samples;
    var last: harness.HandshakeResult = undefined;
    for (0..samples) |i| {
        var counting = harness.CountingAllocator.init(allocator);
        last = try harness.runHandshakesOnce(allocator, &counting, .{});
        entry.samples_handshakes_per_sec[i] = last.handshakes_per_sec;
        std.debug.print("handshakes sample {d}/{d}: {d:.1}/s ({d} in {d} ms)\n", .{
            i + 1, samples, last.handshakes_per_sec, last.handshakes, last.wall_ns / std.time.ns_per_ms,
        });
    }
    const s = stats(entry.samples_handshakes_per_sec[0..samples]);
    entry.median_handshakes_per_sec = s.median;
    entry.mad_handshakes_per_sec = s.mad;
    entry.last = last;
    std.debug.print("handshakes: {d:.1}/s \u{b1}{d:.1} ({d:.1} allocs/handshake)\n", .{
        s.median, s.mad, last.allocs_per_handshake,
    });
    return entry;
}

const impairment_cells = [_]harness.ImpairmentOptions{
    .{ .name = "impairment_loss0pct", .loss_permille = 0 },
    .{ .name = "impairment_loss1pct", .loss_permille = 10 },
    .{ .name = "impairment_loss5pct", .loss_permille = 50 },
    // What this cell measures is not what its name says, and its one
    // committed seed (106 ms) hides it. MEASURED 2026-10-03.
    //
    // The network drops nothing. It holds 10% of the packets back by
    // 5 ms, on a path with a 2 ms round trip. The sender's loss
    // detection has the fixed thresholds of RFC 9002 (3 packets, 9/8
    // of the RTT), and a packet that is 5 ms late is past both: 100 ms
    // into one run, 853 of 8169 packets (10.4%) were declared lost,
    // and every one of them arrived. To a congestion controller that
    // is a path with 10% loss:
    //
    //     --sweep 24      min       median    max
    //     bbr             103 ms    151 ms    3412 ms
    //     cubic          4197 ms   4364 ms    4553 ms
    //     new_reno       4097 ms   4287 ms    4432 ms
    //
    // CUBIC and NewReno are at the floor in every run. BBR is fast only
    // for as long as its startup lasts: it leaves startup when one
    // round has 6 loss events at a loss rate above 2%. In a slow seed
    // that happens in the first 20 ms, with a bandwidth estimate of
    // 7.5 MB/s, and from then on every probe meets "loss" again: the
    // window stays at about 5 packets (2.7 MB/s) for the whole
    // transfer. In a fast seed startup reaches 266 MB/s first, and the
    // 8 MiB are through before the same decline gets far. So there is
    // no tail here: there is one slow state, and a transfer that is
    // short enough to outrun it three times in four.
    //
    // The proof, one variable: with thresholds wide enough for this
    // reordering (a temporary edit: packet threshold off, time
    // threshold 5 times the RTT) the same 24 seeds give 206 to 306 ms
    // for bbr and 404 to 517 ms for cubic.
    //
    // Not fixed. A sender can find out that a "lost" packet arrived
    // (the ACK for it comes later), widen its thresholds, and take the
    // controller's reaction back; RFC 9002 section 6.1 allows that and
    // does not specify it. That is a feature with its own design, and
    // this cell with `--sweep` is the instrument for it.
    .{ .name = "impairment_reorder10pct", .loss_permille = 0, .reorder_permille = 100 },
    // Bottleneck cells: a rate-limited link with a finite buffer, so
    // an overshooting slow start builds a standing queue and inflates
    // RTT. These are the only cells that can evaluate slow-start exit
    // (RFC 9406 HyStart++); the fixed-delay cells above never inflate
    // RTT at all. 10 Mbit mirrors the "bursty 10 Mbps simulator"
    // condition recorded in 5b9a4f6.
    .{
        .name = "impairment_bottleneck_10mbit",
        .loss_permille = 0,
        .bottleneck_bytes_per_s = 1_250_000,
        .total_bytes = 4 << 20,
    },
    .{
        .name = "impairment_bottleneck_10mbit_loss1pct",
        .loss_permille = 10,
        .bottleneck_bytes_per_s = 1_250_000,
        .total_bytes = 4 << 20,
    },
    // Multiplexed over the same bottleneck: the QNS `multiplexing`
    // (M) shape. This cell exists because HyStart++ was once rejected
    // for regressing M completion under a bursty 10 Mbps simulator
    // (see 5b9a4f6) — that claim is only re-testable with concurrent
    // streams in the mix.
    .{
        .name = "impairment_bottleneck_10mbit_mux8",
        .loss_permille = 0,
        .bottleneck_bytes_per_s = 1_250_000,
        .total_bytes = 4 << 20,
        .streams = 8,
    },
    // Shallow buffer: same 10 Mbit link with only 25 ms of queue
    // before tail drop (the cells above run sim_net's 100 ms
    // default). This is the regime that separates congestion-control
    // philosophies: a loss-based sender's sawtooth repeatedly fills
    // the small buffer (drops + latency spikes), while a rate-based
    // sender that keeps headroom should hold the queue short. Added
    // ahead of the BBR landing so the A/B has the cell where that
    // contrast is starkest — instrument before measure (see 367bfb2).
    .{
        .name = "impairment_bottleneck_10mbit_shallow25ms",
        .loss_permille = 0,
        .bottleneck_bytes_per_s = 1_250_000,
        .max_queue_delay_us = 25_000,
        .total_bytes = 4 << 20,
    },
    // A path that wants more packets in flight than the sent-packet
    // tracker holds (`SentPacketTracker.max_tracked`, 4096). 1 Gbit/s
    // with a 100 ms round trip is 12.5 MB in flight: about 10,400
    // packets of 1200 bytes. Sixteen streams, because one stream
    // buffers 1 MiB at most.
    //
    // MEASURED 2026-10-03 (M5 Max, Zig 0.17.0, ReleaseSafe, bbr):
    //
    //     tracker slots   goodput
    //         2048        157 vMbps
    //         4096        272 vMbps   (shipped)
    //         8192        448 vMbps
    //        16384        479 vMbps
    //
    // So the tracker is what limits this path, and twice the slots
    // gives 65% more. That is a finding, not yet a decision: slots
    // cost memory for every connection. Until v0.24.1 this cell did
    // not finish at all: the 4097th packet in flight made `poll`
    // return `TooManyInFlight`.
    .{
        .name = "impairment_fat_window_1gbit_rtt100ms",
        .bottleneck_bytes_per_s = 125_000_000,
        .one_way_delay_us = 50_000,
        .streams = 16,
        .total_bytes = 256 << 20,
    },
};

// The fairness matrix is fixed (specific matchups), NOT varied by
// --cc: fairness_10mbit_2f_cubic is the harness's own reference for
// what "fair" looks like here, the bbr cells + the mixed cells are
// the DEFAULT-FLIP GATE instrument (src/conn/congestion/Bbr.zig).
// Shared 10 Mbit link, 5 s warmup after the last joiner, 20 s
// measured, deep 100 ms buffer unless the name says otherwise.
const fairness_cells = [_]fairness.FairnessOptions{
    .{
        .name = "fairness_10mbit_2f_cubic",
        .flows = &.{ .{ .congestion_control = .cubic }, .{ .congestion_control = .cubic } },
    },
    .{
        .name = "fairness_10mbit_2f_bbr",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .bbr } },
    },
    .{
        .name = "fairness_10mbit_4f_bbr",
        .flows = &.{
            .{ .congestion_control = .bbr }, .{ .congestion_control = .bbr },
            .{ .congestion_control = .bbr }, .{ .congestion_control = .bbr },
        },
    },
    // Late-joiner convergence: does an established BBR flow yield to
    // a newcomer (§5.3.3.8 probe scheduling)?
    .{
        .name = "fairness_10mbit_2f_bbr_stagger5s",
        .flows = &.{
            .{ .congestion_control = .bbr },
            .{ .congestion_control = .bbr, .start_us = 5 * std.time.us_per_s },
        },
    },
    // Deep buffer: the regime where a loss-based sender historically
    // bullies a model-based one (it fills the queue BBR tries to
    // keep short).
    .{
        .name = "fairness_10mbit_2f_mixed",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
    },
    // Shallow buffer: the regime where BBRv1 historically bullied
    // loss-based flows (its inflight bound ignored their loss signal).
    .{
        .name = "fairness_10mbit_2f_mixed_shallow25ms",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
        .max_queue_delay_us = 25_000,
    },
};

// Stream churn: 2,000 request/reply streams (64-byte request, 256-byte
// reply) over a clean path with a 30 ms round trip, through stream
// windows of 1, 4 and 16. The asking side opens a request whenever it
// may. A stream id comes back only when the stream is fully closed on
// the answering side, so the window is the pipeline depth: the cells
// say what each depth carries. They follow --cc like the impairment
// cells, but nothing here is congestion limited, so the controllers
// must agree: a difference between them is a finding.
const churn_cells = [_]harness.ChurnOptions{
    .{ .name = "churn_window1_rtt30ms", .window = 1 },
    .{ .name = "churn_window4_rtt30ms", .window = 4 },
    .{ .name = "churn_window16_rtt30ms", .window = 16 },
};

/// Which cells run, and with which seeds (`--cell`, `--seed`, `--sweep`).
const Selection = struct {
    cell: ?[]const u8 = null,
    seed: ?u64 = null,
    sweep: usize = 0,

    fn wants(self: Selection, name: []const u8) bool {
        const only = self.cell orelse return true;
        return std.mem.eql(u8, only, name);
    }
};

const max_sweep: usize = 1024;

fn runChurn(allocator: std.mem.Allocator, out: *Entries, cc: quic.CongestionAlgorithm, sel: Selection) !void {
    for (churn_cells) |cell| {
        if (!sel.wants(cell.name)) continue;
        var cc_cell = cell;
        cc_cell.congestion_control = cc;
        const result = try harness.runChurnOnce(allocator, cc_cell);
        try out.churn.append(allocator, result);
        std.debug.print(
            "{s}: {d:.1} streams/vs (virtual {d} ms, window {d}, peak live {d}, limit at end {d}, datagrams {d})\n",
            .{
                result.name,
                result.streams_per_virtual_sec,
                result.virtual_us / std.time.us_per_ms,
                result.window,
                result.peak_live_streams,
                result.final_limit,
                result.enqueued,
            },
        );
    }
}

fn runFairness(allocator: std.mem.Allocator, out: *Entries, sel: Selection) !void {
    for (fairness_cells) |cell| {
        if (!sel.wants(cell.name)) continue;
        const result = try fairness.runFairnessOnce(allocator, cell);
        try out.fairness.append(allocator, result);
        std.debug.print("{s}: jain {d:.4}, util {d:.3}, peakq {d} us, qdrop {d} —", .{
            result.name, result.jain_index, result.utilization, result.peak_queue_delay_us, result.queue_dropped,
        });
        for (0..result.flow_count) |i| {
            std.debug.print(" [{s} {d:.2} Mbps {d:.1}%]", .{
                @tagName(result.cc[i]), result.goodput_mbps[i], result.share[i] * 100.0,
            });
        }
        std.debug.print("\n", .{});
    }
}

fn runImpairment(
    allocator: std.mem.Allocator,
    out: *Entries,
    cc: quic.CongestionAlgorithm,
    hystart: bool,
    sel: Selection,
) !void {
    for (impairment_cells) |cell| {
        if (!sel.wants(cell.name)) continue;
        var cc_cell = cell;
        cc_cell.congestion_control = cc;
        cc_cell.hystart = hystart;
        if (sel.seed) |seed| cc_cell.seed = seed;
        if (sel.sweep > 0) {
            try sweepImpairment(allocator, cc_cell, sel.sweep);
            continue;
        }
        const result = try harness.runImpairmentOnce(allocator, cc_cell);
        try out.impairment.append(allocator, result);
        std.debug.print(
            "{s}: {d:.2} vMbps (virtual {d} ms, dropped {d}/{d}, qdrop {d}, peakq {d} us)\n",
            .{
                result.name,
                result.virtual_goodput_mbps,
                result.virtual_us / std.time.us_per_ms,
                result.dropped,
                result.enqueued,
                result.queue_dropped,
                result.peak_queue_delay_us,
            },
        );
    }
}

/// One impairment cell over `count` seeds, from the cell's seed up.
/// Prints every run and then the minimum, the median and the maximum
/// virtual time, so that a long tail shows.
fn sweepImpairment(allocator: std.mem.Allocator, cell: harness.ImpairmentOptions, count: usize) !void {
    const times_ms = try allocator.alloc(u64, count);
    defer allocator.free(times_ms);
    var worst_seed: u64 = cell.seed;
    var worst_ms: u64 = 0;
    for (0..count) |k| {
        var one = cell;
        one.seed = cell.seed +% k;
        const result = try harness.runImpairmentOnce(allocator, one);
        const ms = result.virtual_us / std.time.us_per_ms;
        times_ms[k] = ms;
        if (ms > worst_ms) {
            worst_ms = ms;
            worst_seed = one.seed;
        }
        std.debug.print("{s} seed {d}: virtual {d} ms (dropped {d}/{d})\n", .{
            result.name, one.seed, ms, result.dropped, result.enqueued,
        });
    }
    std.mem.sort(u64, times_ms, {}, std.sort.asc(u64));
    const median_ms = times_ms[count / 2];
    std.debug.print(
        "{s}: sweep of {d} seeds from {d}: min {d} ms, median {d} ms, max {d} ms (seed {d}), max/median {d:.1}\n",
        .{
            cell.name,   count,                                                                                               cell.seed,
            times_ms[0], median_ms,                                                                                           worst_ms,
            worst_seed,  if (median_ms == 0) 0.0 else @as(f64, @floatFromInt(worst_ms)) / @as(f64, @floatFromInt(median_ms)),
        },
    );
}

fn writeEntrySeparator(out: *std.ArrayList(u8), allocator: std.mem.Allocator, first: *bool) !void {
    if (!first.*) try out.appendSlice(allocator, "    ,\n");
    first.* = false;
}

fn writeE2eEntries(out: *std.ArrayList(u8), allocator: std.mem.Allocator, entries: *const Entries) anyerror!void {
    var first = true;
    if (entries.goodput) |g| {
        try writeEntrySeparator(out, allocator, &first);
        try out.appendSlice(allocator, "    {\n      \"name\": \"goodput_bulk_64mib\",\n      \"kind\": \"goodput\",\n");
        try out.print(allocator, "      \"total_bytes\": {d},\n", .{g.last.total_bytes});
        try out.print(allocator, "      \"sample_count\": {d},\n", .{g.sample_count});
        try out.appendSlice(allocator, "      \"samples_mb_per_sec\": [");
        for (g.samples_mb_per_sec[0..g.sample_count], 0..) |s, j| {
            if (j != 0) try out.appendSlice(allocator, ", ");
            try out.print(allocator, "{d:.3}", .{s});
        }
        try out.appendSlice(allocator, "],\n");
        try out.print(allocator, "      \"median_mb_per_sec\": {d:.3},\n", .{g.median_mb_per_sec});
        try out.print(allocator, "      \"mad_mb_per_sec\": {d:.3},\n", .{g.mad_mb_per_sec});
        try out.print(allocator, "      \"datagrams\": {d},\n", .{g.last.datagrams});
        try out.print(allocator, "      \"client_polls\": {d},\n", .{g.last.client_polls});
        try out.print(allocator, "      \"transfer_allocs\": {d},\n", .{g.last.transfer_allocs});
        try out.print(allocator, "      \"transfer_frees\": {d},\n", .{g.last.transfer_frees});
        try out.print(allocator, "      \"transfer_bytes_allocated\": {d},\n", .{g.last.transfer_bytes_allocated});
        try out.print(allocator, "      \"poll_p50_ns\": {d},\n", .{g.last.poll_p50_ns});
        try out.print(allocator, "      \"poll_p90_ns\": {d},\n", .{g.last.poll_p90_ns});
        try out.print(allocator, "      \"poll_p99_ns\": {d},\n", .{g.last.poll_p99_ns});
        try out.print(allocator, "      \"poll_max_ns\": {d}\n", .{g.last.poll_max_ns});
        try out.appendSlice(allocator, "    }\n");
    }
    if (entries.handshakes) |h| {
        try writeEntrySeparator(out, allocator, &first);
        try out.appendSlice(allocator, "    {\n      \"name\": \"handshakes_full_tls13\",\n      \"kind\": \"handshakes\",\n");
        try out.print(allocator, "      \"sample_count\": {d},\n", .{h.sample_count});
        try out.appendSlice(allocator, "      \"samples_handshakes_per_sec\": [");
        for (h.samples_handshakes_per_sec[0..h.sample_count], 0..) |s, j| {
            if (j != 0) try out.appendSlice(allocator, ", ");
            try out.print(allocator, "{d:.3}", .{s});
        }
        try out.appendSlice(allocator, "],\n");
        try out.print(allocator, "      \"median_handshakes_per_sec\": {d:.3},\n", .{h.median_handshakes_per_sec});
        try out.print(allocator, "      \"mad_handshakes_per_sec\": {d:.3},\n", .{h.mad_handshakes_per_sec});
        try out.print(allocator, "      \"allocs_per_handshake\": {d:.2}\n", .{h.last.allocs_per_handshake});
        try out.appendSlice(allocator, "    }\n");
    }
    for (entries.impairment.items) |cell| {
        try writeEntrySeparator(out, allocator, &first);
        try out.appendSlice(allocator, "    {\n      \"name\": ");
        try report_mod.appendJsonString(out, allocator, cell.name);
        try out.appendSlice(allocator, ",\n      \"kind\": \"impairment\",\n");
        try out.print(allocator, "      \"total_bytes\": {d},\n", .{cell.total_bytes});
        try out.print(allocator, "      \"virtual_us\": {d},\n", .{cell.virtual_us});
        try out.print(allocator, "      \"virtual_goodput_mbps\": {d:.4},\n", .{cell.virtual_goodput_mbps});
        try out.print(allocator, "      \"wall_ns\": {d},\n", .{cell.wall_ns});
        try out.print(allocator, "      \"enqueued\": {d},\n", .{cell.enqueued});
        try out.print(allocator, "      \"dropped\": {d},\n", .{cell.dropped});
        try out.print(allocator, "      \"loss_permille\": {d},\n", .{cell.loss_permille});
        try out.print(allocator, "      \"reorder_permille\": {d},\n", .{cell.reorder_permille});
        try out.print(allocator, "      \"queue_dropped\": {d},\n", .{cell.queue_dropped});
        try out.print(allocator, "      \"peak_queue_delay_us\": {d},\n", .{cell.peak_queue_delay_us});
        try out.print(allocator, "      \"seed\": {d}\n", .{cell.seed});
        try out.appendSlice(allocator, "    }\n");
    }
    for (entries.fairness.items) |cell| {
        try writeEntrySeparator(out, allocator, &first);
        try out.appendSlice(allocator, "    {\n      \"name\": ");
        try report_mod.appendJsonString(out, allocator, cell.name);
        try out.appendSlice(allocator, ",\n      \"kind\": \"fairness\",\n");
        try out.print(allocator, "      \"flow_count\": {d},\n", .{cell.flow_count});
        try out.appendSlice(allocator, "      \"flows\": [");
        for (0..cell.flow_count) |i| {
            if (i != 0) try out.appendSlice(allocator, ", ");
            try out.print(
                allocator,
                "{{\"cc\": \"{s}\", \"start_us\": {d}, \"measured_bytes\": {d}, \"goodput_mbps\": {d:.4}, \"share\": {d:.4}}}",
                .{ @tagName(cell.cc[i]), cell.start_us[i], cell.measured_bytes[i], cell.goodput_mbps[i], cell.share[i] },
            );
        }
        try out.appendSlice(allocator, "],\n");
        try out.print(allocator, "      \"jain_index\": {d:.4},\n", .{cell.jain_index});
        try out.print(allocator, "      \"aggregate_mbps\": {d:.4},\n", .{cell.aggregate_mbps});
        try out.print(allocator, "      \"utilization\": {d:.4},\n", .{cell.utilization});
        try out.print(allocator, "      \"measure_window_us\": {d},\n", .{cell.measure_window_us});
        try out.print(allocator, "      \"virtual_us\": {d},\n", .{cell.virtual_us});
        try out.print(allocator, "      \"enqueued\": {d},\n", .{cell.enqueued});
        try out.print(allocator, "      \"dropped\": {d},\n", .{cell.dropped});
        try out.print(allocator, "      \"queue_dropped\": {d},\n", .{cell.queue_dropped});
        try out.print(allocator, "      \"peak_queue_delay_us\": {d},\n", .{cell.peak_queue_delay_us});
        try out.print(allocator, "      \"seed\": {d}\n", .{cell.seed});
        try out.appendSlice(allocator, "    }\n");
    }
    for (entries.churn.items) |cell| {
        try writeEntrySeparator(out, allocator, &first);
        try out.appendSlice(allocator, "    {\n      \"name\": ");
        try report_mod.appendJsonString(out, allocator, cell.name);
        try out.appendSlice(allocator, ",\n      \"kind\": \"churn\",\n");
        try out.print(allocator, "      \"streams\": {d},\n", .{cell.streams});
        try out.print(allocator, "      \"window\": {d},\n", .{cell.window});
        try out.print(allocator, "      \"one_way_delay_us\": {d},\n", .{cell.one_way_delay_us});
        try out.print(allocator, "      \"virtual_us\": {d},\n", .{cell.virtual_us});
        try out.print(allocator, "      \"streams_per_virtual_sec\": {d:.4},\n", .{cell.streams_per_virtual_sec});
        try out.print(allocator, "      \"wall_ns\": {d},\n", .{cell.wall_ns});
        try out.print(allocator, "      \"enqueued\": {d},\n", .{cell.enqueued});
        try out.print(allocator, "      \"peak_live_streams\": {d},\n", .{cell.peak_live_streams});
        try out.print(allocator, "      \"final_limit\": {d}\n", .{cell.final_limit});
        try out.appendSlice(allocator, "    }\n");
    }
}

const Scenario = enum { all, goodput, handshakes, impairment, fairness, churn };

/// True if `--cell NAME` names a cell that exists. A name with a typing
/// error must not look like a run with nothing to report.
fn knownCell(name: []const u8) bool {
    for (impairment_cells) |cell| if (std.mem.eql(u8, cell.name, name)) return true;
    for (fairness_cells) |cell| if (std.mem.eql(u8, cell.name, name)) return true;
    for (churn_cells) |cell| if (std.mem.eql(u8, cell.name, name)) return true;
    return false;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var scenario: Scenario = .all;
    var samples: usize = default_samples;
    var cc: quic.CongestionAlgorithm = .bbr;
    var hystart = true;
    var json_path: ?[]const u8 = null;
    var json_dir: ?[]const u8 = null;
    var sel: Selection = .{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--scenario")) {
            i += 1;
            if (i >= args.len) return error.MissingScenario;
            scenario = std.meta.stringToEnum(Scenario, args[i]) orelse return error.UnknownScenario;
        } else if (std.mem.eql(u8, args[i], "--cc")) {
            i += 1;
            if (i >= args.len) return error.MissingCcAlgorithm;
            cc = std.meta.stringToEnum(quic.CongestionAlgorithm, args[i]) orelse return error.UnknownCcAlgorithm;
        } else if (std.mem.eql(u8, args[i], "--hystart")) {
            i += 1;
            if (i >= args.len) return error.MissingHyStartValue;
            if (std.mem.eql(u8, args[i], "on")) {
                hystart = true;
            } else if (std.mem.eql(u8, args[i], "off")) {
                hystart = false;
            } else return error.InvalidHyStartValue;
        } else if (std.mem.eql(u8, args[i], "--samples")) {
            i += 1;
            if (i >= args.len) return error.MissingSampleCount;
            const n = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidSampleCount;
            if (n < 1 or n > max_samples) return error.InvalidSampleCount;
            samples = n;
        } else if (std.mem.eql(u8, args[i], "--json")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonPath;
            if (json_dir != null) return error.DuplicateJsonTarget;
            json_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--json-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonDir;
            if (json_path != null) return error.DuplicateJsonTarget;
            json_dir = args[i];
        } else if (std.mem.eql(u8, args[i], "--cell")) {
            i += 1;
            if (i >= args.len) return error.MissingCellName;
            sel.cell = args[i];
        } else if (std.mem.eql(u8, args[i], "--seed")) {
            i += 1;
            if (i >= args.len) return error.MissingSeed;
            sel.seed = std.fmt.parseInt(u64, args[i], 0) catch return error.InvalidSeed;
        } else if (std.mem.eql(u8, args[i], "--sweep")) {
            i += 1;
            if (i >= args.len) return error.MissingSweepCount;
            const n = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidSweepCount;
            if (n < 1 or n > max_sweep) return error.InvalidSweepCount;
            sel.sweep = n;
        } else {
            std.debug.print("unknown bench-e2e argument: {s}\n", .{args[i]});
            return error.UnknownArgument;
        }
    }

    if (sel.cell) |name| {
        if (!knownCell(name)) {
            std.debug.print("unknown bench-e2e cell: {s}\n", .{name});
            return error.UnknownCell;
        }
    }
    if (sel.sweep > 0 and (json_path != null or json_dir != null)) {
        std.debug.print("--sweep writes no JSON report; drop --json / --json-dir\n", .{});
        return error.SweepWritesNoReport;
    }

    std.debug.print("quic e2e benchmarks ({s}, {d} samples, cc={s}, hystart={s}, {s})\n", .{
        @tagName(scenario),           samples,                @tagName(cc),
        if (hystart) "on" else "off", @tagName(builtin.mode),
    });
    std.debug.print("---------------------------------------------------------------\n", .{});

    var entries: Entries = .{};
    defer entries.impairment.deinit(allocator);
    defer entries.fairness.deinit(allocator);
    defer entries.churn.deinit(allocator);

    if (scenario == .all or scenario == .goodput) {
        entries.goodput = try runGoodput(allocator, samples, cc);
    }
    if (scenario == .all or scenario == .handshakes) {
        entries.handshakes = try runHandshakes(allocator, samples);
    }
    if (scenario == .all or scenario == .impairment) {
        try runImpairment(allocator, &entries, cc, hystart, sel);
    }
    if (scenario == .all or scenario == .fairness) {
        try runFairness(allocator, &entries, sel);
    }
    if (scenario == .all or scenario == .churn) {
        try runChurn(allocator, &entries, cc, sel);
    }

    std.debug.print("---------------------------------------------------------------\n", .{});

    const generated_unix_ns: u64 = blk: {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &ts);
        break :blk @as(u64, @intCast(ts.sec)) *% std.time.ns_per_s +% @as(u64, @intCast(ts.nsec));
    };
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname: ?[]const u8 = std.posix.gethostname(&hostname_buf) catch null;
    const machine_id = init.environ_map.get("BENCH_MACHINE_ID") orelse hostname orelse "unknown";
    const github_sha = init.environ_map.get("GITHUB_SHA");
    const github_run_id = init.environ_map.get("GITHUB_RUN_ID");
    const github_ref_name = init.environ_map.get("GITHUB_REF_NAME");

    var generated_report_path: std.ArrayList(u8) = .empty;
    defer generated_report_path.deinit(allocator);
    const report_path: ?[]const u8 = if (json_path) |path|
        path
    else if (json_dir) |dir|
        try report_mod.buildReportPath(
            &generated_report_path,
            allocator,
            dir,
            "quic-zig-bench-e2e",
            generated_unix_ns,
            machine_id,
            github_sha,
            github_run_id,
        )
    else
        null;

    if (report_path) |path| {
        var extra_header: std.ArrayList(u8) = .empty;
        defer extra_header.deinit(allocator);
        try extra_header.print(allocator, "  \"samples_per_benchmark\": {d},\n", .{samples});
        try report_mod.appendCcPosture(&extra_header, allocator, @tagName(cc), hystart);
        try report_mod.writeReport(
            allocator,
            io,
            .{
                .suite = "quic.bench_e2e",
                .generated_unix_ns = generated_unix_ns,
                .machine_id = machine_id,
                .hostname = hostname,
                .report_path = path,
                .github_sha = github_sha,
                .github_run_id = github_run_id,
                .github_ref_name = github_ref_name,
                .extra_header_json = extra_header.items,
            },
            *const Entries,
            &entries,
            writeE2eEntries,
        );
        std.debug.print("wrote e2e benchmark JSON report: {s}\n", .{path});
    }
    std.debug.print("done.\n", .{});
}
