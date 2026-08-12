//! quic_zig end-to-end benchmarks: whole-Connection numbers the
//! microbenchmarks in `main.zig` deliberately leave out.
//!
//!  - goodput:    in-process bulk stream transfer (client -> server
//!                over a memory shuttle); wall-clock MB/s = stack CPU
//!                efficiency, plus allocation counts and per-poll
//!                latency percentiles.
//!  - handshakes: full TLS 1.3 handshakes per second + allocations
//!                per handshake.
//!  - impairment: goodput through a seeded loss/reorder net measured
//!                in VIRTUAL time — deterministic for a given seed, so
//!                congestion-control changes show up as exact deltas.
//!
//! Run with `zig build bench-e2e` (`-- --scenario goodput|handshakes|
//! impairment|all`, `--samples N`, `--json path` / `--json-dir dir`).
//! Same ReleaseSafe default and `-Dbench-unsafe-release-fast` escape
//! hatch as `zig build bench`; reports share the schema-v3 envelope
//! (report.zig) so `zig build bench-compare` reads them.

const std = @import("std");
const builtin = @import("builtin");
const quic_zig = @import("quic_zig");
const report_mod = @import("report.zig");
const harness = @import("e2e/harness.zig");

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
};

fn stats(samples: []const f64) struct { median: f64, mad: f64 } {
    var sorted: [max_samples]f64 = undefined;
    @memcpy(sorted[0..samples.len], samples);
    const median = report_mod.medianInPlace(sorted[0..samples.len]);
    var scratch: [max_samples]f64 = undefined;
    const mad = report_mod.medianAbsoluteDeviation(samples, median, &scratch);
    return .{ .median = median, .mad = mad };
}

fn runGoodput(allocator: std.mem.Allocator, samples: usize, cc: quic_zig.CongestionAlgorithm) !GoodputEntry {
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
    .{ .name = "impairment_reorder10pct", .loss_permille = 0, .reorder_permille = 100 },
};

fn runImpairment(allocator: std.mem.Allocator, out: *Entries, cc: quic_zig.CongestionAlgorithm) !void {
    for (impairment_cells) |cell| {
        var cc_cell = cell;
        cc_cell.congestion_control = cc;
        const result = try harness.runImpairmentOnce(allocator, cc_cell);
        try out.impairment.append(allocator, result);
        std.debug.print("{s}: {d:.2} vMbps (virtual {d} ms, dropped {d}/{d}, wall {d} ms)\n", .{
            result.name,
            result.virtual_goodput_mbps,
            result.virtual_us / std.time.us_per_ms,
            result.dropped,
            result.enqueued,
            result.wall_ns / std.time.ns_per_ms,
        });
    }
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
        try out.print(allocator, "      \"seed\": {d}\n", .{cell.seed});
        try out.appendSlice(allocator, "    }\n");
    }
}

const Scenario = enum { all, goodput, handshakes, impairment };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var scenario: Scenario = .all;
    var samples: usize = default_samples;
    var cc: quic_zig.CongestionAlgorithm = .cubic;
    var json_path: ?[]const u8 = null;
    var json_dir: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--scenario")) {
            i += 1;
            if (i >= args.len) return error.MissingScenario;
            scenario = std.meta.stringToEnum(Scenario, args[i]) orelse return error.UnknownScenario;
        } else if (std.mem.eql(u8, args[i], "--cc")) {
            i += 1;
            if (i >= args.len) return error.MissingCcAlgorithm;
            cc = std.meta.stringToEnum(quic_zig.CongestionAlgorithm, args[i]) orelse return error.UnknownCcAlgorithm;
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
        } else {
            std.debug.print("unknown bench-e2e argument: {s}\n", .{args[i]});
            return error.UnknownArgument;
        }
    }

    std.debug.print("quic_zig e2e benchmarks ({s}, {d} samples, cc={s}, {s})\n", .{
        @tagName(scenario), samples, @tagName(cc), @tagName(builtin.mode),
    });
    std.debug.print("---------------------------------------------------------------\n", .{});

    var entries: Entries = .{};
    defer entries.impairment.deinit(allocator);

    if (scenario == .all or scenario == .goodput) {
        entries.goodput = try runGoodput(allocator, samples, cc);
    }
    if (scenario == .all or scenario == .handshakes) {
        entries.handshakes = try runHandshakes(allocator, samples);
    }
    if (scenario == .all or scenario == .impairment) {
        try runImpairment(allocator, &entries, cc);
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
        try report_mod.writeReport(
            allocator,
            io,
            .{
                .suite = "quic_zig.bench_e2e",
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
