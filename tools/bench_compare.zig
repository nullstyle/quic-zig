//! Compares two benchmark JSON reports (the `bench/report.zig` schema)
//! and flags regressions.
//!
//!     zig build bench-compare -- --baseline baselines/bench/github-ubuntu-x64.json \
//!                                --new benchmark-reports/latest.json \
//!                                [--tolerance-pct 10] [--advisory]
//!
//! A benchmark counts as a regression only when BOTH hold:
//!   1. the new median is worse than baseline by more than `--tolerance-pct`
//!      (direction depends on the metric: ns/op up = worse, MB/s down = worse);
//!   2. the absolute delta exceeds 3x the baseline's MAD (median absolute
//!      deviation) — the noise floor, so a tight tolerance on a noisy
//!      benchmark cannot cry wolf. A baseline without MAD (schema v2)
//!      degrades to the tolerance check alone.
//!
//! Output is a markdown table on stderr, also appended to
//! `$GITHUB_STEP_SUMMARY` when set. Exit is non-zero when regressions
//! were found and `--advisory` was not passed. Renamed/removed baseline
//! entries are listed as warnings, never failures — refreshing the
//! baseline is a deliberate act (see baselines/bench/README.md).

const std = @import("std");

/// Per-kind headline metric. Extended as new suite kinds land
/// (bench/e2e adds goodput/handshakes/impairment kinds).
const Metric = struct {
    kind: []const u8,
    /// Field holding the headline median; `fallback_field` covers
    /// schema-v2 baselines that predate multi-sample statistics.
    field: []const u8,
    fallback_field: ?[]const u8,
    mad_field: []const u8,
    higher_is_worse: bool,
    unit: []const u8,
};

const metric_table = [_]Metric{
    .{
        .kind = "micro",
        .field = "median_ns_per_op",
        .fallback_field = "ns_per_op",
        .mad_field = "mad_ns_per_op",
        .higher_is_worse = true,
        .unit = "ns/op",
    },
    .{
        .kind = "goodput",
        .field = "median_mb_per_sec",
        .fallback_field = null,
        .mad_field = "mad_mb_per_sec",
        .higher_is_worse = false,
        .unit = "MB/s",
    },
    .{
        .kind = "handshakes",
        .field = "median_handshakes_per_sec",
        .fallback_field = null,
        .mad_field = "mad_handshakes_per_sec",
        .higher_is_worse = false,
        .unit = "hs/s",
    },
    .{
        .kind = "impairment",
        .field = "virtual_goodput_mbps",
        .fallback_field = null,
        .mad_field = "mad_virtual_goodput_mbps",
        .higher_is_worse = false,
        .unit = "vMbps",
    },
};

fn metricForKind(kind: []const u8) ?*const Metric {
    for (&metric_table) |*m| {
        if (std.mem.eql(u8, m.kind, kind)) return m;
    }
    return null;
}

pub const Verdict = enum {
    ok,
    regression,
    improvement,
    new_entry,

    fn label(self: Verdict) []const u8 {
        return switch (self) {
            .ok => "ok",
            .regression => "**REGRESSION**",
            .improvement => "improvement",
            .new_entry => "new",
        };
    }
};

/// Pure verdict logic, unit-tested below. `tolerance_pct` is e.g. 10 for
/// 10%; `baseline_mad` of 0 disables the noise floor.
pub fn judge(
    baseline_median: f64,
    baseline_mad: f64,
    new_median: f64,
    tolerance_pct: f64,
    higher_is_worse: bool,
) Verdict {
    const tol = tolerance_pct / 100.0;
    const noise_floor = 3.0 * baseline_mad;
    // Normalize so "worse" is always "up".
    const base = baseline_median;
    const delta = if (higher_is_worse) new_median - base else base - new_median;
    const rel_limit = base * tol;
    if (delta > rel_limit and delta > noise_floor) return .regression;
    if (-delta > rel_limit and -delta > noise_floor) return .improvement;
    return .ok;
}

test "judge: regression needs both tolerance and noise floor exceeded" {
    // 15% worse with MAD 1: 115-100=15 > 10 (tol) and > 3 (floor) -> regression.
    try std.testing.expectEqual(Verdict.regression, judge(100, 1, 115, 10, true));
    // 15% worse but MAD 10: floor is 30 > 15 -> noise, not a regression.
    try std.testing.expectEqual(Verdict.ok, judge(100, 10, 115, 10, true));
    // 5% worse with tiny MAD: inside tolerance -> ok.
    try std.testing.expectEqual(Verdict.ok, judge(100, 0.1, 105, 10, true));
    // 20% better -> improvement.
    try std.testing.expectEqual(Verdict.improvement, judge(100, 1, 80, 10, true));
    // Zero MAD (v2 baseline): tolerance alone decides.
    try std.testing.expectEqual(Verdict.regression, judge(100, 0, 111, 10, true));
}

test "judge: throughput metrics invert direction" {
    // MB/s dropping 20% is a regression.
    try std.testing.expectEqual(Verdict.regression, judge(1000, 5, 800, 10, false));
    // MB/s rising is an improvement.
    try std.testing.expectEqual(Verdict.improvement, judge(1000, 5, 1200, 10, false));
    try std.testing.expectEqual(Verdict.ok, judge(1000, 5, 950, 10, false));
}

fn numField(obj: std.json.ObjectMap, name: []const u8) ?f64 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

fn strField(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

const Row = struct {
    name: []const u8,
    unit: []const u8,
    baseline_median: ?f64,
    new_median: f64,
    delta_pct: ?f64,
    verdict: Verdict,
};

const Comparison = struct {
    rows: std.ArrayList(Row),
    missing: std.ArrayList([]const u8),
    regressions: usize,

    fn deinit(self: *Comparison, allocator: std.mem.Allocator) void {
        self.rows.deinit(allocator);
        self.missing.deinit(allocator);
    }
};

/// Compares parsed baseline/new report roots. Slices in the result alias
/// the parsed JSON values — keep both alive while using it.
pub fn compareReports(
    allocator: std.mem.Allocator,
    baseline_root: std.json.Value,
    new_root: std.json.Value,
    tolerance_pct: f64,
) !Comparison {
    var result: Comparison = .{ .rows = .empty, .missing = .empty, .regressions = 0 };
    errdefer result.deinit(allocator);

    const baseline_entries = baseline_root.object.get("benchmarks") orelse return error.MalformedBaseline;
    const new_entries = new_root.object.get("benchmarks") orelse return error.MalformedNewReport;
    if (baseline_entries != .array or new_entries != .array) return error.MalformedReport;

    var baseline_by_name: std.StringHashMap(std.json.ObjectMap) = .init(allocator);
    defer baseline_by_name.deinit();
    for (baseline_entries.array.items) |entry| {
        if (entry != .object) return error.MalformedBaseline;
        const name = strField(entry.object, "name") orelse return error.MalformedBaseline;
        try baseline_by_name.put(name, entry.object);
    }

    var seen: std.StringHashMap(void) = .init(allocator);
    defer seen.deinit();

    for (new_entries.array.items) |entry| {
        if (entry != .object) return error.MalformedNewReport;
        const obj = entry.object;
        const name = strField(obj, "name") orelse return error.MalformedNewReport;
        // Entries without a kind predate schema v3; treat them as micro.
        const kind = strField(obj, "kind") orelse "micro";
        const metric = metricForKind(kind) orelse continue; // unknown kind: skip, never fail
        const new_median = numField(obj, metric.field) orelse
            (if (metric.fallback_field) |f| numField(obj, f) else null) orelse continue;

        try seen.put(name, {});

        if (baseline_by_name.get(name)) |base_obj| {
            const base_median = numField(base_obj, metric.field) orelse
                (if (metric.fallback_field) |f| numField(base_obj, f) else null) orelse {
                try result.rows.append(allocator, .{
                    .name = name,
                    .unit = metric.unit,
                    .baseline_median = null,
                    .new_median = new_median,
                    .delta_pct = null,
                    .verdict = .new_entry,
                });
                continue;
            };
            const base_mad = numField(base_obj, metric.mad_field) orelse 0;
            const verdict = judge(base_median, base_mad, new_median, tolerance_pct, metric.higher_is_worse);
            if (verdict == .regression) result.regressions += 1;
            const delta_pct: ?f64 = if (base_median != 0)
                (new_median - base_median) / base_median * 100.0
            else
                null;
            try result.rows.append(allocator, .{
                .name = name,
                .unit = metric.unit,
                .baseline_median = base_median,
                .new_median = new_median,
                .delta_pct = delta_pct,
                .verdict = verdict,
            });
        } else {
            try result.rows.append(allocator, .{
                .name = name,
                .unit = metric.unit,
                .baseline_median = null,
                .new_median = new_median,
                .delta_pct = null,
                .verdict = .new_entry,
            });
        }
    }

    for (baseline_entries.array.items) |entry| {
        const name = strField(entry.object, "name") orelse continue;
        if (!seen.contains(name)) try result.missing.append(allocator, name);
    }

    return result;
}

test "compareReports: full verdict matrix from inline reports" {
    const allocator = std.testing.allocator;
    const baseline_json =
        \\{"benchmarks":[
        \\  {"name":"steady","kind":"micro","median_ns_per_op":100.0,"mad_ns_per_op":1.0},
        \\  {"name":"slower","kind":"micro","median_ns_per_op":100.0,"mad_ns_per_op":1.0},
        \\  {"name":"faster","kind":"micro","median_ns_per_op":100.0,"mad_ns_per_op":1.0},
        \\  {"name":"noisy","kind":"micro","median_ns_per_op":100.0,"mad_ns_per_op":10.0},
        \\  {"name":"legacy_v2","ns_per_op":50.0},
        \\  {"name":"removed","kind":"micro","median_ns_per_op":1.0,"mad_ns_per_op":0.1},
        \\  {"name":"pipe","kind":"goodput","median_mb_per_sec":1000.0,"mad_mb_per_sec":5.0}
        \\]}
    ;
    const new_json =
        \\{"benchmarks":[
        \\  {"name":"steady","kind":"micro","median_ns_per_op":101.0,"mad_ns_per_op":1.0},
        \\  {"name":"slower","kind":"micro","median_ns_per_op":130.0,"mad_ns_per_op":1.0},
        \\  {"name":"faster","kind":"micro","median_ns_per_op":70.0,"mad_ns_per_op":1.0},
        \\  {"name":"noisy","kind":"micro","median_ns_per_op":115.0,"mad_ns_per_op":9.0},
        \\  {"name":"legacy_v2","kind":"micro","median_ns_per_op":52.0,"mad_ns_per_op":0.5},
        \\  {"name":"brand_new","kind":"micro","median_ns_per_op":7.0,"mad_ns_per_op":0.2},
        \\  {"name":"pipe","kind":"goodput","median_mb_per_sec":700.0,"mad_mb_per_sec":5.0},
        \\  {"name":"mystery","kind":"unknown_kind","median_ns_per_op":1.0}
        \\]}
    ;
    var baseline = try std.json.parseFromSlice(std.json.Value, allocator, baseline_json, .{});
    defer baseline.deinit();
    var new_report = try std.json.parseFromSlice(std.json.Value, allocator, new_json, .{});
    defer new_report.deinit();

    var cmp = try compareReports(allocator, baseline.value, new_report.value, 10);
    defer cmp.deinit(allocator);

    // slower (micro, +30%) and pipe (goodput, -30%) regress; unknown kind skipped.
    try std.testing.expectEqual(@as(usize, 2), cmp.regressions);
    try std.testing.expectEqual(@as(usize, 7), cmp.rows.items.len);

    var by_name: std.StringHashMap(Verdict) = .init(allocator);
    defer by_name.deinit();
    for (cmp.rows.items) |row| try by_name.put(row.name, row.verdict);
    try std.testing.expectEqual(Verdict.ok, by_name.get("steady").?);
    try std.testing.expectEqual(Verdict.regression, by_name.get("slower").?);
    try std.testing.expectEqual(Verdict.improvement, by_name.get("faster").?);
    // 15% worse but inside the 3xMAD=30 noise floor.
    try std.testing.expectEqual(Verdict.ok, by_name.get("noisy").?);
    // v2 baseline entry compared via the ns_per_op fallback: +4% -> ok.
    try std.testing.expectEqual(Verdict.ok, by_name.get("legacy_v2").?);
    try std.testing.expectEqual(Verdict.new_entry, by_name.get("brand_new").?);
    try std.testing.expectEqual(Verdict.regression, by_name.get("pipe").?);
    try std.testing.expect(by_name.get("mystery") == null);

    try std.testing.expectEqual(@as(usize, 1), cmp.missing.items.len);
    try std.testing.expectEqualStrings("removed", cmp.missing.items[0]);
}

fn renderMarkdown(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    cmp: *const Comparison,
    baseline_path: []const u8,
    new_path: []const u8,
    tolerance_pct: f64,
    advisory: bool,
) !void {
    try out.print(allocator, "### bench-compare: {s} regressions ({d} of {d} benchmarks)\n\n", .{
        if (cmp.regressions == 0) "no" else "FOUND",
        cmp.regressions,
        cmp.rows.items.len,
    });
    try out.print(allocator, "baseline `{s}` vs new `{s}`, tolerance {d:.1}% + 3xMAD noise floor{s}\n\n", .{
        baseline_path,
        new_path,
        tolerance_pct,
        if (advisory) " (advisory)" else "",
    });
    try out.appendSlice(allocator, "| benchmark | baseline | new | delta | verdict |\n");
    try out.appendSlice(allocator, "|---|---:|---:|---:|---|\n");
    for (cmp.rows.items) |row| {
        try out.print(allocator, "| {s} | ", .{row.name});
        if (row.baseline_median) |b| {
            try out.print(allocator, "{d:.2} {s} | ", .{ b, row.unit });
        } else {
            try out.appendSlice(allocator, "- | ");
        }
        try out.print(allocator, "{d:.2} {s} | ", .{ row.new_median, row.unit });
        if (row.delta_pct) |d| {
            try out.print(allocator, "{s}{d:.1}% | ", .{ if (d >= 0) "+" else "", d });
        } else {
            try out.appendSlice(allocator, "- | ");
        }
        try out.print(allocator, "{s} |\n", .{row.verdict.label()});
    }
    if (cmp.missing.items.len != 0) {
        try out.appendSlice(allocator, "\nWarning — baseline entries absent from the new report (renamed/removed? refresh the baseline):\n");
        for (cmp.missing.items) |name| {
            try out.print(allocator, "- `{s}`\n", .{name});
        }
    }
}

fn appendToStepSummary(io: std.Io, allocator: std.mem.Allocator, summary_path: []const u8, table: []const u8) void {
    // Read-concatenate-rewrite: the summary file is small, only this
    // step writes it while we run, and it sidesteps append-mode APIs.
    const existing: []const u8 = blk: {
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, summary_path, allocator, .limited(4 * 1024 * 1024)) catch break :blk "";
        break :blk bytes;
    };
    var merged: std.ArrayList(u8) = .empty;
    defer merged.deinit(allocator);
    merged.appendSlice(allocator, existing) catch return;
    merged.appendSlice(allocator, table) catch return;
    if (std.fs.path.isAbsolute(summary_path)) {
        var file = std.Io.Dir.createFileAbsolute(io, summary_path, .{}) catch return;
        defer file.close(io);
        file.writeStreamingAll(io, merged.items) catch {};
    } else {
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = summary_path, .data = merged.items }) catch {};
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var baseline_path: ?[]const u8 = null;
    var new_path: ?[]const u8 = null;
    var tolerance_pct: f64 = 10;
    var advisory = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--baseline")) {
            i += 1;
            if (i >= args.len) return error.MissingBaselinePath;
            baseline_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--new")) {
            i += 1;
            if (i >= args.len) return error.MissingNewPath;
            new_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--tolerance-pct")) {
            i += 1;
            if (i >= args.len) return error.MissingTolerance;
            tolerance_pct = std.fmt.parseFloat(f64, args[i]) catch return error.InvalidTolerance;
            if (tolerance_pct < 0) return error.InvalidTolerance;
        } else if (std.mem.eql(u8, args[i], "--advisory")) {
            advisory = true;
        } else {
            std.debug.print("unknown bench-compare argument: {s}\n", .{args[i]});
            return error.UnknownArgument;
        }
    }

    const bpath = baseline_path orelse {
        std.debug.print("usage: bench-compare --baseline <report.json> --new <report.json> [--tolerance-pct 10] [--advisory]\n", .{});
        return error.MissingBaselinePath;
    };
    const npath = new_path orelse return error.MissingNewPath;

    const baseline_bytes = try std.Io.Dir.cwd().readFileAlloc(io, bpath, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(baseline_bytes);
    const new_bytes = try std.Io.Dir.cwd().readFileAlloc(io, npath, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(new_bytes);

    var baseline = try std.json.parseFromSlice(std.json.Value, allocator, baseline_bytes, .{});
    defer baseline.deinit();
    var new_report = try std.json.parseFromSlice(std.json.Value, allocator, new_bytes, .{});
    defer new_report.deinit();

    var cmp = try compareReports(allocator, baseline.value, new_report.value, tolerance_pct);
    defer cmp.deinit(allocator);

    var table: std.ArrayList(u8) = .empty;
    defer table.deinit(allocator);
    try renderMarkdown(&table, allocator, &cmp, bpath, npath, tolerance_pct, advisory);

    std.debug.print("{s}", .{table.items});

    if (init.environ_map.get("GITHUB_STEP_SUMMARY")) |summary_path| {
        appendToStepSummary(io, allocator, summary_path, table.items);
    }

    if (cmp.regressions != 0 and !advisory) {
        return error.BenchmarkRegressionsDetected;
    }
}
