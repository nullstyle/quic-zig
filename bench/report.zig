//! Shared benchmark reporting: robust statistics helpers and the
//! schema-versioned JSON report writer.
//!
//! Both benchmark binaries (`bench/main.zig` microbenchmarks and the
//! `bench/e2e` suite) emit the same report envelope — toolchain, target,
//! system, and CI metadata around a suite-specific `"benchmarks"` array —
//! so comparison tooling (`tools/bench_compare.zig`) can read either.
//!
//! Schema history:
//!  - v1/v2: single-sample `ns_per_op` per benchmark (v2 added system +
//!    GitHub metadata).
//!  - v3: multi-sample statistics. Each entry carries its raw per-sample
//!    values plus `median_*`, `mad_*` (median absolute deviation), and
//!    `min_*`; the legacy `ns_per_op` field remains and is defined as the
//!    median so v2 readers keep working. Entries gain a `"kind"`
//!    discriminator (`"micro"`, and later e2e kinds such as `"goodput"`).

const std = @import("std");
const builtin = @import("builtin");
const quic_zig = @import("quic_zig");

pub const schema_version: u64 = 3;

// -- robust statistics ----------------------------------------------------
//
// Median + MAD rather than mean + stddev: benchmark noise on shared
// runners is heavy-tailed (scheduler preemption, thermal events), and a
// single slow outlier should not move the headline number.

/// Median of an already-sorted, non-empty slice.
pub fn medianOfSorted(sorted: []const f64) f64 {
    std.debug.assert(sorted.len > 0);
    const mid = sorted.len / 2;
    if (sorted.len % 2 == 1) return sorted[mid];
    return (sorted[mid - 1] + sorted[mid]) / 2.0;
}

/// Sorts `values` in place and returns the median.
pub fn medianInPlace(values: []f64) f64 {
    std.mem.sort(f64, values, {}, std.sort.asc(f64));
    return medianOfSorted(values);
}

/// Median absolute deviation around `median`. `scratch` must be at least
/// `values.len` long; it is overwritten.
pub fn medianAbsoluteDeviation(values: []const f64, median: f64, scratch: []f64) f64 {
    std.debug.assert(scratch.len >= values.len);
    for (values, 0..) |v, i| scratch[i] = @abs(v - median);
    return medianInPlace(scratch[0..values.len]);
}

test "medianOfSorted odd and even counts" {
    try std.testing.expectEqual(@as(f64, 3.0), medianOfSorted(&.{ 1.0, 3.0, 9.0 }));
    try std.testing.expectEqual(@as(f64, 2.5), medianOfSorted(&.{ 1.0, 2.0, 3.0, 9.0 }));
    try std.testing.expectEqual(@as(f64, 7.0), medianOfSorted(&.{7.0}));
}

test "medianInPlace sorts and returns the median" {
    var values = [_]f64{ 9.0, 1.0, 3.0 };
    try std.testing.expectEqual(@as(f64, 3.0), medianInPlace(&values));
    try std.testing.expectEqual(@as(f64, 1.0), values[0]);
}

test "medianAbsoluteDeviation is robust to a single outlier" {
    // Samples clustered at ~100 with one wild outlier: the median stays
    // at 100 and the MAD stays small — exactly the property the noise
    // floor in bench_compare relies on.
    const values = [_]f64{ 99.0, 100.0, 100.0, 101.0, 500.0 };
    var scratch: [values.len]f64 = undefined;
    const med = medianOfSorted(&.{ 99.0, 100.0, 100.0, 101.0, 500.0 });
    try std.testing.expectEqual(@as(f64, 100.0), med);
    const mad = medianAbsoluteDeviation(&values, med, &scratch);
    try std.testing.expectEqual(@as(f64, 1.0), mad);
}

// -- JSON building blocks -------------------------------------------------

pub fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(allocator, "\\\""),
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '\n' => try out.appendSlice(allocator, "\\n"),
        '\r' => try out.appendSlice(allocator, "\\r"),
        '\t' => try out.appendSlice(allocator, "\\t"),
        0x00...0x08, 0x0b...0x0c, 0x0e...0x1f => try out.print(
            allocator,
            "\\u{x:0>4}",
            .{c},
        ),
        else => try out.append(allocator, c),
    };
    try out.append(allocator, '"');
}

pub fn appendNullableJsonString(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    maybe: ?[]const u8,
) !void {
    if (maybe) |s| {
        try appendJsonString(out, allocator, s);
    } else {
        try out.appendSlice(allocator, "null");
    }
}

pub fn appendNullableU64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, maybe: ?u64) !void {
    if (maybe) |value| {
        try out.print(allocator, "{d}", .{value});
    } else {
        try out.appendSlice(allocator, "null");
    }
}

test "appendJsonString escapes control and quote characters" {
    const allocator = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendJsonString(&out, allocator, "a\"b\\c\nd\x01");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\\nd\\u0001\"", out.items);
}

// -- report file naming ----------------------------------------------------

fn appendSanitizedToken(out: *std.ArrayList(u8), allocator: std.mem.Allocator, token: []const u8) !void {
    var wrote = false;
    for (token) |c| {
        const safe = switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => c,
            else => '-',
        };
        try out.append(allocator, safe);
        wrote = true;
    }
    if (!wrote) try out.appendSlice(allocator, "unknown");
}

fn shortSha(sha: ?[]const u8) ?[]const u8 {
    const s = sha orelse return null;
    return s[0..@min(s.len, 12)];
}

/// Builds `<dir>/<prefix>-<unix_ns>-<machine>-<sha|local>-<run|manual>.json`
/// into `out` and returns the slice.
pub fn buildReportPath(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    dir: []const u8,
    prefix: []const u8,
    generated_unix_ns: u64,
    machine_id: []const u8,
    github_sha: ?[]const u8,
    github_run_id: ?[]const u8,
) ![]const u8 {
    out.clearRetainingCapacity();
    try out.appendSlice(allocator, dir);
    if (dir.len > 0 and dir[dir.len - 1] != std.fs.path.sep) {
        try out.append(allocator, std.fs.path.sep);
    }
    try out.appendSlice(allocator, prefix);
    try out.append(allocator, '-');
    try out.print(allocator, "{d}-", .{generated_unix_ns});
    try appendSanitizedToken(out, allocator, machine_id);
    try out.append(allocator, '-');
    if (shortSha(github_sha)) |sha| {
        try appendSanitizedToken(out, allocator, sha);
    } else {
        try out.appendSlice(allocator, "local");
    }
    try out.append(allocator, '-');
    if (github_run_id) |run_id| {
        try appendSanitizedToken(out, allocator, run_id);
    } else {
        try out.appendSlice(allocator, "manual");
    }
    try out.appendSlice(allocator, ".json");
    return out.items;
}

test "buildReportPath sanitizes tokens and falls back to local/manual" {
    const allocator = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const path = try buildReportPath(&out, allocator, "reports", "quic-zig-bench", 42, "m5 max!", null, null);
    try std.testing.expectEqualStrings("reports/quic-zig-bench-42-m5-max--local-manual.json", path);
}

// -- report envelope -------------------------------------------------------

pub const Meta = struct {
    /// e.g. "quic_zig.microbench" or "quic_zig.bench_e2e".
    suite: []const u8,
    generated_unix_ns: u64,
    machine_id: []const u8,
    hostname: ?[]const u8,
    report_path: []const u8,
    github_sha: ?[]const u8,
    github_run_id: ?[]const u8,
    github_ref_name: ?[]const u8,
    /// Suite-specific scalar header fields, spliced verbatim into the
    /// header object. Every line must have the shape `  "key": value,\n`
    /// (two-space indent, trailing comma + newline) or be empty.
    extra_header_json: []const u8 = "",
};

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    try std.Io.Dir.cwd().createDirPath(io, parent);
}

pub fn writeReportFile(io: std.Io, path: []const u8, data: []const u8) !void {
    try ensureParentDir(io, path);
    if (std.fs.path.isAbsolute(path)) {
        var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, data);
    } else {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
    }
}

/// Renders the shared report envelope into `out`, calling
/// `writeEntries(out, allocator, entries)` to fill the `"benchmarks"`
/// array body (the callback writes the array *elements*, brackets
/// included by the caller side here).
pub fn renderReport(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    meta: Meta,
    comptime Entries: type,
    entries: Entries,
    comptime writeEntries: fn (*std.ArrayList(u8), std.mem.Allocator, Entries) anyerror!void,
) !void {
    try out.appendSlice(allocator, "{\n");
    try out.print(allocator, "  \"schema_version\": {d},\n", .{schema_version});
    try out.appendSlice(allocator, "  \"suite\": ");
    try appendJsonString(out, allocator, meta.suite);
    try out.appendSlice(allocator, ",\n");
    try out.print(allocator, "  \"generated_unix_ns\": {d},\n", .{meta.generated_unix_ns});
    try out.appendSlice(allocator, meta.extra_header_json);
    try out.appendSlice(allocator, "  \"optimize\": ");
    try appendJsonString(out, allocator, @tagName(builtin.mode));
    try out.appendSlice(allocator, ",\n");
    try out.print(
        allocator,
        "  \"bench_unsafe_release_fast\": {},\n",
        .{builtin.mode == .fast},
    );
    try out.appendSlice(allocator, "  \"report_path\": ");
    try appendJsonString(out, allocator, meta.report_path);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"quic_zig_version\": ");
    try appendJsonString(out, allocator, quic_zig.version());
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"zig_version\": ");
    try appendJsonString(out, allocator, builtin.zig_version_string);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "  \"target\": {\n");
    try out.appendSlice(allocator, "    \"arch\": ");
    try appendJsonString(out, allocator, @tagName(builtin.target.cpu.arch));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"os\": ");
    try appendJsonString(out, allocator, @tagName(builtin.target.os.tag));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"abi\": ");
    try appendJsonString(out, allocator, @tagName(builtin.target.abi));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"cpu_model\": ");
    try appendJsonString(out, allocator, builtin.target.cpu.model.name);
    try out.appendSlice(allocator, "\n  },\n");
    const logical_cpu_count: ?u64 = if (std.Thread.getCpuCount()) |n| @intCast(n) else |_| null;
    const total_memory_bytes: ?u64 = if (std.process.totalSystemMemory()) |n| n else |_| null;
    const uts = std.posix.uname();
    try out.appendSlice(allocator, "  \"system\": {\n");
    try out.appendSlice(allocator, "    \"machine_id\": ");
    try appendJsonString(out, allocator, meta.machine_id);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"hostname\": ");
    try appendNullableJsonString(out, allocator, meta.hostname);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"logical_cpu_count\": ");
    try appendNullableU64(out, allocator, logical_cpu_count);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"total_memory_bytes\": ");
    try appendNullableU64(out, allocator, total_memory_bytes);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"uname\": {\n");
    try out.appendSlice(allocator, "      \"sysname\": ");
    try appendJsonString(out, allocator, std.mem.sliceTo(&uts.sysname, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"release\": ");
    try appendJsonString(out, allocator, std.mem.sliceTo(&uts.release, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"version\": ");
    try appendJsonString(out, allocator, std.mem.sliceTo(&uts.version, 0));
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "      \"machine\": ");
    try appendJsonString(out, allocator, std.mem.sliceTo(&uts.machine, 0));
    try out.appendSlice(allocator, "\n    }\n");
    try out.appendSlice(allocator, "  },\n");
    try out.appendSlice(allocator, "  \"github\": {\n");
    try out.appendSlice(allocator, "    \"sha\": ");
    try appendNullableJsonString(out, allocator, meta.github_sha);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"run_id\": ");
    try appendNullableJsonString(out, allocator, meta.github_run_id);
    try out.appendSlice(allocator, ",\n");
    try out.appendSlice(allocator, "    \"ref_name\": ");
    try appendNullableJsonString(out, allocator, meta.github_ref_name);
    try out.appendSlice(allocator, "\n  },\n");
    try out.appendSlice(allocator, "  \"benchmarks\": [\n");
    try writeEntries(out, allocator, entries);
    try out.appendSlice(allocator, "  ]\n}\n");
}

/// Renders the report and writes it to `meta.report_path`.
pub fn writeReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    meta: Meta,
    comptime Entries: type,
    entries: Entries,
    comptime writeEntries: fn (*std.ArrayList(u8), std.mem.Allocator, Entries) anyerror!void,
) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try renderReport(&out, allocator, meta, Entries, entries, writeEntries);
    try writeReportFile(io, meta.report_path, out.items);
}

test "renderReport produces parseable JSON with the shared envelope" {
    const allocator = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    const Entries = struct {
        fn write(o: *std.ArrayList(u8), a: std.mem.Allocator, _: void) anyerror!void {
            try o.appendSlice(a, "    {\n      \"name\": \"x\",\n      \"kind\": \"micro\",\n      \"ns_per_op\": 1.5\n    }\n");
        }
    };

    try renderReport(&out, allocator, .{
        .suite = "quic_zig.report_test",
        .generated_unix_ns = 7,
        .machine_id = "test-machine",
        .hostname = null,
        .report_path = "unused.json",
        .github_sha = null,
        .github_run_id = null,
        .github_ref_name = null,
        .extra_header_json = "  \"samples_per_benchmark\": 5,\n",
    }, void, {}, Entries.write);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, out.items, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, @intCast(schema_version)), root.get("schema_version").?.integer);
    try std.testing.expectEqualStrings("quic_zig.report_test", root.get("suite").?.string);
    try std.testing.expectEqual(@as(i64, 5), root.get("samples_per_benchmark").?.integer);
    const benchmarks = root.get("benchmarks").?.array;
    try std.testing.expectEqual(@as(usize, 1), benchmarks.items.len);
    try std.testing.expectEqualStrings("micro", benchmarks.items[0].object.get("kind").?.string);
}
