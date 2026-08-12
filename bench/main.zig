//! quic_zig microbenchmarks.
//!
//! Measures hot paths that every sent or received packet exercises:
//!  - varint encode/decode (every length field)
//!  - frame encode/decode (STREAM, ACK)
//!  - short-header pure parse/serialize (no AEAD)
//!  - connection ID generation (BoringSSL CSPRNG)
//!  - packet protection, AEAD, and header protection
//!  - stream send/receive state and reassembly
//!  - ACK range, loss recovery, PTO, and DATAGRAM event surfaces
//!
//! Each benchmark auto-tunes its iteration count to roughly
//! `target_ms` of wall time, then times `--samples` independent hot
//! runs (default 5) and reports robust statistics, printing one line:
//!
//!     name: <median> ns/op ±<MAD> (<ops/sec> ops/sec, <N>x<iters> iters)
//!
//! Median + MAD (median absolute deviation) rather than a single run:
//! shared-runner noise is heavy-tailed, and one preempted sample must
//! not move the headline number. The JSON report (schema v3, shared
//! writer in `report.zig`) carries the raw samples alongside the
//! statistics; `ns_per_op` remains the median for v2 readers.
//!
//! Run with: `zig build bench`, or `zig build bench -- --json path`
//! for a machine-readable report (`--samples N` to override the sample
//! count). The build wires this binary at ReleaseSafe by default; use
//! `-Dbench-unsafe-release-fast=true` for unsafe ReleaseFast
//! measurements.
//!
//! Out of scope:
//!  - Full Connection.handle / pollDatagram lifecycle
//!  - TLS handshake throughput

const std = @import("std");
const builtin = @import("builtin");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const report_mod = @import("report.zig");
const connection_datagram_bench = @import("connection_datagram.zig");
const loss_ack_bench = @import("loss_ack.zig");
const packet_crypto_bench = @import("packet_crypto.zig");
const path_flow_bench = @import("path_flow.zig");
const stream_bench = @import("stream_reassembly.zig");
const tokens_lb_bench = @import("tokens_lb.zig");
const transport_params_bench = @import("transport_params.zig");

const varint = quic_zig.wire.varint;
const header = quic_zig.wire.header;
const frame = quic_zig.frame;
const frame_types = frame.types;
const ack_range = frame.ack_range;

/// Approximate per-benchmark wall budget. We grow the iteration
/// count until elapsed >= this.
const target_ns: u64 = 100 * std.time.ns_per_ms;
const max_bench_results: usize = 64;

/// Lower bound so very fast benchmarks (sub-ns/op) still produce
/// stable numbers.
const min_iters: u64 = 1_000;

/// Upper bound to keep one-shot runs from looping forever on a
/// dead-fast benchmark.
const max_iters: u64 = 200_000_000;

/// Default and ceiling for the per-benchmark sample count. Five samples
/// keep a local run near the old single-run wall time; CI passes more.
const default_samples: usize = 5;
const max_samples: usize = 32;

/// Set once from `--samples` before any benchmark runs. File-scope
/// rather than threaded through 30+ `recordBenchmark` call sites — this
/// is a standalone tool, not library code.
var configured_samples: usize = default_samples;

/// Read a monotonic clock in nanoseconds. We dodge `std.time` here
/// because Zig 0.16 moved time to the new I/O API, and these
/// benchmarks are deliberately Io-free — they exercise pure
/// codecs, not async machinery.
fn nowNanos() u64 {
    var ts: std.c.timespec = undefined;
    // POSIX MONOTONIC. macOS, Linux, BSDs all support this.
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec *% std.time.ns_per_s +% nsec;
}

fn unixNanos() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec *% std.time.ns_per_s +% nsec;
}

fn hostnameSlice(buf: *[std.posix.HOST_NAME_MAX]u8) ?[]const u8 {
    return std.posix.gethostname(buf) catch null;
}

const BenchResult = struct {
    name: []const u8,
    /// Iterations per sample (all samples run the same count).
    iters: u64,
    /// Wall time summed across all samples.
    total_ns: u64,
    /// Legacy headline field, defined as the median since schema v3.
    ns_per_op: f64,
    /// Derived from the median.
    ops_per_sec: f64,
    sample_count: usize,
    /// Raw per-sample ns/op, in run order; only `[0..sample_count]` valid.
    samples_ns_per_op: [max_samples]f64,
    median_ns_per_op: f64,
    mad_ns_per_op: f64,
    min_ns_per_op: f64,
};

fn report(r: BenchResult) void {
    std.debug.print(
        "{s}: {d:.2} ns/op \u{b1}{d:.2} ({d:.2} ops/sec, {d}x{d} iters)\n",
        .{ r.name, r.median_ns_per_op, r.mad_ns_per_op, r.ops_per_sec, r.sample_count, r.iters },
    );
}

/// Run `runOnce` repeatedly with auto-tuned iteration count, then time
/// `configured_samples` independent hot passes. `runOnce(iters)` must
/// perform exactly `iters` work units and return a value to feed
/// `doNotOptimizeAway`. The calibration pass doubles as warmup.
fn benchmark(
    name: []const u8,
    comptime Ctx: type,
    ctx: Ctx,
    comptime runOnce: fn (Ctx, u64) u64,
) BenchResult {
    // Warmup + calibration: start small and double until we cross
    // ~10ms, then extrapolate to target_ns per sample.
    var iters: u64 = min_iters;
    var elapsed_ns: u64 = 0;
    const calibration_floor: u64 = 10 * std.time.ns_per_ms;

    while (iters <= max_iters) {
        const start = nowNanos();
        const sink = runOnce(ctx, iters);
        const end = nowNanos();
        std.mem.doNotOptimizeAway(sink);
        elapsed_ns = end - start;
        if (elapsed_ns >= calibration_floor) break;
        iters *|= 2;
    }

    if (iters > max_iters) iters = max_iters;

    // Extrapolate to ~target_ns based on the calibration run.
    if (elapsed_ns > 0) {
        const scaled: u128 = @as(u128, iters) * @as(u128, target_ns) / @as(u128, elapsed_ns);
        var next: u64 = @intCast(@min(scaled, @as(u128, max_iters)));
        if (next < min_iters) next = min_iters;
        iters = next;
    }

    // Hot runs: N independent samples at the same iteration count.
    const sample_count = configured_samples;
    var samples: [max_samples]f64 = undefined;
    var total_ns: u64 = 0;
    for (samples[0..sample_count]) |*sample| {
        const start = nowNanos();
        const sink = runOnce(ctx, iters);
        const end = nowNanos();
        std.mem.doNotOptimizeAway(sink);
        const t = end - start;
        total_ns += t;
        sample.* = @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(iters));
    }

    var sorted: [max_samples]f64 = samples;
    const median = report_mod.medianInPlace(sorted[0..sample_count]);
    var scratch: [max_samples]f64 = undefined;
    const mad = report_mod.medianAbsoluteDeviation(samples[0..sample_count], median, &scratch);
    const min_ns_per_op = sorted[0];
    const ops_per_sec: f64 = if (median <= 0) 0 else 1e9 / median;

    const result: BenchResult = .{
        .name = name,
        .iters = iters,
        .total_ns = total_ns,
        .ns_per_op = median,
        .ops_per_sec = ops_per_sec,
        .sample_count = sample_count,
        .samples_ns_per_op = samples,
        .median_ns_per_op = median,
        .mad_ns_per_op = mad,
        .min_ns_per_op = min_ns_per_op,
    };
    report(result);
    return result;
}

fn recordBenchmark(
    results: *[max_bench_results]BenchResult,
    result_count: *usize,
    name: []const u8,
    comptime Ctx: type,
    ctx: Ctx,
    comptime runOnce: fn (Ctx, u64) u64,
) void {
    results[result_count.*] = benchmark(name, Ctx, ctx, runOnce);
    result_count.* += 1;
}

/// Writes the schema-v3 `"benchmarks"` array elements for the
/// microbenchmark suite. Passed to `report_mod.writeReport`.
fn writeMicroEntries(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    results: []const BenchResult,
) anyerror!void {
    for (results, 0..) |r, i| {
        try out.appendSlice(allocator, "    {\n");
        try out.appendSlice(allocator, "      \"name\": ");
        try report_mod.appendJsonString(out, allocator, r.name);
        try out.appendSlice(allocator, ",\n");
        try out.appendSlice(allocator, "      \"kind\": \"micro\",\n");
        try out.print(allocator, "      \"iterations\": {d},\n", .{r.iters});
        try out.print(allocator, "      \"total_ns\": {d},\n", .{r.total_ns});
        try out.print(allocator, "      \"ns_per_op\": {d:.6},\n", .{r.ns_per_op});
        try out.print(allocator, "      \"ops_per_sec\": {d:.6},\n", .{r.ops_per_sec});
        try out.print(allocator, "      \"sample_count\": {d},\n", .{r.sample_count});
        try out.appendSlice(allocator, "      \"samples_ns_per_op\": [");
        for (r.samples_ns_per_op[0..r.sample_count], 0..) |s, j| {
            if (j != 0) try out.appendSlice(allocator, ", ");
            try out.print(allocator, "{d:.6}", .{s});
        }
        try out.appendSlice(allocator, "],\n");
        try out.print(allocator, "      \"median_ns_per_op\": {d:.6},\n", .{r.median_ns_per_op});
        try out.print(allocator, "      \"mad_ns_per_op\": {d:.6},\n", .{r.mad_ns_per_op});
        try out.print(allocator, "      \"min_ns_per_op\": {d:.6}\n", .{r.min_ns_per_op});
        try out.appendSlice(allocator, if (i + 1 == results.len) "    }\n" else "    },\n");
    }
}

// -- varint --------------------------------------------------------------

const VarintCtx = struct {
    inputs: [4]u64,
};

fn runVarintEncode(ctx: VarintCtx, iters: u64) u64 {
    var sink: [8]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const v = ctx.inputs[i & 3];
        const n = varint.encode(&sink, v) catch unreachable;
        sum +%= @intCast(n);
        sum +%= sink[0];
    }
    return sum;
}

fn runVarintDecode(ctx: VarintCtx, iters: u64) u64 {
    // Pre-encode the four canonical lengths.
    var encoded: [4][8]u8 = undefined;
    var lens: [4]u8 = undefined;
    for (ctx.inputs, 0..) |v, idx| {
        const n = varint.encode(&encoded[idx], v) catch unreachable;
        lens[idx] = @intCast(n);
    }
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const idx = i & 3;
        const slice = encoded[idx][0..lens[idx]];
        const d = varint.decode(slice) catch unreachable;
        sum +%= d.value;
        sum +%= d.bytes_read;
    }
    return sum;
}

// -- frames: STREAM ------------------------------------------------------

const StreamCtx = struct {
    payload: [100]u8,
};

fn streamFrame(ctx: *const StreamCtx) frame.Frame {
    return .{ .stream = .{
        .stream_id = 4,
        .offset = 1024,
        .data = &ctx.payload,
        .has_offset = true,
        .has_length = true,
        .fin = false,
    } };
}

fn runStreamEncode(ctx: *const StreamCtx, iters: u64) u64 {
    const f = streamFrame(ctx);
    var buf: [256]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = frame.encode(&buf, f) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runStreamDecode(ctx: *const StreamCtx, iters: u64) u64 {
    const f = streamFrame(ctx);
    var encoded: [256]u8 = undefined;
    const enc_len = frame.encode(&encoded, f) catch unreachable;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const d = frame.decode(encoded[0..enc_len]) catch unreachable;
        sum +%= d.bytes_consumed;
        sum +%= d.frame.stream.stream_id;
    }
    return sum;
}

// -- frames: ACK ---------------------------------------------------------

const AckCtx = struct {
    /// Encoded gap/length pairs for 5 subsequent ranges. Built once
    /// in `init` so the encode/decode timing doesn't include
    /// writeRanges.
    ranges_bytes: []const u8,
    ranges_buf: [64]u8,
    ranges_len: usize,
};

fn ackFrame(ctx: *const AckCtx) frame.Frame {
    return .{ .ack = .{
        .largest_acked = 1_000,
        .ack_delay = 250,
        .first_range = 4,
        .range_count = 5,
        .ranges_bytes = ctx.ranges_bytes,
        .ecn_counts = null,
    } };
}

fn runAckEncode(ctx: *const AckCtx, iters: u64) u64 {
    const f = ackFrame(ctx);
    var buf: [128]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = frame.encode(&buf, f) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runAckDecode(ctx: *const AckCtx, iters: u64) u64 {
    const f = ackFrame(ctx);
    var encoded: [128]u8 = undefined;
    const enc_len = frame.encode(&encoded, f) catch unreachable;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const d = frame.decode(encoded[0..enc_len]) catch unreachable;
        sum +%= d.bytes_consumed;
        sum +%= d.frame.ack.largest_acked;
    }
    return sum;
}

// -- short-header packet (1-RTT) ----------------------------------------

const ShortHdrCtx = struct {
    dcid: header.ConnId,
    pn_truncated: u64,
};

fn shortHeader(ctx: *const ShortHdrCtx) header.Header {
    return .{ .one_rtt = .{
        .dcid = ctx.dcid,
        .spin_bit = false,
        .reserved_bits = 0,
        .key_phase = false,
        .pn_length = .four,
        .pn_truncated = ctx.pn_truncated,
    } };
}

fn runShortEncode(ctx: *const ShortHdrCtx, iters: u64) u64 {
    const h = shortHeader(ctx);
    var buf: [64]u8 = undefined;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const n = header.encode(&buf, h) catch unreachable;
        sum +%= n;
        sum +%= buf[0];
    }
    return sum;
}

fn runShortDecode(ctx: *const ShortHdrCtx, iters: u64) u64 {
    const h = shortHeader(ctx);
    var encoded: [64]u8 = undefined;
    const enc_len = header.encode(&encoded, h) catch unreachable;
    const dcid_len = ctx.dcid.len;
    var sum: u64 = 0;
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        const p = header.parse(encoded[0..enc_len], dcid_len) catch unreachable;
        sum +%= p.pn_offset;
        sum +%= p.header.one_rtt.pn_truncated;
    }
    return sum;
}

// -- connection ID generation -------------------------------------------

const CidCtx = struct {
    /// Match the QUIC v1 default DCID length most stacks pick (8).
    cid_len: u8,
};

fn runCidGenerate(ctx: CidCtx, iters: u64) u64 {
    var sum: u64 = 0;
    var bytes: [header.max_cid_len]u8 = undefined;
    const slice = bytes[0..ctx.cid_len];
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        boringssl.crypto.rand.fillBytes(slice) catch unreachable;
        // Fold all output into the sink so the optimizer can't
        // hoist the call.
        for (slice) |b| sum +%= b;
    }
    return sum;
}

// -- entry point ---------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var json_path: ?[]const u8 = null;
    var json_dir: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--json")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonPath;
            if (json_dir != null) return error.DuplicateJsonTarget;
            json_path = args[i];
        } else if (std.mem.eql(u8, args[i], "--json-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonDir;
            if (json_path != null) return error.DuplicateJsonTarget;
            json_dir = args[i];
        } else if (std.mem.eql(u8, args[i], "--samples")) {
            i += 1;
            if (i >= args.len) return error.MissingSampleCount;
            const n = std.fmt.parseInt(usize, args[i], 10) catch return error.InvalidSampleCount;
            if (n < 1 or n > max_samples) return error.InvalidSampleCount;
            configured_samples = n;
        } else {
            std.debug.print("unknown benchmark argument: {s}\n", .{args[i]});
            return error.UnknownArgument;
        }
    }

    const generated_unix_ns = unixNanos();
    var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
    const hostname = hostnameSlice(&hostname_buf);
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
            "quic-zig-bench",
            generated_unix_ns,
            machine_id,
            github_sha,
            github_run_id,
        )
    else
        null;

    std.debug.print("quic_zig microbenchmarks (target ~{d}ms/sample, {d} samples, {s})\n", .{
        target_ns / std.time.ns_per_ms,
        configured_samples,
        @tagName(builtin.mode),
    });
    std.debug.print("---------------------------------------------------------------\n", .{});

    var results: [max_bench_results]BenchResult = undefined;
    var result_count: usize = 0;

    // varint
    const varint_ctx: VarintCtx = .{ .inputs = .{
        0x3F,
        0x3FFF,
        0x3FFF_FFFF,
        0x3FFF_FFFF_FFFF_FFFF,
    } };
    recordBenchmark(&results, &result_count, "varint_encode", VarintCtx, varint_ctx, runVarintEncode);
    recordBenchmark(&results, &result_count, "varint_decode", VarintCtx, varint_ctx, runVarintDecode);

    // STREAM frame
    var stream_ctx: StreamCtx = .{ .payload = undefined };
    for (&stream_ctx.payload, 0..) |*b, idx| b.* = @intCast(idx & 0xff);
    recordBenchmark(&results, &result_count, "frame_stream_encode_100b", *const StreamCtx, &stream_ctx, runStreamEncode);
    recordBenchmark(&results, &result_count, "frame_stream_decode_100b", *const StreamCtx, &stream_ctx, runStreamDecode);

    // ACK frame with 5 ranges
    var ack_ctx: AckCtx = .{
        .ranges_bytes = undefined,
        .ranges_buf = undefined,
        .ranges_len = 0,
    };
    {
        const ranges = [_]frame_types.AckRange{
            .{ .gap = 1, .length = 3 },
            .{ .gap = 2, .length = 5 },
            .{ .gap = 1, .length = 2 },
            .{ .gap = 4, .length = 7 },
            .{ .gap = 0, .length = 1 },
        };
        ack_ctx.ranges_len = try ack_range.writeRanges(&ack_ctx.ranges_buf, &ranges);
        ack_ctx.ranges_bytes = ack_ctx.ranges_buf[0..ack_ctx.ranges_len];
    }
    recordBenchmark(&results, &result_count, "frame_ack_encode_5ranges", *const AckCtx, &ack_ctx, runAckEncode);
    recordBenchmark(&results, &result_count, "frame_ack_decode_5ranges", *const AckCtx, &ack_ctx, runAckDecode);

    // Short-header packet (no AEAD; pure header bytes)
    var short_ctx: ShortHdrCtx = .{
        .dcid = try header.ConnId.fromSlice(&[_]u8{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 }),
        .pn_truncated = 0x12345678,
    };
    _ = &short_ctx;
    recordBenchmark(&results, &result_count, "short_header_encode", *const ShortHdrCtx, &short_ctx, runShortEncode);
    recordBenchmark(&results, &result_count, "short_header_decode", *const ShortHdrCtx, &short_ctx, runShortDecode);

    // Connection ID generation (BoringSSL CSPRNG, 8-byte CID)
    recordBenchmark(&results, &result_count, "cid_generate_8bytes", CidCtx, .{ .cid_len = 8 }, runCidGenerate);

    // Packet protection and AEAD paths
    const hp_ctx = try packet_crypto_bench.initHpMaskAes128CachedCtx();
    recordBenchmark(
        &results,
        &result_count,
        "hp_mask_aes128_cached",
        *const packet_crypto_bench.HpMaskAes128CachedCtx,
        &hp_ctx,
        packet_crypto_bench.runHpMaskAes128Cached,
    );
    var aead_seal_ctx = try packet_crypto_bench.initAeadAes128Seal1200bCtx();
    defer aead_seal_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        "aead_aes128_seal_1200b",
        *const packet_crypto_bench.AeadAes128Seal1200bCtx,
        &aead_seal_ctx,
        packet_crypto_bench.runAeadAes128Seal1200b,
    );
    var aead_open_ctx = try packet_crypto_bench.initAeadAes128Open1200bCtx();
    defer aead_open_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        "aead_aes128_open_1200b",
        *const packet_crypto_bench.AeadAes128Open1200bCtx,
        &aead_open_ctx,
        packet_crypto_bench.runAeadAes128Open1200b,
    );
    const packet_1rtt_seal_ctx = try packet_crypto_bench.initPacket1RttSeal100bAes128Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_1rtt_seal_100b_aes128",
        *const packet_crypto_bench.Packet1RttSeal100bAes128Ctx,
        &packet_1rtt_seal_ctx,
        packet_crypto_bench.runPacket1RttSeal100bAes128,
    );
    const packet_1rtt_open_ctx = try packet_crypto_bench.initPacket1RttOpen100bAes128Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_1rtt_open_100b_aes128",
        *const packet_crypto_bench.Packet1RttOpen100bAes128Ctx,
        &packet_1rtt_open_ctx,
        packet_crypto_bench.runPacket1RttOpen100bAes128,
    );
    const initial_seal_ctx = try packet_crypto_bench.initPacketInitialSeal1200bRfc9001Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_initial_seal_1200b_rfc9001",
        *const packet_crypto_bench.PacketInitialSeal1200bRfc9001Ctx,
        &initial_seal_ctx,
        packet_crypto_bench.runPacketInitialSeal1200bRfc9001,
    );
    var initial_open_ctx = try packet_crypto_bench.initPacketInitialOpen1200bRfc9001Ctx();
    recordBenchmark(
        &results,
        &result_count,
        "packet_initial_open_1200b_rfc9001",
        *packet_crypto_bench.PacketInitialOpen1200bRfc9001Ctx,
        &initial_open_ctx,
        packet_crypto_bench.runPacketInitialOpen1200bRfc9001,
    );

    // Stream send/receive state machines
    var stream_send_ctx = try stream_bench.initStreamSendAckLossRequeueCtx(allocator);
    defer stream_send_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        stream_bench.stream_send_ack_loss_requeue_name,
        *const stream_bench.StreamSendAckLossRequeueCtx,
        &stream_send_ctx,
        stream_bench.runStreamSendAckLossRequeue,
    );
    var stream_recv_ctx = try stream_bench.initStreamRecvReassemblySparse64kCtx(allocator);
    defer stream_recv_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        stream_bench.stream_recv_reassembly_sparse_64k_name,
        *const stream_bench.StreamRecvReassemblySparse64kCtx,
        &stream_recv_ctx,
        stream_bench.runStreamRecvReassemblySparse64k,
    );

    // ACK range and loss recovery primitives
    const pn_ack_ctx = loss_ack_bench.initPnSpaceRecordAckRangesCtx();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.pn_space_record_ack_ranges_name,
        *const loss_ack_bench.PnSpaceRecordAckRangesCtx,
        &pn_ack_ctx,
        loss_ack_bench.runPnSpaceRecordAckRanges,
    );
    const loss_pto_ctx = loss_ack_bench.initLossPtoTickCtx();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.loss_pto_tick_name,
        *const loss_ack_bench.LossPtoTickCtx,
        &loss_pto_ctx,
        loss_ack_bench.runLossPtoTick,
    );
    var connection_ack_loss_ctx = try loss_ack_bench.initConnectionAckLossDispatchCtx(allocator);
    defer connection_ack_loss_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.connection_ack_loss_dispatch_name,
        *const loss_ack_bench.ConnectionAckLossDispatchCtx,
        &connection_ack_loss_ctx,
        loss_ack_bench.runConnectionAckLossDispatch,
    );
    var tracker_churn_ctx = try loss_ack_bench.initTrackerChurnHighOccupancyCtx(allocator);
    defer tracker_churn_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        loss_ack_bench.tracker_churn_high_occupancy_name,
        *const loss_ack_bench.TrackerChurnHighOccupancyCtx,
        &tracker_churn_ctx,
        loss_ack_bench.runTrackerChurnHighOccupancy,
    );

    // Connection-adjacent DATAGRAM ACK/loss event queue
    const datagram_event_ctx = connection_datagram_bench.initDatagramEventCtx();
    recordBenchmark(
        &results,
        &result_count,
        "conn_datagram_send_ack_loss_events",
        *const connection_datagram_bench.DatagramEventCtx,
        &datagram_event_ctx,
        connection_datagram_bench.runConnDatagramSendAckLossEvents,
    );

    // Transport-parameter codec paths
    var tp_encode_ctx = try transport_params_bench.initTransportParamsEncodeCommonCtx();
    defer tp_encode_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_encode_common_name,
        *const transport_params_bench.TransportParamsEncodeCommonCtx,
        &tp_encode_ctx,
        transport_params_bench.runTransportParamsEncodeCommon,
    );
    var tp_decode_ctx = try transport_params_bench.initTransportParamsDecodeCommonCtx();
    defer tp_decode_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_decode_common_name,
        *const transport_params_bench.TransportParamsDecodeCommonCtx,
        &tp_decode_ctx,
        transport_params_bench.runTransportParamsDecodeCommon,
    );
    var tp_extensions_ctx = try transport_params_bench.initTransportParamsDecodeExtensionsCtx();
    defer tp_extensions_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        transport_params_bench.transport_params_decode_extensions_name,
        *const transport_params_bench.TransportParamsDecodeExtensionsCtx,
        &tp_extensions_ctx,
        transport_params_bench.runTransportParamsDecodeExtensions,
    );

    // Token, stateless-reset, and QUIC-LB helpers
    var retry_token_ctx = tokens_lb_bench.initRetryTokenMintValidateCtx();
    defer retry_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.retry_token_mint_validate_name,
        *const tokens_lb_bench.RetryTokenMintValidateCtx,
        &retry_token_ctx,
        tokens_lb_bench.runRetryTokenMintValidate,
    );
    var new_token_ctx = tokens_lb_bench.initNewTokenMintValidateCtx();
    defer new_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.new_token_mint_validate_name,
        *const tokens_lb_bench.NewTokenMintValidateCtx,
        &new_token_ctx,
        tokens_lb_bench.runNewTokenMintValidate,
    );
    var reset_token_ctx = tokens_lb_bench.initStatelessResetTokenDeriveCtx();
    defer reset_token_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.stateless_reset_token_derive_name,
        *const tokens_lb_bench.StatelessResetTokenDeriveCtx,
        &reset_token_ctx,
        tokens_lb_bench.runStatelessResetTokenDerive,
    );
    var quic_lb_ctx = try tokens_lb_bench.initQuicLbCidGenerateCtx();
    defer quic_lb_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        tokens_lb_bench.quic_lb_cid_generate_name,
        *const tokens_lb_bench.QuicLbCidGenerateCtx,
        &quic_lb_ctx,
        tokens_lb_bench.runQuicLbCidGenerate,
    );

    // Flow-control, path-validation, and path scheduling helpers
    var flow_control_ctx = path_flow_bench.initFlowControlCreditUpdateCtx();
    defer flow_control_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.flow_control_credit_update_name,
        *const path_flow_bench.FlowControlCreditUpdateCtx,
        &flow_control_ctx,
        path_flow_bench.runFlowControlCreditUpdate,
    );
    var path_validator_ctx = path_flow_bench.initPathValidatorChallengeResponseCtx();
    defer path_validator_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.path_validator_challenge_response_name,
        *const path_flow_bench.PathValidatorChallengeResponseCtx,
        &path_validator_ctx,
        path_flow_bench.runPathValidatorChallengeResponse,
    );
    var path_set_ctx = try path_flow_bench.initPathSetScheduleRoundRobinCtx(allocator);
    defer path_set_ctx.deinit();
    recordBenchmark(
        &results,
        &result_count,
        path_flow_bench.path_set_schedule_round_robin_name,
        *const path_flow_bench.PathSetScheduleRoundRobinCtx,
        &path_set_ctx,
        path_flow_bench.runPathSetScheduleRoundRobin,
    );

    std.debug.print("---------------------------------------------------------------\n", .{});
    if (report_path) |path| {
        var extra_header: std.ArrayList(u8) = .empty;
        defer extra_header.deinit(allocator);
        try extra_header.print(allocator, "  \"target_ns_per_benchmark\": {d},\n", .{target_ns});
        try extra_header.print(allocator, "  \"min_iters\": {d},\n", .{min_iters});
        try extra_header.print(allocator, "  \"max_iters\": {d},\n", .{max_iters});
        try extra_header.print(allocator, "  \"samples_per_benchmark\": {d},\n", .{configured_samples});
        try report_mod.writeReport(
            allocator,
            io,
            .{
                .suite = "quic_zig.microbench",
                .generated_unix_ns = generated_unix_ns,
                .machine_id = machine_id,
                .hostname = hostname,
                .report_path = path,
                .github_sha = github_sha,
                .github_run_id = github_run_id,
                .github_ref_name = github_ref_name,
                .extra_header_json = extra_header.items,
            },
            []const BenchResult,
            results[0..result_count],
            writeMicroEntries,
        );
        std.debug.print("wrote benchmark JSON report: {s}\n", .{path});
    }
    std.debug.print("done. {d} benchmarks ran.\n", .{result_count});
}
