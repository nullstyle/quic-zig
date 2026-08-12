//! In-process client+server Connection pair and the e2e benchmark
//! scenario engines (goodput, handshakes/sec, impairment goodput).
//!
//! Mirrors the canonical shape from
//! tests/e2e/mock_transport_stream_exchange.zig: two `Connection`s
//! TLS-paired via `peer` (so `advance()` completes a real TLS 1.3
//! handshake in memory), fixed CIDs, and a `poll` -> `handle` datagram
//! shuttle on a virtual clock. No sockets anywhere: wall-clock numbers
//! measure stack CPU efficiency, virtual-clock numbers (impairment)
//! measure protocol behavior deterministically.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");
const sim_net = @import("sim_net.zig");
const counting_allocator = @import("counting_allocator.zig");

pub const CountingAllocator = counting_allocator.CountingAllocator;

const test_cert_pem = @embedFile("support/test_cert.pem");
const test_key_pem = @embedFile("support/test_key.pem");

const client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
const server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x99 };

/// Monotonic wall clock in ns (same dodge as bench/main.zig: these
/// binaries are deliberately Io-free on the measurement path).
pub fn nowNanos() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    const sec: u64 = @intCast(ts.sec);
    const nsec: u64 = @intCast(ts.nsec);
    return sec *% std.time.ns_per_s +% nsec;
}

pub const PairOptions = struct {
    alpn: []const u8 = "hq-bench",
    initial_max_data: u64 = 1 << 24,
    initial_max_stream_data: u64 = 1 << 22,
    initial_max_streams_bidi: u64 = 16,
    /// Congestion controller for both endpoints — the A/B lever the
    /// CUBIC-default flip gate drives. Follows the library default.
    congestion_control: quic_zig.CongestionAlgorithm = .cubic,
    /// RFC 9406 HyStart++ on both endpoints (A/B lever).
    hystart: bool = true,
};

/// Heap-allocated so the `peer` cross-pointers stay valid.
pub const Pair = struct {
    server_tls: boringssl.tls.Context,
    client_tls: boringssl.tls.Context,
    client: quic_zig.Connection,
    server: quic_zig.Connection,

    pub fn create(allocator: std.mem.Allocator, opts: PairOptions) !*Pair {
        const pair = try allocator.create(Pair);
        errdefer allocator.destroy(pair);

        const protos = [_][]const u8{opts.alpn};
        pair.server_tls = try boringssl.tls.Context.initServer(.{
            .verify = .none,
            .min_version = boringssl.raw.TLS1_3_VERSION,
            .max_version = boringssl.raw.TLS1_3_VERSION,
            .alpn = &protos,
        });
        errdefer pair.server_tls.deinit();
        try pair.server_tls.loadCertChainAndKey(test_cert_pem, test_key_pem);
        pair.client_tls = try boringssl.tls.Context.initClient(.{
            .verify = .none,
            .min_version = boringssl.raw.TLS1_3_VERSION,
            .max_version = boringssl.raw.TLS1_3_VERSION,
            .alpn = &protos,
        });
        errdefer pair.client_tls.deinit();

        // Pair is heap-allocated, so the embedded Connections sit at
        // their final addresses — the in-place constructors wire TLS
        // immediately (there is no bind-later step anymore).
        try quic_zig.Connection.initClientAt(&pair.client, allocator, pair.client_tls, "localhost");
        errdefer pair.client.deinit();
        try quic_zig.Connection.initServerAt(&pair.server, allocator, pair.server_tls);
        errdefer pair.server.deinit();

        pair.client.peer = &pair.server;
        pair.server.peer = &pair.client;

        const tp: quic_zig.tls.TransportParams = .{
            .initial_max_data = opts.initial_max_data,
            .initial_max_stream_data_bidi_local = opts.initial_max_stream_data,
            .initial_max_stream_data_bidi_remote = opts.initial_max_stream_data,
            .initial_max_streams_bidi = opts.initial_max_streams_bidi,
        };
        try pair.client.setTransportParams(tp);
        try pair.server.setTransportParams(tp);

        var step: u32 = 0;
        while (step < 50) : (step += 1) {
            if (pair.client.handshakeDone() and pair.server.handshakeDone()) break;
            try pair.client.advance();
            try pair.server.advance();
        }
        if (!pair.client.handshakeDone() or !pair.server.handshakeDone()) {
            return error.HandshakeStalled;
        }

        try pair.client.setPeerDcid(&server_cid);
        try pair.client.setLocalScid(&client_cid);
        try pair.server.setPeerDcid(&client_cid);
        try pair.server.setLocalScid(&server_cid);

        pair.client.setCongestionAlgorithm(opts.congestion_control);
        pair.server.setCongestionAlgorithm(opts.congestion_control);
        pair.client.setHyStartEnabled(opts.hystart);
        pair.server.setHyStartEnabled(opts.hystart);

        return pair;
    }

    pub fn destroy(self: *Pair, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.server.deinit();
        self.server_tls.deinit();
        self.client_tls.deinit();
        allocator.destroy(self);
    }
};

// -- goodput ---------------------------------------------------------------

pub const GoodputOptions = struct {
    total_bytes: usize = 64 << 20,
    chunk_bytes: usize = 256 << 10,
    congestion_control: quic_zig.CongestionAlgorithm = .cubic,
    /// Virtual-clock step per shuttle iteration.
    tick_us: u64 = 100,
    /// Cap on collected per-poll latency samples (8 bytes each).
    max_latency_samples: usize = 1 << 20,
};

pub const GoodputResult = struct {
    total_bytes: usize,
    wall_ns: u64,
    mb_per_sec: f64,
    client_polls: u64,
    datagrams: u64,
    /// Allocation movement across the transfer phase only (pair setup
    /// and handshake excluded).
    transfer_allocs: u64,
    transfer_frees: u64,
    transfer_bytes_allocated: u64,
    poll_p50_ns: u64,
    poll_p90_ns: u64,
    poll_p99_ns: u64,
    poll_max_ns: u64,
};

fn percentileSorted(sorted: []const u64, pct: f64) u64 {
    if (sorted.len == 0) return 0;
    const rank = pct / 100.0 * @as(f64, @floatFromInt(sorted.len - 1));
    const idx: usize = @intFromFloat(@round(rank));
    return sorted[@min(idx, sorted.len - 1)];
}

/// One full bulk transfer over the in-memory shuttle. `counting`, when
/// provided, must be the allocator the pair was created with — the
/// transfer-phase delta is measured through it.
pub fn runGoodputOnce(
    allocator: std.mem.Allocator,
    counting: ?*CountingAllocator,
    opts: GoodputOptions,
) !GoodputResult {
    const pair_allocator = if (counting) |c| c.allocator() else allocator;
    const pair = try Pair.create(pair_allocator, .{ .congestion_control = opts.congestion_control });
    defer pair.destroy(pair_allocator);

    const data = try allocator.alloc(u8, opts.chunk_bytes);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0x900d);
    prng.random().bytes(data);

    const latencies = try allocator.alloc(u64, opts.max_latency_samples);
    defer allocator.free(latencies);
    var latency_count: usize = 0;

    var rbuf: [64 << 10]u8 = undefined;
    var pkt: [2048]u8 = undefined;

    _ = try pair.client.openBidi(0);

    const before = if (counting) |c| c.snapshot() else null;
    var written: usize = 0;
    var consumed: usize = 0;
    var now_us: u64 = 1_000_000;
    var client_polls: u64 = 0;
    var datagrams: u64 = 0;

    const wall_start = nowNanos();
    while (consumed < opts.total_bytes) {
        // Offer more data whenever the send side has room.
        while (written < opts.total_bytes) {
            const want = @min(opts.chunk_bytes, opts.total_bytes - written);
            const accepted = try pair.client.streamWrite(0, data[0..want]);
            written += accepted;
            if (accepted < want) break;
        }
        if (written == opts.total_bytes and !pair.client.stream(0).?.send.fin_marked) {
            try pair.client.streamFinish(0);
        }

        // Drain every pending datagram both ways; cwnd bounds the burst.
        var progressed = true;
        while (progressed) {
            progressed = false;
            const poll_start = nowNanos();
            const maybe_out = try pair.client.poll(&pkt, now_us);
            const poll_ns = nowNanos() - poll_start;
            client_polls += 1;
            if (latency_count < latencies.len) {
                latencies[latency_count] = poll_ns;
                latency_count += 1;
            }
            if (maybe_out) |n| {
                datagrams += 1;
                try pair.server.handle(pkt[0..n], null, now_us);
                progressed = true;
            }
            if (try pair.server.poll(&pkt, now_us)) |n| {
                datagrams += 1;
                try pair.client.handle(pkt[0..n], null, now_us);
                progressed = true;
            }
        }

        while (true) {
            // The stream doesn't exist server-side until the first
            // STREAM frame lands.
            const got = pair.server.streamRead(0, &rbuf) catch |err| switch (err) {
                error.StreamNotFound => break,
                else => return err,
            };
            if (got == 0) break;
            consumed += got;
        }

        now_us += opts.tick_us;
        try pair.client.tick(now_us);
        try pair.server.tick(now_us);
    }
    const wall_ns = nowNanos() - wall_start;

    const delta = if (counting) |c| c.snapshot().since(before.?) else null;

    std.mem.sort(u64, latencies[0..latency_count], {}, std.sort.asc(u64));
    const secs = @as(f64, @floatFromInt(wall_ns)) / 1e9;

    return .{
        .total_bytes = opts.total_bytes,
        .wall_ns = wall_ns,
        .mb_per_sec = if (secs <= 0) 0 else @as(f64, @floatFromInt(opts.total_bytes)) / (1024.0 * 1024.0) / secs,
        .client_polls = client_polls,
        .datagrams = datagrams,
        .transfer_allocs = if (delta) |d| d.allocs else 0,
        .transfer_frees = if (delta) |d| d.frees else 0,
        .transfer_bytes_allocated = if (delta) |d| d.bytes_allocated else 0,
        .poll_p50_ns = percentileSorted(latencies[0..latency_count], 50),
        .poll_p90_ns = percentileSorted(latencies[0..latency_count], 90),
        .poll_p99_ns = percentileSorted(latencies[0..latency_count], 99),
        .poll_max_ns = if (latency_count == 0) 0 else latencies[latency_count - 1],
    };
}

// -- handshakes/sec ----------------------------------------------------------

pub const HandshakeOptions = struct {
    /// Stop after this much wall time or `max_handshakes`, whichever
    /// comes first.
    min_wall_ns: u64 = 300 * std.time.ns_per_ms,
    max_handshakes: u32 = 500,
};

pub const HandshakeResult = struct {
    handshakes: u32,
    wall_ns: u64,
    handshakes_per_sec: f64,
    allocs_per_handshake: f64,
};

pub fn runHandshakesOnce(
    allocator: std.mem.Allocator,
    counting: *CountingAllocator,
    opts: HandshakeOptions,
) !HandshakeResult {
    _ = allocator;
    const pair_allocator = counting.allocator();
    const before = counting.snapshot();

    var count: u32 = 0;
    const wall_start = nowNanos();
    var wall_ns: u64 = 0;
    while (count < opts.max_handshakes) {
        const pair = try Pair.create(pair_allocator, .{});
        pair.destroy(pair_allocator);
        count += 1;
        wall_ns = nowNanos() - wall_start;
        if (wall_ns >= opts.min_wall_ns) break;
    }

    const delta = counting.snapshot().since(before);
    const secs = @as(f64, @floatFromInt(wall_ns)) / 1e9;
    return .{
        .handshakes = count,
        .wall_ns = wall_ns,
        .handshakes_per_sec = if (secs <= 0) 0 else @as(f64, @floatFromInt(count)) / secs,
        .allocs_per_handshake = if (count == 0) 0 else @as(f64, @floatFromInt(delta.allocs)) / @as(f64, @floatFromInt(count)),
    };
}

// -- impairment goodput ------------------------------------------------------

pub const ImpairmentOptions = struct {
    name: []const u8,
    total_bytes: usize = 8 << 20,
    chunk_bytes: usize = 256 << 10,
    tick_us: u64 = 100,
    congestion_control: quic_zig.CongestionAlgorithm = .cubic,
    /// RFC 9406 HyStart++ on both endpoints (A/B lever).
    hystart: bool = true,
    seed: u64 = 0xbe9c4,
    loss_permille: u16 = 0,
    reorder_permille: u16 = 0,
    /// Bottleneck link rate in bytes/s (0 = unlimited). A rate-limited
    /// link builds a standing queue under an overshooting sender,
    /// which is what inflates RTT — the only condition under which
    /// slow-start-exit behavior is observable.
    bottleneck_bytes_per_s: u64 = 0,
    /// Bottleneck buffer depth, expressed as the maximum queueing
    /// delay before tail drop (sim_net's model). 100 ms is a
    /// deep-ish consumer buffer; a shallow value (e.g. 25 ms) is the
    /// regime where a loss-based sender's queue-filling sawtooth and
    /// a rate-based sender's headroom-keeping cruise diverge most.
    /// Ignored when `bottleneck_bytes_per_s` is 0.
    max_queue_delay_us: u64 = 100_000,
    /// Concurrent bidi streams carrying the transfer, round-robin.
    /// >1 reproduces the QNS `multiplexing` (M) shape, where the
    /// send scheduler interleaves many streams rather than draining
    /// one.
    streams: u32 = 1,
    /// Safety bound on virtual time; heavy loss cells that fail to
    /// finish inside it return error.ImpairmentStalled.
    max_virtual_us: u64 = 600 * std.time.us_per_s,
};

pub const ImpairmentResult = struct {
    name: []const u8,
    total_bytes: usize,
    virtual_us: u64,
    virtual_goodput_mbps: f64,
    wall_ns: u64,
    enqueued: u64,
    dropped: u64,
    loss_permille: u16,
    reorder_permille: u16,
    seed: u64,
    /// Bottleneck-model observability (0 when no bottleneck configured).
    queue_dropped: u64 = 0,
    peak_queue_delay_us: u64 = 0,
};

/// Bulk transfer through the seeded impairment net, measured in
/// VIRTUAL time — deterministic for a given seed and option set.
pub fn runImpairmentOnce(allocator: std.mem.Allocator, opts: ImpairmentOptions) !ImpairmentResult {
    const pair = try Pair.create(allocator, .{
        .congestion_control = opts.congestion_control,
        .hystart = opts.hystart,
    });
    defer pair.destroy(allocator);

    var net = sim_net.SimNet.init(allocator, .{
        .seed = opts.seed,
        .loss_permille = opts.loss_permille,
        .reorder_permille = opts.reorder_permille,
        .bottleneck_bytes_per_s = opts.bottleneck_bytes_per_s,
        .max_queue_delay_us = opts.max_queue_delay_us,
    });
    defer net.deinit();

    const data = try allocator.alloc(u8, opts.chunk_bytes);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(opts.seed);
    prng.random().bytes(data);

    var rbuf: [64 << 10]u8 = undefined;
    var pkt: [2048]u8 = undefined;

    // Client-initiated bidi stream ids are 0, 4, 8, ... (RFC 9000 §2.1).
    const stream_count: u32 = @max(1, opts.streams);
    var stream_ids: [64]u64 = undefined;
    var per_stream_target: [64]usize = undefined;
    var per_stream_written: [64]usize = @splat(0);
    std.debug.assert(stream_count <= stream_ids.len);
    {
        var i: u32 = 0;
        while (i < stream_count) : (i += 1) {
            stream_ids[i] = @as(u64, i) * 4;
            _ = try pair.client.openBidi(stream_ids[i]);
            // Split the transfer evenly; the last stream absorbs the
            // remainder so the totals match exactly.
            per_stream_target[i] = opts.total_bytes / stream_count;
            if (i + 1 == stream_count) {
                per_stream_target[i] = opts.total_bytes - (opts.total_bytes / stream_count) * (stream_count - 1);
            }
        }
    }

    const virtual_start: u64 = 1_000_000;
    var now_us: u64 = virtual_start;
    var written: usize = 0;
    var consumed: usize = 0;

    const wall_start = nowNanos();
    while (consumed < opts.total_bytes) {
        if (now_us - virtual_start > opts.max_virtual_us) return error.ImpairmentStalled;

        // Offer to every stream round-robin so the send scheduler sees
        // genuine concurrency rather than one stream draining first.
        var si: u32 = 0;
        while (si < stream_count) : (si += 1) {
            const id = stream_ids[si];
            while (per_stream_written[si] < per_stream_target[si]) {
                const want = @min(opts.chunk_bytes, per_stream_target[si] - per_stream_written[si]);
                const accepted = try pair.client.streamWrite(id, data[0..want]);
                per_stream_written[si] += accepted;
                written += accepted;
                if (accepted < want) break;
            }
            if (per_stream_written[si] == per_stream_target[si]) {
                if (pair.client.stream(id)) |st| {
                    if (!st.send.fin_marked) try pair.client.streamFinish(id);
                }
            }
        }

        var progressed = true;
        while (progressed) {
            progressed = false;
            if (try pair.client.poll(&pkt, now_us)) |n| {
                try net.enqueue(true, pkt[0..n], now_us);
                progressed = true;
            }
            if (try pair.server.poll(&pkt, now_us)) |n| {
                try net.enqueue(false, pkt[0..n], now_us);
                progressed = true;
            }
        }

        try net.deliverDue(&pair.client, &pair.server, now_us);

        var di: u32 = 0;
        while (di < stream_count) : (di += 1) {
            const id = stream_ids[di];
            while (true) {
                // Deliveries are delayed, so a stream doesn't exist
                // server-side until its first STREAM frame lands.
                const got = pair.server.streamRead(id, &rbuf) catch |err| switch (err) {
                    error.StreamNotFound => break,
                    else => return err,
                };
                if (got == 0) break;
                consumed += got;
            }
        }

        now_us += opts.tick_us;
        try pair.client.tick(now_us);
        try pair.server.tick(now_us);
    }
    const wall_ns = nowNanos() - wall_start;
    const virtual_us = now_us - virtual_start;

    return .{
        .name = opts.name,
        .total_bytes = opts.total_bytes,
        .virtual_us = virtual_us,
        .virtual_goodput_mbps = if (virtual_us == 0)
            0
        else
            @as(f64, @floatFromInt(opts.total_bytes)) * 8.0 / @as(f64, @floatFromInt(virtual_us)),
        .wall_ns = wall_ns,
        .enqueued = net.enqueued,
        .dropped = net.dropped,
        .loss_permille = opts.loss_permille,
        .reorder_permille = opts.reorder_permille,
        .seed = opts.seed,
        .queue_dropped = net.queue_dropped,
        .peak_queue_delay_us = net.peak_queue_delay_us,
    };
}

// -- tests -------------------------------------------------------------------

test "pair handshakes and a mini goodput run completes clean" {
    var counting = CountingAllocator.init(std.testing.allocator);
    const result = try runGoodputOnce(std.testing.allocator, &counting, .{
        .total_bytes = 256 << 10,
        .chunk_bytes = 64 << 10,
    });
    try std.testing.expectEqual(@as(usize, 256 << 10), result.total_bytes);
    try std.testing.expect(result.mb_per_sec > 0);
    try std.testing.expect(result.datagrams > (256 << 10) / 1500);
    try std.testing.expect(result.poll_p50_ns <= result.poll_p99_ns);
    // Everything the pair allocated came back (setup + transfer).
    try std.testing.expectEqual(@as(u64, 0), counting.live_bytes);
}

test "impairment run is deterministic in virtual time for a fixed seed" {
    var first: ?ImpairmentResult = null;
    for (0..2) |_| {
        const result = try runImpairmentOnce(std.testing.allocator, .{
            .name = "det-test",
            .total_bytes = 512 << 10,
            .loss_permille = 20,
            .reorder_permille = 50,
        });
        try std.testing.expect(result.dropped > 0);
        if (first) |f| {
            try std.testing.expectEqual(f.virtual_us, result.virtual_us);
            try std.testing.expectEqual(f.enqueued, result.enqueued);
            try std.testing.expectEqual(f.dropped, result.dropped);
        } else {
            first = result;
        }
    }
}

test "handshake batch runs and counts" {
    var counting = CountingAllocator.init(std.testing.allocator);
    const result = try runHandshakesOnce(std.testing.allocator, &counting, .{
        .min_wall_ns = 1,
        .max_handshakes = 3,
    });
    try std.testing.expect(result.handshakes >= 1);
    try std.testing.expect(result.handshakes_per_sec > 0);
    try std.testing.expect(result.allocs_per_handshake > 0);
    try std.testing.expectEqual(@as(u64, 0), counting.live_bytes);
}

test "CUBIC completes a lossy impairment transfer end-to-end" {
    const result = try runImpairmentOnce(std.testing.allocator, .{
        .name = "cubic-loss-e2e",
        .total_bytes = 512 << 10,
        .loss_permille = 20,
        .congestion_control = .cubic,
    });
    try std.testing.expect(result.dropped > 0);
    try std.testing.expect(result.virtual_goodput_mbps > 0);
}

test "max_queue_delay_us reaches the bottleneck model: a shallow buffer tail-drops and caps peak delay" {
    const result = try runImpairmentOnce(std.testing.allocator, .{
        .name = "shallow-buffer-e2e",
        .total_bytes = 1 << 20,
        .bottleneck_bytes_per_s = 1_250_000,
        .max_queue_delay_us = 25_000,
    });
    // The reported peak is the max queue delay among ACCEPTED packets,
    // so a working buffer bound is directly observable...
    try std.testing.expect(result.peak_queue_delay_us <= 25_000);
    // ...and an overshooting slow start into 25 ms of buffer must
    // tail-drop (the deep default rarely does on a clean link).
    try std.testing.expect(result.queue_dropped > 0);
    try std.testing.expect(result.virtual_goodput_mbps > 0);
}
