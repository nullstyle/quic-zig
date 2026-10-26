//! Real public qmsg Req/Rep traffic. Built by profile-applications.py with
//! explicit consumer/transport sources; no access to private connection state.
const std = @import("std");
const qmsg = @import("qmsg");
const quic = @import("quic");
const CountingAllocator = @import("counting_allocator.zig").CountingAllocator;
const cert = @embedFile("cert.pem");
const key = @embedFile("key.pem");
const Req = qmsg.QuicSocket(.req);
const Rep = qmsg.QuicSocket(.rep);

const Config = struct {
    requests: usize = 5000,
    payload_bytes: usize = 1024,
    concurrency: usize = 8,
    stream_window: usize = 8,
    warmup: usize = 128,
    idle_ms: u64 = 200,
    timeout_seconds: u64 = 30,
};

fn nowUs() u64 {
    var t: std.c.timespec = undefined;
    std.debug.assert(std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &t) == 0);
    return @as(u64, @intCast(t.sec)) * std.time.us_per_s + @as(u64, @intCast(@divTrunc(t.nsec, std.time.ns_per_us)));
}

fn cpuUs() u64 {
    var t: std.c.timespec = undefined;
    std.debug.assert(std.c.clock_gettime(std.c.CLOCK.PROCESS_CPUTIME_ID, &t) == 0);
    return @as(u64, @intCast(t.sec)) * std.time.us_per_s + @as(u64, @intCast(@divTrunc(t.nsec, std.time.ns_per_us)));
}

fn park(req: *Req, rep: *Rep, until: u64) !void {
    var handles: [16]std.Io.net.Socket.Handle = undefined;
    var used = try req.readableSockets(&handles);
    used += try rep.readableSockets(handles[used..]);
    var descriptors: [16]std.posix.pollfd = undefined;
    for (handles[0..used], descriptors[0..used]) |fd, *descriptor|
        descriptor.* = .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 };
    var at = until;
    if (req.nextTimer()) |d| at = @min(at, d);
    if (rep.nextTimer()) |d| at = @min(at, d);
    const now = nowUs();
    if (at <= now) return;
    const ms: i32 = @intCast(@min(50, (at - now + 999) / 1000));
    _ = try std.posix.poll(descriptors[0..used], ms);
}

fn discard(socket: anytype) !usize {
    var events: [64]qmsg.NodeEvent = undefined;
    const count = try socket.poll(&events);
    for (events[0..count]) |*event| event.deinit();
    return count;
}

const Phase = struct {
    sent: usize,
    received: usize,
    replies: usize,
    queue_full: usize,
    max_outstanding: usize,
    iterations: usize,
    parks: usize,
    elapsed_us: u64,
    cpu_us: u64,
    latency_p50_us: u64,
    latency_p99_us: u64,
    allocations: CountingAllocator.Snapshot,
};

const Slot = struct { request_id: qmsg.RequestId, wire_id: u64, started: u64 };

fn phase(gpa: std.mem.Allocator, counting: *CountingAllocator, req: *Req, rep: *Rep, session: u64, cfg: Config, body: []const u8, count: usize, base: u64) !Phase {
    const slots = try gpa.alloc(?Slot, cfg.concurrency);
    defer gpa.free(slots);
    @memset(slots, null);
    const seen = try gpa.alloc(bool, count);
    defer gpa.free(seen);
    @memset(seen, false);
    const latencies = try gpa.alloc(u64, count);
    defer gpa.free(latencies);
    const before_alloc = counting.snapshot();
    const before_cpu = cpuUs();
    const start = nowUs();
    const until = start + cfg.timeout_seconds * std.time.us_per_s;
    var result: Phase = .{ .sent = 0, .received = 0, .replies = 0, .queue_full = 0, .max_outstanding = 0, .iterations = 0, .parks = 0, .elapsed_us = 0, .cpu_us = 0, .latency_p50_us = 0, .latency_p99_us = 0, .allocations = undefined };
    var outstanding: usize = 0;
    while (result.replies < count) {
        const now = nowUs();
        if (now >= until) return error.WorkloadTimeout;
        result.iterations += 1;
        var did_work = false;
        try req.pump(now);
        try rep.pump(now);
        {
            var events: [64]qmsg.NodeEvent = undefined;
            const n = try rep.poll(&events);
            defer for (events[0..n]) |*event| event.deinit();
            did_work = n > 0;
            for (events[0..n]) |event| switch (event) {
                .request => |request| {
                    if (request.msg.id < base or request.msg.id >= base + count) return error.UnexpectedRequest;
                    const index: usize = @intCast(request.msg.id - base);
                    if (seen[index]) return error.DuplicateRequest;
                    seen[index] = true;
                    if (!std.mem.eql(u8, body, request.msg.body)) return error.PayloadMismatch;
                    try rep.reply(request.msg.reply_handle.?, .{ .subject = "", .body = request.msg.body });
                    result.received += 1;
                },
                .closed => return error.PeerClosed,
                else => {},
            };
        }
        {
            var events: [64]qmsg.NodeEvent = undefined;
            const n = try req.poll(&events);
            defer for (events[0..n]) |*event| event.deinit();
            did_work = did_work or n > 0;
            for (events[0..n]) |event| switch (event) {
                .reply => |reply| {
                    if (reply.msg.flags.err or !std.mem.eql(u8, body, reply.msg.body)) return error.PayloadMismatch;
                    var matched = false;
                    for (slots) |*slot| {
                        if (slot.*) |pending| {
                            if (pending.request_id != reply.request_id) continue;
                            if (pending.wire_id != reply.msg.id) return error.CorrelationMismatch;
                            latencies[result.replies] = nowUs() - pending.started;
                            slot.* = null;
                            outstanding -= 1;
                            result.replies += 1;
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) return error.UnexpectedReply;
                },
                .request_failed => return error.RequestFailed,
                .closed => return error.PeerClosed,
                else => {},
            };
        }
        while (result.sent < count and outstanding < cfg.concurrency) {
            const id = req.request(session, .{ .id = base + result.sent, .subject = "profile.echo", .body = body, .deadline_ms = 10_000 }) catch |err| switch (err) {
                error.QueueFull => {
                    result.queue_full += 1;
                    break;
                },
                else => return err,
            };
            for (slots) |*slot| if (slot.* == null) {
                slot.* = .{ .request_id = id, .wire_id = base + result.sent, .started = nowUs() };
                break;
            };
            result.sent += 1;
            outstanding += 1;
            result.max_outstanding = @max(result.max_outstanding, outstanding);
            did_work = true;
        }
        if (result.replies < count and !did_work) {
            result.parks += 1;
            try park(req, rep, until);
        }
    }
    result.elapsed_us = nowUs() - start;
    result.cpu_us = cpuUs() - before_cpu;
    result.allocations = counting.snapshot().since(before_alloc);
    if (result.sent != count or result.received != count or outstanding != 0) return error.IncompleteWorkload;
    std.mem.sort(u64, latencies, {}, std.sort.asc(u64));
    result.latency_p50_us = latencies[(count - 1) / 2];
    result.latency_p99_us = latencies[((count - 1) * 99) / 100];
    return result;
}

pub fn main(init: std.process.Init) !void {
    // Same compilation unit as qmsg's imported transport in either lane.
    if (quic.Connection != qmsg.transport.quic_runtime.Connection) @compileError("QUIC module identity differs");
    var cfg: Config = .{};
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    while (args.next()) |flag| {
        const value = args.next() orelse return error.MissingArgument;
        const number = try std.fmt.parseInt(usize, value, 10);
        if (std.mem.eql(u8, flag, "--requests")) cfg.requests = number else if (std.mem.eql(u8, flag, "--payload-bytes")) cfg.payload_bytes = number else if (std.mem.eql(u8, flag, "--concurrency")) cfg.concurrency = number else if (std.mem.eql(u8, flag, "--stream-window")) cfg.stream_window = number else if (std.mem.eql(u8, flag, "--warmup")) cfg.warmup = number else if (std.mem.eql(u8, flag, "--idle-ms")) cfg.idle_ms = number else if (std.mem.eql(u8, flag, "--timeout-seconds")) cfg.timeout_seconds = number else return error.UnknownArgument;
    }
    if (cfg.requests == 0 or cfg.requests > 1_000_000 or cfg.warmup == 0 or cfg.warmup > 1_000_000 or cfg.concurrency == 0 or cfg.concurrency > 1024 or cfg.stream_window == 0 or cfg.stream_window > 1024 or cfg.payload_bytes > 64 * 1024 or cfg.timeout_seconds == 0 or cfg.timeout_seconds > 300 or cfg.idle_ms > 10_000) return error.InvalidWorkload;
    const body = try init.gpa.alloc(u8, cfg.payload_bytes);
    defer init.gpa.free(body);
    for (body, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    var counting = CountingAllocator.init(std.heap.c_allocator);
    const setup_cpu = cpuUs();
    const setup_start = nowUs();
    var req = try Req.init(counting.allocator(), .{ .node = .{ .io = init.io } });
    var req_live = true;
    defer if (req_live) req.deinit();
    var rep = try Rep.init(counting.allocator(), .{ .node = .{ .io = init.io } });
    var rep_live = true;
    defer if (rep_live) rep.deinit();
    const options: qmsg.transport.quic.QuicOptions = .{
        .max_message_size = cfg.payload_bytes + 1024,
        .max_queued_messages = cfg.concurrency + 8,
        .max_queued_bytes = (cfg.payload_bytes + 1024) * (cfg.concurrency + 8),
        .initial_max_streams_bidi = cfg.stream_window,
    };
    const listener = try rep.listen("127.0.0.1:0", .{ .tls_cert_pem = cert, .tls_key_pem = key, .transport = options });
    const address = try rep.localAddress(listener);
    var endpoint: [64]u8 = undefined;
    const target = try std.fmt.bufPrint(&endpoint, "127.0.0.1:{d}", .{address.ip4.port});
    const session = try req.dial(target, .{ .server_name = "localhost", .ca_pem = cert, .transport = options });
    const setup_until = setup_start + cfg.timeout_seconds * std.time.us_per_s;
    while (true) {
        const now = nowUs();
        if (now >= setup_until) return error.ReadinessTimeout;
        try req.pump(now);
        try rep.pump(now);
        const work = (try discard(&req)) + (try discard(&rep));
        if (req.sessionStatus(session)) |status| if (status.state == .ready) break;
        if (work == 0) try park(&req, &rep, setup_until);
    }
    const cold_elapsed_us = nowUs() - setup_start;
    const cold_cpu_us = cpuUs() - setup_cpu;
    const warmup = try phase(init.gpa, &counting, &req, &rep, session, cfg, body, cfg.warmup, 1);
    const warm = try phase(init.gpa, &counting, &req, &rep, session, cfg, body, cfg.requests, cfg.warmup + 1);
    const idle_start = nowUs();
    const idle_cpu = cpuUs();
    const idle_until = idle_start + cfg.idle_ms * std.time.us_per_ms;
    var idle_iterations: usize = 0;
    while (nowUs() < idle_until) {
        const now = nowUs();
        idle_iterations += 1;
        try req.pump(now);
        try rep.pump(now);
        if ((try discard(&req)) + (try discard(&rep)) == 0) try park(&req, &rep, idle_until);
    }
    const idle_elapsed_us = nowUs() - idle_start;
    const idle_cpu_us = cpuUs() - idle_cpu;
    const client_stats = req.stats();
    const server_stats = rep.stats();
    const allocator_before_teardown = counting.snapshot();
    req.deinit();
    req_live = false;
    rep.deinit();
    rep_live = false;
    const allocator_after_teardown = counting.snapshot();
    if (allocator_after_teardown.live_bytes != 0) return error.CountedAllocatorLeak;
    const report = .{
        .schema_version = 1,
        .workload = "public-qmsg-reqrep",
        .config = cfg,
        .cold_elapsed_us = cold_elapsed_us,
        .cold_cpu_us = cold_cpu_us,
        .warmup = warmup,
        .warm = warm,
        .idle = .{ .elapsed_us = idle_elapsed_us, .cpu_us = idle_cpu_us, .iterations = idle_iterations },
        .client_stats = client_stats,
        .server_stats = server_stats,
        .allocator_before_teardown = allocator_before_teardown,
        .allocator_after_teardown = allocator_after_teardown,
    };
    if (report.client_stats.dropped != 0 or report.server_stats.dropped != 0 or report.client_stats.events_dropped != 0 or report.server_stats.events_dropped != 0) return error.UnexpectedDrop;
    const json = try std.json.Stringify.valueAlloc(init.gpa, report, .{});
    defer init.gpa.free(json);
    std.debug.print("APPLICATION_PROFILE {s}\n", .{json});
}
