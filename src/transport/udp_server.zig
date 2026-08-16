//! Opinionated `std.Io`-based UDP server loop for `quic.Server`.
//!
//! `quic.Server` is intentionally I/O-agnostic: the embedder owns the
//! UDP socket and the wall clock. That keeps the library minimal but
//! means every embedder spelling out their first server reaches for the
//! same boilerplate — bind a UDP socket, tune `SO_RCVBUF` /
//! `SO_SNDBUF`, drive a `receiveTimeout` -> `feed` -> `poll-each-slot`
//! -> `tick` -> `reap` loop on a monotonic clock.
//!
//! `runUdpServer` is that boilerplate, distilled. It is opt-in: pass
//! a `*Server` and a `RunUdpOptions` and the function takes over the
//! socket. Embedders who need full control (Retry token issuance,
//! version negotiation, deterministic CIDs, batched I/O via `recvmmsg`,
//! qlog file rotation) keep using `Server.feed` / `Server.poll`
//! directly.
//!
//! Time
//! ----
//! The loop uses `std.Io.Timestamp.now(io, .awake)` (a monotonic clock)
//! and converts to microseconds since the loop start, then feeds that
//! into `Server.feed` / `Server.tick`. Wall-clock skew on the host
//! cannot drag QUIC's recovery timers backwards; `now_us` is strictly
//! monotonically non-decreasing for the lifetime of the server.
//!
//! Shutdown
//! --------
//! If `RunUdpOptions.shutdown_flag` is set, the loop checks the flag
//! on every iteration. Once flipped, it calls `Server.shutdown` to
//! queue `CONNECTION_CLOSE` on every live slot, then continues
//! polling for up to `shutdown_grace_us` so those CONNECTION_CLOSEs
//! actually reach the wire. After the grace period (or once every
//! slot is reaped, whichever comes first), it returns cleanly.
//!
//! See `README.md` for an end-to-end embedder example.

const std = @import("std");
const builtin = @import("builtin");

const Server = @import("../Server.zig");
const egress = @import("egress.zig");
const path_mod = @import("../conn/path.zig");
const socket_opts = @import("socket_opts.zig");
const udp_batch = @import("udp_batch.zig");

const Net = std.Io.net;
const Address = path_mod.Address;
/// Re-export: `SendBatch` moved to `egress.zig` when the server and
/// client loops were collapsed onto one implementation. Kept `pub`
/// here so the historical `quic.transport.udp_server.SendBatch` path
/// that foreign-loop embedders use keeps resolving (same treatment as
/// `ipAddressToPathAddress` below).
pub const SendBatch = egress.SendBatch;

/// Default size of the receive buffer scratch space used by the loop.
/// 64 KiB is the maximum a single UDP datagram can be, and matches
/// the QNS endpoint's `rx` buffer.
pub const default_rx_buffer_bytes: usize = 64 * 1024;

// Hardening guide §8 `max_datagrams_per_event_loop_tick`: ingress per
// iteration is BOUNDED — the loop receives at most
// `RunUdpOptions.max_datagrams_per_iteration` datagrams per listener
// (one batched `receiveManyTimeout` call), then drains every slot's
// outbox and ticks before looping back. The bound keeps PTO /
// loss-detection tick-driven work from being starved by a hot ingress
// queue while amortizing per-wake loop overhead across the batch.
// (This replaced the historical hard-wired 1-per-iteration cap,
// `max_datagrams_per_loop_iteration`.)

/// Default size of the send buffer scratch space used by the loop.
/// 1500 bytes covers the default QUIC `max_udp_payload_size` plus a
/// small margin; embedders that raise the transport parameter cap
/// will need to override.
pub const default_tx_buffer_bytes: usize = 1500;

/// How the loop is configured. The defaults are tuned for a small
/// open-internet QUIC server; tweak as needed for embedded targets,
/// load testers, or fixtures.
pub const RunUdpOptions = struct {
    /// IPv4 or IPv6 listen address as a literal — `"0.0.0.0:443"`,
    /// `"127.0.0.1:4433"`, `"[::]:443"`, etc. Parsed by
    /// `std.Io.net.IpAddress.parseLiteral`.
    listen: []const u8,
    /// Caller-provided `std.Io` instance. quic does not pick its
    /// own I/O backend — pass whatever you're already using
    /// (typically `std.Io.threaded` or a single-threaded harness).
    io: std.Io,
    /// How long to block in `Socket.receiveTimeout` between
    /// feed/tick iterations. The default of 5 ms keeps
    /// `Connection.tick` responsive (QUIC's PTO timer fires on
    /// millisecond-ish granularity) without busy-spinning when the
    /// network is idle. Match what the QNS endpoint uses.
    receive_timeout: std.Io.Duration = std.Io.Duration.fromMilliseconds(5),
    /// Apply quic's recommended `SO_RCVBUF` / `SO_SNDBUF` tuning to
    /// the bound socket via `transport.applyServerTuning`. On by
    /// default — production QUIC servers want big OS buffers to
    /// absorb open-internet bursts. Turn off only for tiny fixtures
    /// where the 4 MiB default is wasteful.
    tune_socket: bool = true,
    /// Tuning applied when `tune_socket` is true. Overriding lets
    /// embedders pick smaller (embedded targets) or larger (10G NIC)
    /// buffers without disabling tuning altogether.
    tuning: socket_opts.ServerTuning = .{},

    /// Enable IETF ECN signaling (RFC 9000 §13.4). When `true`, the
    /// loop sets `IP_TOS` / `IPV6_TCLASS` to ECT(0) on the bound
    /// socket and `IP_RECVTOS` / `IPV6_RECVTCLASS` so the kernel
    /// surfaces the per-datagram TOS byte via cmsg. The parsed
    /// codepoint is plumbed into `Server.feedWithEcn`. On by default
    /// — production QUIC reaps modest goodput wins by reacting to
    /// router-driven CE marks. Embedders on environments that bleach
    /// ECN can flip this off and the loop falls through to the plain
    /// `Server.feed` (Not-ECT) path.
    enable_ecn: bool = true,
    /// Send-side ECN codepoint applied to the bound socket when
    /// `enable_ecn = true`. Defaults to ECT(0) (RFC 9000 §13.4
    /// recommends ECT(0) for QUIC). `not_ect` disables marking;
    /// `ect1` and `ce` are reserved.
    ecn_send_codepoint: socket_opts.EcnCodepoint = .ect0,
    /// Per-recv cmsg control buffer size — PER MESSAGE: the loop
    /// allocates `max_datagrams_per_iteration x cmsg_buffer_bytes` and
    /// hands each batched message its own slice for the kernel's
    /// TOS / TCLASS cmsgs. 64 bytes is comfortably large enough for
    /// both `IP_TOS` and `IPV6_TCLASS` with alignment slack. Bump only
    /// if pipelining other ancillary data (PKTINFO, etc.) onto the
    /// same socket is in scope.
    cmsg_buffer_bytes: usize = socket_opts.default_cmsg_buffer_bytes,
    /// Ingress batch bound: how many datagrams one iteration may
    /// receive per listener before draining outboxes and ticking
    /// (a bounded per-iteration ingress budget). One batched receive
    /// call ingests up to this many; 16 amortizes wake overhead ~an
    /// order of magnitude while keeping the tick cadence tight.
    /// Set to 1 to restore the historical datagram-per-iteration
    /// behavior exactly.
    max_datagrams_per_iteration: u32 = 16,
    /// Egress batch bound: outbound datagrams accumulate into a
    /// per-listener buffer and ship through one `Socket.sendMany`
    /// call (real `sendmmsg` on Linux, 64 messages per syscall; a
    /// plain send loop elsewhere). One batch can carry datagrams for
    /// MANY different peers. 64 matches the kernel chunk size; 1
    /// restores a syscall per datagram.
    max_send_batch_datagrams: u32 = 64,
    /// Linux UDP generic segmentation offload: pack consecutive
    /// same-size datagrams for one connection into a super-datagram
    /// the kernel splits (one sendmsg for up to 64 packets). Probed
    /// per socket at bind; runtime send errors disable it for that
    /// socket and fall back to plain batched sends. No effect off
    /// Linux.
    enable_gso: bool = true,
    /// Linux UDP generic receive offload: the kernel coalesces
    /// consecutive same-source datagrams and reports the segment size
    /// via cmsg; the loop splits and feeds each original datagram.
    /// Enabled per socket where supported. No effect off Linux.
    enable_gro: bool = true,
    /// Optional shutdown signal. The loop calls `flag.load(.acquire)`
    /// at the top of every iteration; once it observes `true`, it
    /// calls `Server.shutdown(0, "")`, drains outgoing CONNECTION_CLOSE
    /// for up to `shutdown_grace_us`, and returns cleanly. Embedders
    /// typically wire this to a `SIGINT` handler.
    shutdown_flag: ?*const std.atomic.Value(bool) = null,
    /// Maximum microseconds to keep the loop running after
    /// `shutdown_flag` is observed true. The grace window lets
    /// CONNECTION_CLOSE frames reach peers; without it, the server
    /// would just stop sending and peers would idle out.
    shutdown_grace_us: u64 = 5_000_000,
    /// Per-datagram receive scratch. The loop allocates
    /// `max_datagrams_per_iteration × rx_buffer_bytes` total: one
    /// ingress batch shares the buffer and the std backend carves it
    /// sequentially, so a burst of jumbo datagrams truncates the tail
    /// if a single rx_buffer_bytes cannot hold one. The 64 KiB default
    /// holds 16 × 4 KiB datagrams (~1 MiB allocation per socket);
    /// jumbo-frame deployments should raise this to at least the
    /// negotiated `max_udp_payload_size`.
    rx_buffer_bytes: usize = default_rx_buffer_bytes,
    /// Send scratch buffer size. Should be at least the connection's
    /// negotiated `max_udp_payload_size` (default 1200 in quic, plus
    /// header overhead — 1500 is safe; bump for jumbo-frame paths).
    /// NOTE: the loop silently clamps every datagram (and DPLPMTUD
    /// probes) to this size — there is no per-connection TP check at
    /// the loop layer, so an undersized tx_buffer_bytes is a quiet
    /// goodput regression, not an error.
    tx_buffer_bytes: usize = default_tx_buffer_bytes,
    /// How often (in iterations) to call `Server.reap`. Reaping is
    /// cheap, but doing it every iteration when the typical loop is
    /// already a few hundred microseconds is pure overhead. The
    /// default of 64 means the slot table is reclaimed every few
    /// hundred milliseconds at idle.
    reap_every_n_iterations: u32 = 64,

    /// Per-iteration application hook — the one safe place to run
    /// application logic against a loop-owned server. Invoked once per
    /// iteration on the loop thread, after inbound datagrams have been
    /// fed and before the per-slot outbox drain, so responses the hook
    /// writes reach the wire in the same iteration. `Server` and
    /// `Connection` have no internal locking; all application access
    /// must be serialized with the loop, and this callback *is* that
    /// serialization: walk `server.iterator()`, drain
    /// `slot.conn.pollEvent()`, read/write streams, send datagrams —
    /// but only from inside the hook. It keeps firing during the
    /// shutdown grace window (peers are draining; the app can observe
    /// closes). An error return stops the loop and propagates out of
    /// `runUdpServer` verbatim. Pair with
    /// `Server.Config.on_connection_will_close` for per-connection
    /// teardown — the every-64-iterations auto-reap runs on this same
    /// thread, so the two hooks never race.
    on_iteration: ?*const fn (ctx: ?*anyopaque, server: *Server, now_us: u64) anyerror!void = null,
    /// Opaque pointer passed back to `on_iteration` every call.
    on_iteration_ctx: ?*anyopaque = null,
};

/// Errors the loop itself can produce. Most are propagated from
/// `std.Io.net.IpAddress.bind`, `Socket.send`, or `Server.feed` —
/// the helper itself does not introduce new error categories. The
/// function signature is `anyerror!void` (not `RunError!void`) only
/// because `RunUdpOptions.on_iteration` errors propagate out verbatim;
/// a loop without a hook fails only with values from this set.
pub const RunError = error{
    /// `RunUdpOptions.listen` did not parse as an IPv4/IPv6 literal.
    InvalidListenAddress,
    /// `tune_socket = true` but the kernel refused both the privileged
    /// (`*BUFFORCE`) and cap-respecting `setsockopt` calls. Production
    /// servers without `CAP_NET_ADMIN` rarely hit this — the
    /// cap-respecting fallback usually returns OK with a smaller
    /// buffer. Embedders that want best-effort tuning should clear
    /// `tune_socket` and call `transport.setRecvBufferSize` /
    /// `transport.setSendBufferSize` directly.
    SocketTuningFailed,
    /// `RunUdpOptions.rx_buffer_bytes` or `tx_buffer_bytes` was set
    /// to 0. Both must be > 0 for the loop to make progress.
    InvalidBufferSize,
    /// The bundled loop cannot run on native Windows at the pinned
    /// toolchain: std's Windows backend has no overlapped-I/O path for
    /// the timed receive the loop needs (receiveManyTimeout →
    /// Batch.awaitConcurrent → net_receive). The protocol engine is
    /// fully portable; drive the connection with
    /// examples/foreign_loop_embedder.zig instead.
    WindowsBundledLoopUnsupported,
    OutOfMemory,
    //
    // Inherited from `Net.Socket.ReceiveTimeoutError`, and worth
    // calling out because one member is a hard platform limit rather
    // than a runtime condition:
    //
    //   `error.ConcurrencyUnavailable` — **this loop cannot run on
    //   native Windows** at the pinned toolchain. Every timed receive
    //   lowers to `Io.operateTimeout` -> `Batch.awaitConcurrent`, and
    //   std's Windows `net_receive` has no overlapped-I/O path yet
    //   (`Io/Threaded.zig`: "TODO integrate with overlapped I/O or
    //   equivalent to avoid this error"), so it refuses the
    //   concurrent wait outright. Untimed `receive` works there but
    //   blocks forever, which would strand `tick` — and with it PTO,
    //   the idle timeout, pacing, and `shutdown_flag`. Since the
    //   timed receive *is* this loop's heartbeat, there is nothing to
    //   degrade to, so the error propagates rather than being
    //   swallowed into a loop that silently stops keeping time.
    //
    //   `enable_ecn = false` is not a workaround: `receiveTimeout`
    //   and `receiveManyTimeout` share that same lowering, so both
    //   receive paths fail identically. This has been true since
    //   before batched receive landed.
    //
    //   Windows embedders drive their own loop instead — see
    //   `examples/foreign_loop_embedder.zig` and the caller-drives
    //   section of `EMBEDDING.md`. The protocol engine itself is
    //   fully supported on Windows; only this bundled convenience
    //   loop is not.
} || Net.IpAddress.BindError ||
    Net.Socket.SendError ||
    Net.Socket.ReceiveTimeoutError ||
    Server.Error;

/// One bound listener-socket plus its per-socket runtime state.
/// `runUdpServer` always populates index 0 with the primary listener
/// (`RunUdpOptions.listen`); when `Server.Config.preferred_address`
/// is set, indices 1..N hold the alt-port listeners. The
/// per-listener `ecn_active` flag is set independently because a
/// kernel that rejects the IPV6_TCLASS / IP_TOS sockopts on one
/// socket may accept them on another. `bind_addr` is the literal
/// the listener was bound to — surfaced to per-connection
/// `noteServerLocalAddressChanged` calls when the dispatch detects
/// a peer flipping from primary to alt-listener (the
/// preferred-address migration trigger).
const Listener = struct {
    sock: Net.Socket,
    bind_addr: Net.IpAddress,
    ecn_active: bool,
    /// UDP_SEGMENT probe passed — GSO cmsgs may be attached to sends
    /// on this socket. Cleared at runtime on the first GSO send error
    /// (offload quirks); plain sends take over.
    gso_active: bool = false,
    /// UDP_GRO enabled — received datagrams may be kernel-coalesced
    /// and carry a segment-size cmsg.
    gro_active: bool = false,
};

const max_listeners: usize = 3;

/// Run a UDP server loop driven by `server`. Blocks until either
/// `RunUdpOptions.shutdown_flag` is observed true or an unrecoverable
/// I/O error occurs.
///
/// The loop owns the socket(s): they are bound, tuned, used, and closed
/// inside this function. The `server` is used non-owning — its
/// `Config` and lifecycle are still entirely the caller's.
///
/// Multi-socket dispatch (preferred-address):
/// when `server.preferred_address` is non-null, the loop additionally
/// binds an alt-port listener for each configured family (IPv4 and/or
/// IPv6). All listeners are polled per iteration; per-iteration
/// receive timeout is divided across them so PTO heartbeat latency
/// stays bounded. The slot's `last_recv_socket_idx` tracks which
/// listener last received an authenticated datagram, and the outbound
/// drain routes replies through that listener — so replies follow the
/// peer's path before AND after a server-initiated migration to the
/// preferred-address (RFC 9000 §5.1.1).
pub fn runUdpServer(server: *Server, options: RunUdpOptions) anyerror!void {
    if (options.rx_buffer_bytes == 0 or options.tx_buffer_bytes == 0) {
        return error.InvalidBufferSize;
    }
    // Fail up front on Windows instead of deep inside the first timed
    // receive (see RunError.WindowsBundledLoopUnsupported).
    if (comptime builtin.os.tag == .windows) {
        return error.WindowsBundledLoopUnsupported;
    }

    var listeners_storage: [max_listeners]Listener = undefined;
    var listeners_len: usize = 0;
    // Always bind the primary listener at index 0 so existing
    // single-socket embedders see no behavior change.
    const primary_addr = Net.IpAddress.parseLiteral(options.listen) catch {
        return error.InvalidListenAddress;
    };
    const primary_sock = try Net.IpAddress.bind(&primary_addr, options.io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    listeners_storage[0] = .{
        .sock = primary_sock,
        .bind_addr = primary_addr,
        .ecn_active = false,
    };
    listeners_len = 1;

    // Bind alt listeners from `Config.preferred_address` (if set).
    // The order matches what the codec advertised in the
    // transport-parameter blob: v4 first if present, then v6. Each
    // alt bind that succeeds claims one Listener slot; failures
    // propagate (we already advertised the address — if we cannot
    // bind it, the connection migration would arrive at a black
    // hole). Embedders that need a different policy bypass this
    // helper and roll their own loop.
    if (server.preferred_address) |pa| {
        if (pa.ipv4) |v4| {
            var bind_v4: Net.IpAddress = .{ .ip4 = v4 };
            const alt_sock = try Net.IpAddress.bind(&bind_v4, options.io, .{
                .mode = .dgram,
                .protocol = .udp,
            });
            listeners_storage[listeners_len] = .{
                .sock = alt_sock,
                .bind_addr = bind_v4,
                .ecn_active = false,
            };
            listeners_len += 1;
        }
        if (pa.ipv6) |v6| {
            var bind_v6: Net.IpAddress = .{ .ip6 = v6 };
            const alt_sock = try Net.IpAddress.bind(&bind_v6, options.io, .{
                .mode = .dgram,
                .protocol = .udp,
            });
            listeners_storage[listeners_len] = .{
                .sock = alt_sock,
                .bind_addr = bind_v6,
                .ecn_active = false,
            };
            listeners_len += 1;
        }
    }
    const listeners = listeners_storage[0..listeners_len];
    defer for (listeners) |l| l.sock.close(options.io);

    // Tune every bound socket identically. Tuning failures surface
    // from the primary listener; alt-listener tuning failures degrade
    // silently to the kernel default.
    if (options.tune_socket) {
        socket_opts.applyServerTuning(listeners[0].sock.handle, options.tuning) catch {
            return error.SocketTuningFailed;
        };
        if (listeners.len > 1) {
            for (listeners[1..]) |l| {
                socket_opts.applyServerTuning(l.sock.handle, options.tuning) catch {};
            }
        }
    }

    // Negotiate offloads (ECN marking + cmsg delivery, GSO probe, GRO)
    // per socket, so a kernel that rejects IPV6_TCLASS on one family
    // but not the other still gets ECN on the accepting socket.
    // `negotiateUdpOffloads` owns the all-or-nothing ECN rule and the
    // probe-before-GSO gate.
    for (listeners) |*l| {
        const offloads = socket_opts.negotiateUdpOffloads(l.sock.handle, .{
            .enable_ecn = options.enable_ecn,
            .ecn_send_codepoint = options.ecn_send_codepoint,
            .enable_gso = options.enable_gso,
            .enable_gro = options.enable_gro,
        });
        l.ecn_active = offloads.ecn_active;
        l.gso_active = offloads.gso_active;
        l.gro_active = offloads.gro_active;
    }

    const allocator = server.allocator;
    const batch_len: usize = @max(1, options.max_datagrams_per_iteration);
    const rx = try allocator.alloc(u8, options.rx_buffer_bytes * batch_len);
    defer allocator.free(rx);
    // cmsg buffer is shared across listeners — only one listener is
    // read per inner-loop iteration, so the kernel re-populates the
    // bytes on each `receiveManyTimeout`. Any listener with
    // ecn_active needs the buffer.
    var any_ecn_active = false;
    for (listeners) |l| {
        if (l.ecn_active) {
            any_ecn_active = true;
            break;
        }
    }
    var any_offload_cmsg = any_ecn_active;
    for (listeners) |l| {
        if (l.gro_active) any_offload_cmsg = true;
    }
    const cmsg_buf_len: usize = if (any_offload_cmsg) options.cmsg_buffer_bytes * batch_len else 0;
    var empty_cmsg_buf: [0]u8 = undefined;
    const cmsg_buf: []u8 = if (cmsg_buf_len > 0)
        try allocator.alloc(u8, cmsg_buf_len)
    else
        empty_cmsg_buf[0..0];
    defer if (cmsg_buf_len > 0) allocator.free(cmsg_buf);

    // Ingress batch: up to `batch_len` messages per listener per
    // iteration through one `receiveManyTimeout` call. Message data
    // slices carve from the shared `rx` buffer; each message gets its
    // own cmsg slice when ECN is active.
    const batch_msgs = try allocator.alloc(Net.IncomingMessage, batch_len);
    defer allocator.free(batch_msgs);

    // GSO super-datagram scratch (immediate sends; safe to share
    // across listeners and slots).
    const gso_buf = try allocator.alloc(
        u8,
        @as(usize, socket_opts.default_gso_max_segments) * options.tx_buffer_bytes,
    );
    defer allocator.free(gso_buf);

    // Per-listener egress batches (OutgoingMessage.address points into
    // the batch's own addrs array, so each listener keeps its own).
    const send_batches = try allocator.alloc(SendBatch, listeners.len);
    var batches_ready: usize = 0;
    defer {
        for (send_batches[0..batches_ready]) |*b| b.deinit(allocator);
        allocator.free(send_batches);
    }
    for (send_batches) |*b| {
        b.* = try SendBatch.init(
            allocator,
            @max(1, options.max_send_batch_datagrams),
            options.tx_buffer_bytes,
        );
        batches_ready += 1;
    }

    // Split the per-iteration recv timeout across listeners so the
    // worst-case PTO-heartbeat latency stays close to the original
    // single-socket value. Two listeners each waiting 5ms would
    // double the QUIC PTO tick latency at idle; halving keeps
    // recovery responsive without requiring a real reactor. Floor
    // at 1ms so we never spin.
    const per_listener_timeout: std.Io.Duration = blk: {
        if (listeners.len <= 1) break :blk options.receive_timeout;
        const ms = options.receive_timeout.toMilliseconds();
        const split: i64 = @max(1, @divFloor(ms, @as(i64, @intCast(listeners.len))));
        break :blk std.Io.Duration.fromMilliseconds(split);
    };

    const start = std.Io.Timestamp.now(options.io, .awake);
    var iteration_count: u32 = 0;
    var shutdown_started: bool = false;
    var shutdown_deadline_us: u64 = 0;

    while (true) {
        var now_us = monotonicNowUs(options.io, start);

        // Shutdown gate: once the flag flips, queue CONNECTION_CLOSE
        // on every slot and start a grace window. We keep polling
        // and ticking inside the window so the queued
        // CONNECTION_CLOSE actually reaches the wire.
        if (!shutdown_started) {
            if (options.shutdown_flag) |flag| {
                if (flag.load(.acquire)) {
                    server.shutdown(0, "");
                    shutdown_started = true;
                    shutdown_deadline_us = now_us +| options.shutdown_grace_us;
                }
            }
        } else {
            // Either the deadline expired or every slot has drained.
            if (now_us >= shutdown_deadline_us or server.connectionCount() == 0) {
                _ = server.reap();
                return;
            }
        }

        // Clamp this iteration's wait to the server's earliest timer
        // deadline (pacing credit, PTO, ack-delay, ...): parking the
        // full receive_timeout past a due deadline adds up to 5 ms of
        // latency to every timer-driven send. Past-due/sub-ms clamps
        // to 1 ms — never a busy spin, never a blocking overshoot.
        const iteration_timeout = clampTimeoutToDeadline(
            per_listener_timeout,
            if (server.nextTimerDeadline(now_us)) |td| td.at_us else null,
            now_us,
        );

        // Receive (or timeout) on each listener in turn. Each
        // listener ingests up to `max_datagrams_per_iteration`
        // datagrams per pass through one batched receive, and still
        // gets a fair recv-timeout slice so a hot listener can't
        // starve a quiet one. Sub-second-scale priority inversion is
        // fine; QUIC's PTO timer fires on millisecond-ish granularity
        // anyway.
        for (listeners, 0..) |l, sock_idx| {
            // One batched receive per listener: the first message
            // waits up to the (deadline-clamped) timeout, the rest
            // drain whatever is already queued, non-blocking. Data
            // slices carve from the shared `rx`; a datagram that
            // doesn't fit the residue is flagged truncated and
            // dropped below (a truncated QUIC datagram is useless).
            for (batch_msgs, 0..) |*msg, i| {
                msg.* = .init;
                if (l.ecn_active or l.gro_active) {
                    msg.control =
                        cmsg_buf[i * options.cmsg_buffer_bytes ..][0..options.cmsg_buffer_bytes];
                }
            }
            const ret = l.sock.receiveManyTimeout(options.io, batch_msgs, rx, .{}, .{
                .duration = .{
                    .raw = iteration_timeout,
                    .clock = .awake,
                },
            });
            var received: usize = ret[1];
            if (ret[0]) |err| switch (classifyReceiveError(err)) {
                // Keep whatever the batch did deliver; see
                // `classifyReceiveError` for why a peer must not be
                // able to end the loop.
                .tolerate => {},
                .fatal => return err,
            };

            // Refresh time after the (possibly-blocking) receive call.
            // Don't reuse the pre-receive timestamp: tick / poll need to
            // see the actual now_us so PTO timers fire on schedule.
            now_us = monotonicNowUs(options.io, start);

            if (received > batch_msgs.len) received = batch_msgs.len;
            // The iterator hands back ready-to-feed datagrams:
            // trunc-filtered, ECN-parsed, address-converted, and
            // GRO-split (the kernel may coalesce several original
            // datagrams into one buffer; QUIC coalescing rules apply
            // per original datagram).
            var ingress: udp_batch.IngressIterator = .init(
                batch_msgs[0..received],
                .{ .ecn_active = l.ecn_active, .gro_active = l.gro_active },
            );
            while (ingress.next()) |d| {
                // `feed` swallows per-connection errors internally;
                // OutOfMemory and rarely RandFailed propagate out, and
                // either is already a hard failure for the loop. The
                // FeedOutcome is informational — production embedders
                // may want to plumb it into a metrics counter, but the
                // default loop just lets it ride.
                _ = try server.feedWithEcn(d.data, d.from, d.ecn, now_us);
                // Stamp the receiving listener-index on the slot so the
                // outbound drain below picks the right socket — once
                // per source message, after its last (possibly
                // GRO-split) datagram: the stamp is an O(slots) scan,
                // so a kernel-coalesced buffer must not multiply it.
                // We look up the slot by source address (the most
                // recently touched slot for this peer) — any
                // post-handshake datagram routes to the same slot
                // regardless of which listener it arrived on.
                // Pre-handshake retransmits in the .accepted / .routed
                // buckets are equally fine to stamp; the field is
                // purely an outbound hint.
                if (d.last_in_message) stampLastRecvSocket(
                    server,
                    d.from,
                    @intCast(sock_idx),
                    listeners[sock_idx].bind_addr,
                    now_us,
                );
            }

            // Drain any Version Negotiation / Retry packets that
            // `feed` queued for this batch. Sending these via the same
            // listener the datagrams arrived on is part of the Server
            // contract: they are stateless responses with no
            // associated slot, so the per-slot poll loop below would
            // never reach them.
            while (server.drainStatelessResponse()) |response| {
                const dest = pathAddressToIpAddress(response.dst) orelse continue;
                l.sock.send(options.io, &dest, response.slice()) catch {
                    // Send-side failures here are not fatal: VN/Retry
                    // is best-effort. The peer will retry on its next
                    // Initial. A persistent failure becomes visible
                    // through the per-slot poll path soon enough.
                };
            }
        }

        // Application hook: inbound is ingested, the outbox drain is
        // next — anything the hook writes ships this same iteration.
        if (options.on_iteration) |hook| {
            try hook(options.on_iteration_ctx, server, now_us);
        }

        // Drain every slot's outbox and tick its recovery clock in
        // one pass. We use `Connection.pollDatagram` (path-aware)
        // rather than `Server.poll` so VN/Retry peers, migration,
        // and multipath all see the right destination address.
        // Slots without a current peer address (synthetic fixtures,
        // disconnected peers) are skipped silently.
        //
        // Per-connection errors are swallowed: a malformed peer must
        // not tear down the whole server. The connection itself
        // transitions to `.closed` and gets reaped on the next pass.
        for (server.iterator()) |slot| {
            // Terminal closed → nothing to do. Closing/draining slots
            // stay in the loop so their deadlines fire and the
            // closing-state CC retransmits can still emit (RFC 9000
            // §10.2.1 ¶3). `drainSlot`/`tick` are both idempotent on
            // those states.
            if (slot.conn.closeState() == .closed) continue;
            const idx: usize = @min(@as(usize, slot.last_recv_socket_idx), listeners.len - 1);
            drainSlot(
                slot,
                &send_batches[idx],
                &listeners[idx],
                gso_buf,
                socket_opts.default_gso_max_segments,
                now_us,
                options.io,
            ) catch |err| countEgressFault(server, err);
            slot.conn.tick(now_us) catch |err| countEgressFault(server, err);
        }
        // Ship whatever the drain pass accumulated — one syscall per
        // listener for up to max_send_batch_datagrams datagrams across
        // ALL slots (best-effort, matching the historical per-datagram
        // posture).
        for (send_batches, 0..) |*b, li| {
            b.flush(options.io, listeners[li].sock) catch |err| countEgressFault(server, err);
        }

        iteration_count +%= 1;
        if (iteration_count % options.reap_every_n_iterations == 0) {
            _ = server.reap();
        }
    }
}

/// Stamp the listener index on the slot whose `peer_addr` matches
/// `from`. Used by `runUdpServer`'s multi-listener dispatch so the
/// outbound drain routes replies through the listener the slot most
/// recently received on. Best-effort: when no slot matches (the
/// inbound was a stateless response or a fresh Initial that opened
/// a brand-new slot whose `peer_addr` is also the same), no harm
/// done — the server iterator will pick the slot up on the next
/// drain pass and the field is initialized to 0 (primary listener)
/// at slot creation, which is the correct default for a fresh
/// connection that hasn't yet migrated.
///
/// When the receiving listener-index transitions from primary (0)
/// to an alt-listener (1+), we also call
/// `Connection.noteServerLocalAddressChanged` so the per-connection
/// path validator runs (RFC 9000 §5.1.1: a server SHOULD validate
/// the new path the peer migrated to via `preferred_address`).
/// The error returns from that API are all benign on this path —
/// `PreferredAddressNotAdvertised` (PA not configured),
/// `PathLimitExceeded` (validation already in flight), and
/// `NotServerContext` (impossible here but cheap to defend against)
/// all idle through. Out-of-memory is the only real failure shape;
/// `runUdpServer` already swallows per-connection failures so the
/// loop's contract is preserved.
fn stampLastRecvSocket(
    server: *Server,
    from: Address,
    sock_idx: u8,
    bind_addr: Net.IpAddress,
    now_us: u64,
) void {
    for (server.iterator()) |slot| {
        const slot_addr = slot.peer_addr orelse continue;
        if (!slot_addr.eql(from)) continue;
        const previous = slot.last_recv_socket_idx;
        slot.last_recv_socket_idx = sock_idx;
        if (sock_idx != 0 and previous != sock_idx) {
            const new_local_addr = ipAddressToPathAddress(bind_addr);
            slot.conn.noteServerLocalAddressChanged(new_local_addr, now_us) catch {};
        }
    }
}

/// Drain every queued outgoing datagram for one slot. Caller wraps
/// the call in a `catch` so a per-connection failure (TLS hiccup,
/// CID exhaustion) doesn't abort the whole server loop. Errors only
/// propagate when the socket itself fails locally — that's a real
/// I/O failure the embedder needs to know about (peer-provoked send
/// errno on the immediate GSO path is tolerated; see `sendTolerant`).
fn drainSlot(
    slot: *Server.Slot,
    batch: *SendBatch,
    l: *Listener,
    gso_buf: []u8,
    max_gso_segments: u32,
    now_us: u64,
    io: std.Io,
) !void {
    if (l.gso_active) {
        // GSO egress: pack the slot's outbox into equal-size
        // super-datagrams (one sendmsg per up to 64 packets); shared
        // with the client loop — see `egress.drainGso`.
        try egress.drainGso(
            slot.conn,
            gso_buf,
            max_gso_segments,
            now_us,
            &l.gso_active,
            GsoSendCtx{ .slot = slot, .sock = l.sock, .io = io },
        );
        // Offload still on: the outbox is empty, done. A cleared flag
        // means the socket rejected offload mid-drain — fall through
        // and finish this slot's outbox via plain batching.
        if (l.gso_active) return;
    }
    while (true) {
        const dst = batch.nextSlot() orelse blk: {
            // Batch full mid-drain: ship it and keep going.
            batch.flush(io, l.sock) catch |err| {
                // Parity with the historical per-datagram posture:
                // egress failures for a slot are non-fatal (QUIC loss
                // recovery covers dropped tails), but stop this
                // slot's drain for the iteration.
                return err;
            };
            break :blk batch.nextSlot() orelse return;
        };
        const out = (try slot.conn.pollDatagram(dst, now_us)) orelse return;
        const target = out.to orelse slot.peer_addr orelse continue;
        const dest = pathAddressToIpAddress(target) orelse continue;
        batch.commit(dest, out.len);
    }
}

/// `egress.drainGso` policy for the server loop: batch destinations
/// fall back to the slot's current peer address, and immediate sends
/// tolerate peer-provoked errno so one unreachable peer can't abandon
/// the rest of the slot's drain — or its migration-probe carry
/// datagram — for the iteration (the same `classifySendError` policy
/// the outer drain path applies via `countEgressFault`).
const GsoSendCtx = struct {
    slot: *Server.Slot,
    sock: Net.Socket,
    io: std.Io,

    pub fn resolve(self: GsoSendCtx, to: ?Address) ?Net.IpAddress {
        const target = to orelse self.slot.peer_addr orelse return null;
        return pathAddressToIpAddress(target);
    }

    pub fn send(self: GsoSendCtx, dest: *const Net.IpAddress, data: []const u8) !void {
        try sendTolerant(self.io, self.sock, dest, data);
    }

    pub fn sendMany(self: GsoSendCtx, msgs: []Net.OutgoingMessage) !void {
        try self.sock.sendMany(self.io, msgs, .{});
    }
};

/// Convert the loop's monotonic-clock origin into a non-negative
/// microsecond offset suitable for `Server.feed` / `Server.tick`.
/// Also reused by `runUdpClient`.
/// Clamp a loop's base receive timeout to an optional timer deadline:
/// no deadline keeps the base; a due or sub-millisecond deadline
/// clamps to 1 ms (blocking-recv floor — never a busy spin); anything
/// else waits exactly until the deadline, rounded up. Shared by
/// `runUdpServer` and `runUdpClient` (INTERNAL).
pub fn clampTimeoutToDeadline(
    base: std.Io.Duration,
    deadline_us: ?u64,
    now_us: u64,
) std.Io.Duration {
    const at_us = deadline_us orelse return base;
    if (at_us <= now_us) return std.Io.Duration.fromMilliseconds(1);
    const until_ms: u64 = ((at_us - now_us) + 999) / 1000; // round up
    const base_ms_i = base.toMilliseconds();
    const base_ms: u64 = if (base_ms_i < 1) 1 else @intCast(base_ms_i);
    const ms = @min(base_ms, @max(until_ms, 1));
    return std.Io.Duration.fromMilliseconds(@intCast(ms));
}

test clampTimeoutToDeadline {
    const five = std.Io.Duration.fromMilliseconds(5);
    // No deadline: base unchanged.
    try std.testing.expectEqual(
        @as(i64, 5),
        clampTimeoutToDeadline(five, null, 1_000).toMilliseconds(),
    );
    // Far deadline: base still wins.
    try std.testing.expectEqual(
        @as(i64, 5),
        clampTimeoutToDeadline(five, 1_000_000, 1_000).toMilliseconds(),
    );
    // Near deadline (2.5 ms away): rounds UP to 3 ms.
    try std.testing.expectEqual(
        @as(i64, 3),
        clampTimeoutToDeadline(five, 3_500, 1_000).toMilliseconds(),
    );
    // Past-due and sub-ms: 1 ms floor, never 0.
    try std.testing.expectEqual(
        @as(i64, 1),
        clampTimeoutToDeadline(five, 500, 1_000).toMilliseconds(),
    );
    try std.testing.expectEqual(
        @as(i64, 1),
        clampTimeoutToDeadline(five, 1_400, 1_000).toMilliseconds(),
    );
}

/// What the loop should do about a failed receive.
pub const ReceiveDisposition = enum {
    /// Not a loop-ending condition: keep whatever messages the batch
    /// did deliver and continue to the next iteration.
    tolerate,
    /// A genuine local fault; propagate to the caller.
    fatal,
};

/// Classify a receive failure.
///
/// Three members of `ReceiveError` are influenced by the *remote* side,
/// and a QUIC endpoint that dies because a peer misbehaved is a
/// denial-of-service vector rather than a safety property. They are
/// tolerated:
///
///   * `PortUnreachable` and `ConnectionResetByPeer` — ICMP feedback
///     queued against the bound socket and reported at the next
///     receive, per the std docs. A peer that went away, or an off-path
///     packet that provokes an ICMP, must not stop us serving everyone
///     else; the socket remains usable. `examples/foreign_loop_embedder.zig`
///     has always taken this posture and the bundled loops did not,
///     which is the inconsistency this fixes.
///   * `MessageOversize` — a datagram larger than the per-message
///     buffer, which a peer chooses. POSIX reports the same event as a
///     *successful* receive with `flags.trunc` set (dropped below);
///     Windows AFD surfaces it as this error instead. Same event, same
///     correct response: discard the datagram, keep the loop.
///
/// `Timeout` is the ordinary idle path. Everything else — resource
/// exhaustion, `NetworkDown`, the Windows `ConcurrencyUnavailable`
/// platform limit — is a local fault and still propagates.
pub fn classifyReceiveError(err: Net.Socket.ReceiveTimeoutError) ReceiveDisposition {
    return switch (err) {
        error.Timeout,
        error.PortUnreachable,
        error.ConnectionResetByPeer,
        error.MessageOversize,
        => .tolerate,
        else => .fatal,
    };
}

test "remote-influenced receive errors never end the loop" {
    // Peer-controllable or peer-provoked conditions: tolerating these
    // is what stops one misbehaving peer from taking down the endpoint.
    for ([_]Net.Socket.ReceiveTimeoutError{
        error.Timeout,
        error.PortUnreachable,
        error.ConnectionResetByPeer,
        error.MessageOversize,
    }) |err| {
        try std.testing.expectEqual(ReceiveDisposition.tolerate, classifyReceiveError(err));
    }

    // Local faults must still surface rather than spin silently.
    for ([_]Net.Socket.ReceiveTimeoutError{
        error.SystemResources,
        error.NetworkDown,
        error.ConcurrencyUnavailable,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
    }) |err| {
        try std.testing.expectEqual(ReceiveDisposition.fatal, classifyReceiveError(err));
    }
}

/// Record a drain/flush failure against the server's metrics.
///
/// The server loop never exits on egress failure — a server that
/// limps is better than one that dies, and QUIC loss recovery covers
/// dropped tails. But "never exits" used to mean "never mentions it
/// either", so a host with no interface or no socket buffers served
/// nothing while reporting perfect health. Local faults now land on
/// `MetricsSnapshot.egress_local_faults`, which embedders already
/// forward to their metrics pipeline.
///
/// Peer-provoked failures stay uncounted on purpose: they are routine
/// on the open internet, and counting them would bury the signal that
/// matters. `drainSlot` can also surface non-send errors (a
/// `pollDatagram` fault); those are local by definition and counted.
fn countEgressFault(server: *Server, err: anyerror) void {
    switch (classifySendError(err)) {
        .tolerate => {},
        .fatal => server.egress_local_faults +%= 1,
    }
}

/// What the loop should do about a failed send. Same two-way split as
/// `ReceiveDisposition`, and for the same reason.
pub const SendDisposition = enum {
    /// This datagram is lost; the loop is fine. QUIC loss recovery
    /// retransmits, and if the peer really is gone the idle timeout
    /// closes the connection cleanly — which is a better outcome than
    /// handing the embedder an error and skipping the close.
    tolerate,
    /// A genuine local fault. The socket cannot send at all.
    fatal,
};

/// Classify a send failure.
///
/// The remote side, or a path change, can provoke every error in the
/// first group. `ConnectionRefused` is the one that bites: a peer that
/// stops listening produces an ICMP port-unreachable, which the kernel
/// queues against the socket and reports on the *next send*. Treating
/// that as fatal lets any peer terminate the loop — the send-side twin
/// of the receive bug fixed alongside this.
///
/// `MessageOversize` belongs here too: a datagram we could not fit is
/// a datagram to drop, not a reason to stop.
///
/// The second group is local — no interface, no buffers, no
/// permission. Nothing the loop does next will work, so callers that
/// can act on it should see it.
///
/// Takes `anyerror` rather than `Net.Socket.SendError` so the server's
/// drain path — whose inferred error set also carries `pollDatagram`
/// faults — can share this one definition. Anything unrecognised
/// classifies as `.fatal`, which is the safe default: an error nobody
/// anticipated should be surfaced, not swallowed.
pub fn classifySendError(err: anyerror) SendDisposition {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.MessageOversize,
        => .tolerate,
        else => .fatal,
    };
}

/// Send one datagram, tolerating peer-provoked failures.
///
/// Both bundled loops route their immediate (non-batched) egress
/// through here so the policy is stated once: an ICMP provoked by a
/// peer that went away must not end a loop or abandon a drain, while
/// a local fault still reaches the caller. See `classifySendError`.
// INTERNAL: pub for direct sibling import (udp_client.zig).
pub fn sendTolerant(
    io: std.Io,
    sock: Net.Socket,
    dest: *const Net.IpAddress,
    data: []const u8,
) !void {
    sock.send(io, dest, data) catch |err| switch (classifySendError(err)) {
        .tolerate => {},
        .fatal => return err,
    };
}

test "a peer cannot end a loop through the send path" {
    // Remote-influenced, and all reachable by ICMP from a peer that
    // went away or a path that changed.
    for ([_]Net.Socket.SendError{
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.MessageOversize,
    }) |err| {
        try std.testing.expectEqual(SendDisposition.tolerate, classifySendError(err));
    }

    // Local faults: the socket is not going to start working.
    for ([_]Net.Socket.SendError{
        error.SystemResources,
        error.NetworkDown,
        error.AccessDenied,
        error.SocketUnconnected,
        error.AddressFamilyUnsupported,
    }) |err| {
        try std.testing.expectEqual(SendDisposition.fatal, classifySendError(err));
    }
}

pub fn monotonicNowUs(io: std.Io, start: std.Io.Timestamp) u64 {
    const now = std.Io.Timestamp.now(io, .awake);
    const delta = start.durationTo(now).toMicroseconds();
    if (delta <= 0) return 0;
    return @intCast(delta);
}

/// Re-export of `udp_batch.ipAddressToPathAddress` — the
/// `std.Io.net.IpAddress` -> `path.Address` projection lives in the
/// batch-helpers leaf now (`udp_batch.IngressIterator` needs it); the
/// alias keeps this loop's historical address-helper pair intact for
/// embedders (pinned by the internal-surface smoke).
pub const ipAddressToPathAddress = udp_batch.ipAddressToPathAddress;

/// Inverse projection. Returns `null` for `.unspecified` — the loop
/// treats that as "no usable destination" and skips the send.
/// Also reused by `runUdpClient`.
pub fn pathAddressToIpAddress(addr: Address) ?Net.IpAddress {
    return switch (addr) {
        .unspecified => null,
        .ipv4 => |v| .{ .ip4 = .{ .bytes = v.addr, .port = v.port } },
        .ipv6 => |v| .{ .ip6 = .{ .bytes = v.addr, .port = v.port, .flow = v.flow } },
    };
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;

test "RunUdpOptions: defaults are sensible" {
    const opts: RunUdpOptions = .{
        .listen = "127.0.0.1:0",
        .io = undefined, // not invoked in this test
    };
    try testing.expectEqualStrings("127.0.0.1:0", opts.listen);
    try testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    try testing.expect(opts.tune_socket);
    try testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    try testing.expectEqual(default_rx_buffer_bytes, opts.rx_buffer_bytes);
    try testing.expectEqual(default_tx_buffer_bytes, opts.tx_buffer_bytes);
    try testing.expect(opts.shutdown_flag == null);
}

test "ipAddressToPathAddress / pathAddressToIpAddress round-trip IPv4" {
    const v4: Net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 192, 168, 1, 7 },
        .port = 4433,
    } };
    const pa = ipAddressToPathAddress(v4);
    try testing.expect(pa == .ipv4);

    const back = pathAddressToIpAddress(pa).?;
    try testing.expect(back == .ip4);
    try testing.expectEqual(v4.ip4.port, back.ip4.port);
    try testing.expectEqualSlices(u8, &v4.ip4.bytes, &back.ip4.bytes);
}

test "ipAddressToPathAddress / pathAddressToIpAddress round-trip IPv6" {
    const v6: Net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 4433,
        .flow = 0xabcdef,
    } };
    const pa = ipAddressToPathAddress(v6);
    try testing.expect(pa == .ipv6);

    const back = pathAddressToIpAddress(pa).?;
    try testing.expect(back == .ip6);
    try testing.expectEqual(v6.ip6.port, back.ip6.port);
    try testing.expectEqual(v6.ip6.flow, back.ip6.flow);
    try testing.expectEqualSlices(u8, &v6.ip6.bytes, &back.ip6.bytes);
}

test "pathAddressToIpAddress returns null for unspecified address" {
    const empty: Address = .unspecified;
    try testing.expect(pathAddressToIpAddress(empty) == null);
}

test "monotonicNowUs is non-negative" {
    const io = std.testing.io;
    const start = std.Io.Timestamp.now(io, .awake);
    const elapsed = monotonicNowUs(io, start);
    // Right after start the elapsed time is small (likely 0) but
    // never wraps to a giant u64.
    try testing.expect(elapsed < 1_000_000); // < 1 second
}
