//! Opinionated `std.Io`-based UDP client loop for `quic.Client`.
//!
//! Takes a freshly-constructed
//! `*Client` and an embedder-supplied target address, binds an
//! ephemeral local UDP socket, and runs the
//! `advance` -> `poll` -> `receive` -> `handle` -> `tick` loop on a
//! monotonic clock until the connection closes (or the embedder
//! flips a shutdown flag).
//!
//! Like `runUdpServer`, the loop is opt-in. Embedders that need
//! full control of socket lifecycle (per-connection migration,
//! batched I/O via `recvmmsg`, qlog file rotation, etc.) keep
//! using `client.conn.advance` / `client.conn.poll` /
//! `client.conn.handle` directly.
//!
//! Time
//! ----
//! Same monotonic-clock contract as `runUdpServer`: the loop
//! captures `Timestamp.now(io, .awake)` at startup and feeds the
//! microsecond delta into every `tick` and `handle` call so QUIC
//! recovery timers cannot drag backwards on wall-clock skew.
//!
//! Shutdown / completion
//! ---------------------
//! The loop returns cleanly when EITHER:
//!  - `client.conn.isClosed()` returns true (the connection
//!    transitioned to `.closed` for any reason — handshake done +
//!    embedder closed it, peer-initiated close, idle timeout, etc.),
//!    OR
//!  - `RunUdpClientOptions.shutdown_flag` flips to true. The loop
//!    then calls `client.conn.close(false, options.shutdown_error_code,
//!    "")` to queue a CONNECTION_CLOSE on the wire and continues
//!    polling for up to `shutdown_grace_us` so the close actually
//!    reaches the server before the socket goes away.
//!
//! Embedder cooperation
//! --------------------
//! The loop owns ONLY the UDP socket, and calls into `client.conn`
//! from the loop thread. `Connection` is single-threaded with no
//! internal locking, so application-level work (opening streams,
//! writing data, reading received data, polling events) must be
//! serialized with the loop: run it inside
//! `RunUdpClientOptions.on_iteration`, which fires once per loop
//! iteration on the loop thread. Never touch `client.conn` from a
//! second thread while the loop runs. Same model as `runUdpServer`.

const std = @import("std");

const Client = @import("../Client.zig");
const conn_state = @import("../Connection.zig");
const Connection = conn_state.Connection;
const path_mod = @import("../conn/path.zig");
const socket_opts = @import("socket_opts.zig");
const udp_batch = @import("udp_batch.zig");
const udp_server = @import("udp_server.zig");

const Net = std.Io.net;
const Address = path_mod.Address;

/// Default size of the receive buffer scratch space. 64 KiB matches
/// `udp_server.default_rx_buffer_bytes` — a single UDP datagram cannot
/// exceed this even with the largest jumbo frame.
pub const default_rx_buffer_bytes: usize = 64 * 1024;

/// Default size of the send buffer scratch space. 1500 bytes covers
/// the default QUIC `max_udp_payload_size` plus a small margin.
pub const default_tx_buffer_bytes: usize = 1500;

/// Default per-iteration `receiveTimeout` duration. 5 ms keeps the
/// loop responsive to QUIC's millisecond-ish PTO timers without
/// busy-spinning.
pub const default_receive_timeout_ms: i64 = 5;

/// Configuration for `runUdpClient`. Shape mirrors `RunUdpOptions`
/// where it makes sense; client-specific bits are the `target`
/// address and the absence of `tune_socket` defaults that assume a
/// large server-class buffer (`runUdpClient`'s default tuning ships
/// with the same `ServerTuning` struct but embedded targets often
/// flip `tune_socket` off).
pub const RunUdpClientOptions = struct {
    /// IPv4 or IPv6 server address as a literal — `"127.0.0.1:4433"`,
    /// `"[2001:db8::1]:443"`, etc. Parsed by
    /// `std.Io.net.IpAddress.parseLiteral`. Hostname resolution is
    /// the embedder's responsibility — the runner takes a literal
    /// because `Client.connect` already accepted an SNI hostname.
    target: []const u8,
    /// Optional local bind literal. Empty / null pulls an ephemeral
    /// port from the kernel: `"0.0.0.0:0"` for an IPv4 target,
    /// `"[::]:0"` for an IPv6 target. Embedders that need a fixed
    /// source 4-tuple (e.g. for path-validation testing) supply
    /// their own literal here.
    bind: ?[]const u8 = null,
    /// Caller-provided `std.Io` instance. Same contract as
    /// `RunUdpOptions.io`.
    io: std.Io,
    /// Ingress batch bound: how many datagrams one iteration may
    /// receive before ticking and draining (see the server option of
    /// the same name). Set to 1 for the historical behavior.
    max_datagrams_per_iteration: u32 = 16,
    /// Egress batch bound: outbound datagrams accumulate into a batch
    /// and ship through one `Socket.sendMany` (see the server option
    /// of the same name). 1 restores a syscall per datagram.
    max_send_batch_datagrams: u32 = 64,
    /// Linux UDP GSO for uploads (see the server option). Probed at
    /// socket setup; runtime send errors fall back to plain batching.
    enable_gso: bool = true,
    /// Linux UDP GRO for downloads (see the server option).
    enable_gro: bool = true,
    /// `Socket.receiveTimeout` interval between `tick` calls.
    /// Default 5 ms keeps PTO firing on time.
    receive_timeout: std.Io.Duration = std.Io.Duration.fromMilliseconds(default_receive_timeout_ms),
    /// Apply the recommended `SO_RCVBUF` / `SO_SNDBUF` tuning.
    /// Defaults to true; embedded targets with tight memory budgets
    /// can flip it off and rely on the kernel defaults.
    tune_socket: bool = true,
    /// Tuning applied when `tune_socket` is true. Same struct as
    /// `RunUdpOptions.tuning`; clients have the same buffer-burst
    /// pressures as servers under heavy fan-out.
    tuning: socket_opts.ServerTuning = .{},

    /// Enable IETF ECN signaling (RFC 9000 §13.4). When `true`, the
    /// loop sets `IP_TOS` / `IPV6_TCLASS` to ECT(0) on the bound
    /// socket and `IP_RECVTOS` / `IPV6_RECVTCLASS` so the kernel
    /// surfaces the per-datagram TOS byte via cmsg. Symmetric to the
    /// server-side path. Default true.
    enable_ecn: bool = true,
    /// Send-side ECN codepoint when `enable_ecn = true`. Defaults to
    /// ECT(0) per RFC 9000 §13.4 guidance.
    ecn_send_codepoint: socket_opts.EcnCodepoint = .ect0,
    /// Per-recv cmsg control buffer size. 64 bytes covers `IP_TOS`
    /// and `IPV6_TCLASS` cmsgs with alignment slack.
    cmsg_buffer_bytes: usize = socket_opts.default_cmsg_buffer_bytes,

    /// Optional shutdown signal. Once observed true, the loop
    /// triggers a graceful close on the connection and continues
    /// polling for up to `shutdown_grace_us`. Unlike the server
    /// case, the loop will also exit on its own once the connection
    /// reaches `.closed` (no shutdown flag required for normal
    /// completion).
    shutdown_flag: ?*const std.atomic.Value(bool) = null,
    /// Microseconds to keep the loop running after `shutdown_flag`
    /// flips, so the queued CONNECTION_CLOSE actually reaches the
    /// peer before the socket goes away.
    shutdown_grace_us: u64 = 5_000_000,
    /// Application error code emitted on the queued
    /// CONNECTION_CLOSE when `shutdown_flag` flips. Default 0
    /// matches the QNS interop "clean exit" semantic.
    shutdown_error_code: u64 = 0,
    /// Receive scratch buffer size.
    rx_buffer_bytes: usize = default_rx_buffer_bytes,
    /// Send scratch buffer size.
    tx_buffer_bytes: usize = default_tx_buffer_bytes,

    /// Per-iteration application hook — the one safe place to run
    /// application logic against a loop-owned client. Invoked once per
    /// iteration on the loop thread, after inbound datagrams have been
    /// handled and the recovery clock ticked; the next outbox drain
    /// runs immediately after the hook returns, so writes it queues
    /// ship without waiting out a receive timeout. `Connection` has no
    /// internal locking; open streams, read data, drain
    /// `client.conn.pollEvent()`, and send datagrams only from inside
    /// the hook. It keeps firing during the shutdown grace window. An
    /// error return stops the loop and propagates out of
    /// `runUdpClient` verbatim.
    on_iteration: ?*const fn (ctx: ?*anyopaque, client: *Client, now_us: u64) anyerror!void = null,
    /// Opaque pointer passed back to `on_iteration` every call.
    on_iteration_ctx: ?*anyopaque = null,
};

/// Errors the loop itself can produce. Mostly propagated from
/// `std.Io.net.IpAddress.bind`, `Socket.send`, or `Connection.handle`.
/// The function signature is `anyerror!void` (not `RunError!void`)
/// only because `RunUdpClientOptions.on_iteration` errors propagate
/// out verbatim; a loop without a hook fails only with values from
/// this set.
pub const RunError = error{
    /// `RunUdpClientOptions.target` did not parse as an IPv4/IPv6 literal.
    InvalidTargetAddress,
    /// `RunUdpClientOptions.bind` was non-null but did not parse.
    InvalidBindAddress,
    /// `tune_socket = true` but the kernel refused both the
    /// privileged and cap-respecting `setsockopt` calls.
    SocketTuningFailed,
    /// `rx_buffer_bytes` or `tx_buffer_bytes` was set to 0.
    InvalidBufferSize,
    OutOfMemory,
    //
    // Inherited from `Net.Socket.ReceiveTimeoutError`:
    // `error.ConcurrencyUnavailable` means **this loop cannot run on
    // native Windows** at the pinned toolchain. See the matching note
    // on `udp_server.RunError` for the full explanation; the short
    // version is that std has no overlapped-I/O `net_receive` on
    // Windows, so no timed receive is possible, and a timed receive is
    // what drives `tick`. Windows embedders drive their own loop —
    // see `examples/foreign_loop_embedder.zig`.
} || Net.IpAddress.BindError ||
    Net.Socket.SendError ||
    Net.Socket.ReceiveTimeoutError ||
    conn_state.Error;

/// Run a UDP client loop driven by `client`. The loop owns the
/// socket: it is bound, optionally tuned, used, and closed inside
/// this function. The `client` is used non-owning — its `Config`
/// and lifecycle are still entirely the caller's.
///
/// Returns when the connection reaches the `.closed` state OR the
/// shutdown flag is observed true (and the grace window expires or
/// the connection drains, whichever comes first).
///
/// Threading: `runUdpClient` owns the receive/poll/tick loop and calls
/// into `client.conn` from this thread. `Connection` is single-threaded
/// with no internal locking, so any application work that also touches
/// `client.conn` (opening streams, writing data, reading received data,
/// polling events) MUST be serialized with this loop — do it on the same
/// thread (e.g. from a callback the loop invokes) or guard every
/// `Connection` access with your own mutex. Do NOT drive `client.conn`
/// from another thread concurrently with this loop. Same threading model
/// as `runUdpServer`. Embedders that want application logic interleaved
/// on one thread should use the raw `Connection` cycle in EMBEDDING.md.
pub fn runUdpClient(client: *Client, options: RunUdpClientOptions) anyerror!void {
    if (options.rx_buffer_bytes == 0 or options.tx_buffer_bytes == 0) {
        return error.InvalidBufferSize;
    }

    const target_addr = Net.IpAddress.parseLiteral(options.target) catch {
        return error.InvalidTargetAddress;
    };

    const bind_addr: Net.IpAddress = if (options.bind) |literal|
        (Net.IpAddress.parseLiteral(literal) catch return error.InvalidBindAddress)
    else switch (target_addr) {
        // Default to an unspecified bind on the same address family
        // as the target so the kernel picks an ephemeral port. v4
        // targets get `0.0.0.0:0`; v6 targets get `[::]:0`.
        .ip4 => .{ .ip4 = Net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = Net.Ip6Address.unspecified(0) },
    };

    const sock = try Net.IpAddress.bind(&bind_addr, options.io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(options.io);

    if (options.tune_socket) {
        socket_opts.applyServerTuning(sock.handle, options.tuning) catch {
            return error.SocketTuningFailed;
        };
    }

    var ecn_active = options.enable_ecn;
    if (ecn_active) {
        socket_opts.setEcnSendMarking(sock.handle, options.ecn_send_codepoint) catch {
            ecn_active = false;
        };
        if (ecn_active) {
            socket_opts.setEcnRecvEnabled(sock.handle, true) catch {
                ecn_active = false;
            };
        }
    }
    var gso_active = options.enable_gso and socket_opts.probeUdpGso(sock.handle);
    var gro_active = false;
    if (options.enable_gro) {
        if (socket_opts.setUdpGroEnabled(sock.handle)) |_| {
            gro_active = true;
        } else |_| {}
    }

    const allocator = client.allocator;
    const rx = try allocator.alloc(u8, options.rx_buffer_bytes);
    defer allocator.free(rx);
    var send_batch = try udp_server.SendBatch.init(
        allocator,
        @max(1, options.max_send_batch_datagrams),
        options.tx_buffer_bytes,
    );
    defer send_batch.deinit(allocator);
    const gso_buf = try allocator.alloc(
        u8,
        @as(usize, socket_opts.default_gso_max_segments) * options.tx_buffer_bytes,
    );
    defer allocator.free(gso_buf);
    const cmsg_buf_len: usize = if (ecn_active or gro_active) options.cmsg_buffer_bytes else 0;
    var empty_cmsg_buf: [0]u8 = undefined;
    const batch_len: usize = @max(1, options.max_datagrams_per_iteration);
    const cmsg_buf: []u8 = if (cmsg_buf_len > 0)
        try allocator.alloc(u8, cmsg_buf_len * batch_len)
    else
        empty_cmsg_buf[0..0];
    defer if (cmsg_buf_len > 0) allocator.free(cmsg_buf);

    // Ingress batch: up to `batch_len` messages per iteration through
    // one `receiveManyTimeout` call (see runUdpServer for the shape).
    const batch_msgs = try allocator.alloc(Net.IncomingMessage, batch_len);
    defer allocator.free(batch_msgs);

    // Kick the handshake. `Client.connect` deliberately doesn't call
    // `advance` so 0-RTT-bound STREAM data could be installed before
    // the first ClientHello hits the wire. Embedders driving the
    // client through `runUdpClient` typically don't have that need —
    // any 0-RTT data was already staged by them between
    // `Client.connect` and `runUdpClient`.
    try client.conn.advance();

    const start = std.Io.Timestamp.now(options.io, .awake);
    var shutdown_started: bool = false;
    var shutdown_deadline_us: u64 = 0;

    while (true) {
        var now_us = udp_server.monotonicNowUs(options.io, start);

        // Natural completion: connection is closed for any reason
        // (handshake done + embedder closed, peer-initiated close,
        // idle timeout, stateless reset, etc.).
        if (client.conn.isClosed()) return;

        // Shutdown gate: once the flag flips, queue a CONNECTION_CLOSE
        // and start a grace window. Skip if the connection already
        // initiated its own close.
        if (!shutdown_started) {
            if (options.shutdown_flag) |flag| {
                if (flag.load(.acquire)) {
                    if (client.conn.closeState() == .open) {
                        client.conn.close(false, options.shutdown_error_code, "");
                    }
                    shutdown_started = true;
                    shutdown_deadline_us = now_us +| options.shutdown_grace_us;
                }
            }
        } else if (now_us >= shutdown_deadline_us) {
            return;
        }

        // Drain everything queued before the next receive. Same
        // path-aware shape as the server's drainSlot.
        try drainOutbound(
            client.conn,
            &send_batch,
            .{ .buf = gso_buf, .active = &gso_active },
            now_us,
            sock,
            options.io,
            target_addr,
        );

        // Clamp the wait to the connection's earliest timer deadline
        // (pacing credit, PTO, ack-delay, ...) — see
        // `udp_server.clampTimeoutToDeadline`.
        const iteration_timeout = udp_server.clampTimeoutToDeadline(
            options.receive_timeout,
            if (client.conn.nextTimerDeadline(now_us)) |td| td.at_us else null,
            now_us,
        );

        // Batched receive (or timeout): the first message waits up to
        // the deadline-clamped timeout, the rest drain what's already
        // queued. Per-message cmsg slices carry IP_TOS / IPV6_TCLASS
        // when ECN is active.
        for (batch_msgs, 0..) |*msg, i| {
            msg.* = .init;
            if (ecn_active or gro_active) {
                msg.control = cmsg_buf[i * cmsg_buf_len ..][0..cmsg_buf_len];
            }
        }
        const ret = sock.receiveManyTimeout(options.io, batch_msgs, rx, .{}, .{
            .duration = .{
                .raw = iteration_timeout,
                .clock = .awake,
            },
        });
        var received: usize = ret[1];
        if (ret[0]) |err| switch (udp_server.classifyReceiveError(err)) {
            // Same posture as the server loop: a peer-provoked ICMP or
            // an oversized datagram must not tear down the client.
            .tolerate => {},
            .fatal => return err,
        };

        // Refresh time after the (possibly-blocking) receive.
        now_us = udp_server.monotonicNowUs(options.io, start);

        if (received > batch_msgs.len) received = batch_msgs.len;
        for (batch_msgs[0..received]) |*msg| {
            if (msg.flags.trunc) continue;
            const ecn: socket_opts.EcnCodepoint = if (ecn_active)
                socket_opts.parseEcnFromControl(msg.control)
            else
                .not_ect;
            const from_addr = udp_server.ipAddressToPathAddress(msg.from);
            // GRO: split a kernel-coalesced buffer back into original
            // datagrams (see runUdpServer).
            if (gro_active) {
                if (socket_opts.parseGroSegmentFromControl(msg.control)) |gro_seg| {
                    if (msg.data.len > gro_seg) {
                        var off: usize = 0;
                        var gro_failed = false;
                        while (off < msg.data.len) {
                            const end = @min(off + @as(usize, gro_seg), msg.data.len);
                            client.conn.handleWithEcn(msg.data[off..end], from_addr, ecn, now_us) catch |err| switch (err) {
                                error.HandshakeFailed,
                                error.PeerAlerted,
                                error.UnsupportedCipherSuite,
                                => {
                                    gro_failed = true;
                                    break;
                                },
                                else => return err,
                            };
                            off = end;
                        }
                        if (gro_failed) return;
                        continue;
                    }
                }
            }
            // `Connection.handleWithEcn` swallows per-frame errors
            // internally; only fatal connection-level errors
            // propagate out (e.g. OOM during a stream allocation).
            // The legacy `handle` is a Not-ECT thunk over the same
            // path so embedders that opt out of ECN still go through
            // the same dispatcher.
            client.conn.handleWithEcn(msg.data, from_addr, ecn, now_us) catch |err| switch (err) {
                error.HandshakeFailed,
                error.PeerAlerted,
                error.UnsupportedCipherSuite,
                => return,
                else => return err,
            };
        }

        // Tick the recovery clock. PTO / loss detection / key-update
        // deadlines all fire in here.
        try client.conn.tick(now_us);

        // Application hook: inbound handled and clock ticked; the top
        // of the next iteration drains the outbox immediately, so
        // anything the hook queues ships without a timeout wait.
        if (options.on_iteration) |hook| {
            try hook(options.on_iteration_ctx, client, now_us);
        }
    }
}

/// Send one datagram, tolerating peer-provoked failures.
///
/// Every egress site in this file goes through here so the policy is
/// stated once: an ICMP provoked by a peer that went away must not end
/// the client loop, while a local fault still reaches the embedder.
/// See `udp_server.classifySendError`.
fn sendTolerant(
    io: std.Io,
    sock: Net.Socket,
    dest: *const Net.IpAddress,
    data: []const u8,
) !void {
    sock.send(io, dest, data) catch |err| switch (udp_server.classifySendError(err)) {
        .tolerate => {},
        .fatal => return err,
    };
}

fn drainOutbound(
    conn: *Connection,
    batch: *udp_server.SendBatch,
    gso: struct { buf: []u8, active: *bool },
    now_us: u64,
    sock: Net.Socket,
    io: std.Io,
    fallback: Net.IpAddress,
) RunError!void {
    if (gso.active.*) {
        while (true) {
            const filled = try udp_batch.fillGsoBatch(
                conn,
                gso.buf,
                socket_opts.default_gso_max_segments,
                now_us,
            );
            if (filled.count == 0) return;
            var dest: Net.IpAddress = fallback;
            if (filled.to) |path_addr| {
                if (udp_server.pathAddressToIpAddress(path_addr)) |resolved| dest = resolved;
            }
            if (filled.count == 1) {
                try sendTolerant(io, sock, &dest, gso.buf[0..filled.total_len]);
            } else {
                var cmsg: [64]u8 = undefined;
                const cmsg_len = socket_opts.writeUdpSegmentCmsg(&cmsg, @intCast(filled.seg_size));
                var msgs = [_]Net.OutgoingMessage{.{
                    .address = &dest,
                    .data_ptr = gso.buf.ptr,
                    .data_len = filled.total_len,
                    .control = cmsg[0..cmsg_len],
                }};
                sock.sendMany(io, &msgs, .{}) catch {
                    // Runtime offload failure: disable and re-ship the
                    // already-built segments plainly.
                    gso.active.* = false;
                    var off: usize = 0;
                    while (off < filled.total_len) {
                        const end = @min(off + filled.seg_size, filled.total_len);
                        try sendTolerant(io, sock, &dest, gso.buf[off..end]);
                        off = end;
                    }
                };
            }
            if (filled.hasCarry()) {
                var carry_dest: Net.IpAddress = fallback;
                if (filled.carry_to) |path_addr| {
                    if (udp_server.pathAddressToIpAddress(path_addr)) |resolved| carry_dest = resolved;
                }
                try sendTolerant(io, sock, &carry_dest, gso.buf[filled.carry_offset..][0..filled.carry_len]);
            }
        }
    }
    while (true) {
        const dst = batch.nextSlot() orelse blk: {
            try batch.flush(io, sock);
            break :blk batch.nextSlot() orelse return;
        };
        const out = (try conn.pollDatagram(dst, now_us)) orelse break;
        const dest: Net.IpAddress = blk: {
            if (out.to) |path_addr| {
                if (udp_server.pathAddressToIpAddress(path_addr)) |resolved| {
                    break :blk resolved;
                }
            }
            // No explicit destination on the outgoing datagram (the
            // common path for a single-path client) — send to the
            // configured target.
            break :blk fallback;
        };
        batch.commit(dest, out.len);
    }
    // Client posture: *local* egress faults propagate, so an embedder
    // whose interface died hears about it. Peer-provoked failures do
    // not — a peer that stopped listening produces an ICMP that the
    // kernel reports on our next send, and letting that end the loop
    // would hand any peer a kill switch. The datagram is simply lost;
    // loss recovery retransmits, and a peer that is really gone is
    // closed out by the idle timeout, which is the clean path.
    batch.flush(io, sock) catch |err| switch (udp_server.classifySendError(err)) {
        .tolerate => {},
        .fatal => return err,
    };
}

// ---- Tests --------------------------------------------------------------

const testing = std.testing;

test "RunUdpClientOptions: defaults are sensible" {
    const opts: RunUdpClientOptions = .{
        .target = "127.0.0.1:4433",
        .io = undefined, // not invoked in this test
    };
    try testing.expectEqualStrings("127.0.0.1:4433", opts.target);
    try testing.expectEqual(@as(?[]const u8, null), opts.bind);
    try testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    try testing.expect(opts.tune_socket);
    try testing.expect(opts.enable_ecn);
    try testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    try testing.expectEqual(@as(u64, 0), opts.shutdown_error_code);
    try testing.expectEqual(default_rx_buffer_bytes, opts.rx_buffer_bytes);
    try testing.expectEqual(default_tx_buffer_bytes, opts.tx_buffer_bytes);
    try testing.expect(opts.shutdown_flag == null);
}

test "runUdpClient rejects InvalidBufferSize on zero rx/tx" {
    // We can short-circuit the loop without ever binding a socket
    // by setting rx_buffer_bytes = 0; the validation runs at the
    // very top.
    var fake_client: Client = undefined;
    try testing.expectError(error.InvalidBufferSize, runUdpClient(&fake_client, .{
        .target = "127.0.0.1:0",
        .io = undefined,
        .rx_buffer_bytes = 0,
    }));
    try testing.expectError(error.InvalidBufferSize, runUdpClient(&fake_client, .{
        .target = "127.0.0.1:0",
        .io = undefined,
        .tx_buffer_bytes = 0,
    }));
}

test "runUdpClient rejects InvalidTargetAddress on garbage literal" {
    var fake_client: Client = undefined;
    try testing.expectError(error.InvalidTargetAddress, runUdpClient(&fake_client, .{
        .target = "not-a-real-address",
        .io = undefined,
    }));
}

test "runUdpClient rejects InvalidBindAddress on garbage bind literal" {
    var fake_client: Client = undefined;
    try testing.expectError(error.InvalidBindAddress, runUdpClient(&fake_client, .{
        .target = "127.0.0.1:0",
        .bind = "not-a-real-address",
        .io = undefined,
    }));
}
