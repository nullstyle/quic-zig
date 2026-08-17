//! Foreign event loop embedder — the I/O-agnostic ("caller-drives")
//! path wired into a hand-rolled `std.posix.poll` reactor instead of
//! `quic.transport.runUdpServer` / `runUdpClient`.
//!
//! ```sh
//! zig build examples
//! ./zig-out/bin/foreign-loop-embedder-example     # server + client in one poll loop
//! ```
//!
//! The shape to copy when your runtime already owns the wait:
//!
//!  1. **Scheduling math is pure.** `pollTimeoutMs` turns a
//!     `quic.TimerDeadline` into a `poll(2)` timeout. Past-due
//!     deadlines must clamp to `0` (a negative timeout means "block
//!     forever" and your PTO never fires) and sub-millisecond ones
//!     must round *up* to `1` (or the loop spins hot). This is where
//!     hand-rolled loops go wrong, so it lives on its own and is
//!     tested on every platform.
//!  2. **The QUIC call sequence is transport-free.** `ServerPump` /
//!     `ClientPump` implement one loop iteration — events,
//!     application I/O, `tick`, outbox drain, periodic `reap` — over
//!     an injected `DatagramSink`. Nothing in them names a socket,
//!     which is why the in-memory test below can complete a real
//!     TLS 1.3 handshake with no `std.posix` in sight.
//!  3. **Drain the outbox after every state change and immediately
//!     before you park.** This is *the* invariant, and it is why both
//!     `service` methods end with the drain rather than with `tick`
//!     the way `runUdpServer` does. Get it wrong and the loop parks
//!     with bytes queued: worst case is bootstrap, where `advance()`
//!     stages the ClientHello at an instant when the connection has
//!     no timer armed at all, so nothing but the idle cap will wake
//!     you. `PosixPollReactor.run` services both endpoints *before*
//!     computing its timeout and asserts the drain stamp to keep it
//!     that way.
//!  4. **The reactor owns the wait, the clock, and the fds.**
//!     `PosixPollReactor` binds the sockets, builds the poll set,
//!     refreshes `now_us` *after* the blocking wait (reusing the
//!     pre-wait timestamp makes PTO timers fire late), and reads at
//!     most one datagram per readable fd per iteration so tick-driven
//!     recovery work can't be starved by a hot ingress queue. It also
//!     never trusts `POLLIN`: readiness is advisory, so the read is
//!     timeout-bounded — see `PosixPollReactor.receiveOne`, which is
//!     the subtlest thing in this file.
//!  5. **Off-thread work goes through a queue plus a wake fd.**
//!     `Server` and `Connection` have no internal locking, so no
//!     thread but the loop thread may touch them. Producers push onto
//!     `WorkQueue` under its mutex and call `Waker.wake`; the loop
//!     thread drains the queue and is the only thing that ever calls
//!     into quic.
//!  6. **Everything the packaged loops do, you now owe.** Bind and
//!     (optionally) tune the socket, drain `drainStatelessResponse`
//!     separately from the per-slot outbox, pick destinations as
//!     `out.to orelse slot.peer_addr`, contain per-connection errors,
//!     skip terminal-`.closed` slots but keep closing/draining ones,
//!     `reap` periodically, and honour a shutdown grace window. See
//!     `src/transport/udp_server.zig` for the reference implementation
//!     of each.
//!
//! Deliberately out of scope, and each one costs you something if you
//! need it: ECN (`std.Io.net.Socket.receive` builds its own
//! `IncomingMessage` with an empty control buffer, so it cannot carry
//! cmsgs — ECN in a foreign loop needs `receiveManyTimeout` with a
//! caller-owned control buffer; skipping it costs goodput, not
//! correctness), socket buffer tuning (`SO_RCVBUF`/`SO_SNDBUF`, so
//! the example runs unprivileged), and multi-listener
//! `preferred_address` dispatch (configuring `preferred_address`
//! under a foreign loop obliges you to replicate
//! `runUdpServer`'s listener fan-out and `noteServerLocalAddressChanged`
//! transition).
//!
//! Four sizing/API traps this file marks explicitly, because all four
//! fail *silently* rather than erroring: a socket receive buffer
//! shorter than 64 KiB (the kernel truncates, the AEAD then fails, and
//! it all reads as packet loss — see `socket_rx_bytes`);
//! `StreamReadResult.fin`, which reports that the FIN *frame arrived*,
//! not that you have drained the stream (see `echoStream`); a read that
//! returns 0 bytes, which means "nothing readable right now" and is
//! also what a gap below the read offset looks like, so it is not an
//! end-of-stream signal either (see `echoStream`); and
//! `Connection.streamWrite`, which short-writes by design under
//! send-buffer pressure and must never be asserted on (see
//! `StreamEcho.flush`).
//!
//! Unlike `echo_smoke.zig`, this file is **both** a standalone binary
//! and a `zig build test` target. The split is deliberate: the
//! scheduling math (Group A), the wake/queue semantics (Group B), and
//! the full in-memory handshake through the pumps (Group C) are pure
//! and run on every tier-1 platform including Windows; only the
//! socket/poll group (Group D) touches real fds, and it skips on
//! Windows, where std routes sockets through `std.Io` and
//! `std.posix.poll` is a hard `@compileError`. The whole thing uses
//! only the public `quic` API surface.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");
const common = @import("echo_common.zig");

/// ALPN this example negotiates, so it is self-identifying on the
/// wire and cannot be confused with the echo pair's `echo/1`. Client
/// and server must agree — QUIC mandates ALPN (RFC 9001 §8.1).
pub const alpn = "foreign-loop/1";

/// Payload for the stream leg of the round-trip.
pub const stream_message = "hello through a foreign event loop";
/// Payload for the RFC 9221 DATAGRAM leg.
pub const datagram_message = "and one datagram, too";

// -- L1: scheduling math (pure, no I/O, no platform deps) -------------------

/// Longest a foreign loop may block when no QUIC timer is armed.
/// A loop with a wake fd in its set can block indefinitely (-1); this
/// cap is the belt-and-braces value for loops without one.
pub const default_idle_cap_ms: i32 = 1_000;

/// Convert a quic-zig timer deadline into a `poll(2)` timeout, in
/// milliseconds.
///
///  * `null` deadline -> `idle_cap_ms`, or -1 (block until an fd is
///    readable) when `has_wake_fd` is true: a foreign loop with a wake
///    channel never needs a periodic heartbeat, which is the whole
///    point of owning the wait yourself.
///  * deadline already in the past -> 0. Returning a negative number
///    here is the classic bug: `poll` reads -1 as "block forever" and
///    the connection's PTO never fires.
///  * sub-millisecond deadline -> 1, never 0. Rounding *up* keeps the
///    loop from spinning hot on a 300 µs ACK-delay timer.
///
/// `deadline.at_us` is absolute microseconds on *your* monotonic clock
/// origin — the same origin you feed to `feed` / `handle` / `tick`.
/// `Connection.nextTimerDeadline` ignores its `now_us` argument
/// entirely for exactly that reason.
pub fn pollTimeoutMs(
    now_us: u64,
    deadline: ?quic.TimerDeadline,
    idle_cap_ms: i32,
    has_wake_fd: bool,
) i32 {
    const armed = deadline orelse return if (has_wake_fd) -1 else idle_cap_ms;
    // Past-due (or exactly due) means "tick now", not "sleep".
    if (armed.at_us <= now_us) return 0;
    const delta_us = armed.at_us - now_us;
    // Round up: a 300 µs deadline becomes 1 ms, never 0.
    const ms = (delta_us + 999) / 1_000;
    // Clamp to the cap so a far-future idle timer (hours) can't
    // overflow the i32 `poll` takes.
    const cap: u64 = @intCast(@max(idle_cap_ms, 0));
    return @intCast(@min(ms, cap));
}

/// Soonest of two optional deadlines. A loop driving several
/// endpoints (this file's `main` drives a `Server` *and* a `Client`,
/// and folds in its own wall-clock budget) parks on the minimum, so
/// this reduction is part of the scheduling surface.
pub fn earlier(
    a: ?quic.TimerDeadline,
    b: ?quic.TimerDeadline,
) ?quic.TimerDeadline {
    const lhs = a orelse return b;
    const rhs = b orelse return lhs;
    return if (rhs.at_us < lhs.at_us) rhs else lhs;
}

// -- L1b: clock + address projections (local copies, on purpose) ------------

/// Non-negative microsecond offset from a captured monotonic origin.
/// A six-line copy of `quic.transport.udp_server.monotonicNowUs`
/// (`src/transport/udp_server.zig`): the library ships this, but a
/// foreign loop owes `transport/` nothing, and spelling it out here
/// makes that concrete. `Server.feed` / `tick` only require a
/// monotonic non-decreasing microsecond counter on a consistent
/// origin — any origin.
pub fn monotonicNowUs(io: std.Io, start: std.Io.Timestamp) u64 {
    const now = std.Io.Timestamp.now(io, .awake);
    const delta = start.durationTo(now).toMicroseconds();
    if (delta <= 0) return 0;
    return @intCast(delta);
}

/// Project a `std.Io.net.IpAddress` into quic's tagged-union
/// `Address`. Library equivalent:
/// `quic.transport.udp_server.ipAddressToPathAddress`.
pub fn ipAddressToPathAddress(addr: std.Io.net.IpAddress) quic.Address {
    return switch (addr) {
        .ip4 => |ip4| .{ .ipv4 = .{ .addr = ip4.bytes, .port = ip4.port } },
        .ip6 => |ip6| .{ .ipv6 = .{ .addr = ip6.bytes, .port = ip6.port, .flow = ip6.flow } },
    };
}

/// Inverse projection. `null` for `.unspecified` — the loop treats
/// that as "no usable destination" and skips the send. Library
/// equivalent: `quic.transport.udp_server.pathAddressToIpAddress`.
pub fn pathAddressToIpAddress(addr: quic.Address) ?std.Io.net.IpAddress {
    return switch (addr) {
        .unspecified => null,
        .ipv4 => |v| .{ .ip4 = .{ .bytes = v.addr, .port = v.port } },
        .ipv6 => |v| .{ .ip6 = .{ .bytes = v.addr, .port = v.port, .flow = v.flow } },
    };
}

// -- L2: pumps (pure quic, transport injected) --------------------------

/// Where a pump hands finished datagrams. House-style opaque-ctx +
/// fn-pointer, matching `transport.RunUdpOptions.on_iteration` and
/// `Server.Config.on_connection_will_close`. Injecting the transport
/// is what lets the same pump code be driven by a UDP socket or by
/// another pump's `ingest` (see the in-memory test at the bottom).
pub const DatagramSink = struct {
    ctx: ?*anyopaque = null,
    send: *const fn (ctx: ?*anyopaque, dst: quic.Address, bytes: []const u8) anyerror!void,
};

/// Max concurrently-tracked connections in `ServerApp`'s state pool.
/// A fixed pool rather than an allocator keeps the example's subject
/// on the loop; the `Slot.user_data` lifecycle — the part a foreign
/// loop must not get wrong — is identical either way. This is a
/// *demo* cap, not a capacity mechanism:
/// `Server.Config.max_concurrent_connections` (1000 by default) is
/// the real one, and it drops excess Initials before any TLS or
/// `Connection` state exists. See the `.handshake_established` arm in
/// `ServerPump.service` for what happens when the two disagree.
pub const max_tracked_connections: usize = 2;

/// Max concurrently-tracked peer bidi streams per connection. Must be
/// at least the `initial_max_streams_bidi` we advertise, or a peer can
/// legally open a stream this example silently never echoes — which on
/// the wire looks like a server that hung. Pinned below.
pub const max_tracked_streams: usize = 16;

comptime {
    std.debug.assert(max_tracked_streams >= common.transportParams().initial_max_streams_bidi);
}

/// Bytes of one peer stream staged per echo pass. Deliberately small:
/// a correct echo has to survive a peer stream far larger than one
/// chunk, and a small chunk is what makes the tests below actually
/// walk that path.
const echo_chunk_bytes: usize = 1024;

/// Outbound QUIC datagram scratch, and the read buffer for inbound
/// RFC 9221 DATAGRAM frames. Must be at least the
/// `max_datagram_frame_size` we advertise (1200): `receiveDatagram`
/// drops the payload from the queue whether or not it fit, so a short
/// buffer silently truncates.
const max_quic_datagram_bytes: usize = 2048;

comptime {
    std.debug.assert(max_quic_datagram_bytes >= common.transportParams().max_datagram_frame_size);
}

/// Inbound *socket* scratch. A single UDP datagram can be 64 KiB, and
/// a short buffer does not error: the kernel truncates, `feed` then
/// fails the AEAD, and the whole thing reads as packet loss. This is
/// why `runUdpServer` defaults to the same value
/// (`udp_server.default_rx_buffer_bytes`). Separate from
/// `max_quic_datagram_bytes` on purpose — what a peer *may* send you
/// and what QUIC *should* send are different numbers.
const socket_rx_bytes: usize = 64 * 1024;

/// Where the server hands echoed stream bytes. Same opaque-ctx +
/// fn-pointer shape as `DatagramSink`, for the same reason: it makes
/// the short-write path testable. `streamWrite` short-writes **by
/// design** (it clamps to the stream's remaining send-buffer room),
/// and that path only triggers under real backpressure, which an
/// in-process echo demo never generates on its own.
pub const StreamWriter = struct {
    ctx: ?*anyopaque = null,
    write: *const fn (ctx: ?*anyopaque, id: u64, data: []const u8) anyerror!usize,
};

/// `StreamWriter` bound to a live connection. `ctx` is the
/// `*Connection` itself, which is already pointer-stable.
fn connectionStreamWriter(conn: *quic.Connection) StreamWriter {
    return .{ .ctx = conn, .write = connectionStreamWrite };
}

fn connectionStreamWrite(ctx: ?*anyopaque, id: u64, data: []const u8) anyerror!usize {
    const conn: *quic.Connection = @ptrCast(@alignCast(ctx.?));
    return conn.streamWrite(id, data);
}

/// One peer bidi stream mid-echo, plus the bytes the connection has
/// not accepted yet.
pub const StreamEcho = struct {
    id: u64 = 0,
    active: bool = false,
    /// Bytes read from the peer and staged for the write-back.
    /// `buf[off..len]` is what still owes a `streamWrite`.
    buf: [echo_chunk_bytes]u8 = undefined,
    off: usize = 0,
    len: usize = 0,
    // Note what this struct deliberately does NOT carry: a `fin_seen`
    // latch. `StreamReadResult.fin` only says the FIN *frame* arrived,
    // which is true long before the stream is drained and can even be
    // true while a chunk below the read offset is still in flight, so
    // latching it here would only tempt a reader to end the stream on
    // it. `echoStream` asks `Connection.streamRecvState` instead.

    /// Hand the staged bytes to `writer`, keeping whatever it refuses.
    /// Returns false when the write short-wrote: that is the
    /// documented backpressure signal (`Connection.streamWrite` clamps
    /// to `max_buffered -| buffered` and returns the accepted count),
    /// *not* an error, and definitely not something to assert on. The
    /// remainder stays staged and is retried on a later pass.
    pub fn flush(self: *StreamEcho, writer: StreamWriter) !bool {
        while (self.off < self.len) {
            const accepted = try writer.write(writer.ctx, self.id, self.buf[self.off..self.len]);
            if (accepted == 0) return false;
            self.off += accepted;
        }
        self.off = 0;
        self.len = 0;
        return true;
    }
};

/// What one echo pass over a stream achieved.
pub const EchoOutcome = enum {
    /// Still work to do later: the peer's recv half is not terminal
    /// yet (more bytes coming, or a gap below a FIN that already
    /// arrived), or our send buffer is full and holds a staged
    /// remainder.
    pending,
    /// The peer's recv half went terminal, everything it sent was
    /// echoed, and our half is FIN'd.
    echoed,
    /// The stream is gone (peer RESET, then the stream GC reaped it).
    abandoned,
};

/// Per-connection application state, handed out of `ServerApp`'s pool
/// on the first event from a connection, hung off `Slot.user_data`,
/// and returned to the pool in `ServerApp.onConnectionWillClose`.
/// quic never reads or frees `user_data`; the will-close hook —
/// which `Server.reap` invokes while the slot is still fully valid —
/// is the last safe place to release whatever it points at.
pub const ConnState = struct {
    in_use: bool = false,
    streams: [max_tracked_streams]StreamEcho = @splat(.{}),
    streams_echoed: u32 = 0,
    datagrams_echoed: u32 = 0,

    /// Start tracking a peer-opened bidi stream. False means the
    /// tracker is full, which the `comptime` assert above makes
    /// unreachable for a peer that respects our advertised
    /// `initial_max_streams_bidi`.
    fn track(self: *ConnState, id: u64) bool {
        for (&self.streams) |*e| {
            if (e.active) continue;
            e.* = .{ .id = id, .active = true };
            return true;
        }
        return false;
    }
};

/// The server's whole application: echo every peer bidi stream and
/// every RFC 9221 DATAGRAM. Threaded into `Server.Config` as the
/// `on_connection_will_close` context and into `ServerPump` as the
/// per-slot state source.
pub const ServerApp = struct {
    pool: [max_tracked_connections]ConnState = @splat(.{}),
    /// Cumulative counters, so the reactor can assert progress after
    /// the slots themselves are gone.
    streams_echoed: u32 = 0,
    datagrams_echoed: u32 = 0,
    /// Bumped when the pool is exhausted. Non-zero means the demo cap
    /// was hit, not that anything is broken.
    states_refused: u32 = 0,

    /// `Server.Config.on_connection_will_close` — runs inside `reap`
    /// for each `.closed` slot while `slot.conn` / `slot.user_data`
    /// are still valid. Release per-connection state here and nowhere
    /// else.
    pub fn onConnectionWillClose(ctx: ?*anyopaque, slot: *quic.Server.Slot) void {
        const self: *ServerApp = @ptrCast(@alignCast(ctx.?));
        const state = stateOf(slot) orelse return;
        self.streams_echoed += state.streams_echoed;
        self.datagrams_echoed += state.datagrams_echoed;
        state.* = .{};
        slot.user_data = null;
    }

    /// Number of pool entries currently attached to a live slot.
    /// The reactor asserts this returns to 0 after teardown, which is
    /// the real test of the `user_data` lifecycle.
    pub fn liveStates(self: *const ServerApp) usize {
        var n: usize = 0;
        for (self.pool) |entry| {
            if (entry.in_use) n += 1;
        }
        return n;
    }

    fn ensureState(self: *ServerApp, slot: *quic.Server.Slot) ?*ConnState {
        if (stateOf(slot)) |state| return state;
        for (&self.pool) |*entry| {
            if (entry.in_use) continue;
            entry.* = .{ .in_use = true };
            slot.user_data = entry;
            return entry;
        }
        self.states_refused += 1;
        return null;
    }

    fn stateOf(slot: *quic.Server.Slot) ?*ConnState {
        const ptr = slot.user_data orelse return null;
        return @ptrCast(@alignCast(ptr));
    }
};

/// One iteration of the server side of the raw connection cycle,
/// with the transport injected. Mirrors `runUdpServer`'s body
/// (`src/transport/udp_server.zig`) step for step, minus the socket.
pub const ServerPump = struct {
    server: *quic.Server,
    app: *ServerApp,
    sink: DatagramSink,
    /// Outbound scratch. `pollDatagram` writes one datagram per call
    /// into this; size it to your PMTU ceiling.
    tx: []u8,
    iteration: u32 = 0,
    /// `runUdpServer`'s default. `reap` is what invokes
    /// `Config.on_connection_will_close`, so this is also how often
    /// application state gets released.
    reap_every_n_iterations: u32 = 64,
    /// `now_us` of the most recent `service` call, i.e. the instant
    /// through which the outbox is known empty. The reactor asserts
    /// this equals the `now_us` it is about to park on — see
    /// `PosixPollReactor.run`.
    drained_through_us: ?u64 = null,

    /// Ingest one datagram and flush any Version Negotiation / Retry
    /// it queued. `bytes` MUST be mutable — header unprotection
    /// rewrites it in place, which is why every quic ingest path
    /// takes `[]u8` and not `[]const u8`.
    ///
    /// The stateless drain is a separate step because VN and Retry
    /// have no slot: the per-slot outbox walk in `service` would
    /// never reach them.
    pub fn ingest(
        self: *ServerPump,
        bytes: []u8,
        from: quic.Address,
        now_us: u64,
    ) !quic.Server.FeedOutcome {
        const outcome = try self.server.feed(bytes, from, now_us);
        while (self.server.drainStatelessResponse()) |response| {
            // Best-effort, exactly as `runUdpServer` treats them: the
            // peer retries on its next Initial.
            self.sink.send(self.sink.ctx, response.dst, response.slice()) catch {};
        }
        return outcome;
    }

    /// Events, application echo, `tick`, per-slot outbox drain, and a
    /// periodic `reap`. Per-connection failures are swallowed exactly
    /// as `runUdpServer` swallows them: a malformed peer must not tear
    /// down the whole server.
    ///
    /// Note the application step runs before `tick`, not after. That
    /// is not cosmetic: `tick` runs the stream GC, and a bidi stream
    /// counts as reclaimable once every byte plus the FIN has
    /// *arrived* — drained or not (`Stream.recvFullyTerminated`
    /// accepts `data_recvd`). Read first, tick second, or the GC can
    /// reap data the application never saw.
    ///
    /// **Post-condition: every slot's outbox is empty on return.**
    /// That is what makes it safe for the caller to park afterwards,
    /// and it is why the drain comes *last* — after `tick`, not before
    /// it as in `runUdpServer`. The packaged loop can get away with
    /// drain-then-tick because its `receive_timeout` bounds how long a
    /// tick-queued PTO retransmit waits; a foreign loop that parks on
    /// `nextTimerDeadline` may have no other reason to wake, so
    /// anything `tick` queues has to be drained before the park or it
    /// sits there for a whole poll interval.
    pub fn service(self: *ServerPump, now_us: u64) !void {
        // Events first — they are what establishes per-connection
        // state — then the application work.
        for (self.server.iterator()) |slot| {
            while (slot.conn.pollEvent()) |event| switch (event) {
                .handshake_established => {
                    if (self.app.ensureState(slot) == null) {
                        // Refusing application state must refuse the
                        // *connection*. Accepting the handshake and
                        // then never draining the peer's streams
                        // leaves it waiting out its idle timeout
                        // against a server that looks healthy — a
                        // black hole is worse than a rejection.
                        // RFC 9000 §20.1 CONNECTION_REFUSED (0x02) is
                        // the transport code for precisely this, and
                        // `is_transport = true` puts it in the
                        // transport error space.
                        //
                        // Note this arm only exists because THIS
                        // example's pool
                        // (`max_tracked_connections`) is smaller than
                        // the server's slot table. The mechanism a
                        // real deployment uses is
                        // `Server.Config.max_concurrent_connections`,
                        // which drops excess Initials before any TLS
                        // or `Connection` state is allocated.
                        slot.conn.close(true, 0x02, "server application state exhausted");
                    }
                },
                .stream_opened => |info| {
                    // Only bidi streams can be echoed; uni streams
                    // have no return direction.
                    if (!info.bidi) continue;
                    const state = ServerApp.stateOf(slot) orelse continue;
                    if (!state.track(info.stream_id)) {
                        // Unreachable for a conforming peer (see the
                        // comptime assert on `max_tracked_streams`),
                        // but silence here would be another black
                        // hole. RFC 9000 §20.1 STREAM_LIMIT_ERROR.
                        slot.conn.close(true, 0x04, "stream tracker exhausted");
                    }
                },
                // The mandatory catch-all arm: quic may add event
                // variants in a minor release. See
                // `docs/API_STABILITY.md`.
                else => {},
            };

            const state = ServerApp.stateOf(slot) orelse continue;
            echoStreams(slot, state) catch {};
            echoDatagrams(slot, state) catch {};
        }

        // Clock, then outbox. `pollDatagram` (not `Server.poll`) so
        // VN/Retry peers, migration, and multipath all see the right
        // destination address.
        for (self.server.iterator()) |slot| {
            // Terminal `.closed` slots have nothing to do; closing /
            // draining ones stay in the loop so their deadlines fire
            // and the closing-state CONNECTION_CLOSE retransmits can
            // still emit (RFC 9000 §10.2.1 ¶3).
            if (slot.conn.closeState() == .closed) continue;
            slot.conn.tick(now_us) catch {};
            self.drainSlot(slot, now_us) catch {};
        }

        self.iteration +%= 1;
        if (self.iteration % self.reap_every_n_iterations == 0) {
            _ = self.server.reap();
        }
        self.drained_through_us = now_us;
    }

    /// Earliest pending timer across every live slot, or null when no
    /// slot has one armed. This is what a foreign loop parks on
    /// instead of a fixed tick.
    pub fn nextDeadline(self: *const ServerPump, now_us: u64) ?quic.TimerDeadline {
        return self.server.nextTimerDeadline(now_us);
    }

    fn drainSlot(self: *ServerPump, slot: *quic.Server.Slot, now_us: u64) !void {
        while (try slot.conn.pollDatagram(self.tx, now_us)) |out| {
            // `out.to` wins (migration / multipath / VN peers); the
            // slot's last-seen peer address is the fallback. Neither
            // means there is nowhere to send, so skip.
            const dst = out.to orelse slot.peer_addr orelse continue;
            try self.sink.send(self.sink.ctx, dst, self.tx[0..out.len]);
        }
    }
};

/// Pump every tracked bidi stream one pass.
fn echoStreams(slot: *quic.Server.Slot, state: *ConnState) !void {
    for (&state.streams) |*e| {
        if (!e.active) continue;
        switch (try echoStream(slot.conn, e)) {
            .pending => {},
            .echoed => {
                state.streams_echoed += 1;
                e.* = .{};
            },
            .abandoned => e.* = .{},
        }
    }
}

/// Echo one bidi stream: flush any staged remainder, then read and
/// write back until nothing more is readable, then FIN our half once
/// the peer's recv half is *terminal*.
///
/// The three easy ways to get this wrong, all of which silently
/// corrupt the stream rather than erroring:
///
///  1. Treating `StreamReadResult.fin` as "all data read". It means
///     the FIN frame arrived. A peer that sends 5000 bytes + FIN in
///     one flight makes the very first `streamReadFin` return
///     `n = echo_chunk_bytes, fin = true` — finishing there throws
///     away everything past the first chunk. Keep reading until a read
///     returns zero bytes.
///  2. Treating a zero-byte read as "the peer is done". It means
///     nothing is readable *at this instant*, and one reason for that
///     is a chunk below the read offset still being in flight. Under
///     reordering, "empty read + FIN seen" is exactly the state of a
///     stream with a hole in it, so the pair is not an end-of-stream
///     test either. `streamRecvState(id).terminal` is: it is true only
///     once every byte arrived AND was read, or the peer RESET the
///     stream. See the reordering regression test in Group C.
///  3. Asserting `streamWrite` accepted everything. It short-writes by
///     design under send-buffer pressure; see `StreamEcho.flush`.
fn echoStream(conn: *quic.Connection, e: *StreamEcho) !EchoOutcome {
    const writer = connectionStreamWriter(conn);

    // Whatever the connection refused last pass goes first, so bytes
    // stay in order.
    if (!try e.flush(writer)) return .pending;

    while (true) {
        // `streamRead`, not `streamReadFin`: this loop has no use for
        // the FIN flag, because it is not what ends the stream.
        const n = conn.streamRead(e.id, &e.buf) catch |err| switch (err) {
            // The stream left the live table. For an echo server that
            // means the peer RESET it and the GC reaped it: our send
            // half cannot be terminal yet (we only `streamFinish`
            // below), so a clean FIN could not have triggered the reap.
            error.StreamNotFound => return .abandoned,
            else => return err,
        };
        e.off = 0;
        e.len = n;
        if (!try e.flush(writer)) return .pending;
        // Nothing readable *right now* — not "nothing more is coming".
        // See point 2 of the doc comment above.
        if (n == 0) break;
    }

    // The recv half decides, not the read loop. `null` means the stream
    // already left the live table (see the `StreamNotFound` arm above).
    const st = conn.streamRecvState(e.id) orelse return .abandoned;
    if (!st.terminal) return .pending; // more to come, or a gap below the FIN
    if (st.reset_seen) return .abandoned; // peer aborted; no clean EOF to mirror
    conn.streamFinish(e.id) catch |err| switch (err) {
        error.StreamNotFound => return .abandoned,
        else => return err,
    };
    return .echoed;
}

/// Echo every queued inbound DATAGRAM verbatim.
fn echoDatagrams(slot: *quic.Server.Slot, state: *ConnState) !void {
    // Sized to the advertised `max_datagram_frame_size`, not to the
    // stream chunk: `receiveDatagram` pops the payload whether or not
    // it fit, so a short buffer loses the tail with no error.
    var buf: [max_quic_datagram_bytes]u8 = undefined;
    while (slot.conn.receiveDatagram(&buf)) |n| {
        slot.conn.sendDatagram(buf[0..n]) catch |err| switch (err) {
            // Peer didn't advertise datagram support, or shrank the
            // limit below what it just sent — drop, don't kill the
            // connection.
            error.DatagramUnavailable, error.DatagramTooLarge => continue,
            else => return err,
        };
        state.datagrams_echoed += 1;
    }
}

/// The client's whole application: a five-stage state machine
/// advanced once per `ClientPump.service` call.
pub const ClientFlow = struct {
    stage: Stage = .awaiting_handshake,
    stream_id: u64 = 0,
    /// Payload bytes `streamWrite` has *accepted* so far — which is
    /// not the same as bytes offered, because it short-writes under
    /// send-buffer pressure.
    sent: usize = 0,
    /// Echo bytes accumulated so far (a stream can deliver in chunks).
    reply_len: usize = 0,
    /// The echo's FIN frame has arrived. Latched separately from
    /// `reply_len` because FIN arrival and stream drain are different
    /// events, and because the stream GC can reap the recv half once
    /// it goes terminal.
    fin_seen: bool = false,
    /// The stream has left `Connection`'s live table. Latched for the
    /// same reason `fin_seen` is: `Stream.recvFullyTerminated` counts
    /// `data_recvd` — every byte plus the FIN *arrived* — as terminal
    /// whether or not the application has drained it, so once our own
    /// send half is terminal too, the GC inside `tick` may reap a bidi
    /// stream whose echo is still sitting in the recv buffer. Reading
    /// before ticking (which `service` does) is what keeps that safe;
    /// latching this is what keeps it *detectable* if it ever isn't.
    stream_gone: bool = false,
    datagram_verified: bool = false,

    pub const Stage = enum {
        awaiting_handshake,
        sending_payload,
        awaiting_stream_echo,
        awaiting_datagram_echo,
        done,
    };
};

/// One iteration of the client side of the raw connection cycle.
/// Mirror of `ServerPump` with the two documented deltas: `bootstrap`
/// (a `Client` needs one `advance()` before its first iteration or the
/// ClientHello never reaches the wire) and a single-path destination
/// fallback (`out.to orelse target`).
pub const ClientPump = struct {
    client: *quic.Client,
    sink: DatagramSink,
    tx: []u8,
    /// Where datagrams go when the connection doesn't name a path.
    target: quic.Address,
    /// Bytes to write on the bidi stream.
    payload: []const u8 = stream_message,
    /// Accumulator for the echo, exactly `payload.len` bytes.
    /// Caller-owned so a test can drive a payload larger than any
    /// fixed buffer this file would otherwise pick.
    reply: []u8,
    flow: ClientFlow = .{},
    /// See `ServerPump.drained_through_us`.
    drained_through_us: ?u64 = null,

    /// `Client.connect` deliberately does *not* call `advance` so
    /// 0-RTT-bound STREAM data can be staged first. Call this once,
    /// before the first loop iteration, or nothing is ever sent.
    ///
    /// Note what this does *not* do: send anything. `advance` only
    /// queues the ClientHello into the outbox — and at that moment the
    /// connection has no armed timer at all (nothing ack-eliciting has
    /// been sent, so there is no PTO; the peer's transport parameters
    /// are unknown, so there is no idle timer). A loop that parks
    /// before its first drain therefore has *nothing* to wake it but
    /// its own idle cap. Drain before you park.
    pub fn bootstrap(self: *ClientPump) !void {
        if (self.reply.len != self.payload.len) return error.ForeignLoopReplyBufferMismatch;
        try self.client.conn.advance();
    }

    /// Feed one inbound datagram. `bytes` must be mutable for the
    /// same in-place header-unprotection reason as `ServerPump.ingest`.
    pub fn ingest(self: *ClientPump, bytes: []u8, now_us: u64) !void {
        try self.client.conn.handle(bytes, null, now_us);
    }

    /// Events, application state machine, `tick`, outbox drain.
    ///
    /// The application step precedes `tick` for the same
    /// stream-GC reason as `ServerPump.service`, and the outbox drain
    /// follows it.
    ///
    /// **Post-condition: the outbox is empty on return** — same
    /// contract, and same drain-last ordering, as
    /// `ServerPump.service`. That is the single invariant a foreign
    /// loop has to hold: drain after every state change and
    /// immediately before you sleep.
    pub fn service(self: *ClientPump, now_us: u64) !void {
        while (self.client.conn.pollEvent()) |event| switch (event) {
            .handshake_established => {
                const stream = try self.client.conn.openNextBidi();
                self.flow.stream_id = stream.id;
                self.flow.stage = .sending_payload;
            },
            else => {},
        };

        try self.advanceApp();

        try self.client.conn.tick(now_us);
        while (try self.client.conn.pollDatagram(self.tx, now_us)) |out| {
            const dst = out.to orelse self.target;
            try self.sink.send(self.sink.ctx, dst, self.tx[0..out.len]);
        }
        self.drained_through_us = now_us;
    }

    /// One step of the application state machine. Never sends: every
    /// exit path falls back into `service`'s drain.
    fn advanceApp(self: *ClientPump) !void {
        const conn = self.client.conn;
        switch (self.flow.stage) {
            .awaiting_handshake, .done => {},
            .sending_payload => {
                // `streamWrite` clamps to the stream's remaining
                // send-buffer room and returns what it accepted, so a
                // short write is backpressure to resume from, not an
                // error and certainly not an assertion.
                while (self.flow.sent < self.payload.len) {
                    const accepted = try conn.streamWrite(
                        self.flow.stream_id,
                        self.payload[self.flow.sent..],
                    );
                    if (accepted == 0) return; // full; resume next pass
                    self.flow.sent += accepted;
                }
                try conn.streamFinish(self.flow.stream_id);
                self.flow.stage = .awaiting_stream_echo;
            },
            .awaiting_stream_echo => {
                // Drain whatever is buffered, however many passes that
                // takes. `fin` says the FIN frame arrived, not that the
                // stream is drained: an out-of-order flight can set it
                // with a gap still unfilled, and a payload larger than
                // one read needs several reads.
                while (self.flow.reply_len < self.reply.len) {
                    const res = conn.streamReadFin(
                        self.flow.stream_id,
                        self.reply[self.flow.reply_len..],
                    ) catch |err| switch (err) {
                        error.StreamNotFound => {
                            self.flow.stream_gone = true;
                            break;
                        },
                        else => return err,
                    };
                    self.flow.reply_len += res.n;
                    if (res.fin) self.flow.fin_seen = true;
                    if (res.n == 0) break;
                }

                // Re-read end-of-stream from the recv half rather than
                // trusting that some read happened to observe `fin`.
                // Two ways that read can miss it: the final bytes and
                // the FIN can fill `reply` exactly on a pass where the
                // FIN frame had not landed yet (after which the loop
                // above has no room left to read again), and the GC can
                // reap the stream first — see `ClientFlow.stream_gone`.
                // `null` here means reaped, because we opened it.
                if (conn.streamRecvState(self.flow.stream_id)) |st| {
                    if (st.fin_seen) self.flow.fin_seen = true;
                } else {
                    self.flow.stream_gone = true;
                }

                if (self.flow.reply_len < self.reply.len) {
                    // Bytes missing and no stream left to read them
                    // from: that is a real failure, not "wait longer".
                    if (self.flow.stream_gone) return error.ForeignLoopEchoTruncated;
                    return; // still in flight
                }
                // Every expected byte is back. A clean end is either
                // the FIN we observed or the GC having reaped a stream
                // it only reaps once terminal.
                if (!self.flow.fin_seen and !self.flow.stream_gone) return;
                if (!std.mem.eql(u8, self.reply, self.payload)) {
                    return error.ForeignLoopEchoMismatch;
                }
                try conn.sendDatagram(datagram_message);
                self.flow.stage = .awaiting_datagram_echo;
            },
            .awaiting_datagram_echo => {
                var buf: [max_quic_datagram_bytes]u8 = undefined;
                const n = conn.receiveDatagram(&buf) orelse return;
                if (!std.mem.eql(u8, buf[0..n], datagram_message)) {
                    return error.ForeignLoopEchoMismatch;
                }
                self.flow.datagram_verified = true;
                self.requestClose();
            },
        }
    }

    /// Clean application close (`is_transport = false`). Safe to call
    /// from the loop thread only — including from work the loop
    /// drained off `WorkQueue`.
    pub fn requestClose(self: *ClientPump) void {
        self.client.conn.close(false, 0, "foreign loop done");
        self.flow.stage = .done;
    }

    pub fn nextDeadline(self: *const ClientPump, now_us: u64) ?quic.TimerDeadline {
        return self.client.conn.nextTimerDeadline(now_us);
    }

    /// True once the round-trip finished (or the peer/transport closed
    /// the connection under us). `service` drains the outbox after the
    /// application step, so the CONNECTION_CLOSE queued by
    /// `requestClose` has already been handed to the sink by the time
    /// this first reports true.
    pub fn done(self: *const ClientPump) bool {
        return self.flow.stage == .done or self.client.conn.isClosed();
    }

    /// The round-trip actually happened, as opposed to the loop
    /// exiting because the connection died.
    pub fn succeeded(self: *const ClientPump) bool {
        return self.flow.datagram_verified;
    }
};

// -- L3: the wake channel and the off-thread work queue ---------------------

/// Fixed queue depth. Bounded on purpose: a runaway producer must not
/// be able to pin unbounded memory in the loop's address space.
pub const max_queued_work: usize = 16;

/// One unit of work handed from an application thread to the loop
/// thread. Deliberately tiny and copyable — anything that needs to
/// touch a `Connection` becomes a `Work` item, because the loop
/// thread is the only thread allowed to make that call.
pub const Work = struct {
    kind: Kind,
    /// Producer-assigned sequence number. quic never sees it; it
    /// exists so the tests (and a human reading the log) can observe
    /// that FIFO order survived the hand-off.
    seq: u64 = 0,

    pub const Kind = enum {
        /// Print a progress line from the loop thread.
        report_stats,
        /// Ask the loop to close the client connection cleanly. This
        /// is the shape a control plane uses: it never calls
        /// `Connection.close` itself.
        request_close,
    };
};

/// Mutex-guarded, fixed-capacity work queue. `push` is the only
/// method other threads may call; `drainInto` is loop-thread-only.
///
/// Pairing this with `Waker` is the whole cross-thread story: enqueue
/// under the mutex, then poke the wake fd. Wakes coalesce — N `wake()`
/// calls may produce fewer than N readable events — so the loop must
/// treat a wake as "check the queue", never "one item is waiting".
pub const WorkQueue = struct {
    /// `std.Io.Mutex` needs an `Io` to lock, so the queue carries the
    /// one the loop was built with rather than making every caller
    /// pass it. `lockUncancelable` keeps `push` / `drainInto`
    /// error-free: a producer thread has nowhere useful to propagate a
    /// cancellation to, and the critical section is a memcpy.
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    items: [max_queued_work]Work = undefined,
    len: usize = 0,

    /// Any thread. Returns false when the queue is full; the caller
    /// decides whether to drop, retry, or apply backpressure.
    pub fn push(self: *WorkQueue, w: Work) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.len == max_queued_work) return false;
        self.items[self.len] = w;
        self.len += 1;
        return true;
    }

    /// Loop thread only. Copies up to `out.len` items out in FIFO
    /// order and empties the queue, so the lock is held for a memcpy
    /// rather than for the duration of the work.
    pub fn drainInto(self: *WorkQueue, out: []Work) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const n = @min(out.len, self.len);
        @memcpy(out[0..n], self.items[0..n]);
        // Anything that didn't fit shifts down; with
        // `out.len >= max_queued_work` (the normal case) this is a
        // no-op.
        const remaining = self.len - n;
        if (remaining > 0) {
            std.mem.copyForwards(Work, self.items[0..remaining], self.items[n..self.len]);
        }
        self.len = remaining;
        return n;
    }
};

/// Whether this target can host the poll reactor below.
///
/// `std.posix.poll` opens with `if (native_os == .windows)
/// @compileError("use std.Io instead")`, so merely *analysing* it on
/// Windows fails the build — a runtime check is not enough. Worse,
/// `std.posix.pollfd` and `std.posix.POLL` resolve to
/// `ws2_32.pollfd` / `ws2_32.POLL`, neither of which this toolchain
/// defines, so even naming the types is a Windows compile error.
/// Everything poll-shaped in this file therefore goes through the
/// comptime-selected aliases below, and L1/L2 above — which is what
/// the portable tests exercise — never touch `std.posix` at all.
pub const poll_reactor_supported = builtin.os.tag != .windows;

/// `poll(2)`'s per-fd descriptor, or a layout-compatible placeholder
/// on targets without one, so signatures mentioning it still compile
/// everywhere.
pub const PollFd = if (poll_reactor_supported) std.posix.pollfd else struct {
    fd: std.Io.net.Socket.Handle,
    events: i16,
    revents: i16,
};

/// `POLLIN`, or 0 where poll does not exist (the reactor never runs
/// there, so the mask value is inert).
const poll_in: i16 = if (poll_reactor_supported) std.posix.POLL.IN else 0;
/// `POLLERR | POLLHUP | POLLNVAL`. Always check these: a silent
/// `NVAL` on a closed fd turns the loop into an infinite spin, since
/// `poll` reports the fd ready forever and `receive` never has data.
const poll_failure_mask: i16 = if (poll_reactor_supported)
    std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL
else
    0;

/// The one place `std.posix.poll` is named. The `if` condition is
/// comptime-known, so the untaken branch is never analysed and the
/// `@compileError` in `std.posix.poll` never fires on Windows.
pub fn pollWait(fds: []PollFd, timeout_ms: i32) !usize {
    if (comptime poll_reactor_supported) {
        return std.posix.poll(fds, timeout_ms);
    }
    return error.ForeignLoopUnsupportedOnThisTarget;
}

fn isReadable(fd: PollFd) bool {
    return (fd.revents & poll_in) != 0;
}

fn hasFailed(fd: PollFd) bool {
    return (fd.revents & poll_failure_mask) != 0;
}

/// Cross-thread nudge for a loop parked in `poll`: a UDP socket bound
/// to loopback that sends a single byte to itself.
///
/// The classic self-pipe was the first choice and does not work here.
/// This toolchain's `std.posix` has no `pipe`/`pipe2` at all, and no
/// `write` or `close` either (it ships `read`, but the rest would have
/// to go through `std.posix.system.*` raw syscalls with hand-rolled
/// errno handling); `std.Io.Threaded.pipe2` exists but is
/// backend-specific, so building on it would bind this example to one
/// `std.Io` implementation. A datagram socket gets the same pollable
/// fd through the portable `std.Io.net` API, keeps
/// `[wake_fd, quic_fd...]` architecturally identical, and behaves the
/// same on Linux and macOS.
///
/// `wake()` is the ONLY method any thread other than the loop thread
/// may call on any type in this file. `Connection` has no internal
/// locking: a producer pushes onto `WorkQueue` under its mutex and
/// calls `wake()`; the loop thread drains the queue and is the only
/// thing that ever touches `Connection`.
pub const Waker = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    /// `sock.address` with the ephemeral port already resolved by the
    /// bind, which is what makes the send-to-self trick work without
    /// a second socket.
    addr: std.Io.net.IpAddress,

    pub fn bind(io: std.Io) !Waker {
        const sock = try bindLoopbackUdp(io);
        return .{ .io = io, .sock = sock, .addr = sock.address };
    }

    pub fn deinit(self: Waker) void {
        self.sock.close(self.io);
    }

    /// Any thread. Errors are swallowed: a failed wake degrades the
    /// loop to its idle cap, it does not corrupt anything.
    pub fn wake(self: Waker) void {
        const byte = [_]u8{0};
        self.sock.send(self.io, &self.addr, &byte) catch {};
    }

    /// Loop thread, only when `poll` reported the wake fd readable.
    /// Reads exactly one datagram: wakes coalesce, so draining "until
    /// empty" would be a pointless syscall loop — the queue is the
    /// source of truth, not the byte count.
    pub fn drain(self: Waker, scratch: []u8) void {
        _ = self.sock.receive(self.io, scratch) catch {};
    }
};

/// Bind a UDP socket to an ephemeral loopback port. `sock.address`
/// carries the resolved port back out.
pub fn bindLoopbackUdp(io: std.Io) !std.Io.net.Socket {
    const addr = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    // Demo posture: no `applyServerTuning` / SO_RCVBUF bump, so the
    // example runs unprivileged everywhere. Production servers under
    // a foreign loop should replicate `runUdpServer`'s 4 MiB tuning
    // (`src/transport/socket_opts.zig`) — kernel defaults are ~200 KiB
    // on Linux and ~9 KiB on macOS, and the resulting drops look like
    // loss to QUIC's congestion controller.
    return std.Io.net.IpAddress.bind(&addr, io, .{ .mode = .dgram, .protocol = .udp });
}

/// A `DatagramSink` backed by one UDP socket.
const SocketSink = struct {
    io: std.Io,
    sock: *const std.Io.net.Socket,

    fn sendFn(ctx: ?*anyopaque, dst: quic.Address, bytes: []const u8) anyerror!void {
        const self: *SocketSink = @ptrCast(@alignCast(ctx.?));
        const ip = pathAddressToIpAddress(dst) orelse return;
        try self.sock.send(self.io, &ip, bytes);
    }

    fn sink(self: *SocketSink) DatagramSink {
        return .{ .ctx = self, .send = SocketSink.sendFn };
    }
};

/// The foreign event loop itself: one `poll` set covering the wake fd,
/// the server socket, and the client socket; one monotonic clock; and
/// the two pumps from L2.
///
/// A real embedder's reactor drives one role, not both — the pairing
/// here just keeps the example to a single process.
pub const PosixPollReactor = struct {
    io: std.Io,
    /// Monotonic origin. Every `now_us` in this file is an offset from
    /// here, and it is the only clock the connections ever see.
    start: std.Io.Timestamp,
    waker: Waker,
    queue: *WorkQueue,
    server_sock: *const std.Io.net.Socket,
    client_sock: *const std.Io.net.Socket,
    server: ServerPump,
    client: ClientPump,
    /// Hard wall-clock budget, as an offset from `start`. Folded into
    /// the poll timeout like any other deadline so the loop can block
    /// indefinitely on QUIC's own timers without risking a hang.
    budget_us: u64,
    idle_cap_ms: i32 = default_idle_cap_ms,
    /// Set true to have progress printed from the loop thread.
    verbose: bool = false,
    iterations: u32 = 0,
    work_items_handled: u32 = 0,

    /// Socket sinks, outbound scratch, and the client's echo
    /// accumulator live *inside* the reactor so the pumps'
    /// `DatagramSink.ctx`, `tx`, and `reply` slices have a stable home
    /// without an allocator. Populated by `bindSelf`.
    server_sink: SocketSink = undefined,
    client_sink: SocketSink = undefined,
    server_tx: [max_quic_datagram_bytes]u8 = undefined,
    client_tx: [max_quic_datagram_bytes]u8 = undefined,
    client_reply: [stream_message.len]u8 = undefined,

    pub const Options = struct {
        io: std.Io,
        server: *quic.Server,
        app: *ServerApp,
        client: *quic.Client,
        server_sock: *const std.Io.net.Socket,
        client_sock: *const std.Io.net.Socket,
        waker: Waker,
        queue: *WorkQueue,
        /// Wall-clock give-up budget, so a stall fails fast instead of
        /// parking forever.
        budget_us: u64,
    };

    /// Construction is two-phase on purpose: the pumps point back into
    /// the reactor's own storage, so the interior pointers can only be
    /// taken once the value has reached its final address. Declare it
    /// as a local `var`, call `bindSelf`, then `run`.
    pub fn init(opts: Options) PosixPollReactor {
        return .{
            .io = opts.io,
            // Capture the monotonic origin exactly once. Every
            // `now_us` the connections ever see is an offset from here.
            .start = std.Io.Timestamp.now(opts.io, .awake),
            .waker = opts.waker,
            .queue = opts.queue,
            .server_sock = opts.server_sock,
            .client_sock = opts.client_sock,
            .server = .{
                .server = opts.server,
                .app = opts.app,
                .sink = undefined,
                .tx = undefined,
            },
            .client = .{
                .client = opts.client,
                .sink = undefined,
                .tx = undefined,
                .reply = undefined,
                .target = ipAddressToPathAddress(opts.server_sock.address),
            },
            .budget_us = opts.budget_us,
        };
    }

    /// Wire the interior pointers. Must run after the reactor lands at
    /// its final address and before `run`.
    pub fn bindSelf(self: *PosixPollReactor) void {
        self.server_sink = .{ .io = self.io, .sock = self.server_sock };
        self.client_sink = .{ .io = self.io, .sock = self.client_sock };
        self.server.sink = self.server_sink.sink();
        self.server.tx = &self.server_tx;
        self.client.sink = self.client_sink.sink();
        self.client.tx = &self.client_tx;
        self.client.reply = &self.client_reply;
    }

    /// One iteration, in the only order that is safe when the loop can
    /// park indefinitely:
    ///
    ///   1. `service` both endpoints. Each ends with an outbox drain,
    ///      so on return there are no queued bytes anywhere.
    ///   2. Compute the sleep and park.
    ///   3. Ingest whatever arrived; the next iteration's step 1 turns
    ///      it into replies.
    ///
    /// Servicing *before* the park (rather than after the ingest, which
    /// is the intuitive order and how the first draft of this file did
    /// it) is load-bearing. `client.bootstrap()` queues the ClientHello
    /// with no timer armed at all, so a loop that parks first stalls
    /// the entire handshake for a full idle-cap interval — and once
    /// running, every PTO retransmit `tick` queues would be delayed the
    /// same way.
    pub fn run(self: *PosixPollReactor) !void {
        var fds = [_]PollFd{
            .{ .fd = self.waker.sock.handle, .events = poll_in, .revents = 0 },
            .{ .fd = self.server_sock.handle, .events = poll_in, .revents = 0 },
            .{ .fd = self.client_sock.handle, .events = poll_in, .revents = 0 },
        };
        var rx: [socket_rx_bytes]u8 = undefined;
        var wake_scratch: [64]u8 = undefined;

        try self.client.bootstrap();

        while (true) {
            var now_us = monotonicNowUs(self.io, self.start);
            if (now_us >= self.budget_us) return error.ForeignLoopTimedOut;

            // 1. Drive state and drain.
            try self.server.service(now_us);
            try self.client.service(now_us);
            self.iterations +%= 1;
            if (self.client.done()) break;

            // Cheap guard on the invariant that makes the park safe.
            // If a future edit moves either `service` call below the
            // park, this fires instead of silently adding a poll
            // interval of latency to every flight.
            std.debug.assert(self.server.drained_through_us == now_us);
            std.debug.assert(self.client.drained_through_us == now_us);

            // 2. Sleep. The reactor's own budget is just another
            // deadline, so `earlier` folds it in and the QUIC-armed
            // cases keep their exact semantics.
            const budget: quic.TimerDeadline = .{ .kind = .idle, .at_us = self.budget_us };
            const deadline = earlier(
                budget,
                earlier(self.server.nextDeadline(now_us), self.client.nextDeadline(now_us)),
            );
            const timeout_ms = pollTimeoutMs(now_us, deadline, self.idle_cap_ms, true);

            const ready = try pollWait(&fds, timeout_ms);

            // Refresh the clock AFTER the blocking wait. Reusing the
            // pre-wait timestamp is the bug that makes PTO timers
            // fire a whole poll-interval late.
            now_us = monotonicNowUs(self.io, self.start);

            // 3. Ingest.
            if (ready > 0) {
                for (fds) |fd| {
                    if (hasFailed(fd)) return error.ForeignLoopPollFailed;
                }
                if (isReadable(fds[0])) {
                    self.waker.drain(&wake_scratch);
                    self.runQueuedWork();
                }
                // One datagram per readable fd per iteration — a
                // deliberately tight per-tick ingress budget (the
                // packaged loops batch up to
                // `RunUdpOptions.max_datagrams_per_iteration`), so a
                // hot ingress queue cannot starve tick-driven loss
                // detection. A batching embedder raises this and takes
                // responsibility for its own per-tick budget.
                if (isReadable(fds[1])) try self.ingestServer(&rx, now_us);
                if (isReadable(fds[2])) try self.ingestClient(&rx, now_us);
            }
        }

        // Teardown: the client queued CONNECTION_CLOSE and `service`
        // already shipped it, so keep servicing the server until its
        // slot reaches `.closed` and `reap` has run the will-close
        // hook. Same service-then-park ordering as above. This is the
        // foreign-loop equivalent of `runUdpServer`'s
        // `shutdown_grace_us` window.
        self.server.reap_every_n_iterations = 1;
        var grace: u32 = 0;
        while (grace < 64) : (grace += 1) {
            var now_us = monotonicNowUs(self.io, self.start);
            try self.server.service(now_us);
            if (self.server.server.connectionCount() == 0) break;
            // `has_wake_fd = false` here: the wake fd is out of the
            // set, so the draining slot's own deadline (or the 50 ms
            // cap) is what has to bound the park.
            const timeout_ms = pollTimeoutMs(now_us, self.server.nextDeadline(now_us), 50, false);
            const ready = try pollWait(fds[1..2], timeout_ms);
            now_us = monotonicNowUs(self.io, self.start);
            if (ready > 0 and isReadable(fds[1])) try self.ingestServer(&rx, now_us);
        }
    }

    /// Read one datagram off a socket `poll` just called readable.
    /// Returns null when there was nothing to read after all, or when
    /// the datagram is unusable.
    ///
    /// **UDP readiness is advisory, and this is the sharpest edge in a
    /// hand-rolled reactor.** Between `poll` returning and the read,
    /// the kernel can drop the datagram — a bad UDP checksum is the
    /// classic case, an `SO_RCVBUF` eviction or a second reader on a
    /// shared socket are others. The plain blocking `Socket.receive`
    /// would then park the loop inside `recvmsg` with no timeout at
    /// all, silently defeating the `budget_us` contract this reactor
    /// advertises. So: a zero-duration `receiveTimeout`, which the
    /// `Threaded` backend answers with `MSG_DONTWAIT` first and turns a
    /// spurious readiness into `error.Timeout`.
    ///
    /// `receiveTimeout` routes through `Io.operateTimeout` →
    /// `Batch.awaitConcurrent`, which an `Io` implementation without
    /// concurrency support answers with `error.ConcurrencyUnavailable`.
    /// On those we fall back to the blocking read and inherit the
    /// hazard, because a loop that can never read at all is strictly
    /// worse than one that can stall.
    fn receiveOne(
        self: *PosixPollReactor,
        sock: *const std.Io.net.Socket,
        rx: []u8,
    ) !?std.Io.net.IncomingMessage {
        const msg = sock.receiveTimeout(self.io, rx, .{
            .duration = .{ .raw = std.Io.Duration.fromMilliseconds(0), .clock = .awake },
        }) catch |err| switch (err) {
            // Readiness was advisory; nothing there after all.
            error.Timeout => return null,
            // Transient ICMP feedback from a peer that went away; the
            // socket is still fine.
            error.PortUnreachable, error.ConnectionResetByPeer => return null,
            error.ConcurrencyUnavailable => blk: {
                break :blk sock.receive(self.io, rx) catch |inner| switch (inner) {
                    error.PortUnreachable, error.ConnectionResetByPeer => return null,
                    else => return inner,
                };
            },
            else => return err,
        };
        // `rx` is 64 KiB — the largest a single UDP datagram can be —
        // so this should never fire. Check it anyway: a truncated
        // datagram fed to `feed` fails the AEAD and reads as packet
        // loss, which is a miserable thing to debug.
        if (msg.flags.trunc) return null;
        return msg;
    }

    fn ingestServer(self: *PosixPollReactor, rx: []u8, now_us: u64) !void {
        const msg = (try self.receiveOne(self.server_sock, rx)) orelse return;
        // `msg.data` aliases `rx`, so it is already the mutable slice
        // `feed` requires.
        _ = try self.server.ingest(msg.data, ipAddressToPathAddress(msg.from), now_us);
    }

    fn ingestClient(self: *PosixPollReactor, rx: []u8, now_us: u64) !void {
        const msg = (try self.receiveOne(self.client_sock, rx)) orelse return;
        self.client.ingest(msg.data, now_us) catch |err| switch (err) {
            // The three shapes `runUdpClient` treats as a terminal
            // handshake outcome rather than a loop bug. Surfaced as
            // one error here so the example fails loudly instead of
            // spinning until the budget expires.
            error.HandshakeFailed,
            error.PeerAlerted,
            error.UnsupportedCipherSuite,
            => return error.ForeignLoopHandshakeFailed,
            else => return err,
        };
    }

    fn runQueuedWork(self: *PosixPollReactor) void {
        var items: [max_queued_work]Work = undefined;
        const n = self.queue.drainInto(&items);
        for (items[0..n]) |item| switch (item.kind) {
            .report_stats => if (self.verbose) std.debug.print(
                "[foreign-loop] work #{d} from an application thread: " ++
                    "{d} iterations, {d} live connection(s)\n",
                .{ item.seq, self.iterations, self.server.server.connectionCount() },
            ),
            .request_close => self.client.requestClose(),
        };
        self.work_items_handled += @intCast(n);
    }
};

// -- main: server + client in one hand-rolled poll loop ---------------------

pub fn main(init: std.process.Init) !void {
    if (comptime poll_reactor_supported) {
        try runDemo(init);
    } else {
        // Not a build failure: `zig build examples` must still produce
        // this binary on Windows. The portable layers (`pollTimeoutMs`,
        // `earlier`, `ServerPump`, `ClientPump`, `WorkQueue`) are all
        // usable there — only the `std.posix.poll` reactor is not. See
        // the module doc comment.
        std.debug.print(
            "[foreign-loop] this target routes sockets through std.Io; " ++
                "the std.posix.poll reactor is unavailable here.\n",
            .{},
        );
    }
}

/// Producer running on a non-loop thread, to prove the only legal
/// cross-thread interaction: push onto the queue, poke the wake fd,
/// touch nothing else.
const Producer = struct {
    queue: *WorkQueue,
    waker: Waker,
    pushed: bool = false,

    fn run(self: *Producer) void {
        self.pushed = self.queue.push(.{ .kind = .report_stats, .seq = 1 });
        // Coalescing-safe: one wake for however many items landed.
        // The loop reads it as "check the queue".
        self.waker.wake();
    }
};

fn runDemo(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var server_sock = try bindLoopbackUdp(io);
    defer server_sock.close(io);
    var client_sock = try bindLoopbackUdp(io);
    defer client_sock.close(io);
    const waker = try Waker.bind(io);
    defer waker.deinit();

    std.debug.print(
        "[foreign-loop] server on {f}, client on {f}, wake fd on {f}\n",
        .{ server_sock.address, client_sock.address, waker.addr },
    );

    const protos = [_][]const u8{alpn};
    var app: ServerApp = .{};

    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = ServerApp.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
        // Defaults are the production posture: the per-source Initial
        // and Version-Negotiation limiters are ON (32 / 8 per window).
        // Owning the wait yourself changes nothing about that —
        // spelled out here because `.disabled` is the only way to turn
        // a default-on DoS mitigation off, and a foreign loop is
        // exactly where an embedder is tempted to reach for one.
        .initial_source_rate_limit = .default,
        .vn_source_rate_limit = .default,
    });
    defer server.deinit();

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        // The demo server presents a self-signed test certificate.
        // Never set this against an untrusted network — verify against
        // the system store (the default) or pin roots via
        // `tls_context_override`.
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    var queue: WorkQueue = .{ .io = io };
    var producer: Producer = .{ .queue = &queue, .waker = waker };
    {
        // A genuine second thread: both the `push` and the `wake()`
        // happen off the loop thread, which is the only cross-thread
        // interaction this file permits. Joined *before* `run` so the
        // demo is deterministic — the wake datagram is already sitting
        // on the socket when the first `poll` parks. A wake that lands
        // while the loop is mid-park takes the identical path; it just
        // isn't something a smoke run can schedule reliably.
        const producer_thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
        producer_thread.join();
    }
    if (!producer.pushed) return error.ForeignLoopQueueFull;

    var reactor = PosixPollReactor.init(.{
        .io = io,
        .server = &server,
        .app = &app,
        .client = &client,
        .server_sock = &server_sock,
        .client_sock = &client_sock,
        .waker = waker,
        .queue = &queue,
        .budget_us = 15 * std.time.us_per_s,
    });
    reactor.bindSelf();
    reactor.verbose = true;

    reactor.run() catch |err| {
        std.debug.print("[foreign-loop] FAIL ({s})\n", .{@errorName(err)});
        return err;
    };

    if (!reactor.client.succeeded()) {
        std.debug.print("[foreign-loop] FAIL (round-trip did not complete)\n", .{});
        return error.ForeignLoopIncomplete;
    }
    if (reactor.work_items_handled == 0) {
        std.debug.print("[foreign-loop] FAIL (cross-thread wake never observed)\n", .{});
        return error.ForeignLoopWakeMissed;
    }

    std.debug.print(
        "[foreign-loop] PASS ({d} poll iterations, {d} stream(s) + {d} datagram(s) echoed, " ++
            "{d} cross-thread work item(s), {d} live app state(s) after teardown)\n",
        .{
            reactor.iterations,
            app.streams_echoed,
            app.datagrams_echoed,
            reactor.work_items_handled,
            app.liveStates(),
        },
    );
}

// -- tests ------------------------------------------------------------------

const testing = std.testing;

// Group A — scheduling math. Portable: no I/O, no platform deps, and
// the highest-value regression in the file.

test "pollTimeoutMs: null deadline with a wake fd blocks indefinitely" {
    try testing.expectEqual(@as(i32, -1), pollTimeoutMs(1_000, null, default_idle_cap_ms, true));
}

test "pollTimeoutMs: null deadline without a wake fd falls back to the idle cap" {
    try testing.expectEqual(
        default_idle_cap_ms,
        pollTimeoutMs(1_000, null, default_idle_cap_ms, false),
    );
}

test "pollTimeoutMs: a past-due deadline returns 0, never a negative timeout" {
    // A negative return would be read by `poll` as "block forever",
    // so the connection's PTO would never fire and the loop would
    // stall until the next inbound datagram.
    const now_us: u64 = 1_000_000;
    const past: quic.TimerDeadline = .{ .kind = .pto, .at_us = now_us - 5_000 };
    try testing.expectEqual(@as(i32, 0), pollTimeoutMs(now_us, past, default_idle_cap_ms, true));

    const exactly_due: quic.TimerDeadline = .{ .kind = .pto, .at_us = now_us };
    try testing.expectEqual(
        @as(i32, 0),
        pollTimeoutMs(now_us, exactly_due, default_idle_cap_ms, true),
    );
}

test "pollTimeoutMs: a sub-millisecond deadline rounds up to 1 ms" {
    const now_us: u64 = 1_000_000;
    const soon: quic.TimerDeadline = .{ .kind = .ack_delay, .at_us = now_us + 300 };
    // 0 here would spin the loop hot on a 300 µs ACK-delay timer.
    try testing.expectEqual(@as(i32, 1), pollTimeoutMs(now_us, soon, default_idle_cap_ms, true));
}

test "pollTimeoutMs: an exact millisecond deadline is not inflated" {
    const now_us: u64 = 1_000_000;
    const in_2ms: quic.TimerDeadline = .{ .kind = .loss_detection, .at_us = now_us + 2_000 };
    try testing.expectEqual(@as(i32, 2), pollTimeoutMs(now_us, in_2ms, default_idle_cap_ms, true));
}

test "pollTimeoutMs: a far-future deadline is clamped to the idle cap" {
    const now_us: u64 = 1_000_000;
    // An hour out: the microsecond delta doesn't fit an i32
    // millisecond timeout, so the clamp is load-bearing.
    const far: quic.TimerDeadline = .{ .kind = .idle, .at_us = now_us + 3_600_000_000 };
    try testing.expectEqual(
        default_idle_cap_ms,
        pollTimeoutMs(now_us, far, default_idle_cap_ms, true),
    );
}

test "earlier: picks the sooner of two armed deadlines and tolerates nulls" {
    const a: quic.TimerDeadline = .{ .kind = .pto, .at_us = 5_000 };
    const b: quic.TimerDeadline = .{ .kind = .idle, .at_us = 9_000 };

    try testing.expect(earlier(null, null) == null);
    try testing.expectEqual(@as(u64, 5_000), earlier(a, null).?.at_us);
    try testing.expectEqual(@as(u64, 9_000), earlier(null, b).?.at_us);
    try testing.expectEqual(@as(u64, 5_000), earlier(a, b).?.at_us);
    try testing.expectEqual(@as(u64, 5_000), earlier(b, a).?.at_us);
    // The kind rides along untouched — the embedder treats it as
    // opaque and only feeds `at_us` back into the loop.
    try testing.expectEqual(quic.TimerKind.pto, earlier(b, a).?.kind);
}

// Group B — wake/queue semantics. Portable: `std.Thread.Mutex` works
// on Windows, and nothing here touches an fd.

test "WorkQueue: push from a producer, drain on the loop thread, FIFO order" {
    var queue: WorkQueue = .{ .io = testing.io };
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 1 }));
    try testing.expect(queue.push(.{ .kind = .request_close, .seq = 2 }));

    var out: [max_queued_work]Work = undefined;
    try testing.expectEqual(@as(usize, 2), queue.drainInto(&out));
    try testing.expectEqual(@as(u64, 1), out[0].seq);
    try testing.expectEqual(Work.Kind.report_stats, out[0].kind);
    try testing.expectEqual(@as(u64, 2), out[1].seq);
    try testing.expectEqual(Work.Kind.request_close, out[1].kind);
    // Drained means emptied.
    try testing.expectEqual(@as(usize, 0), queue.drainInto(&out));
}

test "WorkQueue: refuses work past max_queued_work instead of growing" {
    var queue: WorkQueue = .{ .io = testing.io };
    var i: u64 = 0;
    while (i < max_queued_work) : (i += 1) {
        try testing.expect(queue.push(.{ .kind = .report_stats, .seq = i }));
    }
    // A runaway producer gets a `false`, not unbounded memory in the
    // loop's address space.
    try testing.expect(!queue.push(.{ .kind = .report_stats, .seq = 999 }));

    var out: [max_queued_work]Work = undefined;
    try testing.expectEqual(max_queued_work, queue.drainInto(&out));
    // Room again after the drain.
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 1_000 }));
}

test "WorkQueue: N pushes coalesce into one drain - a wake means 'check the queue', not 'one item'" {
    // This is the invariant that keeps a coalescing wake fd correct.
    // Three `wake()` calls may collapse into a single readable event,
    // so the loop must never assume one wake == one item.
    var queue: WorkQueue = .{ .io = testing.io };
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 1 }));
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 2 }));
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 3 }));

    var out: [max_queued_work]Work = undefined;
    try testing.expectEqual(@as(usize, 3), queue.drainInto(&out));
}

test "WorkQueue: a short drain buffer leaves the remainder in FIFO order" {
    var queue: WorkQueue = .{ .io = testing.io };
    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        try testing.expect(queue.push(.{ .kind = .report_stats, .seq = i }));
    }

    var small: [2]Work = undefined;
    try testing.expectEqual(@as(usize, 2), queue.drainInto(&small));
    try testing.expectEqual(@as(u64, 0), small[0].seq);
    try testing.expectEqual(@as(u64, 1), small[1].seq);

    var rest: [max_queued_work]Work = undefined;
    try testing.expectEqual(@as(usize, 2), queue.drainInto(&rest));
    try testing.expectEqual(@as(u64, 2), rest[0].seq);
    try testing.expectEqual(@as(u64, 3), rest[1].seq);
}

// Group B2 — the stream-echo backpressure contract. Portable: a stub
// writer stands in for `Connection.streamWrite`, because the short-write
// path only triggers under real send-buffer pressure that an
// in-process echo demo never generates.

/// `StreamWriter` that accepts at most `accept` bytes per call and
/// returns 0 once it has been called `stop_after` times — i.e. the
/// exact two shapes `Connection.streamWrite` produces under
/// backpressure.
const ShortWriter = struct {
    accept: usize,
    stop_after: u32 = std.math.maxInt(u32),
    calls: u32 = 0,
    seen: [64]u8 = undefined,
    len: usize = 0,

    fn writer(self: *ShortWriter) StreamWriter {
        return .{ .ctx = self, .write = ShortWriter.write };
    }

    fn write(ctx: ?*anyopaque, id: u64, data: []const u8) anyerror!usize {
        _ = id;
        const self: *ShortWriter = @ptrCast(@alignCast(ctx.?));
        if (self.calls >= self.stop_after) return 0;
        self.calls += 1;
        const n = @min(self.accept, data.len);
        @memcpy(self.seen[self.len..][0..n], data[0..n]);
        self.len += n;
        return n;
    }
};

test "StreamEcho.flush: repeated short writes deliver every byte in order" {
    var w: ShortWriter = .{ .accept = 4 };
    var e: StreamEcho = .{ .id = 7, .active = true };
    @memcpy(e.buf[0..10], "0123456789");
    e.len = 10;

    try testing.expect(try e.flush(w.writer()));
    try testing.expectEqualStrings("0123456789", w.seen[0..w.len]);
    // Fully flushed means the staging window is reset.
    try testing.expectEqual(@as(usize, 0), e.off);
    try testing.expectEqual(@as(usize, 0), e.len);
    // 10 bytes at 4 per call.
    try testing.expectEqual(@as(u32, 3), w.calls);
}

test "StreamEcho.flush: a refused write keeps the remainder staged for the next pass" {
    // One accepted call, then the send buffer is full. The old shape of
    // this code asserted `written == n` and panicked here.
    var w: ShortWriter = .{ .accept = 4, .stop_after = 1 };
    var e: StreamEcho = .{ .id = 7, .active = true };
    @memcpy(e.buf[0..10], "0123456789");
    e.len = 10;

    try testing.expect(!try e.flush(w.writer()));
    try testing.expectEqual(@as(usize, 4), e.off);
    try testing.expectEqual(@as(usize, 10), e.len);
    try testing.expectEqualStrings("0123", w.seen[0..w.len]);

    // Backpressure clears; the staged tail goes out, in order, with
    // nothing lost or duplicated.
    w.stop_after = std.math.maxInt(u32);
    try testing.expect(try e.flush(w.writer()));
    try testing.expectEqualStrings("0123456789", w.seen[0..w.len]);
    try testing.expectEqual(@as(usize, 0), e.len);
}

// Group C — the raw API sequence end to end with NO sockets. This is
// the strongest claim in the file: a foreign loop driving only `feed`
// / `drainStatelessResponse` / `pollDatagram` / `tick` / `pollEvent` /
// `reap` really does complete a TLS 1.3 handshake and round-trip
// application data. Portable, including Windows.

/// Wires one pump's `DatagramSink` straight into the other's
/// `ingest`. The copy into `scratch` is not incidental: quic's
/// ingest paths take `[]u8` because header unprotection rewrites the
/// buffer in place, and `DatagramSink.send` hands out `[]const u8`.
const MemoryWire = struct {
    server: ?*ServerPump = null,
    client: ?*ClientPump = null,
    now_us: u64 = 0,
    to_server: u32 = 0,
    to_client: u32 = 0,
    scratch: [max_quic_datagram_bytes]u8 = undefined,

    /// Client -> server reordering impairment, armed by `Reorder`.
    /// Zero delivers every datagram in order, which is what every test
    /// but the reordering one wants.
    hold_nth_post_handshake: u32 = 0,
    /// Client -> server datagrams counted from the first one sent after
    /// the client's handshake completed.
    post_handshake_seq: u32 = 0,
    /// The datagram currently held back, if any.
    held_len: ?usize = null,
    held_buf: [max_quic_datagram_bytes]u8 = undefined,
    /// Set once the server has been observed with the peer's FIN seen
    /// and its recv half NOT terminal — a hole below an already-arrived
    /// FIN. That is the exact state in which "empty read + FIN seen"
    /// lies, so a reordering test that never reaches it is testing
    /// nothing and must fail.
    trap_observed: bool = false,

    fn toServer(ctx: ?*anyopaque, dst: quic.Address, bytes: []const u8) anyerror!void {
        _ = dst;
        const self: *MemoryWire = @ptrCast(@alignCast(ctx.?));
        self.to_server += 1;
        if (self.hold_nth_post_handshake != 0 and self.client.?.client.conn.handshakeDone()) {
            self.post_handshake_seq += 1;
            if (self.post_handshake_seq == self.hold_nth_post_handshake) {
                // Hold this one back so the datagrams behind it reach
                // the server first. Nothing is lost: `releaseHeld`
                // delivers it later, which is what a reordered path
                // does and what QUIC is required to tolerate.
                @memcpy(self.held_buf[0..bytes.len], bytes);
                self.held_len = bytes.len;
                return;
            }
        }
        @memcpy(self.scratch[0..bytes.len], bytes);
        _ = try self.server.?.ingest(self.scratch[0..bytes.len], synthetic_peer, self.now_us);
    }

    fn toClient(ctx: ?*anyopaque, dst: quic.Address, bytes: []const u8) anyerror!void {
        _ = dst;
        const self: *MemoryWire = @ptrCast(@alignCast(ctx.?));
        @memcpy(self.scratch[0..bytes.len], bytes);
        self.to_client += 1;
        try self.client.?.ingest(self.scratch[0..bytes.len], self.now_us);
    }

    /// Deliver the held-back datagram, closing the gap.
    fn releaseHeld(self: *MemoryWire) !void {
        const len = self.held_len orelse return;
        self.held_len = null;
        @memcpy(self.scratch[0..len], self.held_buf[0..len]);
        _ = try self.server.?.ingest(self.scratch[0..len], synthetic_peer, self.now_us);
    }

    /// Latch `trap_observed` if the server's recv half is sitting in
    /// the misread state right now.
    fn noteTrapState(self: *MemoryWire) void {
        const pump = self.server orelse return;
        if (pump.server.connectionCount() == 0) return;
        const slot = pump.server.iterator()[0];
        const st = slot.conn.streamRecvState(self.client.?.flow.stream_id) orelse return;
        if (st.fin_seen and !st.terminal) self.trap_observed = true;
    }
};

/// Client -> server packet reordering for `runInMemoryEcho`. All-zero
/// (the default) means an unimpaired wire.
const Reorder = struct {
    /// Which client -> server datagram to hold back, counted from the
    /// first one sent after the client's handshake completed. `1` is
    /// the flight that carries the client Finished, so the useful
    /// values start at `2` — the first datagram that is pure
    /// application data.
    hold_nth_post_handshake: u32 = 0,
    /// Hard backstop: let the held datagram through at this loop step
    /// even if the trap state never appeared, so a run can never stall
    /// on the impairment itself.
    release_by_step: u32 = 0,
};

/// Synthetic client tuple the in-memory server sees every datagram
/// arrive from.
const synthetic_peer: quic.Address = .{
    .ipv4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 4433 },
};

/// Everything the socketless run is asked to prove, captured by value
/// so the assertions outlive the `Server` / `Client` they came from.
const MemoryRun = struct {
    steps: u32,
    to_server: u32,
    to_client: u32,
    client_handshake_done: bool,
    server_handshake_done: bool,
    alpn_matched: bool,
    succeeded: bool,
    stage: ClientFlow.Stage,
    live_states_mid_run: usize,
    live_states_after_teardown: usize,
    connections_after_teardown: usize,
    streams_echoed: u32,
    datagrams_echoed: u32,
    states_refused: u32,
    /// See `MemoryWire.trap_observed`. Always false on an unimpaired
    /// wire, because packets never arrive out of order there.
    trap_observed: bool,
};

/// Drive a full `Server` <-> `Client` echo with the two pumps wired
/// straight into each other — no sockets, no threads, no `std.posix`,
/// and a fake clock. `max_steps` bounds the run so a stall fails fast.
/// `reorder` optionally holds one client -> server datagram back; pass
/// `.{}` for an in-order wire.
fn runInMemoryEcho(payload: []const u8, reply: []u8, max_steps: u32, reorder: Reorder) !MemoryRun {
    const allocator = testing.allocator;
    const protos = [_][]const u8{alpn};

    var app: ServerApp = .{};
    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = ServerApp.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
    });
    defer server.deinit();

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .insecure_skip_verify = true, // self-signed test fixture
    });
    defer client.deinit();

    var wire: MemoryWire = .{ .hold_nth_post_handshake = reorder.hold_nth_post_handshake };
    var server_tx: [max_quic_datagram_bytes]u8 = undefined;
    var client_tx: [max_quic_datagram_bytes]u8 = undefined;

    var server_pump: ServerPump = .{
        .server = &server,
        .app = &app,
        .sink = .{ .ctx = &wire, .send = MemoryWire.toClient },
        .tx = &server_tx,
    };
    var client_pump: ClientPump = .{
        .client = &client,
        .sink = .{ .ctx = &wire, .send = MemoryWire.toServer },
        .tx = &client_tx,
        .payload = payload,
        .reply = reply,
        .target = synthetic_peer,
    };
    wire.server = &server_pump;
    wire.client = &client_pump;

    try client_pump.bootstrap();

    // A fake clock advanced by a fixed step per iteration: the pumps
    // only require monotonic non-decreasing microseconds, so no real
    // time has to pass.
    var now_us: u64 = 0;
    var steps: u32 = 0;
    while (steps < max_steps and !client_pump.done()) : (steps += 1) {
        now_us += 1_000;
        wire.now_us = now_us;
        try client_pump.service(now_us);
        try server_pump.service(now_us);
        if (wire.held_len != null) {
            // Sample AFTER the server has had a full service pass with
            // the gap open, then close the gap. Sampling here is what
            // makes the impairment a real gate: an echo loop that ends
            // the stream on "empty read + FIN seen" has already
            // truncated by this point, so the run stalls and fails.
            wire.noteTrapState();
            if (wire.trap_observed or steps + 1 >= reorder.release_by_step) {
                try wire.releaseHeld();
            }
        }
    }

    var result: MemoryRun = .{
        .steps = steps,
        .to_server = wire.to_server,
        .to_client = wire.to_client,
        .client_handshake_done = client.conn.handshakeDone(),
        .server_handshake_done = server.connectionCount() > 0 and
            server.iterator()[0].conn.handshakeDone(),
        // `negotiatedAlpn` is the public accessor; reaching through
        // `conn.inner` would work but would make this file's "public
        // surface only" claim false.
        .alpn_matched = if (client.conn.negotiatedAlpn()) |got|
            std.mem.eql(u8, got, alpn)
        else
            false,
        .succeeded = client_pump.succeeded(),
        .stage = client_pump.flow.stage,
        .live_states_mid_run = app.liveStates(),
        .live_states_after_teardown = 0,
        .connections_after_teardown = 0,
        .streams_echoed = 0,
        .datagrams_echoed = 0,
        .states_refused = 0,
        .trap_observed = wire.trap_observed,
    };

    // Teardown: the client's CONNECTION_CLOSE is already on the wire,
    // so drive the server until its slot latches `.closed`, `reap`
    // runs, and `onConnectionWillClose` hands the pool entry back.
    // This is the `Slot.user_data` lifecycle a foreign loop must not
    // get wrong.
    server_pump.reap_every_n_iterations = 1;
    var grace: u32 = 0;
    while (server.connectionCount() > 0 and grace < 64) : (grace += 1) {
        now_us += std.time.us_per_s;
        wire.now_us = now_us;
        try server_pump.service(now_us);
    }

    result.connections_after_teardown = server.connectionCount();
    result.live_states_after_teardown = app.liveStates();
    result.streams_echoed = app.streams_echoed;
    result.datagrams_echoed = app.datagrams_echoed;
    result.states_refused = app.states_refused;
    return result;
}

test "ServerPump/ClientPump: full handshake + stream echo + datagram echo over an in-memory sink" {
    var reply: [stream_message.len]u8 = undefined;
    const run = try runInMemoryEcho(stream_message, &reply, 128, .{});

    try testing.expect(run.client_handshake_done);
    try testing.expect(run.server_handshake_done);
    try testing.expect(run.alpn_matched);

    // The round-trip, not just the handshake.
    try testing.expect(run.succeeded);
    try testing.expectEqual(ClientFlow.Stage.done, run.stage);
    // Datagrams flowed in both directions through the injected sink.
    try testing.expect(run.to_server > 0);
    try testing.expect(run.to_client > 0);
    // Sanity-cap the iteration count so a future regression that
    // technically converges but takes 100 rounds still fails.
    try testing.expect(run.steps <= 32);

    // One pool entry was live mid-run, and `reap` handed it back.
    try testing.expectEqual(@as(usize, 1), run.live_states_mid_run);
    try testing.expectEqual(@as(usize, 0), run.connections_after_teardown);
    try testing.expectEqual(@as(usize, 0), run.live_states_after_teardown);
    try testing.expect(run.streams_echoed >= 1);
    try testing.expect(run.datagrams_echoed >= 1);
    try testing.expectEqual(@as(u32, 0), run.states_refused);
}

test "ServerPump: a stream larger than one echo chunk is echoed whole, not truncated at the FIN" {
    // `StreamReadResult.fin` flips when the FIN *frame* arrives, not
    // when the application has drained the stream. A server that
    // finishes on the first `fin` echoes only its first chunk, and the
    // client then waits forever for the rest — so this payload has to
    // be several chunks long to catch it.
    const payload_len = echo_chunk_bytes * 5 - 3; // deliberately not a multiple
    comptime {
        std.debug.assert(payload_len > echo_chunk_bytes);
        std.debug.assert(payload_len <= common.transportParams().initial_max_stream_data_bidi_remote);
    }

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    var reply: [payload_len]u8 = undefined;

    // More steps than the short-payload case: the echo needs one pass
    // per chunk in each direction.
    const run = try runInMemoryEcho(&payload, &reply, 256, .{});

    // `ClientPump` compares the echo against the payload and errors on
    // a mismatch, so reaching `.done` at all means every byte came
    // back in order.
    try testing.expect(run.succeeded);
    try testing.expectEqual(ClientFlow.Stage.done, run.stage);
    try testing.expect(run.streams_echoed >= 1);
    try testing.expectEqual(@as(usize, 0), run.live_states_after_teardown);
    // An in-order wire never produces a hole, which is exactly why the
    // test below has to exist.
    try testing.expect(!run.trap_observed);
}

test "ServerPump: a FIN that arrives ahead of a missing chunk does not end the stream" {
    // The trap this pins is one step past the test above, and the two
    // are NOT the same. There, the FIN arrives while later chunks are
    // still queued *in order*, and reading until a read comes back
    // empty is enough. Here a chunk is missing *below* the read offset,
    // so the read comes back empty with the FIN already seen and bytes
    // still to come. An echo loop that ends the stream on that pair
    // echoes a prefix, FINs, and silently truncates — no error, on
    // either side, ever.
    //
    // Loopback and the in-order wire cannot produce this state, so the
    // wire holds one client datagram back until the server has been
    // observed in it (`MemoryRun.trap_observed`, asserted below so the
    // test fails loudly rather than passing vacuously if the impairment
    // stops biting).
    //
    // The payload spans several datagrams so there is a chunk to hold
    // back and a FIN behind it.
    const payload_len = echo_chunk_bytes * 6;
    comptime {
        std.debug.assert(payload_len > echo_chunk_bytes);
        std.debug.assert(payload_len <= common.transportParams().initial_max_stream_data_bidi_remote);
    }

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 17 +% 3);
    var reply: [payload_len]u8 = undefined;

    const run = try runInMemoryEcho(&payload, &reply, 512, .{
        // 1 carries the client Finished; 2 is the first datagram that
        // is pure stream data, and the FIN rides a later one.
        .hold_nth_post_handshake = 2,
        .release_by_step = 128,
    });

    // The impairment actually produced the misread state...
    try testing.expect(run.trap_observed);
    // ...and the echo still came back whole. `ClientPump` compares the
    // reply against the payload and errors on a mismatch, so reaching
    // `.done` means every byte returned, in order.
    try testing.expect(run.succeeded);
    try testing.expectEqual(ClientFlow.Stage.done, run.stage);
    try testing.expect(run.streams_echoed >= 1);
    try testing.expectEqual(@as(usize, 0), run.live_states_after_teardown);
}

test "ClientPump: bootstrap queues the ClientHello with nothing armed to wake the loop" {
    // The regression this pins: a reactor that computes its poll
    // timeout and parks BEFORE the first `service` call stalls the
    // whole handshake. `advance()` only queues the ClientHello, and at
    // that instant the connection has no timer armed at all — nothing
    // ack-eliciting has been sent, so there is no PTO, and the peer's
    // transport parameters are unknown, so there is no idle timer.
    const allocator = testing.allocator;
    const protos = [_][]const u8{alpn};

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    var counter: CountingSink = .{};
    var tx: [max_quic_datagram_bytes]u8 = undefined;
    var reply: [stream_message.len]u8 = undefined;
    var pump: ClientPump = .{
        .client = &client,
        .sink = counter.sink(),
        .tx = &tx,
        .reply = &reply,
        .target = synthetic_peer,
    };

    try pump.bootstrap();

    // Nothing on the wire yet...
    try testing.expectEqual(@as(u32, 0), counter.datagrams);
    // ...and nothing to wake a loop that parks here. With a wake fd in
    // the set that is a -1 timeout: block until an application thread
    // happens to poke us, which for a handshake is forever.
    try testing.expect(client.conn.nextTimerDeadline(0) == null);
    try testing.expectEqual(
        @as(i32, -1),
        pollTimeoutMs(0, client.conn.nextTimerDeadline(0), default_idle_cap_ms, true),
    );

    // One `service` ships the ClientHello...
    try pump.service(1_000);
    try testing.expect(counter.datagrams > 0);
    try testing.expect(counter.bytes > 0);

    // ...leaves the outbox empty (this is the post-condition the
    // reactor asserts on before every park)...
    try testing.expectEqual(@as(?u64, 1_000), pump.drained_through_us);
    var probe: [max_quic_datagram_bytes]u8 = undefined;
    try testing.expect((try client.conn.pollDatagram(&probe, 1_000)) == null);

    // ...and only now is there a deadline to park on: the PTO for the
    // Initial we just sent.
    const armed = client.conn.nextTimerDeadline(1_000);
    try testing.expect(armed != null);
    try testing.expect(pollTimeoutMs(1_000, armed, default_idle_cap_ms, true) >= 0);
}

/// `DatagramSink` that counts instead of delivering.
const CountingSink = struct {
    datagrams: u32 = 0,
    bytes: usize = 0,

    fn sink(self: *CountingSink) DatagramSink {
        return .{ .ctx = self, .send = CountingSink.send };
    }

    fn send(ctx: ?*anyopaque, dst: quic.Address, bytes: []const u8) anyerror!void {
        _ = dst;
        const self: *CountingSink = @ptrCast(@alignCast(ctx.?));
        self.datagrams += 1;
        self.bytes += bytes.len;
    }
};

// Group D — the real poll path. Skipped on Windows, where
// `std.posix.poll` is a compile error; the `if (comptime ...)` form
// comptime-excludes the bodies there rather than relying on a runtime
// branch. Policy: `docs/RELEASE_READINESS.md` "Real-socket std.Io
// loopback smoke tests ... stay skipped in-tree".

/// Map the standing sandbox-bind failures onto a test skip. Copied
/// from `tests/e2e/server_loop_smoke.zig`: CI runners sometimes block
/// UDP binds outright, and that is not a quic-zig regression.
fn sandboxSkip(err: anyerror) anyerror {
    return switch (err) {
        error.AddressInUse,
        error.AddressUnavailable,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SocketModeUnsupported,
        error.OptionUnsupported,
        error.NetworkDown,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        => error.SkipZigTest,
        else => err,
    };
}

test "PosixPollReactor: a poll-driven loop completes the echo round-trip over loopback" {
    if (comptime poll_reactor_supported) try reactorSmoke() else return error.SkipZigTest;
}

fn reactorSmoke() !void {
    const io = testing.io;
    const allocator = testing.allocator;

    var server_sock = bindLoopbackUdp(io) catch |err| return sandboxSkip(err);
    defer server_sock.close(io);
    var client_sock = bindLoopbackUdp(io) catch |err| return sandboxSkip(err);
    defer client_sock.close(io);
    const waker = Waker.bind(io) catch |err| return sandboxSkip(err);
    defer waker.deinit();

    const protos = [_][]const u8{alpn};
    var app: ServerApp = .{};

    var server = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.cert_pem,
        .tls_key_pem = common.key_pem,
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .on_connection_will_close = ServerApp.onConnectionWillClose,
        .on_connection_will_close_user_data = &app,
    });
    defer server.deinit();

    var client = try quic.Client.connect(.{
        .allocator = allocator,
        .server_name = "localhost",
        .alpn_protocols = &protos,
        .transport_params = common.transportParams(),
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    // Prove the cross-thread path without a thread: `push` is the
    // producer-side API and `wake()` is legal from any thread, so
    // queueing one item up front means the very first `poll` returns
    // on the wake fd. The threaded variant lives in `main`.
    var queue: WorkQueue = .{ .io = io };
    try testing.expect(queue.push(.{ .kind = .report_stats, .seq = 7 }));
    waker.wake();

    // Wall-clock cap so a stall fails fast instead of hanging CI.
    var reactor = PosixPollReactor.init(.{
        .io = io,
        .server = &server,
        .app = &app,
        .client = &client,
        .server_sock = &server_sock,
        .client_sock = &client_sock,
        .waker = waker,
        .queue = &queue,
        .budget_us = 20 * std.time.us_per_s,
    });
    reactor.bindSelf();
    try reactor.run();

    try testing.expect(reactor.client.succeeded());
    try testing.expect(reactor.work_items_handled >= 1);
    try testing.expect(client.conn.handshakeDone());
    try testing.expect(app.streams_echoed >= 1);
    try testing.expect(app.datagrams_echoed >= 1);
    // The reactor's teardown window drove the server slot to `.closed`
    // and reaped it, which is what released the app state.
    try testing.expectEqual(@as(usize, 0), app.liveStates());
}

test "Waker: wake() makes a parked poll return before its timeout" {
    if (comptime poll_reactor_supported) try wakerParkedPoll() else return error.SkipZigTest;
}

fn wakerParkedPoll() !void {
    const io = testing.io;
    const waker = Waker.bind(io) catch |err| return sandboxSkip(err);
    defer waker.deinit();

    // Single-threaded, so this is deterministic: the wake datagram is
    // already queued on the socket before we park.
    waker.wake();

    var fds = [_]PollFd{.{ .fd = waker.sock.handle, .events = poll_in, .revents = 0 }};
    const ready = try pollWait(&fds, 1_000);
    try testing.expectEqual(@as(usize, 1), ready);
    try testing.expect(isReadable(fds[0]));
    try testing.expect(!hasFailed(fds[0]));

    var scratch: [64]u8 = undefined;
    waker.drain(&scratch);

    // And the fd is quiet again afterwards: a zero timeout must not
    // report ready, or the loop would spin.
    fds[0].revents = 0;
    try testing.expectEqual(@as(usize, 0), try pollWait(&fds, 0));
}
