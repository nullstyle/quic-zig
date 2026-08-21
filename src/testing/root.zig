//! quic.testing - in-memory loopback harness for embedder tests.
//!
//! Ships in the package so downstream servers can write in-process
//! integration tests against a real `quic.Server` / `quic.Client`
//! pair — real TLS, real packet protection, real loss recovery —
//! with datagrams handed back and forth in memory instead of through
//! a UDP socket. No threads, no ports, no flakiness.
//!
//! The shape mirrors what `transport.runUdpServer` does per
//! iteration, in the order it does it: client→server datagrams,
//! application servicing (the optional Driver), server→client
//! datagrams plus the stateless-response drain, then both `tick`s.
//! `step` is one such iteration; `handshake` drives `step` until the
//! TLS handshake completes; `drive` runs until a predicate or a step
//! budget.
//!
//! ```zig
//! var srv = try quic.Server.init(.{ ... });
//! var cli = try quic.Client.connect(.{ ... });
//! var lb = try quic.testing.Loopback.init(.{
//!     .allocator = allocator,
//!     .server = &srv,
//!     .client = &cli,
//! });
//! defer lb.deinit();
//! try lb.handshake(&driver); // or &quic.testing.NullDriver{}
//! // ... open streams, write, then:
//! try lb.drive(&driver, .{ .budget_steps = 10_000, .until = myDonePredicate });
//! ```

const std = @import("std");
const quic = @import("../root.zig");

/// A canned loopback peer address (IPv4 205.205.205.205) for feeds
/// that want source attribution. Any value works in-memory.
pub const loopback_addr: quic.Address = .{ .ipv4 = .{ .addr = @splat(0xcd), .port = 0 } };

/// No-op driver for `Loopback.step` / `handshake` / `drive` when
/// there is no application layer to service (the harness still pumps
/// datagrams and ticks both connections).
pub const NullDriver = struct {
    // `*const` so the documented `&quic.testing.NullDriver{}` spelling
    // (a const pointer) compiles; a mutable `&nd` coerces fine too.
    pub fn service(_: *const NullDriver, _: *quic.Server) anyerror!void {}
};

/// In-memory client↔server datagram pump. Owns only its scratch
/// buffers; the `Server` and `Client` remain the embedder's.
pub const Loopback = struct {
    allocator: std.mem.Allocator,
    server: *quic.Server,
    client: *quic.Client,
    /// Simulated clock, advanced 1 ms per `step` by default.
    now_us: u64 = 1_000,
    rx: []u8,

    pub const Options = struct {
        allocator: std.mem.Allocator,
        server: *quic.Server,
        client: *quic.Client,
        /// Scratch for one datagram in each direction per pump. 4 KiB
        /// covers a full-MTU QUIC packet with headroom.
        rx_bytes: usize = 4096,
        /// Starting microsecond timestamp.
        now_us: u64 = 1_000,
    };

    pub fn init(options: Options) !Loopback {
        const rx = try options.allocator.alloc(u8, @max(options.rx_bytes, 1));
        return .{
            .allocator = options.allocator,
            .server = options.server,
            .client = options.client,
            .now_us = options.now_us,
            .rx = rx,
        };
    }

    pub fn deinit(self: *Loopback) void {
        self.allocator.free(self.rx);
        self.* = undefined;
    }

    /// Client → server: every datagram the client can emit, fed
    /// through `Server.feed`. Returns the datagram count.
    pub fn pumpClientToServer(self: *Loopback) !usize {
        var n: usize = 0;
        while (try self.client.conn.poll(self.rx, self.now_us)) |len| {
            _ = try self.server.feed(self.rx[0..len], loopback_addr, self.now_us);
            n += 1;
        }
        return n;
    }

    /// Server → client: every datagram every server slot can emit,
    /// handled by the client. Stateless responses (VN/Retry) are
    /// drained and discarded — correct for same-version, retry-less
    /// in-memory setups. Returns the datagram count.
    pub fn pumpServerToClient(self: *Loopback) !usize {
        var n: usize = 0;
        for (self.server.iterator()) |slot| {
            while (try slot.conn.poll(self.rx, self.now_us)) |len| {
                try self.client.conn.handle(self.rx[0..len], null, self.now_us);
                n += 1;
            }
        }
        while (self.server.drainStatelessResponse()) |_| {}
        return n;
    }

    /// One full loop iteration in the `runUdpServer` order: ingest,
    /// (optional) application servicing, egress, ticks, clock. The
    /// `driver` is a POINTER to anything with a
    /// `service(*quic.Server)` method — typically a
    /// `*quic.app.Driver(App)` (or `&quic.testing.NullDriver{}` when
    /// there is no application layer). Application servicing runs
    /// BEFORE `tick` on purpose: the stream GC inside `tick` must not
    /// reap a stream whose arrived bytes the app has not read yet.
    pub fn step(self: *Loopback, driver: anytype) !void {
        _ = try self.pumpClientToServer();
        try driver.service(self.server);
        _ = try self.pumpServerToClient();
        try self.server.tick(self.now_us);
        try self.client.conn.tick(self.now_us);
        self.now_us += 1_000;
    }

    /// Drive `step` until both sides report `handshakeDone()`.
    /// Fails with `error.HandshakeStalled` after a fixed 64-step
    /// budget — far above what a loss-free in-memory handshake needs.
    pub fn handshake(self: *Loopback, driver: anytype) !void {
        try self.client.conn.advance();
        var steps: usize = 0;
        while (steps < 64) : (steps += 1) {
            if (self.client.conn.handshakeDone() and
                self.server.iterator().len > 0 and
                self.server.iterator()[0].conn.handshakeDone()) return;
            try self.step(driver);
        }
        return error.HandshakeStalled;
    }

    pub const DriveOptions = struct {
        budget_steps: usize = 10_000,
        /// Called after each step; driving stops when it returns true.
        /// Runs with the loopback and the caller's captured context.
        until: *const fn (*Loopback) bool,
        /// Advance the simulated clock by this many microseconds per
        /// step instead of the default 1 ms — larger to fast-forward
        /// through draining / idle timeouts in teardown, smaller for
        /// fine-grained timer tests. Sub-millisecond values are fine.
        step_us: u64 = 1_000,
    };

    /// Drive `step` until `until` answers true or the step budget is
    /// exhausted (`error.DriveBudgetExhausted`). The predicate sees
    /// the `Loopback` (`.client`, `.server`, `.now_us`).
    pub fn drive(self: *Loopback, driver: anytype, options: DriveOptions) !void {
        var steps: usize = 0;
        while (steps < options.budget_steps) : (steps += 1) {
            if (options.until(self)) return;
            try self.step(driver);
            if (options.step_us != 1_000) {
                // step() already advanced 1 ms; retarget the net
                // advance to step_us. Two writes, not one subtraction,
                // so a sub-millisecond step_us cannot underflow.
                self.now_us -= 1_000;
                self.now_us += options.step_us;
            }
        }
        if (options.until(self)) return;
        return error.DriveBudgetExhausted;
    }
};

test "Loopback: option defaults pinned" {
    // Structural smoke only — the full pair exercise lives in
    // tests/e2e/testing_loopback.zig, which is also the usage example.
    const opts: Loopback.Options = .{
        .allocator = undefined,
        .server = undefined,
        .client = undefined,
    };
    try std.testing.expectEqual(@as(u64, 1_000), opts.now_us);
    try std.testing.expectEqual(@as(usize, 4096), opts.rx_bytes);
}
