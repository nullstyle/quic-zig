//! Smoke tests for `quic.transport.runUdpServer`.
//!
//! The full loop is awkward to drive headless: it needs a real UDP
//! peer to handshake against, a thread to run the loop, and a way to
//! signal shutdown. The QUIC interop runner already exercises the
//! end-to-end path when the QNS endpoint is rebuilt against this
//! helper, so here we settle for compile-time checks plus a couple
//! of zero-side-effect assertions on the option surface.
//!
//! What we *can* verify cheaply:
//!   1. The helper compiles when called against a real `Server`.
//!   2. `RunUdpOptions` has the documented defaults.
//!   3. `runUdpServer` rejects malformed listen addresses without
//!      ever touching the socket layer.
//!   4. The shutdown_flag plumbing accepts `*const std.atomic.Value(bool)`
//!      without the caller having to whisper-cast.
//!
//! What we can't easily verify here:
//!   - End-to-end handshake against a real peer. Driving that
//!     requires a second quic client (or quic-go) on a known port,
//!     which is what `interop/qns_endpoint.zig` and the commands in
//!     `interop/README.md` are for.
//!   - Behavior under socket errors, signal-driven shutdown, or
//!     load. Those would need a fault-injection `std.Io` shim that
//!     is out of scope for this smoke test.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("quic");

const common = @import("common.zig");

const test_cert_pem = common.test_cert_pem;
const test_key_pem = common.test_key_pem;
const defaultParams = common.defaultParams;

test "runUdpServer is importable from the transport namespace" {
    // `runUdpServer` and the option struct must both live on the
    // public `transport` API surface so embedders can reach them
    // without dipping into private modules.
    // `anyerror` return: `RunUdpOptions.on_iteration` hook errors
    // propagate out verbatim; hook-less loops still fail only with
    // `transport.RunError` values.
    const helper: *const fn (
        *quic.Server,
        quic.transport.RunUdpOptions,
    ) anyerror!void = quic.transport.runUdpServer;
    _ = helper;
    // The documented loop-error set stays public.
    _ = quic.transport.RunError;
}

test "RunUdpOptions defaults match the documented contract" {
    const opts: quic.transport.RunUdpOptions = .{
        .listen = "127.0.0.1:0",
        .io = undefined, // not invoked
    };
    // 5 ms heartbeat — short enough for QUIC's PTO granularity,
    // long enough to avoid spinning on an idle network.
    try std.testing.expectEqual(@as(i64, 5), opts.receive_timeout.toMilliseconds());
    // Tuning on by default for production sanity.
    try std.testing.expect(opts.tune_socket);
    // Port-sharing is opt-in; a lone server must keep the historical
    // exclusive bind.
    try std.testing.expect(!opts.reuse_port);
    // 5 second grace — plenty for CONNECTION_CLOSE to flush even
    // through a single 200 ms RTT path with retransmits.
    try std.testing.expectEqual(@as(u64, 5_000_000), opts.shutdown_grace_us);
    // No shutdown flag by default; the loop runs forever until the
    // embedder either cancels the I/O or kills the process.
    try std.testing.expect(opts.shutdown_flag == null);
}

test "runUdpServer rejects a malformed listen literal" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Garbage in -> InvalidListenAddress out, before bind is ever
    // attempted. Important: this confirms the helper validates input
    // up front so a typo'd listen string doesn't surface as a
    // confusing socket error from deep in std.Io.
    const result = quic.transport.runUdpServer(&srv, .{
        .listen = "not-an-address",
        .io = std.testing.io,
    });
    try std.testing.expectError(error.InvalidListenAddress, result);
}

test "runUdpServer rejects zero-byte buffers" {
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    // Bad rx buffer.
    try std.testing.expectError(error.InvalidBufferSize, quic.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .rx_buffer_bytes = 0,
    }));

    // Bad tx buffer.
    try std.testing.expectError(error.InvalidBufferSize, quic.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .tx_buffer_bytes = 0,
    }));
}

test "runUdpServer with shutdown_flag already set returns immediately" {
    // This is the closest we get to exercising the loop body
    // without a peer: pre-set the shutdown flag, point the loop at
    // a loopback ephemeral port, and verify it cleans up without
    // blocking. The receive timeout caps the worst case at ~5 ms.
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var stop = std.atomic.Value(bool).init(true);

    // Skip if the test environment can't bind UDP at all (sandboxed
    // CI runners sometimes block this).
    quic.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .shutdown_flag = &stop,
        // Don't try to tune buffers — most CI sandboxes lack
        // CAP_NET_ADMIN and we'd hit error.SocketTuningFailed.
        .tune_socket = false,
        // Tiny grace so the test doesn't sit on the loop.
        .shutdown_grace_us = 1_000,
        // Tiny receive timeout so the very first iteration sees the
        // flag and bails.
        .receive_timeout = std.Io.Duration.fromMilliseconds(1),
    }) catch |err| switch (err) {
        // The loopback bind itself can fail in a sandbox.
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
        => return error.SkipZigTest,
        error.WindowsBundledLoopUnsupported => {
            // Native Windows cannot run this loop at all (std has no
            // overlapped-I/O `net_receive`), and the loop refuses up
            // front — after argument validation, before any socket is
            // bound — with its own documented error. Pinned as a
            // platform contract rather than skipped — if the gate is
            // ever lifted, this assertion fails and tells us to
            // re-check the loop there. See the note on
            // `transport.RunError`.
            try std.testing.expect(builtin.os.tag == .windows);
            return;
        },
        else => return err,
    };

    // No live connections were ever fed in, so `connectionCount`
    // must be exactly 0 after the loop returns.
    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

test "runUdpServer binds preferred-address alt listener and returns cleanly" {
    // Same shape as the shutdown-flag-already-set test, but with a
    // `preferred_address` configured. The loop must bind both the
    // primary and the alt listener (else the bind error surfaces),
    // then bail on the first iteration when it sees the shutdown
    // flag. The alt-listener binds on a separate ephemeral port so
    // the test cannot collide with anything else on the host.
    const protos = [_][]const u8{"hq-test"};

    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
        .stateless_reset_key = @splat(0x42),
        .preferred_address = .{
            // ephemeral port, IPv4 loopback
            .ipv4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 },
        },
    });
    defer srv.deinit();

    var stop = std.atomic.Value(bool).init(true);

    quic.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = std.testing.io,
        .shutdown_flag = &stop,
        .tune_socket = false,
        .shutdown_grace_us = 1_000,
        .receive_timeout = std.Io.Duration.fromMilliseconds(1),
    }) catch |err| switch (err) {
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
        => return error.SkipZigTest,
        error.WindowsBundledLoopUnsupported => {
            // Native Windows cannot run this loop at all (std has no
            // overlapped-I/O `net_receive`), and the loop refuses up
            // front — after argument validation, before any socket is
            // bound — with its own documented error. Pinned as a
            // platform contract rather than skipped — if the gate is
            // ever lifted, this assertion fails and tells us to
            // re-check the loop there. See the note on
            // `transport.RunError`.
            try std.testing.expect(builtin.os.tag == .windows);
            return;
        },
        else => return err,
    };

    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

/// Fixture for the two `reuse_port` tests below: a socket that holds
/// a loopback port in a `SO_REUSEPORT` group and stays open, standing
/// in for "worker #1 is already running" while the loop under test
/// plays worker #2. `listen_literal` receives the shared port.
const ReuseGroupHolder = struct {
    sock: std.Io.net.Socket,

    fn init() !ReuseGroupHolder {
        if (!quic.transport.has_reuseport_sockopt) return error.SkipZigTest;
        const addr = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
        const sock = try quic.transport.bindUdpSocket(&addr, .{ .reuse_port = true });
        return .{ .sock = sock };
    }

    fn deinit(self: *ReuseGroupHolder) void {
        self.sock.close(std.testing.io);
    }

    fn listenLiteral(self: *const ReuseGroupHolder, buf: []u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "127.0.0.1:{d}", .{self.sock.address.ip4.port});
    }
};

test "runUdpServer with reuse_port joins a port another socket holds" {
    // Worker #2 boots while worker #1's socket is bound: the loop's
    // primary listener must join the reuseport group instead of dying
    // with AddressInUse, then exit cleanly on the preset shutdown
    // flag. Without the flag this exact setup fails — the test below
    // pins that contrast.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var holder = try ReuseGroupHolder.init();
    defer holder.deinit();
    var lit_buf: [32]u8 = undefined;
    const listen = try holder.listenLiteral(&lit_buf);

    const protos = [_][]const u8{"hq-test"};
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var stop = std.atomic.Value(bool).init(true);
    quic.transport.runUdpServer(&srv, .{
        .listen = listen,
        .io = std.testing.io,
        .reuse_port = true,
        .shutdown_flag = &stop,
        .tune_socket = false,
        .shutdown_grace_us = 1_000,
        .receive_timeout = std.Io.Duration.fromMilliseconds(1),
    }) catch |err| switch (err) {
        // The reuse group join itself can fail in a sandbox.
        error.AddressUnavailable,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SocketModeUnsupported,
        error.NetworkDown,
        => return error.SkipZigTest,
        // AddressInUse here would mean the flag is not wired to the
        // bind path — the exact regression this test exists for.
        else => return err,
    };

    try std.testing.expectEqual(@as(usize, 0), srv.connectionCount());
}

/// Pins which `bindListener` branch is compiled in. On a std whose
/// `IpAddress.BindOptions` has `reuse_port`, the loop's listener bind must
/// reach the `Io` vtable with the flag set; on an older std it must not
/// (the POSIX-direct fallback binds instead). The plain reuse_port tests
/// above cannot tell the two apart: `std.testing.io` is `Io.Threaded`,
/// whose sockets are blocking too, so both branches pass them.
const RecordingBindIo = struct {
    var inner: std.Io = undefined;
    var bind_calls: usize = 0;
    var saw_reuse_port: bool = false;

    fn netBindIp(
        userdata: ?*anyopaque,
        address: *const std.Io.net.IpAddress,
        options: std.Io.net.IpAddress.BindOptions,
    ) std.Io.net.IpAddress.BindError!std.Io.net.Socket {
        bind_calls += 1;
        if (@hasField(@TypeOf(options), "reuse_port")) saw_reuse_port = options.reuse_port;
        return inner.vtable.netBindIp(userdata, address, options);
    }
};

test "runUdpServer with reuse_port binds through the Io vtable when std can" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    if (!quic.transport.has_reuseport_sockopt) return error.SkipZigTest;
    // Spelled independently of the library's own gate, so a typo in the
    // library's `@hasField` string fails here instead of passing quietly.
    const std_has = @hasField(std.Io.net.IpAddress.BindOptions, "reuse_port");
    try std.testing.expectEqual(std_has, quic.transport.std_bind_has_reuse_port);

    RecordingBindIo.inner = std.testing.io;
    RecordingBindIo.bind_calls = 0;
    RecordingBindIo.saw_reuse_port = false;
    var vtable = std.testing.io.vtable.*;
    vtable.netBindIp = RecordingBindIo.netBindIp;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };

    const protos = [_][]const u8{"hq-test"};
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    var stop = std.atomic.Value(bool).init(true);
    quic.transport.runUdpServer(&srv, .{
        .listen = "127.0.0.1:0",
        .io = io,
        .reuse_port = true,
        .shutdown_flag = &stop,
        .tune_socket = false,
        .shutdown_grace_us = 1_000,
        .receive_timeout = std.Io.Duration.fromMilliseconds(1),
    }) catch |err| switch (err) {
        error.AddressInUse,
        error.AddressUnavailable,
        error.AddressFamilyUnsupported,
        error.SystemResources,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SocketModeUnsupported,
        error.NetworkDown,
        => return error.SkipZigTest,
        else => return err,
    };

    if (std_has) {
        try std.testing.expectEqual(@as(usize, 1), RecordingBindIo.bind_calls);
        try std.testing.expect(RecordingBindIo.saw_reuse_port);
    } else {
        try std.testing.expectEqual(@as(usize, 0), RecordingBindIo.bind_calls);
    }
}

test "runUdpServer without reuse_port conflicts with an open holder" {
    // The contrast arm: same open reuseport holder, no flag, and the
    // loop's plain bind must fail with AddressInUse — deterministic,
    // because the holder stays open for the whole call and a bind
    // without SO_REUSEPORT cannot join it.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var holder = try ReuseGroupHolder.init();
    defer holder.deinit();
    var lit_buf: [32]u8 = undefined;
    const listen = try holder.listenLiteral(&lit_buf);

    const protos = [_][]const u8{"hq-test"};
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = test_cert_pem,
        .tls_key_pem = test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = defaultParams(),
    });
    defer srv.deinit();

    try std.testing.expectError(
        error.AddressInUse,
        quic.transport.runUdpServer(&srv, .{
            .listen = listen,
            .io = std.testing.io,
            .tune_socket = false,
        }),
    );
}
