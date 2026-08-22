//! Pins for the Server config-ergonomics surface:
//! `Config.defaultTransportParams` (a non-zero admission working set),
//! `Config.mintKey` (CSPRNG key material for the 32-byte key fields),
//! and the `config_warning` log event `Server.init` emits when
//! `transport_params` would admit no streams, bytes, or datagrams.

const std = @import("std");
const quic = @import("quic");
const common = @import("common.zig");

const WarnCtx = struct {
    warnings: std.ArrayListUnmanaged([]const u8) = .empty,

    fn onLog(user_data: ?*anyopaque, ev: quic.Server.LogEvent) void {
        const ctx: *WarnCtx = @ptrCast(@alignCast(user_data.?));
        switch (ev) {
            .config_warning => |w| ctx.warnings.append(std.testing.allocator, w.message) catch {},
            else => {},
        }
    }
};

test "Server.init warns when transport_params admit nothing" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var ctx: WarnCtx = .{};
    defer ctx.warnings.deinit(allocator);

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = .{}, // the footgun under test
        .log_callback = WarnCtx.onLog,
        .log_user_data = &ctx,
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(usize, 1), ctx.warnings.items.len);
    try std.testing.expect(std.mem.indexOf(u8, ctx.warnings.items[0], "admit no streams") != null);
}

test "Server.init warns when transport_params.stateless_reset_token is hand-set" {
    // The footgun: `transport_params` is copied verbatim onto every
    // accepted connection and the accept path only OVERWRITES this
    // field when a `stateless_reset_key` exists — so a hand-set token
    // is advertised, unchanged, to every peer. One shared token means
    // any peer that ever handshook can reset any other connection
    // (RFC 9000 §10.3 wants per-CID unpredictable tokens), and this
    // server can never emit a matching reset anyway (the emitter
    // derives from the key it does not have).
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var ctx: WarnCtx = .{};
    defer ctx.warnings.deinit(allocator);

    var params = quic.Server.Config.defaultTransportParams();
    params.stateless_reset_token = @splat(0x77);

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .log_callback = WarnCtx.onLog,
        .log_user_data = &ctx,
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(usize, 1), ctx.warnings.items.len);
    try std.testing.expect(
        std.mem.indexOf(u8, ctx.warnings.items[0], "stateless_reset_token is set directly") != null,
    );
}

test "no stateless-reset-token warning once a real key is configured" {
    // With a key the accept path overwrites the field per-connection
    // with a properly derived per-CID token, so the hand-set value is
    // harmless and the warning must stay silent — otherwise every
    // correctly-configured server would carry a spurious warning.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var ctx: WarnCtx = .{};
    defer ctx.warnings.deinit(allocator);

    var params = quic.Server.Config.defaultTransportParams();
    params.stateless_reset_token = @splat(0x77);

    var srv = try quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
        .stateless_reset_key = try quic.Server.Config.mintKey(),
        .log_callback = WarnCtx.onLog,
        .log_user_data = &ctx,
    });
    defer srv.deinit();

    try std.testing.expectEqual(@as(usize, 0), ctx.warnings.items.len);
}

test "no config_warning for a working set or a datagram-only posture" {
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};
    var ctx: WarnCtx = .{};
    defer ctx.warnings.deinit(allocator);

    // The blessed defaults admit streams — no warning.
    {
        var srv = try quic.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = common.test_cert_pem,
            .tls_key_pem = common.test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = quic.Server.Config.defaultTransportParams(),
            .log_callback = WarnCtx.onLog,
            .log_user_data = &ctx,
        });
        defer srv.deinit();
    }

    // A datagram-only server (no streams, but datagrams enabled) is a
    // legitimate all-zero-stream posture — no warning either.
    {
        var srv = try quic.Server.init(.{
            .allocator = allocator,
            .tls_cert_pem = common.test_cert_pem,
            .tls_key_pem = common.test_key_pem,
            .alpn_protocols = &protos,
            .transport_params = .{ .max_datagram_frame_size = 1200 },
            .log_callback = WarnCtx.onLog,
            .log_user_data = &ctx,
        });
        defer srv.deinit();
    }

    try std.testing.expectEqual(@as(usize, 0), ctx.warnings.items.len);
}

test "defaultTransportParams matches the documented quick-start values and idle-timeout default" {
    const tp = quic.Server.Config.defaultTransportParams();
    try std.testing.expectEqual(quic.Server.default_server_idle_timeout_ms, tp.max_idle_timeout_ms);
    try std.testing.expect(tp.initial_max_data > 0);
    try std.testing.expect(tp.initial_max_streams_bidi > 0);
    try std.testing.expect(tp.initial_max_streams_uni > 0);
    try std.testing.expect(tp.initial_max_stream_data_bidi_local > 0);
    try std.testing.expect(tp.initial_max_stream_data_bidi_remote > 0);
    try std.testing.expect(tp.initial_max_stream_data_uni > 0);
    // DATAGRAM stays opt-in.
    try std.testing.expectEqual(@as(u64, 0), tp.max_datagram_frame_size);
}

test "mintKey returns fresh 32 bytes usable as every server key field" {
    const a = try quic.Server.Config.mintKey();
    const b = try quic.Server.Config.mintKey();
    try std.testing.expectEqual(@as(usize, 32), a.len);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));

    // Type-checks against all three key fields.
    const protos = [_][]const u8{"hq-test"};
    var srv = try quic.Server.init(.{
        .allocator = std.testing.allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = .{ .max_datagram_frame_size = 1200 },
        .stateless_reset_key = a,
        .retry_token_key = b,
        .new_token_key = a,
    });
    defer srv.deinit();
}
