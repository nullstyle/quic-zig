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

test "Server.init refuses a hand-set transport_params.stateless_reset_token without a key" {
    // The footgun: §18.2's token is the HANDSHAKE CID's token — a
    // different value per connection — so a value in per-server
    // config cannot be correct for more than one connection.
    // `transport_params` is copied verbatim onto every accepted
    // connection and the accept path only OVERWRITES this field when
    // a key exists, so keyless the SAME token reaches every peer: any
    // peer that ever handshook could reset any other connection
    // (§10.3 wants per-CID unpredictable tokens), and this server
    // could never emit a matching reset anyway. Refused, not warned —
    // a warning reaches only embedders who wired `log_callback`.
    const allocator = std.testing.allocator;
    const protos = [_][]const u8{"hq-test"};

    var params = quic.Server.Config.defaultTransportParams();
    params.stateless_reset_token = @splat(0x77);

    try std.testing.expectError(error.InvalidConfig, quic.Server.init(.{
        .allocator = allocator,
        .tls_cert_pem = common.test_cert_pem,
        .tls_key_pem = common.test_key_pem,
        .alpn_protocols = &protos,
        .transport_params = params,
    }));
}

test "a hand-set token is accepted once a real key makes it inert" {
    // With a key the accept path overwrites the field per-connection
    // with a properly derived per-CID token, so the hand-set value is
    // dead config rather than a hazard. Accepting it keeps the
    // refusal scoped to the configuration that is actually harmful.
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
