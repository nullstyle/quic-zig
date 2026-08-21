//! Out-of-tree consumer smoke test.
//!
//! Consumes quic-zig the way an application does (a build.zig.zon
//! dependency) and asserts the property that breaks real consumers
//! when it regresses: the boringssl module instance exported by
//! quic-zig's build.zig is the same module quic's API is typed
//! against, so a consumer-built `boringssl.tls.Context` is accepted
//! by `Client.Config.tls_context_override` (the private-CA-pinning /
//! custom-TLS path). Compiling is the test; main only prints
//! versions.

const std = @import("std");
const quic = @import("quic");
const boringssl = @import("boringssl");

comptime {
    // Type identity across the package boundary: the field is
    // `?boringssl.tls.Context`, and "boringssl" here is the module
    // instance exported by quic-zig — a consumer that declared its own
    // boringssl dependency would get a different instance whose
    // Context type does NOT unify.
    const OverrideField = std.meta.fieldInfo(quic.Client.Config, .tls_context_override).type;
    std.debug.assert(OverrideField == ?boringssl.tls.Context);
    // Same instance check for the server-side override.
    const ServerOverrideField = std.meta.fieldInfo(quic.Server.Config, .tls_context_override).type;
    std.debug.assert(ServerOverrideField == ?boringssl.tls.Context);
}

/// The load-bearing runtime shape: an app-built TLS context (from the
/// exported boringssl module) must satisfy `Client.Config`. Never
/// called — semantic analysis of the field assignment is the test.
fn wireTlsOverride(ctx: boringssl.tls.Context) quic.Client.Config {
    return .{
        .allocator = std.heap.page_allocator,
        .server_name = "pinned.example",
        .alpn_protocols = &.{"smoke/1"},
        .transport_params = .{},
        .tls_context_override = ctx,
    };
}

pub fn main() void {
    _ = &wireTlsOverride; // force semantic analysis of the identity check
    _ = &wireAppLayer; // force semantic analysis of the app-layer surface
    std.debug.print("consumer-smoke ok: quic-zig {s}\n", .{quic.version()});
}

const SmokeApp = struct {
    pub const StreamState = void;
    pub const ConnState = void;

    fn onStreamData(_: *SmokeApp, s: *D.Session, e: *D.StreamEntry, chunk: []const u8) anyerror!void {
        try s.outbox.push(s.conn, e.id, chunk);
    }

    fn onStreamEnd(_: *SmokeApp, s: *D.Session, e: *D.StreamEntry, end: quic.app.StreamEnd) anyerror!void {
        if (end == .fin) try s.outbox.finish(s.conn, e.id);
    }
};

const D = quic.app.Driver(SmokeApp);

/// The application-layer surface a downstream server builds on must
/// resolve from the consumer side of the package boundary: the
/// Driver instantiation with required state decls, explicit hook
/// registration, the config helpers, and the shipped test harness.
/// Never called — semantic analysis is the test.
fn wireAppLayer() void {
    const hooks: D.Hooks = .{
        .on_stream_data = SmokeApp.onStreamData,
        .on_stream_end = SmokeApp.onStreamEnd,
    };
    _ = hooks;

    // Config helpers + testing harness resolve.
    const tp = comptime quic.Server.Config.defaultTransportParams();
    comptime std.debug.assert(tp.initial_max_streams_bidi > 0);
    _ = &quic.Server.Config.mintKey;
    _ = &quic.testing.Loopback.init;
    _ = quic.testing.NullDriver{};
}
