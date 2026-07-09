//! Out-of-tree consumer smoke test.
//!
//! Consumes quic-zig the way an application does (a build.zig.zon
//! dependency) and asserts the property that breaks real consumers
//! when it regresses: the boringssl module instance exported by
//! quic-zig's build.zig is the same module quic_zig's API is typed
//! against, so a consumer-built `boringssl.tls.Context` is accepted
//! by `Client.Config.tls_context_override` (the private-CA-pinning /
//! custom-TLS path). Compiling is the test; main only prints
//! versions.

const std = @import("std");
const quic_zig = @import("quic_zig");
const boringssl = @import("boringssl");

comptime {
    // Type identity across the package boundary: the field is
    // `?boringssl.tls.Context`, and "boringssl" here is the module
    // instance exported by quic-zig — a consumer that declared its own
    // boringssl-zig dependency would get a different instance whose
    // Context type does NOT unify.
    const OverrideField = std.meta.fieldInfo(quic_zig.Client.Config, .tls_context_override).type;
    std.debug.assert(OverrideField == ?boringssl.tls.Context);
    // Same instance check for the server-side override.
    const ServerOverrideField = std.meta.fieldInfo(quic_zig.Server.Config, .tls_context_override).type;
    std.debug.assert(ServerOverrideField == ?boringssl.tls.Context);
}

/// The load-bearing runtime shape: an app-built TLS context (from the
/// exported boringssl module) must satisfy `Client.Config`. Never
/// called — semantic analysis of the field assignment is the test.
fn wireTlsOverride(ctx: boringssl.tls.Context) quic_zig.Client.Config {
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
    std.debug.print("consumer-smoke ok: quic-zig {s}\n", .{quic_zig.version()});
}
