const std = @import("std");

/// The two ways a consumer can tell quic-zig which mode to build in.
const Wiring = enum {
    /// `.release = optimize != .debug`: works with every release of
    /// quic-zig, and for an application in any mode (quic-zig builds
    /// ReleaseSafe inside a ReleaseFast application).
    release,
    /// `.optimize = optimize`: what most packages take. quic-zig
    /// accepts it from 0.24.1 on (Debug and ReleaseSafe; it refuses
    /// ReleaseFast and ReleaseSmall).
    optimize,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const wiring = b.option(
        Wiring,
        "wiring",
        "How this build passes its mode to quic: `release` (default) or `optimize`",
    ) orelse .release;

    // Through 0.24.0 quic's build had no `optimize` option, and this
    // file passed `.optimize = optimize`, as the README told consumers
    // to. The build printed `error: invalid option: "optimize"`, went
    // on, and compiled quic and BoringSSL in Debug whatever this
    // build's mode was (MEASURED with `zig build --verbose
    // -Doptimize=ReleaseSafe` on the 0.24.0 tarball: `-Osafe
    // -Mroot=... -Odebug -Mquic=... -Odebug -Mboringssl=...`). CI ran
    // this smoke in Debug only, read its last line, and stayed green.
    // Both spellings are exercised now (`-Dwiring=`), in both modes.
    const quic_dep = switch (wiring) {
        .release => b.dependency("quic", .{
            .target = target,
            .release = optimize != .debug,
        }),
        .optimize => b.dependency("quic", .{
            .target = target,
            .optimize = optimize,
        }),
    };
    // The guard: the modules we import must be built in the mode this
    // build asked for. It runs when the build is configured, so
    // `zig build check` (a step with nothing to compile) is enough to
    // run it.
    const want_mode: std.lang.Optimize = if (optimize == .debug) .debug else .safe;
    for ([_][]const u8{ "quic", "boringssl" }) |name| {
        const got = quic_dep.module(name).optimize;
        if (got != want_mode) {
            std.debug.panic("the {s} module is built in {?t}, and this build wants {t} (wiring: {t})", .{
                name, got, want_mode, wiring,
            });
        }
    }
    _ = b.step("check", "Run only the build-mode guard (nothing is compiled)");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("quic", quic_dep.module("quic"));
    // The exported shared boringssl instance is the point of this smoke
    // test: a consumer must be able to name `boringssl.tls.Context`
    // values that type-unify with quic's API (e.g.
    // `Client.Config.tls_context_override` for private-CA pinning)
    // without declaring its own boringssl dependency.
    exe_mod.addImport("boringssl", quic_dep.module("boringssl"));

    const exe = b.addExecutable(.{
        .name = "consumer-smoke",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the consumer smoke binary");
    run_step.dependOn(&run.step);
}
