const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // `release`, not `optimize`: quic's build has two modes (Debug and
    // ReleaseSafe) and so registers the boolean. This file passed
    // `.optimize = optimize` until after 0.24.0, as the README told
    // consumers to. The package has no such option: the build printed
    // `error: invalid option: "optimize"`, went on, and compiled quic
    // and BoringSSL in Debug whatever this build's mode was (MEASURED
    // with `zig build --verbose -Doptimize=ReleaseSafe` on the 0.24.0
    // tarball: `-Osafe -Mroot=... -Odebug -Mquic=... -Odebug
    // -Mboringssl=...`).
    const quic_dep = b.dependency("quic", .{
        .target = target,
        .release = optimize != .debug,
    });
    // The guard for that wiring: the module we import must be built in
    // the mode this build asked for.
    const want_quic_mode: std.lang.Optimize = if (optimize == .debug) .debug else .safe;
    if (quic_dep.module("quic").optimize != want_quic_mode) {
        std.debug.panic("the quic module is built in {?t}, and this build wants {t}", .{
            quic_dep.module("quic").optimize, want_quic_mode,
        });
    }

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
