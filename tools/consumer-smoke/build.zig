const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const quic_dep = b.dependency("quic_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("quic_zig", quic_dep.module("quic_zig"));
    // The exported shared boringssl instance is the point of this smoke
    // test: a consumer must be able to name `boringssl.tls.Context`
    // values that type-unify with quic_zig's API (e.g.
    // `Client.Config.tls_context_override` for private-CA pinning)
    // without declaring its own boringssl-zig dependency.
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
