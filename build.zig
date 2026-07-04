const std = @import("std");

// Build-mode policy (hardening guide §3.1).
//
// `b.standardOptimizeOption` defaults to `Debug` so iterative
// development (`zig build test`, embedder smoke runs, interop
// fixtures) is fast and prints useful panic stacks. **Production /
// internet-facing builds MUST pass `-Doptimize=ReleaseSafe`** to
// keep Zig's runtime safety checks enabled (integer overflow,
// out-of-bounds slicing, optional unwrap, `unreachable`,
// `@setRuntimeSafety` toggles) while optimizing.
//
// `ReleaseFast` and `ReleaseSmall` are forbidden by default for the
// network-input parser surface. Both compile out runtime safety,
// which means the residual `unreachable` paths in `wire/`, `frame/`,
// and `conn/state.zig` (documented as non-peer-reachable invariants)
// stop being trapped — `unreachable` becomes "the optimizer assumes
// this is impossible". An adversarial input that reaches one of those
// sites in `ReleaseFast` produces undefined behavior instead of a
// controlled panic. The benchmark harness below defaults to
// `ReleaseSafe`; use `-Dbench-unsafe-release-fast=true` only when you
// intentionally want unsafe peak-speed measurements.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const quic_zig_mod = b.addModule("quic_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_zig_mod.addImport("boringssl", boringssl_mod);

    // Single-source the library version from build.zig.zon so `version()`
    // can't drift from the package manifest (it silently did: 0.2.0 vs 0.3.0).
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", @import("build.zig.zon").version);
    const build_options_mod = build_options.createModule();
    quic_zig_mod.addImport("build_options", build_options_mod);

    const test_step = b.step("test", "Run quic_zig tests");

    const unit_tests = b.addTest(.{ .root_module = quic_zig_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Cross-cutting integration tests live in tests/. They have
    // their own module so they can `@embedFile` test data without
    // shipping it inside the published `quic_zig` package.
    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("quic_zig", quic_zig_mod);
    tests_mod.addImport("boringssl", boringssl_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    // RFC-traceable conformance suites under tests/conformance/. Each
    // file mirrors a section of an RFC and uses BCP 14 keywords plus
    // `[RFC#### §X.Y ¶N]` citations in test names so failures point an
    // auditor straight at the offending requirement. See
    // `tests/conformance/README.md` for the full grammar.
    //
    // The conformance binary is its own `addTest` invocation so we can
    // expose a narrower `zig build conformance` entry point and so a
    // `-Dconformance-filter='RFC9000 §17'` invocation only walks the
    // conformance corpus. It uses the default Zig test runner so we
    // don't take on a third-party runner dependency.
    //
    // The Zig default runner doesn't accept `--test-filter` at runtime
    // — filtering is a compile-time `--test-filter` flag wired via
    // `TestOptions.filters`. That is fine for our use case (auditors
    // run `zig build conformance` against a fresh tree).
    const conformance_filter = b.option(
        []const u8,
        "conformance-filter",
        "Substring filter for the RFC conformance suite (e.g. 'RFC9000 §17')",
    );
    const conformance_filters: []const []const u8 =
        if (conformance_filter) |f| &.{f} else &.{};
    const conformance_mod = b.createModule(.{
        // Lives at tests/conformance.zig (sibling of tests/root.zig)
        // so the package boundary is tests/. Suites that need the
        // existing tests/data/test_cert.pem fixture for Server-level
        // assertions can `@embedFile("../data/test_cert.pem")`.
        .root_source_file = b.path("tests/conformance.zig"),
        .target = target,
        .optimize = optimize,
    });
    conformance_mod.addImport("quic_zig", quic_zig_mod);
    conformance_mod.addImport("boringssl", boringssl_mod);
    const conformance_tests = b.addTest(.{
        .root_module = conformance_mod,
        .filters = conformance_filters,
    });
    const run_conformance_tests = b.addRunArtifact(conformance_tests);
    test_step.dependOn(&run_conformance_tests.step);

    const conformance_step = b.step("conformance", "Run quic_zig RFC-traceable conformance suites");
    conformance_step.dependOn(&run_conformance_tests.step);

    const qns_mod = b.createModule(.{
        .root_source_file = b.path("interop/qns_endpoint.zig"),
        .target = target,
        .optimize = optimize,
    });
    qns_mod.addImport("quic_zig", quic_zig_mod);
    qns_mod.addImport("boringssl", boringssl_mod);

    const qns_exe = b.addExecutable(.{
        .name = "qns-endpoint",
        .root_module = qns_mod,
    });
    const qns_install = b.addInstallArtifact(qns_exe, .{});
    b.getInstallStep().dependOn(&qns_install.step);

    const qns_tests = b.addTest(.{ .root_module = qns_mod });
    const run_qns_tests = b.addRunArtifact(qns_tests);
    test_step.dependOn(&run_qns_tests.step);

    const qns_step = b.step("qns-endpoint", "Build the QUIC interop-runner endpoint");
    qns_step.dependOn(&qns_install.step);

    // Reference embedder for the alternative-server-address receive
    // surface. Builds as both a runnable example
    // (`zig build examples`) and a test target
    // (`zig build test` walks its inline tests via `test_step`).
    const alt_addr_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/alt_addr_embedder.zig"),
        .target = target,
        .optimize = optimize,
    });
    alt_addr_example_mod.addImport("quic_zig", quic_zig_mod);
    alt_addr_example_mod.addImport("boringssl", boringssl_mod);

    const alt_addr_example_exe = b.addExecutable(.{
        .name = "alt-addr-embedder-example",
        .root_module = alt_addr_example_mod,
    });
    const alt_addr_example_install = b.addInstallArtifact(alt_addr_example_exe, .{});

    const alt_addr_example_tests = b.addTest(.{ .root_module = alt_addr_example_mod });
    const run_alt_addr_example_tests = b.addRunArtifact(alt_addr_example_tests);
    test_step.dependOn(&run_alt_addr_example_tests.step);

    const examples_step = b.step("examples", "Build the embedder example programs");
    examples_step.dependOn(&alt_addr_example_install.step);

    const interop_tool_mod = b.createModule(.{
        .root_source_file = b.path("tools/external_interop.zig"),
        .target = target,
        .optimize = optimize,
    });
    const interop_tool_exe = b.addExecutable(.{
        .name = "quic-zig-external-interop",
        .root_module = interop_tool_mod,
    });
    b.installArtifact(interop_tool_exe);

    const interop_tool_tests = b.addTest(.{ .root_module = interop_tool_mod });
    const run_interop_tool_tests = b.addRunArtifact(interop_tool_tests);
    test_step.dependOn(&run_interop_tool_tests.step);

    const run_interop_tool = b.addRunArtifact(interop_tool_exe);
    run_interop_tool.addPassthruArgs();
    const external_interop_step = b.step("external-interop", "Run the external QUIC interop gate helper");
    external_interop_step.dependOn(&run_interop_tool.step);

    // Microbenchmarks. Built with ReleaseSafe by default, regardless
    // of the user's -Doptimize choice for the rest of the tree. This
    // keeps benchmark fixtures aligned with the production safety
    // policy while still avoiding Debug-mode noise.
    //
    // Opt into ReleaseFast only with an explicit unsafe flag, since
    // that mode disables runtime safety checks on parser surfaces.
    const bench_unsafe_release_fast = b.option(
        bool,
        "bench-unsafe-release-fast",
        "Build benchmarks with ReleaseFast instead of the default ReleaseSafe; disables runtime safety checks",
    ) orelse false;
    const bench_optimize: std.builtin.OptimizeMode = if (bench_unsafe_release_fast)
        .ReleaseFast
    else
        .ReleaseSafe;
    const bench_boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = bench_optimize,
    });
    const bench_boringssl_mod = bench_boringssl_dep.module("boringssl");

    const bench_quic_zig_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_quic_zig_mod.addImport("boringssl", bench_boringssl_mod);
    bench_quic_zig_mod.addImport("build_options", build_options_mod);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_mod.addImport("quic_zig", bench_quic_zig_mod);
    bench_mod.addImport("boringssl", bench_boringssl_mod);

    const bench_exe = b.addExecutable(.{
        .name = "quic-zig-bench",
        .root_module = bench_mod,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    run_bench.addPassthruArgs();
    const bench_step = b.step("bench", "Run quic_zig microbenchmarks");
    bench_step.dependOn(&run_bench.step);

    const bench_tests_mod = b.createModule(.{
        .root_source_file = b.path("bench/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_tests_mod.addImport("quic_zig", bench_quic_zig_mod);
    bench_tests_mod.addImport("boringssl", bench_boringssl_mod);
    const bench_tests = b.addTest(.{ .root_module = bench_tests_mod });
    const run_bench_tests = b.addRunArtifact(bench_tests);
    test_step.dependOn(&run_bench_tests.step);

    const bench_test_step = b.step("bench-test", "Run benchmark helper fixture tests");
    bench_test_step.dependOn(&run_bench_tests.step);

    // Coverage-guided fuzzing.
    //
    // Every `std.testing.fuzz` site in src/ runs once against its seed
    // corpus under plain `zig build test`, so the harnesses are exercised
    // on every CI run — that smoke pass is the per-commit regression gate
    // (see CONTRIBUTING.md "Fuzzing").
    //
    // Deep coverage-guided fuzzing uses the build-system flag on the
    // UNFILTERED unit-test binary. This is what CI runs
    // (.github/workflows/fuzz.yml) and, on 0.17.0-dev.1158, the only
    // invocation that works:
    //
    //     zig build test --fuzz=1M    # limit mode (1M inputs)
    //     zig build test --fuzz       # forever (until Ctrl-C) + web UI
    //
    // There is deliberately NO per-site or `-j<N>` parallel fuzz step. The
    // runner hard-codes n_instances = 1 (ziglang/zig#25352), so a run
    // saturates one core and the fuzzer rotates across the binary's sites
    // by weighted selection. The obvious workaround — one
    // `addTest(.filters = ...)` binary per site, run in parallel — does NOT
    // work: a *filtered* test binary under `--fuzz` aborts the build-runner
    // ("reached unreachable code") on this Zig, while the unfiltered binary
    // fuzzes cleanly. Confirmed on Linux: unfiltered `zig build test --fuzz`
    // exits 0 (750k+ runs); a single filtered site exits 1 on the same
    // tree. So we ship no filtered fuzz binaries; `just fuzz` /
    // `mise run fuzz` call the unfiltered command above.
}
