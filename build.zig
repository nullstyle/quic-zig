const std = @import("std");

fn parseSanitizeC(value: []const u8) std.zig.SanitizeC {
    if (std.mem.eql(u8, value, "off")) return .off;
    if (std.mem.eql(u8, value, "trap")) return .trap;
    if (std.mem.eql(u8, value, "full")) return .full;
    std.debug.panic("invalid -Dsanitize-c value '{s}' (expected off, trap, or full)", .{value});
}

fn sanitizeCOption(mode: std.zig.SanitizeC) []const u8 {
    return switch (mode) {
        .off => "off",
        .trap => "trap",
        .full => "full",
    };
}

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
    const is_windows = target.result.os.tag == .windows;
    const sanitize_c: ?std.zig.SanitizeC = if (b.option(
        []const u8,
        "sanitize-c",
        "Override C/UB sanitizer mode for quic-zig and boringssl-zig modules: off, trap, or full",
    )) |mode| parseSanitizeC(mode) else null;

    const boringssl_dep = if (sanitize_c) |mode|
        b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = optimize,
            .@"sanitize-c" = sanitizeCOption(mode),
        })
    else
        b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = optimize,
        });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const quic_zig_mod = b.addModule("quic_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    quic_zig_mod.addImport("boringssl", boringssl_mod);

    // Export the exact boringssl module instance quic_zig is compiled
    // against so consumers can name types that unify with quic_zig's
    // API surface — e.g. constructing a `boringssl.tls.Context` for
    // `Client.Config.tls_context_override` (private-CA pinning, custom
    // session-ticket capture). A consumer that declared its own
    // boringssl-zig dependency would get a *different* module instance
    // whose `tls.Context` type does not unify. Mirrors http3-zig's
    // export of the same module; tools/consumer-smoke pins the type
    // identity end-to-end.
    b.modules.put(b.graph.arena, "boringssl", boringssl_mod) catch @panic("OOM");

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
        .sanitize_c = sanitize_c,
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
        .sanitize_c = sanitize_c,
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
        .sanitize_c = sanitize_c,
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
        .sanitize_c = sanitize_c,
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

    // Canonical first-hour echo pair: a hostable echo server and the
    // client that round-trips a stream + a DATAGRAM against it, both
    // built on the `transport.runUdp*` loops' `on_iteration` hooks.
    // `examples/echo_common.zig` (shared fixtures) and
    // `examples/support/*.pem` (self-signed test cert) ride along via
    // relative @import/@embedFile inside the examples/ module root.
    const echo_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo_server.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    echo_server_mod.addImport("quic_zig", quic_zig_mod);
    const echo_server_exe = b.addExecutable(.{
        .name = "echo-server-example",
        .root_module = echo_server_mod,
    });
    const echo_server_install = b.addInstallArtifact(echo_server_exe, .{});
    examples_step.dependOn(&echo_server_install.step);

    const echo_client_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo_client.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    echo_client_mod.addImport("quic_zig", quic_zig_mod);
    const echo_client_exe = b.addExecutable(.{
        .name = "echo-client-example",
        .root_module = echo_client_mod,
    });
    const echo_client_install = b.addInstallArtifact(echo_client_exe, .{});
    examples_step.dependOn(&echo_client_install.step);

    // One-process echo smoke: server loop on a thread, client loop to
    // completion, non-zero exit unless the round-trip happened. A
    // standalone binary (real sockets + threads) rather than a test
    // target; CI runs `zig build run-echo-smoke` on the Linux leg.
    const echo_smoke_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo_smoke.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    echo_smoke_mod.addImport("quic_zig", quic_zig_mod);
    const echo_smoke_exe = b.addExecutable(.{
        .name = "echo-smoke",
        .root_module = echo_smoke_mod,
    });
    const run_echo_smoke = b.addRunArtifact(echo_smoke_exe);
    const echo_smoke_step = b.step(
        "run-echo-smoke",
        "Run the echo example end-to-end (server thread + client) over loopback UDP",
    );
    echo_smoke_step.dependOn(&run_echo_smoke.step);

    // Zig autodocs for the public quic_zig module. `zig build docs`
    // emits the static site into zig-out/docs (open index.html).
    const docs_obj = b.addObject(.{
        .name = "quic_zig",
        .root_module = quic_zig_mod,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate quic_zig API documentation (Zig autodocs)");
    docs_step.dependOn(&install_docs.step);

    const interop_tool_mod = b.createModule(.{
        .root_source_file = b.path("tools/external_interop.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
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
    const bench_boringssl_dep = if (sanitize_c) |mode|
        b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = bench_optimize,
            .@"sanitize-c" = sanitizeCOption(mode),
        })
    else
        b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = bench_optimize,
        });
    const bench_boringssl_mod = bench_boringssl_dep.module("boringssl");

    const bench_quic_zig_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
        .sanitize_c = sanitize_c,
    });
    bench_quic_zig_mod.addImport("boringssl", bench_boringssl_mod);
    bench_quic_zig_mod.addImport("build_options", build_options_mod);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = bench_optimize,
        .sanitize_c = sanitize_c,
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
        .sanitize_c = sanitize_c,
    });
    bench_tests_mod.addImport("quic_zig", bench_quic_zig_mod);
    bench_tests_mod.addImport("boringssl", bench_boringssl_mod);
    const bench_tests = b.addTest(.{ .root_module = bench_tests_mod });
    const run_bench_tests = b.addRunArtifact(bench_tests);

    const bench_test_step = b.step("bench-test", "Run benchmark helper fixture tests");
    // On native Windows, Zig currently probes `pkg-config.BAT` while compiling
    // the ReleaseSafe benchmark test binary and fails before falling back to the
    // bundled BoringSSL build. Keep the production/library test surface green
    // there and leave benchmark fixtures to Unix CI until that toolchain quirk
    // settles.
    if (!is_windows) {
        test_step.dependOn(&run_bench_tests.step);
        bench_test_step.dependOn(&run_bench_tests.step);
    }

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
