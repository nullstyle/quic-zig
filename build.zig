const std = @import("std");
const builtin = @import("builtin");
const manifest = @import("build.zig.zon");

// Zig's build runner parses `minimum_zig_version` from build.zig.zon
// but never compares it against the running compiler, so an
// out-of-floor toolchain otherwise fails with an unexplained compile
// error somewhere inside the tree — usually inside a vendored
// dependency, from a consumer's point of view. This assert is the
// enforcement, and it runs for dependency builds too, so downstream
// projects get the same diagnostic. Floor bumps are recorded as
// breaking changes in CHANGELOG.md.
comptime {
    const required = std.SemanticVersion.parse(manifest.minimum_zig_version) catch
        @compileError("build.zig.zon minimum_zig_version is not valid semver: " ++
            manifest.minimum_zig_version);
    if (builtin.zig_version.order(required) == .lt) {
        @compileError(std.fmt.comptimePrint(
            "quic-zig requires zig {s} or newer (build.zig.zon minimum_zig_version); " ++
                "this build is running zig {s}. Upgrade the toolchain, or pin a quic-zig " ++
                "release whose CHANGELOG declares support for yours.",
            .{ manifest.minimum_zig_version, builtin.zig_version_string },
        ));
    }
}

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

/// Options forwarded into the boringssl_zig dependency. Each is null
/// when the user didn't pass it, and an unpassed option is NOT
/// forwarded: `b.dependency` memoizes on the exact args, so passing a
/// default explicitly would split boringssl into duplicate compile
/// graphs (and break `tls_context_override` type identity for
/// consumers of the exported `boringssl` module).
const BoringsslForward = struct {
    sanitize_c: ?std.zig.SanitizeC,
    /// "zig" builds BoringSSL from source; "cmake" links the
    /// prebuilt archives under boringssl-zig's vendor tree.
    source: ?[]const u8,
    /// With source="cmake": which vendor/boringssl-prebuilt/<dir> to
    /// link. Resolved to "native" when only `source` was passed.
    prebuilt_target: ?[]const u8,
};

fn boringsslDependency(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    fwd: BoringsslForward,
) *std.Build.Dependency {
    // `b.dependency`'s args struct is comptime-shaped, so every
    // combination of forwarded options is its own call site.
    if (fwd.source) |src| {
        const prebuilt = fwd.prebuilt_target orelse "native";
        if (fwd.sanitize_c) |mode| {
            return b.dependency("boringssl_zig", .{
                .target = target,
                .optimize = optimize,
                .@"sanitize-c" = sanitizeCOption(mode),
                .@"boringssl-source" = src,
                .@"boringssl-target" = prebuilt,
            });
        }
        return b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = optimize,
            .@"boringssl-source" = src,
            .@"boringssl-target" = prebuilt,
        });
    }
    if (fwd.sanitize_c) |mode| {
        return b.dependency("boringssl_zig", .{
            .target = target,
            .optimize = optimize,
            .@"sanitize-c" = sanitizeCOption(mode),
        });
    }
    return b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
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

    // Pass-throughs for boringssl-zig's own build options, so a
    // consumer can reach the prebuilt-BoringSSL escape hatch (283 C++
    // TUs avoided) without depending on boringssl-zig directly.
    const bssl_source = b.option(
        []const u8,
        "boringssl-source",
        "Forwarded to boringssl_zig: 'zig' compiles BoringSSL from source (default), 'cmake' links its vendor/ prebuilt archives",
    );
    if (bssl_source) |src| {
        if (!std.mem.eql(u8, src, "zig") and !std.mem.eql(u8, src, "cmake")) {
            std.debug.panic("invalid -Dboringssl-source value '{s}' (expected zig or cmake)", .{src});
        }
    }
    const bssl_prebuilt_target = b.option(
        []const u8,
        "boringssl-target",
        "Forwarded to boringssl_zig: with -Dboringssl-source=cmake, selects vendor/boringssl-prebuilt/<dir> (default: native)",
    );
    // Upstream only consults `boringssl-target` in cmake mode, so a
    // target passed without `-Dboringssl-source=cmake` would be
    // silently ignored — the user asked for a specific prebuilt and
    // would get the full from-source build instead. Fail loudly.
    if (bssl_prebuilt_target != null and
        (bssl_source == null or !std.mem.eql(u8, bssl_source.?, "cmake")))
    {
        std.debug.panic("-Dboringssl-target requires -Dboringssl-source=cmake", .{});
    }
    const bssl_fwd: BoringsslForward = .{
        .sanitize_c = sanitize_c,
        .source = bssl_source,
        .prebuilt_target = bssl_prebuilt_target,
    };

    const boringssl_dep = boringsslDependency(b, target, optimize, bssl_fwd);
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
    build_options.addOption([]const u8, "version", manifest.version);
    const build_options_mod = build_options.createModule();
    quic_zig_mod.addImport("build_options", build_options_mod);

    // Everything below is development-only surface: test suites, the
    // QNS endpoint, examples, docs, interop tooling, benchmarks. When
    // quic-zig runs as a dependency (`pkg_hash` is empty only for the
    // root package), stop here — consumers need only the module graph
    // above, and the published archive deliberately omits the dev
    // trees (see `.paths` in build.zig.zon).
    if (b.pkg_hash.len != 0) return;

    // Coverage-guided fuzzing needs the target modules compiled with
    // Zig's fuzzer instrumentation, which is a per-module opt-in
    // (`std.Build.Module.fuzz`; see the note on
    // `Step.Compile.sanitize_coverage_trace_pc_guard`). Nothing in the
    // build runner turns it on for you: `--fuzz` will happily execute
    // every `std.testing.fuzz` target against an *uninstrumented*
    // binary, where the fuzzer collects zero program counters. That
    // yields blind random input generation with no coverage feedback,
    // and the build runner then fails the run reporting a "corrupted
    // coverage file ... pcs_len was zero" — which is what the
    // pre-release `rc-fuzz` gate had been dying on.
    //
    // It is an option rather than an unconditional flag because
    // `quic_zig_mod` is the very module `b.addModule` publishes to
    // consumers: instrumenting it here would instrument every
    // downstream build. Pass `-Dfuzz=true` alongside `--fuzz`
    // (rc-fuzz.yml does).
    const fuzz_instrumentation = b.option(
        bool,
        "fuzz",
        "Compile the test modules with fuzzer coverage instrumentation. Use ONLY together with `--fuzz`, and only on Linux: it links Zig's fuzzer runtime, whose `runner_*` hooks the macOS test runner does not provide (a plain `zig build test -Dfuzz=true` fails to link there).",
    ) orelse false;
    if (fuzz_instrumentation) quic_zig_mod.fuzz = true;

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

    // Foreign-event-loop embedder: the caller-drives (no-I/O) path
    // wired into a hand-rolled `std.posix.poll` reactor instead of
    // `transport.runUdp*`. Ships as both a runnable example
    // (`zig build examples`) and a test target (`zig build test` walks
    // its inline tests via `test_step`) — the portable scheduling +
    // in-memory pump tests run on every tier-1 platform, and the
    // socket/poll tests skip on Windows, where std routes sockets
    // through `std.Io` and `std.posix.poll` is a compile error.
    // `examples/echo_common.zig` (shared fixtures) and
    // `examples/support/*.pem` ride along via relative
    // @import/@embedFile inside the examples/ module root.
    const foreign_loop_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/foreign_loop_embedder.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_c = sanitize_c,
    });
    foreign_loop_example_mod.addImport("quic_zig", quic_zig_mod);

    const foreign_loop_example_exe = b.addExecutable(.{
        .name = "foreign-loop-embedder-example",
        .root_module = foreign_loop_example_mod,
    });
    const foreign_loop_example_install = b.addInstallArtifact(foreign_loop_example_exe, .{});
    examples_step.dependOn(&foreign_loop_example_install.step);

    const foreign_loop_example_tests = b.addTest(.{ .root_module = foreign_loop_example_mod });
    const run_foreign_loop_example_tests = b.addRunArtifact(foreign_loop_example_tests);
    test_step.dependOn(&run_foreign_loop_example_tests.step);

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
    const bench_boringssl_dep = boringsslDependency(b, target, bench_optimize, bssl_fwd);
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
