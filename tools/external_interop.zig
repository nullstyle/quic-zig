const std = @import("std");

const default_image = "quic-zig-qns:local";
const default_runner_python = "3.12";
const default_wireshark_image = "quic-zig-interop-wireshark:local";

const case_aliases = [_]CaseAlias{
    .{ .short = "H", .long = "handshake" },
    .{ .short = "D", .long = "transfer" },
    .{ .short = "C", .long = "chacha20" },
    .{ .short = "S", .long = "retry" },
    .{ .short = "R", .long = "resumption" },
    .{ .short = "Z", .long = "zerortt" },
    .{ .short = "M", .long = "multiplexing" },
    .{ .short = "B", .long = "blackhole" },
    .{ .short = "L1", .long = "handshakeloss" },
    .{ .short = "L2", .long = "transferloss" },
    .{ .short = "C1", .long = "handshakecorruption" },
    .{ .short = "C2", .long = "transfercorruption" },
    .{ .short = "BP", .long = "rebind-port" },
    .{ .short = "U", .long = "keyupdate" },
    .{ .short = "BA", .long = "rebind-addr" },
    .{ .short = "CM", .long = "connectionmigration" },
    .{ .short = "V2", .long = "v2" },
    // The runner ships no `versionnegotiation` testcase; `v2` is the
    // version-negotiation testcase, so `V` is an alias for `v2`.
    .{ .short = "V", .long = "v2" },
    .{ .short = "LR", .long = "longrtt" },
    .{ .short = "IPV6", .long = "ipv6" },
    .{ .short = "6", .long = "ipv6" },
    .{ .short = "E", .long = "ecn" },
    .{ .short = "A", .long = "amplificationlimit" },
    // Measurement cells (the runner reports Mbps in result.json
    // rather than pass/fail): raw goodput and goodput under
    // competing cross-traffic.
    .{ .short = "G", .long = "goodput" },
    .{ .short = "CT", .long = "crosstraffic" },
};

const CaseAlias = struct {
    short: []const u8,
    long: []const u8,
};

const Config = struct {
    repo: []const u8,
    workspace: []const u8,
    path_env: []const u8 = "",
    home_env: []const u8 = "",
    zig_global_cache_env: []const u8 = "",
    image: []const u8 = default_image,
    /// Null means "whatever the Dockerfile pins", which is the
    /// only combination whose SHA-256 check can pass.
    zig_version: ?[]const u8 = null,
    dry_run: bool = false,
    runner_dir: ?[]const u8 = null,
    role: RunnerRole = .server,
    clients: []const u8 = "quic-go,ngtcp2,quiche",
    servers: []const u8 = "quic-go,ngtcp2,quiche",
    tests: []const u8 = "core+retry",
    runner_python: []const u8 = default_runner_python,
    wireshark_image: []const u8 = default_wireshark_image,
    log_dir: ?[]const u8 = null,
    json_path: ?[]const u8 = null,
    build_image: bool = false,
    scenario: ?[]const u8 = null,
    quic_go_image: ?[]const u8 = null,
    assume_compliant: []const u8 = "",
    /// Every cell must be `succeeded`: an `unsupported` cell is a
    /// failure too. For a gate whose cells this implementation is
    /// required to pass.
    strict: bool = false,
    /// A comma list of `peer:test` cells that are expected to fail. A
    /// listed cell that fails does not fail the run; one that passes
    /// does, so the list cannot go stale.
    known_failures: []const u8 = "",
    flaky: []const u8 = "",
};

const RunnerRole = enum {
    server,
    client,
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = init.io;

    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);

    const repo = cwd;
    const workspace = std.Io.Dir.path.dirname(repo) orelse ".";
    var cfg = Config{
        .repo = repo,
        .workspace = workspace,
        .path_env = init.environ_map.get("PATH") orelse "",
        .home_env = init.environ_map.get("HOME") orelse "",
        .zig_global_cache_env = init.environ_map.get("ZIG_GLOBAL_CACHE_DIR") orelse "",
    };

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    const command = args.next() orelse {
        usage();
        std.process.exit(1);
    };
    var rest: std.ArrayList([]const u8) = .empty;
    defer rest.deinit(allocator);
    while (args.next()) |arg| try rest.append(allocator, arg);

    if (std.mem.eql(u8, command, "preflight")) {
        try parsePreflight(rest.items, &cfg);
        try preflight(allocator, io, cfg, false);
        return;
    }
    if (std.mem.eql(u8, command, "build-image")) {
        try parseBuildImage(rest.items, &cfg);
        try buildImage(allocator, io, cfg);
        return;
    }
    if (std.mem.eql(u8, command, "runner")) {
        try parseRunner(allocator, rest.items, &cfg);
        if (cfg.build_image) try buildImage(allocator, io, cfg);
        try runRunner(allocator, io, cfg);
        return;
    }

    usage();
    std.debug.print("unknown command: {s}\n", .{command});
    std.process.exit(1);
}

fn usage() void {
    std.debug.print(
        \\usage:
        \\  zig build external-interop -- preflight [--image quic-zig-qns:local] [--dry-run]
        \\  zig build external-interop -- build-image [--image quic-zig-qns:local] [--zig-version <ver> (also needs matching --build-arg hashes)] [--dry-run]
        \\  zig build external-interop -- runner [--role server|client] [--build-image] [--runner-dir ../quic-interop-runner] [--clients quic-go,ngtcp2,quiche] [--servers quic-go,ngtcp2,quiche] [--tests core+retry] [--quic-go-image martenseemann/quic-go-interop@sha256:...] [--assume-compliant quic-go] [--strict] [--known-failures peer:test] [--flaky quiche:multiplexing] [--scenario "drop-rate ..."] [--python 3.12] [--wireshark-image quic-zig-interop-wireshark:local] [--dry-run]
        \\
    , .{});
}

fn parsePreflight(args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        if (try parseCommonAt(args, &i, cfg)) continue;
        std.debug.print("unknown preflight argument: {s}\n", .{args[i]});
        return error.UnknownArgument;
    }
}

fn parseBuildImage(args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (try parseCommonAt(args, &i, cfg)) continue;
        if (std.mem.eql(u8, arg, "--zig-version")) {
            i += 1;
            if (i >= args.len) return error.MissingZigVersion;
            cfg.zig_version = args[i];
            i += 1;
        } else {
            std.debug.print("unknown build-image argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
}

fn parseRunner(allocator: std.mem.Allocator, args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (try parseCommonAt(args, &i, cfg)) continue;
        if (std.mem.eql(u8, arg, "--runner-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingRunnerDir;
            cfg.runner_dir = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--role")) {
            i += 1;
            if (i >= args.len) return error.MissingRole;
            cfg.role = parseRole(args[i]) orelse return error.InvalidRole;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--clients")) {
            i += 1;
            if (i >= args.len) return error.MissingClients;
            cfg.clients = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--servers")) {
            i += 1;
            if (i >= args.len) return error.MissingServers;
            cfg.servers = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--tests")) {
            i += 1;
            if (i >= args.len) return error.MissingTests;
            cfg.tests = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--python")) {
            i += 1;
            if (i >= args.len) return error.MissingPython;
            cfg.runner_python = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--wireshark-image")) {
            i += 1;
            if (i >= args.len) return error.MissingWiresharkImage;
            cfg.wireshark_image = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--log-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingLogDir;
            cfg.log_dir = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--json")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonPath;
            cfg.json_path = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--build-image")) {
            cfg.build_image = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--scenario")) {
            i += 1;
            if (i >= args.len) return error.MissingScenario;
            cfg.scenario = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--quic-go-image")) {
            i += 1;
            if (i >= args.len) return error.MissingQuicGoImage;
            cfg.quic_go_image = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--assume-compliant")) {
            i += 1;
            if (i >= args.len) return error.MissingAssumeCompliant;
            cfg.assume_compliant = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--strict")) {
            cfg.strict = true;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--flaky")) {
            i += 1;
            if (i >= args.len) return error.MissingFlaky;
            cfg.flaky = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--known-failures")) {
            i += 1;
            if (i >= args.len) return error.MissingKnownFailures;
            cfg.known_failures = args[i];
            i += 1;
        } else {
            std.debug.print("unknown runner argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    if (cfg.runner_dir == null) {
        cfg.runner_dir = try std.Io.Dir.path.join(allocator, &.{ cfg.workspace, "quic-interop-runner" });
    }
    if (cfg.log_dir == null) {
        cfg.log_dir = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, "interop", "logs" });
    }
    if (cfg.json_path == null) {
        cfg.json_path = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, "interop", "results", defaultRunnerJsonName(cfg.role) });
    }
    cfg.runner_dir = try absolutePath(allocator, cfg.repo, cfg.runner_dir.?);
    cfg.log_dir = try absolutePath(allocator, cfg.repo, cfg.log_dir.?);
    cfg.json_path = try absolutePath(allocator, cfg.repo, cfg.json_path.?);
}

fn parseRole(role: []const u8) ?RunnerRole {
    if (std.ascii.eqlIgnoreCase(role, "server")) return .server;
    if (std.ascii.eqlIgnoreCase(role, "client")) return .client;
    return null;
}

fn defaultRunnerJsonName(role: RunnerRole) []const u8 {
    return switch (role) {
        .server => "quic-zig-server.json",
        .client => "quic-zig-client.json",
    };
}

fn absolutePath(allocator: std.mem.Allocator, base: []const u8, path: []const u8) ![]const u8 {
    if (std.Io.Dir.path.isAbsolute(path)) return path;
    return try std.Io.Dir.path.resolveAlloc(allocator, &.{ base, path });
}

fn parseCommonAt(args: []const []const u8, i: *usize, cfg: *Config) !bool {
    const arg = args[i.*];
    if (std.mem.eql(u8, arg, "--image")) {
        i.* += 1;
        if (i.* >= args.len) return error.MissingImage;
        cfg.image = args[i.*];
        i.* += 1;
        return true;
    }
    if (std.mem.eql(u8, arg, "--dry-run")) {
        cfg.dry_run = true;
        i.* += 1;
        return true;
    }
    return false;
}

fn preflight(allocator: std.mem.Allocator, io: std.Io, cfg: Config, runner: bool) !void {
    try expectPath(allocator, io, try std.Io.Dir.path.join(allocator, &.{ cfg.repo, "interop", "qns", "Dockerfile" }));

    if (!cfg.dry_run) {
        try runAndRequireZero(allocator, io, &.{ "docker", "--version" }, null);
        if (runner) {
            try runAndRequireZero(allocator, io, &.{ "uv", "--version" }, null);
        }
    }
    std.debug.print("tools ok; quic-zig image tag will be {s}\n", .{cfg.image});
}

fn buildImage(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    try preflight(allocator, io, cfg, false);
    const docker_context = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, ".zig-cache", "interop-docker-context" });
    try recreateDir(io, docker_context);

    const staged_quic_zig = try std.Io.Dir.path.join(allocator, &.{ docker_context, "quic-zig" });
    try copyTree(allocator, io, cfg.repo, staged_quic_zig);

    // Always create the package-cache directory so the Dockerfile can
    // COPY it whether or not the host has a populated Zig cache.
    const staged_cache_p = try std.Io.Dir.path.join(allocator, &.{ docker_context, "zig-cache-p" });
    try std.Io.Dir.cwd().createDirPath(io, staged_cache_p);

    // Stage the host's Zig package cache into the docker context if
    // available. The Dockerfile copies this into the container's cache
    // so `zig build` can find URL+hash dependencies locally when the
    // host has already fetched them, while fresh CI remains able to
    // fetch from the pins in build.zig.zon.
    const host_cache_p = try hostZigPackageCachePath(allocator, cfg);
    if (host_cache_p) |src| {
        if (pathExists(io, src)) {
            // Best-effort: if copyTree fails (e.g., permissions), continue;
            // the container will fall back to the URL fetch.
            copyTree(allocator, io, src, staged_cache_p) catch |err| {
                std.debug.print("note: skipping zig cache stage ({s}); container will fetch from URL\n", .{@errorName(err)});
            };
        }
    }

    // The Dockerfile owns the Zig pin, because it also owns the per-arch
    // SHA-256 that must match it. Overriding just the version from here
    // would leave the two disagreeing and fail the hash check — which is
    // exactly how this drifted to a dead pin and took the interop gate
    // down. So pass the build-arg only when a caller explicitly asks for
    // a different toolchain, and let them own the mismatch.
    var cmd: std.ArrayList([]const u8) = .empty;
    defer cmd.deinit(allocator);
    try cmd.appendSlice(allocator, &.{ "docker", "build" });
    if (cfg.zig_version) |v| {
        try cmd.appendSlice(allocator, &.{
            "--build-arg",
            try allocator.print("ZIG_VERSION={s}", .{v}),
        });
    }
    try cmd.appendSlice(allocator, &.{
        "-f",
        "quic-zig/interop/qns/Dockerfile",
        "-t",
        cfg.image,
        ".",
    });
    try runCommand(io, cmd.items, docker_context, cfg.dry_run);
}

fn hostZigPackageCachePath(allocator: std.mem.Allocator, cfg: Config) !?[]const u8 {
    if (cfg.zig_global_cache_env.len != 0) {
        return try std.Io.Dir.path.join(allocator, &.{ cfg.zig_global_cache_env, "p" });
    }
    if (cfg.home_env.len != 0) {
        return try std.Io.Dir.path.join(allocator, &.{ cfg.home_env, ".cache", "zig", "p" });
    }
    return null;
}

fn runRunner(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    try preflight(allocator, io, cfg, true);
    const runner_dir = cfg.runner_dir.?;
    try expectPath(allocator, io, runner_dir);

    const overlay = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, ".zig-cache", "interop-runner-overlay" });
    try recreateDir(io, overlay);
    try copyTree(allocator, io, runner_dir, overlay);
    if (!cfg.dry_run) try requireEngineForCompose(allocator, io, overlay);
    try patchRunnerKeylogSelection(allocator, io, overlay);
    try patchRunnerComplianceOutput(allocator, io, overlay);
    if (cfg.scenario != null) try patchRunnerScenarioOverride(allocator, io, overlay);
    if (cfg.assume_compliant.len != 0) try patchRunnerAssumeCompliant(allocator, io, overlay);
    try injectQuicZigImplementation(allocator, io, overlay, cfg.image, @tagName(cfg.role));
    if (cfg.quic_go_image) |image| {
        try overrideImplementationImage(allocator, io, overlay, "quic-go", image);
    }
    const trace_tools_dir = try prepareTraceTools(allocator, io, cfg, overlay);

    const tests = try expandCases(allocator, cfg.tests);
    defer allocator.free(tests);
    try prepareRunnerOutputs(io, cfg);

    var cmd: std.ArrayList([]const u8) = .empty;
    defer cmd.deinit(allocator);
    if (trace_tools_dir != null or cfg.scenario != null or cfg.assume_compliant.len != 0) {
        try cmd.append(allocator, "/usr/bin/env");
        if (trace_tools_dir) |dir| {
            const env_path = if (cfg.path_env.len > 0)
                try allocator.print("PATH={s}:{s}", .{ dir, cfg.path_env })
            else
                try allocator.print("PATH={s}", .{dir});
            try cmd.append(allocator, env_path);
        }
        if (cfg.assume_compliant.len != 0) {
            try cmd.append(allocator, try allocator.print("QUIC_ZIG_ASSUME_COMPLIANT={s}", .{cfg.assume_compliant}));
        }
        if (cfg.scenario) |scenario| {
            try cmd.append(allocator, try allocator.print("QUIC_ZIG_INTEROP_SCENARIO={s}", .{scenario}));
        }
    }
    try cmd.appendSlice(allocator, &.{ "uv", "run", "--python", cfg.runner_python });
    const requirements = try std.Io.Dir.path.join(allocator, &.{ overlay, "requirements.txt" });
    if (pathExists(io, requirements)) {
        try cmd.appendSlice(allocator, &.{ "--with-requirements", "requirements.txt" });
    }
    try cmd.appendSlice(allocator, &.{
        "python",
        "run.py",
    });
    switch (cfg.role) {
        .server => try cmd.appendSlice(allocator, &.{
            "-s",
            "quic-zig",
            "-c",
            cfg.clients,
        }),
        .client => try cmd.appendSlice(allocator, &.{
            "-s",
            cfg.servers,
            "-c",
            "quic-zig",
        }),
    }
    try cmd.appendSlice(allocator, &.{
        "-t",
        tests,
        "-l",
        cfg.log_dir.?,
        "-j",
        cfg.json_path.?,
        "-m",
        "-i",
        "quic-zig",
    });
    const code = try runCommandCode(io, cmd.items, overlay, cfg.dry_run);
    if (cfg.dry_run) return;

    // The runner's exit code is its count of failed test cases, so a
    // run that skipped every pair exits 0. The result file is the
    // evidence; a clean exit code alone is not a pass.
    const proven = reportEvidence(allocator, io, cfg.json_path.?, cfg.strict, cfg.known_failures, cfg.flaky, code);
    if (!proven) std.process.exit(if (code != 0) code else 1);
}

/// What the runner's result file says happened, cell by cell. A cell is
/// one test case or one measurement for one client/server pair.
const Evidence = struct {
    pairs: usize = 0,
    succeeded: usize = 0,
    /// Failed, and not on the `--known-failures` list.
    failed: usize = 0,
    /// Failed, and on the list.
    known_failed: usize = 0,
    /// The part of `known_failed` that is test cases, not measurements:
    /// the runner's exit code counts those and nothing else.
    known_failed_tests: usize = 0,
    /// On the list, and succeeded: the list is out of date.
    fixed: usize = 0,
    /// On the `--flaky` list: a cell that fails some of the time for a
    /// reason that is not ours to fix. It is run, counted and named,
    /// and changes the verdict in neither direction: a pass is not
    /// proof of anything, and a failure is not a regression.
    flaky_passed: usize = 0,
    flaky_failed: usize = 0,
    /// The part of `flaky_failed` that is test cases (see
    /// `known_failed_tests`).
    flaky_failed_tests: usize = 0,
    unsupported: usize = 0,
    /// Cells the runner never ran. When a compliance preflight fails,
    /// the runner skips the pair, writes `"result": null` for each of
    /// its test cases, leaves its measurements out, and counts none of
    /// it as a failure.
    skipped: usize = 0,

    fn cells(ev: Evidence) usize {
        return ev.succeeded + ev.failed + ev.known_failed + ev.flaky_passed + ev.flaky_failed + ev.unsupported + ev.skipped;
    }
};

/// The implementation on the other side of quic-zig in a pair.
fn peerOf(client: []const u8, server: []const u8) []const u8 {
    return if (std.mem.eql(u8, client, "quic-zig")) server else client;
}

/// True when `list` (a comma list of `peer:test`, the test by runner
/// name or by this wrapper's short selector) names this cell. The
/// `--known-failures` and `--flaky` lists share the format.
fn isListed(list: []const u8, peer: []const u8, test_name: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t\r\n");
        const colon = std.mem.findScalar(u8, entry, ':') orelse continue;
        if (!std.mem.eql(u8, entry[0..colon], peer)) continue;
        if (std.mem.eql(u8, aliasCase(entry[colon + 1 ..]), test_name)) return true;
    }
    return false;
}

fn stringItems(value: std.json.Value) ![]const std.json.Value {
    if (value != .array) return error.InvalidResultJson;
    for (value.array.items) |item| if (item != .string) return error.InvalidResultJson;
    return value.array.items;
}

/// Counts the cells of a runner result file. `known` is the
/// `--known-failures` list and `flaky` the `--flaky` list; a cell on
/// both is `error.CellListedTwice` (the two say opposite things about
/// a pass). Each cell that is not a plain success is also named, one
/// per line, in `notes` when it is given.
fn summarizeResults(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    known: []const u8,
    flaky: []const u8,
    notes: ?*std.ArrayList(u8),
) !Evidence {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidResultJson;
    const root = parsed.value.object;

    const results = root.get("results") orelse return error.InvalidResultJson;
    const measurements = root.get("measurements") orelse return error.InvalidResultJson;
    const tests = root.get("tests") orelse return error.InvalidResultJson;
    if (results != .array or measurements != .array or tests != .object) return error.InvalidResultJson;
    const clients = try stringItems(root.get("clients") orelse return error.InvalidResultJson);
    const servers = try stringItems(root.get("servers") orelse return error.InvalidResultJson);

    // The runner writes one row per pair: for each client, each server.
    const pairs = results.array.items.len;
    if (pairs != clients.len * servers.len) return error.InvalidResultJson;
    var ev: Evidence = .{ .pairs = pairs };

    // `tests` names the test cases and the measurements together, and a
    // pair's `results` row always has one cell per test case, so the
    // difference is how many measurements each pair owes. A measurement
    // that did not run is absent, not null.
    var tests_per_pair: usize = 0;
    var measurement_cells: usize = 0;
    for ([_]std.json.Value{ results, measurements }, [_]bool{ true, false }) |table, is_test| {
        for (table.array.items, 0..) |row, r| {
            if (row != .array) return error.InvalidResultJson;
            if (r >= pairs) return error.InvalidResultJson;
            const peer = peerOf(clients[r / servers.len].string, servers[r % servers.len].string);
            if (is_test) tests_per_pair = row.array.items.len else measurement_cells += row.array.items.len;
            for (row.array.items) |cell| {
                if (cell != .object) return error.InvalidResultJson;
                const abbr = cell.object.get("abbr") orelse return error.InvalidResultJson;
                if (abbr != .string) return error.InvalidResultJson;
                const described = tests.object.get(abbr.string) orelse return error.InvalidResultJson;
                if (described != .object) return error.InvalidResultJson;
                const name = described.object.get("name") orelse return error.InvalidResultJson;
                if (name != .string) return error.InvalidResultJson;
                const listed = isListed(known, peer, name.string);
                const unstable = isListed(flaky, peer, name.string);
                if (listed and unstable) return error.CellListedTwice;

                const result = cell.object.get("result") orelse return error.InvalidResultJson;
                const outcome: []const u8 = switch (result) {
                    .null => "skipped",
                    .string => |s| s,
                    else => return error.InvalidResultJson,
                };
                var label: []const u8 = outcome;
                if (std.mem.eql(u8, outcome, "succeeded")) {
                    if (unstable) {
                        ev.flaky_passed += 1;
                        label = "succeeded (flaky)";
                    } else {
                        ev.succeeded += 1;
                        if (!listed) continue;
                        ev.fixed += 1;
                        label = "succeeded, but is on the known-failures list";
                    }
                } else if (std.mem.eql(u8, outcome, "failed")) {
                    if (unstable) {
                        ev.flaky_failed += 1;
                        if (is_test) ev.flaky_failed_tests += 1;
                        label = "failed (flaky)";
                    } else if (listed) {
                        ev.known_failed += 1;
                        if (is_test) ev.known_failed_tests += 1;
                        label = "failed (known)";
                    } else ev.failed += 1;
                } else if (std.mem.eql(u8, outcome, "unsupported")) {
                    ev.unsupported += 1;
                } else if (std.mem.eql(u8, outcome, "skipped")) {
                    ev.skipped += 1;
                } else return error.InvalidResultJson;
                if (notes) |out| {
                    const line = try allocator.print("  {s}:{s}: {s}\n", .{ peer, name.string, label });
                    defer allocator.free(line);
                    try out.appendSlice(allocator, line);
                }
            }
        }
    }
    const measurements_per_pair = tests.object.count() -| tests_per_pair;
    ev.skipped += (pairs * measurements_per_pair) -| measurement_cells;
    return ev;
}

/// Why this run is not a pass, or null when the evidence holds.
fn evidenceProblem(ev: Evidence, strict: bool) ?[]const u8 {
    if (ev.cells() == 0) return "the result file has no cells: nothing ran";
    if (ev.skipped != 0) return "the runner skipped cells: a failed compliance preflight skips the pair and still exits 0";
    if (ev.failed != 0) return "cells failed";
    if (ev.succeeded == 0) return "no cell succeeded";
    if (ev.fixed != 0) return "a known failure passed: remove it from --known-failures";
    if (strict and ev.unsupported != 0) return "--strict needs every cell to succeed, and some were unsupported";
    return null;
}

/// The runner exits with its count of failed test cases (modulo 256).
/// The result file must account for that number: none, or exactly the
/// known failures plus the flaky cells that failed this time. Anything
/// else means the two disagree.
fn exitCodeExplained(ev: Evidence, runner_exit_code: u8) bool {
    return runner_exit_code == @as(u8, @truncate(ev.known_failed_tests + ev.flaky_failed_tests));
}

/// Prints the line that says what the run proved, names each cell that
/// is not a plain success, and returns whether the run is a pass.
fn reportEvidence(
    allocator: std.mem.Allocator,
    io: std.Io,
    json_path: []const u8,
    strict: bool,
    known: []const u8,
    flaky: []const u8,
    runner_exit_code: u8,
) bool {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, json_path, allocator, .limited(64 * 1024 * 1024)) catch |err| {
        std.debug.print("interop evidence: NOT A PASS: no result file at {s} ({s})\n", .{ json_path, @errorName(err) });
        return false;
    };
    defer allocator.free(bytes);
    var notes: std.ArrayList(u8) = .empty;
    defer notes.deinit(allocator);
    const ev = summarizeResults(allocator, bytes, known, flaky, &notes) catch |err| {
        std.debug.print("interop evidence: NOT A PASS: cannot read {s} ({s})\n", .{ json_path, @errorName(err) });
        return false;
    };
    std.debug.print(
        "interop evidence: pairs={d} cells={d} succeeded={d} failed={d} known_failed={d} unsupported={d} skipped={d} flaky_passed={d} flaky_failed={d}\n{s}",
        .{ ev.pairs, ev.cells(), ev.succeeded, ev.failed, ev.known_failed, ev.unsupported, ev.skipped, ev.flaky_passed, ev.flaky_failed, notes.items },
    );
    if (evidenceProblem(ev, strict)) |problem| {
        std.debug.print("interop evidence: NOT A PASS: {s}\n", .{problem});
        return false;
    }
    if (!exitCodeExplained(ev, runner_exit_code)) {
        std.debug.print(
            "interop evidence: NOT A PASS: the runner exited {d}, and the result file accounts for {d} failed test cases\n",
            .{ runner_exit_code, ev.known_failed_tests + ev.flaky_failed_tests },
        );
        return false;
    }
    return true;
}

/// The first Docker Engine release that accepts `interface_name` on a
/// compose service network.
const interface_name_engine: [2]u32 = .{ 28, 1 };

/// True when `version` ("28.0.4", "29.4.0-rc.1") is at least
/// `major.minor`; null when it does not parse.
fn engineAtLeast(version: []const u8, min: [2]u32) ?bool {
    var it = std.mem.splitScalar(u8, version, '.');
    const major = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    if (major != min[0]) return major > min[0];
    return minor >= min[1];
}

/// The pinned runner names the simulator's interfaces with
/// `interface_name` in docker-compose.yml (its fix for the interface
/// order of Docker Engine 28). An older daemon refuses to create the
/// `sim` container, the runner reads that as "not compliant", skips the
/// pair, and exits 0. GitHub's ubuntu image carried Engine 28.0.4, so
/// both interop workflows ran zero tests from 2026-07-05 to 2026-10-03
/// and showed green. Say so up front instead.
fn requireEngineForCompose(allocator: std.mem.Allocator, io: std.Io, overlay: []const u8) !void {
    const compose_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "docker-compose.yml" });
    const compose = try std.Io.Dir.cwd().readFileAlloc(io, compose_path, allocator, .limited(1024 * 1024));
    defer allocator.free(compose);
    if (std.mem.find(u8, compose, "interface_name") == null) return;

    const argv = [_][]const u8{ "docker", "version", "--format", "{{.Server.Version}}" };
    const result = std.process.run(allocator, io, .{
        .argv = &argv,
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch |err| {
        std.debug.print("could not run: ", .{});
        printCommand(&argv);
        std.debug.print("  ({s})\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    const version = std.mem.trim(u8, result.stdout, " \t\r\n");
    const ok = engineAtLeast(version, interface_name_engine) orelse {
        std.debug.print("note: cannot read the Docker Engine version (\"{s}\"); the runner needs {d}.{d} or later\n", .{ version, interface_name_engine[0], interface_name_engine[1] });
        if (result.stderr.len > 0) std.debug.print("{s}\n", .{result.stderr});
        return;
    };
    if (ok) return;
    std.debug.print(
        \\Docker Engine {s} is too old for this quic-interop-runner.
        \\Its docker-compose.yml uses `interface_name`, which needs Engine {d}.{d} or later.
        \\With an older Engine no container starts and the runner skips every pair.
        \\In GitHub Actions, install a newer Engine with docker/setup-docker-action.
        \\
    , .{ version, interface_name_engine[0], interface_name_engine[1] });
    std.process.exit(1);
}

fn prepareTraceTools(allocator: std.mem.Allocator, io: std.Io, cfg: Config, overlay: []const u8) !?[]const u8 {
    if (commandAvailable(allocator, io, cfg.path_env, "tshark") and commandAvailable(allocator, io, cfg.path_env, "editcap")) {
        return null;
    }

    std.debug.print("host tshark/editcap not found; using Docker Wireshark tools image {s}\n", .{cfg.wireshark_image});
    try ensureWiresharkImage(allocator, io, cfg);

    const bin_dir = try std.Io.Dir.path.join(allocator, &.{ overlay, ".quic-zig-tools-bin" });
    if (cfg.dry_run) return bin_dir;

    try std.Io.Dir.cwd().createDirPath(io, bin_dir);
    try writeDockerToolShim(allocator, io, bin_dir, "tshark", cfg);
    try writeDockerToolShim(allocator, io, bin_dir, "editcap", cfg);
    return bin_dir;
}

fn ensureWiresharkImage(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    if (!cfg.dry_run and dockerImageExists(allocator, io, cfg.wireshark_image)) return;

    const dockerfile = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, "interop", "qns-tools", "Dockerfile" });
    const context = try std.Io.Dir.path.join(allocator, &.{ cfg.repo, "interop", "qns-tools" });
    const cmd = [_][]const u8{
        "docker",
        "build",
        "-f",
        dockerfile,
        "-t",
        cfg.wireshark_image,
        ".",
    };
    try runCommand(io, &cmd, context, cfg.dry_run);
}

fn dockerImageExists(allocator: std.mem.Allocator, io: std.Io, image: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "docker", "image", "inspect", image },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn writeDockerToolShim(allocator: std.mem.Allocator, io: std.Io, bin_dir: []const u8, tool: []const u8, cfg: Config) !void {
    const path = try std.Io.Dir.path.join(allocator, &.{ bin_dir, tool });
    const script = try allocator.print(
        \\#!/bin/sh
        \\exec docker run --rm -i -v '{s}:{s}:rw' -v /tmp:/tmp:rw -v /private:/private:rw --entrypoint {s} {s} "$@"
        \\
    , .{ cfg.workspace, cfg.workspace, tool, cfg.wireshark_image });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = script });
    try runAndRequireZero(allocator, io, &.{ "chmod", "+x", path }, null);
}

fn commandAvailable(allocator: std.mem.Allocator, io: std.Io, path_env: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, path_env, std.Io.Dir.path.delimiter);
    while (it.next()) |dir| {
        const candidate = std.Io.Dir.path.join(allocator, &.{ dir, name }) catch continue;
        defer allocator.free(candidate);
        std.Io.Dir.accessAbsolute(io, candidate, .{}) catch continue;
        return true;
    }
    return false;
}

fn recreateDir(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().deleteTree(io, path);
    try std.Io.Dir.cwd().createDirPath(io, path);
}

fn prepareRunnerOutputs(io: std.Io, cfg: Config) !void {
    if (cfg.dry_run) return;
    try std.Io.Dir.cwd().deleteTree(io, cfg.log_dir.?);
    try ensureParentDir(io, cfg.log_dir.?);

    // The result file is read back as the evidence of this run. One
    // left over from an earlier run would be read as this run's result
    // if the runner stopped before it wrote a new one.
    std.Io.Dir.cwd().deleteFile(io, cfg.json_path.?) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    // The interop runner owns the log directory and fails fast if it
    // already exists. Only prepare the JSON parent when doing so does not
    // recreate that same log directory.
    const json_parent = std.Io.Dir.path.dirname(cfg.json_path.?) orelse return;
    if (!std.mem.eql(u8, json_parent, cfg.log_dir.?)) {
        try std.Io.Dir.cwd().createDirPath(io, json_parent);
    }
}

fn copyTree(allocator: std.mem.Allocator, io: std.Io, source_path: []const u8, dest_path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, dest_path);
    var src = try std.Io.Dir.openDirAbsolute(io, source_path, .{ .iterate = true });
    defer src.close(io);
    var dst = try std.Io.Dir.openDirAbsolute(io, dest_path, .{});
    defer dst.close(io);

    var walker = try src.walkSelectively(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (ignoreCopyPath(entry.path)) {
            continue;
        }
        switch (entry.kind) {
            .directory => {
                try dst.createDirPath(io, entry.path);
                try walker.enter(io, entry);
            },
            .file, .sym_link => {
                try std.Io.Dir.copyFile(src, entry.path, dst, entry.path, io, .{ .make_path = true });
            },
            else => {},
        }
    }
}

fn ignoreCopyPath(path: []const u8) bool {
    const exact = [_][]const u8{
        ".git",
        ".zig-cache",
        "zig-cache",
        "zig-out",
        ".cache",
        "zig-pkg",
        "__pycache__",
        "interop/logs",
        "interop/results",
    };
    for (exact) |name| {
        if (pathHasPrefix(path, name)) return true;
    }
    if (std.mem.endsWith(u8, path, ".pyc")) return true;
    return false;
}

fn isPathSep(byte: u8) bool {
    return byte == '/' or byte == '\\';
}

fn pathHasPrefix(path: []const u8, prefix: []const u8) bool {
    if (path.len < prefix.len) return false;
    for (prefix, 0..) |byte, i| {
        if (isPathSep(byte)) {
            if (!isPathSep(path[i])) return false;
        } else if (path[i] != byte) {
            return false;
        }
    }
    return path.len == prefix.len or isPathSep(path[prefix.len]);
}

fn injectQuicZigImplementation(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
    image: []const u8,
    role: []const u8,
) !void {
    const impl_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "implementations_quic.json" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, impl_path, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidImplementationsJson;

    var quic = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try quic.put(allocator, "image", .{ .string = image });
    try quic.put(allocator, "url", .{ .string = "https://github.com/nullstyle/quic-zig" });
    try quic.put(allocator, "role", .{ .string = role });
    try parsed.value.object.put(allocator, "quic-zig", .{ .object = quic });

    const rendered = try allocator.print("{f}\n", .{std.json.fmt(parsed.value, .{ .whitespace = .indent_2 })});
    defer allocator.free(rendered);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = impl_path, .data = rendered });
}

fn overrideImplementationImage(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
    name: []const u8,
    image: []const u8,
) !void {
    const impl_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "implementations_quic.json" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, impl_path, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidImplementationsJson;
    const impl = parsed.value.object.getPtr(name) orelse return error.UnknownImplementation;
    if (impl.* != .object) return error.InvalidImplementationsJson;
    try impl.object.put(allocator, "image", .{ .string = image });

    const rendered = try allocator.print("{f}\n", .{std.json.fmt(parsed.value, .{ .whitespace = .indent_2 })});
    defer allocator.free(rendered);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = impl_path, .data = rendered });
}

fn patchRunnerKeylogSelection(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
) !void {
    const testcase_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "testcase.py" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, testcase_path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(bytes);

    const needle =
        \\    def _keylog_file(self) -> str:
        \\        if self._is_valid_keylog(self._client_keylog_file):
        \\            logging.debug("Using the client's key log file.")
        \\            return self._client_keylog_file
        \\        elif self._is_valid_keylog(self._server_keylog_file):
        \\            logging.debug("Using the server's key log file.")
        \\            return self._server_keylog_file
        \\        logging.debug("No key log file found.")
    ;
    const replacement =
        \\    def _keylog_file(self) -> str:
        \\        client_valid = self._is_valid_keylog(self._client_keylog_file)
        \\        server_valid = self._is_valid_keylog(self._server_keylog_file)
        \\        if client_valid and server_valid:
        \\            merged = self._client_keylog_file + ".combined"
        \\            try:
        \\                if (
        \\                    not os.path.isfile(merged)
        \\                    or os.path.getmtime(merged)
        \\                    < max(
        \\                        os.path.getmtime(self._client_keylog_file),
        \\                        os.path.getmtime(self._server_keylog_file),
        \\                    )
        \\                ):
        \\                    with open(merged, "w") as out:
        \\                        with open(self._client_keylog_file, "r") as client:
        \\                            shutil.copyfileobj(client, out)
        \\                        out.write("\n")
        \\                        with open(self._server_keylog_file, "r") as server:
        \\                            shutil.copyfileobj(server, out)
        \\                logging.debug("Using combined client/server key log file.")
        \\                return merged
        \\            except OSError as e:
        \\                logging.debug("Failed to merge key log files: %s", e)
        \\        if client_valid:
        \\            logging.debug("Using the client's key log file.")
        \\            return self._client_keylog_file
        \\        elif server_valid:
        \\            logging.debug("Using the server's key log file.")
        \\            return self._server_keylog_file
        \\        logging.debug("No key log file found.")
    ;

    if (std.mem.find(u8, bytes, replacement) != null) return;
    const idx = std.mem.find(u8, bytes, needle) orelse return error.UnsupportedRunnerKeylogMethod;
    var patched: std.ArrayList(u8) = .empty;
    defer patched.deinit(allocator);
    try patched.appendSlice(allocator, bytes[0..idx]);
    try patched.appendSlice(allocator, replacement);
    try patched.appendSlice(allocator, bytes[idx + needle.len ..]);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = testcase_path, .data = patched.items });
}

fn patchRunnerScenarioOverride(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
) !void {
    const interop_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "interop.py" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, interop_path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(bytes);

    const needle =
        \\        ).format(test.scenario())
    ;
    const replacement =
        \\        ).format(os.environ.get("QUIC_ZIG_INTEROP_SCENARIO", test.scenario()))
    ;
    if (std.mem.find(u8, bytes, replacement) != null) return;
    const idx = std.mem.find(u8, bytes, needle) orelse return error.UnsupportedRunnerScenarioFormat;
    var patched: std.ArrayList(u8) = .empty;
    defer patched.deinit(allocator);
    try patched.appendSlice(allocator, bytes[0..idx]);
    try patched.appendSlice(allocator, replacement);
    try patched.appendSlice(allocator, bytes[idx + needle.len ..]);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = interop_path, .data = patched.items });
}

fn patchRunnerAssumeCompliant(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
) !void {
    const interop_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "interop.py" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, interop_path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(bytes);

    const needle =
        \\    def _check_impl_is_compliant(self, name: str, role: Perspective) -> bool:
        \\        """Check if an implementation returns UNSUPPORTED for unknown test cases."""
    ;
    const replacement =
        \\    def _check_impl_is_compliant(self, name: str, role: Perspective) -> bool:
        \\        """Check if an implementation returns UNSUPPORTED for unknown test cases."""
        \\        if name in set(filter(None, os.environ.get("QUIC_ZIG_ASSUME_COMPLIANT", "").split(","))):
        \\            logging.debug("%s %s compliance assumed by wrapper.", name, role.name.lower())
        \\            self.compliant.setdefault(name, {})[role] = True
        \\            return True
    ;
    if (std.mem.find(u8, bytes, replacement) != null) return;
    const idx = std.mem.find(u8, bytes, needle) orelse return error.UnsupportedRunnerComplianceMethod;
    var patched: std.ArrayList(u8) = .empty;
    defer patched.deinit(allocator);
    try patched.appendSlice(allocator, bytes[0..idx]);
    try patched.appendSlice(allocator, replacement);
    try patched.appendSlice(allocator, bytes[idx + needle.len ..]);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = interop_path, .data = patched.items });
}

/// When a compliance preflight fails, the runner prints "<name> not
/// compliant" and logs what docker compose actually said at debug
/// level, which nothing shows. In CI the hidden text was a Docker
/// Engine error, and it stayed hidden for three months. Raise it to
/// error level, so the reason is in the log next to the verdict.
fn patchRunnerComplianceOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
) !void {
    const interop_path = try std.Io.Dir.path.join(allocator, &.{ overlay, "interop.py" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, interop_path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(bytes);

    const needle =
        \\logging.debug("%s", output.stdout.decode("utf-8", errors="replace"))
    ;
    const replacement =
        \\logging.error("%s", output.stdout.decode("utf-8", errors="replace"))
    ;
    if (std.mem.find(u8, bytes, needle) == null) {
        if (std.mem.find(u8, bytes, replacement) != null) return;
        return error.UnsupportedRunnerComplianceLogging;
    }
    const patched = try std.mem.replaceOwned(u8, allocator, bytes, needle, replacement);
    defer allocator.free(patched);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = interop_path, .data = patched });
}

fn expandCases(allocator: std.mem.Allocator, spec: []const u8) ![]u8 {
    if (std.mem.eql(u8, spec, "core")) {
        return try allocator.dupe(u8, "handshake,transfer,chacha20,resumption,zerortt,multiplexing");
    }
    if (std.mem.eql(u8, spec, "core+retry")) {
        return try allocator.dupe(u8, "handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing");
    }
    if (std.mem.eql(u8, spec, "loss")) {
        return try allocator.dupe(u8, "handshakeloss,transferloss");
    }
    if (std.mem.eql(u8, spec, "loss+corruption")) {
        return try allocator.dupe(u8, "handshakeloss,transferloss,handshakecorruption,transfercorruption");
    }
    if (std.mem.eql(u8, spec, "recovery")) {
        return try allocator.dupe(u8, "handshakeloss,transferloss,blackhole,rebind-port");
    }

    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, spec, ',');
    var first = true;
    while (it.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t\r\n");
        if (item.len == 0) continue;
        if (!first) try out.append(allocator, ',');
        first = false;
        try out.appendSlice(allocator, aliasCase(item));
    }
    return try out.toOwnedSlice(allocator);
}

fn aliasCase(item: []const u8) []const u8 {
    for (case_aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(item, alias.short)) return alias.long;
    }
    return item;
}

fn expectPath(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    _ = allocator;
    std.Io.Dir.accessAbsolute(io, path, .{}) catch |err| {
        std.debug.print("missing: {s}\n", .{path});
        return err;
    };
}

fn pathExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.Io.Dir.path.dirname(path) orelse return;
    try std.Io.Dir.cwd().createDirPath(io, parent);
}

fn runCommand(io: std.Io, argv: []const []const u8, cwd: []const u8, dry_run: bool) !void {
    const code = try runCommandCode(io, argv, cwd, dry_run);
    if (code != 0) std.process.exit(code);
}

/// Like `runCommand`, but hands the exit code back, so the caller can
/// still report on what the command left behind.
fn runCommandCode(io: std.Io, argv: []const []const u8, cwd: []const u8, dry_run: bool) !u8 {
    printCommand(argv);
    if (dry_run) return 0;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code,
        .signal, .stopped, .unknown => 1,
    };
}

fn runAndRequireZero(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, cwd: ?[]const u8) !void {
    const result = std.process.run(allocator, io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch |err| {
        // The executable couldn't even be spawned (most commonly it isn't
        // installed or isn't on PATH). Report it cleanly and exit — a
        // preflight exists to surface missing prerequisites, not to
        // stack-trace on them.
        std.debug.print("could not run: ", .{});
        printCommand(argv);
        std.debug.print("  ({s}) — is '{s}' installed and on PATH?\n", .{ @errorName(err), argv[0] });
        std.process.exit(1);
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("command failed: ", .{});
    printCommand(argv);
    if (result.stderr.len > 0) std.debug.print("{s}\n", .{result.stderr});
    std.process.exit(1);
}

fn printCommand(argv: []const []const u8) void {
    std.debug.print("+", .{});
    for (argv) |arg| std.debug.print(" {s}", .{arg});
    std.debug.print("\n", .{});
}

test "case expansion supports presets and aliases" {
    const allocator = std.testing.allocator;
    const core = try expandCases(allocator, "H,D,C");
    defer allocator.free(core);
    try std.testing.expectEqualStrings("handshake,transfer,chacha20", core);

    const preset = try expandCases(allocator, "core+retry");
    defer allocator.free(preset);
    try std.testing.expect(std.mem.find(u8, preset, "retry") != null);

    const loss = try expandCases(allocator, "loss");
    defer allocator.free(loss);
    try std.testing.expectEqualStrings("handshakeloss,transferloss", loss);

    const recovery = try expandCases(allocator, "L1,L2,B,BP");
    defer allocator.free(recovery);
    try std.testing.expectEqualStrings("handshakeloss,transferloss,blackhole,rebind-port", recovery);

    // New aliases for runner testcases that previously had no short form.
    const extras = try expandCases(allocator, "BA,CM,V2,V,LR,IPV6,6,E,A");
    defer allocator.free(extras);
    try std.testing.expectEqualStrings(
        "rebind-addr,connectionmigration,v2,v2,longrtt,ipv6,ipv6,ecn,amplificationlimit",
        extras,
    );
}

test "runner paths are normalized to absolute paths" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .repo = "/tmp/quic",
        .workspace = "/tmp",
    };
    const args = [_][]const u8{
        "--runner-dir",
        "../quic-interop-runner",
        "--log-dir",
        "interop/logs",
        "--json",
        "interop/results/out.json",
        "--quic-go-image",
        "martenseemann/quic-go-interop@sha256:37db",
        "--scenario",
        "drop-rate --delay=15ms",
        "--assume-compliant",
        "quic-go",
    };
    try parseRunner(allocator, &args, &cfg);
    defer allocator.free(cfg.runner_dir.?);
    defer allocator.free(cfg.log_dir.?);
    defer allocator.free(cfg.json_path.?);

    try std.testing.expect(std.Io.Dir.path.isAbsolute(cfg.runner_dir.?));
    try std.testing.expect(std.Io.Dir.path.isAbsolute(cfg.log_dir.?));
    try std.testing.expect(std.Io.Dir.path.isAbsolute(cfg.json_path.?));
    try std.testing.expect(std.mem.endsWith(u8, cfg.runner_dir.?, "quic-interop-runner"));
    const log_tail = try std.Io.Dir.path.join(allocator, &.{ "interop", "logs" });
    defer allocator.free(log_tail);
    const json_tail = try std.Io.Dir.path.join(allocator, &.{ "interop", "results", "out.json" });
    defer allocator.free(json_tail);
    try std.testing.expect(std.mem.endsWith(u8, cfg.log_dir.?, log_tail));
    try std.testing.expect(std.mem.endsWith(u8, cfg.json_path.?, json_tail));
    try std.testing.expectEqualStrings("drop-rate --delay=15ms", cfg.scenario.?);
    try std.testing.expectEqualStrings("martenseemann/quic-go-interop@sha256:37db", cfg.quic_go_image.?);
    try std.testing.expectEqualStrings("quic-go", cfg.assume_compliant);
}

test "evidence: a skipped pair is not a pass" {
    // Verbatim from the hard gate on the v0.23.0 release commit (run
    // 37111206247, 2026-10-03): the preflight failed, the runner skipped
    // the only pair, exited 0, and the workflow showed green.
    const skipped_run =
        \\{"start_time": 1791017942.8862, "end_time": 1791017946.71258, "log_dir": "/home/runner/work/quic-zig/quic-zig/interop-logs/quic-go-hard", "servers": ["quic-go"], "clients": ["quic-zig"], "urls": {"quic-zig": "https://github.com/nullstyle/quic-zig", "quic-go": "https://github.com/quic-go/quic-go"}, "tests": {"H": {"name": "handshake", "desc": "Handshake completes successfully."}, "DC": {"name": "transfer", "desc": "Stream data is being sent and received correctly. Connection close completes with a zero error code."}}, "quic_version": "0x1", "results": [[{"abbr": "H", "name": "handshake", "result": null}, {"abbr": "DC", "name": "transfer", "result": null}]], "measurements": [[]]}
    ;
    const ev = try summarizeResults(std.testing.allocator, skipped_run, "", "", null);
    try std.testing.expectEqual(@as(usize, 1), ev.pairs);
    try std.testing.expectEqual(@as(usize, 2), ev.cells());
    try std.testing.expectEqual(@as(usize, 2), ev.skipped);
    try std.testing.expectEqual(@as(usize, 0), ev.succeeded);
    try std.testing.expect(evidenceProblem(ev, false) != null);
    try std.testing.expect(evidenceProblem(ev, true) != null);
}

test "evidence: a skipped measurement is absent, and still counted" {
    // Two pairs, one test case and one measurement each. The second
    // pair was skipped: its test cell is null and its measurement row
    // is empty.
    const half_run =
        \\{"servers": ["quic-zig"], "clients": ["quic-go", "quiche"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}, "G": {"name": "goodput", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}],
        \\             [{"abbr": "H", "name": "handshake", "result": null}]],
        \\ "measurements": [[{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9000 kbps"}], []]}
    ;
    const ev = try summarizeResults(std.testing.allocator, half_run, "", "", null);
    try std.testing.expectEqual(@as(usize, 2), ev.pairs);
    try std.testing.expectEqual(@as(usize, 4), ev.cells());
    try std.testing.expectEqual(@as(usize, 2), ev.succeeded);
    try std.testing.expectEqual(@as(usize, 2), ev.skipped);
    try std.testing.expect(evidenceProblem(ev, false) != null);
}

test "evidence: a pass needs every cell run and none failed" {
    const allocator = std.testing.allocator;
    const passed =
        \\{"servers": ["quic-go"], "clients": ["quic-zig"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}, "DC": {"name": "transfer", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"},
        \\              {"abbr": "DC", "name": "transfer", "result": "succeeded"}]],
        \\ "measurements": [[]]}
    ;
    const ok = try summarizeResults(allocator, passed, "", "", null);
    try std.testing.expectEqual(@as(usize, 2), ok.succeeded);
    try std.testing.expectEqual(@as(usize, 0), ok.skipped);
    try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ok, false));
    try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ok, true));

    // A failed measurement is not in the runner's exit code. It is a
    // failure here.
    const failed_measurement =
        \\{"servers": ["quic-zig"], "clients": ["quic-go"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}, "G": {"name": "goodput", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}]],
        \\ "measurements": [[{"name": "goodput", "abbr": "G", "result": "failed", "details": ""}]]}
    ;
    const bad = try summarizeResults(allocator, failed_measurement, "", "", null);
    try std.testing.expectEqual(@as(usize, 1), bad.failed);
    try std.testing.expect(evidenceProblem(bad, false) != null);

    // `unsupported` is a peer's right in a matrix, and a failure in a
    // gate this implementation must pass.
    const unsupported =
        \\{"servers": ["quic-go"], "clients": ["quic-zig"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}, "DC": {"name": "transfer", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"},
        \\              {"abbr": "DC", "name": "transfer", "result": "unsupported"}]],
        \\ "measurements": [[]]}
    ;
    const partial = try summarizeResults(allocator, unsupported, "", "", null);
    try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(partial, false));
    try std.testing.expect(evidenceProblem(partial, true) != null);

    // Nothing but `unsupported` proves nothing.
    try std.testing.expect(evidenceProblem(.{ .pairs = 1, .unsupported = 2 }, false) != null);
    // No cells at all proves nothing, and says so.
    try std.testing.expectEqualStrings("the result file has no cells: nothing ran", evidenceProblem(.{}, false).?);
    try std.testing.expectError(error.InvalidResultJson, summarizeResults(allocator, "{}", "", "", null));
}

test "evidence: a known failure does not fail the run, and cannot go stale" {
    const allocator = std.testing.allocator;
    // The first real matrix (2026-10-03, quic-zig as server), with the
    // descriptions cut: 19 cells succeeded, quiche does not support
    // chacha20, and quiche x multiplexing failed.
    const matrix =
        \\{"servers": ["quic-zig"], "clients": ["quic-go", "ngtcp2", "quiche"], "tests": {"H": {"name": "handshake", "desc": ""}, "DC": {"name": "transfer", "desc": ""}, "C20": {"name": "chacha20", "desc": ""}, "M": {"name": "multiplexing", "desc": ""}, "L2": {"name": "transferloss", "desc": ""}, "B": {"name": "blackhole", "desc": ""}, "G": {"name": "goodput", "desc": ""}}, "quic_version": "0x1", "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}, {"abbr": "DC", "name": "transfer", "result": "succeeded"}, {"abbr": "C20", "name": "chacha20", "result": "succeeded"}, {"abbr": "M", "name": "multiplexing", "result": "succeeded"}, {"abbr": "L2", "name": "transferloss", "result": "succeeded"}, {"abbr": "B", "name": "blackhole", "result": "succeeded"}], [{"abbr": "H", "name": "handshake", "result": "succeeded"}, {"abbr": "DC", "name": "transfer", "result": "succeeded"}, {"abbr": "C20", "name": "chacha20", "result": "succeeded"}, {"abbr": "M", "name": "multiplexing", "result": "succeeded"}, {"abbr": "L2", "name": "transferloss", "result": "succeeded"}, {"abbr": "B", "name": "blackhole", "result": "succeeded"}], [{"abbr": "H", "name": "handshake", "result": "succeeded"}, {"abbr": "DC", "name": "transfer", "result": "succeeded"}, {"abbr": "C20", "name": "chacha20", "result": "unsupported"}, {"abbr": "M", "name": "multiplexing", "result": "failed"}, {"abbr": "L2", "name": "transferloss", "result": "succeeded"}, {"abbr": "B", "name": "blackhole", "result": "succeeded"}]], "measurements": [[{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9287 kbps"}], [{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9096 kbps"}], [{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9073 kbps"}]]}
    ;

    // No list: the failed cell fails the run, and the runner's exit
    // code of 1 says the same.
    const plain = try summarizeResults(allocator, matrix, "", "", null);
    try std.testing.expectEqual(@as(usize, 3), plain.pairs);
    try std.testing.expectEqual(@as(usize, 21), plain.cells());
    try std.testing.expectEqual(@as(usize, 19), plain.succeeded);
    try std.testing.expectEqual(@as(usize, 1), plain.failed);
    try std.testing.expectEqual(@as(usize, 1), plain.unsupported);
    try std.testing.expect(evidenceProblem(plain, false) != null);

    // Listed, by runner name or by the wrapper's short selector: the
    // run passes, the cell is still counted and named, and the runner's
    // exit code of 1 is accounted for.
    for ([_][]const u8{ "quiche:multiplexing", "ngtcp2:ecn, quiche:M" }) |known| {
        var notes: std.ArrayList(u8) = .empty;
        defer notes.deinit(allocator);
        const ev = try summarizeResults(allocator, matrix, known, "", &notes);
        try std.testing.expectEqual(@as(usize, 21), ev.cells());
        try std.testing.expectEqual(@as(usize, 0), ev.failed);
        try std.testing.expectEqual(@as(usize, 1), ev.known_failed);
        try std.testing.expectEqual(@as(usize, 1), ev.known_failed_tests);
        try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ev, false));
        try std.testing.expect(exitCodeExplained(ev, 1));
        try std.testing.expect(!exitCodeExplained(ev, 0));
        try std.testing.expect(!exitCodeExplained(ev, 2));
        try std.testing.expectEqualStrings(
            "  quiche:chacha20: unsupported\n  quiche:multiplexing: failed (known)\n",
            notes.items,
        );
    }

    // The same test for another peer is not covered by the entry.
    const other_peer = try summarizeResults(allocator, matrix, "ngtcp2:multiplexing", "", null);
    try std.testing.expectEqual(@as(usize, 1), other_peer.failed);
    try std.testing.expectEqual(@as(usize, 1), other_peer.fixed);

    // A listed cell that passes fails the run: take it off the list.
    const stale = try summarizeResults(allocator, matrix, "quiche:multiplexing,quic-go:handshake", "", null);
    try std.testing.expectEqual(@as(usize, 1), stale.fixed);
    try std.testing.expectEqualStrings(
        "a known failure passed: remove it from --known-failures",
        evidenceProblem(stale, false).?,
    );

    // With no list, the runner's exit code must be 0 for a pass.
    try std.testing.expect(exitCodeExplained(.{ .pairs = 1, .succeeded = 2 }, 0));
    try std.testing.expect(!exitCodeExplained(.{ .pairs = 1, .succeeded = 2 }, 3));
}

test "evidence: a flaky cell is run, counted and named, and decides nothing" {
    const allocator = std.testing.allocator;
    // The real matrix of the test above: quiche x multiplexing failed.
    // That cell fails some of the time against every server it was
    // measured with (2026-10-03, one machine: 4 of 10 against quic-zig,
    // 4 of 8 against quic-go and 2 of 8 against ngtcp2 with no quic-zig
    // in the pair): the fault is in quiche's test client. A
    // known-failures entry is wrong for it, because a run in which it
    // passes is a failed run under that ratchet.
    const failed_run =
        \\{"servers": ["quic-zig"], "clients": ["quic-go", "quiche"], "tests": {"H": {"name": "handshake", "desc": ""}, "M": {"name": "multiplexing", "desc": ""}, "G": {"name": "goodput", "desc": ""}}, "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}, {"abbr": "M", "name": "multiplexing", "result": "succeeded"}], [{"abbr": "H", "name": "handshake", "result": "succeeded"}, {"abbr": "M", "name": "multiplexing", "result": "failed"}]], "measurements": [[{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9287 kbps"}], [{"name": "goodput", "abbr": "G", "result": "succeeded", "details": "9073 kbps"}]]}
    ;
    const passed_run = try std.mem.replaceOwned(u8, allocator, failed_run, "\"result\": \"failed\"", "\"result\": \"succeeded\"");
    defer allocator.free(passed_run);

    // It failed: the run still passes, and the runner's exit code of 1
    // is accounted for.
    {
        var notes: std.ArrayList(u8) = .empty;
        defer notes.deinit(allocator);
        const ev = try summarizeResults(allocator, failed_run, "", "quiche:multiplexing", &notes);
        try std.testing.expectEqual(@as(usize, 6), ev.cells());
        try std.testing.expectEqual(@as(usize, 5), ev.succeeded);
        try std.testing.expectEqual(@as(usize, 0), ev.failed);
        try std.testing.expectEqual(@as(usize, 1), ev.flaky_failed);
        try std.testing.expectEqual(@as(usize, 0), ev.flaky_passed);
        try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ev, false));
        try std.testing.expect(exitCodeExplained(ev, 1));
        try std.testing.expect(!exitCodeExplained(ev, 0));
        try std.testing.expectEqualStrings("  quiche:multiplexing: failed (flaky)\n", notes.items);
    }
    // It passed: the run passes too (a known failure that passes does
    // not), the pass is named, and it is not counted as a success.
    {
        var notes: std.ArrayList(u8) = .empty;
        defer notes.deinit(allocator);
        const ev = try summarizeResults(allocator, passed_run, "", "quiche:M", &notes);
        try std.testing.expectEqual(@as(usize, 6), ev.cells());
        try std.testing.expectEqual(@as(usize, 5), ev.succeeded);
        try std.testing.expectEqual(@as(usize, 1), ev.flaky_passed);
        try std.testing.expectEqual(@as(usize, 0), ev.flaky_failed);
        try std.testing.expectEqual(@as(usize, 0), ev.fixed);
        try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ev, false));
        try std.testing.expect(exitCodeExplained(ev, 0));
        try std.testing.expect(!exitCodeExplained(ev, 1));
        try std.testing.expectEqualStrings("  quiche:multiplexing: succeeded (flaky)\n", notes.items);
    }
    // The same cell for another peer is not covered, and a failure that
    // is not listed still fails the run.
    const other_peer = try summarizeResults(allocator, failed_run, "", "quic-go:multiplexing", null);
    try std.testing.expectEqual(@as(usize, 1), other_peer.failed);
    try std.testing.expectEqual(@as(usize, 1), other_peer.flaky_passed);
    try std.testing.expect(evidenceProblem(other_peer, false) != null);

    // A flaky pass proves nothing: a run in which only flaky cells
    // succeeded is not a pass.
    try std.testing.expectEqualStrings("no cell succeeded", evidenceProblem(.{ .pairs = 1, .flaky_passed = 2 }, false).?);

    // Both lists name the cell: they say opposite things about a pass.
    try std.testing.expectError(
        error.CellListedTwice,
        summarizeResults(allocator, failed_run, "quiche:multiplexing", "quiche:M", null),
    );

    // A failed measurement is not in the runner's exit code, flaky or
    // not.
    const failed_goodput = try std.mem.replaceOwned(u8, allocator, passed_run, "\"result\": \"succeeded\", \"details\": \"9073 kbps\"", "\"result\": \"failed\", \"details\": \"\"");
    defer allocator.free(failed_goodput);
    const measured = try summarizeResults(allocator, failed_goodput, "", "quiche:goodput", null);
    try std.testing.expectEqual(@as(usize, 1), measured.flaky_failed);
    try std.testing.expectEqual(@as(usize, 0), measured.flaky_failed_tests);
    try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(measured, false));
    try std.testing.expect(exitCodeExplained(measured, 0));

    // A flaky failure and a known failure in one run: the exit code is
    // the sum.
    try std.testing.expect(exitCodeExplained(.{ .pairs = 1, .succeeded = 1, .known_failed = 1, .known_failed_tests = 1, .flaky_failed = 2, .flaky_failed_tests = 2 }, 3));
}

test "evidence: the peer of a pair is the side that is not quic-zig" {
    try std.testing.expectEqualStrings("quiche", peerOf("quiche", "quic-zig"));
    try std.testing.expectEqualStrings("quic-go", peerOf("quic-zig", "quic-go"));

    // Client role: the known failure names the server.
    const client_role =
        \\{"servers": ["quic-go", "ngtcp2"], "clients": ["quic-zig"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}, "G": {"name": "goodput", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}],
        \\             [{"abbr": "H", "name": "handshake", "result": "failed"}]],
        \\ "measurements": [[{"name": "goodput", "abbr": "G", "result": "succeeded", "details": ""}],
        \\                  [{"name": "goodput", "abbr": "G", "result": "failed", "details": ""}]]}
    ;
    const ev = try summarizeResults(std.testing.allocator, client_role, "ngtcp2:H,ngtcp2:G", "", null);
    try std.testing.expectEqual(@as(usize, 0), ev.failed);
    try std.testing.expectEqual(@as(usize, 2), ev.known_failed);
    // The failed measurement is not in the runner's exit code.
    try std.testing.expectEqual(@as(usize, 1), ev.known_failed_tests);
    try std.testing.expectEqual(@as(?[]const u8, null), evidenceProblem(ev, false));

    // A row count that does not match clients x servers is not a result
    // this code can attribute.
    const short =
        \\{"servers": ["quic-go", "ngtcp2"], "clients": ["quic-zig"],
        \\ "tests": {"H": {"name": "handshake", "desc": ""}},
        \\ "results": [[{"abbr": "H", "name": "handshake", "result": "succeeded"}]],
        \\ "measurements": [[]]}
    ;
    try std.testing.expectError(error.InvalidResultJson, summarizeResults(std.testing.allocator, short, "", "", null));
}

test "engine version gate for the runner's compose file" {
    // 28.0.4 is what GitHub's ubuntu image carried while both interop
    // workflows ran zero tests.
    try std.testing.expectEqual(@as(?bool, false), engineAtLeast("28.0.4", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, false), engineAtLeast("27.5.1", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, true), engineAtLeast("28.1.0", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, true), engineAtLeast("28.1.0-rc.1", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, true), engineAtLeast("29.4.0", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, null), engineAtLeast("", interface_name_engine));
    try std.testing.expectEqual(@as(?bool, null), engineAtLeast("dev", interface_name_engine));
}

test "runner client role defaults to client result path" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .repo = "/tmp/quic",
        .workspace = "/tmp",
    };
    const args = [_][]const u8{
        "--role",
        "client",
        "--servers",
        "quic-go",
        "--strict",
        "--flaky",
        "quiche:multiplexing",
        "--known-failures",
        "ngtcp2:ecn",
    };
    try std.testing.expect(!cfg.strict);
    try parseRunner(allocator, &args, &cfg);
    try std.testing.expectEqualStrings("quiche:multiplexing", cfg.flaky);
    try std.testing.expectEqualStrings("ngtcp2:ecn", cfg.known_failures);
    defer allocator.free(cfg.runner_dir.?);
    defer allocator.free(cfg.log_dir.?);
    defer allocator.free(cfg.json_path.?);

    try std.testing.expect(cfg.strict);
    try std.testing.expectEqual(RunnerRole.client, cfg.role);
    try std.testing.expectEqualStrings("quic-go", cfg.servers);
    const json_tail = try std.Io.Dir.path.join(allocator, &.{ "interop", "results", "quic-zig-client.json" });
    defer allocator.free(json_tail);
    try std.testing.expect(std.mem.endsWith(u8, cfg.json_path.?, json_tail));
}

test "host Zig package cache honors ZIG_GLOBAL_CACHE_DIR first" {
    const allocator = std.testing.allocator;
    const cfg = Config{
        .repo = "/tmp/quic",
        .workspace = "/tmp",
        .home_env = "/home/user",
        .zig_global_cache_env = "/tmp/quic/.zig-global-cache",
    };
    const cache = (try hostZigPackageCachePath(allocator, cfg)).?;
    defer allocator.free(cache);

    const expected = try std.Io.Dir.path.join(allocator, &.{ "/tmp/quic/.zig-global-cache", "p" });
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, cache);
}

test "copy ignore filters generated trees" {
    try std.testing.expect(ignoreCopyPath(".git"));
    try std.testing.expect(ignoreCopyPath(".zig-cache/foo"));
    try std.testing.expect(ignoreCopyPath("interop/logs/output.txt"));
    try std.testing.expect(ignoreCopyPath("tools/__pycache__/x.pyc"));
    try std.testing.expect(!ignoreCopyPath("interop/qns/Dockerfile"));
}
