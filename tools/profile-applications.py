#!/usr/bin/env python3
"""Measure public qmsg Req/Rep on frozen consumer/QUIC inputs, without pin edits."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files(path):
    if (path / ".git").exists():
        names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=path).split(b"\0")
        return sorted({os.fsdecode(name) for name in names if name and (path / os.fsdecode(name)).is_file()})
    return sorted(str(p.relative_to(path)) for p in path.rglob("*") if p.is_file())


def identity(path):
    entries = {name: sha256(path / name) for name in files(path)}
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result = {"path": str(path), "files": entries, "files_sha256": digest}
    if (path / ".git").exists():
        result["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
        result["status"] = subprocess.check_output(["git", "status", "--short"], cwd=path, text=True).strip()
    manifest = path / "build.zig.zon"
    if manifest.is_file():
        result["dependency_pins"] = {
            name: {"url": url, "hash": package_hash}
            for name, url, package_hash in re.findall(
                r'\.(quic|boringssl|paseto)\s*=\s*\.\{\s*\.url\s*=\s*"([^"]+)"\s*,\s*\.hash\s*=\s*"([^"]+)"',
                manifest.read_text(),
            )
        }
    return result


def snapshot(source, destination):
    before = identity(source)
    for name in before["files"]:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    after = identity(source)
    copied = identity(destination)
    if before != after or copied["files"] != before["files"]:
        raise RuntimeError(f"source changed while snapshotting: {source}")
    return {"original": before, "snapshot": copied}


BUILD = '''const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const qmsg = b.dependency("qmsg", .{ .target = target, .optimize = optimize });
    if (b.option(bool, "selected", "Inject selected QUIC into qmsg") orelse false) {
        const quic = b.dependency("quic", .{ .target = target, .release = optimize != .debug, .@"sanitize-c" = @as([]const u8, "trap") });
        qmsg.module("qmsg").addImport("quic", quic.module("quic"));
    }
    const mod = b.createModule(.{ .root_source_file = b.path("main.zig"), .target = target, .optimize = optimize });
    mod.addImport("qmsg", qmsg.module("qmsg"));
    mod.addImport("quic", qmsg.module("qmsg").import_table.get("quic").?);
    const exe = b.addExecutable(.{ .name = "application-profile", .root_module = mod });
    b.installArtifact(exe);
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmsg-path", type=Path, required=True)
    parser.add_argument("--quic-path", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--mode", choices=("native", "selected", "both"), default="both")
    parser.add_argument("--optimize", choices=("Debug", "ReleaseSafe"), default="ReleaseSafe")
    for name, default in (("requests", 5000), ("payload-bytes", 1024), ("concurrency", 8), ("stream-window", 8), ("warmup", 128), ("idle-ms", 200), ("timeout-seconds", 30)):
        parser.add_argument("--" + name, type=int, default=default)
    args = parser.parse_args()
    if not 1 <= args.samples <= 9 or not 1 <= args.jobs <= 2:
        parser.error("samples must be 1..9; jobs must be 1..2")
    for name in ("qmsg_path", "quic_path"):
        path = getattr(args, name).resolve()
        if not (path / "build.zig.zon").is_file():
            parser.error(f"{name} must be an explicit source package")
        setattr(args, name, path)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = (args.output_dir or ROOT / "benchmark-reports/application-profiles" / stamp).resolve()
    output.mkdir(parents=True, exist_ok=False)
    zig = Path(shutil.which("zig") or "zig").resolve()
    report = {"schema_version": 1, "started_utc": stamp, "scope": "host-local real IPv4 UDP; public qmsg Req/Rep; no physical network or hosted CI claim", "host": platform.platform(), "cpu_count": os.cpu_count(), "compiler": {"path": str(zig), "sha256": sha256(zig), "version": subprocess.check_output([str(zig), "version"], text=True).strip()}, "optimize": args.optimize, "module_options": {"target": "native", "release": args.optimize != "Debug", "sanitize-c": "trap"}, "samples": [], "passed": False}
    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    report["sources"] = {"qmsg": snapshot(args.qmsg_path, output / "sources/qmsg"), "quic": snapshot(args.quic_path, output / "sources/quic")}
    stage = output / "consumer"
    stage.mkdir()
    (stage / "build.zig").write_text(BUILD)
    manifest = ROOT.joinpath("tools/consumer-smoke/build.zig.zon").read_text()
    # Keep the established scratch consumer package identity; select sources by
    # explicit local path only. Public package URL/hash pins are never changed.
    begin = manifest.index("    .dependencies =")
    manifest = manifest[:begin] + '    .dependencies = .{\n        .qmsg = .{ .path = "../sources/qmsg" },\n        .quic = .{ .path = "../sources/quic" },\n    },\n    .paths = .{ "build.zig", "build.zig.zon", "main.zig", "counting_allocator.zig", "cert.pem", "key.pem" },\n}\n'
    (stage / "build.zig.zon").write_text(manifest)
    for source, target in ((ROOT / "tools/application-profile.zig", stage / "main.zig"), (ROOT / "bench/e2e/counting_allocator.zig", stage / "counting_allocator.zig"), (ROOT / "examples/support/test_cert.pem", stage / "cert.pem"), (ROOT / "examples/support/test_key.pem", stage / "key.pem")):
        shutil.copyfile(source, target)
    report["harness"] = identity(stage)
    env = os.environ.copy()
    env["COPYFILE_DISABLE"] = "1"
    env["ZIG_LOCAL_PKG_DIR"] = str(ROOT / "zig-pkg")
    (ROOT / "zig-pkg").mkdir(exist_ok=True)
    modes = ("native", "selected") if args.mode == "both" else (args.mode,)
    report["builds"] = []
    for mode in modes:
        prefix = output / ("install-" + mode)
        command = [str(zig), "build", f"-j{args.jobs}", f"-Doptimize={args.optimize}", "-Dselected=" + str(mode == "selected").lower(), "--prefix", str(prefix), "--summary", "all"]
        log = output / (mode + "-build.log")
        print(f"Building {mode}", flush=True)
        with log.open("w") as stream:
            built = subprocess.run(command, cwd=stage, env=env, stdout=stream, stderr=subprocess.STDOUT)
        report["builds"].append({"mode": mode, "command": command, "returncode": built.returncode, "log": log.name})
        save()
        if built.returncode:
            print(log.read_text()[-6000:])
            return built.returncode
        binary = prefix / "bin/application-profile"
        report["builds"][-1].update(binary=str(binary), binary_sha256=sha256(binary))
    report["resolved_dependencies"] = {}
    pins = dict(report["sources"]["qmsg"]["snapshot"].get("dependency_pins", {}))
    pins.update(report["sources"]["quic"]["snapshot"].get("dependency_pins", {}))
    for name, pin in pins.items():
        cached = ROOT / "zig-pkg" / pin["hash"]
        if cached.is_dir():
            report["resolved_dependencies"][name] = identity(cached)
            report["resolved_dependencies"][name]["package_pin"] = pin
    save()
    arguments = []
    for name in ("requests", "payload_bytes", "concurrency", "stream_window", "warmup", "idle_ms", "timeout_seconds"):
        arguments.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
    # Alternate order so one implementation does not always inherit the same
    # host/cache order. Build and profiling time is outside timed workloads.
    for sample in range(args.samples):
        order = modes if sample % 2 == 0 else tuple(reversed(modes))
        for mode in order:
            binary = output / ("install-" + mode) / "bin/application-profile"
            command = [str(binary), *arguments]
            log = output / f"{mode}-{sample + 1}.log"
            before_processes = output / f"{mode}-{sample + 1}-processes-before.txt"
            after_processes = output / f"{mode}-{sample + 1}-processes-after.txt"
            with before_processes.open("w") as stream:
                subprocess.run(["ps", "-axo", "pid,ppid,%cpu,%mem,etime,comm"], stdout=stream, check=True)
            start = time.monotonic()
            with log.open("w") as stream:
                child = subprocess.Popen(command, cwd=stage, env=env, stdout=stream, stderr=subprocess.STDOUT)
                _, status, usage = os.wait4(child.pid, 0)
                child.returncode = os.waitstatus_to_exitcode(status)
            wall_seconds = time.monotonic() - start
            with after_processes.open("w") as stream:
                subprocess.run(["ps", "-axo", "pid,ppid,%cpu,%mem,etime,comm"], stdout=stream, check=True)
            records = [json.loads(line.removeprefix("APPLICATION_PROFILE ")) for line in log.read_text().splitlines() if line.startswith("APPLICATION_PROFILE ")]
            item = {"mode": mode, "sample": sample + 1, "command": command, "log": log.name, "returncode": child.returncode, "process_wall_seconds": wall_seconds, "process_user_seconds": usage.ru_utime, "process_system_seconds": usage.ru_stime, "process_peak_rss_bytes": usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024, "process_snapshots": [before_processes.name, after_processes.name], "workload": records[0] if len(records) == 1 else None}
            report["samples"].append(item)
            save()
            if child.returncode or len(records) != 1:
                print(log.read_text()[-6000:])
                return child.returncode or 1
            warm = records[0]["warm"]
            print(f"{mode} {sample + 1}: {warm['replies']} replies, wall {warm['elapsed_us']} us, CPU {warm['cpu_us']} us", flush=True)
    report["summary"] = {mode: {field: statistics.median(row["workload"]["warm"][field] for row in report["samples"] if row["mode"] == mode) for field in ("elapsed_us", "cpu_us", "latency_p50_us", "latency_p99_us")} for mode in modes}
    report["passed"] = True
    report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    print(f"Evidence: {output / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
