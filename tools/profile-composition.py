#!/usr/bin/env python3
"""Profile the two public composition workloads on frozen local source inputs.

Builds happen outside measured runs. The caller must provide a quiet window;
this script neither changes pins nor treats unrelated host load as controlled.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
LANES = ("native", "selected")
WORKLOADS = {
    "pubsub": ("qmsg-pubsub-workload", "PUBSUB_WORKLOAD "),
    "recovery": ("qmesh-snapshot-recovery", "RECOVERY_WORKLOAD "),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    """Same per-file canonical JSON digest scheme as profile-applications.py."""
    if (path / ".git").exists():
        names = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=path
        ).split(b"\0")
        names = sorted({os.fsdecode(name) for name in names if name})
    else:
        excluded = {".git", ".zig-cache", ".zig-global-cache", "zig-pkg", "zig-out", "__pycache__"}
        names = sorted(str(p.relative_to(path)) for p in path.rglob("*")
                       if p.is_file() and not excluded.intersection(p.relative_to(path).parts))
    entries = {name: sha256(path / name) for name in names if (path / name).is_file()}
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    result = {"path": str(path), "files": entries, "file_count": len(entries), "files_sha256": digest}
    if (path / ".git").exists():
        result["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()
        result["status"] = subprocess.check_output(["git", "status", "--short"], cwd=path, text=True).strip()
    return result


def compact(value):
    return {key: item for key, item in value.items() if key != "files"}


def local_dependency(manifest, name, workspace):
    match = re.search(r"\." + re.escape(name) + r'\s*=\s*\.\{\s*\.path\s*=\s*"([^"]+)"\s*[,}]', manifest)
    if not match:
        raise ValueError(f"workspace dependency {name} must select an explicit frozen local path")
    return (workspace / match[1]).resolve(strict=True)


def pin(path, name):
    text = (path / "build.zig.zon").read_text()
    match = re.search(r"\." + re.escape(name) + r'\s*=\s*\.\{\s*\.url\s*=\s*"([^"]+)"\s*,\s*\.hash\s*=\s*"([^"]+)"', text)
    if not match:
        raise ValueError(f"{path} must retain its released {name} URL/hash pin")
    return {"url": match[1], "hash": match[2]}


def workspace_identity(workspace):
    # Only source/configuration inputs: install prefixes and generated caches are
    # deliberately outside this list. Consumer test sources live one level up.
    paths = [workspace / "build.zig", workspace / "build.zig.zon"]
    paths.extend(workspace.parent / name for name in
                 ("composition_test.zig", "sprint2_composition_test.zig", "sprint3_composition_test.zig"))
    data = workspace.parent / "data"
    if data.is_dir():
        paths.extend(p for p in data.rglob("*") if p.is_file())
    entries = {os.path.relpath(path, workspace): sha256(path) for path in paths if path.is_file()}
    serialized = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"path": str(workspace), "files": entries, "file_count": len(entries),
            "files_sha256": hashlib.sha256(serialized).hexdigest()}


def compiler_identity(zig):
    return {"path": str(zig), "sha256": sha256(zig),
            "version": subprocess.check_output([str(zig), "version"], text=True).strip()}


def process_snapshot(path):
    with path.open("w") as stream:
        subprocess.run(["ps", "-axo", "pid,ppid,%cpu,%mem,etime,comm"], stdout=stream, check=True)


def run_child(command, cwd, env, log, timeout):
    """External watchdog; wait4 gives this exact child's CPU and peak RSS."""
    state = {"running": True, "timed_out": False}
    lock = threading.Lock()
    with log.open("w") as stream:
        start = time.monotonic()
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                 stderr=subprocess.STDOUT, start_new_session=True)

        def expire():
            with lock:
                if not state["running"]:
                    return
                state["timed_out"] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        watchdog = threading.Timer(timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            with lock:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            raise
        finally:
            with lock:
                state["running"] = False
            watchdog.cancel()
            watchdog.join()
        wall = time.monotonic() - start
    rss_unit = "bytes" if platform.system() == "Darwin" else "KiB"
    return {
        "returncode": child.returncode, "timed_out": state["timed_out"],
        "watchdog_seconds": timeout, "process_wall_seconds": wall,
        "process_user_seconds": usage.ru_utime, "process_system_seconds": usage.ru_stime,
        "process_cpu_seconds": usage.ru_utime + usage.ru_stime,
        "process_peak_rss_raw": usage.ru_maxrss, "process_peak_rss_unit": rss_unit,
        "process_peak_rss_bytes": usage.ru_maxrss if rss_unit == "bytes" else usage.ru_maxrss * 1024,
    }


def integer(record, field):
    value = record.get(field)
    if type(value) is not int or value < 0:
        raise ValueError(f"workload field {field} must be a nonnegative integer")
    return value


def validate(workload, record, publications):
    if not isinstance(record, dict):
        raise ValueError("workload JSON must be an object")
    if workload == "pubsub":
        fields = ("attempted", "matched", "queued", "backpressured", "dropped", "healthy_delivered",
                  "slow_delivered", "peak_pending_messages", "peak_pending_bytes",
                  "configured_queue_messages_per_peer", "configured_queue_bytes_per_peer",
                  "cold_handshake_us", "warm_elapsed_us")
        values = {field: integer(record, field) for field in fields}
        checks = {
            "application_completed": record.get("reconnected") is True,
            "attempted": values["attempted"] == publications,
            "source_filter_and_fanout": values["matched"] == 3 * publications,
            "healthy_delivery": values["healthy_delivered"] == 2 * publications,
            "paused_peer_isolation": values["slow_delivered"] == 0 and values["backpressured"] > 0,
            "admission_accounting": values["queued"] >= 2 * publications and
                values["queued"] + values["backpressured"] + values["dropped"] == values["matched"],
            "default_block_policy": values["dropped"] == 0,
            "queue_configuration": values["configured_queue_messages_per_peer"] == 4 and
                values["configured_queue_bytes_per_peer"] == 16 * 1024,
            "bounded_queue": 0 < values["peak_pending_messages"] <= 3 * values["configured_queue_messages_per_peer"] and
                0 < values["peak_pending_bytes"] <= 3 * values["configured_queue_bytes_per_peer"],
            "application_timing": values["cold_handshake_us"] > 0 and values["warm_elapsed_us"] > 0,
        }
    else:
        fields = ("authority_revision", "replica_revision", "gossip_only_revision", "hints_published",
                  "noise_published", "hints_evicted", "hints_delivered_after_heal", "snapshot_attempts",
                  "snapshot_timeouts", "snapshots_applied", "snapshot_bytes", "peak_pending_requests",
                  "peak_pool_entries", "elapsed_us")
        values = {field: integer(record, field) for field in fields}
        checks = {
            "application_completed": record.get("converged") is True,
            "state_convergence": values["authority_revision"] == values["replica_revision"] == 40,
            "gossip_only_stale": values["gossip_only_revision"] == 0,
            "all_hints_evicted": values["hints_published"] == values["hints_evicted"] == 40 and values["noise_published"] == 40,
            "no_late_hint": values["hints_delivered_after_heal"] == 0,
            "bounded_real_timeouts": 0 < values["snapshot_timeouts"] < values["snapshot_attempts"] <= 120,
            "terminal_accounting": values["snapshot_attempts"] == values["snapshot_timeouts"] + values["snapshots_applied"],
            "fixed_snapshot": values["snapshots_applied"] == 1 and values["snapshot_bytes"] == 81,
            "bounded_pending": values["peak_pending_requests"] == values["peak_pool_entries"] == 1,
            "application_timing": 500_000 <= values["elapsed_us"] <= 8_000_000,
        }
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True,
                        help="absolute parent consumer directory containing build.zig and build.zig.zon")
    parser.add_argument("--qmsg-path", type=Path, required=True)
    parser.add_argument("--qmesh-path", type=Path, required=True)
    parser.add_argument("--quic-path", type=Path, help="optional assertion of the workspace's selected local QUIC path")
    parser.add_argument("--output-dir", type=Path, required=True, help="new evidence directory, preferably ignored")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--pubsub-publications", type=int, default=24)
    parser.add_argument("--pubsub-payload-bytes", type=int, default=128)
    parser.add_argument("--watchdog-seconds", type=int, default=30)
    args = parser.parse_args()
    if not args.workspace.is_absolute():
        parser.error("--workspace must be an absolute path")
    if platform.system() not in ("Darwin", "Linux") or not hasattr(os, "wait4"):
        parser.error("native Darwin/Linux with wait4 is required")
    if not 1 <= args.jobs <= 2 or not 1 <= args.watchdog_seconds <= 120:
        parser.error("jobs must be 1..2 and watchdog-seconds must be 1..120")
    if not 16 <= args.pubsub_publications <= 100_000 or not 1 <= args.pubsub_payload_bytes <= 2048:
        parser.error("pubsub-publications must be 16..100000 and pubsub-payload-bytes must be 1..2048")
    args.workspace = args.workspace.resolve(strict=True)
    for name in ("qmsg_path", "qmesh_path"):
        path = getattr(args, name).resolve(strict=True)
        if not (path / "build.zig.zon").is_file():
            parser.error(f"{name.replace('_', '-')} must identify an explicit source package")
        setattr(args, name, path)
    if not all((args.workspace / name).is_file() for name in ("build.zig", "build.zig.zon")):
        parser.error("workspace must contain build.zig and build.zig.zon")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    provenance = output / "provenance"
    provenance.mkdir()
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report = {
        "schema_version": 1, "started_utc": stamp, "passed": False,
        "scope": "host-local public IPv4 UDP workloads; three alternating samples per lane; builds excluded",
        "host": platform.platform(), "cpu_count": os.cpu_count(), "samples_per_lane": 3,
        "source_digest_algorithm": "sha256 of canonical JSON path-to-file-sha256 map",
        "workspace": str(args.workspace), "builds": [], "samples": [],
        "module_options": {"target": "native", "optimize": "ReleaseSafe", "release": True, "sanitize-c": "trap"},
        "sources_unchanged": False,
        "workload_options": {"pubsub_publications": args.pubsub_publications,
                             "pubsub_payload_bytes": args.pubsub_payload_bytes,
                             "pubsub_timeout_ms": 10_000, "recovery": "source defaults"},
    }

    def save():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    before = None
    paths = None
    zig = None

    def capture_state():
        return {**{name: identity(path) for name, path in paths.items()},
                "workspace": workspace_identity(args.workspace), "compiler": compiler_identity(zig)}

    def unchanged(state):
        return state == before

    save()
    try:
        manifest = (args.workspace / "build.zig.zon").read_text()
        for name in ("qmsg", "qmesh"):
            resolved = local_dependency(manifest, name, args.workspace)
            if resolved != getattr(args, name + "_path"):
                raise ValueError(f"workspace {name} path {resolved} differs from explicit input")
        quic_path = local_dependency(manifest, "quic", args.workspace)
        if args.quic_path and args.quic_path.resolve(strict=True) != quic_path:
            raise ValueError("--quic-path differs from the selected workspace dependency")
        if not (quic_path / "build.zig.zon").is_file():
            raise ValueError("selected QUIC must be a source package")
        paths = {"qmsg": args.qmsg_path, "qmesh": args.qmesh_path, "quic": quic_path}
        native_pins = {name: pin(paths[name], "quic") for name in ("qmsg", "qmesh")}
        if native_pins["qmsg"] != native_pins["qmesh"] or not native_pins["qmsg"]["url"].endswith("/v0.37.2.tar.gz"):
            raise ValueError("native lane requires both consumers' unchanged matching v0.37.2 URL/hash pins")
        zig_name = shutil.which("zig")
        if not zig_name:
            raise ValueError("zig must be available in PATH (use the pinned mise toolchain)")
        zig = Path(zig_name).resolve(strict=True)
        before = capture_state()
        if before["compiler"]["version"] != "0.17.0":
            raise ValueError("stock Zig 0.17.0 is required")
        (provenance / "inputs-before.json").write_text(json.dumps(before, indent=2) + "\n")
        for name in ("build.zig", "build.zig.zon"):
            shutil.copyfile(args.workspace / name, provenance / ("workspace-" + name))
        report["sources_before"] = {name: compact(value) for name, value in before.items()}
        report["input_manifest"] = "provenance/inputs-before.json"
        report["native_quic_pins"] = native_pins
        report["selected_quic_path"] = str(quic_path)
        save()
        env = os.environ.copy()
        env["COPYFILE_DISABLE"] = "1"
        env["ZIG_LOCAL_PKG_DIR"] = str(args.qmesh_path / "zig-pkg")
        (args.qmesh_path / "zig-pkg").mkdir(exist_ok=True)
        report["package_cache"] = env["ZIG_LOCAL_PKG_DIR"]
        for lane in LANES:
            prefix = output / ("install-" + lane)
            command = [str(zig), "build", "install-workloads", "-Doptimize=ReleaseSafe",
                       "-Dlocal-quic=" + str(lane == "selected").lower(), f"-j{args.jobs}",
                       "--prefix", str(prefix), "--summary", "all"]
            row = {"lane": lane, "command": command, "log": lane + "-build.log", "binaries": {}}
            report["builds"].append(row)
            save()
            print(f"Building {lane} outside timed samples", flush=True)
            # Reuse the process-group watchdog for setup, but discard its
            # timing/usage fields: build cost is never a workload measurement.
            built = run_child(command, args.workspace, env, output / row["log"], 900)
            row.update(returncode=built["returncode"], timed_out=built["timed_out"])
            if row["timed_out"]:
                raise RuntimeError(f"{lane} build exceeded its external 900-second setup limit")
            if row["returncode"]:
                raise RuntimeError(f"{lane} build failed; see {row['log']}")
            for workload, (filename, _) in WORKLOADS.items():
                binary = prefix / "bin" / filename
                row["binaries"][workload] = {"path": str(binary), "sha256": sha256(binary), "bytes": binary.stat().st_size}
            state = capture_state()
            row["inputs_after_build"] = {name: compact(value) for name, value in state.items()}
            row["sources_unchanged"] = unchanged(state)
            save()
            if not row["sources_unchanged"]:
                raise RuntimeError("source/compiler/workspace inputs changed during build; timed runs refused")
        report["sources_unchanged_after_builds"] = True
        process_snapshot(output / "processes-before-samples.txt")
        for sample in range(1, 4):
            order = LANES if sample % 2 else tuple(reversed(LANES))
            for workload, (filename, marker) in WORKLOADS.items():
                for lane in order:
                    build = next(row for row in report["builds"] if row["lane"] == lane)
                    binary_info = build["binaries"][workload]
                    binary = Path(binary_info["path"])
                    if sha256(binary) != binary_info["sha256"]:
                        raise RuntimeError("installed binary changed before measurement")
                    command = [str(binary)]
                    child_env = env.copy()
                    overrides = {}
                    if workload == "pubsub":
                        child_env["QMSG_RUN_LIVE_UDP"] = "1"
                        overrides["QMSG_RUN_LIVE_UDP"] = "1"
                        command.extend(["--publications", str(args.pubsub_publications),
                                        "--payload-bytes", str(args.pubsub_payload_bytes), "--timeout-ms", "10000"])
                    log = output / f"{workload}-{lane}-{sample}.log"
                    row = {"workload_name": workload, "lane": lane, "sample": sample,
                           "command": command, "environment_overrides": overrides, "log": log.name,
                           "binary_sha256": binary_info["sha256"], "passed": False}
                    report["samples"].append(row)
                    row.update(run_child(command, args.workspace, child_env, log, args.watchdog_seconds))
                    row["binary_unchanged"] = sha256(binary) == binary_info["sha256"]
                    lines = [line[len(marker):] for line in log.read_text(errors="replace").splitlines() if line.startswith(marker)]
                    row["json_records"] = len(lines)
                    if len(lines) == 1:
                        try:
                            row["workload"] = json.loads(lines[0])
                            row["correctness_checks"] = validate(workload, row["workload"], args.pubsub_publications)
                        except (ValueError, TypeError) as error:
                            row["validation_error"] = str(error)
                    row["passed"] = row["returncode"] == 0 and not row["timed_out"] and row["binary_unchanged"] and \
                        len(lines) == 1 and bool(row.get("correctness_checks")) and all(row["correctness_checks"].values())
                    save()
                    if not row["passed"]:
                        raise RuntimeError(f"{workload}/{lane}/{sample} failed correctness/watchdog; see {log.name}")
                    print(f"{workload} {lane} {sample}: wall={row['process_wall_seconds']:.6f}s CPU={row['process_cpu_seconds']:.6f}s RSS={row['process_peak_rss_bytes']}B", flush=True)
        process_snapshot(output / "processes-after-samples.txt")
        report["summary"] = {}
        process_fields = ("process_wall_seconds", "process_user_seconds", "process_system_seconds", "process_cpu_seconds", "process_peak_rss_bytes")
        for workload in WORKLOADS:
            report["summary"][workload] = {}
            app_fields = ("cold_handshake_us", "warm_elapsed_us") if workload == "pubsub" else ("elapsed_us",)
            for lane in LANES:
                rows = [row for row in report["samples"] if row["workload_name"] == workload and row["lane"] == lane]
                report["summary"][workload][lane] = {
                    "samples": len(rows),
                    "median_process": {field: statistics.median(row[field] for row in rows) for field in process_fields},
                    "median_application": {field: statistics.median(row["workload"][field] for row in rows) for field in app_fields},
                }
        report["measurements_passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if before is not None:
            try:
                after = capture_state()
                report["sources_after"] = {name: compact(value) for name, value in after.items()}
                report["sources_unchanged_at_finish"] = unchanged(after)
                report["sources_unchanged"] = unchanged(after) and all(
                    row.get("sources_unchanged", True) for row in report["builds"])
                if not report["sources_unchanged"]:
                    (provenance / "inputs-after-changed.json").write_text(json.dumps(after, indent=2) + "\n")
            except BaseException as error:
                report["final_identity_error"] = {"type": type(error).__name__, "message": str(error)}
                report["sources_unchanged"] = False
        report["passed"] = bool(report.get("measurements_passed")) and report["sources_unchanged"] and not report.get("error")
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(f"Evidence: {output / 'report.json'}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
