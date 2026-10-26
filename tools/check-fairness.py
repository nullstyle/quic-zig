#!/usr/bin/env python3
"""Qualify the bounded 14-cell coexistence grid against frozen Sprint 4.

Run with mise exec -- python3 -B tools/check-fairness.py --output-dir PATH.
Sources are snapshotted; this never edits the checkout or dependency pins.
Every per-cell regression is reported. Passing the mean/worst gates is a
bounded virtual-network result, not a claim of universal fairness.
"""

import argparse
import concurrent.futures
import datetime
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import time


ROOT = Path(__file__).resolve().parent.parent
BASELINE = "b51749a52fac0f54068f112f16e1148bb018382d"
COMMON = ("bench/e2e_main.zig", "bench/e2e/fairness.zig", "bench/e2e/harness.zig", "bench/e2e/sim_net.zig")
EXCLUDED = {".git", ".zig-cache", ".zig-global-cache", "zig-pkg", "zig-out", "__pycache__", "benchmark-reports"}
# Immutable S4 bytes ensure an altered workload/toolchain cannot silently
# become a new comparison baseline. The exact Jain values are derived below.
BASELINE_BYTES = {
    "fairness_10mbit_2f_cubic": [13256844, 11022153],
    "fairness_10mbit_2f_bbr": [11800355, 12478780],
    "fairness_10mbit_4f_bbr": [5755198, 5672693, 6096706, 6754510],
    "fairness_10mbit_2f_bbr_stagger5s": [12384794, 11894327],
    "fairness_10mbit_2f_mixed": [6514960, 17764095],
    "fairness_10mbit_2f_mixed_shallow25ms": [15630273, 8648841],
    "fairness_grid_mixed_reverse": [18561702, 5717369],
    "fairness_grid_mixed_reverse_shallow25ms": [9697417, 14581697],
    "fairness_grid_mixed_cubic_delayed1s": [6108173, 18170948],
    "fairness_grid_mixed_bbr_delayed1s": [12087917, 12079879],
    "fairness_grid_mixed_base10ms": [8215545, 16063422],
    "fairness_grid_mixed_shallow5ms": [15590156, 8693542],
    "fairness_grid_mixed_deep250ms": [4417751, 19861294],
    "fairness_grid_mixed_measure60s": [31889436, 40947447],
}
EXTRA_CELLS = '''
    .{
        .name = "fairness_grid_mixed_reverse",
        .flows = &.{ .{ .congestion_control = .cubic }, .{ .congestion_control = .bbr } },
    },
    .{
        .name = "fairness_grid_mixed_reverse_shallow25ms",
        .flows = &.{ .{ .congestion_control = .cubic }, .{ .congestion_control = .bbr } },
        .max_queue_delay_us = 25000,
    },
    .{
        .name = "fairness_grid_mixed_cubic_delayed1s",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic, .start_us = 1000000 } },
    },
    .{
        .name = "fairness_grid_mixed_bbr_delayed1s",
        .flows = &.{ .{ .congestion_control = .bbr, .start_us = 1000000 }, .{ .congestion_control = .cubic } },
    },
    .{
        .name = "fairness_grid_mixed_base10ms",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
        .base_delay_us = 10000,
    },
    .{
        .name = "fairness_grid_mixed_shallow5ms",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
        .max_queue_delay_us = 5000,
    },
    .{
        .name = "fairness_grid_mixed_deep250ms",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
        .max_queue_delay_us = 250000,
    },
    .{
        .name = "fairness_grid_mixed_measure60s",
        .flows = &.{ .{ .congestion_control = .bbr }, .{ .congestion_control = .cubic } },
        .measure_us = 60000000,
    },'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def inventory(source):
    if (source / ".git").exists():
        names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=source).split(b"\0")
        names = sorted({os.fsdecode(name) for name in names if name})
    else:
        names = []
        for directory, dirs, files in os.walk(source):
            dirs[:] = [name for name in dirs if name not in EXCLUDED]
            names.extend(str((Path(directory) / name).relative_to(source)) for name in files)
    return {name: sha(source / name) for name in sorted(names) if (source / name).is_file()}


def runtime_digest(source, entries):
    digest = hashlib.sha256()
    for name in sorted(entries):
        if not (name.startswith("src/") or name in ("build.zig", "build.zig.zon")):
            continue
        data, encoded = (source / name).read_bytes(), name.encode()
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def snapshot(source, destination):
    before = inventory(source)
    for name in before:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    if inventory(source) != before or inventory(destination) != before:
        raise ValueError("candidate source changed during snapshot")
    identity = {"path": str(source), "files": before, "runtime_build_tree_sha256": runtime_digest(source, before)}
    if (source / ".git").exists():
        identity.update(commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                        status=subprocess.check_output(["git", "status", "--short"], cwd=source, text=True).strip())
    return identity


def append_grid(source):
    path = source / "bench/e2e_main.zig"
    text = path.read_text()
    marker = "const fairness_cells = [_]fairness.FairnessOptions{"
    if text.count(marker) != 1:
        raise ValueError("fairness declaration must occur exactly once")
    begin = text.index(marker)
    end = text.index("\n};", begin)
    names = re.findall(r'\.name = "([^"]+)"', text[begin:end])
    if names != list(BASELINE_BYTES)[:6]:
        raise ValueError("expected the original six fairness cells, in their recorded order")
    path.write_text(text[:end] + EXTRA_CELLS + text[end:])


def run_lane(name, source, output, zig, env, jobs, timeout):
    report_path, log = output / (name + "-bench.json"), output / (name + ".log")
    frozen = inventory(source)
    command = [str(zig), "build", "bench-e2e", "-j" + str(jobs), "--", "--scenario", "fairness", "--samples", "1", "--json", str(report_path)]
    started = time.monotonic()
    timed_out = False
    with log.open("w") as stream:
        child = subprocess.Popen(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=timeout)
        except BaseException as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            if not timed_out:
                raise
            code = 124
    result = {"command": command, "returncode": code, "timed_out": timed_out,
              "watchdog_seconds": timeout, "elapsed_seconds": time.monotonic() - started,
              "local_cache": str(source / ".zig-cache"),
              "source_files_unchanged": all(sha(source / path) == digest for path, digest in frozen.items()),
              "runtime_build_tree_sha256": runtime_digest(source, frozen),
              "log": log.name, "log_sha256": sha(log)}
    if report_path.is_file():
        result.update(report=report_path.name, report_sha256=sha(report_path))
    binaries = list((source / ".zig-cache/o").glob("*/quic-zig-bench-e2e"))
    if code == 0 and len(binaries) == 1:
        result["binary"] = {"path": str(binaries[0]), "sha256": sha(binaries[0])}
    else:
        result["binary_error"] = "expected exactly one fresh benchmark binary"
    write(output / (name + "-execution.json"), result)
    if code or not result["source_files_unchanged"] or "binary_error" in result:
        raise ValueError(f"{name} execution failed; see {log}")
    return result


def rows(report):
    if (report.get("optimize"), report.get("zig_version"), report.get("samples_per_benchmark")) != ("safe", "0.17.0", 1):
        raise ValueError("expected Zig 0.17.0 ReleaseSafe, one deterministic sample per cell")
    values = report.get("benchmarks", [])
    result = {row["name"]: row for row in values}
    if len(values) != 14 or set(result) != set(BASELINE_BYTES):
        raise ValueError("expected all 14 unique declared cells")
    for name, row in result.items():
        flows = row.get("flows", [])
        if row.get("kind") != "fairness" or len(flows) != len(BASELINE_BYTES[name]) or row.get("flow_count") != len(flows):
            raise ValueError("wrong cell type or flow count: " + name)
        expected_cc = (["cubic", "cubic"] if name.endswith("2f_cubic") else
                       ["bbr"] * len(flows) if "mixed" not in name else
                       ["cubic", "bbr"] if "reverse" in name else ["bbr", "cubic"])
        expected_starts = [0] * len(flows)
        if name.endswith("stagger5s"): expected_starts[1] = 5_000_000
        if name.endswith("cubic_delayed1s"): expected_starts[1] = 1_000_000
        if name.endswith("bbr_delayed1s"): expected_starts[0] = 1_000_000
        window = 60_000_000 if name.endswith("measure60s") else 20_000_000
        if (row.get("seed"), row.get("measure_window_us"), row.get("virtual_us")) != (780740, window, max(expected_starts) + 5_000_000 + window):
            raise ValueError("wrong workload seed/window: " + name)
        if [f.get("cc") for f in flows] != expected_cc or [f.get("start_us") for f in flows] != expected_starts:
            raise ValueError("wrong controller/order/start: " + name)
        for flow in flows:
            if type(flow.get("measured_bytes")) is not int or flow["measured_bytes"] < 0:
                raise ValueError("invalid measured bytes: " + name)
        for key in ("enqueued", "dropped", "queue_dropped", "peak_queue_delay_us"):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError("invalid queue/counter field: " + name)
    return result


def measure(row):
    values = [flow["measured_bytes"] for flow in row["flows"]]
    total, squares = sum(values), sum(value * value for value in values)
    return (Fraction(total * total, len(values) * squares) if squares else Fraction(0),
            Fraction(total * 1_000_000, row["measure_window_us"] * 1_250_000))


def compare(baseline, candidate):
    baseline, candidate = rows(baseline), rows(candidate)
    if any([flow["measured_bytes"] for flow in baseline[name]["flows"]] != expected for name, expected in BASELINE_BYTES.items()):
        raise ValueError("fresh S4 baseline differs from immutable measured-byte controls")
    mixed = [name for name in baseline if "mixed" in name]
    homogeneous = [name for name in baseline if {f["cc"] for f in baseline[name]["flows"]} == {"bbr"}]
    stats = {lane: {name: measure(row) for name, row in data.items()} for lane, data in (("baseline", baseline), ("candidate", candidate))}
    means = {lane: sum(data[name][0] for name in mixed) / len(mixed) for lane, data in stats.items()}
    worst = {lane: min(data[name][0] for name in mixed) for lane, data in stats.items()}
    parity_keys = ("flows", "seed", "measure_window_us", "virtual_us", "enqueued", "dropped", "queue_dropped", "peak_queue_delay_us")
    cubic = "fairness_10mbit_2f_cubic"
    controls = {
        "mixed_mean_jain_improved": means["candidate"] > means["baseline"],
        "mixed_worst_jain_nonregressed": worst["candidate"] >= worst["baseline"],
        "all_clean_link_utilization_at_least_095": all(value[1] >= Fraction(95, 100) for value in stats["candidate"].values()),
        "all_flows_progress": all(flow["measured_bytes"] > 0 for row in candidate.values() for flow in row["flows"]),
        "homogeneous_bbr_jain_at_least_098": all(stats["candidate"][name][0] >= Fraction(98, 100) for name in homogeneous),
        "pure_cubic_reference_unchanged": all(baseline[cubic][key] == candidate[cubic][key] for key in parity_keys),
    }
    details = []
    for name in baseline:
        delta = stats["candidate"][name][0] - stats["baseline"][name][0]
        lanes = {}
        for lane, data in (("baseline", baseline), ("candidate", candidate)):
            row = data[name]
            total = sum(flow["measured_bytes"] for flow in row["flows"])
            lanes[lane] = {key: row[key] for key in ("seed", "measure_window_us", "virtual_us", "enqueued", "dropped", "queue_dropped", "peak_queue_delay_us")}
            lanes[lane].update(jain=float(stats[lane][name][0]), utilization=float(stats[lane][name][1]),
                               flows=[{**flow, "share": flow["measured_bytes"] / total if total else 0} for flow in row["flows"]])
        details.append({"name": name, "mixed": name in mixed, "jain_delta": float(delta),
                        "outcome": "improved" if delta > 0 else "worse" if delta < 0 else "equal", "lanes": lanes})
    queue_costs = [{"name": name, "baseline_peak_us": baseline[name]["peak_queue_delay_us"],
                    "candidate_peak_us": candidate[name]["peak_queue_delay_us"],
                    "baseline_queue_dropped": baseline[name]["queue_dropped"], "candidate_queue_dropped": candidate[name]["queue_dropped"],
                    "baseline_total_dropped": baseline[name]["dropped"], "candidate_total_dropped": candidate[name]["dropped"]} for name in homogeneous]
    return {"controls": controls, "passed_fairness_controls": all(controls.values()),
            "mixed_mean_jain": {lane: float(value) for lane, value in means.items()},
            "mixed_worst_jain": {lane: float(value) for lane, value in worst.items()},
            "mixed_outcomes": {outcome: sum(row["mixed"] and row["outcome"] == outcome for row in details) for outcome in ("improved", "worse", "equal")},
            "homogeneous_queue_costs": queue_costs,
            "queue_cost_acceptance": "Requires explicit review; the fairness gate alone does not accept increased queue peaks or drops.",
            "rows": details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT, help="candidate source, including current uncommitted files")
    parser.add_argument("--baseline-ref", default=BASELINE, help="Sprint 4 git revision; must resolve to the held measured-byte baseline " + BASELINE)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2, help="jobs per lane; two lanes run concurrently")
    parser.add_argument("--timeout-seconds", type=int, default=600, help="external watchdog per lane, including build")
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 3600:
        parser.error("timeout must be 1..3600 seconds")
    source = args.source.resolve(strict=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = (args.output_dir or ROOT / "benchmark-reports/fairness-qualification" / stamp).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "started_utc": stamp, "baseline_commit": BASELINE,
              "scope": "Fixed-seed zero-random-loss virtual-time topology/window/order grid; no randomized-link, hosted-CI or Internet-wide claim.",
              "counts": {"lanes": 2, "cells_per_lane": 14, "mixed_cells_per_lane": 10, "homogeneous_bbr_cells_per_lane": 3, "flow_observations_per_lane": 30},
              "passed": False}
    try:
        baseline_commit = subprocess.check_output(["git", "rev-parse", args.baseline_ref + "^{commit}"], cwd=ROOT, text=True).strip()
        if baseline_commit != BASELINE:
            raise ValueError("baseline ref must resolve to the held Sprint 4 baseline; recorded thresholds are not silently rebased")
        report["baseline_requested_ref"] = args.baseline_ref
        zig_name = shutil.which("zig")
        if not zig_name:
            raise ValueError("zig unavailable; run this tool through mise exec")
        zig = Path(zig_name).resolve()
        report["compiler"] = {"path": str(zig), "sha256": sha(zig), "version": subprocess.check_output([str(zig), "version"], text=True).strip()}
        if report["compiler"]["version"] != "0.17.0":
            raise ValueError("requires pinned Zig 0.17.0")
        report["candidate_origin"] = snapshot(source, output / "candidate")
        archive = subprocess.check_output(["git", "archive", "--format=tar", baseline_commit], cwd=ROOT)
        report["baseline_archive_sha256"] = hashlib.sha256(archive).hexdigest()
        baseline = output / "baseline"
        baseline.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(baseline, filter="data")
        # Identical benchmark sources for both runtimes. Fresh baseline goldens
        # reject any changed fixture that shifts the historical measurement.
        for relative in COMMON:
            shutil.copyfile(output / "candidate" / relative, baseline / relative)
        for name in ("baseline", "candidate"):
            append_grid(output / name)
            write(output / (name + "-source-files.json"), inventory(output / name))
        report["common_harness_sha256"] = {relative: sha(baseline / relative) for relative in COMMON}
        if report["common_harness_sha256"] != {relative: sha(output / "candidate" / relative) for relative in COMMON}:
            raise ValueError("benchmark inputs differ between lanes")
        env = os.environ.copy()
        env.update(PYTHONDONTWRITEBYTECODE="1", ZIG_LOCAL_PKG_DIR=str(ROOT / "zig-pkg"), ZIG_GLOBAL_CACHE_DIR=str(ROOT / ".zig-global-cache"))
        report["cache_paths"] = {name: env[name] for name in ("ZIG_LOCAL_PKG_DIR", "ZIG_GLOBAL_CACHE_DIR")}
        report["dependency_pins"] = re.findall(r'\.url\s*=\s*"([^"]+)"\s*,\s*\.hash\s*=\s*"([^"]+)"', (baseline / "build.zig.zon").read_text())
        write(output / "report.json", report)
        print("Running frozen baseline and candidate (14 cells each)", flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            pending = {name: pool.submit(run_lane, name, output / name, output, zig, env, args.jobs, args.timeout_seconds) for name in ("baseline", "candidate")}
            report["executions"] = {name: future.result() for name, future in pending.items()}
        result = compare(json.loads((output / "baseline-bench.json").read_text()), json.loads((output / "candidate-bench.json").read_text()))
        report["comparison"] = result
        report["passed"] = result["passed_fairness_controls"]
        for row in result["rows"]:
            if row["mixed"]:
                print(f"{row['name']}: {row['outcome']} Jain {row['lanes']['baseline']['jain']:.9f} -> {row['lanes']['candidate']['jain']:.9f}")
        print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))
    except Exception as error:
        report["error"] = str(error)
        print(str(error), flush=True)
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(output / "report.json", report)
        print("Evidence: " + str(output / "report.json"), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
