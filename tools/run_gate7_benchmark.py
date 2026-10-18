#!/usr/bin/env python3
"""Run fixed offline indexing/search and owned-loopback crawl trials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCH_TEST = "gate7_benchmark::fixed_workload_benchmark"
MEASURED_TRIALS = 5


def command_output(argv: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return f"exit={result.returncode}\n{result.stdout}{result.stderr}"
    return result.stdout.strip()


def file_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def cpu_model() -> str | None:
    cpuinfo = file_text(Path("/proc/cpuinfo"))
    if cpuinfo:
        for line in cpuinfo.splitlines():
            if line.lower().startswith(("model name", "hardware")) and ":" in line:
                return line.split(":", 1)[1].strip()
    return platform.processor() or None


def machine_metadata(output_dir: Path) -> dict[str, object]:
    workload_path = ROOT / "fixtures/benchmark-v1.json"
    filesystem = os.statvfs(output_dir)
    meminfo = file_text(Path("/proc/meminfo")) or ""
    memory_total = next(
        (int(match.group(1)) * 1024 for line in meminfo.splitlines()
         if (match := re.match(r"MemTotal:\s+(\d+)\s+kB", line))),
        None,
    )
    status = subprocess.run(
        ["git", "status", "--short", "--branch", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    diff = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    changed_paths = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    ).stdout.splitlines()
    untracked_paths = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    ).stdout.splitlines()
    candidate_file_hashes = {}
    for name in sorted(set(changed_paths + untracked_paths)):
        candidate_path = ROOT / name
        if candidate_path.is_file():
            content = candidate_path.read_bytes()
            candidate_file_hashes[name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
    mount = command_output(["findmnt", "-no", "SOURCE,FSTYPE,TARGET", "--target", str(output_dir)])
    block_devices = command_output(["lsblk", "-d", "-o", "NAME,MODEL,TYPE,ROTA,SIZE"])
    try:
        load_average = os.getloadavg()
    except OSError:
        load_average = None
    return {
        "git": {
            "head": command_output(["git", "rev-parse", "HEAD"]),
            "branch": command_output(["git", "branch", "--show-current"]),
            "statusBeforeRun": status.stdout.strip(),
            "statusExit": status.returncode,
            "trackedDiffSha256": hashlib.sha256(diff.stdout).hexdigest(),
            "trackedDiffExit": diff.returncode,
            "candidateFileHashes": candidate_file_hashes,
        },
        "host": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpuModel": cpu_model(),
            "logicalCpuCount": os.cpu_count(),
            "memoryTotalBytes": memory_total,
            "loadAverageAtStart": load_average,
            "storageMount": mount,
            "blockDevices": block_devices,
            "storageFreeBytesAtStart": filesystem.f_bavail * filesystem.f_frsize,
            "storageTotalBytes": filesystem.f_blocks * filesystem.f_frsize,
        },
        "tools": {
            "python": sys.version,
            "rustc": command_output(["rustc", "--version", "--verbose"]),
            "cargo": command_output(["cargo", "--version", "--verbose"]),
            "node": command_output(["node", "--version"]),
            "npm": command_output(["npm", "--version"]),
        },
        "workload": {
            "path": "fixtures/benchmark-v1.json",
            "sha256": hashlib.sha256(workload_path.read_bytes()).hexdigest(),
            "bytes": workload_path.stat().st_size,
        },
        "benchmarkEnvironment": {
            key: os.environ.get(key)
            for key in (
                "RUSTFLAGS",
                "CARGO_PROFILE_RELEASE_DEBUG",
                "CARGO_TARGET_DIR",
                "LC_ALL",
                "LANG",
                "TZ",
            )
            if key in os.environ
        },
        "method": {
            "cargoLock": "Cargo.lock; cargo fetch --locked runs before offline builds",
            "buildProfile": "release",
            "measuredTrials": MEASURED_TRIALS,
            "warmupTrials": 1,
            "storePolicy": "fresh validation and measured index plus fresh frontier for every trial",
            "cachePolicy": "OS page cache not flushed; benchmark test warms each query 20 complete passes before 100 timed repetitions",
            "crawlerMetric": "controlled-demo reports only its first run_until_idle; local robots/request/fetch/extract/frontier/outbox/index work included; process startup and later revoke/readmit excluded",
        },
    }


class Runner:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.commands_path = output_dir / "commands.jsonl"
        self.command_records: list[dict[str, object]] = []

    def run(self, label: str, argv: list[str], env_updates: dict[str, str] | None = None) -> int:
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label)
        stdout_path = self.output_dir / f"{safe_label}.stdout.txt"
        stderr_path = self.output_dir / f"{safe_label}.stderr.txt"
        env = os.environ.copy()
        if env_updates:
            env.update(env_updates)
        started = time.perf_counter_ns()
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, check=False)
        elapsed_ns = time.perf_counter_ns() - started
        record = {
            "label": label,
            "argv": argv,
            "cwd": str(ROOT),
            "environmentOverrides": env_updates or {},
            "exitCode": result.returncode,
            "elapsedNs": elapsed_ns,
            "stdout": stdout_path.name,
            "stderr": stderr_path.name,
        }
        self.command_records.append(record)
        with self.commands_path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, sort_keys=True) + "\n")
        return result.returncode


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def trial_values(trials: list[dict[str, object]], path: tuple[str, ...]) -> list[float]:
    values: list[float] = []
    for trial in trials:
        value: object = trial
        for key in path:
            if not isinstance(value, dict):
                break
            value = value.get(key)
        if isinstance(value, (float, int)):
            values.append(float(value))
    return values


def median_or_none(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path, help="new persistent evidence directory")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        parser.error(f"output directory already exists; refusing to overwrite: {output_dir}")
    output_dir.mkdir(parents=True)
    runner = Runner(output_dir)
    metadata = machine_metadata(output_dir)
    (output_dir / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (output_dir / "warmup").mkdir()
    (output_dir / "index-trials").mkdir()
    (output_dir / "crawler-trials").mkdir()

    dependency_fetch_exit = runner.run("fetch-locked-dependencies", ["cargo", "fetch", "--locked"])
    if dependency_fetch_exit == 0:
        test_build = [
            "cargo", "test", "--locked", "--offline", "--release", "--lib",
            BENCH_TEST, "--no-run",
        ]
        test_build_exit = runner.run("build-release-benchmark-test", test_build)
        binary_build = runner.run(
            "build-release-ley-binary",
            ["cargo", "build", "--locked", "--offline", "--release", "--bin", "ley"],
        )
    else:
        test_build_exit = dependency_fetch_exit
        binary_build = dependency_fetch_exit

    index_trials: list[dict[str, object]] = []
    index_warmup_dir = output_dir / "warmup/index"
    index_warmup_dir.mkdir()
    if test_build_exit == 0:
        runner.run(
            "warmup-index-search",
            ["cargo", "test", "--locked", "--offline", "--release", "--lib", BENCH_TEST,
             "--", "--ignored", "--nocapture", "--test-threads=1"],
            {"LEY_GATE7_BENCH_TRIAL": str(index_warmup_dir), "RUST_BACKTRACE": "1"},
        )
        for number in range(1, MEASURED_TRIALS + 1):
            trial_dir = output_dir / "index-trials" / f"trial-{number:02d}"
            trial_dir.mkdir()
            exit_code = runner.run(
                f"index-trial-{number:02d}",
                ["cargo", "test", "--locked", "--offline", "--release", "--lib", BENCH_TEST,
                 "--", "--ignored", "--nocapture", "--test-threads=1"],
                {"LEY_GATE7_BENCH_TRIAL": str(trial_dir), "RUST_BACKTRACE": "1"},
            )
            record: dict[str, object] = {"trial": number, "exitCode": exit_code, "path": str(trial_dir)}
            report_path = trial_dir / "trial.json"
            if exit_code == 0 and report_path.is_file():
                record["report"] = read_json(report_path)
            else:
                record["failure"] = "benchmark command failed or trial.json was not written"
            index_trials.append(record)

    crawler_trials: list[dict[str, object]] = []
    binary = ROOT / "target/release/ley"
    if binary_build == 0 and binary.is_file():
        crawler_warmup = output_dir / "warmup/crawler"
        crawler_warmup.mkdir()
        warm_bundle = crawler_warmup / "bundle"
        runner.run("warmup-loopback-crawler", [str(binary), "controlled-demo", "--retain-dir", str(warm_bundle)])
        for number in range(1, MEASURED_TRIALS + 1):
            trial_dir = output_dir / "crawler-trials" / f"trial-{number:02d}"
            trial_dir.mkdir()
            bundle = trial_dir / "bundle"
            exit_code = runner.run(
                f"crawler-trial-{number:02d}",
                [str(binary), "controlled-demo", "--retain-dir", str(bundle)],
            )
            stdout_path = output_dir / f"crawler-trial-{number:02d}.stdout.txt"
            stdout = stdout_path.read_text(encoding="utf-8") if stdout_path.exists() else ""
            match = re.search(r"^First crawl timing: (\{.*\})$", stdout, re.MULTILINE)
            record = {"trial": number, "exitCode": exit_code, "path": str(trial_dir)}
            if exit_code == 0 and match:
                record["measurement"] = json.loads(match.group(1))
            else:
                record["failure"] = "controlled demo failed or timing record was not found"
            crawler_trials.append(record)

    successful_index = [
        record["report"] for record in index_trials
        if record.get("exitCode") == 0 and isinstance(record.get("report"), dict)
    ]
    successful_crawler = [
        record["measurement"] for record in crawler_trials
        if record.get("exitCode") == 0 and isinstance(record.get("measurement"), dict)
    ]
    docs_per_second = trial_values(successful_index, ("indexing", "documentsPerSecond"))
    search_p50 = trial_values(successful_index, ("search", "aggregate", "p50Ns"))
    search_p95 = trial_values(successful_index, ("search", "aggregate", "p95Ns"))
    qps = trial_values(successful_index, ("search", "throughput", "queriesPerSecond"))
    compact_ns = trial_values(successful_index, ("compaction", "elapsedNs"))
    page_rates = trial_values(successful_crawler, ("pagesPerSecond",))
    request_rates: list[float] = []
    for measurement in successful_crawler:
        duration_ns = measurement.get("durationNs", 0)
        requests = measurement.get("requests", 0)
        if isinstance(duration_ns, (int, float)) and duration_ns > 0:
            request_rates.append(float(requests) / (float(duration_ns) / 1_000_000_000))

    failed = [record for record in runner.command_records if record["exitCode"] != 0]
    summary = {
        "schema": "ley-gate7-benchmark-summary-v1",
        "status": "complete" if len(successful_index) == MEASURED_TRIALS and len(successful_crawler) == MEASURED_TRIALS and not failed else "incomplete",
        "measuredIndexTrials": len(successful_index),
        "measuredCrawlerTrials": len(successful_crawler),
        "failedCommands": failed,
        "indexingDocumentsPerSecond": {"median": median_or_none(docs_per_second), "samples": docs_per_second},
        "queryP50NsAcrossWarmTrials": {"medianOfTrialP50": median_or_none(search_p50), "samples": search_p50},
        "queryP95NsAcrossWarmTrials": {"medianOfTrialP95": median_or_none(search_p95), "samples": search_p95},
        "queryThroughputPerSecond": {"median": median_or_none(qps), "samples": qps},
        "compactionElapsedNs": {"median": median_or_none(compact_ns), "samples": compact_ns},
        "loopbackCrawlerPagesPerSecond": {"median": median_or_none(page_rates), "samples": page_rates},
        "loopbackCrawlerRequestsPerSecond": {"median": median_or_none(request_rates), "samples": request_rates},
        "indexTrials": index_trials,
        "crawlerTrials": crawler_trials,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    status = summary["status"]
    print(f"Gate 7 benchmark {status}: {output_dir}")
    return 0 if status == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
