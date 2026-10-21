#!/usr/bin/env python3
"""Run the frozen Stage C S1 task set against three local collection stores."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter
from urllib.parse import urlsplit


PROFILES = ("seed-only", "link-discovery", "extra-seeds")
RUN_PHASES = ("v1", "v2", "404-confirmation")
MAX_HITS = 4


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def tree_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"refusing to hash collection symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def checked_manifest(path: pathlib.Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    expected_path = path.with_suffix(".sha256")
    expected = expected_path.read_text(encoding="utf-8").split()[0]
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ValueError(f"frozen task manifest hash mismatch: {actual} != {expected}")
    manifest = json.loads(raw)
    if not manifest.get("frozen_before_candidate_crawls_and_retrieval"):
        raise ValueError("task manifest does not declare a pre-candidate freeze")
    for task in manifest["tasks"]:
        for passage in task["expected_support_passages"]:
            actual_text_hash = hashlib.sha256(
                passage["contains_exact_text"].encode("utf-8")
            ).hexdigest()
            if actual_text_hash != passage["text_sha256"]:
                raise ValueError(f"expected passage hash mismatch in task {task['id']}")
    corpus_root = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "stage-c-s1"
    actual_route_hash = hashlib.sha256((corpus_root / "routes.json").read_bytes()).hexdigest()
    if actual_route_hash != manifest["collection"]["route_manifest_sha256"]:
        raise ValueError("fixture route manifest hash differs from the frozen evaluation")
    actual_dataset_hash = fixture_dataset_sha256(corpus_root)
    if actual_dataset_hash != manifest["collection"]["dataset_sha256"]:
        raise ValueError("fixture dataset hash differs from the frozen evaluation")
    return manifest, actual


def fixture_dataset_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"refusing to hash fixture symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        # The task manifest has its own frozen hash and is not crawl input.
        if relative in {
            b"evaluation-tasks-v1.json",
            b"evaluation-tasks-v1.sha256",
        }:
            continue
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def run_status(binary: pathlib.Path, workspace: pathlib.Path, source_id: str) -> tuple[dict, dict]:
    before = tree_sha256(workspace)
    command = [
        str(binary),
        "crawl-status",
        "--store",
        str(workspace / "store"),
        "--frontier",
        str(workspace / "frontier.sqlite"),
        "--source-id",
        source_id,
        "--fixture-clock",
        str(workspace / "fixture-clock.json"),
        "--include-url-inventory",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"crawl-status failed: {completed.stderr.strip()}")
    status = json.loads(completed.stdout)
    after = tree_sha256(workspace)
    if before != after:
        raise RuntimeError(f"read-only status changed bytes in {workspace}")
    if not status.get("readOnly") or status["definitions"].get("privateHtmlOrBodyInOutput"):
        raise RuntimeError("crawl-status did not return the declared read-only metadata contract")
    return status, {"treeSha256Before": before, "treeSha256After": after, "unchanged": before == after}


def run_reports(
    evidence_root: pathlib.Path,
    profile: str,
    expected_source_urls: list[str],
    expected_source_id: str,
    expected_origin: str,
    expected_store_identity: str,
    expected_dataset_hash: str,
) -> list[dict]:
    reports = []
    for phase in RUN_PHASES:
        path = evidence_root / f"{profile}-run-{phase}.json"
        report = read_json(path)
        if report.get("profile") != profile or not report.get("runUntilIdleReturnedSuccessfully"):
            raise ValueError(f"invalid or incomplete run report: {path}")
        if (
            report.get("sourceUrlKeys") != expected_source_urls
            or report.get("sourceId") != expected_source_id
            or report.get("origin") != expected_origin
            or report.get("storeIdentity") != expected_store_identity
            or report.get("datasetSha256") != expected_dataset_hash
        ):
            raise ValueError(f"run report identity mismatch: {path}")
        audit = report.get("destinationAudit", {})
        if audit.get("unexpectedDestinations") or audit.get("proxyUsed"):
            raise ValueError(f"run report contains an unexpected destination or proxy: {path}")
        expected_peer = urlsplit(expected_origin).netloc
        for evidence in report.get("networkEvidence", []):
            requested = urlsplit(evidence.get("requestedUrl", ""))
            if f"{requested.scheme}://{requested.netloc}" != expected_origin:
                raise ValueError(f"request evidence escaped the fixture origin: {path}")
            if evidence.get("connectedPeer") != expected_peer:
                raise ValueError(f"connected peer escaped the owned listener: {path}")
            resolved = evidence.get("resolvedAddresses", [])
            if not resolved or any(address != expected_peer for address in resolved):
                raise ValueError(f"resolved destination escaped the owned listener: {path}")
            if evidence.get("proxyUsed"):
                raise ValueError(f"a proxy was reported for owned fixture traffic: {path}")
        reports.append(report)
    return reports


def aggregate_run_metrics(reports: list[dict]) -> dict:
    status_counts: Counter[str] = Counter()
    counts: Counter[str] = Counter()
    discovery: Counter[str] = Counter()
    wire_bytes = 0
    decoded_bytes = 0
    elapsed_ns = 0
    rss_high_water = []
    apply_latency = []
    for report in reports:
        for name, value in report["counts"].items():
            if name == "httpStatus":
                continue
            if name == "linkDiscovery":
                discovery.update(value)
            elif isinstance(value, (int, float)):
                counts[name] += value
        for status, count in report["counts"].get("httpStatus", {}).items():
            status_counts[str(status)] += count
        wire_bytes += report["receivedEntityBytes"]["wire"]
        decoded_bytes += report["receivedEntityBytes"]["decoded"]
        elapsed_ns += report["elapsedNanoseconds"]
        if report.get("rssHighWaterBytes") is not None:
            rss_high_water.append(report["rssHighWaterBytes"])
        apply_latency.append(report.get("indexApplyLatency", {}))
    return {
        "invocations": len(reports),
        "processIds": [report.get("processId") for report in reports],
        "requests": counts["requests"],
        "responseEvidence": counts["responseEvidence"],
        "httpStatus": dict(sorted(status_counts.items())),
        "pagesFetched": counts["pagesFetched"],
        "indexedIntentsApplied": counts["indexedIntentsApplied"],
        "tombstoned": counts["tombstoned"],
        "retries": counts["retries"],
        "disallowed": counts["disallowed"],
        "duplicateUrls": counts["duplicateUrls"],
        "failedPages": counts["failedPages"],
        "transportFailures": counts["transportFailures"],
        "rejectedIntents": counts["rejectedIntents"],
        "outboxReplays": counts["outboxReplays"],
        "linkDiscovery": dict(sorted(discovery.items())),
        "wireEntityBytes": wire_bytes,
        "decodedEntityBytes": decoded_bytes,
        "elapsedNanosecondsSum": elapsed_ns,
        "peakReportedRssHighWaterBytes": max(rss_high_water, default=None),
        "perInvocationWorkspaceDiskBytes": [report.get("workspaceDiskBytes") for report in reports],
        "perInvocationIndexApplyLatency": apply_latency,
        "singleWriterMeasurementsDoNotResolveM2FourReaderP95Risk": True,
    }


def evaluate_task(
    binary: pathlib.Path,
    store: pathlib.Path,
    task: dict,
    inventory_by_url: dict[str, dict],
) -> dict:
    command = [
        str(binary),
        "retrieve",
        "--store",
        str(store),
        "--question",
        task["question"],
        "--max-hits",
        str(MAX_HITS),
    ]
    started = time.perf_counter_ns()
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    elapsed = time.perf_counter_ns() - started
    response = None
    parse_error = None
    if completed.returncode == 0:
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            parse_error = str(error)
    hits = response.get("hits", []) if response else []
    expected_sources = task["expected_source_urls"]
    source_coverage = []
    for url in expected_sources:
        item = inventory_by_url.get(url)
        source_coverage.append(
            {
                "expectedSourceUrl": url,
                "frontierState": item.get("state") if item else None,
                "frontierDiscovered": item is not None,
                "indexedLive": bool(item and item.get("indexedLive")),
                "presentInTopK": any(hit.get("requested_url") == url for hit in hits),
            }
        )
    passage_support = []
    for expected in task["expected_support_passages"]:
        expected_url = expected["source_url"]
        expected_text = expected["contains_exact_text"]
        passage_support.append(
            {
                "expectedSourceUrl": expected_url,
                "expectedTextSha256": expected["text_sha256"],
                "foundExactTextInTopK": any(
                    hit.get("requested_url") == expected_url
                    and expected_text in hit.get("passage", {}).get("text", "")
                    for hit in hits
                ),
            }
        )
    outcome = {
        "taskId": task["id"],
        "split": task["split"],
        "kind": task["kind"],
        "question": task["question"],
        "processExitCode": completed.returncode,
        "elapsedNanoseconds": elapsed,
        "stderr": completed.stderr.strip(),
        "responseParseError": parse_error,
        "rawResponse": response,
        "sourceCoverage": {
            "coveredExpectedSources": sum(item["indexedLive"] for item in source_coverage),
            "expectedSourceCount": len(source_coverage),
            "expectedSources": source_coverage,
        },
        "topKPassageSupport": {
            "supportedExpectedPassages": sum(item["foundExactTextInTopK"] for item in passage_support),
            "expectedPassageCount": len(passage_support),
            "expectedPassages": passage_support,
        },
    }
    if task["kind"] in {"negative", "ambiguous"}:
        outcome["falsePositiveAssessment"] = (
            "not_assessed; preserve raw hits for independent judgment; no confidence assigned"
        )
    return outcome


def split_summary(outcomes: list[dict], split: str) -> dict:
    selected = [outcome for outcome in outcomes if outcome["split"] == split]
    sources = [
        source
        for outcome in selected
        for source in outcome["sourceCoverage"]["expectedSources"]
    ]
    passages = [
        passage
        for outcome in selected
        for passage in outcome["topKPassageSupport"]["expectedPassages"]
    ]
    return {
        "tasks": len(selected),
        "indexedExpectedSourceReferences": sum(source["indexedLive"] for source in sources),
        "expectedSourceReferences": len(sources),
        "supportedExpectedPassagesInTopK": sum(passage["foundExactTextInTopK"] for passage in passages),
        "expectedPassages": len(passages),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--evidence-root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    evidence_root = args.evidence_root.resolve()
    output = args.output.resolve()
    output.relative_to(evidence_root)
    if output.exists():
        raise ValueError(f"refusing to overwrite evaluation output: {output}")
    manifest, manifest_hash = checked_manifest(args.manifest)
    frozen = manifest["collection"]
    if frozen["origin"] != "http://127.0.0.1:41697":
        raise ValueError("frozen evaluation origin changed; do not rewrite task URL identities")
    profile_results = {}
    common_budget = None
    for profile in PROFILES:
        workspace = evidence_root / profile
        config = read_json(workspace / "collection.json")
        if config["profile"] != profile or config["source_id"] != frozen["source_id"]:
            raise ValueError(f"collection identity mismatch for profile {profile}")
        if config["origin"] != frozen["origin"] or config["dataset_sha256"] != frozen["dataset_sha256"]:
            raise ValueError(f"origin or fixture hash mismatch for profile {profile}")
        actual_seed_urls = config["seed_urls"]
        if actual_seed_urls != frozen["profile_seed_url_keys"][profile]:
            raise ValueError(f"seed URL identity changed for profile {profile}")
        status, status_hashes = run_status(binary, workspace, frozen["source_id"])
        source = status["sources"][0]
        if source["id"] != frozen["source_id"] or status["store"]["identity"] != config["store_identity"]:
            raise ValueError(f"status store/source identity mismatch for profile {profile}")
        inventory = source.get("frontierUrlInventory")
        if inventory is None:
            raise ValueError(f"crawl-status did not return URL inventory for {profile}")
        inventory_by_url = {item["urlKey"]: item for item in inventory}
        if len(inventory_by_url) != len(inventory):
            raise ValueError(f"duplicate frontier URL key in {profile}")
        reports = run_reports(
            evidence_root,
            profile,
            frozen["source_url_keys"],
            frozen["source_id"],
            frozen["origin"],
            config["store_identity"],
            frozen["dataset_sha256"],
        )
        budgets = [report["limits"] for report in reports]
        if any(budget != budgets[0] for budget in budgets[1:]):
            raise ValueError(f"per-invocation budgets changed during {profile}")
        if common_budget is None:
            common_budget = budgets[0]
        elif budgets[0] != common_budget:
            raise ValueError("profiles do not share the same declared invocation budget")
        outcomes = [
            evaluate_task(binary, workspace / "store", task, inventory_by_url)
            for task in manifest["tasks"]
        ]
        expected_source_urls = {
            url for task in manifest["tasks"] for url in task["expected_source_urls"]
        }
        indexed_expected_urls = sorted(
            url
            for url in expected_source_urls
            if inventory_by_url.get(url, {}).get("indexedLive", False)
        )
        known_source_coverage = [
            {
                "sourceUrl": url,
                "frontierState": inventory_by_url.get(url, {}).get("state"),
                "frontierDiscovered": url in inventory_by_url,
                "indexedLive": bool(inventory_by_url.get(url, {}).get("indexedLive", False)),
            }
            for url in frozen["source_url_keys"]
        ]
        profile_results[profile] = {
            "storeIdentity": config["store_identity"],
            "sourceId": source["id"],
            "origin": config["origin"],
            "sourceUrlKeys": frozen["source_url_keys"],
            "seedUrlKeys": actual_seed_urls,
            "linkDiscoveryEnabled": config["link_discovery_enabled"],
            "runMetrics": aggregate_run_metrics(reports),
            "persistentRequestBudget": source["persistentRequests"],
            "indexedLiveUrlCount": source["currentlyIndexedLiveUrls"],
            "removedFrontierUrlCount": source["removedFrontierUrls"],
            "uniqueExpectedSourceCoverage": {
                "indexedLiveUrls": indexed_expected_urls,
                "coveredCount": len(indexed_expected_urls),
                "expectedUniqueSourceUrlCount": len(expected_source_urls),
            },
            "knownSourceCoverage": {
                "indexedLiveCount": sum(item["indexedLive"] for item in known_source_coverage),
                "frontierDiscoveredCount": sum(item["frontierDiscovered"] for item in known_source_coverage),
                "knownSourceUrlCount": len(known_source_coverage),
                "urls": known_source_coverage,
            },
            "readOnlyStatusByteHashes": status_hashes,
            "readOnlyStatus": status,
            "taskOutcomes": outcomes,
            "developmentSummary": split_summary(outcomes, "development"),
            "heldoutSummary": split_summary(outcomes, "heldout"),
        }
    result = {
        "schema": "ley-stage-c-s1-evaluation-results-v1",
        "frozenTaskManifestSha256": manifest_hash,
        "frozenBeforeCandidateOutput": True,
        "judgmentProvenance": manifest["authoring_and_judgment_provenance"],
        "retrievalContract": manifest["protocol"]["retrieval_contract"],
        "topK": MAX_HITS,
        "budgetsCompared": common_budget,
        "sourceCoverageAndTopKPassageSupportAreSeparate": True,
        "heldoutNotUsedForTuning": True,
        "negativeAndAmbiguousHitsAreNotAutomaticallyLabeledFalsePositive": True,
        "profileResults": profile_results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json_bytes(result))
    print(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(f"evaluation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
