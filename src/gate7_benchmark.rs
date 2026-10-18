use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::index::{InMemoryIndex, SearchResult, StatisticsSource};
use crate::storage::{Intent, PersistentIndex, ReadView};
use crate::url_key::UrlKey;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    schema: String,
    description: String,
    documents: Vec<WorkloadDocument>,
    queries: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadDocument {
    id: String,
    title: String,
    body: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ParityRecord {
    query: String,
    result_count: usize,
    full_result_debug_sha256: String,
}

#[test]
#[ignore = "run only through tools/run_gate7_benchmark.py with a fresh trial directory"]
fn fixed_workload_benchmark() {
    let output_dir = std::env::var_os("LEY_GATE7_BENCH_TRIAL")
        .map(PathBuf::from)
        .expect("runner must set LEY_GATE7_BENCH_TRIAL");
    assert!(output_dir.is_dir(), "trial directory must exist");

    let workload_bytes = include_bytes!("../fixtures/benchmark-v1.json");
    let workload_hash = hex_digest(Sha256::digest(workload_bytes).as_slice());
    let expected_hash = include_str!("../fixtures/benchmark-v1.sha256").trim();
    assert_eq!(workload_hash, expected_hash, "benchmark workload checksum");
    let workload: Workload = serde_json::from_slice(workload_bytes).expect("valid workload JSON");
    assert_eq!(workload.schema, "ley-benchmark-workload-v1");
    assert!(!workload.description.is_empty());
    assert!(!workload.documents.is_empty());
    assert!(!workload.queries.is_empty());

    let mut reference = InMemoryIndex::new();
    for document in &workload.documents {
        reference
            .insert_fields(
                document.id.clone(),
                document.id.clone(),
                document.title.clone(),
                document.body.clone(),
            )
            .expect("valid workload document");
    }

    // Prove the semantic oracle and persistent query path agree before any
    // timed measurement is accepted.
    let validation_path = output_dir.join("validation");
    let validation = index_workload(&validation_path, &workload.documents);
    let validation_view = validation.read_view().expect("validation read view");
    let validation_parity =
        assert_reference_parity(&validation_view, &reference, &workload.queries);
    drop(validation_view);
    drop(validation);

    let measured_path = output_dir.join("measured");
    let indexing_started = Instant::now();
    let measured = index_workload(&measured_path, &workload.documents);
    let indexing_elapsed = indexing_started.elapsed();
    let measured_view = measured.read_view().expect("measured read view");
    let before_compaction_parity =
        assert_reference_parity(&measured_view, &reference, &workload.queries);

    // Query timing starts only after the complete measured store has passed
    // exact independent-reference comparison.
    let query_measurement = measure_queries(&measured_view, &workload.queries);
    let bytes_before_compaction = regular_file_bytes(&measured_path);
    let peak_rss_before_compaction = process_peak_rss_bytes();
    drop(measured_view);
    drop(measured);

    let reopened = PersistentIndex::open(&measured_path).expect("reopen measured index");
    let reopened_view = reopened.read_view().expect("reopened read view");
    let reopened_parity = assert_reference_parity(&reopened_view, &reference, &workload.queries);
    drop(reopened_view);
    let compaction_started = Instant::now();
    let compaction = reopened.compact().expect("compact measured index");
    let compaction_elapsed = compaction_started.elapsed();
    let compacted_view = reopened.read_view().expect("compacted read view");
    let compacted_parity = assert_reference_parity(&compacted_view, &reference, &workload.queries);
    let bytes_after_compaction = regular_file_bytes(&measured_path);
    let peak_rss_bytes = process_peak_rss_bytes().max(peak_rss_before_compaction);
    let title_bytes: usize = workload.documents.iter().map(|doc| doc.title.len()).sum();
    let body_bytes: usize = workload.documents.iter().map(|doc| doc.body.len()).sum();
    let token_count: usize = reference
        .documents()
        .values()
        .map(|doc| doc.title_terms.len() + doc.body_terms.len())
        .sum();
    let compaction_input_bytes: u64 = compaction
        .merged_segments
        .iter()
        .map(|item| item.byte_len)
        .sum();
    let compaction_output_bytes: u64 = compaction
        .replacement_segments
        .iter()
        .map(|item| item.byte_len)
        .sum();
    let indexing_ns = indexing_elapsed.as_nanos();
    let compaction_ns = compaction_elapsed.as_nanos();
    let report = serde_json::json!({
        "schema": "ley-gate7-benchmark-trial-v1",
        "workload": {
            "path": "fixtures/benchmark-v1.json",
            "sha256": workload_hash,
            "description": workload.description,
            "documentCount": workload.documents.len(),
            "queryCount": workload.queries.len(),
            "queries": workload.queries,
            "titleUtf8Bytes": title_bytes,
            "bodyUtf8Bytes": body_bytes,
            "totalAnalyzedTokens": token_count,
            "documentsByTopic": topic_counts(&workload.documents),
        },
        "build": {
            "crateVersion": env!("CARGO_PKG_VERSION"),
            "profile": "release",
            "analyzerId": crate::analyzer::ANALYZER_ID,
            "storageFormat": "manifest 1.0, segment 1.0",
        },
        "correctness": {
            "validationBeforeTiming": validation_parity,
            "measuredBeforeQueryTiming": before_compaction_parity,
            "afterReopen": reopened_parity,
            "afterCompaction": compacted_parity,
            "compactionNewGeneration": compaction.new_generation,
        },
        "indexing": {
            "elapsedNs": indexing_ns,
            "documents": workload.documents.len(),
            "documentsPerSecond": workload.documents.len() as f64 / indexing_elapsed.as_secs_f64(),
            "definition": "wall time from immediately before fresh store creation through URL parsing, per-document fencing, analysis, segment append, and manifest publication; includes store creation and excludes workload JSON loading, correctness validation, reference parity checks, and compaction",
        },
        "search": query_measurement,
        "persistentDisk": {
            "bytesAfterInitialIndexing": bytes_before_compaction,
            "bytesAfterCompaction": bytes_after_compaction,
            "measurement": "sum of regular-file lengths recursively under the measured index directory, including manifests, segment files, and retained history; excludes the validation store and frontier",
        },
        "compaction": {
            "elapsedNs": compaction_ns,
            "mergedSegmentCount": compaction.merged_segments.len(),
            "replacementSegmentCount": compaction.replacement_segments.len(),
            "mergedSegmentBytes": compaction_input_bytes,
            "replacementSegmentBytes": compaction_output_bytes,
            "definition": "PersistentIndex::compact wall time and segment descriptors; includes replacement write and commit, excludes subsequent filesystem inventory",
        },
        "memory": {
            "processPeakRssBytes": peak_rss_bytes,
            "measurement": "Linux /proc/self/status VmHWM for the entire isolated release test process; includes Rust test harness, reference corpus, validation store work, measured store, and benchmark allocations; not an isolated index heap measurement",
        },
        "cachePolicy": "fresh validation and measured stores per trial; OS page cache is not flushed; each query batch has 20 complete warmup passes before timed samples",
    });
    let report_path = output_dir.join("trial.json");
    fs::write(
        report_path,
        serde_json::to_vec_pretty(&report).expect("serialize benchmark report"),
    )
    .expect("write benchmark report");
}

fn index_workload(path: &Path, documents: &[WorkloadDocument]) -> PersistentIndex {
    let store = PersistentIndex::create(path).expect("create fresh workload store");
    for document in documents {
        let key = UrlKey::parse(&document.id).expect("valid fixture URL key");
        let lease = store.issue_fence(&key).expect("issue document fence");
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: document.id.clone(),
                    title: document.title.clone(),
                    body: document.body.clone(),
                },
            )
            .expect("append document and publish generation");
    }
    store
}

fn assert_reference_parity(
    view: &ReadView,
    reference: &InMemoryIndex,
    queries: &[String],
) -> Vec<ParityRecord> {
    queries
        .iter()
        .map(|expression| {
            let actual = view.query(expression).expect("persistent query");
            assert!(
                !actual.is_empty(),
                "fixed benchmark query should select documents: {expression}"
            );
            let parsed = crate::query::parse_query(expression).expect("parse benchmark query");
            let mut expected: Vec<SearchResult> =
                crate::reference::exhaustive_search(reference, &parsed)
                    .into_iter()
                    .map(|hit| hit.result)
                    .collect();
            for result in &mut expected {
                result.explanation.statistics_source =
                    StatisticsSource::PersistentGeneration(view.generation_id());
            }
            assert_eq!(
                actual, expected,
                "independent reference parity: {expression}"
            );
            ParityRecord {
                query: expression.clone(),
                result_count: actual.len(),
                full_result_debug_sha256: digest_debug(&actual),
            }
        })
        .collect()
}

fn measure_queries(view: &ReadView, queries: &[String]) -> serde_json::Value {
    for _ in 0..20 {
        for expression in queries {
            view.query(expression).expect("query warmup");
        }
    }
    let mut samples = BTreeMap::<String, Vec<u128>>::new();
    let batch_started = Instant::now();
    for _ in 0..100 {
        for expression in queries {
            let started = Instant::now();
            view.query(expression).expect("timed query");
            samples
                .entry(expression.clone())
                .or_default()
                .push(started.elapsed().as_nanos());
        }
    }
    let batch_elapsed = batch_started.elapsed();
    let mut per_query = serde_json::Map::new();
    let all_samples: Vec<u128> = samples.values().flatten().copied().collect();
    for (expression, values) in &samples {
        let (p50, p95) = percentiles(values);
        per_query.insert(
            expression.clone(),
            serde_json::json!({
                "sampleCount": values.len(),
                "samplesNs": values,
                "p50Ns": p50,
                "p95Ns": p95,
            }),
        );
    }
    let (p50, p95) = percentiles(&all_samples);
    serde_json::json!({
        "perQuery": per_query,
        "aggregate": {
            "sampleCount": all_samples.len(),
            "p50Ns": p50,
            "p95Ns": p95,
        },
        "throughput": {
            "queries": all_samples.len(),
            "elapsedNs": batch_elapsed.as_nanos(),
            "queriesPerSecond": all_samples.len() as f64 / batch_elapsed.as_secs_f64(),
            "definition": "completed PersistentIndex::ReadView::query calls divided by one wall-clock batch interval across 100 repetitions of every manifest query; includes parser, retrieval, BM25 scoring, explanations, result disposal, loop and per-call timer overhead, BTreeMap sample lookup or insertion, and sample-vector recording; excludes HTTP/API/JSON/UI",
        },
        "latencyDefinition": "individual warm-cache samples start immediately before ReadView::query and read elapsed time after the result is dropped and the cloned expression's BTreeMap sample entry is looked up or inserted; includes query parsing, postings/statistics, ranking, matches, explanations, result disposal, expression cloning, map bookkeeping, and elapsed-timer read overhead; excludes the subsequent sample-vector append, process startup, and HTTP/API/JSON/UI serialization",
    })
}

fn percentiles(values: &[u128]) -> (u128, u128) {
    assert!(!values.is_empty());
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let nearest_rank = |fraction: f64| {
        let rank = (fraction * sorted.len() as f64).ceil() as usize;
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
    };
    (nearest_rank(0.50), nearest_rank(0.95))
}

fn topic_counts(documents: &[WorkloadDocument]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for document in documents {
        let topic = document
            .title
            .split_whitespace()
            .nth(1)
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        *counts.entry(topic).or_default() += 1;
    }
    counts
}

fn regular_file_bytes(path: &Path) -> u64 {
    let mut bytes = 0;
    let mut pending = vec![path.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(current).expect("read benchmark store directory") {
            let entry = entry.expect("read benchmark store entry");
            let kind = entry.file_type().expect("read benchmark entry type");
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                bytes += entry
                    .metadata()
                    .expect("read benchmark file metadata")
                    .len();
            }
        }
    }
    bytes
}

fn process_peak_rss_bytes() -> u64 {
    let status = fs::read_to_string("/proc/self/status").expect("Linux procfs is required");
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:")?.split_whitespace().next())
        .expect("Linux procfs VmHWM");
    kib.parse::<u64>().expect("numeric VmHWM") * 1024
}

fn digest_debug(value: &impl Debug) -> String {
    hex_digest(Sha256::digest(format!("{value:?}").as_bytes()).as_slice())
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
