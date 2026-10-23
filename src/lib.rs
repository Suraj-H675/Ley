pub mod analyzer;
pub mod api;
pub(crate) mod controlled_crawler;
mod crawl_status;
mod crawler;
mod demo;
pub mod html;
pub mod index;
mod local_collection;
#[cfg(target_os = "linux")]
mod managed_collection;
#[cfg(not(target_os = "linux"))]
mod managed_collection {
    pub(crate) fn run_cli(_args: Vec<String>) -> Result<String, String> {
        Err("managed local HTML collections currently require Linux".to_owned())
    }
}
pub mod local_ingest;
pub mod mcp;
mod page_policy;
pub mod public_policy;
mod query;
pub mod retrieval;
mod robots;
mod safe_fetch;
pub mod storage;
pub mod url_key;

#[cfg(test)]
mod reference;

#[cfg(test)]
mod gate7_benchmark;

pub use demo::{
    DemoError, DemoOutput, DemoStats, create_search_fixture_index, run_controlled_fixture_demo,
    run_controlled_fixture_demo_retained, run_demo, run_demo_with_options,
};
pub use retrieval::{
    AnswerAssessment, DOCUMENT_INSPECTION_CONTRACT_VERSION, DOCUMENT_INSPECTION_PAGE_BYTES,
    DocumentInspectionPage, DocumentInspectionRequest, EvidenceHit, EvidencePassage,
    EvidenceReference, EvidenceResolveError, InsufficientEvidenceReason, QuestionRequest,
    ResolvedEvidence, RetrievalCompleteness, RetrievalError, RetrievalMode, RetrievalRequest,
    RetrievalResponse, RetrievalStatus,
};

pub fn crawl_status_json(
    store_path: impl AsRef<std::path::Path>,
    frontier_path: impl AsRef<std::path::Path>,
    source_id: Option<&str>,
    fixture_clock_path: Option<&std::path::Path>,
    include_url_inventory: bool,
) -> Result<String, String> {
    crawl_status::status_json(
        store_path.as_ref(),
        frontier_path.as_ref(),
        source_id,
        fixture_clock_path,
        include_url_inventory,
    )
}

pub fn run_fixture_collection(args: &[String]) -> Result<String, String> {
    local_collection::run_cli(args)
}

#[derive(Debug, Eq, PartialEq)]
pub struct PublicCrawlOutput {
    pub report_json: String,
    pub bounded_run_finished: bool,
}

pub fn run_public_crawl(
    policy: &public_policy::PublicCrawlPolicy,
    index_path: impl AsRef<std::path::Path>,
    frontier_path: impl AsRef<std::path::Path>,
    request_count: usize,
    approved_policy_sha256: &str,
    allow_public_requests: bool,
) -> Result<PublicCrawlOutput, String> {
    if !allow_public_requests {
        return Err("public crawl requires explicit request opt-in".to_owned());
    }
    if !policy.matches_sha256(approved_policy_sha256) {
        return Err("public crawl policy hash does not match the approved digest".to_owned());
    }
    let result = controlled_crawler::run_public_crawl(
        index_path.as_ref(),
        frontier_path.as_ref(),
        policy,
        request_count,
    )
    .map_err(|_| {
        "bounded public crawl stopped; inspect the private frontier event log".to_owned()
    })?;
    let report = &result.report;
    let output = serde_json::json!({
        "schema": "ley-public-crawl-report-v1",
        "policySha256": policy.sha256(),
        "requestBudget": request_count,
        "maxRuntimeSeconds": 60,
        "stopReason": result.stop_reason.as_str(),
        "boundedRunFinished": result.stop_reason.bounded_run_finished(),
        "counts": {
            "requests": report.requests,
            "pagesFetched": report.pages_fetched,
            "accepted": report.indexed,
            "skipped": report.disallowed,
            "rejected": report.rejected_intents,
            "failed": report.failed_pages.saturating_add(report.transport_failures),
            "duplicates": report.duplicate_urls,
            "failedPages": report.failed_pages,
            "failedTransportRequests": report.transport_failures,
            "retrySchedules": report.retries,
            "tombstoned": report.tombstoned,
        },
        "linkDiscovery": {
            "candidates": report.link_discovery.candidates(),
            "enqueued": report.link_discovery.enqueued,
            "sourceDenied": report.link_discovery.source_denied,
            "duplicates": report.link_discovery.duplicates,
            "malformed": report.link_discovery.malformed,
            "capacity": report.link_discovery.capacity,
        },
        "skippedReasons": report.skipped_reasons,
        "failureReasons": report.failure_reasons,
        "receivedBodyBytes": {
            "wire": report.compressed_bytes,
            "decoded": report.decompressed_bytes,
        },
        "countDefinitions": {
            "accepted": "index upsert intents acknowledged by the durable generation",
            "skipped": "page candidates withheld by source scope or robots policy; discovered-link outcomes are reported separately in linkDiscovery",
            "rejected": "durable index intents rejected by the fencing authority",
            "failed": "terminal failed pages plus fetches without a usable HTTP response; retry schedules are reported separately",
            "duplicates": "duplicate normalized outgoing URLs removed during HTML extraction; frontier duplicates are counted in linkDiscovery.duplicates",
            "linkDiscovery": "non-overlapping outcomes for each unique extracted link candidate processed after durable completion: enqueued, sourceDenied, duplicates, malformed, or capacity; replayed outbox completions are counted once",
            "receivedBodyBytes": "response entity bytes only; headers, TLS, and protocol framing are excluded; wire is pre-decompression and decoded is post-decompression",
        },
        "connectedDestinations": report.network_evidence,
    });
    let report_json = serde_json::to_string_pretty(&output)
        .map_err(|_| "could not serialize the crawl report".to_owned())?;
    Ok(PublicCrawlOutput {
        report_json,
        bounded_run_finished: result.stop_reason.bounded_run_finished(),
    })
}

pub fn revoke_public_source(
    index_path: impl AsRef<std::path::Path>,
    frontier_path: impl AsRef<std::path::Path>,
    source_id: &str,
) -> Result<(), String> {
    controlled_crawler::revoke_public_source(index_path.as_ref(), frontier_path.as_ref(), source_id)
        .map_err(|_| "could not revoke the requested public source".to_owned())
}

/// Entry point used by the command line adapter for managed local HTML collections.
#[doc(hidden)]
pub fn run_managed_local_collection_cli(args: Vec<String>) -> Result<String, String> {
    managed_collection::run_cli(args).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{public_policy::PublicCrawlPolicy, run_public_crawl};

    #[test]
    fn public_library_entry_requires_opt_in_and_exact_hash_before_opening_paths() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ley-public-api-test-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let policy_path = directory.join("policy.json");
        std::fs::write(
            &policy_path,
            include_bytes!("../policy/public-sources.json"),
        )
        .unwrap();
        let policy = PublicCrawlPolicy::load(&policy_path).unwrap();
        let store = directory.join("store");
        let frontier = directory.join("frontier.sqlite");

        assert_eq!(
            run_public_crawl(&policy, &store, &frontier, 1, &policy.sha256(), false,),
            Err("public crawl requires explicit request opt-in".to_owned())
        );
        assert_eq!(
            run_public_crawl(&policy, &store, &frontier, 1, &"0".repeat(64), true),
            Err("public crawl policy hash does not match the approved digest".to_owned())
        );
        assert_eq!(
            run_public_crawl(&policy, &store, &frontier, 1, &policy.sha256(), true),
            Err("bounded public crawl stopped; inspect the private frontier event log".to_owned())
        );
        assert!(!store.exists());
        assert!(!frontier.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
