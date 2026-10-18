use crate::controlled_crawler::{
    Clock, ControlledCrawler, CrawlCancellation, CrawlLimits, SourcePolicy, SystemClock,
};
use crate::crawler::{
    CrawlConfig, CrawlError, CrawlStats, FixtureResponse, LocalFixture, crawl_fixture,
};
use crate::index::{FieldScoreExplanation, MatchEvidence, QueryError, SearchResult};
use crate::query::parse_query;
use crate::safe_fetch::SystemResolver;
use crate::storage::PersistentIndex;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LoopbackManifest {
    schema: String,
    source_id: String,
    seed_path: String,
    private_path: String,
    redirect_requested_path: String,
    redirect_effective_path: String,
    redirect_identity_query: String,
    expected_indexed_paths: Vec<String>,
    queries: Vec<String>,
    routes: Vec<LoopbackRoute>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LoopbackRoute {
    path: String,
    status: u16,
    content_type: String,
    headers: Vec<[String; 2]>,
    body: String,
}

#[derive(Clone, Debug)]
pub struct DemoOutput {
    pub stdout: String,
    pub request_log: Vec<String>,
    pub results: Vec<SearchResult>,
    pub stats: DemoStats,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemoStats {
    pub requests: usize,
    pub pages_fetched: usize,
    pub redirects: usize,
    pub unique_links: usize,
    pub duplicate_links_dropped: usize,
    pub disallowed_links: usize,
    pub out_of_origin_links: usize,
}

impl From<CrawlStats> for DemoStats {
    fn from(stats: CrawlStats) -> Self {
        Self {
            requests: stats.requests,
            pages_fetched: stats.pages_fetched,
            redirects: stats.redirects,
            unique_links: stats.unique_links,
            duplicate_links_dropped: stats.duplicate_links_dropped,
            disallowed_links: stats.disallowed_links,
            out_of_origin_links: stats.out_of_origin_links,
        }
    }
}

#[derive(Debug)]
pub enum DemoError {
    Crawl(String),
    Query(QueryError),
    Proof(String),
}

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crawl(message) => f.write_str(message),
            Self::Query(error) => error.fmt(f),
            Self::Proof(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DemoError {}

impl From<CrawlError> for DemoError {
    fn from(error: CrawlError) -> Self {
        Self::Crawl(error.to_string())
    }
}

impl From<QueryError> for DemoError {
    fn from(error: QueryError) -> Self {
        Self::Query(error)
    }
}

pub fn run_demo(query: &str) -> Result<DemoOutput, DemoError> {
    run_demo_with_options(query, false)
}

pub fn run_demo_with_options(query: &str, explain: bool) -> Result<DemoOutput, DemoError> {
    let parsed_query = parse_query(query)?;
    let routes = vec![
        (
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: LeyBot\nDisallow: /private\n"),
        ),
        (
            "/".to_owned(),
            FixtureResponse::html(
                "<!doctype html><html><head><title>Ley local fixture</title></head><body><p>A tiny deterministic search demo.</p><p><a href=\"/guide/rust\">Rust guide</a> <a href=\"/guide/rust#same-page\">Rust guide repeat</a></p><a href=\"/private/never-fetch\">private page</a></body></html>",
            ),
        ),
        (
            "/guide/rust".to_owned(),
            FixtureResponse::html(
                "<!doctype html><html><head><title>Rust in Ley</title></head><body><p>Rust retrieval uses a Ley-owned in-memory inverted index.</p></body></html>",
            ),
        ),
        (
            "/private/never-fetch".to_owned(),
            FixtureResponse::html("<title>Must never be fetched</title>"),
        ),
    ];
    let fixture = LocalFixture::start(routes)?;
    let start = fixture.origin().url("/")?;
    let result = crawl_fixture(fixture.origin(), start, CrawlConfig::default())?;
    let request_log = fixture.request_log();
    prove_demo_path(&request_log, &result.stats, result.index.len())?;
    let results = result.index.query_parsed(&parsed_query)?;
    let port = fixture
        .base_url()
        .port_or_known_default()
        .ok_or_else(|| DemoError::Proof("fixture listener has no bound port".to_owned()))?;
    let stdout = render_output(
        query,
        port,
        &request_log,
        &result.stats,
        result.index.len(),
        &results,
        explain,
    );
    Ok(DemoOutput {
        stdout,
        request_log,
        results,
        stats: result.stats.into(),
    })
}

/// Run the controlled crawler against the authored loopback corpus, keeping
/// its paired index and frontier under a temporary directory.
pub fn run_controlled_fixture_demo() -> Result<String, DemoError> {
    run_controlled_fixture_demo_at(None)
}

/// Run the same owned loopback crawl while retaining the paired index and
/// frontier under a new directory. The destination must not already exist.
pub fn run_controlled_fixture_demo_retained(path: impl AsRef<Path>) -> Result<String, DemoError> {
    run_controlled_fixture_demo_at(Some(path.as_ref()))
}

fn run_controlled_fixture_demo_at(retain_dir: Option<&Path>) -> Result<String, DemoError> {
    let manifest: LoopbackManifest = serde_json::from_str(include_str!(
        "../fixtures/gate7-loopback-v1.json"
    ))
    .map_err(|error| DemoError::Proof(format!("invalid Gate 7 loopback manifest: {error}")))?;
    if manifest.schema != "ley-loopback-fixture-v1"
        || manifest.queries.is_empty()
        || !manifest.queries.contains(&manifest.redirect_identity_query)
    {
        return Err(DemoError::Proof(
            "Gate 7 loopback manifest has an unsupported schema or no queries".to_owned(),
        ));
    }
    let routes: Vec<(String, FixtureResponse)> = manifest
        .routes
        .iter()
        .map(|route| {
            let response = route.headers.iter().fold(
                FixtureResponse::new(route.status, &route.content_type, &route.body),
                |response, [name, value]| response.with_header(name, value),
            );
            (route.path.clone(), response)
        })
        .collect();
    let fixture = LocalFixture::start(routes)?;
    let temporary_root = if retain_dir.is_none() {
        Some(Gate4TempDir::create()?)
    } else {
        None
    };
    let root_path = if let Some(path) = retain_dir {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(DemoError::Proof(format!(
                    "refusing to replace existing retained demo directory: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(DemoError::Proof(format!(
                    "could not inspect retained demo directory: {error}"
                )));
            }
        }
        fs::create_dir(path).map_err(|error| {
            DemoError::Proof(format!("could not create retained demo directory: {error}"))
        })?;
        path.to_path_buf()
    } else {
        temporary_root
            .as_ref()
            .expect("temporary root was created")
            .path()
            .to_path_buf()
    };
    let index_path = root_path.join("index");
    let frontier_path = root_path.join("frontier.sqlite");
    let index = Arc::new(PersistentIndex::create(&index_path).map_err(|error| {
        DemoError::Proof(format!("could not create Gate 7 demo index: {error}"))
    })?);
    let origin = fixture.base_url().origin().ascii_serialization();
    let now = SystemClock.now_ms();
    let policy = SourcePolicy::owned_fixture(
        manifest.source_id.clone(),
        vec![origin],
        vec!["/".to_owned()],
        now.saturating_add(60_000),
    );
    let mut crawler = ControlledCrawler::<SystemResolver, SystemClock>::open_system(
        &frontier_path,
        Arc::clone(&index),
        vec![fixture.capability()],
        CrawlLimits::default(),
    )
    .map_err(|error| DemoError::Proof(format!("could not open Gate 7 demo crawler: {error}")))?;
    let seed_url = fixture
        .base_url()
        .join(&manifest.seed_path)
        .map_err(|error| DemoError::Proof(format!("invalid Gate 7 fixture seed URL: {error}")))?;
    let seed = crate::url_key::UrlKey::parse(seed_url.as_str())
        .map_err(|error| DemoError::Proof(format!("invalid Gate 7 fixture URL: {error}")))?;
    crawler
        .admit_source(policy, &[seed])
        .map_err(|error| DemoError::Proof(format!("could not admit Gate 7 fixture: {error}")))?;
    let first_crawl_started = Instant::now();
    let first_report = crawler
        .run_until_idle(&CrawlCancellation::default())
        .map_err(|error| DemoError::Proof(format!("Gate 7 fixture crawl failed: {error}")))?;
    let first_crawl_elapsed = first_crawl_started.elapsed();
    let request_log = fixture.request_log();
    if request_log
        .iter()
        .any(|path| path.starts_with(&manifest.private_path))
    {
        return Err(DemoError::Proof(
            "Gate 7 fixture fetched a robots-disallowed path".to_owned(),
        ));
    }
    if first_report.indexed != manifest.expected_indexed_paths.len() {
        return Err(DemoError::Proof(format!(
            "Gate 7 fixture indexed {} pages, expected {}; report={first_report:?}, log={request_log:?}",
            first_report.indexed,
            manifest.expected_indexed_paths.len()
        )));
    }
    for required_path in [
        "/robots.txt",
        manifest.seed_path.as_str(),
        manifest.redirect_effective_path.as_str(),
    ] {
        if !request_log.iter().any(|path| path == required_path) {
            return Err(DemoError::Proof(format!(
                "Gate 7 fixture did not request required route {required_path:?}: {request_log:?}"
            )));
        }
    }
    for indexed_path in &manifest.expected_indexed_paths {
        if !request_log.iter().any(|path| path == indexed_path) {
            return Err(DemoError::Proof(format!(
                "Gate 7 fixture did not fetch expected indexed route {indexed_path:?}"
            )));
        }
    }
    let requested_url = fixture
        .base_url()
        .join(&manifest.redirect_requested_path)
        .map_err(|error| DemoError::Proof(format!("invalid redirect URL: {error}")))?;
    let effective_url = fixture
        .base_url()
        .join(&manifest.redirect_effective_path)
        .map_err(|error| DemoError::Proof(format!("invalid redirect URL: {error}")))?;
    let requested_key = crate::url_key::UrlKey::parse(requested_url.as_str())
        .map_err(|error| DemoError::Proof(format!("invalid requested URL key: {error}")))?;
    let initial_view = index.read_view().map_err(|error| {
        DemoError::Proof(format!("could not read initial Gate 7 generation: {error}"))
    })?;
    let redirect_document = initial_view.document(&requested_key).ok_or_else(|| {
        DemoError::Proof("redirected page lost its requested URL identity".to_owned())
    })?;
    if redirect_document.id != requested_url.as_str()
        || redirect_document.effective_url != effective_url.as_str()
        || redirect_document.version_id.is_empty()
    {
        return Err(DemoError::Proof(format!(
            "redirect identity mismatch: id={}, effective={}, version={}",
            redirect_document.id, redirect_document.effective_url, redirect_document.version_id
        )));
    }
    let mut before = Vec::with_capacity(manifest.queries.len());
    for query in &manifest.queries {
        let results = initial_view.query(query).map_err(|error| {
            DemoError::Proof(format!("Gate 7 query failed for {query:?}: {error}"))
        })?;
        before.push((query.clone(), results));
    }
    if !before.iter().any(|(_, results)| !results.is_empty()) {
        return Err(DemoError::Proof(
            "Gate 7 query manifest produced no results".to_owned(),
        ));
    }
    crawler
        .revoke_source(&manifest.source_id)
        .map_err(|error| DemoError::Proof(format!("could not revoke Gate 7 fixture: {error}")))?;
    if !index
        .query("controlled")
        .map_err(|error| DemoError::Proof(format!("revocation query failed: {error}")))?
        .is_empty()
    {
        return Err(DemoError::Proof(
            "revoked Gate 7 fixture remained searchable".to_owned(),
        ));
    }
    let renewed_policy = SourcePolicy::owned_fixture(
        manifest.source_id.clone(),
        vec![fixture.base_url().origin().ascii_serialization()],
        vec!["/".to_owned()],
        SystemClock.now_ms().saturating_add(60_000),
    );
    crawler.readmit_source(renewed_policy).map_err(|error| {
        DemoError::Proof(format!(
            "could not explicitly readmit Gate 7 fixture: {error}"
        ))
    })?;
    let recovery_report = crawler
        .run_until_idle(&CrawlCancellation::default())
        .map_err(|error| DemoError::Proof(format!("Gate 7 recovery crawl failed: {error}")))?;
    if recovery_report.indexed != manifest.expected_indexed_paths.len() {
        return Err(DemoError::Proof(format!(
            "explicit Gate 7 readmission indexed {} pages instead of {} (requests={}, log={:?})",
            recovery_report.indexed,
            manifest.expected_indexed_paths.len(),
            recovery_report.requests,
            fixture.request_log()
        )));
    }
    let final_request_log = fixture.request_log();
    drop(crawler);
    drop(index);
    let reopened = PersistentIndex::open(&index_path)
        .map_err(|error| DemoError::Proof(format!("could not reopen Gate 7 index: {error}")))?;
    let reopened_view = reopened.read_view().map_err(|error| {
        DemoError::Proof(format!("could not read reopened Gate 7 index: {error}"))
    })?;
    for (query, expected) in &before {
        let actual = reopened_view.query(query).map_err(|error| {
            DemoError::Proof(format!(
                "reopened Gate 7 query failed for {query:?}: {error}"
            ))
        })?;
        if !same_results_across_generations(expected, &actual) {
            return Err(DemoError::Proof(format!(
                "IDs, scores, matches, or explanations changed after restart for {query:?}"
            )));
        }
    }
    let reopened_redirect = reopened_view.document(&requested_key).ok_or_else(|| {
        DemoError::Proof("redirected page disappeared after reopening the index".to_owned())
    })?;
    if reopened_redirect != redirect_document {
        return Err(DemoError::Proof(
            "requested URL identity, effective URL, or version changed after reopening".to_owned(),
        ));
    }
    let elapsed_ns = first_crawl_elapsed.as_nanos();
    let pages_per_second = if first_crawl_elapsed.is_zero() {
        0.0
    } else {
        first_report.pages_fetched as f64 / first_crawl_elapsed.as_secs_f64()
    };
    let crawler_measurement = serde_json::json!({
        "durationNs": elapsed_ns,
        "requests": first_report.requests,
        "pagesFetched": first_report.pages_fetched,
        "indexed": first_report.indexed,
        "pagesPerSecond": pages_per_second,
        "definition": "initial controlled fixture run_until_idle only; includes loopback HTTP, robots retrieval, extraction, frontier/outbox work, and persistent indexing; excludes process startup and later revoke/readmit"
    });
    let output = format!(
        "Ley Gate 7 Flagship 1.0\nFixture origin: {} (owned loopback listener)\nHTTP requests: {} (accepted sockets: {})\nPages fetched/indexed: {}/{}\nFirst crawl timing: {}\nRetained bundle: {}\nPersistent index: {}\nFrontier database: {}\nRedirect requested ID: {}\nRedirect effective URL: {}\nRedirect version ID: {}\nRestart parity: {} manifest queries; ordered IDs, scores, matches, and full explanations verified\nRevocation/readmission: verified\nRobots-disallowed path: NOT FETCHED\nFixture request log:\n{}\n",
        fixture.base_url().origin().ascii_serialization(),
        first_report.requests + recovery_report.requests,
        fixture.accepted_connections(),
        first_report.pages_fetched,
        first_report.indexed,
        serde_json::to_string(&crawler_measurement).unwrap_or_default(),
        root_path.display(),
        index_path.display(),
        frontier_path.display(),
        redirect_document.id,
        redirect_document.effective_url,
        redirect_document.version_id,
        manifest.queries.len(),
        final_request_log
            .iter()
            .map(|path| format!("  GET {path}\n"))
            .collect::<String>(),
    );
    Ok(output)
}

fn same_results_across_generations(expected: &[SearchResult], actual: &[SearchResult]) -> bool {
    expected.len() == actual.len()
        && expected.iter().zip(actual).all(|(expected, actual)| {
            let mut expected = expected.clone();
            expected.explanation.statistics_source = actual.explanation.statistics_source.clone();
            expected == *actual
        })
}

/// Create a new persistent index containing only authored synthetic search
/// documents. The fixture URLs are identifiers; this function performs no
/// network requests and refuses to replace an existing store.
pub fn create_search_fixture_index(path: impl AsRef<Path>) -> Result<(usize, u64), DemoError> {
    let index = PersistentIndex::create(path)
        .map_err(|error| DemoError::Proof(format!("could not create fixture index: {error}")))?;
    let documents = [
        (
            "https://fixtures.ley.test/guide/rust",
            "Rust in Ley: retrieval notes",
            "Rust retrieval uses a Ley-owned inverted index. A small local corpus keeps ranking transparent.",
        ),
        (
            "https://fixtures.ley.test/notes/bm25",
            "Search score <img src=x onerror=alert(1)> explanations",
            "Ley ranks documents with BM25 and exposes a score explanation from one durable generation. <img src=x onerror=alert(1)>",
        ),
    ];
    for (url, title, body) in documents {
        let key = crate::url_key::UrlKey::parse(url)
            .map_err(|error| DemoError::Proof(format!("invalid fixture URL: {error}")))?;
        let lease = index.issue_fence(&key).map_err(|error| {
            DemoError::Proof(format!("could not register fixture URL: {error}"))
        })?;
        index
            .apply(
                &lease,
                crate::storage::Intent::Upsert {
                    effective_url: url.to_owned(),
                    title: title.to_owned(),
                    body: body.to_owned(),
                },
            )
            .map_err(|error| {
                DemoError::Proof(format!("could not index fixture document: {error}"))
            })?;
    }
    let long_url = format!("https://fixtures.ley.test/long/{}", "u".repeat(160));
    let long_key = crate::url_key::UrlKey::parse(&long_url)
        .map_err(|error| DemoError::Proof(format!("invalid adversarial fixture URL: {error}")))?;
    let long_lease = index.issue_fence(&long_key).map_err(|error| {
        DemoError::Proof(format!(
            "could not register adversarial fixture URL: {error}"
        ))
    })?;
    index
        .apply(
            &long_lease,
            crate::storage::Intent::Upsert {
                effective_url: long_url,
                title: format!("adversarial {}", vec!["T".repeat(30); 6].join(" ")),
                body: format!("adversarial {}", vec!["S".repeat(40); 9].join(" ")),
            },
        )
        .map_err(|error| {
            DemoError::Proof(format!(
                "could not index adversarial fixture document: {error}"
            ))
        })?;
    let view = index
        .read_view()
        .map_err(|error| DemoError::Proof(format!("could not read fixture generation: {error}")))?;
    Ok((view.document_count(), view.generation_id()))
}

struct Gate4TempDir(PathBuf);

impl Gate4TempDir {
    fn create() -> Result<Self, DemoError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ley-gate4-demo-{}-{elapsed}", std::process::id()));
        fs::create_dir(&path).map_err(|error| {
            DemoError::Proof(format!("could not create Gate 4 demo directory: {error}"))
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Gate4TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prove_demo_path(
    request_log: &[String],
    stats: &CrawlStats,
    indexed_documents: usize,
) -> Result<(), DemoError> {
    let count = |path: &str| {
        request_log
            .iter()
            .filter(|logged| logged.as_str() == path)
            .count()
    };
    if count("/robots.txt") != 1 || count("/") != 1 || count("/guide/rust") != 1 {
        return Err(DemoError::Proof(format!(
            "fixture request log did not show exactly one robots, root, and guide request: {request_log:?}"
        )));
    }
    if request_log.iter().any(|path| path.starts_with("/private/")) {
        return Err(DemoError::Proof(
            "robots-disallowed fixture route was fetched".to_owned(),
        ));
    }
    if indexed_documents != 2 || stats.disallowed_links != 1 || stats.duplicate_links_dropped != 1 {
        return Err(DemoError::Proof(format!(
            "fixture path checks failed: indexed={indexed_documents}, disallowed={}, duplicates={}",
            stats.disallowed_links, stats.duplicate_links_dropped
        )));
    }
    Ok(())
}

fn render_output(
    query: &str,
    port: u16,
    request_log: &[String],
    stats: &CrawlStats,
    indexed_documents: usize,
    results: &[SearchResult],
    explain: bool,
) -> String {
    let mut output = format!(
        "Ley Gate 2 Search Core 0.2\nFixture origin: http://127.0.0.1:{port} (in-process, exact-origin allow)\nHTTP requests: {} (redirects: {})\nPages fetched and indexed: {}/{}\nUnique outgoing URL keys: {}; duplicate links removed: {}\nDisallowed links skipped: {}\nBlocked route /private/never-fetch: NOT FETCHED (checked against fixture request log)\nFixture request log:\n",
        stats.requests,
        stats.redirects,
        stats.pages_fetched,
        indexed_documents,
        stats.unique_links,
        stats.duplicate_links_dropped,
        stats.disallowed_links,
    );
    for path in request_log {
        output.push_str("  GET ");
        output.push_str(path);
        output.push('\n');
    }
    output.push_str(&format!(
        "Query: {}\nResults:\n",
        escape_terminal_controls(query)
    ));
    if results.is_empty() {
        output.push_str("  (no matches)\n");
    } else {
        for (rank, result) in results.iter().enumerate() {
            output.push_str(&format!(
                "  {}. {} | {} | score={:.6}\n     {}\n",
                rank + 1,
                escape_terminal_controls(&result.id),
                escape_terminal_controls(&result.title),
                result.score,
                escape_terminal_controls(&result.snippet),
            ));
            if explain {
                render_explanation(&mut output, result, rank + 1);
            }
        }
    }
    output.push_str(
        "Demo limit: local fixture only; this path uses an in-memory index and does not exercise PersistentIndex.\n",
    );
    output
}

fn render_explanation(output: &mut String, result: &SearchResult, rank: usize) {
    let explanation = &result.explanation;
    output.push_str(&format!(
        "     Explain {rank}: terms={:?} matched={}; N={} source={} avg_title={:.6} avg_body={:.6}\n",
        explanation
            .normalized_terms
            .iter()
            .map(|term| escape_terminal_controls(term))
            .collect::<Vec<_>>(),
        render_match_evidence(&result.matched),
        explanation.document_count,
        explanation.statistics_source,
        explanation.average_title_length,
        explanation.average_body_length,
    ));
    for term in &explanation.terms {
        output.push_str(&format!(
            "       {}: title {} | body {}\n",
            escape_terminal_controls(&term.term),
            render_field_score(&term.title),
            render_field_score(&term.body),
        ));
    }
    output.push_str(&format!(
        "       total={:.12} tie_policy=score_desc_then_url_utf8_ascending key={:?} version={}\n",
        explanation.total_score,
        result.id.as_bytes(),
        result.version_id,
    ));
}

fn render_match_evidence(evidence: &MatchEvidence) -> String {
    match evidence {
        MatchEvidence::Term {
            term,
            title_positions,
            body_positions,
        } => format!(
            "term({:?}, title={title_positions:?}, body={body_positions:?})",
            escape_terminal_controls(term)
        ),
        MatchEvidence::Phrase {
            terms,
            title_starts,
            body_starts,
        } => format!(
            "phrase({:?}, title_starts={title_starts:?}, body_starts={body_starts:?})",
            terms
                .iter()
                .map(|term| escape_terminal_controls(term))
                .collect::<Vec<_>>()
        ),
        MatchEvidence::And(children) => format!(
            "and[{}]",
            children
                .iter()
                .map(render_match_evidence)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        MatchEvidence::Or(children) => format!(
            "or[{}]",
            children
                .iter()
                .map(render_match_evidence)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn render_field_score(field: &FieldScoreExplanation) -> String {
    format!(
        "tf={} df={} len={} avg={:.6} idf={:.12} w={} contribution={:.12}",
        field.term_frequency,
        field.document_frequency,
        field.document_length,
        field.average_length,
        field.idf,
        field.weight,
        field.contribution,
    )
}

fn escape_terminal_controls(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_path_fetches_deduplicates_blocks_and_returns_computed_scores() {
        let result = run_demo("Rust").unwrap();
        assert_eq!(result.stats.requests, 3);
        assert_eq!(result.stats.pages_fetched, 2);
        assert_eq!(result.stats.duplicate_links_dropped, 1);
        assert_eq!(result.stats.disallowed_links, 1);
        assert_eq!(result.request_log, ["/robots.txt", "/", "/guide/rust"]);
        assert!(
            result
                .results
                .iter()
                .any(|hit| hit.id.ends_with("/guide/rust"))
        );
        assert!(
            result
                .stdout
                .contains("Blocked route /private/never-fetch: NOT FETCHED")
        );
        assert!(
            !result
                .request_log
                .iter()
                .any(|path| path.contains("private"))
        );
    }

    #[test]
    fn unsupported_query_forms_return_a_clear_cli_error() {
        let error = run_demo("title:Rust").unwrap_err();
        assert!(error.to_string().contains("unsupported syntax"));
    }

    #[test]
    fn explain_output_reports_match_positions_and_actual_score_components() {
        let result = run_demo_with_options("Rust OR Ley", true).unwrap();
        assert!(result.stdout.contains("Explain 1: terms="));
        assert!(result.stdout.contains("matched=or["));
        assert!(
            result
                .stdout
                .contains("source=current in-memory document view")
        );
        assert!(result.stdout.contains("tf="));
        assert!(result.stdout.contains("contribution="));
        assert!(
            result
                .stdout
                .contains("tie_policy=score_desc_then_url_utf8_ascending")
        );
        assert!(result.stdout.contains("version="));
    }

    #[test]
    fn output_escapes_controls_without_changing_printable_unicode() {
        let result = SearchResult {
            id: "http://127.0.0.1/é/\u{1b}".to_owned(),
            version_id: "version".to_owned(),
            title: "Rüst\u{7} guide".to_owned(),
            snippet: "body\u{1b} text".to_owned(),
            score: 1.0,
            matched: MatchEvidence::Term {
                term: "rust".to_owned(),
                title_positions: vec![0],
                body_positions: vec![1],
            },
            explanation: crate::index::ScoreExplanation {
                normalized_terms: vec!["rust".to_owned()],
                document_count: 1,
                average_title_length: 1.0,
                average_body_length: 2.0,
                statistics_source: crate::index::StatisticsSource::CurrentInMemoryDocumentView,
                terms: vec![crate::index::TermScoreExplanation {
                    term: "rust".to_owned(),
                    title: FieldScoreExplanation {
                        term_frequency: 1,
                        document_frequency: 1,
                        document_length: 1,
                        average_length: 1.0,
                        idf: 1.0,
                        weight: 2.0,
                        contribution: 1.0,
                    },
                    body: FieldScoreExplanation {
                        term_frequency: 1,
                        document_frequency: 1,
                        document_length: 2,
                        average_length: 2.0,
                        idf: 1.0,
                        weight: 1.0,
                        contribution: 0.0,
                    },
                }],
                total_score: 1.0,
            },
        };
        let output = render_output(
            "Rüst\u{7}\u{1b}",
            12345,
            &[],
            &CrawlStats::default(),
            1,
            &[result],
            false,
        );

        assert!(output.contains("Query: Rüst\\u{7}\\u{1b}\n"));
        assert!(output.contains("http://127.0.0.1/é/\\u{1b} | Rüst\\u{7} guide"));
        assert!(
            !output
                .chars()
                .any(|character| character.is_control() && character != '\n' && character != '\r')
        );
    }

    #[test]
    fn query_controls_are_escaped_after_search_semantics_are_applied() {
        let plain = run_demo("Rust").unwrap();
        let controlled = run_demo("Rust\u{7}\u{1b}").unwrap();

        let result_shape = |results: &[SearchResult]| {
            results
                .iter()
                .map(|result| {
                    (
                        url::Url::parse(&result.id).unwrap().path().to_owned(),
                        result.title.clone(),
                        result.score,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            result_shape(&controlled.results),
            result_shape(&plain.results)
        );
        assert!(controlled.stdout.contains("Query: Rust\\u{7}\\u{1b}\n"));
        assert!(
            !controlled
                .stdout
                .chars()
                .any(|character| matches!(character, '\u{7}' | '\u{1b}'))
        );
    }

    #[test]
    fn oversized_query_is_rejected_before_the_fixture_starts() {
        let query = " ".repeat(4097);
        assert_eq!(
            run_demo(&query).unwrap_err().to_string(),
            "query is 4097 UTF-8 bytes; limit is 4096. Shorten the query and retry."
        );
    }

    #[test]
    fn retained_controlled_demo_crawls_one_manifest_and_preserves_redirect_identity() {
        let root = Gate4TempDir::create().unwrap();
        let retained = root.path().join("retained");
        let output = run_controlled_fixture_demo_retained(&retained).unwrap();
        assert!(output.contains("Ley Gate 7 Flagship 1.0"));
        assert!(output.contains("Robots-disallowed path: NOT FETCHED"));
        assert!(output.contains("redirect/requested"));
        assert!(output.contains("redirect/effective"));
        assert!(retained.join("index/CURRENT").is_file());
        assert!(retained.join("frontier.sqlite").is_file());

        let index = PersistentIndex::open(retained.join("index")).unwrap();
        let manifest: LoopbackManifest =
            serde_json::from_str(include_str!("../fixtures/gate7-loopback-v1.json")).unwrap();
        let view = index.read_view().unwrap();
        let hits = view.query(&manifest.redirect_identity_query).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].id.ends_with("/redirect/requested"));
        assert!(hits[0].version_id.len() > 10);

        let origin = url::Url::parse(&hits[0].id)
            .unwrap()
            .origin()
            .ascii_serialization();
        let mut independent = crate::index::InMemoryIndex::new();
        for path in &manifest.expected_indexed_paths {
            let key = crate::url_key::UrlKey::parse(&format!("{origin}{path}")).unwrap();
            let document = view.document(&key).unwrap();
            independent
                .insert_fields(
                    document.id,
                    document.effective_url,
                    document.title,
                    document.body,
                )
                .unwrap();
        }
        for query in &manifest.queries {
            let actual = view.query(query).unwrap();
            let parsed = crate::query::parse_query(query).unwrap();
            let mut expected: Vec<_> = crate::reference::exhaustive_search(&independent, &parsed)
                .into_iter()
                .map(|hit| hit.result)
                .collect();
            for result in &mut expected {
                result.explanation.statistics_source =
                    crate::index::StatisticsSource::PersistentGeneration(view.generation_id());
            }
            assert_eq!(actual, expected, "fixture reference parity for {query:?}");
        }

        let error = run_controlled_fixture_demo_retained(&retained).unwrap_err();
        assert!(error.to_string().contains("refusing to replace existing"));
        assert_eq!(view.query(&manifest.redirect_identity_query).unwrap(), hits);
    }
}
