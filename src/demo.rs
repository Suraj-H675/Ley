use crate::crawler::{
    CrawlConfig, CrawlError, CrawlStats, FixtureResponse, LocalFixture, crawl_fixture,
};
use crate::index::{QueryError, SearchResult, validate_query_length};
use std::fmt;

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
    validate_query_length(query)?;
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
    let results = result.index.query(query)?;
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
    );
    Ok(DemoOutput {
        stdout,
        request_log,
        results,
        stats: result.stats.into(),
    })
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
) -> String {
    let mut output = format!(
        "Ley Gate 1 Demo 0.1\nFixture origin: http://127.0.0.1:{port} (in-process, exact-origin allow)\nHTTP requests: {} (redirects: {})\nPages fetched and indexed: {}/{}\nUnique outgoing URL keys: {}; duplicate links removed: {}\nDisallowed links skipped: {}\nBlocked route /private/never-fetch: NOT FETCHED (checked against fixture request log)\nFixture request log:\n",
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
                "  {}. {} | {} | score={:.6}\n",
                rank + 1,
                escape_terminal_controls(&result.id),
                escape_terminal_controls(&result.title),
                result.score
            ));
        }
    }
    output.push_str("Limit: local fixture only; no public crawling or persistent storage.\n");
    output
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
        let error = run_demo("Rust guide").unwrap_err();
        assert!(error.to_string().contains("one unfielded search term"));
    }

    #[test]
    fn output_escapes_controls_without_changing_printable_unicode() {
        let result = SearchResult {
            id: "http://127.0.0.1/é/\u{1b}".to_owned(),
            title: "Rüst\u{7} guide".to_owned(),
            score: 1.0,
        };
        let output = render_output(
            "Rüst\u{7}\u{1b}",
            12345,
            &[],
            &CrawlStats::default(),
            1,
            &[result],
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
}
