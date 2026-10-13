use crate::crawler::{
    CrawlConfig, CrawlError, CrawlStats, FixtureResponse, LocalFixture, crawl_fixture,
};
use crate::index::{FieldScoreExplanation, MatchEvidence, QueryError, SearchResult};
use crate::query::parse_query;
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
    output.push_str("Limit: local fixture only; no public crawling or persistent storage.\n");
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
                statistics_source: "current in-memory document view",
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
}
