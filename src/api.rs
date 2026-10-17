use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use http_body::Body as HttpBody;
use serde::Serialize;

use crate::index::{MatchEvidence, SearchResult, StatisticsSource};
use crate::storage::{PersistentIndex, ReadView, StorageError};

pub const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7331);
const MAX_URI_BYTES: usize = 12 * 1024;
const MAX_QUERY_BYTES: usize = 4096;
const MAX_RESULTS: usize = 20;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

#[derive(Clone)]
struct ApiState {
    index: Arc<PersistentIndex>,
    port: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchResponse {
    query: String,
    generation: u64,
    corpus_size: usize,
    total_results: usize,
    truncated: bool,
    results: Vec<SearchHit>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    id: String,
    version_id: String,
    title: String,
    snippet: String,
    score: f64,
    matched: MatchSummary,
    explanation: Explanation,
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum MatchSummary {
    Term {
        term: String,
        title_occurrences: usize,
        body_occurrences: usize,
    },
    Phrase {
        terms: Vec<String>,
        title_occurrences: usize,
        body_occurrences: usize,
    },
    And {
        children: Vec<MatchSummary>,
    },
    Or {
        children: Vec<MatchSummary>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Explanation {
    normalized_terms: Vec<String>,
    document_count: usize,
    average_title_length: f64,
    average_body_length: f64,
    statistics_source: StatisticsSourceDto,
    terms: Vec<TermExplanation>,
    total_score: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatisticsSourceDto {
    kind: &'static str,
    generation: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TermExplanation {
    term: String,
    title: FieldExplanation,
    body: FieldExplanation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldExplanation {
    term_frequency: usize,
    document_frequency: usize,
    document_length: usize,
    average_length: f64,
    idf: f64,
    weight: f64,
    contribution: f64,
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
}

#[derive(Debug)]
enum SearchFailure {
    InvalidQuery,
    TooLarge,
    IndexUnavailable,
}

impl SearchFailure {
    fn cli_message(&self) -> &'static str {
        match self {
            Self::InvalidQuery => "query is invalid",
            Self::TooLarge => "search input or response exceeds its limit",
            Self::IndexUnavailable => "index store is unavailable",
        }
    }

    fn response(self) -> Response {
        let (status, error) = match self {
            Self::InvalidQuery => (StatusCode::BAD_REQUEST, "invalid_query"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "response_limit_exceeded"),
            Self::IndexUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "index_unavailable"),
        };
        (status, Json(ApiError { error })).into_response()
    }
}

pub fn run(store_path: impl AsRef<Path>, bind: SocketAddr) -> Result<(), String> {
    if !bind.ip().is_loopback() {
        return Err("API binding must use a loopback address".to_owned());
    }
    let index = Arc::new(
        PersistentIndex::open(store_path)
            .map_err(|_| "could not open the index store".to_owned())?,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "could not start the API runtime".to_owned())?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|_| "could not bind the loopback API listener".to_owned())?;
        let app = router(index, bind.port());
        axum::serve(listener, app)
            .await
            .map_err(|_| "the API listener stopped unexpectedly".to_owned())
    })
}

/// Search one stable persistent generation and serialize the same response
/// shape used by the read-only HTTP endpoint.
pub fn search_store_json(store_path: impl AsRef<Path>, query: &str) -> Result<String, String> {
    let index = PersistentIndex::open(store_path).map_err(|_| "index store is unavailable")?;
    let response = make_search_response(&index, query).map_err(|error| error.cli_message())?;
    let body = serde_json::to_vec(&response).map_err(|_| "could not serialize search results")?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("search input or response exceeds its limit".to_owned());
    }
    serde_json::to_string_pretty(&response)
        .map_err(|_| "could not serialize search results".to_owned())
}

fn router(index: Arc<PersistentIndex>, port: u16) -> Router {
    let state = ApiState { index, port };
    Router::new()
        .route("/api/health", any(health))
        .route("/api/search", any(search))
        .fallback(not_found)
        .with_state(state)
}

async fn health(State(state): State<ApiState>, request: Request<Body>) -> Response {
    if let Some(error) = validate_local_authority(&request, state.port) {
        return local_authority_error(error);
    }
    if !request_body_is_empty(&request) {
        return body_not_allowed();
    }
    if request.method() != Method::GET {
        return method_not_allowed();
    }
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" }))).into_response()
}

async fn search(State(state): State<ApiState>, request: Request<Body>) -> Response {
    if let Some(error) = validate_local_authority(&request, state.port) {
        return local_authority_error(error);
    }
    if !request_body_is_empty(&request) {
        return body_not_allowed();
    }
    if request.method() != Method::GET {
        return method_not_allowed();
    }
    if request.uri().to_string().len() > MAX_URI_BYTES {
        return SearchFailure::TooLarge.response();
    }
    let query = match parse_query_parameter(request.uri().query().unwrap_or_default()) {
        Ok(query) => query,
        Err(QueryParameterError::TooLarge) => return SearchFailure::TooLarge.response(),
        Err(QueryParameterError::Malformed) => return SearchFailure::InvalidQuery.response(),
    };
    match make_search_response(&state.index, &query) {
        Ok(response) => match serde_json::to_vec(&response) {
            Ok(body) if body.len() <= MAX_RESPONSE_BYTES => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::from(body))
                .unwrap_or_else(|_| internal_error()),
            _ => SearchFailure::TooLarge.response(),
        },
        Err(error) => error.response(),
    }
}

async fn not_found(State(state): State<ApiState>, request: Request<Body>) -> Response {
    if let Some(error) = validate_local_authority(&request, state.port) {
        return local_authority_error(error);
    }
    (StatusCode::NOT_FOUND, Json(ApiError { error: "not_found" })).into_response()
}

fn local_authority_error(error: &'static str) -> Response {
    (StatusCode::FORBIDDEN, Json(ApiError { error })).into_response()
}

fn validate_local_authority(request: &Request<Body>, port: u16) -> Option<&'static str> {
    let host_values = request.headers().get_all(header::HOST);
    let mut hosts = host_values.iter();
    let Some(host) = hosts.next() else {
        return Some("invalid_host");
    };
    let Ok(host) = host.to_str() else {
        return Some("invalid_host");
    };
    if hosts.next().is_some() {
        return Some("invalid_host");
    }
    let Some(host_authority) = local_authority(host, port) else {
        return Some("invalid_host");
    };
    if let Some(uri_authority) = request.uri().authority()
        && (request.uri().scheme_str() != Some("http")
            || local_authority(uri_authority.as_str(), port).as_ref() != Some(&host_authority))
    {
        return Some("invalid_host");
    }

    let origin_name = HeaderName::from_static("origin");
    let origin_values = request.headers().get_all(origin_name);
    let mut origins = origin_values.iter();
    let origin = origins.next()?;
    if origins.next().is_some() {
        return Some("invalid_origin");
    }
    let Ok(origin) = origin.to_str() else {
        return Some("invalid_origin");
    };
    let Ok(origin_url) = url::Url::parse(origin) else {
        return Some("invalid_origin");
    };
    if origin_url.scheme() != "http"
        || !origin_url.username().is_empty()
        || origin_url.password().is_some()
        || origin_url.path() != "/"
        || origin_url.query().is_some()
        || origin_url.fragment().is_some()
    {
        return Some("invalid_origin");
    }
    let origin_host = origin_url.host_str().unwrap_or_default();
    let origin_port = origin_url.port_or_known_default().unwrap_or_default();
    let origin_authority = if origin_host.contains(':') {
        format!("[{origin_host}]:{origin_port}")
    } else {
        format!("{origin_host}:{origin_port}")
    };
    let Some(origin_authority) = local_authority(&origin_authority, port) else {
        return Some("invalid_origin");
    };
    if origin_authority != host_authority {
        return Some("invalid_origin");
    }
    None
}

fn local_authority(value: &str, expected_port: u16) -> Option<(String, u16)> {
    let authority = value.parse::<axum::http::uri::Authority>().ok()?;
    if authority.as_str().contains('@') || authority.port_u16()? != expected_port {
        return None;
    }
    let host = authority.host().trim_matches(['[', ']']);
    let normalized_host = host.to_ascii_lowercase();
    let is_loopback = normalized_host == "localhost"
        || normalized_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    is_loopback.then_some((normalized_host, expected_port))
}

fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "GET")],
        Json(ApiError {
            error: "method_not_allowed",
        }),
    )
        .into_response()
}

fn body_not_allowed() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: "request_body_not_allowed",
        }),
    )
        .into_response()
}

fn request_body_is_empty(request: &Request<Body>) -> bool {
    request.body().is_end_stream() && request.body().size_hint().exact() == Some(0)
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            error: "internal_error",
        }),
    )
        .into_response()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryParameterError {
    Malformed,
    TooLarge,
}

fn parse_query_parameter(raw: &str) -> Result<String, QueryParameterError> {
    if raw.len() > MAX_URI_BYTES {
        return Err(QueryParameterError::TooLarge);
    }
    let mut value = None;
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err(QueryParameterError::Malformed);
        }
        let (name, raw_value) = pair.split_once('=').ok_or(QueryParameterError::Malformed)?;
        if name != "q" || value.is_some() || !valid_percent_escapes(raw_value) {
            return Err(QueryParameterError::Malformed);
        }
        let mut decoded = Vec::with_capacity(raw_value.len());
        let bytes = raw_value.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'+' => {
                    decoded.push(b' ');
                    index += 1;
                }
                b'%' => {
                    let high = hex_value(bytes[index + 1]).ok_or(QueryParameterError::Malformed)?;
                    let low = hex_value(bytes[index + 2]).ok_or(QueryParameterError::Malformed)?;
                    decoded.push((high << 4) | low);
                    index += 3;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
            if decoded.len() > MAX_QUERY_BYTES {
                return Err(QueryParameterError::TooLarge);
            }
        }
        value = Some(String::from_utf8(decoded).map_err(|_| QueryParameterError::Malformed)?);
    }
    value.ok_or(QueryParameterError::Malformed)
}

fn valid_percent_escapes(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || hex_value(bytes[index + 1]).is_none()
                || hex_value(bytes[index + 2]).is_none()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn make_search_response(
    index: &PersistentIndex,
    query: &str,
) -> Result<SearchResponse, SearchFailure> {
    if query.is_empty() || query.len() > MAX_QUERY_BYTES {
        return Err(if query.len() > MAX_QUERY_BYTES {
            SearchFailure::TooLarge
        } else {
            SearchFailure::InvalidQuery
        });
    }
    let view = index
        .read_view()
        .map_err(|_| SearchFailure::IndexUnavailable)?;
    search_view(&view, query)
}

fn search_view(view: &ReadView, query: &str) -> Result<SearchResponse, SearchFailure> {
    let all_results = view.query(query).map_err(|error| match error {
        StorageError::Query(_) => SearchFailure::InvalidQuery,
        _ => SearchFailure::IndexUnavailable,
    })?;
    let total_results = all_results.len();
    let generation = view.generation_id();
    let results = all_results
        .iter()
        .take(MAX_RESULTS)
        .map(to_hit)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SearchResponse {
        query: query.to_owned(),
        generation,
        corpus_size: view.document_count(),
        total_results,
        truncated: total_results > MAX_RESULTS,
        results,
    })
}

fn to_hit(result: &SearchResult) -> Result<SearchHit, SearchFailure> {
    if !result.score.is_finite() || !result.explanation.total_score.is_finite() {
        return Err(SearchFailure::IndexUnavailable);
    }
    let statistics_source = match &result.explanation.statistics_source {
        StatisticsSource::PersistentGeneration(generation) => StatisticsSourceDto {
            kind: "persistent-generation",
            generation: Some(*generation),
        },
        StatisticsSource::CurrentInMemoryDocumentView => StatisticsSourceDto {
            kind: "in-memory-view",
            generation: None,
        },
    };
    Ok(SearchHit {
        id: result.id.clone(),
        version_id: result.version_id.clone(),
        title: result.title.clone(),
        snippet: result.snippet.clone(),
        score: result.score,
        matched: summarize_evidence(&result.matched),
        explanation: Explanation {
            normalized_terms: result.explanation.normalized_terms.clone(),
            document_count: result.explanation.document_count,
            average_title_length: result.explanation.average_title_length,
            average_body_length: result.explanation.average_body_length,
            statistics_source,
            terms: result
                .explanation
                .terms
                .iter()
                .map(|term| TermExplanation {
                    term: term.term.clone(),
                    title: field_explanation(&term.title),
                    body: field_explanation(&term.body),
                })
                .collect(),
            total_score: result.explanation.total_score,
        },
    })
}

fn field_explanation(field: &crate::index::FieldScoreExplanation) -> FieldExplanation {
    FieldExplanation {
        term_frequency: field.term_frequency,
        document_frequency: field.document_frequency,
        document_length: field.document_length,
        average_length: field.average_length,
        idf: field.idf,
        weight: field.weight,
        contribution: field.contribution,
    }
}

fn summarize_evidence(evidence: &MatchEvidence) -> MatchSummary {
    match evidence {
        MatchEvidence::Term {
            term,
            title_positions,
            body_positions,
        } => MatchSummary::Term {
            term: term.clone(),
            title_occurrences: title_positions.len(),
            body_occurrences: body_positions.len(),
        },
        MatchEvidence::Phrase {
            terms,
            title_starts,
            body_starts,
        } => MatchSummary::Phrase {
            terms: terms.clone(),
            title_occurrences: title_starts.len(),
            body_occurrences: body_starts.len(),
        },
        MatchEvidence::And(children) => MatchSummary::And {
            children: children.iter().map(summarize_evidence).collect(),
        },
        MatchEvidence::Or(children) => MatchSummary::Or {
            children: children.iter().map(summarize_evidence).collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use super::{
        DEFAULT_BIND, QueryParameterError, make_search_response, parse_query_parameter, router,
    };
    use crate::storage::{Intent, PersistentIndex, PublicCollectionGate};
    use crate::url_key::UrlKey;
    use sha2::{Digest, Sha256};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TempStore(std::path::PathBuf);

    impl TempStore {
        fn new() -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ley-api-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn populated_index() -> (TempStore, PersistentIndex, String) {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        let key = UrlKey::parse("https://fixtures.example.test/rust").unwrap();
        let lease = store.issue_fence(&key).unwrap();
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: key.as_str().to_owned(),
                    title: "<script>Rust guide</script>\n\u{1b}[31m".to_owned(),
                    body: "Rust retrieval uses a small Ley-owned inverted index.".to_owned(),
                },
            )
            .unwrap();
        let expected = store.query("rust").unwrap().remove(0).version_id;
        (temp, store, expected)
    }

    fn expired_public_index() -> (TempStore, PersistentIndex) {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        let notice = b"owned test notice";
        let gate = PublicCollectionGate {
            policy_sha256: "a".repeat(64),
            source_id: "owned-test-source".to_owned(),
            origin: "https://docs.example.org".to_owned(),
            path_prefixes: vec!["/public/".to_owned()],
            installed_at_ms: 10,
            visible_until_ms: 20,
            license: "MIT".to_owned(),
            source_version: "owned test source".to_owned(),
            notice_file: "rust-stdlib-documentation-MIT.txt".to_owned(),
            notice_sha256: Sha256::digest(notice)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        };
        store
            .install_public_collection_gate(&gate, notice, 10)
            .unwrap();
        let key = UrlKey::parse("https://docs.example.org/public/rust").unwrap();
        let lease = store.issue_fence(&key).unwrap();
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: key.as_str().to_owned(),
                    title: "expired source content".to_owned(),
                    body: "rust corpus data".to_owned(),
                },
            )
            .unwrap();
        (temp, store)
    }

    #[test]
    fn query_parameter_decoder_is_strict_and_bounded() {
        assert_eq!(parse_query_parameter("q=rust+guide").unwrap(), "rust guide");
        assert_eq!(parse_query_parameter("q=%E2%9C%93").unwrap(), "✓");
        assert_eq!(
            parse_query_parameter("q=%GG"),
            Err(QueryParameterError::Malformed)
        );
        assert_eq!(
            parse_query_parameter("q=one&q=two"),
            Err(QueryParameterError::Malformed)
        );
        assert_eq!(
            parse_query_parameter("q=one&debug=1"),
            Err(QueryParameterError::Malformed)
        );
        assert_eq!(
            parse_query_parameter("q=%FF"),
            Err(QueryParameterError::Malformed)
        );
        let long = format!("q={}", "x".repeat(4097));
        assert_eq!(
            parse_query_parameter(&long),
            Err(QueryParameterError::TooLarge)
        );
    }

    #[test]
    fn api_uses_one_generation_and_preserves_score_explanation_and_text() {
        let (_temp, store, version) = populated_index();
        let expected_generation = store.read_view().unwrap().generation_id();
        let direct = store.query("rust").unwrap();
        let response = make_search_response(&store, "rust").unwrap();
        let hit = &response.results[0];
        assert_eq!(response.generation, expected_generation);
        assert_eq!(response.corpus_size, 1);
        assert_eq!(hit.version_id, version);
        assert_eq!(hit.score, direct[0].score);
        assert_eq!(
            hit.explanation.total_score,
            direct[0].explanation.total_score
        );
        assert_eq!(
            hit.explanation.normalized_terms,
            direct[0].explanation.normalized_terms
        );
        assert_eq!(
            hit.explanation.terms.len(),
            direct[0].explanation.terms.len()
        );
        assert_eq!(
            hit.explanation.statistics_source.generation,
            Some(expected_generation)
        );
        let serialized = serde_json::to_value(hit).unwrap();
        assert!(serialized["matched"].get("titleOccurrences").is_some());
        assert!(serialized["matched"].get("title_occurrences").is_none());
        assert!(hit.title.contains("<script>"));
        assert!(matches!(hit.matched, super::MatchSummary::Term { .. }));
    }

    #[test]
    fn empty_index_and_malformed_query_return_distinct_finite_states() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        let empty = make_search_response(&store, "rust").unwrap();
        assert_eq!(empty.corpus_size, 0);
        assert!(empty.results.is_empty());
        assert!(make_search_response(&store, "\"").is_err());
    }

    #[tokio::test]
    async fn http_routes_are_read_only_and_have_finite_errors() {
        let (_temp, store, _) = populated_index();
        let app = router(Arc::new(store), DEFAULT_BIND.port());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=rust")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let api_json = axum::body::to_bytes(response.into_body(), super::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let cli_json = super::search_store_json(_temp.path().join("index"), "rust").unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&api_json).unwrap(),
            serde_json::from_str::<serde_json::Value>(&cli_json).unwrap()
        );
        assert!(cli_json.contains("\\n\\u001b[31m"));
        assert!(!cli_json.contains('\u{1b}'));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/search?q=rust")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=rust")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::from("payload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=%GG")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(DEFAULT_BIND.ip().is_loopback());
    }

    #[tokio::test]
    async fn idle_api_and_cli_refuse_expired_public_collection_content() {
        let (temp, store) = expired_public_index();
        assert_eq!(
            super::search_store_json(temp.path().join("index"), "rust").unwrap_err(),
            "index store is unavailable"
        );
        let response = router(Arc::new(store), DEFAULT_BIND.port())
            .oneshot(
                Request::builder()
                    .uri("/api/search?q=rust")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), super::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "index_unavailable");
        assert!(!String::from_utf8_lossy(&body).contains("expired source content"));
    }

    fn raw_http_request(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn real_loopback_socket_allows_local_origin_and_rejects_foreign_authorities() {
        let (_temp, store, _) = populated_index();
        let (address_sender, address_receiver) = std::sync::mpsc::channel();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                address_sender.send(address).unwrap();
                axum::serve(listener, router(Arc::new(store), address.port()))
                    .with_graceful_shutdown(async {
                        let _ = shutdown_receiver.await;
                    })
                    .await
                    .unwrap();
            });
        });
        let address = address_receiver.recv().unwrap();
        let port = address.port();

        let local = raw_http_request(
            address,
            &format!(
                "GET /api/search?q=rust HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://localhost:{port}\r\nConnection: close\r\n\r\n"
            ),
        );
        let foreign_host = raw_http_request(
            address,
            &format!(
                "GET /api/search?q=rust HTTP/1.1\r\nHost: attacker.example:{port}\r\nConnection: close\r\n\r\n"
            ),
        );
        let foreign_origin = raw_http_request(
            address,
            &format!(
                "GET /api/search?q=rust HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://attacker.example\r\nConnection: close\r\n\r\n"
            ),
        );
        shutdown_sender.send(()).unwrap();
        server.join().unwrap();

        assert!(local.starts_with("HTTP/1.1 200"), "{local}");
        assert!(local.contains("Rust guide"), "{local}");
        assert!(foreign_host.starts_with("HTTP/1.1 403"), "{foreign_host}");
        assert!(!foreign_host.contains("Rust guide"), "{foreign_host}");
        assert!(
            foreign_origin.starts_with("HTTP/1.1 403"),
            "{foreign_origin}"
        );
        assert!(!foreign_origin.contains("Rust guide"), "{foreign_origin}");
    }
}
