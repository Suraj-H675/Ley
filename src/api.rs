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
use serde::de::DeserializeOwned;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::index::{MatchEvidence, SearchResult, StatisticsSource};
use crate::retrieval::{
    DOCUMENT_INSPECTION_CONTRACT_VERSION, DocumentInspectionRequest, EvidenceReference,
    EvidenceResolveError, RetrievalError, RetrievalRequest,
};
use crate::storage::{PersistentIndex, ReadView, StorageError};

pub const DEFAULT_BIND: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7331);
const MAX_URI_BYTES: usize = 12 * 1024;
const MAX_QUERY_BYTES: usize = 4096;
const MAX_RESULTS: usize = 20;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_TYPED_REQUEST_BYTES: usize = 16 * 1024;
const MAX_STORAGE_WORKERS: usize = 1;

#[derive(Clone)]
struct ApiState {
    index: Arc<PersistentIndex>,
    port: u16,
    storage_work: Arc<Semaphore>,
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
        no_store_json(status, &ApiError { error })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientFailure {
    InvalidRequest,
    UnsupportedContract,
    MalformedReference,
    WrongStore,
    NotLive,
    Revoked,
    VersionSuperseded,
    PublicCollectionExpired,
    ResourceCap,
    RequestBodyTooLarge,
    StorageFault,
    UnsupportedMediaType,
    NotAcceptable,
}

impl ClientFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedContract => "unsupported_contract",
            Self::MalformedReference => "malformed_reference",
            Self::WrongStore => "wrong_store",
            Self::NotLive => "not_live",
            Self::Revoked => "revoked",
            Self::VersionSuperseded => "version_superseded",
            Self::PublicCollectionExpired => "public_collection_expired",
            Self::ResourceCap => "resource_cap",
            Self::RequestBodyTooLarge => "resource_cap",
            Self::StorageFault => "storage_fault",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::NotAcceptable => "not_acceptable",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest | Self::MalformedReference => StatusCode::BAD_REQUEST,
            Self::UnsupportedContract => StatusCode::UNPROCESSABLE_ENTITY,
            Self::WrongStore => StatusCode::NOT_FOUND,
            Self::NotLive
            | Self::Revoked
            | Self::VersionSuperseded
            | Self::PublicCollectionExpired => StatusCode::GONE,
            Self::ResourceCap => StatusCode::TOO_MANY_REQUESTS,
            Self::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Self::StorageFault => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn response(self) -> Response {
        no_store_json(self.status(), &ApiError { error: self.code() })
    }
}

enum BlockingFailure {
    Saturated,
    WorkerFailed,
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
    let body = serde_json::to_string_pretty(&response)
        .map_err(|_| "could not serialize search results".to_owned())?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("search input or response exceeds its limit".to_owned());
    }
    Ok(body)
}

pub fn retrieve_store_json(
    store_path: impl AsRef<Path>,
    request: RetrievalRequest,
) -> Result<String, ClientFailure> {
    let index = PersistentIndex::open(store_path).map_err(|_| ClientFailure::StorageFault)?;
    let response = index.retrieve(request).map_err(map_retrieval_failure)?;
    serialize_client_response(&response)
}

pub fn resolve_evidence_store_json(
    store_path: impl AsRef<Path>,
    reference: &EvidenceReference,
) -> Result<String, ClientFailure> {
    let index = PersistentIndex::open(store_path).map_err(|_| ClientFailure::StorageFault)?;
    let response = index
        .resolve_evidence(reference)
        .map_err(map_resolve_failure)?;
    serialize_client_response(&response)
}

fn serialize_client_response<T: Serialize>(response: &T) -> Result<String, ClientFailure> {
    let body = serde_json::to_string_pretty(response).map_err(|_| ClientFailure::StorageFault)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ClientFailure::ResourceCap);
    }
    Ok(body)
}

fn router(index: Arc<PersistentIndex>, port: u16) -> Router {
    router_with_state(ApiState {
        index,
        port,
        storage_work: Arc::new(Semaphore::new(MAX_STORAGE_WORKERS)),
    })
}

fn router_with_state(state: ApiState) -> Router {
    Router::new()
        .route("/api/health", any(health))
        .route("/api/search", any(search))
        .route("/api/v1/retrieve", any(retrieve_v1))
        .route("/api/v1/evidence/resolve", any(resolve_evidence_v1))
        .route("/api/v1/evidence/inspect", any(inspect_evidence_v1))
        .fallback(not_found)
        .with_state(state)
}

async fn health(State(state): State<ApiState>, request: Request<Body>) -> Response {
    if let Some(error) = validate_local_authority(&request, state.port, false) {
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
    if let Some(error) = validate_local_authority(&request, state.port, false) {
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
    let search_result = match run_storage(state.clone(), move |index| {
        make_search_response(&index, &query)
    })
    .await
    {
        Ok(result) => result,
        Err(BlockingFailure::Saturated | BlockingFailure::WorkerFailed) => {
            return SearchFailure::IndexUnavailable.response();
        }
    };
    match search_result {
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

async fn retrieve_v1(State(state): State<ApiState>, request: Request<Body>) -> Response {
    let require_origin = request.method() == Method::POST;
    if let Some(error) = validate_local_authority(&request, state.port, require_origin) {
        return local_authority_error(error);
    }
    if request.method() != Method::POST {
        return method_not_allowed_for("POST");
    }
    if let Err(error) = validate_json_headers(&request, MAX_TYPED_REQUEST_BYTES) {
        return error.response();
    }
    let permit = match acquire_storage_permit(&state) {
        Ok(permit) => permit,
        Err(BlockingFailure::Saturated) => return ClientFailure::ResourceCap.response(),
        Err(BlockingFailure::WorkerFailed) => return ClientFailure::StorageFault.response(),
    };
    let retrieval_request =
        match read_json_body::<RetrievalRequest>(request, MAX_TYPED_REQUEST_BYTES).await {
            Ok(request) => request,
            Err(error) => return error.response(),
        };
    let retrieval = match run_storage_with_permit(state.index, permit, move |index| {
        index.retrieve(retrieval_request)
    })
    .await
    {
        Ok(result) => result.map_err(map_retrieval_failure),
        Err(BlockingFailure::Saturated) => Err(ClientFailure::ResourceCap),
        Err(BlockingFailure::WorkerFailed) => Err(ClientFailure::StorageFault),
    };
    match retrieval {
        Ok(response) => typed_success(&response),
        Err(error) => error.response(),
    }
}

async fn resolve_evidence_v1(State(state): State<ApiState>, request: Request<Body>) -> Response {
    let require_origin = request.method() == Method::POST;
    if let Some(error) = validate_local_authority(&request, state.port, require_origin) {
        return local_authority_error(error);
    }
    if request.method() != Method::POST {
        return method_not_allowed_for("POST");
    }
    if let Err(error) = validate_json_headers(&request, MAX_TYPED_REQUEST_BYTES) {
        return error.response();
    }
    let permit = match acquire_storage_permit(&state) {
        Ok(permit) => permit,
        Err(BlockingFailure::Saturated) => return ClientFailure::ResourceCap.response(),
        Err(BlockingFailure::WorkerFailed) => return ClientFailure::StorageFault.response(),
    };
    let reference =
        match read_json_body::<EvidenceReference>(request, MAX_TYPED_REQUEST_BYTES).await {
            Ok(reference) => reference,
            Err(error) => return error.response(),
        };
    let resolution = match run_storage_with_permit(state.index, permit, move |index| {
        index.resolve_evidence(&reference)
    })
    .await
    {
        Ok(result) => result.map_err(map_resolve_failure),
        Err(BlockingFailure::Saturated) => Err(ClientFailure::ResourceCap),
        Err(BlockingFailure::WorkerFailed) => Err(ClientFailure::StorageFault),
    };
    match resolution {
        Ok(response) => typed_success(&response),
        Err(error) => error.response(),
    }
}

async fn inspect_evidence_v1(State(state): State<ApiState>, request: Request<Body>) -> Response {
    let require_origin = request.method() == Method::POST;
    if let Some(error) = validate_local_authority(&request, state.port, require_origin) {
        return local_authority_error(error);
    }
    if request.method() != Method::POST {
        return method_not_allowed_for("POST");
    }
    if let Err(error) = validate_json_headers(&request, MAX_TYPED_REQUEST_BYTES) {
        return error.response();
    }
    let permit = match acquire_storage_permit(&state) {
        Ok(permit) => permit,
        Err(BlockingFailure::Saturated) => return ClientFailure::ResourceCap.response(),
        Err(BlockingFailure::WorkerFailed) => return ClientFailure::StorageFault.response(),
    };
    let inspection =
        match read_json_body::<DocumentInspectionRequest>(request, MAX_TYPED_REQUEST_BYTES).await {
            Ok(request) => request,
            Err(error) => return error.response(),
        };
    if inspection.contract_version != DOCUMENT_INSPECTION_CONTRACT_VERSION {
        return ClientFailure::UnsupportedContract.response();
    }
    let page = match run_storage_with_permit(state.index, permit, move |index| {
        index.inspect_document_page(&inspection.reference, inspection.offset_byte)
    })
    .await
    {
        Ok(result) => result.map_err(map_inspection_failure),
        Err(BlockingFailure::Saturated) => Err(ClientFailure::ResourceCap),
        Err(BlockingFailure::WorkerFailed) => Err(ClientFailure::StorageFault),
    };
    match page {
        Ok(page) => typed_success(&page),
        Err(error) => error.response(),
    }
}

async fn run_storage<T, F>(state: ApiState, operation: F) -> Result<T, BlockingFailure>
where
    T: Send + 'static,
    F: FnOnce(Arc<PersistentIndex>) -> T + Send + 'static,
{
    let permit = acquire_storage_permit(&state)?;
    run_storage_with_permit(state.index, permit, operation).await
}

fn acquire_storage_permit(state: &ApiState) -> Result<OwnedSemaphorePermit, BlockingFailure> {
    state
        .storage_work
        .clone()
        .try_acquire_owned()
        .map_err(|_| BlockingFailure::Saturated)
}

async fn run_storage_with_permit<T, F>(
    index: Arc<PersistentIndex>,
    permit: OwnedSemaphorePermit,
    operation: F,
) -> Result<T, BlockingFailure>
where
    T: Send + 'static,
    F: FnOnce(Arc<PersistentIndex>) -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit: OwnedSemaphorePermit = permit;
        operation(index)
    })
    .await
    .map_err(|_| BlockingFailure::WorkerFailed)
}

fn validate_json_headers(request: &Request<Body>, body_limit: usize) -> Result<(), ClientFailure> {
    let mut content_types = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = content_types
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(ClientFailure::UnsupportedMediaType)?;
    if content_types.next().is_some()
        || !content_type.trim().eq_ignore_ascii_case("application/json")
    {
        return Err(ClientFailure::UnsupportedMediaType);
    }

    let mut accepts = request.headers().get_all(header::ACCEPT).iter();
    let accept = accepts
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(ClientFailure::NotAcceptable)?;
    if accepts.next().is_some() || !accept.trim().eq_ignore_ascii_case("application/json") {
        return Err(ClientFailure::NotAcceptable);
    }

    if request
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| {
            value
                .to_str()
                .map(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"))
                .unwrap_or(true)
        })
    {
        return Err(ClientFailure::UnsupportedMediaType);
    }

    let mut lengths = request.headers().get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next() {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ClientFailure::InvalidRequest)?;
        if lengths.next().is_some() {
            return Err(ClientFailure::InvalidRequest);
        }
        if length > body_limit {
            return Err(ClientFailure::RequestBodyTooLarge);
        }
    }
    Ok(())
}

async fn read_json_body<T: DeserializeOwned>(
    request: Request<Body>,
    body_limit: usize,
) -> Result<T, ClientFailure> {
    let bytes = axum::body::to_bytes(request.into_body(), body_limit)
        .await
        .map_err(|_| ClientFailure::RequestBodyTooLarge)?;
    serde_json::from_slice(&bytes).map_err(|_| ClientFailure::InvalidRequest)
}

fn typed_success<T: Serialize>(value: &T) -> Response {
    let Ok(body) = serde_json::to_vec(value) else {
        return ClientFailure::StorageFault.response();
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return ClientFailure::ResourceCap.response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap_or_else(|_| ClientFailure::StorageFault.response())
}

fn no_store_json<T: Serialize>(status: StatusCode, value: &T) -> Response {
    let body =
        serde_json::to_vec(value).unwrap_or_else(|_| b"{\"error\":\"internal_error\"}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn method_not_allowed_for(method: &'static str) -> Response {
    let mut response = no_store_json(
        StatusCode::METHOD_NOT_ALLOWED,
        &ApiError {
            error: "method_not_allowed",
        },
    );
    response
        .headers_mut()
        .insert(header::ALLOW, axum::http::HeaderValue::from_static(method));
    response
}

fn map_retrieval_failure(error: RetrievalError) -> ClientFailure {
    match error {
        RetrievalError::UnsupportedContractVersion(_) => ClientFailure::UnsupportedContract,
        RetrievalError::ResourceLimit | RetrievalError::ResponseTooLarge => {
            ClientFailure::ResourceCap
        }
        RetrievalError::PublicCollectionExpired => ClientFailure::PublicCollectionExpired,
        RetrievalError::CorruptStorage | RetrievalError::StorageUnavailable => {
            ClientFailure::StorageFault
        }
        RetrievalError::InvalidHitLimit
        | RetrievalError::QuestionTooLong { .. }
        | RetrievalError::TooManyTerms { .. }
        | RetrievalError::TooManyDistinctTerms { .. }
        | RetrievalError::PhraseTooLong { .. }
        | RetrievalError::TokenTooLong { .. }
        | RetrievalError::UnterminatedQuote
        | RetrievalError::InvalidEscape
        | RetrievalError::EmptyQuotedPhrase
        | RetrievalError::InvalidRange => ClientFailure::InvalidRequest,
    }
}

fn map_resolve_failure(error: EvidenceResolveError) -> ClientFailure {
    match error {
        EvidenceResolveError::MalformedReference
        | EvidenceResolveError::OutOfBounds
        | EvidenceResolveError::NotUtf8Boundary
        | EvidenceResolveError::InvalidPassageWindow => ClientFailure::MalformedReference,
        EvidenceResolveError::UnsupportedPassageSchema => ClientFailure::UnsupportedContract,
        EvidenceResolveError::WrongStore => ClientFailure::WrongStore,
        EvidenceResolveError::NotLive => ClientFailure::NotLive,
        EvidenceResolveError::Revoked => ClientFailure::Revoked,
        EvidenceResolveError::VersionSuperseded => ClientFailure::VersionSuperseded,
        EvidenceResolveError::PublicCollectionExpired => ClientFailure::PublicCollectionExpired,
        EvidenceResolveError::ResourceLimit => ClientFailure::ResourceCap,
        EvidenceResolveError::CorruptStorage | EvidenceResolveError::StorageUnavailable => {
            ClientFailure::StorageFault
        }
    }
}

fn map_inspection_failure(error: EvidenceResolveError) -> ClientFailure {
    match error {
        EvidenceResolveError::OutOfBounds | EvidenceResolveError::NotUtf8Boundary => {
            ClientFailure::InvalidRequest
        }
        other => map_resolve_failure(other),
    }
}

async fn not_found(State(state): State<ApiState>, request: Request<Body>) -> Response {
    if let Some(error) = validate_local_authority(&request, state.port, false) {
        return local_authority_error(error);
    }
    no_store_json(StatusCode::NOT_FOUND, &ApiError { error: "not_found" })
}

fn local_authority_error(error: &'static str) -> Response {
    no_store_json(StatusCode::FORBIDDEN, &ApiError { error })
}

fn validate_local_authority(
    request: &Request<Body>,
    port: u16,
    require_origin: bool,
) -> Option<&'static str> {
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
    let Some(origin) = origins.next() else {
        return require_origin.then_some("invalid_origin");
    };
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
    let mut response = no_store_json(
        StatusCode::METHOD_NOT_ALLOWED,
        &ApiError {
            error: "method_not_allowed",
        },
    );
    response
        .headers_mut()
        .insert(header::ALLOW, axum::http::HeaderValue::from_static("GET"));
    response
}

fn body_not_allowed() -> Response {
    no_store_json(
        StatusCode::BAD_REQUEST,
        &ApiError {
            error: "request_body_not_allowed",
        },
    )
}

fn request_body_is_empty(request: &Request<Body>) -> bool {
    request.body().is_end_stream() && request.body().size_hint().exact() == Some(0)
}

fn internal_error() -> Response {
    no_store_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &ApiError {
            error: "internal_error",
        },
    )
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
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Waker};
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use super::{
        DEFAULT_BIND, QueryParameterError, make_search_response, parse_query_parameter, router,
        router_with_state,
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
    async fn typed_question_and_resolution_match_cli_contracts() {
        let (temp, store, _) = populated_index();
        let app = router(Arc::new(store), DEFAULT_BIND.port());
        let retrieval_request = crate::retrieval::RetrievalRequest::question(
            "Where does Rust retrieval use a Ley-owned inverted index?",
        );
        let cli_retrieval =
            super::retrieve_store_json(temp.path().join("index"), retrieval_request.clone())
                .unwrap();
        let response = app
            .clone()
            .oneshot(typed_post(
                "/api/v1/retrieve",
                serde_json::to_vec(&retrieval_request).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let api_body = axum::body::to_bytes(response.into_body(), super::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let api_json: serde_json::Value = serde_json::from_slice(&api_body).unwrap();
        let cli_json: serde_json::Value = serde_json::from_str(&cli_retrieval).unwrap();
        assert_eq!(api_json, cli_json);
        assert_eq!(api_json["answer_assessment"], "not_assessed");
        assert_eq!(
            api_json["hits"][0]["passage"]["text"],
            "Rust retrieval uses a small Ley-owned inverted index."
        );
        assert_eq!(
            api_json["hits"][0]["requested_url"],
            "https://fixtures.example.test/rust"
        );

        let reference: crate::retrieval::EvidenceReference =
            serde_json::from_value(api_json["hits"][0]["passage"]["reference"].clone()).unwrap();
        let cli_resolution =
            super::resolve_evidence_store_json(temp.path().join("index"), &reference).unwrap();
        let response = app
            .oneshot(typed_post(
                "/api/v1/evidence/resolve",
                serde_json::to_vec(&reference).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let api_resolution = axum::body::to_bytes(response.into_body(), super::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&api_resolution).unwrap(),
            serde_json::from_str::<serde_json::Value>(&cli_resolution).unwrap()
        );
    }

    #[tokio::test]
    async fn typed_document_inspection_returns_bounded_current_extracted_text() {
        let (temp, store, _) = populated_index();
        let reference = store
            .retrieve(crate::retrieval::RetrievalRequest::question(
                "rust retrieval",
            ))
            .unwrap()
            .hits
            .remove(0)
            .passage
            .reference;
        let initial_generation = store.read_view().unwrap().generation_id();
        let expected_page = store.inspect_document_page(&reference, 0).unwrap();
        assert_eq!(
            expected_page.text,
            "Rust retrieval uses a small Ley-owned inverted index."
        );
        assert_eq!(expected_page.next_offset_byte, None);

        let app = router(Arc::new(store), DEFAULT_BIND.port());
        let request = crate::retrieval::DocumentInspectionRequest {
            contract_version: crate::retrieval::DOCUMENT_INSPECTION_CONTRACT_VERSION,
            reference: reference.clone(),
            offset_byte: 0,
        };
        let response = app
            .clone()
            .oneshot(typed_post(
                "/api/v1/evidence/inspect",
                serde_json::to_vec(&request).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), super::MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert!(bytes.len() <= super::MAX_RESPONSE_BYTES);
        let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(page, serde_json::to_value(expected_page).unwrap());
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&temp.path().to_string_lossy().to_string())
        );

        let mut invalid_offset = request.clone();
        invalid_offset.offset_byte = u32::MAX;
        let response = app
            .clone()
            .oneshot(typed_post(
                "/api/v1/evidence/inspect",
                serde_json::to_vec(&invalid_offset).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
            "invalid_request"
        );

        let mut unknown_field = serde_json::to_value(&request).unwrap();
        unknown_field["path"] = serde_json::Value::String("../../etc/passwd".to_owned());
        unknown_field["page_bytes"] = serde_json::Value::Number(999_999.into());
        let response = app
            .clone()
            .oneshot(typed_post(
                "/api/v1/evidence/inspect",
                serde_json::to_vec(&unknown_field).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
            "invalid_request"
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("/etc/passwd"));

        let mut unsupported_contract = request.clone();
        unsupported_contract.contract_version += 1;
        let response = app
            .clone()
            .oneshot(typed_post(
                "/api/v1/evidence/inspect",
                serde_json::to_vec(&unsupported_contract).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
            "unsupported_contract"
        );

        let response = app
            .oneshot(typed_post(
                "/api/v1/evidence/inspect",
                vec![b'x'; super::MAX_TYPED_REQUEST_BYTES + 1],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let reopened = PersistentIndex::open(temp.path().join("index")).unwrap();
        assert_eq!(
            reopened.read_view().unwrap().generation_id(),
            initial_generation
        );
    }

    #[tokio::test]
    async fn typed_routes_reject_unsafe_headers_unknown_json_and_overflow_without_text() {
        let (_temp, store, _) = populated_index();
        let app = router(Arc::new(store), DEFAULT_BIND.port());
        let valid_body = br#"{"mode":"question","request":{"contract_version":1,"question":"rust","max_hits":8}}"#;

        for (request, expected_code) in [
            (
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/retrieve")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ACCEPT, "application/json")
                    .body(Body::from(valid_body.to_vec()))
                    .unwrap(),
                "invalid_origin",
            ),
            (
                typed_post_with_origin(
                    "http://attacker.example",
                    "/api/v1/retrieve",
                    valid_body.to_vec(),
                ),
                "invalid_origin",
            ),
            (
                typed_post_with_host("attacker.example", "/api/v1/retrieve", valid_body.to_vec()),
                "invalid_host",
            ),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], expected_code);
            assert!(!String::from_utf8_lossy(&body).contains("Rust retrieval uses"));
        }

        for (request, status, code) in [
            (typed_post("/api/v1/retrieve", valid_body.to_vec()), StatusCode::OK, None),
            (typed_post_with("/api/v1/retrieve", valid_body.to_vec(), "text/plain", "application/json"), StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("unsupported_media_type")),
            (typed_post_with("/api/v1/retrieve", valid_body.to_vec(), "application/json", "text/plain"), StatusCode::NOT_ACCEPTABLE, Some("not_acceptable")),
            (typed_post("/api/v1/retrieve", br#"{"mode":"question","request":{"contract_version":1,"question":"rust","max_hits":8,"extra":true}}"#.to_vec()), StatusCode::BAD_REQUEST, Some("invalid_request")),
            (typed_post("/api/v1/retrieve", br#"{"mode":"question","mode":"question","request":{"contract_version":1,"question":"rust","max_hits":8}}"#.to_vec()), StatusCode::BAD_REQUEST, Some("invalid_request")),
            (typed_post("/api/v1/retrieve", br#"{"mode":"question","request":{"contract_version":99,"question":"rust","max_hits":8}}"#.to_vec()), StatusCode::UNPROCESSABLE_ENTITY, Some("unsupported_contract")),
            (typed_post("/api/v1/retrieve", vec![b'x'; super::MAX_TYPED_REQUEST_BYTES + 1]), StatusCode::PAYLOAD_TOO_LARGE, Some("resource_cap")),
        ] {
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if let Some(code) = code {
                let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(json["error"], code);
                assert!(!String::from_utf8_lossy(&body).contains("Rust retrieval uses"));
            }
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/retrieve")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .header(
                        "origin",
                        format!("http://localhost:{}", DEFAULT_BIND.port()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "POST");
    }

    #[tokio::test]
    async fn typed_routes_reject_saturated_work_before_parsing_request_body() {
        let (_temp, store, _) = populated_index();
        let state = super::ApiState {
            index: Arc::new(store),
            port: DEFAULT_BIND.port(),
            storage_work: Arc::new(tokio::sync::Semaphore::new(0)),
        };
        let app = router_with_state(state);
        let response = app
            .oneshot(typed_post("/api/v1/retrieve", b"{".to_vec()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "resource_cap");
    }

    #[tokio::test]
    async fn typed_resolution_rechecks_tombstone_revocation_and_superseded_versions() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        let cases = [
            ("tombstone", Intent::Tombstone, "not_live"),
            ("revoked", Intent::Revoke, "revoked"),
            (
                "superseded",
                Intent::Upsert {
                    effective_url: "https://fixtures.example.test/superseded".to_owned(),
                    title: "Updated document".to_owned(),
                    body: "new current passage text".to_owned(),
                },
                "version_superseded",
            ),
        ];
        let mut captured = Vec::new();
        for (name, _, _) in &cases {
            let key = UrlKey::parse(&format!("https://fixtures.example.test/{name}")).unwrap();
            let lease = store.issue_fence(&key).unwrap();
            store
                .apply(
                    &lease,
                    Intent::Upsert {
                        effective_url: key.as_str().to_owned(),
                        title: format!("{name} source"),
                        body: format!("old passage text for {name}"),
                    },
                )
                .unwrap();
            captured.push(
                store
                    .retrieve(crate::retrieval::RetrievalRequest::question(format!(
                        "old passage {name}"
                    )))
                    .unwrap()
                    .hits
                    .into_iter()
                    .find(|hit| hit.requested_url == key.as_str())
                    .unwrap()
                    .passage
                    .reference,
            );
        }
        for ((name, action, _), reference) in cases.iter().zip(captured.iter()) {
            let key = UrlKey::parse(&format!("https://fixtures.example.test/{name}")).unwrap();
            let lease = store.issue_fence(&key).unwrap();
            store.apply(&lease, action.clone()).unwrap();
            assert_eq!(reference.requested_url, key.as_str());
        }

        let app = router(Arc::new(store), DEFAULT_BIND.port());
        for ((_, _, expected_code), reference) in cases.iter().zip(captured.iter()) {
            let response = app
                .clone()
                .oneshot(typed_post(
                    "/api/v1/evidence/resolve",
                    serde_json::to_vec(reference).unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(error["error"], *expected_code);
            assert!(!String::from_utf8_lossy(&bytes).contains("old passage text"));

            let inspection = crate::retrieval::DocumentInspectionRequest {
                contract_version: crate::retrieval::DOCUMENT_INSPECTION_CONTRACT_VERSION,
                reference: reference.clone(),
                offset_byte: 0,
            };
            let response = app
                .clone()
                .oneshot(typed_post(
                    "/api/v1/evidence/inspect",
                    serde_json::to_vec(&inspection).unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::GONE);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(error["error"], *expected_code);
            assert!(!String::from_utf8_lossy(&bytes).contains("old passage text"));
        }
    }

    fn typed_post(path: &str, body: Vec<u8>) -> Request<Body> {
        typed_post_with(path, body, "application/json", "application/json")
    }

    fn typed_post_with(
        path: &str,
        body: Vec<u8>,
        content_type: &str,
        accept: &str,
    ) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
            .header(
                "origin",
                format!("http://localhost:{}", DEFAULT_BIND.port()),
            )
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT, accept)
            .body(Body::from(body))
            .unwrap()
    }

    fn typed_post_with_origin(origin: &str, path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
            .header("origin", origin)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn typed_post_with_host(host: &str, path: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, host)
            .header(
                "origin",
                format!("http://localhost:{}", DEFAULT_BIND.port()),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn storage_search_yields_the_api_runtime_for_health_requests() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        let block = "blockingprobe durable lexical retrieval scheduling storage query ";
        let body = block.repeat(600_000 / block.len() + 1);
        for number in 0..6 {
            let key =
                UrlKey::parse(&format!("https://fixtures.example.test/overlap/{number}")).unwrap();
            let lease = store.issue_fence(&key).unwrap();
            store
                .apply(
                    &lease,
                    Intent::Upsert {
                        effective_url: key.as_str().to_owned(),
                        title: format!("blocking probe document {number}"),
                        body: body.clone(),
                    },
                )
                .unwrap();
        }
        let app = router(Arc::new(store), DEFAULT_BIND.port());
        let search_request = Request::builder()
            .uri("/api/search?q=blockingprobe%20AND%20durable")
            .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
            .body(Body::empty())
            .unwrap();
        let mut search = Box::pin(app.clone().oneshot(search_request));
        let first_poll_started = Instant::now();
        let first_poll = search
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let first_poll_ms = first_poll_started.elapsed().as_secs_f64() * 1000.0;
        assert!(
            first_poll.is_pending(),
            "storage search completed inline before yielding to /api/health ({first_poll_ms:.3} ms)"
        );

        let health_started = Instant::now();
        let health = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .header(header::HOST, format!("localhost:{}", DEFAULT_BIND.port()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let health_ms = health_started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(health.status(), StatusCode::OK);

        let search_started = Instant::now();
        let search_response = search.await.unwrap();
        let search_ms = search_started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(search_response.status(), StatusCode::OK);
        println!(
            "api overlap probe: documents=6 body_bytes_each={} first_poll_ms={first_poll_ms:.3} health_ms={health_ms:.3} remaining_search_ms={search_ms:.3}",
            body.len()
        );
    }

    #[test]
    fn cli_json_rejects_pretty_response_over_byte_limit() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path().join("index")).unwrap();
        for number in 0..20 {
            let key = UrlKey::parse(&format!(
                "https://fixtures.example.test/large-response/{number}"
            ))
            .unwrap();
            let lease = store.issue_fence(&key).unwrap();
            store
                .apply(
                    &lease,
                    Intent::Upsert {
                        effective_url: key.as_str().to_owned(),
                        title: format!("response limit document {number}"),
                        body: "needle".to_owned(),
                    },
                )
                .unwrap();
        }

        let query = std::iter::once("needle".to_owned())
            .chain((1..64).map(|number| format!("term{number:02}")))
            .collect::<Vec<_>>()
            .join(" OR ");
        assert_eq!(store.query(&query).unwrap().len(), 20);

        assert_eq!(
            super::search_store_json(temp.path().join("index"), &query)
                .map(|response| response.len()),
            Err("search input or response exceeds its limit".to_owned())
        );
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
