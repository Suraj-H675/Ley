use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use url::Url;

use crate::html::{
    MAX_COMPRESSED_RESPONSE_BYTES, MAX_DECODED_RESPONSE_BYTES, MAX_FIELDS_BYTES,
    MAX_OUTGOING_LINKS, MAX_TITLE_BYTES, extract_html,
};
use crate::page_policy::parse_x_robots_tags;
use crate::public_policy::{PublicCrawlPolicy, PublicPolicyError, PublicSourcePolicy};
use crate::robots::{MAX_ROBOTS_BYTES, parse_robots};
use crate::safe_fetch::{
    DEFAULT_REQUEST_TIMEOUT, DestinationEvidence, DestinationResolver, FixtureCapability,
    HttpResponse, MAX_ROBOTS_REDIRECTS, PublicAuthority, SafeFetchError, SafeFetcher,
    SystemResolver,
};
use crate::storage::{ApplyOutcome, Intent, PersistentIndex, StorageError};
use crate::url_key::UrlKey;

const MAX_FRONTIER_ENTRIES: usize = 10_000;
const MAX_ORIGINS: usize = 64;
const MAX_OUTBOX_ROWS: usize = 10_000;
const MAX_OUTBOX_BYTES: usize = 16 * 1024 * 1024;
const CONTROL_BATCH_SIZE: usize = 128;
const MAX_SQLITE_PAGES: u32 = 8192;
const MAX_EVENT_ROWS: usize = 100_000;
const MAX_ROBOTS_AGE_MS: u64 = 24 * 60 * 60 * 1000;
const DEFAULT_ROBOTS_AGE_MS: u64 = 60 * 60 * 1000;
const DEFAULT_RETRY_MS: u64 = 1_000;
const DEFAULT_RECRAWL_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_RETRY_MS: u64 = 60 * 60 * 1000;
const MAX_HEADER_VALUE_BYTES: usize = 8192;
const MAX_SOURCE_ID_BYTES: usize = 128;
const MAX_POLICY_TEXT_BYTES: usize = 1024;
const MAX_CRAWL_WIRE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CRAWL_DECODED_BYTES: usize = 128 * 1024 * 1024;
const MAX_ROBOTS_STORE_BYTES: usize = 8 * 1024 * 1024;
const AGENT_TOKEN: &str = "LeyBot";

#[derive(Debug)]
pub(crate) enum CrawlError {
    Io(io::Error),
    Sql(rusqlite::Error),
    Storage(StorageError),
    Url(String),
    Policy(String),
    Transport(String),
    Capacity(&'static str),
    Cancelled,
    RuntimeLimit,
}

impl fmt::Display for CrawlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "crawler I/O error: {error}"),
            Self::Sql(error) => write!(f, "frontier database error: {error}"),
            Self::Storage(error) => write!(f, "index storage error: {error}"),
            Self::Url(message) => write!(f, "crawler URL error: {message}"),
            Self::Policy(message) => write!(f, "source policy error: {message}"),
            Self::Transport(message) => write!(f, "controlled fetch failed: {message}"),
            Self::Capacity(limit) => write!(f, "crawler capacity exceeded: {limit}"),
            Self::Cancelled => f.write_str("crawl cancelled"),
            Self::RuntimeLimit => f.write_str("crawler runtime limit reached"),
        }
    }
}

impl std::error::Error for CrawlError {}

impl From<io::Error> for CrawlError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for CrawlError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}

impl From<StorageError> for CrawlError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionPolicy {
    Until(u64),
    WhilePolicyValid,
}

pub(crate) struct PublicSourceAdmission {
    pub id: String,
    pub origins: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub policy_sha256: String,
    pub crawl_contact: String,
    pub valid_until_ms: u64,
    pub retention: RetentionPolicy,
    pub max_requests: u64,
    pub min_origin_delay_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourcePolicy {
    pub id: String,
    pub allowed_origins: Vec<String>,
    pub allowed_path_prefixes: Vec<String>,
    pub rights_basis: String,
    pub crawl_contact: String,
    pub valid_until_ms: u64,
    pub retention: RetentionPolicy,
    pub max_requests: u64,
    pub min_origin_delay_ms: u64,
}

impl SourcePolicy {
    pub(crate) fn owned_fixture(
        id: impl Into<String>,
        origins: Vec<String>,
        allowed_path_prefixes: Vec<String>,
        valid_until_ms: u64,
    ) -> Self {
        Self {
            id: id.into(),
            allowed_origins: origins,
            allowed_path_prefixes,
            rights_basis: "authored_local_fixture".to_owned(),
            crawl_contact: "ley-local-fixture".to_owned(),
            valid_until_ms,
            retention: RetentionPolicy::WhilePolicyValid,
            max_requests: 512,
            min_origin_delay_ms: 0,
        }
    }

    pub(crate) fn public(admission: PublicSourceAdmission) -> Self {
        Self {
            id: admission.id,
            allowed_origins: admission.origins,
            allowed_path_prefixes: admission.allowed_path_prefixes,
            rights_basis: format!("public_source_policy_sha256={}", admission.policy_sha256),
            crawl_contact: admission.crawl_contact,
            valid_until_ms: admission.valid_until_ms,
            retention: admission.retention,
            max_requests: admission.max_requests,
            min_origin_delay_ms: admission.min_origin_delay_ms,
        }
    }

    fn validate<R: DestinationResolver + 'static>(
        &self,
        now_ms: u64,
        fetcher: &SafeFetcher<R>,
    ) -> Result<(), CrawlError> {
        if self.id.is_empty()
            || self.id.len() > MAX_SOURCE_ID_BYTES
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CrawlError::Policy("source ID is invalid".to_owned()));
        }
        let fixture_policy = self.rights_basis == "authored_local_fixture"
            && self.crawl_contact == "ley-local-fixture";
        let public_policy = self
            .rights_basis
            .strip_prefix("public_source_policy_sha256=")
            .is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            && !self.crawl_contact.trim().is_empty()
            && self.crawl_contact.len() <= MAX_POLICY_TEXT_BYTES;
        if (!fixture_policy && !public_policy)
            || self.rights_basis.len() > MAX_POLICY_TEXT_BYTES
            || self.crawl_contact.len() > MAX_POLICY_TEXT_BYTES
        {
            return Err(CrawlError::Policy(
                "source policy must have an explicit fixture or reviewed public basis".to_owned(),
            ));
        }
        if self.valid_until_ms <= now_ms
            || self.max_requests == 0
            || self.allowed_origins.is_empty()
        {
            return Err(CrawlError::Policy(
                "policy must be current, request-bounded, and name an origin".to_owned(),
            ));
        }
        if self.allowed_origins.len() > MAX_ORIGINS {
            return Err(CrawlError::Capacity("source origin count"));
        }
        for origin in &self.allowed_origins {
            let parsed = Url::parse(origin).map_err(|error| CrawlError::Url(error.to_string()))?;
            let authorized = if fixture_policy {
                fetcher.has_fixture_capability(&parsed)
            } else {
                fetcher.has_public_authority(&parsed)
            };
            if origin_of_url(&parsed) != *origin
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || !authorized
            {
                return Err(CrawlError::Policy(
                    "origin is not an exact authority in the active source policy".to_owned(),
                ));
            }
        }
        if self.allowed_path_prefixes.is_empty()
            || self.allowed_path_prefixes.iter().any(|path| {
                !crate::url_key::path_is_within_prefix(path, path)
                    || path.len() > 2048
                    || path.contains(['?', '#', '\\', '\r', '\n'])
            })
        {
            return Err(CrawlError::Policy(
                "policy requires bounded absolute path scopes".to_owned(),
            ));
        }
        if let RetentionPolicy::Until(deadline) = self.retention
            && deadline <= now_ms
        {
            return Err(CrawlError::Policy(
                "retention deadline is expired".to_owned(),
            ));
        }
        Ok(())
    }

    fn allows_url(&self, url: &Url, now_ms: u64) -> bool {
        if now_ms >= self.valid_until_ms
            || matches!(self.retention, RetentionPolicy::Until(deadline) if now_ms >= deadline)
        {
            return false;
        }
        if !self
            .allowed_origins
            .iter()
            .any(|origin| origin == &origin_of_url(url))
        {
            return false;
        }
        self.allowed_path_prefixes
            .iter()
            .any(|prefix| crate::url_key::path_is_within_prefix(url.path(), prefix))
    }

    fn allows_origin_url(&self, url: &Url, now_ms: u64) -> bool {
        now_ms < self.valid_until_ms
            && !matches!(self.retention, RetentionPolicy::Until(deadline) if now_ms >= deadline)
            && self
                .allowed_origins
                .iter()
                .any(|origin| origin == &origin_of_url(url))
    }

    fn same_admission_except_retention_deadline(&self, other: &Self) -> bool {
        self.id == other.id
            && self.allowed_origins == other.allowed_origins
            && self.allowed_path_prefixes == other.allowed_path_prefixes
            && self.rights_basis == other.rights_basis
            && self.crawl_contact == other.crawl_contact
            && self.valid_until_ms == other.valid_until_ms
            && self.max_requests == other.max_requests
            && self.min_origin_delay_ms == other.min_origin_delay_ms
            && matches!(
                (self.retention, other.retention),
                (RetentionPolicy::Until(_), RetentionPolicy::Until(_))
                    | (
                        RetentionPolicy::WhilePolicyValid,
                        RetentionPolicy::WhilePolicyValid
                    )
            )
    }

    fn to_db_fields(&self) -> (String, String, i64, String, String, i64, i64, i64) {
        let retention_until = match self.retention {
            RetentionPolicy::Until(deadline) => deadline as i64,
            RetentionPolicy::WhilePolicyValid => 0,
        };
        (
            self.allowed_origins.join("\n"),
            self.allowed_path_prefixes.join("\n"),
            self.valid_until_ms as i64,
            self.rights_basis.clone(),
            self.crawl_contact.clone(),
            retention_until,
            self.max_requests.min(i64::MAX as u64) as i64,
            self.min_origin_delay_ms.min(i64::MAX as u64) as i64,
        )
    }

    fn from_db(id: String, fields: StoredPolicyFields) -> Result<Self, CrawlError> {
        let StoredPolicyFields {
            origins,
            paths,
            valid_until_ms,
            rights_basis,
            crawl_contact,
            retention_until_ms,
            max_requests,
            min_origin_delay_ms,
        } = fields;
        Ok(Self {
            id,
            allowed_origins: origins.lines().map(str::to_owned).collect(),
            allowed_path_prefixes: paths.lines().map(str::to_owned).collect(),
            rights_basis,
            crawl_contact,
            valid_until_ms: u64::try_from(valid_until_ms)
                .map_err(|_| CrawlError::Policy("invalid stored policy expiry".to_owned()))?,
            retention: if retention_until_ms == 0 {
                RetentionPolicy::WhilePolicyValid
            } else {
                RetentionPolicy::Until(u64::try_from(retention_until_ms).map_err(|_| {
                    CrawlError::Policy("invalid stored retention deadline".to_owned())
                })?)
            },
            max_requests: u64::try_from(max_requests)
                .map_err(|_| CrawlError::Policy("invalid stored request limit".to_owned()))?,
            min_origin_delay_ms: u64::try_from(min_origin_delay_ms)
                .map_err(|_| CrawlError::Policy("invalid stored origin delay".to_owned()))?,
        })
    }
}

struct StoredPolicyFields {
    origins: String,
    paths: String,
    valid_until_ms: i64,
    rights_basis: String,
    crawl_contact: String,
    retention_until_ms: i64,
    max_requests: i64,
    min_origin_delay_ms: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct CrawlLimits {
    pub max_requests_per_run: usize,
    pub global_active: usize,
    pub per_origin_active: usize,
    pub max_wire_bytes_per_run: usize,
    pub max_decompressed_bytes_per_run: usize,
    pub max_runtime: Duration,
    pub request_timeout: Duration,
    pub max_retries: u16,
    pub page_redirects: usize,
}

impl Default for CrawlLimits {
    fn default() -> Self {
        Self {
            max_requests_per_run: 256,
            global_active: 4,
            per_origin_active: 2,
            max_wire_bytes_per_run: MAX_CRAWL_WIRE_BYTES,
            max_decompressed_bytes_per_run: MAX_CRAWL_DECODED_BYTES,
            max_runtime: Duration::from_secs(60),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_retries: 3,
            page_redirects: 10,
        }
    }
}

impl CrawlLimits {
    fn validate(&self) -> Result<(), CrawlError> {
        if self.max_requests_per_run == 0
            || self.max_requests_per_run > 10_000
            || self.global_active == 0
            || self.global_active > 16
            || self.per_origin_active == 0
            || self.per_origin_active > 8
            || self.max_wire_bytes_per_run < MAX_COMPRESSED_RESPONSE_BYTES
            || self.max_wire_bytes_per_run > MAX_CRAWL_WIRE_BYTES
            || self.max_decompressed_bytes_per_run < MAX_DECODED_RESPONSE_BYTES
            || self.max_decompressed_bytes_per_run > MAX_CRAWL_DECODED_BYTES
            || self.max_runtime.is_zero()
            || self.max_runtime > Duration::from_secs(60 * 60)
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(30)
            || self.max_retries > 12
            || self.page_redirects > 10
        {
            return Err(CrawlError::Policy(
                "crawl limits are outside hard bounds".to_owned(),
            ));
        }
        Ok(())
    }

    fn bounded_public(
        request_count: usize,
        max_wire_bytes: usize,
        max_decoded_bytes: usize,
    ) -> Result<Self, CrawlError> {
        if request_count == 0 || request_count > 12 {
            return Err(CrawlError::Policy(
                "public request budget must be between 1 and 12".to_owned(),
            ));
        }
        let limits = Self {
            max_requests_per_run: request_count,
            global_active: 2,
            per_origin_active: 1,
            max_wire_bytes_per_run: max_wire_bytes,
            max_decompressed_bytes_per_run: max_decoded_bytes,
            max_runtime: Duration::from_secs(60),
            request_timeout: Duration::from_secs(5),
            max_retries: 1,
            page_redirects: 5,
        };
        limits.validate()?;
        Ok(limits)
    }
}

pub(crate) trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

#[derive(Clone, Default)]
pub(crate) struct CrawlCancellation(Arc<AtomicBool>);

impl CrawlCancellation {
    pub(crate) fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CrawlReport {
    pub requests: usize,
    pub pages_fetched: usize,
    pub indexed: usize,
    pub tombstoned: usize,
    pub retries: usize,
    pub disallowed: usize,
    pub duplicate_urls: usize,
    pub link_discovery: LinkDiscoveryCounts,
    pub failed_pages: usize,
    pub skipped_reasons: BTreeMap<String, usize>,
    pub failure_reasons: Vec<String>,
    pub transport_failures: usize,
    pub outbox_replays: usize,
    pub rejected_intents: usize,
    pub max_active: usize,
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    pub network_evidence: Vec<DestinationEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundedStopReason {
    FrontierIdle,
    RequestBudget,
    ByteBudget,
    RuntimeBudget,
    SourceBudget,
    SourceDeadline,
    NoProgress,
}

impl BoundedStopReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::FrontierIdle => "frontier_idle",
            Self::RequestBudget => "request_budget",
            Self::ByteBudget => "byte_budget",
            Self::RuntimeBudget => "runtime_budget",
            Self::SourceBudget => "source_budget",
            Self::SourceDeadline => "source_deadline",
            Self::NoProgress => "no_progress",
        }
    }

    pub(crate) fn bounded_run_finished(self) -> bool {
        self == Self::FrontierIdle
    }
}

pub(crate) struct BoundedCrawlResult {
    pub report: CrawlReport,
    pub stop_reason: BoundedStopReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchEligibility {
    At(u64),
    SourceBudget,
    SourceDeadline,
    Idle,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkDiscoveryCounts {
    pub enqueued: usize,
    pub source_denied: usize,
    pub duplicates: usize,
    pub malformed: usize,
    pub capacity: usize,
}

impl LinkDiscoveryCounts {
    fn merge(&mut self, next: Self) {
        self.enqueued = self.enqueued.saturating_add(next.enqueued);
        self.source_denied = self.source_denied.saturating_add(next.source_denied);
        self.duplicates = self.duplicates.saturating_add(next.duplicates);
        self.malformed = self.malformed.saturating_add(next.malformed);
        self.capacity = self.capacity.saturating_add(next.capacity);
    }

    pub(crate) fn candidates(&self) -> usize {
        self.enqueued
            .saturating_add(self.source_denied)
            .saturating_add(self.duplicates)
            .saturating_add(self.malformed)
            .saturating_add(self.capacity)
    }
}

impl CrawlReport {
    fn merge(&mut self, mut next: Self) {
        self.requests = self.requests.saturating_add(next.requests);
        self.pages_fetched = self.pages_fetched.saturating_add(next.pages_fetched);
        self.indexed = self.indexed.saturating_add(next.indexed);
        self.tombstoned = self.tombstoned.saturating_add(next.tombstoned);
        self.retries = self.retries.saturating_add(next.retries);
        self.disallowed = self.disallowed.saturating_add(next.disallowed);
        self.duplicate_urls = self.duplicate_urls.saturating_add(next.duplicate_urls);
        self.link_discovery.merge(next.link_discovery);
        self.failed_pages = self.failed_pages.saturating_add(next.failed_pages);
        for (reason, count) in next.skipped_reasons {
            if self.skipped_reasons.contains_key(&reason) || self.skipped_reasons.len() < 32 {
                *self.skipped_reasons.entry(reason).or_default() += count;
            }
        }
        self.failure_reasons.append(&mut next.failure_reasons);
        self.failure_reasons.truncate(64);
        self.transport_failures = self
            .transport_failures
            .saturating_add(next.transport_failures);
        self.outbox_replays = self.outbox_replays.saturating_add(next.outbox_replays);
        self.rejected_intents = self.rejected_intents.saturating_add(next.rejected_intents);
        self.max_active = self.max_active.max(next.max_active);
        self.compressed_bytes = self.compressed_bytes.saturating_add(next.compressed_bytes);
        self.decompressed_bytes = self
            .decompressed_bytes
            .saturating_add(next.decompressed_bytes);
        let available_evidence = 10_000usize.saturating_sub(self.network_evidence.len());
        self.network_evidence
            .extend(next.network_evidence.into_iter().take(available_evidence));
    }

    fn skipped(&mut self, reason: impl Into<String>) {
        self.disallowed = self.disallowed.saturating_add(1);
        let reason = reason.into();
        if self.skipped_reasons.contains_key(&reason) || self.skipped_reasons.len() < 32 {
            *self.skipped_reasons.entry(reason).or_default() += 1;
        }
    }

    fn failure(&mut self, reason: &str) {
        if self.failure_reasons.len() >= 64 {
            return;
        }
        let bounded = reason.chars().take(512).collect::<String>();
        if !bounded.is_empty() {
            self.failure_reasons.push(bounded);
        }
    }
}

#[derive(Clone)]
struct RobotCache {
    body: Vec<u8>,
    expires_ms: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Clone)]
struct Completion {
    state: String,
    reason: String,
    links: Vec<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    next_due_ms: Option<u64>,
}

#[derive(Clone)]
struct PendingOutbox {
    id: i64,
    key: UrlKey,
    source_id: String,
    lease_token: Vec<u8>,
    kind: i64,
    effective_url: Option<String>,
    title: Option<String>,
    body: Option<String>,
    completion: Completion,
}

struct FrontierDb {
    conn: Connection,
}

impl FrontierDb {
    fn open(path: &Path, store_identity: [u8; 16]) -> Result<Self, CrawlError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(CrawlError::Policy(
                    "frontier path must be a regular file, not a symlink".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                }
                #[cfg(not(unix))]
                {
                    OpenOptions::new().write(true).create_new(true).open(path)?;
                }
            }
            Err(error) => return Err(CrawlError::Io(error)),
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(2))?;
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        conn.pragma_update(None, "max_page_count", MAX_SQLITE_PAGES)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS source_policy (
                source_id TEXT PRIMARY KEY,
                origins TEXT NOT NULL,
                paths TEXT NOT NULL,
                valid_until_ms INTEGER NOT NULL,
                rights_basis TEXT NOT NULL,
                crawl_contact TEXT NOT NULL,
                retention_until_ms INTEGER NOT NULL,
                max_requests INTEGER NOT NULL,
                min_origin_delay_ms INTEGER NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','revoked','readmitting'))
            );
            CREATE TABLE IF NOT EXISTS frontier (
                url_key TEXT PRIMARY KEY,
                source_id TEXT NOT NULL REFERENCES source_policy(source_id),
                fetch_url TEXT NOT NULL,
                state TEXT NOT NULL,
                due_ms INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                not_found_count INTEGER NOT NULL DEFAULT 0,
                etag TEXT,
                last_modified TEXT,
                schedule_id INTEGER,
                redirect_count INTEGER NOT NULL DEFAULT 0,
                redirect_seen TEXT NOT NULL,
                unconditional INTEGER NOT NULL DEFAULT 0,
                lease_token BLOB,
                reason TEXT NOT NULL DEFAULT '',
                revocation_published INTEGER NOT NULL DEFAULT 0,
                readmitted INTEGER NOT NULL DEFAULT 0,
                queued_sequence INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS frontier_due_origin
                ON frontier(state, due_ms, fetch_url, queued_sequence);
            CREATE INDEX IF NOT EXISTS frontier_source
                ON frontier(source_id, state);
            CREATE TABLE IF NOT EXISTS robots_cache (
                origin TEXT PRIMARY KEY,
                body BLOB,
                expires_ms INTEGER NOT NULL,
                denied_retry_ms INTEGER NOT NULL DEFAULT 0,
                etag TEXT,
                last_modified TEXT,
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS origin_state (
                origin TEXT PRIMARY KEY,
                next_request_ms INTEGER NOT NULL DEFAULT 0,
                backoff_until_ms INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS robots_inflight (
                candidate_key TEXT PRIMARY KEY REFERENCES frontier(url_key) ON DELETE CASCADE,
                origins TEXT NOT NULL,
                min_origin_delay_ms INTEGER NOT NULL CHECK(min_origin_delay_ms >= 0)
            );
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_key TEXT NOT NULL,
                source_id TEXT NOT NULL,
                lease_token BLOB NOT NULL,
                kind INTEGER NOT NULL,
                effective_url TEXT,
                title TEXT,
                body TEXT,
                links TEXT NOT NULL DEFAULT '',
                etag TEXT,
                last_modified TEXT,
                completion_due_ms INTEGER,
                completion_state TEXT NOT NULL,
                completion_reason TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK(status IN ('pending','applied','rejected')),
                error TEXT NOT NULL DEFAULT '',
                created_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(status, id);
            CREATE TABLE IF NOT EXISTS crawl_event (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_ms INTEGER NOT NULL,
                source_id TEXT NOT NULL,
                url_key TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS frontier_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            PRAGMA user_version=5;",
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO frontier_meta(key,value) VALUES ('index_store_id',?1)",
            [store_identity.as_slice()],
        )?;
        let stored_identity: Vec<u8> = conn.query_row(
            "SELECT value FROM frontier_meta WHERE key='index_store_id'",
            [],
            |row| row.get(0),
        )?;
        if stored_identity.as_slice() != store_identity {
            return Err(CrawlError::Policy(
                "frontier database belongs to a different index store".to_owned(),
            ));
        }
        Ok(Self { conn })
    }

    fn transaction(&mut self) -> Result<Transaction<'_>, CrawlError> {
        Ok(self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    fn event(
        tx: &Transaction<'_>,
        now_ms: u64,
        source_id: &str,
        key: Option<&str>,
        state: &str,
        reason: &str,
    ) -> Result<(), CrawlError> {
        let event_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM crawl_event", [], |row| row.get(0))?;
        if event_count as usize >= MAX_EVENT_ROWS {
            tx.execute(
                "DELETE FROM crawl_event WHERE sequence=(SELECT sequence FROM crawl_event ORDER BY sequence LIMIT 1)",
                [],
            )?;
        }
        tx.execute(
            "INSERT INTO crawl_event(occurred_ms,source_id,url_key,state,reason) VALUES (?1,?2,?3,?4,?5)",
            params![now_ms as i64, source_id, key.unwrap_or(""), state, reason.chars().take(256).collect::<String>()],
        )?;
        Ok(())
    }

    fn source(&self, source_id: &str) -> Result<(SourcePolicy, String, u64), CrawlError> {
        self.conn
            .query_row(
                "SELECT origins,paths,valid_until_ms,rights_basis,crawl_contact,retention_until_ms,max_requests,min_origin_delay_ms,lifecycle,request_count FROM source_policy WHERE source_id=?1",
                [source_id],
                |row| {
                    let policy = SourcePolicy::from_db(
                        source_id.to_owned(),
                        StoredPolicyFields {
                            origins: row.get(0)?,
                            paths: row.get(1)?,
                            valid_until_ms: row.get(2)?,
                            rights_basis: row.get(3)?,
                            crawl_contact: row.get(4)?,
                            retention_until_ms: row.get(5)?,
                            max_requests: row.get(6)?,
                            min_origin_delay_ms: row.get(7)?,
                        },
                    )
                    .map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?;
                    Ok((policy, row.get(8)?, row.get::<_, i64>(9)? as u64))
                },
            )
            .optional()?
            .ok_or_else(|| CrawlError::Policy("source policy is missing".to_owned()))
    }
}

fn frontier_absolute_path(path: &Path) -> Result<PathBuf, CrawlError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| CrawlError::Policy("frontier path has no filename".to_owned()))?;
    Ok(parent.join(name))
}

fn acquire_frontier_owner(path: &Path) -> Result<File, CrawlError> {
    let mut lock_path = frontier_absolute_path(path)?.into_os_string();
    lock_path.push(".owner.lock");
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(PathBuf::from(lock_path))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(CrawlError::Policy(
                    "frontier already has a live coordinator".to_owned(),
                ));
            }
            return Err(CrawlError::Io(error));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = lock_path;
        Err(CrawlError::Policy(
            "frontier ownership locks require a Unix host".to_owned(),
        ))
    }
}

fn validate_frontier_store(path: &Path, index: &PersistentIndex) -> Result<(), CrawlError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CrawlError::Policy(
            "frontier path must be a regular file, not a symlink".to_owned(),
        ));
    }
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let table_exists = |table: &str| -> Result<bool, CrawlError> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?)
    };
    if table_exists("frontier_meta")? {
        let identity: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM frontier_meta WHERE key='index_store_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if identity.is_some_and(|identity| identity.as_slice() != index.store_identity()) {
            return Err(CrawlError::Policy(
                "frontier database belongs to a different index store".to_owned(),
            ));
        }
    } else {
        for table in ["outbox", "frontier"] {
            if !table_exists(table)? {
                continue;
            }
            let sql =
                format!("SELECT lease_token FROM {table} WHERE lease_token IS NOT NULL LIMIT 1");
            let token: Option<Vec<u8>> = conn.query_row(&sql, [], |row| row.get(0)).optional()?;
            if let Some(token) = token
                && index.restore_lease(&token).is_err()
            {
                return Err(CrawlError::Policy(
                    "frontier lease belongs to a different index store".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct PageJob {
    key: UrlKey,
    source: SourcePolicy,
    url: Url,
    lease_token: Vec<u8>,
    schedule_id: u64,
    redirect_count: usize,
    redirect_seen: String,
    unconditional: bool,
    etag: Option<String>,
    last_modified: Option<String>,
    attempt: u16,
}

#[derive(Clone)]
struct RobotsJob {
    candidate_key: UrlKey,
    origin: String,
    source: SourcePolicy,
    cached: Option<RobotCache>,
    request_budget: usize,
}

enum WorkerJob {
    Page(PageJob),
    Robots(RobotsJob),
}

enum WorkerResult {
    Page {
        job: PageJob,
        result: Result<HttpResponse, SafeFetchError>,
    },
    Robots {
        job: RobotsJob,
        result: Result<RobotsWorkerSuccess, RobotsWorkerFailure>,
    },
}

struct WorkerDrain {
    cancellation: CrawlCancellation,
    handles: Vec<thread::JoinHandle<()>>,
    active: usize,
}

impl WorkerDrain {
    fn new(cancellation: &CrawlCancellation) -> Self {
        Self {
            cancellation: cancellation.clone(),
            handles: Vec::new(),
            active: 0,
        }
    }

    fn track(&mut self, handle: thread::JoinHandle<()>) {
        self.handles.push(handle);
        self.active += 1;
    }

    fn result_received(&mut self) {
        self.active = self.active.saturating_sub(1);
    }

    fn reap_finished(&mut self) {
        let mut index = self.handles.len();
        while index > 0 {
            index -= 1;
            if self.handles[index].is_finished() {
                let handle = self.handles.swap_remove(index);
                let _ = handle.join();
            }
        }
    }
}

impl Drop for WorkerDrain {
    fn drop(&mut self) {
        if self.active > 0 {
            self.cancellation.cancel();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

struct RobotsWorkerSuccess {
    body: Vec<u8>,
    response_headers: HeaderMap,
    requests: usize,
    wire_bytes: usize,
    decoded_bytes: usize,
    no_store: bool,
    visited_origins: Vec<String>,
}

struct RobotsWorkerFailure {
    reason: String,
    requests: usize,
    retry_after_ms: Option<u64>,
    wire_bytes: usize,
    decoded_bytes: usize,
    visited_origins: Vec<String>,
}

fn execute_worker_job<R: DestinationResolver + 'static, C: Clock + 'static>(
    job: WorkerJob,
    fetcher: Arc<SafeFetcher<R>>,
    limiter: Arc<OriginLimiter>,
    per_origin_active: usize,
    cancel: &CrawlCancellation,
    clock: Arc<C>,
) -> WorkerResult {
    match job {
        WorkerJob::Page(job) => {
            let origin = origin_of_url(&job.url);
            let delay = Duration::from_millis(job.source.min_origin_delay_ms.min(MAX_RETRY_MS));
            let result = limiter
                .acquire(&origin, per_origin_active, delay, cancel)
                .and_then(|_permit| {
                    if cancel.is_cancelled() {
                        return Err(SafeFetchError::Request("crawl cancelled".to_owned()));
                    }
                    if !job.source.allows_url(&job.url, clock.now_ms()) {
                        return Err(SafeFetchError::Request(
                            "source policy expired before the page request".to_owned(),
                        ));
                    }
                    let mut headers = HeaderMap::new();
                    if !job.unconditional {
                        insert_header(&mut headers, IF_NONE_MATCH, job.etag.as_deref())
                            .map_err(|error| SafeFetchError::Request(error.to_string()))?;
                        insert_header(
                            &mut headers,
                            IF_MODIFIED_SINCE,
                            job.last_modified.as_deref(),
                        )
                        .map_err(|error| SafeFetchError::Request(error.to_string()))?;
                    }
                    fetcher.fetch_with_headers(&job.url, &headers)
                });
            WorkerResult::Page { job, result }
        }
        WorkerJob::Robots(job) => {
            let result = fetch_robots_worker(
                &job,
                &fetcher,
                &limiter,
                per_origin_active,
                cancel,
                clock.as_ref(),
            );
            WorkerResult::Robots { job, result }
        }
    }
}

fn fetch_robots_worker<R: DestinationResolver + 'static, C: Clock>(
    job: &RobotsJob,
    fetcher: &SafeFetcher<R>,
    limiter: &Arc<OriginLimiter>,
    per_origin_active: usize,
    cancel: &CrawlCancellation,
    clock: &C,
) -> Result<RobotsWorkerSuccess, RobotsWorkerFailure> {
    let mut current = Url::parse(&format!("{}/robots.txt", job.origin))
        .map_err(|error| robot_failure(error.to_string(), 0, None, 0, 0, Vec::new()))?;
    let mut requests = 0usize;
    let mut wire_bytes = 0usize;
    let mut decoded_bytes = 0usize;
    let mut redirects = 0usize;
    let mut conditional_sent = false;
    let mut unconditional_retried = false;
    let mut visited_origins = Vec::new();

    loop {
        if cancel.is_cancelled() {
            return Err(robot_failure(
                "crawl cancelled".to_owned(),
                requests,
                None,
                wire_bytes,
                decoded_bytes,
                visited_origins,
            ));
        }
        if requests >= job.request_budget {
            return Err(robot_failure(
                "robots request budget exhausted".to_owned(),
                requests,
                None,
                wire_bytes,
                decoded_bytes,
                visited_origins,
            ));
        }
        let source_allows = if redirects == 0 && origin_of_url(&current) == job.origin {
            job.source.allows_origin_url(&current, clock.now_ms())
        } else {
            job.source.allows_url(&current, clock.now_ms())
        };
        if !source_allows || !fetcher.has_capability(&current) {
            return Err(robot_failure(
                "robots redirect is outside admitted source scope".to_owned(),
                requests,
                None,
                wire_bytes,
                decoded_bytes,
                visited_origins,
            ));
        }
        let origin = origin_of_url(&current);
        let delay = Duration::from_millis(job.source.min_origin_delay_ms.min(MAX_RETRY_MS));
        let permit = limiter
            .acquire(&origin, per_origin_active, delay, cancel)
            .map_err(|error| {
                robot_failure(
                    error.to_string(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins.clone(),
                )
            })?;
        let mut headers = HeaderMap::new();
        if redirects == 0
            && !conditional_sent
            && let Some(cache) = &job.cached
        {
            insert_header(&mut headers, IF_NONE_MATCH, cache.etag.as_deref()).map_err(|error| {
                robot_failure(
                    error.to_string(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins.clone(),
                )
            })?;
            insert_header(
                &mut headers,
                IF_MODIFIED_SINCE,
                cache.last_modified.as_deref(),
            )
            .map_err(|error| {
                robot_failure(
                    error.to_string(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins.clone(),
                )
            })?;
            conditional_sent = cache.etag.is_some() || cache.last_modified.is_some();
        }
        let response = fetcher.fetch_with_headers(&current, &headers);
        drop(permit);
        requests += 1;
        visited_origins.push(origin);
        let response = response.map_err(|error| {
            robot_failure(
                error.to_string(),
                requests,
                None,
                wire_bytes,
                decoded_bytes,
                visited_origins.clone(),
            )
        })?;
        wire_bytes = wire_bytes.saturating_add(response.wire_bytes);
        decoded_bytes = decoded_bytes.saturating_add(response.decoded_bytes);

        if response.status == 304 {
            if let Some(cache) = &job.cached {
                let no_store = has_cache_control_directive(&response.headers, "no-store");
                return Ok(RobotsWorkerSuccess {
                    body: cache.body.clone(),
                    response_headers: response.headers,
                    requests,
                    wire_bytes,
                    decoded_bytes,
                    no_store,
                    visited_origins,
                });
            }
            if unconditional_retried || requests >= job.request_budget {
                return Err(robot_failure(
                    "robots 304 had no stored representation".to_owned(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins,
                ));
            }
            unconditional_retried = true;
            conditional_sent = true;
            continue;
        }
        if is_redirect(response.status) {
            if redirects >= MAX_ROBOTS_REDIRECTS {
                return Err(robot_failure(
                    "robots redirect limit exceeded".to_owned(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins,
                ));
            }
            let location = response
                .location()
                .map_err(|error| {
                    robot_failure(
                        error.to_string(),
                        requests,
                        None,
                        wire_bytes,
                        decoded_bytes,
                        visited_origins.clone(),
                    )
                })?
                .ok_or_else(|| {
                    robot_failure(
                        "robots redirect has no Location".to_owned(),
                        requests,
                        None,
                        wire_bytes,
                        decoded_bytes,
                        visited_origins.clone(),
                    )
                })?;
            let target_key = UrlKey::resolve(&current, location).map_err(|error| {
                robot_failure(
                    error.to_string(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins.clone(),
                )
            })?;
            let target = target_key.to_url().map_err(|error| {
                robot_failure(
                    error.to_string(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins.clone(),
                )
            })?;
            if !job.source.allows_url(&target, clock.now_ms()) || !fetcher.has_capability(&target) {
                return Err(robot_failure(
                    "robots redirect target is unadmitted or unsafe".to_owned(),
                    requests,
                    None,
                    wire_bytes,
                    decoded_bytes,
                    visited_origins,
                ));
            }
            current = target;
            redirects += 1;
            continue;
        }
        if !(200..300).contains(&response.status) {
            return Err(robot_failure(
                format!("robots HTTP status {} denies this origin", response.status),
                requests,
                retry_after_at(&response.headers, clock.now_ms()),
                wire_bytes,
                decoded_bytes,
                visited_origins,
            ));
        }
        let no_store = response.header_values("cache-control").any(|value| {
            value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case("no-store"))
        });
        let body = match response.body {
            Ok(body) => body,
            Err(error) => {
                return Err(robot_failure(
                    error.to_string(),
                    requests,
                    retry_after_at(&response.headers, clock.now_ms()),
                    wire_bytes,
                    decoded_bytes,
                    visited_origins,
                ));
            }
        };
        if body.len() > MAX_ROBOTS_BYTES {
            return Err(robot_failure(
                "robots body exceeded parser bound".to_owned(),
                requests,
                None,
                wire_bytes,
                decoded_bytes,
                visited_origins,
            ));
        }
        return Ok(RobotsWorkerSuccess {
            body,
            response_headers: response.headers,
            requests,
            wire_bytes,
            decoded_bytes,
            no_store,
            visited_origins,
        });
    }
}

fn robot_failure(
    reason: String,
    requests: usize,
    retry_after_ms: Option<u64>,
    wire_bytes: usize,
    decoded_bytes: usize,
    visited_origins: Vec<String>,
) -> RobotsWorkerFailure {
    RobotsWorkerFailure {
        reason,
        requests,
        retry_after_ms,
        wire_bytes,
        decoded_bytes,
        visited_origins,
    }
}

#[derive(Default)]
struct OriginActivity {
    active: usize,
    active_with_delay: usize,
    quiet_until: Option<Instant>,
}

#[derive(Default)]
struct OriginLimiter {
    activity: Mutex<HashMap<String, OriginActivity>>,
    changed: Condvar,
}

struct OriginPermit {
    limiter: Arc<OriginLimiter>,
    origin: String,
    min_delay: Duration,
}

impl OriginLimiter {
    fn acquire(
        self: &Arc<Self>,
        origin: &str,
        per_origin_active: usize,
        min_delay: Duration,
        cancel: &CrawlCancellation,
    ) -> Result<OriginPermit, SafeFetchError> {
        let mut activity = self
            .activity
            .lock()
            .map_err(|_| SafeFetchError::Request("origin limiter poisoned".to_owned()))?;
        loop {
            if cancel.is_cancelled() {
                return Err(SafeFetchError::Request("crawl cancelled".to_owned()));
            }
            let state = activity.entry(origin.to_owned()).or_default();
            let now = Instant::now();
            let delay = state
                .quiet_until
                .map_or(Duration::ZERO, |next| next.saturating_duration_since(now));
            let spacing_active = !min_delay.is_zero() || state.active_with_delay > 0;
            let active_slot = if spacing_active {
                state.active == 0
            } else {
                state.active < per_origin_active
            };
            if active_slot && delay.is_zero() {
                state.active += 1;
                state.active_with_delay += usize::from(!min_delay.is_zero());
                return Ok(OriginPermit {
                    limiter: Arc::clone(self),
                    origin: origin.to_owned(),
                    min_delay,
                });
            }
            let wait_for = if delay.is_zero() {
                Duration::from_millis(25)
            } else {
                delay.min(Duration::from_millis(25))
            };
            let (next, _) = self
                .changed
                .wait_timeout(activity, wait_for)
                .map_err(|_| SafeFetchError::Request("origin limiter poisoned".to_owned()))?;
            activity = next;
        }
    }
}

impl Drop for OriginPermit {
    fn drop(&mut self) {
        if let Ok(mut activity) = self.limiter.activity.lock() {
            if let Some(state) = activity.get_mut(&self.origin) {
                state.active = state.active.saturating_sub(1);
                if !self.min_delay.is_zero() {
                    state.active_with_delay = state.active_with_delay.saturating_sub(1);
                    let quiet_until = Instant::now() + self.min_delay;
                    state.quiet_until = Some(
                        state
                            .quiet_until
                            .map_or(quiet_until, |existing| existing.max(quiet_until)),
                    );
                }
            }
            self.limiter.changed.notify_all();
        }
    }
}

pub(crate) struct ControlledCrawler<R, C> {
    _owner_lock: File,
    db: FrontierDb,
    index: Arc<PersistentIndex>,
    fetcher: Arc<SafeFetcher<R>>,
    clock: Arc<C>,
    limits: CrawlLimits,
    limiter: Arc<OriginLimiter>,
    one_shot_robots: HashMap<UrlKey, RobotCache>,
    last_origin: String,
    pending_replay_count: usize,
    pending_rejected_count: usize,
    pending_link_discovery: LinkDiscoveryCounts,
    pending_failed_pages: usize,
    pending_failure_reasons: Vec<String>,
}

impl<R, C> ControlledCrawler<R, C>
where
    R: DestinationResolver + 'static,
    C: Clock + 'static,
{
    #[cfg(test)]
    pub(crate) fn open(
        path: &Path,
        index: Arc<PersistentIndex>,
        resolver: R,
        capabilities: Vec<FixtureCapability>,
        limits: CrawlLimits,
        clock: C,
    ) -> Result<Self, CrawlError> {
        Self::open_with_public(
            path,
            index,
            resolver,
            capabilities,
            Vec::new(),
            limits,
            clock,
        )
    }

    pub(crate) fn open_with_public(
        path: &Path,
        index: Arc<PersistentIndex>,
        resolver: R,
        capabilities: Vec<FixtureCapability>,
        public_authorities: Vec<PublicAuthority>,
        limits: CrawlLimits,
        clock: C,
    ) -> Result<Self, CrawlError> {
        limits.validate()?;
        let owner_lock = acquire_frontier_owner(path)?;
        validate_frontier_store(path, &index)?;
        let fetcher = Arc::new(
            SafeFetcher::new_with_public(resolver, capabilities, public_authorities)
                .with_timeout(limits.request_timeout),
        );
        let db = FrontierDb::open(path, index.store_identity())?;
        let mut crawler = Self {
            _owner_lock: owner_lock,
            db,
            index,
            fetcher,
            clock: Arc::new(clock),
            limits,
            limiter: Arc::new(OriginLimiter::default()),
            one_shot_robots: HashMap::new(),
            last_origin: String::new(),
            pending_replay_count: 0,
            pending_rejected_count: 0,
            pending_link_discovery: LinkDiscoveryCounts::default(),
            pending_failed_pages: 0,
            pending_failure_reasons: Vec::new(),
        };
        crawler.recover_abandoned_fetches()?;
        crawler.expire_due_sources()?;
        crawler.reconcile_controls()?;
        Ok(crawler)
    }

    pub(crate) fn open_system(
        path: &Path,
        index: Arc<PersistentIndex>,
        capabilities: Vec<FixtureCapability>,
        limits: CrawlLimits,
    ) -> Result<ControlledCrawler<SystemResolver, SystemClock>, CrawlError> {
        ControlledCrawler::<SystemResolver, SystemClock>::open_system_with_public(
            path,
            index,
            capabilities,
            Vec::new(),
            limits,
        )
    }

    pub(crate) fn open_system_with_public(
        path: &Path,
        index: Arc<PersistentIndex>,
        capabilities: Vec<FixtureCapability>,
        public_authorities: Vec<PublicAuthority>,
        limits: CrawlLimits,
    ) -> Result<ControlledCrawler<SystemResolver, SystemClock>, CrawlError> {
        ControlledCrawler::open_with_public(
            path,
            index,
            SystemResolver,
            capabilities,
            public_authorities,
            limits,
            SystemClock,
        )
    }

    pub(crate) fn admit_source(
        &mut self,
        policy: SourcePolicy,
        seeds: &[UrlKey],
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        policy.validate(now, &self.fetcher)?;
        if seeds.is_empty() {
            return Err(CrawlError::Policy(
                "at least one seed is required".to_owned(),
            ));
        }
        let (origins, paths, valid_until, rights, contact, retention, max_requests, delay) =
            policy.to_db_fields();
        let tx = self.db.transaction()?;
        let existing = tx
            .query_row(
                "SELECT origins,paths,valid_until_ms,rights_basis,crawl_contact,retention_until_ms,max_requests,min_origin_delay_ms,lifecycle FROM source_policy WHERE source_id=?1",
                [&policy.id],
                |row| {
                    let stored = SourcePolicy::from_db(
                        policy.id.clone(),
                        StoredPolicyFields {
                            origins: row.get(0)?,
                            paths: row.get(1)?,
                            valid_until_ms: row.get(2)?,
                            rights_basis: row.get(3)?,
                            crawl_contact: row.get(4)?,
                            retention_until_ms: row.get(5)?,
                            max_requests: row.get(6)?,
                            min_origin_delay_ms: row.get(7)?,
                        },
                    )
                    .map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok((stored, row.get::<_, String>(8)?))
                },
            )
            .optional()?;
        let is_existing_source = if let Some((stored, lifecycle)) = existing {
            if lifecycle != "active" || !stored.same_admission_except_retention_deadline(&policy) {
                return Err(CrawlError::Policy(
                    "source ID already has a different or inactive policy; revoke and explicitly readmit it"
                        .to_owned(),
                ));
            }
            true
        } else {
            false
        };
        let existing_origins: String = tx.query_row(
            "SELECT COALESCE(group_concat(origins,char(10)),'') FROM source_policy",
            [],
            |row| row.get(0),
        )?;
        let unique_origins: HashSet<String> = existing_origins
            .lines()
            .chain(policy.allowed_origins.iter().map(String::as_str))
            .map(str::to_owned)
            .collect();
        if unique_origins.len() > MAX_ORIGINS {
            return Err(CrawlError::Capacity("frontier origin count"));
        }
        let frontier_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM frontier", [], |row| row.get(0))?;
        let mut new_seeds = Vec::new();
        for seed in seeds {
            let url =
                Url::parse(seed.as_str()).map_err(|error| CrawlError::Url(error.to_string()))?;
            if !policy.allows_url(&url, now) || !self.fetcher.has_capability(&url) {
                return Err(CrawlError::Policy(format!(
                    "seed is outside admitted source scope: {seed}"
                )));
            }
            let existing_owner: Option<String> = tx
                .query_row(
                    "SELECT source_id FROM frontier WHERE url_key=?1",
                    [seed.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            match existing_owner {
                Some(owner) if owner == policy.id => {}
                Some(_) => {
                    return Err(CrawlError::Policy(format!(
                        "seed is already owned by another source policy: {seed}"
                    )));
                }
                None => new_seeds.push(seed),
            }
        }
        if (frontier_count as usize).saturating_add(new_seeds.len()) > MAX_FRONTIER_ENTRIES {
            return Err(CrawlError::Capacity("frontier URL count"));
        }
        if !is_existing_source {
            tx.execute(
                "INSERT INTO source_policy(source_id,origins,paths,valid_until_ms,rights_basis,crawl_contact,retention_until_ms,max_requests,min_origin_delay_ms,lifecycle) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'active')",
                params![policy.id, origins, paths, valid_until, rights, contact, retention, max_requests, delay],
            )?;
        }
        for seed in new_seeds {
            tx.execute(
                "INSERT INTO frontier(url_key,source_id,fetch_url,state,due_ms,redirect_seen,queued_sequence) VALUES (?1,?2,?1,'ready',?3,?1,?4)",
                params![seed.as_str(), policy.id, now as i64, now as i64],
            )?;
            FrontierDb::event(
                &tx,
                now,
                &policy.id,
                Some(seed.as_str()),
                "candidate",
                "explicitly admitted seed",
            )?;
        }
        if !is_existing_source {
            FrontierDb::event(
                &tx,
                now,
                &policy.id,
                None,
                "admitted",
                "explicit source policy",
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn enqueue_seed(&mut self, source_id: &str, seed: UrlKey) -> Result<(), CrawlError> {
        let (policy, lifecycle, _) = self.db.source(source_id)?;
        if lifecycle != "active" {
            return Err(CrawlError::Policy(
                "source is not actively admitted".to_owned(),
            ));
        }
        let now = self.clock.now_ms();
        let url = Url::parse(seed.as_str()).map_err(|error| CrawlError::Url(error.to_string()))?;
        if !policy.allows_url(&url, now) || !self.fetcher.has_capability(&url) {
            return Err(CrawlError::Policy(
                "seed is outside admitted fixture scope".to_owned(),
            ));
        }
        let tx = self.db.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM frontier", [], |row| row.get(0))?;
        if count as usize >= MAX_FRONTIER_ENTRIES {
            return Err(CrawlError::Capacity("frontier URL count"));
        }
        tx.execute(
            "INSERT OR IGNORE INTO frontier(url_key,source_id,fetch_url,state,due_ms,redirect_seen,queued_sequence) VALUES (?1,?2,?1,'ready',?3,?1,?3)",
            params![seed.as_str(), source_id, now as i64],
        )?;
        FrontierDb::event(
            &tx,
            now,
            source_id,
            Some(seed.as_str()),
            "candidate",
            "explicit seed",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn revoke_source(&mut self, source_id: &str) -> Result<(), CrawlError> {
        self.mark_source_revoked(source_id, "explicit policy revocation")?;
        self.reconcile_controls()
    }

    fn mark_source_revoked(&mut self, source_id: &str, reason: &str) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        let changed = tx.execute(
            "UPDATE source_policy SET lifecycle='revoked' WHERE source_id=?1 AND lifecycle!='revoked'",
            [source_id],
        )?;
        if changed == 0 {
            let lifecycle: Option<String> = tx
                .query_row(
                    "SELECT lifecycle FROM source_policy WHERE source_id=?1",
                    [source_id],
                    |row| row.get(0),
                )
                .optional()?;
            if lifecycle.is_none() {
                return Err(CrawlError::Policy("source policy is missing".to_owned()));
            }
        }
        tx.execute(
            "UPDATE outbox SET status='rejected',error='source revoked before apply' WHERE source_id=?1 AND status='pending' AND kind=0",
            [source_id],
        )?;
        tx.execute(
            "UPDATE frontier SET state='blocked',reason='source revoked',lease_token=NULL,revocation_published=0,readmitted=0 WHERE source_id=?1",
            [source_id],
        )?;
        FrontierDb::event(&tx, now, source_id, None, "revoked", reason)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn readmit_source(&mut self, policy: SourcePolicy) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        policy.validate(now, &self.fetcher)?;
        let (_, lifecycle, _) = self.db.source(&policy.id)?;
        if lifecycle != "revoked" {
            return Err(CrawlError::Policy(
                "only a revoked source can be explicitly readmitted".to_owned(),
            ));
        }
        let fields = policy.to_db_fields();
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE source_policy SET origins=?2,paths=?3,valid_until_ms=?4,rights_basis=?5,crawl_contact=?6,retention_until_ms=?7,max_requests=?8,min_origin_delay_ms=?9,lifecycle='readmitting',request_count=0 WHERE source_id=?1",
            params![policy.id, fields.0, fields.1, fields.2, fields.3, fields.4, fields.5, fields.6, fields.7],
        )?;
        tx.execute(
            "UPDATE frontier SET state='blocked',reason='readmission awaiting index controls',readmitted=0 WHERE source_id=?1",
            [&policy.id],
        )?;
        FrontierDb::event(
            &tx,
            now,
            &policy.id,
            None,
            "readmitting",
            "explicit renewed fixture policy",
        )?;
        tx.commit()?;
        self.reconcile_controls()
    }

    pub(crate) fn run_until_idle(
        &mut self,
        cancellation: &CrawlCancellation,
    ) -> Result<CrawlReport, CrawlError> {
        self.fetcher.clear_network_evidence();
        self.pending_failed_pages = 0;
        self.pending_failure_reasons.clear();
        let started = self.clock.now_ms();
        let deadline = started.saturating_add(self.limits.max_runtime.as_millis() as u64);
        let mut report = CrawlReport {
            outbox_replays: self.pending_replay_count,
            rejected_intents: self.pending_rejected_count,
            ..CrawlReport::default()
        };
        self.pending_replay_count = 0;
        self.pending_rejected_count = 0;
        let mut reserved_requests = 0usize;
        let mut actual_requests = 0usize;
        let mut reserved_wire_bytes = 0usize;
        let mut reserved_decompressed_bytes = 0usize;
        let mut spent_wire_bytes = 0usize;
        let mut spent_decompressed_bytes = 0usize;
        let mut active_by_origin = HashMap::<String, usize>::new();
        let mut active_origins = HashSet::<String>::new();
        let (sender, receiver) = mpsc::channel::<WorkerResult>();
        let mut active = 0usize;
        let mut stop_dispatch = false;
        let mut runtime_expired = false;
        let mut byte_budget_exhausted = false;

        self.expire_due_sources()?;
        self.reconcile_controls()?;
        let mut workers = WorkerDrain::new(cancellation);

        loop {
            if self.clock.now_ms() >= deadline {
                runtime_expired = true;
                cancellation.cancel();
                stop_dispatch = true;
            } else if cancellation.is_cancelled() {
                stop_dispatch = true;
            }
            if !stop_dispatch {
                while active < self.limits.global_active
                    && actual_requests.saturating_add(reserved_requests)
                        < self.limits.max_requests_per_run
                {
                    let response_slots = response_request_slots(
                        self.limits
                            .max_wire_bytes_per_run
                            .saturating_sub(spent_wire_bytes)
                            .saturating_sub(reserved_wire_bytes),
                        self.limits
                            .max_decompressed_bytes_per_run
                            .saturating_sub(spent_decompressed_bytes)
                            .saturating_sub(reserved_decompressed_bytes),
                    );
                    if response_slots == 0 {
                        if active == 0 && !self.due_candidates(self.clock.now_ms())?.is_empty() {
                            byte_budget_exhausted = true;
                            stop_dispatch = true;
                        }
                        break;
                    }
                    let Some(job) = self.next_job(
                        &mut report,
                        actual_requests,
                        reserved_requests,
                        response_slots,
                        &active_by_origin,
                        &active_origins,
                    )?
                    else {
                        break;
                    };
                    let (origin, reserved) = match &job {
                        WorkerJob::Page(page) => (origin_of_url(&page.url), 1),
                        WorkerJob::Robots(robots) => (robots.origin.clone(), robots.request_budget),
                    };
                    reserved_requests = reserved_requests.saturating_add(reserved);
                    reserved_wire_bytes = reserved_wire_bytes
                        .saturating_add(reserved.saturating_mul(MAX_COMPRESSED_RESPONSE_BYTES));
                    reserved_decompressed_bytes = reserved_decompressed_bytes
                        .saturating_add(reserved.saturating_mul(MAX_DECODED_RESPONSE_BYTES));
                    *active_by_origin.entry(origin.clone()).or_default() += 1;
                    active_origins.insert(origin.clone());
                    active += 1;
                    report.max_active = report.max_active.max(active);
                    let fetcher = Arc::clone(&self.fetcher);
                    let limiter = Arc::clone(&self.limiter);
                    let sender = sender.clone();
                    let token = cancellation.clone();
                    let clock = Arc::clone(&self.clock);
                    let per_origin = self.limits.per_origin_active;
                    let worker = thread::Builder::new()
                        .name("ley-crawl-fetch".to_owned())
                        .spawn(move || {
                            let output = execute_worker_job(
                                job, fetcher, limiter, per_origin, &token, clock,
                            );
                            let _ = sender.send(output);
                        })?;
                    workers.track(worker);
                }
            }

            if active == 0 {
                if stop_dispatch && cancellation.is_cancelled() && !runtime_expired {
                    self.one_shot_robots.clear();
                    return Err(CrawlError::Cancelled);
                }
                if runtime_expired {
                    self.one_shot_robots.clear();
                    return Err(CrawlError::RuntimeLimit);
                }
                break;
            }

            let worker_result = receiver.recv_timeout(Duration::from_millis(20)).ok();
            if let Some(worker_result) = worker_result {
                workers.result_received();
                workers.reap_finished();
                active = active.saturating_sub(1);
                let (reserved, wire_charge, decompressed_charge) = match &worker_result {
                    WorkerResult::Page { job, .. } => {
                        let origin = origin_of_url(&job.url);
                        if let Some(value) = active_by_origin.get_mut(&origin) {
                            *value = value.saturating_sub(1);
                            if *value == 0 {
                                active_by_origin.remove(&origin);
                                active_origins.remove(&origin);
                            }
                        }
                        let (wire, decompressed) = match &worker_result {
                            WorkerResult::Page {
                                result: Ok(response),
                                ..
                            } => (response.wire_bytes, response.decoded_bytes),
                            WorkerResult::Page { result: Err(_), .. } => {
                                (MAX_COMPRESSED_RESPONSE_BYTES, MAX_DECODED_RESPONSE_BYTES)
                            }
                            WorkerResult::Robots { .. } => unreachable!(),
                        };
                        (1, wire, decompressed)
                    }
                    WorkerResult::Robots { job, .. } => {
                        let origin = job.origin.clone();
                        if let Some(value) = active_by_origin.get_mut(&origin) {
                            *value = value.saturating_sub(1);
                            if *value == 0 {
                                active_by_origin.remove(&origin);
                                active_origins.remove(&origin);
                            }
                        }
                        let (wire, decompressed) = match &worker_result {
                            WorkerResult::Robots {
                                result: Ok(result), ..
                            } => (result.wire_bytes, result.decoded_bytes),
                            WorkerResult::Robots {
                                result: Err(result),
                                ..
                            } => (
                                result
                                    .requests
                                    .saturating_mul(MAX_COMPRESSED_RESPONSE_BYTES),
                                result.requests.saturating_mul(MAX_DECODED_RESPONSE_BYTES),
                            ),
                            WorkerResult::Page { .. } => unreachable!(),
                        };
                        (job.request_budget, wire, decompressed)
                    }
                };
                let used = self.handle_worker_result(worker_result, &mut report)?;
                actual_requests = actual_requests.saturating_add(used);
                reserved_requests = reserved_requests.saturating_sub(reserved);
                reserved_wire_bytes = reserved_wire_bytes
                    .saturating_sub(reserved.saturating_mul(MAX_COMPRESSED_RESPONSE_BYTES));
                reserved_decompressed_bytes = reserved_decompressed_bytes
                    .saturating_sub(reserved.saturating_mul(MAX_DECODED_RESPONSE_BYTES));
                spent_wire_bytes = spent_wire_bytes.saturating_add(wire_charge);
                spent_decompressed_bytes =
                    spent_decompressed_bytes.saturating_add(decompressed_charge);
            }
            if stop_dispatch && active == 0 {
                break;
            }
        }

        report.requests = actual_requests;
        self.one_shot_robots.clear();
        self.expire_due_sources()?;
        self.reconcile_controls()?;
        report.outbox_replays = report
            .outbox_replays
            .saturating_add(self.pending_replay_count);
        self.pending_replay_count = 0;
        report.rejected_intents = report
            .rejected_intents
            .saturating_add(self.pending_rejected_count);
        self.pending_rejected_count = 0;
        report
            .link_discovery
            .merge(std::mem::take(&mut self.pending_link_discovery));
        report.failed_pages = self.pending_failed_pages;
        report
            .failure_reasons
            .append(&mut self.pending_failure_reasons);
        self.pending_failed_pages = 0;
        report.network_evidence = self.fetcher.take_network_evidence();
        if runtime_expired || self.clock.now_ms() >= deadline {
            Err(CrawlError::RuntimeLimit)
        } else if cancellation.is_cancelled() {
            Err(CrawlError::Cancelled)
        } else if byte_budget_exhausted {
            Err(CrawlError::Capacity("per-run response byte budget"))
        } else {
            Ok(report)
        }
    }
}

pub(crate) fn run_public_crawl(
    index_path: &Path,
    frontier_path: &Path,
    policy: &PublicCrawlPolicy,
    request_count: usize,
) -> Result<BoundedCrawlResult, CrawlError> {
    let now = SystemClock.now_ms();
    policy
        .validate_enabled(now)
        .map_err(|error: PublicPolicyError| CrawlError::Policy(error.to_string()))?;
    let (max_wire_bytes, max_decoded_bytes) = policy
        .sources()
        .iter()
        .map(PublicSourcePolicy::run_byte_limits)
        .reduce(|left, right| (left.0.min(right.0), left.1.min(right.1)))
        .ok_or_else(|| CrawlError::Policy("public source allowlist is empty".to_owned()))?;
    let limits = CrawlLimits::bounded_public(request_count, max_wire_bytes, max_decoded_bytes)?;
    let max_runtime = limits.max_runtime;
    let authorities = policy
        .sources()
        .iter()
        .map(|source| source.authority(policy.identity(), policy.contact()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CrawlError::Policy(error.to_string()))?;
    let index = match fs::symlink_metadata(index_path) {
        Ok(_) => Arc::new(PersistentIndex::open(index_path)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Arc::new(PersistentIndex::create(index_path)?)
        }
        Err(error) => return Err(CrawlError::Io(error)),
    };
    let gate = policy
        .collection_gate(now)
        .map_err(|error| CrawlError::Policy(error.to_string()))?;
    let notice = policy
        .notice_bytes()
        .map_err(|error| CrawlError::Policy(error.to_string()))?;
    index.install_public_collection_gate(&gate, notice, now)?;
    let mut crawler = ControlledCrawler::<SystemResolver, SystemClock>::open_system_with_public(
        frontier_path,
        Arc::clone(&index),
        Vec::new(),
        authorities,
        limits,
    )?;
    for source in policy.sources() {
        let source_policy = source
            .crawler_policy(policy.contact(), now, &policy.sha256())
            .map_err(|error| CrawlError::Policy(error.to_string()))?;
        let seeds = source
            .seeds()
            .map_err(|error| CrawlError::Policy(error.to_string()))?;
        crawler.admit_source(source_policy, &seeds)?;
    }

    run_bounded_crawl(
        &mut crawler,
        request_count,
        max_wire_bytes,
        max_decoded_bytes,
        max_runtime,
    )
}

fn run_bounded_crawl<R: DestinationResolver + 'static, C: Clock + 'static>(
    crawler: &mut ControlledCrawler<R, C>,
    request_count: usize,
    max_wire_bytes: usize,
    max_decoded_bytes: usize,
    max_runtime: Duration,
) -> Result<BoundedCrawlResult, CrawlError> {
    let overall_deadline = Instant::now() + max_runtime;
    let mut report = CrawlReport::default();
    let stop_reason;
    loop {
        let remaining_runtime = overall_deadline.saturating_duration_since(Instant::now());
        let remaining_requests = request_count.saturating_sub(report.requests);
        let remaining_wire = max_wire_bytes.saturating_sub(report.compressed_bytes);
        let remaining_decoded = max_decoded_bytes.saturating_sub(report.decompressed_bytes);
        if remaining_runtime.is_zero() {
            report.failure("overall public crawl runtime limit reached");
            stop_reason = BoundedStopReason::RuntimeBudget;
            break;
        }
        if remaining_requests == 0 {
            stop_reason = BoundedStopReason::RequestBudget;
            break;
        }
        if remaining_wire < MAX_COMPRESSED_RESPONSE_BYTES
            || remaining_decoded < MAX_DECODED_RESPONSE_BYTES
        {
            report.failure("public crawl byte budget cannot reserve another bounded response");
            stop_reason = BoundedStopReason::ByteBudget;
            break;
        }
        crawler.limits.max_requests_per_run = remaining_requests;
        crawler.limits.max_wire_bytes_per_run = remaining_wire;
        crawler.limits.max_decompressed_bytes_per_run = remaining_decoded;
        crawler.limits.max_runtime = remaining_runtime;
        let batch = crawler.run_until_idle(&CrawlCancellation::default())?;
        let batch_requests = batch.requests;
        let batch_bytes = batch
            .compressed_bytes
            .saturating_add(batch.decompressed_bytes);
        report.merge(batch);
        let now = crawler.clock.now_ms();
        let next_eligibility = crawler.next_dispatch_eligibility(now)?;
        let next_due = match next_eligibility {
            DispatchEligibility::Idle => {
                stop_reason = BoundedStopReason::FrontierIdle;
                break;
            }
            DispatchEligibility::SourceBudget => {
                report.failure(
                    "source lifetime request budget exhausted with admitted URLs remaining",
                );
                stop_reason = BoundedStopReason::SourceBudget;
                break;
            }
            DispatchEligibility::SourceDeadline => {
                report.failure(
                    "source retention or policy deadline precedes the next eligible request",
                );
                stop_reason = BoundedStopReason::SourceDeadline;
                break;
            }
            DispatchEligibility::At(next_due) => next_due,
        };
        let delay = Duration::from_millis(next_due.saturating_sub(now));
        let remaining_requests = request_count.saturating_sub(report.requests);
        let remaining_wire = max_wire_bytes.saturating_sub(report.compressed_bytes);
        let remaining_decoded = max_decoded_bytes.saturating_sub(report.decompressed_bytes);
        if remaining_requests == 0 {
            stop_reason = BoundedStopReason::RequestBudget;
            break;
        }
        if remaining_wire < MAX_COMPRESSED_RESPONSE_BYTES
            || remaining_decoded < MAX_DECODED_RESPONSE_BYTES
        {
            report.failure("public crawl byte budget cannot reserve another bounded response");
            stop_reason = BoundedStopReason::ByteBudget;
            break;
        }
        let remaining_runtime = overall_deadline.saturating_duration_since(Instant::now());
        if delay >= remaining_runtime {
            report.failure(
                "next eligible public request is due after the public crawl runtime limit",
            );
            stop_reason = BoundedStopReason::RuntimeBudget;
            break;
        }
        if batch_requests == 0 && delay.is_zero() && batch_bytes == 0 {
            report.failure("public crawl made no progress while an admitted URL was due");
            stop_reason = BoundedStopReason::NoProgress;
            break;
        }
        if !delay.is_zero() {
            thread::sleep(delay);
        }
    }
    Ok(BoundedCrawlResult {
        report,
        stop_reason,
    })
}

pub(crate) fn revoke_public_source(
    index_path: &Path,
    frontier_path: &Path,
    source_id: &str,
) -> Result<(), CrawlError> {
    if source_id.is_empty()
        || source_id.len() > MAX_SOURCE_ID_BYTES
        || !source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CrawlError::Policy("source ID is invalid".to_owned()));
    }
    let index = Arc::new(PersistentIndex::open(index_path)?);
    let mut crawler = ControlledCrawler::<SystemResolver, SystemClock>::open_system(
        frontier_path,
        index,
        Vec::new(),
        CrawlLimits::default(),
    )?;
    crawler.revoke_source(source_id)
}

fn origin_of_url(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(0);
    format!("{}://{}:{}", url.scheme().to_ascii_lowercase(), host, port)
}

fn response_request_slots(remaining_wire: usize, remaining_decompressed: usize) -> usize {
    (remaining_wire / MAX_COMPRESSED_RESPONSE_BYTES)
        .min(remaining_decompressed / MAX_DECODED_RESPONSE_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageResponseClass {
    RedirectContinuation,
    NotFound,
    TerminalNon404,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotFoundEvidence {
    Preserve,
    Observe,
    Reset,
}

impl PageResponseClass {
    fn classify(status: u16) -> Self {
        if is_redirect(status) {
            Self::RedirectContinuation
        } else if status == 404 {
            Self::NotFound
        } else {
            Self::TerminalNon404
        }
    }

    fn not_found_evidence(self) -> NotFoundEvidence {
        match self {
            Self::RedirectContinuation => NotFoundEvidence::Preserve,
            Self::NotFound => NotFoundEvidence::Observe,
            Self::TerminalNon404 => NotFoundEvidence::Reset,
        }
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn insert_header(
    headers: &mut HeaderMap,
    name: reqwest::header::HeaderName,
    value: Option<&str>,
) -> Result<(), CrawlError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return Err(CrawlError::Capacity("HTTP validator header bytes"));
    }
    headers.insert(
        name,
        HeaderValue::from_str(value)
            .map_err(|error| CrawlError::Transport(format!("invalid validator header: {error}")))?,
    );
    Ok(())
}

fn single_header_values(headers: &HeaderMap, name: &str) -> Result<Option<String>, CrawlError> {
    let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|error| CrawlError::Transport(error.to_string()))?;
    let mut values = headers.get_all(header_name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(CrawlError::Transport(format!("repeated {name} header")));
    }
    let text = value
        .to_str()
        .map_err(|error| CrawlError::Transport(format!("invalid {name} header: {error}")))?;
    if text.len() > MAX_HEADER_VALUE_BYTES {
        return Err(CrawlError::Capacity("HTTP header value bytes"));
    }
    Ok(Some(text.to_owned()))
}

fn single_response_header(
    response: &HttpResponse,
    name: &str,
) -> Result<Option<String>, CrawlError> {
    single_header_values(&response.headers, name)
}

fn retry_after_at(headers: &HeaderMap, now_ms: u64) -> Option<u64> {
    let raw = single_header_values(headers, "retry-after")
        .ok()
        .flatten()?;
    if let Ok(seconds) = raw.trim().parse::<u64>() {
        return Some(now_ms.saturating_add(seconds.saturating_mul(1000).min(MAX_RETRY_MS)));
    }
    let date = httpdate::parse_http_date(raw.trim()).ok()?;
    let date_ms = date
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .min(u64::MAX as u128) as u64;
    Some(date_ms.max(now_ms).min(now_ms.saturating_add(MAX_RETRY_MS)))
}

fn robots_expiry(
    headers: &HeaderMap,
    now_ms: u64,
    no_store_from_worker: bool,
) -> (u64, bool, bool) {
    let mut no_cache = false;
    let mut no_store = no_store_from_worker;
    let mut max_age: Option<u64> = None;
    for raw in headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for directive in raw.split(',').map(str::trim) {
            if directive.eq_ignore_ascii_case("no-cache") {
                no_cache = true;
            } else if directive.eq_ignore_ascii_case("no-store") {
                no_store = true;
            } else if let Some((name, value)) = directive.split_once('=')
                && name.trim().eq_ignore_ascii_case("max-age")
            {
                let value = value.trim().trim_matches('"');
                if let Ok(seconds) = value.parse::<u64>() {
                    max_age = Some(max_age.map_or(seconds, |current| current.min(seconds)));
                }
            }
        }
    }
    let age_seconds = headers
        .get("age")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let ttl_ms = if no_cache {
        0
    } else if let Some(seconds) = max_age {
        seconds.saturating_sub(age_seconds).saturating_mul(1000)
    } else if let Some(expires) = headers
        .get("expires")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
    {
        expires
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(now_ms)
            .saturating_sub(now_ms)
            .saturating_sub(age_seconds.saturating_mul(1000))
    } else {
        DEFAULT_ROBOTS_AGE_MS
    }
    .min(MAX_ROBOTS_AGE_MS);
    (
        now_ms.saturating_add(ttl_ms),
        no_cache || ttl_ms == 0,
        no_store,
    )
}

fn has_cache_control_directive(headers: &HeaderMap, wanted: &str) -> bool {
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case(wanted))
}

struct PageCandidate {
    key: UrlKey,
    source_id: String,
    fetch_url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    schedule_id: Option<u64>,
    redirect_count: usize,
    redirect_seen: String,
    unconditional: bool,
    attempts: u16,
}

impl<R, C> ControlledCrawler<R, C>
where
    R: DestinationResolver + 'static,
    C: Clock + 'static,
{
    fn next_job(
        &mut self,
        report: &mut CrawlReport,
        actual_requests: usize,
        reserved_requests: usize,
        response_slots: usize,
        active_by_origin: &HashMap<String, usize>,
        active_origins: &HashSet<String>,
    ) -> Result<Option<WorkerJob>, CrawlError> {
        let now = self.clock.now_ms();
        let candidates = self.due_candidates(now)?;
        if candidates.is_empty() {
            return Ok(None);
        }
        let mut candidate_origins: Vec<String> = candidates
            .iter()
            .filter_map(|candidate| {
                Url::parse(&candidate.fetch_url)
                    .ok()
                    .map(|url| origin_of_url(&url))
            })
            .collect();
        candidate_origins.sort();
        candidate_origins.dedup();
        let start_index = candidate_origins
            .iter()
            .position(|origin| origin > &self.last_origin)
            .unwrap_or(0);
        candidate_origins.rotate_left(start_index);

        for origin in candidate_origins {
            if active_origins.contains(&origin)
                || active_by_origin.get(&origin).copied().unwrap_or(0)
                    >= self.limits.per_origin_active
            {
                continue;
            }
            let origin_state = self.origin_state(&origin)?;
            let origin_ready_ms = origin_state.0.max(origin_state.1);
            if origin_ready_ms > now {
                self.defer_origin_pages(&origin, origin_ready_ms, "politeness or backoff delay")?;
                continue;
            }

            for candidate in candidates.iter().filter(|candidate| {
                Url::parse(&candidate.fetch_url)
                    .ok()
                    .is_some_and(|url| origin_of_url(&url) == origin)
            }) {
                let (policy, lifecycle, source_requests) = self.db.source(&candidate.source_id)?;
                if lifecycle != "active" {
                    continue;
                }
                if now >= policy.valid_until_ms
                    || matches!(policy.retention, RetentionPolicy::Until(deadline) if now >= deadline)
                {
                    self.revoke_source(&policy.id)?;
                    continue;
                }
                let fetch_key = UrlKey::parse(&candidate.fetch_url)
                    .map_err(|error| CrawlError::Url(error.to_string()))?;
                let url = fetch_key
                    .to_url()
                    .map_err(|error| CrawlError::Url(error.to_string()))?;
                if !policy.allows_url(&url, now) || !self.fetcher.has_capability(&url) {
                    self.mark_page_blocked(
                        &candidate.key,
                        &policy.id,
                        "url is outside current admission scope",
                    )?;
                    report.skipped("page URL outside source path or authority scope");
                    continue;
                }

                let (cache, denied_retry, cache_reason) =
                    self.robot_entry(&candidate.key, &origin, now)?;
                if let Some(cache) = cache {
                    let rules = match parse_robots(&cache.body) {
                        Ok(rules) => rules,
                        Err(error) => {
                            self.set_robot_denied(
                                &origin,
                                now,
                                now.saturating_add(MAX_RETRY_MS),
                                &error.to_string(),
                            )?;
                            self.mark_page_deferred(
                                &candidate.key,
                                now.saturating_add(MAX_RETRY_MS),
                                &error.to_string(),
                            )?;
                            report.skipped("robots rules could not be parsed");
                            continue;
                        }
                    };
                    if !rules.fetch_allowed(AGENT_TOKEN, &fetch_key) {
                        let retry_at = if cache.expires_ms > now {
                            cache.expires_ms
                        } else {
                            now.saturating_add(DEFAULT_RETRY_MS)
                        };
                        self.mark_page_deferred(
                            &candidate.key,
                            retry_at,
                            "robots rule denies path",
                        )?;
                        report.skipped("robots rules denied the page path");
                        continue;
                    }
                    let free_run = self
                        .limits
                        .max_requests_per_run
                        .saturating_sub(actual_requests.saturating_add(reserved_requests));
                    if free_run == 0 || source_requests >= policy.max_requests {
                        self.mark_page_deferred(
                            &candidate.key,
                            now.saturating_add(MAX_RETRY_MS),
                            "request budget exhausted",
                        )?;
                        continue;
                    }
                    let schedule_id = candidate.schedule_id.unwrap_or_else(|| now.max(1));
                    let mut token = self.current_lease_token(&candidate.key)?;
                    if token.is_none() {
                        let lease = self.index.issue_fence(&candidate.key)?;
                        token = Some(self.index.export_lease(&lease)?);
                    }
                    let token = token.expect("lease token was issued or retained");
                    let mut redirect_seen = candidate.redirect_seen.clone();
                    if candidate.schedule_id.is_none() {
                        redirect_seen = url.to_string();
                    }
                    let min_delay = policy.min_origin_delay_ms.min(MAX_RETRY_MS) as i64;
                    let tx = self.db.transaction()?;
                    tx.execute(
                    "UPDATE frontier SET state='inflight',schedule_id=?2,lease_token=?3,redirect_seen=?4,reason='' WHERE url_key=?1",
                    params![candidate.key.as_str(), schedule_id as i64, token, redirect_seen],
                )?;
                    tx.execute(
                        "UPDATE source_policy SET request_count=request_count+1 WHERE source_id=?1",
                        [&policy.id],
                    )?;
                    tx.execute(
                    "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,?2,0,0) ON CONFLICT(origin) DO UPDATE SET next_request_ms=MAX(next_request_ms,excluded.next_request_ms)",
                    params![origin, now.saturating_add(min_delay as u64) as i64],
                )?;
                    FrontierDb::event(
                        &tx,
                        now,
                        &policy.id,
                        Some(candidate.key.as_str()),
                        "inflight",
                        "scheduled page request",
                    )?;
                    tx.commit()?;

                    let mut headers = HeaderMap::new();
                    if !candidate.unconditional {
                        insert_header(&mut headers, IF_NONE_MATCH, candidate.etag.as_deref())?;
                        insert_header(
                            &mut headers,
                            IF_MODIFIED_SINCE,
                            candidate.last_modified.as_deref(),
                        )?;
                    }
                    self.last_origin = origin;
                    return Ok(Some(WorkerJob::Page(PageJob {
                        key: candidate.key.clone(),
                        source: policy,
                        url,
                        lease_token: token,
                        schedule_id,
                        redirect_count: candidate.redirect_count,
                        redirect_seen,
                        unconditional: candidate.unconditional,
                        etag: candidate.etag.clone(),
                        last_modified: candidate.last_modified.clone(),
                        attempt: candidate.attempts,
                    })));
                }

                if denied_retry > now {
                    self.mark_page_deferred(&candidate.key, denied_retry, &cache_reason)?;
                    report.skipped(if cache_reason.is_empty() {
                        "robots policy denied the origin"
                    } else {
                        cache_reason.as_str()
                    });
                    continue;
                }
                let remaining_source = policy.max_requests.saturating_sub(source_requests) as usize;
                let remaining_run = self
                    .limits
                    .max_requests_per_run
                    .saturating_sub(actual_requests.saturating_add(reserved_requests));
                let request_budget = 7usize
                    .min(remaining_source)
                    .min(remaining_run)
                    .min(response_slots);
                if request_budget == 0 {
                    self.mark_page_deferred(
                        &candidate.key,
                        now.saturating_add(MAX_RETRY_MS),
                        "robots request budget exhausted",
                    )?;
                    continue;
                }
                let cached = self.stale_robot_cache(&origin)?;
                let tx = self.db.transaction()?;
                tx.execute(
                    "UPDATE source_policy SET request_count=request_count+?2 WHERE source_id=?1",
                    params![policy.id, request_budget as i64],
                )?;
                tx.execute(
                "INSERT INTO robots_inflight(candidate_key,origins,min_origin_delay_ms) VALUES (?1,?2,?3)",
                params![
                    candidate.key.as_str(),
                    policy.allowed_origins.join("\n"),
                    policy.min_origin_delay_ms.min(MAX_RETRY_MS) as i64,
                ],
            )?;
                FrontierDb::event(
                    &tx,
                    now,
                    &policy.id,
                    None,
                    "robots_inflight",
                    "refresh robots for original authority",
                )?;
                tx.commit()?;
                self.last_origin = origin.clone();
                return Ok(Some(WorkerJob::Robots(RobotsJob {
                    candidate_key: candidate.key.clone(),
                    origin,
                    source: policy,
                    cached,
                    request_budget,
                })));
            }
        }
        Ok(None)
    }

    fn due_candidates(&self, now: u64) -> Result<Vec<PageCandidate>, CrawlError> {
        let mut statement = self.db.conn.prepare(
            "SELECT url_key,source_id,fetch_url,etag,last_modified,schedule_id,redirect_count,redirect_seen,unconditional,attempts FROM frontier WHERE state IN ('ready','deferred','complete') AND due_ms<=?1 ORDER BY fetch_url,queued_sequence",
        )?;
        let rows = statement.query_map([now as i64], |row| {
            let key_text: String = row.get(0)?;
            let key = UrlKey::parse(&key_text).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(PageCandidate {
                key,
                source_id: row.get(1)?,
                fetch_url: row.get(2)?,
                etag: row.get(3)?,
                last_modified: row.get(4)?,
                schedule_id: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
                redirect_count: row.get::<_, i64>(6)? as usize,
                redirect_seen: row.get(7)?,
                unconditional: row.get::<_, i64>(8)? != 0,
                attempts: row.get::<_, i64>(9)? as u16,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(CrawlError::from)
    }

    fn next_dispatch_eligibility(&self, now: u64) -> Result<DispatchEligibility, CrawlError> {
        let candidates = {
            let mut statement = self.db.conn.prepare(
                "SELECT f.fetch_url,f.due_ms,s.max_requests,s.request_count,s.valid_until_ms,s.retention_until_ms FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='active' AND (f.state IN ('ready','deferred') OR (f.state='complete' AND f.due_ms<=?1)) ORDER BY f.due_ms,f.queued_sequence",
            )?;
            let rows = statement.query_map([now as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut earliest = None;
        let mut source_budget_exhausted = false;
        let mut source_deadline_exhausted = false;
        for (fetch_url, due_ms, max_requests, request_count, valid_until, retention_until) in
            candidates
        {
            if request_count >= max_requests {
                source_budget_exhausted = true;
                continue;
            }
            let url = Url::parse(&fetch_url).map_err(|error| CrawlError::Url(error.to_string()))?;
            let key =
                UrlKey::parse(&fetch_url).map_err(|error| CrawlError::Url(error.to_string()))?;
            let origin = origin_of_url(&url);
            let origin_state = self.origin_state(&origin)?;
            let mut eligible_ms = u64::try_from(due_ms).unwrap_or_default();
            eligible_ms = eligible_ms.max(origin_state.0).max(origin_state.1);

            let robot_entry = self
                .db
                .conn
                .query_row(
                    "SELECT body,expires_ms,denied_retry_ms FROM robots_cache WHERE origin=?1",
                    [&origin],
                    |row| {
                        Ok((
                            row.get::<_, Option<Vec<u8>>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((body, expires_ms, denied_retry_ms)) = robot_entry {
                let expires_ms = u64::try_from(expires_ms).unwrap_or_default();
                let denied_retry_ms = u64::try_from(denied_retry_ms).unwrap_or_default();
                if let Some(body) = body.filter(|_| expires_ms > now) {
                    match parse_robots(&body) {
                        Ok(rules) if !rules.fetch_allowed(AGENT_TOKEN, &key) => {
                            eligible_ms = eligible_ms.max(expires_ms);
                        }
                        Err(_) => {
                            eligible_ms = eligible_ms
                                .max(denied_retry_ms.max(now.saturating_add(MAX_RETRY_MS)));
                        }
                        _ => {}
                    }
                } else {
                    eligible_ms = eligible_ms.max(denied_retry_ms);
                }
            }

            let policy_deadline = [valid_until, retention_until]
                .into_iter()
                .filter(|deadline| *deadline > 0)
                .map(|deadline| u64::try_from(deadline).unwrap_or_default())
                .min()
                .unwrap_or(u64::MAX);
            if eligible_ms >= policy_deadline {
                source_deadline_exhausted = true;
                continue;
            }
            earliest = Some(earliest.map_or(eligible_ms, |current: u64| current.min(eligible_ms)));
        }
        Ok(match earliest {
            Some(eligible_ms) => DispatchEligibility::At(eligible_ms),
            None if source_budget_exhausted => DispatchEligibility::SourceBudget,
            None if source_deadline_exhausted => DispatchEligibility::SourceDeadline,
            None => DispatchEligibility::Idle,
        })
    }

    fn origin_state(&self, origin: &str) -> Result<(u64, u64, u64), CrawlError> {
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT next_request_ms,backoff_until_ms,failures FROM origin_state WHERE origin=?1",
                [origin],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64)),
            )
            .optional()?
            .unwrap_or((0, 0, 0)))
    }

    fn robot_entry(
        &mut self,
        candidate_key: &UrlKey,
        origin: &str,
        now: u64,
    ) -> Result<(Option<RobotCache>, u64, String), CrawlError> {
        if let Some(cache) = self.one_shot_robots.remove(candidate_key) {
            return Ok((Some(cache), 0, String::new()));
        }
        let stored = self.db.conn.query_row(
            "SELECT body,expires_ms,denied_retry_ms,reason,etag,last_modified FROM robots_cache WHERE origin=?1",
            [origin],
            |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, i64>(1)? as u64, row.get::<_, i64>(2)? as u64, row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?)),
        ).optional()?;
        let Some((body, expires, retry, reason, etag, last_modified)) = stored else {
            return Ok((None, 0, String::new()));
        };
        if let Some(body) = body
            && expires > now
        {
            return Ok((
                Some(RobotCache {
                    body,
                    expires_ms: expires,
                    etag,
                    last_modified,
                }),
                retry,
                reason,
            ));
        }
        Ok((None, retry, reason))
    }

    fn stale_robot_cache(&self, origin: &str) -> Result<Option<RobotCache>, CrawlError> {
        self.db.conn.query_row(
            "SELECT body,expires_ms,etag,last_modified FROM robots_cache WHERE origin=?1 AND body IS NOT NULL",
            [origin],
            |row| Ok(RobotCache { body: row.get(0)?, expires_ms: row.get::<_, i64>(1)? as u64, etag: row.get(2)?, last_modified: row.get(3)? }),
        ).optional().map_err(CrawlError::from)
    }

    fn current_lease_token(&self, key: &UrlKey) -> Result<Option<Vec<u8>>, CrawlError> {
        self.db
            .conn
            .query_row(
                "SELECT lease_token FROM frontier WHERE url_key=?1",
                [key.as_str()],
                |row| row.get(0),
            )
            .map_err(CrawlError::from)
    }

    fn page_job_is_current(&self, job: &PageJob) -> Result<bool, CrawlError> {
        Ok(self.db.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM frontier WHERE url_key=?1 AND state='inflight' AND schedule_id=?2 AND lease_token=?3)",
            params![job.key.as_str(), job.schedule_id as i64, job.lease_token],
            |row| row.get(0),
        )?)
    }

    fn expire_source_if_due(&mut self, source_id: &str) -> Result<bool, CrawlError> {
        let (policy, lifecycle, _) = self.db.source(source_id)?;
        let now = self.clock.now_ms();
        let retention_expired =
            matches!(policy.retention, RetentionPolicy::Until(deadline) if now >= deadline);
        if lifecycle == "active" && (now >= policy.valid_until_ms || retention_expired) {
            self.revoke_source(source_id)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn defer_origin_pages(
        &mut self,
        origin: &str,
        due_ms: u64,
        reason: &str,
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let matching_keys = {
            let mut statement = self.db.conn.prepare(
                "SELECT url_key,fetch_url FROM frontier WHERE state IN ('ready','deferred')",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(|(key, fetch_url)| {
                    Url::parse(&fetch_url)
                        .ok()
                        .filter(|url| origin_of_url(url) == origin)
                        .map(|_| key)
                })
                .collect::<Vec<_>>()
        };
        let tx = self.db.transaction()?;
        for key in matching_keys {
            tx.execute(
                "UPDATE frontier SET state='deferred',due_ms=?2,reason=?3 WHERE url_key=?1 AND state IN ('ready','deferred') AND due_ms<=?2",
                params![key, due_ms as i64, reason],
            )?;
        }
        FrontierDb::event(&tx, now, "", None, "deferred", reason)?;
        tx.commit()?;
        Ok(())
    }

    fn mark_page_blocked(
        &mut self,
        key: &UrlKey,
        source_id: &str,
        reason: &str,
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE frontier SET state='blocked',lease_token=NULL,schedule_id=NULL,reason=?2 WHERE url_key=?1",
            params![key.as_str(), reason],
        )?;
        FrontierDb::event(&tx, now, source_id, Some(key.as_str()), "blocked", reason)?;
        tx.commit()?;
        Ok(())
    }

    fn mark_page_deferred(
        &mut self,
        key: &UrlKey,
        due_ms: u64,
        reason: &str,
    ) -> Result<(), CrawlError> {
        let source_id: String = self.db.conn.query_row(
            "SELECT source_id FROM frontier WHERE url_key=?1",
            [key.as_str()],
            |row| row.get(0),
        )?;
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE frontier SET state='deferred',due_ms=?2,lease_token=NULL,schedule_id=NULL,reason=?3 WHERE url_key=?1",
            params![key.as_str(), due_ms as i64, reason],
        )?;
        FrontierDb::event(&tx, now, &source_id, Some(key.as_str()), "deferred", reason)?;
        tx.commit()?;
        Ok(())
    }

    fn handle_worker_result(
        &mut self,
        result: WorkerResult,
        report: &mut CrawlReport,
    ) -> Result<usize, CrawlError> {
        match result {
            WorkerResult::Page { job, result } => {
                self.record_page_completion(&job)?;
                if !self.page_job_is_current(&job)? {
                    return Ok(1);
                }
                if self.expire_source_if_due(&job.source.id)? {
                    return Ok(1);
                }
                match result {
                    Ok(response) => {
                        report.compressed_bytes =
                            report.compressed_bytes.saturating_add(response.wire_bytes);
                        report.decompressed_bytes = report
                            .decompressed_bytes
                            .saturating_add(response.decoded_bytes);
                        if report.compressed_bytes > self.limits.max_wire_bytes_per_run
                            || report.decompressed_bytes
                                > self.limits.max_decompressed_bytes_per_run
                        {
                            self.finish_page_failure(
                                &job,
                                "per-run response byte budget exhausted",
                                true,
                            )?;
                            return Ok(1);
                        }
                        self.handle_page_response(job, response, report)?;
                    }
                    Err(error) => {
                        report.transport_failures += 1;
                        report.failure(&error.to_string());
                        self.retry_page(&job, &error.to_string(), None, false, report)?;
                    }
                }
                Ok(1)
            }
            WorkerResult::Robots { job, result } => {
                let (requests, wire_bytes, decoded_bytes) = match &result {
                    Ok(result) => (result.requests, result.wire_bytes, result.decoded_bytes),
                    Err(result) => (result.requests, result.wire_bytes, result.decoded_bytes),
                };
                let unused = job.request_budget.saturating_sub(requests);
                let visited_origins = match &result {
                    Ok(result) => result.visited_origins.as_slice(),
                    Err(result) => result.visited_origins.as_slice(),
                };
                self.finish_robots_attempt(&job, visited_origins, unused)?;
                report.compressed_bytes = report.compressed_bytes.saturating_add(wire_bytes);
                report.decompressed_bytes = report.decompressed_bytes.saturating_add(decoded_bytes);
                if report.compressed_bytes > self.limits.max_wire_bytes_per_run
                    || report.decompressed_bytes > self.limits.max_decompressed_bytes_per_run
                {
                    return Err(CrawlError::Capacity("per-run response byte budget"));
                }
                if self.expire_source_if_due(&job.source.id)? {
                    return Ok(requests);
                }
                match result {
                    Ok(success) => self.accept_robots(job, success, report)?,
                    Err(failure) => self.reject_robots(job, failure, report)?,
                }
                Ok(requests)
            }
        }
    }

    fn record_page_completion(&mut self, job: &PageJob) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let due = now.saturating_add(job.source.min_origin_delay_ms.min(MAX_RETRY_MS));
        self.db.conn.execute(
            "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,?2,0,0) ON CONFLICT(origin) DO UPDATE SET next_request_ms=MAX(next_request_ms,excluded.next_request_ms)",
            params![origin_of_url(&job.url), due as i64],
        )?;
        Ok(())
    }

    fn finish_robots_attempt(
        &mut self,
        job: &RobotsJob,
        visited_origins: &[String],
        unused_requests: usize,
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let due = now.saturating_add(job.source.min_origin_delay_ms.min(MAX_RETRY_MS));
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE source_policy SET request_count=MAX(0,request_count-?2) WHERE source_id=?1",
            params![job.source.id, unused_requests as i64],
        )?;
        for origin in std::iter::once(&job.origin).chain(visited_origins) {
            tx.execute(
                "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,?2,0,0) ON CONFLICT(origin) DO UPDATE SET next_request_ms=MAX(next_request_ms,excluded.next_request_ms)",
                params![origin, due as i64],
            )?;
        }
        tx.execute(
            "DELETE FROM robots_inflight WHERE candidate_key=?1",
            [job.candidate_key.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn handle_page_response(
        &mut self,
        job: PageJob,
        response: HttpResponse,
        report: &mut CrawlReport,
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let (current_policy, lifecycle, _) = self.db.source(&job.source.id)?;
        if lifecycle != "active" {
            self.mark_page_blocked(&job.key, &job.source.id, "policy revoked during fetch")?;
            return Ok(());
        }
        if now >= current_policy.valid_until_ms
            || matches!(current_policy.retention, RetentionPolicy::Until(deadline) if now >= deadline)
        {
            self.revoke_source(&job.source.id)?;
            return Ok(());
        }

        if PageResponseClass::classify(response.status).not_found_evidence()
            == NotFoundEvidence::Reset
        {
            self.reset_404_count(&job.key)?;
        }

        if is_redirect(response.status) {
            let location = response
                .location()
                .map_err(|error| CrawlError::Transport(error.to_string()))?
                .ok_or_else(|| CrawlError::Transport("redirect has no Location".to_owned()))?;
            let target_key = UrlKey::resolve(&job.url, location)
                .map_err(|error| CrawlError::Url(error.to_string()))?;
            let target = target_key
                .to_url()
                .map_err(|error| CrawlError::Url(error.to_string()))?;
            if job.redirect_count >= self.limits.page_redirects
                || job
                    .redirect_seen
                    .lines()
                    .any(|seen| seen == target_key.as_str())
                || !current_policy.allows_url(&target, now)
                || !self.fetcher.has_capability(&target)
            {
                self.reset_404_count(&job.key)?;
                self.finish_page_failure(
                    &job,
                    "redirect loop, limit, or source/network scope denial",
                    true,
                )?;
                report.skipped("page redirect exceeded source, network, or loop bounds");
                return Ok(());
            }
            let mut chain = job.redirect_seen.clone();
            if !chain.is_empty() {
                chain.push('\n');
            }
            chain.push_str(target_key.as_str());
            let tx = self.db.transaction()?;
            tx.execute(
                "UPDATE frontier SET state='ready',fetch_url=?2,redirect_count=?3,redirect_seen=?4,due_ms=?5,reason='validated redirect' WHERE url_key=?1",
                params![job.key.as_str(), target_key.as_str(), (job.redirect_count + 1) as i64, chain, now as i64],
            )?;
            FrontierDb::event(
                &tx,
                now,
                &job.source.id,
                Some(job.key.as_str()),
                "redirected",
                "validated redirect target queued for a fresh policy and DNS check",
            )?;
            tx.commit()?;
            return Ok(());
        }

        if response.status == 429 || response.status == 503 || response.status >= 500 {
            let retry_after = retry_after_at(&response.headers, now);
            self.retry_page(
                &job,
                &format!(
                    "HTTP {} retained the prior indexed version",
                    response.status
                ),
                retry_after,
                true,
                report,
            )?;
            return Ok(());
        }

        let header_restrictions = parse_x_robots_tags(response.header_values("x-robots-tag"));
        if response.status == 304 && header_restrictions.noindex {
            self.tombstone_page(
                &job,
                "applicable X-Robots-Tag noindex/none on 304",
                Vec::new(),
                report,
            )?;
            return Ok(());
        }

        if response.status == 404 {
            let count: i64 = self.db.conn.query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [job.key.as_str()],
                |row| row.get(0),
            )?;
            let next_count = count.saturating_add(1).min(2);
            if next_count >= 2 {
                let outbox_id = self.persist_page_intent(
                    &job,
                    Intent::Tombstone,
                    Completion {
                        state: "removed".to_owned(),
                        reason: "two separately scheduled terminal 404 observations".to_owned(),
                        links: Vec::new(),
                        etag: None,
                        last_modified: None,
                        next_due_ms: None,
                    },
                    report,
                )?;
                if self.outbox_is_applied(outbox_id)? {
                    report.tombstoned += 1;
                }
            } else {
                let due = now.saturating_add(DEFAULT_RETRY_MS);
                let tx = self.db.transaction()?;
                tx.execute(
                    "UPDATE frontier SET state='ready',fetch_url=url_key,not_found_count=?2,due_ms=?3,schedule_id=NULL,lease_token=NULL,attempts=0,redirect_count=0,redirect_seen=url_key,reason='first terminal 404; confirm on a later schedule' WHERE url_key=?1",
                    params![job.key.as_str(), next_count, due as i64],
                )?;
                FrontierDb::event(
                    &tx,
                    now,
                    &job.source.id,
                    Some(job.key.as_str()),
                    "404_observed",
                    "one of two required separately scheduled 404 responses",
                )?;
                tx.commit()?;
            }
            return Ok(());
        }

        if response.status == 410 {
            let outbox_id = self.persist_page_intent(
                &job,
                Intent::Tombstone,
                Completion {
                    state: "removed".to_owned(),
                    reason: "HTTP 410 Gone".to_owned(),
                    links: Vec::new(),
                    etag: None,
                    last_modified: None,
                    next_due_ms: None,
                },
                report,
            )?;
            if self.outbox_is_applied(outbox_id)? {
                report.tombstoned += 1;
            }
            return Ok(());
        }

        if response.status == 304 {
            let view = self.index.read_view()?;
            if let Some(document) = view.document(&job.key) {
                let etag = match single_response_header(&response, "etag") {
                    Ok(value) => value.or(job.etag.clone()),
                    Err(error) => {
                        self.finish_page_failure(&job, &error.to_string(), true)?;
                        return Ok(());
                    }
                };
                let modified = match single_response_header(&response, "last-modified") {
                    Ok(value) => value.or(job.last_modified.clone()),
                    Err(error) => {
                        self.finish_page_failure(&job, &error.to_string(), true)?;
                        return Ok(());
                    }
                };
                let outbox_id = self.persist_page_intent(
                    &job,
                    Intent::Upsert {
                        effective_url: document.effective_url,
                        title: document.title,
                        body: document.body,
                    },
                    Completion {
                        state: "complete".to_owned(),
                        reason: "304 reused the complete pinned index representation".to_owned(),
                        links: Vec::new(),
                        etag,
                        last_modified: modified,
                        next_due_ms: Some(now.saturating_add(DEFAULT_RECRAWL_MS)),
                    },
                    report,
                )?;
                if self.outbox_is_applied(outbox_id)? {
                    report.indexed += 1;
                }
            } else if !job.unconditional {
                let tx = self.db.transaction()?;
                tx.execute(
                    "UPDATE frontier SET state='ready',unconditional=1,etag=NULL,last_modified=NULL,due_ms=?2,reason='304 without stored representation; retry unconditionally' WHERE url_key=?1",
                    params![job.key.as_str(), now as i64],
                )?;
                FrontierDb::event(
                    &tx,
                    now,
                    &job.source.id,
                    Some(job.key.as_str()),
                    "unconditional_retry",
                    "304 had no stored representation",
                )?;
                tx.commit()?;
            } else {
                self.finish_page_failure(&job, "unconditional retry still returned 304", true)?;
            }
            return Ok(());
        }

        if !(200..300).contains(&response.status) {
            self.finish_page_failure(
                &job,
                &format!("HTTP status {} retained prior version", response.status),
                true,
            )?;
            return Ok(());
        }

        let response_body = match response.body.as_ref() {
            Ok(body) => body.as_slice(),
            Err(_error) if header_restrictions.noindex => {
                self.tombstone_page(
                    &job,
                    "X-Robots-Tag noindex on response with rejected body",
                    Vec::new(),
                    report,
                )?;
                return Ok(());
            }
            Err(error) => {
                self.retry_page(&job, &error.to_string(), None, false, report)?;
                return Ok(());
            }
        };

        report.pages_fetched += 1;
        let content_type = match single_response_header(&response, "content-type") {
            Ok(Some(value)) => value,
            Ok(None) => {
                if header_restrictions.noindex {
                    self.tombstone_page(
                        &job,
                        "X-Robots-Tag noindex on response without Content-Type",
                        Vec::new(),
                        report,
                    )?;
                } else {
                    self.finish_page_failure(&job, "successful response lacks Content-Type", true)?;
                }
                return Ok(());
            }
            Err(error) => {
                if header_restrictions.noindex {
                    self.tombstone_page(
                        &job,
                        "X-Robots-Tag noindex on response with invalid Content-Type",
                        Vec::new(),
                        report,
                    )?;
                } else {
                    self.finish_page_failure(&job, &error.to_string(), true)?;
                }
                return Ok(());
            }
        };
        let extracted = match extract_html(
            response_body,
            &content_type,
            None,
            job.key.clone(),
            response.requested_url.as_str(),
        ) {
            Ok(extracted) => extracted,
            Err(error) => {
                if header_restrictions.noindex {
                    self.tombstone_page(
                        &job,
                        "X-Robots-Tag noindex on rejected response content",
                        Vec::new(),
                        report,
                    )?;
                } else {
                    self.finish_page_failure(&job, &error.to_string(), true)?;
                }
                return Ok(());
            }
        };
        let mut restrictions = header_restrictions;
        restrictions.combine(extracted.restrictions);
        report.duplicate_urls = report
            .duplicate_urls
            .saturating_add(extracted.duplicate_links);
        if restrictions.noindex {
            let links = if restrictions.nofollow {
                Vec::new()
            } else {
                extracted
                    .links
                    .iter()
                    .map(|key| key.as_str().to_owned())
                    .collect()
            };
            let reason = if restrictions.nofollow {
                "applicable noindex/none with nofollow page directive"
            } else {
                "applicable noindex page directive; admitted links remain eligible"
            };
            self.tombstone_page(&job, reason, links, report)?;
            return Ok(());
        }
        let links = if restrictions.nofollow {
            Vec::new()
        } else {
            extracted
                .links
                .iter()
                .map(|key| key.as_str().to_owned())
                .collect()
        };
        let etag = match single_response_header(&response, "etag") {
            Ok(value) => value,
            Err(error) => {
                self.finish_page_failure(&job, &error.to_string(), true)?;
                return Ok(());
            }
        };
        let last_modified = match single_response_header(&response, "last-modified") {
            Ok(value) => value,
            Err(error) => {
                self.finish_page_failure(&job, &error.to_string(), true)?;
                return Ok(());
            }
        };
        let upsert = Intent::Upsert {
            effective_url: extracted.effective_url,
            title: extracted.title,
            body: extracted.body,
        };
        let outbox_id = self.persist_page_intent(
            &job,
            upsert,
            Completion {
                state: "complete".to_owned(),
                reason: if restrictions.nofollow {
                    "indexed with nofollow; no discovered links queued".to_owned()
                } else {
                    "indexed extracted fixture response".to_owned()
                },
                links,
                etag,
                last_modified,
                next_due_ms: Some(now.saturating_add(DEFAULT_RECRAWL_MS)),
            },
            report,
        )?;
        if self.outbox_is_applied(outbox_id)? {
            report.indexed += 1;
        }
        Ok(())
    }

    fn tombstone_page(
        &mut self,
        job: &PageJob,
        reason: &str,
        links: Vec<String>,
        report: &mut CrawlReport,
    ) -> Result<(), CrawlError> {
        let outbox_id = self.persist_page_intent(
            job,
            Intent::Tombstone,
            Completion {
                state: "removed".to_owned(),
                reason: reason.to_owned(),
                links,
                etag: None,
                last_modified: None,
                next_due_ms: None,
            },
            report,
        )?;
        if self.outbox_is_applied(outbox_id)? {
            report.tombstoned += 1;
        }
        Ok(())
    }

    fn reset_404_count(&mut self, key: &UrlKey) -> Result<(), CrawlError> {
        self.db.conn.execute(
            "UPDATE frontier SET not_found_count=0 WHERE url_key=?1",
            [key.as_str()],
        )?;
        Ok(())
    }

    fn finish_page_failure(
        &mut self,
        job: &PageJob,
        reason: &str,
        terminal: bool,
    ) -> Result<(), CrawlError> {
        if terminal {
            self.pending_failed_pages = self.pending_failed_pages.saturating_add(1);
            if self.pending_failure_reasons.len() < 64 {
                self.pending_failure_reasons
                    .push(reason.chars().take(512).collect());
            }
        }
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE frontier SET state=?2,fetch_url=url_key,reason=?3,lease_token=NULL,schedule_id=NULL,attempts=0,redirect_count=0,redirect_seen=url_key,unconditional=0 WHERE url_key=?1",
            params![job.key.as_str(), if terminal { "failed" } else { "deferred" }, reason],
        )?;
        FrontierDb::event(
            &tx,
            now,
            &job.source.id,
            Some(job.key.as_str()),
            if terminal { "failed" } else { "deferred" },
            reason,
        )?;
        tx.commit()?;
        Ok(())
    }

    fn retry_page(
        &mut self,
        job: &PageJob,
        reason: &str,
        retry_after_ms: Option<u64>,
        terminal_http: bool,
        report: &mut CrawlReport,
    ) -> Result<(), CrawlError> {
        report.failure(reason);
        let now = self.clock.now_ms();
        let next_attempt = job.attempt.saturating_add(1);
        if next_attempt > self.limits.max_retries {
            let due = now.saturating_add(MAX_RETRY_MS);
            let tx = self.db.transaction()?;
            tx.execute(
                "UPDATE frontier SET state='deferred',fetch_url=url_key,due_ms=?2,attempts=0,lease_token=NULL,schedule_id=NULL,redirect_count=0,redirect_seen=url_key,reason=?3 WHERE url_key=?1",
                params![job.key.as_str(), due as i64, reason],
            )?;
            FrontierDb::event(
                &tx,
                now,
                &job.source.id,
                Some(job.key.as_str()),
                "deferred",
                reason,
            )?;
            tx.commit()?;
            return Ok(());
        }
        report.retries += 1;
        let exp = DEFAULT_RETRY_MS
            .saturating_mul(1u64 << u32::from(next_attempt.min(16)))
            .min(MAX_RETRY_MS);
        let due = retry_after_ms.unwrap_or(0).max(now.saturating_add(exp));
        let origin = origin_of_url(&job.url);
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE frontier SET state='deferred',due_ms=?2,attempts=?3,lease_token=NULL,reason=?4 WHERE url_key=?1",
            params![job.key.as_str(), due as i64, next_attempt as i64, reason],
        )?;
        if terminal_http {
            tx.execute(
                "INSERT INTO origin_state(origin,backoff_until_ms,failures) VALUES (?1,?2,1) ON CONFLICT(origin) DO UPDATE SET backoff_until_ms=MAX(backoff_until_ms,excluded.backoff_until_ms),failures=failures+1",
                params![origin, due as i64],
            )?;
        }
        FrontierDb::event(
            &tx,
            now,
            &job.source.id,
            Some(job.key.as_str()),
            "retry",
            reason,
        )?;
        tx.commit()?;
        Ok(())
    }

    fn persist_page_intent(
        &mut self,
        job: &PageJob,
        intent: Intent,
        completion: Completion,
        _report: &mut CrawlReport,
    ) -> Result<i64, CrawlError> {
        let now = self.clock.now_ms();
        let source_lifecycle: String = self.db.conn.query_row(
            "SELECT lifecycle FROM source_policy WHERE source_id=?1",
            [&job.source.id],
            |row| row.get(0),
        )?;
        if source_lifecycle != "active" {
            self.mark_page_blocked(
                &job.key,
                &job.source.id,
                "policy no longer admits automatic upsert",
            )?;
            return Ok(-1);
        }
        let (kind, effective_url, title, body) = match intent {
            Intent::Upsert {
                effective_url,
                title,
                body,
            } => (0i64, Some(effective_url), Some(title), Some(body)),
            Intent::Tombstone => (1i64, None, None, None),
            Intent::Revoke | Intent::Readmit => {
                return Err(CrawlError::Policy(
                    "page fetch cannot create policy control intent".to_owned(),
                ));
            }
        };
        if title
            .as_ref()
            .is_some_and(|value| value.len() > MAX_TITLE_BYTES)
            || title
                .as_ref()
                .unwrap_or(&String::new())
                .len()
                .saturating_add(body.as_ref().unwrap_or(&String::new()).len())
                > MAX_FIELDS_BYTES
            || completion.links.len() > MAX_OUTGOING_LINKS
            || completion
                .etag
                .as_ref()
                .is_some_and(|value| value.len() > MAX_HEADER_VALUE_BYTES)
            || completion
                .last_modified
                .as_ref()
                .is_some_and(|value| value.len() > MAX_HEADER_VALUE_BYTES)
        {
            return Err(CrawlError::Capacity("outbox intent field bounds"));
        }
        let links = completion.links.join("\n");
        let payload_bytes = job
            .lease_token
            .len()
            .saturating_add(job.key.as_str().len())
            .saturating_add(job.source.id.len())
            .saturating_add(effective_url.as_ref().map_or(0, String::len))
            .saturating_add(title.as_ref().map_or(0, String::len))
            .saturating_add(body.as_ref().map_or(0, String::len))
            .saturating_add(links.len())
            .saturating_add(completion.etag.as_ref().map_or(0, String::len))
            .saturating_add(completion.last_modified.as_ref().map_or(0, String::len))
            .saturating_add(completion.state.len())
            .saturating_add(completion.reason.len());
        let current_count: i64 =
            self.db
                .conn
                .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        let current_bytes: i64 = self.db.conn.query_row(
            "SELECT COALESCE(SUM(length(CAST(url_key AS BLOB))+length(CAST(source_id AS BLOB))+length(lease_token)+length(CAST(COALESCE(effective_url,'') AS BLOB))+length(CAST(COALESCE(title,'') AS BLOB))+length(CAST(COALESCE(body,'') AS BLOB))+length(CAST(links AS BLOB))+length(CAST(COALESCE(etag,'') AS BLOB))+length(CAST(COALESCE(last_modified,'') AS BLOB))+length(CAST(completion_state AS BLOB))+length(CAST(completion_reason AS BLOB))+length(CAST(error AS BLOB))),0) FROM outbox",
            [],
            |row| row.get(0),
        )?;
        if current_count as usize >= MAX_OUTBOX_ROWS
            || (current_bytes as usize).saturating_add(payload_bytes) > MAX_OUTBOX_BYTES
        {
            return Err(CrawlError::Capacity("durable outbox rows or bytes"));
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO outbox(url_key,source_id,lease_token,kind,effective_url,title,body,links,etag,last_modified,completion_due_ms,completion_state,completion_reason,status,created_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'pending',?14)",
            params![job.key.as_str(), job.source.id, job.lease_token, kind, effective_url, title, body, links, completion.etag, completion.last_modified, completion.next_due_ms.map(|value| value as i64), completion.state, completion.reason, now as i64],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute("UPDATE frontier SET state='pending',reason='complete intent durably recorded' WHERE url_key=?1", [job.key.as_str()])?;
        FrontierDb::event(
            &tx,
            now,
            &job.source.id,
            Some(job.key.as_str()),
            "outbox_pending",
            "complete index intent committed before apply",
        )?;
        tx.commit()?;
        self.replay_outbox()?;
        Ok(id)
    }

    fn outbox_is_applied(&self, id: i64) -> Result<bool, CrawlError> {
        if id < 0 {
            return Ok(false);
        }
        Ok(self.db.conn.query_row(
            "SELECT status='applied' FROM outbox WHERE id=?1",
            [id],
            |row| row.get(0),
        )?)
    }

    fn replay_outbox(&mut self) -> Result<(), CrawlError> {
        loop {
            let pending = {
                let mut statement = self.db.conn.prepare(
                "SELECT id,url_key,source_id,lease_token,kind,effective_url,title,body,links,etag,last_modified,completion_due_ms,completion_state,completion_reason FROM outbox WHERE status='pending' ORDER BY id LIMIT 256",
            )?;
                let rows = statement.query_map([], |row| {
                    let key_text: String = row.get(1)?;
                    let key = UrlKey::parse(&key_text).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    let links: String = row.get(8)?;
                    Ok(PendingOutbox {
                        id: row.get(0)?,
                        key,
                        source_id: row.get(2)?,
                        lease_token: row.get(3)?,
                        kind: row.get(4)?,
                        effective_url: row.get(5)?,
                        title: row.get(6)?,
                        body: row.get(7)?,
                        completion: Completion {
                            state: row.get(12)?,
                            reason: row.get(13)?,
                            links: links.lines().map(str::to_owned).collect(),
                            etag: row.get(9)?,
                            last_modified: row.get(10)?,
                            next_due_ms: row.get::<_, Option<i64>>(11)?.map(|value| value as u64),
                        },
                    })
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            if pending.is_empty() {
                return Ok(());
            }
            for item in pending {
                let (lifecycle, valid_until, retention_until): (String, i64, i64) = self.db.conn.query_row(
                "SELECT lifecycle,valid_until_ms,retention_until_ms FROM source_policy WHERE source_id=?1",
                [&item.source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
                let now = self.clock.now_ms();
                if lifecycle == "active"
                    && (now >= valid_until as u64
                        || (retention_until > 0 && now >= retention_until as u64))
                {
                    self.mark_source_revoked(
                        &item.source_id,
                        "source policy expired before outbox apply",
                    )?;
                    continue;
                }
                if (lifecycle == "revoked" || lifecycle == "readmitting")
                    && !matches!(item.kind, 2 | 3)
                {
                    self.reject_outbox(&item, "source policy blocks automatic recovery")?;
                    continue;
                }
                let lease = match self.index.restore_lease(&item.lease_token) {
                    Ok(lease) => lease,
                    Err(error) => {
                        self.reject_outbox(&item, &format!("lease restore rejected: {error}"))?;
                        continue;
                    }
                };
                let intent = match item.kind {
                    0 => Intent::Upsert {
                        effective_url: item.effective_url.clone().ok_or_else(|| {
                            CrawlError::Policy("outbox upsert lacks effective URL".to_owned())
                        })?,
                        title: item.title.clone().ok_or_else(|| {
                            CrawlError::Policy("outbox upsert lacks title".to_owned())
                        })?,
                        body: item.body.clone().ok_or_else(|| {
                            CrawlError::Policy("outbox upsert lacks body".to_owned())
                        })?,
                    },
                    1 => Intent::Tombstone,
                    2 => Intent::Revoke,
                    3 => Intent::Readmit,
                    _ => {
                        return Err(CrawlError::Policy(
                            "outbox has unknown intent kind".to_owned(),
                        ));
                    }
                };
                let (lifecycle, valid_until, retention_until): (String, i64, i64) =
                    self.db.conn.query_row(
                        "SELECT lifecycle,valid_until_ms,retention_until_ms FROM source_policy WHERE source_id=?1",
                        [&item.source_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )?;
                let now = self.clock.now_ms();
                if lifecycle == "active"
                    && (now >= valid_until as u64
                        || (retention_until > 0 && now >= retention_until as u64))
                {
                    self.mark_source_revoked(
                        &item.source_id,
                        "source policy expired at index apply boundary",
                    )?;
                    continue;
                }
                if (lifecycle == "revoked" || lifecycle == "readmitting")
                    && !matches!(item.kind, 2 | 3)
                {
                    self.reject_outbox(&item, "source policy blocks automatic recovery")?;
                    continue;
                }
                match self.index.apply(&lease, intent) {
                    Ok(ApplyOutcome::Applied | ApplyOutcome::AlreadyApplied) => {
                        #[cfg(test)]
                        if std::env::var("LEY_GATE4_FAILPOINT").as_deref()
                            == Ok("after-index-apply-before-ack")
                        {
                            std::process::exit(87);
                        }
                        self.acknowledge_outbox(&item)?;
                        self.pending_replay_count += 1;
                    }
                    Err(
                        StorageError::StaleFence
                        | StorageError::ConflictingIntent
                        | StorageError::Revoked
                        | StorageError::NotRevoked,
                    ) => {
                        self.reject_outbox(
                            &item,
                            "index rejected stale, conflicting, or revoked intent",
                        )?;
                    }
                    Err(error) => return Err(CrawlError::Storage(error)),
                }
            }
        }
    }

    fn acknowledge_outbox(&mut self, item: &PendingOutbox) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let policy = if (item.kind == 0 && item.completion.state == "complete")
            || (item.kind == 1 && !item.completion.links.is_empty())
        {
            let (policy, lifecycle, _) = self.db.source(&item.source_id)?;
            (lifecycle == "active").then_some(policy)
        } else {
            None
        };
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE outbox SET status='applied' WHERE id=?1 AND status='pending'",
            [item.id],
        )?;
        match item.kind {
            0 | 1 => {
                tx.execute(
                    "UPDATE frontier SET state=?2,fetch_url=url_key,due_ms=COALESCE(?3,due_ms),reason=?4,etag=?5,last_modified=?6,not_found_count=0,lease_token=NULL,schedule_id=NULL,attempts=0,redirect_count=0,redirect_seen=url_key,unconditional=0 WHERE url_key=?1",
                    params![item.key.as_str(), item.completion.state, item.completion.next_due_ms.map(|value| value as i64), item.completion.reason, item.completion.etag, item.completion.last_modified],
                )?;
                if let Some(policy) = policy.as_ref()
                    && !item.completion.links.is_empty()
                {
                    self.pending_link_discovery
                        .merge(Self::enqueue_outbox_links(
                            &tx,
                            item,
                            policy,
                            &self.fetcher,
                            now,
                        )?);
                }
            }
            2 => {
                tx.execute(
                    "UPDATE frontier SET state='blocked',reason='source revoked',revocation_published=1,lease_token=NULL,schedule_id=NULL WHERE url_key=?1",
                    [item.key.as_str()],
                )?;
            }
            3 => {
                tx.execute(
                    "UPDATE frontier SET state='blocked',readmitted=1,lease_token=NULL,schedule_id=NULL,reason='explicit source readmission published' WHERE url_key=?1",
                    [item.key.as_str()],
                )?;
            }
            _ => return Err(CrawlError::Policy("unknown outbox kind".to_owned())),
        }
        FrontierDb::event(
            &tx,
            now,
            &item.source_id,
            Some(item.key.as_str()),
            "outbox_applied",
            "index returned Applied or exact AlreadyApplied",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn enqueue_outbox_links(
        tx: &Transaction<'_>,
        item: &PendingOutbox,
        policy: &SourcePolicy,
        fetcher: &SafeFetcher<R>,
        now: u64,
    ) -> Result<LinkDiscoveryCounts, CrawlError> {
        let mut count: i64 = tx.query_row("SELECT COUNT(*) FROM frontier", [], |row| row.get(0))?;
        let mut outcomes = LinkDiscoveryCounts::default();
        for (index, raw) in item.completion.links.iter().enumerate() {
            if count as usize >= MAX_FRONTIER_ENTRIES {
                outcomes.capacity = outcomes
                    .capacity
                    .saturating_add(item.completion.links.len().saturating_sub(index));
                break;
            }
            let Ok(url) = Url::parse(raw) else {
                outcomes.malformed = outcomes.malformed.saturating_add(1);
                continue;
            };
            let Ok(key) = UrlKey::parse(raw) else {
                outcomes.malformed = outcomes.malformed.saturating_add(1);
                continue;
            };
            if !policy.allows_url(&url, now) || !fetcher.has_capability(&url) {
                outcomes.source_denied = outcomes.source_denied.saturating_add(1);
                continue;
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO frontier(url_key,source_id,fetch_url,state,due_ms,redirect_seen,queued_sequence) VALUES (?1,?2,?1,'ready',?3,?1,?3)",
                params![key.as_str(), item.source_id, now as i64],
            )?;
            if inserted == 0 {
                outcomes.duplicates = outcomes.duplicates.saturating_add(1);
            } else {
                count += inserted as i64;
                outcomes.enqueued = outcomes.enqueued.saturating_add(1);
            }
        }
        if outcomes.candidates() > 0 {
            FrontierDb::event(
                tx,
                now,
                &item.source_id,
                Some(item.key.as_str()),
                "link_discovery",
                &format!(
                    "enqueued={}; source_denied={}; duplicate={}; malformed={}; capacity={}",
                    outcomes.enqueued,
                    outcomes.source_denied,
                    outcomes.duplicates,
                    outcomes.malformed,
                    outcomes.capacity,
                ),
            )?;
        }
        Ok(outcomes)
    }

    fn reject_outbox(&mut self, item: &PendingOutbox, reason: &str) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE outbox SET status='rejected',error=?2 WHERE id=?1 AND status='pending'",
            params![item.id, reason],
        )?;
        tx.execute(
            "UPDATE frontier SET state='failed',reason=?2,lease_token=NULL,schedule_id=NULL WHERE url_key=?1",
            params![item.key.as_str(), reason],
        )?;
        FrontierDb::event(
            &tx,
            now,
            &item.source_id,
            Some(item.key.as_str()),
            "outbox_rejected",
            reason,
        )?;
        tx.commit()?;
        self.pending_rejected_count = self.pending_rejected_count.saturating_add(1);
        Ok(())
    }

    fn reconcile_controls(&mut self) -> Result<(), CrawlError> {
        loop {
            let before: i64 = self.db.conn.query_row(
                "SELECT (SELECT COUNT(*) FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='revoked' AND f.revocation_published=0) + (SELECT COUNT(*) FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='readmitting' AND f.readmitted=0)",
                [],
                |row| row.get(0),
            )?;
            self.finish_revocations()?;
            self.finish_readmissions()?;
            self.replay_outbox()?;
            self.finish_readmissions()?;
            let rejected: i64 = self.db.conn.query_row(
                "SELECT COUNT(*) FROM outbox o JOIN frontier f ON f.url_key=o.url_key WHERE o.status='rejected' AND ((o.kind=2 AND f.revocation_published=0) OR (o.kind=3 AND f.readmitted=0))",
                [],
                |row| row.get(0),
            )?;
            if rejected > 0 {
                return Err(CrawlError::Policy(
                    "a source control intent was rejected by the index".to_owned(),
                ));
            }
            let after: i64 = self.db.conn.query_row(
                "SELECT (SELECT COUNT(*) FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='revoked' AND f.revocation_published=0) + (SELECT COUNT(*) FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='readmitting' AND f.readmitted=0)",
                [],
                |row| row.get(0),
            )?;
            if after == 0 {
                return Ok(());
            }
            if before > 0 && after >= before {
                return Err(CrawlError::Policy(
                    "source control reconciliation made no progress".to_owned(),
                ));
            }
        }
    }

    fn finish_revocations(&mut self) -> Result<(), CrawlError> {
        let rows = {
            let mut statement = self.db.conn.prepare(
                "SELECT f.url_key,f.source_id FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='revoked' AND f.revocation_published=0 AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.url_key=f.url_key AND o.kind=2 AND o.status='pending') ORDER BY f.url_key LIMIT ?1",
            )?;
            let values = statement.query_map([CONTROL_BATCH_SIZE as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            values.collect::<Result<Vec<_>, _>>()?
        };
        for (key_text, source_id) in rows {
            let key =
                UrlKey::parse(&key_text).map_err(|error| CrawlError::Url(error.to_string()))?;
            let lease = self.index.issue_fence(&key)?;
            let token = self.index.export_lease(&lease)?;
            self.persist_control_outbox(&key, &source_id, token, 2, "source revocation tombstone")?;
        }
        Ok(())
    }

    fn finish_readmissions(&mut self) -> Result<(), CrawlError> {
        let rows = {
            let mut statement = self.db.conn.prepare(
                "SELECT f.url_key,f.source_id FROM frontier f JOIN source_policy s ON s.source_id=f.source_id WHERE s.lifecycle='readmitting' AND f.readmitted=0 AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.url_key=f.url_key AND o.kind=3 AND o.status='pending') ORDER BY f.url_key LIMIT ?1",
            )?;
            let values = statement.query_map([CONTROL_BATCH_SIZE as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            values.collect::<Result<Vec<_>, _>>()?
        };
        for (key_text, source_id) in rows {
            let key =
                UrlKey::parse(&key_text).map_err(|error| CrawlError::Url(error.to_string()))?;
            let lease = self.index.issue_fence(&key)?;
            let token = self.index.export_lease(&lease)?;
            self.persist_control_outbox(&key, &source_id, token, 3, "explicit source readmission")?;
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE source_policy SET lifecycle='active' WHERE lifecycle='readmitting' AND NOT EXISTS (SELECT 1 FROM frontier f WHERE f.source_id=source_policy.source_id AND f.readmitted=0)",
            [],
        )?;
        let now = self.clock.now_ms();
        tx.execute(
            "UPDATE frontier SET state='ready',due_ms=?1,reason='explicitly readmitted; eligible for a new scheduled fetch' WHERE readmitted=1 AND source_id IN (SELECT source_id FROM source_policy WHERE lifecycle='active') AND state='blocked' AND reason LIKE 'explicit source readmission%'",
            [now as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn persist_control_outbox(
        &mut self,
        key: &UrlKey,
        source_id: &str,
        token: Vec<u8>,
        kind: i64,
        reason: &str,
    ) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        let mut bytes: i64 = tx.query_row(
            "SELECT COALESCE(SUM(length(CAST(url_key AS BLOB))+length(CAST(source_id AS BLOB))+length(lease_token)+length(CAST(COALESCE(effective_url,'') AS BLOB))+length(CAST(COALESCE(title,'') AS BLOB))+length(CAST(COALESCE(body,'') AS BLOB))+length(CAST(links AS BLOB))+length(CAST(COALESCE(etag,'') AS BLOB))+length(CAST(COALESCE(last_modified,'') AS BLOB))+length(CAST(completion_state AS BLOB))+length(CAST(completion_reason AS BLOB))+length(CAST(error AS BLOB))),0) FROM outbox",
            [],
            |row| row.get(0),
        )?;
        let payload_bytes = token
            .len()
            .saturating_add(key.as_str().len())
            .saturating_add(source_id.len())
            .saturating_add("blocked".len())
            .saturating_add(reason.len());
        let mut count = count;
        while count as usize >= MAX_OUTBOX_ROWS
            || (bytes as usize).saturating_add(payload_bytes) > MAX_OUTBOX_BYTES
        {
            let removed = tx.execute(
                "DELETE FROM outbox WHERE id=(SELECT id FROM outbox WHERE status!='pending' ORDER BY id LIMIT 1)",
                [],
            )?;
            if removed == 0 {
                return Err(CrawlError::Capacity("durable control outbox rows or bytes"));
            }
            count -= 1;
            bytes = tx.query_row(
                "SELECT COALESCE(SUM(length(CAST(url_key AS BLOB))+length(CAST(source_id AS BLOB))+length(lease_token)+length(CAST(COALESCE(effective_url,'') AS BLOB))+length(CAST(COALESCE(title,'') AS BLOB))+length(CAST(COALESCE(body,'') AS BLOB))+length(CAST(links AS BLOB))+length(CAST(COALESCE(etag,'') AS BLOB))+length(CAST(COALESCE(last_modified,'') AS BLOB))+length(CAST(completion_state AS BLOB))+length(CAST(completion_reason AS BLOB))+length(CAST(error AS BLOB))),0) FROM outbox",
                [],
                |row| row.get(0),
            )?;
        }
        tx.execute(
            "INSERT INTO outbox(url_key,source_id,lease_token,kind,completion_state,completion_reason,status,created_ms) VALUES (?1,?2,?3,?4,'blocked',?5,'pending',?6)",
            params![key.as_str(), source_id, token, kind, reason, now as i64],
        )?;
        tx.execute(
            "UPDATE frontier SET state='pending',reason=?2,lease_token=?3 WHERE url_key=?1",
            params![key.as_str(), reason, token],
        )?;
        FrontierDb::event(
            &tx,
            now,
            source_id,
            Some(key.as_str()),
            if kind == 2 {
                "revoke_pending"
            } else {
                "readmit_pending"
            },
            "durable control intent before index publication",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn recover_abandoned_fetches(&mut self) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let tx = self.db.transaction()?;
        let abandoned_pages = {
            let mut statement = tx.prepare(
                "SELECT f.fetch_url,s.min_origin_delay_ms FROM frontier f LEFT JOIN source_policy s ON s.source_id=f.source_id WHERE f.state='inflight'",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (fetch_url, stored_delay) in abandoned_pages {
            let delay = stored_delay
                .and_then(|value| u64::try_from(value).ok())
                .ok_or_else(|| {
                    CrawlError::Policy("inflight page has invalid source delay".to_owned())
                })?
                .min(MAX_RETRY_MS);
            let url = Url::parse(&fetch_url).map_err(|error| CrawlError::Url(error.to_string()))?;
            let origin = origin_of_url(&url);
            tx.execute(
                "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,?2,0,0) ON CONFLICT(origin) DO UPDATE SET next_request_ms=MAX(next_request_ms,excluded.next_request_ms)",
                params![origin, now.saturating_add(delay) as i64],
            )?;
        }
        let abandoned_robots = {
            let mut statement = tx.prepare(
                "SELECT origins,min_origin_delay_ms FROM robots_inflight ORDER BY candidate_key",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (origins, stored_delay) in abandoned_robots {
            let delay = u64::try_from(stored_delay)
                .map_err(|_| {
                    CrawlError::Policy("robots marker has invalid origin delay".to_owned())
                })?
                .min(MAX_RETRY_MS);
            let origins: Vec<&str> = origins.lines().collect();
            if origins.is_empty() || origins.len() > MAX_ORIGINS {
                return Err(CrawlError::Policy(
                    "robots marker has an invalid admitted-origin snapshot".to_owned(),
                ));
            }
            for origin in origins {
                let url = Url::parse(origin).map_err(|error| CrawlError::Url(error.to_string()))?;
                if origin_of_url(&url) != origin
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                {
                    return Err(CrawlError::Policy(
                        "robots marker contains a non-canonical origin".to_owned(),
                    ));
                }
                tx.execute(
                    "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,?2,0,0) ON CONFLICT(origin) DO UPDATE SET next_request_ms=MAX(next_request_ms,excluded.next_request_ms)",
                    params![origin, now.saturating_add(delay) as i64],
                )?;
            }
        }
        tx.execute(
            "UPDATE frontier SET state='ready',fetch_url=url_key,schedule_id=NULL,lease_token=NULL,attempts=0,redirect_count=0,redirect_seen=url_key,reason='recovered abandoned network lease; replacement gets a higher index fence' WHERE state='inflight'",
            [],
        )?;
        tx.execute("DELETE FROM robots_inflight", [])?;
        FrontierDb::event(
            &tx,
            now,
            "",
            None,
            "recovery",
            "abandoned network leases will be reissued with a higher fence",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn accept_robots(
        &mut self,
        job: RobotsJob,
        result: RobotsWorkerSuccess,
        _report: &mut CrawlReport,
    ) -> Result<(), CrawlError> {
        parse_robots(&result.body).map_err(|error| {
            CrawlError::Transport(format!("robots parser rejected body: {error}"))
        })?;
        let now = self.clock.now_ms();
        let (expires_ms, no_cache, no_store) =
            robots_expiry(&result.response_headers, now, result.no_store);
        let etag = single_header_values(&result.response_headers, "etag")?;
        let last_modified = single_header_values(&result.response_headers, "last-modified")?;
        let cache = RobotCache {
            body: result.body.clone(),
            expires_ms,
            etag: etag.or_else(|| job.cached.as_ref().and_then(|cache| cache.etag.clone())),
            last_modified: last_modified.or_else(|| {
                job.cached
                    .as_ref()
                    .and_then(|cache| cache.last_modified.clone())
            }),
        };

        if no_store {
            self.db
                .conn
                .execute("DELETE FROM robots_cache WHERE origin=?1", [&job.origin])?;
            let one_shot_cache = RobotCache {
                expires_ms: now,
                ..cache
            };
            self.one_shot_robots
                .insert(job.candidate_key.clone(), one_shot_cache);
        } else {
            let stored_bytes: i64 = self.db.conn.query_row(
                "SELECT COALESCE(SUM(length(body)),0) FROM robots_cache WHERE body IS NOT NULL AND origin!=?1",
                [&job.origin],
                |row| row.get(0),
            )?;
            if (stored_bytes as usize).saturating_add(result.body.len()) > MAX_ROBOTS_STORE_BYTES {
                return Err(CrawlError::Capacity("persistent robots cache bytes"));
            }
            self.db.conn.execute(
                "INSERT INTO robots_cache(origin,body,expires_ms,denied_retry_ms,etag,last_modified,reason) VALUES (?1,?2,?3,0,?4,?5,'') ON CONFLICT(origin) DO UPDATE SET body=excluded.body,expires_ms=excluded.expires_ms,denied_retry_ms=0,etag=excluded.etag,last_modified=excluded.last_modified,reason=''",
                params![job.origin, result.body, if no_cache { now as i64 } else { cache.expires_ms as i64 }, cache.etag, cache.last_modified],
            )?;
            if no_cache {
                let one_shot_cache = RobotCache {
                    expires_ms: now,
                    ..cache
                };
                self.one_shot_robots
                    .insert(job.candidate_key.clone(), one_shot_cache);
            }
        }
        let tx = self.db.transaction()?;
        for origin in result.visited_origins {
            tx.execute(
                "UPDATE origin_state SET backoff_until_ms=0,failures=0 WHERE origin=?1",
                [origin],
            )?;
        }
        FrontierDb::event(
            &tx,
            now,
            &job.source.id,
            None,
            "robots_cached",
            "fresh rules cached by original requesting authority",
        )?;
        tx.commit()?;
        Ok(())
    }

    fn reject_robots(
        &mut self,
        job: RobotsJob,
        failure: RobotsWorkerFailure,
        report: &mut CrawlReport,
    ) -> Result<(), CrawlError> {
        report.skipped(failure.reason.clone());
        report.failure(&failure.reason);
        let now = self.clock.now_ms();
        let (_, backoff, failures) = self.origin_state(&job.origin)?;
        let failure_count = failures.saturating_add(1).min(16);
        let exp = DEFAULT_RETRY_MS
            .saturating_mul(1u64 << (failure_count as u32).min(16))
            .min(MAX_RETRY_MS);
        let retry = failure
            .retry_after_ms
            .unwrap_or(0)
            .max(now.saturating_add(exp))
            .min(now.saturating_add(MAX_RETRY_MS));
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO robots_cache(origin,body,expires_ms,denied_retry_ms,etag,last_modified,reason) VALUES (?1,NULL,0,?2,NULL,NULL,?3) ON CONFLICT(origin) DO UPDATE SET body=NULL,expires_ms=0,denied_retry_ms=excluded.denied_retry_ms,etag=NULL,last_modified=NULL,reason=excluded.reason",
            params![job.origin, retry as i64, failure.reason],
        )?;
        tx.execute(
            "UPDATE origin_state SET backoff_until_ms=MAX(backoff_until_ms,?2),failures=?3 WHERE origin=?1",
            params![job.origin, backoff.max(retry) as i64, failure_count as i64],
        )?;
        FrontierDb::event(
            &tx,
            now,
            &job.source.id,
            None,
            "robots_denied",
            &failure.reason,
        )?;
        tx.commit()?;
        Ok(())
    }

    fn set_robot_denied(
        &mut self,
        origin: &str,
        now: u64,
        retry_ms: u64,
        reason: &str,
    ) -> Result<(), CrawlError> {
        self.db.conn.execute(
            "INSERT INTO robots_cache(origin,body,expires_ms,denied_retry_ms,etag,last_modified,reason) VALUES (?1,NULL,0,?2,NULL,NULL,?3) ON CONFLICT(origin) DO UPDATE SET body=NULL,expires_ms=0,denied_retry_ms=excluded.denied_retry_ms,etag=NULL,last_modified=NULL,reason=excluded.reason",
            params![origin, retry_ms as i64, reason],
        )?;
        let tx = self.db.transaction()?;
        FrontierDb::event(&tx, now, "", None, "robots_unavailable", reason)?;
        tx.commit()?;
        Ok(())
    }

    fn expire_due_sources(&mut self) -> Result<(), CrawlError> {
        let now = self.clock.now_ms();
        let expired = {
            let mut statement = self.db.conn.prepare(
                "SELECT source_id FROM source_policy WHERE lifecycle='active' AND (valid_until_ms<=?1 OR (retention_until_ms>0 AND retention_until_ms<=?1)) ORDER BY source_id",
            )?;
            let rows = statement.query_map([now as i64], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for source_id in expired {
            self.mark_source_revoked(&source_id, "source policy expired")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::crawler::{FixtureResponse, LocalFixture};
    use crate::index::InMemoryIndex;
    use crate::query::parse_query;
    use crate::safe_fetch::DestinationResolver;

    #[derive(Clone)]
    struct SequenceResolver {
        answers: Arc<Vec<std::net::SocketAddr>>,
        next: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl SequenceResolver {
        fn new(answers: Vec<std::net::SocketAddr>) -> Self {
            Self {
                answers: Arc::new(answers),
                next: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    impl DestinationResolver for SequenceResolver {
        fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            let answer = self
                .answers
                .get(index)
                .or_else(|| self.answers.last())
                .copied()
                .ok_or_else(|| std::io::Error::other("sequence has no DNS answers"))?;
            Ok(vec![answer])
        }
    }

    #[derive(Clone)]
    struct AnswerSetResolver {
        answers: Arc<Vec<Vec<std::net::SocketAddr>>>,
        next: Arc<std::sync::atomic::AtomicUsize>,
        delayed_call: Option<(usize, Duration)>,
        observations: Arc<Mutex<Vec<(usize, Instant, Instant)>>>,
    }

    impl AnswerSetResolver {
        fn new(answers: Vec<Vec<std::net::SocketAddr>>) -> Self {
            Self {
                answers: Arc::new(answers),
                next: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                delayed_call: None,
                observations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn delay_call(mut self, call: usize, delay: Duration) -> Self {
            self.delayed_call = Some((call, delay));
            self
        }
    }

    impl DestinationResolver for AnswerSetResolver {
        fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            let started = Instant::now();
            if let Some((delayed_call, delay)) = self.delayed_call
                && index == delayed_call
            {
                thread::sleep(delay);
            }
            self.observations
                .lock()
                .unwrap()
                .push((index, started, Instant::now()));
            self.answers
                .get(index)
                .or_else(|| self.answers.last())
                .cloned()
                .ok_or_else(|| std::io::Error::other("DNS fixture has no answer sets"))
        }
    }

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ley-gate4-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create unique test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct ManualClock(Arc<std::sync::atomic::AtomicU64>);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(Arc::new(std::sync::atomic::AtomicU64::new(now_ms)))
        }

        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    struct FixtureResolver(Arc<BTreeMap<String, Vec<std::net::SocketAddr>>>);

    impl DestinationResolver for FixtureResolver {
        fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<std::net::SocketAddr>> {
            self.0
                .get(&host.to_ascii_lowercase())
                .map(|answers| {
                    answers
                        .iter()
                        .copied()
                        .filter(|answer| answer.port() == port)
                        .collect()
                })
                .filter(|answers: &Vec<std::net::SocketAddr>| !answers.is_empty())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unmapped test fixture"))
        }
    }

    fn policy(fixture: &LocalFixture, id: &str, now: u64) -> SourcePolicy {
        SourcePolicy::owned_fixture(
            id,
            vec![fixture.base_url().origin().ascii_serialization()],
            vec!["/".to_owned()],
            now.saturating_add(7 * 24 * 60 * 60 * 1000),
        )
    }

    fn fixture_seed(fixture: &LocalFixture, path: &str) -> UrlKey {
        UrlKey::parse(fixture.base_url().join(path).unwrap().as_str()).unwrap()
    }

    fn not_found_count<R: DestinationResolver + 'static, C: Clock + 'static>(
        crawler: &ControlledCrawler<R, C>,
        key: &UrlKey,
    ) -> i64 {
        crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [key.as_str()],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn assert_reference_parity(index: &PersistentIndex, urls: &[String], expression: &str) {
        let view = index.read_view().unwrap();
        let mut reference = InMemoryIndex::new();
        for url in urls {
            let key = UrlKey::parse(url).unwrap();
            if let Some(document) = view.document(&key) {
                reference
                    .insert_fields(
                        document.id,
                        document.effective_url,
                        document.title,
                        document.body,
                    )
                    .unwrap();
            }
        }
        let parsed = parse_query(expression).unwrap();
        let expected = crate::reference::exhaustive_search(&reference, &parsed);
        let actual = view.query(expression).unwrap();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.id, expected.id);
            assert!((actual.score - expected.score).abs() <= 1e-12);
        }
    }

    fn open_fixture_crawler(
        path: &Path,
        index: Arc<PersistentIndex>,
        fixture: &LocalFixture,
        clock: ManualClock,
    ) -> ControlledCrawler<SystemResolver, ManualClock> {
        ControlledCrawler::open(
            path,
            index,
            SystemResolver,
            vec![fixture.capability()],
            CrawlLimits::default(),
            clock,
        )
        .unwrap()
    }

    struct PublicTlsSourceSpec {
        id: &'static str,
        seed_path: &'static str,
        max_requests: u64,
        min_origin_delay_ms: u64,
    }

    fn open_public_tls_crawler(
        temp: &TestDir,
        fixture: &crate::safe_fetch::tls_test_support::Fixture,
        answers: Vec<Vec<std::net::SocketAddr>>,
        limits: CrawlLimits,
        source: PublicTlsSourceSpec,
    ) -> (
        Arc<PersistentIndex>,
        ControlledCrawler<AnswerSetResolver, SystemClock>,
    ) {
        let origin = format!("https://public.example.org:{}", fixture.address.port());
        open_public_tls_crawler_at_origin(temp, fixture, answers, limits, source, origin)
    }

    fn open_public_tls_crawler_at_origin(
        temp: &TestDir,
        fixture: &crate::safe_fetch::tls_test_support::Fixture,
        answers: Vec<Vec<std::net::SocketAddr>>,
        limits: CrawlLimits,
        source: PublicTlsSourceSpec,
        origin: String,
    ) -> (
        Arc<PersistentIndex>,
        ControlledCrawler<AnswerSetResolver, SystemClock>,
    ) {
        open_public_tls_crawler_at_origin_with_resolver(
            temp,
            fixture,
            AnswerSetResolver::new(answers),
            limits,
            source,
            origin,
        )
    }

    fn open_public_tls_crawler_at_origin_with_resolver(
        temp: &TestDir,
        fixture: &crate::safe_fetch::tls_test_support::Fixture,
        resolver: AnswerSetResolver,
        limits: CrawlLimits,
        source: PublicTlsSourceSpec,
        origin: String,
    ) -> (
        Arc<PersistentIndex>,
        ControlledCrawler<AnswerSetResolver, SystemClock>,
    ) {
        let origin_url = Url::parse(&format!("{origin}/")).unwrap();
        let canonical_origin = origin_of_url(&origin_url);
        let authority = crate::safe_fetch::PublicAuthority::from_origin(&origin_url)
            .unwrap()
            .with_crawler_identity(
                concat!("LeyBot/", env!("CARGO_PKG_VERSION")),
                "https://github.com/Suraj-H675/Ley/issues",
            );
        let now = SystemClock.now_ms();
        let policy = SourcePolicy::public(PublicSourceAdmission {
            id: source.id.to_owned(),
            origins: vec![canonical_origin],
            allowed_path_prefixes: vec!["/".to_owned()],
            policy_sha256: "a".repeat(64),
            crawl_contact: "https://github.com/Suraj-H675/Ley/issues".to_owned(),
            valid_until_ms: now.saturating_add(60_000),
            retention: RetentionPolicy::Until(now.saturating_add(60_000)),
            max_requests: source.max_requests,
            min_origin_delay_ms: source.min_origin_delay_ms,
        });
        let index = Arc::new(
            PersistentIndex::create(temp.path().join(format!("{}-index", source.id))).unwrap(),
        );
        let frontier_path = temp.path().join(format!("{}-frontier.sqlite", source.id));
        let mut crawler = ControlledCrawler::open_with_public(
            &frontier_path,
            Arc::clone(&index),
            resolver,
            Vec::new(),
            vec![authority],
            limits,
            SystemClock,
        )
        .unwrap();
        Arc::get_mut(&mut crawler.fetcher)
            .unwrap()
            .set_test_public_tls(
                "public.example.org",
                fixture.address,
                fixture.root_certificate_pem(),
            );
        let seed = UrlKey::parse(&format!("{}{}", origin, source.seed_path)).unwrap();
        crawler.admit_source(policy, &[seed]).unwrap();
        (index, crawler)
    }

    #[test]
    fn public_crawl_spacing_does_not_expire_during_dns_resolution() {
        let host = "public.example.org";
        let fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>First page</title><a href=\"/second\">Second</a>",
                    ),
                ),
                (
                    "/second".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Second page</title>",
                    ),
                ),
            ]),
        );
        let temp = TestDir::new();
        let origin = format!("https://{host}");
        let resolver = AnswerSetResolver::new(vec![vec![fixture.address]])
            .delay_call(1, Duration::from_millis(400));
        let observed_resolver = resolver.clone();
        let (index, mut crawler) = open_public_tls_crawler_at_origin_with_resolver(
            &temp,
            &fixture,
            resolver,
            CrawlLimits::default(),
            PublicTlsSourceSpec {
                id: "tls-delayed-resolver-spacing",
                seed_path: "/page",
                max_requests: 6,
                min_origin_delay_ms: 200,
            },
            origin,
        );

        let result = run_bounded_crawl(
            &mut crawler,
            6,
            12 * MAX_COMPRESSED_RESPONSE_BYTES,
            32 * MAX_DECODED_RESPONSE_BYTES,
            Duration::from_secs(5),
        )
        .unwrap();

        assert_eq!(result.report.requests, 3);
        assert_eq!(result.report.pages_fetched, 2);
        assert_eq!(index.query("First OR Second").unwrap().len(), 2);
        let resolutions = observed_resolver.observations.lock().unwrap().clone();
        assert_eq!(resolutions.len(), 3);
        assert_eq!(resolutions[1].0, 1);
        assert!(
            resolutions[1].2.duration_since(resolutions[1].1) >= Duration::from_millis(400),
            "the page resolver call must consume the configured 400ms delay"
        );
        let inflight_robots: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM robots_inflight", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            inflight_robots, 0,
            "completed robots work clears its marker"
        );
        let starts = fixture.request_starts();
        assert_eq!(starts.len(), 3);
        let page_to_second = starts[2].duration_since(starts[1]);
        eprintln!(
            "resolver_delay={:?}; server_arrival_gap={page_to_second:?}; configured_delay=200ms",
            resolutions[1].2.duration_since(resolutions[1].1)
        );
        assert!(
            page_to_second >= Duration::from_millis(180),
            "server saw /page then /second after {page_to_second:?}; min_origin_delay_ms is 200"
        );
    }

    #[test]
    fn bounded_public_crawl_waits_for_default_port_origin_and_fetches_linked_pages() {
        let host = "public.example.org";
        let fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>First page</title><p>first marker</p><a href=\"/second\">Second</a>",
                    ),
                ),
                (
                    "/second".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Second page</title><p>second marker</p>",
                    ),
                ),
            ]),
        );
        let temp = TestDir::new();
        let origin = format!("https://{host}");
        let (index, mut crawler) = open_public_tls_crawler_at_origin(
            &temp,
            &fixture,
            vec![vec![fixture.address]],
            CrawlLimits::default(),
            PublicTlsSourceSpec {
                id: "tls-default-port-scheduler",
                seed_path: "/page",
                max_requests: 6,
                min_origin_delay_ms: 80,
            },
            origin,
        );

        let result = run_bounded_crawl(
            &mut crawler,
            6,
            12 * MAX_COMPRESSED_RESPONSE_BYTES,
            32 * MAX_DECODED_RESPONSE_BYTES,
            Duration::from_secs(4),
        )
        .unwrap();
        let report = result.report;

        assert_eq!(report.requests, 3);
        assert_eq!(report.pages_fetched, 2);
        assert_eq!(report.indexed, 2);
        assert_eq!(
            index.query("first marker OR second marker").unwrap().len(),
            2
        );
        assert_eq!(fixture.requests(), ["/robots.txt", "/page", "/second"]);
        let starts = fixture.request_starts();
        assert_eq!(starts.len(), 3);
        assert!(starts[1].duration_since(starts[0]) >= Duration::from_millis(60));
        assert!(starts[2].duration_since(starts[1]) >= Duration::from_millis(60));
        assert_eq!(result.stop_reason, BoundedStopReason::FrontierIdle);

        let budget_fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Budget page</title><a href=\"/second\">Second</a>",
                    ),
                ),
                (
                    "/second".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Over budget</title>",
                    ),
                ),
            ]),
        );
        let (index, mut budget_crawler) = open_public_tls_crawler_at_origin(
            &temp,
            &budget_fixture,
            vec![vec![budget_fixture.address]],
            CrawlLimits::default(),
            PublicTlsSourceSpec {
                id: "tls-default-port-request-budget",
                seed_path: "/page",
                max_requests: 6,
                min_origin_delay_ms: 80,
            },
            format!("https://{host}"),
        );
        let budget_result = run_bounded_crawl(
            &mut budget_crawler,
            2,
            12 * MAX_COMPRESSED_RESPONSE_BYTES,
            32 * MAX_DECODED_RESPONSE_BYTES,
            Duration::from_secs(4),
        )
        .unwrap();
        assert_eq!(budget_result.report.requests, 2);
        assert_eq!(budget_result.stop_reason, BoundedStopReason::RequestBudget);
        assert_eq!(budget_fixture.requests(), ["/robots.txt", "/page"]);
        assert_eq!(index.query("budget page").unwrap().len(), 1);
    }

    #[test]
    fn bounded_dispatch_eligibility_waits_for_origin_backoff_and_robots_retry() {
        let fixture = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
        )])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            index,
            &fixture,
            clock.clone(),
        );
        let source = policy(&fixture, "scheduler-backoff", clock.now_ms());
        let seed = fixture_seed(&fixture, "/page");
        crawler
            .admit_source(source, std::slice::from_ref(&seed))
            .unwrap();
        let origin = origin_of_url(&Url::parse(seed.as_str()).unwrap());
        crawler
            .db
            .conn
            .execute(
                "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,12_000,15_000,2)",
                [&origin],
            )
            .unwrap();

        assert_eq!(
            crawler.next_dispatch_eligibility(clock.now_ms()).unwrap(),
            DispatchEligibility::At(15_000)
        );
        crawler
            .db
            .conn
            .execute(
                "INSERT INTO robots_cache(origin,body,expires_ms,denied_retry_ms,reason) VALUES (?1,NULL,0,17_000,'robots retry fixture')",
                [&origin],
            )
            .unwrap();
        assert_eq!(
            crawler.next_dispatch_eligibility(clock.now_ms()).unwrap(),
            DispatchEligibility::At(17_000)
        );
        crawler
            .db
            .conn
            .execute(
                "UPDATE frontier SET state='complete',due_ms=10_000 WHERE url_key=?1",
                [seed.as_str()],
            )
            .unwrap();
        assert_eq!(
            crawler.next_dispatch_eligibility(clock.now_ms()).unwrap(),
            DispatchEligibility::At(17_000)
        );
        crawler
            .db
            .conn
            .execute(
                "UPDATE source_policy SET valid_until_ms=16_000 WHERE source_id='scheduler-backoff'",
                [],
            )
            .unwrap();
        assert_eq!(
            crawler.next_dispatch_eligibility(clock.now_ms()).unwrap(),
            DispatchEligibility::SourceDeadline
        );
        crawler
            .db
            .conn
            .execute(
                "UPDATE source_policy SET request_count=max_requests WHERE source_id='scheduler-backoff'",
                [],
            )
            .unwrap();
        assert_eq!(
            crawler.next_dispatch_eligibility(clock.now_ms()).unwrap(),
            DispatchEligibility::SourceBudget
        );
    }

    #[test]
    fn origin_politeness_deferral_preserves_later_retry_cooldown() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/a-retry".to_owned(),
                FixtureResponse::text("retry candidate"),
            ),
            (
                "/z-current".to_owned(),
                FixtureResponse::text("current candidate"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let limits = CrawlLimits {
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            index,
            SystemResolver,
            vec![fixture.capability()],
            limits,
            clock.clone(),
        )
        .unwrap();
        let mut source = policy(&fixture, "origin-deferral-cooldown", clock.now_ms());
        source.min_origin_delay_ms = 1_000;
        let retry_key = fixture_seed(&fixture, "/a-retry");
        let current_key = fixture_seed(&fixture, "/z-current");
        crawler
            .admit_source(source, &[retry_key.clone(), current_key.clone()])
            .unwrap();
        let origin = origin_of_url(&Url::parse(retry_key.as_str()).unwrap());
        crawler
            .db
            .conn
            .execute(
                "INSERT INTO robots_cache(origin,body,expires_ms,denied_retry_ms,reason) VALUES (?1,?2,?3,0,'')",
                params![origin, b"User-agent: LeyBot\nAllow: /\n".as_slice(), (clock.now_ms() + 2 * MAX_RETRY_MS) as i64],
            )
            .unwrap();

        let mut report = CrawlReport::default();
        let active_by_origin = HashMap::new();
        let active_origins = HashSet::new();
        let Some(WorkerJob::Page(retry_job)) = crawler
            .next_job(&mut report, 0, 0, 1, &active_by_origin, &active_origins)
            .unwrap()
        else {
            panic!("the first admitted page should be dispatched");
        };
        assert_eq!(retry_job.url.path(), "/a-retry");
        crawler
            .retry_page(
                &retry_job,
                "transport retry limit reached",
                None,
                false,
                &mut report,
            )
            .unwrap();
        let retry_due_ms = clock.now_ms() + MAX_RETRY_MS;

        assert!(
            crawler
                .next_job(&mut report, 1, 0, 1, &active_by_origin, &active_origins,)
                .unwrap()
                .is_none()
        );
        let retry_row = crawler
            .db
            .conn
            .query_row(
                "SELECT state,due_ms,reason,attempts FROM frontier WHERE url_key=?1",
                [retry_key.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            retry_row,
            (
                "deferred".to_owned(),
                retry_due_ms as i64,
                "transport retry limit reached".to_owned(),
                0,
            )
        );
        let current_row = crawler
            .db
            .conn
            .query_row(
                "SELECT state,due_ms,reason FROM frontier WHERE url_key=?1",
                [current_key.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            current_row,
            (
                "deferred".to_owned(),
                (clock.now_ms() + 1_000) as i64,
                "politeness or backoff delay".to_owned(),
            )
        );

        clock.set(clock.now_ms() + 1_000);
        let Some(WorkerJob::Page(current_job)) = crawler
            .next_job(&mut report, 1, 0, 1, &active_by_origin, &active_origins)
            .unwrap()
        else {
            panic!("the postponed current page should be dispatched");
        };
        assert_eq!(current_job.url.path(), "/z-current");

        clock.set(retry_due_ms);
        let Some(WorkerJob::Page(eligible_retry)) = crawler
            .next_job(&mut report, 2, 0, 1, &active_by_origin, &active_origins)
            .unwrap()
        else {
            panic!("the retry should become dispatchable at its cooldown deadline");
        };
        assert_eq!(eligible_retry.url.path(), "/a-retry");
    }

    #[test]
    fn public_tls_crawler_fetches_page_with_pinned_peer_and_origin_rate_limit() {
        let host = "public.example.org";
        let fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Owned public TLS fixture</title><p>pinned transport marker</p>",
                    ),
                ),
            ]),
        );
        let temp = TestDir::new();
        let (index, mut crawler) = open_public_tls_crawler(
            &temp,
            &fixture,
            vec![vec![fixture.address]],
            CrawlLimits::default(),
            PublicTlsSourceSpec {
                id: "tls-success",
                seed_path: "/page",
                max_requests: 6,
                min_origin_delay_ms: 1000,
            },
        );

        let result = run_bounded_crawl(
            &mut crawler,
            6,
            12 * MAX_COMPRESSED_RESPONSE_BYTES,
            32 * MAX_DECODED_RESPONSE_BYTES,
            Duration::from_secs(5),
        )
        .unwrap();
        let report = result.report;

        assert_eq!(report.requests, 2);
        assert_eq!(report.indexed, 1);
        assert_eq!(index.query("pinned transport").unwrap().len(), 1);
        assert_eq!(fixture.requests(), ["/robots.txt", "/page"]);
        assert_eq!(
            fixture.user_agents(),
            [
                concat!(
                    "LeyBot/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://github.com/Suraj-H675/Ley/issues)"
                ),
                concat!(
                    "LeyBot/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://github.com/Suraj-H675/Ley/issues)"
                )
            ]
        );
        assert_eq!(report.network_evidence.len(), 2);
        assert!(report.network_evidence.iter().all(|item| {
            item.connected_peer == fixture.address
                && item.resolved_addresses == [fixture.address]
                && !item.proxy_used
        }));
        let request_starts = fixture.request_starts();
        assert_eq!(request_starts.len(), 2);
        assert!(request_starts[1].duration_since(request_starts[0]) >= Duration::from_millis(950));
    }

    #[test]
    fn public_tls_page_and_robots_redirects_revalidate_changed_and_mixed_dns() {
        let host = "public.example.org";
        let page_fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::redirect("/next"),
                ),
                (
                    "/next".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Must not connect</title><p>unsafe redirect target</p>",
                    ),
                ),
            ]),
        );
        let temp = TestDir::new();
        let changed_page_answers = vec![
            vec![page_fixture.address],
            vec![page_fixture.address],
            vec![std::net::SocketAddr::new(
                "127.0.0.2".parse().unwrap(),
                page_fixture.address.port(),
            )],
        ];
        let limits = CrawlLimits {
            max_requests_per_run: 3,
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (index, mut changed_page) = open_public_tls_crawler(
            &temp,
            &page_fixture,
            changed_page_answers,
            limits.clone(),
            PublicTlsSourceSpec {
                id: "tls-page-changed",
                seed_path: "/page",
                max_requests: 3,
                min_origin_delay_ms: 0,
            },
        );
        let changed_report = changed_page
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(page_fixture.requests(), ["/robots.txt", "/page"]);
        assert_eq!(changed_report.network_evidence.len(), 2);
        assert!(index.query("unsafe redirect").unwrap().is_empty());

        let mixed_page_answers = vec![
            vec![page_fixture.address],
            vec![page_fixture.address],
            vec![
                page_fixture.address,
                std::net::SocketAddr::new("fd00::9".parse().unwrap(), page_fixture.address.port()),
            ],
        ];
        let (index, mut mixed_page) = open_public_tls_crawler(
            &temp,
            &page_fixture,
            mixed_page_answers,
            limits,
            PublicTlsSourceSpec {
                id: "tls-page-mixed",
                seed_path: "/page",
                max_requests: 3,
                min_origin_delay_ms: 0,
            },
        );
        let mixed_report = mixed_page
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            page_fixture.requests(),
            ["/robots.txt", "/page", "/robots.txt", "/page"]
        );
        assert_eq!(mixed_report.network_evidence.len(), 2);
        assert!(index.query("unsafe redirect").unwrap().is_empty());

        let robots_fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::redirect("/robots-next"),
                ),
                (
                    "/robots-next".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Robots redirect must deny</title><p>never indexed</p>",
                    ),
                ),
            ]),
        );
        let changed_robots_answers = vec![
            vec![robots_fixture.address],
            vec![std::net::SocketAddr::new(
                "127.0.0.2".parse().unwrap(),
                robots_fixture.address.port(),
            )],
        ];
        let limits = CrawlLimits {
            max_requests_per_run: 2,
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (index, mut changed_robots) = open_public_tls_crawler(
            &temp,
            &robots_fixture,
            changed_robots_answers,
            limits.clone(),
            PublicTlsSourceSpec {
                id: "tls-robots-changed",
                seed_path: "/page",
                max_requests: 2,
                min_origin_delay_ms: 0,
            },
        );
        let changed_robots_report = changed_robots
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(robots_fixture.requests(), ["/robots.txt"]);
        assert_eq!(changed_robots_report.network_evidence.len(), 1);
        assert!(index.query("never indexed").unwrap().is_empty());

        let mixed_robots_answers = vec![
            vec![robots_fixture.address],
            vec![
                robots_fixture.address,
                std::net::SocketAddr::new(
                    "fd00::9".parse().unwrap(),
                    robots_fixture.address.port(),
                ),
            ],
        ];
        let (index, mut mixed_robots) = open_public_tls_crawler(
            &temp,
            &robots_fixture,
            mixed_robots_answers,
            limits,
            PublicTlsSourceSpec {
                id: "tls-robots-mixed",
                seed_path: "/page",
                max_requests: 2,
                min_origin_delay_ms: 0,
            },
        );
        let mixed_robots_report = mixed_robots
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(robots_fixture.requests(), ["/robots.txt", "/robots.txt"]);
        assert_eq!(mixed_robots_report.network_evidence.len(), 1);
        assert!(index.query("never indexed").unwrap().is_empty());
    }

    #[test]
    fn public_tls_enforces_request_redirect_and_overall_deadline_budgets() {
        let host = "public.example.org";
        let mut robot_routes = BTreeMap::from([(
            "/robots.txt".to_owned(),
            crate::safe_fetch::tls_test_support::Response::redirect("/hop1"),
        )]);
        for index in 1..=6 {
            robot_routes.insert(
                format!("/hop{index}"),
                crate::safe_fetch::tls_test_support::Response::redirect(&format!(
                    "/hop{}",
                    index + 1
                )),
            );
        }
        let robots_fixture =
            crate::safe_fetch::tls_test_support::Fixture::start(host, robot_routes);
        let temp = TestDir::new();

        let request_limited = CrawlLimits {
            max_requests_per_run: 2,
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (_, mut request_crawler) = open_public_tls_crawler(
            &temp,
            &robots_fixture,
            vec![vec![robots_fixture.address]],
            request_limited,
            PublicTlsSourceSpec {
                id: "tls-request-budget",
                seed_path: "/page",
                max_requests: 2,
                min_origin_delay_ms: 0,
            },
        );
        let request_report = request_crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(request_report.requests, 2);
        assert_eq!(robots_fixture.requests(), ["/robots.txt", "/hop1"]);

        let redirect_limited = CrawlLimits {
            max_requests_per_run: 12,
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (_, mut redirect_crawler) = open_public_tls_crawler(
            &temp,
            &robots_fixture,
            vec![vec![robots_fixture.address]],
            redirect_limited,
            PublicTlsSourceSpec {
                id: "tls-robot-redirect-budget",
                seed_path: "/page",
                max_requests: 12,
                min_origin_delay_ms: 0,
            },
        );
        let redirect_report = redirect_crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(redirect_report.requests, 6);
        assert_eq!(
            robots_fixture.requests(),
            [
                "/robots.txt",
                "/hop1",
                "/robots.txt",
                "/hop1",
                "/hop2",
                "/hop3",
                "/hop4",
                "/hop5"
            ]
        );

        let page_fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::redirect("/p1"),
                ),
                (
                    "/p1".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::redirect("/p2"),
                ),
                (
                    "/p2".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::redirect("/p3"),
                ),
                (
                    "/p3".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Page redirect bound</title><p>must not connect</p>",
                    ),
                ),
            ]),
        );
        let page_limited = CrawlLimits {
            page_redirects: 2,
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (_, mut page_crawler) = open_public_tls_crawler(
            &temp,
            &page_fixture,
            vec![vec![page_fixture.address]],
            page_limited,
            PublicTlsSourceSpec {
                id: "tls-page-redirect-budget",
                seed_path: "/page",
                max_requests: 8,
                min_origin_delay_ms: 0,
            },
        );
        let page_report = page_crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            page_fixture.requests(),
            ["/robots.txt", "/page", "/p1", "/p2"]
        );
        assert!(page_report.disallowed > 0);

        let deadline_fixture = crate::safe_fetch::tls_test_support::Fixture::start(
            host,
            BTreeMap::from([
                (
                    "/robots.txt".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::text(
                        "User-agent: LeyBot\nAllow: /\n",
                    ),
                ),
                (
                    "/page".to_owned(),
                    crate::safe_fetch::tls_test_support::Response::html(
                        "<title>Overall deadline</title><p>deadline marker</p>",
                    ),
                ),
            ]),
        );
        let deadline_limited = CrawlLimits {
            max_runtime: Duration::from_millis(300),
            max_retries: 0,
            ..CrawlLimits::default()
        };
        let (_, mut deadline_crawler) = open_public_tls_crawler(
            &temp,
            &deadline_fixture,
            vec![vec![deadline_fixture.address]],
            deadline_limited,
            PublicTlsSourceSpec {
                id: "tls-overall-deadline",
                seed_path: "/page",
                max_requests: 6,
                min_origin_delay_ms: 1000,
            },
        );
        let started = Instant::now();
        let deadline_result = run_bounded_crawl(
            &mut deadline_crawler,
            6,
            12 * MAX_COMPRESSED_RESPONSE_BYTES,
            32 * MAX_DECODED_RESPONSE_BYTES,
            Duration::from_millis(300),
        )
        .unwrap();
        let deadline_report = deadline_result.report;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(deadline_report.requests, 1);
        assert_eq!(
            deadline_result.stop_reason,
            BoundedStopReason::RuntimeBudget
        );
        assert!(
            deadline_report
                .failure_reasons
                .iter()
                .any(|reason| { reason.contains("due after the public crawl runtime limit") })
        );
        assert_eq!(deadline_fixture.requests(), ["/robots.txt"]);
    }

    #[test]
    fn repeated_identical_source_admission_is_idempotent_and_keeps_budget_state() {
        let fixture = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
        )])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            index,
            &fixture,
            clock.clone(),
        );
        let mut source = policy(&fixture, "repeat-admission", clock.now_ms());
        source.retention = RetentionPolicy::Until(clock.now_ms() + 5_000);
        let source_request_limit = source.max_requests as i64;
        let seed = fixture_seed(&fixture, "/");
        crawler
            .admit_source(source.clone(), std::slice::from_ref(&seed))
            .unwrap();
        crawler
            .db
            .conn
            .execute(
                "UPDATE source_policy SET request_count=7 WHERE source_id='repeat-admission'",
                [],
            )
            .unwrap();

        let mut later_retention_deadline = source.clone();
        later_retention_deadline.retention = RetentionPolicy::Until(clock.now_ms() + 20_000);
        crawler
            .admit_source(later_retention_deadline, std::slice::from_ref(&seed))
            .unwrap();

        let mut changed_policy = source;
        changed_policy.max_requests += 1;
        assert!(matches!(
            crawler.admit_source(changed_policy, std::slice::from_ref(&seed)),
            Err(CrawlError::Policy(_))
        ));

        let (sources, frontier, candidates, request_count, retention, max_requests):
            (i64, i64, i64, i64, i64, i64) = crawler
            .db
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM source_policy WHERE source_id='repeat-admission'), (SELECT COUNT(*) FROM frontier WHERE source_id='repeat-admission'), (SELECT COUNT(*) FROM crawl_event WHERE source_id='repeat-admission' AND state='candidate'), (SELECT request_count FROM source_policy WHERE source_id='repeat-admission'), (SELECT retention_until_ms FROM source_policy WHERE source_id='repeat-admission'), (SELECT max_requests FROM source_policy WHERE source_id='repeat-admission')",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!((sources, frontier, candidates, request_count), (1, 1, 1, 7));
        assert_eq!(retention, 15_000);
        assert_eq!(max_requests, source_request_limit);
    }

    #[test]
    fn owner_lock_child_holds_frontier_until_process_exit() {
        let Ok(frontier_path) = std::env::var("LEY_GATE4_OWNER_FRONTIER") else {
            return;
        };
        let index_path = std::env::var("LEY_GATE4_OWNER_INDEX").unwrap();
        let index = Arc::new(PersistentIndex::open(index_path).unwrap());
        let _owner = ControlledCrawler::open(
            Path::new(&frontier_path),
            index,
            FixtureResolver(Arc::new(BTreeMap::new())),
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(1),
        )
        .unwrap();
        println!("owner-ready");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        use std::io::Read;
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
    }

    #[test]
    fn second_coordinator_is_rejected_and_crash_releases_frontier_owner() {
        use std::io::BufRead;
        use std::process::Stdio;

        let temp = TestDir::new();
        let index_path = temp.path().join("index");
        let frontier_path = temp.path().join("frontier.sqlite");
        let index = Arc::new(PersistentIndex::create(&index_path).unwrap());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::owner_lock_child_holds_frontier_until_process_exit",
                "--nocapture",
            ])
            .env("LEY_GATE4_OWNER_FRONTIER", &frontier_path)
            .env("LEY_GATE4_OWNER_INDEX", &index_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut ready = String::new();
        loop {
            ready.clear();
            assert_ne!(
                stdout.read_line(&mut ready).unwrap(),
                0,
                "child exited before locking frontier"
            );
            if ready.trim() == "owner-ready" {
                break;
            }
        }

        let contender = ControlledCrawler::open(
            &frontier_path,
            Arc::clone(&index),
            FixtureResolver(Arc::new(BTreeMap::new())),
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(1),
        );
        assert!(
            matches!(contender, Err(CrawlError::Policy(message)) if message.contains("live coordinator"))
        );

        child.kill().unwrap();
        child.wait().unwrap();
        let owner_after_crash = ControlledCrawler::open(
            &frontier_path,
            index,
            FixtureResolver(Arc::new(BTreeMap::new())),
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(1),
        )
        .unwrap();
        drop(owner_after_crash);
    }

    #[test]
    fn frontier_store_mismatch_is_rejected_before_frontier_mutation() {
        let fixture = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n"),
        )])
        .unwrap();
        let temp = TestDir::new();
        let frontier_path = temp.path().join("frontier.sqlite");
        let first_index_path = temp.path().join("first-index");
        let second_index_path = temp.path().join("second-index");
        let first_index = Arc::new(PersistentIndex::create(&first_index_path).unwrap());
        let owner =
            open_fixture_crawler(&frontier_path, first_index, &fixture, ManualClock::new(1));
        drop(owner);
        let before = fs::read(&frontier_path).unwrap();
        let second_index = Arc::new(PersistentIndex::create(second_index_path).unwrap());
        let result = ControlledCrawler::open(
            &frontier_path,
            second_index,
            SystemResolver,
            vec![fixture.capability()],
            CrawlLimits::default(),
            ManualClock::new(1),
        );
        let error = match result {
            Ok(_) => panic!("wrong index store unexpectedly acquired the frontier"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("different index store"));
        assert_eq!(fs::read(&frontier_path).unwrap(), before);
    }

    #[test]
    fn fetch_extract_index_query_restart_and_reference_scores_match() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>Controlled root</title><p>controlled retrieval marker</p><a href=\"/docs\">docs</a>",
                ),
            ),
            (
                "/docs".to_owned(),
                FixtureResponse::html(
                    "<title>Durable document</title><p>controlled durable restart marker</p>",
                ),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index_path = temp.path().join("index");
        let frontier_path = temp.path().join("frontier.sqlite");
        let index = Arc::new(PersistentIndex::create(&index_path).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock.clone());
        crawler
            .admit_source(
                policy(&fixture, "parity", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            (report.requests, report.pages_fetched, report.indexed),
            (3, 2, 2)
        );
        assert_eq!(fixture.accepted_connections(), 3);
        let observed_headers = fixture.request_header_log();
        assert_eq!(observed_headers.len(), 3);
        assert!(observed_headers.iter().all(|headers| {
            headers.iter().any(|(name, value)| {
                name == "user-agent"
                    && value
                        == concat!(
                            "LeyBot/",
                            env!("CARGO_PKG_VERSION"),
                            " (+https://github.com/Suraj-H675/Ley/issues)"
                        )
            })
        }));
        let urls = vec![
            fixture.base_url().to_string(),
            fixture.base_url().join("docs").unwrap().to_string(),
        ];
        assert_reference_parity(&index, &urls, "controlled AND marker");
        let before = index.query("restart").unwrap();
        assert_eq!(before.len(), 1);
        drop(crawler);
        drop(index);

        let reopened = Arc::new(PersistentIndex::open(&index_path).unwrap());
        let reopened_crawler =
            open_fixture_crawler(&frontier_path, Arc::clone(&reopened), &fixture, clock);
        drop(reopened_crawler);
        let after = reopened.query("restart").unwrap();
        assert_eq!(
            before.iter().map(|hit| &hit.id).collect::<Vec<_>>(),
            after.iter().map(|hit| &hit.id).collect::<Vec<_>>()
        );
        assert_reference_parity(&reopened, &urls, "controlled AND marker");
        assert_eq!(
            fixture.accepted_connections(),
            3,
            "completed frontier must not refetch before its due time"
        );
    }

    #[test]
    fn five_safe_cross_authority_robots_redirects_cache_rules_for_original_authority() {
        let aliases: Vec<String> = (1..=5)
            .map(|index| format!("robot-hop-{index}.fixture.test"))
            .collect();
        let fixture = LocalFixture::start_with_origin(|origin| {
            let port = Url::parse(origin.url("/").unwrap().as_str())
                .unwrap()
                .port()
                .unwrap();
            let mut routes = vec![(
                "/robots.txt".to_owned(),
                FixtureResponse::redirect(format!("http://{}:{port}/hop1", aliases[0])),
            )];
            for (index, alias) in aliases.iter().enumerate().skip(1) {
                routes.push((
                    format!("/hop{index}"),
                    FixtureResponse::redirect(format!("http://{alias}:{port}/hop{}", index + 1)),
                ));
            }
            routes.push((
                "/hop5".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nDisallow: /\n"),
            ));
            routes
        })
        .unwrap();
        let original_origin = fixture.base_url().origin().ascii_serialization();
        let port = fixture.base_url().port().unwrap();
        let endpoint: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut mapping = BTreeMap::from([("127.0.0.1".to_owned(), vec![endpoint])]);
        let mut capabilities = vec![fixture.capability()];
        let mut allowed_origins = vec![original_origin.clone()];
        for alias in &aliases {
            mapping.insert(alias.clone(), vec![endpoint]);
            allowed_origins.push(format!("http://{alias}:{port}"));
            capabilities.push(
                fixture
                    .capability()
                    .named_for_host(alias)
                    .expect("alias of an owned listener"),
            );
        }
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            FixtureResolver(Arc::new(mapping)),
            capabilities,
            CrawlLimits::default(),
            ManualClock::new(10_000),
        )
        .unwrap();
        let mut source = SourcePolicy::owned_fixture(
            "robots-redirects",
            allowed_origins,
            vec!["/".to_owned()],
            1_000_000,
        );
        source.max_requests = 64;
        crawler
            .admit_source(source, &[fixture_seed(&fixture, "/")])
            .unwrap();
        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            report.requests, 6,
            "one original robots request plus five cross-authority hops"
        );
        assert_eq!(fixture.accepted_connections(), 6);
        let observed_headers = fixture.request_header_log();
        assert_eq!(observed_headers.len(), 6);
        assert!(observed_headers.iter().all(|headers| {
            headers.iter().any(|(name, value)| {
                name == "user-agent"
                    && value
                        == concat!(
                            "LeyBot/",
                            env!("CARGO_PKG_VERSION"),
                            " (+https://github.com/Suraj-H675/Ley/issues)"
                        )
            })
        }));
        assert_eq!(report.indexed, 0);
        let log = fixture.request_log();
        assert_eq!(
            log,
            ["/robots.txt", "/hop1", "/hop2", "/hop3", "/hop4", "/hop5"]
        );
        assert!(!log.iter().any(|path| path == "/"));
        let cached_origin: String = crawler
            .db
            .conn
            .query_row(
                "SELECT origin FROM robots_cache WHERE body IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cached_origin, original_origin);
        let visited_authorities: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM origin_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(visited_authorities, 6);
    }

    #[test]
    fn sixth_robots_redirect_is_denied_before_the_sixth_hop() {
        let fixture = LocalFixture::start_with_origin(|origin| {
            let mut routes = vec![(
                "/robots.txt".to_owned(),
                FixtureResponse::redirect(origin.url("/hop1").unwrap().to_string()),
            )];
            for index in 1..=5 {
                routes.push((
                    format!("/hop{index}"),
                    FixtureResponse::redirect(
                        origin
                            .url(&format!("/hop{}", index + 1))
                            .unwrap()
                            .to_string(),
                    ),
                ));
            }
            routes
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "robots-sixth-hop", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        assert_eq!(fixture.accepted_connections(), 6);
        assert_eq!(
            fixture.request_log(),
            ["/robots.txt", "/hop1", "/hop2", "/hop3", "/hop4", "/hop5"]
        );
        assert!(!fixture.request_log().iter().any(|path| path == "/hop6"));
        assert!(!fixture.request_log().iter().any(|path| path == "/"));
    }

    #[test]
    fn unadmitted_robots_redirect_has_zero_connections_to_the_target() {
        let target = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n"),
        )])
        .unwrap();
        let source = LocalFixture::start_with_origin(|_| {
            vec![(
                "/robots.txt".to_owned(),
                FixtureResponse::redirect(
                    target.base_url().join("robots.txt").unwrap().to_string(),
                ),
            )]
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &source,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&source, "robots-unadmitted-target", clock.now_ms()),
                &[fixture_seed(&source, "/")],
            )
            .unwrap();

        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        assert_eq!(source.request_log(), ["/robots.txt"]);
        assert_eq!(target.accepted_connections(), 0);
        assert!(index.query("unreachable").unwrap().is_empty());
    }

    #[test]
    fn raw_empty_userinfo_redirects_are_rejected_before_page_or_robots_target_sockets() {
        let robots_fixture = LocalFixture::start_with_origin(|origin| {
            let port = origin.url("/").unwrap().to_url().unwrap().port().unwrap();
            vec![(
                "/robots.txt".to_owned(),
                FixtureResponse::redirect(format!("http://@127.0.0.1:{port}/target")),
            )]
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("robots-index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("robots-frontier.sqlite"),
            Arc::clone(&index),
            &robots_fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&robots_fixture, "raw-robots-userinfo", clock.now_ms()),
                &[fixture_seed(&robots_fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(robots_fixture.request_log(), ["/robots.txt"]);
        assert_eq!(robots_fixture.accepted_connections(), 1);

        let page_fixture = LocalFixture::start_with_origin(|origin| {
            let port = origin.url("/").unwrap().to_url().unwrap().port().unwrap();
            vec![
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: *\nAllow: /\n"),
                ),
                (
                    "/".to_owned(),
                    FixtureResponse::redirect(format!("http://@127.0.0.1:{port}/target")),
                ),
            ]
        })
        .unwrap();
        let page_index = Arc::new(PersistentIndex::create(temp.path().join("page-index")).unwrap());
        let page_clock = ManualClock::new(20_000);
        let mut page_crawler = open_fixture_crawler(
            &temp.path().join("page-frontier.sqlite"),
            Arc::clone(&page_index),
            &page_fixture,
            page_clock.clone(),
        );
        page_crawler
            .admit_source(
                policy(&page_fixture, "raw-page-userinfo", page_clock.now_ms()),
                &[fixture_seed(&page_fixture, "/")],
            )
            .unwrap();
        assert!(matches!(
            page_crawler.run_until_idle(&CrawlCancellation::default()),
            Err(CrawlError::Url(message)) if message.contains("userinfo")
        ));
        assert_eq!(page_fixture.request_log(), ["/robots.txt", "/"]);
        assert_eq!(page_fixture.accepted_connections(), 2);
        assert!(page_index.query("target").unwrap().is_empty());
    }

    #[test]
    fn malformed_scheme_and_overlong_redirects_are_rejected_for_pages_and_robots() {
        use crate::url_key::MAX_URL_KEY_BYTES;

        for kind in ["malformed-escape", "unsupported-scheme", "overlong"] {
            for robots_redirect in [false, true] {
                let fixture = LocalFixture::start_with_origin(|origin| {
                    let base = origin.url("/").unwrap().to_url().unwrap();
                    let port = base.port().unwrap();
                    let location = match kind {
                        "malformed-escape" => format!("http://127.0.0.1:{port}/%GG"),
                        "unsupported-scheme" => format!("ftp://127.0.0.1:{port}/target"),
                        "overlong" => format!(
                            "http://127.0.0.1:{port}/{}",
                            "x".repeat(MAX_URL_KEY_BYTES + 1)
                        ),
                        _ => unreachable!(),
                    };
                    let redirect = FixtureResponse::redirect(location);
                    if robots_redirect {
                        vec![("/robots.txt".to_owned(), redirect)]
                    } else {
                        vec![
                            (
                                "/robots.txt".to_owned(),
                                FixtureResponse::text("User-agent: *\nAllow: /\n"),
                            ),
                            ("/".to_owned(), redirect),
                        ]
                    }
                })
                .unwrap();
                let temp = TestDir::new();
                let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
                let clock = ManualClock::new(30_000);
                let mut crawler = open_fixture_crawler(
                    &temp.path().join("frontier.sqlite"),
                    Arc::clone(&index),
                    &fixture,
                    clock.clone(),
                );
                crawler
                    .admit_source(
                        policy(
                            &fixture,
                            &format!("redirect-{kind}-{}", robots_redirect),
                            clock.now_ms(),
                        ),
                        &[fixture_seed(&fixture, "/")],
                    )
                    .unwrap();
                let result = crawler.run_until_idle(&CrawlCancellation::default());
                if robots_redirect {
                    result.unwrap();
                    assert_eq!(fixture.accepted_connections(), 1);
                } else {
                    assert!(matches!(result, Err(CrawlError::Url(_))));
                    assert_eq!(fixture.accepted_connections(), 2);
                }
                assert!(
                    !fixture
                        .request_log()
                        .iter()
                        .any(|path| path != "/robots.txt" && path != "/")
                );
            }
        }
    }

    #[test]
    fn unreachable_robots_resolution_keeps_the_page_deferred() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: *\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Unreachable</title><p>must not fetch</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(30_000);
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            SequenceResolver::new(Vec::new()),
            vec![fixture.capability()],
            CrawlLimits::default(),
            clock.clone(),
        )
        .unwrap();
        crawler
            .admit_source(
                policy(&fixture, "unreachable-robots", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        assert_eq!(fixture.accepted_connections(), 0);
        assert!(fixture.request_log().is_empty());
        assert!(index.query("unreachable").unwrap().is_empty());
        let state: String = crawler
            .db
            .conn
            .query_row(
                "SELECT state FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "deferred");
    }

    #[test]
    fn frontier_url_capacity_rejects_the_next_candidate() {
        let fixture = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n"),
        )])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let now = 35_000;
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            index,
            &fixture,
            ManualClock::new(now),
        );
        crawler
            .admit_source(
                policy(&fixture, "frontier-capacity", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let tx = crawler.db.transaction().unwrap();
        for sequence in 1..MAX_FRONTIER_ENTRIES {
            let key = UrlKey::parse(
                fixture
                    .base_url()
                    .join(&format!("page/{sequence}"))
                    .unwrap()
                    .as_str(),
            )
            .unwrap();
            tx.execute(
                "INSERT INTO frontier(url_key,source_id,fetch_url,state,due_ms,redirect_seen,queued_sequence) VALUES (?1,'frontier-capacity',?1,'ready',?2,?1,?3)",
                params![key.as_str(), now as i64, (sequence + 1) as i64],
            )
            .unwrap();
        }
        tx.commit().unwrap();

        assert!(matches!(
            crawler.enqueue_seed("frontier-capacity", fixture_seed(&fixture, "/overflow")),
            Err(CrawlError::Capacity("frontier URL count"))
        ));
        let count: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM frontier", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count as usize, MAX_FRONTIER_ENTRIES);
    }

    #[test]
    fn robots_cache_byte_capacity_stops_before_page_fetch() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: *\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Cache capacity</title><p>must not fetch</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let now = 36_000;
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            ManualClock::new(now),
        );
        crawler
            .admit_source(
                policy(&fixture, "robots-cache-capacity", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .db
            .conn
            .execute(
                "INSERT INTO robots_cache(origin,body,expires_ms,reason) VALUES ('http://unused.fixture.test:80',zeroblob(?1),?2,'capacity fixture')",
                params![MAX_ROBOTS_STORE_BYTES as i64, now as i64],
            )
            .unwrap();

        assert!(matches!(
            crawler.run_until_idle(&CrawlCancellation::default()),
            Err(CrawlError::Capacity("persistent robots cache bytes"))
        ));
        assert_eq!(fixture.request_log(), ["/robots.txt"]);
        assert_eq!(fixture.accepted_connections(), 1);
        assert!(index.query("capacity").unwrap().is_empty());
    }

    #[test]
    fn skipped_links_emit_bounded_source_denial_and_deduplication_counts() {
        let denied = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n"),
        )])
        .unwrap();
        let fixture = LocalFixture::start_with_origin(|_| {
            vec![
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: *\nAllow: /\n"),
                ),
                (
                    "/".to_owned(),
                    FixtureResponse::html(format!(
                        "<title>Link diagnostics</title><p>diagnostics</p><a href='/child'>one</a><a href='/child'>duplicate</a><a href='{}'>denied</a>",
                        denied.base_url().join("secret").unwrap()
                    )),
                ),
                (
                    "/child".to_owned(),
                    FixtureResponse::html("<title>Child</title><p>child marker</p>"),
                ),
            ]
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(40_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "link-diagnostics", clock.now_ms()),
                &[
                    fixture_seed(&fixture, "/"),
                    fixture_seed(&fixture, "/child"),
                ],
            )
            .unwrap();

        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        let counts: String = crawler
            .db
            .conn
            .query_row(
                "SELECT reason FROM crawl_event WHERE state='link_discovery' ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(counts.contains("enqueued=0"), "{counts}");
        assert!(counts.contains("source_denied=1"), "{counts}");
        assert!(counts.contains("duplicate=1"), "{counts}");
        assert_eq!(report.duplicate_urls, 1);
        assert_eq!(report.link_discovery.candidates(), 2);
        assert_eq!(report.link_discovery.enqueued, 0);
        assert_eq!(report.link_discovery.source_denied, 1);
        assert_eq!(report.link_discovery.duplicates, 1);
        assert_eq!(report.link_discovery.malformed, 0);
        assert_eq!(report.link_discovery.capacity, 0);
        let replay = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(replay.link_discovery, LinkDiscoveryCounts::default());
        assert_eq!(fixture.accepted_connections(), 3);
        assert_eq!(denied.accepted_connections(), 0);
    }

    #[test]
    fn changed_dns_on_page_and_robots_redirects_never_reaches_unowned_listener() {
        for robots_redirect in [false, true] {
            let fixture = if robots_redirect {
                LocalFixture::start_with_origin(|origin| {
                    vec![
                        (
                            "/robots.txt".to_owned(),
                            FixtureResponse::redirect(origin.url("/hop").unwrap().to_string()),
                        ),
                        (
                            "/".to_owned(),
                            FixtureResponse::html("<title>Must not fetch</title><p>blocked</p>"),
                        ),
                    ]
                })
                .unwrap()
            } else {
                LocalFixture::start_with_origin(|origin| {
                    vec![
                        (
                            "/robots.txt".to_owned(),
                            FixtureResponse::text("User-agent: *\nAllow: /\n"),
                        ),
                        (
                            "/".to_owned(),
                            FixtureResponse::redirect(origin.url("/next").unwrap().to_string()),
                        ),
                    ]
                })
                .unwrap()
            };
            let port = fixture.base_url().port().unwrap();
            let denied_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();
            let denied_listener =
                std::net::TcpListener::bind(std::net::SocketAddr::new(denied_ip, port)).unwrap();
            denied_listener.set_nonblocking(true).unwrap();
            let authorized = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), port);
            let denied = denied_listener.local_addr().unwrap();
            let answers = if robots_redirect {
                vec![authorized, denied]
            } else {
                vec![authorized, authorized, denied]
            };
            let temp = TestDir::new();
            let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
            let clock = ManualClock::new(10_000);
            let mut crawler = ControlledCrawler::open(
                &temp.path().join("frontier.sqlite"),
                Arc::clone(&index),
                SequenceResolver::new(answers),
                vec![fixture.capability()],
                CrawlLimits::default(),
                clock.clone(),
            )
            .unwrap();
            crawler
                .admit_source(
                    policy(
                        &fixture,
                        if robots_redirect {
                            "robots-dns-change"
                        } else {
                            "page-dns-change"
                        },
                        clock.now_ms(),
                    ),
                    &[fixture_seed(&fixture, "/")],
                )
                .unwrap();

            crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap();

            assert_eq!(
                fixture.accepted_connections(),
                if robots_redirect { 1 } else { 2 },
                "only the initially pinned authorized requests reach the owned listener"
            );
            assert_eq!(
                denied_listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "changed DNS answers must be denied before a socket reaches the unauthorized listener"
            );
            if robots_redirect {
                assert_eq!(fixture.request_log(), ["/robots.txt"]);
            } else {
                assert_eq!(fixture.request_log(), ["/robots.txt", "/"]);
            }
        }
    }

    #[test]
    fn robots_expiry_reuses_fresh_cache_then_fails_closed_without_stale_rules() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")
                    .with_header("Cache-Control", "max-age=1"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Cache marker</title><p>cache marker one</p>"),
            ),
            (
                "/extra".to_owned(),
                FixtureResponse::html("<title>Cache marker two</title><p>cache marker two</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(10_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "cache-policy", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        crawler
            .enqueue_seed("cache-policy", fixture_seed(&fixture, "/extra"))
            .unwrap();
        clock.set(10_999);
        let before_expiry = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            before_expiry.requests, 1,
            "still-fresh cache avoids another robots request"
        );
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/robots.txt")
                .count(),
            1
        );

        fixture.replace_response(
            "/robots.txt",
            FixtureResponse::new(503, "text/plain", "temporarily unavailable")
                .with_header("Retry-After", "5"),
        );
        let now = 10_999 + DEFAULT_RECRAWL_MS;
        clock.set(now);
        let expired = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            expired.requests, 1,
            "one failed robots refresh gates every due page"
        );
        assert_eq!(fixture.accepted_connections(), 4);
        assert_eq!(
            index.query("cache").unwrap().len(),
            2,
            "failed refresh retains prior indexed documents"
        );
        let (body, retry): (Option<Vec<u8>>, i64) = crawler
            .db
            .conn
            .query_row(
                "SELECT body,denied_retry_ms FROM robots_cache WHERE origin=?1",
                [fixture.base_url().origin().ascii_serialization()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            body.is_none(),
            "stale rules must not be used after refresh failure"
        );
        assert_eq!(
            retry as u64,
            now + 5_000,
            "Retry-After controls the bounded denial retry"
        );
    }

    #[test]
    fn no_store_robots_apply_to_one_scheduled_url_and_a_robots_404_fails_closed() {
        let denied = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::new(404, "text/plain", "no robots file"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Must stay unfetched</title><p>denied marker</p>"),
            ),
        ])
        .unwrap();
        let denied_temp = TestDir::new();
        let denied_index =
            Arc::new(PersistentIndex::create(denied_temp.path().join("index")).unwrap());
        let denied_clock = ManualClock::new(11_000);
        let mut denied_crawler = open_fixture_crawler(
            &denied_temp.path().join("frontier.sqlite"),
            Arc::clone(&denied_index),
            &denied,
            denied_clock.clone(),
        );
        denied_crawler
            .admit_source(
                policy(&denied, "robots-404", denied_clock.now_ms()),
                &[fixture_seed(&denied, "/")],
            )
            .unwrap();
        let denied_report = denied_crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(denied_report.requests, 1);
        assert_eq!(denied.accepted_connections(), 1);
        assert!(denied_index.query("denied").unwrap().is_empty());

        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")
                    .with_header("Cache-Control", "no-store, max-age=3600"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>No-store root</title><p>no-store marker root</p><a href=\"/child\">child</a>",
                ),
            ),
            (
                "/child".to_owned(),
                FixtureResponse::html("<title>No-store child</title><p>no-store marker child</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index_path = temp.path().join("index");
        let frontier_path = temp.path().join("frontier.sqlite");
        let index = Arc::new(PersistentIndex::create(&index_path).unwrap());
        let clock = ManualClock::new(12_000);
        let mut crawler =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock.clone());
        crawler
            .admit_source(
                policy(&fixture, "no-store", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let first_run = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(first_run.indexed, 2);
        assert_eq!(first_run.requests, 4);
        assert_eq!(fixture.accepted_connections(), 4);
        let stored_robots: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM robots_cache", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored_robots, 0);
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/robots.txt")
                .count(),
            2,
            "no-store robots rules must be fetched for each scheduled URL"
        );
        drop(crawler);

        clock.set(12_000 + DEFAULT_RECRAWL_MS);
        let mut reopened =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock);
        let recrawl = reopened
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(recrawl.indexed, 2);
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/robots.txt")
                .count(),
            4,
            "a later recrawl must fetch no-store rules again for each URL"
        );
        assert_eq!(
            reopened
                .db
                .conn
                .query_row::<i64, _, _>("SELECT COUNT(*) FROM robots_cache", [], |row| row.get(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn no_cache_robots_revalidate_between_urls_and_reuse_a_304_body() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::new(
                    304,
                    "text/plain",
                    "User-agent: LeyBot\nAllow: /\n",
                )
                .with_header("Cache-Control", "no-cache")
                .with_header("ETag", "\"rules-v1\""),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>No-cache root</title><p>no-cache marker root</p><a href=\"/child\">child</a>",
                ),
            ),
            (
                "/child".to_owned(),
                FixtureResponse::html(
                    "<title>No-cache child</title><p>no-cache marker child</p>",
                ),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let now = 13_000;
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            ManualClock::new(now),
        );
        crawler
            .admit_source(
                policy(&fixture, "no-cache", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(report.indexed, 2);
        assert_eq!(report.requests, 4);
        assert_eq!(fixture.accepted_connections(), 4);
        assert_eq!(fixture.conditional_requests(), 1);
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/robots.txt")
                .count(),
            2
        );
        let (body, expires_ms, etag): (Vec<u8>, i64, Option<String>) = crawler
            .db
            .conn
            .query_row(
                "SELECT body,expires_ms,etag FROM robots_cache WHERE body IS NOT NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(body, b"User-agent: LeyBot\nAllow: /\n");
        assert_eq!(expires_ms as u64, now);
        assert_eq!(etag.as_deref(), Some("\"rules-v1\""));
        assert_eq!(index.query("no-cache marker").unwrap().len(), 2);
    }

    #[test]
    fn page_redirect_is_manual_and_rechecked_before_the_target_request() {
        let fixture = LocalFixture::start_with_origin(|origin| {
            let port = Url::parse(origin.url("/").unwrap().as_str())
                .unwrap()
                .port()
                .unwrap();
            vec![
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
                ),
                (
                    "/".to_owned(),
                    FixtureResponse::redirect(format!("http://127.0.0.1:{port}/final")),
                ),
                (
                    "/final".to_owned(),
                    FixtureResponse::html("<title>Redirected page</title><p>redirect marker</p>"),
                ),
            ]
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(13_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "page-redirect", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(report.requests, 3);
        assert_eq!(report.indexed, 1);
        assert_eq!(fixture.request_log(), ["/robots.txt", "/", "/final"]);
        let result = index.query("redirect").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].id.ends_with('/'));
    }

    #[test]
    fn scheduled_redirect_recrawl_restarts_at_requested_url() {
        let fixture = LocalFixture::start_with_origin(|origin| {
            vec![
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: *\nAllow: /\n"),
                ),
                (
                    "/".to_owned(),
                    FixtureResponse::redirect(origin.url("/old").unwrap().as_str()),
                ),
                (
                    "/old".to_owned(),
                    FixtureResponse::html(
                        "<title>Old destination</title><p>obsolete redirect marker</p>",
                    ),
                ),
                (
                    "/new".to_owned(),
                    FixtureResponse::html(
                        "<title>New destination</title><p>current redirect marker</p>",
                    ),
                ),
            ]
        })
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(23_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "redirect-recrawl", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("obsolete redirect marker").unwrap().len(), 1);

        fixture.replace_response(
            "/",
            FixtureResponse::redirect(fixture.base_url().join("new").unwrap().as_str()),
        );
        clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        let log = fixture.request_log();
        assert_eq!(log.iter().filter(|path| path.as_str() == "/").count(), 2);
        assert_eq!(log.iter().filter(|path| path.as_str() == "/old").count(), 1);
        assert_eq!(log.iter().filter(|path| path.as_str() == "/new").count(), 1);
        assert!(index.query("obsolete redirect marker").unwrap().is_empty());
        assert_eq!(index.query("current redirect marker").unwrap().len(), 1);
    }

    #[test]
    fn due_origin_round_robin_finds_second_origin_beyond_large_first_origin_queue() {
        let first = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: *\nAllow: /\n"),
            ),
            (
                "/00000".to_owned(),
                FixtureResponse::html("<p>slow first origin</p>")
                    .delayed(Duration::from_millis(300)),
            ),
        ])
        .unwrap();
        let second = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: *\nAllow: /\n"),
            ),
            (
                "/second".to_owned(),
                FixtureResponse::html("<title>Fair origin</title><p>second origin progressed</p>"),
            ),
        ])
        .unwrap();
        let first_origin = first.base_url().origin().ascii_serialization();
        let second_origin = second.base_url().origin().ascii_serialization();
        let (first_fixture, second_fixture, first_origin, second_origin) =
            if first_origin < second_origin {
                (first, second, first_origin, second_origin)
            } else {
                (second, first, second_origin, first_origin)
            };
        first_fixture.replace_response(
            "/00000",
            FixtureResponse::html("<p>slow first origin</p>").delayed(Duration::from_millis(300)),
        );
        second_fixture.replace_response(
            "/second",
            FixtureResponse::html("<title>Fair origin</title><p>second origin progressed</p>"),
        );
        let mut seeds = (0..2050)
            .map(|index| fixture_seed(&first_fixture, &format!("/{index:05}")))
            .collect::<Vec<_>>();
        seeds.push(fixture_seed(&second_fixture, "/second"));
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let limits = CrawlLimits {
            max_requests_per_run: 4,
            ..CrawlLimits::default()
        };
        let mut source = SourcePolicy::owned_fixture(
            "origin-fairness",
            vec![first_origin, second_origin],
            vec!["/".to_owned()],
            1_000_000,
        );
        source.max_requests = 16;
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            FixtureResolver(Arc::new(BTreeMap::from([(
                "127.0.0.1".to_owned(),
                vec![
                    format!("127.0.0.1:{}", first_fixture.base_url().port().unwrap())
                        .parse()
                        .unwrap(),
                    format!("127.0.0.1:{}", second_fixture.base_url().port().unwrap())
                        .parse()
                        .unwrap(),
                ],
            )]))),
            vec![first_fixture.capability(), second_fixture.capability()],
            limits,
            ManualClock::new(24_000),
        )
        .unwrap();
        crawler.admit_source(source, &seeds).unwrap();

        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        assert_eq!(report.requests, 4);
        assert!(second_fixture.request_log().contains(&"/second".to_owned()));
        assert!(first_fixture.request_log().contains(&"/00000".to_owned()));
        assert_eq!(index.query("second origin progressed").unwrap().len(), 1);
    }

    #[test]
    fn page_directives_honor_agent_scope_repeated_fields_noindex_none_and_nofollow() {
        let fixture = LocalFixture::start([
            ("/robots.txt".to_owned(), FixtureResponse::text("User-agent: *\nAllow: /\n")),
            ("/".to_owned(), FixtureResponse::html("<title>Root marker</title><p>root marker</p><a href=\"/other\">other</a><a href=\"/noindex\">noindex</a><a href=\"/nofollow\">nofollow</a><a href=\"/none\">none</a>")),
            ("/other".to_owned(), FixtureResponse::html("<title>Other scope</title><p>scope marker</p><a href=\"/other-child\">child</a>").with_header("X-Robots-Tag", "OtherBot: noindex, nofollow")),
            ("/other-child".to_owned(), FixtureResponse::html("<title>Other child</title><p>scope child marker</p>")),
            ("/noindex".to_owned(), FixtureResponse::html("<title>No index</title><p>private marker</p>").with_header("X-Robots-Tag", "OtherBot: noindex").with_header("X-Robots-Tag", "LeyBot: noindex")),
            ("/nofollow".to_owned(), FixtureResponse::html("<title>No follow</title><p>follow marker</p><a href=\"/nofollow-child\">child</a>").with_header("X-Robots-Tag", "LeyBot: nofollow")),
            ("/nofollow-child".to_owned(), FixtureResponse::html("<title>Must not follow</title><p>hidden marker</p>")),
            ("/none".to_owned(), FixtureResponse::html("<html><head><meta name=\"robots\" content=\"none\"><title>None</title></head><body><p>hidden marker</p><a href=\"/none-child\">child</a></body></html>")),
            ("/none-child".to_owned(), FixtureResponse::html("<title>Must not follow none</title><p>hidden marker</p>")),
        ]).unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(20_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "directives", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            report.indexed, 4,
            "root, other-scoped page, its child, and nofollow page are indexable"
        );
        assert_eq!(report.tombstoned, 2);
        let log = fixture.request_log();
        assert!(
            log.contains(&"/other-child".to_owned()),
            "unmatched product scope is ignored"
        );
        assert!(!log.contains(&"/nofollow-child".to_owned()));
        assert!(!log.contains(&"/none-child".to_owned()));
        assert_eq!(index.query("hidden").unwrap().len(), 0);
        assert_eq!(index.query("marker").unwrap().len(), 4);
    }

    #[test]
    fn meta_noindex_tombstones_source_but_still_fetches_admitted_links() {
        let fixture = LocalFixture::start([
            ("/robots.txt".to_owned(), FixtureResponse::text("User-agent: *\nAllow: /\n")),
            ("/".to_owned(), FixtureResponse::html("<html><head><meta name=\"robots\" content=\"noindex\"></head><body><a href=\"/child\">child</a></body></html>")),
            ("/child".to_owned(), FixtureResponse::html("<title>Child</title><p>admitted child marker</p>")),
        ]).unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(21_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "meta-noindex-links", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        assert_eq!(report.tombstoned, 1);
        assert_eq!(report.indexed, 1);
        assert!(fixture.request_log().contains(&"/child".to_owned()));
        let result = index.query("admitted child marker").unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].id.ends_with("/child"));
        assert!(index.query("noindex").unwrap().is_empty());
    }

    #[test]
    fn noindex_response_header_removes_prior_document_on_304_and_rejected_content() {
        for (case, replacement) in [
            (
                "304",
                FixtureResponse::new(304, "text/html", "")
                    .with_header("ETag", "v2")
                    .with_header("X-Robots-Tag", "LeyBot: noindex"),
            ),
            (
                "unsupported",
                FixtureResponse::text("not HTML").with_header("X-Robots-Tag", "LeyBot: noindex"),
            ),
        ] {
            let fixture = LocalFixture::start([
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: *\nAllow: /\n"),
                ),
                (
                    "/page".to_owned(),
                    FixtureResponse::html("<title>Prior live title</title><p>priorlive marker</p>")
                        .with_header("ETag", "v1"),
                ),
            ])
            .unwrap();
            let temp = TestDir::new();
            let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
            let clock = ManualClock::new(22_000);
            let mut crawler = open_fixture_crawler(
                &temp.path().join("frontier.sqlite"),
                Arc::clone(&index),
                &fixture,
                clock.clone(),
            );
            crawler
                .admit_source(
                    policy(&fixture, case, clock.now_ms()),
                    &[fixture_seed(&fixture, "/page")],
                )
                .unwrap();
            assert_eq!(
                crawler
                    .run_until_idle(&CrawlCancellation::default())
                    .unwrap()
                    .indexed,
                1
            );
            assert_eq!(index.query("priorlive marker").unwrap().len(), 1);

            fixture.replace_response("/page", replacement);
            clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
            let report = crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap();

            assert_eq!(
                report.tombstoned, 1,
                "{case} directive must publish removal"
            );
            assert!(
                index.query("priorlive marker").unwrap().is_empty(),
                "{case}"
            );
        }
    }

    #[test]
    fn removal_metadata_survives_rejected_response_bodies() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'x'; MAX_DECODED_RESPONSE_BYTES + 1])
            .unwrap();
        let expanded_gzip = encoder.finish().unwrap();
        let oversized_wire = vec![b'x'; MAX_COMPRESSED_RESPONSE_BYTES + 1];
        let cases = [
            (
                "410 with oversized wire body",
                FixtureResponse::new(410, "text/html", oversized_wire.clone()),
                true,
            ),
            (
                "generic noindex with oversized wire body",
                FixtureResponse::new(200, "text/html", oversized_wire.clone())
                    .with_header("X-Robots-Tag", "noindex"),
                true,
            ),
            (
                "LeyBot noindex with oversized gzip expansion",
                FixtureResponse::new(200, "text/html", expanded_gzip)
                    .with_header("Content-Encoding", "gzip")
                    .with_header("X-Robots-Tag", "LeyBot: noindex"),
                true,
            ),
            (
                "noindex with invalid gzip body",
                FixtureResponse::new(200, "text/html", b"not a gzip stream")
                    .with_header("Content-Encoding", "gzip")
                    .with_header("X-Robots-Tag", "noindex"),
                true,
            ),
            (
                "noindex with unsupported media type",
                FixtureResponse::text("not HTML").with_header("X-Robots-Tag", "noindex"),
                true,
            ),
            (
                "oversized wire body without removal metadata",
                FixtureResponse::new(200, "text/html", oversized_wire),
                false,
            ),
            (
                "invalid gzip body without removal metadata",
                FixtureResponse::new(200, "text/html", b"not a gzip stream")
                    .with_header("Content-Encoding", "gzip"),
                false,
            ),
            (
                "unsupported media type without removal metadata",
                FixtureResponse::text("not HTML"),
                false,
            ),
        ];

        for (name, replacement, remove) in cases {
            let fixture = LocalFixture::start([
                (
                    "/robots.txt".to_owned(),
                    FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
                ),
                (
                    "/".to_owned(),
                    FixtureResponse::html("<p>bodyrejectionmarker</p>"),
                ),
            ])
            .unwrap();
            let temp = TestDir::new();
            let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
            let clock = ManualClock::new(23_000);
            let mut crawler = open_fixture_crawler(
                &temp.path().join("frontier.sqlite"),
                Arc::clone(&index),
                &fixture,
                clock.clone(),
            );
            crawler
                .admit_source(
                    policy(&fixture, "body-rejection", clock.now_ms()),
                    &[fixture_seed(&fixture, "/")],
                )
                .unwrap();
            assert_eq!(
                crawler
                    .run_until_idle(&CrawlCancellation::default())
                    .unwrap()
                    .indexed,
                1,
                "{name}: seed page must first become visible"
            );
            assert_eq!(index.query("bodyrejectionmarker").unwrap().len(), 1);

            fixture.replace_response("/", replacement);
            clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
            let report = crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap();

            assert_eq!(
                index.query("bodyrejectionmarker").unwrap().is_empty(),
                remove,
                "{name}"
            );
            assert_eq!(
                report.transport_failures, 0,
                "{name}: valid HTTP heads are not network failures"
            );
            if remove {
                assert_eq!(report.tombstoned, 1, "{name}");
            }
            assert_eq!(
                fixture.accepted_connections(),
                4,
                "{name}: both scheduled runs fetch robots and the page"
            );
        }
    }

    #[test]
    fn rejected_body_http_status_resets_prior_404_evidence() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<p>body404marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(24_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "rejected-body-404", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        fixture.replace_response("/", FixtureResponse::new(404, "text/plain", "missing"));
        clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(not_found_count(&crawler, &fixture_seed(&fixture, "/")), 1);

        fixture.replace_response(
            "/",
            FixtureResponse::new(
                200,
                "text/html",
                vec![b'x'; MAX_COMPRESSED_RESPONSE_BYTES + 1],
            ),
        );
        clock.set(clock.now_ms().saturating_add(DEFAULT_RETRY_MS + 1));
        let body_rejection = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(body_rejection.transport_failures, 0);
        assert_eq!(body_rejection.retries, 1);
        assert_eq!(not_found_count(&crawler, &fixture_seed(&fixture, "/")), 0);
        assert_eq!(index.query("body404marker").unwrap().len(), 1);

        fixture.replace_response("/", FixtureResponse::new(404, "text/plain", "missing"));
        clock.set(clock.now_ms().saturating_add(2 * DEFAULT_RETRY_MS + 1));
        let next_404 = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(next_404.tombstoned, 0);
        assert_eq!(not_found_count(&crawler, &fixture_seed(&fixture, "/")), 1);
        assert_eq!(index.query("body404marker").unwrap().len(), 1);
    }

    #[test]
    fn missing_representation_retries_unconditionally_and_304_reuses_pinned_document() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")
                    .with_header("Cache-Control", "max-age=86400"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::new(
                    304,
                    "text/html; charset=utf-8",
                    "<title>Unconditional recovery</title><p>conditional recovery marker</p>",
                )
                .with_header("ETag", "\"v1\""),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(30_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "conditional", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .db
            .conn
            .execute(
                "UPDATE frontier SET etag='\"missing\"' WHERE url_key=?1",
                [fixture.base_url().as_str()],
            )
            .unwrap();
        let first = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            first.requests, 3,
            "robots, conditional 304, then unconditional 200"
        );
        assert_eq!(first.indexed, 1);
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/")
                .count(),
            2
        );
        assert_eq!(index.query("recovery").unwrap().len(), 1);
        let before = index.query("recovery").unwrap();

        clock.set(30_000 + DEFAULT_RECRAWL_MS);
        let recrawl = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            recrawl.indexed, 1,
            "304 is a successful reuse of the pinned document"
        );
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/")
                .count(),
            3
        );
        let after = index.query("recovery").unwrap();
        assert_eq!(
            before.iter().map(|hit| &hit.id).collect::<Vec<_>>(),
            after.iter().map(|hit| &hit.id).collect::<Vec<_>>()
        );
        assert_eq!(before[0].title, after[0].title);
    }

    #[test]
    fn a_410_removes_immediately_and_two_separately_scheduled_404s_remove_later() {
        let fixture = LocalFixture::start([
            ("/robots.txt".to_owned(), FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")),
            ("/".to_owned(), FixtureResponse::html("<title>Removal root</title><p>removal root</p><a href=\"/changing\">change</a><a href=\"/gone\">gone</a>")),
            ("/changing".to_owned(), FixtureResponse::html("<title>Changing document</title><p>removable marker</p>")),
            ("/gone".to_owned(), FixtureResponse::html("<title>Gone document</title><p>gone marker</p>")),
        ]).unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(40_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "removals", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("removable").unwrap().len(), 1);
        assert_eq!(index.query("gone").unwrap().len(), 1);

        fixture.replace_response(
            "/changing",
            FixtureResponse::new(404, "text/plain", "not found"),
        );
        fixture.replace_response("/gone", FixtureResponse::new(410, "text/plain", "gone"));
        clock.set(40_000 + DEFAULT_RECRAWL_MS);
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            index.query("removable").unwrap().len(),
            1,
            "one 404 observation retains the indexed version"
        );
        assert_eq!(
            index.query("gone").unwrap().len(),
            0,
            "410 tombstones immediately"
        );

        let between_schedules = 40_000 + DEFAULT_RECRAWL_MS + DEFAULT_RETRY_MS - 1;
        clock.set(between_schedules);
        let early = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(
            early.requests, 0,
            "the second 404 is scheduled for a later time"
        );
        clock.set(between_schedules + 1);
        let confirmed = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(confirmed.tombstoned, 1);
        assert_eq!(index.query("removable").unwrap().len(), 0);
    }

    #[test]
    fn redirect_continuation_preserves_404_evidence_for_a_later_schedule() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>Redirect confirmation</title><p>confirmation marker</p>",
                ),
            ),
            (
                "/missing".to_owned(),
                FixtureResponse::new(404, "text/plain", "not found"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(44_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "redirect-404", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("confirmation marker").unwrap().len(), 1);

        fixture.replace_response("/", FixtureResponse::new(404, "text/plain", "not found"));
        clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("confirmation marker").unwrap().len(), 1);
        let observed: i64 = crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(observed, 1);

        fixture.replace_response(
            "/",
            FixtureResponse::redirect(fixture.base_url().join("missing").unwrap().as_str()),
        );
        clock.set(clock.now_ms().saturating_add(DEFAULT_RETRY_MS + 1));
        let confirmed = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(confirmed.tombstoned, 1);
        assert_eq!(index.query("confirmation marker").unwrap().len(), 0);
        assert!(fixture.request_log().iter().any(|path| path == "/missing"));
    }

    #[test]
    fn terminal_server_failure_resets_prior_404_evidence() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Failure confirmation</title><p>failure marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(45_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "server-reset-404", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();

        fixture.replace_response("/", FixtureResponse::new(404, "text/plain", "not found"));
        clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("failure marker").unwrap().len(), 1);

        fixture.replace_response("/", FixtureResponse::new(503, "text/plain", "busy"));
        clock.set(clock.now_ms().saturating_add(DEFAULT_RETRY_MS + 1));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        let after_server_failure: i64 = crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_server_failure, 0);
        assert_eq!(index.query("failure marker").unwrap().len(), 1);

        fixture.replace_response("/", FixtureResponse::new(404, "text/plain", "not found"));
        clock.set(clock.now_ms().saturating_add(2 * DEFAULT_RETRY_MS + 1));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("failure marker").unwrap().len(), 1);
        let later: i64 = crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(later, 1);

        clock.set(clock.now_ms().saturating_add(DEFAULT_RETRY_MS + 1));
        let removed = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(removed.tombstoned, 1);
        assert_eq!(index.query("failure marker").unwrap().len(), 0);
    }

    #[test]
    fn rejected_redirect_ends_schedule_and_resets_404_evidence() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/allowed".to_owned(),
                FixtureResponse::html(
                    "<title>Redirect failure</title><p>redirect failure marker</p>",
                ),
            ),
            (
                "/outside".to_owned(),
                FixtureResponse::html("<title>Outside scope</title><p>never requested</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(46_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        let mut source = policy(&fixture, "rejected-redirect-404", clock.now_ms());
        source.allowed_path_prefixes = vec!["/allowed".to_owned(), "/robots.txt".to_owned()];
        crawler
            .admit_source(source, &[fixture_seed(&fixture, "/allowed")])
            .unwrap();
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(index.query("redirect failure marker").unwrap().len(), 1);

        fixture.replace_response(
            "/allowed",
            FixtureResponse::new(404, "text/plain", "not found"),
        );
        clock.set(clock.now_ms().saturating_add(DEFAULT_RECRAWL_MS));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        let first_observation: i64 = crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/allowed").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_observation, 1);
        assert_eq!(index.query("redirect failure marker").unwrap().len(), 1);

        fixture.replace_response(
            "/allowed",
            FixtureResponse::redirect(fixture.base_url().join("outside").unwrap().as_str()),
        );
        clock.set(clock.now_ms().saturating_add(DEFAULT_RETRY_MS + 1));
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        let reset: i64 = crawler
            .db
            .conn
            .query_row(
                "SELECT not_found_count FROM frontier WHERE url_key=?1",
                [fixture_seed(&fixture, "/allowed").as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reset, 0);
        assert_eq!(index.query("redirect failure marker").unwrap().len(), 1);
        assert!(!fixture.request_log().iter().any(|path| path == "/outside"));
    }

    #[test]
    fn fair_origin_dispatch_and_global_request_caps_are_observable() {
        let slow = Duration::from_millis(60);
        let left = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n").delayed(slow),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Left origin</title><p>fair marker left</p>")
                    .delayed(slow),
            ),
        ])
        .unwrap();
        let right = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n").delayed(slow),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Right origin</title><p>fair marker right</p>")
                    .delayed(slow),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let left_origin = left.base_url().origin().ascii_serialization();
        let right_origin = right.base_url().origin().ascii_serialization();
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            SystemResolver,
            vec![left.capability(), right.capability()],
            CrawlLimits {
                global_active: 2,
                per_origin_active: 1,
                ..CrawlLimits::default()
            },
            ManualClock::new(50_000),
        )
        .unwrap();
        let mut source = SourcePolicy::owned_fixture(
            "fair",
            vec![left_origin, right_origin],
            vec!["/".to_owned()],
            1_000_000,
        );
        source.max_requests = 16;
        crawler
            .admit_source(
                source,
                &[fixture_seed(&left, "/"), fixture_seed(&right, "/")],
            )
            .unwrap();
        let report = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(report.indexed, 2);
        assert_eq!(report.requests, 4);
        assert_eq!(
            report.max_active, 2,
            "two origins make progress concurrently under the global limit"
        );
        assert_eq!(left.accepted_connections(), 2);
        assert_eq!(right.accepted_connections(), 2);

        let limited = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Must wait</title><p>limit marker</p>"),
            ),
        ])
        .unwrap();
        let limited_index =
            Arc::new(PersistentIndex::create(temp.path().join("limited-index")).unwrap());
        let mut capped = ControlledCrawler::open(
            &temp.path().join("limited-frontier.sqlite"),
            limited_index,
            SystemResolver,
            vec![limited.capability()],
            CrawlLimits {
                max_requests_per_run: 1,
                ..CrawlLimits::default()
            },
            ManualClock::new(60_000),
        )
        .unwrap();
        capped
            .admit_source(
                policy(&limited, "request-cap", 60_000),
                &[fixture_seed(&limited, "/")],
            )
            .unwrap();
        let capped_report = capped
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(capped_report.requests, 1);
        assert_eq!(
            limited.accepted_connections(),
            1,
            "request cap stops before page fetch"
        );
    }

    #[test]
    fn run_byte_budget_reserves_response_bounds_before_dispatch() {
        let mut large_page =
            b"<title>Budget marker root</title><p>budget marker</p><a href=\"/child\">child</a><!--"
                .to_vec();
        large_page.resize(MAX_COMPRESSED_RESPONSE_BYTES - 3, b'x');
        large_page.extend_from_slice(b"-->");
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            ("/".to_owned(), FixtureResponse::html(large_page)),
            (
                "/child".to_owned(),
                FixtureResponse::html("<title>Child</title><p>child marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let now = 70_000;
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            SystemResolver,
            vec![fixture.capability()],
            CrawlLimits {
                max_wire_bytes_per_run: 2 * MAX_COMPRESSED_RESPONSE_BYTES,
                max_decompressed_bytes_per_run: 2 * MAX_DECODED_RESPONSE_BYTES,
                ..CrawlLimits::default()
            },
            ManualClock::new(now),
        )
        .unwrap();
        crawler
            .admit_source(
                policy(&fixture, "byte-cap", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        assert!(matches!(
            crawler.run_until_idle(&CrawlCancellation::default()),
            Err(CrawlError::Capacity("per-run response byte budget"))
        ));
        assert_eq!(
            fixture.accepted_connections(),
            2,
            "requests: {:?}",
            fixture.request_log()
        );
        assert_eq!(fixture.request_log(), ["/robots.txt", "/"]);
        assert_eq!(index.query("budget marker").unwrap().len(), 1);
    }

    #[test]
    fn cancellation_stops_new_dispatch_after_the_in_flight_request_finishes() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")
                    .delayed(Duration::from_millis(120)),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Cancelled</title><p>cancel marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(70_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            index,
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "cancel", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let cancellation = CrawlCancellation::default();
        let signal = cancellation.clone();
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            signal.cancel();
        });
        assert!(matches!(
            crawler.run_until_idle(&cancellation),
            Err(CrawlError::Cancelled)
        ));
        trigger.join().unwrap();
        assert_eq!(fixture.request_log(), ["/robots.txt"]);
        assert_eq!(fixture.accepted_connections(), 1);
    }

    #[test]
    fn coordinator_error_cancels_and_drains_workers_before_returning() {
        let first = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n").delayed(Duration::from_millis(60)),
        )])
        .unwrap();
        let second = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n").delayed(Duration::from_millis(600)),
        )])
        .unwrap();
        let (fast, slow) = if first.base_url().port() < second.base_url().port() {
            (&first, &second)
        } else {
            (&second, &first)
        };
        slow.replace_response(
            "/robots.txt",
            FixtureResponse::redirect(slow.base_url().join("/hop").unwrap().to_string())
                .delayed(Duration::from_millis(600)),
        );
        slow.replace_response("/hop", FixtureResponse::text("User-agent: *\nAllow: /\n"));

        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(80_000);
        let port_a = first.base_url().port().unwrap();
        let port_b = second.base_url().port().unwrap();
        let resolver = FixtureResolver(Arc::new(BTreeMap::from([(
            "127.0.0.1".to_owned(),
            vec![
                format!("127.0.0.1:{port_a}").parse().unwrap(),
                format!("127.0.0.1:{port_b}").parse().unwrap(),
            ],
        )])));
        let mut crawler = ControlledCrawler::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            resolver,
            vec![first.capability(), second.capability()],
            CrawlLimits {
                global_active: 2,
                ..CrawlLimits::default()
            },
            clock.clone(),
        )
        .unwrap();
        let mut source = SourcePolicy::owned_fixture(
            "worker-drain",
            vec![
                first.base_url().origin().ascii_serialization(),
                second.base_url().origin().ascii_serialization(),
            ],
            vec!["/".to_owned()],
            clock.now_ms() + 1_000_000,
        );
        source.max_requests = 64;
        crawler
            .admit_source(
                source,
                &[fixture_seed(&first, "/"), fixture_seed(&second, "/")],
            )
            .unwrap();
        let fast_origin = fast.base_url().origin().ascii_serialization();
        crawler
            .db
            .conn
            .execute_batch(&format!(
                "CREATE TRIGGER inject_fast_robots_store_error BEFORE INSERT ON robots_cache WHEN NEW.origin='{fast_origin}' BEGIN SELECT RAISE(ABORT,'injected worker-result failure'); END;"
            ))
            .unwrap();

        assert!(matches!(
            crawler.run_until_idle(&CrawlCancellation::default()),
            Err(CrawlError::Sql(_))
        ));
        let fast_count = fast.accepted_connections();
        let slow_count = slow.accepted_connections();
        let slow_log = slow.request_log();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(fast.accepted_connections(), fast_count);
        assert_eq!(slow.accepted_connections(), slow_count);
        assert_eq!(slow.request_log(), slow_log);
        assert!(!slow_log.is_empty());
    }

    #[test]
    fn robots_cache_control_expiry_is_bounded_and_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.append(
            "cache-control",
            HeaderValue::from_static("public, MAX-AGE=3600"),
        );
        headers.append("cache-control", HeaderValue::from_static("max-age=1800"));
        headers.insert("age", HeaderValue::from_static("10"));
        let (expires, no_cache, no_store) = robots_expiry(&headers, 10_000, false);
        assert_eq!(expires, 10_000 + 1_790_000);
        assert!(!no_cache);
        assert!(!no_store);

        let mut no_store_headers = HeaderMap::new();
        no_store_headers.insert(
            "cache-control",
            HeaderValue::from_static("no-store, max-age=60"),
        );
        let (_, _, no_store) = robots_expiry(&no_store_headers, 10_000, false);
        assert!(no_store);

        let mut capped = HeaderMap::new();
        capped.insert(
            "cache-control",
            HeaderValue::from_static("max-age=999999999"),
        );
        let (expires, _, _) = robots_expiry(&capped, 10_000, false);
        assert_eq!(expires, 10_000 + MAX_ROBOTS_AGE_MS);
    }

    #[test]
    fn outbox_crash_child() {
        if std::env::var("LEY_GATE4_CHILD").as_deref() != Ok("1") {
            return;
        }
        let root = PathBuf::from(std::env::var_os("LEY_GATE4_ROOT").unwrap());
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>Subprocess recovery</title><p>subprocess parity token</p>",
                ),
            ),
        ])
        .unwrap();
        let index = Arc::new(PersistentIndex::open(root.join("index")).unwrap());
        let now = SystemClock.now_ms();
        let mut crawler = ControlledCrawler::<SystemResolver, SystemClock>::open_system(
            &root.join("frontier.sqlite"),
            index,
            vec![fixture.capability()],
            CrawlLimits::default(),
        )
        .unwrap();
        crawler
            .admit_source(
                policy(&fixture, "subprocess", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let result = crawler.run_until_idle(&CrawlCancellation::default());
        panic!("child expected injected exit before returning, got {result:?}");
    }

    #[test]
    fn source_revocation_capacity_crash_child() {
        if std::env::var("LEY_GATE4_REVOKE_CHILD").as_deref() != Ok("1") {
            return;
        }
        let root = PathBuf::from(std::env::var_os("LEY_GATE4_ROOT").unwrap());
        let index = Arc::new(PersistentIndex::open(root.join("index")).unwrap());
        let mut crawler = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &root.join("frontier.sqlite"),
            index,
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(20_000),
        )
        .unwrap();
        let result = crawler.revoke_source("capacity-revoke");
        panic!("child expected publication failpoint during revocation, got {result:?}");
    }

    #[test]
    fn revocation_drains_multiple_batches_after_capacity_and_publication_crash() {
        let temp = TestDir::new();
        let index_path = temp.path().join("index");
        let frontier_path = temp.path().join("frontier.sqlite");
        let index = Arc::new(PersistentIndex::create(&index_path).unwrap());
        let fixture = LocalFixture::start([(
            "/robots.txt".to_owned(),
            FixtureResponse::text("User-agent: *\nAllow: /\n"),
        )])
        .unwrap();
        let now = 10_000;
        let mut crawler = open_fixture_crawler(
            &frontier_path,
            Arc::clone(&index),
            &fixture,
            ManualClock::new(now),
        );
        crawler
            .admit_source(
                policy(&fixture, "capacity-revoke", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();

        let root_key = fixture_seed(&fixture, "/");
        let lease = index.issue_fence(&root_key).unwrap();
        index
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: root_key.to_string(),
                    title: "Capacity marker".to_owned(),
                    body: "revoke batch marker".to_owned(),
                },
            )
            .unwrap();
        let kept_key = fixture_seed(&fixture, "/keep");
        let kept_lease = index.issue_fence(&kept_key).unwrap();
        index
            .apply(
                &kept_lease,
                Intent::Upsert {
                    effective_url: kept_key.to_string(),
                    title: "Retained marker".to_owned(),
                    body: "revoke batch marker".to_owned(),
                },
            )
            .unwrap();
        let frontier_tx = crawler.db.transaction().unwrap();
        for sequence in 1..257 {
            let key = UrlKey::parse(
                fixture
                    .base_url()
                    .join(&format!("page/{sequence}"))
                    .unwrap()
                    .as_str(),
            )
            .unwrap();
            frontier_tx
                .execute(
                    "INSERT INTO frontier(url_key,source_id,fetch_url,state,due_ms,redirect_seen,queued_sequence) VALUES (?1,'capacity-revoke',?1,'complete',?2,?1,?3)",
                    params![key.as_str(), now as i64, sequence + 1],
                )
                .unwrap();
        }
        frontier_tx.commit().unwrap();

        let capacity_tx = crawler.db.transaction().unwrap();
        capacity_tx
            .execute(
                "INSERT INTO outbox(url_key,source_id,lease_token,kind,body,completion_state,status,created_ms) VALUES (?1,'capacity-revoke',zeroblob(?2),0,zeroblob(?3),'complete','applied',?4)",
                params![root_key.as_str(), 32_i64, (MAX_OUTBOX_BYTES + 1) as i64, now as i64],
            )
            .unwrap();
        {
            let mut insert = capacity_tx
                .prepare("INSERT INTO outbox(url_key,source_id,lease_token,kind,completion_state,status,created_ms) VALUES (?1,'capacity-revoke',zeroblob(32),0,'complete','applied',?2)")
                .unwrap();
            for sequence in 1..MAX_OUTBOX_ROWS {
                insert
                    .execute(params![
                        format!("http://fixture.invalid/{sequence}"),
                        now as i64
                    ])
                    .unwrap();
            }
        }
        {
            let initial_events: i64 = capacity_tx
                .query_row("SELECT COUNT(*) FROM crawl_event", [], |row| row.get(0))
                .unwrap();
            let to_insert = MAX_EVENT_ROWS - initial_events as usize;
            let mut insert = capacity_tx
                .prepare("INSERT INTO crawl_event(occurred_ms,source_id,url_key,state,reason) VALUES (?1,'capacity-revoke','','prior','capacity fixture')")
                .unwrap();
            for sequence in 0..to_insert {
                insert.execute([sequence as i64]).unwrap();
            }
        }
        capacity_tx.commit().unwrap();
        let event_count_before: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM crawl_event", [], |row| row.get(0))
            .unwrap();
        assert_eq!(event_count_before as usize, MAX_EVENT_ROWS);
        assert_eq!(
            crawler
                .db
                .conn
                .query_row("SELECT COUNT(*) FROM outbox", [], |row| row
                    .get::<_, i64>(0))
                .unwrap() as usize,
            MAX_OUTBOX_ROWS
        );
        let pinned_before = index.read_view().unwrap();
        let prior_results = pinned_before.query("batch marker").unwrap();
        assert_eq!(prior_results.len(), 2);
        assert_eq!(prior_results[0].explanation.document_count, 2);
        assert_eq!(
            prior_results[0].explanation.terms[0]
                .body
                .document_frequency,
            2
        );
        drop(crawler);
        drop(index);

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::source_revocation_capacity_crash_child",
                "--nocapture",
            ])
            .env("LEY_GATE4_REVOKE_CHILD", "1")
            .env("LEY_GATE4_ROOT", temp.path())
            .env("LEY_STORAGE_FAILPOINT", "apply_before_publish")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "revocation child did not stop at index publication: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let recovered_index = Arc::new(PersistentIndex::open(&index_path).unwrap());
        let mut visible_after_revoke = recovered_index.query("batch marker").unwrap();
        assert_eq!(
            visible_after_revoke.len(),
            2,
            "a crash before index publication leaves the complete old generation visible"
        );
        assert_eq!(visible_after_revoke[0].explanation.document_count, 2);
        assert_eq!(
            visible_after_revoke[0].explanation.terms[0]
                .body
                .document_frequency,
            2
        );
        let recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &frontier_path,
            Arc::clone(&recovered_index),
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(20_000),
        )
        .unwrap();
        let (published, pending): (i64, i64) = recovery
            .db
            .conn
            .query_row(
                "SELECT SUM(revocation_published), (SELECT COUNT(*) FROM outbox WHERE status='pending') FROM frontier WHERE source_id='capacity-revoke'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(published, 257, "recovery must publish every bounded batch");
        assert_eq!(pending, 0);
        visible_after_revoke = recovered_index.query("batch marker").unwrap();
        assert_eq!(visible_after_revoke.len(), 1);
        assert_eq!(visible_after_revoke[0].id, kept_key.as_str());
        assert_eq!(
            pinned_before.query("batch marker").unwrap().len(),
            2,
            "a pinned pre-revocation generation stays internally consistent"
        );
        assert_eq!(
            recovery
                .db
                .conn
                .query_row("SELECT COUNT(*) FROM crawl_event", [], |row| row
                    .get::<_, i64>(0))
                .unwrap() as usize,
            MAX_EVENT_ROWS,
            "the event ring remains bounded while revocation records its progress"
        );
        drop(recovery);

        let mut readmitter = ControlledCrawler::open(
            &frontier_path,
            Arc::clone(&recovered_index),
            SystemResolver,
            vec![fixture.capability()],
            CrawlLimits::default(),
            ManualClock::new(20_000),
        )
        .unwrap();
        readmitter
            .readmit_source(policy(&fixture, "capacity-revoke", 20_000))
            .unwrap();
        let readmitted: i64 = readmitter
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM frontier WHERE source_id='capacity-revoke' AND readmitted=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let lifecycle: String = readmitter
            .db
            .conn
            .query_row(
                "SELECT lifecycle FROM source_policy WHERE source_id='capacity-revoke'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(readmitted, 257, "readmission drains every bounded batch");
        assert_eq!(lifecycle, "active");
        let after_readmission = recovered_index.query("batch marker").unwrap();
        assert_eq!(after_readmission.len(), 1);
        assert_eq!(
            after_readmission[0].id,
            kept_key.as_str(),
            "explicit readmission does not restore old revoked content"
        );
        drop(readmitter);

        let reopened = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &frontier_path,
            Arc::clone(&recovered_index),
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(20_000),
        )
        .unwrap();
        let readmitted_after_restart: i64 = reopened
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM frontier WHERE source_id='capacity-revoke' AND readmitted=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(readmitted_after_restart, 257);
    }

    #[test]
    fn durable_outbox_replays_across_crash_before_and_after_index_publication() {
        for (gate4_failpoint, storage_failpoint, expected_before) in [
            ("", "apply_before_publish", false),
            ("after-index-apply-before-ack", "", true),
        ] {
            let temp = TestDir::new();
            PersistentIndex::create(temp.path().join("index")).unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "controlled_crawler::tests::outbox_crash_child",
                    "--nocapture",
                ])
                .env("LEY_GATE4_CHILD", "1")
                .env("LEY_GATE4_ROOT", temp.path())
                .env("LEY_GATE4_FAILPOINT", gate4_failpoint)
                .env("LEY_STORAGE_FAILPOINT", storage_failpoint)
                .output()
                .unwrap();
            let expected_code = if expected_before { 87 } else { 86 };
            assert_eq!(
                output.status.code(),
                Some(expected_code),
                "child did not stop at the intended outbox seam: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let index = Arc::new(PersistentIndex::open(temp.path().join("index")).unwrap());
            let before = index.query("subprocess").unwrap();
            assert_eq!(!before.is_empty(), expected_before);
            let generation_before_replay = index.read_view().unwrap().generation_id();
            let mut recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
                &temp.path().join("frontier.sqlite"),
                Arc::clone(&index),
                SystemResolver,
                Vec::new(),
                CrawlLimits::default(),
                ManualClock::new(SystemClock.now_ms()),
            )
            .unwrap();
            let report = recovery
                .run_until_idle(&CrawlCancellation::default())
                .unwrap();
            assert!(report.outbox_replays >= 1);
            let key_url: String = recovery
                .db
                .conn
                .query_row(
                    "SELECT url_key FROM outbox WHERE kind=0 LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let after = index.query("subprocess").unwrap();
            assert_eq!(after.len(), 1);
            if expected_before {
                assert_eq!(
                    index.read_view().unwrap().generation_id(),
                    generation_before_replay,
                    "exact replay after publication must not republish"
                );
            }
            let applied: i64 = recovery
                .db
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM outbox WHERE status='applied'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(applied, 1);
            assert_reference_parity(&index, &[key_url], "subprocess AND parity");
        }
    }

    #[test]
    fn expired_source_blocks_a_crashed_pending_upsert_before_replay() {
        let temp = TestDir::new();
        PersistentIndex::create(temp.path().join("index")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::outbox_crash_child",
                "--nocapture",
            ])
            .env("LEY_GATE4_CHILD", "1")
            .env("LEY_GATE4_ROOT", temp.path())
            .env("LEY_STORAGE_FAILPOINT", "apply_before_publish")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(86));

        let frontier_path = temp.path().join("frontier.sqlite");
        let frontier = Connection::open(&frontier_path).unwrap();
        frontier
            .execute(
                "UPDATE source_policy SET valid_until_ms=?1 WHERE source_id='subprocess'",
                [SystemClock.now_ms() as i64],
            )
            .unwrap();
        drop(frontier);

        let index = Arc::new(PersistentIndex::open(temp.path().join("index")).unwrap());
        assert!(index.query("subprocess").unwrap().is_empty());
        let recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &frontier_path,
            Arc::clone(&index),
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(SystemClock.now_ms()),
        )
        .unwrap();

        assert!(index.query("subprocess").unwrap().is_empty());
        let upsert_status: String = recovery
            .db
            .conn
            .query_row(
                "SELECT status FROM outbox WHERE kind=0 ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(upsert_status, "rejected");
        let lifecycle: String = recovery
            .db
            .conn
            .query_row(
                "SELECT lifecycle FROM source_policy WHERE source_id='subprocess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lifecycle, "revoked");
        assert!(
            recovery
                .db
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox WHERE kind=2 AND status='applied')",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        assert!(index.query("subprocess").unwrap().is_empty());
    }

    #[test]
    fn stale_outbox_lease_is_rejected_and_never_reported_as_applied() {
        let temp = TestDir::new();
        PersistentIndex::create(temp.path().join("index")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::outbox_crash_child",
                "--nocapture",
            ])
            .env("LEY_GATE4_CHILD", "1")
            .env("LEY_GATE4_ROOT", temp.path())
            .env("LEY_GATE4_FAILPOINT", "")
            .env("LEY_STORAGE_FAILPOINT", "apply_before_publish")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(86));

        let frontier = Connection::open(temp.path().join("frontier.sqlite")).unwrap();
        let key_text: String = frontier
            .query_row("SELECT url_key FROM outbox WHERE kind=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(frontier);
        let key = UrlKey::parse(&key_text).unwrap();
        let index = Arc::new(PersistentIndex::open(temp.path().join("index")).unwrap());
        let _newer_lease = index.issue_fence(&key).unwrap();
        let mut recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(SystemClock.now_ms()),
        )
        .unwrap();
        let report = recovery
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(report.outbox_replays, 0);
        assert_eq!(report.rejected_intents, 1);
        assert!(index.query("subprocess").unwrap().is_empty());
        let status: String = recovery
            .db
            .conn
            .query_row("SELECT status FROM outbox WHERE kind=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "rejected");
        assert_reference_parity(&index, &[key_text], "subprocess AND parity");
    }

    #[test]
    fn persisted_revocation_blocks_recovery_until_explicit_readmission() {
        let temp = TestDir::new();
        PersistentIndex::create(temp.path().join("index")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::outbox_crash_child",
                "--nocapture",
            ])
            .env("LEY_GATE4_CHILD", "1")
            .env("LEY_GATE4_ROOT", temp.path())
            .env("LEY_GATE4_FAILPOINT", "")
            .env("LEY_STORAGE_FAILPOINT", "apply_before_publish")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(86));

        let frontier_path = temp.path().join("frontier.sqlite");
        let frontier = Connection::open(&frontier_path).unwrap();
        frontier
            .execute(
                "UPDATE source_policy SET lifecycle='revoked' WHERE source_id='subprocess'",
                [],
            )
            .unwrap();
        drop(frontier);
        let index = Arc::new(PersistentIndex::open(temp.path().join("index")).unwrap());
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/fresh".to_owned(),
                FixtureResponse::html(
                    "<title>Explicit readmission</title><p>readmission marker</p>",
                ),
            ),
        ])
        .unwrap();
        let mut recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &frontier_path,
            Arc::clone(&index),
            SystemResolver,
            vec![fixture.capability()],
            CrawlLimits::default(),
            ManualClock::new(SystemClock.now_ms()),
        )
        .unwrap();
        assert!(index.query("subprocess").unwrap().is_empty());
        let upsert_status: String = recovery
            .db
            .conn
            .query_row("SELECT status FROM outbox WHERE kind=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        let revoke_count: i64 = recovery
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE kind=2 AND status='applied'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(upsert_status, "rejected");
        assert_eq!(revoke_count, 1);

        let now = SystemClock.now_ms();
        recovery
            .readmit_source(policy(&fixture, "subprocess", now))
            .unwrap();
        recovery
            .enqueue_seed("subprocess", fixture_seed(&fixture, "/fresh"))
            .unwrap();
        let report = recovery
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert!(report.rejected_intents >= 1);
        assert_eq!(report.indexed, 1);
        assert_eq!(fixture.accepted_connections(), 2);
        assert!(index.query("subprocess").unwrap().is_empty());
        assert_eq!(index.query("readmission").unwrap().len(), 1);
    }

    #[test]
    fn same_authority_readmission_issues_a_fresh_fence_for_the_next_upsert() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Renewed source</title><p>renewed fixture marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(90_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        let renewed_policy = policy(&fixture, "same-authority", clock.now_ms());
        crawler
            .admit_source(renewed_policy.clone(), &[fixture_seed(&fixture, "/")])
            .unwrap();
        assert_eq!(
            crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap()
                .indexed,
            1
        );
        crawler.revoke_source("same-authority").unwrap();
        assert!(index.query("renewed").unwrap().is_empty());

        crawler.readmit_source(renewed_policy).unwrap();
        let after_readmission = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(after_readmission.indexed, 1);
        assert_eq!(index.query("renewed").unwrap().len(), 1);
        assert_eq!(fixture.accepted_connections(), 3);
    }

    #[test]
    fn local_source_revocation_command_tombstones_without_network_access() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Local removal</title><p>withdrawal marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index_path = temp.path().join("index");
        let frontier_path = temp.path().join("frontier.sqlite");
        let index = Arc::new(PersistentIndex::create(&index_path).unwrap());
        let now = SystemClock.now_ms();
        let clock = ManualClock::new(now);
        let mut crawler =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock.clone());
        crawler
            .admit_source(
                policy(&fixture, "local-removal", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        assert_eq!(
            crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap()
                .indexed,
            1
        );
        let requests_before_revoke = fixture.request_log();
        assert_eq!(index.query("withdrawal").unwrap().len(), 1);
        drop(crawler);

        revoke_public_source(&index_path, &frontier_path, "local-removal").unwrap();

        assert!(
            PersistentIndex::open(&index_path)
                .unwrap()
                .query("withdrawal")
                .unwrap()
                .is_empty()
        );
        assert_eq!(fixture.request_log(), requests_before_revoke);
    }

    #[test]
    fn page_retry_after_and_exponential_backoff_reschedule_without_false_success() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::new(503, "text/plain", "busy").with_header("Retry-After", "5"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(80_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        crawler
            .admit_source(
                policy(&fixture, "page-retry", clock.now_ms()),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let first = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(first.requests, 2);
        assert_eq!(first.indexed, 0);
        assert!(index.query("busy").unwrap().is_empty());
        let (first_due, first_attempts): (i64, i64) = crawler
            .db
            .conn
            .query_row(
                "SELECT due_ms,attempts FROM frontier WHERE url_key=?1",
                [fixture.base_url().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(first_due as u64, 85_000);
        assert_eq!(first_attempts, 1);

        fixture.replace_response("/", FixtureResponse::new(503, "text/plain", "still busy"));
        clock.set(first_due as u64);
        let second = crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(second.requests, 1);
        let (second_due, second_attempts): (i64, i64) = crawler
            .db
            .conn
            .query_row(
                "SELECT due_ms,attempts FROM frontier WHERE url_key=?1",
                [fixture.base_url().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(second_due as u64, first_due as u64 + 4_000);
        assert_eq!(second_attempts, 2);
        assert_eq!(
            fixture
                .request_log()
                .iter()
                .filter(|path| *path == "/")
                .count(),
            2
        );
    }

    #[test]
    fn runtime_limit_stops_dispatch_and_bounds_wait_to_the_active_request_timeout() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n")
                    .delayed(Duration::from_millis(120)),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Runtime limit</title><p>runtime marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let now = SystemClock.now_ms();
        let limits = CrawlLimits {
            max_runtime: Duration::from_millis(25),
            ..CrawlLimits::default()
        };
        let mut crawler = ControlledCrawler::<SystemResolver, SystemClock>::open_system(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            vec![fixture.capability()],
            limits,
        )
        .unwrap();
        crawler
            .admit_source(
                policy(&fixture, "runtime", now),
                &[fixture_seed(&fixture, "/")],
            )
            .unwrap();
        let started = Instant::now();
        assert!(matches!(
            crawler.run_until_idle(&CrawlCancellation::default()),
            Err(CrawlError::RuntimeLimit)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(fixture.request_log(), ["/robots.txt"]);
        assert!(index.query("runtime").unwrap().is_empty());
    }

    #[test]
    fn abandoned_inflight_frontier_recovers_and_issues_a_newer_index_fence() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html(
                    "<title>Frontier restart</title><p>frontier restart marker</p>",
                ),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let frontier_path = temp.path().join("frontier.sqlite");
        let clock = ManualClock::new(100_000);
        let mut crawler =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock.clone());
        let key = fixture_seed(&fixture, "/");
        crawler
            .admit_source(
                policy(&fixture, "frontier-restart", clock.now_ms()),
                std::slice::from_ref(&key),
            )
            .unwrap();
        let origin = origin_of_url(&key.to_url().unwrap());
        crawler
            .db
            .conn
            .execute(
                "UPDATE source_policy SET min_origin_delay_ms=250 WHERE source_id='frontier-restart'",
                [],
            )
            .unwrap();
        crawler
            .db
            .conn
            .execute(
                "INSERT INTO origin_state(origin,next_request_ms,backoff_until_ms,failures) VALUES (?1,99000,0,0)",
                [&origin],
            )
            .unwrap();
        let stale_lease = index.issue_fence(&key).unwrap();
        let stale_token = index.export_lease(&stale_lease).unwrap();
        crawler
            .db
            .conn
            .execute(
                "UPDATE frontier SET state='inflight',schedule_id=123,lease_token=?2 WHERE url_key=?1",
                params![key.as_str(), stale_token],
            )
            .unwrap();
        drop(crawler);

        let mut recovered =
            open_fixture_crawler(&frontier_path, Arc::clone(&index), &fixture, clock.clone());
        let (state, schedule, token): (String, Option<i64>, Option<Vec<u8>>) = recovered
            .db
            .conn
            .query_row(
                "SELECT state,schedule_id,lease_token FROM frontier WHERE url_key=?1",
                [key.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, "ready");
        assert!(schedule.is_none());
        assert!(token.is_none());
        let recovered_due: i64 = recovered
            .db
            .conn
            .query_row(
                "SELECT next_request_ms FROM origin_state WHERE origin=?1",
                [&origin],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recovered_due, 100_250);
        clock.set(100_250);
        assert_eq!(
            recovered
                .run_until_idle(&CrawlCancellation::default())
                .unwrap()
                .requests,
            1,
            "recovered work refreshes robots before the page request"
        );
        clock.set(100_500);
        assert_eq!(
            recovered
                .run_until_idle(&CrawlCancellation::default())
                .unwrap()
                .indexed,
            1
        );
        assert_eq!(fixture.accepted_connections(), 2);
        assert!(matches!(
            index.apply(
                &stale_lease,
                Intent::Upsert {
                    effective_url: key.as_str().to_owned(),
                    title: "stale attempt".to_owned(),
                    body: "must not replace recovery".to_owned(),
                }
            ),
            Err(StorageError::StaleFence)
        ));
        assert_eq!(index.query("frontier").unwrap().len(), 1);
        assert_reference_parity(&index, &[key.as_str().to_owned()], "frontier AND restart");
    }

    #[test]
    fn abandoned_robots_refresh_recovers_quiet_period_for_all_admitted_origins() {
        let alias = "robots-recovery-hop.fixture.test";
        let fixture = LocalFixture::start_with_origin(|origin| {
            let port = Url::parse(origin.url("/").unwrap().as_str())
                .unwrap()
                .port()
                .unwrap();
            vec![(
                "/robots.txt".to_owned(),
                FixtureResponse::redirect(format!("http://{alias}:{port}/hop")),
            )]
        })
        .unwrap();
        let original_origin = fixture.base_url().origin().ascii_serialization();
        let port = fixture.base_url().port().unwrap();
        let endpoint: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut mapping = BTreeMap::from([("127.0.0.1".to_owned(), vec![endpoint])]);
        mapping.insert(alias.to_owned(), vec![endpoint]);
        let mut capabilities = vec![fixture.capability()];
        capabilities.push(
            fixture
                .capability()
                .named_for_host(alias)
                .expect("alias of an owned listener"),
        );
        let redirected_origin = format!("http://{alias}:{port}");
        let origins = vec![original_origin, redirected_origin];
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let frontier_path = temp.path().join("frontier.sqlite");
        let clock = ManualClock::new(200_000);
        let resolver = FixtureResolver(Arc::new(mapping));
        let mut crawler = ControlledCrawler::open(
            &frontier_path,
            Arc::clone(&index),
            resolver.clone(),
            capabilities.clone(),
            CrawlLimits::default(),
            clock.clone(),
        )
        .unwrap();
        let mut source = SourcePolicy::owned_fixture(
            "robots-recovery",
            origins.clone(),
            vec!["/".to_owned()],
            1_000_000,
        );
        source.min_origin_delay_ms = 250;
        let seed = fixture_seed(&fixture, "/");
        crawler
            .admit_source(source, std::slice::from_ref(&seed))
            .unwrap();
        drop(crawler);
        let legacy = Connection::open(&frontier_path).unwrap();
        legacy
            .execute_batch("DROP TABLE robots_inflight; PRAGMA user_version=4;")
            .unwrap();
        drop(legacy);
        let mut crawler = ControlledCrawler::open(
            &frontier_path,
            Arc::clone(&index),
            resolver.clone(),
            capabilities.clone(),
            CrawlLimits::default(),
            clock.clone(),
        )
        .unwrap();
        let preserved_sources: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM source_policy", [], |row| row.get(0))
            .unwrap();
        assert_eq!(preserved_sources, 1);
        let mut report = CrawlReport::default();
        let job = crawler
            .next_job(&mut report, 0, 0, 1, &HashMap::new(), &HashSet::new())
            .unwrap()
            .expect("robots refresh should be dispatched first");
        assert!(matches!(&job, WorkerJob::Robots(_)));
        let marker_count: i64 = crawler
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM robots_inflight", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker_count, 1);
        drop(job);
        drop(crawler);

        let recovered = ControlledCrawler::open(
            &frontier_path,
            index,
            resolver,
            capabilities,
            CrawlLimits::default(),
            clock,
        )
        .unwrap();
        assert_eq!(
            recovered
                .db
                .conn
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5
        );
        for origin in origins {
            let due: i64 = recovered
                .db
                .conn
                .query_row(
                    "SELECT next_request_ms FROM origin_state WHERE origin=?1",
                    [&origin],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(due, 200_250, "restart must quiet admitted origin {origin}");
        }
        let marker_count: i64 = recovered
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM robots_inflight", [], |row| row.get(0))
            .unwrap();
        assert_eq!(marker_count, 0);
        assert_eq!(fixture.accepted_connections(), 0);
    }

    #[test]
    fn retention_expiry_tombstones_content_and_unowned_admission_is_rejected() {
        let fixture = LocalFixture::start([
            (
                "/robots.txt".to_owned(),
                FixtureResponse::text("User-agent: LeyBot\nAllow: /\n"),
            ),
            (
                "/".to_owned(),
                FixtureResponse::html("<title>Retention test</title><p>retained marker</p>"),
            ),
        ])
        .unwrap();
        let temp = TestDir::new();
        let index = Arc::new(PersistentIndex::create(temp.path().join("index")).unwrap());
        let clock = ManualClock::new(110_000);
        let mut crawler = open_fixture_crawler(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            &fixture,
            clock.clone(),
        );
        let mut retention_policy = policy(&fixture, "retention", clock.now_ms());
        retention_policy.retention = RetentionPolicy::Until(clock.now_ms() + 5_000);
        crawler
            .admit_source(retention_policy, &[fixture_seed(&fixture, "/")])
            .unwrap();
        assert_eq!(
            crawler
                .run_until_idle(&CrawlCancellation::default())
                .unwrap()
                .indexed,
            1
        );
        assert_eq!(index.query("retained").unwrap().len(), 1);
        clock.set(115_000);
        crawler
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert!(index.query("retained").unwrap().is_empty());
        let lifecycle: String = crawler
            .db
            .conn
            .query_row(
                "SELECT lifecycle FROM source_policy WHERE source_id='retention'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lifecycle, "revoked");
        assert_eq!(
            fixture.accepted_connections(),
            2,
            "expiry publishes removal without fetching again"
        );

        let denied_temp = TestDir::new();
        let denied_index =
            Arc::new(PersistentIndex::create(denied_temp.path().join("index")).unwrap());
        let denied_clock = ManualClock::new(120_000);
        let mut denied = open_fixture_crawler(
            &denied_temp.path().join("frontier.sqlite"),
            denied_index,
            &fixture,
            denied_clock.clone(),
        );
        let mut unowned = policy(&fixture, "unowned", denied_clock.now_ms());
        unowned.allowed_origins = vec!["http://198.51.100.10:80".to_owned()];
        let seed = UrlKey::parse("http://198.51.100.10/").unwrap();
        assert!(matches!(
            denied.admit_source(unowned, &[seed]),
            Err(CrawlError::Policy(_))
        ));
        assert_eq!(
            fixture.accepted_connections(),
            2,
            "unowned authority was denied before any request"
        );
        let source_count: i64 = denied
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM source_policy", [], |row| row.get(0))
            .unwrap();
        assert_eq!(source_count, 0);
    }

    #[test]
    fn a_conflicting_same_fence_outbox_intent_is_rejected_not_counted_as_success() {
        let temp = TestDir::new();
        PersistentIndex::create(temp.path().join("index")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "controlled_crawler::tests::outbox_crash_child",
                "--nocapture",
            ])
            .env("LEY_GATE4_CHILD", "1")
            .env("LEY_GATE4_ROOT", temp.path())
            .env("LEY_GATE4_FAILPOINT", "")
            .env("LEY_STORAGE_FAILPOINT", "apply_before_publish")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(86));

        let frontier = Connection::open(temp.path().join("frontier.sqlite")).unwrap();
        let (key_text, token): (String, Vec<u8>) = frontier
            .query_row(
                "SELECT url_key,lease_token FROM outbox WHERE kind=0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        drop(frontier);
        let key = UrlKey::parse(&key_text).unwrap();
        let index = Arc::new(PersistentIndex::open(temp.path().join("index")).unwrap());
        let lease = index.restore_lease(&token).unwrap();
        assert_eq!(
            index.apply(&lease, Intent::Tombstone).unwrap(),
            ApplyOutcome::Applied
        );
        let mut recovery = ControlledCrawler::<SystemResolver, ManualClock>::open(
            &temp.path().join("frontier.sqlite"),
            Arc::clone(&index),
            SystemResolver,
            Vec::new(),
            CrawlLimits::default(),
            ManualClock::new(SystemClock.now_ms()),
        )
        .unwrap();
        let report = recovery
            .run_until_idle(&CrawlCancellation::default())
            .unwrap();
        assert_eq!(report.rejected_intents, 1);
        assert_eq!(report.outbox_replays, 0);
        assert!(index.query("subprocess").unwrap().is_empty());
        let status: String = recovery
            .db
            .conn
            .query_row("SELECT status FROM outbox WHERE kind=0", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(status, "rejected");
        assert_reference_parity(&index, &[key.as_str().to_owned()], "subprocess AND parity");
    }
}
