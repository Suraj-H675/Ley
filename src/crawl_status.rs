use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use url::Url;

use crate::storage::PersistentIndex;

const FRONTIER_SCHEMA_VERSION: i64 = 5;
const MAX_EVENT_ROWS: u64 = 100_000;
const MAX_STATUS_ITEMS: usize = 50;
const MAX_STATUS_TEXT_BYTES: usize = 1_024;
const MAX_STATUS_FRONTIER_URLS: usize = 10_000;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CrawlStatus {
    schema: &'static str,
    read_only: bool,
    store: StoreStatus,
    frontier: FrontierStatus,
    time: TimeStatus,
    sources: Vec<SourceStatus>,
    definitions: StatusDefinitions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoreStatus {
    path: String,
    identity: String,
    generation: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrontierStatus {
    path: String,
    schema_version: i64,
    event_log: EventLogStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventLogStatus {
    bounded: bool,
    maximum_rows: u64,
    rows_now: u64,
    older_events_may_have_been_evicted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TimeStatus {
    basis: &'static str,
    now_ms: u64,
    fixture_clock_path: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceStatus {
    id: String,
    origins: Vec<String>,
    origin_schedule: Vec<OriginScheduleStatus>,
    allowed_path_prefixes: Vec<String>,
    rights_basis: String,
    lifecycle: String,
    valid_until_ms: u64,
    policy_expired_at_status_time: bool,
    retention_expired_at_status_time: bool,
    expired_at_status_time: bool,
    retention_until_ms: u64,
    persistent_requests: RequestBudgetStatus,
    frontier_state_counts: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frontier_url_inventory: Option<Vec<FrontierUrlStatus>>,
    due_work_count: u64,
    next_due_ms: Option<u64>,
    currently_indexed_live_urls: usize,
    removed_frontier_urls: u64,
    pending_outbox_count: u64,
    rejected_outbox_count: u64,
    pending_or_rejected_intents_truncated: bool,
    pending_or_rejected_intents: Vec<OutboxStatus>,
    latest_retry_or_failure_events_truncated: bool,
    latest_retry_or_failure_events: Vec<EventStatus>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrontierUrlStatus {
    url_key: String,
    state: String,
    due_ms: u64,
    indexed_live: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OriginScheduleStatus {
    origin: String,
    next_request_ms: u64,
    backoff_until_ms: u64,
    consecutive_failures: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestBudgetStatus {
    persistent_used: u64,
    persistent_limit: u64,
    persistent_remaining: u64,
    persistent_counter_semantics: &'static str,
    per_invocation_counters_persisted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutboxStatus {
    id: i64,
    url_key: String,
    kind: i64,
    status: String,
    error: String,
    error_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EventStatus {
    sequence: i64,
    occurred_ms: u64,
    url_key: String,
    state: String,
    reason: String,
    reason_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusDefinitions {
    due_work: &'static str,
    indexed_live_urls: &'static str,
    removed_frontier_urls: &'static str,
    last_fetch: &'static str,
    private_html_or_body_in_output: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureClockFile {
    schema: String,
    now_ms: u64,
    time_basis: String,
}

pub(crate) fn status_json(
    store_path: &Path,
    frontier_path: &Path,
    source_id: Option<&str>,
    fixture_clock_path: Option<&Path>,
    include_url_inventory: bool,
) -> Result<String, String> {
    let store_path = checked_directory(store_path, "store")?;
    let frontier_path = checked_regular_file(frontier_path, "frontier")?;
    let _owner_lock = acquire_frontier_reader(&frontier_path)?;
    let inspection = PersistentIndex::inspect_read_only(&store_path)
        .map_err(|error| format!("could not inspect index read-only: {error}"))?;
    let time = match fixture_clock_path {
        Some(path) => read_fixture_clock(path)?,
        None => TimeStatus {
            basis: "system-utc",
            now_ms: system_time_ms()?,
            fixture_clock_path: None,
        },
    };
    let connection = Connection::open_with_flags(
        &frontier_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("could not open frontier read-only: {error}"))?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|error| format!("could not enforce SQLite query-only mode: {error}"))?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|error| format!("could not disable trusted SQLite schema: {error}"))?;
    let mut connection = connection;
    let transaction = connection
        .transaction()
        .map_err(|error| format!("could not start read-only snapshot: {error}"))?;
    let schema_version: i64 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| format!("could not read frontier schema version: {error}"))?;
    if schema_version != FRONTIER_SCHEMA_VERSION {
        return Err(format!(
            "unsupported frontier database version {schema_version}; expected {FRONTIER_SCHEMA_VERSION}; no migration was attempted"
        ));
    }
    validate_schema(&transaction)?;
    let stored_identity: Vec<u8> = transaction
        .query_row(
            "SELECT value FROM frontier_meta WHERE key='index_store_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("frontier store identity is unavailable: {error}"))?;
    if stored_identity.as_slice() != inspection.store_id {
        return Err("frontier database belongs to a different index store".to_owned());
    }
    let event_rows: i64 = transaction
        .query_row("SELECT COUNT(*) FROM crawl_event", [], |row| row.get(0))
        .map_err(|error| format!("could not count persisted crawl events: {error}"))?;
    if event_rows < 0 || event_rows as u64 > MAX_EVENT_ROWS {
        return Err("frontier event log exceeds its declared row bound".to_owned());
    }

    let source_ids = select_source_ids(&transaction, source_id)?;
    let mut sources = Vec::with_capacity(source_ids.len());
    for id in source_ids {
        sources.push(read_source_status(
            &transaction,
            &id,
            time.now_ms,
            &inspection.live_document_keys,
            include_url_inventory,
        )?);
    }
    if fixture_clock_path.is_none()
        && sources
            .iter()
            .any(|source| source.rights_basis == "authored_local_fixture")
    {
        return Err(
            "fixture source status requires --fixture-clock so due work uses its persisted logical time"
                .to_owned(),
        );
    }
    transaction
        .commit()
        .map_err(|error| format!("could not finish read-only snapshot: {error}"))?;
    let status = CrawlStatus {
        schema: "ley-crawl-status-v1",
        read_only: true,
        store: StoreStatus {
            path: store_path.display().to_string(),
            identity: hex(&inspection.store_id),
            generation: inspection.generation_id,
        },
        frontier: FrontierStatus {
            path: frontier_path.display().to_string(),
            schema_version,
            event_log: EventLogStatus {
                bounded: true,
                maximum_rows: MAX_EVENT_ROWS,
                rows_now: event_rows as u64,
                older_events_may_have_been_evicted: event_rows as u64 == MAX_EVENT_ROWS,
            },
        },
        time,
        sources,
        definitions: StatusDefinitions {
            due_work: "ready, deferred, or complete URLs whose frontier due time and persisted origin next-request/backoff times are due for an active, unexpired source; request-budget availability and robots revalidation can still prevent dispatch",
            indexed_live_urls: "frontier URL keys for this source intersected with the current committed index live-key set",
            removed_frontier_urls: "frontier rows in state removed; this reports durable removal state, not physical segment reclamation",
            last_fetch: "not available: the schema has no reliable per-URL last-fetch timestamp",
            private_html_or_body_in_output: false,
        },
    };
    serde_json::to_string_pretty(&status)
        .map_err(|error| format!("could not serialize status: {error}"))
}

pub(crate) fn validate_existing_frontier(
    path: &Path,
    expected_store_id: [u8; 16],
) -> Result<(), String> {
    let frontier_path = checked_regular_file(path, "frontier")?;
    let connection = Connection::open_with_flags(
        frontier_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("could not inspect existing frontier read-only: {error}"))?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| format!("could not read existing frontier version: {error}"))?;
    if schema_version != FRONTIER_SCHEMA_VERSION {
        return Err(format!(
            "existing frontier schema is version {schema_version}; expected {FRONTIER_SCHEMA_VERSION}; no migration was attempted"
        ));
    }
    validate_schema(&connection)?;
    let stored_identity: Vec<u8> = connection
        .query_row(
            "SELECT value FROM frontier_meta WHERE key='index_store_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| format!("existing frontier store identity is unavailable: {error}"))?;
    if stored_identity.as_slice() != expected_store_id {
        return Err("frontier database belongs to a different index store".to_owned());
    }
    Ok(())
}

fn read_source_status(
    connection: &Connection,
    source_id: &str,
    now_ms: u64,
    index_keys: &BTreeSet<String>,
    include_url_inventory: bool,
) -> Result<SourceStatus, String> {
    let (origins, paths, valid_until, rights_basis, retention_until, max_requests, request_count, lifecycle) = connection
        .query_row(
            "SELECT origins,paths,valid_until_ms,rights_basis,retention_until_ms,max_requests,request_count,lifecycle FROM source_policy WHERE source_id=?1",
            [source_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?, row.get::<_, String>(7)?)),
        )
        .map_err(|error| format!("could not read source policy {source_id:?}: {error}"))?;
    let valid_until = nonnegative_u64(valid_until, "source expiry")?;
    let retention_until = nonnegative_u64(retention_until, "source retention expiry")?;
    let max_requests = nonnegative_u64(max_requests, "source request limit")?;
    let request_count = nonnegative_u64(request_count, "source request count")?;
    let policy_expired = valid_until <= now_ms;
    let retention_expired = retention_until != 0 && retention_until <= now_ms;
    let source_currently_eligible = lifecycle == "active" && !policy_expired && !retention_expired;

    let mut frontier_state_counts = BTreeMap::new();
    let mut due_work_count = 0u64;
    let mut next_due_ms = None;
    let mut currently_indexed_live_urls = 0usize;
    let mut removed_frontier_urls = 0u64;
    let mut origin_schedule = BTreeMap::new();
    let mut frontier_url_inventory = include_url_inventory.then(Vec::new);
    for origin in split_lines(origins.clone()) {
        let state_key = origin_state_key(&origin)?;
        origin_schedule.insert(
            state_key.clone(),
            read_origin_schedule(connection, &state_key)?,
        );
    }
    {
        let mut statement = connection
            .prepare("SELECT url_key,state,due_ms,fetch_url FROM frontier WHERE source_id=?1")
            .map_err(|error| format!("could not inspect source frontier: {error}"))?;
        let rows = statement
            .query_map([source_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|error| format!("could not read source frontier: {error}"))?;
        for row in rows {
            let (url_key, state, due, fetch_url) =
                row.map_err(|error| format!("invalid frontier row: {error}"))?;
            let due = nonnegative_u64(due, "frontier due time")?;
            *frontier_state_counts.entry(state.clone()).or_insert(0) += 1;
            if index_keys.contains(&url_key) {
                currently_indexed_live_urls += 1;
            }
            if let Some(inventory) = frontier_url_inventory.as_mut() {
                if inventory.len() >= MAX_STATUS_FRONTIER_URLS {
                    return Err(format!(
                        "source frontier exceeds the bounded URL inventory limit of {MAX_STATUS_FRONTIER_URLS}"
                    ));
                }
                inventory.push(FrontierUrlStatus {
                    indexed_live: index_keys.contains(&url_key),
                    url_key,
                    state: state.clone(),
                    due_ms: due,
                });
            }
            if state == "removed" {
                removed_frontier_urls += 1;
            }
            let eligible_state = matches!(state.as_str(), "ready" | "deferred" | "complete");
            if source_currently_eligible && eligible_state {
                let state_key = origin_state_key(&fetch_url)?;
                if !origin_schedule.contains_key(&state_key) {
                    origin_schedule.insert(
                        state_key.clone(),
                        read_origin_schedule(connection, &state_key)?,
                    );
                }
                let origin_state = origin_schedule
                    .get(&state_key)
                    .expect("origin schedule was inserted above");
                let effective_due = due
                    .max(origin_state.next_request_ms)
                    .max(origin_state.backoff_until_ms);
                if effective_due <= now_ms {
                    due_work_count += 1;
                }
                next_due_ms = Some(
                    next_due_ms.map_or(effective_due, |current: u64| current.min(effective_due)),
                );
            }
        }
    }

    let pending_outbox_count = count_outbox(connection, source_id, "pending")?;
    let rejected_outbox_count = count_outbox(connection, source_id, "rejected")?;
    let pending_or_rejected_intents = read_outbox_items(connection, source_id)?;
    let pending_or_rejected_intents_truncated = pending_outbox_count
        .saturating_add(rejected_outbox_count)
        > pending_or_rejected_intents.len() as u64;
    let failure_event_count = count_recent_events(connection, source_id)?;
    let latest_retry_or_failure_events = read_recent_events(connection, source_id)?;
    let latest_retry_or_failure_events_truncated =
        failure_event_count > latest_retry_or_failure_events.len() as u64;

    Ok(SourceStatus {
        id: source_id.to_owned(),
        origins: split_lines(origins),
        origin_schedule: origin_schedule.into_values().collect(),
        allowed_path_prefixes: split_lines(paths),
        rights_basis,
        lifecycle,
        valid_until_ms: valid_until,
        policy_expired_at_status_time: policy_expired,
        retention_expired_at_status_time: retention_expired,
        expired_at_status_time: policy_expired || retention_expired,
        retention_until_ms: retention_until,
        persistent_requests: RequestBudgetStatus {
            persistent_used: request_count,
            persistent_limit: max_requests,
            persistent_remaining: max_requests.saturating_sub(request_count),
            persistent_counter_semantics: "source_policy.request_count includes page accounting and robots request reservations; it is not a count of successful HTTP responses",
            per_invocation_counters_persisted: false,
        },
        frontier_state_counts,
        frontier_url_inventory,
        due_work_count,
        next_due_ms,
        currently_indexed_live_urls,
        removed_frontier_urls,
        pending_outbox_count,
        rejected_outbox_count,
        pending_or_rejected_intents_truncated,
        pending_or_rejected_intents,
        latest_retry_or_failure_events_truncated,
        latest_retry_or_failure_events,
    })
}

fn count_outbox(connection: &Connection, source_id: &str, status: &str) -> Result<u64, String> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE source_id=?1 AND status=?2",
            params![source_id, status],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not count {status} outbox intents: {error}"))?;
    nonnegative_u64(count, "outbox count")
}

fn read_outbox_items(
    connection: &Connection,
    source_id: &str,
) -> Result<Vec<OutboxStatus>, String> {
    let mut statement = connection
        .prepare("SELECT id,url_key,kind,status,error FROM outbox WHERE source_id=?1 AND status IN ('pending','rejected') ORDER BY id DESC LIMIT ?2")
        .map_err(|error| format!("could not prepare outbox status query: {error}"))?;
    let rows = statement
        .query_map(params![source_id, MAX_STATUS_ITEMS as i64], |row| {
            let error = row.get::<_, String>(4)?;
            let (error, error_truncated) = truncate_status_text(error);
            Ok(OutboxStatus {
                id: row.get(0)?,
                url_key: row.get(1)?,
                kind: row.get(2)?,
                status: row.get(3)?,
                error,
                error_truncated,
            })
        })
        .map_err(|error| format!("could not read outbox status: {error}"))?;
    rows.map(|row| row.map_err(|error| format!("invalid outbox status row: {error}")))
        .collect()
}

fn read_recent_events(
    connection: &Connection,
    source_id: &str,
) -> Result<Vec<EventStatus>, String> {
    let mut statement = connection
        .prepare("SELECT sequence,occurred_ms,url_key,state,reason FROM crawl_event WHERE source_id=?1 AND (state IN ('retry','failed','deferred') OR state LIKE '%retry%' OR state LIKE '%fail%' OR state LIKE '%denied%' OR state LIKE '%unavailable%' OR state LIKE '%reject%') ORDER BY sequence DESC LIMIT ?2")
        .map_err(|error| format!("could not prepare crawl event query: {error}"))?;
    let rows = statement
        .query_map(params![source_id, MAX_STATUS_ITEMS as i64], |row| {
            let occurred: i64 = row.get(1)?;
            let reason = row.get::<_, String>(4)?;
            let (reason, reason_truncated) = truncate_status_text(reason);
            Ok(EventStatus {
                sequence: row.get(0)?,
                occurred_ms: occurred.max(0) as u64,
                url_key: row.get(2)?,
                state: row.get(3)?,
                reason,
                reason_truncated,
            })
        })
        .map_err(|error| format!("could not read crawl event status: {error}"))?;
    rows.map(|row| row.map_err(|error| format!("invalid crawl event row: {error}")))
        .collect()
}

fn count_recent_events(connection: &Connection, source_id: &str) -> Result<u64, String> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM crawl_event WHERE source_id=?1 AND (state IN ('retry','failed','deferred') OR state LIKE '%retry%' OR state LIKE '%fail%' OR state LIKE '%denied%' OR state LIKE '%unavailable%' OR state LIKE '%reject%')",
            [source_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("could not count persisted retry/failure events: {error}"))?;
    nonnegative_u64(count, "persisted retry/failure event count")
}

fn select_source_ids(
    connection: &Connection,
    requested: Option<&str>,
) -> Result<Vec<String>, String> {
    if let Some(source_id) = requested {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_policy WHERE source_id=?1)",
                [source_id],
                |row| row.get(0),
            )
            .map_err(|error| format!("could not validate source ID: {error}"))?;
        return if exists {
            Ok(vec![source_id.to_owned()])
        } else {
            Err(format!("source policy {source_id:?} does not exist"))
        };
    }
    let mut statement = connection
        .prepare("SELECT source_id FROM source_policy ORDER BY source_id")
        .map_err(|error| format!("could not list source policies: {error}"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| format!("could not list source policies: {error}"))?;
    rows.map(|row| row.map_err(|error| format!("invalid source ID row: {error}")))
        .collect()
}

fn validate_schema(connection: &Connection) -> Result<(), String> {
    let required = [
        ("frontier_meta", ["key", "value"].as_slice()),
        (
            "source_policy",
            [
                "source_id",
                "origins",
                "paths",
                "valid_until_ms",
                "rights_basis",
                "retention_until_ms",
                "max_requests",
                "request_count",
                "lifecycle",
            ]
            .as_slice(),
        ),
        (
            "frontier",
            [
                "url_key",
                "source_id",
                "state",
                "due_ms",
                "attempts",
                "reason",
                "revocation_published",
                "readmitted",
            ]
            .as_slice(),
        ),
        (
            "outbox",
            ["id", "url_key", "source_id", "kind", "status", "error"].as_slice(),
        ),
        (
            "crawl_event",
            [
                "sequence",
                "occurred_ms",
                "source_id",
                "url_key",
                "state",
                "reason",
            ]
            .as_slice(),
        ),
        (
            "origin_state",
            ["origin", "next_request_ms", "backoff_until_ms", "failures"].as_slice(),
        ),
    ];
    for (table, columns) in required {
        let mut statement = connection
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .map_err(|error| format!("could not inspect SQLite table {table}: {error}"))?;
        let rows = statement
            .query_map([table], |row| row.get::<_, String>(0))
            .map_err(|error| format!("could not inspect SQLite table {table}: {error}"))?;
        let existing: BTreeSet<String> = rows
            .map(|row| row.map_err(|error| format!("invalid table info: {error}")))
            .collect::<Result<_, _>>()?;
        if columns.iter().any(|column| !existing.contains(*column)) {
            return Err(format!(
                "frontier table {table} lacks a required column; no repair or migration was attempted"
            ));
        }
    }
    Ok(())
}

fn acquire_frontier_reader(path: &Path) -> Result<fs::File, String> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".owner.lock");
    let lock_path = PathBuf::from(lock_path);
    let metadata = fs::symlink_metadata(&lock_path)
        .map_err(|error| format!("frontier owner lock is unavailable: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("frontier owner lock must be a regular file".to_owned());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock_path)
        .map_err(|error| format!("could not open frontier owner lock read-only: {error}"))?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err("frontier has a live coordinator; status was not read".to_owned());
        }
        return Err(format!(
            "could not acquire read-only frontier lock: {error}"
        ));
    }
    Ok(file)
}

fn checked_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} path is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} path must be a directory, not a symlink"));
    }
    fs::canonicalize(path).map_err(|error| format!("could not canonicalize {label} path: {error}"))
}

fn checked_regular_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} path is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} path must be a regular file, not a symlink"
        ));
    }
    fs::canonicalize(path).map_err(|error| format!("could not canonicalize {label} path: {error}"))
}

fn read_fixture_clock(path: &Path) -> Result<TimeStatus, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("fixture logical clock is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
        return Err("fixture logical clock must be a small regular file, not a symlink".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| format!("could not read fixture clock: {error}"))?;
    let clock: FixtureClockFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("fixture clock is invalid: {error}"))?;
    if clock.schema != "ley-fixture-clock-v1" || clock.time_basis != "fixture-logical" {
        return Err("fixture clock has an unknown schema or time basis".to_owned());
    }
    Ok(TimeStatus {
        basis: "fixture-logical",
        now_ms: clock.now_ms,
        fixture_clock_path: Some(
            fs::canonicalize(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
                .to_string(),
        ),
    })
}

fn system_time_ms() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system UTC time is unavailable: {error}"))?
        .as_millis()
        .min(u64::MAX as u128) as u64)
}

fn origin_state_key(value: &str) -> Result<String, String> {
    let url = Url::parse(value).map_err(|error| format!("invalid frontier origin URL: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "frontier origin URL has no host".to_owned())?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "frontier origin URL has no known port".to_owned())?;
    Ok(format!(
        "{}://{host}:{port}",
        url.scheme().to_ascii_lowercase()
    ))
}

fn read_origin_schedule(
    connection: &Connection,
    origin: &str,
) -> Result<OriginScheduleStatus, String> {
    let persisted: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT next_request_ms,backoff_until_ms,failures FROM origin_state WHERE origin=?1",
            [origin],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| format!("could not read persisted origin schedule: {error}"))?;
    let (next_request_ms, backoff_until_ms, failures) = persisted.unwrap_or((0, 0, 0));
    Ok(OriginScheduleStatus {
        origin: origin.to_owned(),
        next_request_ms: nonnegative_u64(next_request_ms, "origin next-request time")?,
        backoff_until_ms: nonnegative_u64(backoff_until_ms, "origin backoff time")?,
        consecutive_failures: nonnegative_u64(failures, "origin failure count")?,
    })
}

fn split_lines(value: String) -> Vec<String> {
    value
        .split('\n')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{label} is negative or out of range"))
}

fn truncate_status_text(value: String) -> (String, bool) {
    if value.len() <= MAX_STATUS_TEXT_BYTES {
        return (value, false);
    }
    let mut end = MAX_STATUS_TEXT_BYTES - '…'.len_utf8();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}…", &value[..end]), true)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
