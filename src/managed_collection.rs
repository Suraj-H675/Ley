//! Repeatable, offline synchronization of one operator-selected HTML directory.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::analyzer::ANALYZER_ID;
use crate::html::{self, HTML_SCHEMA_ID};
use crate::index::InMemoryIndex;
use crate::storage::{
    ManagedBatchAction, ManagedBatchIntent, ManagedExpectedState, ManagedReservation,
    ManagedStorageError, ManagedStoreSnapshot, PersistentIndex, StorageError,
};
use crate::url_key::UrlKey;

const OWNER_STATE_NAME: &str = "LOCAL_COLLECTION";
const OWNER_STATE_TEMP_NAME: &str = ".LOCAL_COLLECTION.tmp";
const OWNER_LOCK_NAME: &str = ".LOCAL_COLLECTION_LOCK";
const OWNER_STATE_SCHEMA: &str = "ley-managed-local-html-v1";
const MAX_OWNER_STATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_OWNED_PATH_RECORDS: usize = 4096;
const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";

#[derive(Debug)]
pub(crate) enum ManagedCollectionError {
    InvalidCommand,
    InvalidArguments(String),
    InvalidSource(String),
    InvalidStore(String),
    SourceChanged,
    ForeignUrlCollision(String),
    OwnershipConflict(String),
    PendingRecovery(String),
    Io(io::Error),
    Storage(StorageError),
    ManagedStorage(ManagedStorageError),
    Html(String),
    Url(String),
}

impl fmt::Display for ManagedCollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCommand => f.write_str(
                "usage: local-collection init|sync|status [--store PATH] [--directory DIR --url-prefix URL]",
            ),
            Self::InvalidArguments(message)
            | Self::InvalidSource(message)
            | Self::InvalidStore(message)
            | Self::OwnershipConflict(message)
            | Self::PendingRecovery(message)
            | Self::Html(message)
            | Self::Url(message) => f.write_str(message),
            Self::SourceChanged => f.write_str(
                "the selected source changed during the bounded scan; no removals were applied",
            ),
            Self::ForeignUrlCollision(url) => write!(
                f,
                "URL identity {url} is already live or has lifecycle history outside this collection"
            ),
            Self::Io(error) => write!(f, "managed collection I/O error: {error}"),
            Self::Storage(error) => write!(f, "managed collection storage error: {error}"),
            Self::ManagedStorage(error) => write!(f, "managed collection storage error: {error}"),
        }
    }
}

impl std::error::Error for ManagedCollectionError {}

impl From<io::Error> for ManagedCollectionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StorageError> for ManagedCollectionError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}

impl From<ManagedStorageError> for ManagedCollectionError {
    fn from(value: ManagedStorageError) -> Self {
        Self::ManagedStorage(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerState {
    schema: String,
    collection_id: String,
    store_id: [u8; 16],
    store_path: String,
    source_path: String,
    source_device: u64,
    source_inode: u64,
    url_prefix: String,
    analyzer_id: String,
    html_schema_id: String,
    lifecycle: String,
    entries: BTreeMap<String, OwnerEntry>,
    last_sync: Option<SyncCounts>,
    last_failure: Option<String>,
    last_ack: Option<AckRecord>,
    pending: Option<PendingSync>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerEntry {
    requested_url: String,
    indexed_version: Option<String>,
    terminal_fence: Option<u64>,
    noindex: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncCounts {
    added: usize,
    changed: usize,
    removed: usize,
    noindex: usize,
    unchanged: usize,
    elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRecord {
    sync_id: String,
    base_generation: u64,
    committed_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingSync {
    reservation: ManagedReservation,
    base_segment_count: usize,
    actions: Vec<PendingAction>,
    desired_entries: BTreeMap<String, OwnerEntry>,
    counts: SyncCounts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingAction {
    requested_url: String,
    expected: ManagedExpectedState,
    kind: PendingKind,
    target_version: Option<String>,
    target_fence: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingKind {
    Upsert,
    Tombstone,
}

struct ScannedDocument {
    requested_url: UrlKey,
    effective_url: String,
    title: String,
    body: String,
    version: String,
    noindex: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct DirectoryStamp {
    file: File,
    parent: Option<(usize, CString)>,
    stamp: FileStamp,
}

struct FileBinding {
    parent_directory: usize,
    name: CString,
    stamp: FileStamp,
}

struct SourceSnapshot {
    canonical_root: PathBuf,
    root_device: u64,
    root_inode: u64,
    directories: Vec<DirectoryStamp>,
    files: BTreeMap<String, FileBinding>,
    documents: BTreeMap<String, ScannedDocument>,
}

struct StagedStoreDirectory(PathBuf);

impl Drop for StagedStoreDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Plan {
    actions: Vec<PendingAction>,
    desired_entries: BTreeMap<String, OwnerEntry>,
    counts: SyncCounts,
}

pub(crate) fn run_cli(args: Vec<String>) -> Result<String, ManagedCollectionError> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(ManagedCollectionError::InvalidCommand);
    };
    let flags = parse_flags(&args[1..])?;
    match command {
        "init" => {
            let store = required(&flags, "--store")?;
            let directory = required(&flags, "--directory")?;
            let url_prefix = required(&flags, "--url-prefix")?;
            ensure_only_flags(&flags, &["--store", "--directory", "--url-prefix"])?;
            let status = initialize(store, directory, url_prefix)?;
            Ok(format_status(&status, "initialized"))
        }
        "sync" => {
            let store = required(&flags, "--store")?;
            let directory = required(&flags, "--directory")?;
            let url_prefix = required(&flags, "--url-prefix")?;
            ensure_only_flags(&flags, &["--store", "--directory", "--url-prefix"])?;
            let status = synchronize(store, directory, url_prefix)?;
            Ok(format_status(&status, "synced"))
        }
        "status" => {
            let store = required(&flags, "--store")?;
            ensure_only_flags(&flags, &["--store"])?;
            let status = inspect_status(store)?;
            Ok(format_status(&status, "status"))
        }
        _ => Err(ManagedCollectionError::InvalidCommand),
    }
}

#[derive(Clone)]
struct Status {
    collection_id: String,
    store_id: String,
    store_path: String,
    source_path: String,
    url_prefix: String,
    state: String,
    generation: u64,
    segments: usize,
    live_documents: usize,
    entries: usize,
    last_sync: SyncCounts,
    last_failure: Option<String>,
    pending: bool,
    source_valid: bool,
    ownership_consistent: bool,
}

fn format_status(status: &Status, operation: &str) -> String {
    let last = &status.last_sync;
    format!(
        "Managed offline HTML collection {operation}\n  collection: {}\n  store: {} ({})\n  source: {}\n  URL identity prefix: {}\n  URL fetches: none (HTTP(S) values are document identities only)\n  state: {}\n  generation: {}\n  segments: {}\n  live documents: {}\n  owned path records: {}\n  last sync: added {}, changed {}, removed {}, noindex {}, unchanged {} in {} ms\n  recovery pending: {}\n  last failure: {}",
        status.collection_id,
        status.store_path,
        status.store_id,
        status.source_path,
        status.url_prefix,
        if status.pending {
            "recovery_required"
        } else if !status.source_valid {
            "source_unavailable"
        } else if !status.ownership_consistent {
            "ownership_conflict"
        } else {
            status.state.as_str()
        },
        status.generation,
        status.segments,
        status.live_documents,
        status.entries,
        last.added,
        last.changed,
        last.removed,
        last.noindex,
        last.unchanged,
        last.elapsed_ms,
        status.pending,
        if status.pending {
            status
                .last_failure
                .as_deref()
                .unwrap_or("pending sync requires recovery")
        } else if !status.source_valid {
            "bound source directory is missing or has changed identity"
        } else if !status.ownership_consistent {
            "one or more owned index entries changed outside this collection"
        } else {
            status.last_failure.as_deref().unwrap_or("none")
        }
    )
}

fn initialize(
    store_arg: &str,
    directory_arg: &str,
    prefix_arg: &str,
) -> Result<Status, ManagedCollectionError> {
    let source_path = canonical_source_path(Path::new(directory_arg))?;
    let prefix = normalize_url_prefix(prefix_arg)?;
    let destination = canonical_new_destination(Path::new(store_arg), &source_path)?;
    let initial_source = scan_source(&source_path, &prefix)?;
    initial_source.revalidate()?;

    let staging_path = new_staged_store_path(&destination)?;
    let store = PersistentIndex::create(&staging_path)?;
    let _staged_store = StagedStoreDirectory(staging_path.clone());
    let store_path = fs::canonicalize(&staging_path)?;
    let lock_path = store_path.join(OWNER_LOCK_NAME);
    create_private_file(&lock_path, &[]).map_err(ManagedCollectionError::Io)?;
    let _collection_lock = CollectionLock::open(&lock_path)?;
    let store_snapshot = store.managed_snapshot()?;
    if store_snapshot.generation_id != 1 || !store_snapshot.documents.is_empty() {
        return Err(ManagedCollectionError::InvalidStore(
            "new managed collection did not start with an empty index".to_owned(),
        ));
    }
    let mut owner = OwnerState {
        schema: OWNER_STATE_SCHEMA.to_owned(),
        collection_id: random_id()?,
        store_id: store.store_identity(),
        store_path: destination.to_string_lossy().into_owned(),
        source_path: source_path.to_string_lossy().into_owned(),
        source_device: initial_source.root_device,
        source_inode: initial_source.root_inode,
        url_prefix: prefix.as_str().to_owned(),
        analyzer_id: ANALYZER_ID.to_owned(),
        html_schema_id: HTML_SCHEMA_ID.to_owned(),
        lifecycle: "ready".to_owned(),
        entries: BTreeMap::new(),
        last_sync: None,
        last_failure: None,
        last_ack: None,
        pending: None,
    };
    write_owner_state(&store_path, &owner)?;
    if let Err(error) = initial_source.revalidate() {
        owner.last_failure = Some(error.to_string());
        owner.lifecycle = "failed".to_owned();
        let _ = write_owner_state(&store_path, &owner);
        return Err(error);
    }
    drop(initial_source);
    if let Err(error) = synchronize_locked(&store, &store_path, &mut owner, &source_path, &prefix) {
        owner.last_failure = Some(error.to_string());
        owner.lifecycle = if owner.pending.is_some() {
            "recovery_required".to_owned()
        } else {
            "failed".to_owned()
        };
        let _ = write_owner_state(&store_path, &owner);
        return Err(error);
    }
    store.publish_managed_collection(&destination)?;
    let published_store = PersistentIndex::open(&destination)?;
    let published_owner = read_owner_state(&destination)?;
    status_from(&published_store, &destination, &published_owner)
}

fn synchronize(
    store_arg: &str,
    directory_arg: &str,
    prefix_arg: &str,
) -> Result<Status, ManagedCollectionError> {
    let store_path = canonical_existing_store_path(Path::new(store_arg))?;
    let store = PersistentIndex::open(&store_path)?;
    let lock_path = store_path.join(OWNER_LOCK_NAME);
    let _collection_lock = CollectionLock::open(&lock_path)?;
    let mut owner = read_owner_state(&store_path)?;
    validate_store_binding(&store, &store_path, &owner)?;
    let result = (|| {
        let directory = canonical_source_path(Path::new(directory_arg))?;
        let prefix = normalize_url_prefix(prefix_arg)?;
        validate_binding(&store, &store_path, &directory, &prefix, &owner)?;
        synchronize_locked(&store, &store_path, &mut owner, &directory, &prefix)
    })();
    if let Err(error) = result {
        owner.last_failure = Some(error.to_string());
        owner.lifecycle = if owner.pending.is_some() {
            "recovery_required".to_owned()
        } else {
            "failed".to_owned()
        };
        let _ = write_owner_state(&store_path, &owner);
        return Err(error);
    }
    status_from(&store, &store_path, &owner)
}

fn inspect_status(store_arg: &str) -> Result<Status, ManagedCollectionError> {
    let store_path = canonical_existing_store_path(Path::new(store_arg))?;
    let store = PersistentIndex::open(&store_path)?;
    let _collection_lock = CollectionLock::open(&store_path.join(OWNER_LOCK_NAME))?;
    let mut owner = read_owner_state(&store_path)?;
    validate_store_binding(&store, &store_path, &owner)?;
    let reservation = store.managed_reservation()?;
    match (&owner.pending, &reservation) {
        (Some(pending), Some(reservation)) if &pending.reservation == reservation => {}
        (None, Some(reservation))
            if owner.last_ack.as_ref().is_some_and(|ack| {
                ack.sync_id == reservation.sync_id
                    && ack.base_generation == reservation.base_generation
            }) => {}
        (None, None) => {}
        _ => {
            owner.lifecycle = "recovery_required".to_owned();
            owner.last_failure = Some("reservation and owner metadata do not agree".to_owned());
            write_owner_state(&store_path, &owner)?;
        }
    }
    status_from(&store, &store_path, &owner)
}

fn synchronize_locked(
    store: &PersistentIndex,
    store_path: &Path,
    owner: &mut OwnerState,
    source_path: &Path,
    prefix: &Url,
) -> Result<(), ManagedCollectionError> {
    recover_pending(store, store_path, owner, source_path, prefix)?;
    let started = Instant::now();
    let source = scan_source(source_path, prefix)?;
    ensure_source_binding(&source, owner)?;
    source.revalidate()?;
    let snapshot = store.managed_snapshot()?;
    verify_schema(&snapshot, owner)?;
    let mut plan = make_plan(&source, &snapshot, owner)?;
    plan.counts.elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

    if plan.actions.is_empty() {
        source.revalidate()?;
        owner.entries = plan.desired_entries;
        owner.last_sync = Some(plan.counts);
        owner.lifecycle = "ready".to_owned();
        owner.last_failure = None;
        write_owner_state(store_path, owner)?;
        return Ok(());
    }

    let reservation = ManagedReservation {
        sync_id: random_id()?,
        base_generation: snapshot.generation_id,
    };
    let mut pending = PendingSync {
        reservation: reservation.clone(),
        base_segment_count: snapshot.segment_count,
        actions: std::mem::take(&mut plan.actions),
        desired_entries: plan.desired_entries,
        counts: plan.counts,
    };
    let mut pending_owner = owner.clone();
    pending_owner.pending = Some(pending.clone());
    pending_owner.lifecycle = "sync_pending".to_owned();
    pending_owner.last_failure = None;
    encode_owner_state(&pending_owner)?;
    source.revalidate()?;
    store.managed_install_reservation(&reservation)?;
    *owner = pending_owner;
    write_owner_state(store_path, owner)?;

    let current_source = scan_source(source_path, prefix)?;
    ensure_source_binding(&current_source, owner)?;
    current_source.revalidate()?;
    let current_snapshot = store.managed_snapshot()?;
    if current_snapshot.generation_id != reservation.base_generation {
        return Err(ManagedCollectionError::PendingRecovery(
            "index changed after its managed reservation was installed".to_owned(),
        ));
    }
    if !source_equivalent_for_plan(&current_source, &pending) {
        let replanned = make_plan(&current_source, &current_snapshot, owner)?;
        pending.actions = replanned.actions;
        pending.desired_entries = replanned.desired_entries;
        pending.counts = replanned.counts;
        pending.counts.elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        owner.pending = Some(pending.clone());
        write_owner_state(store_path, owner)?;
    }
    if pending.actions.is_empty() {
        owner.pending = None;
        owner.entries = pending.desired_entries;
        owner.last_sync = Some(pending.counts);
        owner.last_ack = Some(AckRecord {
            sync_id: reservation.sync_id.clone(),
            base_generation: reservation.base_generation,
            committed_generation: current_snapshot.generation_id,
        });
        owner.lifecycle = "ready".to_owned();
        owner.last_failure = None;
        write_owner_state(store_path, owner)?;
        store.managed_clear_reservation(&reservation)?;
        return Ok(());
    }

    current_source.revalidate()?;
    let actions = batch_actions(&current_source, &pending)?;
    let (generation, target_fences) = store.managed_batch(&reservation, actions)?;
    for action in &mut pending.actions {
        action.target_fence = *target_fences.get(&action.requested_url).ok_or_else(|| {
            ManagedCollectionError::PendingRecovery(
                "committed batch omitted an expected URL identity".to_owned(),
            )
        })?;
    }
    let committed_snapshot = store.managed_snapshot()?;
    if !verify_committed_target(&committed_snapshot, &pending, generation) {
        return Err(ManagedCollectionError::PendingRecovery(
            "published index does not match the complete pending target".to_owned(),
        ));
    }
    acknowledge(store, store_path, owner, pending, &committed_snapshot)
}

fn recover_pending(
    store: &PersistentIndex,
    store_path: &Path,
    owner: &mut OwnerState,
    source_path: &Path,
    prefix: &Url,
) -> Result<(), ManagedCollectionError> {
    let marker = store.managed_reservation()?;
    match (owner.pending.clone(), marker) {
        (None, None) => Ok(()),
        (None, Some(marker)) => {
            let current = store.managed_snapshot()?;
            let acknowledged = owner.last_ack.as_ref().is_some_and(|ack| {
                ack.sync_id == marker.sync_id
                    && ack.base_generation == marker.base_generation
                    && current.generation_id == ack.committed_generation
                    && (current.generation_id == marker.base_generation
                        || current.generation_id == marker.base_generation.saturating_add(1))
            });
            // The reservation was installed at this generation and blocks all
            // current writers. If it is still at its base, no managed batch
            // published; unrelated writes may have advanced the generation
            // since the previous acknowledged sync.
            let orphan_before_publish = current.generation_id == marker.base_generation;
            if acknowledged || orphan_before_publish {
                store.managed_clear_reservation(&marker)?;
                owner.lifecycle = "ready".to_owned();
                write_owner_state(store_path, owner)?;
                Ok(())
            } else {
                Err(ManagedCollectionError::PendingRecovery(
                    "reservation has no matching pending or acknowledged owner record".to_owned(),
                ))
            }
        }
        (Some(pending), Some(marker)) if pending.reservation == marker => {
            let snapshot = store.managed_snapshot()?;
            if snapshot.generation_id == marker.base_generation {
                let source = scan_source(source_path, prefix)?;
                ensure_source_binding(&source, owner)?;
                source.revalidate()?;
                let mut replanned = make_plan(&source, &snapshot, owner)?;
                replanned.counts.elapsed_ms = pending.counts.elapsed_ms;
                let mut pending = pending;
                pending.actions = replanned.actions;
                pending.desired_entries = replanned.desired_entries;
                pending.counts = replanned.counts;
                owner.pending = Some(pending.clone());
                write_owner_state(store_path, owner)?;
                if pending.actions.is_empty() {
                    owner.pending = None;
                    owner.entries = pending.desired_entries;
                    owner.last_sync = Some(pending.counts);
                    owner.last_ack = Some(AckRecord {
                        sync_id: marker.sync_id.clone(),
                        base_generation: marker.base_generation,
                        committed_generation: snapshot.generation_id,
                    });
                    owner.lifecycle = "ready".to_owned();
                    owner.last_failure = None;
                    write_owner_state(store_path, owner)?;
                    store.managed_clear_reservation(&marker)?;
                    return Ok(());
                }
                source.revalidate()?;
                let actions = batch_actions(&source, &pending)?;
                let (generation, _) = store.managed_batch(&marker, actions)?;
                let committed = store.managed_snapshot()?;
                if !verify_committed_target(&committed, &pending, generation) {
                    return Err(ManagedCollectionError::PendingRecovery(
                        "replayed batch did not match its complete target".to_owned(),
                    ));
                }
                return acknowledge(store, store_path, owner, pending, &committed);
            }
            let target_generation = marker.base_generation.checked_add(1).ok_or_else(|| {
                ManagedCollectionError::PendingRecovery("generation id exhausted".to_owned())
            })?;
            if snapshot.generation_id == target_generation
                && verify_committed_target(&snapshot, &pending, target_generation)
            {
                acknowledge(store, store_path, owner, pending, &snapshot)
            } else {
                Err(ManagedCollectionError::PendingRecovery(
                    "index is neither the reserved base nor the exact complete target".to_owned(),
                ))
            }
        }
        _ => Err(ManagedCollectionError::PendingRecovery(
            "reservation marker and pending owner intent do not match".to_owned(),
        )),
    }
}

fn acknowledge(
    store: &PersistentIndex,
    store_path: &Path,
    owner: &mut OwnerState,
    pending: PendingSync,
    snapshot: &ManagedStoreSnapshot,
) -> Result<(), ManagedCollectionError> {
    owner.entries = pending.desired_entries;
    owner.last_sync = Some(pending.counts);
    owner.last_ack = Some(AckRecord {
        sync_id: pending.reservation.sync_id.clone(),
        base_generation: pending.reservation.base_generation,
        committed_generation: snapshot.generation_id,
    });
    owner.pending = None;
    owner.lifecycle = "ready".to_owned();
    owner.last_failure = None;
    write_owner_state(store_path, owner)?;
    store.managed_clear_reservation(&pending.reservation)?;
    Ok(())
}

fn make_plan(
    source: &SourceSnapshot,
    snapshot: &ManagedStoreSnapshot,
    owner: &OwnerState,
) -> Result<Plan, ManagedCollectionError> {
    let mut plan = Plan::default();
    let mut seen_url_keys = BTreeSet::new();
    for (relative, document) in &source.documents {
        if !seen_url_keys.insert(document.requested_url.as_str().to_owned()) {
            return Err(ManagedCollectionError::InvalidSource(
                "multiple source paths map to the same URL identity".to_owned(),
            ));
        }
        if document.noindex {
            plan.counts.noindex += 1;
            let prior = owner.entries.get(relative);
            let state = snapshot_state(snapshot, document.requested_url.as_str());
            if let Some(prior) = prior {
                if prior.requested_url != document.requested_url.as_str() {
                    return Err(ManagedCollectionError::OwnershipConflict(
                        "stored source path maps to a different URL identity".to_owned(),
                    ));
                }
                if prior.indexed_version.is_some() {
                    require_owned_live(prior, &state, document.requested_url.as_str())?;
                    let target_fence = state.high_water.checked_add(1).ok_or_else(|| {
                        ManagedCollectionError::OwnershipConflict("URL fence exhausted".to_owned())
                    })?;
                    plan.actions.push(PendingAction {
                        requested_url: document.requested_url.to_string(),
                        expected: state.clone(),
                        kind: PendingKind::Tombstone,
                        target_version: None,
                        target_fence,
                    });
                    plan.counts.removed += 1;
                    plan.desired_entries.insert(
                        relative.clone(),
                        OwnerEntry {
                            requested_url: document.requested_url.to_string(),
                            indexed_version: None,
                            terminal_fence: Some(target_fence),
                            noindex: true,
                        },
                    );
                } else {
                    if prior.terminal_fence.is_some() {
                        require_owned_tombstone(prior, &state, document.requested_url.as_str())?;
                    } else {
                        require_unowned_url(&state, document.requested_url.as_str())?;
                    }
                    plan.desired_entries.insert(
                        relative.clone(),
                        OwnerEntry {
                            requested_url: document.requested_url.to_string(),
                            indexed_version: None,
                            terminal_fence: prior.terminal_fence,
                            noindex: true,
                        },
                    );
                }
            } else {
                require_unowned_url(&state, document.requested_url.as_str())?;
                plan.desired_entries.insert(
                    relative.clone(),
                    OwnerEntry {
                        requested_url: document.requested_url.to_string(),
                        indexed_version: None,
                        terminal_fence: None,
                        noindex: true,
                    },
                );
            }
            continue;
        }

        let key = document.requested_url.as_str();
        let prior = owner.entries.get(relative);
        let state = snapshot_state(snapshot, key);
        let indexed_document = snapshot.documents.get(key);
        let version_matches = indexed_document.is_some_and(|indexed| {
            indexed.id == key
                && indexed.effective_url == document.effective_url
                && indexed.title == document.title
                && indexed.body == document.body
                && indexed.version_id == document.version
        });
        if let Some(prior) = prior {
            if prior.requested_url != key {
                return Err(ManagedCollectionError::OwnershipConflict(
                    "stored source path maps to a different URL identity".to_owned(),
                ));
            }
            if prior.indexed_version.is_some() {
                require_owned_live(prior, &state, key)?;
                if version_matches && prior.indexed_version.as_deref() == Some(&document.version) {
                    plan.counts.unchanged += 1;
                    plan.desired_entries.insert(
                        relative.clone(),
                        OwnerEntry {
                            requested_url: key.to_owned(),
                            indexed_version: Some(document.version.clone()),
                            terminal_fence: prior.terminal_fence,
                            noindex: false,
                        },
                    );
                    continue;
                }
                let target_fence = state.high_water.checked_add(1).ok_or_else(|| {
                    ManagedCollectionError::OwnershipConflict("URL fence exhausted".to_owned())
                })?;
                plan.actions.push(PendingAction {
                    requested_url: key.to_owned(),
                    expected: state.clone(),
                    kind: PendingKind::Upsert,
                    target_version: Some(document.version.clone()),
                    target_fence,
                });
                plan.counts.changed += 1;
                plan.desired_entries.insert(
                    relative.clone(),
                    OwnerEntry {
                        requested_url: key.to_owned(),
                        indexed_version: Some(document.version.clone()),
                        terminal_fence: Some(target_fence),
                        noindex: false,
                    },
                );
                continue;
            }
            if prior.terminal_fence.is_some() {
                require_owned_tombstone(prior, &state, key)?;
                let target_fence = state.high_water.checked_add(1).ok_or_else(|| {
                    ManagedCollectionError::OwnershipConflict("URL fence exhausted".to_owned())
                })?;
                plan.actions.push(PendingAction {
                    requested_url: key.to_owned(),
                    expected: state.clone(),
                    kind: PendingKind::Upsert,
                    target_version: Some(document.version.clone()),
                    target_fence,
                });
                plan.counts.added += 1;
                plan.desired_entries.insert(
                    relative.clone(),
                    OwnerEntry {
                        requested_url: key.to_owned(),
                        indexed_version: Some(document.version.clone()),
                        terminal_fence: Some(target_fence),
                        noindex: false,
                    },
                );
                continue;
            }
        }
        if indexed_document.is_some() || state.high_water != 0 || state.revoked {
            return Err(ManagedCollectionError::ForeignUrlCollision(key.to_owned()));
        }
        let target_fence = state.high_water.checked_add(1).ok_or_else(|| {
            ManagedCollectionError::OwnershipConflict("URL fence exhausted".to_owned())
        })?;
        plan.actions.push(PendingAction {
            requested_url: key.to_owned(),
            expected: state.clone(),
            kind: PendingKind::Upsert,
            target_version: Some(document.version.clone()),
            target_fence,
        });
        plan.counts.added += 1;
        plan.desired_entries.insert(
            relative.clone(),
            OwnerEntry {
                requested_url: key.to_owned(),
                indexed_version: Some(document.version.clone()),
                terminal_fence: Some(target_fence),
                noindex: false,
            },
        );
    }

    for (relative, prior) in &owner.entries {
        if source.documents.contains_key(relative) {
            continue;
        }
        if let Some(version) = prior.indexed_version.as_deref() {
            let state = snapshot_state(snapshot, &prior.requested_url);
            require_owned_live(prior, &state, &prior.requested_url)?;
            if state.live_version.as_deref() != Some(version) {
                return Err(ManagedCollectionError::OwnershipConflict(format!(
                    "owned URL {} no longer has its recorded live version",
                    prior.requested_url
                )));
            }
            let target_fence = state.high_water.checked_add(1).ok_or_else(|| {
                ManagedCollectionError::OwnershipConflict("URL fence exhausted".to_owned())
            })?;
            plan.actions.push(PendingAction {
                requested_url: prior.requested_url.clone(),
                expected: state.clone(),
                kind: PendingKind::Tombstone,
                target_version: None,
                target_fence,
            });
            plan.counts.removed += 1;
            plan.desired_entries.insert(
                relative.clone(),
                OwnerEntry {
                    requested_url: prior.requested_url.clone(),
                    indexed_version: None,
                    terminal_fence: Some(target_fence),
                    noindex: prior.noindex,
                },
            );
        } else {
            let state = snapshot_state(snapshot, &prior.requested_url);
            if prior.terminal_fence.is_some() {
                require_owned_tombstone(prior, &state, &prior.requested_url)?;
            } else {
                require_unowned_url(&state, &prior.requested_url)?;
            }
            plan.desired_entries.insert(relative.clone(), prior.clone());
        }
    }
    plan.actions
        .sort_by(|left, right| left.requested_url.cmp(&right.requested_url));
    if plan.desired_entries.len() > MAX_OWNED_PATH_RECORDS {
        return Err(ManagedCollectionError::InvalidSource(
            "managed ownership history reached its 4096 path record limit".to_owned(),
        ));
    }
    Ok(plan)
}

fn require_owned_live(
    prior: &OwnerEntry,
    current: &ManagedExpectedState,
    key: &str,
) -> Result<(), ManagedCollectionError> {
    if current.revoked
        || current.live_version.as_deref() != prior.indexed_version.as_deref()
        || current.terminal_fence != prior.terminal_fence
        || current.terminal_version.as_deref() != prior.indexed_version.as_deref()
        || current.terminal_tombstone
        || prior.terminal_fence != Some(current.high_water)
    {
        return Err(ManagedCollectionError::OwnershipConflict(format!(
            "owned URL {key} changed outside this collection; no sync mutation was applied"
        )));
    }
    Ok(())
}

fn require_owned_tombstone(
    prior: &OwnerEntry,
    current: &ManagedExpectedState,
    key: &str,
) -> Result<(), ManagedCollectionError> {
    if current.revoked
        || current.live_version.is_some()
        || current.terminal_fence != prior.terminal_fence
        || !current.terminal_tombstone
        || prior.terminal_fence != Some(current.high_water)
    {
        return Err(ManagedCollectionError::OwnershipConflict(format!(
            "owned noindex URL {key} changed outside this collection; no sync mutation was applied"
        )));
    }
    Ok(())
}

fn require_unowned_url(
    current: &ManagedExpectedState,
    key: &str,
) -> Result<(), ManagedCollectionError> {
    if current.high_water != 0
        || current.terminal_fence.is_some()
        || current.terminal_version.is_some()
        || current.terminal_tombstone
        || current.live_version.is_some()
        || current.revoked
    {
        return Err(ManagedCollectionError::ForeignUrlCollision(key.to_owned()));
    }
    Ok(())
}

fn snapshot_state(snapshot: &ManagedStoreSnapshot, key: &str) -> ManagedExpectedState {
    let control = snapshot.controls.get(key);
    ManagedExpectedState {
        high_water: control.map_or(0, |item| item.high_water),
        terminal_fence: control.and_then(|item| item.terminal_fence),
        terminal_version: control.and_then(|item| item.terminal_version.clone()),
        terminal_tombstone: control.is_some_and(|item| item.terminal_tombstone),
        live_version: snapshot
            .documents
            .get(key)
            .map(|document| document.version_id.clone()),
        revoked: control.is_some_and(|item| item.revoked),
    }
}

fn source_equivalent_for_plan(source: &SourceSnapshot, pending: &PendingSync) -> bool {
    let expected_live: BTreeMap<_, _> = pending
        .desired_entries
        .iter()
        .filter_map(|(path, entry)| {
            if entry.noindex {
                None
            } else {
                Some((
                    path.as_str(),
                    (
                        entry.requested_url.as_str(),
                        entry.indexed_version.as_deref(),
                    ),
                ))
            }
        })
        .collect();
    if expected_live.len()
        + pending
            .desired_entries
            .values()
            .filter(|entry| entry.noindex)
            .count()
        != source.documents.len()
    {
        return false;
    }
    source.documents.iter().all(|(path, document)| {
        pending.desired_entries.get(path).is_some_and(|entry| {
            entry.requested_url == document.requested_url.as_str()
                && entry.noindex == document.noindex
                && (document.noindex
                    || entry.indexed_version.as_deref() == Some(document.version.as_str()))
        })
    })
}

fn batch_actions(
    source: &SourceSnapshot,
    pending: &PendingSync,
) -> Result<Vec<ManagedBatchAction>, ManagedCollectionError> {
    let mut actions = Vec::with_capacity(pending.actions.len());
    for action in &pending.actions {
        let key = UrlKey::parse(&action.requested_url)
            .map_err(|error| ManagedCollectionError::Url(error.to_string()))?;
        let intent = match action.kind {
            PendingKind::Upsert => {
                let document = source
                    .documents
                    .values()
                    .find(|document| document.requested_url.as_str() == action.requested_url)
                    .ok_or_else(|| {
                        ManagedCollectionError::PendingRecovery(
                            "pending upsert has no validated source document".to_owned(),
                        )
                    })?;
                if document.noindex
                    || Some(document.version.as_str()) != action.target_version.as_deref()
                {
                    return Err(ManagedCollectionError::SourceChanged);
                }
                ManagedBatchIntent::Upsert {
                    effective_url: document.effective_url.clone(),
                    title: document.title.clone(),
                    body: document.body.clone(),
                }
            }
            PendingKind::Tombstone => ManagedBatchIntent::Tombstone,
        };
        actions.push(ManagedBatchAction {
            key,
            expected: action.expected.clone(),
            intent,
        });
    }
    Ok(actions)
}

fn verify_committed_target(
    snapshot: &ManagedStoreSnapshot,
    pending: &PendingSync,
    generation: u64,
) -> bool {
    if snapshot.generation_id != generation
        || generation != pending.reservation.base_generation.saturating_add(1)
        || snapshot.segment_count
            != pending.base_segment_count
                + usize::from(
                    pending
                        .actions
                        .iter()
                        .any(|action| matches!(action.kind, PendingKind::Upsert)),
                )
    {
        return false;
    }
    let target_by_url: BTreeMap<_, _> = pending
        .actions
        .iter()
        .map(|action| (action.requested_url.as_str(), action))
        .collect();
    if target_by_url.len() != pending.actions.len() {
        return false;
    }
    for action in &pending.actions {
        let state = snapshot_state(snapshot, &action.requested_url);
        if state.high_water != action.target_fence
            || state.terminal_fence != Some(action.target_fence)
            || state.revoked
        {
            return false;
        }
        match action.kind {
            PendingKind::Upsert => {
                if state.terminal_version != action.target_version
                    || state.live_version != action.target_version
                    || state.terminal_tombstone
                {
                    return false;
                }
            }
            PendingKind::Tombstone => {
                if state.live_version.is_some() || !state.terminal_tombstone {
                    return false;
                }
            }
        }
    }
    for entry in pending.desired_entries.values() {
        let state = snapshot_state(snapshot, &entry.requested_url);
        if let Some(version) = &entry.indexed_version {
            if state.live_version.as_ref() != Some(version)
                || state.terminal_version.as_ref() != Some(version)
                || state.terminal_fence != entry.terminal_fence
                || state.high_water != entry.terminal_fence.unwrap_or(0)
                || state.revoked
            {
                return false;
            }
        } else if entry.terminal_fence.is_some()
            && (state.live_version.is_some()
                || !state.terminal_tombstone
                || state.terminal_fence != entry.terminal_fence
                || state.high_water != entry.terminal_fence.unwrap_or(0)
                || state.revoked)
        {
            return false;
        }
    }
    true
}

fn verify_schema(
    snapshot: &ManagedStoreSnapshot,
    owner: &OwnerState,
) -> Result<(), ManagedCollectionError> {
    if snapshot.store_id != owner.store_id
        || snapshot.analyzer_id != owner.analyzer_id
        || snapshot.html_schema_id != owner.html_schema_id
        || owner.analyzer_id != ANALYZER_ID
        || owner.html_schema_id != HTML_SCHEMA_ID
    {
        return Err(ManagedCollectionError::InvalidStore(
            "managed collection schema or store identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_binding(
    store: &PersistentIndex,
    store_path: &Path,
    source_path: &Path,
    prefix: &Url,
    owner: &OwnerState,
) -> Result<(), ManagedCollectionError> {
    validate_store_binding(store, store_path, owner)?;
    let metadata = fs::metadata(source_path).map_err(|_| {
        ManagedCollectionError::InvalidSource("bound source directory is missing".to_owned())
    })?;
    if source_path.to_string_lossy() != owner.source_path
        || metadata.dev() != owner.source_device
        || metadata.ino() != owner.source_inode
        || prefix.as_str() != owner.url_prefix
    {
        return Err(ManagedCollectionError::InvalidArguments(
            "sync source path, directory identity, or URL prefix differs from the initialized binding".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_source_binding(
    source: &SourceSnapshot,
    owner: &OwnerState,
) -> Result<(), ManagedCollectionError> {
    if source.canonical_root.to_string_lossy() != owner.source_path
        || source.root_device != owner.source_device
        || source.root_inode != owner.source_inode
    {
        return Err(ManagedCollectionError::SourceChanged);
    }
    Ok(())
}

fn validate_store_binding(
    store: &PersistentIndex,
    store_path: &Path,
    owner: &OwnerState,
) -> Result<(), ManagedCollectionError> {
    if owner.schema != OWNER_STATE_SCHEMA
        || owner.store_id != store.store_identity()
        || store_path.to_string_lossy() != owner.store_path
        || owner.analyzer_id != ANALYZER_ID
        || owner.html_schema_id != HTML_SCHEMA_ID
    {
        return Err(ManagedCollectionError::InvalidStore(
            "store is not the initialized managed collection or its binding changed".to_owned(),
        ));
    }
    Ok(())
}

fn status_from(
    store: &PersistentIndex,
    store_path: &Path,
    owner: &OwnerState,
) -> Result<Status, ManagedCollectionError> {
    let snapshot = store.managed_snapshot()?;
    verify_schema(&snapshot, owner)?;
    let marker = store.managed_reservation()?;
    let pending_matches = owner.pending.as_ref().is_some_and(|pending| {
        marker
            .as_ref()
            .is_some_and(|marker| marker == &pending.reservation)
    });
    let state = owner.lifecycle.clone();
    let source_path = PathBuf::from(&owner.source_path);
    let source_valid = fs::symlink_metadata(&source_path).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink()
            && metadata.is_dir()
            && metadata.dev() == owner.source_device
            && metadata.ino() == owner.source_inode
    }) && fs::canonicalize(&source_path)
        .is_ok_and(|canonical| canonical == source_path);
    let ownership_consistent = owner.entries.values().all(|entry| {
        let current = snapshot_state(&snapshot, &entry.requested_url);
        match (&entry.indexed_version, entry.terminal_fence) {
            (Some(version), Some(fence)) => {
                !current.revoked
                    && current.live_version.as_ref() == Some(version)
                    && current.terminal_version.as_ref() == Some(version)
                    && current.terminal_fence == Some(fence)
                    && current.high_water == fence
            }
            (None, Some(fence)) => {
                !current.revoked
                    && current.live_version.is_none()
                    && current.terminal_tombstone
                    && current.terminal_fence == Some(fence)
                    && current.high_water == fence
            }
            (None, None) => {
                current.high_water == 0
                    && current.terminal_fence.is_none()
                    && current.terminal_version.is_none()
                    && !current.terminal_tombstone
                    && current.live_version.is_none()
                    && !current.revoked
            }
            (Some(_), None) => false,
        }
    });
    let last_sync = owner.last_sync.clone().unwrap_or_default();
    Ok(Status {
        collection_id: owner.collection_id.clone(),
        store_id: hex_lower(&owner.store_id),
        store_path: store_path.to_string_lossy().into_owned(),
        source_path: owner.source_path.clone(),
        url_prefix: owner.url_prefix.clone(),
        state: state.to_owned(),
        generation: snapshot.generation_id,
        segments: snapshot.segment_count,
        live_documents: snapshot.documents.len(),
        entries: owner.entries.len(),
        last_sync,
        last_failure: owner.last_failure.clone(),
        pending: pending_matches || owner.pending.is_some() || marker.is_some(),
        source_valid,
        ownership_consistent,
    })
}

fn canonical_source_path(path: &Path) -> Result<PathBuf, ManagedCollectionError> {
    let path = trim_trailing_slashes(path);
    let metadata = fs::symlink_metadata(&path).map_err(|_| {
        ManagedCollectionError::InvalidSource(
            "source directory is missing or unreadable".to_owned(),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ManagedCollectionError::InvalidSource(
            "source must be a real readable directory, not a symbolic link".to_owned(),
        ));
    }
    let opened = open_directory(&path)?;
    let opened_metadata = opened.metadata()?;
    if opened_metadata.dev() != metadata.dev() || opened_metadata.ino() != metadata.ino() {
        return Err(ManagedCollectionError::SourceChanged);
    }
    let canonical = fs::canonicalize(proc_fd_path(&opened)).map_err(|_| {
        ManagedCollectionError::InvalidSource("source directory cannot be canonicalized".to_owned())
    })?;
    let after_open =
        fs::symlink_metadata(&path).map_err(|_| ManagedCollectionError::SourceChanged)?;
    if after_open.file_type().is_symlink()
        || !after_open.is_dir()
        || after_open.dev() != opened_metadata.dev()
        || after_open.ino() != opened_metadata.ino()
    {
        return Err(ManagedCollectionError::SourceChanged);
    }
    if canonical.to_str().is_none() {
        return Err(ManagedCollectionError::InvalidSource(
            "canonical source path is not valid UTF-8".to_owned(),
        ));
    }
    Ok(canonical)
}

fn trim_trailing_slashes(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let mut end = bytes.len();
    while end > 1 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    PathBuf::from(OsStr::from_bytes(&bytes[..end]))
}

fn canonical_existing_store_path(path: &Path) -> Result<PathBuf, ManagedCollectionError> {
    fs::canonicalize(path)
        .map_err(|_| ManagedCollectionError::InvalidStore("store path does not exist".to_owned()))
}

fn canonical_new_destination(
    path: &Path,
    source_root: &Path,
) -> Result<PathBuf, ManagedCollectionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(ManagedCollectionError::InvalidStore(
            "local-collection init requires a new store path; existing stores are never adopted"
                .to_owned(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        ManagedCollectionError::InvalidStore(
            "store destination must include a directory name".to_owned(),
        )
    })?;
    let parent = fs::canonicalize(parent)?;
    let destination = parent.join(name);
    if destination.to_str().is_none() {
        return Err(ManagedCollectionError::InvalidStore(
            "canonical store path is not valid UTF-8".to_owned(),
        ));
    }
    if destination == source_root || destination.starts_with(source_root) {
        return Err(ManagedCollectionError::InvalidStore(
            "store destination must be outside the source directory".to_owned(),
        ));
    }
    Ok(destination)
}

fn new_staged_store_path(destination: &Path) -> Result<PathBuf, ManagedCollectionError> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for _ in 0..8 {
        let staging = parent.join(format!(".ley-managed-init-{}", random_id()?));
        match fs::symlink_metadata(&staging) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(staging),
            Ok(_) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ManagedCollectionError::InvalidStore(
        "could not reserve a private staging path for initialization".to_owned(),
    ))
}

fn normalize_url_prefix(value: &str) -> Result<Url, ManagedCollectionError> {
    let url = Url::parse(value).map_err(|_| {
        ManagedCollectionError::Url("URL prefix must be a valid HTTP(S) directory URL".to_owned())
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(ManagedCollectionError::Url(
            "URL prefix must be an HTTP(S) directory URL without credentials, query, or fragment"
                .to_owned(),
        ));
    }
    UrlKey::parse(url.as_str()).map_err(|_| {
        ManagedCollectionError::Url("URL prefix is not a valid document identity".to_owned())
    })?;
    Ok(url)
}

fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, ManagedCollectionError> {
    let mut result = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = &args[index];
        if !matches!(key.as_str(), "--store" | "--directory" | "--url-prefix") {
            return Err(ManagedCollectionError::InvalidArguments(format!(
                "unknown or repeated local-collection argument: {key:?}"
            )));
        }
        let value = args.get(index + 1).ok_or_else(|| {
            ManagedCollectionError::InvalidArguments(format!("{key} requires a value"))
        })?;
        if value.starts_with("--") || result.insert(key.clone(), value.clone()).is_some() {
            return Err(ManagedCollectionError::InvalidArguments(format!(
                "missing value or repeated local-collection argument: {key:?}"
            )));
        }
        index += 2;
    }
    Ok(result)
}

fn required<'a>(
    flags: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, ManagedCollectionError> {
    flags.get(key).map(String::as_str).ok_or_else(|| {
        ManagedCollectionError::InvalidArguments(format!("local-collection requires {key}"))
    })
}

fn ensure_only_flags(
    flags: &BTreeMap<String, String>,
    allowed: &[&str],
) -> Result<(), ManagedCollectionError> {
    if flags.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(ManagedCollectionError::InvalidArguments(
            "unsupported local-collection arguments".to_owned(),
        ))
    }
}

fn canonical_source_scan_root(path: &Path) -> Result<(PathBuf, File), ManagedCollectionError> {
    let canonical = canonical_source_path(path)?;
    if canonical != path {
        return Err(ManagedCollectionError::SourceChanged);
    }
    let file = open_directory(&canonical)?;
    Ok((canonical, file))
}

fn scan_source(root: &Path, prefix: &Url) -> Result<SourceSnapshot, ManagedCollectionError> {
    let (canonical_root, root_file) = canonical_source_scan_root(root)?;
    if canonical_root != root {
        return Err(ManagedCollectionError::SourceChanged);
    }
    let root_metadata = root_file.metadata()?;
    let root_stamp = file_stamp(&root_metadata);
    let mut directories = vec![DirectoryStamp {
        file: root_file,
        parent: None,
        stamp: root_stamp.clone(),
    }];
    let mut pending_directories = vec![(0usize, String::new())];
    let mut files = BTreeMap::new();
    let mut documents = BTreeMap::new();
    let mut entries_seen = 0usize;
    let mut total_bytes = 0usize;
    while let Some((directory_index, prefix_path)) = pending_directories.pop() {
        let directory_file = directories[directory_index].file.try_clone()?;
        let directory_before = file_stamp(&directory_file.metadata()?);
        if directory_before.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ManagedCollectionError::InvalidSource(
                "source contains an unsupported directory entry".to_owned(),
            ));
        }
        let proc_path = proc_fd_path(&directory_file);
        let mut children = Vec::new();
        for child in fs::read_dir(&proc_path)? {
            entries_seen += 1;
            if entries_seen > crate::local_ingest::MAX_HTML_DIRECTORY_ENTRIES {
                return Err(ManagedCollectionError::InvalidSource(
                    "source exceeds the 4096-entry limit".to_owned(),
                ));
            }
            children.push(child?);
        }
        children.sort_by(|left, right| {
            left.file_name()
                .as_bytes()
                .cmp(right.file_name().as_bytes())
        });
        for entry in children {
            let name_os = entry.file_name();
            let name = name_os.to_str().ok_or_else(|| {
                ManagedCollectionError::InvalidSource(
                    "source path contains a non-UTF-8 entry name".to_owned(),
                )
            })?;
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
            {
                return Err(ManagedCollectionError::InvalidSource(
                    "source contains an invalid path component".to_owned(),
                ));
            }
            let c_name = CString::new(name_os.as_bytes()).map_err(|_| {
                ManagedCollectionError::InvalidSource("source path contains a NUL byte".to_owned())
            })?;
            let entry_path = proc_path.join(&name_os);
            let entry_metadata = fs::symlink_metadata(&entry_path)?;
            let entry_stamp = file_stamp(&entry_metadata);
            if entry_metadata.file_type().is_symlink() {
                return Err(ManagedCollectionError::InvalidSource(
                    "source contains a symbolic link".to_owned(),
                ));
            }
            let relative = if prefix_path.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix_path}/{name}")
            };
            let file_type = entry_stamp.mode & libc::S_IFMT;
            if file_type == libc::S_IFDIR {
                let child = open_at(
                    &directory_file,
                    &c_name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )?;
                let opened = file_stamp(&child.metadata()?);
                if opened != entry_stamp {
                    return Err(ManagedCollectionError::SourceChanged);
                }
                let child_index = directories.len();
                directories.push(DirectoryStamp {
                    file: child,
                    parent: Some((directory_index, c_name)),
                    stamp: opened,
                });
                pending_directories.push((child_index, relative));
                continue;
            }
            if file_type != libc::S_IFREG {
                return Err(ManagedCollectionError::InvalidSource(
                    "source contains an unsupported non-regular entry".to_owned(),
                ));
            }
            if !is_html_name(name) {
                files.insert(
                    relative,
                    FileBinding {
                        parent_directory: directory_index,
                        name: c_name,
                        stamp: entry_stamp,
                    },
                );
                continue;
            }
            if files.len() == crate::local_ingest::MAX_HTML_DOCUMENTS {
                return Err(ManagedCollectionError::InvalidSource(
                    "source exceeds the 128 HTML file limit".to_owned(),
                ));
            }
            if entry_stamp.size > crate::local_ingest::MAX_HTML_FILE_BYTES as u64 {
                return Err(ManagedCollectionError::InvalidSource(
                    "an HTML file exceeds the 2 MiB limit".to_owned(),
                ));
            }
            let collection_remaining =
                crate::local_ingest::MAX_HTML_COLLECTION_BYTES.saturating_sub(total_bytes);
            if entry_stamp.size > collection_remaining as u64 {
                return Err(ManagedCollectionError::InvalidSource(
                    "source exceeds the 32 MiB aggregate byte limit".to_owned(),
                ));
            }
            let mut file = open_at(
                &directory_file,
                &c_name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )?;
            let before = file_stamp(&file.metadata()?);
            if before != entry_stamp {
                return Err(ManagedCollectionError::SourceChanged);
            }
            let read_limit = crate::local_ingest::MAX_HTML_FILE_BYTES
                .min(collection_remaining)
                .saturating_add(1);
            let mut bytes = Vec::with_capacity(
                (entry_stamp.size as usize).min(crate::local_ingest::MAX_HTML_FILE_BYTES),
            );
            (&mut file)
                .take(read_limit as u64)
                .read_to_end(&mut bytes)?;
            let after = file_stamp(&file.metadata()?);
            if before != after || bytes.len() as u64 != entry_stamp.size {
                return Err(ManagedCollectionError::SourceChanged);
            }
            if bytes.len() > crate::local_ingest::MAX_HTML_FILE_BYTES {
                return Err(ManagedCollectionError::InvalidSource(
                    "an HTML file exceeds the 2 MiB limit".to_owned(),
                ));
            }
            total_bytes = total_bytes.checked_add(bytes.len()).ok_or_else(|| {
                ManagedCollectionError::InvalidSource("source byte count overflowed".to_owned())
            })?;
            let html_text = std::str::from_utf8(&bytes).map_err(|_| {
                ManagedCollectionError::InvalidSource(format!(
                    "HTML file {relative:?} is not valid UTF-8"
                ))
            })?;
            let requested_url = map_relative_path(prefix, &relative)?;
            let extracted = html::extract_html(
                html_text.as_bytes(),
                HTML_CONTENT_TYPE,
                None,
                requested_url.clone(),
                requested_url.as_str(),
            )
            .map_err(|error| {
                ManagedCollectionError::Html(format!(
                    "HTML file {relative:?} failed bounded extraction: {error}"
                ))
            })?;
            let mut index = InMemoryIndex::new();
            index
                .upsert_fields(
                    requested_url.to_string(),
                    extracted.effective_url.clone(),
                    extracted.title.clone(),
                    extracted.body.clone(),
                )
                .map_err(|error| ManagedCollectionError::Html(error.to_string()))?;
            let document = index
                .documents()
                .get(requested_url.as_str())
                .ok_or_else(|| {
                    ManagedCollectionError::Html(
                        "extracted document disappeared during indexing".to_owned(),
                    )
                })?;
            let indexed = ScannedDocument {
                requested_url: requested_url.clone(),
                effective_url: extracted.effective_url,
                title: extracted.title,
                body: extracted.body,
                version: document.version_id.clone(),
                noindex: extracted.restrictions.noindex,
            };
            files.insert(
                relative.clone(),
                FileBinding {
                    parent_directory: directory_index,
                    name: c_name,
                    stamp: entry_stamp,
                },
            );
            documents.insert(relative, indexed);
        }
        let directory_after = file_stamp(&directory_file.metadata()?);
        if directory_before != directory_after {
            return Err(ManagedCollectionError::SourceChanged);
        }
    }
    if directories[0].stamp != file_stamp(&directories[0].file.metadata()?) {
        return Err(ManagedCollectionError::SourceChanged);
    }
    let source = SourceSnapshot {
        canonical_root,
        root_device: root_stamp.device,
        root_inode: root_stamp.inode,
        directories,
        files,
        documents,
    };
    source.revalidate()?;
    Ok(source)
}

impl SourceSnapshot {
    fn revalidate(&self) -> Result<(), ManagedCollectionError> {
        let metadata = fs::symlink_metadata(&self.canonical_root)
            .map_err(|_| ManagedCollectionError::SourceChanged)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.root_device
            || metadata.ino() != self.root_inode
        {
            return Err(ManagedCollectionError::SourceChanged);
        }
        let opened_root = open_directory(&self.canonical_root)
            .map_err(|_| ManagedCollectionError::SourceChanged)?;
        let root_stamp = file_stamp(&opened_root.metadata()?);
        if root_stamp.device != self.root_device || root_stamp.inode != self.root_inode {
            return Err(ManagedCollectionError::SourceChanged);
        }
        for (index, directory) in self.directories.iter().enumerate() {
            if directory.stamp != file_stamp(&directory.file.metadata()?) {
                return Err(ManagedCollectionError::SourceChanged);
            }
            if let Some((parent_index, name)) = &directory.parent {
                let parent = self
                    .directories
                    .get(*parent_index)
                    .ok_or(ManagedCollectionError::SourceChanged)?;
                let path = proc_fd_path(&parent.file).join(OsStr::from_bytes(name.as_bytes()));
                let current = fs::symlink_metadata(path)
                    .map_err(|_| ManagedCollectionError::SourceChanged)?;
                if current.file_type().is_symlink() || file_stamp(&current) != directory.stamp {
                    return Err(ManagedCollectionError::SourceChanged);
                }
                let reopened = open_at(
                    &parent.file,
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
                .map_err(|_| ManagedCollectionError::SourceChanged)?;
                if file_stamp(&reopened.metadata()?) != directory.stamp {
                    return Err(ManagedCollectionError::SourceChanged);
                }
            } else if index != 0 {
                return Err(ManagedCollectionError::SourceChanged);
            }
        }
        for binding in self.files.values() {
            let parent = self
                .directories
                .get(binding.parent_directory)
                .ok_or(ManagedCollectionError::SourceChanged)?;
            let path = proc_fd_path(&parent.file).join(OsStr::from_bytes(binding.name.as_bytes()));
            let current =
                fs::symlink_metadata(path).map_err(|_| ManagedCollectionError::SourceChanged)?;
            if current.file_type().is_symlink() || file_stamp(&current) != binding.stamp {
                return Err(ManagedCollectionError::SourceChanged);
            }
            let reopened = open_at(
                &parent.file,
                &binding.name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|_| ManagedCollectionError::SourceChanged)?;
            if file_stamp(&reopened.metadata()?) != binding.stamp {
                return Err(ManagedCollectionError::SourceChanged);
            }
        }
        Ok(())
    }
}

fn file_stamp(metadata: &fs::Metadata) -> FileStamp {
    FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn open_directory(path: &Path) -> Result<File, ManagedCollectionError> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        ManagedCollectionError::InvalidSource("source path contains a NUL byte".to_owned())
    })?;
    // SAFETY: the path is NUL-terminated and the returned descriptor is owned by File below.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(ManagedCollectionError::InvalidSource(
            "source directory cannot be opened without following links".to_owned(),
        ));
    }
    // SAFETY: open returned a new descriptor, transferred exactly once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_at(parent: &File, name: &CString, flags: i32) -> Result<File, ManagedCollectionError> {
    // SAFETY: parent is a live directory descriptor and name is NUL-terminated without slashes.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(ManagedCollectionError::InvalidSource(
                "source contains a symbolic link".to_owned(),
            ));
        }
        return Err(ManagedCollectionError::InvalidSource(format!(
            "source entry cannot be opened safely: {error}"
        )));
    }
    // SAFETY: openat returned a new descriptor, transferred exactly once to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn proc_fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn is_html_name(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("html") || extension.eq_ignore_ascii_case("htm")
        })
}

fn relative_components(path: &Path) -> Result<String, ManagedCollectionError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_str().ok_or_else(|| {
                    ManagedCollectionError::InvalidSource(
                        "source path contains non-UTF-8 text".to_owned(),
                    )
                })?;
                if text.is_empty()
                    || text == "."
                    || text == ".."
                    || text.contains('/')
                    || text.contains('\\')
                {
                    return Err(ManagedCollectionError::InvalidSource(
                        "source path contains an invalid component".to_owned(),
                    ));
                }
                parts.push(text);
            }
            _ => {
                return Err(ManagedCollectionError::InvalidSource(
                    "source path escapes its root".to_owned(),
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(ManagedCollectionError::InvalidSource(
            "source path is empty".to_owned(),
        ));
    }
    Ok(parts.join("/"))
}

fn map_relative_path(prefix: &Url, relative: &str) -> Result<UrlKey, ManagedCollectionError> {
    let relative_path = relative_components(Path::new(relative))?;
    let mut url = prefix.clone();
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            ManagedCollectionError::Url(
                "URL prefix cannot accept document path segments".to_owned(),
            )
        })?;
        segments.pop_if_empty();
        for component in relative_path.split('/') {
            segments.push(component);
        }
    }
    UrlKey::parse(url.as_str()).map_err(|error| ManagedCollectionError::Url(error.to_string()))
}

fn read_owner_state(store_path: &Path) -> Result<OwnerState, ManagedCollectionError> {
    let path = store_path.join(OWNER_STATE_NAME);
    let metadata = fs::symlink_metadata(&path).map_err(|_| {
        ManagedCollectionError::InvalidStore(
            "store has no managed collection owner state; unmanaged stores are never adopted"
                .to_owned(),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_OWNER_STATE_BYTES as u64 {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state exceeds its 2 MiB bound".to_owned(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_OWNER_STATE_BYTES as u64) as usize);
    options
        .open(&path)?
        .take((MAX_OWNER_STATE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OWNER_STATE_BYTES {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state exceeds its 2 MiB bound".to_owned(),
        ));
    }
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state changed while reading".to_owned(),
        ));
    }
    let state: OwnerState = serde_json::from_slice(&bytes).map_err(|_| {
        ManagedCollectionError::InvalidStore("managed owner state is malformed".to_owned())
    })?;
    validate_owner_state(&state)?;
    Ok(state)
}

fn validate_owner_state(state: &OwnerState) -> Result<(), ManagedCollectionError> {
    if state.entries.len() > MAX_OWNED_PATH_RECORDS {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner history exceeds its 4096 path record limit".to_owned(),
        ));
    }
    if state.schema != OWNER_STATE_SCHEMA
        || !valid_id(&state.collection_id)
        || state.store_id == [0; 16]
        || !Path::new(&state.store_path).is_absolute()
        || !Path::new(&state.source_path).is_absolute()
        || state.analyzer_id != ANALYZER_ID
        || state.html_schema_id != HTML_SCHEMA_ID
        || !matches!(
            state.lifecycle.as_str(),
            "ready" | "failed" | "sync_pending" | "recovery_required"
        )
    {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state schema, identity, or size is invalid".to_owned(),
        ));
    }
    let prefix = normalize_url_prefix(&state.url_prefix)?;
    if prefix.as_str() != state.url_prefix {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner URL prefix is not canonical".to_owned(),
        ));
    }
    for (relative, entry) in &state.entries {
        let mapped = map_relative_path(&prefix, relative).map_err(|_| {
            ManagedCollectionError::InvalidStore("managed owner path is malformed".to_owned())
        })?;
        if relative_components(Path::new(relative)).ok().as_deref() != Some(relative)
            || mapped.as_str() != entry.requested_url
            || (entry.indexed_version.is_some() && entry.noindex)
            || (entry.indexed_version.is_some() && entry.terminal_fence.is_none())
            || entry.terminal_fence == Some(0)
            || entry
                .indexed_version
                .as_deref()
                .is_some_and(|version| !valid_version(version))
        {
            return Err(ManagedCollectionError::InvalidStore(
                "managed owner path mapping or version is malformed".to_owned(),
            ));
        }
        UrlKey::parse(&entry.requested_url).map_err(|_| {
            ManagedCollectionError::InvalidStore(
                "managed owner URL identity is malformed".to_owned(),
            )
        })?;
    }
    if let Some(pending) = &state.pending {
        if !valid_id(&pending.reservation.sync_id)
            || pending.reservation.base_generation == 0
            || pending.actions.len() > MAX_OWNED_PATH_RECORDS * 2
            || pending.desired_entries.len() > MAX_OWNED_PATH_RECORDS
        {
            return Err(ManagedCollectionError::InvalidStore(
                "managed pending intent is malformed or exceeds its bound".to_owned(),
            ));
        }
        let mut action_keys = BTreeSet::new();
        for action in &pending.actions {
            let key = UrlKey::parse(&action.requested_url).map_err(|_| {
                ManagedCollectionError::InvalidStore(
                    "managed pending URL identity is malformed".to_owned(),
                )
            })?;
            if !action_keys.insert(key.as_str().to_owned())
                || action.target_fence != action.expected.high_water.checked_add(1).unwrap_or(0)
                || action.target_fence == 0
                || action
                    .target_version
                    .as_deref()
                    .is_some_and(|version| !valid_version(version))
                || action
                    .expected
                    .terminal_version
                    .as_deref()
                    .is_some_and(|version| !valid_version(version))
                || action
                    .expected
                    .live_version
                    .as_deref()
                    .is_some_and(|version| !valid_version(version))
                || matches!(action.kind, PendingKind::Upsert) != action.target_version.is_some()
            {
                return Err(ManagedCollectionError::InvalidStore(
                    "managed pending action target is inconsistent".to_owned(),
                ));
            }
        }
        let mut seen_urls = BTreeSet::new();
        for (relative, entry) in &pending.desired_entries {
            let mapped = map_relative_path(&prefix, relative).map_err(|_| {
                ManagedCollectionError::InvalidStore("managed pending path is malformed".to_owned())
            })?;
            if relative_components(Path::new(relative)).ok().as_deref() != Some(relative)
                || mapped.as_str() != entry.requested_url
                || !seen_urls.insert(entry.requested_url.clone())
            {
                return Err(ManagedCollectionError::InvalidStore(
                    "managed pending path map is inconsistent".to_owned(),
                ));
            }
        }
    }
    if let Some(ack) = &state.last_ack {
        if !valid_id(&ack.sync_id)
            || ack.base_generation == 0
            || !(ack.committed_generation == ack.base_generation
                || ack.committed_generation == ack.base_generation.saturating_add(1))
        {
            return Err(ManagedCollectionError::InvalidStore(
                "managed last-ack record is malformed".to_owned(),
            ));
        }
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_version(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_owner_state(state: &OwnerState) -> Result<Vec<u8>, ManagedCollectionError> {
    validate_owner_state(state)?;
    let bytes = serde_json::to_vec(state).map_err(|_| {
        ManagedCollectionError::InvalidStore("managed owner state could not be encoded".to_owned())
    })?;
    if bytes.len() > MAX_OWNER_STATE_BYTES {
        return Err(ManagedCollectionError::InvalidStore(
            "managed owner state exceeds its 2 MiB bound".to_owned(),
        ));
    }
    Ok(bytes)
}

fn write_owner_state(store_path: &Path, state: &OwnerState) -> Result<(), ManagedCollectionError> {
    let bytes = encode_owner_state(state)?;
    write_private_file_atomically(
        &store_path.join(OWNER_STATE_NAME),
        &store_path.join(OWNER_STATE_TEMP_NAME),
        &bytes,
    )?;
    Ok(())
}

fn create_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn write_private_file_atomically(
    destination: &Path,
    temporary: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    match fs::symlink_metadata(temporary) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(temporary)?
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "temporary state path is not a file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, destination)?;
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

struct CollectionLock(File);

impl CollectionLock {
    fn open(path: &Path) -> Result<Self, ManagedCollectionError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            ManagedCollectionError::InvalidStore("managed collection lock is missing".to_owned())
        })?;
        if !metadata.file_type().is_file() {
            return Err(ManagedCollectionError::InvalidStore(
                "managed collection lock is not a regular file".to_owned(),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        loop {
            // SAFETY: file owns a live descriptor for the lock throughout this guard.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(ManagedCollectionError::Io(error));
            }
        }
    }
}

impl Drop for CollectionLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains owned by this guard until Drop finishes.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn random_id() -> Result<String, ManagedCollectionError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex_lower(&bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::retrieval::EvidenceResolveError;
    use crate::storage::{ApplyOutcome, Intent};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
    const PREFIX: &str = "https://offline.example/guide/";

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ley-managed-local-test-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_page(title: &str, body: &str) -> String {
        format!(
            "<!doctype html><html><head><title>{title}</title></head><body><p>{body}</p></body></html>"
        )
    }

    fn fixture_noindex(title: &str, body: &str) -> String {
        format!(
            "<!doctype html><html><head><title>{title}</title><meta name=\"robots\" content=\"noindex\"></head><body><p>{body}</p></body></html>"
        )
    }

    fn init_args(store: &Path, source: &Path) -> Vec<String> {
        vec![
            "init".to_owned(),
            "--store".to_owned(),
            store.to_string_lossy().into_owned(),
            "--directory".to_owned(),
            source.to_string_lossy().into_owned(),
            "--url-prefix".to_owned(),
            PREFIX.to_owned(),
        ]
    }

    fn sync_args(store: &Path, source: &Path) -> Vec<String> {
        let mut args = init_args(store, source);
        args[0] = "sync".to_owned();
        args
    }

    fn indexed_reference(
        store: &PersistentIndex,
        key: &str,
        query: &str,
    ) -> crate::retrieval::EvidenceReference {
        let response = store
            .retrieve(crate::retrieval::RetrievalRequest::question(query))
            .unwrap();
        response
            .hits
            .into_iter()
            .find(|hit| hit.requested_url == key)
            .unwrap()
            .passage
            .reference
    }

    #[test]
    fn initialization_publishes_only_a_complete_managed_store() {
        if let Ok(store) = std::env::var("LEY_MANAGED_INIT_CRASH_STORE") {
            let source = std::env::var("LEY_MANAGED_INIT_CRASH_SOURCE").unwrap();
            let result = run_cli(init_args(Path::new(&store), Path::new(&source)));
            panic!("storage failpoint did not terminate initialization: {result:?}");
        }

        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("guide.html"),
            fixture_page("Guide", "initialization must recover after restart"),
        )
        .unwrap();

        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "managed_collection::tests::initialization_publishes_only_a_complete_managed_store",
            ])
            .env("LEY_MANAGED_INIT_CRASH_STORE", store_path.to_str().unwrap())
            .env("LEY_MANAGED_INIT_CRASH_SOURCE", source.to_str().unwrap())
            .env("LEY_STORAGE_FAILPOINT", "managed_init_before_publish")
            .output()
            .unwrap();
        assert_eq!(
            child.status.code(),
            Some(86),
            "child failed to stop before store publication: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(!store_path.exists());

        let output = run_cli(init_args(&store_path, &source)).unwrap();
        assert!(output.contains("state: ready"));
        assert!(output.contains("generation: 2"));
        assert!(store_path.join(OWNER_STATE_NAME).is_file());
    }

    #[test]
    fn managed_collection_lifecycle_is_idempotent_and_preserves_foreign_documents() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("a.html"),
            fixture_page("Alpha", "uniqueoldtoken old passage"),
        )
        .unwrap();
        fs::write(
            source.join("skip.html"),
            fixture_noindex("Skipped", "not searchable"),
        )
        .unwrap();

        let output = run_cli(init_args(&store_path, &source)).unwrap();
        assert!(output.contains("added 1, changed 0, removed 0, noindex 1"));
        let store = PersistentIndex::open(&store_path).unwrap();
        let initial = store.managed_snapshot().unwrap();
        assert_eq!(initial.generation_id, 2);
        assert_eq!(initial.segment_count, 1);
        assert_eq!(initial.documents.len(), 1);
        let old_reference = indexed_reference(
            &store,
            "https://offline.example/guide/a.html",
            "uniqueoldtoken",
        );
        assert!(store.resolve_evidence(&old_reference).is_ok());

        run_cli(sync_args(&store_path, &source)).unwrap();
        let unchanged = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(unchanged.generation_id, initial.generation_id);
        assert_eq!(unchanged.segment_count, initial.segment_count);
        assert!(store.resolve_evidence(&old_reference).is_ok());

        fs::write(
            source.join("a.html"),
            "<html><head><title>Alpha</title><meta name=description content=ignored></head><body><p>uniqueoldtoken old passage</p></body></html>",
        )
        .unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        let metadata_only_change = store.managed_snapshot().unwrap();
        assert_eq!(metadata_only_change.generation_id, initial.generation_id);
        assert_eq!(metadata_only_change.segment_count, initial.segment_count);
        assert!(store.resolve_evidence(&old_reference).is_ok());

        let foreign_key =
            UrlKey::parse("https://offline.example/foreign/owned-elsewhere.html").unwrap();
        let foreign_lease = store.issue_fence(&foreign_key).unwrap();
        assert_eq!(
            store
                .apply(
                    &foreign_lease,
                    Intent::Upsert {
                        effective_url: foreign_key.to_string(),
                        title: "Foreign".to_owned(),
                        body: "foreign retained passage".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::Applied
        );
        run_cli(sync_args(&store_path, &source)).unwrap();
        let before_add = store.managed_snapshot().unwrap();
        fs::write(
            source.join("b.html"),
            fixture_page("Beta", "uniquebetapassage"),
        )
        .unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        let after_add = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after_add.generation_id, before_add.generation_id + 1);
        assert_eq!(after_add.segment_count, before_add.segment_count + 1);
        let beta_reference = indexed_reference(
            &store,
            "https://offline.example/guide/b.html",
            "uniquebetapassage",
        );
        assert!(store.resolve_evidence(&old_reference).is_ok());

        fs::write(
            source.join("a.html"),
            fixture_page("Alpha Updated", "uniquenewtoken new passage"),
        )
        .unwrap();
        let before_update = store.managed_snapshot().unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        let after_update = store.managed_snapshot().unwrap();
        assert_eq!(after_update.generation_id, before_update.generation_id + 1);
        assert!(matches!(
            store.resolve_evidence(&old_reference),
            Err(EvidenceResolveError::VersionSuperseded)
        ));
        let new_reference = indexed_reference(
            &store,
            "https://offline.example/guide/a.html",
            "uniquenewtoken",
        );
        assert!(store.resolve_evidence(&new_reference).is_ok());

        fs::remove_file(source.join("b.html")).unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        assert!(matches!(
            store.resolve_evidence(&beta_reference),
            Err(EvidenceResolveError::NotLive)
        ));
        fs::write(
            source.join("a.html"),
            fixture_noindex("Alpha", "uniquenewtoken should disappear"),
        )
        .unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        assert!(matches!(
            store.resolve_evidence(&new_reference),
            Err(EvidenceResolveError::NotLive)
        ));
        fs::remove_file(source.join("a.html")).unwrap();
        let generation_before_missing_noindex = store.managed_snapshot().unwrap().generation_id;
        run_cli(sync_args(&store_path, &source)).unwrap();
        let owner = read_owner_state(&store_path).unwrap();
        assert!(
            owner
                .entries
                .get("a.html")
                .is_some_and(|entry| entry.noindex)
        );
        assert_eq!(
            store.managed_snapshot().unwrap().generation_id,
            generation_before_missing_noindex
        );
        let final_snapshot = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(final_snapshot.documents.len(), 1);
        assert!(final_snapshot.documents.contains_key(foreign_key.as_str()));
        assert!(
            !final_snapshot
                .documents
                .contains_key("https://offline.example/guide/a.html")
        );
    }

    #[test]
    fn noindex_paths_fail_closed_on_foreign_url_collisions() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        run_cli(init_args(&store_path, &source)).unwrap();
        let store = PersistentIndex::open(&store_path).unwrap();

        let unseen_key = UrlKey::parse("https://offline.example/guide/unseen.html").unwrap();
        let unseen_lease = store.issue_fence(&unseen_key).unwrap();
        store
            .apply(
                &unseen_lease,
                Intent::Upsert {
                    effective_url: unseen_key.to_string(),
                    title: "Foreign unseen".to_owned(),
                    body: "foreign unseen content".to_owned(),
                },
            )
            .unwrap();
        let before_collision = store.managed_snapshot().unwrap();
        fs::write(
            source.join("unseen.html"),
            fixture_noindex("Unseen", "noindex must not claim a foreign URL"),
        )
        .unwrap();
        assert!(matches!(
            run_cli(sync_args(&store_path, &source)),
            Err(ManagedCollectionError::ForeignUrlCollision(url)) if url == unseen_key.as_str()
        ));
        let owner = read_owner_state(&store_path).unwrap();
        assert!(!owner.entries.contains_key("unseen.html"));
        let after_collision = store.managed_snapshot().unwrap();
        assert_eq!(
            after_collision.generation_id,
            before_collision.generation_id
        );
        assert!(after_collision.documents.contains_key(unseen_key.as_str()));

        fs::remove_file(source.join("unseen.html")).unwrap();
        fs::write(
            source.join("owned-skip.html"),
            fixture_noindex("Owned skip", "not indexed initially"),
        )
        .unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        let owned_skip_key =
            UrlKey::parse("https://offline.example/guide/owned-skip.html").unwrap();
        let owned_skip_lease = store.issue_fence(&owned_skip_key).unwrap();
        store
            .apply(
                &owned_skip_lease,
                Intent::Upsert {
                    effective_url: owned_skip_key.to_string(),
                    title: "Foreign after noindex".to_owned(),
                    body: "foreign content after noindex".to_owned(),
                },
            )
            .unwrap();
        let status = run_cli(vec![
            "status".to_owned(),
            "--store".to_owned(),
            store_path.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert!(status.contains("state: ownership_conflict"));
        let before_second_collision = store.managed_snapshot().unwrap();
        assert!(matches!(
            run_cli(sync_args(&store_path, &source)),
            Err(ManagedCollectionError::ForeignUrlCollision(url)) if url == owned_skip_key.as_str()
        ));
        let after_second_collision = store.managed_snapshot().unwrap();
        assert_eq!(
            after_second_collision.generation_id,
            before_second_collision.generation_id
        );
        assert!(
            after_second_collision
                .documents
                .contains_key(owned_skip_key.as_str())
        );
        fs::remove_file(source.join("owned-skip.html")).unwrap();
        assert!(matches!(
            run_cli(sync_args(&store_path, &source)),
            Err(ManagedCollectionError::ForeignUrlCollision(url)) if url == owned_skip_key.as_str()
        ));
        assert!(
            read_owner_state(&store_path)
                .unwrap()
                .entries
                .get("owned-skip.html")
                .is_some_and(|entry| entry.noindex)
        );
        let after_removed_collision = store.managed_snapshot().unwrap();
        assert_eq!(
            after_removed_collision.generation_id,
            before_second_collision.generation_id
        );
        assert!(
            after_removed_collision
                .documents
                .contains_key(owned_skip_key.as_str())
        );
    }

    #[test]
    fn invalid_or_racing_source_never_deletes_an_owned_page() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("keep.html"),
            fixture_page("Keep", "uniquekeepcontent"),
        )
        .unwrap();
        run_cli(init_args(&store_path, &source)).unwrap();
        let store = PersistentIndex::open(&store_path).unwrap();
        let generation = store.managed_snapshot().unwrap().generation_id;
        fs::remove_file(source.join("keep.html")).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", source.join("link.css")).unwrap();
        assert!(run_cli(sync_args(&store_path, &source)).is_err());
        fs::remove_file(source.join("link.css")).unwrap();

        fs::write(source.join("invalid.html"), [0xff, 0xfe]).unwrap();
        assert!(run_cli(sync_args(&store_path, &source)).is_err());
        fs::remove_file(source.join("invalid.html")).unwrap();

        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = source.join("unreadable.html");
            fs::write(&unreadable, fixture_page("Unreadable", "must fail closed")).unwrap();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o0)).unwrap();
            assert!(run_cli(sync_args(&store_path, &source)).is_err());
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(unreadable).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid_name = std::ffi::OsString::from_vec(b"bad\\name.html".to_vec());
            fs::write(source.join(invalid_name), fixture_page("Bad", "badpath")).unwrap();
            assert!(run_cli(sync_args(&store_path, &source)).is_err());
            fs::remove_file(source.join("bad\\name.html")).unwrap();
        }

        assert!(run_cli(sync_args(&store_path, &temp.path().join("missing"))).is_err());
        let missing_status = run_cli(vec![
            "status".to_owned(),
            "--store".to_owned(),
            store_path.to_string_lossy().into_owned(),
        ])
        .unwrap();
        assert!(missing_status.contains("last failure: source directory is missing or unreadable"));
        let snapshot = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(snapshot.generation_id, generation);
        assert!(
            snapshot
                .documents
                .contains_key("https://offline.example/guide/keep.html")
        );

        fs::write(source.join("race.html"), fixture_page("Before", "before")).unwrap();
        let scanned = scan_source(
            &canonical_source_path(&source).unwrap(),
            &normalize_url_prefix(PREFIX).unwrap(),
        )
        .unwrap();
        fs::write(source.join("race.html"), fixture_page("After", "after")).unwrap();
        assert!(matches!(
            scanned.revalidate(),
            Err(ManagedCollectionError::SourceChanged)
        ));

        let moved_source = temp.path().join("moved-source");
        fs::rename(&source, &moved_source).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("keep.html"),
            fixture_page("Replacement", "replacement source must not be read"),
        )
        .unwrap();
        assert!(run_cli(sync_args(&store_path, &source)).is_err());
        let after_move = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after_move.generation_id, generation);
        assert!(
            after_move
                .documents
                .contains_key("https://offline.example/guide/keep.html")
        );

        fs::remove_dir_all(&source).unwrap();
        std::os::unix::fs::symlink(&moved_source, &source).unwrap();
        assert!(run_cli(sync_args(&store_path, &source)).is_err());
        let after_symlink_swap = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after_symlink_swap.generation_id, generation);
        assert!(
            after_symlink_swap
                .documents
                .contains_key("https://offline.example/guide/keep.html")
        );
    }

    #[test]
    fn ordinary_non_html_assets_are_ignored_without_index_mutation() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("page.html"),
            fixture_page("Page", "stable indexed passage"),
        )
        .unwrap();
        fs::write(source.join("style.css"), "body { color: navy; }").unwrap();
        fs::write(source.join("README.md"), "local collection notes").unwrap();

        let initialized = run_cli(init_args(&store_path, &source)).unwrap();
        assert!(initialized.contains("added 1"));
        let store = PersistentIndex::open(&store_path).unwrap();
        let before = store.managed_snapshot().unwrap();

        let scanned = scan_source(
            &canonical_source_path(&source).unwrap(),
            &normalize_url_prefix(PREFIX).unwrap(),
        )
        .unwrap();
        fs::write(source.join("style.css"), "body { color: teal; }").unwrap();
        assert!(matches!(
            scanned.revalidate(),
            Err(ManagedCollectionError::SourceChanged)
        ));
        fs::write(source.join("README.md"), "changed notes").unwrap();
        let synced = run_cli(sync_args(&store_path, &source)).unwrap();
        assert!(synced.contains("unchanged 1"));

        let after = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after.generation_id, before.generation_id);
        assert_eq!(after.segment_count, before.segment_count);
        assert_eq!(after.controls, before.controls);
        assert_eq!(after.documents.len(), before.documents.len());
        assert!(
            after
                .documents
                .contains_key("https://offline.example/guide/page.html")
        );
    }

    #[test]
    fn owner_history_exceeds_scan_limit_and_fails_at_its_own_bound() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("page-000.html"),
            fixture_page("Page 0", "original owned passage"),
        )
        .unwrap();
        run_cli(init_args(&store_path, &source)).unwrap();

        let rotations = 130;
        let mut current = "page-000.html".to_owned();
        for number in 1..=rotations {
            fs::remove_file(source.join(&current)).unwrap();
            current = format!("page-{number:03}.html");
            fs::write(
                source.join(&current),
                fixture_page(
                    &format!("Page {number}"),
                    &format!("rotated passage {number}"),
                ),
            )
            .unwrap();
            run_cli(sync_args(&store_path, &source)).unwrap();
        }

        fs::remove_file(source.join(&current)).unwrap();
        fs::write(
            source.join("page-000.html"),
            fixture_page("Page 0 again", "reintroduced old source path"),
        )
        .unwrap();
        run_cli(sync_args(&store_path, &source)).unwrap();
        let store = PersistentIndex::open(&store_path).unwrap();
        let live = store.managed_snapshot().unwrap();
        assert_eq!(live.documents.len(), 1);
        assert!(
            live.documents
                .contains_key("https://offline.example/guide/page-000.html")
        );

        let _collection_lock = CollectionLock::open(&store_path.join(OWNER_LOCK_NAME)).unwrap();
        let mut owner = read_owner_state(&store_path).unwrap();
        assert!(owner.entries.len() > crate::local_ingest::MAX_HTML_DOCUMENTS);
        while owner.entries.len() < MAX_OWNED_PATH_RECORDS {
            let number = owner.entries.len();
            let relative = format!("historic-{number:04}.html");
            let requested_url =
                map_relative_path(&normalize_url_prefix(PREFIX).unwrap(), &relative).unwrap();
            owner.entries.insert(
                relative,
                OwnerEntry {
                    requested_url: requested_url.to_string(),
                    indexed_version: None,
                    terminal_fence: None,
                    noindex: true,
                },
            );
        }
        write_owner_state(&store_path, &owner).unwrap();
        let owner_bytes = serde_json::to_vec(&owner).unwrap();
        assert!(owner_bytes.len() <= MAX_OWNER_STATE_BYTES);
        assert_eq!(
            fs::metadata(store_path.join(OWNER_STATE_NAME))
                .unwrap()
                .len() as usize,
            owner_bytes.len()
        );
        eprintln!(
            "history_capacity records={} owner_state_bytes={} index_segments={}",
            owner.entries.len(),
            owner_bytes.len(),
            live.segment_count
        );
        drop(_collection_lock);

        fs::write(
            source.join("overflow.html"),
            fixture_page("Overflow", "must not replace the existing page"),
        )
        .unwrap();
        let refusal = run_cli(sync_args(&store_path, &source)).unwrap_err();
        assert!(refusal.to_string().contains("4096 path record limit"));
        assert!(store.managed_reservation().unwrap().is_none());

        let after = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after.generation_id, live.generation_id);
        assert_eq!(after.segment_count, live.segment_count);
        assert_eq!(after.documents.len(), 1);
        assert!(
            after
                .documents
                .contains_key("https://offline.example/guide/page-000.html")
        );
        assert!(
            !after
                .documents
                .contains_key("https://offline.example/guide/overflow.html")
        );

        let _collection_lock = CollectionLock::open(&store_path.join(OWNER_LOCK_NAME)).unwrap();
        let mut owner = read_owner_state(&store_path).unwrap();
        owner
            .entries
            .retain(|relative, _| relative == "page-000.html");
        let prefix = normalize_url_prefix(PREFIX).unwrap();
        let suffix = "x".repeat(850);
        for number in 0..700 {
            let relative = format!("metadata-{number:04}-{suffix}.html");
            let requested_url = map_relative_path(&prefix, &relative).unwrap();
            owner.entries.insert(
                relative,
                OwnerEntry {
                    requested_url: requested_url.to_string(),
                    indexed_version: None,
                    terminal_fence: None,
                    noindex: true,
                },
            );
        }
        let owner_bytes = serde_json::to_vec(&owner).unwrap();
        assert!(owner_bytes.len() < MAX_OWNER_STATE_BYTES);
        write_owner_state(&store_path, &owner).unwrap();
        drop(_collection_lock);

        let byte_refusal = run_cli(sync_args(&store_path, &source)).unwrap_err();
        assert!(byte_refusal.to_string().contains("exceeds its 2 MiB bound"));
        assert!(store.managed_reservation().unwrap().is_none());
        let after_byte_refusal = PersistentIndex::open(&store_path)
            .unwrap()
            .managed_snapshot()
            .unwrap();
        assert_eq!(after_byte_refusal.generation_id, live.generation_id);
        assert_eq!(after_byte_refusal.segment_count, live.segment_count);
        assert_eq!(after_byte_refusal.documents.len(), 1);
        assert!(
            after_byte_refusal
                .documents
                .contains_key("https://offline.example/guide/page-000.html")
        );
        eprintln!(
            "metadata_capacity owner_records={} owner_state_bytes={} pending_refusal={:?}",
            read_owner_state(&store_path).unwrap().entries.len(),
            owner_bytes.len(),
            byte_refusal
        );
    }

    #[test]
    fn reservation_recovery_converges_before_and_after_publication() {
        if let Ok(store) = std::env::var("LEY_MANAGED_CRASH_STORE") {
            let source = std::env::var("LEY_MANAGED_CRASH_SOURCE").unwrap();
            let result = run_cli(sync_args(Path::new(&store), Path::new(&source)));
            panic!("storage failpoint did not terminate the child process: {result:?}");
        }

        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a.html"), fixture_page("A", "initialpassage")).unwrap();
        run_cli(init_args(&store_path, &source)).unwrap();
        let store = PersistentIndex::open(&store_path).unwrap();
        let foreign_key =
            UrlKey::parse("https://offline.example/foreign/before-crash.html").unwrap();
        let foreign_lease = store.issue_fence(&foreign_key).unwrap();
        store
            .apply(
                &foreign_lease,
                Intent::Upsert {
                    effective_url: foreign_key.to_string(),
                    title: "Foreign before crash".to_owned(),
                    body: "preserve this unrelated document".to_owned(),
                },
            )
            .unwrap();
        let acknowledged = read_owner_state(&store_path).unwrap().last_ack.unwrap();
        assert!(
            acknowledged.committed_generation < store.managed_snapshot().unwrap().generation_id
        );

        for (point, file, published) in [
            ("managed_reservation_installed", "b.html", false),
            ("managed_batch_before_publish", "c.html", false),
            ("managed_batch_after_publish", "d.html", true),
        ] {
            fs::write(source.join(file), fixture_page("Added", file)).unwrap();
            let before = store.managed_snapshot().unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "managed_collection::tests::reservation_recovery_converges_before_and_after_publication",
                ])
                .env("LEY_MANAGED_CRASH_STORE", store_path.to_str().unwrap())
                .env("LEY_MANAGED_CRASH_SOURCE", source.to_str().unwrap())
                .env("LEY_STORAGE_FAILPOINT", point)
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(86),
                "child failed to stop at {point}: {}",
                String::from_utf8_lossy(&child.stderr)
            );
            assert!(store.managed_reservation().unwrap().is_some());
            let crashed = PersistentIndex::open(&store_path)
                .unwrap()
                .managed_snapshot()
                .unwrap();
            assert_eq!(
                crashed.generation_id,
                before.generation_id + if published { 1 } else { 0 }
            );
            run_cli(sync_args(&store_path, &source)).unwrap();
            let after = PersistentIndex::open(&store_path)
                .unwrap()
                .managed_snapshot()
                .unwrap();
            assert_eq!(after.generation_id, before.generation_id + 1);
            assert_eq!(after.segment_count, before.segment_count + 1);
            assert!(store.managed_reservation().unwrap().is_none());
            assert!(
                after
                    .documents
                    .contains_key(&format!("https://offline.example/guide/{file}"))
            );
        }
        assert!(
            store
                .managed_snapshot()
                .unwrap()
                .documents
                .contains_key(foreign_key.as_str())
        );
    }

    #[test]
    fn concurrent_syncs_serialize_and_storage_writers_obey_reservation() {
        let temp = TempDirectory::new();
        let source = temp.path().join("source");
        let store_path = temp.path().join("index");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("a.html"), fixture_page("A", "initialpassage")).unwrap();
        run_cli(init_args(&store_path, &source)).unwrap();
        fs::write(source.join("b.html"), fixture_page("B", "secondpassage")).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let store_path = store_path.clone();
            let source = source.clone();
            workers.push(thread::spawn(move || {
                barrier.wait();
                run_cli(sync_args(&store_path, &source)).unwrap()
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        let store = PersistentIndex::open(&store_path).unwrap();
        let lease_key = UrlKey::parse("https://offline.example/lease/prepared.html").unwrap();
        let lease = store.issue_fence(&lease_key).unwrap();
        let before = store.managed_snapshot().unwrap();
        assert_eq!(before.documents.len(), 2);
        assert_eq!(before.generation_id, 4);

        let reservation = ManagedReservation {
            sync_id: "0123456789abcdef0123456789abcdef".to_owned(),
            base_generation: before.generation_id,
        };
        store.managed_install_reservation(&reservation).unwrap();
        let key = UrlKey::parse("https://offline.example/guide/blocked.html").unwrap();
        assert!(matches!(
            store.issue_fence(&key),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            store.apply(&lease, Intent::Tombstone),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            store.export_lease(&lease),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            store.compact(),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock
        ));
        store.managed_clear_reservation(&reservation).unwrap();
    }
}
