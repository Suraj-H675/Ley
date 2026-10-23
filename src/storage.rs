use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::analyzer::{ANALYZER_ID, Analyzer, MAX_TERM_SCALARS};
use crate::html::{HTML_SCHEMA_ID, MAX_DOCUMENT_TOKENS, MAX_FIELDS_BYTES, MAX_TITLE_BYTES};
use crate::index::{
    CorpusStatistics as QueryCorpusStatistics, InMemoryIndex, IndexedDocument, Posting, QueryError,
    SearchResult, bm25_field_contribution, query_with_segment_postings,
};
use crate::query::parse_query;
use crate::retrieval::{
    AnswerAssessment, DOCUMENT_INSPECTION_CONTRACT_VERSION, DOCUMENT_INSPECTION_PAGE_BYTES,
    DocumentInspectionPage, EvidenceHit, EvidencePassage, EvidenceReference, EvidenceResolveError,
    InsufficientEvidenceReason, MAX_PASSAGE_BYTES, MAX_RESPONSE_BYTES, MAX_RESPONSE_PASSAGE_BYTES,
    QuestionPlan, QuestionRequest, ResolvedEvidence, RetrievalCompleteness, RetrievalError,
    RetrievalMode, RetrievalRequest, RetrievalResponse, RetrievalStatus,
    match_passage_text_bounded, passage_windows, plan_question,
};
use crate::url_key::{MAX_URL_KEY_BYTES, UrlKey};

mod manifest;
mod segment;
use manifest::{
    ControlRecord, CorpusStatistics, CurrentPointer, Manifest, PolicyRecord, TerminalRecord,
};
use segment::{Segment, SegmentDescriptor};

const STORE_NAME: &str = "STORE";
const LEASE_KEY_NAME: &str = "LEASE_KEY";
const LOCK_NAME: &str = "LOCK";
const CURRENT_NAME: &str = "CURRENT";
const PUBLIC_COLLECTION_NAME: &str = "PUBLIC_COLLECTION";
const PUBLIC_NOTICE_STORE_BASENAME: &str = "rust-stdlib-documentation-MIT.txt";
const MANAGED_RESERVATION_NAME: &str = ".LOCAL_COLLECTION_RESERVATION";
const MANAGED_RESERVATION_TEMP_NAME: &str = ".LOCAL_COLLECTION_RESERVATION.tmp";
const MANAGED_OWNER_STATE_NAME: &str = "LOCAL_COLLECTION";
const MAX_PUBLIC_COLLECTION_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_NOTICE_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_PERMISSION_TEXT_BYTES: usize = 1024;
const STORE_MAGIC: &[u8; 8] = b"LEYSTOR3";
const LEASE_KEY_MAGIC: &[u8; 8] = b"LEYMACK3";
const CURRENT_MAGIC: &[u8; 8] = b"LEYHEAD3";
const GENERATION_MAGIC: &[u8; 8] = b"LEYGEN03";
const LEASE_MAGIC: &[u8; 8] = b"LEYLEASE";
const LEASE_DOMAIN: &[u8] = b"ley-fence-lease-v1\0";
const LEASE_VERSION: u16 = 1;
const FORMAT_MAJOR: u16 = 0;
const FORMAT_MINOR: u16 = 3;
const PUBLIC_STORE_MINOR: u16 = 4;
const PUBLIC_STORE_FLAG: u32 = 1;
const STORE_BYTES: usize = 64;
const LEASE_KEY_BYTES: usize = 96;
const CURRENT_BYTES: usize = 112;
const HEADER_BYTES: usize = 448;
const DESCRIPTOR_BYTES: usize = 56;
const SECTION_COUNT: usize = 4;
const MAX_GENERATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 128 * 1024 * 1024;
const MAX_SEGMENT_BYTES: usize = 512 * 1024 * 1024;
const MAX_ACTIVE_SEGMENT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SEGMENTS: usize = 4096;
const MAX_PHYSICAL_POSTING_RECORDS: usize = 4_000_000;
const MAX_POSITION_VALUES: u64 = 50_000_000;
const MAX_SNAPSHOT_ESTIMATE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_QUESTION_SEGMENT_PROBES: usize = MAX_SEGMENTS;
const MAX_QUESTION_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_QUESTION_SEGMENT_MEMORY_ESTIMATE: u64 = 256 * 1024 * 1024;
const MAX_QUESTION_POSTING_PROBES: usize = 8_192;
const MAX_QUESTION_CANDIDATES: usize = 256;
const MAX_QUESTION_PASSAGE_DOCUMENTS: usize = 32;
const MAX_QUESTION_PASSAGE_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_QUESTION_PASSAGE_WINDOW_BYTES: usize = 64 * 1024 * 1024;
const STORE_MAGIC_V6: &[u8; 8] = b"LEYSTOR6";
const LEASE_KEY_MAGIC_V6: &[u8; 8] = b"LEYMACK6";
const STORE_V6_MAJOR: u16 = 1;
const STORE_V6_MINOR: u16 = 0;
const MAX_DOCUMENTS: usize = 100_000;
const MAX_TERMS: usize = 500_000;
const MAX_POSTING_RECORDS: usize = 1_000_000;
const MAX_CONTROL_KEYS: usize = 100_000;
const MAX_TERMINAL_INTENTS: usize = 500_000;
const MAX_EFFECTIVE_URL_BYTES: usize = 2048;
const LEASE_HEADER_BYTES: usize = 38;
const LEASE_TAG_BYTES: usize = 32;
const MAX_LEASE_TOKEN_BYTES: usize = LEASE_HEADER_BYTES + MAX_URL_KEY_BYTES + LEASE_TAG_BYTES;
const PUBLIC_COLLECTION_DOMAIN: &[u8] = b"ley-public-collection-v1\0";

type StoreId = [u8; 16];
type VersionId = [u8; 32];
type LeaseMacKey = [u8; 32];
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Intent {
    Upsert {
        effective_url: String,
        title: String,
        body: String,
    },
    Tombstone,
    Revoke,
    Readmit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Query(QueryError),
    UrlKey(String),
    CorruptCommitted(String),
    UnsupportedFormat { major: u16, minor: u16 },
    ReindexRequired(String),
    IncompleteInitialStore,
    StoreAlreadyExists,
    WrongStoreLease,
    InvalidLease,
    StaleFence,
    ConflictingIntent,
    Revoked,
    NotRevoked,
    CapacityExceeded(&'static str),
    UnsupportedPlatform,
    PublicCollectionExpired,
    PublicCollectionConflict,
    ClockUnavailable,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O error: {error}"),
            Self::Query(error) => write!(f, "index error: {error}"),
            Self::UrlKey(error) => write!(f, "invalid URL key: {error}"),
            Self::CorruptCommitted(message) => {
                write!(f, "committed storage generation is corrupt: {message}")
            }
            Self::UnsupportedFormat { major, minor } => {
                write!(f, "unsupported storage format {major}.{minor}")
            }
            Self::ReindexRequired(message) => write!(f, "reindex required: {message}"),
            Self::IncompleteInitialStore => {
                f.write_str("store has no committed initial generation")
            }
            Self::StoreAlreadyExists => f.write_str("store path already exists"),
            Self::WrongStoreLease => f.write_str("lease belongs to a different store"),
            Self::InvalidLease => f.write_str("lease is invalid for this store or fence"),
            Self::StaleFence => f.write_str("lease fence is no longer current"),
            Self::ConflictingIntent => {
                f.write_str("a different intent is already recorded at this fence")
            }
            Self::Revoked => f.write_str("URL key is revoked until explicit readmission"),
            Self::NotRevoked => f.write_str("URL key is not revoked"),
            Self::CapacityExceeded(limit) => write!(f, "storage capacity exceeded: {limit}"),
            Self::UnsupportedPlatform => {
                f.write_str("the storage adapter currently supports Linux only")
            }
            Self::PublicCollectionExpired => {
                f.write_str("public collection retention or policy deadline has expired")
            }
            Self::PublicCollectionConflict => {
                f.write_str("public collection policy conflicts with this index store")
            }
            Self::ClockUnavailable => {
                f.write_str("system clock is unavailable for public collection checks")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Query(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<QueryError> for StorageError {
    fn from(error: QueryError) -> Self {
        Self::Query(error)
    }
}

#[derive(Debug)]
pub(crate) enum ManagedStorageError {
    Storage(StorageError),
    Reserved,
    Conflict,
}

impl fmt::Display for ManagedStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{error}"),
            Self::Reserved => {
                f.write_str("store is reserved by a pending managed local collection sync")
            }
            Self::Conflict => {
                f.write_str("managed local collection store state changed; sync is blocked")
            }
        }
    }
}

impl From<StorageError> for ManagedStorageError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<io::Error> for ManagedStorageError {
    fn from(error: io::Error) -> Self {
        Self::Storage(StorageError::Io(error))
    }
}

impl From<QueryError> for ManagedStorageError {
    fn from(error: QueryError) -> Self {
        Self::Storage(StorageError::Query(error))
    }
}

fn managed_write_blocked(detail: &'static str) -> StorageError {
    StorageError::Io(io::Error::new(io::ErrorKind::WouldBlock, detail))
}

#[derive(Clone, Debug)]
pub struct FenceLease {
    store_id: StoreId,
    key: UrlKey,
    fence: NonZeroU64,
}

impl FenceLease {
    pub fn key(&self) -> &UrlKey {
        &self.key
    }

    pub fn fence(&self) -> NonZeroU64 {
        self.fence
    }
}

#[derive(Clone)]
pub struct ReadView {
    snapshot: Arc<SegmentedSnapshot>,
    public_visible_until_ms: Option<u64>,
}

pub(crate) struct ReadOnlyIndexInspection {
    pub store_id: [u8; 16],
    pub generation_id: u64,
    pub live_document_keys: BTreeSet<String>,
    _lock: FileLock,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedReservation {
    pub sync_id: String,
    pub base_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedControlSnapshot {
    pub high_water: u64,
    pub terminal_fence: Option<u64>,
    pub terminal_version: Option<String>,
    pub terminal_tombstone: bool,
    pub revoked: bool,
}

#[derive(Clone)]
pub(crate) struct ManagedStoreSnapshot {
    pub store_id: [u8; 16],
    pub generation_id: u64,
    pub segment_count: usize,
    pub analyzer_id: String,
    pub html_schema_id: String,
    pub documents: BTreeMap<String, crate::index::IndexedDocument>,
    pub controls: BTreeMap<String, ManagedControlSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedExpectedState {
    pub high_water: u64,
    pub terminal_fence: Option<u64>,
    pub terminal_version: Option<String>,
    pub terminal_tombstone: bool,
    pub live_version: Option<String>,
    pub revoked: bool,
}

pub(crate) enum ManagedBatchIntent {
    Upsert {
        effective_url: String,
        title: String,
        body: String,
    },
    Tombstone,
}

pub(crate) struct ManagedBatchAction {
    pub key: UrlKey,
    pub expected: ManagedExpectedState,
    pub intent: ManagedBatchIntent,
}

struct SegmentedSnapshot {
    manifest: Manifest,
    segments: BTreeMap<u64, Arc<Segment>>,
    documents: BTreeMap<String, crate::index::IndexedDocument>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicPermissionEvidence {
    pub granted: bool,
    pub basis: String,
    pub evidence: String,
    pub reviewed_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicCollectionGate {
    pub policy_sha256: String,
    pub source_id: String,
    pub origin: String,
    pub path_prefixes: Vec<String>,
    pub installed_at_ms: u64,
    pub visible_until_ms: u64,
    pub license: String,
    pub source_version: String,
    pub notice_file: String,
    pub notice_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_permission: Option<PublicPermissionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_permission: Option<PublicPermissionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_permission: Option<PublicPermissionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_permission: Option<PublicPermissionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_contact: Option<String>,
}

impl PublicCollectionGate {
    fn same_admission(&self, other: &Self) -> bool {
        self.policy_sha256 == other.policy_sha256
            && self.source_id == other.source_id
            && self.origin == other.origin
            && self.path_prefixes == other.path_prefixes
            && self.license == other.license
            && self.source_version == other.source_version
            && self.notice_file == other.notice_file
            && self.notice_sha256 == other.notice_sha256
            && self.fetch_permission == other.fetch_permission
            && self.storage_permission == other.storage_permission
            && self.index_permission == other.index_permission
            && self.display_permission == other.display_permission
            && self.removal_contact == other.removal_contact
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PublicCollectionRecord {
    schema: String,
    store_id: [u8; 16],
    gate: PublicCollectionGate,
    mac: String,
}

impl ReadView {
    pub fn generation_id(&self) -> u64 {
        self.snapshot.manifest.generation_id
    }

    pub fn document_count(&self) -> usize {
        self.snapshot.documents.len()
    }

    pub fn query(&self, expression: &str) -> Result<Vec<SearchResult>, StorageError> {
        self.query_at(expression, system_time_ms()?)
    }

    fn query_at(&self, expression: &str, now_ms: u64) -> Result<Vec<SearchResult>, StorageError> {
        if self
            .public_visible_until_ms
            .is_some_and(|deadline| now_ms >= deadline)
        {
            return Err(StorageError::PublicCollectionExpired);
        }
        let query = parse_query(expression)?;
        let postings = self.snapshot.query_postings(&query.score_terms)?;
        let statistics = self.snapshot.query_statistics()?;
        Ok(query_with_segment_postings(
            &self.snapshot.documents,
            &postings,
            &query,
            &statistics,
            self.snapshot.manifest.generation_id,
        )?)
    }

    pub(crate) fn document(&self, key: &UrlKey) -> Option<crate::index::IndexedDocument> {
        self.snapshot.documents.get(key.as_str()).cloned()
    }
}

impl SegmentedSnapshot {
    fn query_postings(
        &self,
        terms: &[String],
    ) -> Result<BTreeMap<String, BTreeMap<String, crate::index::Posting>>, StorageError> {
        let mut merged = BTreeMap::new();
        for term in terms {
            let mut by_document = BTreeMap::new();
            for (segment_id, segment) in &self.segments {
                let Some(records) = segment.postings.get(term) else {
                    continue;
                };
                for (ordinal, posting) in records {
                    let document = segment
                        .documents
                        .get(*ordinal as usize)
                        .ok_or_else(|| corrupt("posting ordinal is missing in pinned segment"))?;
                    let visible = self
                        .manifest
                        .live
                        .get(&document.id)
                        .is_some_and(|reference| {
                            reference.segment_id == *segment_id
                                && reference.ordinal == *ordinal
                                && decode_version_id(&document.version_id).ok()
                                    == Some(reference.version)
                        });
                    if visible
                        && by_document
                            .insert(document.id.clone(), posting.clone())
                            .is_some()
                    {
                        return Err(corrupt("two live segments contain the same document key"));
                    }
                }
            }
            if !by_document.is_empty() {
                merged.insert(term.clone(), by_document);
            }
        }
        Ok(merged)
    }

    fn query_statistics(&self) -> Result<QueryCorpusStatistics, StorageError> {
        let statistics = &self.manifest.statistics;
        let document_count = usize::try_from(statistics.document_count)
            .map_err(|_| corrupt("live document count overflow"))?;
        let mut field_document_frequencies = BTreeMap::new();
        for (term, frequencies) in &statistics.field_document_frequencies {
            field_document_frequencies.insert(
                term.clone(),
                (
                    usize::try_from(frequencies.title).map_err(|_| corrupt("title DF overflow"))?,
                    usize::try_from(frequencies.body).map_err(|_| corrupt("body DF overflow"))?,
                ),
            );
        }
        Ok(QueryCorpusStatistics {
            document_count,
            title_token_total: statistics.title_token_total,
            body_token_total: statistics.body_token_total,
            field_document_frequencies,
        })
    }
}

pub struct PersistentIndex {
    path: PathBuf,
    store_id: StoreId,
    writer: Mutex<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionReport {
    pub old_generation: u64,
    pub new_generation: u64,
    pub merged_segments: Vec<SegmentDescriptorSummary>,
    pub replacement_segments: Vec<SegmentDescriptorSummary>,
    pub removed_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentDescriptorSummary {
    pub id: u64,
    pub byte_len: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReport {
    pub source_generation: u64,
    pub destination_generation: u64,
    pub document_count: usize,
    pub destination: PathBuf,
}

#[derive(Clone, Debug, Default)]
struct DocumentControl {
    high_water: u64,
    terminal: BTreeMap<u64, TerminalIntent>,
    policy: BTreeMap<u64, PolicyEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalIntent {
    Upsert(VersionId),
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyEvent {
    Revoked,
    Readmitted,
}

#[derive(Clone)]
struct Generation {
    id: u64,
    parent_id: u64,
    index: InMemoryIndex,
    controls: BTreeMap<UrlKey, DocumentControl>,
}

impl PersistentIndex {
    pub(crate) fn store_identity(&self) -> [u8; 16] {
        self.store_id
    }

    pub(crate) fn publish_managed_collection(
        &self,
        destination: impl AsRef<Path>,
    ) -> Result<(), ManagedStorageError> {
        let destination = destination.as_ref();
        let owner_state = fs::symlink_metadata(self.path.join(MANAGED_OWNER_STATE_NAME))?;
        if !owner_state.file_type().is_file() {
            return Err(ManagedStorageError::Conflict);
        }
        let source_parent = fs::canonicalize(
            self.path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let destination_parent = fs::canonicalize(
            destination
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        if source_parent != destination_parent {
            return Err(ManagedStorageError::Conflict);
        }
        storage_failpoint("managed_init_before_publish");
        rename_directory_noreplace(&self.path, destination)?;
        sync_directory(&destination_parent)?;
        Ok(())
    }

    pub(crate) fn managed_snapshot(&self) -> Result<ManagedStoreSnapshot, ManagedStorageError> {
        let _lock = self.lock_shared()?;
        let snapshot = self.load_snapshot_locked()?;
        let mut controls = BTreeMap::new();
        for (key, control) in &snapshot.manifest.controls {
            let (terminal_fence, terminal_version, terminal_tombstone) =
                match control.terminal.last_key_value() {
                    Some((fence, TerminalRecord::Upsert(version))) => {
                        (Some(*fence), Some(hex_lowercase(version)), false)
                    }
                    Some((fence, TerminalRecord::Tombstone)) => (Some(*fence), None, true),
                    None => (None, None, false),
                };
            controls.insert(
                key.clone(),
                ManagedControlSnapshot {
                    high_water: control.high_water,
                    terminal_fence,
                    terminal_version,
                    terminal_tombstone,
                    revoked: manifest_is_revoked(control),
                },
            );
        }
        Ok(ManagedStoreSnapshot {
            store_id: self.store_id,
            generation_id: snapshot.manifest.generation_id,
            segment_count: snapshot.manifest.segments.len(),
            analyzer_id: snapshot.manifest.analyzer_id,
            html_schema_id: snapshot.manifest.html_schema_id,
            documents: snapshot.documents,
            controls,
        })
    }

    pub(crate) fn managed_reservation(
        &self,
    ) -> Result<Option<ManagedReservation>, ManagedStorageError> {
        let _lock = self.lock_shared()?;
        Ok(self.read_managed_reservation_locked()?)
    }

    pub(crate) fn managed_install_reservation(
        &self,
        reservation: &ManagedReservation,
    ) -> Result<(), ManagedStorageError> {
        validate_managed_reservation(reservation)?;
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        if self.read_managed_reservation_locked()?.is_some() {
            return Err(ManagedStorageError::Reserved);
        }
        if self.load_public_collection_locked()?.is_some() {
            return Err(ManagedStorageError::Conflict);
        }
        let current = self.load_manifest_locked()?;
        if current.generation_id != reservation.base_generation {
            return Err(ManagedStorageError::Conflict);
        }
        let bytes = serde_json::to_vec(reservation)
            .map_err(|_| corrupt("managed reservation could not be encoded"))?;
        write_private_file_atomically(
            &self.path.join(MANAGED_RESERVATION_NAME),
            &self.path.join(MANAGED_RESERVATION_TEMP_NAME),
            &bytes,
        )?;
        storage_failpoint("managed_reservation_installed");
        Ok(())
    }

    pub(crate) fn managed_clear_reservation(
        &self,
        expected: &ManagedReservation,
    ) -> Result<(), ManagedStorageError> {
        validate_managed_reservation(expected)?;
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        if self.read_managed_reservation_locked()?.as_ref() != Some(expected) {
            return Err(ManagedStorageError::Conflict);
        }
        fs::remove_file(self.path.join(MANAGED_RESERVATION_NAME))?;
        sync_directory(&self.path)?;
        Ok(())
    }

    pub(crate) fn managed_batch(
        &self,
        reservation: &ManagedReservation,
        actions: Vec<ManagedBatchAction>,
    ) -> Result<(u64, BTreeMap<String, u64>), ManagedStorageError> {
        validate_managed_reservation(reservation)?;
        if actions.is_empty() {
            return Err(ManagedStorageError::Conflict);
        }
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        if self.read_managed_reservation_locked()?.as_ref() != Some(reservation) {
            return Err(ManagedStorageError::Conflict);
        }
        if self.load_public_collection_locked()?.is_some() {
            return Err(ManagedStorageError::Conflict);
        }
        let current_snapshot = self.load_snapshot_locked()?;
        let current = &current_snapshot.manifest;
        if current.generation_id != reservation.base_generation {
            return Err(ManagedStorageError::Conflict);
        }

        let mut next = next_manifest(current)?;
        let mut seen = BTreeSet::new();
        let mut prepared = Vec::with_capacity(actions.len());
        let mut target_fences = BTreeMap::new();
        for action in actions {
            let key_text = action.key.as_str().to_owned();
            if !seen.insert(key_text.clone()) {
                return Err(ManagedStorageError::Conflict);
            }
            let control = current.controls.get(&key_text);
            let (terminal_fence, terminal_version, terminal_tombstone, high_water, revoked) =
                match control {
                    Some(control) => match control.terminal.last_key_value() {
                        Some((fence, TerminalRecord::Upsert(version))) => (
                            Some(*fence),
                            Some(hex_lowercase(version)),
                            false,
                            control.high_water,
                            manifest_is_revoked(control),
                        ),
                        Some((fence, TerminalRecord::Tombstone)) => (
                            Some(*fence),
                            None,
                            true,
                            control.high_water,
                            manifest_is_revoked(control),
                        ),
                        None => (
                            None,
                            None,
                            false,
                            control.high_water,
                            manifest_is_revoked(control),
                        ),
                    },
                    None => (None, None, false, 0, false),
                };
            let live = current_snapshot.documents.get(&key_text);
            let live_version = live.map(|document| document.version_id.clone());
            let actual = ManagedExpectedState {
                high_water,
                terminal_fence,
                terminal_version,
                terminal_tombstone,
                live_version,
                revoked,
            };
            if actual != action.expected || revoked {
                if revoked {
                    return Err(StorageError::Revoked.into());
                }
                return Err(ManagedStorageError::Conflict);
            }
            let fence = high_water
                .checked_add(1)
                .ok_or(StorageError::CapacityExceeded("u64 fence exhausted"))?;
            target_fences.insert(key_text.clone(), fence);
            let mut control = control.cloned().unwrap_or_default();
            control.high_water = fence;
            match action.intent {
                ManagedBatchIntent::Upsert {
                    effective_url,
                    title,
                    body,
                } => {
                    if effective_url.is_empty() || effective_url.len() > MAX_EFFECTIVE_URL_BYTES {
                        return Err(
                            StorageError::CapacityExceeded("effective URL byte limit").into()
                        );
                    }
                    UrlKey::parse(&effective_url)
                        .map_err(|error| StorageError::UrlKey(error.to_string()))?;
                    let mut prepared_index = InMemoryIndex::new();
                    prepared_index.upsert_fields(key_text.clone(), effective_url, title, body)?;
                    let document = prepared_index
                        .documents()
                        .get(&key_text)
                        .cloned()
                        .ok_or_else(|| corrupt("managed upsert document disappeared"))?;
                    let version = decode_version_id(&document.version_id)?;
                    if let Some(previous) = current_snapshot.documents.get(&key_text) {
                        remove_document_statistics(&mut next.statistics, previous)?;
                    }
                    add_document_statistics(&mut next.statistics, &document)?;
                    control
                        .terminal
                        .insert(fence, TerminalRecord::Upsert(version));
                    prepared.push((key_text, control, Some(document)));
                }
                ManagedBatchIntent::Tombstone => {
                    let Some(previous) = current_snapshot.documents.get(&key_text) else {
                        return Err(ManagedStorageError::Conflict);
                    };
                    remove_document_statistics(&mut next.statistics, previous)?;
                    control.terminal.insert(fence, TerminalRecord::Tombstone);
                    prepared.push((key_text, control, None));
                }
            }
        }

        let mut segment = None;
        let mut documents = prepared
            .iter()
            .filter_map(|(_, _, document)| document.clone())
            .collect::<Vec<_>>();
        if !documents.is_empty() {
            documents.sort_by(|left, right| left.id.cmp(&right.id));
            let segment_id = next.next_segment_id;
            next.next_segment_id = segment_id
                .checked_add(1)
                .ok_or(StorageError::CapacityExceeded("segment id exhausted"))?;
            let new_segment = Segment::from_documents(segment_id, documents)?;
            for (ordinal, document) in new_segment.documents.iter().enumerate() {
                next.live.insert(
                    document.id.clone(),
                    manifest::LiveReference {
                        segment_id,
                        ordinal: u32::try_from(ordinal)
                            .map_err(|_| StorageError::CapacityExceeded("segment ordinal"))?,
                        version: decode_version_id(&document.version_id)?,
                    },
                );
            }
            next.segments.push(new_segment.descriptor.clone());
            next.segments.sort_by_key(|descriptor| descriptor.id);
            segment = Some(new_segment);
        }
        for (key, control, document) in prepared {
            if document.is_none() {
                next.live.remove(&key);
            }
            next.controls.insert(key, control);
        }
        validate_proposed_manifest_shape(&next, self.store_id)?;
        storage_failpoint("managed_batch_before_publish");
        self.publish_manifest_locked(&next, segment.as_ref())?;
        storage_failpoint("managed_batch_after_publish");
        Ok((next.generation_id, target_fences))
    }

    fn read_managed_reservation_locked(&self) -> Result<Option<ManagedReservation>, StorageError> {
        let path = self.path.join(MANAGED_RESERVATION_NAME);
        let bytes = match read_bounded_file(&path, 4096) {
            Ok(bytes) => bytes,
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let reservation: ManagedReservation = serde_json::from_slice(&bytes)
            .map_err(|_| corrupt("managed collection reservation is malformed"))?;
        validate_managed_reservation(&reservation)
            .map_err(|_| corrupt("managed collection reservation is malformed"))?;
        Ok(Some(reservation))
    }

    fn ensure_no_managed_reservation_locked(&self) -> Result<(), StorageError> {
        match self.read_managed_reservation_locked() {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(managed_write_blocked(
                "store is reserved by a pending managed local collection sync",
            )),
            Err(error) => Err(error),
        }
    }

    fn ensure_not_managed_collection_locked(&self) -> Result<(), StorageError> {
        match fs::symlink_metadata(self.path.join(MANAGED_OWNER_STATE_NAME)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(managed_write_blocked(
                "store is bound to a managed local collection; use its sync command",
            )),
            Err(error) => Err(error.into()),
        }
    }

    /// Inspect committed index metadata without exposing mutation operations or
    /// opening the store's lock file for writing.
    pub(crate) fn inspect_read_only(
        path: impl AsRef<Path>,
    ) -> Result<ReadOnlyIndexInspection, StorageError> {
        let path = path.as_ref();
        validate_store_directory(path)?;
        let store_bytes = read_bounded_file(&path.join(STORE_NAME), STORE_BYTES)?;
        if store_bytes.get(..8) == Some(STORE_MAGIC.as_slice()) {
            return Err(StorageError::ReindexRequired(
                "read-only inspection does not support legacy Gate 3 stores".to_owned(),
            ));
        }
        let (store_id, _) = decode_store(&store_bytes)?;
        let store = Self {
            path: fs::canonicalize(path)?,
            store_id,
            writer: Mutex::new(()),
        };
        let lock = FileLock::new_shared_read_only(&store.path.join(LOCK_NAME))?;
        let snapshot = store.load_snapshot_locked()?;
        Ok(ReadOnlyIndexInspection {
            store_id,
            generation_id: snapshot.manifest.generation_id,
            live_document_keys: snapshot.documents.into_keys().collect(),
            _lock: lock,
        })
    }

    pub fn create(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(StorageError::StoreAlreadyExists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        create_store_directory(&path)?;
        create_private_file(&path.join(LOCK_NAME), &[])?;
        let store_id = random_store_id()?;
        let store_bytes = encode_store_v6(store_id, false);
        create_private_file(&path.join(STORE_NAME), &store_bytes)?;
        let lease_mac_key = random_lease_mac_key()?;
        create_private_file(
            &path.join(LEASE_KEY_NAME),
            &encode_lease_key_v6(store_id, lease_mac_key),
        )?;
        sync_directory(&path)?;
        sync_directory(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let path = fs::canonicalize(path)?;

        let store = Self {
            path,
            store_id,
            writer: Mutex::new(()),
        };
        let _lock = store.lock_exclusive()?;
        let initial = empty_manifest(store_id);
        store.publish_manifest_locked(&initial, None)?;
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        validate_store_directory(&path)?;
        let store_bytes = read_bounded_file(&path.join(STORE_NAME), STORE_BYTES)?;
        if store_bytes.get(..8) == Some(STORE_MAGIC.as_slice()) {
            let path_text = path.display();
            return Err(StorageError::ReindexRequired(format!(
                "Gate 3 store at {path_text} must be converted to a separate destination; stop all writers, then run `ley reindex-gate3 --source {path_text} --destination NEW_PATH`"
            )));
        }
        let (store_id, _) = decode_store(&store_bytes)?;
        let store = Self {
            path: fs::canonicalize(path)?,
            store_id,
            writer: Mutex::new(()),
        };
        {
            let _lock = store.lock_shared()?;
            store.load_snapshot_locked()?;
        }
        Ok(store)
    }

    pub fn issue_fence(&self, key: &UrlKey) -> Result<FenceLease, StorageError> {
        validate_url_key(key.as_str())?;
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        self.ensure_no_managed_reservation_locked()?;
        let current_snapshot = self.load_snapshot_locked()?;
        let current = &current_snapshot.manifest;
        let mut next = next_manifest(current)?;
        let control = next.controls.entry(key.as_str().to_owned()).or_default();
        control.high_water = control
            .high_water
            .checked_add(1)
            .ok_or(StorageError::CapacityExceeded("u64 fence exhausted"))?;
        let fence = NonZeroU64::new(control.high_water).ok_or(StorageError::InvalidLease)?;
        self.publish_manifest_locked(&next, None)?;
        Ok(FenceLease {
            store_id: self.store_id,
            key: key.clone(),
            fence,
        })
    }

    pub fn export_lease(&self, lease: &FenceLease) -> Result<Vec<u8>, StorageError> {
        if lease.store_id != self.store_id {
            return Err(StorageError::WrongStoreLease);
        }
        validate_url_key(lease.key.as_str()).map_err(|_| StorageError::InvalidLease)?;
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        self.ensure_no_managed_reservation_locked()?;
        let current = self.load_manifest_locked()?;
        let Some(control) = current.controls.get(lease.key.as_str()) else {
            return Err(StorageError::InvalidLease);
        };
        if lease.fence.get() > control.high_water {
            return Err(StorageError::InvalidLease);
        }
        let mac_key = self.ensure_lease_mac_key_locked()?;
        encode_lease_token(self.store_id, &mac_key, &lease.key, lease.fence)
    }

    pub fn restore_lease(&self, token: &[u8]) -> Result<FenceLease, StorageError> {
        let _lock = self.lock_shared()?;
        let mac_key = self.read_lease_mac_key_locked()?;
        let (store_id, key, fence) = decode_lease_token(token, &mac_key)?;
        if store_id != self.store_id {
            return Err(StorageError::WrongStoreLease);
        }
        let current = self.load_manifest_locked()?;
        let Some(control) = current.controls.get(key.as_str()) else {
            return Err(StorageError::InvalidLease);
        };
        if fence.get() > control.high_water {
            return Err(StorageError::InvalidLease);
        }
        Ok(FenceLease {
            store_id,
            key,
            fence,
        })
    }

    pub fn apply(&self, lease: &FenceLease, intent: Intent) -> Result<ApplyOutcome, StorageError> {
        if lease.store_id != self.store_id {
            return Err(StorageError::WrongStoreLease);
        }
        if lease.fence.get() == 0 {
            return Err(StorageError::InvalidLease);
        }
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        self.ensure_no_managed_reservation_locked()?;
        let current_snapshot = self.load_snapshot_locked()?;
        let current = &current_snapshot.manifest;
        let mut next = next_manifest(current)?;
        let fence = lease.fence.get();
        let key = lease.key.clone();
        let mut prepared_document = None;
        let (terminal, policy) = match &intent {
            Intent::Upsert {
                effective_url,
                title,
                body,
            } => {
                if effective_url.is_empty() || effective_url.len() > MAX_EFFECTIVE_URL_BYTES {
                    return Err(StorageError::CapacityExceeded("effective URL byte limit"));
                }
                UrlKey::parse(effective_url)
                    .map_err(|error| StorageError::UrlKey(error.to_string()))?;
                let mut prepared = InMemoryIndex::new();
                prepared.upsert_fields(
                    key.as_str().to_owned(),
                    effective_url.clone(),
                    title.clone(),
                    body.clone(),
                )?;
                let document = prepared
                    .documents()
                    .get(key.as_str())
                    .ok_or_else(|| corrupt("prepared upsert disappeared"))?;
                let version = decode_version_id(&document.version_id)?;
                prepared_document = Some(document.clone());
                (Some(TerminalRecord::Upsert(version)), None)
            }
            Intent::Tombstone => (Some(TerminalRecord::Tombstone), None),
            Intent::Revoke => (Some(TerminalRecord::Tombstone), Some(PolicyRecord::Revoked)),
            Intent::Readmit => (None, Some(PolicyRecord::Readmitted)),
        };

        let key_text = key.as_str().to_owned();
        let mut control = next.controls.get(&key_text).cloned().unwrap_or_default();
        let stored_terminal = control.terminal.get(&fence).copied();
        let stored_policy = control.policy.get(&fence).copied();
        if is_exact_manifest_replay(terminal, policy, stored_terminal, stored_policy) {
            return Ok(ApplyOutcome::AlreadyApplied);
        }
        if stored_terminal.is_some() || stored_policy.is_some() {
            return Err(StorageError::ConflictingIntent);
        }
        if control.high_water != fence {
            return Err(StorageError::StaleFence);
        }
        let revoked = manifest_is_revoked(&control);
        let old_document = current_snapshot.documents.get(&key_text).cloned();
        let mut new_segment = None;
        match intent {
            Intent::Upsert { .. } => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                let Some(document) = prepared_document else {
                    return Err(corrupt("prepared upsert fields missing"));
                };
                if let Some(previous) = &old_document {
                    remove_document_statistics(&mut next.statistics, previous)?;
                }
                add_document_statistics(&mut next.statistics, &document)?;
                let segment_id = next.next_segment_id;
                next.next_segment_id = segment_id
                    .checked_add(1)
                    .ok_or(StorageError::CapacityExceeded("segment id exhausted"))?;
                let segment = Segment::from_documents(segment_id, vec![document.clone()])?;
                next.live.insert(
                    key_text.clone(),
                    manifest::LiveReference {
                        segment_id,
                        ordinal: 0,
                        version: decode_version_id(&document.version_id)?,
                    },
                );
                next.segments.push(segment.descriptor.clone());
                next.segments.sort_by_key(|descriptor| descriptor.id);
                new_segment = Some(segment);
                control.terminal.insert(
                    fence,
                    terminal.ok_or_else(|| corrupt("upsert terminal identity missing"))?,
                );
            }
            Intent::Tombstone => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                if let Some(previous) = &old_document {
                    remove_document_statistics(&mut next.statistics, previous)?;
                    next.live.remove(&key_text);
                }
                control.terminal.insert(fence, TerminalRecord::Tombstone);
            }
            Intent::Revoke => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                if let Some(previous) = &old_document {
                    remove_document_statistics(&mut next.statistics, previous)?;
                    next.live.remove(&key_text);
                }
                control.terminal.insert(fence, TerminalRecord::Tombstone);
                control.policy.insert(fence, PolicyRecord::Revoked);
            }
            Intent::Readmit => {
                if !revoked {
                    return Err(StorageError::NotRevoked);
                }
                control.policy.insert(fence, PolicyRecord::Readmitted);
            }
        }
        next.controls.insert(key_text, control);
        validate_proposed_manifest_shape(&next, self.store_id)?;
        storage_failpoint("apply_before_publish");
        self.publish_manifest_locked(&next, new_segment.as_ref())?;
        Ok(ApplyOutcome::Applied)
    }

    pub fn compact(&self) -> Result<CompactionReport, StorageError> {
        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        self.ensure_no_managed_reservation_locked()?;
        let snapshot = self.load_snapshot_locked()?;
        let current = &snapshot.manifest;
        let old_segments = current
            .segments
            .iter()
            .map(segment_summary)
            .collect::<Vec<_>>();
        let physical_document_count = snapshot
            .segments
            .values()
            .map(|segment| segment.documents.len())
            .sum::<usize>();
        if current.segments.len() <= 1 && physical_document_count == snapshot.documents.len() {
            return Ok(CompactionReport {
                old_generation: current.generation_id,
                new_generation: current.generation_id,
                merged_segments: old_segments.clone(),
                replacement_segments: old_segments,
                removed_paths: Vec::new(),
            });
        }
        storage_failpoint("compaction_before_merge");
        let mut next = next_manifest(current)?;
        next.segments.clear();
        next.live.clear();
        let mut replacement = None;
        if !snapshot.documents.is_empty() {
            let segment_id = next.next_segment_id;
            next.next_segment_id = segment_id
                .checked_add(1)
                .ok_or(StorageError::CapacityExceeded("segment id exhausted"))?;
            let documents = snapshot.documents.values().cloned().collect::<Vec<_>>();
            let segment = Segment::from_documents(segment_id, documents)?;
            for (ordinal, document) in segment.documents.iter().enumerate() {
                next.live.insert(
                    document.id.clone(),
                    manifest::LiveReference {
                        segment_id,
                        ordinal: u32::try_from(ordinal)
                            .map_err(|_| StorageError::CapacityExceeded("segment ordinal"))?,
                        version: decode_version_id(&document.version_id)?,
                    },
                );
            }
            next.segments.push(segment.descriptor.clone());
            replacement = Some(segment);
        }
        if statistics_for_documents(snapshot.documents.values())? != next.statistics {
            return Err(corrupt("compaction changed exact live statistics"));
        }
        validate_proposed_manifest_shape(&next, self.store_id)?;
        storage_failpoint("compaction_merge_complete");
        self.publish_manifest_locked(&next, replacement.as_ref())?;
        let committed = self.load_manifest_locked()?;
        let removed_paths = old_segments
            .iter()
            .filter(|old| !committed.segments.iter().any(|new| new.id == old.id))
            .map(|old| segment_name(old.id))
            .collect();
        let replacement_segments = committed.segments.iter().map(segment_summary).collect();
        Ok(CompactionReport {
            old_generation: current.generation_id,
            new_generation: committed.generation_id,
            merged_segments: old_segments,
            replacement_segments,
            removed_paths,
        })
    }

    pub fn reindex_gate3(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<MigrationReport, StorageError> {
        Self::reindex_gate3_with_publish_hook(source, destination, |_| Ok(()))
    }

    fn reindex_gate3_with_publish_hook(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        before_publish: impl FnOnce(&Path) -> Result<(), StorageError>,
    ) -> Result<MigrationReport, StorageError> {
        let target = resolve_migration_target(source.as_ref(), destination.as_ref())?;
        let source_path = target.source;
        let destination_path = target.destination;
        let parent = target.parent;
        validate_store_directory(&source_path)?;
        let source_store = read_bounded_file(&source_path.join(STORE_NAME), STORE_BYTES)?;
        if source_store.get(..8) != Some(STORE_MAGIC.as_slice()) {
            return Err(StorageError::ReindexRequired(
                "source is not an authentic Gate 3 store".to_owned(),
            ));
        }
        let (store_id, public_gate_required) = decode_store(&source_store)?;
        let source_index = Self {
            path: source_path.clone(),
            store_id,
            writer: Mutex::new(()),
        };
        let _writer = source_index
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _source_lock = source_index.lock_exclusive()?;
        let legacy = source_index.load_committed_locked()?;
        let lease_mac_key = source_index.read_lease_mac_key_locked()?;
        let gate = source_index.load_public_collection_locked()?;
        if public_gate_required != gate.is_some() {
            return Err(corrupt(
                "Gate 3 public collection sidecars are inconsistent",
            ));
        }
        let notice = if gate.is_some() {
            Some(read_bounded_file(
                &source_index.path.join(PUBLIC_NOTICE_STORE_BASENAME),
                MAX_PUBLIC_NOTICE_BYTES,
            )?)
        } else {
            None
        };
        let public_record = if gate.is_some() {
            Some(read_bounded_file(
                &source_index.path.join(PUBLIC_COLLECTION_NAME),
                MAX_PUBLIC_COLLECTION_BYTES,
            )?)
        } else {
            None
        };

        let destination_name = destination_path
            .file_name()
            .ok_or_else(|| {
                StorageError::ReindexRequired("destination must name a directory".to_owned())
            })?
            .to_string_lossy();
        let stage_name = format!(
            ".{destination_name}.ley-reindex-{}-{}",
            std::process::id(),
            system_time_ms()?
        );
        let stage_path = parent.join(stage_name);
        create_store_directory(&stage_path)?;
        let _stage = OwnedStageDirectory(stage_path.clone());
        create_private_file(&stage_path.join(LOCK_NAME), &[])?;
        create_private_file(
            &stage_path.join(STORE_NAME),
            &encode_store_v6(store_id, gate.is_some()),
        )?;
        create_private_file(
            &stage_path.join(LEASE_KEY_NAME),
            &encode_lease_key_v6(store_id, lease_mac_key),
        )?;
        if let (Some(_gate), Some(notice), Some(record)) = (&gate, &notice, &public_record) {
            create_private_file(&stage_path.join(PUBLIC_COLLECTION_NAME), record)?;
            create_private_file(&stage_path.join(PUBLIC_NOTICE_STORE_BASENAME), notice)?;
        }
        sync_directory(&stage_path)?;

        let documents = legacy
            .index
            .documents()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut manifest = Manifest {
            generation_id: legacy.id,
            parent_id: legacy.parent_id,
            next_segment_id: 1,
            format_major: 1,
            format_minor: 0,
            store_id,
            analyzer_id: ANALYZER_ID.to_owned(),
            html_schema_id: HTML_SCHEMA_ID.to_owned(),
            segments: Vec::new(),
            live: BTreeMap::new(),
            controls: controls_to_records(&legacy.controls),
            statistics: statistics_for_documents(legacy.index.documents().values())?,
        };
        let segment = if documents.is_empty() {
            None
        } else {
            let segment_id = manifest.next_segment_id;
            manifest.next_segment_id = segment_id
                .checked_add(1)
                .ok_or(StorageError::CapacityExceeded("segment id exhausted"))?;
            let segment = Segment::from_documents(segment_id, documents)?;
            for (ordinal, document) in segment.documents.iter().enumerate() {
                manifest.live.insert(
                    document.id.clone(),
                    manifest::LiveReference {
                        segment_id,
                        ordinal: u32::try_from(ordinal)
                            .map_err(|_| StorageError::CapacityExceeded("segment ordinal"))?,
                        version: decode_version_id(&document.version_id)?,
                    },
                );
            }
            manifest.segments.push(segment.descriptor.clone());
            Some(segment)
        };
        validate_proposed_manifest_shape(&manifest, store_id)?;
        let destination_store = Self {
            path: fs::canonicalize(&stage_path)?,
            store_id,
            writer: Mutex::new(()),
        };
        {
            let _destination_lock = destination_store.lock_exclusive()?;
            destination_store.publish_manifest_locked(&manifest, segment.as_ref())?;
            let snapshot = destination_store.load_snapshot_locked()?;
            if snapshot.documents.len() != legacy.index.len()
                || snapshot.manifest.controls != manifest.controls
                || snapshot.manifest.statistics != manifest.statistics
            {
                return Err(corrupt(
                    "Gate 3 migration destination failed logical verification",
                ));
            }
        }
        ensure_destination_absent(&destination_path)?;
        before_publish(&destination_path)?;
        rename_directory_noreplace(&stage_path, &destination_path)?;
        sync_directory(&parent)?;
        Ok(MigrationReport {
            source_generation: legacy.id,
            destination_generation: manifest.generation_id,
            document_count: manifest.live.len(),
            destination: destination_path,
        })
    }

    pub(crate) fn install_public_collection_gate(
        &self,
        gate: &PublicCollectionGate,
        notice: &[u8],
        now_ms: u64,
    ) -> Result<(), StorageError> {
        validate_public_collection_admission(gate, notice)?;
        if gate.installed_at_ms > now_ms {
            return Err(StorageError::PublicCollectionConflict);
        }

        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        self.ensure_no_managed_reservation_locked()?;
        self.ensure_not_managed_collection_locked()?;
        let current = self.load_manifest_locked()?;
        if let Some(existing) = self.load_public_collection_locked()? {
            if !existing.same_admission(gate) {
                return Err(StorageError::PublicCollectionConflict);
            }
            if now_ms >= existing.visible_until_ms {
                return Err(StorageError::PublicCollectionExpired);
            }
            let stored_notice = read_bounded_file(
                &self.path.join(PUBLIC_NOTICE_STORE_BASENAME),
                MAX_PUBLIC_NOTICE_BYTES,
            )?;
            if stored_notice != notice {
                return Err(corrupt(
                    "public source notice differs from its admitted copy",
                ));
            }
            self.mark_store_as_public_collection()?;
            return Ok(());
        }
        if current.generation_id != 1 || !current.live.is_empty() || gate.visible_until_ms <= now_ms
        {
            return Err(StorageError::PublicCollectionConflict);
        }

        self.install_public_notice(notice)?;
        let mac_key = self.ensure_lease_mac_key_locked()?;
        let record = encode_public_collection_record(self.store_id, gate, &mac_key)?;
        write_private_file_atomically(
            &self.path.join(PUBLIC_COLLECTION_NAME),
            &self.path.join(".PUBLIC_COLLECTION.tmp"),
            &record,
        )?;
        self.mark_store_as_public_collection()?;
        Ok(())
    }

    pub fn read_view(&self) -> Result<ReadView, StorageError> {
        self.read_view_at(system_time_ms()?)
    }

    pub(crate) fn read_view_at(&self, now_ms: u64) -> Result<ReadView, StorageError> {
        let _lock = self.lock_shared()?;
        let public_visible_until_ms = self
            .load_public_collection_locked()?
            .map(|gate| gate.visible_until_ms);
        if public_visible_until_ms.is_some_and(|deadline| now_ms >= deadline) {
            return Err(StorageError::PublicCollectionExpired);
        }
        let snapshot = self.load_snapshot_locked()?;
        Ok(ReadView {
            snapshot: Arc::new(snapshot),
            public_visible_until_ms,
        })
    }

    pub fn query(&self, expression: &str) -> Result<Vec<SearchResult>, StorageError> {
        self.read_view()?.query(expression)
    }

    /// Retrieve body passages for an explicitly typed ordinary-question request.
    /// The legacy `query(&str)` method remains the advanced Boolean/phrase DSL.
    pub fn retrieve(&self, request: RetrievalRequest) -> Result<RetrievalResponse, RetrievalError> {
        match request {
            RetrievalRequest::Question(question) => self.retrieve_question(question),
        }
    }

    fn retrieve_question(
        &self,
        request: QuestionRequest,
    ) -> Result<RetrievalResponse, RetrievalError> {
        if request.contract_version() != crate::retrieval::RETRIEVAL_CONTRACT_VERSION {
            return Err(RetrievalError::UnsupportedContractVersion(
                request.contract_version(),
            ));
        }
        if !(1..=crate::retrieval::MAX_HITS).contains(&request.max_hits()) {
            return Err(RetrievalError::InvalidHitLimit);
        }
        let plan = plan_question(request.question())?;
        let _lock = self.lock_shared().map_err(map_retrieval_storage_error)?;
        let gate = self
            .load_public_collection_locked()
            .map_err(map_retrieval_storage_error)?;
        let now_ms = system_time_ms().map_err(map_retrieval_storage_error)?;
        ensure_public_collection_current(gate.as_ref(), now_ms)
            .map_err(map_retrieval_storage_error)?;
        let manifest = self
            .load_manifest_locked()
            .map_err(map_retrieval_storage_error)?;
        let seed = question_sample_seed(self.store_id, &plan);
        let mut partial = false;

        let mut response_hits = Vec::new();
        let mut title_only_match = false;
        if plan.term_alternatives.is_empty() && plan.phrase_groups.is_empty() {
            let response = RetrievalResponse {
                contract_version: crate::retrieval::RETRIEVAL_CONTRACT_VERSION,
                mode: RetrievalMode::Question,
                generation_id: manifest.generation_id,
                status: RetrievalStatus::InsufficientEvidence(
                    InsufficientEvidenceReason::NoSearchableTerms,
                ),
                completeness: RetrievalCompleteness::Complete,
                normalized_terms: plan.normalized_terms.clone(),
                hits: Vec::new(),
                answer_assessment: AnswerAssessment::NotAssessed,
            };
            ensure_response_bound(&response)?;
            self.check_retrieval_expiry(gate.as_ref())?;
            return Ok(response);
        }

        let (descriptors, skipped_segments) = select_question_segments(&manifest.segments, &seed)
            .map_err(map_retrieval_storage_error)?;
        partial |= skipped_segments;

        let mut segments = Vec::with_capacity(descriptors.len());
        for descriptor in &descriptors {
            let path = self.path.join(segment_name(descriptor.id));
            let bytes = match read_bounded_file(&path, MAX_SEGMENT_BYTES) {
                Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(RetrievalError::CorruptStorage);
                }
                result => result.map_err(map_retrieval_storage_error)?,
            };
            let segment =
                Segment::from_bytes(descriptor, &bytes).map_err(map_retrieval_storage_error)?;
            segments.push((descriptor.id, segment));
        }

        let mut sampled_by_segment = vec![BTreeSet::<u32>::new(); segments.len()];
        let mut posting_probes = 0usize;
        for (segment_index, (segment_id, segment)) in segments.iter().enumerate() {
            for term in &plan.candidate_terms {
                let Some(records) = segment.postings.get(term) else {
                    continue;
                };
                if posting_probes >= MAX_QUESTION_POSTING_PROBES {
                    partial = true;
                    break;
                }
                let term_seed = sample_term_seed(&seed, term, *segment_id);
                let probe_budget = MAX_QUESTION_POSTING_PROBES - posting_probes;
                let (ordinals, probes) = sample_question_postings(
                    records,
                    segment.documents.len(),
                    &term_seed,
                    probe_budget,
                );
                posting_probes = posting_probes.saturating_add(probes);
                if ordinals.len() < records.len() {
                    partial = true;
                }
                for ordinal in ordinals {
                    let Some(document) = segment.documents.get(ordinal as usize) else {
                        return Err(RetrievalError::CorruptStorage);
                    };
                    let current =
                        manifest_document_is_live(&manifest, document, *segment_id, ordinal)
                            .map_err(map_retrieval_storage_error)?;
                    if current {
                        sampled_by_segment[segment_index].insert(ordinal);
                    }
                }
            }
        }

        let mut admitted_by_segment = Vec::<Vec<u32>>::with_capacity(segments.len());
        if !segments.is_empty() {
            let quota = MAX_QUESTION_CANDIDATES.div_ceil(segments.len()).max(1);
            for (segment_index, (segment_id, _segment)) in segments.iter().enumerate() {
                let mut ordinals = sampled_by_segment[segment_index]
                    .iter()
                    .copied()
                    .collect::<Vec<_>>();
                if ordinals.len() > quota {
                    partial = true;
                    ordinals
                        .sort_by_key(|ordinal| sample_ordinal_key(&seed, *segment_id, *ordinal));
                    ordinals.truncate(quota);
                    ordinals.sort_unstable();
                }
                admitted_by_segment.push(ordinals);
            }
        }

        let mut locations = Vec::<(usize, u32)>::new();
        let max_depth = admitted_by_segment.iter().map(Vec::len).max().unwrap_or(0);
        'round_robin: for depth in 0..max_depth {
            for (segment_index, ordinals) in admitted_by_segment.iter().enumerate() {
                if let Some(ordinal) = ordinals.get(depth) {
                    if locations.len() == MAX_QUESTION_CANDIDATES {
                        partial = true;
                        break 'round_robin;
                    }
                    locations.push((segment_index, *ordinal));
                }
            }
        }

        let mut ranked = Vec::with_capacity(locations.len());
        for (segment_index, ordinal) in locations {
            let (_, segment) = &segments[segment_index];
            let document = segment
                .documents
                .get(ordinal as usize)
                .ok_or(RetrievalError::CorruptStorage)?;
            let score = question_bm25_score(segment, ordinal, &plan, &manifest.statistics);
            if !score.is_finite() {
                return Err(RetrievalError::CorruptStorage);
            }
            let title_match = document
                .title_terms
                .iter()
                .any(|term| plan.scoring_terms.binary_search(term).is_ok());
            ranked.push(QuestionCandidate {
                segment_index,
                ordinal,
                score,
                title_match,
            });
        }
        ranked.sort_by(|left, right| {
            right.score.total_cmp(&left.score).then_with(|| {
                let left_id = &segments[left.segment_index].1.documents[left.ordinal as usize].id;
                let right_id =
                    &segments[right.segment_index].1.documents[right.ordinal as usize].id;
                left_id.as_bytes().cmp(right_id.as_bytes())
            })
        });
        if ranked.len() > MAX_QUESTION_PASSAGE_DOCUMENTS {
            partial = true;
        }

        let mut scanned_body_bytes = 0usize;
        let mut scanned_window_bytes = 0usize;
        let mut phrase_steps = 0usize;
        for candidate in ranked.iter().take(MAX_QUESTION_PASSAGE_DOCUMENTS) {
            let segment = &segments[candidate.segment_index].1;
            let document = segment
                .documents
                .get(candidate.ordinal as usize)
                .ok_or(RetrievalError::CorruptStorage)?;
            if scanned_body_bytes
                .checked_add(document.body.len())
                .is_none_or(|total| total > MAX_QUESTION_PASSAGE_BODY_BYTES)
            {
                partial = true;
                break;
            }
            scanned_body_bytes += document.body.len();
            let windows = passage_windows(&document.body)?;
            let mut best: Option<(u32, usize, usize, crate::retrieval::PassageMatch)> = None;
            for window in windows {
                let byte_len = window.end_byte - window.start_byte;
                if scanned_window_bytes
                    .checked_add(byte_len)
                    .is_none_or(|total| total > MAX_QUESTION_PASSAGE_WINDOW_BYTES)
                {
                    partial = true;
                    break;
                }
                scanned_window_bytes += byte_len;
                let text = document
                    .body
                    .get(window.start_byte..window.end_byte)
                    .ok_or(RetrievalError::InvalidRange)?;
                let terms = Analyzer
                    .analyze(text)
                    .map_err(|_| RetrievalError::CorruptStorage)?;
                let (matched, phrase_budget_reached) =
                    match_passage_text_bounded(&terms, text, &plan, &mut phrase_steps);
                if phrase_budget_reached {
                    partial = true;
                }
                let Some(matched) = matched else {
                    continue;
                };
                let replace = best.as_ref().is_none_or(|(best_score, best_start, _, _)| {
                    matched.score > *best_score
                        || (matched.score == *best_score && window.start_byte < *best_start)
                });
                if replace {
                    best = Some((matched.score, window.start_byte, window.end_byte, matched));
                }
            }
            if let Some((_, start_byte, end_byte, matched)) = best {
                let content_version =
                    decode_version_id(&document.version_id).map_err(map_retrieval_storage_error)?;
                let reference = EvidenceReference::new(
                    self.store_id,
                    document.id.clone(),
                    content_version,
                    start_byte,
                    end_byte,
                )?;
                response_hits.push(EvidenceHit {
                    requested_url: document.id.clone(),
                    effective_url: document.effective_url.clone(),
                    title: document.title.clone(),
                    score: candidate.score,
                    matched_terms: matched.terms,
                    matched_phrases: matched.phrases,
                    passage: EvidencePassage {
                        reference,
                        text: document
                            .body
                            .get(start_byte..end_byte)
                            .ok_or(RetrievalError::InvalidRange)?
                            .to_owned(),
                    },
                });
            } else if candidate.title_match {
                title_only_match = true;
            }
        }

        response_hits.sort_by(|left, right| {
            right.score.total_cmp(&left.score).then_with(|| {
                left.requested_url
                    .as_bytes()
                    .cmp(right.requested_url.as_bytes())
            })
        });
        let max_hits = usize::from(request.max_hits());
        response_hits.truncate(max_hits);
        let response_passage_bytes = response_hits.iter().try_fold(0usize, |total, hit| {
            total.checked_add(hit.passage.text.len())
        });
        if response_passage_bytes.is_none_or(|size| size > MAX_RESPONSE_PASSAGE_BYTES) {
            return Err(RetrievalError::ResponseTooLarge);
        }

        let status = if !response_hits.is_empty() {
            RetrievalStatus::RetrievedText
        } else if partial {
            RetrievalStatus::InsufficientEvidence(InsufficientEvidenceReason::WorkBudgetReached)
        } else if title_only_match {
            RetrievalStatus::InsufficientEvidence(InsufficientEvidenceReason::OnlyTitleMatches)
        } else {
            RetrievalStatus::NoRelevantTextMatch
        };
        let response = RetrievalResponse {
            contract_version: crate::retrieval::RETRIEVAL_CONTRACT_VERSION,
            mode: RetrievalMode::Question,
            generation_id: manifest.generation_id,
            status,
            completeness: if partial {
                RetrievalCompleteness::Partial
            } else {
                RetrievalCompleteness::Complete
            },
            normalized_terms: plan.normalized_terms,
            hits: response_hits,
            answer_assessment: AnswerAssessment::NotAssessed,
        };
        ensure_response_bound(&response)?;
        self.check_retrieval_expiry(gate.as_ref())?;
        Ok(response)
    }

    fn check_retrieval_expiry(
        &self,
        initial_gate: Option<&PublicCollectionGate>,
    ) -> Result<(), RetrievalError> {
        let current_gate = self
            .load_public_collection_locked()
            .map_err(map_retrieval_storage_error)?;
        let now_ms = system_time_ms().map_err(map_retrieval_storage_error)?;
        if initial_gate.is_some_and(|gate| now_ms >= gate.visible_until_ms) {
            return Err(RetrievalError::PublicCollectionExpired);
        }
        ensure_public_collection_current(current_gate.as_ref(), now_ms)
            .map_err(map_retrieval_storage_error)
    }

    /// Resolve an evidence reference against the current authenticated store state.
    /// A pinned `ReadView` is never accepted as authority for this operation.
    pub fn resolve_evidence(
        &self,
        reference: &EvidenceReference,
    ) -> Result<ResolvedEvidence, EvidenceResolveError> {
        self.resolve_evidence_with_clock(reference, system_time_ms)
    }

    fn resolve_evidence_with_clock(
        &self,
        reference: &EvidenceReference,
        mut clock: impl FnMut() -> Result<u64, StorageError>,
    ) -> Result<ResolvedEvidence, EvidenceResolveError> {
        self.with_current_evidence_document(reference, &mut clock, |document| {
            let start = usize::try_from(reference.start_byte)
                .map_err(|_| EvidenceResolveError::OutOfBounds)?;
            let end = usize::try_from(reference.end_byte)
                .map_err(|_| EvidenceResolveError::OutOfBounds)?;
            if end > document.body.len() || start > end {
                return Err(EvidenceResolveError::OutOfBounds);
            }
            if !document.body.is_char_boundary(start) || !document.body.is_char_boundary(end) {
                return Err(EvidenceResolveError::NotUtf8Boundary);
            }
            let text = document
                .body
                .get(start..end)
                .ok_or(EvidenceResolveError::OutOfBounds)?
                .to_owned();
            Ok(ResolvedEvidence {
                reference: reference.clone(),
                requested_url: document.id.clone(),
                effective_url: document.effective_url.clone(),
                title: document.title.clone(),
                text,
            })
        })
    }

    pub(crate) fn inspect_document_page(
        &self,
        reference: &EvidenceReference,
        offset_byte: u32,
    ) -> Result<DocumentInspectionPage, EvidenceResolveError> {
        self.inspect_document_page_with_clock(reference, offset_byte, system_time_ms)
    }

    fn inspect_document_page_with_clock(
        &self,
        reference: &EvidenceReference,
        offset_byte: u32,
        mut clock: impl FnMut() -> Result<u64, StorageError>,
    ) -> Result<DocumentInspectionPage, EvidenceResolveError> {
        self.with_current_evidence_document(reference, &mut clock, |document| {
            let start =
                usize::try_from(offset_byte).map_err(|_| EvidenceResolveError::OutOfBounds)?;
            if start >= document.body.len() {
                return Err(EvidenceResolveError::OutOfBounds);
            }
            if !document.body.is_char_boundary(start) {
                return Err(EvidenceResolveError::NotUtf8Boundary);
            }

            let total_bytes = u32::try_from(document.body.len())
                .map_err(|_| EvidenceResolveError::ResourceLimit)?;
            let mut end = start
                .saturating_add(DOCUMENT_INSPECTION_PAGE_BYTES)
                .min(document.body.len());
            while !document.body.is_char_boundary(end) {
                end -= 1;
            }
            let start_byte = u32::try_from(start).map_err(|_| EvidenceResolveError::OutOfBounds)?;
            let end_byte = u32::try_from(end).map_err(|_| EvidenceResolveError::OutOfBounds)?;
            let text = document
                .body
                .get(start..end)
                .ok_or(EvidenceResolveError::OutOfBounds)?
                .to_owned();
            Ok(DocumentInspectionPage {
                contract_version: DOCUMENT_INSPECTION_CONTRACT_VERSION,
                reference: reference.clone(),
                requested_url: document.id.clone(),
                effective_url: document.effective_url.clone(),
                title: document.title.clone(),
                start_byte,
                end_byte,
                total_bytes,
                next_offset_byte: (end < document.body.len()).then_some(end_byte),
                text,
            })
        })
    }

    fn with_current_evidence_document<T>(
        &self,
        reference: &EvidenceReference,
        mut clock: impl FnMut() -> Result<u64, StorageError>,
        operation: impl FnOnce(&IndexedDocument) -> Result<T, EvidenceResolveError>,
    ) -> Result<T, EvidenceResolveError> {
        reference.validate_shape_and_identity()?;
        if reference.store_id != self.store_id {
            return Err(EvidenceResolveError::WrongStore);
        }
        if u64::from(reference.end_byte - reference.start_byte) > MAX_PASSAGE_BYTES as u64 {
            return Err(EvidenceResolveError::InvalidPassageWindow);
        }
        let _lock = self.lock_shared().map_err(map_evidence_storage_error)?;
        let gate = self
            .load_public_collection_locked()
            .map_err(map_evidence_storage_error)?;
        let now_ms = clock().map_err(map_evidence_storage_error)?;
        if gate
            .as_ref()
            .is_some_and(|value| now_ms >= value.visible_until_ms)
        {
            return Err(EvidenceResolveError::PublicCollectionExpired);
        }
        let manifest = self
            .load_manifest_locked()
            .map_err(map_evidence_storage_error)?;
        let key = reference.requested_url.as_str();
        if manifest.controls.get(key).is_some_and(manifest_is_revoked) {
            return Err(EvidenceResolveError::Revoked);
        }
        let Some(live) = manifest.live.get(key) else {
            return Err(EvidenceResolveError::NotLive);
        };
        if live.version != reference.content_version {
            return Err(EvidenceResolveError::VersionSuperseded);
        }
        let descriptor = manifest
            .segments
            .iter()
            .find(|descriptor| descriptor.id == live.segment_id)
            .ok_or(EvidenceResolveError::CorruptStorage)?;
        let estimate =
            segment_memory_estimate(descriptor).ok_or(EvidenceResolveError::CorruptStorage)?;
        if estimate > MAX_SNAPSHOT_ESTIMATE_BYTES {
            return Err(EvidenceResolveError::ResourceLimit);
        }
        let path = self.path.join(segment_name(descriptor.id));
        let bytes = match read_bounded_file(&path, MAX_SEGMENT_BYTES) {
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(EvidenceResolveError::CorruptStorage);
            }
            result => result.map_err(map_evidence_storage_error)?,
        };
        let segment =
            Segment::from_bytes(descriptor, &bytes).map_err(map_evidence_storage_error)?;
        let document = segment
            .documents
            .get(live.ordinal as usize)
            .ok_or(EvidenceResolveError::CorruptStorage)?;
        if document.id != reference.requested_url
            || decode_version_id(&document.version_id).map_err(map_evidence_storage_error)?
                != reference.content_version
        {
            return Err(EvidenceResolveError::CorruptStorage);
        }
        if !manifest_document_is_live(&manifest, document, live.segment_id, live.ordinal)
            .map_err(map_evidence_storage_error)?
        {
            return Err(EvidenceResolveError::NotLive);
        }
        let start =
            usize::try_from(reference.start_byte).map_err(|_| EvidenceResolveError::OutOfBounds)?;
        let end =
            usize::try_from(reference.end_byte).map_err(|_| EvidenceResolveError::OutOfBounds)?;
        if end > document.body.len() || start > end {
            return Err(EvidenceResolveError::OutOfBounds);
        }
        if !document.body.is_char_boundary(start) || !document.body.is_char_boundary(end) {
            return Err(EvidenceResolveError::NotUtf8Boundary);
        }
        let windows = passage_windows(&document.body).map_err(|error| match error {
            RetrievalError::ResourceLimit => EvidenceResolveError::ResourceLimit,
            _ => EvidenceResolveError::CorruptStorage,
        })?;
        if !windows
            .iter()
            .any(|window| window.start_byte == start && window.end_byte == end)
        {
            return Err(EvidenceResolveError::InvalidPassageWindow);
        }
        let result = operation(document)?;
        let final_gate = self
            .load_public_collection_locked()
            .map_err(map_evidence_storage_error)?;
        let final_now_ms = clock().map_err(map_evidence_storage_error)?;
        if final_gate
            .as_ref()
            .is_some_and(|value| final_now_ms >= value.visible_until_ms)
        {
            return Err(EvidenceResolveError::PublicCollectionExpired);
        }
        Ok(result)
    }

    fn load_committed_locked(&self) -> Result<Generation, StorageError> {
        let current_path = self.path.join(CURRENT_NAME);
        match fs::symlink_metadata(&current_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::IncompleteInitialStore);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let current_bytes = read_bounded_file(&current_path, CURRENT_BYTES)?;
        let (generation_id, generation_length, generation_hash) =
            decode_current(&current_bytes, self.store_id)?;
        let generation_path = self.path.join(generation_name(generation_id));
        let bytes = match read_bounded_file(&generation_path, MAX_GENERATION_BYTES) {
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(corrupt("CURRENT references a missing generation file"));
            }
            result => result?,
        };
        if bytes.len() as u64 != generation_length || sha256(&bytes) != generation_hash {
            return Err(corrupt("CURRENT generation length or checksum mismatch"));
        }
        let generation = decode_generation(&bytes, self.store_id, generation_id)?;
        Ok(generation)
    }

    fn load_manifest_locked(&self) -> Result<Manifest, StorageError> {
        let current_path = self.path.join(CURRENT_NAME);
        match fs::symlink_metadata(&current_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::IncompleteInitialStore);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let pointer_bytes = read_bounded_file(&current_path, CURRENT_BYTES)?;
        let pointer = CurrentPointer::decode(&pointer_bytes, self.store_id)?;
        let manifest_path = self.path.join(manifest_name(pointer.generation_id));
        let manifest_bytes = match read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES) {
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(corrupt("CURRENT references a missing manifest"));
            }
            result => result?,
        };
        if manifest_bytes.len() as u64 != pointer.manifest_len
            || sha256(&manifest_bytes) != pointer.manifest_sha256
        {
            return Err(corrupt("CURRENT manifest length or checksum mismatch"));
        }
        let manifest = Manifest::decode(&manifest_bytes, self.store_id, pointer.generation_id)?;
        validate_manifest_shape(&manifest, self.store_id)?;
        Ok(manifest)
    }

    fn load_snapshot_locked(&self) -> Result<SegmentedSnapshot, StorageError> {
        let pointer_bytes = read_bounded_file(&self.path.join(CURRENT_NAME), CURRENT_BYTES)?;
        let pointer = CurrentPointer::decode(&pointer_bytes, self.store_id)?;
        let manifest = self.load_manifest_locked()?;
        let estimate = snapshot_memory_estimate(&manifest, pointer.manifest_len)?;
        if estimate > MAX_SNAPSHOT_ESTIMATE_BYTES {
            return Err(StorageError::CapacityExceeded(
                "decoded snapshot memory estimate",
            ));
        }
        let mut segments = BTreeMap::new();
        for descriptor in &manifest.segments {
            let path = self.path.join(segment_name(descriptor.id));
            let bytes = match read_bounded_file(&path, MAX_SEGMENT_BYTES) {
                Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(corrupt("manifest references a missing segment"));
                }
                result => result?,
            };
            let segment = Segment::from_bytes(descriptor, &bytes)?;
            if segments.insert(descriptor.id, Arc::new(segment)).is_some() {
                return Err(corrupt("manifest contains a duplicate segment id"));
            }
        }
        let mut documents = BTreeMap::new();
        for (key, reference) in &manifest.live {
            let segment = segments
                .get(&reference.segment_id)
                .ok_or_else(|| corrupt("live document references an absent segment"))?;
            let document = segment
                .documents
                .get(reference.ordinal as usize)
                .ok_or_else(|| corrupt("live document ordinal is outside its segment"))?;
            if document.id != *key || decode_version_id(&document.version_id)? != reference.version
            {
                return Err(corrupt(
                    "live document reference differs from its segment record",
                ));
            }
            documents.insert(key.clone(), document.clone());
        }
        validate_live_control_records(&documents, &manifest.controls)?;
        let actual_statistics = statistics_for_documents(documents.values())?;
        if actual_statistics != manifest.statistics {
            return Err(corrupt(
                "manifest live statistics differ from visible documents",
            ));
        }
        Ok(SegmentedSnapshot {
            manifest,
            segments,
            documents,
        })
    }

    fn publish_manifest_locked(
        &self,
        manifest: &Manifest,
        new_segment: Option<&Segment>,
    ) -> Result<(), StorageError> {
        validate_proposed_manifest_shape(manifest, self.store_id)?;
        let current = match self.load_manifest_locked() {
            Ok(value) => Some(value),
            Err(StorageError::IncompleteInitialStore) => None,
            Err(error) => return Err(error),
        };
        if let Some(current) = &current {
            let expected_generation =
                current
                    .generation_id
                    .checked_add(1)
                    .ok_or(StorageError::CapacityExceeded(
                        "manifest generation id exhausted",
                    ))?;
            if manifest.parent_id != current.generation_id
                || manifest.generation_id != expected_generation
            {
                return Err(corrupt("manifest does not extend the current generation"));
            }
        }
        cleanup_gate6_orphans(&self.path, current.as_ref())?;

        if let Some(segment) = new_segment {
            let descriptor = manifest
                .segments
                .iter()
                .find(|descriptor| descriptor.id == segment.id)
                .ok_or_else(|| corrupt("new segment is absent from next manifest"))?;
            if descriptor != &segment.descriptor {
                return Err(corrupt("new segment descriptor differs from next manifest"));
            }
            let bytes = segment.encode()?;
            let _ = Segment::from_bytes(descriptor, &bytes)?;
            let temporary = self.path.join(segment_temp_name(segment.id));
            let ready = self.path.join(segment_name(segment.id));
            let mut file = create_private_file_handle(&temporary)?;
            let split = bytes.len() / 2;
            file.write_all(&bytes[..split])?;
            storage_failpoint("segment_write_half");
            file.write_all(&bytes[split..])?;
            file.flush()?;
            storage_failpoint("segment_write_complete");
            let staged = read_bounded_file(&temporary, MAX_SEGMENT_BYTES)?;
            let _ = Segment::from_bytes(descriptor, &staged)?;
            storage_failpoint("segment_validate");
            file.sync_all()?;
            storage_failpoint("segment_sync");
            drop(file);
            fs::rename(&temporary, &ready)?;
            storage_failpoint("segment_rename");
            sync_directory(&self.path)?;
            storage_failpoint("segment_directory_sync");
        }

        let bytes = manifest.encode()?;
        let checked = Manifest::decode(&bytes, self.store_id, manifest.generation_id)?;
        validate_proposed_manifest_shape(&checked, self.store_id)?;
        let temporary = self.path.join(manifest_temp_name(manifest.generation_id));
        let ready = self.path.join(manifest_name(manifest.generation_id));
        let mut file = create_private_file_handle(&temporary)?;
        let split = bytes.len() / 2;
        file.write_all(&bytes[..split])?;
        storage_failpoint("manifest_write_half");
        file.write_all(&bytes[split..])?;
        file.flush()?;
        storage_failpoint("manifest_write_complete");
        let staged = read_bounded_file(&temporary, MAX_MANIFEST_BYTES)?;
        let _ = Manifest::decode(&staged, self.store_id, manifest.generation_id)?;
        storage_failpoint("manifest_validate");
        file.sync_all()?;
        storage_failpoint("manifest_sync");
        drop(file);
        fs::rename(&temporary, &ready)?;
        storage_failpoint("manifest_rename");
        sync_directory(&self.path)?;
        storage_failpoint("manifest_directory_sync");

        let pointer = CurrentPointer {
            store_id: self.store_id,
            generation_id: manifest.generation_id,
            manifest_len: bytes.len() as u64,
            manifest_sha256: sha256(&bytes),
        };
        let pointer_bytes = pointer.encode();
        let temporary = self.path.join(".CURRENT.v6.tmp");
        let mut pointer_file = create_private_file_handle(&temporary)?;
        pointer_file.write_all(&pointer_bytes)?;
        pointer_file.flush()?;
        storage_failpoint("current_write_complete");
        let staged = read_bounded_file(&temporary, CURRENT_BYTES)?;
        let _ = CurrentPointer::decode(&staged, self.store_id)?;
        if staged != pointer_bytes {
            return Err(corrupt(
                "staged Gate 6 CURRENT differs from encoded pointer",
            ));
        }
        pointer_file.sync_all()?;
        storage_failpoint("current_sync");
        drop(pointer_file);
        fs::rename(&temporary, self.path.join(CURRENT_NAME))?;
        storage_failpoint("pointer_rename");
        sync_directory(&self.path)?;
        storage_failpoint("directory_sync");

        let committed = self.load_manifest_locked()?;
        if committed.generation_id != manifest.generation_id {
            return Err(corrupt("reopened manifest differs from publication"));
        }
        cleanup_gate6_orphans(&self.path, Some(&committed))?;
        Ok(())
    }

    #[cfg(test)]
    fn publish_locked(
        &self,
        generation: &Generation,
        current: Option<&Generation>,
    ) -> Result<(), StorageError> {
        cleanup_owned_files(&self.path, current)?;
        let bytes = encode_generation(generation, self.store_id)?;

        let temporary_path = self.path.join(generation_temp_name(generation.id));
        let ready_path = self.path.join(generation_name(generation.id));
        let mut file = create_private_file_handle(&temporary_path)?;
        let split = bytes.len() / 2;
        file.write_all(&bytes[..split])?;
        storage_failpoint("generation_write_half");
        file.write_all(&bytes[split..])?;
        file.flush()?;
        storage_failpoint("generation_write_complete");
        let temp_bytes = read_bounded_file(&temporary_path, MAX_GENERATION_BYTES)?;
        let validated = decode_generation(&temp_bytes, self.store_id, generation.id)?;
        if validated.parent_id != generation.parent_id {
            return Err(corrupt("writer validation changed the parent generation"));
        }
        storage_failpoint("generation_validate");
        file.sync_all()?;
        storage_failpoint("generation_sync");
        drop(file);
        fs::rename(&temporary_path, &ready_path)?;
        sync_directory(&self.path)?;
        storage_failpoint("generation_ready");

        let pointer = encode_current(
            self.store_id,
            generation.id,
            bytes.len() as u64,
            sha256(&bytes),
        );
        let pointer_temp_path = self.path.join(".CURRENT.tmp");
        let mut pointer_file = create_private_file_handle(&pointer_temp_path)?;
        pointer_file.write_all(&pointer)?;
        pointer_file.flush()?;
        let staged_pointer = read_bounded_file(&pointer_temp_path, CURRENT_BYTES)?;
        let _ = decode_current(&staged_pointer, self.store_id)?;
        if staged_pointer != pointer {
            return Err(corrupt("staged CURRENT differs from encoded pointer"));
        }
        pointer_file.sync_all()?;
        storage_failpoint("current_sync");
        drop(pointer_file);
        fs::rename(&pointer_temp_path, self.path.join(CURRENT_NAME))?;
        storage_failpoint("pointer_rename");
        sync_directory(&self.path)?;
        storage_failpoint("directory_sync");
        let committed = self.load_committed_locked()?;
        if committed.id != generation.id {
            return Err(corrupt("reopened generation differs from publication"));
        }
        Ok(())
    }

    fn lock_shared(&self) -> Result<FileLock, StorageError> {
        FileLock::new(&self.path.join(LOCK_NAME), false)
    }

    fn lock_exclusive(&self) -> Result<FileLock, StorageError> {
        FileLock::new(&self.path.join(LOCK_NAME), true)
    }

    fn read_lease_mac_key_locked(&self) -> Result<LeaseMacKey, StorageError> {
        let bytes = match read_bounded_file(&self.path.join(LEASE_KEY_NAME), LEASE_KEY_BYTES) {
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::InvalidLease);
            }
            result => result?,
        };
        decode_lease_key(&bytes, self.store_id)
    }

    fn load_public_collection_locked(&self) -> Result<Option<PublicCollectionGate>, StorageError> {
        let store_bytes = read_bounded_file(&self.path.join(STORE_NAME), STORE_BYTES)?;
        let (store_id, requires_public_gate) = decode_store(&store_bytes)?;
        if store_id != self.store_id {
            return Err(corrupt("STORE identity changed while open"));
        }
        let path = self.path.join(PUBLIC_COLLECTION_NAME);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if requires_public_gate {
                    return Err(corrupt("public collection metadata is missing"));
                }
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(corrupt("public collection metadata is not a regular file"));
            }
            Ok(_) => {}
        }
        let bytes = read_bounded_file(&path, MAX_PUBLIC_COLLECTION_BYTES)?;
        let mac_key = self.read_lease_mac_key_locked()?;
        let gate = decode_public_collection_record(&bytes, self.store_id, &mac_key)?;
        let notice = read_bounded_file(
            &self.path.join(PUBLIC_NOTICE_STORE_BASENAME),
            MAX_PUBLIC_NOTICE_BYTES,
        )?;
        if !valid_public_notice(&notice) || sha256(&notice) != decode_sha256(&gate.notice_sha256)? {
            return Err(corrupt("public source notice checksum mismatch"));
        }
        Ok(Some(gate))
    }

    fn mark_store_as_public_collection(&self) -> Result<(), StorageError> {
        let path = self.path.join(STORE_NAME);
        let store_bytes = read_bounded_file(&path, STORE_BYTES)?;
        let (store_id, requires_public_gate) = decode_store(&store_bytes)?;
        if store_id != self.store_id {
            return Err(corrupt("STORE identity changed while open"));
        }
        if !requires_public_gate {
            write_private_file_atomically(
                &path,
                &self.path.join(".STORE.tmp"),
                &encode_store_v6(self.store_id, true),
            )?;
        }
        Ok(())
    }

    fn install_public_notice(&self, notice: &[u8]) -> Result<(), StorageError> {
        let path = self.path.join(PUBLIC_NOTICE_STORE_BASENAME);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if read_bounded_file(&path, MAX_PUBLIC_NOTICE_BYTES)? != notice {
                    return Err(StorageError::PublicCollectionConflict);
                }
                Ok(())
            }
            Ok(_) => Err(corrupt("public source notice path is not a regular file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => write_private_file_atomically(
                &path,
                &self.path.join(".rust-stdlib-documentation-MIT.txt.tmp"),
                notice,
            ),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_lease_mac_key_locked(&self) -> Result<LeaseMacKey, StorageError> {
        let path = self.path.join(LEASE_KEY_NAME);
        match read_bounded_file(&path, LEASE_KEY_BYTES) {
            Ok(bytes) => decode_lease_key(&bytes, self.store_id),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                let mac_key = random_lease_mac_key()?;
                create_private_file(&path, &encode_lease_key_v6(self.store_id, mac_key))?;
                sync_directory(&self.path)?;
                Ok(mac_key)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy)]
struct QuestionCandidate {
    segment_index: usize,
    ordinal: u32,
    score: f64,
    title_match: bool,
}

fn map_retrieval_storage_error(error: StorageError) -> RetrievalError {
    match error {
        StorageError::PublicCollectionExpired => RetrievalError::PublicCollectionExpired,
        StorageError::CapacityExceeded(_) => RetrievalError::ResourceLimit,
        StorageError::CorruptCommitted(_)
        | StorageError::Query(_)
        | StorageError::UnsupportedFormat { .. }
        | StorageError::ReindexRequired(_) => RetrievalError::CorruptStorage,
        StorageError::Io(_) => RetrievalError::StorageUnavailable,
        _ => RetrievalError::StorageUnavailable,
    }
}

fn map_evidence_storage_error(error: StorageError) -> EvidenceResolveError {
    match error {
        StorageError::PublicCollectionExpired => EvidenceResolveError::PublicCollectionExpired,
        StorageError::CapacityExceeded(_) => EvidenceResolveError::ResourceLimit,
        StorageError::CorruptCommitted(_)
        | StorageError::Query(_)
        | StorageError::UnsupportedFormat { .. }
        | StorageError::ReindexRequired(_) => EvidenceResolveError::CorruptStorage,
        StorageError::Io(_) => EvidenceResolveError::StorageUnavailable,
        _ => EvidenceResolveError::StorageUnavailable,
    }
}

fn ensure_public_collection_current(
    gate: Option<&PublicCollectionGate>,
    now_ms: u64,
) -> Result<(), StorageError> {
    if gate.is_some_and(|value| now_ms >= value.visible_until_ms) {
        return Err(StorageError::PublicCollectionExpired);
    }
    Ok(())
}

fn manifest_document_is_live(
    manifest: &Manifest,
    document: &crate::index::IndexedDocument,
    segment_id: u64,
    ordinal: u32,
) -> Result<bool, StorageError> {
    let Some(live) = manifest.live.get(&document.id) else {
        return Ok(false);
    };
    if live.segment_id != segment_id || live.ordinal != ordinal {
        return Ok(false);
    }
    let document_version = decode_version_id(&document.version_id)?;
    if document_version != live.version {
        return Err(corrupt(
            "live manifest version differs from sampled document",
        ));
    }
    let control = manifest
        .controls
        .get(&document.id)
        .ok_or_else(|| corrupt("live sampled document has no lifecycle control"))?;
    if manifest_is_revoked(control)
        || control
            .terminal
            .last_key_value()
            .map(|(_, terminal)| *terminal)
            != Some(TerminalRecord::Upsert(document_version))
    {
        return Err(corrupt(
            "live sampled document differs from current lifecycle controls",
        ));
    }
    Ok(true)
}

fn ensure_response_bound(response: &RetrievalResponse) -> Result<(), RetrievalError> {
    let bytes = serde_json::to_vec(response).map_err(|_| RetrievalError::CorruptStorage)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(RetrievalError::ResponseTooLarge);
    }
    Ok(())
}

fn question_sample_seed(store_id: StoreId, plan: &QuestionPlan) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ley-question-sampling-v1\0");
    digest.update(store_id);
    for term in &plan.normalized_terms {
        digest.update((term.len() as u64).to_be_bytes());
        digest.update(term.as_bytes());
    }
    digest.finalize().into()
}

fn sample_term_seed(seed: &[u8; 32], term: &str, segment_id: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ley-question-term-sample-v1\0");
    digest.update(seed);
    digest.update(segment_id.to_be_bytes());
    digest.update((term.len() as u64).to_be_bytes());
    digest.update(term.as_bytes());
    digest.finalize().into()
}

fn sample_ordinal_key(seed: &[u8; 32], segment_id: u64, ordinal: u32) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ley-question-candidate-sample-v1\0");
    digest.update(seed);
    digest.update(segment_id.to_be_bytes());
    digest.update(ordinal.to_be_bytes());
    digest.finalize().into()
}

fn select_question_segments(
    descriptors: &[SegmentDescriptor],
    seed: &[u8; 32],
) -> Result<(Vec<SegmentDescriptor>, bool), StorageError> {
    let mut ordered = descriptors.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        sample_segment_key(seed, left.id)
            .cmp(&sample_segment_key(seed, right.id))
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut selected = Vec::new();
    let mut selected_bytes = 0u64;
    let mut selected_estimate = 0u64;
    let mut skipped = descriptors.len() > MAX_QUESTION_SEGMENT_PROBES;
    for descriptor in ordered {
        if selected.len() == MAX_QUESTION_SEGMENT_PROBES {
            skipped = true;
            break;
        }
        let Some(estimate) = segment_memory_estimate(descriptor) else {
            return Err(corrupt("segment memory estimate overflow"));
        };
        let Some(next_bytes) = selected_bytes.checked_add(descriptor.byte_len) else {
            return Err(corrupt("question segment byte bound overflow"));
        };
        let Some(next_estimate) = selected_estimate.checked_add(estimate) else {
            return Err(corrupt("question segment memory estimate overflow"));
        };
        if descriptor.byte_len > MAX_QUESTION_SEGMENT_BYTES
            || estimate > MAX_QUESTION_SEGMENT_MEMORY_ESTIMATE
            || next_bytes > MAX_QUESTION_SEGMENT_BYTES
            || next_estimate > MAX_QUESTION_SEGMENT_MEMORY_ESTIMATE
        {
            skipped = true;
            continue;
        }
        selected_bytes = next_bytes;
        selected_estimate = next_estimate;
        selected.push(descriptor.clone());
    }
    Ok((selected, skipped))
}

fn sample_segment_key(seed: &[u8; 32], segment_id: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ley-question-segment-sample-v1\0");
    digest.update(seed);
    digest.update(segment_id.to_be_bytes());
    digest.finalize().into()
}

fn segment_memory_estimate(descriptor: &SegmentDescriptor) -> Option<u64> {
    descriptor
        .byte_len
        .checked_mul(4)?
        .checked_add(descriptor.position_count.checked_mul(64)?)?
        .checked_add(descriptor.posting_count.checked_mul(256)?)?
        .checked_add(u64::from(descriptor.term_count).checked_mul(256)?)
}

fn sample_question_postings(
    records: &BTreeMap<u32, Posting>,
    document_count: usize,
    seed: &[u8; 32],
    probe_budget: usize,
) -> (Vec<u32>, usize) {
    const SAMPLE_COUNT: usize = 8;
    if records.len() <= SAMPLE_COUNT {
        let ordinals = records
            .keys()
            .take(probe_budget)
            .copied()
            .collect::<Vec<_>>();
        let probes = ordinals.len();
        return (ordinals, probes);
    }
    if document_count == 0 {
        return (Vec::new(), 0);
    }
    let document_count = document_count as u64;
    let start =
        u64::from_be_bytes(seed[..8].try_into().expect("fixed hash length")) % document_count;
    let stride = document_count.div_ceil(SAMPLE_COUNT as u64).max(1);
    let first = records.keys().next().copied();
    let mut ordinals = BTreeSet::new();
    let probes = SAMPLE_COUNT.min(probe_budget);
    for sample in 0..probes {
        let target = (start + (sample as u64 * stride)) % document_count;
        let target = u32::try_from(target).unwrap_or(u32::MAX);
        if let Some((&ordinal, _)) = records.range(target..).next() {
            ordinals.insert(ordinal);
        } else if let Some(ordinal) = first {
            ordinals.insert(ordinal);
        }
    }
    (ordinals.into_iter().collect(), probes)
}

fn question_bm25_score(
    segment: &Segment,
    ordinal: u32,
    plan: &QuestionPlan,
    corpus: &CorpusStatistics,
) -> f64 {
    let Some(document) = segment.documents.get(ordinal as usize) else {
        return 0.0;
    };
    let Ok(document_count) = usize::try_from(corpus.document_count) else {
        return 0.0;
    };
    if document_count == 0 {
        return 0.0;
    }
    let count = document_count as f64;
    let average_title = corpus.title_token_total as f64 / count;
    let average_body = corpus.body_token_total as f64 / count;
    let term_score = |term: &str| {
        let posting = segment
            .postings
            .get(term)
            .and_then(|records| records.get(&ordinal));
        let frequencies = corpus
            .field_document_frequencies
            .get(term)
            .copied()
            .unwrap_or_default();
        let title_df = usize::try_from(frequencies.title).unwrap_or(usize::MAX);
        let body_df = usize::try_from(frequencies.body).unwrap_or(usize::MAX);
        bm25_field_contribution(
            posting.map_or(0, |value| value.title_positions.len()),
            title_df,
            document.title_terms.len(),
            average_title,
            document_count,
            2.0,
        ) + bm25_field_contribution(
            posting.map_or(0, |value| value.body_positions.len()),
            body_df,
            document.body_terms.len(),
            average_body,
            document_count,
            1.0,
        )
    };
    let mut score = 0.0;
    for term in &plan.scoring_terms {
        if plan.term_alternatives.binary_search(term).is_ok() {
            continue;
        }
        score += term_score(term);
    }
    for family in &plan.term_families {
        score += family
            .iter()
            .map(|term| term_score(term))
            .fold(0.0, f64::max);
    }
    score
}

struct OwnedStageDirectory(PathBuf);

impl Drop for OwnedStageDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn resolve_migration_target(
    source: &Path,
    destination: &Path,
) -> Result<ResolvedMigrationTarget, StorageError> {
    let source = fs::canonicalize(source)?;
    let requested_parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(requested_parent)?;
    let name = destination.file_name().ok_or_else(|| {
        StorageError::ReindexRequired("destination must name a directory".to_owned())
    })?;
    let destination = parent.join(name);
    if destination.starts_with(&source) {
        return Err(StorageError::ReindexRequired(
            "Gate 3 migration destination must be outside the retained source directory".to_owned(),
        ));
    }
    ensure_destination_absent(&destination)?;
    Ok(ResolvedMigrationTarget {
        source,
        parent,
        destination,
    })
}

struct ResolvedMigrationTarget {
    source: PathBuf,
    parent: PathBuf,
    destination: PathBuf,
}

fn ensure_destination_absent(destination: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(StorageError::StoreAlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn rename_directory_noreplace(source: &Path, destination: &Path) -> Result<(), StorageError> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EEXIST) => Err(StorageError::StoreAlreadyExists),
        Some(libc::ENOSYS) | Some(libc::EINVAL) => Err(StorageError::UnsupportedPlatform),
        _ => Err(error.into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_directory_noreplace(_source: &Path, _destination: &Path) -> Result<(), StorageError> {
    Err(StorageError::UnsupportedPlatform)
}

fn empty_manifest(store_id: StoreId) -> Manifest {
    Manifest {
        generation_id: 1,
        parent_id: 0,
        next_segment_id: 1,
        format_major: 1,
        format_minor: 0,
        store_id,
        analyzer_id: ANALYZER_ID.to_owned(),
        html_schema_id: HTML_SCHEMA_ID.to_owned(),
        segments: Vec::new(),
        live: BTreeMap::new(),
        controls: BTreeMap::new(),
        statistics: CorpusStatistics::default(),
    }
}

fn next_manifest(current: &Manifest) -> Result<Manifest, StorageError> {
    let generation_id =
        current
            .generation_id
            .checked_add(1)
            .ok_or(StorageError::CapacityExceeded(
                "manifest generation id exhausted",
            ))?;
    let mut next = current.clone();
    next.parent_id = current.generation_id;
    next.generation_id = generation_id;
    Ok(next)
}

fn is_exact_manifest_replay(
    terminal: Option<TerminalRecord>,
    policy: Option<PolicyRecord>,
    stored_terminal: Option<TerminalRecord>,
    stored_policy: Option<PolicyRecord>,
) -> bool {
    match (terminal, policy) {
        (Some(terminal), None) => stored_terminal == Some(terminal),
        (Some(TerminalRecord::Tombstone), Some(PolicyRecord::Revoked)) => {
            stored_terminal == Some(TerminalRecord::Tombstone)
                && stored_policy == Some(PolicyRecord::Revoked)
        }
        (None, Some(policy)) => stored_terminal.is_none() && stored_policy == Some(policy),
        _ => false,
    }
}

fn manifest_is_revoked(control: &ControlRecord) -> bool {
    control
        .policy
        .last_key_value()
        .is_some_and(|(_, event)| *event == PolicyRecord::Revoked)
}

fn checked_increment(value: &mut u64, label: &'static str) -> Result<(), StorageError> {
    *value = value
        .checked_add(1)
        .ok_or(StorageError::CapacityExceeded(label))?;
    Ok(())
}

fn add_document_statistics(
    statistics: &mut CorpusStatistics,
    document: &crate::index::IndexedDocument,
) -> Result<(), StorageError> {
    checked_increment(&mut statistics.document_count, "live document count")?;
    let term_count = document
        .title_terms
        .iter()
        .chain(&document.body_terms)
        .collect::<BTreeSet<_>>()
        .len() as u64;
    statistics.live_posting_record_count = statistics
        .live_posting_record_count
        .checked_add(term_count)
        .ok_or(StorageError::CapacityExceeded("live posting record count"))?;
    if statistics.live_posting_record_count > MAX_POSTING_RECORDS as u64 {
        return Err(StorageError::CapacityExceeded("live posting record limit"));
    }
    statistics.title_token_total = statistics
        .title_token_total
        .checked_add(document.title_terms.len() as u64)
        .ok_or(StorageError::CapacityExceeded("title token total"))?;
    statistics.body_token_total = statistics
        .body_token_total
        .checked_add(document.body_terms.len() as u64)
        .ok_or(StorageError::CapacityExceeded("body token total"))?;
    update_field_frequencies(statistics, &document.title_terms, true, true)?;
    update_field_frequencies(statistics, &document.body_terms, false, true)?;
    Ok(())
}

fn remove_document_statistics(
    statistics: &mut CorpusStatistics,
    document: &crate::index::IndexedDocument,
) -> Result<(), StorageError> {
    statistics.document_count = statistics
        .document_count
        .checked_sub(1)
        .ok_or_else(|| corrupt("live document statistic underflow"))?;
    let term_count = document
        .title_terms
        .iter()
        .chain(&document.body_terms)
        .collect::<BTreeSet<_>>()
        .len() as u64;
    statistics.live_posting_record_count = statistics
        .live_posting_record_count
        .checked_sub(term_count)
        .ok_or_else(|| corrupt("live posting record statistic underflow"))?;
    statistics.title_token_total = statistics
        .title_token_total
        .checked_sub(document.title_terms.len() as u64)
        .ok_or_else(|| corrupt("title token statistic underflow"))?;
    statistics.body_token_total = statistics
        .body_token_total
        .checked_sub(document.body_terms.len() as u64)
        .ok_or_else(|| corrupt("body token statistic underflow"))?;
    update_field_frequencies(statistics, &document.title_terms, true, false)?;
    update_field_frequencies(statistics, &document.body_terms, false, false)?;
    Ok(())
}

fn update_field_frequencies(
    statistics: &mut CorpusStatistics,
    terms: &[String],
    title: bool,
    add: bool,
) -> Result<(), StorageError> {
    let distinct = terms.iter().collect::<BTreeSet<_>>();
    for term in distinct {
        if add {
            let frequency = statistics
                .field_document_frequencies
                .entry(term.clone())
                .or_default();
            let value = if title {
                &mut frequency.title
            } else {
                &mut frequency.body
            };
            checked_increment(value, "field document frequency")?;
        } else {
            let frequency = statistics
                .field_document_frequencies
                .get_mut(term.as_str())
                .ok_or_else(|| corrupt("field document frequency is missing"))?;
            let value = if title {
                &mut frequency.title
            } else {
                &mut frequency.body
            };
            *value = value
                .checked_sub(1)
                .ok_or_else(|| corrupt("field document frequency underflow"))?;
            if frequency.title == 0 && frequency.body == 0 {
                statistics.field_document_frequencies.remove(term.as_str());
            }
        }
    }
    Ok(())
}

fn statistics_for_documents<'a>(
    documents: impl IntoIterator<Item = &'a crate::index::IndexedDocument>,
) -> Result<CorpusStatistics, StorageError> {
    let mut statistics = CorpusStatistics::default();
    for document in documents {
        add_document_statistics(&mut statistics, document)?;
    }
    Ok(statistics)
}

fn controls_to_records(
    controls: &BTreeMap<UrlKey, DocumentControl>,
) -> BTreeMap<String, ControlRecord> {
    controls
        .iter()
        .map(|(key, control)| {
            let terminal = control
                .terminal
                .iter()
                .map(|(fence, intent)| {
                    let intent = match intent {
                        TerminalIntent::Upsert(version) => TerminalRecord::Upsert(*version),
                        TerminalIntent::Tombstone => TerminalRecord::Tombstone,
                    };
                    (*fence, intent)
                })
                .collect();
            let policy = control
                .policy
                .iter()
                .map(|(fence, event)| {
                    let event = match event {
                        PolicyEvent::Revoked => PolicyRecord::Revoked,
                        PolicyEvent::Readmitted => PolicyRecord::Readmitted,
                    };
                    (*fence, event)
                })
                .collect();
            (
                key.as_str().to_owned(),
                ControlRecord {
                    high_water: control.high_water,
                    terminal,
                    policy,
                },
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
enum ManifestValidationKind {
    Committed,
    Proposed,
}

#[derive(Clone, Copy)]
enum ManifestLimit {
    ActiveSegmentCount,
    LiveDocumentCount,
    LifecycleControlKeys,
    LivePostingCount,
    LiveTermCount,
    SingleSegmentDocuments,
    SingleSegmentBytes,
    SingleSegmentTerms,
    SingleSegmentPostings,
    SingleSegmentPositions,
    ActiveSegmentBytes,
    ActivePostingCount,
    ActivePositionCount,
    PerDocumentLifecycleHistory,
    LifecycleHistory,
}

impl ManifestLimit {
    fn error(self, kind: ManifestValidationKind) -> StorageError {
        let message = match (kind, self) {
            (ManifestValidationKind::Committed, _) => "manifest counts exceed configured bounds",
            (ManifestValidationKind::Proposed, Self::ActiveSegmentCount) => {
                "active segment count exceeds 4096; run `ley compact --store <store-path>` to merge active segments and reduce descriptor count"
            }
            (ManifestValidationKind::Proposed, Self::LiveDocumentCount) => {
                "live document count exceeds 100000; remove live documents to continue"
            }
            (ManifestValidationKind::Proposed, Self::LifecycleControlKeys) => {
                "retained lifecycle control key count exceeds 100000; compaction cannot reduce retained lifecycle history"
            }
            (ManifestValidationKind::Proposed, Self::LivePostingCount) => {
                "live posting record count exceeds 1000000; reduce live indexed content to continue"
            }
            (ManifestValidationKind::Proposed, Self::LiveTermCount) => {
                "live term count exceeds 500000; reduce live indexed content to continue"
            }
            (ManifestValidationKind::Proposed, Self::SingleSegmentDocuments) => {
                "single segment document limit exceeded; split indexed content across writes"
            }
            (ManifestValidationKind::Proposed, Self::SingleSegmentBytes) => {
                "single segment byte limit exceeded; reduce the indexed document content"
            }
            (ManifestValidationKind::Proposed, Self::SingleSegmentTerms) => {
                "single segment term limit exceeded; reduce the indexed document content"
            }
            (ManifestValidationKind::Proposed, Self::SingleSegmentPostings) => {
                "single segment posting limit exceeded; reduce the indexed document content"
            }
            (ManifestValidationKind::Proposed, Self::SingleSegmentPositions) => {
                "single segment position limit exceeded; reduce the indexed document content"
            }
            (ManifestValidationKind::Proposed, Self::ActiveSegmentBytes) => {
                "active segment bytes exceed 536870912; run `ley compact --store <store-path>` if stale entries or segment overhead account for the excess"
            }
            (ManifestValidationKind::Proposed, Self::ActivePostingCount) => {
                "physical posting records exceed 4000000; run `ley compact --store <store-path>` if stale segments account for the excess"
            }
            (ManifestValidationKind::Proposed, Self::ActivePositionCount) => {
                "physical positions exceed 50000000; run `ley compact --store <store-path>` if stale segments account for the excess"
            }
            (ManifestValidationKind::Proposed, Self::PerDocumentLifecycleHistory) => {
                "per-document lifecycle history exceeds 500000 events; compaction cannot reduce retained lifecycle history"
            }
            (ManifestValidationKind::Proposed, Self::LifecycleHistory) => {
                "lifecycle history exceeds 500000 events; compaction cannot reduce retained lifecycle history"
            }
        };
        match kind {
            ManifestValidationKind::Committed => corrupt(message),
            ManifestValidationKind::Proposed => StorageError::CapacityExceeded(message),
        }
    }
}

fn validate_manifest_shape(manifest: &Manifest, store_id: StoreId) -> Result<(), StorageError> {
    validate_manifest_shape_for(manifest, store_id, ManifestValidationKind::Committed)
}

fn validate_proposed_manifest_shape(
    manifest: &Manifest,
    store_id: StoreId,
) -> Result<(), StorageError> {
    validate_manifest_shape_for(manifest, store_id, ManifestValidationKind::Proposed)
}

fn validate_manifest_shape_for(
    manifest: &Manifest,
    store_id: StoreId,
    kind: ManifestValidationKind,
) -> Result<(), StorageError> {
    let manifest_document_count = usize::try_from(manifest.statistics.document_count)
        .map_err(|_| corrupt("live document count does not fit this platform"))?;
    if manifest.generation_id == 0
        || manifest.parent_id >= manifest.generation_id
        || manifest.next_segment_id == 0
        || manifest.format_major != 1
        || manifest.format_minor != 0
        || manifest.store_id != store_id
        || manifest.analyzer_id != ANALYZER_ID
        || manifest.html_schema_id != HTML_SCHEMA_ID
    {
        return Err(corrupt("manifest version, identity, or schema is invalid"));
    }
    if manifest.segments.len() > MAX_SEGMENTS {
        return Err(ManifestLimit::ActiveSegmentCount.error(kind));
    }
    if manifest.live.len() > MAX_DOCUMENTS {
        return Err(ManifestLimit::LiveDocumentCount.error(kind));
    }
    if manifest.controls.len() > MAX_CONTROL_KEYS {
        return Err(ManifestLimit::LifecycleControlKeys.error(kind));
    }
    if manifest_document_count != manifest.live.len() {
        return Err(corrupt("manifest counts exceed configured bounds"));
    }
    if manifest.statistics.live_posting_record_count > MAX_POSTING_RECORDS as u64 {
        return Err(ManifestLimit::LivePostingCount.error(kind));
    }
    if manifest.statistics.field_document_frequencies.len() > MAX_TERMS {
        return Err(ManifestLimit::LiveTermCount.error(kind));
    }
    let mut segment_ids = BTreeSet::new();
    let mut segment_bytes = 0u64;
    let mut posting_count = 0u64;
    let mut position_count = 0u64;
    let mut previous_segment = 0;
    for descriptor in &manifest.segments {
        if descriptor.id == 0
            || descriptor.id <= previous_segment
            || descriptor.id >= manifest.next_segment_id
            || descriptor.byte_len < 164
            || descriptor.document_count == 0
            || !segment_ids.insert(descriptor.id)
        {
            return Err(corrupt("manifest segment descriptor is invalid"));
        }
        if descriptor.byte_len > MAX_SEGMENT_BYTES as u64 {
            return Err(ManifestLimit::SingleSegmentBytes.error(kind));
        }
        if descriptor.document_count as usize > MAX_DOCUMENTS {
            return Err(ManifestLimit::SingleSegmentDocuments.error(kind));
        }
        if descriptor.term_count as usize > MAX_TERMS {
            return Err(ManifestLimit::SingleSegmentTerms.error(kind));
        }
        if descriptor.posting_count > MAX_PHYSICAL_POSTING_RECORDS as u64 {
            return Err(ManifestLimit::SingleSegmentPostings.error(kind));
        }
        if descriptor.position_count > MAX_POSITION_VALUES {
            return Err(ManifestLimit::SingleSegmentPositions.error(kind));
        }
        previous_segment = descriptor.id;
        segment_bytes = segment_bytes
            .checked_add(descriptor.byte_len)
            .ok_or_else(|| corrupt("active segment byte total overflow"))?;
        posting_count = posting_count
            .checked_add(descriptor.posting_count)
            .ok_or_else(|| corrupt("physical posting total overflow"))?;
        position_count = position_count
            .checked_add(descriptor.position_count)
            .ok_or_else(|| corrupt("physical position total overflow"))?;
    }
    if segment_bytes > MAX_ACTIVE_SEGMENT_BYTES {
        return Err(ManifestLimit::ActiveSegmentBytes.error(kind));
    }
    if posting_count > MAX_PHYSICAL_POSTING_RECORDS as u64 {
        return Err(ManifestLimit::ActivePostingCount.error(kind));
    }
    if position_count > MAX_POSITION_VALUES {
        return Err(ManifestLimit::ActivePositionCount.error(kind));
    }
    for (key, reference) in &manifest.live {
        validate_url_key(key).map_err(|error| corrupt(&error.to_string()))?;
        let descriptor = manifest
            .segments
            .iter()
            .find(|segment| segment.id == reference.segment_id)
            .ok_or_else(|| corrupt("live document references an absent segment"))?;
        if reference.ordinal >= descriptor.document_count || reference.version == [0; 32] {
            return Err(corrupt(
                "live document reference is outside its segment or has an invalid version",
            ));
        }
    }
    let mut total_terminal = 0usize;
    let mut total_policy = 0usize;
    let mut old_controls = BTreeMap::new();
    for (key_text, control) in &manifest.controls {
        validate_url_key(key_text).map_err(|error| corrupt(&error.to_string()))?;
        if control.high_water == 0 {
            return Err(corrupt("manifest control has a zero fence high-water"));
        }
        total_terminal = total_terminal
            .checked_add(control.terminal.len())
            .ok_or_else(|| corrupt("terminal history count overflow"))?;
        total_policy = total_policy
            .checked_add(control.policy.len())
            .ok_or_else(|| corrupt("policy history count overflow"))?;
        if control.terminal.len() > MAX_TERMINAL_INTENTS
            || control.policy.len() > MAX_TERMINAL_INTENTS
        {
            return Err(ManifestLimit::PerDocumentLifecycleHistory.error(kind));
        }
        if control
            .terminal
            .keys()
            .any(|fence| *fence == 0 || *fence > control.high_water)
            || control
                .policy
                .keys()
                .any(|fence| *fence == 0 || *fence > control.high_water)
        {
            return Err(corrupt("manifest control history exceeds its bound"));
        }
        let key = UrlKey::parse(key_text).map_err(|error| corrupt(&error.to_string()))?;
        let terminal = control
            .terminal
            .iter()
            .map(|(fence, intent)| {
                let intent = match intent {
                    TerminalRecord::Upsert(version) => TerminalIntent::Upsert(*version),
                    TerminalRecord::Tombstone => TerminalIntent::Tombstone,
                };
                (*fence, intent)
            })
            .collect();
        let policy = control
            .policy
            .iter()
            .map(|(fence, event)| {
                let event = match event {
                    PolicyRecord::Revoked => PolicyEvent::Revoked,
                    PolicyRecord::Readmitted => PolicyEvent::Readmitted,
                };
                (*fence, event)
            })
            .collect();
        old_controls.insert(
            key,
            DocumentControl {
                high_water: control.high_water,
                terminal,
                policy,
            },
        );
    }
    if total_terminal > MAX_TERMINAL_INTENTS || total_policy > MAX_TERMINAL_INTENTS {
        return Err(ManifestLimit::LifecycleHistory.error(kind));
    }
    validate_control_history(&old_controls)?;
    let live_document_count = manifest.statistics.document_count;
    if manifest.statistics.title_token_total
        > live_document_count.saturating_mul(MAX_DOCUMENT_TOKENS as u64)
        || manifest.statistics.body_token_total
            > live_document_count.saturating_mul(MAX_DOCUMENT_TOKENS as u64)
    {
        return Err(corrupt("manifest token totals exceed document limits"));
    }
    for (term, frequencies) in &manifest.statistics.field_document_frequencies {
        let normalized = Analyzer
            .analyze(term)
            .map_err(|_| corrupt("manifest term is invalid"))?;
        if normalized.len() != 1
            || normalized[0] != *term
            || (frequencies.title == 0 && frequencies.body == 0)
            || frequencies.title > live_document_count
            || frequencies.body > live_document_count
        {
            return Err(corrupt("manifest field document frequency is invalid"));
        }
    }
    Ok(())
}

fn validate_live_control_records(
    documents: &BTreeMap<String, crate::index::IndexedDocument>,
    controls: &BTreeMap<String, ControlRecord>,
) -> Result<(), StorageError> {
    for (key, document) in documents {
        let control = controls
            .get(key)
            .ok_or_else(|| corrupt("live document has no lifecycle control"))?;
        if manifest_is_revoked(control)
            || control
                .terminal
                .last_key_value()
                .map(|(_, terminal)| *terminal)
                != Some(TerminalRecord::Upsert(decode_version_id(
                    &document.version_id,
                )?))
        {
            return Err(corrupt(
                "live document differs from its latest lifecycle control",
            ));
        }
    }
    for (key, control) in controls {
        let has_live_upsert = !manifest_is_revoked(control)
            && matches!(
                control.terminal.last_key_value(),
                Some((_, TerminalRecord::Upsert(_)))
            );
        if has_live_upsert && !documents.contains_key(key) {
            return Err(corrupt(
                "latest upsert is absent from the live document view",
            ));
        }
    }
    Ok(())
}

fn snapshot_memory_estimate(manifest: &Manifest, manifest_bytes: u64) -> Result<u64, StorageError> {
    let segment_bytes = manifest
        .segments
        .iter()
        .try_fold(0u64, |total, item| total.checked_add(item.byte_len))
        .ok_or_else(|| corrupt("snapshot segment byte estimate overflow"))?;
    let positions = manifest
        .segments
        .iter()
        .try_fold(0u64, |total, item| total.checked_add(item.position_count))
        .ok_or_else(|| corrupt("snapshot position estimate overflow"))?;
    let postings = manifest
        .segments
        .iter()
        .try_fold(0u64, |total, item| total.checked_add(item.posting_count))
        .ok_or_else(|| corrupt("snapshot posting estimate overflow"))?;
    let terms = manifest
        .segments
        .iter()
        .try_fold(0u64, |total, item| {
            total.checked_add(u64::from(item.term_count))
        })
        .ok_or_else(|| corrupt("snapshot term estimate overflow"))?;
    let controls = manifest.controls.len() as u64;
    let histories = manifest
        .controls
        .values()
        .try_fold(0u64, |total, item| {
            total.checked_add((item.terminal.len() + item.policy.len()) as u64)
        })
        .ok_or_else(|| corrupt("snapshot history estimate overflow"))?;
    let estimate = manifest_bytes
        .checked_mul(4)
        .and_then(|value| value.checked_add(segment_bytes.checked_mul(4)?))
        .and_then(|value| value.checked_add(positions.checked_mul(64)?))
        .and_then(|value| value.checked_add(postings.checked_mul(256)?))
        .and_then(|value| value.checked_add(terms.checked_mul(256)?))
        .and_then(|value| value.checked_add((manifest.live.len() as u64).checked_mul(2048)?))
        .and_then(|value| value.checked_add(controls.checked_mul(128)?))
        .and_then(|value| value.checked_add(histories.checked_mul(64)?))
        .ok_or_else(|| corrupt("snapshot memory estimate overflow"))?;
    Ok(estimate)
}

fn segment_summary(descriptor: &SegmentDescriptor) -> SegmentDescriptorSummary {
    SegmentDescriptorSummary {
        id: descriptor.id,
        byte_len: descriptor.byte_len,
        sha256: descriptor
            .sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn manifest_name(id: u64) -> String {
    format!("manifest-{id}.ley")
}

fn manifest_temp_name(id: u64) -> String {
    format!(".manifest-{id}.tmp")
}

fn segment_name(id: u64) -> String {
    format!("seg-{id}.ley")
}

fn segment_temp_name(id: u64) -> String {
    format!(".seg-{id}.tmp")
}

fn parse_owned_id(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let id = digits.parse::<u64>().ok()?;
    (id.to_string() == digits).then_some(id)
}

fn cleanup_gate6_orphans(path: &Path, current: Option<&Manifest>) -> Result<(), StorageError> {
    let keep_segments = current
        .map(|value| {
            value
                .segments
                .iter()
                .map(|item| item.id)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let keep_manifests = current
        .map(|value| BTreeSet::from([value.generation_id]))
        .unwrap_or_default();
    let mut removed = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_dir() {
            continue;
        }
        let stale_segment =
            parse_owned_id(&name, "seg-", ".ley").is_some_and(|id| !keep_segments.contains(&id));
        let stale_manifest = parse_owned_id(&name, "manifest-", ".ley")
            .is_some_and(|id| !keep_manifests.contains(&id));
        let temporary = parse_owned_id(&name, ".seg-", ".tmp").is_some()
            || parse_owned_id(&name, ".manifest-", ".tmp").is_some()
            || name == ".CURRENT.v6.tmp";
        if (stale_segment || stale_manifest || temporary)
            && (metadata.file_type().is_file() || metadata.file_type().is_symlink())
        {
            fs::remove_file(entry.path())?;
            removed = true;
            storage_failpoint("cleanup_after_unlink");
        }
    }
    if removed {
        sync_directory(path)?;
        storage_failpoint("cleanup_directory_sync");
    }
    Ok(())
}

fn is_revoked(control: &DocumentControl) -> bool {
    control
        .policy
        .last_key_value()
        .is_some_and(|(_, event)| *event == PolicyEvent::Revoked)
}

fn encode_store_v6(store_id: StoreId, public_collection: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORE_BYTES);
    bytes.extend_from_slice(STORE_MAGIC_V6);
    put_u16(&mut bytes, STORE_V6_MAJOR);
    put_u16(&mut bytes, STORE_V6_MINOR);
    put_u32(&mut bytes, u32::from(public_collection) * PUBLIC_STORE_FLAG);
    bytes.extend_from_slice(&store_id);
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

#[cfg(test)]
fn encode_store_version(store_id: StoreId, minor: u16, flags: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STORE_BYTES);
    bytes.extend_from_slice(STORE_MAGIC);
    put_u16(&mut bytes, FORMAT_MAJOR);
    put_u16(&mut bytes, minor);
    put_u32(&mut bytes, flags);
    bytes.extend_from_slice(&store_id);
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

fn validate_public_collection_gate(gate: &PublicCollectionGate) -> Result<(), StorageError> {
    let origin =
        url::Url::parse(&gate.origin).map_err(|_| StorageError::PublicCollectionConflict)?;
    if !is_lower_sha256(&gate.policy_sha256)
        || gate.source_id.is_empty()
        || gate.source_id.len() > 128
        || !gate
            .source_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.origin().ascii_serialization() != gate.origin
        || gate.path_prefixes.is_empty()
        || gate.path_prefixes.len() > 64
        || gate.path_prefixes.iter().any(|path| {
            path.len() > MAX_URL_KEY_BYTES
                || !crate::url_key::path_is_within_prefix(path, path)
                || path.contains(['?', '#', '\\', '\r', '\n'])
        })
        || gate.installed_at_ms == 0
        || gate.visible_until_ms <= gate.installed_at_ms
        || gate.license.trim().is_empty()
        || gate.license.len() > 256
        || gate.license.chars().any(char::is_control)
        || gate.source_version.is_empty()
        || gate.source_version.len() > 200
        || gate.source_version.chars().any(char::is_control)
        || !is_safe_notice_file_name(&gate.notice_file)
        || !is_lower_sha256(&gate.notice_sha256)
        || !valid_permission_metadata(gate)
    {
        return Err(StorageError::PublicCollectionConflict);
    }
    Ok(())
}

pub(crate) fn validate_public_collection_admission(
    gate: &PublicCollectionGate,
    notice: &[u8],
) -> Result<(), StorageError> {
    validate_public_collection_gate(gate)?;
    if !valid_public_notice(notice) || sha256(notice) != decode_sha256(&gate.notice_sha256)? {
        return Err(StorageError::PublicCollectionConflict);
    }
    let record = PublicCollectionRecord {
        schema: "ley-public-collection-v1".to_owned(),
        store_id: [0; 16],
        gate: gate.clone(),
        mac: "0".repeat(64),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| StorageError::PublicCollectionConflict)?;
    if bytes.len() > MAX_PUBLIC_COLLECTION_BYTES {
        return Err(StorageError::PublicCollectionConflict);
    }
    Ok(())
}

fn valid_permission_metadata(gate: &PublicCollectionGate) -> bool {
    let permissions = [
        &gate.fetch_permission,
        &gate.storage_permission,
        &gate.index_permission,
        &gate.display_permission,
    ];
    if permissions.iter().all(|permission| permission.is_none()) && gate.removal_contact.is_none() {
        return true;
    }
    let Some(removal_contact) = gate.removal_contact.as_deref() else {
        return false;
    };
    if removal_contact.trim().is_empty()
        || removal_contact.len() > 512
        || removal_contact.chars().any(char::is_control)
    {
        return false;
    }
    permissions.iter().all(|permission| {
        permission.as_ref().is_some_and(|permission| {
            permission.granted
                && permission.reviewed_at_ms > 0
                && permission.reviewed_at_ms <= gate.installed_at_ms
                && valid_public_permission_text(&permission.basis)
                && valid_public_permission_text(&permission.evidence)
        })
    })
}

fn valid_public_permission_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_PUBLIC_PERMISSION_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_public_notice(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    !text.trim().is_empty()
        && bytes.len() <= MAX_PUBLIC_NOTICE_BYTES
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn is_safe_notice_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_sha256(value: &str) -> Result<[u8; 32], StorageError> {
    if !is_lower_sha256(value) {
        return Err(corrupt("SHA-256 value has an invalid encoding"));
    }
    let mut decoded = [0; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2])? << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1])?;
    }
    Ok(decoded)
}

fn encode_public_collection_record(
    store_id: StoreId,
    gate: &PublicCollectionGate,
    mac_key: &LeaseMacKey,
) -> Result<Vec<u8>, StorageError> {
    validate_public_collection_gate(gate)?;
    let payload = serde_json::to_vec(gate)
        .map_err(|_| corrupt("public collection metadata could not be encoded"))?;
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| corrupt("public collection authentication key is invalid"))?;
    mac.update(PUBLIC_COLLECTION_DOMAIN);
    mac.update(&store_id);
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();
    let record = PublicCollectionRecord {
        schema: "ley-public-collection-v1".to_owned(),
        store_id,
        gate: gate.clone(),
        mac: tag.iter().map(|byte| format!("{byte:02x}")).collect(),
    };
    serde_json::to_vec(&record)
        .map_err(|_| corrupt("public collection record could not be encoded"))
}

fn decode_public_collection_record(
    bytes: &[u8],
    expected_store_id: StoreId,
    mac_key: &LeaseMacKey,
) -> Result<PublicCollectionGate, StorageError> {
    let record: PublicCollectionRecord = serde_json::from_slice(bytes)
        .map_err(|_| corrupt("public collection record is invalid"))?;
    validate_public_collection_gate(&record.gate)?;
    if record.schema != "ley-public-collection-v1" || record.store_id != expected_store_id {
        return Err(corrupt(
            "public collection record belongs to a different store",
        ));
    }
    let payload = serde_json::to_vec(&record.gate)
        .map_err(|_| corrupt("public collection metadata could not be encoded"))?;
    let tag = decode_sha256(&record.mac)?;
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|_| corrupt("public collection authentication key is invalid"))?;
    mac.update(PUBLIC_COLLECTION_DOMAIN);
    mac.update(&expected_store_id);
    mac.update(&payload);
    mac.verify_slice(&tag)
        .map_err(|_| corrupt("public collection authentication failed"))?;
    Ok(record.gate)
}

fn decode_store(bytes: &[u8]) -> Result<(StoreId, bool), StorageError> {
    if bytes.len() != STORE_BYTES {
        return Err(corrupt("STORE has an invalid length"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    let flags = get_u32(bytes, 12)?;
    let expected_magic = match &bytes[..8] {
        magic if magic == STORE_MAGIC => STORE_MAGIC,
        magic if magic == STORE_MAGIC_V6 => STORE_MAGIC_V6,
        _ => return Err(corrupt("STORE magic mismatch")),
    };
    let is_v6 = expected_magic == STORE_MAGIC_V6;
    if is_v6 && (major != STORE_V6_MAJOR || minor != STORE_V6_MINOR) {
        return Err(StorageError::UnsupportedFormat { major, minor });
    }
    let requires_public_gate = match (major, minor, flags) {
        (FORMAT_MAJOR, FORMAT_MINOR, 0) => false,
        (FORMAT_MAJOR, PUBLIC_STORE_MINOR, PUBLIC_STORE_FLAG) => true,
        (STORE_V6_MAJOR, STORE_V6_MINOR, 0) if is_v6 => false,
        (STORE_V6_MAJOR, STORE_V6_MINOR, PUBLIC_STORE_FLAG) if is_v6 => true,
        (FORMAT_MAJOR, version, _) if version == FORMAT_MINOR || version == PUBLIC_STORE_MINOR => {
            return Err(corrupt("STORE flags do not match its version"));
        }
        (STORE_V6_MAJOR, STORE_V6_MINOR, _) if is_v6 => {
            return Err(corrupt("STORE flags do not match its Gate 6 version"));
        }
        _ => return Err(StorageError::UnsupportedFormat { major, minor }),
    };
    if sha256(&bytes[..32]) != bytes[32..64] {
        return Err(corrupt("STORE checksum mismatch"));
    }
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[16..32]);
    Ok((id, requires_public_gate))
}

#[cfg(test)]
fn encode_lease_key(store_id: StoreId, lease_mac_key: LeaseMacKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LEASE_KEY_BYTES);
    bytes.extend_from_slice(LEASE_KEY_MAGIC);
    put_u16(&mut bytes, FORMAT_MAJOR);
    put_u16(&mut bytes, FORMAT_MINOR);
    put_u32(&mut bytes, 0);
    bytes.extend_from_slice(&store_id);
    bytes.extend_from_slice(&lease_mac_key);
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

fn encode_lease_key_v6(store_id: StoreId, lease_mac_key: LeaseMacKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LEASE_KEY_BYTES);
    bytes.extend_from_slice(LEASE_KEY_MAGIC_V6);
    put_u16(&mut bytes, STORE_V6_MAJOR);
    put_u16(&mut bytes, STORE_V6_MINOR);
    put_u32(&mut bytes, 0);
    bytes.extend_from_slice(&store_id);
    bytes.extend_from_slice(&lease_mac_key);
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

fn decode_lease_key(bytes: &[u8], expected_store_id: StoreId) -> Result<LeaseMacKey, StorageError> {
    if bytes.len() != LEASE_KEY_BYTES {
        return Err(corrupt("LEASE_KEY has an invalid length or magic"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    let is_v6 = &bytes[..8] == LEASE_KEY_MAGIC_V6;
    let header_is_valid = if is_v6 {
        major == STORE_V6_MAJOR && minor == STORE_V6_MINOR
    } else {
        &bytes[..8] == LEASE_KEY_MAGIC && major == FORMAT_MAJOR && minor == FORMAT_MINOR
    };
    if !header_is_valid {
        return Err(StorageError::UnsupportedFormat { major, minor });
    }
    if get_u32(bytes, 12)? != 0 {
        return Err(corrupt("LEASE_KEY reserved flags are nonzero"));
    }
    if bytes[16..32] != expected_store_id {
        return Err(corrupt("LEASE_KEY belongs to a different store"));
    }
    if sha256(&bytes[..64]) != bytes[64..96] {
        return Err(corrupt("LEASE_KEY checksum mismatch"));
    }
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[32..64]);
    Ok(key)
}

fn encode_lease_token(
    store_id: StoreId,
    mac_key: &LeaseMacKey,
    key: &UrlKey,
    fence: NonZeroU64,
) -> Result<Vec<u8>, StorageError> {
    let key_bytes = key.as_str().as_bytes();
    if key_bytes.is_empty() || key_bytes.len() > MAX_URL_KEY_BYTES {
        return Err(StorageError::InvalidLease);
    }
    let key_length = u16::try_from(key_bytes.len()).map_err(|_| StorageError::InvalidLease)?;
    let mut bytes = Vec::with_capacity(LEASE_HEADER_BYTES + key_bytes.len() + LEASE_TAG_BYTES);
    bytes.extend_from_slice(LEASE_MAGIC);
    put_u16(&mut bytes, LEASE_VERSION);
    put_u16(&mut bytes, 0);
    bytes.extend_from_slice(&store_id);
    put_u64(&mut bytes, fence.get());
    put_u16(&mut bytes, key_length);
    bytes.extend_from_slice(key_bytes);
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| StorageError::InvalidLease)?;
    mac.update(LEASE_DOMAIN);
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}

fn decode_lease_token(
    token: &[u8],
    mac_key: &LeaseMacKey,
) -> Result<(StoreId, UrlKey, NonZeroU64), StorageError> {
    if token.len() < LEASE_HEADER_BYTES + LEASE_TAG_BYTES
        || token.len() > MAX_LEASE_TOKEN_BYTES
        || &token[..8] != LEASE_MAGIC
        || get_u16(token, 8).map_err(|_| StorageError::InvalidLease)? != LEASE_VERSION
        || get_u16(token, 10).map_err(|_| StorageError::InvalidLease)? != 0
    {
        return Err(StorageError::InvalidLease);
    }
    let key_length = usize::from(get_u16(token, 36).map_err(|_| StorageError::InvalidLease)?);
    if key_length == 0 || key_length > MAX_URL_KEY_BYTES {
        return Err(StorageError::InvalidLease);
    }
    let signed_length = LEASE_HEADER_BYTES
        .checked_add(key_length)
        .ok_or(StorageError::InvalidLease)?;
    let expected_length = signed_length
        .checked_add(LEASE_TAG_BYTES)
        .ok_or(StorageError::InvalidLease)?;
    if token.len() != expected_length {
        return Err(StorageError::InvalidLease);
    }
    let mut mac = HmacSha256::new_from_slice(mac_key).map_err(|_| StorageError::InvalidLease)?;
    mac.update(LEASE_DOMAIN);
    mac.update(&token[..signed_length]);
    mac.verify_slice(&token[signed_length..])
        .map_err(|_| StorageError::InvalidLease)?;

    let mut store_id = [0; 16];
    store_id.copy_from_slice(&token[12..28]);
    let fence = NonZeroU64::new(get_u64(token, 28).map_err(|_| StorageError::InvalidLease)?)
        .ok_or(StorageError::InvalidLease)?;
    let key_text = std::str::from_utf8(&token[LEASE_HEADER_BYTES..signed_length])
        .map_err(|_| StorageError::InvalidLease)?;
    let key = UrlKey::parse(key_text).map_err(|_| StorageError::InvalidLease)?;
    if key.as_str().as_bytes() != &token[LEASE_HEADER_BYTES..signed_length] {
        return Err(StorageError::InvalidLease);
    }
    Ok((store_id, key, fence))
}

#[cfg(test)]
fn encode_current(store_id: StoreId, generation_id: u64, length: u64, hash: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CURRENT_BYTES);
    bytes.extend_from_slice(CURRENT_MAGIC);
    put_u16(&mut bytes, FORMAT_MAJOR);
    put_u16(&mut bytes, FORMAT_MINOR);
    put_u32(&mut bytes, 0);
    bytes.extend_from_slice(&store_id);
    put_u64(&mut bytes, generation_id);
    put_u64(&mut bytes, length);
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&sha256(&bytes));
    bytes
}

fn decode_current(
    bytes: &[u8],
    expected_store_id: StoreId,
) -> Result<(u64, u64, [u8; 32]), StorageError> {
    if bytes.len() != CURRENT_BYTES {
        return Err(corrupt("CURRENT has an invalid length"));
    }
    if &bytes[..8] != CURRENT_MAGIC {
        return Err(corrupt("CURRENT magic mismatch"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
        return Err(StorageError::UnsupportedFormat { major, minor });
    }
    if get_u32(bytes, 12)? != 0 {
        return Err(corrupt("CURRENT reserved flags are nonzero"));
    }
    if bytes[16..32] != expected_store_id {
        return Err(corrupt("CURRENT belongs to a different store"));
    }
    if sha256(&bytes[..80]) != bytes[80..112] {
        return Err(corrupt("CURRENT checksum mismatch"));
    }
    let generation_id = get_u64(bytes, 32)?;
    let length = get_u64(bytes, 40)?;
    if generation_id == 0 || length < HEADER_BYTES as u64 || length > MAX_GENERATION_BYTES as u64 {
        return Err(corrupt("CURRENT generation identity or length is invalid"));
    }
    let mut hash = [0; 32];
    hash.copy_from_slice(&bytes[48..80]);
    Ok((generation_id, length, hash))
}

#[cfg(test)]
fn encode_generation(generation: &Generation, store_id: StoreId) -> Result<Vec<u8>, StorageError> {
    if generation.id == 0
        || (generation.id == 1 && generation.parent_id != 0)
        || (generation.id > 1 && generation.parent_id.checked_add(1) != Some(generation.id))
    {
        return Err(corrupt("generation identity sequence is invalid"));
    }
    if generation.index.len() > MAX_DOCUMENTS {
        return Err(StorageError::CapacityExceeded("live document count"));
    }
    if generation.index.postings().len() > MAX_TERMS {
        return Err(StorageError::CapacityExceeded("term count"));
    }
    if generation.controls.len() > MAX_CONTROL_KEYS {
        return Err(StorageError::CapacityExceeded("control key count"));
    }

    let mut posting_record_count = 0usize;
    for documents in generation.index.postings().values() {
        posting_record_count = posting_record_count
            .checked_add(documents.len())
            .ok_or(StorageError::CapacityExceeded("posting count overflow"))?;
    }
    if posting_record_count > MAX_POSTING_RECORDS {
        return Err(StorageError::CapacityExceeded("posting record count"));
    }
    let mut terminal_count = 0usize;
    let mut policy_count = 0usize;
    for control in generation.controls.values() {
        terminal_count = terminal_count.checked_add(control.terminal.len()).ok_or(
            StorageError::CapacityExceeded("terminal intent count overflow"),
        )?;
        policy_count = policy_count.checked_add(control.policy.len()).ok_or(
            StorageError::CapacityExceeded("policy event count overflow"),
        )?;
    }
    if terminal_count > MAX_TERMINAL_INTENTS {
        return Err(StorageError::CapacityExceeded("terminal intent count"));
    }
    if policy_count > MAX_TERMINAL_INTENTS {
        return Err(StorageError::CapacityExceeded("policy event count"));
    }

    let mut remaining = MAX_GENERATION_BYTES - HEADER_BYTES;
    let (documents, title_tokens, body_tokens) = encode_documents(&generation.index, remaining)?;
    remaining = remaining
        .checked_sub(documents.len())
        .ok_or(StorageError::CapacityExceeded("generation byte limit"))?;
    let (dictionary, postings) = encode_terms(&generation.index, remaining)?;
    remaining = remaining
        .checked_sub(dictionary.len())
        .and_then(|value| value.checked_sub(postings.len()))
        .ok_or(StorageError::CapacityExceeded("generation byte limit"))?;
    let controls = encode_controls(&generation.controls, remaining)?;
    let sections = [documents, dictionary, postings, controls];
    let section_counts = [
        generation.index.len(),
        generation.index.postings().len(),
        posting_record_count,
        generation.controls.len(),
    ];
    let total_len = sections
        .iter()
        .try_fold(HEADER_BYTES, |length, section| {
            length.checked_add(section.len())
        })
        .ok_or(StorageError::CapacityExceeded(
            "generation byte length overflow",
        ))?;
    if total_len > MAX_GENERATION_BYTES {
        return Err(StorageError::CapacityExceeded("generation byte limit"));
    }

    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.extend_from_slice(GENERATION_MAGIC);
    put_u16(&mut header, FORMAT_MAJOR);
    put_u16(&mut header, FORMAT_MINOR);
    put_u32(&mut header, HEADER_BYTES as u32);
    put_u32(&mut header, 0);
    header.extend_from_slice(&store_id);
    put_u64(&mut header, generation.id);
    put_u64(&mut header, generation.parent_id);
    header.extend_from_slice(&sha256(HTML_SCHEMA_ID.as_bytes()));
    header.extend_from_slice(&sha256(ANALYZER_ID.as_bytes()));
    put_u64(&mut header, total_len as u64);
    put_u64(&mut header, generation.index.len() as u64);
    put_u64(&mut header, generation.index.postings().len() as u64);
    put_u64(&mut header, posting_record_count as u64);
    put_u64(&mut header, generation.controls.len() as u64);
    put_u64(&mut header, terminal_count as u64);
    put_u64(&mut header, title_tokens as u64);
    put_u64(&mut header, body_tokens as u64);
    put_u32(&mut header, SECTION_COUNT as u32);
    header.extend_from_slice(&[0; 4]);
    let mut offset = HEADER_BYTES as u64;
    for (section, record_count) in sections.iter().zip(section_counts) {
        put_u64(&mut header, offset);
        put_u64(&mut header, section.len() as u64);
        put_u64(&mut header, record_count as u64);
        header.extend_from_slice(&sha256(section));
        offset = offset
            .checked_add(section.len() as u64)
            .ok_or(StorageError::CapacityExceeded("section offset overflow"))?;
    }
    header.extend_from_slice(&[0; 4]);
    if header.len() != 416 {
        return Err(corrupt("generation header prefix has an invalid size"));
    }
    header.extend_from_slice(&sha256(&header));
    if header.len() != HEADER_BYTES {
        return Err(corrupt("generation header has an invalid size"));
    }

    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&header);
    for section in sections {
        bytes.extend_from_slice(&section);
    }
    Ok(bytes)
}

#[cfg(test)]
fn encode_documents(
    index: &InMemoryIndex,
    maximum: usize,
) -> Result<(Vec<u8>, usize, usize), StorageError> {
    let mut encoder = Encoder::new(maximum);
    let mut title_tokens = 0usize;
    let mut body_tokens = 0usize;
    for (id, document) in index.documents() {
        validate_url_key(id)?;
        if id != &document.id {
            return Err(corrupt("document table key differs from record identity"));
        }
        let id_bytes = id.as_bytes();
        let effective_bytes = document.effective_url.as_bytes();
        let title_bytes = document.title.as_bytes();
        let body_bytes = document.body.as_bytes();
        if id_bytes.len() > MAX_URL_KEY_BYTES
            || effective_bytes.len() > MAX_EFFECTIVE_URL_BYTES
            || title_bytes.len() > MAX_TITLE_BYTES
            || title_bytes.len().saturating_add(body_bytes.len()) > MAX_FIELDS_BYTES
        {
            return Err(StorageError::CapacityExceeded("document field byte limit"));
        }
        let version = decode_version_id(&document.version_id)?;
        encoder.u16(to_u16(id_bytes.len(), "URL key length")?)?;
        encoder.u16(to_u16(effective_bytes.len(), "effective URL length")?)?;
        encoder.u32(to_u32(title_bytes.len(), "title length")?)?;
        encoder.u32(to_u32(body_bytes.len(), "body length")?)?;
        encoder.u32(to_u32(document.title_terms.len(), "title token count")?)?;
        encoder.u32(to_u32(document.body_terms.len(), "body token count")?)?;
        encoder.bytes(&version)?;
        encoder.bytes(id_bytes)?;
        encoder.bytes(effective_bytes)?;
        encoder.bytes(title_bytes)?;
        encoder.bytes(body_bytes)?;
        title_tokens = title_tokens
            .checked_add(document.title_terms.len())
            .ok_or(StorageError::CapacityExceeded("title token total overflow"))?;
        body_tokens = body_tokens
            .checked_add(document.body_terms.len())
            .ok_or(StorageError::CapacityExceeded("body token total overflow"))?;
    }
    Ok((encoder.finish(), title_tokens, body_tokens))
}

#[cfg(test)]
fn encode_terms(index: &InMemoryIndex, maximum: usize) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    let mut ordinals = BTreeMap::new();
    for (ordinal, id) in index.documents().keys().enumerate() {
        ordinals.insert(
            id.as_str(),
            u32::try_from(ordinal)
                .map_err(|_| StorageError::CapacityExceeded("document ordinal"))?,
        );
    }

    let mut posting_encoder = Encoder::new(maximum);
    let mut descriptors = Vec::with_capacity(index.postings().len());
    for (term, by_document) in index.postings() {
        if term.chars().count() > MAX_TERM_SCALARS || term.len() > MAX_TERM_SCALARS * 4 {
            return Err(StorageError::CapacityExceeded("term length"));
        }
        if by_document.is_empty() {
            return Err(corrupt("empty term posting list"));
        }
        let offset = posting_encoder.len();
        posting_encoder.u32(to_u32(by_document.len(), "posting count")?)?;
        let mut title_df = 0u32;
        let mut body_df = 0u32;
        for (id, posting) in by_document {
            let ordinal = ordinals
                .get(id.as_str())
                .copied()
                .ok_or_else(|| corrupt("posting references an absent document"))?;
            posting_encoder.u32(ordinal)?;
            posting_encoder.u32(to_u32(posting.title_positions.len(), "title positions")?)?;
            posting_encoder.u32(to_u32(posting.body_positions.len(), "body positions")?)?;
            if !posting.title_positions.is_empty() {
                title_df = title_df
                    .checked_add(1)
                    .ok_or(StorageError::CapacityExceeded("title df overflow"))?;
            }
            if !posting.body_positions.is_empty() {
                body_df = body_df
                    .checked_add(1)
                    .ok_or(StorageError::CapacityExceeded("body df overflow"))?;
            }
            for position in posting
                .title_positions
                .iter()
                .chain(&posting.body_positions)
            {
                posting_encoder.u32(*position)?;
            }
        }
        descriptors.push((
            term,
            title_df,
            body_df,
            to_u32(by_document.len(), "posting count")?,
            offset,
            posting_encoder.len() - offset,
        ));
    }

    let posting_bytes = posting_encoder.finish();
    let dictionary_maximum = maximum
        .checked_sub(posting_bytes.len())
        .ok_or(StorageError::CapacityExceeded("generation byte limit"))?;
    let mut dictionary_encoder = Encoder::new(dictionary_maximum);
    for (term, title_df, body_df, count, offset, length) in descriptors {
        let term_bytes = term.as_bytes();
        dictionary_encoder.u16(to_u16(term_bytes.len(), "term byte length")?)?;
        dictionary_encoder.u16(0)?;
        dictionary_encoder.u32(title_df)?;
        dictionary_encoder.u32(body_df)?;
        dictionary_encoder.u32(count)?;
        dictionary_encoder.u32(0)?;
        dictionary_encoder.u64(offset as u64)?;
        dictionary_encoder.u64(length as u64)?;
        dictionary_encoder.bytes(term_bytes)?;
    }
    Ok((dictionary_encoder.finish(), posting_bytes))
}

#[cfg(test)]
fn encode_controls(
    controls: &BTreeMap<UrlKey, DocumentControl>,
    maximum: usize,
) -> Result<Vec<u8>, StorageError> {
    let mut encoder = Encoder::new(maximum);
    for (key, control) in controls {
        let key_bytes = key.as_str().as_bytes();
        validate_url_key(key.as_str())?;
        if control.high_water == 0 {
            return Err(corrupt("control record has no issued fence"));
        }
        encoder.u16(to_u16(key_bytes.len(), "control URL key length")?)?;
        encoder.u64(control.high_water)?;
        encoder.u32(to_u32(control.terminal.len(), "terminal count")?)?;
        encoder.u32(to_u32(control.policy.len(), "policy count")?)?;
        encoder.bytes(key_bytes)?;
        for (fence, intent) in &control.terminal {
            encoder.u64(*fence)?;
            match intent {
                TerminalIntent::Upsert(version) => {
                    encoder.u8(1)?;
                    encoder.bytes(&[0; 7])?;
                    encoder.bytes(version)?;
                }
                TerminalIntent::Tombstone => {
                    encoder.u8(2)?;
                    encoder.bytes(&[0; 7])?;
                    encoder.bytes(&[0; 32])?;
                }
            }
        }
        for (fence, event) in &control.policy {
            encoder.u64(*fence)?;
            encoder.u8(match event {
                PolicyEvent::Revoked => 1,
                PolicyEvent::Readmitted => 2,
            })?;
            encoder.bytes(&[0; 7])?;
        }
    }
    Ok(encoder.finish())
}

#[cfg(test)]
struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

#[cfg(test)]
impl Encoder {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn append(&mut self, value: &[u8]) -> Result<(), StorageError> {
        let new_len =
            self.bytes
                .len()
                .checked_add(value.len())
                .ok_or(StorageError::CapacityExceeded(
                    "encoded section length overflow",
                ))?;
        if new_len > self.maximum {
            return Err(StorageError::CapacityExceeded("encoded section byte limit"));
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), StorageError> {
        self.append(value)
    }

    fn u8(&mut self, value: u8) -> Result<(), StorageError> {
        self.append(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), StorageError> {
        self.append(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), StorageError> {
        self.append(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), StorageError> {
        self.append(&value.to_be_bytes())
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn decode_generation(
    bytes: &[u8],
    expected_store_id: StoreId,
    expected_generation_id: u64,
) -> Result<Generation, StorageError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_GENERATION_BYTES {
        return Err(corrupt("generation byte length is outside format bounds"));
    }
    if &bytes[..8] != GENERATION_MAGIC {
        return Err(corrupt("generation magic mismatch"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
        return Err(StorageError::UnsupportedFormat { major, minor });
    }
    if get_u32(bytes, 12)? as usize != HEADER_BYTES || get_u32(bytes, 16)? != 0 {
        return Err(corrupt("generation header size or flags are invalid"));
    }
    if bytes[20..36] != expected_store_id {
        return Err(corrupt("generation belongs to a different store"));
    }
    let generation_id = get_u64(bytes, 36)?;
    let parent_id = get_u64(bytes, 44)?;
    if generation_id != expected_generation_id
        || generation_id == 0
        || (generation_id == 1 && parent_id != 0)
        || (generation_id > 1 && parent_id.checked_add(1) != Some(generation_id))
    {
        return Err(corrupt("generation identity sequence is invalid"));
    }
    if bytes[52..84] != sha256(HTML_SCHEMA_ID.as_bytes())
        || bytes[84..116] != sha256(ANALYZER_ID.as_bytes())
    {
        return Err(StorageError::ReindexRequired(
            "HTML schema or analyzer identity changed".to_owned(),
        ));
    }
    if get_u64(bytes, 116)? != bytes.len() as u64 {
        return Err(corrupt("generation header length differs from file length"));
    }
    let document_count = bounded_count(get_u64(bytes, 124)?, MAX_DOCUMENTS, "document count")?;
    let term_count = bounded_count(get_u64(bytes, 132)?, MAX_TERMS, "term count")?;
    let posting_record_count = bounded_count(
        get_u64(bytes, 140)?,
        MAX_POSTING_RECORDS,
        "posting record count",
    )?;
    let control_count = bounded_count(get_u64(bytes, 148)?, MAX_CONTROL_KEYS, "control count")?;
    let terminal_count = bounded_count(
        get_u64(bytes, 156)?,
        MAX_TERMINAL_INTENTS,
        "terminal intent count",
    )?;
    let title_token_total = get_u64(bytes, 164)?;
    let body_token_total = get_u64(bytes, 172)?;
    if get_u32(bytes, 180)? as usize != SECTION_COUNT
        || bytes[184..188] != [0; 4]
        || bytes[412..416] != [0; 4]
    {
        return Err(corrupt(
            "generation section count or reserved bytes are invalid",
        ));
    }
    if sha256(&bytes[..416]) != bytes[416..448] {
        return Err(corrupt("generation header checksum mismatch"));
    }

    let expected_counts = [
        document_count,
        term_count,
        posting_record_count,
        control_count,
    ];
    let mut descriptors = Vec::with_capacity(SECTION_COUNT);
    let mut next_offset = HEADER_BYTES as u64;
    for (section, expected_count) in expected_counts.into_iter().enumerate() {
        let position = 188 + section * DESCRIPTOR_BYTES;
        let offset = get_u64(bytes, position)?;
        let length = get_u64(bytes, position + 8)?;
        let record_count = bounded_count(
            get_u64(bytes, position + 16)?,
            match section {
                0 => MAX_DOCUMENTS,
                1 => MAX_TERMS,
                2 => MAX_POSTING_RECORDS,
                _ => MAX_CONTROL_KEYS,
            },
            "section record count",
        )?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| corrupt("section offset overflow"))?;
        if offset != next_offset || end > bytes.len() as u64 || record_count != expected_count {
            return Err(corrupt("section layout or record count is invalid"));
        }
        let start_usize =
            usize::try_from(offset).map_err(|_| corrupt("section offset overflow"))?;
        let end_usize = usize::try_from(end).map_err(|_| corrupt("section end overflow"))?;
        let section_bytes = &bytes[start_usize..end_usize];
        if sha256(section_bytes) != bytes[position + 24..position + 56] {
            return Err(corrupt("section checksum mismatch"));
        }
        descriptors.push((start_usize, end_usize, record_count));
        next_offset = end;
    }
    if next_offset != bytes.len() as u64 {
        return Err(corrupt("section layout does not cover the generation"));
    }

    let mut index = InMemoryIndex::new();
    let mut token_totals = (0u64, 0u64);
    decode_documents(
        &bytes[descriptors[0].0..descriptors[0].1],
        document_count,
        &mut index,
        &mut token_totals,
    )?;
    if token_totals != (title_token_total, body_token_total) {
        return Err(corrupt("live token totals differ from document records"));
    }
    let postings = decode_terms(
        &bytes[descriptors[1].0..descriptors[1].1],
        &bytes[descriptors[2].0..descriptors[2].1],
        term_count,
        posting_record_count,
        &index,
    )?;
    index
        .install_validated_postings(postings)
        .map_err(|error| {
            corrupt(&format!(
                "persisted postings disagree with documents: {error}"
            ))
        })?;
    let controls = decode_controls(
        &bytes[descriptors[3].0..descriptors[3].1],
        control_count,
        terminal_count,
    )?;
    validate_live_controls(&index, &controls)?;

    Ok(Generation {
        id: generation_id,
        parent_id,
        index,
        controls,
    })
}

fn decode_documents(
    bytes: &[u8],
    count: usize,
    index: &mut InMemoryIndex,
    token_totals: &mut (u64, u64),
) -> Result<(), StorageError> {
    let mut reader = Reader::new(bytes);
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let key_len = usize::from(reader.u16()?);
        let effective_len = usize::from(reader.u16()?);
        let title_len = reader.u32()? as usize;
        let body_len = reader.u32()? as usize;
        let title_tokens = reader.u32()? as usize;
        let body_tokens = reader.u32()? as usize;
        let mut version = [0; 32];
        version.copy_from_slice(reader.bytes(32)?);
        if key_len == 0
            || key_len > MAX_URL_KEY_BYTES
            || effective_len == 0
            || effective_len > MAX_EFFECTIVE_URL_BYTES
            || title_len > MAX_TITLE_BYTES
            || title_len
                .checked_add(body_len)
                .is_none_or(|sum| sum > MAX_FIELDS_BYTES)
            || title_tokens
                .checked_add(body_tokens)
                .is_none_or(|sum| sum > MAX_DOCUMENT_TOKENS)
        {
            return Err(corrupt(
                "document field length or token count exceeds bounds",
            ));
        }
        let id = reader.string(key_len)?;
        validate_url_key(&id)?;
        if previous
            .as_ref()
            .is_some_and(|value| value.as_bytes() >= id.as_bytes())
        {
            return Err(corrupt("document keys are not strictly sorted"));
        }
        previous = Some(id.clone());
        let effective_url = reader.string(effective_len)?;
        UrlKey::parse(&effective_url).map_err(|error| corrupt(&error.to_string()))?;
        let title = reader.string(title_len)?;
        let body = reader.string(body_len)?;
        index.upsert_fields(id.clone(), effective_url, title, body)?;
        let document = index
            .documents()
            .get(&id)
            .ok_or_else(|| corrupt("decoded document disappeared"))?;
        if document.title_terms.len() != title_tokens
            || document.body_terms.len() != body_tokens
            || decode_version_id(&document.version_id)? != version
        {
            return Err(corrupt("document token counts or version hash mismatch"));
        }
        token_totals.0 = token_totals
            .0
            .checked_add(title_tokens as u64)
            .ok_or_else(|| corrupt("title token total overflow"))?;
        token_totals.1 = token_totals
            .1
            .checked_add(body_tokens as u64)
            .ok_or_else(|| corrupt("body token total overflow"))?;
    }
    reader.finish("document section has trailing or truncated bytes")
}

#[derive(Clone)]
struct TermDescriptor {
    term: String,
    title_df: u32,
    body_df: u32,
    posting_count: usize,
    offset: usize,
    length: usize,
}

fn decode_terms(
    dictionary: &[u8],
    posting_bytes: &[u8],
    term_count: usize,
    expected_posting_records: usize,
    index: &InMemoryIndex,
) -> Result<BTreeMap<String, BTreeMap<String, crate::index::Posting>>, StorageError> {
    let mut dictionary_reader = Reader::new(dictionary);
    let mut terms = Vec::with_capacity(term_count);
    let mut previous: Option<String> = None;
    let mut posting_total = 0usize;
    for _ in 0..term_count {
        let term_len = usize::from(dictionary_reader.u16()?);
        if dictionary_reader.u16()? != 0 {
            return Err(corrupt("dictionary reserved bytes are nonzero"));
        }
        let title_df = dictionary_reader.u32()?;
        let body_df = dictionary_reader.u32()?;
        let posting_count = dictionary_reader.u32()? as usize;
        if dictionary_reader.u32()? != 0 {
            return Err(corrupt("dictionary reserved count is nonzero"));
        }
        let offset = bounded_count(
            dictionary_reader.u64()?,
            MAX_GENERATION_BYTES,
            "posting offset",
        )?;
        let length = bounded_count(
            dictionary_reader.u64()?,
            MAX_GENERATION_BYTES,
            "posting length",
        )?;
        if term_len == 0 || term_len > MAX_TERM_SCALARS * 4 || posting_count == 0 {
            return Err(corrupt("dictionary term or posting count is invalid"));
        }
        let term = dictionary_reader.string(term_len)?;
        if term.chars().count() > MAX_TERM_SCALARS
            || Analyzer
                .analyze(&term)
                .map_err(|error| corrupt(&error.to_string()))?
                != [term.clone()]
        {
            return Err(corrupt(
                "dictionary term is not one canonical analyzer token",
            ));
        }
        if previous
            .as_ref()
            .is_some_and(|value| value.as_bytes() >= term.as_bytes())
        {
            return Err(corrupt("dictionary terms are not strictly sorted"));
        }
        previous = Some(term.clone());
        posting_total = posting_total
            .checked_add(posting_count)
            .ok_or_else(|| corrupt("posting record count overflow"))?;
        terms.push(TermDescriptor {
            term,
            title_df,
            body_df,
            posting_count,
            offset,
            length,
        });
    }
    dictionary_reader.finish("dictionary section has trailing or truncated bytes")?;
    if posting_total != expected_posting_records {
        return Err(corrupt("dictionary posting counts differ from header"));
    }

    let documents = index.documents().values().collect::<Vec<_>>();
    let mut persisted = BTreeMap::new();
    let mut next_offset = 0usize;
    for descriptor in terms {
        if descriptor.offset != next_offset || descriptor.length == 0 {
            return Err(corrupt("term posting offset or length is invalid"));
        }
        let start = descriptor.offset;
        let end = start
            .checked_add(descriptor.length)
            .filter(|end| *end <= posting_bytes.len())
            .ok_or_else(|| corrupt("term posting range is outside the section"))?;
        let mut records = Reader::new(&posting_bytes[start..end]);
        let count = records.u32()? as usize;
        if count != descriptor.posting_count {
            return Err(corrupt(
                "term posting count differs from its dictionary entry",
            ));
        }
        let mut by_document = BTreeMap::new();
        let mut previous_ordinal = None;
        let mut title_df = 0u32;
        let mut body_df = 0u32;
        for _ in 0..count {
            let ordinal = records.u32()? as usize;
            let title_count = records.u32()? as usize;
            let body_count = records.u32()? as usize;
            if ordinal >= documents.len()
                || previous_ordinal.is_some_and(|previous| previous >= ordinal)
                || title_count
                    .checked_add(body_count)
                    .is_none_or(|sum| sum == 0)
            {
                return Err(corrupt(
                    "posting document ordinal or position count is invalid",
                ));
            }
            previous_ordinal = Some(ordinal);
            let document = documents[ordinal];
            let title_positions =
                decode_positions(&mut records, title_count, document.title_terms.len())?;
            let body_positions =
                decode_positions(&mut records, body_count, document.body_terms.len())?;
            if !title_positions.is_empty() {
                title_df = title_df
                    .checked_add(1)
                    .ok_or_else(|| corrupt("title document frequency overflow"))?;
            }
            if !body_positions.is_empty() {
                body_df = body_df
                    .checked_add(1)
                    .ok_or_else(|| corrupt("body document frequency overflow"))?;
            }
            by_document.insert(
                document.id.clone(),
                crate::index::Posting {
                    title_positions,
                    body_positions,
                },
            );
        }
        records.finish("term posting record has trailing or truncated bytes")?;
        if title_df != descriptor.title_df || body_df != descriptor.body_df {
            return Err(corrupt("dictionary field document frequencies are invalid"));
        }
        next_offset = end;
        persisted.insert(descriptor.term, by_document);
    }
    if next_offset != posting_bytes.len() {
        return Err(corrupt("posting section has unreferenced trailing bytes"));
    }
    Ok(persisted)
}

fn decode_positions(
    reader: &mut Reader<'_>,
    count: usize,
    token_count: usize,
) -> Result<Vec<u32>, StorageError> {
    if count > MAX_DOCUMENT_TOKENS {
        return Err(corrupt("posting position count exceeds document limit"));
    }
    let mut positions = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let position = reader.u32()?;
        if position as usize >= token_count || previous.is_some_and(|value| value >= position) {
            return Err(corrupt("posting positions are unordered or out of range"));
        }
        previous = Some(position);
        positions.push(position);
    }
    Ok(positions)
}

fn decode_controls(
    bytes: &[u8],
    control_count: usize,
    expected_terminal_count: usize,
) -> Result<BTreeMap<UrlKey, DocumentControl>, StorageError> {
    let mut reader = Reader::new(bytes);
    let mut controls = BTreeMap::new();
    let mut previous_key: Option<String> = None;
    let mut total_terminal = 0usize;
    let mut total_policy = 0usize;
    for _ in 0..control_count {
        let key_len = usize::from(reader.u16()?);
        let high_water = reader.u64()?;
        let terminal_count = reader.u32()? as usize;
        let policy_count = reader.u32()? as usize;
        if key_len == 0 || key_len > MAX_URL_KEY_BYTES || high_water == 0 {
            return Err(corrupt("control key or fence high-water is invalid"));
        }
        total_terminal = total_terminal
            .checked_add(terminal_count)
            .ok_or_else(|| corrupt("terminal intent count overflow"))?;
        total_policy = total_policy
            .checked_add(policy_count)
            .ok_or_else(|| corrupt("policy event count overflow"))?;
        if total_terminal > MAX_TERMINAL_INTENTS
            || total_policy > MAX_TERMINAL_INTENTS
            || terminal_count > MAX_TERMINAL_INTENTS
        {
            return Err(corrupt("control history exceeds its bound"));
        }
        let key_text = reader.string(key_len)?;
        validate_url_key(&key_text)?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous.as_bytes() >= key_text.as_bytes())
        {
            return Err(corrupt("control keys are not strictly sorted"));
        }
        previous_key = Some(key_text.clone());
        let key =
            UrlKey::parse(&key_text).map_err(|error| StorageError::UrlKey(error.to_string()))?;
        let mut control = DocumentControl {
            high_water,
            terminal: BTreeMap::new(),
            policy: BTreeMap::new(),
        };
        let mut previous_fence = 0u64;
        for _ in 0..terminal_count {
            let fence = reader.u64()?;
            let kind = reader.u8()?;
            if reader.bytes(7)? != [0; 7] || fence <= previous_fence || fence > high_water {
                return Err(corrupt(
                    "terminal fence order or reserved bytes are invalid",
                ));
            }
            previous_fence = fence;
            let mut version = [0; 32];
            version.copy_from_slice(reader.bytes(32)?);
            let intent = match kind {
                1 => TerminalIntent::Upsert(version),
                2 if version == [0; 32] => TerminalIntent::Tombstone,
                2 => return Err(corrupt("tombstone has a nonzero version field")),
                _ => return Err(corrupt("unknown terminal intent kind")),
            };
            control.terminal.insert(fence, intent);
        }
        previous_fence = 0;
        for _ in 0..policy_count {
            let fence = reader.u64()?;
            let kind = reader.u8()?;
            if reader.bytes(7)? != [0; 7] || fence <= previous_fence || fence > high_water {
                return Err(corrupt("policy fence order or reserved bytes are invalid"));
            }
            previous_fence = fence;
            let event = match kind {
                1 => PolicyEvent::Revoked,
                2 => PolicyEvent::Readmitted,
                _ => return Err(corrupt("unknown policy event kind")),
            };
            control.policy.insert(fence, event);
        }
        controls.insert(key, control);
    }
    reader.finish("control section has trailing or truncated bytes")?;
    if total_terminal != expected_terminal_count {
        return Err(corrupt("terminal intent total differs from header"));
    }
    validate_control_history(&controls)?;
    Ok(controls)
}

fn validate_control_history(
    controls: &BTreeMap<UrlKey, DocumentControl>,
) -> Result<(), StorageError> {
    for control in controls.values() {
        let mut terminal = control.terminal.iter().peekable();
        let mut policy = control.policy.iter().peekable();
        let mut revoked = false;

        loop {
            match (terminal.peek(), policy.peek()) {
                (Some((terminal_fence, _)), Some((policy_fence, _))) => {
                    match terminal_fence.cmp(policy_fence) {
                        std::cmp::Ordering::Less => {
                            if revoked {
                                return Err(corrupt("terminal intent occurs while URL is revoked"));
                            }
                            terminal.next();
                        }
                        std::cmp::Ordering::Greater => {
                            let (_, event) = policy.next().ok_or_else(|| {
                                corrupt("policy history changed during validation")
                            })?;
                            match event {
                                PolicyEvent::Revoked => {
                                    return Err(corrupt(
                                        "revocation lacks a tombstone at the same fence",
                                    ));
                                }
                                PolicyEvent::Readmitted if revoked => revoked = false,
                                PolicyEvent::Readmitted => {
                                    return Err(corrupt("readmission has no revoked interval"));
                                }
                            }
                        }
                        std::cmp::Ordering::Equal => {
                            let (_, intent) = terminal.next().ok_or_else(|| {
                                corrupt("terminal history changed during validation")
                            })?;
                            let (_, event) = policy.next().ok_or_else(|| {
                                corrupt("policy history changed during validation")
                            })?;
                            if revoked
                                || *intent != TerminalIntent::Tombstone
                                || *event != PolicyEvent::Revoked
                            {
                                return Err(corrupt(
                                    "only a unique revoke tombstone may share a fence",
                                ));
                            }
                            revoked = true;
                        }
                    }
                }
                (Some(_), None) => {
                    if revoked {
                        return Err(corrupt("terminal intent occurs while URL is revoked"));
                    }
                    terminal.next();
                }
                (None, Some(_)) => {
                    let (_, event) = policy
                        .next()
                        .ok_or_else(|| corrupt("policy history changed during validation"))?;
                    match event {
                        PolicyEvent::Revoked => {
                            return Err(corrupt("revocation lacks a tombstone at the same fence"));
                        }
                        PolicyEvent::Readmitted if revoked => revoked = false,
                        PolicyEvent::Readmitted => {
                            return Err(corrupt("readmission has no revoked interval"));
                        }
                    }
                }
                (None, None) => break,
            }
        }
    }
    Ok(())
}

fn validate_live_controls(
    index: &InMemoryIndex,
    controls: &BTreeMap<UrlKey, DocumentControl>,
) -> Result<(), StorageError> {
    let live_ids = index
        .documents()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (id, document) in index.documents() {
        let key = UrlKey::parse(id).map_err(|error| corrupt(&error.to_string()))?;
        let control = controls
            .get(&key)
            .ok_or_else(|| corrupt("live document has no lifecycle control"))?;
        if is_revoked(control) {
            return Err(corrupt("revoked document is present in the live view"));
        }
        let latest = control.terminal.last_key_value().map(|(_, intent)| intent);
        if latest
            != Some(&TerminalIntent::Upsert(decode_version_id(
                &document.version_id,
            )?))
        {
            return Err(corrupt(
                "live document differs from latest terminal version",
            ));
        }
    }
    for key in controls.keys() {
        if control_has_live_upsert(&controls[key]) && !live_ids.contains(key.as_str()) {
            return Err(corrupt("latest upsert is absent from the live view"));
        }
    }
    Ok(())
}

fn control_has_live_upsert(control: &DocumentControl) -> bool {
    !is_revoked(control)
        && matches!(
            control.terminal.last_key_value().map(|(_, value)| value),
            Some(TerminalIntent::Upsert(_))
        )
}

fn random_store_id() -> Result<StoreId, StorageError> {
    let mut source = File::open("/dev/urandom")?;
    let mut store_id = [0; 16];
    source.read_exact(&mut store_id)?;
    Ok(store_id)
}

fn random_lease_mac_key() -> Result<LeaseMacKey, StorageError> {
    let mut source = File::open("/dev/urandom")?;
    let mut mac_key = [0; 32];
    source.read_exact(&mut mac_key)?;
    Ok(mac_key)
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(corrupt("storage path is not a regular file"));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| corrupt("file length overflow"))?;
    if length > maximum {
        return Err(corrupt("storage file exceeds its byte limit"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(corrupt("opened storage path is not a regular file"));
    }
    let read_limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::with_capacity(length);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(corrupt("storage file length changed while reading"));
    }
    Ok(bytes)
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = create_private_file_handle(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_private_file_atomically(
    destination: &Path,
    temporary: &Path,
    bytes: &[u8],
) -> Result<(), StorageError> {
    match fs::symlink_metadata(temporary) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(temporary)?;
        }
        Ok(_) => return Err(corrupt("public collection temporary path is not a file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = create_private_file_handle(temporary)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, destination)?;
    let directory = destination
        .parent()
        .ok_or_else(|| corrupt("public collection file has no parent directory"))?;
    sync_directory(directory)
}

fn create_private_file_handle(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn create_store_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(StorageError::UnsupportedPlatform)
    }
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(target_os = "linux")]
    {
        File::open(path)?.sync_all()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(StorageError::UnsupportedPlatform)
    }
}

fn generation_name(generation_id: u64) -> String {
    format!("gen-{generation_id}.ley")
}

#[cfg(test)]
fn generation_temp_name(generation_id: u64) -> String {
    format!(".gen-{generation_id}.tmp")
}

#[cfg(test)]
fn parse_generation_name(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let id = digits.parse::<u64>().ok()?;
    (id.to_string() == digits).then_some(id)
}

#[cfg(test)]
fn cleanup_owned_files(path: &Path, current: Option<&Generation>) -> Result<(), StorageError> {
    let mut removed = false;
    let keep = current.map(|generation| (generation.id, generation.parent_id));
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_dir() {
            continue;
        }
        let stale_temp =
            name == ".CURRENT.tmp" || parse_generation_name(name, ".gen-", ".tmp").is_some();
        let stale_generation = parse_generation_name(name, "gen-", ".ley").is_some_and(|id| {
            keep.is_none_or(|(current_id, parent_id)| id != current_id && id != parent_id)
        });
        if (stale_temp || stale_generation)
            && (metadata.file_type().is_file() || metadata.file_type().is_symlink())
        {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory(path)?;
    }
    Ok(())
}

fn validate_url_key(value: &str) -> Result<(), StorageError> {
    let parsed = UrlKey::parse(value).map_err(|error| StorageError::UrlKey(error.to_string()))?;
    if parsed.as_str() != value {
        return Err(corrupt("URL key is not in canonical round-trip form"));
    }
    Ok(())
}

fn decode_version_id(value: &str) -> Result<VersionId, StorageError> {
    if value.len() != 64 {
        return Err(corrupt("document version ID has an invalid length"));
    }
    let mut version = [0; 32];
    for (index, byte) in version.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(value.as_bytes()[offset])? << 4)
            | hex_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(version)
}

fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_nibble(byte: u8) -> Result<u8, StorageError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(corrupt("document version ID is not lowercase hexadecimal")),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn system_time_ms() -> Result<u64, StorageError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::ClockUnavailable)?
        .as_millis()
        .min(u64::MAX as u128) as u64)
}

#[cfg(test)]
fn to_u16(value: usize, label: &'static str) -> Result<u16, StorageError> {
    u16::try_from(value).map_err(|_| StorageError::CapacityExceeded(label))
}

#[cfg(test)]
fn to_u32(value: usize, label: &'static str) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::CapacityExceeded(label))
}

fn bounded_count(value: u64, maximum: usize, label: &'static str) -> Result<usize, StorageError> {
    let count = usize::try_from(value).map_err(|_| corrupt(label))?;
    if count > maximum {
        return Err(corrupt(label));
    }
    Ok(count)
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, StorageError> {
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or_else(|| corrupt("offset overflow"))?,
        )
        .ok_or_else(|| corrupt("truncated integer"))?;
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, StorageError> {
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| corrupt("offset overflow"))?,
        )
        .ok_or_else(|| corrupt("truncated integer"))?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, StorageError> {
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(8)
                    .ok_or_else(|| corrupt("offset overflow"))?,
        )
        .ok_or_else(|| corrupt("truncated integer"))?;
    Ok(u64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], StorageError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| corrupt("record offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| corrupt("record is truncated"))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, StorageError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StorageError> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, StorageError> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, StorageError> {
        let bytes = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn string(&mut self, count: usize) -> Result<String, StorageError> {
        let bytes = self.bytes(count)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| corrupt("record string is not valid UTF-8"))
    }

    fn finish(self, message: &'static str) -> Result<(), StorageError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(corrupt(message))
        }
    }
}

fn corrupt(message: &str) -> StorageError {
    StorageError::CorruptCommitted(message.to_owned())
}

fn validate_managed_reservation(
    reservation: &ManagedReservation,
) -> Result<(), ManagedStorageError> {
    if reservation.base_generation == 0
        || reservation.sync_id.len() != 32
        || !reservation
            .sync_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManagedStorageError::Conflict);
    }
    Ok(())
}

fn validate_store_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(corrupt("store path is not a directory"));
    }
    let lock_path = path.join(LOCK_NAME);
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    if !lock_metadata.file_type().is_file() {
        return Err(corrupt("LOCK is not a regular file"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct FileLock(File);

#[cfg(target_os = "linux")]
impl FileLock {
    fn new(path: &Path, exclusive: bool) -> Result<Self, StorageError> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options.open(path)?;
        let operation = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        loop {
            // SAFETY: `file` owns a live descriptor for LOCK for the duration of this guard.
            let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), operation) };
            if result == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }

    fn new_shared_read_only(path: &Path) -> Result<Self, StorageError> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        loop {
            // SAFETY: `file` owns a read-only descriptor for LOCK while shared flock is held.
            let result =
                unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_SH) };
            if result == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains owned by this guard until after Drop completes.
        let _ = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN) };
    }
}

#[cfg(not(target_os = "linux"))]
struct FileLock;

#[cfg(not(target_os = "linux"))]
impl FileLock {
    fn new(_path: &Path, _exclusive: bool) -> Result<Self, StorageError> {
        Err(StorageError::UnsupportedPlatform)
    }

    fn new_shared_read_only(_path: &Path) -> Result<Self, StorageError> {
        Err(StorageError::UnsupportedPlatform)
    }
}

#[cfg(all(target_os = "linux", test))]
fn storage_failpoint(name: &str) {
    if std::env::var("LEY_STORAGE_FAILPOINT").as_deref() == Ok(name) {
        std::process::exit(86);
    }
}

#[cfg(any(not(target_os = "linux"), not(test)))]
fn storage_failpoint(_name: &str) {}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use crate::index::StatisticsSource;
    use crate::query::parse_query;

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    type CorruptionCase = Box<dyn FnOnce(&TempStore)>;

    struct TempStore(PathBuf);

    impl TempStore {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("ley-storage-test-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(self.0.with_extension("expected"));
            let _ = fs::remove_file(self.0.with_extension("leases"));
        }
    }

    fn key(path: &str) -> UrlKey {
        UrlKey::parse(&format!("https://example.test/{path}")).unwrap()
    }

    fn public_gate(
        notice: &[u8],
        installed_at_ms: u64,
        visible_until_ms: u64,
    ) -> PublicCollectionGate {
        PublicCollectionGate {
            policy_sha256: "a".repeat(64),
            source_id: "rust-stdlib-docs-candidate".to_owned(),
            origin: "https://doc.rust-lang.org".to_owned(),
            path_prefixes: vec!["/stable/std/string/struct.String.html".to_owned()],
            installed_at_ms,
            visible_until_ms,
            license: "MIT".to_owned(),
            source_version: "rustdoc test fixture".to_owned(),
            notice_file: PUBLIC_NOTICE_STORE_BASENAME.to_owned(),
            notice_sha256: sha256(notice)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            fetch_permission: None,
            storage_permission: None,
            index_permission: None,
            display_permission: None,
            removal_contact: None,
        }
    }

    #[test]
    fn public_collection_expiry_is_durable_and_repeated_install_does_not_extend_it() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let notice = b"full source license notice";
        let gate = public_gate(notice, 10, 40);
        store
            .install_public_collection_gate(&gate, notice, 10)
            .unwrap();

        let document =
            UrlKey::parse("https://doc.rust-lang.org/stable/std/string/struct.String.html")
                .unwrap();
        let lease = store.issue_fence(&document).unwrap();
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: document.as_str().to_owned(),
                    title: "Rust string".to_owned(),
                    body: "rust collection retention".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            fs::read(store.path.join(PUBLIC_NOTICE_STORE_BASENAME)).unwrap(),
            notice
        );
        assert_eq!(
            store
                .read_view_at(39)
                .unwrap()
                .query_at("rust", 39)
                .unwrap()
                .len(),
            1
        );

        let reopened = PersistentIndex::open(store.path.clone()).unwrap();
        let proposed_later_deadline = public_gate(notice, 20, 50);
        reopened
            .install_public_collection_gate(&proposed_later_deadline, notice, 20)
            .unwrap();
        assert_eq!(
            reopened
                .read_view_at(39)
                .unwrap()
                .query_at("rust", 39)
                .unwrap()
                .len(),
            1
        );
        let pinned_before_expiry = reopened.read_view_at(39).unwrap();
        assert!(matches!(
            pinned_before_expiry.query_at("rust", 40),
            Err(StorageError::PublicCollectionExpired)
        ));
        assert!(matches!(
            reopened.read_view_at(40),
            Err(StorageError::PublicCollectionExpired)
        ));
        fs::remove_file(reopened.path.join(PUBLIC_COLLECTION_NAME)).unwrap();
        assert!(matches!(
            reopened.read_view_at(39),
            Err(StorageError::CorruptCommitted(_))
        ));
    }

    #[test]
    fn public_collection_gate_cannot_be_added_after_documents_are_visible() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("fixture");
        let lease = store.issue_fence(&document).unwrap();
        store
            .apply(
                &lease,
                Intent::Upsert {
                    effective_url: document.as_str().to_owned(),
                    title: "local fixture".to_owned(),
                    body: "local content".to_owned(),
                },
            )
            .unwrap();
        let notice = b"full source license notice";
        assert!(matches!(
            store.install_public_collection_gate(&public_gate(notice, 10, 40), notice, 10),
            Err(StorageError::PublicCollectionConflict)
        ));
    }

    #[test]
    fn public_collection_persists_custom_terms_and_permission_evidence() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let notice = b"Publisher terms notice, authored storage fixture.\n";
        let mut gate = public_gate(notice, 10, 40);
        gate.license = "Publisher terms, reviewed offline".to_owned();
        gate.notice_file = "source-notice.txt".to_owned();
        let permission = || PublicPermissionEvidence {
            granted: true,
            basis: "authored storage fixture only".to_owned(),
            evidence: "not a real permission grant".to_owned(),
            reviewed_at_ms: 1,
        };
        gate.fetch_permission = Some(permission());
        gate.storage_permission = Some(permission());
        gate.index_permission = Some(permission());
        gate.display_permission = Some(permission());
        gate.removal_contact = Some("operator@example.org".to_owned());

        store
            .install_public_collection_gate(&gate, notice, 10)
            .unwrap();
        assert_eq!(
            fs::read(store.path.join(PUBLIC_NOTICE_STORE_BASENAME)).unwrap(),
            notice
        );
        let restored = {
            let _lock = store.lock_shared().unwrap();
            store.load_public_collection_locked().unwrap().unwrap()
        };
        assert_eq!(restored, gate);
        assert_eq!(restored.license, "Publisher terms, reviewed offline");
    }

    #[test]
    fn public_collection_preflight_rejects_gate_larger_than_record_budget() {
        let notice = b"Publisher terms notice.\n";
        let mut gate = public_gate(notice, 10, 40);
        gate.path_prefixes = (0..64)
            .map(|index| format!("/{}-{index}", "x".repeat(2000)))
            .collect();
        assert!(validate_public_collection_admission(&gate, notice).is_err());
    }

    fn write_lease_bundle(root: &Path, leases: &[Vec<u8>]) {
        let mut bytes = Vec::new();
        put_u16(&mut bytes, u16::try_from(leases.len()).unwrap());
        for lease in leases {
            put_u16(&mut bytes, u16::try_from(lease.len()).unwrap());
            bytes.extend_from_slice(lease);
        }
        fs::write(root.with_extension("leases"), bytes).unwrap();
    }

    fn read_lease_bundle(root: &Path) -> Vec<Vec<u8>> {
        let bytes = fs::read(root.with_extension("leases")).unwrap();
        let mut reader = Reader::new(&bytes);
        let count = usize::from(reader.u16().unwrap());
        assert!(count <= 16);
        let mut leases = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(reader.u16().unwrap());
            assert!(length <= MAX_LEASE_TOKEN_BYTES);
            leases.push(reader.bytes(length).unwrap().to_vec());
        }
        reader.finish("lease bundle has trailing bytes").unwrap();
        leases
    }

    fn lifecycle_expected_index() -> InMemoryIndex {
        let mut index = InMemoryIndex::new();
        for (path, title, body) in [
            ("alpha", "Twin Blue", "red blue common phrase"),
            ("beta", "Twin Blue", "red blue common phrase"),
            ("sentinel", "Twin Red", "red blue sentinel phrase"),
            ("updated", "Twin Green", "red blue current"),
            ("empty", "", ""),
        ] {
            let id = key(path).to_string();
            index
                .insert_fields(id.clone(), id, title.to_owned(), body.to_owned())
                .unwrap();
        }
        index
    }

    fn assert_reference_view(view: &ReadView, expected: &InMemoryIndex, queries: &[&str]) {
        for expression in queries {
            let actual = view.query(expression).unwrap();
            let mut expected_results = expected.query(expression).unwrap();
            for result in &mut expected_results {
                result.explanation.statistics_source =
                    StatisticsSource::PersistentGeneration(view.generation_id());
            }
            assert_eq!(actual, expected_results, "full results for {expression:?}");

            let parsed = parse_query(expression).unwrap();
            let reference = crate::reference::exhaustive_search(expected, &parsed);
            assert_eq!(
                actual.len(),
                reference.len(),
                "reference count for {expression:?}"
            );
            let mut reference_results = reference
                .iter()
                .map(|hit| hit.result.clone())
                .collect::<Vec<_>>();
            for result in &mut reference_results {
                result.explanation.statistics_source =
                    StatisticsSource::PersistentGeneration(view.generation_id());
            }
            assert_eq!(
                actual, reference_results,
                "full independent result for {expression:?}"
            );
            for (actual, reference) in actual.iter().zip(&reference) {
                assert_eq!(
                    actual.id, reference.id,
                    "reference match for {expression:?}"
                );
                assert!((actual.score - reference.score).abs() < 1e-12);
                assert_eq!(actual.score, actual.explanation.total_score);
            }
        }
    }

    fn assert_lifecycle_statistics(view: &ReadView) {
        assert_eq!(view.document_count(), 5);
        let twin = view.query("twin").unwrap();
        assert_eq!(twin.len(), 4);
        assert!(twin.iter().all(|result| result.score == twin[0].score));
        assert_eq!(
            twin.iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>(),
            [
                "https://example.test/alpha",
                "https://example.test/beta",
                "https://example.test/sentinel",
                "https://example.test/updated",
            ]
        );
        for result in &twin {
            assert_eq!(result.explanation.document_count, 5);
            assert!((result.explanation.average_title_length - 1.6).abs() < 1e-12);
            assert!((result.explanation.average_body_length - 3.0).abs() < 1e-12);
            assert_eq!(
                result.explanation.statistics_source,
                StatisticsSource::PersistentGeneration(view.generation_id())
            );
        }
        let term_stats = |expression: &str, term: &str| {
            view.query(expression)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
                .explanation
                .terms
                .into_iter()
                .find(|stats| stats.term == term)
                .unwrap()
        };
        let twin_df = term_stats("twin", "twin");
        assert_eq!(twin_df.title.document_frequency, 4);
        assert_eq!(twin_df.body.document_frequency, 0);
        let red_df = term_stats("\"red blue\"", "red");
        assert_eq!(red_df.title.document_frequency, 1);
        assert_eq!(red_df.body.document_frequency, 4);
        let blue_df = term_stats("\"red blue\"", "blue");
        assert_eq!(blue_df.title.document_frequency, 2);
        assert_eq!(blue_df.body.document_frequency, 4);
        let current_df = term_stats("twin AND current", "current");
        assert_eq!(current_df.title.document_frequency, 0);
        assert_eq!(current_df.body.document_frequency, 1);
        for removed_term in ["obsolete", "retired", "secret"] {
            let stale_df = term_stats("common OR obsolete OR retired OR secret", removed_term);
            assert_eq!(stale_df.title.document_frequency, 0, "{removed_term}");
            assert_eq!(stale_df.body.document_frequency, 0, "{removed_term}");
        }
        assert!(
            view.query("obsolete OR retired OR secret")
                .unwrap()
                .is_empty()
        );
    }

    fn crash_expected_index(action: &str, committed_new: bool) -> InMemoryIndex {
        let mut index = InMemoryIndex::new();
        let mut add = |path: &str, title: &str, body: &str| {
            let id = key(path).as_str().to_owned();
            index
                .insert_fields(id.clone(), id, title.to_owned(), body.to_owned())
                .unwrap();
        };
        if !(action == "tombstone" && committed_new) {
            if action == "upsert" && committed_new {
                add("crash", "Twin Old", "new marker marker");
            } else {
                add("crash", "Twin Old", "old marker");
            }
        }
        add("sentinel", "Twin Sentinel", "old marker sentinel");
        index
    }

    fn assert_crash_view(store: &PersistentIndex, action: &str, committed_new: bool) {
        let view = store.read_view().unwrap();
        let expected = crash_expected_index(action, committed_new);
        let queries = [
            "twin",
            "old",
            "new",
            "sentinel",
            "\"old marker\"",
            "twin AND sentinel",
            "old OR new",
        ];
        assert_reference_view(&view, &expected, &queries);
        assert_eq!(view.document_count(), expected.len());
        let twin = view.query("twin").unwrap();
        let expected_twin_df = if action == "tombstone" && committed_new {
            1
        } else {
            2
        };
        let expected_body_average = if committed_new && matches!(action, "upsert" | "tombstone") {
            3.0
        } else {
            2.5
        };
        for result in twin {
            assert_eq!(result.explanation.document_count, expected.len());
            assert!((result.explanation.average_title_length - 2.0).abs() < 1e-12);
            assert!((result.explanation.average_body_length - expected_body_average).abs() < 1e-12);
            assert_eq!(
                result.explanation.terms[0].title.document_frequency,
                expected_twin_df
            );
        }
    }

    fn upsert(
        store: &PersistentIndex,
        key: &UrlKey,
        effective_url: &str,
        title: &str,
        body: &str,
    ) -> FenceLease {
        let lease = store.issue_fence(key).unwrap();
        assert_eq!(
            store
                .apply(
                    &lease,
                    Intent::Upsert {
                        effective_url: effective_url.to_owned(),
                        title: title.to_owned(),
                        body: body.to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::Applied
        );
        lease
    }

    #[test]
    fn ordinary_question_retrieval_is_typed_and_preserves_the_legacy_dsl() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("pam-login-limits");
        upsert(
            &store,
            &document,
            "https://example.test/effective-pam-doc",
            "Linux authentication limits",
            "On Linux, PAM login limits determine sessions for every user.",
        );

        let raw_question = "On our shared Linux server, I need a PAM login limit for each user. Which setting controls it, what does the limit count, and what should happen after a user reaches it?";
        assert!(matches!(
            store.query(raw_question),
            Err(StorageError::Query(QueryError::UnsupportedSyntax))
        ));
        assert!(
            store
                .query(raw_question.trim_end_matches('?'))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.query("PAM AND login").unwrap()[0].id,
            document.as_str()
        );

        let response = store
            .retrieve(RetrievalRequest::question(raw_question))
            .unwrap();
        assert_eq!(response.mode, RetrievalMode::Question);
        assert_eq!(response.status, RetrievalStatus::RetrievedText);
        assert_eq!(response.answer_assessment, AnswerAssessment::NotAssessed);
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].requested_url, document.as_str());
        assert_eq!(
            response.hits[0].effective_url,
            "https://example.test/effective-pam-doc"
        );
        assert!(response.hits[0].matched_terms.contains(&"pam".to_owned()));
        assert_eq!(
            response.hits[0].passage.text,
            "On Linux, PAM login limits determine sessions for every user."
        );

        let no_match = store
            .retrieve(RetrievalRequest::question("quantum foobar"))
            .unwrap();
        assert_eq!(no_match.status, RetrievalStatus::NoRelevantTextMatch);
        assert_eq!(no_match.completeness, RetrievalCompleteness::Complete);

        let no_terms = store
            .retrieve(RetrievalRequest::question("what is the and"))
            .unwrap();
        assert_eq!(
            no_terms.status,
            RetrievalStatus::InsufficientEvidence(InsufficientEvidenceReason::NoSearchableTerms)
        );
        assert!(matches!(
            store.retrieve(RetrievalRequest::question("\"unterminated")),
            Err(RetrievalError::UnterminatedQuote)
        ));
    }

    #[test]
    fn question_retrieval_matches_surface_forms_and_exact_inline_code() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let limits = key("pcre2-limits");
        upsert(
            &store,
            &limits,
            limits.as_str(),
            "PCRE2 pattern limits",
            "The default limit for nesting parenthesized subpatterns is 250.",
        );
        let nested = store
            .retrieve(RetrievalRequest::question(
                "How deeply may I nest parentheses in a PCRE2 pattern by default?",
            ))
            .unwrap();
        let limit_hit = nested
            .hits
            .iter()
            .find(|hit| hit.requested_url == limits.as_str())
            .unwrap();
        assert!(limit_hit.passage.text.contains("nesting"));

        let syntax = key("pcre2-syntax");
        upsert(
            &store,
            &syntax,
            syntax.as_str(),
            "PCRE2 pattern syntax",
            r"In PCRE2, \h matches any horizontal white space character.",
        );
        let code = store
            .retrieve(RetrievalRequest::question(
                r"What does `\h` match in a PCRE2 pattern?",
            ))
            .unwrap();
        let code_hit = code
            .hits
            .iter()
            .find(|hit| hit.requested_url == syntax.as_str())
            .unwrap();
        assert!(code_hit.matched_terms.contains(&"h".to_owned()));
        assert!(code_hit.passage.text.contains(r"\h"));
    }

    #[test]
    fn question_mode_preserves_technical_identifiers_and_exact_quoted_phrases() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let identifier = key("identifier");
        upsert(
            &store,
            &identifier,
            identifier.as_str(),
            "PAM setting",
            "The PAM::MAX_LOGINS setting limits concurrent sessions.",
        );
        let exact = key("exact-phrase");
        upsert(
            &store,
            &exact,
            exact.as_str(),
            "Login failure handling",
            "This page covers failed login attempts.",
        );
        let separated = key("separated-phrase");
        upsert(
            &store,
            &separated,
            separated.as_str(),
            "Another login page",
            "This page covers failed repeated login attempts.",
        );

        let identifier_response = store
            .retrieve(RetrievalRequest::question("What does PAM::MAX_LOGINS do?"))
            .unwrap();
        assert!(
            identifier_response
                .hits
                .iter()
                .any(|hit| hit.requested_url == identifier.as_str())
        );
        assert!(identifier_response.hits.iter().any(|hit| {
            hit.requested_url == identifier.as_str()
                && hit
                    .matched_phrases
                    .contains(&vec!["pam".to_owned(), "max_logins".to_owned()])
        }));

        let quoted = store
            .retrieve(RetrievalRequest::question("\"failed login\""))
            .unwrap();
        assert_eq!(quoted.hits.len(), 1);
        assert_eq!(quoted.hits[0].requested_url, exact.as_str());
        assert_eq!(
            quoted.hits[0].matched_phrases,
            [vec!["failed".to_owned(), "login".to_owned(),]]
        );
        assert_eq!(store.query("\"failed login\"").unwrap().len(), 1);
    }

    #[test]
    fn title_only_matches_are_insufficient_and_passage_cap_reports_partial() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let title_only = key("title-only");
        upsert(
            &store,
            &title_only,
            title_only.as_str(),
            "unique setting",
            "body contains unrelated content only",
        );
        let title_response = store
            .retrieve(RetrievalRequest::question("unique setting"))
            .unwrap();
        assert_eq!(
            title_response.status,
            RetrievalStatus::InsufficientEvidence(InsufficientEvidenceReason::OnlyTitleMatches)
        );
        assert!(title_response.hits.is_empty());

        for index in 0..33 {
            let document = key(&format!("segment-{index}"));
            upsert(
                &store,
                &document,
                document.as_str(),
                "Shared marker",
                "body has unrelated content only",
            );
        }
        let partial = store
            .retrieve(RetrievalRequest::question("shared marker"))
            .unwrap();
        assert_eq!(partial.completeness, RetrievalCompleteness::Partial);
        assert_eq!(
            partial.status,
            RetrievalStatus::InsufficientEvidence(InsufficientEvidenceReason::WorkBudgetReached)
        );
        assert!(partial.hits.is_empty());
    }

    #[test]
    fn question_search_visits_all_small_segments_across_restart() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let target = key("page-39");
        let question = "Where is qzvanta?";

        for index in 0..40 {
            let document = key(&format!("page-{index}"));
            let body = if document == target {
                "The qzvanta control is documented here."
            } else {
                "Routine indexed material for an unrelated page."
            };
            upsert(
                &store,
                &document,
                document.as_str(),
                &format!("Indexed page {index}"),
                body,
            );
        }

        let first = store
            .retrieve(RetrievalRequest::question(question))
            .unwrap();
        assert_eq!(first.completeness, RetrievalCompleteness::Complete);
        assert_eq!(first.status, RetrievalStatus::RetrievedText);
        assert_eq!(first.hits.len(), 1);
        assert_eq!(first.hits[0].requested_url, target.as_str());
        let first_reference = first.hits[0].passage.reference.clone();

        let unrelated = key("later-unrelated");
        upsert(
            &store,
            &unrelated,
            unrelated.as_str(),
            "Unrelated page",
            "Ordinary content without the queried term.",
        );
        drop(store);

        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let after_restart = reopened
            .retrieve(RetrievalRequest::question(question))
            .unwrap();
        assert_eq!(after_restart.completeness, RetrievalCompleteness::Complete);
        assert_eq!(after_restart.status, RetrievalStatus::RetrievedText);
        assert_eq!(after_restart.hits.len(), 1);
        assert_eq!(after_restart.hits[0].requested_url, target.as_str());
        assert_eq!(after_restart.hits[0].passage.reference, first_reference);
    }

    #[test]
    fn evidence_reference_is_stable_across_restart_and_unrelated_generations() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("stable-ref");
        let body = format!(
            "{}Réglage café controls login sessions. End.",
            "Préface café. ".repeat(900)
        );
        upsert(
            &store,
            &document,
            "https://example.test/effective",
            "Cafe",
            &body,
        );
        let response = store
            .retrieve(RetrievalRequest::question("\"café controls\""))
            .unwrap();
        assert_eq!(response.hits.len(), 1);
        let hit = &response.hits[0];
        let reference = hit.passage.reference.clone();
        assert!(reference.start_byte > 0);
        assert!(body.is_char_boundary(reference.end_byte as usize));
        assert_eq!(
            body.get(reference.start_byte as usize..reference.end_byte as usize),
            Some(hit.passage.text.as_str())
        );

        let before = store.read_view().unwrap();
        upsert(
            &store,
            &document,
            "https://example.test/effective-after-redirect",
            "Cafe",
            &body,
        );
        let other = key("unrelated");
        upsert(
            &store,
            &other,
            other.as_str(),
            "Other",
            "unrelated storage generation",
        );
        assert!(store.resolve_evidence(&reference).is_ok());
        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let resolved = reopened.resolve_evidence(&reference).unwrap();
        assert_eq!(resolved.text, hit.passage.text);
        assert_eq!(resolved.requested_url, document.as_str());
        assert_eq!(
            resolved.effective_url,
            "https://example.test/effective-after-redirect"
        );
        assert_eq!(before.generation_id(), response.generation_id);
        assert_ne!(
            reopened.read_view().unwrap().generation_id(),
            response.generation_id
        );
    }

    #[test]
    fn evidence_offsets_are_utf8_body_bytes_and_reject_mid_scalar_ranges() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("utf8-offsets");
        let body = format!(
            "{} café controls after this prefix",
            "padding ".repeat(1200)
        );
        let target = body.find("café").unwrap();
        upsert(&store, &document, document.as_str(), "Unicode", &body);
        let hit = store
            .retrieve(RetrievalRequest::question("\"café controls\""))
            .unwrap()
            .hits
            .remove(0);
        let reference = hit.passage.reference.clone();
        assert!(reference.start_byte > 0);
        assert!(reference.start_byte as usize <= target);
        assert!(reference.end_byte as usize >= target + "café controls".len());
        assert!(body.is_char_boundary(reference.start_byte as usize));
        assert!(body.is_char_boundary(reference.end_byte as usize));
        assert_eq!(
            body.get(reference.start_byte as usize..reference.end_byte as usize),
            Some(hit.passage.text.as_str())
        );

        let invalid_boundary = EvidenceReference::new(
            store.store_id,
            document.to_string(),
            reference.content_version,
            target + 3,
            target + 4,
        )
        .unwrap();
        assert_eq!(
            store.resolve_evidence(&invalid_boundary),
            Err(EvidenceResolveError::NotUtf8Boundary)
        );
    }

    #[test]
    fn document_inspection_pages_are_bounded_utf8_safe_and_version_bound() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("document-inspection-pages");
        let prefix = format!("{}x", "w ".repeat((DOCUMENT_INSPECTION_PAGE_BYTES - 1) / 2));
        assert_eq!(prefix.len(), DOCUMENT_INSPECTION_PAGE_BYTES - 1);
        let body = format!("{prefix}é{}", " tail".repeat(2000));
        upsert(
            &store,
            &document,
            document.as_str(),
            "Long indexed guide",
            &body,
        );
        let reference = store
            .retrieve(RetrievalRequest::question("tail"))
            .unwrap()
            .hits
            .remove(0)
            .passage
            .reference;
        let initial_generation = store.read_view().unwrap().generation_id();

        let first = store.inspect_document_page(&reference, 0).unwrap();
        assert_eq!(first.contract_version, DOCUMENT_INSPECTION_CONTRACT_VERSION);
        assert_eq!(first.reference, reference);
        assert_eq!(first.requested_url, document.as_str());
        assert_eq!(first.title, "Long indexed guide");
        assert_eq!(first.start_byte, 0);
        assert_eq!(first.end_byte as usize, prefix.len());
        assert_eq!(first.total_bytes as usize, body.len());
        assert_eq!(first.next_offset_byte, Some(prefix.len() as u32));
        assert!(first.text.len() <= DOCUMENT_INSPECTION_PAGE_BYTES);
        assert!(first.text.is_char_boundary(first.text.len()));
        assert_eq!(first.text, prefix);

        let second = store
            .inspect_document_page(&reference, first.next_offset_byte.unwrap())
            .unwrap();
        assert_eq!(second.start_byte as usize, prefix.len());
        assert_eq!(second.next_offset_byte, None);
        assert!(second.text.len() <= DOCUMENT_INSPECTION_PAGE_BYTES);
        assert!(second.text.starts_with('é'));
        assert_eq!(format!("{}{}", first.text, second.text), body);

        assert_eq!(
            store.inspect_document_page(&reference, prefix.len() as u32 + 1),
            Err(EvidenceResolveError::NotUtf8Boundary)
        );
        assert_eq!(
            store.inspect_document_page(&reference, u32::MAX),
            Err(EvidenceResolveError::OutOfBounds)
        );
        assert_eq!(
            store.read_view().unwrap().generation_id(),
            initial_generation
        );

        upsert(
            &store,
            &document,
            document.as_str(),
            "Updated guide",
            "replacement content",
        );
        assert_eq!(
            store.inspect_document_page(&reference, 0),
            Err(EvidenceResolveError::VersionSuperseded)
        );
    }

    #[test]
    fn evidence_resolver_rejects_forged_subranges_and_oversized_windows() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("canonical-window");
        let body = "alpha ".repeat(1600);
        upsert(&store, &document, document.as_str(), "Long body", &body);
        let reference = store
            .retrieve(RetrievalRequest::question("alpha"))
            .unwrap()
            .hits[0]
            .passage
            .reference
            .clone();

        let resolved = store.resolve_evidence(&reference).unwrap();
        assert_eq!(resolved.text.len(), crate::retrieval::MAX_PASSAGE_BYTES);

        let forged_subrange = EvidenceReference::new(
            store.store_id,
            document.to_string(),
            reference.content_version,
            1,
            4,
        )
        .unwrap();
        assert_eq!(
            store.resolve_evidence(&forged_subrange),
            Err(EvidenceResolveError::InvalidPassageWindow)
        );

        let forged_oversized = EvidenceReference::new(
            store.store_id,
            document.to_string(),
            reference.content_version,
            0,
            body.len(),
        )
        .unwrap();
        assert_eq!(
            store.resolve_evidence(&forged_oversized),
            Err(EvidenceResolveError::InvalidPassageWindow)
        );

        let descriptor = current_manifest(temp.path()).segments[0].clone();
        let path = temp.path().join(segment_name(descriptor.id));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            store.resolve_evidence(&forged_oversized),
            Err(EvidenceResolveError::InvalidPassageWindow)
        );
    }

    #[test]
    fn evidence_resolver_rejects_wrong_store_superseded_and_out_of_bounds_references() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("reference-errors");
        upsert(
            &store,
            &document,
            document.as_str(),
            "Reference",
            "current evidence text",
        );
        let response = store
            .retrieve(RetrievalRequest::question("current evidence"))
            .unwrap();
        let reference = response.hits[0].passage.reference.clone();

        let other_temp = TempStore::new();
        let other = PersistentIndex::create(other_temp.path()).unwrap();
        assert_eq!(
            other.resolve_evidence(&reference),
            Err(EvidenceResolveError::WrongStore)
        );
        let out_of_bounds = EvidenceReference::new(
            store.store_id,
            reference.requested_url.clone(),
            reference.content_version,
            9000,
            9001,
        )
        .unwrap();
        assert_eq!(
            store.resolve_evidence(&out_of_bounds),
            Err(EvidenceResolveError::OutOfBounds)
        );

        upsert(
            &store,
            &document,
            document.as_str(),
            "Updated reference",
            "superseding content version",
        );
        assert_eq!(
            store.resolve_evidence(&reference),
            Err(EvidenceResolveError::VersionSuperseded)
        );
    }

    #[test]
    fn question_retrieval_and_reference_resolution_fail_closed_on_segment_corruption() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("corrupt-evidence");
        upsert(
            &store,
            &document,
            document.as_str(),
            "Evidence",
            "corruption evidence marker",
        );
        let reference = store
            .retrieve(RetrievalRequest::question("evidence marker"))
            .unwrap()
            .hits[0]
            .passage
            .reference
            .clone();
        let descriptor = current_manifest(temp.path()).segments[0].clone();
        let path = temp.path().join(segment_name(descriptor.id));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            store.retrieve(RetrievalRequest::question("evidence marker")),
            Err(RetrievalError::CorruptStorage)
        ));
        assert_eq!(
            store.resolve_evidence(&reference),
            Err(EvidenceResolveError::CorruptStorage)
        );
    }

    #[test]
    fn evidence_resolution_rechecks_tombstone_revocation_and_readmission() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let tombstoned = key("reference-tombstone");
        let revoked = key("reference-revocation");
        upsert(
            &store,
            &tombstoned,
            tombstoned.as_str(),
            "Tombstone",
            "tombstone evidence marker",
        );
        upsert(
            &store,
            &revoked,
            revoked.as_str(),
            "Revocation",
            "revocation evidence marker",
        );
        let stale_view = store.read_view().unwrap();
        let tombstone_reference = store
            .retrieve(RetrievalRequest::question("tombstone evidence"))
            .unwrap()
            .hits
            .into_iter()
            .find(|hit| hit.requested_url == tombstoned.as_str())
            .unwrap()
            .passage
            .reference;
        let revoke_reference = store
            .retrieve(RetrievalRequest::question("revocation evidence"))
            .unwrap()
            .hits
            .into_iter()
            .find(|hit| hit.requested_url == revoked.as_str())
            .unwrap()
            .passage
            .reference;

        let tombstone = store.issue_fence(&tombstoned).unwrap();
        store.apply(&tombstone, Intent::Tombstone).unwrap();
        assert!(stale_view.document(&tombstoned).is_some());
        assert_eq!(
            store.resolve_evidence(&tombstone_reference),
            Err(EvidenceResolveError::NotLive)
        );

        let revoke = store.issue_fence(&revoked).unwrap();
        store.apply(&revoke, Intent::Revoke).unwrap();
        assert!(stale_view.document(&revoked).is_some());
        assert_eq!(
            store.resolve_evidence(&revoke_reference),
            Err(EvidenceResolveError::Revoked)
        );
        let readmit = store.issue_fence(&revoked).unwrap();
        store.apply(&readmit, Intent::Readmit).unwrap();
        assert_eq!(
            store.resolve_evidence(&revoke_reference),
            Err(EvidenceResolveError::NotLive)
        );
        let restore = store.issue_fence(&revoked).unwrap();
        store
            .apply(
                &restore,
                Intent::Upsert {
                    effective_url: revoked.as_str().to_owned(),
                    title: "Revocation".to_owned(),
                    body: "revocation evidence marker".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(
            store.resolve_evidence(&revoke_reference).unwrap().text,
            "revocation evidence marker"
        );
    }

    #[test]
    fn evidence_resolution_checks_collection_expiry_before_and_after_loading_text() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let current = system_time_ms().unwrap();
        let deadline = current + 60_000;
        let notice = b"owned test collection notice";
        store
            .install_public_collection_gate(
                &public_gate(notice, current, deadline),
                notice,
                current,
            )
            .unwrap();
        let document = key("expiring-reference");
        upsert(
            &store,
            &document,
            document.as_str(),
            "Expiring evidence",
            "collection expiry evidence marker",
        );
        let reference = store
            .retrieve(RetrievalRequest::question("expiry evidence"))
            .unwrap()
            .hits[0]
            .passage
            .reference
            .clone();

        assert_eq!(
            store.resolve_evidence_with_clock(&reference, || Ok(deadline)),
            Err(EvidenceResolveError::PublicCollectionExpired)
        );
        let mut times = [deadline - 1, deadline].into_iter();
        assert_eq!(
            store.resolve_evidence_with_clock(&reference, || Ok(times.next().unwrap())),
            Err(EvidenceResolveError::PublicCollectionExpired)
        );
    }

    #[test]
    fn question_sampling_and_response_sizes_have_explicit_caps() {
        let seed = [0x5a; 32];
        let mut descriptors = (1..=40)
            .map(|id| SegmentDescriptor {
                id,
                byte_len: 1024,
                sha256: [0; 32],
                document_count: 1,
                term_count: 1,
                posting_count: 1,
                position_count: 1,
            })
            .collect::<Vec<_>>();
        descriptors.push(SegmentDescriptor {
            id: 41,
            byte_len: MAX_SEGMENT_BYTES as u64,
            sha256: [0; 32],
            document_count: 1,
            term_count: 1,
            posting_count: 1,
            position_count: MAX_POSITION_VALUES,
        });
        let (selected, partial) = select_question_segments(&descriptors, &seed).unwrap();
        assert!(partial);
        assert_eq!(selected.len(), 40);
        let total_bytes = selected.iter().map(|item| item.byte_len).sum::<u64>();
        let total_estimate = selected
            .iter()
            .map(|item| segment_memory_estimate(item).unwrap())
            .sum::<u64>();
        assert!(total_bytes <= MAX_QUESTION_SEGMENT_BYTES);
        assert!(total_estimate <= MAX_QUESTION_SEGMENT_MEMORY_ESTIMATE);

        let records = (0..10_000u32)
            .map(|ordinal| {
                (
                    ordinal,
                    Posting {
                        title_positions: Vec::new(),
                        body_positions: vec![0],
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let (sampled, probes) = sample_question_postings(&records, 10_000, &seed, 8);
        assert_eq!(probes, 8);
        assert!(sampled.len() <= 8);
        assert!(sampled.iter().all(|ordinal| records.contains_key(ordinal)));

        let oversized = RetrievalResponse {
            contract_version: crate::retrieval::RETRIEVAL_CONTRACT_VERSION,
            mode: RetrievalMode::Question,
            generation_id: 1,
            status: RetrievalStatus::RetrievedText,
            completeness: RetrievalCompleteness::Complete,
            normalized_terms: vec!["evidence".to_owned()],
            hits: vec![EvidenceHit {
                requested_url: "https://example.test/large".to_owned(),
                effective_url: "https://example.test/large".to_owned(),
                title: "Large".to_owned(),
                score: 1.0,
                matched_terms: vec!["evidence".to_owned()],
                matched_phrases: Vec::new(),
                passage: EvidencePassage {
                    reference: EvidenceReference::new(
                        [1; 16],
                        "https://example.test/large".to_owned(),
                        [2; 32],
                        0,
                        1,
                    )
                    .unwrap(),
                    text: "x".repeat(MAX_RESPONSE_BYTES),
                },
            }],
            answer_assessment: AnswerAssessment::NotAssessed,
        };
        assert_eq!(
            ensure_response_bound(&oversized),
            Err(RetrievalError::ResponseTooLarge)
        );
    }

    #[test]
    fn cold_open_decodes_compacted_postings_without_rebuilding_or_reencoding() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let mut expected = InMemoryIndex::new();
        for (path, title, body) in [
            ("alpha", "Rust indexing", "positions survive compaction"),
            ("beta", "Incremental index", "rust postings are persisted"),
            ("gamma", "Exact phrase", "positions survive cold open"),
        ] {
            let id = key(path);
            upsert(&store, &id, id.as_str(), title, body);
            expected
                .insert_fields(
                    id.as_str().to_owned(),
                    id.as_str().to_owned(),
                    title.to_owned(),
                    body.to_owned(),
                )
                .unwrap();
        }
        store.compact().unwrap();
        assert_eq!(current_manifest(temp.path()).segments.len(), 1);

        crate::index::reset_full_posting_build_count();
        segment::reset_segment_encoding_count();
        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let view = reopened.read_view().unwrap();
        assert_eq!(crate::index::full_posting_build_count(), 0);
        assert_eq!(segment::segment_encoding_count(), 0);
        assert_reference_view(
            &view,
            &expected,
            &[
                "rust",
                "index",
                "\"positions survive\"",
                "rust AND postings",
            ],
        );
        assert_eq!(crate::index::full_posting_build_count(), 0);
        assert_eq!(segment::segment_encoding_count(), 0);
    }

    fn current_manifest(root: &Path) -> Manifest {
        let store_bytes = read_bounded_file(&root.join(STORE_NAME), STORE_BYTES).unwrap();
        let (store_id, _) = decode_store(&store_bytes).unwrap();
        let bytes = read_bounded_file(&root.join(CURRENT_NAME), CURRENT_BYTES).unwrap();
        let pointer = CurrentPointer::decode(&bytes, store_id).unwrap();
        let manifest_bytes = read_bounded_file(
            &root.join(manifest_name(pointer.generation_id)),
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        Manifest::decode(&manifest_bytes, store_id, pointer.generation_id).unwrap()
    }

    fn install_test_manifest(root: &Path, manifest: &Manifest) {
        let bytes = manifest.encode().unwrap();
        fs::write(root.join(manifest_name(manifest.generation_id)), &bytes).unwrap();
        let pointer = CurrentPointer {
            store_id: manifest.store_id,
            generation_id: manifest.generation_id,
            manifest_len: bytes.len() as u64,
            manifest_sha256: sha256(&bytes),
        };
        fs::write(root.join(CURRENT_NAME), pointer.encode()).unwrap();
    }

    fn file_inventory(root: &Path) -> BTreeMap<String, (u64, String)> {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let bytes = fs::read(entry.path()).unwrap();
                (name, (bytes.len() as u64, hex_digest(&sha256(&bytes))))
            })
            .collect()
    }

    fn test_gate(root: &Path, suffix: &str) -> PathBuf {
        root.join(format!(".test-{suffix}"))
    }

    fn await_test_gate(root: &Path, role: &str) {
        let ready = test_gate(root, &format!("{role}-ready"));
        let release = test_gate(root, "release");
        fs::write(ready, b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !release.exists() {
            assert!(
                Instant::now() < deadline,
                "test worker did not get released"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn hex_digest(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn write_gate3_fixture(root: &Path) -> (Vec<u8>, Vec<u8>) {
        create_store_directory(root).unwrap();
        create_private_file(&root.join(LOCK_NAME), &[]).unwrap();
        let store_id = [0x43; 16];
        let lease_mac_key = [0x61; 32];
        let key = UrlKey::parse("https://doc.rust-lang.org/stable/std/string/struct.String.html")
            .unwrap();
        let title = "Gate 3 fixture".to_owned();
        let body = "incremental migration preserves this current document".to_owned();
        let mut index = InMemoryIndex::new();
        index
            .upsert_fields(
                key.as_str().to_owned(),
                key.as_str().to_owned(),
                title.clone(),
                body.clone(),
            )
            .unwrap();
        let version =
            decode_version_id(&index.documents().get(key.as_str()).unwrap().version_id).unwrap();
        let control = DocumentControl {
            high_water: 2,
            terminal: BTreeMap::from([(1, TerminalIntent::Upsert(version))]),
            policy: BTreeMap::new(),
        };
        let generation = Generation {
            id: 7,
            parent_id: 6,
            index,
            controls: BTreeMap::from([(key.clone(), control)]),
        };
        let notice = b"Owned Gate 3 migration fixture notice";
        let now = system_time_ms().unwrap();
        let gate = public_gate(notice, now, now + 86_400_000);
        create_private_file(
            &root.join(STORE_NAME),
            &encode_store_version(store_id, PUBLIC_STORE_MINOR, PUBLIC_STORE_FLAG),
        )
        .unwrap();
        create_private_file(
            &root.join(LEASE_KEY_NAME),
            &encode_lease_key(store_id, lease_mac_key),
        )
        .unwrap();
        create_private_file(
            &root.join(PUBLIC_COLLECTION_NAME),
            &encode_public_collection_record(store_id, &gate, &lease_mac_key).unwrap(),
        )
        .unwrap();
        create_private_file(&root.join(PUBLIC_NOTICE_STORE_BASENAME), notice).unwrap();
        let store = PersistentIndex {
            path: fs::canonicalize(root).unwrap(),
            store_id,
            writer: Mutex::new(()),
        };
        {
            let _lock = store.lock_exclusive().unwrap();
            store.publish_locked(&generation, None).unwrap();
        }
        let exact = encode_lease_token(store_id, &lease_mac_key, &key, NonZeroU64::new(1).unwrap())
            .unwrap();
        let pending =
            encode_lease_token(store_id, &lease_mac_key, &key, NonZeroU64::new(2).unwrap())
                .unwrap();
        (exact, pending)
    }

    fn read_lease_mac_key(store: &PersistentIndex) -> Result<LeaseMacKey, StorageError> {
        let _lock = store.lock_shared()?;
        store.read_lease_mac_key_locked()
    }

    fn validate_timeline(
        high_water: u64,
        terminal: &[(u64, TerminalIntent)],
        policy: &[(u64, PolicyEvent)],
    ) -> Result<(), StorageError> {
        let control = DocumentControl {
            high_water,
            terminal: terminal.iter().copied().collect(),
            policy: policy.iter().copied().collect(),
        };
        validate_control_history(&BTreeMap::from([(key("timeline"), control)]))
    }

    fn resign_test_lease(token: &mut [u8], mac_key: &LeaseMacKey, domain: &[u8]) {
        let signed_length = token.len() - LEASE_TAG_BYTES;
        let mut mac = HmacSha256::new_from_slice(mac_key).unwrap();
        mac.update(domain);
        mac.update(&token[..signed_length]);
        token[signed_length..].copy_from_slice(&mac.finalize().into_bytes());
    }

    fn assert_corrupt_open(root: &Path) {
        assert!(matches!(
            PersistentIndex::open(root),
            Err(StorageError::CorruptCommitted(_))
        ));
    }

    #[test]
    fn child_storage_worker() {
        let Ok(action) = std::env::var("LEY_STORAGE_TEST_ACTION") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("LEY_STORAGE_TEST_PATH").unwrap());
        match action.as_str() {
            "create" => {
                let _ = PersistentIndex::create(root);
            }
            "populate" => {
                let store = PersistentIndex::create(&root).unwrap();
                upsert(
                    &store,
                    &key("rust"),
                    "https://example.test/rust",
                    "Rust search",
                    "positional search uses Rust",
                );
                upsert(&store, &key("empty"), "https://example.test/empty", "", "");
                let results = store.query("rust AND search").unwrap();
                fs::write(root.with_extension("expected"), format!("{results:?}")).unwrap();
            }
            "lifecycle_seed" => {
                let store = PersistentIndex::create(&root).unwrap();
                let mut leases = Vec::new();
                let removed_key = key("removed");
                let removed = upsert(
                    &store,
                    &removed_key,
                    "https://example.test/removed",
                    "Twin Old",
                    "red blue retired secret phrase",
                );
                leases.push(store.export_lease(&removed).unwrap());
                let removed_tombstone = store.issue_fence(&removed_key).unwrap();
                store.apply(&removed_tombstone, Intent::Tombstone).unwrap();

                let beta_key = key("beta");
                let beta = upsert(
                    &store,
                    &beta_key,
                    "https://example.test/beta",
                    "Twin Blue",
                    "red blue common phrase",
                );
                leases.push(store.export_lease(&beta).unwrap());

                let updated_key = key("updated");
                let superseded = upsert(
                    &store,
                    &updated_key,
                    "https://example.test/updated",
                    "Twin Old",
                    "obsolete marker",
                );
                leases.push(store.export_lease(&superseded).unwrap());
                upsert(
                    &store,
                    &updated_key,
                    "https://example.test/updated",
                    "Twin Green",
                    "red blue current",
                );

                let stale_key = key("stale");
                let stale = store.issue_fence(&stale_key).unwrap();
                leases.push(store.export_lease(&stale).unwrap());
                let current = store.issue_fence(&stale_key).unwrap();
                store.apply(&current, Intent::Tombstone).unwrap();

                upsert(
                    &store,
                    &key("alpha"),
                    "https://example.test/alpha",
                    "Twin Blue",
                    "red blue common phrase",
                );
                upsert(
                    &store,
                    &key("sentinel"),
                    "https://example.test/sentinel",
                    "Twin Red",
                    "red blue sentinel phrase",
                );
                upsert(&store, &key("empty"), "https://example.test/empty", "", "");
                write_lease_bundle(&root, &leases);
            }
            "lifecycle_replay" => {
                let store = PersistentIndex::open(&root).unwrap();
                let leases = read_lease_bundle(&root);
                assert_eq!(leases.len(), 4);

                let removed = store.restore_lease(&leases[0]).unwrap();
                assert_eq!(
                    store
                        .apply(
                            &removed,
                            Intent::Upsert {
                                effective_url: "https://example.test/removed".to_owned(),
                                title: "Twin Old".to_owned(),
                                body: "red blue retired secret phrase".to_owned(),
                            },
                        )
                        .unwrap(),
                    ApplyOutcome::AlreadyApplied
                );

                let beta = store.restore_lease(&leases[1]).unwrap();
                assert!(matches!(
                    store.apply(&beta, Intent::Tombstone),
                    Err(StorageError::ConflictingIntent)
                ));

                let superseded = store.restore_lease(&leases[2]).unwrap();
                assert_eq!(
                    store
                        .apply(
                            &superseded,
                            Intent::Upsert {
                                effective_url: "https://example.test/updated".to_owned(),
                                title: "Twin Old".to_owned(),
                                body: "obsolete marker".to_owned(),
                            },
                        )
                        .unwrap(),
                    ApplyOutcome::AlreadyApplied
                );

                let stale = store.restore_lease(&leases[3]).unwrap();
                assert!(matches!(
                    store.apply(
                        &stale,
                        Intent::Upsert {
                            effective_url: "https://example.test/stale".to_owned(),
                            title: "Stale".to_owned(),
                            body: "cannot return".to_owned(),
                        }
                    ),
                    Err(StorageError::StaleFence)
                ));
            }
            "upsert" | "tombstone" => {
                let store = PersistentIndex::open(&root).unwrap();
                let key = key("crash");
                let leases = read_lease_bundle(&root);
                assert_eq!(leases.len(), 1);
                let lease = store.restore_lease(&leases[0]).unwrap();
                assert_eq!(lease.key(), &key);
                let intent = if action == "upsert" {
                    Intent::Upsert {
                        effective_url: "https://example.test/crash".to_owned(),
                        title: "Twin Old".to_owned(),
                        body: "new marker marker".to_owned(),
                    }
                } else {
                    Intent::Tombstone
                };
                let _ = store.apply(&lease, intent);
            }
            "compact" => {
                PersistentIndex::open(&root).unwrap().compact().unwrap();
            }
            "compact_process" => {
                if std::env::var("LEY_STORAGE_WAIT_FOR_GATE").as_deref() == Ok("1") {
                    let role = std::env::var("LEY_STORAGE_PROCESS_ROLE").unwrap();
                    await_test_gate(&root, &role);
                }
                if let Ok(role) = std::env::var("LEY_STORAGE_PROCESS_ROLE") {
                    fs::write(
                        test_gate(&root, &format!("{role}-attempting")),
                        b"attempting",
                    )
                    .unwrap();
                }
                PersistentIndex::open(&root).unwrap().compact().unwrap();
            }
            "upsert_process" => {
                await_test_gate(&root, "upsert");
                let store = PersistentIndex::open(&root).unwrap();
                let beta = key("beta");
                let lease = store.issue_fence(&beta).unwrap();
                store
                    .apply(
                        &lease,
                        Intent::Upsert {
                            effective_url: "https://example.test/beta".to_owned(),
                            title: "Beta revised".to_owned(),
                            body: "beta revised".to_owned(),
                        },
                    )
                    .unwrap();
            }
            "issue_fence_process" => {
                let role = std::env::var("LEY_STORAGE_PROCESS_ROLE").unwrap();
                await_test_gate(&root, &role);
                let lease = PersistentIndex::open(&root)
                    .unwrap()
                    .issue_fence(&key("shared"))
                    .unwrap();
                fs::write(
                    test_gate(&root, &format!("{role}-fence")),
                    lease.fence().get().to_be_bytes(),
                )
                .unwrap();
            }
            "hold_reader_lock" => {
                let store = PersistentIndex::open(&root).unwrap();
                let _lock = store.lock_shared().unwrap();
                await_test_gate(&root, "reader");
            }
            "verify_crash_snapshot" => {
                let action = std::env::var("LEY_STORAGE_EXPECT_ACTION").unwrap();
                let committed_new = std::env::var("LEY_STORAGE_EXPECT_NEW").unwrap() == "1";
                let expected_generation = std::env::var("LEY_STORAGE_EXPECT_GENERATION")
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                let store = PersistentIndex::open(&root).unwrap();
                let view = store.read_view().unwrap();
                assert_eq!(view.generation_id(), expected_generation);
                assert_crash_view(&store, &action, committed_new);
            }
            "verify_differential" => {
                let store = PersistentIndex::open(&root).unwrap();
                let view = store.read_view().unwrap();
                let mut expected = InMemoryIndex::new();
                expected
                    .insert_fields(
                        key("alpha").to_string(),
                        "https://example.test/alpha".to_owned(),
                        "New Again".to_owned(),
                        "blue fresh marker".to_owned(),
                    )
                    .unwrap();
                assert_reference_view(
                    &view,
                    &expected,
                    &["blue", "fresh", "\"fresh marker\"", "old OR missing"],
                );
            }
            _ => panic!("unknown child storage action"),
        }
    }

    #[test]
    fn gate3_migration_preserves_source_and_public_bytes_and_restores_replayable_fences() {
        let source = TempStore::new();
        let destination = TempStore::new();
        let (exact_token, pending_token) = write_gate3_fixture(source.path());
        let before = file_inventory(source.path());
        let source_store_bytes = fs::read(source.path().join(STORE_NAME)).unwrap();
        let (store_id, _) = decode_store(&source_store_bytes).unwrap();
        let record = fs::read(source.path().join(PUBLIC_COLLECTION_NAME)).unwrap();
        let notice = fs::read(source.path().join(PUBLIC_NOTICE_STORE_BASENAME)).unwrap();

        let report = PersistentIndex::reindex_gate3(source.path(), destination.path()).unwrap();
        assert_eq!(report.source_generation, 7);
        assert_eq!(report.destination_generation, 7);
        assert_eq!(report.document_count, 1);
        assert_eq!(file_inventory(source.path()), before);
        assert!(matches!(
            PersistentIndex::open(source.path()),
            Err(StorageError::ReindexRequired(_))
        ));

        let migrated = PersistentIndex::open(destination.path()).unwrap();
        assert_eq!(migrated.store_identity(), store_id);
        assert_eq!(
            fs::read(destination.path().join(PUBLIC_COLLECTION_NAME)).unwrap(),
            record
        );
        assert_eq!(
            fs::read(destination.path().join(PUBLIC_NOTICE_STORE_BASENAME)).unwrap(),
            notice
        );
        let view = migrated.read_view().unwrap();
        assert_eq!(view.document_count(), 1);
        let key = UrlKey::parse("https://doc.rust-lang.org/stable/std/string/struct.String.html")
            .unwrap();
        let current = migrated.restore_lease(&exact_token).unwrap();
        assert_eq!(
            migrated
                .apply(
                    &current,
                    Intent::Upsert {
                        effective_url: key.as_str().to_owned(),
                        title: "Gate 3 fixture".to_owned(),
                        body: "incremental migration preserves this current document".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert!(matches!(
            migrated.apply(&current, Intent::Tombstone),
            Err(StorageError::ConflictingIntent)
        ));
        let pending = migrated.restore_lease(&pending_token).unwrap();
        assert_eq!(
            migrated.apply(&pending, Intent::Tombstone).unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(
            migrated.apply(&pending, Intent::Tombstone).unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert!(migrated.query("incremental").unwrap().is_empty());
        assert_reference_view(
            &view,
            &{
                let mut expected = InMemoryIndex::new();
                expected
                    .insert_fields(
                        key.as_str().to_owned(),
                        key.as_str().to_owned(),
                        "Gate 3 fixture".to_owned(),
                        "incremental migration preserves this current document".to_owned(),
                    )
                    .unwrap();
                expected
            },
            &["incremental", "\"migration preserves\""],
        );
        assert!(matches!(
            PersistentIndex::reindex_gate3(source.path(), destination.path()),
            Err(StorageError::StoreAlreadyExists)
        ));
        assert_eq!(file_inventory(source.path()), before);
    }

    #[cfg(unix)]
    #[test]
    fn gate3_migration_rejects_nested_dot_and_symlink_parent_destinations_before_staging() {
        use std::os::unix::fs::symlink;

        let source = TempStore::new();
        write_gate3_fixture(source.path());
        let before = file_inventory(source.path());
        let alias = source.path().with_extension("source-alias");
        symlink(source.path(), &alias).unwrap();
        let destinations = [
            source.path().join("nested-store"),
            source.path().join(".").join("dot-store"),
            alias.join("symlink-store"),
        ];
        for destination in destinations {
            assert!(matches!(
                PersistentIndex::reindex_gate3(source.path(), &destination),
                Err(StorageError::ReindexRequired(message))
                    if message.contains("outside the retained source")
            ));
            assert_eq!(file_inventory(source.path()), before);
        }
        let nested = source.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let dot_dot_destination = nested.join("..").join("dot-dot-store");
        assert!(matches!(
            PersistentIndex::reindex_gate3(source.path(), &dot_dot_destination),
            Err(StorageError::ReindexRequired(message))
                if message.contains("outside the retained source")
        ));
        assert_eq!(fs::read_dir(&nested).unwrap().count(), 0);
        fs::remove_dir(&nested).unwrap();
        assert_eq!(file_inventory(source.path()), before);
        assert!(!source.path().join("nested-store").exists());
        assert!(!source.path().join("dot-store").exists());
        assert!(!source.path().join("dot-dot-store").exists());
        assert!(!source.path().join("symlink-store").exists());
        fs::remove_file(alias).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gate3_migration_no_replace_preserves_a_destination_created_at_publish() {
        use std::cell::Cell;
        use std::os::unix::fs::MetadataExt;

        let source = TempStore::new();
        let destination = TempStore::new();
        write_gate3_fixture(source.path());
        let source_before = file_inventory(source.path());
        let contender_inode = Cell::new(None);
        let result = PersistentIndex::reindex_gate3_with_publish_hook(
            source.path(),
            destination.path(),
            |path| {
                fs::create_dir(path)?;
                contender_inode.set(Some(fs::symlink_metadata(path)?.ino()));
                Ok(())
            },
        );
        assert!(matches!(result, Err(StorageError::StoreAlreadyExists)));
        let contender = fs::symlink_metadata(destination.path()).unwrap();
        assert!(contender.is_dir());
        assert_eq!(contender.ino(), contender_inode.get().unwrap());
        assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 0);
        assert_eq!(file_inventory(source.path()), source_before);
    }

    #[test]
    fn manifest_writer_capacity_is_distinct_from_committed_corruption() {
        let store_id = [0x6a; 16];
        let mut at_limit = empty_manifest(store_id);
        at_limit.next_segment_id = MAX_SEGMENTS as u64 + 1;
        at_limit.segments = (1..=MAX_SEGMENTS as u64)
            .map(|id| SegmentDescriptor {
                id,
                byte_len: 164,
                sha256: [0; 32],
                document_count: 1,
                term_count: 0,
                posting_count: 0,
                position_count: 0,
            })
            .collect();
        validate_manifest_shape(&at_limit, store_id).unwrap();

        let mut over_limit = at_limit.clone();
        let id = over_limit.next_segment_id;
        over_limit.next_segment_id += 1;
        over_limit.segments.push(SegmentDescriptor {
            id,
            byte_len: 164,
            sha256: [0; 32],
            document_count: 1,
            term_count: 0,
            posting_count: 0,
            position_count: 0,
        });
        assert!(matches!(
            validate_manifest_shape(&over_limit, store_id),
            Err(StorageError::CorruptCommitted(_))
        ));
        match validate_proposed_manifest_shape(&over_limit, store_id) {
            Err(StorageError::CapacityExceeded(message)) => {
                assert!(message.contains("ley compact --store <store-path>"));
            }
            result => panic!("writer proposal should report actionable capacity: {result:?}"),
        }

        for limit in [
            ManifestLimit::LiveDocumentCount,
            ManifestLimit::LifecycleHistory,
        ] {
            let message = ManifestLimit::error(limit, ManifestValidationKind::Proposed).to_string();
            assert!(!message.contains("ley compact"), "{message}");
        }
    }

    #[test]
    fn generations_reopen_with_exact_results_and_reference_scores() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let rust = key("rust");
        let empty = key("empty");
        upsert(
            &store,
            &rust,
            "https://example.test/rust",
            "Rust search",
            "The quick brown fox finds positional search in Rust.",
        );
        upsert(&store, &empty, "https://example.test/empty", "", "");

        let pinned = store.read_view().unwrap();
        let before = pinned.query("rust AND search").unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].explanation.document_count, 2);
        assert_eq!(before[0].explanation.average_title_length, 1.0);
        assert_eq!(before[0].explanation.average_body_length, 4.5);
        let parsed = parse_query("rust AND search").unwrap();
        let mut reference_index = InMemoryIndex::new();
        for document in pinned.snapshot.documents.values() {
            reference_index
                .upsert_fields(
                    document.id.clone(),
                    document.effective_url.clone(),
                    document.title.clone(),
                    document.body.clone(),
                )
                .unwrap();
        }
        let reference = crate::reference::exhaustive_search(&reference_index, &parsed);
        assert_eq!(reference.len(), before.len());
        for (expected, actual) in reference.iter().zip(&before) {
            assert_eq!(expected.id, actual.id);
            assert!((expected.score - actual.score).abs() < 1e-12);
        }

        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let after = reopened.query("rust AND search").unwrap();
        assert_eq!(after, before);
        let phrase_before = pinned.query("\"positional search\"").unwrap();
        let phrase_after = reopened.query("\"positional search\"").unwrap();
        assert_eq!(phrase_after, phrase_before);
    }

    #[test]
    fn separate_process_lifecycle_replay_matches_reference_and_live_statistics() {
        let temp = TempStore::new();
        for action in ["lifecycle_seed", "lifecycle_replay"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "storage::tests::child_storage_worker",
                    "--nocapture",
                ])
                .env("LEY_STORAGE_TEST_ACTION", action)
                .env("LEY_STORAGE_TEST_PATH", temp.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child {action} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let expected = lifecycle_expected_index();
        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let view = reopened.read_view().unwrap();
        assert_lifecycle_statistics(&view);
        assert_reference_view(
            &view,
            &expected,
            &[
                "twin",
                "\"red blue\"",
                "twin AND current",
                "common OR current",
                "common OR obsolete OR retired OR secret",
                "obsolete OR retired OR secret",
            ],
        );
    }

    #[test]
    fn append_update_remove_and_compaction_preserve_hashes_and_full_reference_results()
    -> Result<(), StorageError> {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let alpha = key("alpha");
        let beta = key("beta");
        let mut inventories = BTreeMap::new();
        let mut expected = InMemoryIndex::new();

        upsert(
            &store,
            &alpha,
            "https://example.test/alpha",
            "Old Version",
            "alpha old blue phrase",
        );
        expected
            .insert_fields(
                alpha.to_string(),
                "https://example.test/alpha".to_owned(),
                "Old Version".to_owned(),
                "alpha old blue phrase".to_owned(),
            )
            .unwrap();
        inventories.insert("after_first_append", file_inventory(temp.path()));
        let second = upsert(
            &store,
            &beta,
            "https://example.test/beta",
            "Second Page",
            "blue shared phrase",
        );
        expected
            .insert_fields(
                beta.to_string(),
                "https://example.test/beta".to_owned(),
                "Second Page".to_owned(),
                "blue shared phrase".to_owned(),
            )
            .unwrap();
        let after_append = file_inventory(temp.path());
        for (name, proof) in inventories["after_first_append"]
            .iter()
            .filter(|(name, _)| name.starts_with("seg-"))
        {
            assert_eq!(after_append.get(name), Some(proof), "append rewrote {name}");
        }
        inventories.insert("after_second_append", after_append);
        assert_reference_view(
            &store.read_view().unwrap(),
            &expected,
            &["blue", "phrase", "alpha AND old", "missing OR shared"],
        );

        let alpha_update = upsert(
            &store,
            &alpha,
            "https://example.test/alpha",
            "Updated Version",
            "green fresh phrase",
        );
        expected
            .upsert_fields(
                alpha.to_string(),
                "https://example.test/alpha".to_owned(),
                "Updated Version".to_owned(),
                "green fresh phrase".to_owned(),
            )
            .unwrap();
        let after_update = file_inventory(temp.path());
        for (name, proof) in inventories["after_second_append"]
            .iter()
            .filter(|(name, _)| name.starts_with("seg-"))
        {
            assert_eq!(after_update.get(name), Some(proof), "update rewrote {name}");
        }
        inventories.insert("after_update", after_update);
        assert_eq!(
            store
                .apply(
                    &alpha_update,
                    Intent::Upsert {
                        effective_url: "https://example.test/alpha".to_owned(),
                        title: "Updated Version".to_owned(),
                        body: "green fresh phrase".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert!(matches!(
            store.apply(&alpha_update, Intent::Tombstone),
            Err(StorageError::ConflictingIntent)
        ));
        let stale_key = key("stale");
        let stale = store.issue_fence(&stale_key).unwrap();
        let _current_stale_key = store.issue_fence(&stale_key).unwrap();
        assert!(matches!(
            store.apply(&stale, Intent::Tombstone),
            Err(StorageError::StaleFence)
        ));

        assert_eq!(
            store
                .apply(
                    &second,
                    Intent::Upsert {
                        effective_url: "https://example.test/beta".to_owned(),
                        title: "Second Page".to_owned(),
                        body: "blue shared phrase".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert!(matches!(
            store.apply(&second, Intent::Tombstone),
            Err(StorageError::ConflictingIntent)
        ));
        let beta_delete = store.issue_fence(&beta).unwrap();
        store.apply(&beta_delete, Intent::Tombstone).unwrap();
        expected.remove_document(beta.as_str());
        let after_remove = file_inventory(temp.path());
        for (name, proof) in inventories["after_update"]
            .iter()
            .filter(|(name, _)| name.starts_with("seg-"))
        {
            assert_eq!(after_remove.get(name), Some(proof), "remove rewrote {name}");
        }
        inventories.insert("after_remove", after_remove);
        assert_reference_view(
            &store.read_view().unwrap(),
            &expected,
            &["green", "old OR fresh", "\"fresh phrase\""],
        );

        let revoke = store.issue_fence(&alpha).unwrap();
        store.apply(&revoke, Intent::Revoke).unwrap();
        expected.remove_document(alpha.as_str());
        assert_reference_view(
            &store.read_view().unwrap(),
            &expected,
            &["green", "old OR fresh"],
        );
        let readmit = store.issue_fence(&alpha).unwrap();
        store.apply(&readmit, Intent::Readmit).unwrap();
        assert_reference_view(
            &store.read_view().unwrap(),
            &expected,
            &["green", "old OR fresh"],
        );
        upsert(
            &store,
            &alpha,
            "https://example.test/alpha",
            "New Again",
            "blue fresh marker",
        );
        expected
            .upsert_fields(
                alpha.to_string(),
                "https://example.test/alpha".to_owned(),
                "New Again".to_owned(),
                "blue fresh marker".to_owned(),
            )
            .unwrap();
        let before_compaction = store.read_view().unwrap();
        let before_compaction_results = before_compaction.query("blue OR fresh").unwrap();
        inventories.insert("before_compaction", file_inventory(temp.path()));
        let input_manifest = current_manifest(temp.path());
        let input_segment_ids = input_manifest
            .segments
            .iter()
            .map(|descriptor| descriptor.id)
            .collect::<Vec<_>>();

        let report = store.compact().unwrap();
        let after_compaction = store.read_view().unwrap();
        let after_compaction_results = after_compaction.query("blue OR fresh").unwrap();
        let mut before_compaction_at_new_generation = before_compaction_results.clone();
        for result in &mut before_compaction_at_new_generation {
            result.explanation.statistics_source =
                StatisticsSource::PersistentGeneration(report.new_generation);
        }
        assert_eq!(
            before_compaction_at_new_generation,
            after_compaction_results
        );
        assert_reference_view(
            &after_compaction,
            &expected,
            &["blue", "fresh", "\"fresh marker\"", "old OR missing"],
        );
        assert_eq!(report.merged_segments.len(), input_segment_ids.len());
        assert_eq!(
            report
                .merged_segments
                .iter()
                .map(|segment| segment.id)
                .collect::<Vec<_>>(),
            input_segment_ids
        );
        assert_eq!(report.replacement_segments.len(), 1);
        let after_compaction_inventory = file_inventory(temp.path());
        for (name, proof) in &inventories["before_compaction"] {
            if name == STORE_NAME || name == LEASE_KEY_NAME || name == LOCK_NAME {
                assert_eq!(after_compaction_inventory.get(name), Some(proof));
            }
        }
        for segment_id in &input_segment_ids {
            assert!(!temp.path().join(segment_name(*segment_id)).exists());
        }
        assert!(
            temp.path()
                .join(segment_name(report.replacement_segments[0].id))
                .exists()
        );
        assert_eq!(
            before_compaction.query("blue OR fresh").unwrap(),
            before_compaction_results,
            "an eager reader snapshot remains queryable after its source files are removed"
        );
        inventories.insert("after_compaction", after_compaction_inventory);

        let mut verifier = Command::new(std::env::current_exe().unwrap());
        verifier
            .args([
                "--exact",
                "storage::tests::child_storage_worker",
                "--nocapture",
            ])
            .env("LEY_STORAGE_TEST_ACTION", "verify_differential")
            .env("LEY_STORAGE_TEST_PATH", temp.path());
        let output = verifier.output().unwrap();
        assert!(
            output.status.success(),
            "fresh-process post-compaction reference check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        if let Some(evidence_path) = std::env::var_os("LEY_GATE6_EVIDENCE_OUT") {
            let evidence = serde_json::json!({
                "snapshots": inventories,
                "compaction": {
                    "old_generation": report.old_generation,
                    "new_generation": report.new_generation,
                    "merged_segments": report.merged_segments.iter().map(|segment| {
                        serde_json::json!({"id": segment.id, "byte_len": segment.byte_len, "sha256": segment.sha256})
                    }).collect::<Vec<_>>(),
                    "replacement_segments": report.replacement_segments.iter().map(|segment| {
                        serde_json::json!({"id": segment.id, "byte_len": segment.byte_len, "sha256": segment.sha256})
                    }).collect::<Vec<_>>(),
                    "removed_paths": report.removed_paths,
                },
                "checks": {
                    "append_kept_existing_segment_hashes": true,
                    "update_kept_existing_segment_hashes": true,
                    "remove_kept_all_segment_hashes": true,
                    "compaction_removed_only_merged_inputs_and_added_one_replacement": true,
                    "old_reader_queried_after_input_files_were_removed": true,
                    "fresh_process_reference_match": true,
                },
            });
            let mut file = File::create(evidence_path)?;
            serde_json::to_writer_pretty(&mut file, &evidence)
                .map_err(|_| corrupt("incremental evidence could not be written"))?;
            file.sync_all()?;
        }
        Ok(())
    }

    #[test]
    fn lease_tokens_are_bounded_authenticated_and_fence_scoped() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let lease = store.issue_fence(&key("lease")).unwrap();
        let token = store.export_lease(&lease).unwrap();
        let generation_id = store.read_view().unwrap().generation_id();
        let mut invalid = vec![token[..token.len() - 1].to_vec(), token.clone()];
        invalid[1].extend_from_slice(&vec![0; MAX_LEASE_TOKEN_BYTES]);
        let mut trailing = token.clone();
        trailing.push(0);
        invalid.push(trailing);
        let mut bad_mac = token.clone();
        *bad_mac.last_mut().unwrap() ^= 1;
        invalid.push(bad_mac);

        let mut future_version = token.clone();
        future_version[8..10].copy_from_slice(&(LEASE_VERSION + 1).to_be_bytes());
        resign_test_lease(
            &mut future_version,
            &read_lease_mac_key(&store).unwrap(),
            LEASE_DOMAIN,
        );
        invalid.push(future_version);

        let mac_key = read_lease_mac_key(&store).unwrap();
        let mut zero_fence = token.clone();
        zero_fence[28..36].copy_from_slice(&0u64.to_be_bytes());
        resign_test_lease(&mut zero_fence, &mac_key, LEASE_DOMAIN);
        invalid.push(zero_fence);

        let mut future_fence = token.clone();
        future_fence[28..36].copy_from_slice(&2u64.to_be_bytes());
        resign_test_lease(&mut future_fence, &mac_key, LEASE_DOMAIN);
        invalid.push(future_fence);

        let mut unknown_key = token.clone();
        unknown_key[LEASE_HEADER_BYTES..LEASE_HEADER_BYTES + b"https://example.test/lease".len()]
            .copy_from_slice(b"https://example.test/other");
        resign_test_lease(&mut unknown_key, &mac_key, LEASE_DOMAIN);
        invalid.push(unknown_key);

        let mut noncanonical_key = token.clone();
        noncanonical_key
            [LEASE_HEADER_BYTES..LEASE_HEADER_BYTES + b"https://example.test/lease".len()]
            .copy_from_slice(b"https://EXAMPLE.test/lease");
        resign_test_lease(&mut noncanonical_key, &mac_key, LEASE_DOMAIN);
        invalid.push(noncanonical_key);

        let mut wrong_domain = token.clone();
        resign_test_lease(&mut wrong_domain, &mac_key, b"another-token-domain\0");
        invalid.push(wrong_domain);

        for token in invalid {
            assert!(matches!(
                store.restore_lease(&token),
                Err(StorageError::InvalidLease)
            ));
        }
        let other_temp = TempStore::new();
        let other = PersistentIndex::create(other_temp.path()).unwrap();
        assert!(matches!(
            other.restore_lease(&token),
            Err(StorageError::InvalidLease)
        ));
        assert_eq!(store.read_view().unwrap().generation_id(), generation_id);
        assert_eq!(store.restore_lease(&token).unwrap().fence(), lease.fence());
        fs::remove_file(temp.path().join(LEASE_KEY_NAME)).unwrap();
        assert!(matches!(
            store.restore_lease(&token),
            Err(StorageError::InvalidLease)
        ));
        let reexported = store.export_lease(&lease).unwrap();
        assert!(matches!(
            store.restore_lease(&token),
            Err(StorageError::InvalidLease)
        ));
        assert_eq!(
            store.restore_lease(&reexported).unwrap().fence(),
            lease.fence()
        );
        assert_eq!(store.read_view().unwrap().generation_id(), generation_id);
    }

    #[test]
    fn fences_replay_tombstones_revocation_and_pinned_readers_hold() {
        use std::sync::mpsc;

        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("document");
        let accepted = upsert(
            &store,
            &document,
            "https://example.test/first-effective",
            "First",
            "alpha retained",
        );
        let old_view = store.read_view().unwrap();
        let old_generation_id = old_view.generation_id();
        let old_segment_id = *old_view.snapshot.segments.keys().next().unwrap();
        let old_snapshot = old_view.query("alpha").unwrap();
        assert_eq!(
            old_snapshot[0].explanation.statistics_source,
            StatisticsSource::PersistentGeneration(old_generation_id)
        );
        let reader_view = old_view.clone();
        let (ready_send, ready_receive) = mpsc::channel();
        let (query_send, query_receive) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            ready_send.send(()).unwrap();
            query_receive.recv().unwrap();
            reader_view.query("alpha").unwrap()
        });
        ready_receive.recv().unwrap();
        assert_eq!(
            store
                .apply(
                    &accepted,
                    Intent::Upsert {
                        effective_url: "https://example.test/other-provenance".to_owned(),
                        title: "First".to_owned(),
                        body: "alpha retained".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert_eq!(old_view.query("alpha").unwrap()[0].title, "First");

        let tombstone = store.issue_fence(&document).unwrap();
        store.apply(&tombstone, Intent::Tombstone).unwrap();
        assert_eq!(store.query("alpha").unwrap().len(), 0);
        assert_eq!(old_view.query("alpha").unwrap().len(), 1);
        assert_eq!(
            store
                .apply(
                    &accepted,
                    Intent::Upsert {
                        effective_url: "https://example.test/first-effective".to_owned(),
                        title: "First".to_owned(),
                        body: "alpha retained".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );
        assert_eq!(store.query("alpha").unwrap().len(), 0);

        let revoked_key = key("revoked");
        upsert(
            &store,
            &revoked_key,
            "https://example.test/revoked",
            "Private",
            "secret marker",
        );
        let revoke = store.issue_fence(&revoked_key).unwrap();
        store.apply(&revoke, Intent::Revoke).unwrap();
        assert_eq!(store.query("secret").unwrap().len(), 0);
        let readmit = store.issue_fence(&revoked_key).unwrap();
        store.apply(&readmit, Intent::Readmit).unwrap();
        assert_eq!(store.query("secret").unwrap().len(), 0);
        let renewed = store.issue_fence(&revoked_key).unwrap();
        store
            .apply(
                &renewed,
                Intent::Upsert {
                    effective_url: "https://example.test/revoked".to_owned(),
                    title: "Public again".to_owned(),
                    body: "fresh marker".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(store.query("fresh").unwrap().len(), 1);
        assert_eq!(
            store
                .apply(&renewed, Intent::Readmit)
                .unwrap_err()
                .to_string(),
            StorageError::ConflictingIntent.to_string()
        );

        let first = store.issue_fence(&document).unwrap();
        let second = store.issue_fence(&document).unwrap();
        assert!(matches!(
            store.apply(&first, Intent::Tombstone),
            Err(StorageError::StaleFence)
        ));
        store.apply(&second, Intent::Tombstone).unwrap();
        assert!(matches!(
            store.apply(
                &second,
                Intent::Upsert {
                    effective_url: "https://example.test/document".to_owned(),
                    title: "Conflict".to_owned(),
                    body: "alpha".to_owned(),
                }
            ),
            Err(StorageError::ConflictingIntent)
        ));

        let superseded_key = key("superseded");
        let superseded = upsert(
            &store,
            &superseded_key,
            "https://example.test/superseded",
            "Old version",
            "obsolete marker",
        );
        let replacement = store.issue_fence(&superseded_key).unwrap();
        store
            .apply(
                &replacement,
                Intent::Upsert {
                    effective_url: "https://example.test/superseded".to_owned(),
                    title: "New version".to_owned(),
                    body: "current marker".to_owned(),
                },
            )
            .unwrap();
        assert_eq!(store.query("obsolete").unwrap().len(), 0);
        assert_eq!(store.query("current").unwrap().len(), 1);
        assert_eq!(
            store
                .apply(
                    &superseded,
                    Intent::Upsert {
                        effective_url: "https://example.test/superseded".to_owned(),
                        title: "Old version".to_owned(),
                        body: "obsolete marker".to_owned(),
                    },
                )
                .unwrap(),
            ApplyOutcome::AlreadyApplied
        );

        let other_temp = TempStore::new();
        let other = PersistentIndex::create(other_temp.path()).unwrap();
        assert!(matches!(
            other.apply(&second, Intent::Tombstone),
            Err(StorageError::WrongStoreLease)
        ));
        let reopened = PersistentIndex::open(temp.path()).unwrap();
        assert_eq!(reopened.query("alpha").unwrap().len(), 0);
        assert_eq!(reopened.query("fresh").unwrap().len(), 1);
        assert_eq!(reopened.query("obsolete").unwrap().len(), 0);
        assert_eq!(reopened.query("current").unwrap().len(), 1);
        let current_view = reopened.read_view().unwrap();
        assert_ne!(current_view.generation_id(), old_generation_id);
        assert!(temp.path().join(segment_name(old_segment_id)).exists());
        assert!(
            temp.path()
                .join(manifest_name(current_view.generation_id()))
                .exists()
        );
        assert!(!temp.path().join(manifest_name(old_generation_id)).exists());
        assert_eq!(old_view.query("alpha").unwrap(), old_snapshot);
        query_send.send(()).unwrap();
        assert_eq!(reader.join().unwrap(), old_snapshot);
    }

    #[test]
    fn rejects_live_upsert_that_precedes_its_readmission() {
        let temp = TempStore::new();
        let store = PersistentIndex::create(temp.path()).unwrap();
        let document = key("revoked-history");
        upsert(
            &store,
            &document,
            "https://example.test/revoked-history",
            "Old",
            "old marker",
        );
        let revoke = store.issue_fence(&document).unwrap();
        store.apply(&revoke, Intent::Revoke).unwrap();
        let readmit = store.issue_fence(&document).unwrap();
        store.apply(&readmit, Intent::Readmit).unwrap();
        let replacement = store.issue_fence(&document).unwrap();
        store
            .apply(
                &replacement,
                Intent::Upsert {
                    effective_url: "https://example.test/revoked-history".to_owned(),
                    title: "New".to_owned(),
                    body: "new marker".to_owned(),
                },
            )
            .unwrap();
        let unused = store.issue_fence(&document).unwrap();

        let mut manifest = current_manifest(temp.path());
        let control = manifest.controls.get_mut(document.as_str()).unwrap();
        assert_eq!(control.terminal.len(), 3);
        control
            .policy
            .insert(unused.fence().get(), PolicyRecord::Readmitted);
        install_test_manifest(temp.path(), &manifest);

        assert_corrupt_open(temp.path());
    }

    #[test]
    fn control_history_accepts_unused_fences_and_rejects_invalid_revocation_transitions() {
        assert!(validate_timeline(12, &[], &[]).is_ok());
        assert!(
            validate_timeline(
                12,
                &[
                    (1, TerminalIntent::Upsert([1; 32])),
                    (3, TerminalIntent::Tombstone),
                    (4, TerminalIntent::Tombstone),
                    (9, TerminalIntent::Upsert([2; 32])),
                ],
                &[(4, PolicyEvent::Revoked), (7, PolicyEvent::Readmitted)],
            )
            .is_ok()
        );

        let invalid_histories = [
            (
                vec![
                    (1, TerminalIntent::Tombstone),
                    (2, TerminalIntent::Tombstone),
                    (4, TerminalIntent::Upsert([1; 32])),
                ],
                vec![(2, PolicyEvent::Revoked), (5, PolicyEvent::Readmitted)],
            ),
            (
                vec![
                    (1, TerminalIntent::Tombstone),
                    (2, TerminalIntent::Tombstone),
                    (4, TerminalIntent::Tombstone),
                ],
                vec![(2, PolicyEvent::Revoked), (5, PolicyEvent::Readmitted)],
            ),
            (vec![], vec![(2, PolicyEvent::Readmitted)]),
            (
                vec![(1, TerminalIntent::Upsert([1; 32]))],
                vec![(1, PolicyEvent::Readmitted)],
            ),
            (
                vec![
                    (2, TerminalIntent::Tombstone),
                    (4, TerminalIntent::Tombstone),
                ],
                vec![(2, PolicyEvent::Revoked), (4, PolicyEvent::Revoked)],
            ),
            (vec![], vec![(2, PolicyEvent::Revoked)]),
        ];
        for (terminal, policy) in invalid_histories {
            assert!(validate_timeline(12, &terminal, &policy).is_err());
        }
    }

    #[test]
    fn independent_store_handles_serialize_fence_high_water_updates() {
        let temp = TempStore::new();
        PersistentIndex::create(temp.path()).unwrap();
        let first_store = PersistentIndex::open(temp.path()).unwrap();
        let second_store = PersistentIndex::open(temp.path()).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_store.issue_fence(&key("shared")).unwrap()
        });
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_store.issue_fence(&key("shared")).unwrap()
        });
        barrier.wait();

        let mut leases = [first.join().unwrap(), second.join().unwrap()];
        leases.sort_by_key(FenceLease::fence);
        assert_eq!([leases[0].fence.get(), leases[1].fence.get()], [1, 2]);
        let store = PersistentIndex::open(temp.path()).unwrap();
        assert!(matches!(
            store.apply(&leases[0], Intent::Tombstone),
            Err(StorageError::StaleFence)
        ));
        store.apply(&leases[1], Intent::Tombstone).unwrap();
        assert_eq!(store.query("missing").unwrap(), Vec::new());
    }

    #[test]
    fn cross_process_writers_readers_and_compaction_races_are_serialized() {
        fn spawn_worker(
            root: &Path,
            action: &str,
            role: Option<&str>,
            wait: bool,
        ) -> std::process::Child {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "storage::tests::child_storage_worker",
                    "--nocapture",
                ])
                .env("LEY_STORAGE_TEST_ACTION", action)
                .env("LEY_STORAGE_TEST_PATH", root);
            if let Some(role) = role {
                command.env("LEY_STORAGE_PROCESS_ROLE", role);
            }
            if wait {
                command.env("LEY_STORAGE_WAIT_FOR_GATE", "1");
            }
            command.spawn().unwrap()
        }

        fn wait_ready(root: &Path, role: &str) {
            let ready = test_gate(root, &format!("{role}-ready"));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.exists() {
                assert!(
                    Instant::now() < deadline,
                    "{role} child did not become ready"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn finish_child(child: std::process::Child, label: &str) {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{label} child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn clear_gates(root: &Path) {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().starts_with(".test-") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }

        let temp = TempStore::new();
        PersistentIndex::create(temp.path()).unwrap();
        let first = spawn_worker(temp.path(), "issue_fence_process", Some("first"), true);
        let second = spawn_worker(temp.path(), "issue_fence_process", Some("second"), true);
        wait_ready(temp.path(), "first");
        wait_ready(temp.path(), "second");
        fs::write(test_gate(temp.path(), "release"), b"go").unwrap();
        finish_child(first, "first fence writer");
        finish_child(second, "second fence writer");
        let mut fence_values = [
            u64::from_be_bytes(
                fs::read(test_gate(temp.path(), "first-fence"))
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            u64::from_be_bytes(
                fs::read(test_gate(temp.path(), "second-fence"))
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        ];
        fence_values.sort_unstable();
        assert_eq!(fence_values, [1, 2]);
        assert_eq!(
            current_manifest(temp.path()).controls["https://example.test/shared"].high_water,
            2
        );
        clear_gates(temp.path());

        let store = PersistentIndex::open(temp.path()).unwrap();
        upsert(
            &store,
            &key("alpha"),
            "https://example.test/alpha",
            "Alpha",
            "alpha stable",
        );
        upsert(
            &store,
            &key("beta"),
            "https://example.test/beta",
            "Beta",
            "beta obsolete",
        );

        let reader = spawn_worker(temp.path(), "hold_reader_lock", None, false);
        wait_ready(temp.path(), "reader");
        let mut compactor = spawn_worker(
            temp.path(),
            "compact_process",
            Some("blocked-compactor"),
            false,
        );
        let attempt_notice = test_gate(temp.path(), "blocked-compactor-attempting");
        let attempt_deadline = Instant::now() + Duration::from_secs(10);
        while !attempt_notice.exists() {
            assert!(Instant::now() < attempt_deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            compactor.try_wait().unwrap().is_none(),
            "exclusive compaction passed an active cross-process shared lock"
        );
        fs::write(test_gate(temp.path(), "release"), b"release reader").unwrap();
        finish_child(reader, "shared-lock reader");
        finish_child(compactor, "waiting compactor");
        clear_gates(temp.path());

        let before_race_generation = current_manifest(temp.path()).generation_id;
        let racing_compactor = spawn_worker(temp.path(), "compact_process", Some("compact"), true);
        let racing_writer = spawn_worker(temp.path(), "upsert_process", Some("upsert"), true);
        wait_ready(temp.path(), "compact");
        wait_ready(temp.path(), "upsert");
        fs::write(test_gate(temp.path(), "release"), b"race").unwrap();
        finish_child(racing_compactor, "racing compactor");
        finish_child(racing_writer, "racing writer");
        let reopened = PersistentIndex::open(temp.path()).unwrap();
        let generation_delta = reopened
            .read_view()
            .unwrap()
            .generation_id()
            .saturating_sub(before_race_generation);
        assert!(
            matches!(generation_delta, 2 | 3),
            "serialized writer/compactor order publishes two generations when the already compacted store is compacted first, and three when the update creates stale postings first; observed delta {generation_delta}"
        );
        let mut expected = InMemoryIndex::new();
        expected
            .insert_fields(
                "https://example.test/alpha".to_owned(),
                "https://example.test/alpha".to_owned(),
                "Alpha".to_owned(),
                "alpha stable".to_owned(),
            )
            .unwrap();
        expected
            .insert_fields(
                "https://example.test/beta".to_owned(),
                "https://example.test/beta".to_owned(),
                "Beta revised".to_owned(),
                "beta revised".to_owned(),
            )
            .unwrap();
        assert_reference_view(
            &reopened.read_view().unwrap(),
            &expected,
            &["alpha", "beta", "obsolete", "beta AND revised"],
        );
    }

    #[test]
    fn gate6_format_rejects_versions_truncation_counts_offsets_positions_checksums_and_missing_files()
     {
        fn seed(temp: &TempStore) -> (Manifest, Vec<u8>) {
            let store = PersistentIndex::create(temp.path()).unwrap();
            upsert(
                &store,
                &key("format"),
                "https://example.test/format",
                "",
                "alpha beta",
            );
            let manifest = current_manifest(temp.path());
            let descriptor = manifest.segments.first().unwrap();
            let bytes = fs::read(temp.path().join(segment_name(descriptor.id))).unwrap();
            (manifest, bytes)
        }

        fn install_segment(temp: &TempStore, mut manifest: Manifest, bytes: Vec<u8>) {
            let descriptor = manifest.segments.first_mut().unwrap();
            descriptor.byte_len = bytes.len() as u64;
            descriptor.sha256 = sha256(&bytes);
            fs::write(temp.path().join(segment_name(descriptor.id)), &bytes).unwrap();
            install_test_manifest(temp.path(), &manifest);
        }

        fn refresh_segment_checksums(bytes: &mut [u8]) {
            let payload_hash = sha256(&bytes[164..]);
            bytes[100..132].copy_from_slice(&payload_hash);
            let header_hash = sha256(&bytes[..132]);
            bytes[132..164].copy_from_slice(&header_hash);
        }

        let mut cases: Vec<CorruptionCase> = Vec::new();
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert!(matches!(
                PersistentIndex::open(temp.path()),
                Err(StorageError::UnsupportedFormat { major: 2, .. })
            ));
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            bytes.truncate(bytes.len() - 1);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (mut manifest, mut bytes) = seed(temp);
            let count = u32::from_be_bytes(bytes[24..28].try_into().unwrap()) + 1;
            bytes[24..28].copy_from_slice(&count.to_be_bytes());
            manifest.segments[0].document_count = count;
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (mut manifest, mut bytes) = seed(temp);
            let count = u64::from_be_bytes(bytes[32..40].try_into().unwrap()) + 1;
            bytes[32..40].copy_from_slice(&count.to_be_bytes());
            manifest.segments[0].posting_count = count;
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            bytes[48..56].copy_from_slice(&165u64.to_be_bytes());
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            let dictionary_offset = u64::from_be_bytes(bytes[64..72].try_into().unwrap()) as usize;
            let term_len = usize::from(u16::from_be_bytes(
                bytes[dictionary_offset + 4..dictionary_offset + 6]
                    .try_into()
                    .unwrap(),
            ));
            let first_posting_offset = dictionary_offset + 4 + 2 + term_len;
            bytes[first_posting_offset..first_posting_offset + 8]
                .copy_from_slice(&u64::MAX.to_be_bytes());
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            let posting_offset = u64::from_be_bytes(bytes[80..88].try_into().unwrap()) as usize;
            bytes[posting_offset + 3] = 0;
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            let posting_offset = u64::from_be_bytes(bytes[80..88].try_into().unwrap()) as usize;
            assert_eq!(bytes[posting_offset + 3], 1);
            bytes[posting_offset + 3] = 2;
            refresh_segment_checksums(&mut bytes);
            install_segment(temp, manifest, bytes);
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, mut bytes) = seed(temp);
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            fs::write(
                temp.path().join(segment_name(manifest.segments[0].id)),
                bytes,
            )
            .unwrap();
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, _) = seed(temp);
            fs::remove_file(temp.path().join(segment_name(manifest.segments[0].id))).unwrap();
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, _) = seed(temp);
            fs::remove_file(temp.path().join(manifest_name(manifest.generation_id))).unwrap();
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let (manifest, _) = seed(temp);
            let path = temp.path().join(manifest_name(manifest.generation_id));
            let mut bytes = fs::read(&path).unwrap();
            let payload = serde_json::from_slice::<serde_json::Value>(&bytes[112..]).unwrap();
            let mut payload = payload;
            payload
                .as_object_mut()
                .unwrap()
                .insert("unexpected".to_owned(), serde_json::json!(true));
            let payload = serde_json::to_vec(&payload).unwrap();
            bytes.truncate(112);
            bytes[32..40].copy_from_slice(&(payload.len() as u64).to_be_bytes());
            bytes[40..72].copy_from_slice(&sha256(&payload));
            let header_hash = sha256(&bytes[..72]);
            bytes[72..104].copy_from_slice(&header_hash);
            bytes.extend_from_slice(&payload);
            let pointer = CurrentPointer {
                store_id: manifest.store_id,
                generation_id: manifest.generation_id,
                manifest_len: bytes.len() as u64,
                manifest_sha256: sha256(&bytes),
            };
            fs::write(path, bytes).unwrap();
            fs::write(temp.path().join(CURRENT_NAME), pointer.encode()).unwrap();
            assert_corrupt_open(temp.path());
        }));
        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            upsert(
                &store,
                &key("format"),
                "https://example.test/format",
                "",
                "alpha",
            );
            let pointer_path = temp.path().join(CURRENT_NAME);
            let mut pointer = fs::read(&pointer_path).unwrap();
            pointer[32] ^= 1;
            fs::write(pointer_path, pointer).unwrap();
            assert_corrupt_open(temp.path());
        }));

        for case in cases {
            let temp = TempStore::new();
            case(&temp);
        }
    }

    #[test]
    fn child_termination_at_segment_manifest_merge_and_cleanup_seams_reopens_one_generation() {
        let scenarios = [
            ("upsert", "segment_write_half", false),
            ("upsert", "segment_write_complete", false),
            ("upsert", "segment_validate", false),
            ("upsert", "segment_sync", false),
            ("upsert", "segment_rename", false),
            ("upsert", "segment_directory_sync", false),
            ("upsert", "manifest_write_half", false),
            ("upsert", "manifest_write_complete", false),
            ("upsert", "manifest_validate", false),
            ("upsert", "manifest_sync", false),
            ("upsert", "manifest_rename", false),
            ("upsert", "manifest_directory_sync", false),
            ("upsert", "current_write_complete", false),
            ("upsert", "current_sync", false),
            ("upsert", "pointer_rename", true),
            ("upsert", "directory_sync", true),
            ("tombstone", "manifest_write_half", false),
            ("tombstone", "pointer_rename", true),
            ("compact", "compaction_before_merge", false),
            ("compact", "compaction_merge_complete", false),
            ("compact", "cleanup_after_unlink", true),
            ("compact", "cleanup_directory_sync", true),
        ];

        for (action, failpoint, committed_new) in scenarios {
            let temp = TempStore::new();
            let store = PersistentIndex::create(temp.path()).unwrap();
            let crash_key = key("crash");
            upsert(
                &store,
                &crash_key,
                "https://example.test/crash",
                "Twin Old",
                "old marker",
            );
            upsert(
                &store,
                &key("sentinel"),
                "https://example.test/sentinel",
                "Twin Sentinel",
                "old marker sentinel",
            );
            let lease = store.issue_fence(&crash_key).unwrap();
            write_lease_bundle(&temp.0, &[store.export_lease(&lease).unwrap()]);
            let old_generation = current_manifest(temp.path()).generation_id;

            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "storage::tests::child_storage_worker",
                    "--nocapture",
                ])
                .env("LEY_STORAGE_TEST_ACTION", action)
                .env("LEY_STORAGE_TEST_PATH", temp.path())
                .env("LEY_STORAGE_FAILPOINT", failpoint);
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(86),
                "child did not stop at {failpoint} for {action}: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let expected_generation = old_generation + u64::from(committed_new);
            let mut verifier = Command::new(std::env::current_exe().unwrap());
            verifier
                .args([
                    "--exact",
                    "storage::tests::child_storage_worker",
                    "--nocapture",
                ])
                .env("LEY_STORAGE_TEST_ACTION", "verify_crash_snapshot")
                .env("LEY_STORAGE_TEST_PATH", temp.path())
                .env("LEY_STORAGE_EXPECT_ACTION", action)
                .env(
                    "LEY_STORAGE_EXPECT_NEW",
                    u8::from(committed_new).to_string(),
                )
                .env(
                    "LEY_STORAGE_EXPECT_GENERATION",
                    expected_generation.to_string(),
                );
            let verified = verifier.output().unwrap();
            assert!(
                verified.status.success(),
                "fresh-process verification failed after {failpoint} for {action}: {}",
                String::from_utf8_lossy(&verified.stderr)
            );
        }

        for (failpoint, committed) in [("manifest_write_half", false), ("pointer_rename", true)] {
            let temp = TempStore::new();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "storage::tests::child_storage_worker",
                    "--nocapture",
                ])
                .env("LEY_STORAGE_TEST_ACTION", "create")
                .env("LEY_STORAGE_TEST_PATH", temp.path())
                .env("LEY_STORAGE_FAILPOINT", failpoint);
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(86));
            if committed {
                let store = PersistentIndex::open(temp.path()).unwrap();
                assert_eq!(store.read_view().unwrap().document_count(), 0);
            } else {
                assert!(PersistentIndex::open(temp.path()).is_err());
            }
        }
    }
}
