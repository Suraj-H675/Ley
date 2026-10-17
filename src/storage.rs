use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::analyzer::{ANALYZER_ID, Analyzer, MAX_TERM_SCALARS};
use crate::html::{HTML_SCHEMA_ID, MAX_DOCUMENT_TOKENS, MAX_FIELDS_BYTES, MAX_TITLE_BYTES};
use crate::index::{InMemoryIndex, QueryError, SearchResult, StatisticsSource};
use crate::url_key::{MAX_URL_KEY_BYTES, UrlKey};

const STORE_NAME: &str = "STORE";
const LEASE_KEY_NAME: &str = "LEASE_KEY";
const LOCK_NAME: &str = "LOCK";
const CURRENT_NAME: &str = "CURRENT";
const PUBLIC_COLLECTION_NAME: &str = "PUBLIC_COLLECTION";
const PUBLIC_NOTICE_NAME: &str = "rust-stdlib-documentation-MIT.txt";
const MAX_PUBLIC_COLLECTION_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_NOTICE_BYTES: usize = 16 * 1024;
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
    generation: Arc<Generation>,
    public_visible_until_ms: Option<u64>,
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
        self.generation.id
    }

    pub fn document_count(&self) -> usize {
        self.generation.index.len()
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
        let mut results = self
            .generation
            .index
            .query(expression)
            .map_err(StorageError::from)?;
        for result in &mut results {
            result.explanation.statistics_source =
                StatisticsSource::PersistentGeneration(self.generation.id);
        }
        Ok(results)
    }

    pub(crate) fn document(&self, key: &UrlKey) -> Option<crate::index::IndexedDocument> {
        self.generation.index.documents().get(key.as_str()).cloned()
    }
}

pub struct PersistentIndex {
    path: PathBuf,
    store_id: StoreId,
    writer: Mutex<()>,
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
        let store_bytes = encode_store(store_id);
        create_private_file(&path.join(STORE_NAME), &store_bytes)?;
        let lease_mac_key = random_lease_mac_key()?;
        create_private_file(
            &path.join(LEASE_KEY_NAME),
            &encode_lease_key(store_id, lease_mac_key),
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
        let initial = Generation {
            id: 1,
            parent_id: 0,
            index: InMemoryIndex::new(),
            controls: BTreeMap::new(),
        };
        store.publish_locked(&initial, None)?;
        Ok(store)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        validate_store_directory(&path)?;
        let (store_id, _) = decode_store(&read_bounded_file(&path.join(STORE_NAME), STORE_BYTES)?)?;
        let store = Self {
            path: fs::canonicalize(path)?,
            store_id,
            writer: Mutex::new(()),
        };
        {
            let _lock = store.lock_shared()?;
            store.load_committed_locked()?;
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
        let current = self.load_committed_locked()?;
        let mut next = next_generation(&current)?;
        let control = next.controls.entry(key.clone()).or_default();
        control.high_water = control
            .high_water
            .checked_add(1)
            .ok_or(StorageError::CapacityExceeded("u64 fence exhausted"))?;
        let fence = NonZeroU64::new(control.high_water).ok_or(StorageError::InvalidLease)?;
        self.publish_locked(&next, Some(&current))?;
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
        let current = self.load_committed_locked()?;
        let Some(control) = current.controls.get(&lease.key) else {
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
        let current = self.load_committed_locked()?;
        let Some(control) = current.controls.get(&key) else {
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
        let current = self.load_committed_locked()?;
        let mut next = next_generation(&current)?;
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
                prepared_document = Some((effective_url.clone(), title.clone(), body.clone()));
                (Some(TerminalIntent::Upsert(version)), None)
            }
            Intent::Tombstone => (Some(TerminalIntent::Tombstone), None),
            Intent::Revoke => (Some(TerminalIntent::Tombstone), Some(PolicyEvent::Revoked)),
            Intent::Readmit => (None, Some(PolicyEvent::Readmitted)),
        };

        let control = next.controls.entry(key.clone()).or_default();
        let stored_terminal = control.terminal.get(&fence).copied();
        let stored_policy = control.policy.get(&fence).copied();
        if is_exact_replay(terminal, policy, stored_terminal, stored_policy) {
            return Ok(ApplyOutcome::AlreadyApplied);
        }
        if stored_terminal.is_some() || stored_policy.is_some() {
            return Err(StorageError::ConflictingIntent);
        }
        if control.high_water != fence {
            return Err(StorageError::StaleFence);
        }
        let revoked = is_revoked(control);
        match intent {
            Intent::Upsert { .. } => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                let Some((effective_url, title, body)) = prepared_document else {
                    return Err(corrupt("prepared upsert fields missing"));
                };
                next.index
                    .upsert_fields(key.as_str().to_owned(), effective_url, title, body)?;
                control.terminal.insert(
                    fence,
                    terminal.ok_or_else(|| corrupt("upsert terminal identity missing"))?,
                );
            }
            Intent::Tombstone => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                next.index.remove_document(key.as_str());
                control.terminal.insert(fence, TerminalIntent::Tombstone);
            }
            Intent::Revoke => {
                if revoked {
                    return Err(StorageError::Revoked);
                }
                next.index.remove_document(key.as_str());
                control.terminal.insert(fence, TerminalIntent::Tombstone);
                control.policy.insert(fence, PolicyEvent::Revoked);
            }
            Intent::Readmit => {
                if !revoked {
                    return Err(StorageError::NotRevoked);
                }
                control.policy.insert(fence, PolicyEvent::Readmitted);
            }
        }
        storage_failpoint("apply_before_publish");
        self.publish_locked(&next, Some(&current))?;
        Ok(ApplyOutcome::Applied)
    }

    pub(crate) fn install_public_collection_gate(
        &self,
        gate: &PublicCollectionGate,
        notice: &[u8],
        now_ms: u64,
    ) -> Result<(), StorageError> {
        validate_public_collection_gate(gate)?;
        if notice.is_empty()
            || notice.len() > MAX_PUBLIC_NOTICE_BYTES
            || sha256(notice) != decode_sha256(&gate.notice_sha256)?
            || gate.installed_at_ms > now_ms
        {
            return Err(StorageError::PublicCollectionConflict);
        }

        let _writer = self
            .writer
            .lock()
            .map_err(|_| StorageError::CorruptCommitted("writer mutex was poisoned".to_owned()))?;
        let _lock = self.lock_exclusive()?;
        let current = self.load_committed_locked()?;
        if let Some(existing) = self.load_public_collection_locked()? {
            if !existing.same_admission(gate) {
                return Err(StorageError::PublicCollectionConflict);
            }
            if now_ms >= existing.visible_until_ms {
                return Err(StorageError::PublicCollectionExpired);
            }
            let stored_notice =
                read_bounded_file(&self.path.join(PUBLIC_NOTICE_NAME), MAX_PUBLIC_NOTICE_BYTES)?;
            if stored_notice != notice {
                return Err(corrupt(
                    "public source notice differs from its admitted copy",
                ));
            }
            self.mark_store_as_public_collection()?;
            return Ok(());
        }
        if current.id != 1 || !current.index.is_empty() || gate.visible_until_ms <= now_ms {
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
        let generation = self.load_committed_locked()?;
        Ok(ReadView {
            generation: Arc::new(generation),
            public_visible_until_ms,
        })
    }

    pub fn query(&self, expression: &str) -> Result<Vec<SearchResult>, StorageError> {
        self.read_view()?.query(expression)
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
        let notice =
            read_bounded_file(&self.path.join(PUBLIC_NOTICE_NAME), MAX_PUBLIC_NOTICE_BYTES)?;
        if sha256(&notice) != decode_sha256(&gate.notice_sha256)? {
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
                &encode_public_store(self.store_id),
            )?;
        }
        Ok(())
    }

    fn install_public_notice(&self, notice: &[u8]) -> Result<(), StorageError> {
        let path = self.path.join(PUBLIC_NOTICE_NAME);
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
                create_private_file(&path, &encode_lease_key(self.store_id, mac_key))?;
                sync_directory(&self.path)?;
                Ok(mac_key)
            }
            Err(error) => Err(error),
        }
    }
}

fn next_generation(current: &Generation) -> Result<Generation, StorageError> {
    let id = current
        .id
        .checked_add(1)
        .ok_or(StorageError::CapacityExceeded("generation id exhausted"))?;
    Ok(Generation {
        id,
        parent_id: current.id,
        index: current.index.clone(),
        controls: current.controls.clone(),
    })
}

fn is_exact_replay(
    terminal: Option<TerminalIntent>,
    policy: Option<PolicyEvent>,
    stored_terminal: Option<TerminalIntent>,
    stored_policy: Option<PolicyEvent>,
) -> bool {
    match (terminal, policy) {
        (Some(terminal), None) => stored_terminal == Some(terminal),
        (Some(TerminalIntent::Tombstone), Some(PolicyEvent::Revoked)) => {
            stored_terminal == Some(TerminalIntent::Tombstone)
                && stored_policy == Some(PolicyEvent::Revoked)
        }
        (None, Some(policy)) => stored_terminal.is_none() && stored_policy == Some(policy),
        _ => false,
    }
}

fn is_revoked(control: &DocumentControl) -> bool {
    control
        .policy
        .last_key_value()
        .is_some_and(|(_, event)| *event == PolicyEvent::Revoked)
}

fn encode_store(store_id: StoreId) -> Vec<u8> {
    encode_store_version(store_id, FORMAT_MINOR, 0)
}

fn encode_public_store(store_id: StoreId) -> Vec<u8> {
    encode_store_version(store_id, PUBLIC_STORE_MINOR, PUBLIC_STORE_FLAG)
}

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
        || gate.license != "MIT"
        || gate.source_version.is_empty()
        || gate.source_version.len() > 200
        || gate.source_version.chars().any(char::is_control)
        || gate.notice_file != PUBLIC_NOTICE_NAME
        || !is_lower_sha256(&gate.notice_sha256)
    {
        return Err(StorageError::PublicCollectionConflict);
    }
    Ok(())
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
    if &bytes[..8] != STORE_MAGIC {
        return Err(corrupt("STORE magic mismatch"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    let flags = get_u32(bytes, 12)?;
    let requires_public_gate = match (major, minor, flags) {
        (FORMAT_MAJOR, FORMAT_MINOR, 0) => false,
        (FORMAT_MAJOR, PUBLIC_STORE_MINOR, PUBLIC_STORE_FLAG) => true,
        (FORMAT_MAJOR, version, _) if version == FORMAT_MINOR || version == PUBLIC_STORE_MINOR => {
            return Err(corrupt("STORE flags do not match its version"));
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

fn decode_lease_key(bytes: &[u8], expected_store_id: StoreId) -> Result<LeaseMacKey, StorageError> {
    if bytes.len() != LEASE_KEY_BYTES || &bytes[..8] != LEASE_KEY_MAGIC {
        return Err(corrupt("LEASE_KEY has an invalid length or magic"));
    }
    let major = get_u16(bytes, 8)?;
    let minor = get_u16(bytes, 10)?;
    if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
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

struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

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

fn generation_temp_name(generation_id: u64) -> String {
    format!(".gen-{generation_id}.tmp")
}

fn parse_generation_name(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let id = digits.parse::<u64>().ok()?;
    (id.to_string() == digits).then_some(id)
}

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

fn to_u16(value: usize, label: &'static str) -> Result<u16, StorageError> {
    u16::try_from(value).map_err(|_| StorageError::CapacityExceeded(label))
}

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
            notice_file: PUBLIC_NOTICE_NAME.to_owned(),
            notice_sha256: sha256(notice)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
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
            fs::read(store.path.join(PUBLIC_NOTICE_NAME)).unwrap(),
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
        assert_eq!(view.generation.index.len(), 5);
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
        assert_eq!(view.generation.index.len(), expected.len());
        let twin = view.query("twin").unwrap();
        let expected_twin_df = if action == "tombstone" && committed_new {
            1
        } else {
            2
        };
        let expected_body_average =
            if action == "upsert" && committed_new || action == "tombstone" && committed_new {
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

    fn committed_generation_path(root: &Path) -> PathBuf {
        let store = PersistentIndex::open(root).unwrap();
        let _lock = store.lock_shared().unwrap();
        let bytes = read_bounded_file(&root.join(CURRENT_NAME), CURRENT_BYTES).unwrap();
        let (id, _, _) = decode_current(&bytes, store.store_id).unwrap();
        root.join(generation_name(id))
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

    fn rewrite_current_for_generation(root: &Path, generation: &[u8]) {
        let current_path = root.join(CURRENT_NAME);
        let mut current = read_bounded_file(&current_path, CURRENT_BYTES).unwrap();
        current[40..48].copy_from_slice(&(generation.len() as u64).to_be_bytes());
        current[48..80].copy_from_slice(&sha256(generation));
        let checksum = sha256(&current[..80]);
        current[80..112].copy_from_slice(&checksum);
        fs::write(current_path, current).unwrap();
    }

    fn refresh_generation_checksums(root: &Path, generation: &mut [u8]) {
        for section in 0..SECTION_COUNT {
            let descriptor = 188 + section * DESCRIPTOR_BYTES;
            let offset = get_u64(generation, descriptor).unwrap() as usize;
            let length = get_u64(generation, descriptor + 8).unwrap() as usize;
            let end = offset.checked_add(length).unwrap();
            let checksum = sha256(&generation[offset..end]);
            generation[descriptor + 24..descriptor + 56].copy_from_slice(&checksum);
        }
        let header_checksum = sha256(&generation[..416]);
        generation[416..448].copy_from_slice(&header_checksum);
        rewrite_current_for_generation(root, generation);
    }

    fn refresh_header_and_pointer(root: &Path, generation: &mut [u8]) {
        let header_checksum = sha256(&generation[..416]);
        generation[416..448].copy_from_slice(&header_checksum);
        rewrite_current_for_generation(root, generation);
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
            _ => panic!("unknown child storage action"),
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
        let reference = crate::reference::exhaustive_search(&pinned.generation.index, &parsed);
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
        let current_generation_path = temp
            .path()
            .join(generation_name(current_view.generation_id()));
        let current_generation = fs::read(&current_generation_path).unwrap();
        let retained_parent_id = get_u64(&current_generation, 44).unwrap();
        assert!(retained_parent_id > 0);
        assert!(
            temp.path()
                .join(generation_name(retained_parent_id))
                .exists()
        );
        assert!(
            !temp
                .path()
                .join(generation_name(old_generation_id))
                .exists(),
            "cleanup removed the old generation file while its decoded view remained pinned"
        );
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

        let generation_path = committed_generation_path(temp.path());
        let mut generation = fs::read(&generation_path).unwrap();
        let controls_offset = get_u64(&generation, 188 + 3 * DESCRIPTOR_BYTES).unwrap() as usize;
        let key_len = usize::from(get_u16(&generation, controls_offset).unwrap());
        let terminal_count = get_u32(&generation, controls_offset + 10).unwrap() as usize;
        assert_eq!(terminal_count, 3);
        let readmitted_fence_offset = controls_offset + 18 + key_len + terminal_count * 48 + 16;
        generation[readmitted_fence_offset..readmitted_fence_offset + 8]
            .copy_from_slice(&unused.fence().get().to_be_bytes());
        refresh_generation_checksums(temp.path(), &mut generation);
        fs::write(generation_path, generation).unwrap();

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
    fn committed_format_rejects_invalid_versions_truncation_forged_document_and_posting_counts_offsets_positions_checksums_and_missing_files()
     {
        let mut cases: Vec<CorruptionCase> = Vec::new();

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation[10..12].copy_from_slice(&4u16.to_be_bytes());
            refresh_generation_checksums(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert!(matches!(
                PersistentIndex::open(temp.path()),
                Err(StorageError::UnsupportedFormat { .. })
            ));
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation.truncate(generation.len() - 1);
            rewrite_current_for_generation(temp.path(), &generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation[140..148].copy_from_slice(&999_999u64.to_be_bytes());
            refresh_header_and_pointer(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation[124..132].copy_from_slice(&999_999u64.to_be_bytes());
            refresh_generation_checksums(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha beta");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            let dictionary_descriptor = 188 + DESCRIPTOR_BYTES;
            let dictionary_offset = get_u64(&generation, dictionary_descriptor).unwrap() as usize;
            let dictionary_length =
                get_u64(&generation, dictionary_descriptor + 8).unwrap() as usize;
            assert!(dictionary_length > 0);
            generation.remove(dictionary_offset + dictionary_length - 1);
            let new_generation_length = generation.len() as u64;
            generation[116..124].copy_from_slice(&new_generation_length.to_be_bytes());
            generation[dictionary_descriptor + 8..dictionary_descriptor + 16]
                .copy_from_slice(&((dictionary_length - 1) as u64).to_be_bytes());
            for section in 2..SECTION_COUNT {
                let descriptor = 188 + section * DESCRIPTOR_BYTES;
                let offset = get_u64(&generation, descriptor).unwrap();
                generation[descriptor..descriptor + 8].copy_from_slice(&(offset - 1).to_be_bytes());
            }
            refresh_generation_checksums(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            refresh_generation_checksums(temp.path(), &mut generation);
            generation[188..196].copy_from_slice(&u64::MAX.to_be_bytes());
            refresh_header_and_pointer(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let current_path = temp.path().join(CURRENT_NAME);
            let mut current = fs::read(&current_path).unwrap();
            current[32] ^= 1;
            fs::write(current_path, current).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation[52..84].copy_from_slice(&[7; 32]);
            refresh_header_and_pointer(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert!(matches!(
                PersistentIndex::open(temp.path()),
                Err(StorageError::ReindexRequired(_))
            ));
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            let dictionary_offset = get_u64(&generation, 188 + DESCRIPTOR_BYTES).unwrap() as usize;
            generation[dictionary_offset + 20..dictionary_offset + 28]
                .copy_from_slice(&u64::MAX.to_be_bytes());
            refresh_generation_checksums(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            let posting_offset = get_u64(&generation, 188 + 2 * DESCRIPTOR_BYTES).unwrap() as usize;
            generation[posting_offset + 16..posting_offset + 20]
                .copy_from_slice(&999u32.to_be_bytes());
            refresh_generation_checksums(temp.path(), &mut generation);
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            let mut generation = fs::read(&generation_path).unwrap();
            generation[HEADER_BYTES] ^= 1;
            fs::write(generation_path, generation).unwrap();
            assert_corrupt_open(temp.path());
        }));

        cases.push(Box::new(|temp| {
            let store = PersistentIndex::create(temp.path()).unwrap();
            let k = key("version");
            upsert(&store, &k, "https://example.test/version", "", "alpha");
            let generation_path = committed_generation_path(temp.path());
            fs::remove_file(generation_path).unwrap();
            assert_corrupt_open(temp.path());
        }));

        for case in cases {
            let temp = TempStore::new();
            case(&temp);
        }
    }

    #[test]
    fn process_exit_at_publication_seams_keeps_only_old_or_new_committed_state() {
        const FAILPOINTS: [&str; 8] = [
            "generation_write_half",
            "generation_write_complete",
            "generation_validate",
            "generation_sync",
            "generation_ready",
            "current_sync",
            "pointer_rename",
            "directory_sync",
        ];

        for failpoint in FAILPOINTS {
            for action in ["create", "upsert", "tombstone"] {
                let temp = TempStore::new();
                if action != "create" {
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
                }
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

                let new_is_committed = matches!(failpoint, "pointer_rename" | "directory_sync");
                if action == "create" {
                    if new_is_committed {
                        let reopened = PersistentIndex::open(temp.path()).unwrap();
                        let view = reopened.read_view().unwrap();
                        assert!(view.generation.index.is_empty());
                        assert!(view.query("any").unwrap().is_empty());
                    } else {
                        assert!(matches!(
                            PersistentIndex::open(temp.path()),
                            Err(StorageError::IncompleteInitialStore)
                        ));
                    }
                    continue;
                }
                let reopened = PersistentIndex::open(temp.path()).unwrap();
                assert_crash_view(&reopened, action, new_is_committed);
                let lease = reopened
                    .restore_lease(&read_lease_bundle(temp.path())[0])
                    .unwrap();
                let intent = || {
                    if action == "upsert" {
                        Intent::Upsert {
                            effective_url: "https://example.test/crash".to_owned(),
                            title: "Twin Old".to_owned(),
                            body: "new marker marker".to_owned(),
                        }
                    } else {
                        Intent::Tombstone
                    }
                };
                if new_is_committed {
                    assert_eq!(
                        reopened.apply(&lease, intent()).unwrap(),
                        ApplyOutcome::AlreadyApplied
                    );
                } else {
                    let recovered_id = reopened.read_view().unwrap().generation_id();
                    reopened.issue_fence(&key("sentinel")).unwrap();
                    assert!(
                        !temp
                            .path()
                            .join(generation_temp_name(recovered_id + 1))
                            .exists()
                    );
                    assert!(!temp.path().join(".CURRENT.tmp").exists());
                    assert_crash_view(&reopened, action, false);
                    assert_eq!(
                        reopened.apply(&lease, intent()).unwrap(),
                        ApplyOutcome::Applied
                    );
                    assert_crash_view(&reopened, action, true);
                }
                assert_eq!(
                    reopened.apply(&lease, intent()).unwrap(),
                    ApplyOutcome::AlreadyApplied
                );
                assert_crash_view(&reopened, action, true);
            }
        }
    }
}
