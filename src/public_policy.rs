use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::Path;
#[cfg(unix)]
use std::{
    ffi::CString,
    os::{fd::AsRawFd, fd::FromRawFd, unix::ffi::OsStrExt, unix::fs::OpenOptionsExt},
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::controlled_crawler::{PublicSourceAdmission, RetentionPolicy, SourcePolicy};
use crate::safe_fetch::PublicAuthority;
use crate::url_key::UrlKey;

pub const MAX_POLICY_FILE_BYTES: usize = 64 * 1024;
const MAX_SOURCES: usize = 16;
const MAX_SOURCE_REQUESTS: u64 = 50;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_POLICY_TEXT_BYTES: usize = 1024;
const MAX_RETENTION_DAYS: u32 = 365;
const MAX_POLICY_VALID_DAYS: u64 = 365;
const MAX_LICENSE_TEXT_BYTES: usize = 256;
const MAX_NOTICE_FILE_NAME_BYTES: usize = 128;
const MAX_PUBLIC_NOTICE_BYTES: usize = 16 * 1024;
const LEGACY_NOTICE_FILE_NAME: &str = "rust-stdlib-documentation-MIT.txt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyFormat {
    LegacyV1,
    NoticeBoundV2,
}

#[derive(Clone, Debug)]
pub struct PublicCrawlPolicy {
    format: PolicyFormat,
    enabled: bool,
    identity: String,
    contact: String,
    sources: Vec<PublicSourcePolicy>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
enum RawPublicCrawlPolicy {
    #[serde(rename = "ley-public-sources-v1")]
    V1 {
        enabled: bool,
        identity: String,
        contact: String,
        sources: Vec<LegacyPublicSourcePolicy>,
    },
    #[serde(rename = "ley-public-sources-v2")]
    V2 {
        enabled: bool,
        identity: String,
        contact: String,
        sources: Vec<PublicSourcePolicy>,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPublicSourcePolicy {
    id: String,
    origin: String,
    path_prefixes: Vec<String>,
    seeds: Vec<String>,
    fetch_permission: PermissionEvidence,
    storage_permission: PermissionEvidence,
    index_permission: PermissionEvidence,
    display_permission: PermissionEvidence,
    license: String,
    source_version: String,
    notice_file: String,
    robots: String,
    removal_contact: String,
    retention_days: u32,
    expires_at_ms: u64,
    max_requests: u64,
    min_origin_delay_ms: u64,
    max_wire_bytes: usize,
    max_decoded_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicSourcePolicy {
    id: String,
    origin: String,
    path_prefixes: Vec<String>,
    seeds: Vec<String>,
    fetch_permission: PermissionEvidence,
    storage_permission: PermissionEvidence,
    index_permission: PermissionEvidence,
    display_permission: PermissionEvidence,
    license: String,
    source_version: String,
    notice_file: String,
    notice_sha256: String,
    #[serde(skip)]
    notice_bytes: Vec<u8>,
    robots: String,
    removal_contact: String,
    retention_days: u32,
    expires_at_ms: u64,
    max_requests: u64,
    min_origin_delay_ms: u64,
    max_wire_bytes: usize,
    max_decoded_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionEvidence {
    granted: bool,
    basis: String,
    evidence: String,
    reviewed_at_ms: u64,
}

impl PermissionEvidence {
    fn to_record(&self) -> crate::storage::PublicPermissionEvidence {
        crate::storage::PublicPermissionEvidence {
            granted: self.granted,
            basis: self.basis.clone(),
            evidence: self.evidence.clone(),
            reviewed_at_ms: self.reviewed_at_ms,
        }
    }
}

impl LegacyPublicSourcePolicy {
    fn into_public_source(self) -> PublicSourcePolicy {
        let notice_bytes = include_bytes!("../notices/rust-stdlib-documentation-MIT.txt").to_vec();
        let notice_sha256 = sha256_hex(&notice_bytes);
        PublicSourcePolicy {
            id: self.id,
            origin: self.origin,
            path_prefixes: self.path_prefixes,
            seeds: self.seeds,
            fetch_permission: self.fetch_permission,
            storage_permission: self.storage_permission,
            index_permission: self.index_permission,
            display_permission: self.display_permission,
            license: self.license,
            source_version: self.source_version,
            notice_file: self.notice_file,
            notice_sha256,
            notice_bytes,
            robots: self.robots,
            removal_contact: self.removal_contact,
            retention_days: self.retention_days,
            expires_at_ms: self.expires_at_ms,
            max_requests: self.max_requests,
            min_origin_delay_ms: self.min_origin_delay_ms,
            max_wire_bytes: self.max_wire_bytes,
            max_decoded_bytes: self.max_decoded_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicPolicyError {
    Read,
    TooLarge,
    ApprovalMismatch,
    NoticeRead,
    NoticeTooLarge,
    NoticeHashMismatch,
    Invalid,
    Disabled,
    MissingIdentity,
    MissingContact,
    NoSources,
}

impl fmt::Display for PublicPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("could not read the public source policy"),
            Self::TooLarge => f.write_str("public source policy exceeds its 64 KiB limit"),
            Self::ApprovalMismatch => {
                f.write_str("public source policy SHA-256 does not match the approved value")
            }
            Self::NoticeRead => {
                f.write_str("could not safely read the policy's source notice file")
            }
            Self::NoticeTooLarge => {
                f.write_str("the policy's source notice exceeds its 16 KiB limit")
            }
            Self::NoticeHashMismatch => {
                f.write_str("the source notice SHA-256 does not match the policy")
            }
            Self::Invalid => f.write_str("public source policy is incomplete or invalid"),
            Self::Disabled => f.write_str("public crawling is disabled by policy"),
            Self::MissingIdentity => {
                f.write_str("public crawling needs an explicit crawler identity")
            }
            Self::MissingContact => f.write_str("public crawling needs a real contact address"),
            Self::NoSources => f.write_str("public crawling has no admitted sources"),
        }
    }
}

impl std::error::Error for PublicPolicyError {}

impl PublicCrawlPolicy {
    pub fn load_approved(
        path: impl AsRef<Path>,
        approved_sha256: &str,
    ) -> Result<Self, PublicPolicyError> {
        let path = path.as_ref();
        let (directory, bytes) = read_policy_file(path)?;
        let actual_sha256 = sha256_hex(&bytes);
        if !matches_sha256(&actual_sha256, approved_sha256) {
            return Err(PublicPolicyError::ApprovalMismatch);
        }
        let mut policy = Self::from_bytes(&bytes)?;
        if policy.format == PolicyFormat::NoticeBoundV2 {
            policy.load_source_notices(&directory)?;
        }
        Ok(policy)
    }

    fn load_source_notices(&mut self, directory: &File) -> Result<(), PublicPolicyError> {
        for source in &mut self.sources {
            if !is_safe_notice_file_name(&source.notice_file)
                || !is_lower_sha256(&source.notice_sha256)
            {
                return Err(PublicPolicyError::Invalid);
            }
            let notice = read_sibling_file(directory, &source.notice_file)?;
            if !valid_notice_text(&notice) {
                return Err(PublicPolicyError::Invalid);
            }
            if sha256_hex(&notice) != source.notice_sha256 {
                return Err(PublicPolicyError::NoticeHashMismatch);
            }
            source.notice_bytes = notice;
        }
        Ok(())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PublicPolicyError> {
        if bytes.len() > MAX_POLICY_FILE_BYTES {
            return Err(PublicPolicyError::TooLarge);
        }
        let raw: RawPublicCrawlPolicy =
            serde_json::from_slice(bytes).map_err(|_| PublicPolicyError::Invalid)?;
        let (format, enabled, identity, contact, sources) = match raw {
            RawPublicCrawlPolicy::V1 {
                enabled,
                identity,
                contact,
                sources,
            } => (
                PolicyFormat::LegacyV1,
                enabled,
                identity,
                contact,
                sources
                    .into_iter()
                    .map(LegacyPublicSourcePolicy::into_public_source)
                    .collect(),
            ),
            RawPublicCrawlPolicy::V2 {
                enabled,
                identity,
                contact,
                sources,
            } => (
                PolicyFormat::NoticeBoundV2,
                enabled,
                identity,
                contact,
                sources,
            ),
        };
        Ok(Self {
            format,
            enabled,
            identity,
            contact,
            sources,
            digest: Sha256::digest(bytes).into(),
        })
    }

    pub fn validate_enabled(&self, now_ms: u64) -> Result<(), PublicPolicyError> {
        if !self.enabled {
            return Err(PublicPolicyError::Disabled);
        }
        let identity_version = self.identity.strip_prefix("LeyBot/").unwrap_or_default();
        if identity_version.is_empty()
            || self.identity.len() > 128
            || !identity_version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PublicPolicyError::MissingIdentity);
        }
        if !is_contact(&self.contact) {
            return Err(PublicPolicyError::MissingContact);
        }
        if self.sources.is_empty() {
            return Err(PublicPolicyError::NoSources);
        }
        if self.sources.len() > MAX_SOURCES {
            return Err(PublicPolicyError::Invalid);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut origins = std::collections::BTreeSet::new();
        for source in &self.sources {
            source.validate(self.format, now_ms, &self.contact, &mut ids)?;
            if !origins.insert(source.origin.as_str()) {
                return Err(PublicPolicyError::Invalid);
            }
        }
        Ok(())
    }

    pub(crate) fn sources(&self) -> &[PublicSourcePolicy] {
        &self.sources
    }

    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn contact(&self) -> &str {
        &self.contact
    }

    pub(crate) fn collection_gate(
        &self,
        now_ms: u64,
    ) -> Result<crate::storage::PublicCollectionGate, PublicPolicyError> {
        if self.sources.len() != 1 {
            return Err(PublicPolicyError::Invalid);
        }
        let source = &self.sources[0];
        source.notice_bytes()?;
        let retention_until =
            now_ms.saturating_add(u64::from(source.retention_days) * 24 * 60 * 60 * 1000);
        let visible_until_ms = source.expires_at_ms.min(retention_until);
        if visible_until_ms <= now_ms {
            return Err(PublicPolicyError::Invalid);
        }
        let mut gate = crate::storage::PublicCollectionGate {
            policy_sha256: self.sha256(),
            source_id: source.id.clone(),
            origin: source.origin.clone(),
            path_prefixes: source.path_prefixes.clone(),
            installed_at_ms: now_ms,
            visible_until_ms,
            license: source.license.clone(),
            source_version: source.source_version.clone(),
            notice_file: source.notice_file.clone(),
            notice_sha256: source.notice_sha256.clone(),
            fetch_permission: None,
            storage_permission: None,
            index_permission: None,
            display_permission: None,
            removal_contact: None,
        };
        if self.format == PolicyFormat::NoticeBoundV2 {
            gate.fetch_permission = Some(source.fetch_permission.to_record());
            gate.storage_permission = Some(source.storage_permission.to_record());
            gate.index_permission = Some(source.index_permission.to_record());
            gate.display_permission = Some(source.display_permission.to_record());
            gate.removal_contact = Some(source.removal_contact.clone());
        }
        Ok(gate)
    }

    pub(crate) fn notice_bytes(&self) -> Result<&[u8], PublicPolicyError> {
        if self.sources.len() != 1 {
            return Err(PublicPolicyError::Invalid);
        }
        self.sources[0].notice_bytes()
    }

    pub fn validate_for_crawl(&self, now_ms: u64) -> Result<(), PublicPolicyError> {
        self.validate_enabled(now_ms)?;
        let gate = self.collection_gate(now_ms)?;
        let notice = self.notice_bytes()?;
        crate::storage::validate_public_collection_admission(&gate, notice)
            .map_err(|_| PublicPolicyError::Invalid)
    }

    pub fn sha256(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn matches_sha256(&self, supplied: &str) -> bool {
        matches_sha256(&self.sha256(), supplied)
    }
}

fn matches_sha256(actual: &str, supplied: &str) -> bool {
    supplied.len() == 64
        && supplied.bytes().all(|byte| byte.is_ascii_hexdigit())
        && supplied.eq_ignore_ascii_case(actual)
}

impl PublicSourcePolicy {
    fn notice_bytes(&self) -> Result<&[u8], PublicPolicyError> {
        if self.notice_bytes.is_empty()
            || !valid_notice_text(&self.notice_bytes)
            || sha256_hex(&self.notice_bytes) != self.notice_sha256
        {
            return Err(PublicPolicyError::Invalid);
        }
        Ok(&self.notice_bytes)
    }

    fn validate(
        &self,
        format: PolicyFormat,
        now_ms: u64,
        global_contact: &str,
        ids: &mut std::collections::BTreeSet<String>,
    ) -> Result<(), PublicPolicyError> {
        if self.id.is_empty()
            || self.id.len() > 128
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || !ids.insert(self.id.clone())
        {
            return Err(PublicPolicyError::Invalid);
        }
        let parsed = Url::parse(&self.origin).map_err(|_| PublicPolicyError::Invalid)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none_or(|host| {
                host.parse::<IpAddr>().is_ok() || !host.contains('.') || host.ends_with(".test")
            })
            || parsed.origin().ascii_serialization() != self.origin
        {
            return Err(PublicPolicyError::Invalid);
        }
        if self.path_prefixes.is_empty()
            || self.path_prefixes.len() > 64
            || self.path_prefixes.iter().any(|prefix| {
                !crate::url_key::path_is_within_prefix(prefix, prefix)
                    || prefix.len() > 2048
                    || prefix.contains(['?', '#', '\\', '\r', '\n'])
            })
        {
            return Err(PublicPolicyError::Invalid);
        }
        let valid_license_and_notice = match format {
            PolicyFormat::LegacyV1 => {
                self.license == "MIT" && self.notice_file == LEGACY_NOTICE_FILE_NAME
            }
            PolicyFormat::NoticeBoundV2 => {
                !self.license.trim().is_empty()
                    && self.license.len() <= MAX_LICENSE_TEXT_BYTES
                    && !self.license.chars().any(char::is_control)
                    && is_safe_notice_file_name(&self.notice_file)
                    && is_lower_sha256(&self.notice_sha256)
            }
        };
        if !valid_license_and_notice
            || self.source_version.len() > 200
            || self.source_version.trim().is_empty()
            || self.source_version.chars().any(char::is_control)
        {
            return Err(PublicPolicyError::Invalid);
        }
        if self.seeds.is_empty() || self.seeds.len() > 32 {
            return Err(PublicPolicyError::Invalid);
        }
        for seed in &self.seeds {
            let key = UrlKey::parse(seed).map_err(|_| PublicPolicyError::Invalid)?;
            let url = key.to_url().map_err(|_| PublicPolicyError::Invalid)?;
            if url.origin().ascii_serialization() != self.origin
                || !self
                    .path_prefixes
                    .iter()
                    .any(|path| crate::url_key::path_is_within_prefix(url.path(), path))
            {
                return Err(PublicPolicyError::Invalid);
            }
        }
        if !valid_evidence(&self.fetch_permission, now_ms)
            || !valid_evidence(&self.storage_permission, now_ms)
            || !valid_evidence(&self.index_permission, now_ms)
            || !valid_evidence(&self.display_permission, now_ms)
            || self.robots != "obey"
            || !is_contact(&self.removal_contact)
            || global_contact.is_empty()
            || self.retention_days == 0
            || self.retention_days > MAX_RETENTION_DAYS
            || self.expires_at_ms <= now_ms
            || self.expires_at_ms
                > now_ms.saturating_add(MAX_POLICY_VALID_DAYS * 24 * 60 * 60 * 1000)
            || self.max_requests == 0
            || self.max_requests > MAX_SOURCE_REQUESTS
            || self.min_origin_delay_ms < 1000
            || self.min_origin_delay_ms > MAX_DELAY_MS
            || self.max_wire_bytes < crate::html::MAX_COMPRESSED_RESPONSE_BYTES
            || self.max_wire_bytes > 16 * 1024 * 1024
            || self.max_decoded_bytes < crate::html::MAX_DECODED_RESPONSE_BYTES
            || self.max_decoded_bytes > 32 * 1024 * 1024
            || now_ms == u64::MAX
        {
            return Err(PublicPolicyError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn authority(
        &self,
        identity: &str,
        contact: &str,
    ) -> Result<PublicAuthority, PublicPolicyError> {
        let origin = Url::parse(&self.origin).map_err(|_| PublicPolicyError::Invalid)?;
        PublicAuthority::from_origin(&origin)
            .map(|authority| authority.with_crawler_identity(identity, contact))
            .ok_or(PublicPolicyError::Invalid)
    }

    pub(crate) fn crawler_policy(
        &self,
        identity_contact: &str,
        now_ms: u64,
        policy_sha256: &str,
    ) -> Result<SourcePolicy, PublicPolicyError> {
        let origin = Url::parse(&self.origin).map_err(|_| PublicPolicyError::Invalid)?;
        let origin_key = format!(
            "{}://{}:{}",
            origin.scheme(),
            origin.host_str().ok_or(PublicPolicyError::Invalid)?,
            origin
                .port_or_known_default()
                .ok_or(PublicPolicyError::Invalid)?
        );
        let retention_ms = u64::from(self.retention_days) * 24 * 60 * 60 * 1000;
        Ok(SourcePolicy::public(PublicSourceAdmission {
            id: self.id.clone(),
            origins: vec![origin_key],
            allowed_path_prefixes: self.path_prefixes.clone(),
            policy_sha256: policy_sha256.to_owned(),
            crawl_contact: identity_contact.to_owned(),
            valid_until_ms: self.expires_at_ms,
            retention: RetentionPolicy::Until(now_ms.saturating_add(retention_ms)),
            max_requests: self.max_requests,
            min_origin_delay_ms: self.min_origin_delay_ms,
        }))
    }

    pub(crate) fn seeds(&self) -> Result<Vec<UrlKey>, PublicPolicyError> {
        self.seeds
            .iter()
            .map(|seed| UrlKey::parse(seed).map_err(|_| PublicPolicyError::Invalid))
            .collect()
    }

    pub(crate) fn run_byte_limits(&self) -> (usize, usize) {
        (self.max_wire_bytes, self.max_decoded_bytes)
    }
}

fn valid_evidence(evidence: &PermissionEvidence, now_ms: u64) -> bool {
    evidence.granted
        && evidence.reviewed_at_ms > 0
        && evidence.reviewed_at_ms <= now_ms
        && !evidence.basis.trim().is_empty()
        && evidence.basis.len() <= MAX_POLICY_TEXT_BYTES
        && !evidence.evidence.trim().is_empty()
        && evidence.evidence.len() <= MAX_POLICY_TEXT_BYTES
        && !evidence.basis.chars().any(char::is_control)
        && !evidence.evidence.chars().any(char::is_control)
}

#[cfg(unix)]
fn read_policy_file(path: &Path) -> Result<(File, Vec<u8>), PublicPolicyError> {
    let name = path.file_name().ok_or(PublicPolicyError::Read)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NONBLOCK);
    let directory = options.open(parent).map_err(|_| PublicPolicyError::Read)?;
    if !directory
        .metadata()
        .map_err(|_| PublicPolicyError::Read)?
        .is_dir()
    {
        return Err(PublicPolicyError::Read);
    }
    let file = open_sibling(&directory, name).map_err(|_| PublicPolicyError::Read)?;
    let bytes =
        read_bounded_regular_file(file, MAX_POLICY_FILE_BYTES).map_err(|error| match error {
            BoundedReadError::Read => PublicPolicyError::Read,
            BoundedReadError::TooLarge => PublicPolicyError::TooLarge,
        })?;
    Ok((directory, bytes))
}

#[cfg(not(unix))]
fn read_policy_file(_path: &Path) -> Result<(File, Vec<u8>), PublicPolicyError> {
    Err(PublicPolicyError::Read)
}

#[cfg(unix)]
fn read_sibling_file(directory: &File, name: &str) -> Result<Vec<u8>, PublicPolicyError> {
    let file = open_sibling(directory, std::ffi::OsStr::new(name))
        .map_err(|_| PublicPolicyError::NoticeRead)?;
    read_bounded_regular_file(file, MAX_PUBLIC_NOTICE_BYTES).map_err(|error| match error {
        BoundedReadError::Read => PublicPolicyError::NoticeRead,
        BoundedReadError::TooLarge => PublicPolicyError::NoticeTooLarge,
    })
}

#[cfg(not(unix))]
fn read_sibling_file(_directory: &File, _name: &str) -> Result<Vec<u8>, PublicPolicyError> {
    Err(PublicPolicyError::NoticeRead)
}

#[cfg(unix)]
fn open_sibling(directory: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name contains a null byte",
        )
    })?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

enum BoundedReadError {
    Read,
    TooLarge,
}

fn read_bounded_regular_file(file: File, maximum: usize) -> Result<Vec<u8>, BoundedReadError> {
    let before = file.metadata().map_err(|_| BoundedReadError::Read)?;
    if !before.file_type().is_file() {
        return Err(BoundedReadError::Read);
    }
    let expected_length = usize::try_from(before.len()).map_err(|_| BoundedReadError::TooLarge)?;
    if expected_length > maximum {
        return Err(BoundedReadError::TooLarge);
    }
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = file.take(limit);
    let mut bytes = Vec::with_capacity(expected_length);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedReadError::Read)?;
    if bytes.len() > maximum {
        return Err(BoundedReadError::TooLarge);
    }
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|_| BoundedReadError::Read)?;
    if after.len() != before.len() || bytes.len() != expected_length {
        return Err(BoundedReadError::Read);
    }
    Ok(bytes)
}

fn is_safe_notice_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NOTICE_FILE_NAME_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_notice_text(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    !text.trim().is_empty()
        && !text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_contact(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 512
        || !value.is_ascii()
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '(' | ')' | '\\')
        })
    {
        return false;
    }
    if let Ok(url) = Url::parse(value) {
        return matches!(url.scheme(), "https" | "http")
            && url.username().is_empty()
            && url.password().is_none()
            && url.host_str().is_some();
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !value.contains([' ', '<', '>'])
        && value.len() <= 254
}

#[cfg(test)]
mod tests {
    use super::{
        LEGACY_NOTICE_FILE_NAME, MAX_PUBLIC_NOTICE_BYTES, PublicCrawlPolicy, PublicPolicyError,
        sha256_hex,
    };
    use std::path::{Path, PathBuf};

    struct TempPolicy(PathBuf);

    impl TempPolicy {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ley-public-policy-test-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, value: &serde_json::Value, notice: &[u8]) -> PathBuf {
            std::fs::write(self.0.join("source-notice.txt"), notice).unwrap();
            let policy_path = self.0.join("policy.json");
            std::fs::write(&policy_path, serde_json::to_vec(value).unwrap()).unwrap();
            policy_path
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    fn load_policy(path: impl AsRef<Path>) -> Result<PublicCrawlPolicy, PublicPolicyError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).unwrap();
        PublicCrawlPolicy::load_approved(path, &sha256_hex(&bytes))
    }

    fn current_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    impl Drop for TempPolicy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn synthetic_policy(notice: &[u8]) -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let permission = serde_json::json!({
            "granted": true,
            "basis": "authored validation fixture only",
            "evidence": "not a real permission grant",
            "reviewed_at_ms": now.saturating_sub(1)
        });
        serde_json::json!({
            "schema": "ley-public-sources-v2",
            "enabled": true,
            "identity": "LeyBot/0.1",
            "contact": "operator@example.org",
            "sources": [{
                "id": "authored-validation-fixture",
                "origin": "https://docs.example.org",
                "path_prefixes": ["/docs/"],
                "seeds": ["https://docs.example.org/docs/"],
                "fetch_permission": permission,
                "storage_permission": permission,
                "index_permission": permission,
                "display_permission": permission,
                "license": "Publisher terms, authored test label",
                "source_version": "offline-test-v1",
                "notice_file": "source-notice.txt",
                "notice_sha256": sha256_hex(notice),
                "robots": "obey",
                "removal_contact": "operator@example.org",
                "retention_days": 7,
                "expires_at_ms": now.saturating_add(86_400_000),
                "max_requests": 20,
                "min_origin_delay_ms": 2000,
                "max_wire_bytes": 4194304,
                "max_decoded_bytes": 16777216
            }]
        })
    }

    fn legacy_v1_policy() -> serde_json::Value {
        let notice = include_bytes!("../notices/rust-stdlib-documentation-MIT.txt");
        let mut value = synthetic_policy(notice);
        value["schema"] = serde_json::Value::String("ley-public-sources-v1".to_owned());
        value["sources"][0]["license"] = serde_json::Value::String("MIT".to_owned());
        value["sources"][0]["notice_file"] =
            serde_json::Value::String(LEGACY_NOTICE_FILE_NAME.to_owned());
        value["sources"][0]["source_version"] =
            serde_json::Value::String("rustdoc test fixture".to_owned());
        value["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("notice_sha256");
        value
    }

    fn from_value(value: &serde_json::Value) -> PublicCrawlPolicy {
        let bytes = serde_json::to_vec(value).unwrap();
        PublicCrawlPolicy::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn checked_in_policy_has_a_disabled_cited_candidate_and_real_contact() {
        let policy =
            PublicCrawlPolicy::from_bytes(include_str!("../policy/public-sources.json").as_bytes())
                .unwrap();
        assert_eq!(policy.validate_enabled(1), Err(PublicPolicyError::Disabled));
        assert_eq!(policy.identity(), "LeyBot/0.1.0");
        assert_eq!(policy.contact(), "https://github.com/Suraj-H675/Ley/issues");
        assert_eq!(policy.sources().len(), 1);
        let source = &policy.sources()[0];
        assert_eq!(source.id, "rust-stdlib-docs-candidate");
        assert_eq!(source.origin, "https://doc.rust-lang.org");
        assert_eq!(source.path_prefixes.len(), 3);
        assert_eq!(source.seeds.len(), 3);
        assert!(source.fetch_permission.granted);
        assert!(source.storage_permission.granted);
        assert!(source.index_permission.granted);
        assert!(!source.display_permission.granted);
        assert_eq!(source.license, "MIT");
        assert_eq!(
            source.source_version,
            "rustdoc 1.99.0 (b940084d7, 2026-09-28)"
        );
        assert_eq!(source.notice_file, "source-notice.txt");
        assert_eq!(source.robots, "obey");
        assert_eq!(source.removal_contact, policy.contact());

        let mut candidate: serde_json::Value =
            serde_json::from_slice(include_str!("../policy/public-sources.json").as_bytes())
                .unwrap();
        candidate["enabled"] = serde_json::Value::Bool(true);
        candidate["sources"][0]["display_permission"]["granted"] = serde_json::Value::Bool(true);
        let mut approved_shape = from_value(&candidate);
        approved_shape.sources[0].notice_bytes =
            include_bytes!("../policy/source-notice.txt").to_vec();
        let reviewed_at = 1_791_966_040_000;
        assert!(approved_shape.validate_enabled(reviewed_at).is_ok());
        let gate = approved_shape.collection_gate(reviewed_at).unwrap();
        assert_eq!(gate.origin, "https://doc.rust-lang.org");
        assert_eq!(gate.source_id, "rust-stdlib-docs-candidate");
        assert_eq!(
            gate.visible_until_ms,
            reviewed_at + u64::from(source.retention_days) * 24 * 60 * 60 * 1000
        );
        assert_eq!(
            gate.notice_sha256,
            "00a6a0169d5440bb0db6c06983c7067b1cbb3f2a56339d30d09fd6996e65bd4a"
        );
    }

    #[test]
    fn enabled_policy_requires_real_contact_and_admitted_sources() {
        let notice_sha256 = sha256_hex(b"synthetic policy notice\n");
        let source = serde_json::json!({
            "id": "candidate",
            "origin": "https://www.example.org",
            "path_prefixes": ["/public/"],
            "seeds": ["https://www.example.org/public/"],
            "fetch_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "storage_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "index_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "display_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "license": "Publisher terms, reviewed offline",
            "source_version": "test-fixture-v1",
            "notice_file": "fixture-notice.txt",
            "notice_sha256": notice_sha256,
            "robots": "obey",
            "removal_contact": "owner@example.org",
            "retention_days": 7,
            "expires_at_ms": 10000,
            "max_requests": 20,
            "min_origin_delay_ms": 2000,
            "max_wire_bytes": 4194304,
            "max_decoded_bytes": 16777216
        });
        let mut json = serde_json::json!({
            "schema":"ley-public-sources-v2",
            "enabled":true,
            "identity":"LeyBot/0.1",
            "contact":"operator@example.org",
            "sources":[source]
        });
        let policy = from_value(&json);
        assert!(policy.validate_enabled(1).is_ok());
        assert!(policy.matches_sha256(&policy.sha256()));
        assert!(!policy.matches_sha256("not-the-digest"));

        json["sources"][0]["fetch_permission"]["granted"] = serde_json::Value::Bool(false);
        assert_eq!(
            from_value(&json).validate_enabled(1),
            Err(PublicPolicyError::Invalid)
        );
        json["sources"][0]["fetch_permission"]["granted"] = serde_json::Value::Bool(true);

        json["sources"][0]["seeds"][0] =
            serde_json::Value::String("https://www.example.org/publicity/".to_owned());
        assert_eq!(
            from_value(&json).validate_enabled(1),
            Err(PublicPolicyError::Invalid)
        );
        json["sources"][0]["seeds"][0] =
            serde_json::Value::String("https://www.example.org/public/".to_owned());

        json["sources"][0]["path_prefixes"][0] = serde_json::Value::String("/public".to_owned());
        json["sources"][0]["seeds"][0] =
            serde_json::Value::String("https://www.example.org/publicity/".to_owned());
        assert_eq!(
            from_value(&json).validate_enabled(1),
            Err(PublicPolicyError::Invalid)
        );
        json["sources"][0]["path_prefixes"][0] = serde_json::Value::String("/public/".to_owned());
        json["sources"][0]["seeds"][0] =
            serde_json::Value::String("https://www.example.org/public/".to_owned());

        json["sources"][0]["display_permission"]["reviewed_at_ms"] =
            serde_json::Value::from(10_001);
        assert_eq!(
            from_value(&json).validate_enabled(1),
            Err(PublicPolicyError::Invalid)
        );
        json["sources"][0]["display_permission"]["reviewed_at_ms"] = serde_json::Value::from(1);

        assert_eq!(
            from_value(&json).validate_enabled(10_000),
            Err(PublicPolicyError::Invalid)
        );

        json["identity"] = serde_json::Value::String("LeyBot/0.1\r\nX-Injected: true".to_owned());
        let invalid_identity = from_value(&json);
        assert_eq!(
            invalid_identity.validate_enabled(1),
            Err(PublicPolicyError::MissingIdentity)
        );

        json["identity"] = serde_json::Value::String("LeyBot/0.1".to_owned());
        json["contact"] = serde_json::Value::String("operator (owner)@example.org".to_owned());
        let invalid_contact = from_value(&json);
        assert_eq!(
            invalid_contact.validate_enabled(1),
            Err(PublicPolicyError::MissingContact)
        );

        json["contact"] = serde_json::Value::String(String::new());
        let no_contact = from_value(&json);
        assert_eq!(
            no_contact.validate_enabled(1),
            Err(PublicPolicyError::MissingContact)
        );

        json["contact"] = serde_json::Value::String("operator@example.org".to_owned());
        json["sources"] = serde_json::json!([]);
        let no_sources = from_value(&json);
        assert_eq!(
            no_sources.validate_enabled(1),
            Err(PublicPolicyError::NoSources)
        );
    }

    #[test]
    fn load_binds_non_mit_policy_to_owned_sibling_notice_bytes() {
        let notice = b"Authored offline notice for validation.\n";
        let directory = TempPolicy::new();
        let policy_path = directory.write(&synthetic_policy(notice), notice);
        let policy = load_policy(&policy_path).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(policy.validate_for_crawl(now).is_ok());
        assert_eq!(
            policy.sources()[0].license,
            "Publisher terms, authored test label"
        );
        assert_eq!(policy.notice_bytes().unwrap(), notice);
        let approved_sha = policy.sha256();

        std::fs::write(
            directory.path().join("source-notice.txt"),
            b"replacement text\n",
        )
        .unwrap();
        assert_eq!(policy.notice_bytes().unwrap(), notice);
        assert!(policy.matches_sha256(&approved_sha));
        let gate = policy.collection_gate(now).unwrap();
        assert_eq!(gate.notice_sha256, sha256_hex(notice));
        assert!(gate.fetch_permission.as_ref().unwrap().granted);
        assert!(gate.storage_permission.as_ref().unwrap().granted);
        assert!(gate.index_permission.as_ref().unwrap().granted);
        assert!(gate.display_permission.as_ref().unwrap().granted);
        assert_eq!(
            gate.removal_contact.as_deref(),
            Some("operator@example.org")
        );

        let mut changed_value = synthetic_policy(notice);
        changed_value["sources"][0]["source_version"] =
            serde_json::Value::String("offline-test-v2".to_owned());
        let changed_path = directory.write(&changed_value, notice);
        assert_eq!(
            PublicCrawlPolicy::load_approved(&changed_path, &approved_sha).unwrap_err(),
            PublicPolicyError::ApprovalMismatch
        );
    }

    #[test]
    fn approved_legacy_v1_policy_preserves_old_notice_and_persisted_gate() {
        let now_ms = current_time_ms();
        let mut value = legacy_v1_policy();
        value["sources"][0]["expires_at_ms"] =
            serde_json::Value::from(now_ms + 30 * 24 * 60 * 60 * 1000);
        for permission in [
            "fetch_permission",
            "storage_permission",
            "index_permission",
            "display_permission",
        ] {
            value["sources"][0][permission]["reviewed_at_ms"] =
                serde_json::Value::from(now_ms.saturating_sub(1));
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let directory = TempPolicy::new();
        let policy_path = directory.path().join("legacy-v1.json");
        std::fs::write(&policy_path, &bytes).unwrap();
        let approved_sha256 = sha256_hex(&bytes);
        let policy = PublicCrawlPolicy::load_approved(&policy_path, &approved_sha256).unwrap();
        let notice = include_bytes!("../notices/rust-stdlib-documentation-MIT.txt");

        assert!(policy.validate_enabled(now_ms).is_ok());
        assert!(policy.validate_for_crawl(now_ms).is_ok());
        assert_eq!(policy.sha256(), approved_sha256);
        assert_eq!(policy.notice_bytes().unwrap(), notice);

        let visible_until_ms = now_ms + 7 * 24 * 60 * 60 * 1000;
        let gate = policy.collection_gate(now_ms).unwrap();
        let expected_gate = crate::storage::PublicCollectionGate {
            policy_sha256: approved_sha256,
            source_id: "authored-validation-fixture".to_owned(),
            origin: "https://docs.example.org".to_owned(),
            path_prefixes: vec!["/docs/".to_owned()],
            installed_at_ms: now_ms,
            visible_until_ms,
            license: "MIT".to_owned(),
            source_version: "rustdoc test fixture".to_owned(),
            notice_file: LEGACY_NOTICE_FILE_NAME.to_owned(),
            notice_sha256: sha256_hex(notice),
            fetch_permission: None,
            storage_permission: None,
            index_permission: None,
            display_permission: None,
            removal_contact: None,
        };
        assert_eq!(gate, expected_gate);

        let store_path = directory.path().join("legacy-store");
        let store = crate::storage::PersistentIndex::create(&store_path).unwrap();
        store
            .install_public_collection_gate(&gate, notice, now_ms)
            .unwrap();
        let record_path = store_path.join("PUBLIC_COLLECTION");
        let first_record = std::fs::read(&record_path).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&first_record).unwrap();
        assert_eq!(
            record["gate"],
            serde_json::to_value(&expected_gate).unwrap()
        );
        assert!(record["gate"].get("fetch_permission").is_none());
        assert_eq!(store.read_view_at(now_ms).unwrap().document_count(), 0);

        let retry_ms = now_ms + 1_000;
        let retry_gate = policy.collection_gate(retry_ms).unwrap();
        assert!(retry_gate.visible_until_ms > gate.visible_until_ms);
        store
            .install_public_collection_gate(&retry_gate, notice, retry_ms)
            .unwrap();
        assert_eq!(std::fs::read(record_path).unwrap(), first_record);
        assert!(
            store
                .read_view_at(gate.visible_until_ms - 1)
                .unwrap()
                .document_count()
                == 0
        );
        assert!(store.read_view_at(gate.visible_until_ms).is_err());
    }

    #[test]
    fn legacy_v1_rejects_hybrid_fields_and_non_mit_notice_policy() {
        let notice = include_bytes!("../notices/rust-stdlib-documentation-MIT.txt");

        let directory = TempPolicy::new();
        let mut hybrid = legacy_v1_policy();
        hybrid["sources"][0]["notice_sha256"] = serde_json::Value::String(sha256_hex(notice));
        let policy_path = directory.path().join("hybrid-v1.json");
        let bytes = serde_json::to_vec(&hybrid).unwrap();
        std::fs::write(&policy_path, &bytes).unwrap();
        assert_eq!(
            PublicCrawlPolicy::load_approved(&policy_path, &sha256_hex(&bytes)).unwrap_err(),
            PublicPolicyError::Invalid
        );

        let directory = TempPolicy::new();
        let mut custom_license = legacy_v1_policy();
        custom_license["sources"][0]["license"] =
            serde_json::Value::String("Apache-2.0".to_owned());
        let policy_path = directory.write(&custom_license, notice);
        let policy = load_policy(&policy_path).unwrap();
        assert_eq!(
            policy.validate_enabled(current_time_ms()),
            Err(PublicPolicyError::Invalid)
        );

        let directory = TempPolicy::new();
        let mut custom_notice = legacy_v1_policy();
        custom_notice["sources"][0]["notice_file"] =
            serde_json::Value::String("source-notice.txt".to_owned());
        let policy_path = directory.write(&custom_notice, notice);
        let policy = load_policy(&policy_path).unwrap();
        assert_eq!(
            policy.validate_enabled(current_time_ms()),
            Err(PublicPolicyError::Invalid)
        );
    }

    #[test]
    fn notice_bound_v2_rejects_missing_notice_digest() {
        let notice = b"Authored offline notice.\n";
        let directory = TempPolicy::new();
        let mut value = synthetic_policy(notice);
        value["sources"][0]
            .as_object_mut()
            .unwrap()
            .remove("notice_sha256");
        let policy_path = directory.write(&value, notice);
        assert_eq!(
            load_policy(policy_path).unwrap_err(),
            PublicPolicyError::Invalid
        );
    }

    #[test]
    fn load_rejects_unsafe_notice_paths_and_bad_notice_contents() {
        let valid_notice = b"Authored offline notice.\n";
        for name in [
            "../source-notice.txt",
            "/tmp/source-notice.txt",
            "..",
            ".",
            "x/y",
            "x\\y",
        ] {
            let directory = TempPolicy::new();
            let mut value = synthetic_policy(valid_notice);
            value["sources"][0]["notice_file"] = serde_json::Value::String(name.to_owned());
            let policy_path = directory.write(&value, valid_notice);
            assert_eq!(
                load_policy(policy_path).unwrap_err(),
                PublicPolicyError::Invalid,
                "{name}"
            );
        }

        let oversized_notice = vec![b'x'; MAX_PUBLIC_NOTICE_BYTES + 1];
        let invalid_notices: &[(&[u8], PublicPolicyError)] = &[
            (b"", PublicPolicyError::Invalid),
            (b"  \n\t", PublicPolicyError::Invalid),
            (&[0xff, 0xfe], PublicPolicyError::Invalid),
            (b"notice\0text", PublicPolicyError::Invalid),
            (&oversized_notice, PublicPolicyError::NoticeTooLarge),
        ];
        for (notice, expected) in invalid_notices {
            let directory = TempPolicy::new();
            let policy_path = directory.write(&synthetic_policy(valid_notice), notice);
            assert_eq!(load_policy(policy_path).unwrap_err(), *expected);
        }

        let directory = TempPolicy::new();
        let policy_path = directory.write(&synthetic_policy(valid_notice), valid_notice);
        std::fs::remove_file(directory.path().join("source-notice.txt")).unwrap();
        assert_eq!(
            load_policy(policy_path).unwrap_err(),
            PublicPolicyError::NoticeRead
        );

        let directory = TempPolicy::new();
        let policy_path = directory.write(&synthetic_policy(valid_notice), b"modified notice\n");
        assert_eq!(
            load_policy(policy_path).unwrap_err(),
            PublicPolicyError::NoticeHashMismatch
        );

        let directory = TempPolicy::new();
        let policy_path = directory.write(&synthetic_policy(valid_notice), valid_notice);
        std::fs::remove_file(directory.path().join("source-notice.txt")).unwrap();
        std::fs::create_dir(directory.path().join("source-notice.txt")).unwrap();
        assert_eq!(
            load_policy(policy_path).unwrap_err(),
            PublicPolicyError::NoticeRead
        );
    }

    #[test]
    fn unapproved_policy_does_not_open_its_selected_notice() {
        let notice = b"Authored offline notice.\n";
        let directory = TempPolicy::new();
        let mut value = synthetic_policy(notice);
        value["sources"][0]["notice_file"] =
            serde_json::Value::String("not-present.txt".to_owned());
        let policy_path = directory.write(&value, notice);

        assert_eq!(
            PublicCrawlPolicy::load_approved(&policy_path, &"0".repeat(64)).unwrap_err(),
            PublicPolicyError::ApprovalMismatch
        );

        let actual_approval = sha256_hex(&std::fs::read(&policy_path).unwrap());
        assert_eq!(
            PublicCrawlPolicy::load_approved(&policy_path, &actual_approval).unwrap_err(),
            PublicPolicyError::NoticeRead
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_policy_and_notice_symlinks() {
        use std::os::unix::fs::symlink;

        let notice = b"Authored offline notice.\n";
        let directory = TempPolicy::new();
        let policy_path = directory.write(&synthetic_policy(notice), notice);
        std::fs::rename(&policy_path, directory.path().join("policy-real.json")).unwrap();
        symlink(directory.path().join("policy-real.json"), &policy_path).unwrap();
        assert_eq!(
            PublicCrawlPolicy::load_approved(
                &policy_path,
                &sha256_hex(&std::fs::read(directory.path().join("policy-real.json")).unwrap())
            )
            .unwrap_err(),
            PublicPolicyError::Read
        );

        std::fs::remove_file(&policy_path).unwrap();
        std::fs::rename(directory.path().join("policy-real.json"), &policy_path).unwrap();
        std::fs::remove_file(directory.path().join("source-notice.txt")).unwrap();
        std::fs::write(directory.path().join("notice-real.txt"), notice).unwrap();
        symlink(
            directory.path().join("notice-real.txt"),
            directory.path().join("source-notice.txt"),
        )
        .unwrap();
        assert_eq!(
            load_policy(&policy_path).unwrap_err(),
            PublicPolicyError::NoticeRead
        );
    }

    #[test]
    fn multiple_sources_fail_before_store_or_frontier_creation() {
        let notice = b"Authored offline notice.\n";
        let directory = TempPolicy::new();
        let mut value = synthetic_policy(notice);
        let mut second = value["sources"][0].clone();
        second["id"] = serde_json::Value::String("second-authored-source".to_owned());
        second["origin"] = serde_json::Value::String("https://manuals.example.net".to_owned());
        second["path_prefixes"] = serde_json::json!(["/manuals/"]);
        second["seeds"] = serde_json::json!(["https://manuals.example.net/manuals/"]);
        value["sources"].as_array_mut().unwrap().push(second);
        let policy_path = directory.write(&value, notice);
        let policy = load_policy(policy_path).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(policy.validate_enabled(now).is_ok());

        let store = directory.path().join("store");
        let frontier = directory.path().join("frontier.sqlite");
        let result = crate::controlled_crawler::run_public_crawl(&store, &frontier, &policy, 1);
        assert!(result.is_err());
        assert!(!store.exists());
        assert!(!frontier.exists());
    }
}
