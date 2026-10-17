use std::fmt;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

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

#[derive(Clone, Debug)]
pub struct PublicCrawlPolicy {
    schema: String,
    enabled: bool,
    identity: String,
    contact: String,
    sources: Vec<PublicSourcePolicy>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublicCrawlPolicy {
    schema: String,
    enabled: bool,
    identity: String,
    contact: String,
    sources: Vec<PublicSourcePolicy>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicPolicyError {
    Read,
    TooLarge,
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
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PublicPolicyError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|_| PublicPolicyError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(PublicPolicyError::Read);
        }
        if metadata.len() > MAX_POLICY_FILE_BYTES as u64 {
            return Err(PublicPolicyError::TooLarge);
        }
        let file = fs::File::open(path).map_err(|_| PublicPolicyError::Read)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_POLICY_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PublicPolicyError::Read)?;
        if bytes.len() > MAX_POLICY_FILE_BYTES {
            return Err(PublicPolicyError::TooLarge);
        }
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PublicPolicyError> {
        if bytes.len() > MAX_POLICY_FILE_BYTES {
            return Err(PublicPolicyError::TooLarge);
        }
        let raw: RawPublicCrawlPolicy =
            serde_json::from_slice(bytes).map_err(|_| PublicPolicyError::Invalid)?;
        Ok(Self {
            schema: raw.schema,
            enabled: raw.enabled,
            identity: raw.identity,
            contact: raw.contact,
            sources: raw.sources,
            digest: Sha256::digest(bytes).into(),
        })
    }

    pub fn validate_enabled(&self, now_ms: u64) -> Result<(), PublicPolicyError> {
        if self.schema != "ley-public-sources-v1" {
            return Err(PublicPolicyError::Invalid);
        }
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
            source.validate(now_ms, &self.contact, &mut ids)?;
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
        let notice = source.notice_bytes()?;
        let retention_until =
            now_ms.saturating_add(u64::from(source.retention_days) * 24 * 60 * 60 * 1000);
        let visible_until_ms = source.expires_at_ms.min(retention_until);
        if visible_until_ms <= now_ms {
            return Err(PublicPolicyError::Invalid);
        }
        Ok(crate::storage::PublicCollectionGate {
            policy_sha256: self.sha256(),
            source_id: source.id.clone(),
            origin: source.origin.clone(),
            path_prefixes: source.path_prefixes.clone(),
            installed_at_ms: now_ms,
            visible_until_ms,
            license: source.license.clone(),
            source_version: source.source_version.clone(),
            notice_file: source.notice_file.clone(),
            notice_sha256: Sha256::digest(notice)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
    }

    pub(crate) fn notice_bytes(&self) -> Result<&'static [u8], PublicPolicyError> {
        if self.sources.len() != 1 {
            return Err(PublicPolicyError::Invalid);
        }
        self.sources[0].notice_bytes()
    }

    pub fn sha256(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn matches_sha256(&self, supplied: &str) -> bool {
        supplied.len() == 64
            && supplied.bytes().all(|byte| byte.is_ascii_hexdigit())
            && supplied.eq_ignore_ascii_case(&self.sha256())
    }
}

impl PublicSourcePolicy {
    fn notice_bytes(&self) -> Result<&'static [u8], PublicPolicyError> {
        match self.notice_file.as_str() {
            "rust-stdlib-documentation-MIT.txt" => Ok(include_bytes!(
                "../notices/rust-stdlib-documentation-MIT.txt"
            )),
            _ => Err(PublicPolicyError::Invalid),
        }
    }

    fn validate(
        &self,
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
        if self.license != "MIT"
            || self.source_version.len() > 200
            || self.source_version.trim().is_empty()
            || self.source_version.chars().any(char::is_control)
            || self.notice_file != "rust-stdlib-documentation-MIT.txt"
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
    use super::{PublicCrawlPolicy, PublicPolicyError};
    use sha2::{Digest, Sha256};

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
        assert!(source.display_permission.granted);
        assert_eq!(source.license, "MIT");
        assert_eq!(
            source.source_version,
            "rustdoc 1.99.0 (b940084d7, 2026-09-28)"
        );
        assert_eq!(source.notice_file, "rust-stdlib-documentation-MIT.txt");
        assert_eq!(source.robots, "obey");
        assert_eq!(source.removal_contact, policy.contact());

        let mut candidate: serde_json::Value =
            serde_json::from_slice(include_str!("../policy/public-sources.json").as_bytes())
                .unwrap();
        candidate["enabled"] = serde_json::Value::Bool(true);
        let approved_shape = from_value(&candidate);
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
            Sha256::digest(approved_shape.notice_bytes().unwrap())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
    }

    #[test]
    fn enabled_policy_requires_real_contact_and_admitted_sources() {
        let source = serde_json::json!({
            "id": "candidate",
            "origin": "https://www.example.org",
            "path_prefixes": ["/public/"],
            "seeds": ["https://www.example.org/public/"],
            "fetch_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "storage_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "index_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "display_permission": {"granted":true, "basis":"unit-test fixture only", "evidence":"authored unit-test permission evidence", "reviewed_at_ms":1},
            "license": "MIT",
            "source_version": "test-fixture-v1",
            "notice_file": "rust-stdlib-documentation-MIT.txt",
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
            "schema":"ley-public-sources-v1",
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
}
