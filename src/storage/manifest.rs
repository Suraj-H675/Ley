use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::segment::SegmentDescriptor;
use super::{MAX_MANIFEST_BYTES, StorageError, corrupt, put_u16, put_u32, put_u64, sha256};

const MANIFEST_MAGIC: &[u8; 8] = b"LEYMAN06";
const CURRENT_MAGIC: &[u8; 8] = b"LEYHEAD6";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const MANIFEST_HEADER_BYTES: usize = 112;
const CURRENT_BYTES: usize = 112;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LiveReference {
    pub segment_id: u64,
    pub ordinal: u32,
    pub version: [u8; 32],
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlRecord {
    pub high_water: u64,
    pub terminal: BTreeMap<u64, TerminalRecord>,
    pub policy: BTreeMap<u64, PolicyRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum TerminalRecord {
    Upsert([u8; 32]),
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum PolicyRecord {
    Revoked,
    Readmitted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FieldDocumentFrequency {
    pub title: u64,
    pub body: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorpusStatistics {
    pub document_count: u64,
    pub live_posting_record_count: u64,
    pub title_token_total: u64,
    pub body_token_total: u64,
    pub field_document_frequencies: BTreeMap<String, FieldDocumentFrequency>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub generation_id: u64,
    pub parent_id: u64,
    pub next_segment_id: u64,
    pub format_major: u16,
    pub format_minor: u16,
    pub store_id: [u8; 16],
    pub analyzer_id: String,
    pub html_schema_id: String,
    pub segments: Vec<SegmentDescriptor>,
    pub live: BTreeMap<String, LiveReference>,
    pub controls: BTreeMap<String, ControlRecord>,
    pub statistics: CorpusStatistics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CurrentPointer {
    pub store_id: [u8; 16],
    pub generation_id: u64,
    pub manifest_len: u64,
    pub manifest_sha256: [u8; 32],
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let payload = serde_json::to_vec(self)
            .map_err(|_| corrupt("manifest metadata could not be encoded"))?;
        if payload
            .len()
            .checked_add(MANIFEST_HEADER_BYTES)
            .is_none_or(|length| length > MAX_MANIFEST_BYTES)
        {
            return Err(StorageError::CapacityExceeded("manifest bytes"));
        }
        let mut bytes = vec![0; MANIFEST_HEADER_BYTES];
        bytes[..8].copy_from_slice(MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_MAJOR.to_be_bytes());
        bytes[10..12].copy_from_slice(&FORMAT_MINOR.to_be_bytes());
        bytes[12..16].copy_from_slice(&(MANIFEST_HEADER_BYTES as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&self.generation_id.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.parent_id.to_be_bytes());
        bytes[32..40].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes[40..72].copy_from_slice(&sha256(&payload));
        let header_checksum = sha256(&bytes[..72]);
        bytes[72..104].copy_from_slice(&header_checksum);
        bytes[104..112].fill(0);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        expected_store_id: [u8; 16],
        expected_generation_id: u64,
    ) -> Result<Self, StorageError> {
        if bytes.len() < MANIFEST_HEADER_BYTES || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(corrupt("manifest byte length is outside its bound"));
        }
        if bytes.get(..8) != Some(MANIFEST_MAGIC.as_slice()) {
            return Err(corrupt("manifest magic mismatch"));
        }
        let major = get_u16(bytes, 8)?;
        let minor = get_u16(bytes, 10)?;
        if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
            return Err(StorageError::UnsupportedFormat { major, minor });
        }
        if get_u32(bytes, 12)? as usize != MANIFEST_HEADER_BYTES {
            return Err(corrupt("manifest header length mismatch"));
        }
        let generation_id = get_u64(bytes, 16)?;
        let parent_id = get_u64(bytes, 24)?;
        let payload_len = usize::try_from(get_u64(bytes, 32)?)
            .map_err(|_| corrupt("manifest payload length overflow"))?;
        let payload_end = MANIFEST_HEADER_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| corrupt("manifest payload end overflow"))?;
        if generation_id == 0
            || generation_id != expected_generation_id
            || parent_id >= generation_id
        {
            return Err(corrupt("manifest generation or parent identity is invalid"));
        }
        if payload_end != bytes.len() || bytes.get(104..112) != Some(&[0; 8]) {
            return Err(corrupt("manifest length or reserved bytes are invalid"));
        }
        if bytes.get(72..104) != Some(sha256(&bytes[..72]).as_slice()) {
            return Err(corrupt("manifest header checksum mismatch"));
        }
        let payload = &bytes[MANIFEST_HEADER_BYTES..];
        if bytes.get(40..72) != Some(sha256(payload).as_slice()) {
            return Err(corrupt("manifest payload checksum mismatch"));
        }
        let manifest: Self = serde_json::from_slice(payload)
            .map_err(|_| corrupt("manifest metadata is malformed"))?;
        if manifest.generation_id != generation_id
            || manifest.parent_id != parent_id
            || manifest.next_segment_id == 0
            || manifest.store_id != expected_store_id
            || manifest.format_major != FORMAT_MAJOR
            || manifest.format_minor != FORMAT_MINOR
        {
            return Err(corrupt("manifest payload identity differs from its header"));
        }
        Ok(manifest)
    }
}

impl CurrentPointer {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CURRENT_BYTES);
        bytes.extend_from_slice(CURRENT_MAGIC);
        put_u16(&mut bytes, FORMAT_MAJOR);
        put_u16(&mut bytes, FORMAT_MINOR);
        put_u32(&mut bytes, CURRENT_BYTES as u32);
        bytes.extend_from_slice(&self.store_id);
        put_u64(&mut bytes, self.generation_id);
        put_u64(&mut bytes, self.manifest_len);
        bytes.extend_from_slice(&self.manifest_sha256);
        let checksum = sha256(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub fn decode(bytes: &[u8], expected_store_id: [u8; 16]) -> Result<Self, StorageError> {
        if bytes.len() != CURRENT_BYTES || bytes.get(..8) != Some(CURRENT_MAGIC.as_slice()) {
            return Err(corrupt("CURRENT magic or length mismatch"));
        }
        let major = get_u16(bytes, 8)?;
        let minor = get_u16(bytes, 10)?;
        if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
            return Err(StorageError::UnsupportedFormat { major, minor });
        }
        if get_u32(bytes, 12)? as usize != CURRENT_BYTES {
            return Err(corrupt("CURRENT header length mismatch"));
        }
        let mut store_id = [0; 16];
        store_id.copy_from_slice(&bytes[16..32]);
        if store_id != expected_store_id {
            return Err(corrupt("CURRENT belongs to another store"));
        }
        if bytes.get(80..112) != Some(sha256(&bytes[..80]).as_slice()) {
            return Err(corrupt("CURRENT checksum mismatch"));
        }
        let generation_id = get_u64(bytes, 32)?;
        let manifest_len = get_u64(bytes, 40)?;
        let mut manifest_sha256 = [0; 32];
        manifest_sha256.copy_from_slice(&bytes[48..80]);
        if generation_id == 0
            || manifest_len < MANIFEST_HEADER_BYTES as u64
            || manifest_len > MAX_MANIFEST_BYTES as u64
        {
            return Err(corrupt("CURRENT manifest identity or length is invalid"));
        }
        Ok(Self {
            store_id,
            generation_id,
            manifest_len,
            manifest_sha256,
        })
    }
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, StorageError> {
    let raw = bytes
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or_else(|| corrupt("offset overflow"))?,
        )
        .ok_or_else(|| corrupt("truncated manifest integer"))?;
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
        .ok_or_else(|| corrupt("truncated manifest integer"))?;
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
        .ok_or_else(|| corrupt("truncated manifest integer"))?;
    Ok(u64::from_be_bytes(
        raw.try_into()
            .map_err(|_| corrupt("truncated manifest integer"))?,
    ))
}
