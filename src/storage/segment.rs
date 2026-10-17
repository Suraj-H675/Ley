use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::index::{InMemoryIndex, IndexedDocument, Posting, analyze_document};
use crate::url_key::UrlKey;

use super::{
    MAX_DOCUMENTS, MAX_PHYSICAL_POSTING_RECORDS, MAX_POSITION_VALUES, MAX_SEGMENT_BYTES, Reader,
    StorageError, corrupt, get_u16, get_u32, get_u64, put_u16, put_u32, put_u64, sha256,
};

const MAGIC: &[u8; 8] = b"LEYSEG06";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const HEADER_PREFIX_BYTES: usize = 132;
const HEADER_BYTES: usize = 164;
const MAX_TERMS_PER_SEGMENT: usize = 500_000;
const POSITION_GAP_UVARINT_V1_CODEC_ID: u16 = 1;

#[cfg(test)]
thread_local! {
    static SEGMENT_ENCODINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_segment_encoding_count() {
    SEGMENT_ENCODINGS.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn segment_encoding_count() -> usize {
    SEGMENT_ENCODINGS.with(std::cell::Cell::get)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SegmentDescriptor {
    pub id: u64,
    pub byte_len: u64,
    pub sha256: [u8; 32],
    pub document_count: u32,
    pub term_count: u32,
    pub posting_count: u64,
    pub position_count: u64,
}

#[derive(Clone)]
pub(super) struct Segment {
    pub id: u64,
    pub documents: Vec<IndexedDocument>,
    pub postings: BTreeMap<String, BTreeMap<u32, Posting>>,
    pub descriptor: SegmentDescriptor,
}

impl Segment {
    pub fn from_documents(
        id: u64,
        mut documents: Vec<IndexedDocument>,
    ) -> Result<Self, StorageError> {
        if id == 0 || documents.is_empty() || documents.len() > MAX_DOCUMENTS {
            return Err(StorageError::CapacityExceeded(
                "segment document count or id",
            ));
        }
        documents.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        if documents.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(corrupt("segment contains duplicate document keys"));
        }

        let mut index = InMemoryIndex::new();
        for document in &documents {
            index.upsert_fields(
                document.id.clone(),
                document.effective_url.clone(),
                document.title.clone(),
                document.body.clone(),
            )?;
        }
        let mut postings = BTreeMap::new();
        for (term, by_document) in index.postings() {
            let mut records = BTreeMap::new();
            for (document_id, posting) in by_document {
                let ordinal = documents
                    .binary_search_by(|document| document.id.as_bytes().cmp(document_id.as_bytes()))
                    .map_err(|_| corrupt("rebuilt posting has no segment document"))?;
                let ordinal = u32::try_from(ordinal)
                    .map_err(|_| StorageError::CapacityExceeded("segment ordinal"))?;
                records.insert(ordinal, posting.clone());
            }
            postings.insert(term.clone(), records);
        }
        Self::from_checked_parts(id, documents, postings)
    }

    pub fn from_bytes(expected: &SegmentDescriptor, bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_SEGMENT_BYTES {
            return Err(corrupt("segment byte length is outside its bound"));
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(corrupt("segment magic mismatch"));
        }
        if get_u16(bytes, 8)? != FORMAT_MAJOR || get_u16(bytes, 10)? != FORMAT_MINOR {
            return Err(StorageError::UnsupportedFormat {
                major: get_u16(bytes, 8)?,
                minor: get_u16(bytes, 10)?,
            });
        }
        if get_u32(bytes, 12)? as usize != HEADER_BYTES {
            return Err(corrupt("segment header length mismatch"));
        }
        let id = get_u64(bytes, 16)?;
        let document_count = get_u32(bytes, 24)? as usize;
        let term_count = get_u32(bytes, 28)? as usize;
        let posting_count = get_u64(bytes, 32)?;
        let position_count = get_u64(bytes, 40)?;
        let docs_offset = get_u64(bytes, 48)?;
        let docs_len = get_u64(bytes, 56)?;
        let dict_offset = get_u64(bytes, 64)?;
        let dict_len = get_u64(bytes, 72)?;
        let postings_offset = get_u64(bytes, 80)?;
        let postings_len = get_u64(bytes, 88)?;
        if get_u16(bytes, 96)? != POSITION_GAP_UVARINT_V1_CODEC_ID
            || bytes.get(98..100) != Some(&[0; 2])
        {
            return Err(corrupt(
                "segment codec or reserved header bytes are invalid",
            ));
        }
        if bytes.get(132..HEADER_BYTES) != Some(sha256(&bytes[..HEADER_PREFIX_BYTES]).as_slice()) {
            return Err(corrupt("segment header checksum mismatch"));
        }
        let docs_range = checked_section(docs_offset, docs_len, bytes.len())?;
        let dict_range = checked_section(dict_offset, dict_len, bytes.len())?;
        let postings_range = checked_section(postings_offset, postings_len, bytes.len())?;
        if docs_range.start != HEADER_BYTES
            || docs_range.end != dict_range.start
            || dict_range.end != postings_range.start
            || postings_range.end != bytes.len()
        {
            return Err(corrupt(
                "segment sections overlap, have gaps, or trail the file",
            ));
        }
        if bytes.get(100..132) != Some(sha256(&bytes[HEADER_BYTES..]).as_slice()) {
            return Err(corrupt("segment payload checksum mismatch"));
        }
        let actual_descriptor = SegmentDescriptor {
            id,
            byte_len: bytes.len() as u64,
            sha256: sha256(bytes),
            document_count: u32::try_from(document_count)
                .map_err(|_| corrupt("segment document count overflow"))?,
            term_count: u32::try_from(term_count)
                .map_err(|_| corrupt("segment term count overflow"))?,
            posting_count,
            position_count,
        };
        if &actual_descriptor != expected {
            return Err(corrupt("segment bytes differ from the manifest descriptor"));
        }
        if id == 0
            || document_count == 0
            || document_count > MAX_DOCUMENTS
            || term_count > MAX_TERMS_PER_SEGMENT
            || posting_count > MAX_PHYSICAL_POSTING_RECORDS as u64
            || position_count > MAX_POSITION_VALUES
        {
            return Err(corrupt("segment counts exceed configured bounds"));
        }

        let documents = decode_documents(&bytes[docs_range])?;
        if documents.len() != document_count {
            return Err(corrupt("segment document count differs from its header"));
        }
        let (dictionary, parsed_term_count) = decode_dictionary(&bytes[dict_range], term_count)?;
        if parsed_term_count != term_count {
            return Err(corrupt("segment term count differs from its header"));
        }
        let postings_bytes = &bytes[postings_range];
        if dictionary.values().last().is_some_and(|block| {
            block.offset.checked_add(block.length) != Some(postings_bytes.len() as u64)
        }) || (dictionary.is_empty() && !postings_bytes.is_empty())
        {
            return Err(corrupt("dictionary does not cover the posting section"));
        }
        let mut postings = BTreeMap::new();
        let mut found_records = 0u64;
        let mut found_positions = 0u64;
        for (term, descriptor) in dictionary {
            let start = usize::try_from(descriptor.offset)
                .map_err(|_| corrupt("posting block offset overflow"))?;
            let end = start
                .checked_add(
                    usize::try_from(descriptor.length)
                        .map_err(|_| corrupt("posting block length overflow"))?,
                )
                .ok_or_else(|| corrupt("posting block end overflow"))?;
            let block = postings_bytes
                .get(start..end)
                .ok_or_else(|| corrupt("posting block crosses its section"))?;
            let (records, positions) = decode_posting_block(block, descriptor.count, &documents)?;
            if records.is_empty() {
                return Err(corrupt("dictionary term has an empty posting block"));
            }
            found_records = found_records
                .checked_add(records.len() as u64)
                .ok_or_else(|| corrupt("posting count overflow"))?;
            found_positions = found_positions
                .checked_add(positions)
                .ok_or_else(|| corrupt("position count overflow"))?;
            postings.insert(term, records);
        }
        if found_records != posting_count || found_positions != position_count {
            return Err(corrupt("segment posting totals differ from its header"));
        }
        validate_postings_against_documents(&documents, &postings)?;
        Ok(Self {
            id,
            documents,
            postings,
            descriptor: expected.clone(),
        })
    }

    fn from_checked_parts(
        id: u64,
        documents: Vec<IndexedDocument>,
        postings: BTreeMap<String, BTreeMap<u32, Posting>>,
    ) -> Result<Self, StorageError> {
        let document_count = u32::try_from(documents.len())
            .map_err(|_| StorageError::CapacityExceeded("segment document count"))?;
        let term_count = u32::try_from(postings.len())
            .map_err(|_| StorageError::CapacityExceeded("segment term count"))?;
        if documents.is_empty()
            || documents.len() > MAX_DOCUMENTS
            || postings.len() > MAX_TERMS_PER_SEGMENT
        {
            return Err(StorageError::CapacityExceeded(
                "segment document or term count",
            ));
        }
        let posting_count = postings
            .values()
            .try_fold(0u64, |total, records| {
                total.checked_add(records.len() as u64)
            })
            .ok_or(StorageError::CapacityExceeded("segment posting count"))?;
        let position_count = postings
            .values()
            .flat_map(BTreeMap::values)
            .try_fold(0u64, |total, posting| {
                total
                    .checked_add(posting.title_positions.len() as u64)
                    .and_then(|value| value.checked_add(posting.body_positions.len() as u64))
            })
            .ok_or(StorageError::CapacityExceeded("segment position count"))?;
        if posting_count > MAX_PHYSICAL_POSTING_RECORDS as u64
            || position_count > MAX_POSITION_VALUES
        {
            return Err(StorageError::CapacityExceeded(
                "segment posting or position count",
            ));
        }
        let payload = encode_payload(&documents, &postings)?;
        if payload
            .len()
            .checked_add(HEADER_BYTES)
            .is_none_or(|length| length > MAX_SEGMENT_BYTES)
        {
            return Err(StorageError::CapacityExceeded(
                "single segment byte limit exceeded; reduce indexed document content",
            ));
        }
        let byte_len = (HEADER_BYTES + payload.len()) as u64;
        let descriptor = SegmentDescriptor {
            id,
            byte_len,
            sha256: [0; 32],
            document_count,
            term_count,
            posting_count,
            position_count,
        };
        let mut segment = Self {
            id,
            documents,
            postings,
            descriptor,
        };
        let bytes = segment.encode()?;
        segment.descriptor.byte_len = bytes.len() as u64;
        segment.descriptor.sha256 = sha256(&bytes);
        Ok(segment)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        #[cfg(test)]
        SEGMENT_ENCODINGS.with(|count| count.set(count.get() + 1));
        let payload = encode_payload(&self.documents, &self.postings)?;
        let mut bytes = vec![0; HEADER_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&FORMAT_MAJOR.to_be_bytes());
        bytes[10..12].copy_from_slice(&FORMAT_MINOR.to_be_bytes());
        bytes[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_be_bytes());
        bytes[16..24].copy_from_slice(&self.id.to_be_bytes());
        bytes[24..28].copy_from_slice(&self.descriptor.document_count.to_be_bytes());
        bytes[28..32].copy_from_slice(&self.descriptor.term_count.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.descriptor.posting_count.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.descriptor.position_count.to_be_bytes());
        let docs_len = u64::from_be_bytes(
            payload[0..8]
                .try_into()
                .map_err(|_| corrupt("doc section header"))?,
        );
        let dict_len = u64::from_be_bytes(
            payload[8..16]
                .try_into()
                .map_err(|_| corrupt("dictionary section header"))?,
        );
        let postings_len = u64::from_be_bytes(
            payload[16..24]
                .try_into()
                .map_err(|_| corrupt("posting section header"))?,
        );
        let docs_offset = HEADER_BYTES as u64;
        let dict_offset = docs_offset
            .checked_add(docs_len)
            .ok_or_else(|| corrupt("section offset overflow"))?;
        let postings_offset = dict_offset
            .checked_add(dict_len)
            .ok_or_else(|| corrupt("section offset overflow"))?;
        bytes[48..56].copy_from_slice(&docs_offset.to_be_bytes());
        bytes[56..64].copy_from_slice(&docs_len.to_be_bytes());
        bytes[64..72].copy_from_slice(&dict_offset.to_be_bytes());
        bytes[72..80].copy_from_slice(&dict_len.to_be_bytes());
        bytes[80..88].copy_from_slice(&postings_offset.to_be_bytes());
        bytes[88..96].copy_from_slice(&postings_len.to_be_bytes());
        bytes[96..98].copy_from_slice(&POSITION_GAP_UVARINT_V1_CODEC_ID.to_be_bytes());
        bytes[98..100].fill(0);
        bytes.extend_from_slice(&payload[24..]);
        let payload_checksum = sha256(&bytes[HEADER_BYTES..]);
        bytes[100..132].copy_from_slice(&payload_checksum);
        let header_checksum = sha256(&bytes[..HEADER_PREFIX_BYTES]);
        bytes[132..164].copy_from_slice(&header_checksum);
        let descriptor_hash = sha256(&bytes);
        if descriptor_hash == [0; 32] {
            return Err(corrupt("impossible segment checksum"));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy)]
struct PostingBlockDescriptor {
    offset: u64,
    length: u64,
    count: usize,
}

fn encode_payload(
    documents: &[IndexedDocument],
    postings: &BTreeMap<String, BTreeMap<u32, Posting>>,
) -> Result<Vec<u8>, StorageError> {
    let mut docs = Vec::new();
    put_u32(
        &mut docs,
        u32::try_from(documents.len()).map_err(|_| corrupt("document count overflow"))?,
    );
    for document in documents {
        let key = document.id.as_bytes();
        let effective = document.effective_url.as_bytes();
        let title = document.title.as_bytes();
        let body = document.body.as_bytes();
        put_u16(
            &mut docs,
            u16::try_from(key.len()).map_err(|_| corrupt("document key too long"))?,
        );
        put_u16(
            &mut docs,
            u16::try_from(effective.len()).map_err(|_| corrupt("effective URL too long"))?,
        );
        put_u32(
            &mut docs,
            u32::try_from(title.len()).map_err(|_| corrupt("title too long"))?,
        );
        put_u32(
            &mut docs,
            u32::try_from(body.len()).map_err(|_| corrupt("body too long"))?,
        );
        docs.extend_from_slice(&decode_version_id(&document.version_id)?);
        docs.extend_from_slice(key);
        docs.extend_from_slice(effective);
        docs.extend_from_slice(title);
        docs.extend_from_slice(body);
    }

    let mut posting_bytes = Vec::new();
    let mut dictionary_records = Vec::new();
    for (term, by_ordinal) in postings {
        let offset = posting_bytes.len() as u64;
        let mut prior_ordinal = None;
        for (ordinal, posting) in by_ordinal {
            let gap = match prior_ordinal {
                None => ordinal.checked_add(1),
                Some(prior) => ordinal.checked_sub(prior),
            }
            .filter(|gap| *gap > 0)
            .ok_or_else(|| corrupt("posting ordinals are unordered or overflow"))?;
            encode_uvarint(gap, &mut posting_bytes);
            encode_positions(&posting.title_positions, &mut posting_bytes)?;
            encode_positions(&posting.body_positions, &mut posting_bytes)?;
            prior_ordinal = Some(*ordinal);
        }
        let length = (posting_bytes.len() as u64)
            .checked_sub(offset)
            .ok_or_else(|| corrupt("posting block length underflow"))?;
        dictionary_records.push((term, offset, length, by_ordinal.len()));
    }
    let mut dictionary = Vec::new();
    put_u32(
        &mut dictionary,
        u32::try_from(dictionary_records.len()).map_err(|_| corrupt("term count overflow"))?,
    );
    for (term, offset, length, count) in dictionary_records {
        put_u16(
            &mut dictionary,
            u16::try_from(term.len()).map_err(|_| corrupt("term too long"))?,
        );
        dictionary.extend_from_slice(term.as_bytes());
        put_u64(&mut dictionary, offset);
        put_u64(&mut dictionary, length);
        put_u32(
            &mut dictionary,
            u32::try_from(count).map_err(|_| corrupt("posting count overflow"))?,
        );
    }
    let mut payload = Vec::with_capacity(24 + docs.len() + dictionary.len() + posting_bytes.len());
    put_u64(&mut payload, docs.len() as u64);
    put_u64(&mut payload, dictionary.len() as u64);
    put_u64(&mut payload, posting_bytes.len() as u64);
    payload.extend_from_slice(&docs);
    payload.extend_from_slice(&dictionary);
    payload.extend_from_slice(&posting_bytes);
    Ok(payload)
}

fn decode_documents(bytes: &[u8]) -> Result<Vec<IndexedDocument>, StorageError> {
    let mut reader = Reader::new(bytes);
    let count = reader.u32()? as usize;
    if count == 0 || count > MAX_DOCUMENTS {
        return Err(corrupt("segment document count exceeds its bound"));
    }
    let mut documents = Vec::with_capacity(count);
    let mut previous_key: Option<String> = None;
    for _ in 0..count {
        let key_len = usize::from(reader.u16()?);
        let effective_len = usize::from(reader.u16()?);
        let title_len = reader.u32()? as usize;
        let body_len = reader.u32()? as usize;
        if key_len == 0
            || key_len > crate::url_key::MAX_URL_KEY_BYTES
            || effective_len == 0
            || effective_len > super::MAX_EFFECTIVE_URL_BYTES
            || title_len > crate::html::MAX_TITLE_BYTES
            || title_len
                .checked_add(body_len)
                .is_none_or(|size| size > crate::html::MAX_FIELDS_BYTES)
        {
            return Err(corrupt("segment document field length exceeds its bound"));
        }
        let mut stored_version = [0; 32];
        stored_version.copy_from_slice(reader.bytes(32)?);
        let id = reader.string(key_len)?;
        let effective_url = reader.string(effective_len)?;
        let title = reader.string(title_len)?;
        let body = reader.string(body_len)?;
        UrlKey::parse(&id).map_err(|error| corrupt(&error.to_string()))?;
        UrlKey::parse(&effective_url).map_err(|error| corrupt(&error.to_string()))?;
        if previous_key
            .as_ref()
            .is_some_and(|previous| previous.as_bytes() >= id.as_bytes())
        {
            return Err(corrupt("segment document keys are not strictly sorted"));
        }
        previous_key = Some(id.clone());
        let document = analyze_document(id, effective_url, title, body)?;
        if decode_version_id(&document.version_id)? != stored_version {
            return Err(corrupt(
                "segment document version differs from analyzed fields",
            ));
        }
        documents.push(document);
    }
    reader.finish("document section has trailing or truncated bytes")?;
    Ok(documents)
}

fn validate_postings_against_documents(
    documents: &[IndexedDocument],
    postings: &BTreeMap<String, BTreeMap<u32, Posting>>,
) -> Result<(), StorageError> {
    let mut records_by_ordinal = (0..documents.len())
        .map(|_| Vec::<(&str, &Posting)>::new())
        .collect::<Vec<_>>();
    for (term, records) in postings {
        for (&ordinal, posting) in records {
            let ordinal = usize::try_from(ordinal)
                .map_err(|_| corrupt("posting ordinal does not fit this platform"))?;
            let document_records = records_by_ordinal
                .get_mut(ordinal)
                .ok_or_else(|| corrupt("posting ordinal is outside the document table"))?;
            document_records.push((term, posting));
        }
    }

    for (ordinal, document) in documents.iter().enumerate() {
        let mut expected = BTreeMap::<&str, Posting>::new();
        add_expected_positions(&mut expected, &document.title_terms, true)?;
        add_expected_positions(&mut expected, &document.body_terms, false)?;
        let actual = &records_by_ordinal[ordinal];
        if actual.len() != expected.len()
            || actual.iter().zip(&expected).any(
                |((actual_term, actual_posting), (expected_term, expected_posting))| {
                    *actual_term != *expected_term || *actual_posting != expected_posting
                },
            )
        {
            return Err(corrupt(
                "segment postings differ from analyzed document fields",
            ));
        }
    }
    Ok(())
}

fn add_expected_positions<'a>(
    expected: &mut BTreeMap<&'a str, Posting>,
    terms: &'a [String],
    title: bool,
) -> Result<(), StorageError> {
    for (position, term) in terms.iter().enumerate() {
        let position =
            u32::try_from(position).map_err(|_| corrupt("document position overflow"))?;
        let posting = expected.entry(term).or_insert_with(|| Posting {
            title_positions: Vec::new(),
            body_positions: Vec::new(),
        });
        if title {
            posting.title_positions.push(position);
        } else {
            posting.body_positions.push(position);
        }
    }
    Ok(())
}

fn decode_dictionary(
    bytes: &[u8],
    expected_count: usize,
) -> Result<(BTreeMap<String, PostingBlockDescriptor>, usize), StorageError> {
    let mut reader = Reader::new(bytes);
    let count = reader.u32()? as usize;
    if count != expected_count || count > MAX_TERMS_PER_SEGMENT {
        return Err(corrupt(
            "segment dictionary count exceeds its bound or header",
        ));
    }
    let mut dictionary = BTreeMap::new();
    let mut previous_term: Option<String> = None;
    let mut previous_end = 0u64;
    for _ in 0..count {
        let length = usize::from(reader.u16()?);
        if length == 0 || length > crate::analyzer::MAX_TERM_SCALARS * 4 {
            return Err(corrupt("dictionary term length exceeds its bound"));
        }
        let term = reader.string(length)?;
        if previous_term
            .as_ref()
            .is_some_and(|previous| previous.as_bytes() >= term.as_bytes())
        {
            return Err(corrupt("segment terms are not strictly sorted"));
        }
        if crate::analyzer::Analyzer.analyze(&term).ok() != Some(vec![term.clone()]) {
            return Err(corrupt(
                "dictionary entry is not one canonical analyzed term",
            ));
        }
        let offset = reader.u64()?;
        let length = reader.u64()?;
        let record_count = reader.u32()? as usize;
        if offset != previous_end || length == 0 || record_count == 0 {
            return Err(corrupt("dictionary posting ranges are unordered or empty"));
        }
        previous_end = offset
            .checked_add(length)
            .ok_or_else(|| corrupt("dictionary offset overflow"))?;
        if dictionary
            .insert(
                term.clone(),
                PostingBlockDescriptor {
                    offset,
                    length,
                    count: record_count,
                },
            )
            .is_some()
        {
            return Err(corrupt("duplicate dictionary term"));
        }
        previous_term = Some(term);
    }
    reader.finish("dictionary section has trailing or truncated bytes")?;
    Ok((dictionary, count))
}

fn decode_posting_block(
    bytes: &[u8],
    record_count: usize,
    documents: &[IndexedDocument],
) -> Result<(BTreeMap<u32, Posting>, u64), StorageError> {
    if record_count > MAX_PHYSICAL_POSTING_RECORDS {
        return Err(corrupt("term posting count exceeds its bound"));
    }
    let mut position = 0usize;
    let mut previous_ordinal: Option<u32> = None;
    let mut records = BTreeMap::new();
    let mut position_total = 0u64;
    for _ in 0..record_count {
        let gap = decode_uvarint(bytes, &mut position)?;
        if gap == 0 {
            return Err(corrupt("posting ordinal gap is zero"));
        }
        let ordinal = match previous_ordinal {
            None => gap.checked_sub(1),
            Some(previous) => previous.checked_add(gap),
        }
        .ok_or_else(|| corrupt("posting ordinal overflow"))?;
        let document = documents
            .get(ordinal as usize)
            .ok_or_else(|| corrupt("posting ordinal is out of range"))?;
        let title_positions = decode_positions(bytes, &mut position, document.title_terms.len())?;
        let body_positions = decode_positions(bytes, &mut position, document.body_terms.len())?;
        if title_positions.is_empty() && body_positions.is_empty() {
            return Err(corrupt("posting record has no positions"));
        }
        position_total = position_total
            .checked_add((title_positions.len() + body_positions.len()) as u64)
            .ok_or_else(|| corrupt("position count overflow"))?;
        if records
            .insert(
                ordinal,
                Posting {
                    title_positions,
                    body_positions,
                },
            )
            .is_some()
        {
            return Err(corrupt("duplicate posting ordinal"));
        }
        previous_ordinal = Some(ordinal);
    }
    if position != bytes.len() {
        return Err(corrupt("posting block has trailing bytes"));
    }
    Ok((records, position_total))
}

fn encode_positions(positions: &[u32], out: &mut Vec<u8>) -> Result<(), StorageError> {
    encode_uvarint(
        u32::try_from(positions.len()).map_err(|_| corrupt("position count overflow"))?,
        out,
    );
    let mut prior: Option<u32> = None;
    for position in positions {
        let gap = match prior {
            None => position.checked_add(1),
            Some(previous) => position.checked_sub(previous),
        }
        .filter(|gap| *gap > 0)
        .ok_or_else(|| corrupt("positions are unordered or overflow"))?;
        encode_uvarint(gap, out);
        prior = Some(*position);
    }
    Ok(())
}

fn decode_positions(
    bytes: &[u8],
    cursor: &mut usize,
    field_length: usize,
) -> Result<Vec<u32>, StorageError> {
    let count = decode_uvarint(bytes, cursor)? as usize;
    if count > field_length || count > crate::html::MAX_DOCUMENT_TOKENS {
        return Err(corrupt("position count exceeds the analyzed field length"));
    }
    let mut positions = Vec::with_capacity(count);
    let mut prior: Option<u32> = None;
    for _ in 0..count {
        let gap = decode_uvarint(bytes, cursor)?;
        if gap == 0 {
            return Err(corrupt("position gap is zero"));
        }
        let position = match prior {
            None => gap.checked_sub(1),
            Some(previous) => previous.checked_add(gap),
        }
        .ok_or_else(|| corrupt("position delta overflow"))?;
        if position as usize >= field_length {
            return Err(corrupt("position is outside its analyzed field"));
        }
        positions.push(position);
        prior = Some(position);
    }
    Ok(positions)
}

fn encode_uvarint(mut value: u32, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_uvarint(bytes: &[u8], cursor: &mut usize) -> Result<u32, StorageError> {
    let start = *cursor;
    let mut value = 0u32;
    for index in 0..5 {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| corrupt("truncated position varint"))?;
        *cursor = (*cursor)
            .checked_add(1)
            .ok_or_else(|| corrupt("varint offset overflow"))?;
        if index == 4 && byte & 0xf0 != 0 {
            return Err(corrupt("u32 position varint overflow"));
        }
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(corrupt("position varint is noncanonical"));
            }
            return Ok(value);
        }
    }
    *cursor = start;
    Err(corrupt("position varint exceeds five bytes"))
}

fn checked_section(
    offset: u64,
    length: u64,
    file_len: usize,
) -> Result<std::ops::Range<usize>, StorageError> {
    let start = usize::try_from(offset).map_err(|_| corrupt("section offset overflow"))?;
    let length = usize::try_from(length).map_err(|_| corrupt("section length overflow"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| corrupt("section end overflow"))?;
    if end > file_len {
        return Err(corrupt("section crosses the segment file"));
    }
    Ok(start..end)
}

fn decode_version_id(value: &str) -> Result<[u8; 32], StorageError> {
    super::decode_version_id(value)
}
