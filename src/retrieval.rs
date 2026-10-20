//! Typed lexical retrieval and evidence references.
//!
//! `QuestionRequest` selects ordinary-question semantics explicitly. The existing
//! `PersistentIndex::query(&str)` and `ReadView::query(&str)` methods remain the
//! advanced Boolean/phrase DSL. A retrieval hit reports matching indexed text;
//! it does not assess whether that text answers or verifies a factual claim.
//!
//! Evidence ranges address UTF-8 bytes in the persisted extracted `IndexedDocument.body`,
//! never raw HTML. The requested URL is the document key; the effective URL is display
//! metadata. A resolver checks current store visibility and policy on every open. Logical
//! tombstone/revocation does not physically erase immutable prior segment bytes, and a copy
//! already returned to a caller cannot be recalled by a later visibility change.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analyzer::{AnalyzeError, Analyzer, MAX_TERM_SCALARS};
use crate::url_key::UrlKey;

pub const RETRIEVAL_CONTRACT_VERSION: u16 = 1;
pub const PASSAGE_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_MAX_HITS: u8 = 8;
pub const MAX_HITS: u8 = 8;
pub(crate) const MAX_QUESTION_BYTES: usize = 4096;
pub(crate) const MAX_QUESTION_TOKEN_OCCURRENCES: usize = 64;
pub(crate) const MAX_QUESTION_DISTINCT_TERMS: usize = 32;
pub(crate) const MAX_QUESTION_PHRASE_TERMS: usize = 16;
pub(crate) const MAX_QUESTION_SURFACE_VARIANTS: usize = 3;
pub(crate) const MAX_QUESTION_LITERAL_PHRASES: usize = 8;
pub(crate) const MAX_QUESTION_LITERAL_BYTES: usize = 128;
pub(crate) const MAX_QUESTION_PHRASE_STEPS: usize = 25_000_000;
pub(crate) const MAX_PASSAGE_BYTES: usize = 8192;
pub(crate) const PASSAGE_STEP_BYTES: usize = 4096;
pub(crate) const MAX_PASSAGES_PER_DOCUMENT: usize = 258;
pub(crate) const MAX_RESPONSE_PASSAGE_BYTES: usize = 256 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 512 * 1024;

const REFERENCE_DOMAIN: &[u8] = b"ley-evidence-reference-v1\0";

/// A versioned request whose variant makes ordinary-question semantics explicit.
/// Advanced DSL expressions continue to use the existing `query(&str)` API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum RetrievalRequest {
    Question(QuestionRequest),
}

impl RetrievalRequest {
    pub fn question(question: impl Into<String>) -> Self {
        Self::Question(QuestionRequest::new(question))
    }
}

/// Ordinary natural-language query text with a bounded result count.
///
/// Input is limited to 4,096 UTF-8 bytes, 64 analyzed token occurrences, 32 distinct
/// normalized terms, and 16 terms in each quoted or identifier-like phrase group.
/// Unquoted ordinary terms are alternatives; quoted phrases and identifier-like
/// whitespace atoms are matched as contiguous analyzed-token groups. The question path uses a small versioned English
/// function-word list, retains negation, and does not rewrite or infer an answer. Stopword
/// filtering applies only to unquoted ordinary terms; quoted phrases keep every term.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionRequest {
    contract_version: u16,
    question: String,
    max_hits: u8,
}

impl QuestionRequest {
    pub fn new(question: impl Into<String>) -> Self {
        Self {
            contract_version: RETRIEVAL_CONTRACT_VERSION,
            question: question.into(),
            max_hits: DEFAULT_MAX_HITS,
        }
    }

    pub fn with_max_hits(mut self, max_hits: u8) -> Result<Self, RetrievalError> {
        if !(1..=MAX_HITS).contains(&max_hits) {
            return Err(RetrievalError::InvalidHitLimit);
        }
        self.max_hits = max_hits;
        Ok(self)
    }

    pub fn question(&self) -> &str {
        &self.question
    }

    pub fn max_hits(&self) -> u8 {
        self.max_hits
    }

    pub fn contract_version(&self) -> u16 {
        self.contract_version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMode {
    Question,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalStatus {
    /// One or more extracted body passages matched the lexical query plan.
    RetrievedText,
    /// The bounded, complete lookup found no body text matching the query plan.
    NoRelevantTextMatch,
    /// The lookup cannot provide body text that meets the request's evidence threshold.
    InsufficientEvidence(InsufficientEvidenceReason),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsufficientEvidenceReason {
    NoSearchableTerms,
    OnlyTitleMatches,
    WorkBudgetReached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalCompleteness {
    /// All selected query postings and candidate passages were evaluated within the caps.
    Complete,
    /// A sample or work cap omitted part of the current corpus from consideration.
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerAssessment {
    NotAssessed,
}

/// A typed status and passages from the current indexed body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalResponse {
    pub contract_version: u16,
    pub mode: RetrievalMode,
    /// Diagnostic snapshot generation; this is not part of evidence identity.
    pub generation_id: u64,
    pub status: RetrievalStatus,
    pub completeness: RetrievalCompleteness,
    pub normalized_terms: Vec<String>,
    pub hits: Vec<EvidenceHit>,
    pub answer_assessment: AnswerAssessment,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHit {
    /// Manifest document key, which is the requested URL.
    pub requested_url: String,
    /// Indexed redirect destination, not the document key.
    pub effective_url: String,
    pub title: String,
    pub score: f64,
    pub matched_terms: Vec<String>,
    pub matched_phrases: Vec<Vec<String>>,
    pub passage: EvidencePassage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePassage {
    pub reference: EvidenceReference,
    pub text: String,
}

/// Stable identity for a canonical passage window in one extracted document version.
/// The digest covers store ID, requested URL, content version, passage schema, and
/// exclusive UTF-8 byte range. It is a public deterministic checksum, not an
/// authenticator; a resolver revalidates the canonical window and current visibility.
/// Schema v1 uses UTF-8-safe windows up to 8,192 bytes with a 4,096-byte step.
/// Generation, segment, ordinal, and effective URL are intentionally excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub store_id: [u8; 16],
    pub requested_url: String,
    pub content_version: [u8; 32],
    pub passage_schema_version: u16,
    /// UTF-8 byte offset in extracted body text, inclusive.
    pub start_byte: u32,
    /// UTF-8 byte offset in extracted body text, exclusive.
    pub end_byte: u32,
    /// Public checksum of the reference fields, not proof of authorization or validity.
    pub identity_sha256: [u8; 32],
}

impl EvidenceReference {
    pub(crate) fn new(
        store_id: [u8; 16],
        requested_url: String,
        content_version: [u8; 32],
        start_byte: usize,
        end_byte: usize,
    ) -> Result<Self, RetrievalError> {
        let start_byte = u32::try_from(start_byte).map_err(|_| RetrievalError::InvalidRange)?;
        let end_byte = u32::try_from(end_byte).map_err(|_| RetrievalError::InvalidRange)?;
        let mut reference = Self {
            store_id,
            requested_url,
            content_version,
            passage_schema_version: PASSAGE_SCHEMA_VERSION,
            start_byte,
            end_byte,
            identity_sha256: [0; 32],
        };
        reference.identity_sha256 = reference.expected_identity();
        Ok(reference)
    }

    pub(crate) fn validate_shape_and_identity(&self) -> Result<(), EvidenceResolveError> {
        if UrlKey::parse(&self.requested_url).is_err()
            || self.start_byte >= self.end_byte
            || self.content_version == [0; 32]
            || self.passage_schema_version == 0
            || self.identity_sha256 != self.expected_identity()
        {
            return Err(EvidenceResolveError::MalformedReference);
        }
        if self.passage_schema_version != PASSAGE_SCHEMA_VERSION {
            return Err(EvidenceResolveError::UnsupportedPassageSchema);
        }
        Ok(())
    }

    fn expected_identity(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(REFERENCE_DOMAIN);
        digest.update(self.store_id);
        digest.update((self.requested_url.len() as u64).to_be_bytes());
        digest.update(self.requested_url.as_bytes());
        digest.update(self.content_version);
        digest.update(self.passage_schema_version.to_be_bytes());
        digest.update(self.start_byte.to_be_bytes());
        digest.update(self.end_byte.to_be_bytes());
        digest.finalize().into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Resolved current passage text with bounded indexed metadata.
///
/// Text is one canonical passage window of at most 8,192 UTF-8 bytes. Stored
/// requested/effective URLs are each limited to 2,048 bytes and title to 4,096.
pub struct ResolvedEvidence {
    pub reference: EvidenceReference,
    pub requested_url: String,
    pub effective_url: String,
    pub title: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceResolveError {
    MalformedReference,
    WrongStore,
    UnsupportedPassageSchema,
    Revoked,
    NotLive,
    VersionSuperseded,
    PublicCollectionExpired,
    OutOfBounds,
    NotUtf8Boundary,
    InvalidPassageWindow,
    ResourceLimit,
    CorruptStorage,
    StorageUnavailable,
}

impl fmt::Display for EvidenceResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedReference => "evidence reference is malformed",
            Self::WrongStore => "evidence reference belongs to another store",
            Self::UnsupportedPassageSchema => "passage schema is unsupported",
            Self::Revoked => "document is currently revoked",
            Self::NotLive => "document is not currently live",
            Self::VersionSuperseded => "document content version has changed",
            Self::PublicCollectionExpired => "public collection visibility has expired",
            Self::OutOfBounds => "evidence range is outside the current extracted body",
            Self::NotUtf8Boundary => "evidence range is not on UTF-8 boundaries",
            Self::InvalidPassageWindow => {
                "evidence range is not a canonical passage window for this schema"
            }
            Self::ResourceLimit => "evidence resolution exceeded a configured resource bound",
            Self::CorruptStorage => "current store data failed integrity validation",
            Self::StorageUnavailable => "current store state could not be read",
        })
    }
}

impl std::error::Error for EvidenceResolveError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrievalError {
    InvalidHitLimit,
    UnsupportedContractVersion(u16),
    QuestionTooLong { bytes: usize },
    TooManyTerms { occurrences: usize },
    TooManyDistinctTerms { terms: usize },
    PhraseTooLong { terms: usize },
    TokenTooLong { scalars: usize },
    UnterminatedQuote,
    InvalidEscape,
    EmptyQuotedPhrase,
    InvalidRange,
    ResponseTooLarge,
    PublicCollectionExpired,
    ResourceLimit,
    CorruptStorage,
    StorageUnavailable,
}

impl fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHitLimit => write!(f, "hit limit must be between 1 and {MAX_HITS}"),
            Self::UnsupportedContractVersion(version) => {
                write!(f, "retrieval contract version {version} is unsupported")
            }
            Self::QuestionTooLong { bytes } => write!(
                f,
                "question is {bytes} UTF-8 bytes; limit is {MAX_QUESTION_BYTES}"
            ),
            Self::TooManyTerms { occurrences } => write!(
                f,
                "question has {occurrences} analyzed token occurrences; limit is {MAX_QUESTION_TOKEN_OCCURRENCES}"
            ),
            Self::TooManyDistinctTerms { terms } => write!(
                f,
                "question has {terms} distinct normalized terms; limit is {MAX_QUESTION_DISTINCT_TERMS}"
            ),
            Self::PhraseTooLong { terms } => write!(
                f,
                "phrase has {terms} analyzed terms; limit is {MAX_QUESTION_PHRASE_TERMS}"
            ),
            Self::TokenTooLong { scalars } => write!(
                f,
                "normalized query term has {scalars} Unicode scalars; limit is {MAX_TERM_SCALARS}"
            ),
            Self::UnterminatedQuote => f.write_str("question has an unterminated quoted phrase"),
            Self::InvalidEscape => {
                f.write_str("quoted phrases may only escape a quote or backslash")
            }
            Self::EmptyQuotedPhrase => f.write_str("quoted phrase has no searchable terms"),
            Self::InvalidRange => f.write_str("passage byte range is invalid"),
            Self::ResponseTooLarge => {
                f.write_str("retrieval response exceeds its configured byte limit")
            }
            Self::PublicCollectionExpired => {
                f.write_str("public collection visibility has expired")
            }
            Self::ResourceLimit => f.write_str("retrieval exceeded a configured resource bound"),
            Self::CorruptStorage => f.write_str("current store data failed integrity validation"),
            Self::StorageUnavailable => f.write_str("current store state could not be read"),
        }
    }
}

impl std::error::Error for RetrievalError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QuestionAlternative {
    Term(String),
    Phrase(Vec<String>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PhraseTrie {
    nodes: Vec<PhraseTrieNode>,
    max_phrase_terms: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PhraseTrieNode {
    children: std::collections::BTreeMap<String, usize>,
    outputs: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuestionPlan {
    pub normalized_terms: Vec<String>,
    pub scoring_terms: Vec<String>,
    pub candidate_terms: Vec<String>,
    pub term_alternatives: Vec<String>,
    pub term_families: Vec<Vec<String>>,
    pub phrase_groups: Vec<Vec<String>>,
    pub literal_phrases: Vec<String>,
    phrase_trie: PhraseTrie,
}

pub(crate) fn plan_question(raw: &str) -> Result<QuestionPlan, RetrievalError> {
    if raw.len() > MAX_QUESTION_BYTES {
        return Err(RetrievalError::QuestionTooLong { bytes: raw.len() });
    }

    let atoms = scan_question(raw)?;
    let mut occurrences = 0usize;
    let mut normalized = BTreeSet::new();
    let mut scoring_terms = BTreeSet::new();
    let mut candidate_terms = BTreeSet::new();
    let mut alternatives = Vec::new();
    let mut literal_phrases = BTreeSet::new();

    for atom in atoms {
        let terms = Analyzer.analyze(&atom.text).map_err(map_analysis_error)?;
        let phrase_group = atom.quoted || looks_like_identifier(&atom.text);
        occurrences = occurrences.saturating_add(terms.len());
        if occurrences > MAX_QUESTION_TOKEN_OCCURRENCES {
            return Err(RetrievalError::TooManyTerms { occurrences });
        }
        if atom.quoted && terms.is_empty() {
            return Err(RetrievalError::EmptyQuotedPhrase);
        }
        if phrase_group && terms.len() > MAX_QUESTION_PHRASE_TERMS {
            return Err(RetrievalError::PhraseTooLong { terms: terms.len() });
        }
        if let Some(literal) = &atom.literal
            && !literal.is_empty()
            && literal.len() <= MAX_QUESTION_LITERAL_BYTES
            && literal_phrases.len() < MAX_QUESTION_LITERAL_PHRASES
        {
            literal_phrases.insert(literal.clone());
        }

        if phrase_group {
            if !terms.is_empty() {
                normalized.extend(terms.iter().cloned());
                candidate_terms.insert(terms[0].clone());
                scoring_terms.extend(terms.iter().cloned());
                alternatives.push(QuestionAlternative::Phrase(terms));
            }
            continue;
        }

        for term in terms {
            if !is_question_stopword(&term) {
                normalized.insert(term.clone());
                candidate_terms.insert(term.clone());
                scoring_terms.insert(term.clone());
                alternatives.push(QuestionAlternative::Term(term));
            }
        }
    }

    if normalized.len() > MAX_QUESTION_DISTINCT_TERMS {
        return Err(RetrievalError::TooManyDistinctTerms {
            terms: normalized.len(),
        });
    }
    let mut term_alternatives = BTreeSet::new();
    let mut phrase_groups = BTreeSet::new();
    for alternative in alternatives {
        match alternative {
            QuestionAlternative::Term(term) => {
                term_alternatives.insert(term);
            }
            QuestionAlternative::Phrase(phrase) => {
                phrase_groups.insert(phrase);
            }
        }
    }
    let term_alternatives = term_alternatives.into_iter().collect::<Vec<_>>();
    let phrase_groups = phrase_groups.into_iter().collect::<Vec<_>>();
    let term_families = term_alternatives
        .iter()
        .map(|term| {
            let mut family = vec![term.clone()];
            family.extend(question_surface_variants(term));
            family
        })
        .collect::<Vec<_>>();
    for family in &term_families {
        candidate_terms.extend(family.iter().cloned());
    }
    let phrase_trie = build_phrase_trie(&phrase_groups);
    Ok(QuestionPlan {
        normalized_terms: normalized.into_iter().collect(),
        scoring_terms: scoring_terms.into_iter().collect(),
        candidate_terms: candidate_terms.into_iter().collect(),
        term_alternatives,
        term_families,
        phrase_groups,
        literal_phrases: literal_phrases.into_iter().collect(),
        phrase_trie,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QuestionAtom {
    text: String,
    quoted: bool,
    literal: Option<String>,
}

fn scan_question(raw: &str) -> Result<Vec<QuestionAtom>, RetrievalError> {
    let mut atoms = Vec::new();
    let mut cursor = 0;
    while cursor < raw.len() {
        let character = raw[cursor..]
            .chars()
            .next()
            .expect("cursor is a UTF-8 boundary");
        if character.is_whitespace() {
            cursor += character.len_utf8();
            continue;
        }
        if character == '`'
            && let Some(relative_end) = raw[cursor + character.len_utf8()..].find('`')
        {
            let content_start = cursor + character.len_utf8();
            let content_end = content_start + relative_end;
            let text = raw[content_start..content_end].to_owned();
            cursor = content_end + character.len_utf8();
            if !text.is_empty() {
                atoms.push(QuestionAtom {
                    text: text.clone(),
                    quoted: false,
                    literal: Some(text),
                });
            }
            continue;
        }
        if character == '"' {
            cursor += character.len_utf8();
            let mut text = String::new();
            let mut closed = false;
            while cursor < raw.len() {
                let current = raw[cursor..]
                    .chars()
                    .next()
                    .expect("cursor is a UTF-8 boundary");
                cursor += current.len_utf8();
                match current {
                    '"' => {
                        closed = true;
                        break;
                    }
                    '\\' => {
                        let escaped = raw[cursor..]
                            .chars()
                            .next()
                            .ok_or(RetrievalError::InvalidEscape)?;
                        if escaped != '"' && escaped != '\\' {
                            return Err(RetrievalError::InvalidEscape);
                        }
                        cursor += escaped.len_utf8();
                        text.push(escaped);
                    }
                    other => text.push(other),
                }
            }
            if !closed {
                return Err(RetrievalError::UnterminatedQuote);
            }
            atoms.push(QuestionAtom {
                text,
                quoted: true,
                literal: None,
            });
        } else {
            let start = cursor;
            while cursor < raw.len() {
                let current = raw[cursor..]
                    .chars()
                    .next()
                    .expect("cursor is a UTF-8 boundary");
                if current.is_whitespace() || current == '"' {
                    break;
                }
                cursor += current.len_utf8();
            }
            atoms.push(QuestionAtom {
                text: raw[start..cursor].to_owned(),
                quoted: false,
                literal: None,
            });
        }
    }
    Ok(atoms)
}

fn question_surface_variants(term: &str) -> Vec<String> {
    if term.len() < 4 || !term.bytes().all(|byte| byte.is_ascii_lowercase()) || term.ends_with('s')
    {
        return Vec::new();
    }

    let mut variants = BTreeSet::new();
    if let Some(stem) = term.strip_suffix("ly") {
        if stem.chars().count() >= 3 {
            variants.insert(stem.to_owned());
            variants.insert(format!("{stem}s"));
        }
    } else if let Some(stem) = term.strip_suffix('e') {
        variants.insert(format!("{term}s"));
        variants.insert(format!("{stem}ing"));
    } else if let Some(stem) = term.strip_suffix('y') {
        if stem
            .chars()
            .last()
            .is_some_and(|last| !"aeiou".contains(last))
        {
            variants.insert(format!("{stem}ies"));
            variants.insert(format!("{stem}ied"));
            variants.insert(format!("{stem}ying"));
        } else {
            variants.insert(format!("{term}s"));
            variants.insert(format!("{term}ed"));
            variants.insert(format!("{term}ing"));
        }
    } else {
        variants.insert(format!("{term}s"));
        variants.insert(format!("{term}ed"));
        variants.insert(format!("{term}ing"));
    }
    variants.remove(term);
    variants
        .into_iter()
        .take(MAX_QUESTION_SURFACE_VARIANTS)
        .collect()
}

fn looks_like_identifier(text: &str) -> bool {
    text.contains('_') || text.contains("::") || text.contains('.') || text.contains('/')
}

fn is_question_stopword(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "are"
            | "as"
            | "at"
            | "be"
            | "been"
            | "being"
            | "but"
            | "by"
            | "can"
            | "could"
            | "did"
            | "do"
            | "does"
            | "for"
            | "from"
            | "had"
            | "has"
            | "have"
            | "he"
            | "her"
            | "how"
            | "i"
            | "in"
            | "is"
            | "it"
            | "its"
            | "me"
            | "my"
            | "of"
            | "on"
            | "or"
            | "our"
            | "she"
            | "should"
            | "that"
            | "the"
            | "their"
            | "them"
            | "there"
            | "these"
            | "they"
            | "this"
            | "those"
            | "to"
            | "was"
            | "we"
            | "were"
            | "what"
            | "when"
            | "where"
            | "which"
            | "who"
            | "why"
            | "will"
            | "with"
            | "would"
            | "you"
            | "your"
    )
}

fn map_analysis_error(error: AnalyzeError) -> RetrievalError {
    match error {
        AnalyzeError::TermTooLong { scalars } => RetrievalError::TokenTooLong { scalars },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassageWindow {
    pub start_byte: usize,
    pub end_byte: usize,
}

pub(crate) fn passage_windows(body: &str) -> Result<Vec<PassageWindow>, RetrievalError> {
    let mut windows = Vec::new();
    let mut start = 0usize;
    while start < body.len() {
        if windows.len() >= MAX_PASSAGES_PER_DOCUMENT {
            return Err(RetrievalError::ResourceLimit);
        }
        let requested_end = start.saturating_add(MAX_PASSAGE_BYTES).min(body.len());
        let mut end = requested_end;
        while end > start && !body.is_char_boundary(end) {
            end -= 1;
        }
        if end <= start || body.get(start..end).is_none() {
            return Err(RetrievalError::InvalidRange);
        }
        windows.push(PassageWindow {
            start_byte: start,
            end_byte: end,
        });
        if end == body.len() {
            break;
        }

        let target_start = end.saturating_sub(PASSAGE_STEP_BYTES);
        let mut next_start = target_start;
        while next_start > start && !body.is_char_boundary(next_start) {
            next_start -= 1;
        }
        if next_start <= start {
            return Err(RetrievalError::InvalidRange);
        }
        start = next_start;
    }
    Ok(windows)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassageMatch {
    pub terms: Vec<String>,
    pub phrases: Vec<Vec<String>>,
    pub score: u32,
}

#[cfg(test)]
pub(crate) fn match_passage_terms(
    window_terms: &[String],
    plan: &QuestionPlan,
) -> Option<PassageMatch> {
    let mut phrase_steps = 0;
    match_passage_text_bounded(window_terms, "", plan, &mut phrase_steps).0
}

pub(crate) fn match_passage_text_bounded(
    window_terms: &[String],
    window_text: &str,
    plan: &QuestionPlan,
    phrase_steps: &mut usize,
) -> (Option<PassageMatch>, bool) {
    let available = window_terms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut matched_terms = plan
        .term_alternatives
        .iter()
        .filter(|term| available.contains(term.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut matched_phrases = BTreeSet::new();
    let mut exhausted = false;
    'starts: for start in 0..window_terms.len() {
        let mut node_index = 0usize;
        for term in window_terms
            .iter()
            .skip(start)
            .take(plan.phrase_trie.max_phrase_terms)
        {
            if *phrase_steps >= MAX_QUESTION_PHRASE_STEPS {
                exhausted = true;
                break 'starts;
            }
            *phrase_steps += 1;
            let Some(next) = plan.phrase_trie.nodes[node_index].children.get(term) else {
                break;
            };
            node_index = *next;
            for phrase in &plan.phrase_trie.nodes[node_index].outputs {
                matched_phrases.insert(phrase.clone());
                matched_terms.extend(phrase.iter().cloned());
            }
        }
    }
    let matched_literal_count = plan
        .literal_phrases
        .iter()
        .filter(|literal| contains_code_literal(window_text, literal))
        .count();
    for phrase in &matched_phrases {
        matched_terms.extend(phrase.iter().cloned());
    }
    let phrases = matched_phrases.into_iter().collect::<Vec<_>>();
    let score = u32::try_from(matched_terms.len())
        .unwrap_or(u32::MAX)
        .saturating_add(
            u32::try_from(phrases.len())
                .unwrap_or(u32::MAX)
                .saturating_mul(4),
        )
        .saturating_add(
            u32::try_from(matched_literal_count)
                .unwrap_or(u32::MAX)
                .saturating_mul(4),
        );
    if score == 0 {
        return (None, exhausted);
    }
    (
        Some(PassageMatch {
            terms: matched_terms.into_iter().collect(),
            phrases,
            score,
        }),
        exhausted,
    )
}

fn contains_code_literal(text: &str, literal: &str) -> bool {
    let is_word_character = |character: char| character.is_alphanumeric() || character == '_';
    let first = literal.chars().next();
    let last = literal.chars().next_back();
    text.match_indices(literal).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + literal.len()..].chars().next();
        let left_boundary =
            !first.is_some_and(is_word_character) || !before.is_some_and(is_word_character);
        let right_boundary =
            !last.is_some_and(is_word_character) || !after.is_some_and(is_word_character);
        let not_escaped_backslash = !(literal.starts_with('\\') && before == Some('\\'));
        left_boundary && right_boundary && not_escaped_backslash
    })
}

fn build_phrase_trie(phrases: &[Vec<String>]) -> PhraseTrie {
    let mut trie = PhraseTrie {
        nodes: vec![PhraseTrieNode::default()],
        max_phrase_terms: 0,
    };
    for phrase in phrases {
        trie.max_phrase_terms = trie.max_phrase_terms.max(phrase.len());
        let mut node_index = 0usize;
        for term in phrase {
            let next = if let Some(next) = trie.nodes[node_index].children.get(term) {
                *next
            } else {
                let next = trie.nodes.len();
                trie.nodes[node_index].children.insert(term.clone(), next);
                trie.nodes.push(PhraseTrieNode::default());
                next
            };
            node_index = next;
        }
        if !trie.nodes[node_index].outputs.contains(phrase) {
            trie.nodes[node_index].outputs.push(phrase.clone());
        }
    }
    trie
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_plan_uses_or_terms_and_keeps_quotes_and_identifiers() {
        let plan =
            plan_question("Which setting? Use PAM::MAX_LOGINS and \"failed login\"").unwrap();
        assert_eq!(
            plan.normalized_terms,
            ["failed", "login", "max_logins", "pam", "setting", "use"]
        );
        assert!(plan.term_alternatives.contains(&"setting".to_owned()));
        assert!(
            plan.phrase_groups
                .contains(&vec!["pam".to_owned(), "max_logins".to_owned()])
        );
        assert!(
            plan.phrase_groups
                .contains(&vec!["failed".to_owned(), "login".to_owned()])
        );
    }

    #[test]
    fn question_plan_keeps_canonical_terms_and_adds_bounded_surface_variants() {
        let plan = plan_question("nest literally sequence").unwrap();
        assert_eq!(plan.normalized_terms, ["literally", "nest", "sequence"]);
        assert!(plan.candidate_terms.contains(&"nesting".to_owned()));
        assert!(plan.candidate_terms.contains(&"literal".to_owned()));
        assert!(plan.candidate_terms.contains(&"literals".to_owned()));
        assert!(plan.candidate_terms.contains(&"sequences".to_owned()));
        assert!(plan.term_families.iter().all(|family| family.len() <= 4));

        let matched = match_passage_terms(
            &["nest".into(), "literally".into(), "sequence".into()],
            &plan,
        )
        .unwrap();
        assert_eq!(matched.terms, ["literally", "nest", "sequence"]);
        assert_eq!(matched.score, 3);
    }

    #[test]
    fn inline_code_literal_is_preserved_as_an_exact_passage_signal() {
        let plan = plan_question(r"What does `\h` match in a pattern?").unwrap();
        assert_eq!(plan.literal_phrases, [r"\h"]);
        assert!(plan.term_alternatives.contains(&"h".to_owned()));
        assert!(plan.phrase_groups.is_empty());

        let exact_terms = Analyzer
            .analyze(r"The \h escape matches whitespace.")
            .unwrap();
        let mut phrase_steps = 0;
        let exact = match_passage_text_bounded(
            &exact_terms,
            r"The \h escape matches whitespace.",
            &plan,
            &mut phrase_steps,
        )
        .0
        .unwrap();
        let unrelated_terms = Analyzer
            .analyze("The h symbol matches whitespace.")
            .unwrap();
        let unrelated = match_passage_text_bounded(
            &unrelated_terms,
            "The h symbol matches whitespace.",
            &plan,
            &mut phrase_steps,
        )
        .0
        .unwrap();
        assert!(exact.score > unrelated.score);
        let escaped_terms = Analyzer.analyze(r"The \h is a different escape.").unwrap();
        let escaped = match_passage_text_bounded(
            &escaped_terms,
            r"The \\h is a different escape.",
            &plan,
            &mut phrase_steps,
        )
        .0
        .unwrap();
        assert_eq!(unrelated.score, escaped.score);
        assert!(!unrelated.phrases.iter().flatten().any(|term| term == r"\h"));
    }

    #[test]
    fn malformed_input_and_limits_are_typed() {
        assert_eq!(
            plan_question("\"unfinished").unwrap_err(),
            RetrievalError::UnterminatedQuote
        );
        assert_eq!(
            plan_question("\"a\\nb\"").unwrap_err(),
            RetrievalError::InvalidEscape
        );
        assert_eq!(
            plan_question(&"x".repeat(MAX_QUESTION_BYTES + 1)).unwrap_err(),
            RetrievalError::QuestionTooLong {
                bytes: MAX_QUESTION_BYTES + 1
            }
        );
        assert!(matches!(
            plan_question(&"x".repeat(MAX_TERM_SCALARS + 1)),
            Err(RetrievalError::TokenTooLong { .. })
        ));
        assert_eq!(
            plan_question(&format!("\"{}\"", vec!["term"; 17].join(" "))).unwrap_err(),
            RetrievalError::PhraseTooLong { terms: 17 }
        );
        assert_eq!(
            plan_question(&vec!["term"; 65].join(" ")).unwrap_err(),
            RetrievalError::TooManyTerms { occurrences: 65 }
        );
        assert_eq!(
            plan_question(
                &vec![
                    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
                    "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
                    "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
                    "yankee", "zulu", "amber", "birch", "cedar", "dawn", "ember", "frost", "grove",
                ]
                .join(" ")
            )
            .unwrap_err(),
            RetrievalError::TooManyDistinctTerms { terms: 33 }
        );
        assert_eq!(
            plan_question("Ｓtraße").unwrap().normalized_terms,
            ["strasse"]
        );
        assert!(
            plan_question("what is the and")
                .unwrap()
                .term_alternatives
                .is_empty()
        );
    }

    #[test]
    fn passage_ranges_are_utf8_safe_and_cover_the_body() {
        let body = format!("{} café 🐚 {}", "a".repeat(8100), "é".repeat(5000));
        let windows = passage_windows(&body).unwrap();
        assert!(!windows.is_empty());
        assert!(windows.len() <= MAX_PASSAGES_PER_DOCUMENT);
        for window in &windows {
            assert!(body.is_char_boundary(window.start_byte));
            assert!(body.is_char_boundary(window.end_byte));
            assert!(window.end_byte - window.start_byte <= MAX_PASSAGE_BYTES);
            assert!(body.get(window.start_byte..window.end_byte).is_some());
        }
        assert_eq!(windows.first().unwrap().start_byte, 0);
        assert_eq!(windows.last().unwrap().end_byte, body.len());
        assert!(
            windows
                .windows(2)
                .all(|pair| pair[1].start_byte < pair[0].end_byte)
        );

        let maximum_body = "é".repeat(crate::html::MAX_FIELDS_BYTES / 2);
        let maximum_windows = passage_windows(&maximum_body).unwrap();
        assert!(maximum_windows.len() <= MAX_PASSAGES_PER_DOCUMENT);
        assert_eq!(maximum_windows.last().unwrap().end_byte, maximum_body.len());
    }

    #[test]
    fn passage_match_requires_contiguous_phrase_tokens() {
        let plan = plan_question("\"alpha beta\"").unwrap();
        assert!(
            match_passage_terms(&["alpha".into(), "gap".into(), "beta".into()], &plan).is_none()
        );
        assert!(match_passage_terms(&["alpha".into(), "beta".into()], &plan).is_some());
    }

    #[test]
    fn identity_digest_covers_store_key_version_schema_and_byte_range() {
        let reference =
            EvidenceReference::new([1; 16], "https://example.test/a".to_owned(), [2; 32], 4, 12)
                .unwrap();
        reference.validate_shape_and_identity().unwrap();
        let mut changed = reference.clone();
        changed.end_byte += 1;
        assert_eq!(
            changed.validate_shape_and_identity(),
            Err(EvidenceResolveError::MalformedReference)
        );
    }
}
