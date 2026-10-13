use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::analyzer::{ANALYZER_ID, AnalyzeError, Analyzer};
use crate::html::{
    ExtractedDocument, HTML_SCHEMA_ID, MAX_DOCUMENT_TOKENS, MAX_FIELDS_BYTES, MAX_TITLE_BYTES,
};
pub use crate::query::QueryError;
use crate::query::{Expr, ParsedQuery, parse_query};

pub const MAX_QUERY_BYTES: usize = crate::query::MAX_QUERY_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Posting {
    pub title_positions: Vec<u32>,
    pub body_positions: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedDocument {
    pub id: String,
    pub effective_url: String,
    pub title: String,
    pub body: String,
    pub title_terms: Vec<String>,
    pub body_terms: Vec<String>,
    pub version_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    pub id: String,
    pub version_id: String,
    pub title: String,
    pub snippet: String,
    pub score: f64,
    pub matched: MatchEvidence,
    pub explanation: ScoreExplanation,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MatchEvidence {
    Term {
        term: String,
        title_positions: Vec<u32>,
        body_positions: Vec<u32>,
    },
    Phrase {
        terms: Vec<String>,
        title_starts: Vec<u32>,
        body_starts: Vec<u32>,
    },
    And(Vec<MatchEvidence>),
    Or(Vec<MatchEvidence>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatisticsSource {
    CurrentInMemoryDocumentView,
    PersistentGeneration(u64),
}

impl std::fmt::Display for StatisticsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentInMemoryDocumentView => f.write_str("current in-memory document view"),
            Self::PersistentGeneration(generation_id) => {
                write!(f, "persistent generation {generation_id}")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScoreExplanation {
    pub normalized_terms: Vec<String>,
    pub document_count: usize,
    pub average_title_length: f64,
    pub average_body_length: f64,
    pub statistics_source: StatisticsSource,
    pub terms: Vec<TermScoreExplanation>,
    pub total_score: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TermScoreExplanation {
    pub term: String,
    pub title: FieldScoreExplanation,
    pub body: FieldScoreExplanation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldScoreExplanation {
    pub term_frequency: usize,
    pub document_frequency: usize,
    pub document_length: usize,
    pub average_length: f64,
    pub idf: f64,
    pub weight: f64,
    pub contribution: f64,
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryIndex {
    documents: BTreeMap<String, IndexedDocument>,
    postings: BTreeMap<String, BTreeMap<String, Posting>>,
}

impl InMemoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.documents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub fn documents(&self) -> &BTreeMap<String, IndexedDocument> {
        &self.documents
    }

    pub fn postings(&self) -> &BTreeMap<String, BTreeMap<String, Posting>> {
        &self.postings
    }

    pub(crate) fn install_validated_postings(
        &mut self,
        postings: BTreeMap<String, BTreeMap<String, Posting>>,
    ) -> Result<(), QueryError> {
        let mut rebuilt = Self::new();
        for document in self.documents.values() {
            rebuilt.add_document(analyze_document(
                document.id.clone(),
                document.effective_url.clone(),
                document.title.clone(),
                document.body.clone(),
            )?);
        }
        if rebuilt.postings != postings || rebuilt.documents != self.documents {
            return Err(QueryError::InvalidTerm(
                "persisted index records do not match analyzed documents".to_owned(),
            ));
        }
        self.postings = postings;
        Ok(())
    }

    pub fn insert(&mut self, document: ExtractedDocument) -> Result<(), QueryError> {
        self.insert_fields(
            document.requested_url.to_string(),
            document.effective_url,
            document.title,
            document.body,
        )
    }

    pub fn insert_fields(
        &mut self,
        id: String,
        effective_url: String,
        title: String,
        body: String,
    ) -> Result<(), QueryError> {
        if self.documents.contains_key(&id) {
            return Err(QueryError::InvalidTerm(format!(
                "duplicate document URL key {id}"
            )));
        }
        let record = analyze_document(id, effective_url, title, body)?;
        self.add_document(record);
        Ok(())
    }

    /// Replace the current in-memory document for this URL key.
    pub fn upsert_fields(
        &mut self,
        id: String,
        effective_url: String,
        title: String,
        body: String,
    ) -> Result<(), QueryError> {
        let record = analyze_document(id.clone(), effective_url, title, body)?;
        self.remove_document(&id);
        self.add_document(record);
        Ok(())
    }

    /// Remove a URL key from the current in-memory search view.
    pub fn remove_document(&mut self, id: &str) -> bool {
        let Some(document) = self.documents.remove(id) else {
            return false;
        };
        for term in document
            .title_terms
            .iter()
            .chain(document.body_terms.iter())
        {
            let is_empty = self.postings.get_mut(term).is_some_and(|postings| {
                postings.remove(id);
                postings.is_empty()
            });
            if is_empty {
                self.postings.remove(term);
            }
        }
        true
    }

    pub fn query(&self, expression: &str) -> Result<Vec<SearchResult>, QueryError> {
        let query = parse_query(expression)?;
        self.query_parsed(&query)
    }

    pub(crate) fn query_parsed(
        &self,
        query: &ParsedQuery,
    ) -> Result<Vec<SearchResult>, QueryError> {
        if self.documents.is_empty() {
            return Ok(Vec::new());
        }
        let matches = self.evaluate(&query.root);
        let statistics = self.statistics(&query.score_terms);
        let mut results = Vec::with_capacity(matches.len());
        for (document_id, matched) in matches {
            let Some(document) = self.documents.get(&document_id) else {
                continue;
            };
            let explanation = self.explain_score(document, query, &statistics)?;
            results.push(SearchResult {
                id: document.id.clone(),
                version_id: document.version_id.clone(),
                title: document.title.clone(),
                snippet: make_snippet(&document.body),
                score: explanation.total_score,
                matched,
                explanation,
            });
        }
        results.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
        });
        Ok(results)
    }

    fn add_document(&mut self, document: IndexedDocument) {
        add_positions(
            &mut self.postings,
            &document.id,
            &document.title_terms,
            true,
        );
        add_positions(
            &mut self.postings,
            &document.id,
            &document.body_terms,
            false,
        );
        self.documents.insert(document.id.clone(), document);
    }

    fn evaluate(&self, expression: &Expr) -> BTreeMap<String, MatchEvidence> {
        match expression {
            Expr::Term(term) => self.term_matches(term),
            Expr::Phrase(terms) => self.phrase_matches(terms),
            Expr::And(children) => {
                let mut child_matches = children.iter().map(|child| self.evaluate(child));
                let Some(mut intersection) = child_matches.next() else {
                    return BTreeMap::new();
                };
                for next in child_matches {
                    intersection = intersect_match_sets(intersection, next);
                }
                intersection
            }
            Expr::Or(children) => {
                let mut children = children.iter().map(|child| self.evaluate(child));
                let Some(mut union) = children.next() else {
                    return BTreeMap::new();
                };
                for next in children {
                    union = union_match_sets(union, next);
                }
                union
            }
        }
    }

    fn term_matches(&self, term: &str) -> BTreeMap<String, MatchEvidence> {
        self.postings
            .get(term)
            .into_iter()
            .flat_map(|by_document| by_document.iter())
            .map(|(id, posting)| {
                (
                    id.clone(),
                    MatchEvidence::Term {
                        term: term.to_owned(),
                        title_positions: posting.title_positions.clone(),
                        body_positions: posting.body_positions.clone(),
                    },
                )
            })
            .collect()
    }

    fn phrase_matches(&self, terms: &[String]) -> BTreeMap<String, MatchEvidence> {
        let Some(first) = terms.first() else {
            return BTreeMap::new();
        };
        let Some(candidates) = self.postings.get(first) else {
            return BTreeMap::new();
        };
        let mut matches = BTreeMap::new();
        for id in candidates.keys() {
            let title_starts = phrase_starts(&self.postings, id, terms, true);
            let body_starts = phrase_starts(&self.postings, id, terms, false);
            if !title_starts.is_empty() || !body_starts.is_empty() {
                matches.insert(
                    id.clone(),
                    MatchEvidence::Phrase {
                        terms: terms.to_vec(),
                        title_starts,
                        body_starts,
                    },
                );
            }
        }
        matches
    }

    fn statistics(&self, terms: &[String]) -> SearchStatistics {
        let document_count = self.documents.len();
        let divisor = document_count as f64;
        let average_title_length = self
            .documents
            .values()
            .map(|document| document.title_terms.len() as f64)
            .sum::<f64>()
            / divisor;
        let average_body_length = self
            .documents
            .values()
            .map(|document| document.body_terms.len() as f64)
            .sum::<f64>()
            / divisor;
        let term_statistics = terms
            .iter()
            .map(|term| {
                let title_df = self
                    .postings
                    .get(term)
                    .map(|by_document| {
                        by_document
                            .values()
                            .filter(|posting| !posting.title_positions.is_empty())
                            .count()
                    })
                    .unwrap_or(0);
                let body_df = self
                    .postings
                    .get(term)
                    .map(|by_document| {
                        by_document
                            .values()
                            .filter(|posting| !posting.body_positions.is_empty())
                            .count()
                    })
                    .unwrap_or(0);
                (
                    term.clone(),
                    TermStatistics {
                        title_df,
                        body_df,
                        title_idf: bm25_idf(document_count as f64, title_df as f64),
                        body_idf: bm25_idf(document_count as f64, body_df as f64),
                    },
                )
            })
            .collect();
        SearchStatistics {
            document_count,
            average_title_length,
            average_body_length,
            terms: term_statistics,
        }
    }

    fn explain_score(
        &self,
        document: &IndexedDocument,
        query: &ParsedQuery,
        statistics: &SearchStatistics,
    ) -> Result<ScoreExplanation, QueryError> {
        let mut total_score = 0.0;
        let mut terms = Vec::with_capacity(query.score_terms.len());
        for term in &query.score_terms {
            let posting = self
                .postings
                .get(term)
                .and_then(|by_document| by_document.get(&document.id));
            let term_statistics = statistics
                .terms
                .get(term)
                .expect("query terms have statistics");
            let title = field_score(
                posting.map_or(0, |value| value.title_positions.len()),
                term_statistics.title_df,
                document.title_terms.len(),
                statistics.average_title_length,
                term_statistics.title_idf,
                2.0,
            );
            let body = field_score(
                posting.map_or(0, |value| value.body_positions.len()),
                term_statistics.body_df,
                document.body_terms.len(),
                statistics.average_body_length,
                term_statistics.body_idf,
                1.0,
            );
            total_score += title.contribution;
            total_score += body.contribution;
            terms.push(TermScoreExplanation {
                term: term.clone(),
                title,
                body,
            });
        }
        if !total_score.is_finite() {
            return Err(QueryError::NonFiniteScore);
        }
        Ok(ScoreExplanation {
            normalized_terms: query.score_terms.clone(),
            document_count: statistics.document_count,
            average_title_length: statistics.average_title_length,
            average_body_length: statistics.average_body_length,
            statistics_source: StatisticsSource::CurrentInMemoryDocumentView,
            terms,
            total_score,
        })
    }
}

#[derive(Clone, Debug)]
struct SearchStatistics {
    document_count: usize,
    average_title_length: f64,
    average_body_length: f64,
    terms: BTreeMap<String, TermStatistics>,
}

#[derive(Clone, Debug)]
struct TermStatistics {
    title_df: usize,
    body_df: usize,
    title_idf: f64,
    body_idf: f64,
}

fn analyze_document(
    id: String,
    effective_url: String,
    title: String,
    body: String,
) -> Result<IndexedDocument, QueryError> {
    if title.len() > MAX_TITLE_BYTES {
        return Err(QueryError::TitleTooLong { bytes: title.len() });
    }
    let field_bytes = title.len().saturating_add(body.len());
    if field_bytes > MAX_FIELDS_BYTES {
        return Err(QueryError::FieldsTooLong { bytes: field_bytes });
    }
    let title_terms = Analyzer
        .analyze(&title)
        .map_err(map_document_analysis_error)?;
    let body_terms = Analyzer
        .analyze(&body)
        .map_err(map_document_analysis_error)?;
    let token_count = title_terms.len().saturating_add(body_terms.len());
    if token_count > MAX_DOCUMENT_TOKENS {
        return Err(QueryError::TooManyDocumentTokens {
            tokens: token_count,
        });
    }
    let version_id = document_version(&title, &body);
    Ok(IndexedDocument {
        id,
        effective_url,
        title,
        body,
        title_terms,
        body_terms,
        version_id,
    })
}

fn map_document_analysis_error(error: AnalyzeError) -> QueryError {
    match error {
        AnalyzeError::TermTooLong { scalars } => QueryError::DocumentTermTooLong { scalars },
    }
}

fn document_version(title: &str, body: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ley-document-version-v1\0");
    digest.update(HTML_SCHEMA_ID.as_bytes());
    digest.update([0]);
    digest.update(ANALYZER_ID.as_bytes());
    digest.update([0]);
    update_field(&mut digest, title);
    update_field(&mut digest, body);
    hex_lowercase(&digest.finalize())
}

fn update_field(digest: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len()).expect("Gate 1 field limits fit a u32 length");
    digest.update(length.to_be_bytes());
    digest.update(bytes);
}

fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

fn make_snippet(body: &str) -> String {
    let mut characters = body.chars();
    let snippet: String = characters.by_ref().take(160).collect();
    if characters.next().is_some() {
        format!("{snippet}…")
    } else {
        snippet
    }
}

fn add_positions(
    postings: &mut BTreeMap<String, BTreeMap<String, Posting>>,
    document_id: &str,
    terms: &[String],
    title: bool,
) {
    for (position, term) in terms.iter().enumerate() {
        let posting = postings
            .entry(term.clone())
            .or_default()
            .entry(document_id.to_owned())
            .or_insert_with(|| Posting {
                title_positions: Vec::new(),
                body_positions: Vec::new(),
            });
        let positions = if title {
            &mut posting.title_positions
        } else {
            &mut posting.body_positions
        };
        positions.push(u32::try_from(position).expect("document token limit fits u32"));
    }
}

fn phrase_starts(
    postings: &BTreeMap<String, BTreeMap<String, Posting>>,
    document_id: &str,
    terms: &[String],
    title: bool,
) -> Vec<u32> {
    let Some(first) = terms.first() else {
        return Vec::new();
    };
    let Some(first_posting) = postings
        .get(first)
        .and_then(|by_document| by_document.get(document_id))
    else {
        return Vec::new();
    };
    let first_positions = if title {
        &first_posting.title_positions
    } else {
        &first_posting.body_positions
    };
    first_positions
        .iter()
        .copied()
        .filter(|start| {
            terms.iter().enumerate().skip(1).all(|(offset, term)| {
                let Some(posting) = postings
                    .get(term)
                    .and_then(|by_document| by_document.get(document_id))
                else {
                    return false;
                };
                let positions = if title {
                    &posting.title_positions
                } else {
                    &posting.body_positions
                };
                start
                    .checked_add(u32::try_from(offset).expect("phrase limit fits u32"))
                    .is_some_and(|expected| positions.binary_search(&expected).is_ok())
            })
        })
        .collect()
}

fn combine_and(left: MatchEvidence, right: MatchEvidence) -> MatchEvidence {
    match left {
        MatchEvidence::And(mut children) => {
            children.push(right);
            MatchEvidence::And(children)
        }
        other => MatchEvidence::And(vec![other, right]),
    }
}

fn combine_or(left: MatchEvidence, right: MatchEvidence) -> MatchEvidence {
    match left {
        MatchEvidence::Or(mut children) => {
            children.push(right);
            MatchEvidence::Or(children)
        }
        other => MatchEvidence::Or(vec![other, right]),
    }
}

fn intersect_match_sets(
    left: BTreeMap<String, MatchEvidence>,
    right: BTreeMap<String, MatchEvidence>,
) -> BTreeMap<String, MatchEvidence> {
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut intersection = BTreeMap::new();
    while let (Some((left_id, _)), Some((right_id, _))) = (left.peek(), right.peek()) {
        match left_id.as_bytes().cmp(right_id.as_bytes()) {
            std::cmp::Ordering::Less => {
                left.next();
            }
            std::cmp::Ordering::Greater => {
                right.next();
            }
            std::cmp::Ordering::Equal => {
                let (id, left_evidence) = left.next().expect("peeked left match");
                let (_, right_evidence) = right.next().expect("peeked right match");
                intersection.insert(id, combine_and(left_evidence, right_evidence));
            }
        }
    }
    intersection
}

fn union_match_sets(
    left: BTreeMap<String, MatchEvidence>,
    right: BTreeMap<String, MatchEvidence>,
) -> BTreeMap<String, MatchEvidence> {
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    let mut union = BTreeMap::new();
    loop {
        match (left.peek(), right.peek()) {
            (Some((left_id, _)), Some((right_id, _))) => {
                match left_id.as_bytes().cmp(right_id.as_bytes()) {
                    std::cmp::Ordering::Less => {
                        let (id, evidence) = left.next().expect("peeked left match");
                        union.insert(id, evidence);
                    }
                    std::cmp::Ordering::Greater => {
                        let (id, evidence) = right.next().expect("peeked right match");
                        union.insert(id, evidence);
                    }
                    std::cmp::Ordering::Equal => {
                        let (id, left_evidence) = left.next().expect("peeked left match");
                        let (_, right_evidence) = right.next().expect("peeked right match");
                        union.insert(id, combine_or(left_evidence, right_evidence));
                    }
                }
            }
            (Some(_), None) => {
                union.extend(left);
                break;
            }
            (None, Some(_)) => {
                union.extend(right);
                break;
            }
            (None, None) => break,
        }
    }
    union
}

fn bm25_idf(document_count: f64, document_frequency: f64) -> f64 {
    (1.0 + (document_count - document_frequency + 0.5) / (document_frequency + 0.5)).ln()
}

fn field_score(
    term_frequency: usize,
    document_frequency: usize,
    document_length: usize,
    average_length: f64,
    idf: f64,
    weight: f64,
) -> FieldScoreExplanation {
    let contribution = if term_frequency == 0 || average_length == 0.0 {
        0.0
    } else {
        let k1 = 1.2;
        let b = 0.75;
        let frequency = term_frequency as f64;
        let length_normalization = 1.0 - b + b * document_length as f64 / average_length;
        weight * idf * frequency * (k1 + 1.0) / (frequency + k1 * length_normalization)
    };
    FieldScoreExplanation {
        term_frequency,
        document_frequency,
        document_length,
        average_length,
        idf,
        weight,
        contribution,
    }
}
