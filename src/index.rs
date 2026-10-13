use std::collections::BTreeMap;
use std::fmt;

use crate::analyzer::{AnalyzeError, Analyzer};
use crate::html::ExtractedDocument;

pub const MAX_QUERY_BYTES: usize = 4096;

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
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    pub id: String,
    pub title: String,
    pub score: f64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    EmptyQuery,
    QueryTooLong { bytes: usize },
    UnsupportedSyntax,
    InvalidTerm(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => f.write_str("query has no searchable term"),
            Self::QueryTooLong { bytes } => write!(
                f,
                "query is {bytes} UTF-8 bytes; limit is {MAX_QUERY_BYTES}. Shorten the query and retry."
            ),
            Self::UnsupportedSyntax => f.write_str(
                "Demo 0.1 accepts one unfielded search term; Boolean, phrase, wildcard, and multi-term syntax are unsupported",
            ),
            Self::InvalidTerm(message) => write!(f, "query term is invalid: {message}"),
        }
    }
}

impl std::error::Error for QueryError {}

pub(crate) fn validate_query_length(expression: &str) -> Result<(), QueryError> {
    let bytes = expression.len();
    if bytes > MAX_QUERY_BYTES {
        return Err(QueryError::QueryTooLong { bytes });
    }
    Ok(())
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
        let analyzer = Analyzer;
        let title_terms = analyzer.analyze(&title).map_err(map_analyzer_error)?;
        let body_terms = analyzer.analyze(&body).map_err(map_analyzer_error)?;
        let record = IndexedDocument {
            id: id.clone(),
            effective_url,
            title,
            body,
            title_terms: title_terms.clone(),
            body_terms: body_terms.clone(),
        };
        add_positions(&mut self.postings, &id, &title_terms, true);
        add_positions(&mut self.postings, &id, &body_terms, false);
        self.documents.insert(id, record);
        Ok(())
    }

    pub fn query(&self, expression: &str) -> Result<Vec<SearchResult>, QueryError> {
        validate_query_length(expression)?;
        let query = expression.trim();
        if query.is_empty() {
            return Err(QueryError::EmptyQuery);
        }
        if query.split_whitespace().count() != 1
            || query.chars().any(|ch| {
                matches!(
                    ch,
                    '"' | '*'
                        | '?'
                        | '+'
                        | '-'
                        | '!'
                        | '|'
                        | '&'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ':'
                        | '\\'
                        | '^'
                        | '~'
                )
            })
            || matches!(query, "AND" | "OR" | "NOT")
        {
            return Err(QueryError::UnsupportedSyntax);
        }
        let terms = Analyzer.analyze(query).map_err(map_analyzer_error)?;
        let Some(term) = terms.first() else {
            return Err(QueryError::EmptyQuery);
        };
        if terms.len() != 1 {
            return Err(QueryError::UnsupportedSyntax);
        }
        let Some(posting_by_document) = self.postings.get(term) else {
            return Ok(Vec::new());
        };
        let count = self.documents.len() as f64;
        if count == 0.0 {
            return Ok(Vec::new());
        }
        let avg_title_len = self
            .documents
            .values()
            .map(|document| document.title_terms.len() as f64)
            .sum::<f64>()
            / count;
        let avg_body_len = self
            .documents
            .values()
            .map(|document| document.body_terms.len() as f64)
            .sum::<f64>()
            / count;
        let df_title = posting_by_document
            .values()
            .filter(|posting| !posting.title_positions.is_empty())
            .count() as f64;
        let df_body = posting_by_document
            .values()
            .filter(|posting| !posting.body_positions.is_empty())
            .count() as f64;
        let idf_title = bm25_idf(count, df_title);
        let idf_body = bm25_idf(count, df_body);
        let mut results = Vec::new();
        for (document_id, posting) in posting_by_document {
            let Some(document) = self.documents.get(document_id) else {
                continue;
            };
            let title_score = bm25_field_score(
                posting.title_positions.len(),
                document.title_terms.len(),
                avg_title_len,
                idf_title,
            ) * 2.0;
            let body_score = bm25_field_score(
                posting.body_positions.len(),
                document.body_terms.len(),
                avg_body_len,
                idf_body,
            );
            results.push(SearchResult {
                id: document.id.clone(),
                title: document.title.clone(),
                score: title_score + body_score,
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
        positions.push(position as u32);
    }
}

fn bm25_idf(document_count: f64, document_frequency: f64) -> f64 {
    (1.0 + (document_count - document_frequency + 0.5) / (document_frequency + 0.5)).ln()
}

fn bm25_field_score(
    term_frequency: usize,
    field_length: usize,
    average_length: f64,
    idf: f64,
) -> f64 {
    if term_frequency == 0 || average_length == 0.0 {
        return 0.0;
    }
    let k1 = 1.2;
    let b = 0.75;
    let frequency = term_frequency as f64;
    let length_norm = 1.0 - b + b * field_length as f64 / average_length;
    idf * (frequency * (k1 + 1.0)) / (frequency + k1 * length_norm)
}

fn map_analyzer_error(error: AnalyzeError) -> QueryError {
    QueryError::InvalidTerm(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn reference_index() -> InMemoryIndex {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        let mut index = InMemoryIndex::new();
        for document in fixture["documents"].as_array().expect("documents") {
            index
                .insert_fields(
                    document["id"].as_str().unwrap().to_owned(),
                    document["id"].as_str().unwrap().to_owned(),
                    document["title"].as_str().unwrap().to_owned(),
                    document["body"].as_str().unwrap().to_owned(),
                )
                .unwrap();
        }
        index
    }

    #[test]
    fn builds_positional_field_postings_and_matches_published_bm25_golden() {
        let index = reference_index();
        assert_eq!(index.len(), 10);
        assert_eq!(
            index.postings()["alpha"]["https://example.test/a"].title_positions,
            [0]
        );
        assert_eq!(
            index.postings()["alpha"]["https://example.test/a"].body_positions,
            [0]
        );

        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        let golden = &fixture["ranking_vectors"][0];
        let results = index.query("alpha").unwrap();
        let expected_order: Vec<&str> = golden["expected_order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect();
        let actual_order: Vec<&str> = results.iter().map(|result| result.id.as_str()).collect();
        assert_eq!(actual_order, expected_order);
        for result in &results {
            let expected = golden["expected_scores"][&result.id].as_f64().unwrap();
            assert!((result.score - expected).abs() < 1e-12, "{}", result.id);
        }
    }

    #[test]
    fn explicitly_rejects_unimplemented_query_syntax() {
        let index = reference_index();
        for expression in [
            "alpha beta",
            "\"alpha beta\"",
            "alpha OR beta",
            "title:alpha",
            "alp*",
            "+alpha",
        ] {
            assert_eq!(index.query(expression), Err(QueryError::UnsupportedSyntax));
        }
        assert_eq!(index.query("   "), Err(QueryError::EmptyQuery));
        assert!(index.query("missing").unwrap().is_empty());
    }

    #[test]
    fn checks_raw_query_utf8_bytes_before_trimming_or_analysis() {
        const QUERY_LIMIT: usize = 4096;
        let index = reference_index();
        let at_limit = format!("{}Rust", " ".repeat(QUERY_LIMIT - "Rust".len()));
        assert_eq!(at_limit.len(), QUERY_LIMIT);
        assert_eq!(
            index.query(&at_limit).unwrap(),
            index.query("Rust").unwrap()
        );

        let over_limit = format!("{}Rust", " ".repeat(QUERY_LIMIT - "Rust".len() + 1));
        assert_eq!(over_limit.len(), QUERY_LIMIT + 1);
        assert_eq!(
            index.query(&over_limit).unwrap_err().to_string(),
            "query is 4097 UTF-8 bytes; limit is 4096. Shorten the query and retry."
        );

        let multibyte_at_limit = "é".repeat(QUERY_LIMIT / "é".len());
        assert_eq!(multibyte_at_limit.len(), QUERY_LIMIT);
        assert!(matches!(
            index.query(&multibyte_at_limit),
            Err(QueryError::InvalidTerm(_))
        ));
        let multibyte_over_limit = "é".repeat(QUERY_LIMIT / "é".len() + 1);
        assert_eq!(multibyte_over_limit.len(), QUERY_LIMIT + "é".len());
        assert_eq!(
            index.query(&multibyte_over_limit).unwrap_err().to_string(),
            "query is 4098 UTF-8 bytes; limit is 4096. Shorten the query and retry."
        );
    }
}
