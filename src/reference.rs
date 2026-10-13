use crate::index::{InMemoryIndex, IndexedDocument};
use crate::query::{Expr, ParsedQuery};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReferenceHit {
    pub id: String,
    pub score: f64,
}

pub(crate) fn exhaustive_search(index: &InMemoryIndex, query: &ParsedQuery) -> Vec<ReferenceHit> {
    let documents: Vec<&IndexedDocument> = index.documents().values().collect();
    let count = documents.len();
    if count == 0 {
        return Vec::new();
    }
    let mean_title_length = documents
        .iter()
        .map(|document| document.title_terms.len() as f64)
        .sum::<f64>()
        / count as f64;
    let mean_body_length = documents
        .iter()
        .map(|document| document.body_terms.len() as f64)
        .sum::<f64>()
        / count as f64;
    let mut hits = Vec::new();

    for document in &documents {
        if !matches_document(&query.root, document) {
            continue;
        }
        let mut score = 0.0;
        for term in &query.score_terms {
            let title_frequency = document
                .title_terms
                .iter()
                .filter(|candidate| *candidate == term)
                .count();
            let body_frequency = document
                .body_terms
                .iter()
                .filter(|candidate| *candidate == term)
                .count();
            if title_frequency > 0 {
                let title_frequency_documents = documents
                    .iter()
                    .filter(|candidate| candidate.title_terms.iter().any(|value| value == term))
                    .count();
                score += reference_field_score(
                    count,
                    title_frequency_documents,
                    title_frequency,
                    document.title_terms.len(),
                    mean_title_length,
                    2.0,
                );
            }
            if body_frequency > 0 {
                let body_frequency_documents = documents
                    .iter()
                    .filter(|candidate| candidate.body_terms.iter().any(|value| value == term))
                    .count();
                score += reference_field_score(
                    count,
                    body_frequency_documents,
                    body_frequency,
                    document.body_terms.len(),
                    mean_body_length,
                    1.0,
                );
            }
        }
        hits.push(ReferenceHit {
            id: document.id.clone(),
            score,
        });
    }

    hits.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
    });
    hits
}

fn matches_document(expression: &Expr, document: &IndexedDocument) -> bool {
    match expression {
        Expr::Term(term) => {
            document.title_terms.contains(term) || document.body_terms.contains(term)
        }
        Expr::Phrase(phrase) => {
            phrase_occurs(&document.title_terms, phrase)
                || phrase_occurs(&document.body_terms, phrase)
        }
        Expr::And(children) => children
            .iter()
            .all(|child| matches_document(child, document)),
        Expr::Or(children) => children
            .iter()
            .any(|child| matches_document(child, document)),
    }
}

fn phrase_occurs(field: &[String], phrase: &[String]) -> bool {
    !phrase.is_empty()
        && field
            .windows(phrase.len())
            .any(|window| window.iter().zip(phrase).all(|(left, right)| left == right))
}

fn reference_field_score(
    corpus_size: usize,
    field_document_frequency: usize,
    frequency: usize,
    field_length: usize,
    field_mean: f64,
    boost: f64,
) -> f64 {
    if frequency == 0 || field_mean == 0.0 {
        return 0.0;
    }
    let n = corpus_size as f64;
    let df = field_document_frequency as f64;
    let inverse_frequency = (1.0 + (n - df + 0.5) / (df + 0.5)).ln();
    let tf = frequency as f64;
    let relative_length = field_length as f64 / field_mean;
    let denominator = tf + 1.2 * (1.0 - 0.75 + 0.75 * relative_length);
    boost * inverse_frequency * (tf * 2.2) / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::MAX_TERM_SCALARS;
    use crate::html::{MAX_DOCUMENT_TOKENS, MAX_FIELDS_BYTES, MAX_TITLE_BYTES};
    use crate::index::QueryError;
    use crate::query::{Expr, parse_query};
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

    fn assert_parity(index: &InMemoryIndex, expression: &str) {
        let parsed = parse_query(expression).unwrap();
        let expected = exhaustive_search(index, &parsed);
        let actual = index.query_parsed(&parsed).unwrap();
        assert_eq!(
            actual.iter().map(|hit| hit.id.as_str()).collect::<Vec<_>>(),
            expected
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            "match set and ordering for {expression:?}"
        );
        for (actual, expected) in actual.iter().zip(expected) {
            assert!(
                (actual.score - expected.score).abs() <= 1e-12,
                "score mismatch for {:?} on {expression:?}: {} != {}",
                actual.id,
                actual.score,
                expected.score
            );
            assert_eq!(actual.score, actual.explanation.total_score);
        }
    }

    #[test]
    fn exhaustive_document_scan_matches_every_published_query_and_ranked_score() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        let index = reference_index();

        for query in fixture["queries"].as_array().unwrap() {
            let expression = query["expression"].as_str().unwrap();
            assert_eq!(
                expression_json(&parse_query(expression).unwrap().root),
                query["ast"],
                "fixture AST {}",
                query["id"]
            );
            assert_parity(&index, expression);
            let actual = index.query(expression).unwrap();
            let matches = actual
                .iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>();
            let expected = query["expected_matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>();
            let mut actual_set = matches.clone();
            let mut expected_set = expected.clone();
            actual_set.sort_unstable();
            expected_set.sort_unstable();
            assert_eq!(actual_set, expected_set, "fixture query {}", query["id"]);
        }

        for ranking in fixture["ranking_vectors"].as_array().unwrap() {
            let query_id = ranking["query_id"].as_str().unwrap();
            let query = fixture["queries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|query| query["id"] == query_id)
                .expect("ranking vector names a query");
            let expression = query["expression"].as_str().unwrap();
            assert_parity(&index, expression);
            let results = index.query(expression).unwrap();
            let expected_order = ranking["expected_order"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                results
                    .iter()
                    .map(|result| result.id.as_str())
                    .collect::<Vec<_>>(),
                expected_order,
                "ranking vector {query_id}"
            );
            for result in &results {
                let expected = ranking["expected_scores"][&result.id].as_f64().unwrap();
                assert!((result.score - expected).abs() < 1e-12, "{}", result.id);
            }

            let expected_stats = &ranking["expected_stats"];
            let explanation = &results[0].explanation;
            assert_eq!(
                explanation.document_count,
                expected_stats["N"].as_u64().unwrap() as usize
            );
            assert_close(
                explanation.average_title_length,
                expected_stats["title"]["avg_length"].as_f64().unwrap(),
                "title average length",
            );
            assert_close(
                explanation.average_body_length,
                expected_stats["body"]["avg_length"].as_f64().unwrap(),
                "body average length",
            );
            let expected_terms = ranking["terms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|term| term.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(explanation.normalized_terms, expected_terms);
            for field_name in ["title", "body"] {
                for (term, expected_df) in expected_stats[field_name]["df"].as_object().unwrap() {
                    let term_explanation = explanation
                        .terms
                        .iter()
                        .find(|entry| entry.term == *term)
                        .unwrap();
                    let actual_df = match field_name {
                        "title" => term_explanation.title.document_frequency,
                        "body" => term_explanation.body.document_frequency,
                        _ => unreachable!(),
                    };
                    assert_eq!(actual_df, expected_df.as_u64().unwrap() as usize);
                }
            }
            if let Some(expected_components) = ranking
                .get("expected_components")
                .and_then(Value::as_object)
            {
                for (id, terms) in expected_components {
                    let result = results.iter().find(|result| result.id == *id).unwrap();
                    for (term, components) in terms.as_object().unwrap() {
                        let explanation = result
                            .explanation
                            .terms
                            .iter()
                            .find(|entry| entry.term == *term)
                            .unwrap();
                        assert_close(
                            explanation.title.contribution,
                            components["title"].as_f64().unwrap(),
                            "title BM25 component",
                        );
                        assert_close(
                            explanation.body.contribution,
                            components["body"].as_f64().unwrap(),
                            "body BM25 component",
                        );
                    }
                }
            }
        }
    }

    fn assert_close(actual: f64, expected: f64, description: &str) {
        assert!(
            (actual - expected).abs() <= 1e-12,
            "{description}: {actual} != {expected}"
        );
    }

    fn expression_json(expression: &Expr) -> Value {
        match expression {
            Expr::Term(term) => serde_json::json!({"term": term}),
            Expr::Phrase(terms) => serde_json::json!({"phrase": terms}),
            Expr::And(children) => serde_json::json!({
                "and": children.iter().map(expression_json).collect::<Vec<_>>()
            }),
            Expr::Or(children) => serde_json::json!({
                "or": children.iter().map(expression_json).collect::<Vec<_>>()
            }),
        }
    }

    #[test]
    fn oracle_covers_empty_documents_common_terms_and_unsatisfied_or_branches() {
        let mut index = InMemoryIndex::new();
        index
            .insert_fields("a".into(), "a".into(), "Common".into(), "common".into())
            .unwrap();
        index
            .insert_fields(
                "b".into(),
                "b".into(),
                "Common".into(),
                "common common".into(),
            )
            .unwrap();
        index
            .insert_fields("empty".into(), "empty".into(), String::new(), String::new())
            .unwrap();
        assert_parity(&index, "common");
        let common = index.query("common").unwrap();
        assert_eq!(common[0].explanation.document_count, 3);
        assert_eq!(common[0].explanation.terms[0].title.document_frequency, 2);
        assert_eq!(common[0].explanation.terms[0].body.document_frequency, 2);
        let mut all_common = InMemoryIndex::new();
        all_common
            .insert_fields(
                "first".into(),
                "first".into(),
                "common".into(),
                "common".into(),
            )
            .unwrap();
        all_common
            .insert_fields(
                "second".into(),
                "second".into(),
                "common".into(),
                "common".into(),
            )
            .unwrap();
        assert_parity(&all_common, "common");
        let all_common_results = all_common.query("common").unwrap();
        assert_eq!(
            all_common_results[0].explanation.terms[0]
                .title
                .document_frequency,
            2
        );
        assert_eq!(
            all_common_results[0].explanation.terms[0]
                .body
                .document_frequency,
            2
        );
        assert!(all_common_results.iter().all(|result| result.score > 0.0));

        let fixture = reference_index();
        assert_parity(&fixture, "alpha OR beta AND gamma");
        let result_a = fixture
            .query("alpha OR beta AND gamma")
            .unwrap()
            .into_iter()
            .find(|result| result.id.ends_with("/a"))
            .unwrap();
        let beta = result_a
            .explanation
            .terms
            .iter()
            .find(|term| term.term == "beta")
            .unwrap();
        assert!(matches!(
            result_a.matched,
            crate::index::MatchEvidence::Term { ref term, .. } if term == "alpha"
        ));
        assert_eq!(beta.title.contribution, 0.0);
        assert!(beta.body.contribution > 0.0);
    }

    #[test]
    fn reference_parity_covers_empty_index_and_zero_average_fields() {
        let empty = InMemoryIndex::new();
        assert_parity(&empty, "alpha");
        assert!(empty.query("alpha").unwrap().is_empty());

        let mut all_empty = InMemoryIndex::new();
        for id in ["empty-a", "empty-b"] {
            all_empty
                .insert_fields(id.into(), id.into(), String::new(), String::new())
                .unwrap();
        }
        assert_parity(&all_empty, "alpha");
        assert!(all_empty.query("alpha").unwrap().is_empty());

        let mut empty_titles = InMemoryIndex::new();
        empty_titles
            .insert_fields(
                "body-hit".into(),
                "body-hit".into(),
                "".into(),
                "alpha".into(),
            )
            .unwrap();
        empty_titles
            .insert_fields("empty".into(), "empty".into(), "".into(), "".into())
            .unwrap();
        assert_parity(&empty_titles, "alpha");
        let title_empty_hit = &empty_titles.query("alpha").unwrap()[0];
        assert_eq!(title_empty_hit.explanation.average_title_length, 0.0);
        assert_eq!(title_empty_hit.explanation.document_count, 2);
        assert!(
            title_empty_hit
                .explanation
                .terms
                .iter()
                .all(|term| term.title.contribution == 0.0)
        );

        let mut empty_bodies = InMemoryIndex::new();
        empty_bodies
            .insert_fields(
                "title-hit".into(),
                "title-hit".into(),
                "alpha".into(),
                "".into(),
            )
            .unwrap();
        empty_bodies
            .insert_fields("empty".into(), "empty".into(), "".into(), "".into())
            .unwrap();
        assert_parity(&empty_bodies, "alpha");
        let body_empty_hit = &empty_bodies.query("alpha").unwrap()[0];
        assert_eq!(body_empty_hit.explanation.average_body_length, 0.0);
        assert_eq!(body_empty_hit.explanation.document_count, 2);
        assert!(
            body_empty_hit
                .explanation
                .terms
                .iter()
                .all(|term| term.body.contribution == 0.0)
        );
    }

    #[test]
    fn public_index_enforces_field_and_token_limits() {
        let mut index = InMemoryIndex::new();
        assert!(
            index
                .insert_fields(
                    "title-at-limit".into(),
                    "title-at-limit".into(),
                    " ".repeat(MAX_TITLE_BYTES),
                    String::new(),
                )
                .is_ok()
        );
        assert!(
            index
                .insert_fields(
                    "fields-at-limit".into(),
                    "fields-at-limit".into(),
                    String::new(),
                    " ".repeat(MAX_FIELDS_BYTES),
                )
                .is_ok()
        );
        assert_eq!(
            index
                .insert_fields(
                    "title-over-limit".into(),
                    "title-over-limit".into(),
                    " ".repeat(MAX_TITLE_BYTES + 1),
                    String::new(),
                )
                .unwrap_err(),
            QueryError::TitleTooLong {
                bytes: MAX_TITLE_BYTES + 1
            }
        );
        assert_eq!(
            index
                .insert_fields(
                    "fields-over-limit".into(),
                    "fields-over-limit".into(),
                    String::new(),
                    " ".repeat(MAX_FIELDS_BYTES + 1),
                )
                .unwrap_err(),
            QueryError::FieldsTooLong {
                bytes: MAX_FIELDS_BYTES + 1
            }
        );

        let at_token_limit = "a a ".repeat(MAX_DOCUMENT_TOKENS / 2);
        assert!(
            index
                .insert_fields(
                    "tokens-at-limit".into(),
                    "tokens-at-limit".into(),
                    String::new(),
                    at_token_limit,
                )
                .is_ok()
        );
        let over_token_limit = format!("{}a", "a a ".repeat(MAX_DOCUMENT_TOKENS / 2));
        assert_eq!(
            index
                .insert_fields(
                    "tokens-over-limit".into(),
                    "tokens-over-limit".into(),
                    String::new(),
                    over_token_limit,
                )
                .unwrap_err(),
            QueryError::TooManyDocumentTokens {
                tokens: MAX_DOCUMENT_TOKENS + 1
            }
        );
    }

    #[test]
    fn rejected_upserts_preserve_the_visible_version_results_and_statistics() {
        let mut index = InMemoryIndex::new();
        index
            .insert_fields(
                "live".into(),
                "live".into(),
                "old".into(),
                "old body".into(),
            )
            .unwrap();
        index
            .insert_fields("other".into(), "other".into(), "other".into(), "old".into())
            .unwrap();
        let before_results = index.query("old").unwrap();
        let before_version = index.documents()["live"].version_id.clone();

        assert_eq!(
            index
                .upsert_fields(
                    "live".into(),
                    "live".into(),
                    "replacement".into(),
                    "x".repeat(MAX_TERM_SCALARS + 1),
                )
                .unwrap_err(),
            QueryError::DocumentTermTooLong {
                scalars: MAX_TERM_SCALARS + 1
            }
        );
        assert_eq!(index.documents()["live"].version_id, before_version);
        assert_eq!(index.query("old").unwrap(), before_results);

        assert_eq!(
            index
                .upsert_fields(
                    "live".into(),
                    "live".into(),
                    " ".repeat(MAX_TITLE_BYTES + 1),
                    String::new(),
                )
                .unwrap_err(),
            QueryError::TitleTooLong {
                bytes: MAX_TITLE_BYTES + 1
            }
        );
        assert_eq!(index.documents()["live"].version_id, before_version);
        assert_eq!(index.query("old").unwrap(), before_results);
        assert!(index.query("replacement").unwrap().is_empty());
    }

    #[test]
    fn oracle_covers_repeated_phrases_field_boundaries_ties_and_live_mutations() {
        let mut index = InMemoryIndex::new();
        index
            .insert_fields(
                "repeat-a".into(),
                "repeat-a".into(),
                "same".into(),
                "a a a".into(),
            )
            .unwrap();
        index
            .insert_fields(
                "repeat-b".into(),
                "repeat-b".into(),
                "same".into(),
                "a a b".into(),
            )
            .unwrap();
        index
            .insert_fields(
                "tie-z".into(),
                "tie-z".into(),
                "shared".into(),
                "same".into(),
            )
            .unwrap();
        index
            .insert_fields(
                "tie-a".into(),
                "tie-a".into(),
                "shared".into(),
                "same".into(),
            )
            .unwrap();
        assert_parity(&index, "\"a a\"");
        let repeated = index.query("\"a a\"").unwrap();
        assert_eq!(repeated.len(), 2);
        assert!(repeated.iter().all(|result| {
            matches!(
                result.matched,
                crate::index::MatchEvidence::Phrase { ref body_starts, .. } if !body_starts.is_empty()
            )
        }));
        assert_parity(&index, "shared");
        let ties = index.query("shared").unwrap();
        assert_eq!(
            ties.iter()
                .map(|result| result.id.as_str())
                .collect::<Vec<_>>(),
            ["tie-a", "tie-z"]
        );

        let published = reference_index();
        assert_parity(&published, "\"field separation\"");
        assert!(
            published
                .query("\"field separation\"")
                .unwrap()
                .iter()
                .all(|hit| { hit.id.ends_with("/phrase") })
        );

        let id = "live".to_owned();
        index
            .upsert_fields(id.clone(), id.clone(), "old".into(), "old".into())
            .unwrap();
        assert_parity(&index, "old");
        let old_version = index.documents()[&id].version_id.clone();
        index
            .upsert_fields(id.clone(), id.clone(), "new".into(), "new new".into())
            .unwrap();
        assert_ne!(index.documents()[&id].version_id, old_version);
        assert!(index.query("old").unwrap().is_empty());
        assert_parity(&index, "new");
        assert!(index.remove_document(&id));
        assert!(!index.remove_document(&id));
        assert!(index.query("new").unwrap().is_empty());
        assert_parity(&index, "shared");
    }

    #[test]
    fn fixture_hashes_and_error_names_remain_exact() {
        let fixture: Value = serde_json::from_str(include_str!("../fixtures/reference-v1.json"))
            .expect("published reference fixture is valid JSON");
        let index = reference_index();
        for document in fixture["documents"].as_array().unwrap() {
            let id = document["id"].as_str().unwrap();
            assert_eq!(
                index.documents()[id].version_id,
                document["version_sha256"].as_str().unwrap(),
                "document version {id}"
            );
        }
        for vector in fixture["query_errors"].as_array().unwrap() {
            let expression = vector["expression"].as_str().unwrap();
            let actual = parse_query(expression).unwrap_err();
            assert_eq!(
                format!("{actual:?}"),
                vector["error"].as_str().unwrap(),
                "{expression:?}"
            );
        }
        assert_eq!(
            index.query("alpha OR").unwrap_err(),
            QueryError::MissingOperand
        );
    }
}
