use std::collections::BTreeSet;
use std::fmt;

use crate::analyzer::{AnalyzeError, Analyzer, MAX_TERM_SCALARS};
use crate::html::{MAX_DOCUMENT_TOKENS, MAX_FIELDS_BYTES, MAX_TITLE_BYTES};

pub(crate) const MAX_QUERY_TOKEN_OCCURRENCES: usize = 64;
pub(crate) const MAX_PHRASE_TOKENS: usize = 16;
pub(crate) const MAX_QUERY_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    EmptyQuery,
    NoSearchTerms,
    UnterminatedPhrase,
    InvalidEscape,
    EmptyPhrase,
    MissingOperand,
    UnsupportedSyntax,
    QueryTooLong { bytes: usize },
    TooManyTerms { occurrences: usize },
    PhraseTooLong { tokens: usize },
    TokenTooLong { scalars: usize },
    TitleTooLong { bytes: usize },
    FieldsTooLong { bytes: usize },
    DocumentTermTooLong { scalars: usize },
    TooManyDocumentTokens { tokens: usize },
    NonFiniteScore,
    InvalidTerm(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => formatter.write_str("query is empty or whitespace-only"),
            Self::NoSearchTerms => formatter.write_str("query contains no searchable terms"),
            Self::UnterminatedPhrase => {
                formatter.write_str("query contains an unterminated phrase")
            }
            Self::InvalidEscape => formatter
                .write_str("phrase escapes may only quote a double quote or another backslash"),
            Self::EmptyPhrase => formatter.write_str("quoted phrase contains no searchable terms"),
            Self::MissingOperand => formatter.write_str("Boolean operator is missing an operand"),
            Self::UnsupportedSyntax => formatter.write_str("query uses unsupported syntax"),
            Self::QueryTooLong { bytes } => write!(
                formatter,
                "query is {bytes} UTF-8 bytes; limit is {MAX_QUERY_BYTES}. Shorten the query and retry."
            ),
            Self::TooManyTerms { occurrences } => write!(
                formatter,
                "query has {occurrences} analyzed token occurrences; limit is {MAX_QUERY_TOKEN_OCCURRENCES}"
            ),
            Self::PhraseTooLong { tokens } => write!(
                formatter,
                "phrase has {tokens} analyzed tokens; limit is {MAX_PHRASE_TOKENS}"
            ),
            Self::TokenTooLong { scalars } => write!(
                formatter,
                "analyzed query token has {scalars} Unicode scalar values; maximum is {MAX_TERM_SCALARS}"
            ),
            Self::TitleTooLong { bytes } => write!(
                formatter,
                "document title has {bytes} UTF-8 bytes; limit is {MAX_TITLE_BYTES}"
            ),
            Self::FieldsTooLong { bytes } => write!(
                formatter,
                "document title and body have {bytes} UTF-8 bytes; limit is {MAX_FIELDS_BYTES}"
            ),
            Self::DocumentTermTooLong { scalars } => write!(
                formatter,
                "document analyzer token has {scalars} Unicode scalar values; maximum is {MAX_TERM_SCALARS}"
            ),
            Self::TooManyDocumentTokens { tokens } => write!(
                formatter,
                "document has {tokens} analyzer tokens; limit is {MAX_DOCUMENT_TOKENS}"
            ),
            Self::NonFiniteScore => formatter.write_str("query produced a non-finite score"),
            Self::InvalidTerm(message) => {
                write!(formatter, "indexed document is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for QueryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Expr {
    Term(String),
    Phrase(Vec<String>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedQuery {
    pub root: Expr,
    pub score_terms: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawItem {
    Operand { text: String, phrase: bool },
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Operand(Expr),
    And,
    Or,
}

pub(crate) fn parse_query(raw: &str) -> Result<ParsedQuery, QueryError> {
    if raw.len() > MAX_QUERY_BYTES {
        return Err(QueryError::QueryTooLong { bytes: raw.len() });
    }
    if raw.trim().is_empty() {
        return Err(QueryError::EmptyQuery);
    }

    let items = lex(raw)?;
    validate_operator_positions(&items)?;

    let mut expanded = Vec::new();
    let mut first_analysis_error = None;
    let mut empty_phrase = false;
    let mut occurrences = 0usize;
    let mut too_long_phrase = None;
    for item in items {
        match item {
            RawItem::And => expanded.push(Token::And),
            RawItem::Or => expanded.push(Token::Or),
            RawItem::Operand { text, phrase } => {
                let (analyzed, analysis_failed) = match Analyzer.analyze(&text) {
                    Ok(terms) => (terms, false),
                    Err(AnalyzeError::TermTooLong { scalars }) => {
                        first_analysis_error.get_or_insert(QueryError::TokenTooLong { scalars });
                        (vec![String::new()], true)
                    }
                };
                if phrase && analyzed.is_empty() && !analysis_failed {
                    empty_phrase = true;
                }
                if phrase && analyzed.len() > MAX_PHRASE_TOKENS {
                    too_long_phrase.get_or_insert(analyzed.len());
                }
                occurrences = occurrences.saturating_add(analyzed.len());
                let operands = if phrase {
                    vec![Expr::Phrase(analyzed)]
                } else {
                    analyzed.into_iter().map(Expr::Term).collect()
                };
                if operands.is_empty() {
                    continue;
                }
                if matches!(expanded.last(), Some(Token::Operand(_))) {
                    expanded.push(Token::And);
                }
                for (index, operand) in operands.into_iter().enumerate() {
                    if index > 0 {
                        expanded.push(Token::And);
                    }
                    expanded.push(Token::Operand(operand));
                }
            }
        }
    }

    validate_expanded_operator_positions(&expanded)?;
    if empty_phrase {
        return Err(QueryError::EmptyPhrase);
    }
    if let Some(error) = first_analysis_error {
        return Err(error);
    }
    if let Some(tokens) = too_long_phrase {
        return Err(QueryError::PhraseTooLong { tokens });
    }
    if occurrences > MAX_QUERY_TOKEN_OCCURRENCES {
        return Err(QueryError::TooManyTerms { occurrences });
    }
    if expanded.is_empty() {
        return Err(QueryError::NoSearchTerms);
    }

    let root = parse_expression(&expanded)?;
    let mut score_terms = BTreeSet::new();
    collect_score_terms(&root, &mut score_terms);
    Ok(ParsedQuery {
        root,
        score_terms: score_terms.into_iter().collect(),
    })
}

fn lex(raw: &str) -> Result<Vec<RawItem>, QueryError> {
    let mut items = Vec::new();
    let mut cursor = 0usize;
    while cursor < raw.len() {
        let rest = &raw[cursor..];
        let Some(first) = rest.chars().next() else {
            break;
        };
        if first.is_whitespace() {
            cursor += first.len_utf8();
            continue;
        }
        if first == '"' {
            let start = cursor + first.len_utf8();
            let mut content = String::new();
            let mut position = start;
            let mut closed = false;
            while position < raw.len() {
                let character = raw[position..]
                    .chars()
                    .next()
                    .expect("valid UTF-8 boundary");
                position += character.len_utf8();
                match character {
                    '"' => {
                        closed = true;
                        break;
                    }
                    '\\' => {
                        if position == raw.len() {
                            return Err(QueryError::InvalidEscape);
                        }
                        let escaped = raw[position..]
                            .chars()
                            .next()
                            .expect("position is within the query");
                        position += escaped.len_utf8();
                        match escaped {
                            '"' | '\\' => content.push(escaped),
                            _ => return Err(QueryError::InvalidEscape),
                        }
                    }
                    other => content.push(other),
                }
            }
            if !closed {
                return Err(QueryError::UnterminatedPhrase);
            }
            if position < raw.len()
                && !raw[position..]
                    .chars()
                    .next()
                    .is_some_and(char::is_whitespace)
            {
                return Err(QueryError::UnsupportedSyntax);
            }
            items.push(RawItem::Operand {
                text: content,
                phrase: true,
            });
            cursor = position;
            continue;
        }

        let start = cursor;
        while cursor < raw.len() {
            let character = raw[cursor..].chars().next().expect("valid UTF-8 boundary");
            if character.is_whitespace() {
                break;
            }
            if character == '"' {
                return Err(QueryError::UnsupportedSyntax);
            }
            if matches!(character, '(' | ')' | ':' | '*' | '?' | '~') {
                return Err(QueryError::UnsupportedSyntax);
            }
            cursor += character.len_utf8();
        }
        let lexeme = &raw[start..cursor];
        match lexeme {
            "AND" => items.push(RawItem::And),
            "OR" => items.push(RawItem::Or),
            "NOT" => return Err(QueryError::UnsupportedSyntax),
            _ if is_proximity_syntax(lexeme) => return Err(QueryError::UnsupportedSyntax),
            _ => items.push(RawItem::Operand {
                text: lexeme.to_owned(),
                phrase: false,
            }),
        }
    }
    Ok(items)
}

fn is_proximity_syntax(lexeme: &str) -> bool {
    let Some(distance) = lexeme.strip_prefix("NEAR/") else {
        return false;
    };
    !distance.is_empty() && distance.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_operator_positions(items: &[RawItem]) -> Result<(), QueryError> {
    let mut expecting_operand = true;
    for item in items {
        match item {
            RawItem::Operand { .. } => expecting_operand = false,
            RawItem::And | RawItem::Or if !expecting_operand => expecting_operand = true,
            RawItem::And | RawItem::Or => return Err(QueryError::MissingOperand),
        }
    }
    if expecting_operand && !items.is_empty() {
        return Err(QueryError::MissingOperand);
    }
    Ok(())
}

fn validate_expanded_operator_positions(tokens: &[Token]) -> Result<(), QueryError> {
    let mut expecting_operand = true;
    for token in tokens {
        match token {
            Token::Operand(_) => expecting_operand = false,
            Token::And | Token::Or if !expecting_operand => expecting_operand = true,
            Token::And | Token::Or => return Err(QueryError::MissingOperand),
        }
    }
    if expecting_operand && !tokens.is_empty() {
        return Err(QueryError::MissingOperand);
    }
    Ok(())
}

fn parse_expression(tokens: &[Token]) -> Result<Expr, QueryError> {
    let mut cursor = 0usize;
    let expression = parse_or(tokens, &mut cursor)?;
    if cursor != tokens.len() {
        return Err(QueryError::MissingOperand);
    }
    Ok(expression)
}

fn parse_or(tokens: &[Token], cursor: &mut usize) -> Result<Expr, QueryError> {
    let mut children = vec![parse_and(tokens, cursor)?];
    while matches!(tokens.get(*cursor), Some(Token::Or)) {
        *cursor += 1;
        children.push(parse_and(tokens, cursor)?);
    }
    Ok(flatten(children, true))
}

fn parse_and(tokens: &[Token], cursor: &mut usize) -> Result<Expr, QueryError> {
    let mut children = vec![parse_primary(tokens, cursor)?];
    while matches!(tokens.get(*cursor), Some(Token::And)) {
        *cursor += 1;
        children.push(parse_primary(tokens, cursor)?);
    }
    Ok(flatten(children, false))
}

fn parse_primary(tokens: &[Token], cursor: &mut usize) -> Result<Expr, QueryError> {
    let Some(Token::Operand(expression)) = tokens.get(*cursor) else {
        return Err(QueryError::MissingOperand);
    };
    *cursor += 1;
    Ok(expression.clone())
}

fn flatten(children: Vec<Expr>, disjunction: bool) -> Expr {
    if children.len() == 1 {
        return children.into_iter().next().expect("one child");
    }
    if disjunction {
        Expr::Or(children)
    } else {
        Expr::And(children)
    }
}

fn collect_score_terms(expression: &Expr, terms: &mut BTreeSet<String>) {
    match expression {
        Expr::Term(term) => {
            terms.insert(term.clone());
        }
        Expr::Phrase(phrase) => terms.extend(phrase.iter().cloned()),
        Expr::And(children) | Expr::Or(children) => {
            for child in children {
                collect_score_terms(child, terms);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_queries_keep_the_accepted_ast_and_sorted_score_terms() {
        let query = parse_query("alpha OR beta AND gamma").unwrap();
        assert_eq!(
            query.root,
            Expr::Or(vec![
                Expr::Term("alpha".to_owned()),
                Expr::And(vec![
                    Expr::Term("beta".to_owned()),
                    Expr::Term("gamma".to_owned()),
                ]),
            ])
        );
        assert_eq!(query.score_terms, ["alpha", "beta", "gamma"]);
        assert_eq!(
            parse_query("alpha beta alpha").unwrap().root,
            Expr::And(vec![
                Expr::Term("alpha".to_owned()),
                Expr::Term("beta".to_owned()),
                Expr::Term("alpha".to_owned()),
            ])
        );
        assert_eq!(
            parse_query("alpha-beta").unwrap().root,
            Expr::And(vec![
                Expr::Term("alpha".to_owned()),
                Expr::Term("beta".to_owned()),
            ])
        );
        assert_eq!(
            parse_query("alpha !!! beta").unwrap().root,
            Expr::And(vec![
                Expr::Term("alpha".to_owned()),
                Expr::Term("beta".to_owned()),
            ])
        );
        assert_eq!(
            parse_query("alpha AND !!! beta").unwrap().root,
            Expr::And(vec![
                Expr::Term("alpha".to_owned()),
                Expr::Term("beta".to_owned()),
            ])
        );
    }

    #[test]
    fn phrases_decode_only_the_two_supported_escapes() {
        let expression = format!("\"alpha \\\"beta\\\" {}\"", "\\\\");
        assert_eq!(
            parse_query(&expression).unwrap().root,
            Expr::Phrase(vec!["alpha".to_owned(), "beta".to_owned()])
        );
        assert_eq!(
            parse_query("\"AND\"").unwrap().root,
            Expr::Phrase(vec!["and".to_owned()])
        );
        assert_eq!(
            parse_query("and").unwrap().root,
            Expr::Term("and".to_owned())
        );
        assert_eq!(
            parse_query("AND,").unwrap().root,
            Expr::Term("and".to_owned())
        );
    }

    #[test]
    fn reports_syntax_errors_before_analyzer_limits() {
        assert_eq!(
            parse_query("OR \"bad\\q\"").unwrap_err(),
            QueryError::InvalidEscape
        );
        assert_eq!(parse_query("OR").unwrap_err(), QueryError::MissingOperand);
        assert_eq!(
            parse_query("alpha OR").unwrap_err(),
            QueryError::MissingOperand
        );
        assert_eq!(
            parse_query("NOT alpha").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("alpha:title").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("(alpha)").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("alpha*").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("alpha?").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("alpha~").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("alpha NEAR/3 beta").unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query("\"field").unwrap_err(),
            QueryError::UnterminatedPhrase
        );
        assert_eq!(
            parse_query("\"field\\").unwrap_err(),
            QueryError::InvalidEscape
        );
        let long_token = "x".repeat(MAX_TERM_SCALARS + 1);
        assert_eq!(
            parse_query(&format!("alpha OR {long_token}:")).unwrap_err(),
            QueryError::UnsupportedSyntax
        );
        assert_eq!(
            parse_query(&format!("OR {long_token}")).unwrap_err(),
            QueryError::MissingOperand
        );
        assert_eq!(
            parse_query(&format!("alpha OR {long_token}")).unwrap_err(),
            QueryError::TokenTooLong { scalars: 65 }
        );
    }

    #[test]
    fn zero_token_operands_cannot_erase_or_overwrite_explicit_operators() {
        for expression in [
            "Rust OR !!! AND absent",
            "Rust AND !!! OR absent",
            "alpha AND !!! OR beta",
            "!!! OR alpha",
            "!!! AND alpha",
            "alpha OR !!!",
            "alpha AND !!!",
        ] {
            assert_eq!(
                parse_query(expression).unwrap_err(),
                QueryError::MissingOperand,
                "{expression:?}"
            );
        }

        let long_token = "a".repeat(MAX_TERM_SCALARS + 1);
        assert_eq!(
            parse_query(&format!("!!! OR {long_token}")).unwrap_err(),
            QueryError::MissingOperand
        );
    }

    #[test]
    fn enforces_query_phrase_and_token_limits() {
        let at_byte_limit = format!("{}alpha", " ".repeat(MAX_QUERY_BYTES - 5));
        assert_eq!(at_byte_limit.len(), MAX_QUERY_BYTES);
        assert_eq!(
            parse_query(&at_byte_limit).unwrap().root,
            Expr::Term("alpha".to_owned())
        );
        let over_byte_limit = format!("{}\"bad\\q\"", " ".repeat(MAX_QUERY_BYTES));
        assert_eq!(
            parse_query(&over_byte_limit).unwrap_err(),
            QueryError::QueryTooLong {
                bytes: over_byte_limit.len()
            }
        );
        let multibyte_at_limit = format!("{} alpha  ", "🙂".repeat(1022));
        assert_eq!(multibyte_at_limit.len(), MAX_QUERY_BYTES);
        assert_eq!(
            parse_query(&multibyte_at_limit).unwrap().root,
            Expr::Term("alpha".to_owned())
        );
        let multibyte_over_limit = format!("{} alpha", "🙂".repeat(1023));
        assert_eq!(
            parse_query(&multibyte_over_limit).unwrap_err(),
            QueryError::QueryTooLong {
                bytes: multibyte_over_limit.len()
            }
        );
        let at_limit = vec!["a"; 64].join(" ");
        assert!(parse_query(&at_limit).is_ok());
        let too_many_terms = vec!["a"; 65].join(" ");
        assert_eq!(
            parse_query(&too_many_terms).unwrap_err(),
            QueryError::TooManyTerms { occurrences: 65 }
        );
        let phrase = (0..17).map(|_| "a").collect::<Vec<_>>().join(" ");
        let at_phrase_limit = (0..16).map(|_| "a").collect::<Vec<_>>().join(" ");
        assert!(parse_query(&format!("\"{at_phrase_limit}\"")).is_ok());
        assert_eq!(
            parse_query(&format!("\"{phrase}\"")).unwrap_err(),
            QueryError::PhraseTooLong { tokens: 17 }
        );
        assert_eq!(
            parse_query(&"a".repeat(MAX_TERM_SCALARS + 1)).unwrap_err(),
            QueryError::TokenTooLong { scalars: 65 }
        );
        assert!(parse_query(&"a".repeat(MAX_TERM_SCALARS)).is_ok());
        assert_eq!(parse_query("!!!").unwrap_err(), QueryError::NoSearchTerms);
        assert_eq!(parse_query("\"!!!\"").unwrap_err(), QueryError::EmptyPhrase);
        assert_eq!(parse_query("  ").unwrap_err(), QueryError::EmptyQuery);
    }

    #[test]
    fn counts_duplicates_and_phrase_tokens_before_score_deduplication() {
        let query = parse_query("alpha alpha \"beta beta\"").unwrap();
        assert_eq!(query.score_terms, ["alpha", "beta"]);
        assert_eq!(
            query.root,
            Expr::And(vec![
                Expr::Term("alpha".to_owned()),
                Expr::Term("alpha".to_owned()),
                Expr::Phrase(vec!["beta".to_owned(), "beta".to_owned()]),
            ])
        );
    }
}
