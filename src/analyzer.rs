use icu_casemap::CaseMapper;
use icu_normalizer::ComposingNormalizer;
use icu_properties::{CodePointMapData, CodePointSetData, props};
use unicode_segmentation::UnicodeSegmentation;

pub const ANALYZER_ID: &str = "ley-text-v1";
pub const MAX_TERM_SCALARS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalyzeError {
    TermTooLong { scalars: usize },
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TermTooLong { scalars } => write!(
                formatter,
                "analyzed term has {scalars} Unicode scalar values; maximum is {MAX_TERM_SCALARS}"
            ),
        }
    }
}

impl std::error::Error for AnalyzeError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct Analyzer;

impl Analyzer {
    pub fn analyze(&self, input: &str) -> Result<Vec<String>, AnalyzeError> {
        let normalized = ComposingNormalizer::new_nfkc().normalize(input);
        let folded = CaseMapper::new().fold_string(&normalized);
        let alphabetic = CodePointSetData::new::<props::Alphabetic>();
        let decimal = CodePointMapData::<props::GeneralCategory>::new();
        let mut terms = Vec::new();

        for segment in folded.split_word_bounds() {
            if !segment.chars().any(|ch| {
                alphabetic.contains(ch) || decimal.get(ch) == props::GeneralCategory::DecimalNumber
            }) {
                continue;
            }
            let scalars = segment.chars().count();
            if scalars > MAX_TERM_SCALARS {
                return Err(AnalyzeError::TermTooLong { scalars });
            }
            terms.push(segment.to_owned());
        }
        Ok(terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_nfkc_full_default_folding_and_word_boundaries() {
        let analyzer = Analyzer;
        assert_eq!(analyzer.analyze("Straße").unwrap(), ["strasse"]);
        assert_eq!(analyzer.analyze("ＦＯＯ").unwrap(), ["foo"]);
        assert_eq!(
            analyzer.analyze("café cafe\u{301}").unwrap(),
            ["café", "café"]
        );
        assert_eq!(
            analyzer.analyze("alpha-beta 2001:db8").unwrap(),
            ["alpha", "beta", "2001", "db8"]
        );
        assert_eq!(analyzer.analyze("!!!").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn uses_unicode_17_case_folding_and_properties() {
        let analyzer = Analyzer;
        assert_eq!(analyzer.analyze("\u{A7CE}").unwrap(), ["\u{A7CF}"]);
        assert_eq!(analyzer.analyze("\u{088F}").unwrap(), ["\u{088F}"]);
    }

    #[test]
    fn rejects_overlong_terms_instead_of_truncating() {
        let input = "a".repeat(MAX_TERM_SCALARS + 1);
        assert!(matches!(
            Analyzer.analyze(&input),
            Err(AnalyzeError::TermTooLong { scalars: 65 })
        ));
    }
}
