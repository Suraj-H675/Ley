export type MatchSummary =
  | { kind: "term"; term: string; titleOccurrences: number; bodyOccurrences: number }
  | { kind: "phrase"; terms: string[]; titleOccurrences: number; bodyOccurrences: number }
  | { kind: "and" | "or"; children: MatchSummary[] };

export interface FieldExplanation {
  termFrequency: number;
  documentFrequency: number;
  documentLength: number;
  averageLength: number;
  idf: number;
  weight: number;
  contribution: number;
}

export interface TermExplanation {
  term: string;
  title: FieldExplanation;
  body: FieldExplanation;
}

export interface SearchExplanation {
  normalizedTerms: string[];
  documentCount: number;
  averageTitleLength: number;
  averageBodyLength: number;
  statisticsSource: { kind: string; generation: number | null };
  terms: TermExplanation[];
  totalScore: number;
}

export interface SearchHit {
  id: string;
  versionId: string;
  title: string;
  snippet: string;
  score: number;
  matched: MatchSummary;
  explanation: SearchExplanation;
}

export interface SearchResponse {
  query: string;
  generation: number;
  corpusSize: number;
  totalResults: number;
  truncated: boolean;
  results: SearchHit[];
}

export type InsufficientEvidenceReason =
  | "no_searchable_terms"
  | "only_title_matches"
  | "work_budget_reached";

export type RetrievalStatus =
  | "retrieved_text"
  | "no_relevant_text_match"
  | { insufficient_evidence: InsufficientEvidenceReason };

export interface EvidenceReference {
  store_id: number[];
  requested_url: string;
  content_version: number[];
  passage_schema_version: number;
  start_byte: number;
  end_byte: number;
  identity_sha256: number[];
}

export interface EvidenceHit {
  requested_url: string;
  effective_url: string;
  title: string;
  score: number;
  matched_terms: string[];
  matched_phrases: string[][];
  passage: { reference: EvidenceReference; text: string };
}

export interface RetrievalResponse {
  contract_version: number;
  mode: "question";
  generation_id: number;
  status: RetrievalStatus;
  completeness: "complete" | "partial";
  normalized_terms: string[];
  hits: EvidenceHit[];
  answer_assessment: "not_assessed";
}

export interface ResolvedEvidence {
  reference: EvidenceReference;
  requested_url: string;
  effective_url: string;
  title: string;
  text: string;
}

export type QuestionSearchState =
  | { kind: "idle" }
  | { kind: "loading"; question: string }
  | { kind: "ready"; question: string; response: RetrievalResponse }
  | { kind: "error"; question: string; code: string; message: string };

export type RevalidationState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "current"; evidence: ResolvedEvidence }
  | { kind: "error"; code: string; message: string };

export type SearchState =
  | { kind: "idle" }
  | { kind: "loading"; query: string }
  | { kind: "ready"; response: SearchResponse }
  | { kind: "error"; query: string; message: string };
