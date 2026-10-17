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

export type SearchState =
  | { kind: "idle" }
  | { kind: "loading"; query: string }
  | { kind: "ready"; response: SearchResponse }
  | { kind: "error"; query: string; message: string };
