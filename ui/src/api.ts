import type {
  FieldExplanation,
  MatchSummary,
  SearchExplanation,
  SearchHit,
  SearchResponse,
  TermExplanation,
} from "./types";

const API_RESULT_LIMIT = 20;

export class SearchApiError extends Error {}

export async function searchLey(query: string, signal: AbortSignal): Promise<SearchResponse> {
  let response: Response;
  try {
    response = await fetch(`/api/search?q=${encodeURIComponent(query)}`, {
      headers: { Accept: "application/json" },
      signal,
    });
  } catch {
    throw new SearchApiError("Ley could not be reached. Check that the local API is running.");
  }

  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : "";
    if (response.status === 400 || code === "invalid_query") {
      throw new SearchApiError("That query is not valid. Try a term or a quoted phrase.");
    }
    if (response.status === 413 || response.status === 422) {
      throw new SearchApiError("That search is larger than Ley's current response limit.");
    }
    throw new SearchApiError("Ley could not complete the search. Try again in a moment.");
  }
  if (!isSearchResponse(payload)) {
    throw new SearchApiError("Ley returned a response the interface could not read.");
  }
  return payload;
}

export function safeResultUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}

function isSearchResponse(value: unknown): value is SearchResponse {
  return (
    isRecord(value) &&
    typeof value.query === "string" &&
    isCount(value.generation) &&
    isCount(value.corpusSize) &&
    isCount(value.totalResults) &&
    typeof value.truncated === "boolean" &&
    Array.isArray(value.results) &&
    value.results.length <= API_RESULT_LIMIT &&
    value.results.every(isSearchHit)
  );
}

function isSearchHit(value: unknown): value is SearchHit {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    value.id.length <= 2048 &&
    typeof value.versionId === "string" &&
    value.versionId.length <= 128 &&
    typeof value.title === "string" &&
    typeof value.snippet === "string" &&
    isFiniteNumber(value.score) &&
    isMatchSummary(value.matched) &&
    isExplanation(value.explanation)
  );
}

function isMatchSummary(value: unknown): value is MatchSummary {
  if (!isRecord(value) || typeof value.kind !== "string") return false;
  if (value.kind === "term") {
    return typeof value.term === "string" && isCount(value.titleOccurrences) && isCount(value.bodyOccurrences);
  }
  if (value.kind === "phrase") {
    return (
      isStringArray(value.terms) &&
      isCount(value.titleOccurrences) &&
      isCount(value.bodyOccurrences)
    );
  }
  return (
    (value.kind === "and" || value.kind === "or") &&
    Array.isArray(value.children) &&
    value.children.length <= 64 &&
    value.children.every(isMatchSummary)
  );
}

function isExplanation(value: unknown): value is SearchExplanation {
  return (
    isRecord(value) &&
    isStringArray(value.normalizedTerms) &&
    value.normalizedTerms.length <= 64 &&
    isCount(value.documentCount) &&
    isFiniteNumber(value.averageTitleLength) &&
    isFiniteNumber(value.averageBodyLength) &&
    isRecord(value.statisticsSource) &&
    typeof value.statisticsSource.kind === "string" &&
    (value.statisticsSource.generation === null || isCount(value.statisticsSource.generation)) &&
    Array.isArray(value.terms) &&
    value.terms.length <= 64 &&
    value.terms.every(isTermExplanation) &&
    isFiniteNumber(value.totalScore)
  );
}

function isTermExplanation(value: unknown): value is TermExplanation {
  return (
    isRecord(value) &&
    typeof value.term === "string" &&
    isFieldExplanation(value.title) &&
    isFieldExplanation(value.body)
  );
}

function isFieldExplanation(value: unknown): value is FieldExplanation {
  return (
    isRecord(value) &&
    isCount(value.termFrequency) &&
    isCount(value.documentFrequency) &&
    isCount(value.documentLength) &&
    isFiniteNumber(value.averageLength) &&
    isFiniteNumber(value.idf) &&
    isFiniteNumber(value.weight) &&
    isFiniteNumber(value.contribution)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 64 && value.every((item) => typeof item === "string");
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value >= 0;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
