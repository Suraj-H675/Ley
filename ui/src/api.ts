import type {
  EvidenceHit,
  EvidenceReference,
  DocumentInspectionPage,
  FieldExplanation,
  MatchSummary,
  ResolvedEvidence,
  RetrievalResponse,
  RetrievalStatus,
  SearchExplanation,
  SearchHit,
  SearchResponse,
  SiteWorkspaceStatus,
  TermExplanation,
  SourceTransparencyResponse,
} from "./types";

const API_RESULT_LIMIT = 20;
const QUESTION_RESULT_LIMIT = 8;
const MAX_PASSAGE_BYTES = 8192;
const MAX_DOCUMENT_INSPECTION_PAGE_BYTES = 64 * 1024;
const MAX_INDEXED_BODY_BYTES = 1024 * 1024;
const MAX_PUBLIC_NOTICE_BYTES = 16 * 1024;

export class SearchApiError extends Error {}

export class QuestionApiError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

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

export async function retrieveQuestion(question: string, signal: AbortSignal): Promise<RetrievalResponse> {
  const payload = await typedPost("/api/v1/retrieve", {
    mode: "question",
    request: { contract_version: 1, question, max_hits: QUESTION_RESULT_LIMIT },
  }, signal);
  if (!isRetrievalResponse(payload)) {
    throw new QuestionApiError("invalid_response", "Ley returned a response the interface could not read.");
  }
  return payload;
}

export async function resolveEvidence(
  reference: EvidenceReference,
  signal: AbortSignal,
): Promise<ResolvedEvidence> {
  const payload = await typedPost("/api/v1/evidence/resolve", reference, signal);
  if (!isResolvedEvidence(payload) || !sameReference(payload.reference, reference) || payload.requested_url !== reference.requested_url) {
    throw new QuestionApiError("invalid_response", "Ley returned evidence the interface could not read.");
  }
  return payload;
}

export async function inspectDocumentPage(
  reference: EvidenceReference,
  offsetByte: number,
  signal: AbortSignal,
): Promise<DocumentInspectionPage> {
  if (!Number.isSafeInteger(offsetByte) || offsetByte < 0) {
    throw new QuestionApiError("invalid_request", messageForQuestionError("invalid_request"));
  }
  const payload = await typedPost("/api/v1/evidence/inspect", {
    contract_version: 1,
    reference,
    offset_byte: offsetByte,
  }, signal);
  if (!isDocumentInspectionPage(payload, reference, offsetByte)) {
    throw new QuestionApiError("invalid_response", "Ley returned indexed text the interface could not read.");
  }
  return payload;
}

export async function getSourceTransparency(
  reference: EvidenceReference,
  signal: AbortSignal,
): Promise<SourceTransparencyResponse> {
  const payload = await typedPost("/api/v1/evidence/source", {
    contract_version: 1,
    reference,
  }, signal);
  if (!isSourceTransparencyResponse(payload, reference)) {
    throw new QuestionApiError("invalid_response", "Ley returned source attribution the interface could not read.");
  }
  return payload;
}

export async function getWorkspaceStatus(signal: AbortSignal): Promise<SiteWorkspaceStatus | null> {
  let response: Response;
  try {
    response = await fetch("/api/v1/workspace/status", {
      headers: { Accept: "application/json" },
      cache: "no-store",
      signal,
    });
  } catch {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    throw new QuestionApiError("workspace_status_unavailable", "Ley could not read the selected site workspace status.");
  }

  const payload: unknown = await response.json().catch(() => null);
  if (response.status === 404) return null;
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : "workspace_status_unavailable";
    throw new QuestionApiError(code, "Ley could not read the selected site workspace status. Check its policy binding and local store.");
  }
  if (!isSiteWorkspaceStatus(payload)) {
    throw new QuestionApiError("invalid_workspace_status", "Ley returned workspace status the interface could not read.");
  }
  return payload;
}

async function typedPost(path: string, body: unknown, signal: AbortSignal): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    throw new QuestionApiError("index_api_unavailable", "Ley could not be reached. Check that the local API is running.");
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.error === "string" ? payload.error : "storage_fault";
    throw new QuestionApiError(code, messageForQuestionError(code));
  }
  return payload;
}

export function messageForQuestionError(code: string): string {
  const messages: Record<string, string> = {
    invalid_request: "That request is not valid. Check the question or evidence reference and try again.",
    unsupported_contract: "This Ley server does not support that retrieval or evidence contract version.",
    malformed_reference: "This evidence reference is malformed. No passage text was shown.",
    wrong_store: "This evidence reference belongs to a different index. No passage text was shown.",
    not_live: "This source is no longer in the current index. No passage text was shown.",
    revoked: "This source has been revoked. No passage text was shown.",
    version_superseded: "This passage belongs to an older source version. No passage text was shown.",
    public_collection_expired: "This collection has expired. No passage text was shown.",
    resource_cap: "Ley stopped this request at its configured resource limit.",
    storage_fault: "Ley could not read the current index. Check the local store and try again.",
    unsupported_media_type: "Ley rejected the request media type.",
    not_acceptable: "Ley could not return the requested response type.",
    invalid_origin: "The local server rejected this request origin.",
    invalid_host: "The local server rejected this request host.",
    index_api_unavailable: "Ley could not be reached. Check that the local API is running.",
  };
  return messages[code] ?? "Ley could not complete the request. Try again in a moment.";
}

export function safeResultUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
      return null;
    }
    const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
    const reservedDomains = [
      "invalid", "test", "example", "localhost", "local",
      "example.com", "example.net", "example.org",
    ];
    if (
      !hostname.includes(".") ||
      hostname.startsWith("[") ||
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
      reservedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))
    ) {
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

function isRetrievalResponse(value: unknown): value is RetrievalResponse {
  return (
    isRecord(value) && value.contract_version === 1 && value.mode === "question" &&
    isCount(value.generation_id) && isRetrievalStatus(value.status) &&
    (value.completeness === "complete" || value.completeness === "partial") &&
    isStringArray(value.normalized_terms) && value.normalized_terms.length <= 32 &&
    value.answer_assessment === "not_assessed" && Array.isArray(value.hits) &&
    value.hits.length <= QUESTION_RESULT_LIMIT && value.hits.every(isEvidenceHit)
  );
}

function isRetrievalStatus(value: unknown): value is RetrievalStatus {
  if (value === "retrieved_text" || value === "no_relevant_text_match") return true;
  if (!isRecord(value) || Object.keys(value).length !== 1 || typeof value.insufficient_evidence !== "string") return false;
  return ["no_searchable_terms", "only_title_matches", "work_budget_reached"].includes(value.insufficient_evidence);
}

function isEvidenceHit(value: unknown): value is EvidenceHit {
  return (
    isRecord(value) && typeof value.requested_url === "string" && value.requested_url.length <= 2048 &&
    typeof value.effective_url === "string" && value.effective_url.length <= 2048 &&
    typeof value.title === "string" && value.title.length <= 4096 && isFiniteNumber(value.score) &&
    isStringArray(value.matched_terms) && value.matched_terms.length <= 32 &&
    Array.isArray(value.matched_phrases) && value.matched_phrases.length <= 8 &&
    value.matched_phrases.every((phrase) => isStringArray(phrase) && phrase.length <= 16) &&
    isRecord(value.passage) && isReference(value.passage.reference) && value.passage.reference.requested_url === value.requested_url &&
    typeof value.passage.text === "string" && new TextEncoder().encode(value.passage.text).byteLength <= MAX_PASSAGE_BYTES &&
    byteLength(value.passage.text) === value.passage.reference.end_byte - value.passage.reference.start_byte
  );
}

function isResolvedEvidence(value: unknown): value is ResolvedEvidence {
  return (
    isRecord(value) && isReference(value.reference) &&
    typeof value.requested_url === "string" && value.requested_url.length <= 2048 &&
    typeof value.effective_url === "string" && value.effective_url.length <= 2048 &&
    typeof value.title === "string" && value.title.length <= 4096 &&
    typeof value.text === "string" && new TextEncoder().encode(value.text).byteLength <= MAX_PASSAGE_BYTES &&
    byteLength(value.text) === value.reference.end_byte - value.reference.start_byte
  );
}

function isDocumentInspectionPage(
  value: unknown,
  reference: EvidenceReference,
  requestedOffset: number,
): value is DocumentInspectionPage {
  if (
    !isRecord(value) || value.contract_version !== 1 || !isReference(value.reference) ||
    !sameReference(value.reference, reference) || value.requested_url !== reference.requested_url ||
    typeof value.effective_url !== "string" || value.effective_url.length > 2048 ||
    typeof value.title !== "string" || value.title.length > 4096 ||
    !isCount(value.start_byte) || value.start_byte !== requestedOffset ||
    !isCount(value.end_byte) || !isCount(value.total_bytes) || value.total_bytes === 0 ||
    value.total_bytes > MAX_INDEXED_BODY_BYTES || value.end_byte <= value.start_byte ||
    value.end_byte > value.total_bytes ||
    value.end_byte - value.start_byte > MAX_DOCUMENT_INSPECTION_PAGE_BYTES ||
    typeof value.text !== "string" ||
    new TextEncoder().encode(value.text).byteLength !== value.end_byte - value.start_byte
  ) {
    return false;
  }
  return value.next_offset_byte === null
    ? value.end_byte === value.total_bytes
    : isCount(value.next_offset_byte) &&
      value.next_offset_byte === value.end_byte &&
      value.end_byte < value.total_bytes;
}

function isSourceTransparencyResponse(
  value: unknown,
  reference: EvidenceReference,
): value is SourceTransparencyResponse {
  if (
    !isRecord(value) || value.contract_version !== 1 || !isReference(value.reference) ||
    !sameReference(value.reference, reference) || value.requested_url !== reference.requested_url ||
    typeof value.effective_url !== "string" || value.effective_url.length > 2048 ||
    !isRecord(value.source) || typeof value.source.kind !== "string"
  ) {
    return false;
  }
  const source = value.source;
  if (source.kind === "local_index" || source.kind === "attribution_withheld") {
    return hasExactKeys(source, ["kind"]);
  }
  return (
    hasExactKeys(
      source,
      ["kind", "policy_format", "source_id", "origin", "license_label", "source_version", "installed_at_ms", "visible_until_ms", "notice_sha256", "notice_text"],
      ["display_permission_reviewed_at_ms"],
    ) &&
    source.kind === "operator_source" &&
    (source.policy_format === "legacy_v1" || source.policy_format === "notice_bound_v2") &&
    isBoundedString(source.source_id, 128) && isBoundedString(source.origin, 2048) &&
    isBoundedString(source.license_label, 256) && isBoundedString(source.source_version, 256) &&
    isCount(source.installed_at_ms) && isCount(source.visible_until_ms) &&
    (source.display_permission_reviewed_at_ms === undefined || isCount(source.display_permission_reviewed_at_ms)) &&
    typeof source.notice_sha256 === "string" && /^[0-9a-f]{64}$/.test(source.notice_sha256) &&
    typeof source.notice_text === "string" && byteLength(source.notice_text) <= MAX_PUBLIC_NOTICE_BYTES
  );
}

function sameReference(left: EvidenceReference, right: EvidenceReference): boolean {
  return (
    left.store_id.every((value, index) => value === right.store_id[index]) &&
    left.requested_url === right.requested_url &&
    left.content_version.every((value, index) => value === right.content_version[index]) &&
    left.passage_schema_version === right.passage_schema_version &&
    left.start_byte === right.start_byte && left.end_byte === right.end_byte &&
    left.identity_sha256.every((value, index) => value === right.identity_sha256[index])
  );
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function isReference(value: unknown): value is EvidenceReference {
  return (
    isRecord(value) && isByteArray(value.store_id, 16) && typeof value.requested_url === "string" &&
    value.requested_url.length <= 2048 && isByteArray(value.content_version, 32) &&
    value.passage_schema_version === 1 && isCount(value.start_byte) && isCount(value.end_byte) &&
    value.end_byte > value.start_byte && isByteArray(value.identity_sha256, 32)
  );
}

function isByteArray(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.length === length && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255);
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

function isSiteWorkspaceStatus(value: unknown): value is SiteWorkspaceStatus {
  if (!isRecord(value) || !isRecord(value.source)) return false;
  const source = value.source;
  const budget = source.requestBudget;
  const permissions = source.permissions;
  const stateCounts = source.frontierStateCounts;
  return (
    hasExactKeys(value, ["schema", "backend", "readOnly", "source", "coverageDefinition"]) &&
    value.schema === "ley-site-http-status-v1" && value.backend === "controlled_crawler" && value.readOnly === true &&
    isBoundedString(value.coverageDefinition, 512) &&
    hasExactKeys(source, [
      "id", "origin", "allowedPathPrefixes", "seedUrls", "noticeSha256", "permissions", "expiresAtMs",
      "lifecycle", "policyExpired", "retentionExpired", "requestBudget", "frontierStateCounts", "dueWorkCount",
      "nextDueMs", "currentlyIndexedLiveUrls", "removedFrontierUrls", "pendingOutboxCount", "rejectedOutboxCount",
    ]) &&
    isBoundedString(source.id, 128) && isBoundedString(source.origin, 2048) &&
    isStringArray(source.allowedPathPrefixes) && isStringArray(source.seedUrls) &&
    typeof source.noticeSha256 === "string" && /^[0-9a-f]{64}$/.test(source.noticeSha256) &&
    isRecord(permissions) && hasExactKeys(permissions, ["fetchRecorded", "storageRecorded", "indexRecorded", "displayRecorded"]) &&
    typeof permissions.fetchRecorded === "boolean" && typeof permissions.storageRecorded === "boolean" &&
    typeof permissions.indexRecorded === "boolean" && typeof permissions.displayRecorded === "boolean" &&
    isCount(source.expiresAtMs) && isBoundedString(source.lifecycle, 32) &&
    typeof source.policyExpired === "boolean" && typeof source.retentionExpired === "boolean" &&
    isRecord(budget) && hasExactKeys(budget, [
      "persistentUsed", "persistentLimit", "persistentRemaining", "persistentCounterSemantics", "perInvocationCountersPersisted",
    ]) && isCount(budget.persistentUsed) && isCount(budget.persistentLimit) && isCount(budget.persistentRemaining) &&
    isBoundedString(budget.persistentCounterSemantics, 256) && typeof budget.perInvocationCountersPersisted === "boolean" &&
    isRecord(stateCounts) && Object.keys(stateCounts).length <= 16 && Object.values(stateCounts).every(isCount) &&
    isCount(source.dueWorkCount) && (source.nextDueMs === null || isCount(source.nextDueMs)) &&
    isCount(source.currentlyIndexedLiveUrls) && isCount(source.removedFrontierUrls) &&
    isCount(source.pendingOutboxCount) && isCount(source.rejectedOutboxCount)
  );
}

function hasExactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key));
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

function isBoundedString(value: unknown, maximumBytes: number): value is string {
  return typeof value === "string" && byteLength(value) <= maximumBytes;
}
