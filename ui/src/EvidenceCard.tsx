import { useEffect, useRef, useState } from "react";
import {
  inspectDocumentPage,
  messageForQuestionError,
  QuestionApiError,
  resolveEvidence,
  safeResultUrl,
} from "./api";
import type {
  DocumentInspectionState,
  EvidenceHit,
  RevalidationState,
  SourceAttribution,
  SourceAttributionState,
} from "./types";

const terminalEvidenceErrorCodes = new Set([
  "malformed_reference",
  "wrong_store",
  "not_live",
  "revoked",
  "version_superseded",
  "public_collection_expired",
]);

export function EvidenceCard({
  hit,
  sourceState,
  onRetrySource,
}: {
  hit: EvidenceHit;
  sourceState: SourceAttributionState;
  onRetrySource: () => void;
}) {
  const [revalidation, setRevalidation] = useState<RevalidationState>({ kind: "idle" });
  const [inspection, setInspection] = useState<DocumentInspectionState>({ kind: "closed" });
  const [sourceExpired, setSourceExpired] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const inspectionController = useRef<AbortController | null>(null);
  const requestedHref = safeResultUrl(hit.requested_url);
  const effectiveHref = safeResultUrl(hit.effective_url);
  const hasSourceNotice = sourceState.kind === "ready" && sourceState.source.kind === "operator_source";
  const referenceInvalidated = (revalidation.kind === "error" && terminalEvidenceErrorCodes.has(revalidation.code))
    || (inspection.kind === "error" && terminalEvidenceErrorCodes.has(inspection.code));
  const terminalErrorMessage = revalidation.kind === "error" && terminalEvidenceErrorCodes.has(revalidation.code)
    ? messageForInvalidatedEvidence(revalidation.code, hasSourceNotice)
    : inspection.kind === "error" && terminalEvidenceErrorCodes.has(inspection.code)
      ? messageForInvalidatedEvidence(inspection.code, hasSourceNotice)
      : sourceState.kind === "error" && terminalEvidenceErrorCodes.has(sourceState.code)
        ? sourceState.message
        : null;
  const hiddenSourceMessage = terminalErrorMessage
    ?? (sourceExpired
      ? messageForInvalidatedEvidence("public_collection_expired", true)
      : sourceState.kind === "ready" && sourceState.source.kind === "attribution_withheld"
        ? "Source attribution is withheld. Source details and extracted text remain hidden."
        : "Current source disclosure could not be checked, so source details and extracted text remain hidden.");
  const sourceVisible = sourceState.kind === "ready"
    && sourceState.source.kind !== "attribution_withheld"
    && !sourceExpired
    && !referenceInvalidated;

  useEffect(() => () => {
    controller.current?.abort();
    inspectionController.current?.abort();
  }, []);

  useEffect(() => {
    if (sourceState.kind !== "ready" || sourceState.source.kind !== "operator_source") return;
    const deadline = sourceState.source.visible_until_ms;
    let timer: number | undefined;
    const scheduleExpiry = () => {
      window.clearTimeout(timer);
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        controller.current?.abort();
        inspectionController.current?.abort();
        setInspection({ kind: "closed" });
        setRevalidation({
          kind: "error",
          code: "public_collection_expired",
          message: messageForInvalidatedEvidence("public_collection_expired", true),
        });
        setSourceExpired(true);
        return;
      }
      timer = window.setTimeout(scheduleExpiry, Math.min(remaining, 2_147_000_000));
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") scheduleExpiry();
    };
    scheduleExpiry();
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [sourceState]);

  async function revalidate() {
    if (!sourceVisible) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setRevalidation({ kind: "loading" });
    try {
      const evidence = await resolveEvidence(hit.passage.reference, current.signal);
      if (!current.signal.aborted) setRevalidation({ kind: "current", evidence });
    } catch (error) {
      if (current.signal.aborted) return;
      const code = error instanceof QuestionApiError ? error.code : "storage_fault";
      if (terminalEvidenceErrorCodes.has(code)) {
        inspectionController.current?.abort();
        setInspection({ kind: "closed" });
      }
      setRevalidation({
        kind: "error",
        code,
        message: terminalEvidenceErrorCodes.has(code)
          ? messageForInvalidatedEvidence(code, hasSourceNotice)
          : error instanceof QuestionApiError ? error.message : messageForQuestionError(code),
      });
    }
  }

  async function loadInspectionPage(offsetByte: number, previousText: string, previousTotal?: number) {
    if (!sourceVisible) return;
    inspectionController.current?.abort();
    const current = new AbortController();
    inspectionController.current = current;
    setInspection({ kind: "loading" });
    try {
      const page = await inspectDocumentPage(hit.passage.reference, offsetByte, current.signal);
      const previousBytes = new TextEncoder().encode(previousText).byteLength;
      const pageBytes = new TextEncoder().encode(page.text).byteLength;
      if (
        page.start_byte !== offsetByte ||
        page.total_bytes !== (previousTotal ?? page.total_bytes) ||
        previousBytes !== offsetByte ||
        previousBytes + pageBytes !== page.end_byte
      ) {
        throw new QuestionApiError("invalid_response", "Ley returned indexed text with inconsistent byte offsets.");
      }
      if (!current.signal.aborted) {
        setInspection({ kind: "ready", page, text: previousText + page.text });
      }
    } catch (error) {
      if (current.signal.aborted) return;
      const code = error instanceof QuestionApiError ? error.code : "storage_fault";
      if (terminalEvidenceErrorCodes.has(code)) controller.current?.abort();
      setInspection({
        kind: "error",
        code,
        message: terminalEvidenceErrorCodes.has(code)
          ? messageForInvalidatedEvidence(code, hasSourceNotice)
          : error instanceof QuestionApiError ? error.message : messageForQuestionError(code),
      });
    }
  }

  const passageText = !sourceVisible
    ? null
    : revalidation.kind === "current"
    ? revalidation.evidence.text
    : revalidation.kind === "idle"
      ? hit.passage.text
      : null;
  const passageState = sourceExpired
      ? "Source visibility period ended · passage hidden"
      : sourceState.kind === "error"
        ? "Source disclosure unavailable · passage hidden"
        : sourceState.kind === "ready" && sourceState.source.kind === "attribution_withheld"
          ? "Source attribution withheld · passage hidden"
    : revalidation.kind === "loading"
      ? "Checking current index state"
      : revalidation.kind === "error"
        ? "Revalidation failed · prior text hidden"
        : revalidation.kind === "current"
          ? "Resolved from current index state for this request"
          : "Retrieved text · not revalidated";

  return (
    <article className="result-card evidence-card">
      {sourceVisible ? (
        <>
          <div className="evidence-topline">
            <div className="result-url-wrap">
              {requestedHref && <span className="url-mark" aria-hidden="true">↗</span>}
              {requestedHref ? (
                <a className="result-url" href={requestedHref} target="_blank" rel="noopener noreferrer" aria-label="Open external source address; this address is not checked against the indexed text">Open external address · {hit.requested_url}</a>
              ) : (
                <span className="result-url source-identity">Indexed identity: {hit.requested_url}</span>
              )}
            </div>
            <span className="candidate-label">Lexical candidate</span>
          </div>
          <h3 className="result-title">
            {requestedHref
              ? <a href={requestedHref} target="_blank" rel="noopener noreferrer">{hit.title || "Untitled document"}</a>
              : (hit.title || "Untitled document")}
          </h3>
          {hit.effective_url !== hit.requested_url && (
            <p className="effective-url">
              Effective identity: {effectiveHref
                ? <a href={effectiveHref} target="_blank" rel="noopener noreferrer" aria-label="Open effective external address; this address is not checked against the indexed text">Open external address · {hit.effective_url}</a>
                : <span className="source-identity">{hit.effective_url}</span>}
            </p>
          )}
        </>
      ) : sourceState.kind === "ready" && sourceState.source.kind === "attribution_withheld" && inspection.kind === "closed" ? (
        <p className="verification-message" role="status">{hiddenSourceMessage}</p>
      ) : null}

      {inspection.kind === "closed" && (
        <>
          <div className="passage-heading">
            <strong>Extracted passage</strong>
            <span>{passageState}</span>
          </div>
          {sourceState.kind === "ready" && sourceVisible && (
            <SourceAttributionView source={sourceState.source} />
          )}
          {sourceState.kind === "error" && (
            <div className="source-error" role="alert">
              <p>{sourceState.message} <span className="error-code">{sourceState.code}</span></p>
              {terminalEvidenceErrorCodes.has(sourceState.code)
                ? <p>Search again for current evidence; this reference cannot be checked again.</p>
                : <button type="button" onClick={onRetrySource}>Check source again</button>}
            </div>
          )}
          {passageText !== null
            ? <p className="evidence-passage">{passageText}</p>
            : sourceState.kind === "error" || sourceState.kind === "ready" && sourceState.source.kind === "attribution_withheld"
              ? null
              : <p className="verification-message" role="alert">{revalidation.kind === "error" ? revalidation.message : hiddenSourceMessage}</p>}
        </>
      )}

      {inspection.kind === "loading" && (
        <p className="verification-message" role="status">Checking current indexed text. Previously retrieved text is hidden.</p>
      )}
      {inspection.kind === "error" && (
        <p className="verification-message" role="alert">{inspection.message} <span className="error-code">{inspection.code}</span></p>
      )}
      {inspection.kind === "ready" && sourceVisible && (
        <section className="indexed-document" aria-label="Local indexed extracted text">
          <div className="passage-heading">
            <strong>Local indexed extracted text</strong>
            <span>Current version checked for each page · answer support not assessed</span>
          </div>
          <dl className="inspection-provenance">
            <div><dt>Document identity</dt><dd>{inspection.page.requested_url}</dd></div>
            {inspection.page.effective_url !== inspection.page.requested_url && (
              <div><dt>Effective identity</dt><dd>{inspection.page.effective_url}</dd></div>
            )}
            <div><dt>Indexed title</dt><dd>{inspection.page.title || "Untitled document"}</dd></div>
            <div><dt>Extracted body bytes</dt><dd>{new TextEncoder().encode(inspection.text).byteLength.toLocaleString()} of {inspection.page.total_bytes.toLocaleString()}</dd></div>
          </dl>
          {sourceState.kind === "ready" && sourceVisible && <SourceAttributionView source={sourceState.source} />}
          <pre className="indexed-document-text" tabIndex={0} aria-label="Current indexed extracted text">{inspection.text}</pre>
          <p className="inspection-note">This is plain extracted text from the local index, not source HTML or a verified answer. The identity address may not be publicly reachable.</p>
        </section>
      )}

      {inspection.kind === "ready" && !sourceVisible && (
        <p className="verification-message" role="alert">{hiddenSourceMessage} Previously loaded indexed text is hidden.</p>
      )}

      <div className="evidence-matches">
        {sourceVisible && hit.matched_terms.length > 0 && <p><strong>Matched terms:</strong> {hit.matched_terms.join(", ")}</p>}
        {sourceVisible && hit.matched_phrases.length > 0 && <p><strong>Matched phrases:</strong> {hit.matched_phrases.map((phrase) => `“${phrase.join(" ")}”`).join(" · ")}</p>}
      </div>
      <div className="evidence-actions">
        {inspection.kind === "closed" && (
          <>
            <button type="button" onClick={() => loadInspectionPage(0, "")} disabled={!sourceVisible}>Read current indexed text</button>
            <button type="button" onClick={revalidate} disabled={!sourceVisible || revalidation.kind === "loading"}>
              {revalidation.kind === "loading" ? "Checking passage…" : "Revalidate passage"}
            </button>
            {revalidation.kind === "error" && <span className="error-code">{revalidation.code}</span>}
          </>
        )}
        {inspection.kind === "loading" && <button type="button" disabled>Checking indexed text…</button>}
        {inspection.kind === "error" && (
          <button type="button" onClick={() => loadInspectionPage(0, "")} disabled={!sourceVisible}>Retry indexed text</button>
        )}
        {inspection.kind === "ready" && (
          <>
            <button type="button" onClick={() => loadInspectionPage(0, "")} disabled={!sourceVisible}>Revalidate indexed text</button>
            {inspection.page.next_offset_byte !== null && (
              <button
                type="button"
                disabled={!sourceVisible}
                onClick={() => loadInspectionPage(inspection.page.next_offset_byte!, inspection.text, inspection.page.total_bytes)}
              >Load next part</button>
            )}
          </>
        )}
        {sourceVisible && <details className="explanation">
          <summary>Evidence reference</summary>
          <div className="reference-details">
            <dl>
              <div><dt>Store ID</dt><dd>{hex(hit.passage.reference.store_id)}</dd></div>
              <div><dt>Document</dt><dd>{hit.requested_url}</dd></div>
              <div><dt>Content version</dt><dd>{hex(hit.passage.reference.content_version)}</dd></div>
              <div><dt>Passage schema</dt><dd>{hit.passage.reference.passage_schema_version}</dd></div>
              <div><dt>Extracted body UTF-8 bytes</dt><dd>{hit.passage.reference.start_byte}–{hit.passage.reference.end_byte}</dd></div>
              <div><dt>Public identity checksum</dt><dd>{hex(hit.passage.reference.identity_sha256)}</dd></div>
            </dl>
            <p>The identity checksum is a public consistency check, not proof of authenticity. Answer support is not assessed.</p>
          </div>
        </details>}
      </div>
    </article>
  );
}

function messageForInvalidatedEvidence(code: string, hasSourceNotice: boolean): string {
  const reasons: Record<string, string> = {
    malformed_reference: "This evidence reference is malformed.",
    wrong_store: "This evidence reference belongs to a different index.",
    not_live: "This source is no longer in the current index.",
    revoked: "This source has been revoked.",
    version_superseded: "This passage belongs to an older source version.",
    public_collection_expired: "This collection has expired.",
  };
  const hiddenContent = hasSourceNotice ? "passage and source notice are" : "evidence text is";
  return `${reasons[code] ?? "This evidence reference is no longer current."} Previously displayed ${hiddenContent} hidden.`;
}

function SourceAttributionView({ source }: { source: SourceAttribution }) {
  if (source.kind === "local_index") {
    return <p>This document is in the local index. No public-source attribution is recorded.</p>;
  }
  if (source.kind === "attribution_withheld") {
    return <p>A current source record exists, but its attribution is unavailable.</p>;
  }
  return (
    <div className="source-attribution">
      <dl className="inspection-provenance">
        <div><dt>Source record</dt><dd>{source.source_id}</dd></div>
        <div><dt>Origin</dt><dd>{source.origin}</dd></div>
        <div><dt>License or terms label</dt><dd>{source.license_label}</dd></div>
        <div><dt>Source version</dt><dd>{source.source_version}</dd></div>
        <div><dt>Installed</dt><dd>{formatTimestamp(source.installed_at_ms)}</dd></div>
        <div><dt>Visible until</dt><dd>{formatTimestamp(source.visible_until_ms)}</dd></div>
        {source.display_permission_reviewed_at_ms !== undefined && (
          <div><dt>Display review recorded</dt><dd>{formatTimestamp(source.display_permission_reviewed_at_ms)}</dd></div>
        )}
        <div><dt>Retained notice SHA-256</dt><dd>{source.notice_sha256}</dd></div>
      </dl>
      <p className="source-attribution-caveat">These source permissions are operator declarations, not legal certification. A notice alone does not prove rights to fetch, store, index, or display the content.</p>
      <h4>Verified retained notice · plain text</h4>
      <pre className="source-notice-text" tabIndex={0}>{source.notice_text}</pre>
    </div>
  );
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Invalid timestamp" : date.toISOString();
}

function hex(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
