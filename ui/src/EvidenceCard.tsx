import { useEffect, useRef, useState } from "react";
import {
  inspectDocumentPage,
  messageForQuestionError,
  QuestionApiError,
  resolveEvidence,
  safeResultUrl,
} from "./api";
import type { DocumentInspectionState, EvidenceHit, RevalidationState } from "./types";

export function EvidenceCard({ hit }: { hit: EvidenceHit }) {
  const [revalidation, setRevalidation] = useState<RevalidationState>({ kind: "idle" });
  const [inspection, setInspection] = useState<DocumentInspectionState>({ kind: "closed" });
  const controller = useRef<AbortController | null>(null);
  const inspectionController = useRef<AbortController | null>(null);
  const requestedHref = safeResultUrl(hit.requested_url);
  const effectiveHref = safeResultUrl(hit.effective_url);

  useEffect(() => () => {
    controller.current?.abort();
    inspectionController.current?.abort();
  }, []);

  async function revalidate() {
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
      setRevalidation({ kind: "error", code, message: error instanceof QuestionApiError ? error.message : messageForQuestionError(code) });
    }
  }

  async function loadInspectionPage(offsetByte: number, previousText: string, previousTotal?: number) {
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
      setInspection({ kind: "error", code, message: error instanceof QuestionApiError ? error.message : messageForQuestionError(code) });
    }
  }

  const passageText = revalidation.kind === "current"
    ? revalidation.evidence.text
    : revalidation.kind === "idle"
      ? hit.passage.text
      : null;
  const passageState = revalidation.kind === "current"
    ? "Resolved from current index state for this request"
    : revalidation.kind === "loading"
      ? "Checking current index state"
      : revalidation.kind === "error"
        ? "Revalidation failed · prior text hidden"
        : "Retrieved text · not revalidated";

  return (
    <article className="result-card evidence-card">
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

      {inspection.kind === "closed" && (
        <>
          <div className="passage-heading">
            <strong>Extracted passage</strong>
            <span>{passageState}</span>
          </div>
          {passageText !== null
            ? <p className="evidence-passage">{passageText}</p>
            : <p className="verification-message" role="alert">{revalidation.kind === "error" ? revalidation.message : "Passage text is unavailable."}</p>}
        </>
      )}

      {inspection.kind === "loading" && (
        <p className="verification-message" role="status">Checking current indexed text. Previously retrieved text is hidden.</p>
      )}
      {inspection.kind === "error" && (
        <p className="verification-message" role="alert">{inspection.message} <span className="error-code">{inspection.code}</span></p>
      )}
      {inspection.kind === "ready" && (
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
          <pre className="indexed-document-text" tabIndex={0} aria-label="Current indexed extracted text">{inspection.text}</pre>
          <p className="inspection-note">This is plain extracted text from the local index, not source HTML or a verified answer. The identity address may not be publicly reachable.</p>
        </section>
      )}

      <div className="evidence-matches">
        {hit.matched_terms.length > 0 && <p><strong>Matched terms:</strong> {hit.matched_terms.join(", ")}</p>}
        {hit.matched_phrases.length > 0 && <p><strong>Matched phrases:</strong> {hit.matched_phrases.map((phrase) => `“${phrase.join(" ")}”`).join(" · ")}</p>}
      </div>
      <div className="evidence-actions">
        {inspection.kind === "closed" && (
          <>
            <button type="button" onClick={() => loadInspectionPage(0, "")}>Read current indexed text</button>
            <button type="button" onClick={revalidate} disabled={revalidation.kind === "loading"}>
              {revalidation.kind === "loading" ? "Checking passage…" : "Revalidate passage"}
            </button>
            {revalidation.kind === "error" && <span className="error-code">{revalidation.code}</span>}
          </>
        )}
        {inspection.kind === "loading" && <button type="button" disabled>Checking indexed text…</button>}
        {inspection.kind === "error" && (
          <button type="button" onClick={() => loadInspectionPage(0, "")}>Retry indexed text</button>
        )}
        {inspection.kind === "ready" && (
          <>
            <button type="button" onClick={() => loadInspectionPage(0, "")}>Revalidate indexed text</button>
            {inspection.page.next_offset_byte !== null && (
              <button
                type="button"
                onClick={() => loadInspectionPage(inspection.page.next_offset_byte!, inspection.text, inspection.page.total_bytes)}
              >Load next part</button>
            )}
          </>
        )}
        <details className="explanation">
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
        </details>
      </div>
    </article>
  );
}

function hex(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
