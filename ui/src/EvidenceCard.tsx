import { useEffect, useRef, useState } from "react";
import { messageForQuestionError, QuestionApiError, resolveEvidence, safeResultUrl } from "./api";
import type { EvidenceHit, RevalidationState } from "./types";

export function EvidenceCard({ hit }: { hit: EvidenceHit }) {
  const [revalidation, setRevalidation] = useState<RevalidationState>({ kind: "idle" });
  const controller = useRef<AbortController | null>(null);
  const requestedHref = safeResultUrl(hit.requested_url);
  const effectiveHref = safeResultUrl(hit.effective_url);

  useEffect(() => () => controller.current?.abort(), []);

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

  const passageText = revalidation.kind === "idle"
    ? hit.passage.text
    : revalidation.kind === "current"
      ? revalidation.evidence.text
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
          <span className="url-mark" aria-hidden="true">↗</span>
          {requestedHref ? (
            <a className="result-url" href={requestedHref} target="_blank" rel="noopener noreferrer">{hit.requested_url}</a>
          ) : (
            <span className="result-url unsafe-url">{hit.requested_url}</span>
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
          Effective URL: {effectiveHref
            ? <a href={effectiveHref} target="_blank" rel="noopener noreferrer">{hit.effective_url}</a>
            : <span className="unsafe-url">{hit.effective_url}</span>}
        </p>
      )}

      <div className="passage-heading">
        <strong>Extracted passage</strong>
        <span>{passageState}</span>
      </div>
      {passageText !== null
        ? <p className="evidence-passage">{passageText}</p>
        : revalidation.kind === "loading"
          ? <p className="verification-message" role="status">Checking the current index. Previously retrieved passage text is hidden.</p>
          : <p className="verification-message" role="alert">{revalidation.kind === "error" ? revalidation.message : "Passage text is unavailable."}</p>}

      <div className="evidence-matches">
        {hit.matched_terms.length > 0 && <p><strong>Matched terms:</strong> {hit.matched_terms.join(", ")}</p>}
        {hit.matched_phrases.length > 0 && <p><strong>Matched phrases:</strong> {hit.matched_phrases.map((phrase) => `“${phrase.join(" ")}”`).join(" · ")}</p>}
      </div>
      <div className="evidence-actions">
        <button type="button" onClick={revalidate} disabled={revalidation.kind === "loading"}>
          {revalidation.kind === "loading" ? "Checking…" : "Revalidate passage"}
        </button>
        {revalidation.kind === "error" && <span className="error-code">{revalidation.code}</span>}
        <details className="explanation">
          <summary>Provenance and reference</summary>
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
