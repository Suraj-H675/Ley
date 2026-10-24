import { useEffect, useRef, useState, type SyntheticEvent } from "react";
import {
  getSourceTransparency,
  inspectDocumentPage,
  messageForQuestionError,
  QuestionApiError,
  resolveEvidence,
  safeResultUrl,
} from "./api";
import type {
  DocumentInspectionState,
  EvidenceHit,
  EvidenceReference,
  RevalidationState,
  SourceAttribution,
} from "./types";

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
          <SourceDisclosure reference={hit.passage.reference} />
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

type SourceDisclosureState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; source: SourceAttribution }
  | { kind: "error"; code: string; message: string };

function SourceDisclosure({ reference }: { reference: EvidenceReference }) {
  const [state, setState] = useState<SourceDisclosureState>({ kind: "idle" });
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  useEffect(() => {
    if (state.kind !== "ready" || state.source.kind !== "operator_source") return;
    const deadline = state.source.visible_until_ms;
    let timer: number | undefined;
    const expireIfNeeded = () => {
      if (Date.now() < deadline) return false;
      controller.current?.abort();
      setState({
        kind: "error",
        code: "public_collection_expired",
        message: messageForSourceError("public_collection_expired"),
      });
      return true;
    };
    const scheduleExpiry = () => {
      window.clearTimeout(timer);
      if (expireIfNeeded()) return;
      timer = window.setTimeout(
        scheduleExpiry,
        Math.min(deadline - Date.now(), 2_147_000_000),
      );
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
  }, [state]);

  async function load() {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setState({ kind: "loading" });
    try {
      const response = await getSourceTransparency(reference, current.signal);
      if (current.signal.aborted) return;
      if (response.source.kind === "operator_source" && response.source.visible_until_ms <= Date.now()) {
        throw new QuestionApiError("public_collection_expired", messageForQuestionError("public_collection_expired"));
      }
      setState({ kind: "ready", source: response.source });
    } catch (error) {
      if (current.signal.aborted) return;
      const code = error instanceof QuestionApiError ? error.code : "storage_fault";
      setState({ kind: "error", code, message: messageForSourceError(code) });
    }
  }

  function onToggle(event: SyntheticEvent<HTMLDetailsElement>) {
    if (event.currentTarget.open) {
      void load();
      return;
    }
    controller.current?.abort();
    controller.current = null;
    setState({ kind: "idle" });
  }

  return (
    <details className="source-disclosure" onToggle={onToggle}>
      <summary>Source and attribution</summary>
      {state.kind === "loading" && <p role="status">Checking current source record. Previously loaded notice text is hidden.</p>}
      {state.kind === "error" && (
        <div className="source-error" role="alert">
          <p>{state.message} <span className="error-code">{state.code}</span></p>
          <button type="button" onClick={() => void load()}>Check source again</button>
        </div>
      )}
      {state.kind === "ready" && <SourceAttributionView source={state.source} />}
    </details>
  );
}

function messageForSourceError(code: string): string {
  const messages: Record<string, string> = {
    malformed_reference: "This evidence reference is malformed. No source attribution is shown.",
    wrong_store: "This evidence reference belongs to a different index. No source attribution is shown.",
    not_live: "This source is no longer in the current index. Its source notice is hidden.",
    revoked: "This source has been revoked. Its source notice is hidden.",
    version_superseded: "This evidence reference is for an older source version. Its source notice is hidden.",
    public_collection_expired: "This public collection has expired. Its source notice is hidden.",
  };
  return messages[code] ?? messageForQuestionError(code);
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
