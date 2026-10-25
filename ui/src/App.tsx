import { useEffect, useRef, useState, type FormEvent } from "react";
import { EvidenceCard } from "./EvidenceCard";
import { getSourceTransparency, getWorkspaceStatus, messageForQuestionError, QuestionApiError, retrieveQuestion, SearchApiError, searchLey } from "./api";
import { ResultCard } from "./ResultCard";
import type { EvidenceReference, QuestionSearchState, RetrievalResponse, RetrievalStatus, SearchState, SiteWorkspaceStatus, SourceAttributionState, WorkspaceStatusState } from "./types";

type SearchMode = "question" | "dsl";

export function App() {
  const [mode, setMode] = useState<SearchMode>("question");
  const [query, setQuery] = useState("");
  const [questionState, setQuestionState] = useState<QuestionSearchState>({ kind: "idle" });
  const [dslState, setDslState] = useState<SearchState>({ kind: "idle" });
  const [formError, setFormError] = useState("");
  const [workspaceStatus, setWorkspaceStatus] = useState<WorkspaceStatusState>({ kind: "loading" });
  const [statusRefresh, setStatusRefresh] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const sequence = useRef(0);
  const currentAbort = useRef<AbortController | null>(null);
  const state = mode === "question" ? questionState : dslState;

  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", focusSearch);
    return () => {
      window.removeEventListener("keydown", focusSearch);
      currentAbort.current?.abort();
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setWorkspaceStatus((current) => current.kind === "ready"
      ? { ...current, refreshing: true, refreshError: undefined }
      : { kind: "loading" });
    getWorkspaceStatus(controller.signal).then((status) => {
      if (status) setWorkspaceStatus({ kind: "ready", status });
      else setWorkspaceStatus({ kind: "not_bound" });
    }).catch((error: unknown) => {
      if (controller.signal.aborted) return;
      const message = error instanceof QuestionApiError ? error.message : "Workspace status could not be read.";
      setWorkspaceStatus((current) => current.kind === "ready"
        ? { ...current, refreshing: false, refreshError: message }
        : { kind: "error", message });
    });
    return () => controller.abort();
  }, [statusRefresh]);

  function changeMode(nextMode: SearchMode) {
    if (mode === nextMode) return;
    sequence.current += 1;
    currentAbort.current?.abort();
    currentAbort.current = null;
    setMode(nextMode);
    setFormError("");
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedQuery = query.trim();
    if (!submittedQuery) {
      setFormError(mode === "question" ? "Enter a question to search for matching passages." : "Enter a DSL expression to search.");
      input.current?.focus();
      return;
    }
    setFormError("");
    const requestId = ++sequence.current;
    currentAbort.current?.abort();
    const controller = new AbortController();
    currentAbort.current = controller;

    if (mode === "question") {
      setQuestionState({ kind: "loading", question: submittedQuery });
      try {
        const response = await retrieveQuestion(submittedQuery, controller.signal);
        if (requestId === sequence.current) setQuestionState({ kind: "ready", question: submittedQuery, response });
      } catch (error) {
        if (requestId !== sequence.current || controller.signal.aborted) return;
        const code = error instanceof QuestionApiError ? error.code : "storage_fault";
        const message = error instanceof QuestionApiError ? error.message : "Ley could not complete the question search. Try again.";
        setQuestionState({ kind: "error", question: submittedQuery, code, message });
      }
      return;
    }

    setDslState({ kind: "loading", query: submittedQuery });
    try {
      const response = await searchLey(submittedQuery, controller.signal);
      if (requestId === sequence.current) setDslState({ kind: "ready", response });
    } catch (error) {
      if (requestId !== sequence.current || controller.signal.aborted) return;
      const message = error instanceof SearchApiError
        ? error.message
        : "Ley could not complete the advanced search. Try again in a moment.";
      setDslState({ kind: "error", query: submittedQuery, message });
    }
  }

  const isLoading = state.kind === "loading";

  return (
    <main className="page-shell">
      <header className="masthead">
        <a className="wordmark" href="/" aria-label="Ley search home">
          <span className="wordmark-mark" aria-hidden="true">L</span>
          <span>Ley</span>
        </a>
        <span className="masthead-note">A local search engine</span>
      </header>

      {workspaceStatus.kind !== "loading" && workspaceStatus.kind !== "not_bound" && (
        <WorkspaceStatusPanel state={workspaceStatus} onRefresh={() => setStatusRefresh((value) => value + 1)} />
      )}

      <section className="hero" aria-labelledby="page-title">
        <p className="eyebrow"><span className="status-dot" aria-hidden="true" /> PRIVATE BETA · RUNNING ON YOUR MACHINE</p>
        <h1 id="page-title">Find the thread<br /><em>through your corpus.</em></h1>
        <p className="intro">Ask a question to find extracted passages in your local collection. Ley does not decide whether a passage answers it.</p>

        <fieldset className="search-modes" aria-label="Search mode">
          <legend>Search mode</legend>
          <label><input type="radio" name="search-mode" checked={mode === "question"} onChange={() => changeMode("question")} /> Question</label>
          <label><input type="radio" name="search-mode" checked={mode === "dsl"} onChange={() => changeMode("dsl")} /> Advanced DSL</label>
        </fieldset>
        <form className="search-form" onSubmit={submit} role="search">
          <label className="visually-hidden" htmlFor="query">{mode === "question" ? "Ask a question about indexed documents" : "Enter an advanced Boolean or phrase query"}</label>
          <svg className="search-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="10.8" cy="10.8" r="6.8" />
            <path d="m16 16 4.5 4.5" />
          </svg>
          <input
            id="query"
            ref={input}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              if (formError) setFormError("");
            }}
            maxLength={4096}
            placeholder={mode === "question" ? "Ask a question about your local collection" : 'Try: "exact phrase" AND another term'}
            autoComplete="off"
            aria-describedby="query-hint"
            aria-keyshortcuts="Control+K Meta+K"
            aria-invalid={Boolean(formError)}
          />
          <kbd className="shortcut" aria-hidden="true">⌘ K</kbd>
          <button className="search-button" type="submit" disabled={isLoading}>
            {isLoading ? "Searching" : "Search"}
            {!isLoading && <span aria-hidden="true">↗</span>}
          </button>
        </form>
        <p className="query-hint" id="query-hint">
          {mode === "question" ? "Ordinary question retrieval · lexical candidates only" : "Advanced DSL · terms, quoted phrases, AND, OR"}
          <span>·</span> Enter to search <span>·</span> Ctrl K or ⌘ K to focus
        </p>
        {formError && <p className="field-error" role="alert">{formError}</p>}
      </section>

      <section className="results-section" aria-labelledby="results-heading" aria-live="polite" aria-busy={isLoading}>
        <div className="results-heading-row">
          <h2 id="results-heading">{mode === "question" ? "Passage candidates" : "Advanced DSL results"}</h2>
          {state.kind === "ready" && mode === "question" && questionState.kind === "ready" && (
            <div className="result-meta"><span>Generation {questionState.response.generation_id}</span><span className="meta-divider" aria-hidden="true">/</span><span>Answer assessment: not assessed</span></div>
          )}
          {state.kind === "ready" && mode === "dsl" && dslState.kind === "ready" && (
            <div className="result-meta"><span>Generation {dslState.response.generation}</span><span className="meta-divider" aria-hidden="true">/</span><span>{dslState.response.corpusSize.toLocaleString()} indexed</span></div>
          )}
        </div>

        {state.kind === "idle" && (
          <div className="empty-panel welcome-panel">
            <div className="empty-glyph" aria-hidden="true">⌕</div>
            <p>{mode === "question" ? "Ask about your collection." : "Advanced DSL is ready."}</p>
            <span>{mode === "question" ? "Ley will show matching extracted text and its stored evidence reference." : "Use terms, quoted phrases, AND, OR, or implicit AND."}</span>
          </div>
        )}

        {mode === "question" && questionState.kind === "loading" && (
          <div className="loading-panel" role="status">
            <span className="spinner" aria-hidden="true" />
            <span>Searching for <strong>{questionState.question}</strong></span>
          </div>
        )}

        {mode === "dsl" && dslState.kind === "loading" && (
          <div className="loading-panel" role="status">
            <span className="spinner" aria-hidden="true" />
            <span>Searching for <strong>{dslState.query}</strong></span>
          </div>
        )}

        {state.kind === "error" && (
          <div className="message-panel error-panel" role="alert">
            <span className="message-icon" aria-hidden="true">!</span>
            <div><strong>Search didn’t go through</strong><p>{mode === "question" && questionState.kind === "error" ? questionState.message : dslState.kind === "error" ? dslState.message : "Ley could not complete the search."}</p>
              {mode === "question" && questionState.kind === "error" && <code className="error-code">{questionState.code}</code>}
            </div>
          </div>
        )}

        {mode === "question" && questionState.kind === "ready" && (
          <QuestionResults response={questionState.response} question={questionState.question} />
        )}

        {mode === "dsl" && dslState.kind === "ready" && dslState.response.results.length === 0 && (
          <div className="empty-panel no-results-panel">
            <div className="empty-glyph" aria-hidden="true">∅</div>
            <p>{dslState.response.corpusSize === 0 ? "Your index is empty." : "No matching documents."}</p>
            <span>{dslState.response.corpusSize === 0 ? "Add a permitted collection to your local index, then search again." : "Try fewer terms or a different phrase."}</span>
          </div>
        )}

        {mode === "dsl" && dslState.kind === "ready" && dslState.response.results.length > 0 && (
          <>
            <p className="results-summary">
              {dslState.response.totalResults.toLocaleString()} {dslState.response.totalResults === 1 ? "match" : "matches"}
              {dslState.response.truncated ? ` · first ${dslState.response.results.length} shown` : ""}
              <span> for <strong>{dslState.response.query}</strong></span>
            </p>
            <div className="result-list">
              {dslState.response.results.map((result) => <ResultCard key={`${result.id}:${result.versionId}`} result={result} />)}
            </div>
          </>
        )}
      </section>

      <footer className="page-footer">
        <span>Search stays on this machine.</span>
        <span>Passage matches are not verified answers.</span>
      </footer>
    </main>
  );
}

function WorkspaceStatusPanel({ state, onRefresh }: { state: Extract<WorkspaceStatusState, { kind: "ready" | "error" }>; onRefresh: () => void }) {
  const refreshing = state.kind === "ready" && state.refreshing === true;
  return (
    <section className="workspace-panel" aria-labelledby="workspace-heading" aria-live="polite">
      <div className="workspace-panel-heading">
        <div>
          <p className="workspace-eyebrow">SELECTED SITE COLLECTION</p>
          <h2 id="workspace-heading">Crawl and evidence status</h2>
        </div>
        <button className="workspace-refresh" type="button" onClick={onRefresh} disabled={refreshing}>
          {refreshing ? "Refreshing…" : "Refresh status"}
        </button>
      </div>
      {state.kind === "error" ? (
        <div className="workspace-status-error" role="status">
          <p>{state.message}</p>
          <p>For bounded URL and failure details, run <code>ley site status --workspace &lt;PATH&gt;</code> in the terminal that started Ley.</p>
        </div>
      ) : (
        <>
          <WorkspaceStatusDetails status={state.status} />
          {state.refreshError && <p className="workspace-status-error" role="status">Refresh failed: {state.refreshError} The last successful status remains shown.</p>}
        </>
      )}
    </section>
  );
}

function WorkspaceStatusDetails({ status }: { status: SiteWorkspaceStatus }) {
  const { source } = status;
  const stopped = source.lifecycle !== "active" || source.policyExpired || source.retentionExpired;
  const expiryLabel = source.policyExpired
    ? "Policy expired"
    : source.retentionExpired
      ? "Retention period expired"
      : `Policy expires ${new Date(source.expiresAtMs).toLocaleString()}`;
  const lifecycleLabel = source.lifecycle === "revoked" ? "Source revoked" : source.lifecycle;
  const visibleStates = Object.entries(source.frontierStateCounts).filter(([, count]) => count > 0);

  return (
    <>
      <div className="workspace-summary">
        <div className="workspace-source">
          <span className={`workspace-state${stopped ? " is-stopped" : ""}`}>{lifecycleLabel}</span>
          <span className="workspace-origin">{source.origin}</span>
          <span>{expiryLabel}</span>
        </div>
        <dl className="workspace-counts">
          <div><dt>Request budget reserved</dt><dd>{source.requestBudget.persistentUsed} / {source.requestBudget.persistentLimit}</dd></div>
          <div><dt>Remaining</dt><dd>{source.requestBudget.persistentRemaining}</dd></div>
          <div><dt>Indexed live pages</dt><dd>{source.currentlyIndexedLiveUrls}</dd></div>
          <div><dt>Due work</dt><dd>{source.dueWorkCount}</dd></div>
          <div><dt>Pending / rejected updates</dt><dd>{source.pendingOutboxCount} / {source.rejectedOutboxCount}</dd></div>
        </dl>
      </div>
      <p className="workspace-counter-note">{source.requestBudget.persistentCounterSemantics}</p>
      <div className="workspace-scope">
        <div><strong>Allowed paths</strong><span>{source.allowedPathPrefixes.join(", ")}</span></div>
        <div><strong>Frontier</strong><span>{visibleStates.length ? visibleStates.map(([name, count]) => `${name}: ${count}`).join(" · ") : "No outstanding frontier work"}</span></div>
      </div>
      <div className="workspace-permissions">
        <strong>Recorded policy permissions</strong>
        <dl>
          <div><dt>Fetch</dt><dd>{permissionLabel(source.permissions.fetchRecorded)}</dd></div>
          <div><dt>Storage</dt><dd>{permissionLabel(source.permissions.storageRecorded)}</dd></div>
          <div><dt>Index</dt><dd>{permissionLabel(source.permissions.indexRecorded)}</dd></div>
          <div><dt>Display</dt><dd>{permissionLabel(source.permissions.displayRecorded)}</dd></div>
        </dl>
      </div>
      {(source.pendingOutboxCount > 0 || source.rejectedOutboxCount > 0) && (
        <p className="workspace-action-note" role="status">
          Pending or rejected updates need attention. Run <code>ley site status --workspace &lt;PATH&gt;</code> in the terminal that started Ley for bounded URL and failure details.
        </p>
      )}
      <p className="workspace-rights-note">
        These permission fields are operator declarations, not a legal determination. These counts cover known frontier work; unlinked pages are not counted, so they do not measure full site coverage.
      </p>
      <p className="workspace-coverage-definition">{status.coverageDefinition}</p>
    </>
  );
}

function permissionLabel(granted: boolean): string {
  return granted ? "Recorded as granted" : "Not recorded as granted";
}

function QuestionResults({ response, question }: { response: RetrievalResponse; question: string }) {
  const [sourceStates, setSourceStates] = useState<Record<string, SourceAttributionState>>({});
  const [sourceChecksLoading, setSourceChecksLoading] = useState(response.hits.length > 0);
  const [sourceRetry, setSourceRetry] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setSourceStates({});
    setSourceChecksLoading(response.hits.length > 0);
    if (response.hits.length === 0) return () => controller.abort();

    void (async () => {
      const checked: Record<string, SourceAttributionState> = {};
      for (const hit of response.hits) {
        const reference = hit.passage.reference;
        try {
          const transparency = await getSourceTransparency(reference, controller.signal);
          const source = transparency.source;
          if (source.kind === "operator_source" && source.visible_until_ms <= Date.now()) {
            throw new QuestionApiError(
              "public_collection_expired",
              messageForQuestionError("public_collection_expired"),
            );
          }
          checked[referenceKey(reference)] = { kind: "ready", source };
        } catch (error) {
          if (controller.signal.aborted) return;
          const code = error instanceof QuestionApiError ? error.code : "storage_fault";
          checked[referenceKey(reference)] = {
            kind: "error",
            code,
            message: error instanceof QuestionApiError
              ? error.message
              : messageForQuestionError(code),
          };
        }
      }
      if (controller.signal.aborted) return;
      setSourceStates(checked);
      setSourceChecksLoading(false);
    })();

    return () => controller.abort();
  }, [response, sourceRetry]);

  const retrySourceChecks = () => setSourceRetry((value) => value + 1);

  return (
    <>
      <p className="results-summary">
        <strong>{question || "Question"}</strong>
        <span> · {statusLabel(response.status)}</span>
        <span> · {response.completeness === "partial" ? "Partial bounded search" : "Complete within current work limits"}</span>
      </p>
      <p className="question-metadata">
        Normalized terms: {response.normalized_terms.length ? response.normalized_terms.join(", ") : "none"}
        <span> · </span>Answer assessment: <strong>{response.answer_assessment}</strong>
      </p>
      {response.completeness === "partial" && <p className="partial-notice" role="status">Some current documents were not evaluated within the retrieval work budget.</p>}
      {response.hits.length === 0 ? (
        <div className="empty-panel no-results-panel">
          <div className="empty-glyph" aria-hidden="true">∅</div>
          <p>{emptyQuestionHeading(response.status)}</p>
          <span>{emptyQuestionDescription(response.status, response.completeness)}</span>
        </div>
      ) : (
        <>
          <p className="candidate-disclaimer">These are lexical passage candidates. Ley has not assessed whether they answer the question.</p>
          {sourceChecksLoading ? (
            <p className="source-check-status" role="status">Checking each current source record before showing its passage.</p>
          ) : (
            <div className="result-list">
              {response.hits.map((hit) => {
                const reference = hit.passage.reference;
                const sourceState = sourceStates[referenceKey(reference)] ?? {
                  kind: "error" as const,
                  code: "invalid_response",
                  message: "The current source record was not checked, so this passage is hidden.",
                };
                return (
                  <EvidenceCard
                    key={referenceKey(reference)}
                    hit={hit}
                    sourceState={sourceState}
                    onRetrySource={retrySourceChecks}
                  />
                );
              })}
            </div>
          )}
        </>
      )}
    </>
  );
}

function referenceKey(reference: EvidenceReference): string {
  return JSON.stringify(reference);
}

function statusLabel(status: RetrievalStatus): string {
  if (status === "retrieved_text") return "Passage text matches found";
  if (status === "no_relevant_text_match") return "No passage text matched";
  const reason = status.insufficient_evidence;
  if (reason === "no_searchable_terms") return "No searchable terms found";
  if (reason === "only_title_matches") return "Terms matched titles, but no passage text";
  return "Retrieval work budget reached";
}

function emptyQuestionHeading(status: RetrievalStatus): string {
  return status === "no_relevant_text_match" ? "No passage text matched." : "No passage candidate is available.";
}

function emptyQuestionDescription(status: RetrievalStatus, completeness: "complete" | "partial"): string {
  if (status === "no_relevant_text_match" && completeness === "complete") return "This is not a claim that the collection contains no answer; answer support is not assessed.";
  if (status !== "no_relevant_text_match") return statusLabel(status) + ". Try a more specific question.";
  return "Some work was bounded. Answer support is not assessed.";
}
