import { useEffect, useRef, useState, type FormEvent } from "react";
import { SearchApiError, searchLey } from "./api";
import { ResultCard } from "./ResultCard";
import type { SearchState } from "./types";

export function App() {
  const [query, setQuery] = useState("");
  const [state, setState] = useState<SearchState>({ kind: "idle" });
  const input = useRef<HTMLInputElement>(null);
  const sequence = useRef(0);
  const currentAbort = useRef<AbortController | null>(null);

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

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedQuery = query.trim();
    if (!submittedQuery) {
      input.current?.focus();
      return;
    }
    const requestId = ++sequence.current;
    currentAbort.current?.abort();
    const controller = new AbortController();
    currentAbort.current = controller;
    setState({ kind: "loading", query: submittedQuery });
    try {
      const response = await searchLey(submittedQuery, controller.signal);
      if (requestId === sequence.current) setState({ kind: "ready", response });
    } catch (error) {
      if (requestId !== sequence.current || controller.signal.aborted) return;
      const message =
        error instanceof SearchApiError
          ? error.message
          : "Ley could not complete the search. Try again in a moment.";
      setState({ kind: "error", query: submittedQuery, message });
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

      <section className="hero" aria-labelledby="page-title">
        <p className="eyebrow"><span className="status-dot" aria-hidden="true" /> PRIVATE BETA · RUNNING ON YOUR MACHINE</p>
        <h1 id="page-title">Find the thread<br /><em>through your corpus.</em></h1>
        <p className="intro">Ley searches a locally indexed collection and shows how each result earned its place.</p>

        <form className="search-form" onSubmit={submit} role="search">
          <label className="visually-hidden" htmlFor="query">Search indexed documents</label>
          <svg className="search-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="10.8" cy="10.8" r="6.8" />
            <path d="m16 16 4.5 4.5" />
          </svg>
          <input
            id="query"
            ref={input}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            maxLength={4096}
            placeholder="Try a phrase, or combine terms with AND"
            autoComplete="off"
            aria-describedby="query-hint"
            aria-keyshortcuts="Control+K Meta+K"
          />
          <kbd className="shortcut" aria-hidden="true">⌘ K</kbd>
          <button className="search-button" type="submit" disabled={!query.trim()}>
            {isLoading ? "Searching" : "Search"}
            {!isLoading && <span aria-hidden="true">↗</span>}
          </button>
        </form>
        <p className="query-hint" id="query-hint">Enter to search <span>·</span> Ctrl K or ⌘ K to focus</p>
      </section>

      <section className="results-section" aria-labelledby="results-heading" aria-live="polite" aria-busy={isLoading}>
        <div className="results-heading-row">
          <h2 id="results-heading">{state.kind === "ready" ? "Results" : "Search results"}</h2>
          {state.kind === "ready" && (
            <div className="result-meta">
              <span>Generation {state.response.generation}</span>
              <span className="meta-divider" aria-hidden="true">/</span>
              <span>{state.response.corpusSize.toLocaleString()} indexed</span>
            </div>
          )}
        </div>

        {state.kind === "idle" && (
          <div className="empty-panel welcome-panel">
            <div className="empty-glyph" aria-hidden="true">⌕</div>
            <p>Ready when you are.</p>
            <span>Search your indexed collection to see results and their ranking details.</span>
          </div>
        )}

        {state.kind === "loading" && (
          <div className="loading-panel" role="status">
            <span className="spinner" aria-hidden="true" />
            <span>Searching for <strong>{state.query}</strong></span>
          </div>
        )}

        {state.kind === "error" && (
          <div className="message-panel error-panel" role="alert">
            <span className="message-icon" aria-hidden="true">!</span>
            <div><strong>Search didn’t go through</strong><p>{state.message}</p></div>
          </div>
        )}

        {state.kind === "ready" && state.response.results.length === 0 && (
          <div className="empty-panel no-results-panel">
            <div className="empty-glyph" aria-hidden="true">∅</div>
            <p>{state.response.corpusSize === 0 ? "Your index is empty." : "No matching documents."}</p>
            <span>{state.response.corpusSize === 0 ? "Add a permitted collection to your local index, then search again." : "Try fewer terms or a different phrase."}</span>
          </div>
        )}

        {state.kind === "ready" && state.response.results.length > 0 && (
          <>
            <p className="results-summary">
              {state.response.totalResults.toLocaleString()} {state.response.totalResults === 1 ? "match" : "matches"}
              {state.response.truncated ? ` · first ${state.response.results.length} shown` : ""}
              <span> for <strong>{state.response.query}</strong></span>
            </p>
            <div className="result-list">
              {state.response.results.map((result) => <ResultCard key={`${result.id}:${result.versionId}`} result={result} />)}
            </div>
          </>
        )}
      </section>

      <footer className="page-footer">
        <span>Search stays on this machine.</span>
        <span>Scores and explanations use one index snapshot.</span>
        <a href="/rust-stdlib-documentation-MIT.txt">Candidate source and MIT notice</a>
      </footer>
    </main>
  );
}
