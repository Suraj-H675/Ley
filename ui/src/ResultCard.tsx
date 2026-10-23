import { safeResultUrl } from "./api";
import type { MatchSummary, SearchHit } from "./types";

export function ResultCard({ result }: { result: SearchHit }) {
  const href = safeResultUrl(result.id);
  return (
    <article className="result-card">
      <div className="result-topline">
        <div className="result-url-wrap">
          {href && <span className="url-mark" aria-hidden="true">↗</span>}
          {href ? (
            <a className="result-url" href={href} target="_blank" rel="noopener noreferrer" aria-label="Open external source address; this address is not checked against the indexed text">Open external address · {result.id}</a>
          ) : (
            <span className="result-url source-identity">Indexed identity: {result.id}</span>
          )}
        </div>
        <span className="score-pill">{result.score.toFixed(3)} <span>score</span></span>
      </div>
      <h3 className="result-title">
        {href ? <a href={href} target="_blank" rel="noopener noreferrer">{result.title || "Untitled document"}</a> : (result.title || "Untitled document")}
      </h3>
      <p className="result-snippet">{result.snippet}</p>
      <div className="result-bottomline">
        <div className="match-summary" aria-label="Matched query terms">{renderMatch(result.matched)}</div>
        <details className="explanation">
          <summary>Why this result?</summary>
          <div className="explanation-body">
            <div className="explanation-overview">
              <span>Snapshot <strong>{result.explanation.statisticsSource.generation ?? "in memory"}</strong></span>
              <span>Documents <strong>{result.explanation.documentCount}</strong></span>
              <span>Title avg <strong>{formatLength(result.explanation.averageTitleLength)}</strong></span>
              <span>Body avg <strong>{formatLength(result.explanation.averageBodyLength)}</strong></span>
            </div>
            {result.explanation.terms.map((term) => (
              <div className="term-breakdown" key={term.term}>
                <h4>{term.term}</h4>
                <div className="field-breakdown">
                  <FieldBreakdown name="Title" field={term.title} />
                  <FieldBreakdown name="Body" field={term.body} />
                </div>
              </div>
            ))}
            <p className="explanation-total">Total BM25 score <strong>{result.explanation.totalScore.toFixed(6)}</strong></p>
            <p className="version-id">Version {result.versionId}</p>
          </div>
        </details>
      </div>
    </article>
  );
}

function renderMatch(match: MatchSummary): string[] {
  if (match.kind === "term") {
    return [`${match.term} · ${match.titleOccurrences + match.bodyOccurrences} hit${match.titleOccurrences + match.bodyOccurrences === 1 ? "" : "s"}`];
  }
  if (match.kind === "phrase") {
    const phrase = `“${match.terms.join(" ") }”`;
    return [`${phrase} · ${match.titleOccurrences + match.bodyOccurrences} hit${match.titleOccurrences + match.bodyOccurrences === 1 ? "" : "s"}`];
  }
  return match.children.flatMap(renderMatch);
}

function FieldBreakdown({ name, field }: { name: string; field: SearchHit["explanation"]["terms"][number]["title"] }) {
  return (
    <div className="field-row">
      <strong>{name}</strong>
      <span>tf {field.termFrequency} / df {field.documentFrequency}</span>
      <span>len {field.documentLength} · idf {field.idf.toFixed(4)}</span>
      <span className="contribution">+{field.contribution.toFixed(6)}</span>
    </div>
  );
}

function formatLength(value: number): string {
  return Number.isInteger(value) ? value.toString() : value.toFixed(2);
}
