# Ley: A Search Engine from Scratch

**Status: Gate 0 Domain Contracts and Corpus and Gate 1 Demo 0.1 have been independently accepted by Work. Gate 2 has not begun.**

Ley is an independently implemented, single-machine web search engine intended to demonstrate practical systems engineering. Its planned Rust core includes a policy-aware web crawler, text extraction, positional inverted index, document updates/deletions, an incremental segmented disk format, Boolean and phrase queries, and BM25-based ranking. A command-line interface, local API, and focused React/TypeScript UI will make the engine usable and inspectable.

The project will write its **own** search-specific components rather than relying on Google/Bing results or an existing full-text engine. Established HTTP, TLS, HTML parsing, and runtime libraries are allowed as infrastructure.

## Planned progression

0. Gate 0 freezes URL/document identity, extraction, Unicode analysis, query grammar, BM25, lifecycle, visibility, handoff, allowed infrastructure boundaries, and a small reference corpus.
1. Gate 1 implements a controlled local fixture path, an in-memory index, and a CLI against those contracts. The local fixture-to-query demonstration has passed independent review.
2. Validate positional search and ranking against an independent reference.
3. Add durable, versioned index generations with restart behavior.
4. Add a bounded crawler with robots and network-safety controls.
5. Build a local API/UI over a carefully scoped corpus.
6. Add incremental disk segments, document versions, deletion, compaction, and recovery.
7. Report reproducible correctness, safety, performance, and, when judged data exists, relevance evidence.

The initial developer experience should work locally without paid services. Live-crawl collection sizes, latency, quality and scalability will be reported only after real measurement.

## Current stage and reproducibility

Gate 0 produced authored synthetic fixtures and expected outcomes in [`fixtures/reference-v1.json`](fixtures/reference-v1.json). The 50 removal-policy cases preserve repeated X-Robots-Tag fields and check generic, LeyBot, and other-agent scope, known colon-valued items, malformed entries, effective visibility, and link following. The contract covers a finite header subset; it does not claim general X-Robots-Tag compatibility. The 18-event lifecycle trace checks stale-fence rejection, immutable same-fence intents, replay after tombstone, and revoked-policy recovery denial. The fixture data is dedicated under CC0-1.0 in [`fixtures/LICENSE.txt`](fixtures/LICENSE.txt). It contains no pages fetched from the public web.

Verify the finite fixture corpus from the repository root with Python 3.10 or later:

```sh
python3 tools/verify_reference_corpus.py
```

The verifier uses only the Python standard library and needs no network access. It checks fixture integrity, representative URL and extraction goldens, selected Unicode examples, field tokens and version hashes, finite query matches, BM25 statistics and per-field scores, tie order, removal decisions, scheduled 404s, and update/delete/fence replay. It does not implement the WHATWG URL or HTML parser, query parser, crawler, or index.

The finite Python verifier uses Python's Unicode 16.0.0 database. Official Unicode 16 and 17 data agree for the 42 code points used by its current examples; that supports those finite examples only. The Rust implementation uses ICU4X 2.3.0 Unicode data for NFKC, full default case folding, and Unicode properties, with `unicode-segmentation` 1.13.3 for Unicode 17 word boundaries. Rust tests include Unicode 17 code points absent from Unicode 16. The verifier remains unchanged and does not claim general Unicode 17 conformance.

### Run the local demo

From the repository root, with Rust and Cargo installed:

```sh
cargo run --locked -- demo --query Rust
```

The command starts an in-process HTTP fixture bound to `127.0.0.1` on an ephemeral port, fetches `/robots.txt` and two HTML pages over HTTP, extracts title/body text and links, creates Ley-owned positional postings in memory, and runs a real query through the CLI. The process checks its fixture request log and exits with an error if the repeated fragment link is fetched twice or the disallowed private page is requested. The fixture listener is joined before the command returns.

The accepted query subset is one unfielded analyzed term. Multi-term, Boolean, phrase, wildcard, and field syntax return an explicit unsupported-syntax error. Scores are computed from the index with separate title and body BM25 contributions (`k1=1.2`, `b=0.75`, title weight 2, body weight 1); this is single-term weighted-field BM25, not BM25F. Ties sort by UTF-8 URL key bytes.

The raw query is limited to 4,096 UTF-8 bytes before trimming or analysis. An over-limit query is rejected before the local fixture starts, with an error that reports its byte count and asks the caller to shorten it.

### Gate 1 boundaries

- Fetching is restricted to the one exact loopback fixture origin, including its port. The HTTP client disables ambient proxies and automatic redirects; every seed, link, and redirect is checked before a request. The demo uses bounded request count, redirect hops, body bytes, parser events, tree depth, field sizes, token count, outgoing links, per-request timeouts, and an overall deadline.
- The fixture's `robots.txt` exercise is a deliberately simple `LeyBot` disallow-prefix simulation. It is not an RFC 9309 implementation.
- HTTP content encodings other than `identity` are rejected. HTML bytes use BOM, HTTP charset, the WHATWG first-1024-byte prescan (including its XML fallback), then a deterministic Windows-1252 default; HTML5 parsing runs with scripting disabled.
- The index and postings exist only in memory. There is no public crawler, source admission, persistent frontier, disk index, recovery, API, or UI. Full Boolean and phrase query behavior is not implemented.

Run the focused Rust suite, formatter and lint checks, plus the finite published-corpus verifier with:

```sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 tools/verify_reference_corpus.py
```

The Python verifier remains a finite Gate 0 check; it is not the Rust parser, crawler, analyzer, or runtime.

## Development principles

Build for correctness first, retain a testable reference implementation, validate source permissions and crawl restrictions, measure before optimizing, and maintain a professional Git history. The project uses AI-assisted development; future descriptions will distinguish implemented, reviewed and measured work without overstating individual contributions.

## License

Source-code licensing remains to be determined. Fixture data has its separate CC0-1.0 notice. No crawled content is bundled.
