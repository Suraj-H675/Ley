# Ley: A Search Engine from Scratch

**Status: Gate 0 Domain Contracts and Corpus have been independently accepted by Work. Gate 1 has not begun; no Rust search-engine runtime has been implemented.** This README separates verified project artifacts from planned runtime behavior.

Ley is an independently implemented, single-machine web search engine intended to demonstrate practical systems engineering. Its planned Rust core includes a policy-aware web crawler, text extraction, positional inverted index, document updates/deletions, an incremental segmented disk format, Boolean and phrase queries, and BM25-based ranking. A command-line interface, local API, and focused React/TypeScript UI will make the engine usable and inspectable.

The project will write its **own** search-specific components rather than relying on Google/Bing results or an existing full-text engine. Established HTTP, TLS, HTML parsing, and runtime libraries are allowed as infrastructure.

## Planned progression

0. Gate 0 freezes URL/document identity, extraction, Unicode analysis, query grammar, BM25, lifecycle, visibility, handoff, allowed infrastructure boundaries, and a small reference corpus.
1. Build the local fixture path, in-memory index, and CLI against those contracts.
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

The analyzer contract targets Unicode 17.0.0. Verification ran with Python's Unicode 16.0.0 database. Official Unicode 16 and 17 data agree for the 42 code points used by the current analyzer, document, and query examples. Their UnicodeData records, default full case-fold mappings, and word-break properties are unchanged. This supports the finite examples only. The verifier's regular-expression tokenizer is not a general UAX #29 implementation, and full Unicode 17 analyzer conformance remains unverified. The Rust analyzer must demonstrate the pinned Unicode 17 behavior before runtime claims are made.

No Rust source implementation, crawler, search runtime, CLI, build command, or engine test suite is claimed yet. Public crawling remains disabled. The target architecture is one Rust library plus CLI, using Ley-owned crawl policy, analyzer, positional index, query executor, and BM25 behind permitted infrastructure libraries. Once the first working slice exists, this README will add verified setup commands, runtime architecture, and demonstrated limits.

## Development principles

Build for correctness first, retain a testable reference implementation, validate source permissions and crawl restrictions, measure before optimizing, and maintain a professional Git history. The project uses AI-assisted development; future descriptions will distinguish implemented, reviewed and measured work without overstating individual contributions.

## License

Source-code licensing remains to be determined. Fixture data has its separate CC0-1.0 notice. No crawled content is bundled.
