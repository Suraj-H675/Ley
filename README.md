# Ley: A Search Engine from Scratch

**Status: planning; implementation has not begun.** This README describes intended scope, not verified features.

Ley is an independently implemented, single-machine web search engine intended to demonstrate practical systems engineering. Its planned Rust core includes a policy-aware web crawler, text extraction, positional inverted index, document updates/deletions, an incremental segmented disk format, Boolean and phrase queries, and BM25-based ranking. A command-line interface, local API, and focused React/TypeScript UI will make the engine usable and inspectable.

The project will write its **own** search-specific components rather than relying on Google/Bing results or an existing full-text engine. Established HTTP, TLS, HTML parsing, and runtime libraries are allowed as infrastructure.

## Planned progression

1. Local fixture crawl to an in-memory index and working CLI query.
2. Correct positional search and ranking validated against an independent reference.
3. Durable, versioned index generations with restart behavior.
4. A bounded, respectful crawler with robots and network-safety controls.
5. A local API/UI over a carefully scoped public crawl.
6. Incremental disk segments, document versions, deletion, compression, compaction and recovery.
7. Reproducible correctness, safety, performance and (where judged data exists) relevance evaluation.

The initial developer experience should work locally without paid services. Live-crawl collection sizes, latency, quality and scalability will be reported only after real measurement.

## Current status and reproducibility

No source-code implementation or build/test commands are claimed at this stage. Once the initial working slice exists, this README will be updated with verified prerequisites, exact local setup commands, test commands, architecture diagrams grounded in code, and demonstrated limitations.

## Development principles

Build for correctness first, retain a testable reference implementation, validate source permissions and crawl restrictions, measure before optimizing, and maintain a professional Git history. The project uses AI-assisted development; future descriptions will distinguish implemented, reviewed and measured work without overstating individual contributions.

## License

To be determined before public code or bundled data is released. Source-code licensing and rights to any crawled content are separate matters.
