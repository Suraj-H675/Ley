# Ley: A Search Engine from Scratch

**Status: Gates 0 through 4 have passed independent acceptance. Gate 4 Controlled Crawler 0.4 is accepted for owned local HTTP fixtures. Gate 5 has not begun.**

Ley is an independently implemented, single-machine web search engine intended to demonstrate practical systems engineering. Its planned Rust core includes a policy-aware web crawler, text extraction, positional inverted index, document updates/deletions, an incremental segmented disk format, Boolean and phrase queries, and BM25-based ranking. A command-line interface, local API, and focused React/TypeScript UI will make the engine usable and inspectable.

The project will write its **own** search-specific components rather than relying on Google/Bing results or an existing full-text engine. Established HTTP, TLS, HTML parsing, and runtime libraries are allowed as infrastructure.

## Planned progression

0. Gate 0 freezes URL/document identity, extraction, Unicode analysis, query grammar, BM25, lifecycle, visibility, handoff, allowed infrastructure boundaries, and a small reference corpus.
1. Gate 1 implements a controlled local fixture path, an in-memory index, and a CLI against those contracts. The local fixture-to-query demonstration has passed independent review.
2. Gate 2 implements positional Boolean and phrase retrieval, field-separated BM25, result explanations, and a document-scan reference evaluator. Independent review verified its query, ranking, analyzer, and input-boundary behavior.
3. Gate 3 implements durable, versioned index generations with verified restart and process-crash recovery behavior, described below.
4. Gate 4 implements a bounded controlled crawler with robots and network-safety controls, described below.
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

The locked ICU normalizer, case-mapping, and properties data packages identify their source as `release-78.1rc`, the [ICU 78 release candidate with Unicode 17 data](https://github.com/unicode-org/icu/releases/tag/release-78.1rc). The segmentation tables declare Unicode 17.0.0. The Rust suite checks Unicode 17-specific normalization, folding, character properties, and word boundaries. It also compares all 12 reference queries and 3 BM25 rankings against an independent document scan, including expected corpus statistics and recorded field contributions.

### Run the local demo

From the repository root, with Rust and Cargo installed:

```sh
cargo run --locked -- demo --query Rust
cargo run --locked -- demo --query 'Rust OR Ley'
cargo run --locked -- demo --query '"Rust retrieval"'
cargo run --locked -- demo --query 'Rust OR Ley' --explain
cargo run --locked -- controlled-demo
# Expected to exit with a missing-operand query error:
cargo run --locked -- demo --query 'Rust OR'
```

The command starts an in-process HTTP fixture bound to `127.0.0.1` on an ephemeral port, fetches `/robots.txt` and two HTML pages over HTTP, extracts title/body text and links, creates Ley-owned positional postings in memory, and runs a real query through the CLI. The process checks its fixture request log and exits with an error if the repeated fragment link is fetched twice or the disallowed private page is requested. The fixture listener is joined before the command returns.

`controlled-demo` is a separate Gate 4 path. It uses an owned loopback fixture, a persistent SQLite frontier, the Gate 3 `PersistentIndex`, the same extractor/analyzer, and a query after closing and reopening the index. It also demonstrates source revocation, tombstone visibility, and explicit readmission. Its output includes accepted socket count and the fixture request log. Neither command crawls public or third-party hosts.

The query parser accepts analyzed terms, quoted phrases, exact uppercase standalone `AND` and `OR`, and implicit AND between adjacent operands. AND binds more tightly than OR. Phrases match consecutive positions within either title or body; they cannot cross fields. `NOT`, parentheses, field prefixes, wildcard/fuzzy, and proximity syntax are unsupported. Queries are limited to 4,096 raw UTF-8 bytes and 64 analyzed token occurrences; phrases are limited to 16 tokens and terms to 64 Unicode scalar values.

Scores use separate title and body BM25 contributions (`k1=1.2`, `b=0.75`, title weight 2, body weight 1), not BM25F. Every distinct query term contributes when present in a matched result, including terms in an unsatisfied OR branch. Scores sort by their unrounded binary64 value, then canonical URL key bytes. `--explain` shows matched fields and positions, current in-memory corpus statistics, each title/body term contribution, final score, document version, and URL tie-break key.

The in-memory library supports replacement and removal by stable URL key so live matches and ranking statistics can be checked after mutations. Each indexed result carries the accepted document-version SHA-256 and a bounded plain-text body snippet. These are in-memory search behaviors; no persistent visibility or recovery guarantee is claimed.

Insertion and replacement reject titles over 4,096 UTF-8 bytes, combined fields over 1 MiB, documents over 100,000 emitted tokens, and terms over 64 Unicode scalar values. A rejected replacement preserves the previous document and its search statistics. Query errors return no results, and the CLI validates queries before starting the HTTP fixture.

### Gate 1 and Gate 2 boundaries

- Fetching is restricted to the one exact loopback fixture origin, including its port. The HTTP client disables ambient proxies and automatic redirects; every seed, link, and redirect is checked before a request. The demo uses bounded request count, redirect hops, body bytes, parser events, tree depth, field sizes, token count, outgoing links, per-request timeouts, and an overall deadline.
- The Gate 1 fixture's `robots.txt` exercise is a deliberately simple `LeyBot` disallow-prefix simulation. Gate 4 adds a separate RFC 9309 parser and matcher, documented below.
- HTTP content encodings other than `identity` are rejected. HTML bytes use BOM, HTTP charset, the WHATWG first-1024-byte prescan (including its XML fallback), then a deterministic Windows-1252 default; HTML5 parsing runs with scripting disabled.
- The Gate 1 demo crawler remains local and in memory. Gate 4 adds explicit fixture admission and a persistent frontier, but does not add a public crawler, public source allowlist, API, or UI. The durable index and frontier remain separate stores and do not share a transaction.

### Gate 3 Storage 0.3

`storage::PersistentIndex` stores complete immutable search generations. Callers create or open a store, request a durable fence for a canonical `UrlKey`, then apply an `Intent::Upsert`, `Tombstone`, `Revoke`, or `Readmit`. `read_view()` returns a pinned generation with the existing query, ranking, evidence, and explanation behavior. A pinned view keeps its original results and statistics while later generations publish.

The private store directory contains `STORE`, `LOCK`, `CURRENT`, `LEASE_KEY`, and immutable `gen-<id>.ley` files. Writers stage `.gen-<id>.tmp` and `.CURRENT.tmp` in that directory. Format 0.3 uses big-endian integers and a 448-byte generation header followed by four contiguous, SHA-256 checked sections for live documents, the term dictionary, positional postings, and lifecycle controls. `CURRENT` is a fixed 112-byte pointer that binds the store identity, generation ID, byte length, and whole-generation hash. Section offsets, counts, strings, URL keys, analyzer output, posting references, positions, version hashes, and chronological lifecycle transitions are checked when opening a committed generation. An unknown format or analyzer/schema identity requires an explicit reindex into a fresh store directory. Corruption referenced by `CURRENT` fails closed; orphan generation files are never promoted.

The byte layout is fixed for this format version:

| Record | Fields |
| --- | --- |
| `STORE` (64 bytes) | `LEYSTOR3`, major/minor `u16`, zero flags `u32`, random store ID (16 bytes), SHA-256 checksum (32 bytes). |
| `LEASE_KEY` (96 bytes) | `LEYMACK3`, major/minor `u16`, zero flags `u32`, matching store ID (16 bytes), random HMAC key (32 bytes), SHA-256 checksum (32 bytes). The file is mode `0600`; the containing directory is mode `0700`. |
| `CURRENT` (112 bytes) | `LEYHEAD3`, format version, zero flags, store ID, generation ID `u64`, file length `u64`, whole-generation SHA-256, and checksum. Its generation filename is derived from the validated ID. |
| Generation header (448 bytes) | `LEYGEN03`, version and exact header size, flags, store/generation/parent IDs, HTML-schema and analyzer hashes, total length, live counts and token totals, four section descriptors, reserved zero bytes, and header checksum. Each section descriptor contains absolute offset `u64`, byte length `u64`, record count `u64`, and SHA-256. |
| Documents | Sorted URL keys. Each record stores `u16` key/effective-URL byte lengths, `u32` title/body byte lengths and token counts, the 32-byte `VersionId`, then UTF-8 fields. |
| Dictionary and postings | Sorted terms store field document frequencies, posting count, and a relative offset/length into the posting section. Each posting stores a sorted document ordinal, title/body position counts, then strictly increasing `u32` positions. |
| Lifecycle controls | Sorted URL keys store the fence high-water, terminal-intent and policy-event counts, ordered `u64` fence values, operation/event bytes, zero reserved bytes, and the upsert version hash when present. |

Section files are not independently published. The whole generation is the recovery unit; the only visibility switch is replacement of `CURRENT` after the ready generation is synced.

Each URL key retains its issued fence high-water and terminal history. The terminal operation identity stays `(URL key, fence, Upsert(VersionId) | Tombstone)`. An exact replay remains a no-op after a later update or removal, and changing only the effective URL does not change replay identity or replace the originally stored provenance. Revocation publishes a tombstone and a policy event at one fence. Explicit readmission clears policy state but restores no content; another fence and upsert are required before the key is searchable again. The index and any future crawler outbox or frontier are separate stores and do not share a transaction.

`PersistentIndex::export_lease` and `restore_lease` let callers preserve one issued fence token across process restarts without adding an outbox or frontier. The bounded token is `LEYLEASE`, version `u16`, zero flags, store ID, nonzero fence `u64`, canonical URL-key byte length `u16`, URL-key UTF-8 bytes, and a 32-byte HMAC-SHA-256. Its maximum size is 2,118 bytes. The HMAC covers the fixed `ley-fence-lease-v1\0` domain prefix and all token fields before the tag. Restore checks the authenticator, store ID, canonical key, control record, and fence against durable high-water. An older issued fence can be restored for replay; `apply` accepts only an exact previously accepted intent at that fence and otherwise returns stale or conflict. A missing `LEASE_KEY` can be initialized by export under the writer lock for stores made before this capability; restore fails closed when key material is missing or invalid. Removing the key invalidates previously exported tokens. The token is not encrypted, and HMAC protects against forgery only from callers who cannot read the local key. Copying the full store also copies its ID and key, so copies are the same logical store for token validation.

Persistent query explanations identify `persistent generation <id>` through `StatisticsSource::PersistentGeneration`. Gate 1's in-memory explanation still reports `current in-memory document view`. `ReadView` holds a decoded generation in an `Arc`, so a pinned view keeps its original matches, statistics, and generation identity while writers publish and cleanup removes old generation files. There is no disk pin registry; cleanup retains the current generation and its immediate parent for recovery.

The format has hard bounds of 512 MiB per generation, 100,000 live documents, 500,000 terms, 1,000,000 term/document posting records, 100,000 lifecycle keys, 500,000 terminal intents, and 500,000 policy events. URL keys and effective URLs are each limited to 2,048 UTF-8 bytes; title/body fields and analyzer token limits follow Gate 1. Fence or generation overflow and capacity exhaustion fail closed. Whole generations are rebuilt on mutation, decoded into memory on open, and terminal history is not pruned. This is the first durable local implementation, not the later incremental segment or compaction design.

Publication serializes writers and readers with a stable `flock` file. A writer validates private output, syncs the generation file, renames the ready generation, syncs the store directory, writes and syncs a private pointer, atomically renames `CURRENT`, syncs the directory, then reopens the committed generation. The crash-window tests exit separate child processes at partial/full data write, validation, data sync, ready-generation publication, pointer sync, pointer rename, and directory sync. Initial creation, update, and tombstone crashes are checked; update/tombstone recovery compares complete result views and live statistics against independent expected records. A follow-up publication removes or replaces unreferenced output without promoting it. Before pointer rename, reopening returns the old generation for updates and tombstones; during initial creation it returns an incomplete-store error. At or after pointer rename, reopening sees the new complete generation on the running OS. These tests terminate a process, not the kernel or storage device, so they do not establish hardware power-loss recovery.

The crash/reopen tests ran on Linux 7.2.9 over Btrfs. The first adapter supports Linux on a local filesystem with working `flock`, same-directory atomic rename, file `fsync`, and directory `fsync`. Other operating systems and network filesystems are unsupported until separately verified. The existing Gate 0 corpus verifier and Gate 1 demo remain independent of the storage library.

### Gate 4 Controlled Crawler 0.4

Run the controlled path with:

```sh
cargo run --locked -- controlled-demo
```

This command binds a fixture listener on loopback and explicitly admits its exact origin and `/` path scope. A capability is tied to the owned listener and expires when the fixture stops. The transport resolves each request and redirect hop, rejects the complete DNS answer set if any answer differs from that listener, accepts at most 16 DNS answers, pins the validated loopback address into a fresh HTTP client, disables proxies and automatic redirects, and checks the response-header, wire-body, and decompressed-body bounds before extraction. Every page and robots hop sends `LeyBot/<package-version>` as its User-Agent. No public or third-party hostname is authorized by this implementation.

Resolution runs through a fixed four-worker pool with a queue of 16 and shares the request deadline with connect and response reads. A timed-out resolver cannot create a later connection. A resolver call blocked indefinitely can consume one fixed worker; after the bounded pool and queue fill, new resolutions fail closed. This implementation does not claim public-address validation because Gate 4 has no public-fetch mode. Its demonstrated destination guarantee is limited to owned loopback listeners and their exact ports.

The crawl frontier and outbox live in a private SQLite file using `journal_mode=DELETE`, `synchronous=FULL`, and an 8,192-page database cap (about 32 MiB with SQLite's default 4 KiB pages). The frontier persists source policy, URL key, current fetch URL, due time, schedule ID, attempts, conditional validators, redirect chain, 404 observations, lifecycle state, and reason events. A source must be explicitly admitted with the local-fixture rights basis, exact owned origins, path prefixes, a validity deadline, retention policy, and request budget. Validity or retention expiry publishes revocation tombstones. Readmission is explicit and gets new index fences before any later upsert.

One process owns a frontier at a time through a stable lifetime OS lock. Before schema migration or lease recovery, an existing frontier's persisted index-store identity is checked against the opened index, so a mismatched store is rejected without mutating the frontier. Startup expires sources before replaying pending work; replay checks the current lifecycle and deadlines again at the index apply boundary. Revocation and readmission publish durable per-URL control intents in 128-row batches and continue reconciling until every affected frontier row is settled. Replay drains 256-row pages until no pending intents remain. Control insertion can reclaim the oldest completed outbox rows only when row or payload-byte capacity requires it; pending work and the index's terminal fence history are retained. The event log is a bounded ring that removes its oldest event when full.

The scheduler round-robins due origins, keeps one coordinator job active per origin, and allows at most four fetch workers globally. Workers also enforce a two-request per-origin cap across redirected robots hops. Defaults are 256 requests per run, 60 seconds runtime, 2 seconds per request, three page retries, ten page redirect hops, five robots redirect hops, and 512 requests per admitted source. `Retry-After` and exponential backoff are bounded to one hour. Recrawl is scheduled after 24 hours. Response headers are capped at 32 KiB and 128 values; transport reads are capped at 2 MiB on the wire and 8 MiB after gzip decoding; one run is capped at 64 MiB wire and 128 MiB decoded. The existing HTML extractor and robots parser each accept at most 2 MiB after HTTP content decoding, so the 8 MiB transport limit is only a decompression safety bound. Ingestion of decoded page bodies between 2 and 8 MiB is unsupported. The coordinator reserves each in-flight request's maximum response allowance before dispatch, and returns a capacity error before opening another request when no full response allowance remains for due work. A loopback test uses a smaller deterministic run budget and observes the next page receive no connection. The persistent frontier holds at most 10,000 URL keys, the outbox at most 10,000 rows/16 MiB, the structured event log at most 100,000 rows, and persistent robots bodies at most 8 MiB. These are fixture-crawl limits, not a public crawl capacity claim.

Worker threads are joined before the run returns, including when the SQLite result handler fails. That failure path cancels other workers first; the owned delayed-redirect fixture verifies that no later hop is connected after return. A blocked socket read is not forcibly interrupted and can delay the return up to the bounded request deadline.

The parser implements exact case-insensitive product-token groups, merges every matching named group, uses wildcard groups only when there is no named match, handles Allow/Disallow specificity and tie behavior, and normalizes percent-encoded and literal special bytes. The parser accepts up to 2 MiB rather than silently truncating. These exact fixture decisions are covered by Rust tests:

| Fixture | Expected LeyBot decision |
| --- | --- |
| `User-agent: *` / `Disallow: /blocked`, followed by an empty `User-agent: LeyBot` group at EOF | `/blocked/a` is allowed for LeyBot because the empty named group suppresses wildcard fallback; the same path is denied for OtherBot. |
| `User-agent: LeyBotExtra` / `Disallow: /private` | `/private/a` is allowed for LeyBot and denied for LeyBotExtra; matching is not substring-based. |
| A valid `Disallow: /private` followed by invalid `Allow: */private`; invalid non-slash patterns and product tokens; empty patterns; repeated exact groups | The invalid lines do not override or split valid rules. Empty patterns add no restriction, and repeated exact groups combine their rules. |
| `/Case`, `/foo%2Fbar`, `/path/%2A`, and `/path/foo-%24` disallow rules | `/case` remains allowed; `/foo%2Fbar` is denied while `/foo/bar` is allowed; literal `/path/*` and `/path/foo-$` are denied while `/path/anything` and `/path/foo-X` are allowed. |
| `Disallow: /*foo$` and `Disallow: /*foo` | The anchored rule denies `/foofoo` after retrying the later suffix occurrence; the unanchored rule also denies `/foofoo.txt`. The matcher has a fixed work budget and fails closed if it is exhausted. |
| CR-only lines with malformed directives between valid rules | The malformed lines do not discard the parseable `/first` and `/second` rules on either side. |
| Exactly 500 KiB of robots input; then a second input with `Disallow: /late` after byte 500 KiB | The boundary-sized body parses, and the later `/late` rule is still applied. |
| `http://127.0.0.1:<port>/robots.txt` redirects through `robot-hop-1.fixture.test` … `robot-hop-5.fixture.test`, ending in `Disallow: /` | All six owned socket accepts are observed, no page request is made, and the resulting rules are cached to the original `127.0.0.1` authority. |
| A sixth robots redirect, an unadmitted target, or a changed DNS answer during page/robots redirect | The sixth hop is never requested; the unadmitted and changed-answer listeners observe zero connections. Safe redirect resolution is checked again at each hop. |

Robots cache lifetime honors the smallest valid `max-age`, subtracts `Age`, supports `Expires`, defaults to one hour, and caps freshness at 24 hours. `no-cache` and zero freshness are persisted only for conditional revalidation; the fetched rules are used for the one scheduled URL that triggered the request, then the next URL must revalidate. `no-store` is neither persisted nor reused: its rules are used for only the one scheduled URL that triggered the request, and the next URL or restart fetches robots again. A stale body is never used after a failed refresh. Network errors, unsafe or unadmitted redirects, and robots HTTP failures (including 4xx, under this stricter policy) deny the origin and retry with bounded backoff. A successful cross-authority redirect still stores and applies the fetched rules under the original requesting authority.

Page policy combines repeated `X-Robots-Tag` fields independently, applies the finite generic/`LeyBot:` scope grammar, and reads `robots` and `LeyBot` meta directives from the existing HTML extractor. `noindex` and `none` publish tombstones; `nofollow` indexes the page but queues no links. HTTP 410 removes immediately. A 404 retains the prior visible version until a second, separately scheduled 404; an accepted redirect stays in that schedule, while a terminal non-404 HTTP response clears the earlier 404 evidence. A 304 reuses the complete representation from one pinned `ReadView`; without a stored representation it retries unconditionally. Transient HTTP and transport failures retain the prior visible version.

Response-header restrictions are applied before 304 reuse and before rejecting unsupported, oversized, malformed, or unreadable page bodies. A validated 410 still removes at once. For a 304 or 2xx response, a recognized `noindex` removes a previously visible document even when the body exceeds a transport bound or fails gzip decoding. Incomplete bodies never reach extraction. A 2xx body read or decoding failure without a removal signal retains the prior version and retries; resolution and connection failures remain distinct because no HTTP response metadata exists. `noindex` alone still hands off admitted links through the durable completion intent when extraction succeeds; `nofollow` or `none` suppresses discovery. Each new scheduled fetch starts again at the requested URL key, so a changed redirect target is observed on recrawl. The fixture suite also checks that invalid userinfo, malformed escapes, unsupported schemes, and URL keys over 2,048 bytes stop before a redirect-target connection. Link handoff records one bounded count event for enqueued, source-denied, duplicate, malformed, and capacity-skipped links.

Each complete page intent (including extracted fields, links, validators, terminal state, and completion metadata) is committed to the SQLite outbox before `PersistentIndex::apply`. The stores cannot transact together. A crash after the outbox commit but before `CURRENT` publication leaves a replayable intent and the previous index generation visible until recovery replays it. A crash after `CURRENT` publication but before SQLite acknowledgement causes an exact index replay (`AlreadyApplied`) and then an outbox acknowledgement without republishing. A crash while only a network lease is active resets that frontier row to ready; the replacement fetch receives a higher index fence. Stale, conflicting, and revoked upserts are recorded as rejected, never as successful completion. Revocation rejects pending automatic upserts before publishing tombstones, and recovery remains blocked until explicit readmission. Gate 3's atomic `CURRENT` switch and pinned query snapshots remain the search visibility boundary. These process-exit tests establish restart behavior on the running OS; they are not hardware power-loss tests or a distributed transaction guarantee.

An owned process-exit fixture interrupts a 257-URL source revocation before the first index publication while the SQLite outbox and event ring are at their configured capacities. Both documents in the old generation remain visible at that crash seam. A fresh process replays every tombstone across multiple batches, leaving the unrelated sentinel document live, while the old pinned view still returns both documents. The test then explicitly readmits the same 257 URLs across multiple batches before another restart. The current index generation remains the only search visibility boundary; SQLite state and index publication are separate failure domains, so an index publication can succeed before its frontier acknowledgement is durable.

Cancellation stops new dispatch and waits for already-running requests to finish or hit their request timeout; it does not forcibly interrupt a socket read. The crawler has no external-source mode, HTTP API, UI, JavaScript execution, HTTPS mode, content redistribution policy, or external corpus/performance/relevance evidence. The Gate 1 and Gate 4 demos use separate crawler paths and the same Ley-owned extractor/analyzer/index pipeline.

Run the storage checks and existing milestone checks from the repository root:

```sh
cargo test --locked storage::tests
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
python3 tools/verify_reference_corpus.py
cargo run --locked --quiet -- demo --query 'Rust OR Ley' --explain
cargo run --locked -- controlled-demo
```

The multi-process lifecycle test creates and mutates a store in one child, restores exported leases in a second child, and compares the final reopen against hard-coded live records. It checks versions, match evidence, explanations, exact unrounded optimized scores, ties, phrase/AND/OR behavior, and uses the existing document-scan evaluator for independent match and score parity. It asserts that the empty live document remains in N and averages while removed and superseded terms leave matches and document frequencies. The crash matrix compares complete prior/new views, including live N, field averages and document frequencies, and checks exact terminal replay after recovery.

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
