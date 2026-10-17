# Ley

Ley is a single-machine search engine built around its own crawler policy, HTML extraction, text analysis, positional index, query evaluator, and BM25 ranking. Rust libraries provide HTTP/TLS, HTML parsing, persistence primitives, and the local API framework. The browser interface uses React and TypeScript.

Gates 0 through 6 are accepted. Gate 6 was independently verified with authored local fixtures, incremental file hashes, reference comparisons, process-crash recovery, and the real CLI, API, and browser interface. The checked-in public policy remains disabled. A bounded collection demonstrated a three-page Rust documentation index on 2026-10-14. Its original temporary corpus and runtime artifacts are now unavailable; the historical acceptance is retained with this limitation. The original request budget is unavailable, and no further public requests are authorized.

## Run a local search

Install Rust 1.88 or newer, Node.js with npm, and Python 3.10 or newer. From the repository root, create an authored local fixture index and query it:

```sh
mkdir -p target/ley-fixture
cargo run --locked -- fixture-index --store target/ley-fixture/index
cargo run --locked -- search --store target/ley-fixture/index --query 'rust AND retrieval'
export LEY_STORE=target/ley-fixture/index
```

`search` opens one persistent generation and prints JSON with the generation ID, result ordering, unrounded scores, match evidence, and score explanations. The fixture index contains only authored local text.

The original Rust documentation index, frontier, robots cache, request counter, raw reports, and browser artifacts were kept under temporary storage outside Git and are no longer available. They were not recovered or recreated. The historical public-corpus demonstration cannot currently be repeated against that original state. For an existing independently available store containing the relevant terms, the search commands are:

```sh
export LEY_STORE=/path/to/private/index
cargo run --locked -- search --store "$LEY_STORE" --query 'String'
cargo run --locked -- search --store "$LEY_STORE" --query 'HashMap'
cargo run --locked -- search --store "$LEY_STORE" --query 'Iterator'
```

In the historical demonstration, the collected index was generation 7 with corpus size 3. `String` ranked its page first, followed by `HashMap` and `Iterator`. `Iterator` ranked its page first, followed by `String` and `HashMap`. The `HashMap` query returned its page. These are historically observed results for that small corpus, not current verification or a search-quality claim. To use the reproducible authored fixture with the API and UI below, keep `LEY_STORE=target/ley-fixture/index` instead of the illustrative private-store path.

Start the read-only API over the authored fixture in one terminal:

```sh
export LEY_STORE=target/ley-fixture/index
cargo run --locked -- serve --store "$LEY_STORE" --bind 127.0.0.1:7331
```

The default bind address is `127.0.0.1:7331`. The API exposes `GET /api/health` and `GET /api/search?q=...`. It accepts local Host and same-origin requests, returns bounded search responses, and has no crawl, write, administration, or caller-selected store-path route. For example:

```sh
curl 'http://127.0.0.1:7331/api/search?q=rust'
```

In another terminal, build and start the browser interface:

```sh
cd ui
npm ci
npm run dev
```

Open `http://127.0.0.1:4173`. The UI proxies searches to the local API on port 7331. Set `LEY_API_PORT` or `LEY_UI_PORT` to use other loopback ports. The UI displays real persistent-index results, plain-text source prefixes, snapshot identity, and expandable ranking explanations. Snippets are bounded source prefixes, not query-aware passages. Result links are limited to HTTP and HTTPS URLs.

The fixture crawler remains available through `cargo run --locked -- controlled-demo`. The original in-memory demo remains available through `cargo run --locked -- demo --query 'Rust OR Ley' --explain`. Both use authored loopback pages and do not contact public hosts.

## Verify local behavior

Run the Rust suite, formatter, lint checks, finite reference verifier, UI build, and browser checks from the repository root:

```sh
cargo test --locked --offline -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
python3 tools/verify_reference_corpus.py
cd ui
npm run build
npm run verify:browser
npm run verify:e2e
```

`verify:browser` checks UI states with authored responses and raw local-server requests. It is an adapter check. `verify:e2e` runs Chromium through the real UI server and Rust API against the same persistent authored fixture index, checks full CLI/API JSON equality, exercises hostile Host and Origin headers, verifies malformed-request recovery, and saves desktop and mobile screenshots under `/tmp` by default. Its raw HTTP checks send requests without half-closing the client, dispose each socket, and reject EOF, socket errors, and incomplete responses after a four-second absolute response deadline. Set `LEY_E2E_STORE_PATH` and `LEY_E2E_ARTIFACT_DIR` to retain the fixture and screenshots elsewhere; set `LEY_E2E_REUSE_STORE=1` when reusing an existing fixture. `LEY_E2E_API_PORT` and `LEY_E2E_UI_PORT` can select caller-available loopback ports. The real browser path does not mock `fetch`, intercept browser requests, or contact public websites. A real Chromium session searched the public collection through the UI server and API on 2026-10-14; those original runtime artifacts are now missing. The checks above verify authored local fixtures and do not recover or replace the historical public evidence. The automated `verify:e2e` corpus remains synthetic. Both browser commands need local Chromium and loopback sockets. The TLS transport tests need OpenSSL to create owned local certificates.

## Incremental index (Gate 6)

Gate 6 replaces whole-generation posting rebuilds with Ley-owned immutable segments. Each newly applied upsert appends one field-separated positional segment; update and removal change the manifest's live URL-key references and exact live document-frequency and token statistics. An update leaves its old segment intact until compaction. Queries use the manifest pinned by one `ReadView`, filter postings by exact `(segment, ordinal, version)` identity, and combine only the requested terms for evaluation. The positional codec is `position-gap-uvarint-v1`: canonical unsigned LEB128 gaps encode sorted local ordinals and separate title and body positions.

Writers serialize through a per-handle mutex and an exclusive cross-process `flock`, then reload the current manifest before changing it. Readers use a shared lock while loading and validating the manifest and its referenced segments. A read view then owns a fully decoded immutable snapshot, so it continues to return the original results after publication or compaction removes the source files. Compaction is explicit and merges the current segments into one replacement, preserving visible results and exact live statistics. No background or automatic compaction runs.

Gate 6 uses versioned `STORE`, `CURRENT`, manifest, and segment files. `CURRENT` is the visibility point: segment and manifest files are bounded, checked, file-synced and renamed before the pointer is synced and renamed. Before that rename, restart uses the old committed manifest and ignores incomplete outputs. After it, restart validates the new manifest and all referenced segments; the next successful writer can remove unreferenced Gate 6 outputs. Cleanup errors after pointer publication can leave harmless orphan files. Child-process termination checks cover these process-crash paths; they do not establish hardware power-loss guarantees.

Gate 3 stores are not opened as Gate 6. The migration command validates the old store and writes a separate, absent destination while keeping the source untouched:

```sh
# Stop every process that can write the old store first.
cargo run --locked -- reindex-gate3 --source /path/to/gate3-store --destination /path/to/gate6-store
cargo run --locked -- search --store /path/to/gate6-store --query 'rust'
```

Migration preserves the store identity, lease MAC key, lifecycle history, current live documents, public-collection record, and notice bytes so pending fence tokens remain usable. The destination parent must already exist, and its canonical path must be outside the canonical source directory. Nested paths, `..` aliases, and symlink-parent aliases into the source fail before staging begins. On Linux, the final directory publication uses `renameat2(RENAME_NOREPLACE)`: a file, directory, or symlink created at the destination during migration remains untouched and migration returns an error. Other platforms fail closed without a replacing-rename fallback. Verify the destination before switching the configured store path. Do not keep both paths active as writers. Normal errors remove only the staging directory created by that migration attempt; a process termination before final publication can leave a uniquely named `.ley-reindex-*` staging directory beside the destination. Inspect that owned staging output before removing it or retrying. The original Gate 3 source remains available for a safe retry.

Run explicit compaction after enough updates or removals have accumulated stale postings, or when a capacity error recommends it:

```sh
cargo run --locked -- compact --store "$LEY_STORE"
```

The format caps each manifest at 128 MiB, each segment at 512 MiB and 100,000 documents, the active segment set at 512 MiB, active segment descriptors at 4,096, physical postings at 4 million, and positions at 50 million. A proposed write recommends `ley compact --store <store-path>` when merging active segments can reduce the descriptor count, even if every document is live. For the active byte limit, compaction helps when stale entries or segment overhead account for the excess; physical posting and position limits recommend it only when obsolete entries may account for the excess. Compaction does not reduce the live-document limit (100,000), live posting-record limit (1 million), live term limit (500,000), retained lifecycle-control-key limit (100,000), or the separate terminal and policy history limits (500,000 events each). Those caps preserve bounded live corpus and lifecycle history; errors do not claim compaction will resolve them. The 128 MiB serialized manifest cap also does not make a general compaction recommendation.

Snapshot admission checks a conservative 3 GiB decoded-memory estimate before loading segments. It is an admission bound, not an operating-system RSS guarantee; distinct retained snapshots multiply memory, while cloned `ReadView`s share their `Arc` snapshot. Cold snapshot loading still rereads each referenced segment, reanalyzes its stored title and body, decodes its persisted postings, and validates exact token positions. Validation retains one posting map plus bounded term/posting references (at most the 4-million physical-record limit) and one document-local expected-position map; it does not rebuild or serialize a monolithic index from stored documents. Decoded segments are not cached between new snapshots. These are safety bounds, not expected corpus sizes. A compaction may temporarily need disk space for a replacement segment alongside the existing active segments. No speedup or benchmark claim is made.

The incremental byte/hash proof, crash checks, compatibility fixture, migration source inventory, and browser artifacts for this implementation are kept in the ignored `.audit/gate6-20261017/` directory. Reproduce the segment inventory proof with:

```sh
mkdir -p .audit/gate6-20261017
LEY_GATE6_EVIDENCE_OUT=.audit/gate6-20261017/incremental-index-inventory.json \
  cargo test --locked --offline storage::tests::append_update_remove_and_compaction_preserve_hashes_and_full_reference_results -- --nocapture
```

For a browser run against one retained fixture index through both the Rust API and React UI, use an unused store path on the first run, then add `LEY_E2E_REUSE_STORE=1` on later runs:

```sh
mkdir -p .audit/gate6-20261017/private-fixtures
npm run --prefix ui build
LEY_E2E_STORE_PATH=.audit/gate6-20261017/private-fixtures/browser-index \
LEY_E2E_REUSE_STORE=1 \
LEY_E2E_ARTIFACT_DIR=.audit/gate6-20261017/browser \
  node ui/scripts/verify-http-e2e.mjs
```

The script saves `results.json` and Chromium screenshots in the selected artifact directory. It makes no public requests. For bounded reruns against an existing fixture, keep `LEY_E2E_REUSE_STORE=1`; the script refuses to overwrite an existing path without it.

The shipped script was independently run with real Chromium against the retained fixture index at generation 8 through the React UI and Rust API. Its screenshots and `results.json` are under `.audit/gate6-20261017/work-final/browser`. Earlier sandbox-blocked attempts remain part of the historical trail; they do not describe the later verified run.

The reference verifier checks its finite authored corpus. It is not a general web crawler or relevance evaluation. No search-quality or performance claims are made.

## Public collection policy

`policy/public-sources.json` remains disabled. Its only entry covers three exact plain-text Rust standard-library pages: [`String`](https://doc.rust-lang.org/stable/std/string/struct.String.html), [`HashMap`](https://doc.rust-lang.org/stable/std/collections/struct.HashMap.html), and [`Iterator`](https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html). Read-only licensing research on 2026-10-14 inspected those pages and Rust's [official licensing page](https://rust-lang.org/policies/licenses/), linked from the [Rust policy page](https://rust-lang.org/policies/). The licensing page says official Rust projects, including the website, are generally dual-licensed Apache-2.0 OR MIT. The reviewed candidate selects MIT and records fetch, storage, index, and display license bases. This is a license basis, not a signed permission statement or legal certification.

The hosted pages report `rustdoc 1.99.0 (b940084d7, 2026-09-28)`. The installed Rust 1.97.0 toolchain notice is separate attribution evidence and is not treated as the hosted pages' revision. The full copyright and MIT permission notice is in [`notices/rust-stdlib-documentation-MIT.txt`](notices/rust-stdlib-documentation-MIT.txt). The UI links to that notice, and an admitted store receives a private copy before the crawler can admit a source. Results link to their source pages. The candidate excludes images, logos, and third-party material.

On 2026-10-14, one bounded collection ran with a private enabled copy of the reviewed policy in two invocations. The first fetched only `robots.txt` and made no page progress because the scheduler stopped at the one-second origin delay. After that scheduler defect was corrected, a three-request continuation used the same store and frontier to fetch the admitted pages over validated HTTPS. All four responses returned HTTP 200. The robots response body measured 382 wire bytes and 382 decoded bytes. The three page bodies measured 159,419 wire bytes and 1,581,999 decoded bytes together. Across both invocations, body totals were 159,801 wire bytes and 1,582,381 decoded bytes. These counts exclude headers and TLS or protocol framing.

The crawl accepted 3 pages and reported 0 failed, rejected, or page-skipped candidates. Link discovery processed 1,037 candidates: 1,033 were denied by source scope, 4 were already in the frontier, and 0 were enqueued, malformed, or withheld by capacity. HTML extraction also reported 6,503 duplicate links. That extraction count is separate from the frontier and source-scope outcomes. The run stopped at `frontier_idle`; it did not follow the sitemap hint or discover more sources. The historical index was generation 7 with corpus size 3. CLI and API returned identical JSON for the `String`, `HashMap`, and `Iterator` queries. A real Chromium session displayed those results from the same index.

The source has a lifetime request limit of 6, and the collection used 4 requests, including `robots.txt`. Two requests were recorded as unused when collection stopped. Because the persisted counter is now missing, the original request budget is unavailable; it must not be reset or reused. The three pages became due for their normal 24-hour recrawl, but no recrawl has run. The checked-in policy remains disabled. The crawler fails closed if it cannot fetch and parse robots rules, and it checks page and robots redirects against admitted paths and pinned network destinations.

The candidate allows at most six source-lifetime HTTP requests, uses a one-second per-origin delay, and limits each invocation to 12 MiB of response-body wire bytes, 32 MiB of decoded bytes, and 60 seconds. It caps each index generation at 512 MiB, the frontier at 10,000 URLs, the outbox at 10,000 rows or 16 MiB, and stored robots data at 8 MiB. Body-byte counts exclude headers and TLS or protocol framing. The explicit `crawl-public` command requires an enabled policy, its exact reviewed SHA-256, and `--allow-public-requests`. The checked-in disabled policy cannot start a crawl. Reports include `stopReason` and `boundedRunFinished`; the command exits unsuccessfully when a request, byte, runtime, source budget, source deadline, or progress limit stops the run.

The per-origin delay, capped at the crawler's one-hour delay ceiling, is a quiet period after the complete response has been read. DNS and TLS setup therefore cannot consume it. Requests with a nonzero delay are serialized for that origin through response completion; zero-delay requests retain the configured concurrency cap. Completion timing is persisted for page and robots work. On restart, abandoned page fetches and version-5 robots refreshes receive a fresh quiet period; robots recovery covers the dispatch-time snapshot of every origin admitted for redirects. Opening a version-4 crawler frontier adds the version-5 in-flight robots table without deleting existing frontier, policy, cache, or outbox rows. Version 4 did not persist robots in-flight state, so an interrupted robots request from before that upgrade cannot be identified retrospectively. Restart timing uses persisted wall-clock milliseconds, so system clock changes can affect the wait.

Before public content can enter an index, Ley writes a store-bound authenticated retention record and a private copy of the full source notice. `ReadView`, the API, and the CLI refuse search after the earlier of the 30-day collection-retention deadline and the policy expiry. Reads do not trigger crawling or mutate the index. Run `revoke-source` for explicit local tombstone maintenance. An expired store remains closed to search after tombstoning. Tombstones remove results from the current generation, but prior generations, outbox rows, and robots records may retain private bytes. Gate 5 does not provide physical erasure or compaction. Sources that require physical erasure remain excluded.

The crawler identifies itself as `LeyBot/0.1.0 (+https://github.com/Suraj-H675/Ley/issues)` and uses `LeyBot` as its robots token. Website owners can submit crawling exclusions, content-removal requests, and crawler concerns through the [Ley issue tracker](https://github.com/Suraj-H675/Ley/issues). Issues are public, so do not include sensitive information. Ley makes no response-time guarantee.

Source revocation was tested on an isolated copy of the collected store. That copy published generation 13 with corpus size 0 and no search results. The original generation 7 collection remained unchanged during that historical test. Neither that original collection nor the temporary removal copy is currently available.

## Current limits

The API returns at most 20 results from one pinned generation and caps query and response sizes. The local interface is not an internet-facing service. Public crawling is paused, and no further request is authorized. Gate 5 is accepted on the historical independent review record, with the documented runtime-artifact loss explicitly accepted for publication on 2026-10-17. This does not authorize a replacement crawl. The reproducible local fixture checks remain available.

## Licensing

The Ley source-code license has not been selected. Authored reference fixtures use CC0-1.0 as stated in `fixtures/LICENSE.txt`. Crawled pages, indexes, caches, snippets, and crawler logs remain outside Git.

Gate 5 and Gate 6 implementation used OpenAI Codex with the Poteto workflow. The independent project reviewer accepted both gates.
