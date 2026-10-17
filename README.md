# Ley

Ley is a single-machine search engine built around its own crawler policy, HTML extraction, text analysis, positional index, query evaluator, and BM25 ranking. Rust libraries provide HTTP/TLS, HTML parsing, persistence primitives, and the local API framework. The browser interface uses React and TypeScript.

Gates 0 through 5 are accepted. The checked-in public policy remains disabled. A bounded collection demonstrated a three-page Rust documentation index on 2026-10-14. Its original temporary corpus and runtime artifacts are now unavailable; the historical acceptance is retained with this limitation. The original request budget is unavailable, and no further public requests are authorized.

## Run a local search

Install Rust 1.88 or newer, Node.js with npm, and Python 3.10 or newer. From the repository root, create an authored local fixture index and query it:

```sh
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

`verify:browser` checks UI states with authored responses and raw local-server requests. It is an adapter check. `verify:e2e` runs Chromium through the real UI server and Rust API against a persistent authored fixture index, checks full CLI/API JSON equality, exercises hostile Host and Origin headers, verifies malformed-request recovery, and saves desktop and mobile screenshots under `/tmp`. It does not mock `fetch`, intercept browser requests, or contact public websites. To inspect an available authored fixture index in Chromium, start `serve` with its `LEY_STORE`, start the UI as shown above, and open `http://127.0.0.1:4173`. A real Chromium session searched the public collection through the UI server and API on 2026-10-14; those original runtime artifacts are now missing. The checks above verify authored local fixtures and do not recover or replace the historical public evidence. The automated `verify:e2e` corpus remains synthetic. Both browser commands need local Chromium and loopback sockets. The TLS transport tests need OpenSSL to create owned local certificates.

The reference verifier checks its finite authored corpus. It is not a general web crawler or relevance evaluation. No search-quality or performance claims are made.

## Public collection policy

`policy/public-sources.json` remains disabled. Its only entry covers three exact plain-text Rust standard-library pages: [`String`](https://doc.rust-lang.org/stable/std/string/struct.String.html), [`HashMap`](https://doc.rust-lang.org/stable/std/collections/struct.HashMap.html), and [`Iterator`](https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html). Read-only licensing research on 2026-10-14 inspected those pages and Rust's [official licensing page](https://rust-lang.org/policies/licenses/), linked from the [Rust policy page](https://rust-lang.org/policies/). The licensing page says official Rust projects, including the website, are generally dual-licensed Apache-2.0 OR MIT. The reviewed candidate selects MIT and records fetch, storage, index, and display license bases. This is a license basis, not a signed permission statement or legal certification.

The hosted pages report `rustdoc 1.99.0 (b940084d7, 2026-09-28)`. The installed Rust 1.97.0 toolchain notice is separate attribution evidence and is not treated as the hosted pages' revision. The full copyright and MIT permission notice is in [`notices/rust-stdlib-documentation-MIT.txt`](notices/rust-stdlib-documentation-MIT.txt). The UI links to that notice, and an admitted store receives a private copy before the crawler can admit a source. Results link to their source pages. The candidate excludes images, logos, and third-party material.

On 2026-10-14, one bounded collection ran with a private enabled copy of the reviewed policy in two invocations. The first fetched only `robots.txt` and made no page progress because the scheduler stopped at the one-second origin delay. After that scheduler defect was corrected, a three-request continuation used the same store and frontier to fetch the admitted pages over validated HTTPS. All four responses returned HTTP 200. The robots response body measured 382 wire bytes and 382 decoded bytes. The three page bodies measured 159,419 wire bytes and 1,581,999 decoded bytes together. Across both invocations, body totals were 159,801 wire bytes and 1,582,381 decoded bytes. These counts exclude headers and TLS or protocol framing.

The crawl accepted 3 pages and reported 0 failed, rejected, or page-skipped candidates. Link discovery processed 1,037 candidates: 1,033 were denied by source scope, 4 were already in the frontier, and 0 were enqueued, malformed, or withheld by capacity. HTML extraction also reported 6,503 duplicate links. That extraction count is separate from the frontier and source-scope outcomes. The run stopped at `frontier_idle`; it did not follow the sitemap hint or discover more sources. The historical index was generation 7 with corpus size 3. CLI and API returned identical JSON for the `String`, `HashMap`, and `Iterator` queries. A real Chromium session displayed those results from the same index.

The source has a lifetime request limit of 6, and the collection used 4 requests, including `robots.txt`. Two requests were recorded as unused when collection stopped. Because the persisted counter is now missing, the original request budget is unavailable; it must not be reset or reused. The three pages became due for their normal 24-hour recrawl, but no recrawl has run. The checked-in policy remains disabled. The crawler fails closed if it cannot fetch and parse robots rules, and it checks page and robots redirects against admitted paths and pinned network destinations.

The candidate allows at most six source-lifetime HTTP requests, uses a one-second per-origin delay, and limits each invocation to 12 MiB of response-body wire bytes, 32 MiB of decoded bytes, and 60 seconds. It caps each index generation at 512 MiB, the frontier at 10,000 URLs, the outbox at 10,000 rows or 16 MiB, and stored robots data at 8 MiB. Body-byte counts exclude headers and TLS or protocol framing. The explicit `crawl-public` command requires an enabled policy, its exact reviewed SHA-256, and `--allow-public-requests`. The checked-in disabled policy cannot start a crawl. Reports include `stopReason` and `boundedRunFinished`; the command exits unsuccessfully when a request, byte, runtime, source budget, source deadline, or progress limit stops the run.

Before public content can enter an index, Ley writes a store-bound authenticated retention record and a private copy of the full source notice. `ReadView`, the API, and the CLI refuse search after the earlier of the 30-day collection-retention deadline and the policy expiry. Reads do not trigger crawling or mutate the index. Run `revoke-source` for explicit local tombstone maintenance. An expired store remains closed to search after tombstoning. Tombstones remove results from the current generation, but prior generations, outbox rows, and robots records may retain private bytes. Gate 5 does not provide physical erasure or compaction. Sources that require physical erasure remain excluded.

The crawler identifies itself as `LeyBot/0.1.0 (+https://github.com/Suraj-H675/Ley/issues)` and uses `LeyBot` as its robots token. Website owners can submit crawling exclusions, content-removal requests, and crawler concerns through the [Ley issue tracker](https://github.com/Suraj-H675/Ley/issues). Issues are public, so do not include sensitive information. Ley makes no response-time guarantee.

Source revocation was tested on an isolated copy of the collected store. That copy published generation 13 with corpus size 0 and no search results. The original generation 7 collection remained unchanged during that historical test. Neither that original collection nor the temporary removal copy is currently available.

## Current limits

The persistent index publishes whole generations. It does not use incremental segments or compaction. The API returns at most 20 results from one pinned generation and caps query and response sizes. The local interface is not an internet-facing service. Public crawling is paused, and no further request is authorized. Gate 5 is accepted on the historical independent review record, with the documented runtime-artifact loss explicitly accepted for publication on 2026-10-17. This does not authorize a replacement crawl. The reproducible local fixture checks remain available.

## Licensing

The Ley source-code license has not been selected. Authored reference fixtures use CC0-1.0 as stated in `fixtures/LICENSE.txt`. Crawled pages, indexes, caches, snippets, and crawler logs remain outside Git.

Gate 5 implementation used OpenAI Codex with the Poteto workflow. The independent project reviewer accepted Gate 5.
