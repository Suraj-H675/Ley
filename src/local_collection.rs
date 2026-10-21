use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::controlled_crawler::{
    ControlledCrawler, CrawlCancellation, CrawlLimits, FixtureLogicalClock, SourcePolicy,
};
use crate::crawler::{FixtureResponse, LocalFixture};
use crate::safe_fetch::{DestinationEvidence, SystemResolver};
use crate::storage::PersistentIndex;
use crate::url_key::UrlKey;

const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/stage-c-s1");
const COLLECTION_SCHEMA: &str = "ley-local-fixture-collection-v1";
const CLOCK_SCHEMA: &str = "ley-fixture-clock-v1";
const SOURCE_ID: &str = "stage-c-s1-asteria";
const SOURCE_REQUEST_BUDGET: u64 = 128;
const PER_RUN_REQUEST_BUDGET: usize = 96;
const PER_RUN_WIRE_BUDGET: usize = 16 * 1024 * 1024;
const PER_RUN_DECODED_BUDGET: usize = 32 * 1024 * 1024;
const MAX_RUNTIME: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const SOURCE_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_INPUT_FILE_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct CorpusManifest {
    schema_version: u32,
    collection_id: String,
    document_count: usize,
    profiles: BTreeMap<String, Profile>,
    pages: Vec<Page>,
    special_routes: Vec<SpecialRoute>,
}

#[derive(Clone, Debug, Deserialize)]
struct Profile {
    seed_ids: Vec<String>,
    link_discovery: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct Page {
    id: String,
    path: String,
    versions: BTreeMap<String, RouteVariant>,
}

#[derive(Clone, Debug, Deserialize)]
struct SpecialRoute {
    id: String,
    path: String,
    kind: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    v1: Option<RouteVariant>,
    #[serde(default)]
    v2: Option<RouteVariant>,
}

#[derive(Clone, Debug, Deserialize)]
struct RouteVariant {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionConfig {
    schema: String,
    collection_id: String,
    dataset_sha256: String,
    source_id: String,
    profile: String,
    origin: String,
    port: u16,
    store_identity: String,
    seed_urls: Vec<String>,
    link_discovery_enabled: bool,
    source_request_budget: u64,
    per_run_request_budget: usize,
    per_run_wire_budget_bytes: usize,
    per_run_decoded_budget_bytes: usize,
    max_runtime_seconds: u64,
    request_timeout_seconds: u64,
    source_valid_until_ms: u64,
    created_fixture_logical_ms: u64,
    time_basis: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureClockFile {
    schema: String,
    now_ms: u64,
    time_basis: String,
}

pub(crate) fn run_cli(args: &[String]) -> Result<String, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("fixture-collection requires init, run, or revoke".to_owned());
    };
    match command {
        "init" => run_init(&args[1..]),
        "run" => run_crawl(&args[1..]),
        "revoke" => run_revoke(&args[1..]),
        _ => Err(format!("unknown fixture-collection operation: {command:?}")),
    }
}

fn run_init(args: &[String]) -> Result<String, String> {
    let mut options = Options::parse(args, &["root", "profile", "port"], &[])?;
    let root = PathBuf::from(options.required("root")?);
    let profile_name = options.required("profile")?;
    let requested_port = options
        .take("port")
        .map(|value| {
            let port = value
                .parse::<u16>()
                .map_err(|_| "--port must be a nonzero TCP port".to_owned())?;
            if port == 0 {
                return Err("--port must be a nonzero TCP port".to_owned());
            }
            Ok(port)
        })
        .transpose()?;
    options.finish()?;

    let (manifest, dataset_sha256) = load_corpus()?;
    let profile = manifest
        .profiles
        .get(&profile_name)
        .ok_or_else(|| format!("unknown collection profile {profile_name:?}"))?;
    let root = prepare_new_root_path(&root)?;
    let routes = routes_for_revision(&manifest, "v1")?;
    let fixture = bind_fixture(requested_port, routes)?;
    let port = fixture.port();
    let origin = format!("http://127.0.0.1:{port}");

    fs::create_dir(&root)
        .map_err(|error| format!("could not create new collection workspace: {error}"))?;
    let root = fs::canonicalize(&root)
        .map_err(|error| format!("could not canonicalize collection workspace: {error}"))?;
    let store_path = root.join("store");
    let frontier_path = root.join("frontier.sqlite");
    let clock_path = root.join("fixture-clock.json");
    let config_path = root.join("collection.json");

    let now_ms = system_time_ms()?;
    let source_valid_until_ms = now_ms
        .checked_add(SOURCE_VALIDITY_MS)
        .ok_or_else(|| "source expiry time overflowed".to_owned())?;
    write_json_atomic(
        &clock_path,
        &FixtureClockFile {
            schema: CLOCK_SCHEMA.to_owned(),
            now_ms,
            time_basis: "fixture-logical".to_owned(),
        },
        false,
    )?;

    let index = Arc::new(
        PersistentIndex::create(&store_path)
            .map_err(|error| format!("could not create a new fixture index: {error}"))?,
    );
    let store_identity = hex(&index.store_identity());
    let mut crawler = ControlledCrawler::<SystemResolver, FixtureLogicalClock>::open_with_public(
        &frontier_path,
        Arc::clone(&index),
        SystemResolver,
        vec![fixture.capability()],
        Vec::new(),
        crawl_limits(),
        FixtureLogicalClock::new(now_ms),
    )
    .map_err(|error| format!("could not create the new controlled frontier: {error}"))?;
    let seed_urls = profile
        .seed_ids
        .iter()
        .map(|id| {
            let page = manifest
                .pages
                .iter()
                .find(|page| page.id == *id)
                .ok_or_else(|| format!("profile refers to an unknown seed {id:?}"))?;
            Ok(format!("{}{}", origin, page.path))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let seeds = seed_urls
        .iter()
        .map(|url| UrlKey::parse(url).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut policy = SourcePolicy::owned_fixture(
        SOURCE_ID,
        vec![origin.clone()],
        vec!["/".to_owned()],
        source_valid_until_ms,
    );
    policy.max_requests = SOURCE_REQUEST_BUDGET;
    crawler
        .admit_source(policy, &seeds)
        .map_err(|error| format!("could not admit the owned fixture source: {error}"))?;

    let config = CollectionConfig {
        schema: COLLECTION_SCHEMA.to_owned(),
        collection_id: manifest.collection_id.clone(),
        dataset_sha256: dataset_sha256.clone(),
        source_id: SOURCE_ID.to_owned(),
        profile: profile_name.clone(),
        origin: origin.clone(),
        port,
        store_identity: store_identity.clone(),
        seed_urls: seed_urls.clone(),
        link_discovery_enabled: profile.link_discovery,
        source_request_budget: SOURCE_REQUEST_BUDGET,
        per_run_request_budget: PER_RUN_REQUEST_BUDGET,
        per_run_wire_budget_bytes: PER_RUN_WIRE_BUDGET,
        per_run_decoded_budget_bytes: PER_RUN_DECODED_BUDGET,
        max_runtime_seconds: MAX_RUNTIME.as_secs(),
        request_timeout_seconds: REQUEST_TIMEOUT.as_secs(),
        source_valid_until_ms,
        created_fixture_logical_ms: now_ms,
        time_basis: "fixture-logical".to_owned(),
    };
    write_json_atomic(&config_path, &config, false)?;
    let source_url_keys = known_source_urls(&manifest, &origin);
    let output = serde_json::json!({
        "schema": "ley-local-collection-init-v1",
        "processId": std::process::id(),
        "workspace": root,
        "collectionId": manifest.collection_id,
        "profile": profile_name,
        "sourceId": SOURCE_ID,
        "origin": origin,
        "port": port,
        "sourceUrlKeys": source_url_keys,
        "seedUrlKeys": seed_urls,
        "storeIdentity": store_identity,
        "datasetSha256": dataset_sha256,
        "ownedListener": "127.0.0.1 bound from the listener whose live capability was passed to SafeFetcher",
        "linkDiscoveryEnabled": profile.link_discovery,
        "budgets": budgets_json(),
        "fixtureClock": {"path": clock_path, "nowMs": now_ms, "timeBasis": "fixture-logical"},
        "persistentFrontier": frontier_path,
        "persistentIndex": store_path,
    });
    serde_json::to_string_pretty(&output)
        .map_err(|error| format!("could not serialize init result: {error}"))
}

fn run_crawl(args: &[String]) -> Result<String, String> {
    let mut options = Options::parse(args, &["root", "revision", "advance-ms"], &[])?;
    let root = PathBuf::from(options.required("root")?);
    let revision = options.required("revision")?;
    if !matches!(revision.as_str(), "v1" | "v2") {
        return Err("--revision must be v1 or v2".to_owned());
    }
    let advance_ms = options
        .take("advance-ms")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--advance-ms must be a nonnegative integer".to_owned())
        })
        .transpose()?
        .unwrap_or(0);
    options.finish()?;

    let root = canonical_existing_directory(&root)?;
    let config_path = root.join("collection.json");
    let clock_path = root.join("fixture-clock.json");
    let config: CollectionConfig = read_json_file(&config_path)?;
    validate_config(&config)?;
    let (manifest, dataset_sha256) = load_corpus()?;
    if manifest.collection_id != config.collection_id || dataset_sha256 != config.dataset_sha256 {
        return Err("fixture corpus differs from the collection's frozen dataset hash".to_owned());
    }
    let routes = routes_for_revision(&manifest, &revision)?;
    let fixture = bind_fixture(Some(config.port), routes)?;
    let actual_origin = format!("http://127.0.0.1:{}", fixture.port());
    if actual_origin != config.origin {
        return Err(
            "owned fixture listener origin does not match the persisted collection".to_owned(),
        );
    }

    let old_clock = read_clock(&clock_path)?;
    let now_ms = old_clock
        .now_ms
        .checked_add(advance_ms)
        .ok_or_else(|| "fixture logical clock would overflow".to_owned())?;
    if now_ms >= config.source_valid_until_ms {
        return Err(
            "fixture logical clock reached the persisted source expiry; collection is closed"
                .to_owned(),
        );
    }

    let store_path = root.join("store");
    let frontier_path = root.join("frontier.sqlite");
    let index = Arc::new(
        PersistentIndex::open(&store_path)
            .map_err(|error| format!("could not open fixture index: {error}"))?,
    );
    if hex(&index.store_identity()) != config.store_identity {
        return Err("index store identity differs from the collection manifest".to_owned());
    }
    crate::crawl_status::validate_existing_frontier(&frontier_path, index.store_identity())?;
    validate_fixture_source(&frontier_path, &config)?;
    if advance_ms > 0 {
        write_json_atomic(
            &clock_path,
            &FixtureClockFile {
                schema: CLOCK_SCHEMA.to_owned(),
                now_ms,
                time_basis: "fixture-logical".to_owned(),
            },
            true,
        )?;
    }
    let mut crawler =
        ControlledCrawler::<SystemResolver, FixtureLogicalClock>::open_existing_with_public(
            &frontier_path,
            Arc::clone(&index),
            SystemResolver,
            vec![fixture.capability()],
            Vec::new(),
            crawl_limits(),
            FixtureLogicalClock::new(now_ms),
        )
        .map_err(|error| format!("could not reopen existing fixture frontier: {error}"))?;
    crawler.set_link_discovery_enabled(config.link_discovery_enabled);
    let started = Instant::now();
    let report = crawler
        .run_until_idle(&CrawlCancellation::default())
        .map_err(|error| format!("controlled fixture run did not finish: {error}"))?;
    let elapsed_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let expected_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
    let unexpected_destinations = report
        .network_evidence
        .iter()
        .filter(|evidence| {
            !evidence_matches_owned_listener(evidence, &config.origin, expected_peer)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected_destinations.is_empty() {
        return Err(
            "SafeFetcher reported a destination outside the owned fixture listener".to_owned(),
        );
    }
    let request_log = fixture.request_log();
    let status_counts = report.network_evidence.iter().fold(
        BTreeMap::<u16, usize>::new(),
        |mut counts, evidence| {
            *counts.entry(evidence.response_status).or_default() += 1;
            counts
        },
    );
    let output = serde_json::json!({
        "schema": "ley-local-collection-run-v1",
        "processId": std::process::id(),
        "collectionId": manifest.collection_id,
        "profile": config.profile,
        "revision": revision,
        "sourceId": config.source_id,
        "origin": config.origin,
        "storeIdentity": config.store_identity,
        "datasetSha256": config.dataset_sha256,
        "sourceUrlKeys": known_source_urls(&manifest, &config.origin),
        "seedUrlKeys": config.seed_urls,
        "linkDiscoveryEnabled": config.link_discovery_enabled,
        "time": {
            "basis": "fixture-logical",
            "previousNowMs": old_clock.now_ms,
            "nowMs": now_ms,
            "advanceMs": advance_ms,
            "sourceValidatorTimestampsAreSimulated": true,
            "osClockChanged": false,
        },
        "runUntilIdleReturnedSuccessfully": true,
        "exactStopReason": "not exposed by the existing run_until_idle report contract",
        "counts": {
            "requests": report.requests,
            "responseEvidence": report.network_evidence.len(),
            "httpStatus": status_counts,
            "pagesFetched": report.pages_fetched,
            "indexedIntentsApplied": report.indexed,
            "tombstoned": report.tombstoned,
            "retries": report.retries,
            "disallowed": report.disallowed,
            "duplicateUrls": report.duplicate_urls,
            "failedPages": report.failed_pages,
            "transportFailures": report.transport_failures,
            "rejectedIntents": report.rejected_intents,
            "outboxReplays": report.outbox_replays,
            "linkDiscovery": report.link_discovery,
        },
        "receivedEntityBytes": {
            "wire": report.compressed_bytes,
            "decoded": report.decompressed_bytes,
            "headersAndProtocolFramingIncluded": false,
        },
        "limits": budgets_json(),
        "elapsedNanoseconds": elapsed_ns,
        "rssHighWaterBytes": rss_high_water_bytes(),
        "workspaceDiskBytes": directory_bytes(&root).ok(),
        "indexApplyLatency": summarize_latencies(&report.index_apply_latency_ns),
        "latencyInterpretation": "Single local writer with no concurrent retrieval readers; this sample does not resolve the prior M2 four-reader writer-p95 risk.",
        "destinationAudit": {
            "ownedListener": expected_peer,
            "unexpectedDestinations": unexpected_destinations,
            "allObservedConnectedPeersEqualOwnedListener": true,
            "proxyUsed": report.network_evidence.iter().any(|evidence| evidence.proxy_used),
            "acceptedConnections": fixture.accepted_connections(),
            "requestPaths": request_log,
        },
        "networkEvidence": report.network_evidence,
        "failureReasons": report.failure_reasons,
        "skippedReasons": report.skipped_reasons,
    });
    serde_json::to_string_pretty(&output)
        .map_err(|error| format!("could not serialize run result: {error}"))
}

fn run_revoke(args: &[String]) -> Result<String, String> {
    let mut options = Options::parse(args, &["root"], &[])?;
    let root_arg = options.required("root")?;
    let root = canonical_existing_directory(Path::new(&root_arg))?;
    options.finish()?;
    let config: CollectionConfig = read_json_file(&root.join("collection.json"))?;
    validate_config(&config)?;
    let (manifest, dataset_sha256) = load_corpus()?;
    if dataset_sha256 != config.dataset_sha256 {
        return Err("fixture corpus differs from the collection's frozen dataset hash".to_owned());
    }
    let routes = routes_for_revision(&manifest, "v2")?;
    let fixture = bind_fixture(Some(config.port), routes)?;
    if format!("http://127.0.0.1:{}", fixture.port()) != config.origin {
        return Err(
            "owned fixture listener origin does not match the persisted collection".to_owned(),
        );
    }
    let clock = read_clock(&root.join("fixture-clock.json"))?;
    let index = Arc::new(
        PersistentIndex::open(root.join("store"))
            .map_err(|error| format!("could not open fixture index: {error}"))?,
    );
    if hex(&index.store_identity()) != config.store_identity {
        return Err("index store identity differs from the collection manifest".to_owned());
    }
    let frontier_path = root.join("frontier.sqlite");
    validate_fixture_source(&frontier_path, &config)?;
    let mut crawler =
        ControlledCrawler::<SystemResolver, FixtureLogicalClock>::open_existing_with_public(
            &frontier_path,
            index,
            SystemResolver,
            vec![fixture.capability()],
            Vec::new(),
            crawl_limits(),
            FixtureLogicalClock::new(clock.now_ms),
        )
        .map_err(|error| format!("could not reopen fixture frontier for revocation: {error}"))?;
    crawler
        .revoke_source(&config.source_id)
        .map_err(|error| format!("could not revoke fixture source: {error}"))?;
    let output = serde_json::json!({
        "schema": "ley-local-collection-revoke-v1",
        "processId": std::process::id(),
        "sourceId": config.source_id,
        "origin": config.origin,
        "storeIdentity": config.store_identity,
        "fixtureLogicalNowMs": clock.now_ms,
        "timeBasis": "fixture-logical",
        "networkRequests": 0,
        "frontier": frontier_path,
        "index": root.join("store"),
        "revocation": "persisted source revocation reconciled through the controlled crawler outbox",
    });
    serde_json::to_string_pretty(&output)
        .map_err(|error| format!("could not serialize revoke result: {error}"))
}

fn routes_for_revision(
    manifest: &CorpusManifest,
    revision: &str,
) -> Result<Vec<(String, FixtureResponse)>, String> {
    let mut routes = Vec::new();
    let mut paths = BTreeSet::new();
    for page in &manifest.pages {
        if !paths.insert(page.path.clone()) {
            return Err(format!("duplicate fixture route path {:?}", page.path));
        }
        let variant = page
            .versions
            .get(revision)
            .or_else(|| page.versions.get("v1"))
            .ok_or_else(|| format!("page {:?} has no {revision} or v1 representation", page.id))?;
        routes.push((page.path.clone(), response_for_variant(variant, revision)?));
    }
    for route in &manifest.special_routes {
        if route.kind == "noindex-transition" {
            continue;
        }
        if !paths.insert(route.path.clone()) {
            return Err(format!("duplicate fixture route path {:?}", route.path));
        }
        let response = match route.kind.as_str() {
            "redirect" => {
                let variant = route
                    .v1
                    .as_ref()
                    .and_then(|v1| (revision == "v1").then_some(v1))
                    .or(route.v2.as_ref())
                    .or(route.v1.as_ref())
                    .ok_or_else(|| format!("redirect {:?} lacks a target", route.id))?;
                let status = variant.status.unwrap_or(302);
                let target = variant
                    .target
                    .as_deref()
                    .ok_or_else(|| format!("redirect {:?} lacks a target", route.id))?;
                FixtureResponse::new(status, "text/plain; charset=utf-8", [])
                    .with_header("Location", target)
            }
            "robots-disallowed" => {
                let variant = top_level_variant(route);
                response_for_variant(&variant, revision)?
            }
            "removal-410" | "removal-404" => {
                let variant = choose_variant(route, revision)?;
                response_for_variant(&variant, revision)?
            }
            "robots" => {
                let file = route
                    .file
                    .as_deref()
                    .ok_or_else(|| "robots route has no file".to_owned())?;
                let body = read_corpus_file(file)?;
                let mut response = FixtureResponse::new(
                    route.status.unwrap_or(200),
                    "text/plain; charset=utf-8",
                    body,
                );
                response = add_validator_headers(
                    response,
                    route.etag.as_deref(),
                    route.last_modified.as_deref(),
                );
                response
            }
            kind => return Err(format!("unsupported special route kind {kind:?}")),
        };
        routes.push((route.path.clone(), response));
    }
    Ok(routes)
}

fn response_for_variant(
    variant: &RouteVariant,
    _revision: &str,
) -> Result<FixtureResponse, String> {
    if let Some(target) = &variant.target {
        return Ok(FixtureResponse::new(
            variant.status.unwrap_or(302),
            "text/plain; charset=utf-8",
            [],
        )
        .with_header("Location", target));
    }
    let body = match variant.file.as_deref() {
        Some(file) => read_corpus_file(file)?,
        None => Vec::new(),
    };
    let configured_status = variant.status.unwrap_or(200);
    let has_noindex = variant.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("x-robots-tag") && value.contains("noindex")
    });
    let server_status = if configured_status == 200 && !has_noindex {
        304
    } else {
        configured_status
    };
    let mut response = FixtureResponse::new(server_status, "text/html; charset=utf-8", body);
    if server_status == 304 {
        response = response.with_validator_matched_304();
    }
    response = add_validator_headers(
        response,
        variant.etag.as_deref(),
        variant.last_modified.as_deref(),
    );
    for (name, value) in &variant.headers {
        response = response.with_header(name, value);
    }
    Ok(response)
}

fn add_validator_headers(
    mut response: FixtureResponse,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> FixtureResponse {
    if let Some(etag) = etag {
        response = response.with_header("ETag", etag);
    }
    if let Some(last_modified) = last_modified {
        response = response.with_header("Last-Modified", last_modified);
    }
    response
}

fn choose_variant(route: &SpecialRoute, revision: &str) -> Result<RouteVariant, String> {
    route
        .v1
        .as_ref()
        .filter(|_| revision == "v1")
        .or(route.v2.as_ref())
        .or(route.v1.as_ref())
        .cloned()
        .ok_or_else(|| format!("special route {:?} has no revision", route.id))
}

fn top_level_variant(route: &SpecialRoute) -> RouteVariant {
    RouteVariant {
        status: route.status,
        file: route.file.clone(),
        target: None,
        etag: route.etag.clone(),
        last_modified: route.last_modified.clone(),
        headers: BTreeMap::new(),
    }
}

fn bind_fixture(
    port: Option<u16>,
    routes: Vec<(String, FixtureResponse)>,
) -> Result<LocalFixture, String> {
    let fixture = match port {
        Some(port) => LocalFixture::start_at(port, routes),
        None => LocalFixture::start_with_origin(|_| routes),
    }
    .map_err(|error| format!("could not bind the owned fixture listener: {error}"))?;
    Ok(fixture)
}

fn load_corpus() -> Result<(CorpusManifest, String), String> {
    let root = Path::new(CORPUS_DIR);
    let attribution = read_corpus_file("ATTRIBUTION.txt")?;
    let attribution_text = String::from_utf8(attribution)
        .map_err(|_| "fixture attribution is not UTF-8".to_owned())?;
    if !attribution_text.contains("CC0 1.0")
        || !attribution_text.contains("creativecommons.org/publicdomain/zero/1.0")
    {
        return Err("fixture attribution must identify CC0 1.0 and its legal notice".to_owned());
    }
    let manifest_bytes = read_corpus_file("routes.json")?;
    let manifest: CorpusManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("fixture route manifest is invalid: {error}"))?;
    if manifest.schema_version != 1
        || manifest.pages.len() != manifest.document_count
        || manifest.document_count != 30
    {
        return Err("fixture route manifest must declare exactly 30 logical documents".to_owned());
    }
    for page in &manifest.pages {
        if page.versions.is_empty() || !page.path.starts_with("/pages/") {
            return Err(format!(
                "fixture page {:?} has invalid route metadata",
                page.id
            ));
        }
    }
    for profile in manifest.profiles.values() {
        if profile.seed_ids.is_empty()
            || profile
                .seed_ids
                .iter()
                .any(|id| !manifest.pages.iter().any(|page| page.id == *id))
        {
            return Err("fixture profile contains an unknown or empty seed list".to_owned());
        }
    }
    let dataset_sha256 = hash_directory(root)?;
    Ok((manifest, dataset_sha256))
}

fn read_corpus_file(relative: &str) -> Result<Vec<u8>, String> {
    let relative_path = Path::new(relative);
    if relative_path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!(
            "fixture file path is not relative and normalized: {relative:?}"
        ));
    }
    let root = fs::canonicalize(CORPUS_DIR)
        .map_err(|error| format!("fixture corpus directory is unavailable: {error}"))?;
    let path = root.join(relative_path);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("fixture file {relative:?} is unavailable: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_INPUT_FILE_BYTES
    {
        return Err(format!(
            "fixture file {relative:?} must be a bounded regular file"
        ));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("could not canonicalize fixture file {relative:?}: {error}"))?;
    if !canonical.starts_with(&root) {
        return Err(format!(
            "fixture file {relative:?} escapes the fixture directory"
        ));
    }
    fs::read(canonical)
        .map_err(|error| format!("could not read fixture file {relative:?}: {error}"))
}

fn hash_directory(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    visit_files(root, root, &mut files)?;
    // The task manifest has its own frozen hash and is not crawl input.
    files.retain(|relative| {
        relative != Path::new("evaluation-tasks-v1.json")
            && relative != Path::new("evaluation-tasks-v1.sha256")
    });
    files.sort();
    let mut digest = Sha256::new();
    for relative in files {
        let name = relative
            .to_str()
            .ok_or_else(|| "fixture path is not valid UTF-8".to_owned())?;
        let bytes = read_corpus_file(name)?;
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(&bytes);
        digest.update([0]);
    }
    Ok(hex(&digest.finalize()))
}

fn visit_files(root: &Path, directory: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(directory).map_err(|error| format!("could not list fixture files: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("could not read fixture directory entry: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("could not inspect fixture path: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("fixture tree may not contain symlinks".to_owned());
        }
        if metadata.is_dir() {
            visit_files(root, &entry.path(), found)?;
        } else if metadata.is_file() {
            found.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn known_source_urls(manifest: &CorpusManifest, origin: &str) -> Vec<String> {
    let mut urls: BTreeSet<String> = manifest
        .pages
        .iter()
        .map(|page| format!("{origin}{}", page.path))
        .collect();
    urls.extend(
        manifest
            .special_routes
            .iter()
            .filter(|route| route.kind != "noindex-transition")
            .map(|route| format!("{origin}{}", route.path)),
    );
    urls.into_iter().collect()
}

fn validate_config(config: &CollectionConfig) -> Result<(), String> {
    if config.schema != COLLECTION_SCHEMA
        || config.source_id != SOURCE_ID
        || config.time_basis != "fixture-logical"
        || config.port == 0
        || config.origin != format!("http://127.0.0.1:{}", config.port)
        || config.source_request_budget != SOURCE_REQUEST_BUDGET
        || config.per_run_request_budget != PER_RUN_REQUEST_BUDGET
        || config.per_run_wire_budget_bytes != PER_RUN_WIRE_BUDGET
        || config.per_run_decoded_budget_bytes != PER_RUN_DECODED_BUDGET
    {
        return Err(
            "collection manifest has an unknown schema, identity, origin, clock, or budget"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_fixture_source(path: &Path, config: &CollectionConfig) -> Result<(), String> {
    let path =
        fs::canonicalize(path).map_err(|error| format!("frontier file is unavailable: {error}"))?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| format!("could not verify persisted fixture source read-only: {error}"))?;
    let (origins, paths, rights_basis, max_requests, request_count, lifecycle): (String, String, String, i64, i64, String) = connection
        .query_row(
            "SELECT origins,paths,rights_basis,max_requests,request_count,lifecycle FROM source_policy WHERE source_id=?1",
            [&config.source_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(|error| format!("persisted fixture source is unavailable: {error}"))?;
    if origins != config.origin
        || paths != "/"
        || rights_basis != "authored_local_fixture"
        || max_requests != config.source_request_budget as i64
        || request_count < 0
        || lifecycle != "active"
    {
        return Err("persisted fixture source identity, scope, rights, lifecycle, or request budget changed".to_owned());
    }
    Ok(())
}

fn crawl_limits() -> CrawlLimits {
    CrawlLimits {
        max_requests_per_run: PER_RUN_REQUEST_BUDGET,
        global_active: 2,
        per_origin_active: 1,
        max_wire_bytes_per_run: PER_RUN_WIRE_BUDGET,
        max_decompressed_bytes_per_run: PER_RUN_DECODED_BUDGET,
        max_runtime: MAX_RUNTIME,
        request_timeout: REQUEST_TIMEOUT,
        max_retries: 2,
        page_redirects: 5,
    }
}

fn budgets_json() -> serde_json::Value {
    serde_json::json!({
        "persistentSourceRequestsIncludingRobotsRedirectsAndRetries": SOURCE_REQUEST_BUDGET,
        "requestsPerInvocationIncludingRobotsRedirectsAndRetries": PER_RUN_REQUEST_BUDGET,
        "wireEntityBytesPerInvocation": PER_RUN_WIRE_BUDGET,
        "decodedEntityBytesPerInvocation": PER_RUN_DECODED_BUDGET,
        "maxElapsedSecondsPerInvocation": MAX_RUNTIME.as_secs(),
        "requestTimeoutSeconds": REQUEST_TIMEOUT.as_secs(),
        "maxRetriesPerUrl": 2,
        "maxPageRedirects": 5,
        "globalConcurrency": 2,
        "perOriginConcurrency": 1,
    })
}

fn evidence_matches_owned_listener(
    evidence: &DestinationEvidence,
    origin: &str,
    peer: SocketAddr,
) -> bool {
    let Ok(url) = Url::parse(&evidence.requested_url) else {
        return false;
    };
    evidence.connected_peer == peer
        && evidence
            .resolved_addresses
            .iter()
            .all(|address| *address == peer)
        && !evidence.resolved_addresses.is_empty()
        && !evidence.proxy_used
        && url.origin().ascii_serialization() == origin
}

fn summarize_latencies(values: &[u64]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({"sampleCount": 0, "writerP50Nanoseconds": null, "writerP95Nanoseconds": null, "writerMaxNanoseconds": null});
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| {
        let rank = (sorted.len() * percent).div_ceil(100).max(1);
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
    };
    serde_json::json!({
        "sampleCount": values.len(),
        "writerP50Nanoseconds": percentile(50),
        "writerP95Nanoseconds": percentile(95),
        "writerMaxNanoseconds": sorted.last().copied(),
        "measurement": "time spent in PersistentIndex::apply for a durable outbox intent",
        "concurrentReaders": 0,
    })
}

fn read_clock(path: &Path) -> Result<FixtureClockFile, String> {
    let clock: FixtureClockFile = read_json_file(path)?;
    if clock.schema != CLOCK_SCHEMA || clock.time_basis != "fixture-logical" {
        return Err("fixture logical clock has an unknown schema or time basis".to_owned());
    }
    Ok(clock)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("file {:?} is unavailable: {error}", path))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_INPUT_FILE_BYTES
    {
        return Err(format!(
            "file {:?} must be a bounded regular file, not a symlink",
            path
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(MAX_INPUT_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("could not read file {:?}: {error}", path))?;
    if bytes.len() as u64 > MAX_INPUT_FILE_BYTES {
        return Err(format!("file {:?} exceeds its size limit", path));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("file {:?} is invalid JSON: {error}", path))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<(), String> {
    if replace {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("could not inspect file before replacement: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("replacement target must be a regular file, not a symlink".to_owned());
        }
    } else if fs::symlink_metadata(path).is_ok() {
        return Err(format!("refusing to overwrite existing file {:?}", path));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".tmp.{}", std::process::id()));
    let temporary = PathBuf::from(temporary);
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("could not encode private state file: {error}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("could not create atomic state file: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("could not persist atomic state file: {error}"))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| format!("could not atomically replace state file: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("could not sync state directory: {error}"))?;
    Ok(())
}

fn prepare_new_root_path(path: &Path) -> Result<PathBuf, String> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(format!("collection workspace already exists: {:?}", path));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| "collection root must name a new directory".to_owned())?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| format!("collection parent directory must already exist: {error}"))?;
    Ok(canonical_parent.join(file_name))
}

fn canonical_existing_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("collection workspace is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection workspace must be a directory, not a symlink".to_owned());
    }
    fs::canonicalize(path)
        .map_err(|error| format!("could not canonicalize collection workspace: {error}"))
}

fn directory_bytes(root: &Path) -> io::Result<u64> {
    fn accumulate(path: &Path, total: &mut u64) -> io::Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                accumulate(&entry.path(), total)?;
            } else if metadata.is_file() {
                *total = total.saturating_add(metadata.len());
            }
        }
        Ok(())
    }
    let mut total = 0;
    accumulate(root, &mut total)?;
    Ok(total)
}

fn rss_high_water_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kilobytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(kilobytes.saturating_mul(1024))
}

fn system_time_ms() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system UTC clock unavailable at init: {error}"))?
        .as_millis()
        .min(u64::MAX as u128) as u64)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

struct Options {
    values: BTreeMap<String, String>,
}

impl Options {
    fn parse(
        args: &[String],
        value_options: &[&str],
        flag_options: &[&str],
    ) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let flags: BTreeSet<&str> = flag_options.iter().copied().collect();
        let known: BTreeSet<&str> = value_options.iter().chain(flag_options).copied().collect();
        let mut index = 0;
        while index < args.len() {
            let option = args[index]
                .strip_prefix("--")
                .ok_or_else(|| format!("expected an option, got {:?}", args[index]))?;
            if !known.contains(option) {
                return Err(format!("unknown fixture-collection option --{option}"));
            }
            if values.contains_key(option) {
                return Err(format!("repeated fixture-collection option --{option}"));
            }
            let value = if flags.contains(option) {
                "true".to_owned()
            } else {
                index += 1;
                args.get(index)
                    .ok_or_else(|| format!("--{option} requires a value"))?
                    .clone()
            };
            values.insert(option.to_owned(), value);
            index += 1;
        }
        Ok(Self { values })
    }

    fn take(&mut self, name: &str) -> Option<String> {
        self.values.remove(name)
    }

    fn required(&mut self, name: &str) -> Result<String, String> {
        self.take(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn finish(self) -> Result<(), String> {
        if let Some(name) = self.values.keys().next() {
            return Err(format!("unexpected fixture-collection option --{name}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{load_corpus, read_corpus_file};

    #[test]
    fn tracked_evaluation_manifest_is_not_part_of_crawl_dataset_hash() {
        let evaluation: serde_json::Value =
            serde_json::from_slice(&read_corpus_file("evaluation-tasks-v1.json").unwrap()).unwrap();
        let expected_hash = evaluation["collection"]["dataset_sha256"].as_str().unwrap();
        let (_, actual_hash) = load_corpus().unwrap();

        assert_eq!(actual_hash, expected_hash);
    }
}
