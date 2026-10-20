use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ley::{EvidenceReference, QuestionRequest, RetrievalRequest};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };
    if command == "--help" || command == "-h" {
        print_usage();
        return ExitCode::SUCCESS;
    }
    if command == "controlled-demo" {
        let mut retain_dir = None;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--retain-dir" if retain_dir.is_none() => {
                    let Some(value) = args.next() else {
                        eprintln!("--retain-dir requires a new directory path");
                        return ExitCode::from(2);
                    };
                    retain_dir = Some(value);
                }
                _ => {
                    eprintln!("unknown or repeated controlled-demo argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let result = match retain_dir {
            Some(path) => ley::run_controlled_fixture_demo_retained(path),
            None => ley::run_controlled_fixture_demo(),
        };
        return match result {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "serve" {
        let mut store = None;
        let mut bind = ley::api::DEFAULT_BIND;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--store" if store.is_none() => {
                    let Some(value) = args.next() else {
                        eprintln!("--store requires a path");
                        return ExitCode::from(2);
                    };
                    store = Some(value);
                }
                "--bind" => {
                    let Some(value) = args.next() else {
                        eprintln!("--bind requires a loopback socket address");
                        return ExitCode::from(2);
                    };
                    match value.parse::<SocketAddr>() {
                        Ok(address) if address.ip().is_loopback() => bind = address,
                        _ => {
                            eprintln!("--bind must be a loopback socket address");
                            return ExitCode::from(2);
                        }
                    }
                }
                _ => {
                    eprintln!("unknown or repeated serve argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let Some(store) = store else {
            eprintln!("serve requires --store PATH");
            return ExitCode::from(2);
        };
        return match ley::api::run(store, bind) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "ingest-html" {
        return run_ingest_html(args);
    }
    if command == "retrieve" {
        return run_retrieve(args);
    }
    if command == "resolve-evidence" {
        return run_resolve_evidence(args);
    }
    if command == "search" {
        let mut store = None;
        let mut query = None;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--store" if store.is_none() => store = args.next(),
                "--query" if query.is_none() => query = args.next(),
                _ => {
                    eprintln!("unknown or repeated search argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let (Some(store), Some(query)) = (store, query) else {
            eprintln!("search requires --store PATH and --query EXPR");
            print_usage();
            return ExitCode::from(2);
        };
        return match ley::api::search_store_json(store, &query) {
            Ok(response) => {
                println!("{response}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "fixture-index" {
        let Some(flag) = args.next() else {
            eprintln!("fixture-index requires --store PATH");
            return ExitCode::from(2);
        };
        let Some(path) = args.next() else {
            eprintln!("fixture-index requires a store path");
            return ExitCode::from(2);
        };
        if flag != "--store" || args.next().is_some() {
            eprintln!("fixture-index accepts only --store PATH");
            return ExitCode::from(2);
        }
        return match ley::create_search_fixture_index(&path) {
            Ok((documents, generation)) => {
                println!(
                    "Authored local fixture indexed: {documents} documents, generation {generation}"
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "compact" {
        let Some(flag) = args.next() else {
            eprintln!("compact requires --store PATH");
            return ExitCode::from(2);
        };
        let Some(path) = args.next() else {
            eprintln!("compact requires a store path");
            return ExitCode::from(2);
        };
        if flag != "--store" || args.next().is_some() {
            eprintln!("compact accepts only --store PATH");
            print_usage();
            return ExitCode::from(2);
        }
        return match ley::storage::PersistentIndex::open(&path).and_then(|store| store.compact()) {
            Ok(report) => {
                println!(
                    "Compaction generation {} -> {}; merged {} segments, replaced with {}; removed {} files",
                    report.old_generation,
                    report.new_generation,
                    report.merged_segments.len(),
                    report.replacement_segments.len(),
                    report.removed_paths.len()
                );
                for segment in &report.merged_segments {
                    println!(
                        "  input seg-{}.ley {} {}",
                        segment.id, segment.byte_len, segment.sha256
                    );
                }
                for segment in &report.replacement_segments {
                    println!(
                        "  output seg-{}.ley {} {}",
                        segment.id, segment.byte_len, segment.sha256
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "reindex-gate3" {
        let mut source = None;
        let mut destination = None;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--source" if source.is_none() => source = args.next(),
                "--destination" if destination.is_none() => destination = args.next(),
                _ => {
                    eprintln!("unknown or repeated reindex-gate3 argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let (Some(source), Some(destination)) = (source, destination) else {
            eprintln!("reindex-gate3 requires --source OLD and --destination NEW");
            return ExitCode::from(2);
        };
        return match ley::storage::PersistentIndex::reindex_gate3(&source, &destination) {
            Ok(report) => {
                println!(
                    "Reindexed Gate 3 generation {} to Gate 6 generation {}: {} documents at {}",
                    report.source_generation,
                    report.destination_generation,
                    report.document_count,
                    report.destination.display()
                );
                println!(
                    "Stop old writers and switch the configured store path to the destination."
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "revoke-source" {
        let mut store = None;
        let mut frontier = None;
        let mut source_id = None;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--store" if store.is_none() => store = args.next(),
                "--frontier" if frontier.is_none() => frontier = args.next(),
                "--source-id" if source_id.is_none() => source_id = args.next(),
                _ => {
                    eprintln!("unknown or repeated revoke-source argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let (Some(store), Some(frontier), Some(source_id)) = (store, frontier, source_id) else {
            eprintln!("revoke-source requires --store, --frontier, and --source-id");
            return ExitCode::from(2);
        };
        return match ley::revoke_public_source(store, frontier, &source_id) {
            Ok(()) => {
                println!("Source revoked; its indexed documents are no longer searchable.");
                eprintln!(
                    "Earlier immutable index generations may retain their bytes until compaction."
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command == "crawl-public" {
        let mut policy_path = None;
        let mut store = None;
        let mut frontier = None;
        let mut requests = None;
        let mut approved_hash = None;
        let mut allow_public = false;
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--policy" if policy_path.is_none() => policy_path = args.next(),
                "--store" if store.is_none() => store = args.next(),
                "--frontier" if frontier.is_none() => frontier = args.next(),
                "--requests" if requests.is_none() => {
                    requests = args.next().and_then(|value| value.parse::<usize>().ok())
                }
                "--approved-policy-sha256" if approved_hash.is_none() => {
                    approved_hash = args.next()
                }
                "--allow-public-requests" if !allow_public => allow_public = true,
                _ => {
                    eprintln!("unknown or repeated crawl-public argument: {argument:?}");
                    print_usage();
                    return ExitCode::from(2);
                }
            }
        }
        let (Some(policy_path), Some(store), Some(frontier), Some(requests), Some(approved_hash)) =
            (policy_path, store, frontier, requests, approved_hash)
        else {
            eprintln!(
                "crawl-public requires --policy, --store, --frontier, --requests, and --approved-policy-sha256"
            );
            return ExitCode::from(2);
        };
        if !allow_public {
            eprintln!("crawl-public requires the explicit --allow-public-requests opt-in");
            return ExitCode::from(2);
        }
        if requests == 0 || requests > 12 {
            eprintln!("--requests must be between 1 and 12");
            return ExitCode::from(2);
        }
        let policy = match ley::public_policy::PublicCrawlPolicy::load(&policy_path) {
            Ok(policy) => policy,
            Err(error) => {
                eprintln!("ley: {error}");
                return ExitCode::FAILURE;
            }
        };
        if !policy.matches_sha256(&approved_hash) {
            eprintln!("crawl-public policy hash does not match the supplied Work-approved SHA-256");
            return ExitCode::from(2);
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if let Err(error) = policy.validate_enabled(now_ms) {
            eprintln!("ley: {error}");
            return ExitCode::FAILURE;
        }
        return match ley::run_public_crawl(
            &policy,
            store,
            frontier,
            requests,
            &approved_hash,
            allow_public,
        ) {
            Ok(report) => {
                println!("{}", report.report_json);
                if report.bounded_run_finished {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(error) => {
                eprintln!("ley: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if command != "demo" {
        eprintln!("unknown command: {command:?}");
        print_usage();
        return ExitCode::from(2);
    }

    let mut query = "Rust".to_owned();
    let mut explain = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--query" => {
                let Some(value) = args.next() else {
                    eprintln!("--query requires a value");
                    return ExitCode::from(2);
                };
                query = value;
            }
            "--explain" => explain = true,
            _ => {
                eprintln!("unknown demo argument: {argument:?}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    match ley::run_demo_with_options(&query, explain) {
        Ok(result) => {
            print!("{}", result.stdout);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ley: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_ingest_html(mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut store = None;
    let mut directory = None;
    let mut url_prefix = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--store" if store.is_none() => store = args.next(),
            "--directory" if directory.is_none() => directory = args.next(),
            "--url-prefix" if url_prefix.is_none() => url_prefix = args.next(),
            _ => {
                eprintln!("unknown or repeated ingest-html argument: {argument:?}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }
    let (Some(store), Some(directory), Some(url_prefix)) = (store, directory, url_prefix) else {
        eprintln!("ingest-html requires --store NEW_PATH --directory DIR --url-prefix URL");
        print_usage();
        return ExitCode::from(2);
    };
    match ley::local_ingest::ingest_html_directory(store, directory, &url_prefix) {
        Ok(report) => {
            println!(
                "Imported {} local HTML documents, skipped {} noindex documents, read {} bytes; generation {}",
                report.indexed_documents,
                report.skipped_noindex,
                report.input_bytes,
                report.generation_id
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ley: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_retrieve(mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut store = None;
    let mut question = None;
    let mut max_hits = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--store" if store.is_none() => store = args.next(),
            "--question" if question.is_none() => question = args.next(),
            "--max-hits" if max_hits.is_none() => {
                let Some(value) = args.next() else {
                    eprintln!("--max-hits requires a value between 1 and 8");
                    return ExitCode::from(2);
                };
                match value.parse::<u8>() {
                    Ok(value @ 1..=8) => max_hits = Some(value),
                    _ => {
                        eprintln!("--max-hits requires a value between 1 and 8");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!("unknown or repeated retrieve argument: {argument:?}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }
    let (Some(store), Some(question)) = (store, question) else {
        eprintln!("retrieve requires --store PATH and --question TEXT");
        print_usage();
        return ExitCode::from(2);
    };
    let request = match max_hits {
        Some(max_hits) => match QuestionRequest::new(question).with_max_hits(max_hits) {
            Ok(request) => RetrievalRequest::Question(request),
            Err(_) => {
                eprintln!("ley: invalid_request");
                return ExitCode::FAILURE;
            }
        },
        None => RetrievalRequest::question(question),
    };
    match ley::api::retrieve_store_json(store, request) {
        Ok(response) => {
            println!("{response}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ley: {}", error.code());
            ExitCode::FAILURE
        }
    }
}

fn run_resolve_evidence(mut args: impl Iterator<Item = String>) -> ExitCode {
    let mut store = None;
    let mut reference_file = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--store" if store.is_none() => store = args.next(),
            "--reference-file" if reference_file.is_none() => reference_file = args.next(),
            _ => {
                eprintln!("unknown or repeated resolve-evidence argument: {argument:?}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }
    let (Some(store), Some(reference_file)) = (store, reference_file) else {
        eprintln!("resolve-evidence requires --store PATH and --reference-file PATH|-");
        print_usage();
        return ExitCode::from(2);
    };
    let reference = match read_evidence_reference(&reference_file) {
        Ok(reference) => reference,
        Err(error) => {
            eprintln!("ley: {}", error.code());
            return ExitCode::FAILURE;
        }
    };
    match ley::api::resolve_evidence_store_json(store, &reference) {
        Ok(response) => {
            println!("{response}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ley: {}", error.code());
            ExitCode::FAILURE
        }
    }
}

fn read_evidence_reference(path: &str) -> Result<EvidenceReference, ley::api::ClientFailure> {
    let mut bytes = Vec::with_capacity(ley::api::MAX_TYPED_REQUEST_BYTES);
    if path == "-" {
        io::stdin()
            .lock()
            .take((ley::api::MAX_TYPED_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ley::api::ClientFailure::InvalidRequest)?;
    } else {
        File::open(path)
            .map_err(|_| ley::api::ClientFailure::InvalidRequest)?
            .take((ley::api::MAX_TYPED_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ley::api::ClientFailure::InvalidRequest)?;
    }
    if bytes.len() > ley::api::MAX_TYPED_REQUEST_BYTES {
        return Err(ley::api::ClientFailure::ResourceCap);
    }
    serde_json::from_slice(&bytes).map_err(|_| ley::api::ClientFailure::InvalidRequest)
}

fn print_usage() {
    println!(
        "Ley Search Engine\n\nUsage:\n  cargo run --locked -- demo [--query EXPR] [--explain]\n  cargo run --locked -- controlled-demo [--retain-dir NEW_PATH]\n  cargo run --locked -- fixture-index --store PATH\n  cargo run --locked -- ingest-html --store NEW_PATH --directory DIR --url-prefix URL\n  cargo run --locked -- retrieve --store PATH --question TEXT [--max-hits 1..8]\n  cargo run --locked -- resolve-evidence --store PATH --reference-file PATH|-\n  cargo run --locked -- search --store PATH --query EXPR\n  cargo run --locked -- serve --store PATH [--bind 127.0.0.1:7331]\n  cargo run --locked -- compact --store PATH\n  cargo run --locked -- reindex-gate3 --source OLD --destination NEW\n  cargo run --locked -- revoke-source --store PATH --frontier PATH --source-id ID\n  cargo run --locked -- crawl-public --policy PATH --store PATH --frontier PATH --requests 1..12 --approved-policy-sha256 HASH --allow-public-requests\n\nThe controlled demo uses an owned loopback fixture; --retain-dir keeps its persistent index and frontier under a new directory. fixture-index creates authored synthetic documents without network access. ingest-html reads bounded UTF-8 HTML from an operator-selected local directory into a new store and does not fetch URLs. retrieve runs the versioned ordinary-question contract and prints typed passage candidates; resolve-evidence reads a bounded JSON reference from a file or stdin and revalidates it against the current store. search remains the advanced Boolean/phrase DSL. serve binds to loopback and exposes read-only health, legacy search, question retrieval, and evidence resolution routes. Typed routes use POST /api/v1/retrieve and POST /api/v1/evidence/resolve. The Gate 6 store appends immutable segments and compacts them explicitly; some aggregate segment limits recommend compact when merging can help, while live-corpus and retained lifecycle-history limits do not because compaction cannot reduce them. reindex-gate3 copies a stopped Gate 3 store to a separate destination and preserves the source bytes. Public crawling requires an enabled reviewed policy and an explicit hash approval. Search queries support terms, phrases, AND, OR, and implicit AND."
    );
}
