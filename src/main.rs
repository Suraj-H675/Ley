use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

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
        if args.next().is_some() {
            eprintln!("controlled-demo does not accept arguments");
            print_usage();
            return ExitCode::from(2);
        }
        return match ley::run_controlled_fixture_demo() {
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

fn print_usage() {
    println!(
        "Ley Search Engine\n\nUsage:\n  cargo run --locked -- demo [--query EXPR] [--explain]\n  cargo run --locked -- controlled-demo\n  cargo run --locked -- fixture-index --store PATH\n  cargo run --locked -- search --store PATH --query EXPR\n  cargo run --locked -- serve --store PATH [--bind 127.0.0.1:7331]\n  cargo run --locked -- revoke-source --store PATH --frontier PATH --source-id ID\n  cargo run --locked -- crawl-public --policy PATH --store PATH --frontier PATH --requests 1..12 --approved-policy-sha256 HASH --allow-public-requests\n\nThe controlled demo uses its owned loopback fixture. fixture-index creates authored synthetic documents without network access. search opens a persistent store and prints the current generation's ordered results and full score explanations as bounded JSON. serve binds to loopback and exposes read-only health and search routes. revoke-source publishes local tombstones and makes no network requests; earlier immutable generations may retain bytes until compaction. Public crawling requires an enabled reviewed policy and an explicit hash approval. Search queries support terms, phrases, AND, OR, and implicit AND."
    );
}
