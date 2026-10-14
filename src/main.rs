use std::env;
use std::process::ExitCode;

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
        "Ley Search Engine\n\nUsage:\n  cargo run --locked -- demo [--query EXPR] [--explain]\n  cargo run --locked -- controlled-demo\n\nThe controlled demo uses only its owned loopback fixture. Search queries support terms, phrases, AND, OR, and implicit AND."
    );
}
