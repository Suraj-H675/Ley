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
        "Ley Gate 2 Search Core 0.2\n\nUsage:\n  cargo run --locked -- demo [--query EXPR] [--explain]\n\nQueries support terms, phrases, AND, OR, and implicit AND."
    );
}
