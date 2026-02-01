#![deny(warnings)]

use sentinelle_interface_cli::run_cli;

fn main() {
    // Single entry point: delegates to hexagonal Rust CLI.
    if let Err(e) = run_cli() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}