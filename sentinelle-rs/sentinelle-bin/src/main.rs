#![deny(warnings)]

use sentinelle_interface_cli::run_cli;

fn main() {
    // Point d'entrée unique : délègue à la CLI Rust hexagonale.
    run_cli();
}