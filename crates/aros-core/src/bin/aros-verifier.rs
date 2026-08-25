//! Independent verifier process for AROS.
//!
//! Receives only JSON `VerifierInput` on stdin. Never receives attacker notes,
//! research-worker state, or campaign chain-of-thought.
//!
//! Usage:
//!   aros-verifier --oracle-hit  < input.json
//!   aros-verifier --oracle-miss < input.json
//!
//! Exit codes: 0 success (JSON result on stdout), 2 stdin error, 3 bad input, 4 encode error.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;

use aros_core::verifier::{adjudicate_from_input, VerifierInput};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let oracle_hit = args.iter().any(|a| a == "--oracle-hit");
    let oracle_miss = args.iter().any(|a| a == "--oracle-miss");
    if !oracle_hit && !oracle_miss {
        eprintln!("usage: aros-verifier --oracle-hit|--oracle-miss < stdin JSON VerifierInput");
        return ExitCode::from(1);
    }

    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return ExitCode::from(2);
    }
    let input: VerifierInput = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid VerifierInput JSON: {e}");
            return ExitCode::from(3);
        }
    };

    let result = adjudicate_from_input(&input, oracle_hit);
    match serde_json::to_vec(&result) {
        Ok(bytes) => {
            if std::io::stdout().write_all(&bytes).is_err() {
                return ExitCode::from(4);
            }
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::from(4),
    }
}
