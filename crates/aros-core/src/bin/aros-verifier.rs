//! Dedicated independent verifier process.
//!
//! It receives only a reduced `VerifierInput` on stdin. It independently
//! snapshots the exact target, creates its own fresh verifier target instance,
//! executes the replay and evaluates the oracle. There are deliberately no
//! `--oracle-hit` / `--oracle-miss` arguments.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use aros_core::verifier::run_verifier_child_main;

fn main() -> ExitCode {
    ExitCode::from(run_verifier_child_main() as u8)
}
