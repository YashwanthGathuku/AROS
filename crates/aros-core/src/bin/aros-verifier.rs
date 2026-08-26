//! Dedicated independent verifier process.
//!
//! Receives only reduced JSON `VerifierInput` on stdin. It snapshots the exact
//! target tree and executes the reproduction itself; the parent cannot pass an
//! `oracle-hit` decision.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;

use aros_core::verifier::{verify_input_independently, VerifierInput};

fn main() -> ExitCode {
    let mut buf=Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err(){return ExitCode::from(2);}
    let input:VerifierInput=match serde_json::from_slice(&buf){Ok(v)=>v,Err(e)=>{eprintln!("invalid VerifierInput JSON: {e}");return ExitCode::from(3);}};
    let result=verify_input_independently(&input);
    match serde_json::to_vec(&result){Ok(bytes)=>{if std::io::stdout().write_all(&bytes).is_err(){ExitCode::from(4)}else{ExitCode::SUCCESS}},Err(_)=>ExitCode::from(4)}
}
