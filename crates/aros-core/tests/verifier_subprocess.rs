//! Integration test: independent verifier is a separate OS process.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use aros_core::{verify_in_subprocess, VerifierInput, VerifierProcessResult};

fn verifier_bin() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_aros_verifier") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("target");
    p.push("debug");
    if cfg!(windows) {
        p.push("aros-verifier.exe");
    } else {
        p.push("aros-verifier");
    }
    p
}

#[test]
fn aros_verifier_binary_adjudicates_without_attacker_notes() {
    let input = VerifierInput {
        claim: "idor".into(),
        snapshot_id: "snap".into(),
        candidate_reproduction: Some("digest".into()),
        oracle_contract: "bob-secret present".into(),
        invariant: "tenant isolation".into(),
        attacker_hidden_reasoning: false,
    };

    let via_helper_hit = verify_in_subprocess(&input, true).unwrap();
    assert!(via_helper_hit.accepted);
    assert_eq!(via_helper_hit.result, "Verified");

    let via_helper_miss = verify_in_subprocess(&input, false).unwrap();
    assert!(!via_helper_miss.accepted);
    assert_eq!(via_helper_miss.result, "NonReproducible");

    let tainted = VerifierInput {
        attacker_hidden_reasoning: true,
        ..input.clone()
    };
    let rejected = verify_in_subprocess(&tainted, true).unwrap();
    assert!(!rejected.accepted);

    let bin = verifier_bin();
    assert!(
        bin.is_file(),
        "aros-verifier binary missing at {}",
        bin.display()
    );

    let mut child = Command::new(&bin)
        .arg("--oracle-hit")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let parsed: VerifierProcessResult = serde_json::from_slice(&out.stdout).unwrap();
    assert!(parsed.accepted);
    assert_eq!(parsed.result, "Verified");
}
