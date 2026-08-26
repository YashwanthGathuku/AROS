//! Integration tests for true independent verifier reproduction.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use aros_core::{
    snapshot::snapshot_tree, verify_in_subprocess, FixtureReplayKind, VerifierInput, VerifierReplay,
};
use aros_types::TargetId;

#[test]
fn verifier_process_replays_exact_target_and_observes_oracle() {
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join("server.py"), "VULN_IDOR = True\n").unwrap();
    let snapshot = snapshot_tree(TargetId::new(), fixture.path()).unwrap();
    let input = VerifierInput {
        claim: "idor".into(),
        snapshot_id: snapshot.id.to_string(),
        candidate_reproduction: None,
        oracle_contract: "body contains bob-secret".into(),
        invariant: "tenant isolation".into(),
        replay: Some(VerifierReplay {
            target_root: fixture.path().to_string_lossy().into_owned(),
            expected_tree_digest: snapshot.source_tree_digest.clone(),
            kind: FixtureReplayKind::Authz,
            request_path: "/users/2".into(),
            cookie: Some("user=1".into()),
            oracle_substring: "bob-secret".into(),
        }),
        attacker_hidden_reasoning: false,
    };

    let result = verify_in_subprocess(&input).unwrap();
    assert!(result.accepted, "{}", result.reason);
    assert!(result.oracle_observed);
    assert_eq!(
        result.target_digest_observed.as_deref(),
        Some(snapshot.source_tree_digest.as_str())
    );
}

#[test]
fn exact_target_mutation_is_rejected() {
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(fixture.path().join("server.py"), "VULN_PATH = True\n").unwrap();
    let snapshot = snapshot_tree(TargetId::new(), fixture.path()).unwrap();
    std::fs::write(fixture.path().join("server.py"), "VULN_PATH = False\n").unwrap();

    let input = VerifierInput {
        claim: "path traversal".into(),
        snapshot_id: snapshot.id.to_string(),
        candidate_reproduction: None,
        oracle_contract: "body contains fixture-path-secret".into(),
        invariant: "data root confinement".into(),
        replay: Some(VerifierReplay {
            target_root: fixture.path().to_string_lossy().into_owned(),
            expected_tree_digest: snapshot.source_tree_digest,
            kind: FixtureReplayKind::Path,
            request_path: "/files?path=../secret.txt".into(),
            cookie: None,
            oracle_substring: "fixture-path-secret".into(),
        }),
        attacker_hidden_reasoning: false,
    };

    let result = verify_in_subprocess(&input).unwrap();
    assert!(!result.accepted);
    assert!(result.reason.contains("digest mismatch"));
}

#[test]
fn hidden_attacker_reasoning_never_enters_verifier() {
    let input = VerifierInput {
        claim: "x".into(),
        snapshot_id: "s".into(),
        candidate_reproduction: None,
        oracle_contract: "o".into(),
        invariant: "i".into(),
        replay: None,
        attacker_hidden_reasoning: true,
    };
    let error = verify_in_subprocess(&input).unwrap_err();
    assert!(error.contains("hidden reasoning"));
}
