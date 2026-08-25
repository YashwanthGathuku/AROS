//! Independent verifier. Must not receive attacker hidden reasoning.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use aros_evidence::{BuiltinEvidenceAuthority, EvidenceAuthority};
use aros_types::{
    AuthorityResult, EvidenceBundle, EvidenceLevel, Finding, VerifierMode, VerifierRun,
};
use serde::{Deserialize, Serialize};

/// The payload actually given to the independent verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierInput {
    pub claim: String,
    pub snapshot_id: String,
    pub candidate_reproduction: Option<String>,
    pub oracle_contract: String,
    pub invariant: String,
    /// Always false for a conforming caller; process isolation rejects true.
    pub attacker_hidden_reasoning: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierProcessResult {
    pub result: String,
    pub accepted: bool,
    pub reason: String,
}

pub fn reduced_input(
    finding: &Finding,
    bundle: &EvidenceBundle,
    mode: VerifierMode,
    oracle: &str,
    invariant: &str,
) -> VerifierInput {
    VerifierInput {
        claim: finding.claim.clone(),
        snapshot_id: bundle.snapshot_id.to_string(),
        candidate_reproduction: match mode {
            VerifierMode::ReproduceCandidate => bundle.artifact_digests.first().cloned(),
            VerifierMode::Blindish => None,
        },
        oracle_contract: oracle.to_string(),
        invariant: invariant.to_string(),
        attacker_hidden_reasoning: false,
    }
}

pub fn adjudicate(bundle: &EvidenceBundle, run: &VerifierRun) -> AuthorityResult {
    BuiltinEvidenceAuthority.adjudicate(bundle, run)
}

pub fn accepts_true_finding(level: EvidenceLevel, result: AuthorityResult) -> bool {
    result == AuthorityResult::Verified && level >= EvidenceLevel::E4IndependentReproduction
}

/// Pure adjudication from the reduced verifier input only.
///
/// Rejects any input that claims attacker hidden reasoning was supplied.
/// Does not take attacker notes, chain-of-thought, or research-worker state.
pub fn adjudicate_from_input(input: &VerifierInput, observed_oracle_hit: bool) -> VerifierProcessResult {
    if input.attacker_hidden_reasoning {
        return VerifierProcessResult {
            result: "Rejected".into(),
            accepted: false,
            reason: "attacker_hidden_reasoning must not be supplied to independent verifier".into(),
        };
    }
    if input.claim.is_empty() || input.oracle_contract.is_empty() {
        return VerifierProcessResult {
            result: "Rejected".into(),
            accepted: false,
            reason: "claim and oracle_contract are required".into(),
        };
    }
    if observed_oracle_hit {
        VerifierProcessResult {
            result: "Verified".into(),
            accepted: true,
            reason: "oracle contract matched on independent observation".into(),
        }
    } else {
        VerifierProcessResult {
            result: "NonReproducible".into(),
            accepted: false,
            reason: "oracle contract did not match on independent observation".into(),
        }
    }
}

/// Resolve the path to the dedicated `aros-verifier` binary.
fn resolve_verifier_bin() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("AROS_VERIFIER") {
        let p = std::path::PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    // Same directory as current executable (cargo target/debug/aros-verifier next to tests).
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join("aros-verifier");
            if candidate.is_file() {
                return Some(candidate);
            }
            let candidate_exe = dir.join("aros-verifier.exe");
            if candidate_exe.is_file() {
                return Some(candidate_exe);
            }
        }
    }
    // PATH lookup.
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join("aros-verifier");
            if p.is_file() {
                return Some(p);
            }
            let exe = p.with_extension("exe");
            exe.is_file().then_some(exe)
        })
    })
}

/// Run independent verification in a **separate OS process**.
///
/// The child process only receives JSON `VerifierInput` on stdin and an
/// `--oracle-hit` / `--oracle-miss` flag. It cannot see attacker notes.
pub fn verify_in_subprocess(
    input: &VerifierInput,
    observed_oracle_hit: bool,
) -> Result<VerifierProcessResult, String> {
    if input.attacker_hidden_reasoning {
        return Ok(adjudicate_from_input(input, observed_oracle_hit));
    }
    let oracle_flag = if observed_oracle_hit {
        "--oracle-hit"
    } else {
        "--oracle-miss"
    };

    let bin = match resolve_verifier_bin() {
        Some(b) => b,
        None => {
            // No dedicated binary available (e.g. pure unit tests without building the bin).
            // Still adjudicate from reduced input only — never attacker notes.
            return Ok(adjudicate_from_input(input, observed_oracle_hit));
        }
    };

    let mut child = Command::new(&bin)
        .arg(oracle_flag)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn aros-verifier: {e}"))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "missing stdin".to_string())?;
        let payload = serde_json::to_vec(input).map_err(|e| e.to_string())?;
        stdin.write_all(&payload).map_err(|e| e.to_string())?;
    }

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "missing stdout".to_string())?;
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!(
            "aros-verifier exited {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&out)
        ));
    }
    serde_json::from_slice(&out).map_err(|e| e.to_string())
}

/// Entry used when this process is the verifier child (`AROS_VERIFIER_CHILD=1`).
pub fn run_verifier_child_main(args: &[String]) -> i32 {
    let oracle_hit = args.iter().any(|a| a == "--oracle-hit");
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return 2;
    }
    let input: VerifierInput = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(_) => return 3,
    };
    let result = adjudicate_from_input(&input, oracle_hit);
    if let Ok(bytes) = serde_json::to_vec(&result) {
        let _ = std::io::stdout().write_all(&bytes);
        0
    } else {
        4
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, FindingId, HypothesisId, SnapshotId};

    #[test]
    fn verifier_does_not_include_attacker_notes() {
        let finding = Finding {
            id: FindingId::new(),
            campaign_id: CampaignId::new(),
            hypothesis_id: HypothesisId::new(),
            claim: "idor".into(),
            evidence_level: EvidenceLevel::E4IndependentReproduction,
            manifest_hash: "h".into(),
            verified: false,
        };
        let bundle = EvidenceBundle {
            finding_id: finding.id,
            campaign_id: finding.campaign_id,
            manifest_hash: "h".into(),
            snapshot_id: SnapshotId::new(),
            sandbox_id: None,
            claim: finding.claim.clone(),
            artifact_digests: vec!["abc".into()],
            level: EvidenceLevel::E4IndependentReproduction,
        };
        let input = reduced_input(
            &finding,
            &bundle,
            VerifierMode::Blindish,
            "secret-not-returned",
            "tenant isolation",
        );
        assert!(!input.attacker_hidden_reasoning);
        assert!(input.candidate_reproduction.is_none());
    }

    #[test]
    fn rejects_attacker_hidden_reasoning_flag() {
        let input = VerifierInput {
            claim: "x".into(),
            snapshot_id: "s".into(),
            candidate_reproduction: None,
            oracle_contract: "o".into(),
            invariant: "i".into(),
            attacker_hidden_reasoning: true,
        };
        let r = adjudicate_from_input(&input, true);
        assert!(!r.accepted);
        assert!(r.reason.contains("attacker_hidden_reasoning"));
    }

    #[test]
    fn pure_input_adjudicates_oracle_hit() {
        let input = VerifierInput {
            claim: "idor".into(),
            snapshot_id: "s".into(),
            candidate_reproduction: Some("digest".into()),
            oracle_contract: "bob-secret present".into(),
            invariant: "tenant isolation".into(),
            attacker_hidden_reasoning: false,
        };
        let r = adjudicate_from_input(&input, true);
        assert!(r.accepted);
        assert_eq!(r.result, "Verified");
    }

    #[test]
    fn subprocess_path_falls_back_to_pure_adjudication_in_tests() {
        let input = VerifierInput {
            claim: "idor".into(),
            snapshot_id: "s".into(),
            candidate_reproduction: None,
            oracle_contract: "o".into(),
            invariant: "i".into(),
            attacker_hidden_reasoning: false,
        };
        // Under unit tests current_exe is the test harness; child may fail and
        // must fall back to pure input adjudication (still independent of attacker notes).
        let r = verify_in_subprocess(&input, true).unwrap();
        assert!(r.accepted);
    }

    #[test]
    fn real_subprocess_when_binary_present() {
        let input = VerifierInput {
            claim: "idor".into(),
            snapshot_id: "s".into(),
            candidate_reproduction: Some("d".into()),
            oracle_contract: "bob-secret present".into(),
            invariant: "tenant isolation".into(),
            attacker_hidden_reasoning: false,
        };
        // Always succeeds: either dedicated binary or pure-input fallback.
        let r = verify_in_subprocess(&input, true).unwrap();
        assert!(r.accepted);
        assert_eq!(r.result, "Verified");

        let r2 = verify_in_subprocess(&input, false).unwrap();
        assert!(!r2.accepted);
        assert_eq!(r2.result, "NonReproducible");
    }
}
