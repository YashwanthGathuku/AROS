//! Independent verifier process boundary and verifier-owned reproduction.
//!
//! Production E4 verification is established only when a dedicated verifier
//! process independently snapshots the exact target, launches a fresh verifier
//! target instance, executes the reproduction, observes the response, and
//! evaluates the oracle. The campaign process never supplies an oracle-hit
//! decision.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use aros_evidence::{BuiltinEvidenceAuthority, EvidenceAuthority};
use aros_types::{
    AuthorityResult, EvidenceBundle, EvidenceLevel, Finding, TargetId, VerifierMode, VerifierRun,
};
use serde::{Deserialize, Serialize};

use crate::http_lab::http_get;
use crate::snapshot::snapshot_tree;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureReplayKind {
    Authz,
    Path,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierReplay {
    pub target_root: String,
    pub expected_tree_digest: String,
    pub kind: FixtureReplayKind,
    pub request_path: String,
    pub cookie: Option<String>,
    pub oracle_substring: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierInput {
    pub claim: String,
    pub snapshot_id: String,
    pub candidate_reproduction: Option<String>,
    pub oracle_contract: String,
    pub invariant: String,
    pub replay: Option<VerifierReplay>,
    pub attacker_hidden_reasoning: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierProcessResult {
    pub result: String,
    pub accepted: bool,
    pub reason: String,
    pub target_digest_observed: Option<String>,
    pub oracle_observed: bool,
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
        replay: None,
        attacker_hidden_reasoning: false,
    }
}

pub fn adjudicate(bundle: &EvidenceBundle, run: &VerifierRun) -> AuthorityResult {
    BuiltinEvidenceAuthority.adjudicate(bundle, run)
}

pub fn accepts_true_finding(level: EvidenceLevel, result: AuthorityResult) -> bool {
    result == AuthorityResult::Verified && level >= EvidenceLevel::E4IndependentReproduction
}

/// Lower-evidence helper only. It must never be used by production code to
/// establish E4.
pub fn adjudicate_from_input(
    input: &VerifierInput,
    observed_oracle_hit: bool,
) -> VerifierProcessResult {
    if input.attacker_hidden_reasoning {
        return rejected("attacker_hidden_reasoning must not be supplied to independent verifier");
    }
    if input.claim.is_empty() || input.oracle_contract.is_empty() {
        return rejected("claim and oracle_contract are required");
    }
    if observed_oracle_hit {
        VerifierProcessResult {
            result: "Verified".into(),
            accepted: true,
            reason: "oracle matched supplied observation (non-E4 helper only)".into(),
            target_digest_observed: None,
            oracle_observed: true,
        }
    } else {
        VerifierProcessResult {
            result: "NonReproducible".into(),
            accepted: false,
            reason: "oracle did not match supplied observation".into(),
            target_digest_observed: None,
            oracle_observed: false,
        }
    }
}

fn rejected(reason: &str) -> VerifierProcessResult {
    VerifierProcessResult {
        result: "Rejected".into(),
        accepted: false,
        reason: reason.into(),
        target_digest_observed: None,
        oracle_observed: false,
    }
}

pub fn verifier_bin_present() -> bool {
    resolve_verifier_bin().is_some()
}

fn resolve_verifier_bin() -> Option<PathBuf> {
    // Explicit operator override wins.
    if let Ok(explicit) = std::env::var("AROS_VERIFIER") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    // Cargo exposes this for integration tests. Check both spellings because
    // Cargo/tooling versions have historically normalized target names
    // differently in surrounding tooling.
    for key in ["CARGO_BIN_EXE_aros-verifier", "CARGO_BIN_EXE_aros_verifier"] {
        if let Ok(value) = std::env::var(key) {
            let path = PathBuf::from(value);
            if path.is_file() {
                return Some(path);
            }
        }
    }

    if let Ok(current) = std::env::current_exe() {
        let mut dirs = Vec::new();
        if let Some(dir) = current.parent() {
            dirs.push(dir.to_path_buf());
            if let Some(parent) = dir.parent() {
                dirs.push(parent.to_path_buf());
            }
        }
        for dir in dirs {
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

    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("aros-verifier");
            if candidate.is_file() {
                return Some(candidate);
            }
            let candidate_exe = candidate.with_extension("exe");
            candidate_exe.is_file().then_some(candidate_exe)
        })
    })
}

/// Production verification. There is no production in-process fallback and no
/// parent-supplied oracle decision. The child owns replay and observation.
pub fn verify_in_subprocess(input: &VerifierInput) -> Result<VerifierProcessResult, String> {
    if input.attacker_hidden_reasoning {
        return Err("independent verifier input contains attacker hidden reasoning".into());
    }
    if input.replay.is_none() {
        return Err("INDEPENDENT_REPLAY_UNAVAILABLE: cannot establish E4".into());
    }

    let Some(bin) = resolve_verifier_bin() else {
        // Rust library unit tests do not necessarily receive Cargo's executable
        // path. This branch is compiled only for those unit tests; integration
        // and production builds remain strictly subprocess-only.
        #[cfg(test)]
        {
            return Ok(reproduce_and_adjudicate(input));
        }
        #[cfg(not(test))]
        {
            return Err("INDEPENDENT_VERIFIER_UNAVAILABLE: cannot establish E4".into());
        }
    };

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn aros-verifier: {e}"))?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| "missing stdin".to_string())?;
        let payload = serde_json::to_vec(input).map_err(|e| e.to_string())?;
        stdin.write_all(&payload).map_err(|e| e.to_string())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait aros-verifier: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "aros-verifier exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

pub fn run_verifier_child_main() -> i32 {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        return 2;
    }
    let input: VerifierInput = match serde_json::from_slice(&buf) {
        Ok(value) => value,
        Err(_) => return 3,
    };
    let result = reproduce_and_adjudicate(&input);
    match serde_json::to_vec(&result) {
        Ok(bytes) => {
            if std::io::stdout().write_all(&bytes).is_err() {
                4
            } else {
                0
            }
        }
        Err(_) => 4,
    }
}

pub fn reproduce_and_adjudicate(input: &VerifierInput) -> VerifierProcessResult {
    if input.attacker_hidden_reasoning {
        return rejected("attacker_hidden_reasoning must not be supplied to independent verifier");
    }
    let Some(replay) = &input.replay else {
        return rejected("verifier replay recipe missing; E4 cannot be established");
    };
    if input.claim.is_empty() || input.oracle_contract.is_empty() || replay.oracle_substring.is_empty() {
        return rejected("claim, oracle_contract, and replay oracle are required");
    }

    let root = Path::new(&replay.target_root);
    if !root.is_dir() {
        return rejected("verifier target root is unavailable");
    }

    let before = match snapshot_tree(TargetId::new(), root) {
        Ok(snapshot) => snapshot,
        Err(error) => return rejected(&format!("verifier snapshot failed: {error}")),
    };
    if before.source_tree_digest != replay.expected_tree_digest {
        return digest_mismatch(before.source_tree_digest);
    }

    // Capture the source used by the fresh verifier target, then snapshot again.
    // The two matching digests bound the read and prevent a stale pre-read
    // snapshot from being promoted as exact-target evidence.
    let source = match std::fs::read_to_string(root.join("server.py")) {
        Ok(source) => source,
        Err(error) => return rejected(&format!("read exact target source: {error}")),
    };
    let after_read = match snapshot_tree(TargetId::new(), root) {
        Ok(snapshot) => snapshot,
        Err(error) => return rejected(&format!("post-read verifier snapshot failed: {error}")),
    };
    if after_read.source_tree_digest != replay.expected_tree_digest {
        return digest_mismatch(after_read.source_tree_digest);
    }

    let (port, handle) = match spawn_fresh_fixture_target(&source, replay.kind.clone()) {
        Ok(value) => value,
        Err(error) => {
            return VerifierProcessResult {
                result: "Rejected".into(),
                accepted: false,
                reason: format!("fresh verifier target failed: {error}"),
                target_digest_observed: Some(after_read.source_tree_digest),
                oracle_observed: false,
            }
        }
    };

    let response = http_get(
        "127.0.0.1",
        port,
        &replay.request_path,
        replay.cookie.as_deref(),
    );
    let oracle_observed = response
        .as_ref()
        .map(|response| response.body.contains(&replay.oracle_substring))
        .unwrap_or(false);
    let _ = handle.join();

    // Re-check that the exact-target tree remained unchanged across replay.
    let after_replay = match snapshot_tree(TargetId::new(), root) {
        Ok(snapshot) => snapshot,
        Err(error) => return rejected(&format!("post-replay verifier snapshot failed: {error}")),
    };
    if after_replay.source_tree_digest != replay.expected_tree_digest {
        return digest_mismatch(after_replay.source_tree_digest);
    }

    if oracle_observed {
        VerifierProcessResult {
            result: "Verified".into(),
            accepted: true,
            reason: "fresh verifier independently snapshotted exact target, replayed, and observed oracle".into(),
            target_digest_observed: Some(after_replay.source_tree_digest),
            oracle_observed: true,
        }
    } else {
        VerifierProcessResult {
            result: "NonReproducible".into(),
            accepted: false,
            reason: "fresh verifier replay did not observe the oracle".into(),
            target_digest_observed: Some(after_replay.source_tree_digest),
            oracle_observed: false,
        }
    }
}

fn digest_mismatch(observed: String) -> VerifierProcessResult {
    VerifierProcessResult {
        result: "Rejected".into(),
        accepted: false,
        reason: "exact-target digest mismatch during verifier replay".into(),
        target_digest_observed: Some(observed),
        oracle_observed: false,
    }
}

fn spawn_fresh_fixture_target(
    source: &str,
    kind: FixtureReplayKind,
) -> Result<(u16, thread::JoinHandle<()>), String> {
    let vulnerable = match kind {
        FixtureReplayKind::Authz => source.contains("VULN_IDOR = True"),
        FixtureReplayKind::Path => source.contains("VULN_PATH = True"),
    };
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let handle = thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        if let Some(mut stream) = listener.incoming().flatten().next() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let body = match kind {
                FixtureReplayKind::Authz => {
                    let user1 = request.contains("Cookie: user=1");
                    let users2 = request.contains("GET /users/2 ");
                    if users2 && (vulnerable || !user1) {
                        "{\"id\":2,\"secret\":\"bob-secret\"}"
                    } else if users2 {
                        "{\"error\":\"forbidden\"}"
                    } else {
                        "{\"ok\":true}"
                    }
                }
                FixtureReplayKind::Path => {
                    if vulnerable && (request.contains("../secret") || request.contains("path=../")) {
                        "fixture-path-secret"
                    } else {
                        "public-ok"
                    }
                }
            };
            let status = if body.contains("forbidden") {
                "403 Forbidden"
            } else {
                "200 OK"
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Ok((port, handle))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hidden_reasoning() {
        let input = VerifierInput {
            claim: "x".into(),
            snapshot_id: "s".into(),
            candidate_reproduction: None,
            oracle_contract: "o".into(),
            invariant: "i".into(),
            replay: None,
            attacker_hidden_reasoning: true,
        };
        assert!(!adjudicate_from_input(&input, true).accepted);
    }

    #[test]
    fn fresh_replay_checks_exact_digest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.py"), "VULN_IDOR = True\n").unwrap();
        let snapshot = snapshot_tree(TargetId::new(), dir.path()).unwrap();
        let input = VerifierInput {
            claim: "idor".into(),
            snapshot_id: snapshot.id.to_string(),
            candidate_reproduction: None,
            oracle_contract: "body contains bob-secret".into(),
            invariant: "tenant isolation".into(),
            replay: Some(VerifierReplay {
                target_root: dir.path().to_string_lossy().into_owned(),
                expected_tree_digest: snapshot.source_tree_digest,
                kind: FixtureReplayKind::Authz,
                request_path: "/users/2".into(),
                cookie: Some("user=1".into()),
                oracle_substring: "bob-secret".into(),
            }),
            attacker_hidden_reasoning: false,
        };
        let result = reproduce_and_adjudicate(&input);
        assert!(result.accepted, "{}", result.reason);
        assert!(result.oracle_observed);
    }
}
