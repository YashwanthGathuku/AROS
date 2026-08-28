//! Independent verifier process boundary and verifier-owned reproduction.
//!
//! E4 is established only when a dedicated verifier process copies a
//! byte-identical target tree, launches the actual target program from that
//! copied tree, replays the experiment, observes the result itself, and checks
//! that the source tree did not change throughout the operation.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aros_evidence::{BuiltinEvidenceAuthority, EvidenceAuthority};
use aros_types::{
    env_name, AuthorityResult, EvidenceBundle, EvidenceLevel, Finding, TargetId, VerifierMode,
    VerifierRun, VERIFIER_NAME,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::http_lab::http_get;
use crate::snapshot::snapshot_tree;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureReplayKind {
    Authz,
    Path,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierOracle {
    pub expected_status: Option<u16>,
    pub body_contains: Option<String>,
    pub body_not_contains: Option<String>,
}

impl VerifierOracle {
    fn matches(&self, status: u16, body: &str) -> bool {
        self.expected_status
            .is_none_or(|expected| expected == status)
            && self
                .body_contains
                .as_ref()
                .is_none_or(|needle| body.contains(needle))
            && self
                .body_not_contains
                .as_ref()
                .is_none_or(|needle| !body.contains(needle))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReplay {
    pub target_root: String,
    pub expected_tree_digest: String,
    pub kind: FixtureReplayKind,
    pub request_path: String,
    pub cookie: Option<String>,
    pub oracle: VerifierOracle,
}

/// Reduced verifier channel. Unknown fields are rejected so attacker scratch
/// state/notes cannot be smuggled into the verifier protocol by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInput {
    pub claim: String,
    pub snapshot_id: String,
    pub oracle_contract: String,
    pub invariant: String,
    pub replay: Option<VerifierReplay>,
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
    _mode: VerifierMode,
    oracle: &str,
    invariant: &str,
) -> VerifierInput {
    VerifierInput {
        claim: finding.claim.clone(),
        snapshot_id: bundle.snapshot_id.to_string(),
        oracle_contract: oracle.to_string(),
        invariant: invariant.to_string(),
        replay: None,
    }
}

pub fn adjudicate(bundle: &EvidenceBundle, run: &VerifierRun) -> AuthorityResult {
    BuiltinEvidenceAuthority.adjudicate(bundle, run)
}

pub fn accepts_true_finding(level: EvidenceLevel, result: AuthorityResult) -> bool {
    result == AuthorityResult::Verified && level >= EvidenceLevel::E4IndependentReproduction
}

fn rejected(reason: impl Into<String>) -> VerifierProcessResult {
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
    if let Ok(explicit) = std::env::var(env_name("VERIFIER")) {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }
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
            let plain = dir.join(VERIFIER_NAME);
            if plain.is_file() {
                return Some(plain);
            }
            let exe = dir.join(format!("{VERIFIER_NAME}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let plain = dir.join(VERIFIER_NAME);
            if plain.is_file() {
                return Some(plain);
            }
            let exe = dir.join(format!("{VERIFIER_NAME}.exe"));
            exe.is_file().then_some(exe)
        })
    })
}

/// Production verifier invocation with a hard wall-clock deadline. There is no
/// production in-process fallback.
pub fn verify_in_subprocess(input: &VerifierInput) -> Result<VerifierProcessResult, String> {
    if input.replay.is_none() {
        return Err("INDEPENDENT_REPLAY_UNAVAILABLE: cannot establish E4".into());
    }
    let bin = resolve_verifier_bin()
        .ok_or_else(|| "INDEPENDENT_VERIFIER_UNAVAILABLE: cannot establish E4".to_string())?;
    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn {VERIFIER_NAME}: {error}"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "missing stdin".to_string())?;
        let payload = serde_json::to_vec(input).map_err(|error| error.to_string())?;
        stdin
            .write_all(&payload)
            .map_err(|error| error.to_string())?;
    }
    wait_with_output_deadline(child, Duration::from_secs(15))
}

fn wait_with_output_deadline(
    mut child: Child,
    timeout: Duration,
) -> Result<VerifierProcessResult, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("INDEPENDENT_VERIFIER_TIMEOUT: evidence capped at E3".into());
            }
            Err(error) => return Err(format!("poll verifier: {error}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("collect verifier output: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{VERIFIER_NAME} exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())
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
        Ok(bytes) if std::io::stdout().write_all(&bytes).is_ok() => 0,
        Ok(_) => 4,
        Err(_) => 4,
    }
}

pub fn reproduce_and_adjudicate(input: &VerifierInput) -> VerifierProcessResult {
    let Some(replay) = &input.replay else {
        return rejected("verifier replay recipe missing; E4 cannot be established");
    };
    if input.claim.is_empty() || input.oracle_contract.is_empty() {
        return rejected("claim and oracle_contract are required");
    }

    let root = Path::new(&replay.target_root);
    if !root.is_dir() {
        return rejected("verifier target root is unavailable");
    }
    let before = match snapshot_tree(TargetId::new(), root) {
        Ok(snapshot) => snapshot,
        Err(error) => return rejected(format!("verifier snapshot failed: {error}")),
    };
    if before.source_tree_digest != replay.expected_tree_digest {
        return digest_mismatch(before.source_tree_digest);
    }

    let temp_root = std::env::temp_dir().join(format!("aros-verifier-{}", Uuid::new_v4()));
    if let Err(error) = copy_exact_tree(root, &temp_root) {
        return rejected(format!("copy exact verifier target: {error}"));
    }
    let copied = match snapshot_tree(TargetId::new(), &temp_root) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_root);
            return rejected(format!("snapshot copied target: {error}"));
        }
    };
    if copied.source_tree_digest != replay.expected_tree_digest {
        let _ = fs::remove_dir_all(&temp_root);
        return rejected("copied target digest differs from authorized target");
    }

    let result = run_actual_fixture(&temp_root, replay);
    let after = snapshot_tree(TargetId::new(), root);
    let _ = fs::remove_dir_all(&temp_root);
    let after = match after {
        Ok(snapshot) => snapshot,
        Err(error) => return rejected(format!("post-replay verifier snapshot failed: {error}")),
    };
    if after.source_tree_digest != replay.expected_tree_digest {
        return digest_mismatch(after.source_tree_digest);
    }

    match result {
        Ok((status, body)) if replay.oracle.matches(status, &body) => VerifierProcessResult {
            result: "Verified".into(),
            accepted: true,
            reason: "independent verifier executed the actual byte-identical target and observed the oracle".into(),
            target_digest_observed: Some(after.source_tree_digest),
            oracle_observed: true,
        },
        Ok((_status, _body)) => VerifierProcessResult {
            result: "NonReproducible".into(),
            accepted: false,
            reason: "actual verifier target did not satisfy the oracle".into(),
            target_digest_observed: Some(after.source_tree_digest),
            oracle_observed: false,
        },
        Err(error) => VerifierProcessResult {
            result: "Rejected".into(),
            accepted: false,
            reason: format!("actual verifier target unavailable: {error}"),
            target_digest_observed: Some(after.source_tree_digest),
            oracle_observed: false,
        },
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

fn copy_exact_tree(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|error| error.to_string())?;
    for item in fs::read_dir(src).map_err(|error| error.to_string())? {
        let item = item.map_err(|error| error.to_string())?;
        let kind = item.file_type().map_err(|error| error.to_string())?;
        if kind.is_symlink() {
            return Err(format!(
                "symlink not allowed in verifier target: {}",
                item.path().display()
            ));
        }
        let to = dst.join(item.file_name());
        if kind.is_dir() {
            if item.file_name() == "__pycache__" {
                continue;
            }
            copy_exact_tree(&item.path(), &to)?;
        } else if kind.is_file() {
            fs::copy(item.path(), to).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn resolve_python() -> Option<String> {
    if let Ok(explicit) = std::env::var(env_name("PYTHON")) {
        if !explicit.trim().is_empty() {
            return Some(explicit);
        }
    }
    for candidate in ["python3", "python"] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Some(candidate.into());
        }
    }
    None
}

fn reserve_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| error.to_string())
}

fn run_actual_fixture(root: &Path, replay: &VerifierReplay) -> Result<(u16, String), String> {
    let python = resolve_python().ok_or_else(|| "python interpreter not available".to_string())?;
    let server = root.join("server.py");
    if !server.is_file() {
        return Err("server.py missing from verifier target".into());
    }
    let port = reserve_port()?;
    let mut child = Command::new(python)
        .arg("server.py")
        .current_dir(root)
        .env("AROS_FIXTURE_PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("launch target: {error}"))?;

    let readiness_deadline = Instant::now() + Duration::from_secs(4);
    let mut ready = false;
    while Instant::now() < readiness_deadline {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if http_get("127.0.0.1", port, "/health", None).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        terminate_child(&mut child);
        return Err("target readiness deadline exceeded".into());
    }

    let response = http_get(
        "127.0.0.1",
        port,
        &replay.request_path,
        replay.cookie.as_deref(),
    )
    .map_err(|error| error.to_string());
    terminate_child(&mut child);
    let response = response?;
    Ok((response.status, response.body))
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_verifier_fields_are_rejected() {
        let json = r#"{"claim":"x","snapshot_id":"s","oracle_contract":"o","invariant":"i","replay":null,"attacker_notes":"secret"}"#;
        assert!(serde_json::from_str::<VerifierInput>(json).is_err());
    }

    #[test]
    fn oracle_supports_positive_and_negative_conditions() {
        let oracle = VerifierOracle {
            expected_status: Some(200),
            body_contains: Some("ok".into()),
            body_not_contains: Some("secret".into()),
        };
        assert!(oracle.matches(200, "ok"));
        assert!(!oracle.matches(200, "ok secret"));
        assert!(!oracle.matches(403, "ok"));
    }
}
