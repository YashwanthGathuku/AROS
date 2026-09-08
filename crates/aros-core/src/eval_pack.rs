//! CyberGym-style local eval: PoC (oracle Verified) or nothing. No LLM.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aros_sandbox::RootlessOciSandboxProvider;
use serde::{Deserialize, Serialize};

use crate::campaign_loader::{class_campaign_dir, default_declared_manifest, load_campaign_file};
use crate::engine::{CampaignEngine, EngineError};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvalCase {
    pub id: String,
    pub target: String,
    pub campaign: String,
    pub expect: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvalManifest {
    pub scoring: String,
    #[serde(default)]
    pub note: String,
    pub cases: Vec<EvalCase>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvalCaseResult {
    pub id: String,
    pub expect: String,
    pub observed: String,
    pub hit: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvalReport {
    pub scoring: String,
    pub hits: usize,
    pub total: usize,
    pub containment_blocked: bool,
    pub results: Vec<EvalCaseResult>,
}

pub fn repo_root() -> Option<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..5 {
        if dir.join("evaluation/poc-or-nothing/cases.json").is_file() {
            return Some(dir);
        }
        dir.pop();
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("evaluation/poc-or-nothing/cases.json").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn load_eval_manifest(path: &Path) -> Result<EvalManifest, EngineError> {
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn python_bin() -> String {
    for candidate in ["python", "python3"] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return candidate.into();
        }
    }
    "python".into()
}

fn rewrite_python(command: &str) -> String {
    if let Some(rest) = command.strip_prefix("python ") {
        return format!("{} {rest}", python_bin());
    }
    if let Some(rest) = command.strip_prefix("python3 ") {
        return format!("{} {rest}", python_bin());
    }
    command.to_string()
}

/// Score local fixtures. A hit is only an oracle match against `expect`.
/// Chatter, missing harnesses, and missing containment are not points.
pub fn run_poc_eval_pack(work: &Path, waive_containment: bool) -> Result<EvalReport, EngineError> {
    fs::create_dir_all(work)?;
    let live_oci = RootlessOciSandboxProvider::detect()
        .probe_containment()
        .live_oci_claimable();
    if !waive_containment && !live_oci {
        return Ok(EvalReport {
            scoring: "poc-or-nothing".into(),
            hits: 0,
            total: 0,
            containment_blocked: true,
            results: Vec::new(),
        });
    }
    let root = repo_root().ok_or_else(|| {
        EngineError::FailClosed("evaluation/poc-or-nothing/cases.json not found".into())
    })?;
    let manifest = load_eval_manifest(&root.join("evaluation/poc-or-nothing/cases.json"))?;
    let class_dir = class_campaign_dir().ok_or_else(|| {
        EngineError::FailClosed("campaign-loader/classes is not available".into())
    })?;
    let engine = CampaignEngine::new(waive_containment);
    let mut results = Vec::new();
    let mut hits = 0usize;
    for case in &manifest.cases {
        let spec_path = class_dir.join(format!("{}.campaign.json", case.campaign));
        let target = root.join(&case.target);
        let run_work = work.join(&case.id);
        let observed = match load_campaign_file(&spec_path) {
            Ok(mut spec) => {
                spec.generator.command = rewrite_python(&spec.generator.command);
                match engine.run_declared_campaign(
                    &spec,
                    &target,
                    &run_work,
                    default_declared_manifest(&target),
                ) {
                    Ok(out) => {
                        let verified = out.finding.as_ref().is_some_and(|finding| finding.verified);
                        if verified {
                            "verified".to_string()
                        } else {
                            "held".to_string()
                        }
                    }
                    Err(error) => {
                        results.push(EvalCaseResult {
                            id: case.id.clone(),
                            expect: case.expect.clone(),
                            observed: "error".into(),
                            hit: false,
                            error: Some(error.to_string()),
                        });
                        continue;
                    }
                }
            }
            Err(error) => {
                results.push(EvalCaseResult {
                    id: case.id.clone(),
                    expect: case.expect.clone(),
                    observed: "error".into(),
                    hit: false,
                    error: Some(error.to_string()),
                });
                continue;
            }
        };
        let hit = observed == case.expect;
        if hit {
            hits += 1;
        }
        results.push(EvalCaseResult {
            id: case.id.clone(),
            expect: case.expect.clone(),
            observed,
            hit,
            error: None,
        });
    }
    Ok(EvalReport {
        scoring: manifest.scoring,
        hits,
        total: manifest.cases.len(),
        containment_blocked: false,
        results,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn poc_or_nothing_local_eval_pack() {
        let work = tempfile::tempdir().unwrap();
        let report = run_poc_eval_pack(work.path(), true).unwrap();
        assert!(
            !report.containment_blocked,
            "waived eval must not fail closed on containment"
        );
        assert!(report.total >= 8, "pack too small: {}", report.total);
        let misses: Vec<&EvalCaseResult> = report.results.iter().filter(|row| !row.hit).collect();
        assert!(
            misses.is_empty(),
            "PoC-or-nothing misses: {}",
            serde_json::to_string_pretty(&misses).unwrap()
        );
        assert_eq!(report.hits, report.total);
    }

    #[test]
    fn unwaived_eval_fails_closed_without_live_oci() {
        if RootlessOciSandboxProvider::detect()
            .probe_containment()
            .live_oci_claimable()
        {
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let report = run_poc_eval_pack(work.path(), false).unwrap();
        assert!(report.containment_blocked);
        assert_eq!(report.hits, 0);
    }
}
