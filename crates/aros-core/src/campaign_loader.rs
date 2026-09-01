//! Load RedLab campaign files and execute their generator/oracle without FixtureKind.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::shell::{argv_contains_shell_metacharacters, executable_is_shell};
use aros_store::Store;
use aros_types::{
    unix_now_ms, AuthorizationManifest, Campaign, CampaignOracle, CampaignSpec, CampaignState,
    ExpectedOutcome, Finding, FindingId, HypothesisId, OracleDecides, ResearchEvent,
};

use crate::engine::{CampaignEngine, CampaignOutcome, EngineError};
use crate::snapshot::snapshot_tree;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleJudgement {
    AttackSucceeded,
    InvariantHolds,
    Indeterminate,
}

pub fn load_campaign_file(path: &Path) -> Result<CampaignSpec, EngineError> {
    let raw = fs::read_to_string(path)?;
    Ok(CampaignSpec::from_json_str(&raw)?)
}

pub fn evaluate_oracle(stdout: &str, oracle: &CampaignOracle) -> OracleJudgement {
    if let Some(control) = &oracle.negative_control {
        let token = negative_control_token(control);
        if !token.is_empty() && !stdout.contains(token) {
            return OracleJudgement::Indeterminate;
        }
    }
    match oracle.decides {
        OracleDecides::StdoutContains => {
            let Some(needle) = oracle.r#match.as_deref() else {
                return OracleJudgement::Indeterminate;
            };
            if stdout.contains(needle) {
                OracleJudgement::AttackSucceeded
            } else {
                OracleJudgement::InvariantHolds
            }
        }
        OracleDecides::StdoutNotContains => {
            let Some(needle) = oracle.r#match.as_deref() else {
                return OracleJudgement::Indeterminate;
            };
            if stdout.contains(needle) {
                OracleJudgement::InvariantHolds
            } else {
                OracleJudgement::AttackSucceeded
            }
        }
        _ => OracleJudgement::Indeterminate,
    }
}

impl CampaignEngine {
    pub fn run_declared_campaign(
        &self,
        spec: &CampaignSpec,
        target_root: &Path,
        work_root: &Path,
        mut manifest: AuthorizationManifest,
    ) -> Result<CampaignOutcome, EngineError> {
        if self.waive_containment {
            manifest.require_containment = false;
        }
        let sandbox = self.assert_containment_or_fail(&manifest)?;
        if sandbox.containment_demonstrated {
            return Err(EngineError::FailClosed(
                "declared campaign generator still runs as a host subprocess; refusing to claim contained execution".into(),
            ));
        }

        fs::create_dir_all(work_root)?;
        let cas = ContentAddressedStore::open(work_root.join("cas"), 32 * 1024 * 1024)?;
        let store = Store::open(&work_root.join(aros_types::DATABASE_FILE))?;
        let mut ledger = EventLedger::new();

        let original = snapshot_tree(manifest.target_id, target_root)?;
        ledger.append(
            ResearchEvent::TargetSnapshotted {
                target_id: manifest.target_id,
                snapshot_id: original.id,
                tree_digest: original.source_tree_digest.clone(),
            },
            vec![original.source_tree_digest.clone()],
        )?;

        let mut campaign = Campaign::new(
            manifest.campaign_id,
            manifest.target_id,
            original.id,
            manifest.manifest_hash()?,
        );
        campaign.state = CampaignState::Experimenting;

        if let Some(corpus) = &spec.generator.corpus {
            let corpus_path = target_root.join(corpus);
            if !corpus_path.is_file() {
                return fail_closed_no_evidence(
                    format!(
                        "campaign {} generator corpus {} is not present under {}; zero evidence",
                        spec.id,
                        corpus,
                        target_root.display()
                    ),
                    campaign,
                    original.source_tree_digest,
                    store,
                    ledger,
                );
            }
        }

        let argv = generator_argv(&spec.generator.command)?;
        let timeout = Duration::from_secs(u64::from(spec.resource_limits.wall_clock_seconds));
        let stdout = run_generator(target_root, &argv, timeout)?;
        let artifact = cas.put(stdout.as_bytes(), "text/plain")?;
        ledger.append(
            ResearchEvent::ObservationRecorded {
                campaign_id: campaign.id,
                artifact_digest: artifact.digest_blake3.clone(),
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![artifact.digest_blake3.clone()],
        )?;

        let judgement = evaluate_oracle(&stdout, &spec.oracle);
        let after = snapshot_tree(manifest.target_id, target_root)?;
        let (state, verified, level) = match judgement {
            OracleJudgement::Indeterminate => {
                return fail_closed_no_evidence(
                    format!(
                        "campaign {} oracle is indeterminate (negative control not observed)",
                        spec.id
                    ),
                    campaign,
                    original.source_tree_digest,
                    store,
                    ledger,
                );
            }
            OracleJudgement::AttackSucceeded => (
                CampaignState::Verified,
                true,
                aros_types::EvidenceLevel::E3InvariantViolation,
            ),
            OracleJudgement::InvariantHolds => (
                CampaignState::Refuted,
                false,
                aros_types::EvidenceLevel::E0HypothesisOnly,
            ),
        };

        let finding = Finding {
            id: FindingId::new(),
            campaign_id: campaign.id,
            hypothesis_id: HypothesisId::new(),
            claim: spec.invariant.clone(),
            evidence_level: level,
            manifest_hash: campaign.manifest_hash.clone(),
            verified,
        };
        campaign.state = state;
        campaign.updated_unix_ms = unix_now_ms();
        store.put_campaign(&campaign)?;
        store.persist_ledger_for(campaign.id, &ledger)?;
        let expected_broken = spec.expected_outcome == ExpectedOutcome::InvariantBroken;
        Ok(CampaignOutcome {
            campaign,
            finding: Some(finding),
            evidence_level: Some(level),
            original_digest: original.source_tree_digest,
            original_digest_after: after.source_tree_digest,
            deceptive_rejected: expected_broken && !verified,
            patch: None,
            live_reattack_confirmed: false,
            research_card_id: None,
            verifier_isolated: false,
        })
    }
}

fn fail_closed_no_evidence(
    message: String,
    mut campaign: Campaign,
    digest: String,
    store: Store,
    ledger: EventLedger,
) -> Result<CampaignOutcome, EngineError> {
    campaign.state = CampaignState::InsufficientEvidence;
    campaign.updated_unix_ms = unix_now_ms();
    let _ = store.put_campaign(&campaign);
    let _ = store.persist_ledger_for(campaign.id, &ledger);
    Err(EngineError::FailClosed(
        message + &format!(" digest={digest}"),
    ))
}

fn negative_control_token(control: &str) -> &str {
    for token in ["OPEN_OK", "BOUNDED_OK"] {
        if control.contains(token) {
            return token;
        }
    }
    ""
}

fn generator_argv(command: &str) -> Result<Vec<String>, EngineError> {
    let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
    if argv.is_empty() {
        return Err(EngineError::FailClosed("generator.command is empty".into()));
    }
    if executable_is_shell(&argv[0]) {
        return Err(EngineError::FailClosed(
            "generator.command must not invoke a shell".into(),
        ));
    }
    if argv_contains_shell_metacharacters(&argv) {
        return Err(EngineError::FailClosed(
            "generator.command contains shell metacharacters".into(),
        ));
    }
    let exe = Path::new(&argv[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(argv[0].as_str())
        .to_ascii_lowercase();
    if !matches!(
        exe.as_str(),
        "cargo" | "cargo.exe" | "python" | "python3" | "python.exe"
    ) {
        return Err(EngineError::FailClosed(format!(
            "generator executable {exe} is not allowlisted"
        )));
    }
    Ok(argv)
}

fn run_generator(cwd: &Path, argv: &[String], timeout: Duration) -> Result<String, EngineError> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| EngineError::FailClosed(format!("generator spawn: {error}")))?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(EngineError::FailClosed(
                "generator exceeded wall_clock_seconds".into(),
            ));
        }
        match child.try_wait()? {
            Some(_) => break,
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
    let output = child.wait_with_output()?;
    let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.stderr.is_empty() {
        stdout.push('\n');
        stdout.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Ok(stdout)
}

pub fn default_declared_manifest(target_root: &Path) -> AuthorizationManifest {
    AuthorizationManifest::default_deny_local(
        aros_types::CampaignId::new(),
        aros_types::TargetId::new(),
        target_root.to_string_lossy().into_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aros_types::CampaignSpec;
    use std::io::Write;
    use std::path::PathBuf;

    fn repo_campaign(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("campaign-loader")
            .join(name)
    }

    #[test]
    fn loads_shipped_dycrpt_campaigns() {
        let replay =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        let skip =
            load_campaign_file(&repo_campaign("dycrpt-skipped-key-dos.campaign.json")).unwrap();
        assert_eq!(replay.id, "dycrpt-replay-resistance");
        assert_eq!(skip.id, "dycrpt-skipped-key-dos");
    }

    #[test]
    fn missing_harness_fails_closed_without_verified_finding() {
        let spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        let target = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let engine = CampaignEngine::new(true);
        let manifest = default_declared_manifest(target.path());
        let err = engine
            .run_declared_campaign(&spec, target.path(), work.path(), manifest)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("zero evidence"), "{msg}");
        assert!(msg.contains("redlab_replay"), "{msg}");
    }

    #[test]
    fn oracle_negative_control_is_indeterminate_without_open_ok() {
        let spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        assert_eq!(
            evaluate_oracle("REPLAY_REJECTED\n", &spec.oracle),
            OracleJudgement::Indeterminate
        );
    }

    #[test]
    fn oracle_replay_rejected_after_open_ok_holds_invariant() {
        let spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        assert_eq!(
            evaluate_oracle("OPEN_OK\nREPLAY_REJECTED\n", &spec.oracle),
            OracleJudgement::InvariantHolds
        );
    }

    #[test]
    fn oracle_replay_accepted_after_open_ok_is_attack_success() {
        let spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        assert_eq!(
            evaluate_oracle("OPEN_OK\nREPLAY_ACCEPTED\n", &spec.oracle),
            OracleJudgement::AttackSucceeded
        );
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

    fn holding_spec(command: &str, corpus: &str) -> CampaignSpec {
        let json = format!(
            r#"{{
              "id": "local-oracle-hold",
              "security_class": "integrity",
              "historical_pattern": {{"summary": "test"}},
              "surface": {{"entrypoints": ["local"]}},
              "invariant": "replay must not succeed",
              "attacker_capabilities": ["can replay"],
              "prerequisites": [],
              "resource_limits": {{"wall_clock_seconds": 30, "memory_mb": 64, "network": "none"}},
              "generator": {{"kind": "harness", "command": {command:?}, "corpus": {corpus:?}}},
              "oracle": {{
                "decides": "stdout_contains",
                "success_means": "replay accepted",
                "match": "REPLAY_ACCEPTED",
                "negative_control": "first open must print OPEN_OK"
              }},
              "expected_outcome": "invariant_holds",
              "required_evidence": ["E2", "E3"],
              "severity_rationale": "test"
            }}"#
        );
        CampaignSpec::from_json_str(&json).unwrap()
    }

    #[test]
    fn declared_campaign_runs_without_fixture_kind() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        let harness = target.path().join("harness_ok.py");
        let mut file = fs::File::create(&harness).unwrap();
        writeln!(file, "print('OPEN_OK')").unwrap();
        writeln!(file, "print('REPLAY_REJECTED')").unwrap();
        drop(file);
        let command = format!("{python} harness_ok.py");
        let spec = holding_spec(&command, "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let engine = CampaignEngine::new(true);
        let manifest = default_declared_manifest(target.path());
        let out = engine
            .run_declared_campaign(&spec, target.path(), work.path(), manifest)
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_eq!(
            out.evidence_level,
            Some(aros_types::EvidenceLevel::E0HypothesisOnly)
        );
        assert_eq!(out.campaign.state, CampaignState::Refuted);
    }
}
