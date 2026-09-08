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
    unix_now_ms, AuthorizationManifest, Campaign, CampaignGenerator, CampaignOracle, CampaignSpec,
    CampaignState, EvidenceLevel, ExpectedOutcome, Finding, FindingId, HypothesisId, OracleDecides,
    ResearchEvent,
};

use crate::engine::{CampaignEngine, CampaignOutcome, DeclaredRunMeta, EngineError};
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
        // Unwaived declared campaigns execute via CampaignOciTarget::exec_generator.
        // They must not mint a synthetic HTTP-fixture sandbox identity.
        let require_container = manifest.require_containment && !self.waive_containment;

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

        if let Some(reason) = environment_mismatch(target_root, require_container) {
            campaign.state = CampaignState::Failed;
            store.put_campaign(&campaign)?;
            store.persist_ledger_for(campaign.id, &ledger)?;
            let report_path = write_report(
                work_root,
                spec,
                &campaign,
                &original.source_tree_digest,
                None,
                EvidenceLevel::E0HypothesisOnly,
                false,
                "environment_mismatch",
                Some(&reason),
                &[],
                None,
                None,
                false,
            )?;
            return Ok(CampaignOutcome {
                campaign,
                finding: None,
                evidence_level: None,
                original_digest: original.source_tree_digest.clone(),
                original_digest_after: original.source_tree_digest,
                deceptive_rejected: false,
                patch: None,
                live_reattack_confirmed: false,
                research_card_id: None,
                verifier_isolated: false,
                declared: DeclaredRunMeta {
                    run_kind: "environment_mismatch".into(),
                    environment_notes: Some(reason),
                    report_path: Some(report_path),
                    ledger_verified: true,
                    ..DeclaredRunMeta::default()
                },
            });
        }

        let harness_digest = archive_harnesses(target_root, spec, &cas, campaign.id, &mut ledger)?;

        let timeout = Duration::from_secs(u64::from(spec.resource_limits.wall_clock_seconds));
        let mut control_good = None;
        let mut control_mutant = None;
        if let Some(control) = &spec.structural_control {
            let good_out = run_arm(
                target_root,
                &control.good,
                timeout,
                spec.resource_limits.memory_mb,
                require_container,
            )?;
            let good_j = evaluate_oracle(&good_out, &spec.oracle);
            control_good = Some(format!("{good_j:?}"));
            if good_j != OracleJudgement::InvariantHolds {
                return fail_closed_no_evidence(
                    format!(
                        "campaign {} structural good arm did not hold ({good_j:?}); oracle untrustworthy",
                        spec.id
                    ),
                    campaign,
                    original.source_tree_digest,
                    store,
                    ledger,
                );
            }
            let mutant_out = run_arm(
                target_root,
                &control.mutant,
                timeout,
                spec.resource_limits.memory_mb,
                require_container,
            )?;
            let mutant_j = evaluate_oracle(&mutant_out, &spec.oracle);
            control_mutant = Some(format!("{mutant_j:?}"));
            if mutant_j != OracleJudgement::AttackSucceeded {
                return fail_closed_no_evidence(
                    format!(
                        "campaign {} structural mutant arm did not break ({mutant_j:?}); oracle untrustworthy",
                        spec.id
                    ),
                    campaign,
                    original.source_tree_digest,
                    store,
                    ledger,
                );
            }
        }

        let mut surface_results = Vec::new();
        let mut any_success = false;
        let mut all_hold = true;
        for (name, generator, oracle) in spec.attack_plans() {
            if let Some(corpus) = &generator.corpus {
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
            let stdout = run_arm(
                target_root,
                generator,
                timeout,
                spec.resource_limits.memory_mb,
                require_container,
            )?;
            let artifact = cas.put(stdout.as_bytes(), "text/plain")?;
            ledger.append(
                ResearchEvent::ObservationRecorded {
                    campaign_id: campaign.id,
                    artifact_digest: artifact.digest_blake3.clone(),
                    manifest_hash: campaign.manifest_hash.clone(),
                },
                vec![artifact.digest_blake3.clone()],
            )?;
            let judgement = evaluate_oracle(&stdout, oracle);
            surface_results.push(format!("{name}:{judgement:?}"));
            match judgement {
                OracleJudgement::Indeterminate => {
                    return fail_closed_no_evidence(
                        format!(
                            "campaign {} surface {name} oracle is indeterminate",
                            spec.id
                        ),
                        campaign,
                        original.source_tree_digest,
                        store,
                        ledger,
                    );
                }
                OracleJudgement::AttackSucceeded => {
                    any_success = true;
                    all_hold = false;
                }
                OracleJudgement::InvariantHolds => {}
            }
        }

        let after = snapshot_tree(manifest.target_id, target_root)?;
        let judgement = if any_success {
            OracleJudgement::AttackSucceeded
        } else if all_hold {
            OracleJudgement::InvariantHolds
        } else {
            OracleJudgement::Indeterminate
        };
        let raw_level = match judgement {
            OracleJudgement::AttackSucceeded => EvidenceLevel::E3InvariantViolation,
            OracleJudgement::InvariantHolds => EvidenceLevel::E2DynamicAnomaly,
            OracleJudgement::Indeterminate => EvidenceLevel::E0HypothesisOnly,
        };
        let required = max_required_level(spec);
        let required_met = raw_level >= required;
        let (state, verified, level) = if !required_met {
            (CampaignState::InsufficientEvidence, false, raw_level)
        } else if judgement == OracleJudgement::AttackSucceeded {
            (CampaignState::Verified, true, raw_level)
        } else {
            (CampaignState::Refuted, false, raw_level)
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
        let ledger_ok = ledger.verify().is_ok();
        store.persist_ledger_for(campaign.id, &ledger)?;
        let expected_broken = spec.expected_outcome == ExpectedOutcome::InvariantBroken;
        let report_path = write_report(
            work_root,
            spec,
            &campaign,
            &original.source_tree_digest,
            harness_digest.as_deref(),
            level,
            required_met,
            "security",
            None,
            &surface_results,
            control_good.as_deref(),
            control_mutant.as_deref(),
            ledger_ok,
        )?;
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
            declared: DeclaredRunMeta {
                harness_digest,
                required_evidence_met: required_met,
                contained: require_container,
                run_kind: "security".into(),
                environment_notes: None,
                report_path: Some(report_path),
                surface_results,
                control_good_result: control_good,
                control_mutant_result: control_mutant,
                ledger_verified: ledger_ok,
            },
        })
    }
}

fn parse_level(label: &str) -> Option<EvidenceLevel> {
    Some(match label {
        "E0" => EvidenceLevel::E0HypothesisOnly,
        "E1" => EvidenceLevel::E1StaticSupport,
        "E2" => EvidenceLevel::E2DynamicAnomaly,
        "E3" => EvidenceLevel::E3InvariantViolation,
        "E4" => EvidenceLevel::E4IndependentReproduction,
        "E5" => EvidenceLevel::E5MinimizedReproduction,
        "E6" => EvidenceLevel::E6CounterfactualDifferential,
        "E7" => EvidenceLevel::E7VariantReattackAndRegression,
        _ => return None,
    })
}

fn max_required_level(spec: &CampaignSpec) -> EvidenceLevel {
    spec.required_evidence
        .iter()
        .filter_map(|level| parse_level(level))
        .max()
        .unwrap_or(EvidenceLevel::E0HypothesisOnly)
}

fn environment_mismatch(target_root: &Path, contained_linux: bool) -> Option<String> {
    let path = target_root.join("rust-toolchain.toml");
    let text = fs::read_to_string(path).ok()?;
    let channel = parse_toml_quoted(&text, "channel")?;
    let known = channel.starts_with("stable")
        || channel.starts_with("beta")
        || channel.starts_with("nightly")
        || channel.chars().next().is_some_and(|c| c.is_ascii_digit());
    if !known {
        return Some(format!(
            "rust-toolchain.toml channel {channel} cannot be reproduced on this host"
        ));
    }
    let lower = channel.to_ascii_lowercase();
    let has_triple =
        lower.contains("x86_64-") || lower.contains("aarch64-") || lower.contains("i686-");
    if !has_triple {
        return None;
    }
    if contained_linux && !lower.contains("linux") {
        return Some(format!(
            "toolchain pin {channel} is not a Linux triple; contained generator image cannot reproduce it"
        ));
    }
    if lower.contains("windows-gnu") && !cfg!(all(windows, target_env = "gnu")) {
        return Some(format!(
            "toolchain pin {channel} does not match this host; environment mismatch, not a security result"
        ));
    }
    if lower.contains("windows-msvc") && !cfg!(all(windows, target_env = "msvc")) {
        return Some(format!(
            "toolchain pin {channel} does not match this host; environment mismatch, not a security result"
        ));
    }
    if lower.contains("linux") && cfg!(windows) && !contained_linux {
        return Some(format!(
            "toolchain pin {channel} is Linux; this Windows host cannot reproduce it without containment"
        ));
    }
    if lower.contains("apple-darwin") && !cfg!(target_os = "macos") {
        return Some(format!(
            "toolchain pin {channel} is macOS; environment mismatch, not a security result"
        ));
    }
    if lower.contains("windows") && cfg!(unix) {
        return Some(format!(
            "toolchain pin {channel} is Windows; environment mismatch, not a security result"
        ));
    }
    None
}

fn parse_toml_quoted(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    let start = text.find(&prefix)? + prefix.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn harness_relpaths(spec: &CampaignSpec) -> Vec<String> {
    let mut paths = Vec::new();
    let mut consider = |generator: &CampaignGenerator| {
        if let Some(corpus) = &generator.corpus {
            paths.push(corpus.clone());
        }
        if let Ok(argv) = generator_argv(&generator.command) {
            for token in argv.iter().skip(1) {
                if !token.starts_with('-') {
                    paths.push(token.clone());
                }
            }
        }
    };
    for (_name, generator, _) in spec.attack_plans() {
        consider(generator);
    }
    if let Some(control) = &spec.structural_control {
        consider(&control.good);
        consider(&control.mutant);
    }
    paths.sort();
    paths.dedup();
    paths
}

fn archive_harnesses(
    target_root: &Path,
    spec: &CampaignSpec,
    cas: &ContentAddressedStore,
    campaign_id: aros_types::CampaignId,
    ledger: &mut EventLedger,
) -> Result<Option<String>, EngineError> {
    let mut combined = Vec::new();
    for rel in harness_relpaths(spec) {
        let path = target_root.join(&rel);
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path)?;
        combined.extend_from_slice(rel.as_bytes());
        combined.push(0);
        combined.extend_from_slice(&bytes);
        let artifact = cas.put(&bytes, "text/plain")?;
        ledger.append(
            ResearchEvent::EvidenceCreated {
                campaign_id,
                digest: artifact.digest_blake3.clone(),
            },
            vec![artifact.digest_blake3.clone()],
        )?;
    }
    if combined.is_empty() {
        return Ok(None);
    }
    let snapshot = cas.put(&combined, "application/octet-stream")?;
    ledger.append(
        ResearchEvent::EvidenceCreated {
            campaign_id,
            digest: snapshot.digest_blake3.clone(),
        },
        vec![snapshot.digest_blake3.clone()],
    )?;
    Ok(Some(snapshot.digest_blake3))
}

fn run_arm(
    target_root: &Path,
    generator: &CampaignGenerator,
    timeout: Duration,
    memory_mb: u32,
    require_container: bool,
) -> Result<String, EngineError> {
    let argv = generator_argv(&generator.command)?;
    if require_container {
        return aros_sandbox::CampaignOciTarget::exec_generator(
            target_root,
            &argv,
            timeout,
            memory_mb,
        )
        .map_err(|error| EngineError::FailClosed(error.to_string()));
    }
    run_generator(target_root, &argv, timeout)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[allow(clippy::too_many_arguments)]
fn write_report(
    work_root: &Path,
    spec: &CampaignSpec,
    campaign: &Campaign,
    target_digest: &str,
    harness_digest: Option<&str>,
    achieved: EvidenceLevel,
    required_met: bool,
    run_kind: &str,
    environment_notes: Option<&str>,
    surfaces: &[String],
    control_good: Option<&str>,
    control_mutant: Option<&str>,
    ledger_verified: bool,
) -> Result<String, EngineError> {
    let required = spec.required_evidence.join(", ");
    let pin = spec
        .target
        .as_ref()
        .map(|target| target.revision_pin.as_str())
        .unwrap_or("unpinned");
    let html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body>\
         <h1>RedLab evidence report</h1>\
         <p><b>campaign</b> {}</p>\
         <p><b>claim / invariant</b> {}</p>\
         <p><b>target digest</b> {}</p>\
         <p><b>revision pin</b> {}</p>\
         <p><b>harness digest</b> {}</p>\
         <p><b>generator</b> {}</p>\
         <p><b>oracle</b> {} match={}</p>\
         <p><b>run kind</b> {}</p>\
         <p><b>level achieved</b> {:?} <b>required</b> {} <b>met</b> {}</p>\
         <p><b>ledger verified</b> {}</p>\
         <p><b>negative control (token)</b> {}</p>\
         <p><b>structural good</b> {}</p>\
         <p><b>structural mutant</b> {}</p>\
         <p><b>surfaces</b> {}</p>\
         <p><b>environment</b> {}</p>\
         <p><b>campaign id</b> {}</p>\
         </body></html>",
        html_escape(&spec.id),
        html_escape(&spec.id),
        html_escape(&spec.invariant),
        html_escape(target_digest),
        html_escape(pin),
        html_escape(harness_digest.unwrap_or("none")),
        html_escape(&spec.generator.command),
        html_escape(&spec.oracle.success_means),
        html_escape(spec.oracle.r#match.as_deref().unwrap_or("")),
        html_escape(run_kind),
        achieved,
        html_escape(&required),
        required_met,
        ledger_verified,
        html_escape(spec.oracle.negative_control.as_deref().unwrap_or("none")),
        html_escape(control_good.unwrap_or("n/a")),
        html_escape(control_mutant.unwrap_or("n/a")),
        html_escape(&surfaces.join("; ")),
        html_escape(environment_notes.unwrap_or("none")),
        campaign.id,
    );
    let path = work_root.join("evidence-report.html");
    fs::write(&path, html)?;
    Ok(path.to_string_lossy().into_owned())
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
    use aros_types::{blake3_hex, CampaignSpec};
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
              "required_evidence": ["E2"],
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
            Some(aros_types::EvidenceLevel::E2DynamicAnomaly)
        );
        assert_eq!(out.campaign.state, CampaignState::Refuted);
        assert!(out.declared.required_evidence_met);
        assert!(out.declared.harness_digest.is_some());
        assert!(out
            .declared
            .report_path
            .as_ref()
            .is_some_and(|path| Path::new(path).is_file()));
    }

    #[test]
    fn g1_unwaived_declared_campaign_requires_contained_runtime() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        let harness = target.path().join("harness_ok.py");
        fs::write(&harness, "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n").unwrap();
        let spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let engine = CampaignEngine::new(false);
        let mut manifest = default_declared_manifest(target.path());
        manifest.require_containment = true;
        match engine.run_declared_campaign(&spec, target.path(), work.path(), manifest) {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("containment")
                        || msg.contains("Podman")
                        || msg.contains("OCI")
                        || msg.contains("image")
                        || msg.contains("rootless"),
                    "{msg}"
                );
            }
            Ok(out) => {
                assert!(
                    out.declared.contained,
                    "unwaived success must be a contained generator run"
                );
            }
        }
    }

    #[test]
    fn g2_required_e4_is_not_claimed_at_e2() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        let mut spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        spec.required_evidence = vec!["E2".into(), "E3".into(), "E4".into()];
        let work = tempfile::tempdir().unwrap();
        let engine = CampaignEngine::new(true);
        let out = engine
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert!(!out.declared.required_evidence_met);
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_eq!(out.campaign.state, CampaignState::InsufficientEvidence);
    }

    #[test]
    fn g3_harness_bytes_are_cas_addressed() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        let body = "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n";
        fs::write(target.path().join("harness_ok.py"), body).unwrap();
        let spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        let digest = out.declared.harness_digest.expect("harness digest");
        assert!(!digest.is_empty());
        assert_ne!(digest, blake3_hex(body.as_bytes()));
        let cas = ContentAddressedStore::open(work.path().join("cas"), 32 * 1024 * 1024).unwrap();
        let stored = cas.get(&digest).unwrap();
        assert!(stored
            .windows(body.len())
            .any(|window| window == body.as_bytes()));
    }

    #[test]
    fn g4_structural_controls_must_discriminate() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("good.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("mutant.py"),
            "print('OPEN_OK')\nprint('REPLAY_ACCEPTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        let mut spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        spec.structural_control = Some(aros_types::StructuralControl {
            good: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} good.py"),
                corpus: Some("good.py".into()),
            },
            mutant: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} mutant.py"),
                corpus: Some("mutant.py".into()),
            },
        });
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert_eq!(
            out.declared.control_good_result.as_deref(),
            Some("InvariantHolds")
        );
        assert_eq!(
            out.declared.control_mutant_result.as_deref(),
            Some("AttackSucceeded")
        );
    }

    #[test]
    fn g4_non_discriminating_mutant_fails_closed() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("good.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("mutant.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        let mut spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        spec.structural_control = Some(aros_types::StructuralControl {
            good: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} good.py"),
                corpus: Some("good.py".into()),
            },
            mutant: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} mutant.py"),
                corpus: Some("mutant.py".into()),
            },
        });
        let work = tempfile::tempdir().unwrap();
        let err = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutant") && msg.contains("untrustworthy"),
            "{msg}"
        );
    }

    #[test]
    fn g5_second_surface_can_break_the_campaign() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("cache.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("ratchet.py"),
            "print('OPEN_OK')\nprint('REPLAY_ACCEPTED')\n",
        )
        .unwrap();
        let mut spec = holding_spec(&format!("{python} cache.py"), "cache.py");
        spec.surfaces = vec![
            aros_types::NamedAttackSurface {
                name: "replay-cache".into(),
                entrypoints: vec!["ReplayCache".into()],
                files: vec![],
                generator: aros_types::CampaignGenerator {
                    kind: aros_types::GeneratorKind::Harness,
                    command: format!("{python} cache.py"),
                    corpus: Some("cache.py".into()),
                },
                oracle: None,
            },
            aros_types::NamedAttackSurface {
                name: "ratchet-key".into(),
                entrypoints: vec!["DoubleRatchet".into()],
                files: vec![],
                generator: aros_types::CampaignGenerator {
                    kind: aros_types::GeneratorKind::Harness,
                    command: format!("{python} ratchet.py"),
                    corpus: Some("ratchet.py".into()),
                },
                oracle: None,
            },
        ];
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert!(out
            .declared
            .surface_results
            .iter()
            .any(|row| row.contains("ratchet-key:AttackSucceeded")));
        assert_eq!(
            out.evidence_level,
            Some(EvidenceLevel::E3InvariantViolation)
        );
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn g6_unreproducible_toolchain_is_environment_mismatch() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"aros-nonexistent-channel\"\n",
        )
        .unwrap();
        let spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert_eq!(out.declared.run_kind, "environment_mismatch");
        assert!(out.finding.is_none());
        assert_eq!(out.campaign.state, CampaignState::Failed);
        assert!(out.evidence_level.is_none());
    }

    #[test]
    fn g6_windows_gnu_toolchain_pin_is_not_a_security_result() {
        if cfg!(all(windows, target_env = "gnu")) {
            return;
        }
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        fs::write(
            target.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable-x86_64-pc-windows-gnu\"\n",
        )
        .unwrap();
        let spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert_eq!(out.declared.run_kind, "environment_mismatch");
        assert!(out.finding.is_none());
        assert_eq!(out.campaign.state, CampaignState::Failed);
    }

    #[test]
    fn g7_report_contains_claim_levels_and_harness_digest() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        let spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        let html = fs::read_to_string(out.declared.report_path.as_ref().unwrap()).unwrap();
        assert!(html.contains("replay must not succeed"));
        assert!(html.contains("level achieved"));
        assert!(html.contains("required"));
        assert!(html.contains("harness digest"));
        assert!(html.contains("ledger verified"));
        assert!(html.contains(&out.declared.harness_digest.clone().unwrap()));
    }
}
