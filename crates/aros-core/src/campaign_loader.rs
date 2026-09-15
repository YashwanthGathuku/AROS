//! Load RedLab campaign files and execute their generator/oracle without FixtureKind.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aros_evidence::{ContentAddressedStore, EventLedger};
use aros_policy::shell::{argv_contains_shell_metacharacters, executable_is_shell};
use aros_store::Store;
use aros_types::{
    env_name, unix_now_ms, AuthorizationManifest, Campaign, CampaignGenerator, CampaignOracle,
    CampaignSpec, CampaignState, EvidenceLevel, ExpectedOutcome, FailureCategory, Finding,
    FindingId, HypothesisId, OracleDecides, ResearchEvent, ResearchFailureCard, RunId, TargetId,
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
                None,
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
                work_root,
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
                work_root,
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
        let mut surface_judgements: Vec<(String, OracleJudgement)> = Vec::new();
        let mut any_success = false;
        let mut all_hold = true;
        let mut shrink: Option<ShrinkProof> = None;
        for (name, generator, oracle) in spec.attack_plans() {
            if let Some(reason) = missing_generator_reason(target_root, &spec.id, generator) {
                return fail_closed_no_evidence(
                    reason,
                    campaign,
                    original.source_tree_digest,
                    store,
                    ledger,
                );
            }
            let stdout = run_arm(
                target_root,
                work_root,
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
            if let Some(proof) = parse_shrink(&stdout) {
                shrink = Some(proof);
            }
            let judgement = evaluate_oracle(&stdout, oracle);
            surface_results.push(format!("{name}:{judgement:?}"));
            surface_judgements.push((name.clone(), judgement));
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
        let mut minimized_digest = None;
        if judgement == OracleJudgement::AttackSucceeded {
            if let Some(proof) = &shrink {
                if let Some(bytes) = proof.bytes() {
                    let artifact = cas.put(&bytes, "application/octet-stream")?;
                    ledger.append(
                        ResearchEvent::EvidenceCreated {
                            campaign_id: campaign.id,
                            digest: artifact.digest_blake3.clone(),
                        },
                        vec![artifact.digest_blake3.clone()],
                    )?;
                    fs::write(work_root.join("minimized.bin"), &bytes)?;
                    minimized_digest = Some(artifact.digest_blake3);
                }
            }
        }
        let shrink_ok = minimized_digest.is_some();
        let independent = after.source_tree_digest == original.source_tree_digest
            && independently_reproduce(
                spec,
                target_root,
                work_root,
                &original.source_tree_digest,
                manifest.target_id,
                timeout,
                spec.resource_limits.memory_mb,
                require_container,
                &surface_judgements,
            );
        let raw_level = match judgement {
            OracleJudgement::AttackSucceeded if shrink_ok => EvidenceLevel::E5MinimizedReproduction,
            OracleJudgement::AttackSucceeded if independent => {
                EvidenceLevel::E4IndependentReproduction
            }
            OracleJudgement::AttackSucceeded => EvidenceLevel::E3InvariantViolation,
            OracleJudgement::InvariantHolds => EvidenceLevel::E2DynamicAnomaly,
            OracleJudgement::Indeterminate => EvidenceLevel::E0HypothesisOnly,
        };
        let required_met = evidence_satisfies_required(spec, raw_level, independent);
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
            minimized_digest.as_deref(),
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
                shrink_before: shrink.as_ref().map(|proof| proof.before),
                shrink_len: shrink.as_ref().map(|proof| proof.after),
                minimized_digest,
                failure_card_id: None,
                independent_reproduced: independent,
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

/// E4 is an independent re-run, not an ordinal step. E5 does not imply E4.
fn evidence_satisfies_required(
    spec: &CampaignSpec,
    achieved: EvidenceLevel,
    independent: bool,
) -> bool {
    spec.required_evidence.iter().all(|label| {
        let Some(required) = parse_level(label) else {
            return false;
        };
        match required {
            EvidenceLevel::E4IndependentReproduction => independent,
            EvidenceLevel::E6CounterfactualDifferential
            | EvidenceLevel::E7VariantReattackAndRegression => false,
            EvidenceLevel::E5MinimizedReproduction => {
                achieved == EvidenceLevel::E5MinimizedReproduction
            }
            _ => achieved >= required,
        }
    })
}

fn copy_source_tree(src: &Path, dst: &Path) -> Result<(), EngineError> {
    fs::create_dir_all(dst)?;
    for item in fs::read_dir(src)? {
        let item = item?;
        let name = item.file_name();
        if name == ".git" || name == "target" || name == "__pycache__" || name == ".aros" {
            continue;
        }
        let kind = item.file_type()?;
        if kind.is_symlink() {
            return Err(EngineError::FailClosed(format!(
                "symlink not allowed in E4 replica: {}",
                item.path().display()
            )));
        }
        let to = dst.join(name);
        if kind.is_dir() {
            copy_source_tree(&item.path(), &to)?;
        } else if kind.is_file() {
            fs::copy(item.path(), to)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn independently_reproduce(
    spec: &CampaignSpec,
    target_root: &Path,
    work_root: &Path,
    original_digest: &str,
    target_id: TargetId,
    timeout: Duration,
    memory_mb: u32,
    require_container: bool,
    expected: &[(String, OracleJudgement)],
) -> bool {
    let replica = work_root.join("e4-replica");
    if copy_source_tree(target_root, &replica).is_err() {
        return false;
    }
    let Ok(replica_snap) = snapshot_tree(target_id, &replica) else {
        return false;
    };
    if replica_snap.source_tree_digest != original_digest {
        return false;
    }
    let replica_work = work_root.join("e4-work");
    for (name, generator, oracle) in spec.attack_plans() {
        let Ok(stdout) = run_arm(
            &replica,
            &replica_work,
            generator,
            timeout,
            memory_mb,
            require_container,
        ) else {
            return false;
        };
        let judgement = evaluate_oracle(&stdout, oracle);
        let Some((_, expected_judgement)) = expected.iter().find(|(item, _)| item == &name) else {
            return false;
        };
        if judgement != *expected_judgement {
            return false;
        }
    }
    snapshot_tree(target_id, target_root)
        .ok()
        .is_some_and(|snap| snap.source_tree_digest == original_digest)
}

#[derive(Clone, Debug)]
struct ShrinkProof {
    before: usize,
    after: usize,
    hex: String,
}

impl ShrinkProof {
    fn bytes(&self) -> Option<Vec<u8>> {
        decode_hex(&self.hex)
    }
}

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let pair = std::str::from_utf8(&bytes[index..index + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
        index += 2;
    }
    Some(out)
}

fn parse_shrink(stdout: &str) -> Option<ShrinkProof> {
    let mut before = None;
    let mut after = None;
    let mut hex = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SHRINK_BEFORE ") {
            before = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("SHRINK_LEN ") {
            after = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("SHRINK_HEX ") {
            hex = Some(rest.trim().to_string());
        }
    }
    let after = after?;
    let hex = hex?;
    if after == 0 || decode_hex(&hex).map(|bytes| bytes.len()) != Some(after) {
        return None;
    }
    let before = before.unwrap_or(after);
    if after > before {
        return None;
    }
    Some(ShrinkProof { before, after, hex })
}

fn persist_failure_card(
    store: &Store,
    campaign: &Campaign,
    category: FailureCategory,
    detail: &str,
) -> Option<String> {
    let card = ResearchFailureCard {
        campaign_id: campaign.id,
        run_id: RunId::new(),
        category,
        detail: detail.to_string(),
    };
    let id = card.run_id.to_string();
    let payload = serde_json::to_string(&card).ok()?;
    store.put_record("failure_card", &id, &payload).ok()?;
    Some(id)
}

pub fn write_eval_miss_card(work: &Path, case_id: &str, observed: &str) -> std::io::Result<()> {
    fs::create_dir_all(work)?;
    let path = work.join("failure-cards.jsonl");
    let mut line = serde_json::json!({
        "case": case_id,
        "category": "EXPERIMENT_INADEQUATE",
        "detail": format!("known PoC case missed: expect verified observed {observed}"),
    })
    .to_string();
    line.push('\n');
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())
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

fn harness_catalog_root() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_name("HARNESS_CATALOG")) {
        let path = PathBuf::from(explicit);
        if path.is_dir() {
            return Some(path);
        }
    }
    let from_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("campaign-loader")
        .join("harnesses");
    if from_crate.is_dir() {
        return Some(from_crate);
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("campaign-loader").join("harnesses");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn catalog_harness_entry(id: &str) -> Option<PathBuf> {
    let root = harness_catalog_root()?;
    let harness = root.join(id).join("run.py");
    if harness.is_file() {
        return Some(harness);
    }
    let adapters = root.parent()?.join("adapters").join(id).join("run.py");
    adapters.is_file().then_some(adapters)
}

fn missing_generator_reason(
    target_root: &Path,
    spec_id: &str,
    generator: &CampaignGenerator,
) -> Option<String> {
    if let Some(id) = &generator.harness {
        if catalog_harness_entry(id).is_none() {
            return Some(format!(
                "campaign {spec_id} catalog harness {id} is not in the AROS catalog"
            ));
        }
        return None;
    }
    let corpus = generator.corpus.as_deref()?;
    if target_root.join(corpus).is_file() {
        return None;
    }
    Some(format!(
        "campaign {spec_id} generator corpus {corpus} is not present under {}; zero evidence",
        target_root.display()
    ))
}

fn stage_catalog_harness(
    work_root: &Path,
    generator: &CampaignGenerator,
) -> Result<Option<PathBuf>, EngineError> {
    let Some(id) = generator.harness.as_deref() else {
        return Ok(None);
    };
    let src = catalog_harness_entry(id)
        .ok_or_else(|| EngineError::FailClosed(format!("catalog harness {id} is missing")))?
        .parent()
        .ok_or_else(|| EngineError::FailClosed("catalog harness has no directory".into()))?
        .to_path_buf();
    let dest = work_root.join("aros-harness").join(id);
    fs::create_dir_all(&dest)?;
    for entry in fs::read_dir(&src)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        fs::copy(entry.path(), dest.join(entry.file_name()))?;
    }
    fs::write(dest.join("bind.json"), serde_json::to_vec(&generator.bind)?)?;
    Ok(Some(dest))
}

fn expand_command(command: &str, harness_dir: Option<&Path>) -> Result<String, EngineError> {
    if !command.contains("{harness}") {
        return Ok(command.to_string());
    }
    let dir = harness_dir.ok_or_else(|| {
        EngineError::FailClosed(
            "generator.command uses {harness} but generator.harness is unset".into(),
        )
    })?;
    Ok(command.replace("{harness}", &dir.to_string_lossy()))
}

fn rewrite_argv_for_container(argv: &[String], harness_dir: &Path) -> Vec<String> {
    let host = harness_dir.to_string_lossy();
    argv.iter()
        .map(|arg| {
            if arg.starts_with(host.as_ref()) {
                arg.replacen(host.as_ref(), "/aros-harness", 1)
            } else {
                arg.clone()
            }
        })
        .collect()
}

fn harness_relpaths(spec: &CampaignSpec) -> Vec<String> {
    let mut paths = Vec::new();
    let mut consider = |generator: &CampaignGenerator| {
        if let Some(corpus) = &generator.corpus {
            paths.push(corpus.clone());
        }
        if let Ok(argv) = generator_argv(&generator.command.replace("{harness}", "_")) {
            for token in argv.iter().skip(1) {
                if !token.starts_with('-') && !token.contains("{harness}") {
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

fn archive_file(
    cas: &ContentAddressedStore,
    campaign_id: aros_types::CampaignId,
    ledger: &mut EventLedger,
    combined: &mut Vec<u8>,
    label: &str,
    bytes: &[u8],
) -> Result<(), EngineError> {
    combined.extend_from_slice(label.as_bytes());
    combined.push(0);
    combined.extend_from_slice(bytes);
    let artifact = cas.put(bytes, "text/plain")?;
    ledger.append(
        ResearchEvent::EvidenceCreated {
            campaign_id,
            digest: artifact.digest_blake3.clone(),
        },
        vec![artifact.digest_blake3.clone()],
    )?;
    Ok(())
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
        archive_file(cas, campaign_id, ledger, &mut combined, &rel, &bytes)?;
    }
    let mut generators = Vec::new();
    for (_name, generator, _) in spec.attack_plans() {
        generators.push(generator);
    }
    if let Some(control) = &spec.structural_control {
        generators.push(&control.good);
        generators.push(&control.mutant);
    }
    for generator in generators {
        if let Some(id) = &generator.harness {
            if let Some(entry) = catalog_harness_entry(id) {
                if let Some(dir) = entry.parent() {
                    for file in fs::read_dir(dir)? {
                        let file = file?;
                        if !file.metadata()?.is_file() {
                            continue;
                        }
                        let name = file.file_name();
                        let label = format!("catalog:{id}/{}", name.to_string_lossy());
                        let bytes = fs::read(file.path())?;
                        archive_file(cas, campaign_id, ledger, &mut combined, &label, &bytes)?;
                    }
                }
            }
        }
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
    work_root: &Path,
    generator: &CampaignGenerator,
    timeout: Duration,
    memory_mb: u32,
    require_container: bool,
) -> Result<String, EngineError> {
    let staged = stage_catalog_harness(work_root, generator)?;
    let command = expand_command(&generator.command, staged.as_deref())?;
    let argv = generator_argv(&command)?;
    let bind_file = staged.as_ref().map(|path| path.join("bind.json"));
    if require_container {
        let container_argv = match staged.as_deref() {
            Some(dir) => rewrite_argv_for_container(&argv, dir),
            None => argv,
        };
        return aros_sandbox::CampaignOciTarget::exec_generator_ex(
            target_root,
            &container_argv,
            timeout,
            memory_mb,
            staged.as_deref(),
        )
        .map_err(|error| EngineError::FailClosed(error.to_string()));
    }
    run_generator(
        target_root,
        &argv,
        timeout,
        target_root,
        bind_file.as_deref(),
    )
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
    minimized_digest: Option<&str>,
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
         <p><b>minimized reproduction</b> {}</p>\
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
        html_escape(minimized_digest.unwrap_or("none")),
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
    let category = if message.contains("indeterminate") {
        FailureCategory::VerificationFailure
    } else {
        FailureCategory::ToolGap
    };
    let _ = persist_failure_card(&store, &campaign, category, &message);
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

fn run_generator(
    cwd: &Path,
    argv: &[String],
    timeout: Duration,
    target_root: &Path,
    bind_file: Option<&Path>,
) -> Result<String, EngineError> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(env_name("TARGET_ROOT"), target_root);
    if let Some(bind) = bind_file {
        command.env(env_name("BIND_FILE"), bind);
    }
    let mut child = command
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

pub fn class_campaign_dir() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_name("CLASS_CAMPAIGNS")) {
        let path = PathBuf::from(explicit);
        if path.is_dir() {
            return Some(path);
        }
    }
    let from_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("campaign-loader")
        .join("classes");
    if from_crate.is_dir() {
        return Some(from_crate);
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("campaign-loader").join("classes");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn overlay_surface_bind(spec: &mut CampaignSpec, surface: &crate::SurfaceMap) {
    if let Some(health) = surface.suggested_bind.get("health_path") {
        spec.generator
            .bind
            .entry("health_path".into())
            .or_insert_with(|| health.clone());
    }
    match spec.id.as_str() {
        "http-idor"
        | "http-unauth"
        | "http-cookie-confusion"
        | "http-mr-cookie-drop"
        | "http-mr-method"
        | "http-mr-cross-user"
        | "http-mr-header-noise"
        | "http-mr-xff" => {
            if let Some(path) = surface.suggested_bind.get("idor_path") {
                spec.generator
                    .bind
                    .insert("attack_path".into(), path.clone());
                spec.generator.bind.insert("path_b".into(), path.clone());
            }
        }
        "http-mr-query-noise" => {
            if let Some(path) = surface.suggested_bind.get("idor_path") {
                spec.generator
                    .bind
                    .insert("attack_path".into(), path.clone());
                spec.generator.bind.insert("path_a".into(), path.clone());
            }
        }
        "http-path-traversal" => {
            if let Some(path) = surface.suggested_bind.get("files_path") {
                spec.generator
                    .bind
                    .insert("attack_path".into(), path.clone());
            }
        }
        _ => {}
    }
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
        assert_eq!(replay.generator.harness.as_deref(), Some("dycrpt-lib"));
        assert_eq!(skip.generator.harness.as_deref(), Some("dycrpt-lib"));
    }

    #[test]
    fn missing_harness_fails_closed_without_verified_finding() {
        let spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        let target = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let engine = CampaignEngine::new(true);
        let manifest = default_declared_manifest(target.path());
        let mut spec = spec;
        spec.generator.command = format!("{} {{harness}}/run.py", python_bin());
        let err = engine
            .run_declared_campaign(&spec, target.path(), work.path(), manifest)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("indeterminate")
                || msg.contains("voicechat_crypto")
                || msg.contains("zero evidence"),
            "{msg}"
        );
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
                ..aros_types::CampaignGenerator::default()
            },
            mutant: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} mutant.py"),
                corpus: Some("mutant.py".into()),
                ..aros_types::CampaignGenerator::default()
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
                ..aros_types::CampaignGenerator::default()
            },
            mutant: aros_types::CampaignGenerator {
                kind: aros_types::GeneratorKind::Harness,
                command: format!("{python} mutant.py"),
                corpus: Some("mutant.py".into()),
                ..aros_types::CampaignGenerator::default()
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
                    ..aros_types::CampaignGenerator::default()
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
                    ..aros_types::CampaignGenerator::default()
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
            Some(EvidenceLevel::E4IndependentReproduction)
        );
        assert!(out.finding.as_ref().unwrap().verified);
        assert!(out.declared.independent_reproduced);
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

    fn catalog_spec(result_token: &str) -> CampaignSpec {
        let python = python_bin();
        let json = format!(
            r#"{{
              "id": "catalog-stdout-tokens",
              "security_class": "integrity",
              "historical_pattern": {{"summary": "catalog"}},
              "surface": {{"entrypoints": ["catalog"]}},
              "invariant": "catalog harness must run without files in the target",
              "attacker_capabilities": ["none"],
              "prerequisites": [],
              "resource_limits": {{"wall_clock_seconds": 30, "memory_mb": 64, "network": "none"}},
              "generator": {{
                "kind": "harness",
                "command": "{python} {{harness}}/run.py",
                "harness": "stdout-tokens",
                "bind": {{"open_token": "OPEN_OK", "result_token": "{result_token}"}}
              }},
              "oracle": {{
                "decides": "stdout_contains",
                "success_means": "attack token",
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
    fn catalog_harness_runs_without_files_in_the_target() {
        let target = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let spec = catalog_spec("REPLAY_REJECTED");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert_eq!(out.campaign.state, CampaignState::Refuted);
        assert_eq!(out.evidence_level, Some(EvidenceLevel::E2DynamicAnomaly));
        assert!(out.declared.harness_digest.is_some());
        assert!(target.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn unknown_catalog_harness_fails_closed() {
        let target = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let mut spec = catalog_spec("REPLAY_REJECTED");
        spec.generator.harness = Some("does-not-exist".into());
        let err = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("catalog harness"), "{msg}");
    }

    fn repo_class(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("campaign-loader")
            .join("classes")
            .join(name)
    }

    fn class_spec(name: &str) -> CampaignSpec {
        let mut spec = load_campaign_file(&repo_class(name)).unwrap();
        spec.generator.command = format!("{} {{harness}}/run.py", python_bin());
        spec
    }

    fn fixture_tree(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for part in parts {
            path.push(part);
        }
        path
    }

    #[test]
    fn http_idor_class_verifies_break_on_vulnerable_authz_fixture() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-idor.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
        assert_eq!(
            out.evidence_level,
            Some(EvidenceLevel::E4IndependentReproduction)
        );
        assert!(out.declared.independent_reproduced);
    }

    #[test]
    fn http_idor_class_holds_on_patched_authz_fixture() {
        let target = fixture_tree(&["fixtures", "patched", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-idor.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_eq!(out.campaign.state, CampaignState::Refuted);
    }

    #[test]
    fn http_path_class_verifies_break_on_vulnerable_path_fixture() {
        let target = fixture_tree(&["fixtures", "vulnerable", "path"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-path-traversal.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
        assert_eq!(
            out.evidence_level,
            Some(EvidenceLevel::E4IndependentReproduction)
        );
        assert!(out.declared.independent_reproduced);
    }

    #[test]
    fn http_surface_map_class_maps_without_claiming_an_exploit() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-surface-map.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_eq!(out.campaign.state, CampaignState::Refuted);
        let paths = crate::extract_http_paths_from_tree(&target).unwrap();
        assert!(paths.iter().any(|path| path == "/health"), "{paths:?}");
    }

    #[test]
    fn http_unauth_class_verifies_break_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-unauth.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_cookie_confusion_class_verifies_break_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-cookie-confusion.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn cli_crash_class_verifies_break_on_nul_parser() {
        let target = fixture_tree(&["fixtures", "vulnerable", "parser"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("cli-crash.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn lib_call_twice_class_verifies_replay_of_one_shot() {
        let target = fixture_tree(&["fixtures", "vulnerable", "once"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("lib-call-twice.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_cookie_drop_verifies_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-cookie-drop.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn mutate_fuzz_finds_nul_crash_and_shrinks() {
        let target = fixture_tree(&["fixtures", "vulnerable", "parser"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("mutate-fuzz.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
        assert_eq!(
            out.evidence_level,
            Some(EvidenceLevel::E5MinimizedReproduction)
        );
        assert_eq!(out.declared.shrink_len, Some(1));
        assert!(out.declared.minimized_digest.is_some());
        assert!(work.path().join("minimized.bin").is_file());
    }

    #[test]
    fn mutate_fuzz_independent_rerun_satisfies_required_e4() {
        let target = fixture_tree(&["fixtures", "vulnerable", "parser"]);
        let work = tempfile::tempdir().unwrap();
        let mut spec = class_spec("mutate-fuzz.campaign.json");
        spec.required_evidence = vec!["E4".into()];
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert_eq!(
            out.evidence_level,
            Some(EvidenceLevel::E5MinimizedReproduction)
        );
        assert!(out.declared.independent_reproduced);
        assert!(out.declared.required_evidence_met);
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn independent_hold_satisfies_required_e4_without_a_finding() {
        let python = python_bin();
        let target = tempfile::tempdir().unwrap();
        fs::write(
            target.path().join("harness_ok.py"),
            "print('OPEN_OK')\nprint('REPLAY_REJECTED')\n",
        )
        .unwrap();
        let mut spec = holding_spec(&format!("{python} harness_ok.py"), "harness_ok.py");
        spec.required_evidence = vec!["E2".into(), "E4".into()];
        let work = tempfile::tempdir().unwrap();
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap();
        assert!(out.declared.independent_reproduced);
        assert!(out.declared.required_evidence_met);
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_eq!(out.campaign.state, CampaignState::Refuted);
        assert_eq!(out.evidence_level, Some(EvidenceLevel::E2DynamicAnomaly));
    }

    #[test]
    fn unknown_harness_records_a_failure_card() {
        let target = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let mut spec = catalog_spec("REPLAY_REJECTED");
        spec.generator.harness = Some("does-not-exist".into());
        let err = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .unwrap_err();
        assert!(err.to_string().contains("catalog harness"), "{err}");
        let store = Store::open(&work.path().join(aros_types::DATABASE_FILE)).unwrap();
        let cards = store.list_records("failure_card").unwrap();
        assert!(!cards.is_empty(), "expected a ResearchFailureCard");
        assert!(
            cards[0].1.contains("TOOL_GAP"),
            "failure card payload: {}",
            cards[0].1
        );
    }

    #[test]
    fn http_mr_cross_user_verifies_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-cross-user.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_header_noise_holds_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-header-noise.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_encoded_dotdot_verifies_on_vulnerable_path() {
        let target = fixture_tree(&["fixtures", "vulnerable", "path"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-encoded-dotdot.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn klee_run_holds_without_inventing_a_bitcode_result() {
        let target = fixture_tree(&["fixtures", "vulnerable", "parser"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("klee-run.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_dot_segment_verifies_on_vulnerable_path() {
        let target = fixture_tree(&["fixtures", "vulnerable", "path"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-dot-segment.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_encoded_dot_verifies_on_vulnerable_path() {
        let target = fixture_tree(&["fixtures", "vulnerable", "path"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-encoded-dot.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn http_mr_xff_holds_on_vulnerable_authz() {
        let target = fixture_tree(&["fixtures", "vulnerable", "authz"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("http-mr-xff.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
    }

    #[test]
    fn prop_ascii_holds_on_nul_parser() {
        let target = fixture_tree(&["fixtures", "vulnerable", "parser"]);
        let work = tempfile::tempdir().unwrap();
        let spec = class_spec("prop-ascii.campaign.json");
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                &target,
                work.path(),
                default_declared_manifest(&target),
            )
            .unwrap();
        assert!(!out.finding.as_ref().unwrap().verified);
    }

    fn checkout_pinned_dycrpt(dest: &Path) -> bool {
        const PIN: &str = "e4e200ad71bda9ef81ea0bfa4c6e427dc9d7d82c";
        const URL: &str = "https://github.com/YashwanthGathuku/dycrpt.git";
        let init = Command::new("git").arg("init").arg(dest).status();
        if !init.is_ok_and(|status| status.success()) {
            return false;
        }
        let remote = Command::new("git")
            .current_dir(dest)
            .args(["remote", "add", "origin", URL])
            .status();
        if !remote.is_ok_and(|status| status.success()) {
            return false;
        }
        let fetch = Command::new("git")
            .current_dir(dest)
            .args(["fetch", "--depth", "1", "origin", PIN])
            .status();
        if !fetch.is_ok_and(|status| status.success()) {
            return false;
        }
        Command::new("git")
            .current_dir(dest)
            .args(["checkout", "FETCH_HEAD"])
            .status()
            .is_ok_and(|status| status.success())
            && dest.join("Cargo.toml").is_file()
    }

    #[test]
    fn dycrpt_adapter_source_calls_decrypt() {
        let replay = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("campaign-loader/adapters/dycrpt-lib/replay.rs");
        let raw = fs::read_to_string(replay).unwrap();
        assert!(raw.contains("decrypt("), "{raw}");
        assert!(raw.contains("VoiceChatCryptoEngine"), "{raw}");
        assert!(!raw.contains("todo!("), "{raw}");
    }

    #[test]
    fn dycrpt_replay_adapter_calls_open_path_when_target_present() {
        let target = tempfile::tempdir().unwrap();
        if !checkout_pinned_dycrpt(target.path()) {
            eprintln!("skip dycrpt live adapter: pinned checkout failed");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let mut spec =
            load_campaign_file(&repo_campaign("dycrpt-replay-resistance.campaign.json")).unwrap();
        spec.generator.command = format!("{} {{harness}}/run.py", python_bin());
        let out = CampaignEngine::new(true)
            .run_declared_campaign(
                &spec,
                target.path(),
                work.path(),
                default_declared_manifest(target.path()),
            )
            .expect("adapter must run against pinned voicechat_crypto");
        assert!(!out.finding.as_ref().unwrap().verified);
        assert_ne!(
            out.evidence_level,
            Some(EvidenceLevel::E0HypothesisOnly),
            "decrypt path must produce an observation"
        );
        let report = fs::read_to_string(out.declared.report_path.as_ref().unwrap()).unwrap();
        assert!(report.contains("dycrpt-replay-resistance"), "{report}");
    }
}
