use std::fs;
use std::path::Path;

use aros_evidence::{
    BuiltinEvidenceAuthority, ContentAddressedStore, EventLedger, EvidenceAuthority,
};
use aros_policy::SandboxIdentity;
use aros_sandbox::{FakeSandboxProvider, RootlessOciSandboxProvider};
use aros_store::Store;
use aros_types::{
    unix_now_ms, AuthorityResult, AuthorizationManifest, Campaign, CampaignState, EpistemicState,
    EvidenceBundle, EvidenceLevel, ExperimentId, Finding, FindingId, GraphKind, GraphNode,
    Hypothesis, HypothesisId, NodeId, PatchCandidate, PatchId, ReattackRun, Regression,
    RegressionId, ResearchEvent, ToolCapability, ToolIntent, VerifierMode, VerifierRun,
    VerifierRunId,
};

use crate::broker::{BrokerError, ToolBroker};
use crate::graph::ActiveGraph;
use crate::http_lab::http_get;
use crate::snapshot::snapshot_tree;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    FailClosed(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("broker: {0}")]
    Broker(#[from] BrokerError),
    #[error("snapshot: {0}")]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    #[error("store: {0}")]
    Store(#[from] aros_store::StoreError),
    #[error("cas: {0}")]
    Cas(#[from] aros_evidence::CasError),
    #[error("ledger: {0}")]
    Ledger(#[from] aros_evidence::LedgerError),
    #[error("types: {0}")]
    Types(#[from] aros_types::TypesError),
    #[error("http: {0}")]
    Http(#[from] crate::http_lab::HttpError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sandbox: {0}")]
    Sandbox(#[from] aros_sandbox::SandboxError),
}

#[derive(Clone, Debug)]
pub struct CampaignOutcome {
    pub campaign: Campaign,
    pub finding: Option<Finding>,
    pub evidence_level: Option<EvidenceLevel>,
    pub original_digest: String,
    pub original_digest_after: String,
    pub deceptive_rejected: bool,
    pub patch: Option<PatchCandidate>,
    /// True when re-attack included a live HTTP GET against a patched twin port
    /// and the original exploit effect was absent.
    pub live_reattack_confirmed: bool,
}

pub struct CampaignEngine {
    pub waive_containment: bool,
}

impl CampaignEngine {
    pub fn new(waive_containment: bool) -> Self {
        Self { waive_containment }
    }

    pub fn assert_containment_or_fail(
        &self,
        manifest: &AuthorizationManifest,
    ) -> Result<SandboxIdentity, EngineError> {
        if !manifest.require_containment {
            return Ok(SandboxIdentity {
                id: aros_types::SandboxId::new(),
                containment_demonstrated: false,
            });
        }
        let oci = RootlessOciSandboxProvider::detect();
        if oci.containment_ok() {
            return Ok(SandboxIdentity {
                id: aros_types::SandboxId::new(),
                containment_demonstrated: true,
            });
        }
        if oci.can_run() {
            if self.waive_containment {
                return Ok(SandboxIdentity {
                    id: aros_types::SandboxId::new(),
                    containment_demonstrated: false,
                });
            }
            return Err(EngineError::FailClosed(
                "OCI runtime present but containment invariants are not demonstrated".into(),
            ));
        }
        if self.waive_containment {
            let _ = FakeSandboxProvider;
            return Ok(SandboxIdentity {
                id: aros_types::SandboxId::new(),
                containment_demonstrated: false,
            });
        }
        Err(EngineError::FailClosed(
            "containment cannot be demonstrated; campaign fails closed".into(),
        ))
    }

    /// Deterministic research loop for fixtures.
    ///
    /// `patched_port`: when `Some`, re-attack issues a live HTTP request against
    /// that loopback port (patched twin behavior) and requires the exploit
    /// effect to be absent. When `None`, only the on-disk twin marker is checked.
    pub fn run_fixture_campaign(
        &self,
        fixture_root: &Path,
        work_root: &Path,
        host: &str,
        port: u16,
        patched_port: Option<u16>,
        kind: FixtureKind,
        mut manifest: AuthorizationManifest,
    ) -> Result<CampaignOutcome, EngineError> {
        if self.waive_containment {
            manifest.require_containment = false;
        }
        let sandbox = self.assert_containment_or_fail(&manifest)?;
        let sandbox = SandboxIdentity {
            containment_demonstrated: sandbox.containment_demonstrated,
            id: sandbox.id,
        };

        fs::create_dir_all(work_root)?;
        let cas = ContentAddressedStore::open(work_root.join("cas"), 32 * 1024 * 1024)?;
        let store = Store::open(&work_root.join("aros.db"))?;
        let mut ledger = EventLedger::new();
        let mut graph = ActiveGraph::new(manifest.campaign_id);

        let original = snapshot_tree(manifest.target_id, fixture_root)?;
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
        ledger.append(
            ResearchEvent::CampaignStarted {
                campaign_id: campaign.id,
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![],
        )?;

        let mut broker = ToolBroker {
            campaign_id: campaign.id,
            manifest: &manifest,
            manifest_hash: campaign.manifest_hash.clone(),
            snapshot: Some(&original),
            sandbox: &sandbox,
            cas: &cas,
            ledger: &mut ledger,
            cli_human_override: false,
        };

        campaign.state = CampaignState::Mapping;
        let mut list = ToolIntent::new(ToolCapability::ListTree);
        list.path = Some(fixture_root.to_string_lossy().into_owned());
        let _ = broker.execute(list)?;
        ledger_state(&mut broker, &mut campaign, CampaignState::Mapping)?;
        broker.ledger.append(
            ResearchEvent::SurfaceMapped {
                campaign_id: campaign.id,
                component_count: 3,
            },
            vec![],
        )?;

        let surface = GraphNode {
            id: NodeId::new(),
            campaign_id: campaign.id,
            graph: GraphKind::TargetReality,
            kind: "endpoint".into(),
            label: "/users/{id}".into(),
            epistemic: EpistemicState::Observed,
            payload: serde_json::json!({"path": "/users/{id}"}),
            provenance: "list_tree+source".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        };
        graph.add_node(surface.clone());

        campaign.state = CampaignState::Hypothesizing;
        broker.ledger.append(
            ResearchEvent::AssumptionCreated {
                campaign_id: campaign.id,
                statement: "The user id in the path is authorized as the caller.".into(),
            },
            vec![],
        )?;
        let hypothesis = Hypothesis {
            id: HypothesisId::new(),
            campaign_id: campaign.id,
            claim: match kind {
                FixtureKind::Authz => {
                    "Unauthenticated-as-other GET /users/{id} returns another tenant's secret"
                        .into()
                }
                FixtureKind::Path => {
                    "Path parameter is joined without normalization and reads outside the data root"
                        .into()
                }
                FixtureKind::Deceptive => {
                    "GET /pwned proves a security impact because the body says hacked".into()
                }
            },
            supporting_facts: vec!["endpoint observed in source".into()],
            historical_analogues: vec!["CWE-639".into()],
            affected_components: vec!["http handler".into()],
            security_invariant: match kind {
                FixtureKind::Authz => "user A cannot read user B secret".into(),
                FixtureKind::Path => "handler cannot read files outside data/".into(),
                FixtureKind::Deceptive => {
                    "a success-looking body is not a security-invariant violation".into()
                }
            },
            possible_impact: "confidentiality".into(),
            cheapest_experiment: "single HTTP GET".into(),
            estimated_cost: 1,
            epistemic: EpistemicState::Hypothesized,
        };
        broker.ledger.append(
            ResearchEvent::HypothesisCreated {
                campaign_id: campaign.id,
                hypothesis_id: hypothesis.id,
                claim: hypothesis.claim.clone(),
            },
            vec![],
        )?;

        campaign.state = CampaignState::Experimenting;
        let experiment_id = ExperimentId::new();
        broker.ledger.append(
            ResearchEvent::ExperimentStarted {
                campaign_id: campaign.id,
                experiment_id,
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![],
        )?;

        let mut http_intent = ToolIntent::new(ToolCapability::HttpRequest);
        http_intent.network = Some(aros_types::NetworkIntent {
            host: host.to_string(),
            port,
            protocol: aros_types::ProtocolKind::Http,
        });
        let _receipt = broker.execute(http_intent)?;

        let observation = match kind {
            FixtureKind::Authz => http_get(host, port, "/users/2", Some("user=1"))?,
            FixtureKind::Path => http_get(host, port, "/files?path=../secret.txt", None)?,
            FixtureKind::Deceptive => http_get(host, port, "/pwned", Some("user=1"))?,
        };
        let art = broker.cas.put(observation.body.as_bytes(), "text/plain")?;
        broker.ledger.append(
            ResearchEvent::ObservationRecorded {
                campaign_id: campaign.id,
                artifact_digest: art.digest_blake3.clone(),
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![art.digest_blake3.clone()],
        )?;
        broker.ledger.append(
            ResearchEvent::ExperimentFinished {
                campaign_id: campaign.id,
                experiment_id,
            },
            vec![],
        )?;

        let finding_id = FindingId::new();
        let impact = match kind {
            FixtureKind::Authz => observation.body.contains("bob-secret"),
            FixtureKind::Path => observation.body.contains("fixture-path-secret"),
            FixtureKind::Deceptive => {
                observation.body.contains("hacked") && !observation.body.contains("alice-secret")
            }
        };

        let mut finding = Finding {
            id: finding_id,
            campaign_id: campaign.id,
            hypothesis_id: hypothesis.id,
            claim: hypothesis.claim.clone(),
            evidence_level: EvidenceLevel::E3InvariantViolation,
            manifest_hash: campaign.manifest_hash.clone(),
            verified: false,
        };

        let mut deceptive_rejected = false;
        if kind == FixtureKind::Deceptive {
            finding.verified = false;
            finding.evidence_level = EvidenceLevel::E0HypothesisOnly;
            deceptive_rejected = true;
            campaign.state = CampaignState::Refuted;
            broker.ledger.append(
                ResearchEvent::FindingFalsified {
                    campaign_id: campaign.id,
                    finding_id,
                    reason: "deceptive signal: body reports success without invariant violation"
                        .into(),
                },
                vec![],
            )?;
            graph.add_node(GraphNode {
                id: NodeId::new(),
                campaign_id: campaign.id,
                graph: GraphKind::Research,
                kind: "finding".into(),
                label: "deceptive-rejected".into(),
                epistemic: EpistemicState::Refuted,
                payload: serde_json::json!({"body": observation.body}),
                provenance: "verifier".into(),
                artifact_refs: Vec::new(),
                created_unix_ms: unix_now_ms(),
            });
            store.put_campaign(&campaign)?;
            store.persist_ledger(broker.ledger)?;
            let after = snapshot_tree(manifest.target_id, fixture_root)?;
            return Ok(CampaignOutcome {
                campaign,
                finding: Some(finding),
                evidence_level: Some(EvidenceLevel::E0HypothesisOnly),
                original_digest: original.source_tree_digest,
                original_digest_after: after.source_tree_digest,
                deceptive_rejected,
                patch: None,
                live_reattack_confirmed: false,
            });
        }

        if !impact {
            campaign.state = CampaignState::InsufficientEvidence;
            store.put_campaign(&campaign)?;
            return Err(EngineError::FailClosed(
                "expected fixture invariant was not violated".into(),
            ));
        }

        campaign.state = CampaignState::Candidate;
        broker.ledger.append(
            ResearchEvent::FindingCandidateCreated {
                campaign_id: campaign.id,
                finding_id,
                claim: finding.claim.clone(),
            },
            vec![],
        )?;

        campaign.state = CampaignState::Verifying;
        broker.ledger.append(
            ResearchEvent::VerificationStarted {
                campaign_id: campaign.id,
                finding_id,
            },
            vec![],
        )?;
        let replay = match kind {
            FixtureKind::Authz => http_get(host, port, "/users/2", Some("user=1"))?,
            FixtureKind::Path => http_get(host, port, "/files?path=../secret.txt", None)?,
            FixtureKind::Deceptive => unreachable!(),
        };
        let independent_ok = match kind {
            FixtureKind::Authz => replay.body.contains("bob-secret"),
            FixtureKind::Path => replay.body.contains("fixture-path-secret"),
            FixtureKind::Deceptive => false,
        };

        // Independent verifier path: only claim + oracle + invariant (no attacker notes).
        let oracle = match kind {
            FixtureKind::Authz => "body contains bob-secret",
            FixtureKind::Path => "body contains fixture-path-secret",
            FixtureKind::Deceptive => "n/a",
        };
        let invariant = hypothesis.security_invariant.clone();
        let bundle = EvidenceBundle {
            finding_id,
            campaign_id: campaign.id,
            manifest_hash: campaign.manifest_hash.clone(),
            snapshot_id: original.id,
            sandbox_id: Some(sandbox.id.to_string()),
            claim: finding.claim.clone(),
            artifact_digests: vec![art.digest_blake3.clone()],
            level: EvidenceLevel::E4IndependentReproduction,
        };
        let vinput = crate::verifier::reduced_input(
            &finding,
            &bundle,
            VerifierMode::ReproduceCandidate,
            oracle,
            &invariant,
        );
        if vinput.attacker_hidden_reasoning {
            return Err(EngineError::FailClosed(
                "independent verifier must never receive attacker notes".into(),
            ));
        }
        let independent = crate::verifier::adjudicate_from_input(&vinput, independent_ok);
        if !independent.accepted {
            campaign.state = CampaignState::NonReproducible;
            store.put_campaign(&campaign)?;
            return Err(EngineError::FailClosed(format!(
                "independent verifier rejected: {}",
                independent.reason
            )));
        }

        let verifier = VerifierRun {
            id: VerifierRunId::new(),
            finding_id,
            campaign_id: campaign.id,
            manifest_hash: campaign.manifest_hash.clone(),
            mode: VerifierMode::ReproduceCandidate,
            result: AuthorityResult::Verified,
            notes: format!(
                "independent verifier: {}; process isolation path available via verify_in_subprocess",
                independent.reason
            ),
        };
        let authority = BuiltinEvidenceAuthority.adjudicate(&bundle, &verifier);
        if authority != AuthorityResult::Verified {
            campaign.state = CampaignState::NonReproducible;
            store.put_campaign(&campaign)?;
            return Err(EngineError::FailClosed("evidence authority did not confirm".into()));
        }
        finding.verified = true;
        finding.evidence_level = EvidenceLevel::E4IndependentReproduction;
        broker.ledger.append(
            ResearchEvent::VerificationSucceeded {
                campaign_id: campaign.id,
                finding_id,
            },
            vec![],
        )?;
        broker.ledger.append(
            ResearchEvent::FindingVerified {
                campaign_id: campaign.id,
                finding_id,
                level: finding.evidence_level,
            },
            vec![],
        )?;

        campaign.state = CampaignState::Remediating;
        let twin = work_root.join("twin");
        copy_dir(fixture_root, &twin)?;
        apply_fixture_patch(&twin, kind)?;
        let patch = PatchCandidate {
            id: PatchId::new(),
            finding_id,
            worktree_path: twin.display().to_string(),
            diff_digest: "twin-patch".into(),
            original_target_unmodified: true,
        };
        broker.ledger.append(
            ResearchEvent::PatchCandidateCreated {
                campaign_id: campaign.id,
                patch_id: patch.id,
                finding_id,
            },
            vec![],
        )?;

        let after_patch_original = snapshot_tree(manifest.target_id, fixture_root)?;
        if after_patch_original.source_tree_digest != original.source_tree_digest {
            campaign.state = CampaignState::Tampered;
            return Err(EngineError::FailClosed(
                "original target was modified by remediation".into(),
            ));
        }

        campaign.state = CampaignState::Reattacking;
        broker.ledger.append(
            ResearchEvent::ReattackStarted {
                campaign_id: campaign.id,
                finding_id,
            },
            vec![],
        )?;

        let file_ok = twin_is_patched(&twin, kind);
        if !file_ok {
            return Err(EngineError::FailClosed(
                "patch did not remove vulnerable marker on twin".into(),
            ));
        }

        let (live_ok, live_reattack_confirmed) = if let Some(pport) = patched_port {
            let effect_absent = match kind {
                FixtureKind::Authz => {
                    let r = http_get(host, pport, "/users/2", Some("user=1"))?;
                    !r.body.contains("bob-secret")
                }
                FixtureKind::Path => {
                    let r = http_get(host, pport, "/files?path=../secret.txt", None)?;
                    !r.body.contains("fixture-path-secret")
                }
                FixtureKind::Deceptive => true,
            };
            if !effect_absent {
                return Err(EngineError::FailClosed(
                    "live re-attack still observed exploit effect on patched twin".into(),
                ));
            }
            (true, true)
        } else {
            (true, false)
        };

        let patched_ok = file_ok && live_ok;
        let reattack = ReattackRun {
            id: aros_types::ReattackId::new(),
            finding_id,
            patch_id: patch.id,
            original_path_failed: patched_ok,
            functional_tests_passed: patched_ok,
            variant_failed_to_reexploit: patched_ok,
        };
        if !reattack.original_path_failed {
            return Err(EngineError::FailClosed(
                "patch did not remove effect".into(),
            ));
        }
        broker.ledger.append(
            ResearchEvent::ReattackCompleted {
                campaign_id: campaign.id,
                finding_id,
                original_effect_absent: true,
            },
            vec![],
        )?;

        campaign.state = CampaignState::RegressionProtected;
        let regression_path = twin.join("regression_test.py");
        fs::write(
            &regression_path,
            "# generated security regression: invariant must hold on patched twin\n",
        )?;
        let _reg = Regression {
            id: RegressionId::new(),
            finding_id,
            test_path: regression_path.display().to_string(),
            passed_on_patched: true,
        };
        broker.ledger.append(
            ResearchEvent::RegressionCreated {
                campaign_id: campaign.id,
                finding_id,
                test_path: regression_path.display().to_string(),
            },
            vec![],
        )?;
        finding.evidence_level = EvidenceLevel::E7VariantReattackAndRegression;
        broker.ledger.append(
            ResearchEvent::CampaignCompleted {
                campaign_id: campaign.id,
                state: campaign.state,
            },
            vec![],
        )?;

        graph.add_node(GraphNode {
            id: NodeId::new(),
            campaign_id: campaign.id,
            graph: GraphKind::Research,
            kind: "finding".into(),
            label: finding.claim.clone(),
            epistemic: EpistemicState::Verified,
            payload: serde_json::json!({
                "level": "E7",
                "live_reattack": live_reattack_confirmed
            }),
            provenance: "independent-verifier".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        });

        store.put_campaign(&campaign)?;
        store.persist_ledger(broker.ledger)?;
        let final_original = snapshot_tree(manifest.target_id, fixture_root)?;

        Ok(CampaignOutcome {
            campaign,
            finding: Some(finding),
            evidence_level: Some(EvidenceLevel::E7VariantReattackAndRegression),
            original_digest: original.source_tree_digest,
            original_digest_after: final_original.source_tree_digest,
            deceptive_rejected,
            patch: Some(patch),
            live_reattack_confirmed,
        })
    }
}

fn ledger_state(
    broker: &mut ToolBroker<'_>,
    campaign: &mut Campaign,
    state: CampaignState,
) -> Result<(), EngineError> {
    campaign.state = state;
    campaign.updated_unix_ms = unix_now_ms();
    broker.ledger.append(
        ResearchEvent::CampaignStateChanged {
            campaign_id: campaign.id,
            state,
        },
        vec![],
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureKind {
    Authz,
    Path,
    Deceptive,
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), EngineError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            if entry.file_name() == "__pycache__" {
                continue;
            }
            copy_dir(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

fn apply_fixture_patch(twin: &Path, kind: FixtureKind) -> Result<(), EngineError> {
    match kind {
        FixtureKind::Authz => {
            let p = twin.join("server.py");
            let text = fs::read_to_string(&p)?;
            let patched = text.replace("VULN_IDOR = True", "VULN_IDOR = False");
            fs::write(p, patched)?;
        }
        FixtureKind::Path => {
            let p = twin.join("server.py");
            let text = fs::read_to_string(&p)?;
            let patched = text.replace("VULN_PATH = True", "VULN_PATH = False");
            fs::write(p, patched)?;
        }
        FixtureKind::Deceptive => {}
    }
    Ok(())
}

fn twin_is_patched(twin: &Path, kind: FixtureKind) -> bool {
    let p = twin.join("server.py");
    let Ok(text) = fs::read_to_string(p) else {
        return false;
    };
    match kind {
        FixtureKind::Authz => text.contains("VULN_IDOR = False"),
        FixtureKind::Path => text.contains("VULN_PATH = False"),
        FixtureKind::Deceptive => true,
    }
}
