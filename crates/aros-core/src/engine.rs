use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aros_evidence::{ContentAddressedStore, EventLedger, EvidenceAuthority, TheustadAdapter};
use aros_policy::SandboxIdentity;
use aros_store::Store;
use aros_types::{
    env_name, unix_now_ms, AuthorityResult, AuthorizationManifest, Campaign, CampaignState,
    EpistemicState, EvidenceBundle, EvidenceLevel, ExperimentId, Finding, FindingId, GraphEdge,
    GraphKind, GraphNode, Hypothesis, HypothesisId, NodeId, PatchCandidate, PatchId, ReattackRun,
    Regression, RegressionId, ResearchCard, ResearchEvent, ToolCapability, ToolIntent,
    VerifierMode, VerifierRun, VerifierRunId,
};

use crate::broker::{BrokerError, ToolBroker};
use crate::graph::ActiveGraph;
use crate::http_lab::http_get;
use crate::snapshot::snapshot_tree;
use crate::verifier::{FixtureReplayKind, VerifierOracle, VerifierReplay};

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
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
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
    pub live_reattack_confirmed: bool,
    pub research_card_id: Option<String>,
    pub verifier_isolated: bool,
}

pub struct CampaignEngine {
    pub waive_containment: bool,
}

impl CampaignEngine {
    pub fn new(waive_containment: bool) -> Self {
        Self { waive_containment }
    }

    /// The current fixture engine executes its broker and target orchestration on
    /// the host. A successful OCI admission probe therefore cannot be converted
    /// into a positive `SandboxIdentity`: proof of capability is not proof of
    /// execution. Until a campaign-bound OCI runtime is wired, containment-
    /// required campaigns fail closed. Explicit development waivers are marked
    /// uncontained and must not be reported as contained evidence.
    pub fn assert_containment_or_fail(
        &self,
        manifest: &AuthorizationManifest,
    ) -> Result<SandboxIdentity, EngineError> {
        if !manifest.require_containment || self.waive_containment {
            return Ok(SandboxIdentity {
                id: aros_types::SandboxId::new(),
                containment_demonstrated: false,
            });
        }
        let report = aros_sandbox::RootlessOciSandboxProvider::detect().probe_containment_fresh();
        let diagnostic = if report.live_oci_claimable() {
            "OCI isolation is available but is not bound to this host-side campaign execution"
        } else {
            "OCI containment is not demonstrated on this host"
        };
        Err(EngineError::FailClosed(format!(
            "{diagnostic}; refusing to mint a synthetic sandbox identity"
        )))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_fixture_campaign(
        &self,
        fixture_root: &Path,
        work_root: &Path,
        host: &str,
        port: u16,
        _patched_port: Option<u16>,
        kind: FixtureKind,
        mut manifest: AuthorizationManifest,
    ) -> Result<CampaignOutcome, EngineError> {
        if self.waive_containment {
            manifest.require_containment = false;
        }
        let sandbox = self.assert_containment_or_fail(&manifest)?;

        fs::create_dir_all(work_root)?;
        let cas = ContentAddressedStore::open(work_root.join("cas"), 32 * 1024 * 1024)?;
        let store = Store::open(&work_root.join(aros_types::DATABASE_FILE))?;
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

        ledger_state(&mut broker, &mut campaign, CampaignState::Mapping)?;
        let mut list = ToolIntent::new(ToolCapability::ListTree);
        list.path = Some(fixture_root.to_string_lossy().into_owned());
        let _ = broker.execute(list)?;
        broker.ledger.append(
            ResearchEvent::SurfaceMapped {
                campaign_id: campaign.id,
                component_count: 1,
            },
            vec![],
        )?;

        let surface = GraphNode {
            id: NodeId::new(),
            campaign_id: campaign.id,
            graph: GraphKind::TargetReality,
            kind: "endpoint".into(),
            label: fixture_endpoint(kind).into(),
            epistemic: EpistemicState::Observed,
            payload: serde_json::json!({"path": fixture_endpoint(kind)}),
            provenance: "list_tree+source".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        };
        let surface_id = graph.add_node(surface);

        ledger_state(&mut broker, &mut campaign, CampaignState::Hypothesizing)?;
        broker.ledger.append(
            ResearchEvent::AssumptionCreated {
                campaign_id: campaign.id,
                statement: hypothesis_invariant(kind).into(),
            },
            vec![],
        )?;
        let assumption_id = NodeId::new();
        graph.add_node(GraphNode {
            id: assumption_id,
            campaign_id: campaign.id,
            graph: GraphKind::Research,
            kind: "assumption".into(),
            label: hypothesis_invariant(kind).into(),
            epistemic: EpistemicState::Observed,
            payload: serde_json::json!({"statement": hypothesis_invariant(kind)}),
            provenance: "campaign-observation".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        });
        graph.add_edge(graph_edge(
            campaign.id,
            surface_id,
            assumption_id,
            "supports",
            EpistemicState::Observed,
        ));
        let hypothesis = Hypothesis {
            id: HypothesisId::new(),
            campaign_id: campaign.id,
            claim: hypothesis_claim(kind).into(),
            supporting_facts: vec!["endpoint observed in source".into()],
            historical_analogues: vec![match kind {
                FixtureKind::Authz => "CWE-639".into(),
                FixtureKind::Path => "CWE-22".into(),
                FixtureKind::Deceptive => "negative-control".into(),
            }],
            affected_components: vec!["http handler".into()],
            security_invariant: hypothesis_invariant(kind).into(),
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
        let hypothesis_node = NodeId::new();
        graph.add_node(GraphNode {
            id: hypothesis_node,
            campaign_id: campaign.id,
            graph: GraphKind::Research,
            kind: "hypothesis".into(),
            label: hypothesis.claim.clone(),
            epistemic: EpistemicState::Hypothesized,
            payload: serde_json::to_value(&hypothesis)?,
            provenance: "research-hypothesis".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        });
        graph.add_edge(graph_edge(
            campaign.id,
            assumption_id,
            hypothesis_node,
            "motivates",
            EpistemicState::Hypothesized,
        ));
        store.put_record(
            "hypothesis",
            &hypothesis.id.to_string(),
            &serde_json::to_string(&hypothesis)?,
        )?;

        ledger_state(&mut broker, &mut campaign, CampaignState::Experimenting)?;
        let experiment_id = ExperimentId::new();
        broker.ledger.append(
            ResearchEvent::ExperimentStarted {
                campaign_id: campaign.id,
                experiment_id,
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![],
        )?;
        let experiment_node = NodeId::new();
        graph.add_node(GraphNode {
            id: experiment_node,
            campaign_id: campaign.id,
            graph: GraphKind::Research,
            kind: "experiment".into(),
            label: "cheapest experiment".into(),
            epistemic: EpistemicState::Observed,
            payload: serde_json::json!({"experiment_id": experiment_id.to_string(), "description": hypothesis.cheapest_experiment}),
            provenance: "experiment-planner".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        });
        graph.add_edge(graph_edge(
            campaign.id,
            hypothesis_node,
            experiment_node,
            "tested_by",
            EpistemicState::Observed,
        ));
        let mut http_intent = ToolIntent::new(ToolCapability::HttpRequest);
        http_intent.network = Some(aros_types::NetworkIntent {
            host: host.to_string(),
            port,
            protocol: aros_types::ProtocolKind::Http,
        });
        http_intent.argv = match kind {
            FixtureKind::Authz => vec!["/users/2".into(), "user=1".into()],
            FixtureKind::Path => vec!["/files?path=../secret.txt".into()],
            FixtureKind::Deceptive => vec!["/pwned".into(), "user=1".into()],
        };
        let _ = broker.execute(http_intent)?;

        let observation = perform_attack_request(host, port, kind)?;
        let artifact = broker.cas.put(observation.body.as_bytes(), "text/plain")?;
        broker.ledger.append(
            ResearchEvent::ObservationRecorded {
                campaign_id: campaign.id,
                artifact_digest: artifact.digest_blake3.clone(),
                manifest_hash: campaign.manifest_hash.clone(),
            },
            vec![artifact.digest_blake3.clone()],
        )?;
        broker.ledger.append(
            ResearchEvent::ExperimentFinished {
                campaign_id: campaign.id,
                experiment_id,
            },
            vec![],
        )?;

        let observation_node = NodeId::new();
        graph.add_node(GraphNode {
            id: observation_node,
            campaign_id: campaign.id,
            graph: GraphKind::Research,
            kind: "observation".into(),
            label: observation.body.chars().take(120).collect(),
            epistemic: EpistemicState::Observed,
            payload: serde_json::json!({"status": observation.status, "artifact": artifact.digest_blake3}),
            provenance: "actual-target-http".into(),
            artifact_refs: vec![artifact.digest_blake3.clone()],
            created_unix_ms: unix_now_ms(),
        });
        graph.add_edge(graph_edge(
            campaign.id,
            experiment_node,
            observation_node,
            "produced",
            EpistemicState::Observed,
        ));

        let finding_id = FindingId::new();
        let impact = invariant_violated(kind, observation.status, &observation.body);
        let mut finding = Finding {
            id: finding_id,
            campaign_id: campaign.id,
            hypothesis_id: hypothesis.id,
            claim: hypothesis.claim.clone(),
            evidence_level: if impact {
                EvidenceLevel::E3InvariantViolation
            } else {
                EvidenceLevel::E0HypothesisOnly
            },
            manifest_hash: campaign.manifest_hash.clone(),
            verified: false,
        };

        if !impact {
            campaign.state = CampaignState::Refuted;
            broker.ledger.append(
                ResearchEvent::FindingFalsified {
                    campaign_id: campaign.id,
                    finding_id,
                    reason: "observed response does not violate the declared security invariant"
                        .into(),
                },
                vec![],
            )?;
            let card = ResearchCard {
                id: format!("card-{}", finding.id),
                campaign_id: campaign.id,
                finding_id: Some(finding.id),
                symptom: observation.body.chars().take(200).collect(),
                root_cause: "negative control / hypothesis not supported".into(),
                exploit_primitive: "none".into(),
                violated_invariant: hypothesis.security_invariant.clone(),
            };
            let refuted_node = NodeId::new();
            graph.add_node(GraphNode {
                id: refuted_node,
                campaign_id: campaign.id,
                graph: GraphKind::Research,
                kind: "finding".into(),
                label: finding.claim.clone(),
                epistemic: EpistemicState::Refuted,
                payload: serde_json::json!({"level": "E0", "verified": false}),
                provenance: "negative-control-oracle".into(),
                artifact_refs: vec![artifact.digest_blake3.clone()],
                created_unix_ms: unix_now_ms(),
            });
            graph.add_edge(graph_edge(
                campaign.id,
                observation_node,
                refuted_node,
                "falsifies",
                EpistemicState::Refuted,
            ));
            store.put_record("research_card", &card.id, &serde_json::to_string(&card)?)?;
            store.put_campaign(&campaign)?;
            store.persist_ledger_for(campaign.id, broker.ledger)?;
            store.persist_graph(campaign.id, &graph.nodes(), &graph.edges())?;
            let after = snapshot_tree(manifest.target_id, fixture_root)?;
            return Ok(CampaignOutcome {
                campaign,
                finding: Some(finding),
                evidence_level: Some(EvidenceLevel::E0HypothesisOnly),
                original_digest: original.source_tree_digest,
                original_digest_after: after.source_tree_digest,
                deceptive_rejected: kind == FixtureKind::Deceptive,
                patch: None,
                live_reattack_confirmed: false,
                research_card_id: Some(card.id),
                verifier_isolated: false,
            });
        }

        ledger_state(&mut broker, &mut campaign, CampaignState::Candidate)?;
        broker.ledger.append(
            ResearchEvent::FindingCandidateCreated {
                campaign_id: campaign.id,
                finding_id,
                claim: finding.claim.clone(),
            },
            vec![],
        )?;
        ledger_state(&mut broker, &mut campaign, CampaignState::Verifying)?;
        broker.ledger.append(
            ResearchEvent::VerificationStarted {
                campaign_id: campaign.id,
                finding_id,
            },
            vec![],
        )?;

        let mut bundle = EvidenceBundle {
            finding_id,
            campaign_id: campaign.id,
            manifest_hash: campaign.manifest_hash.clone(),
            snapshot_id: original.id,
            sandbox_id: sandbox
                .containment_demonstrated
                .then(|| sandbox.id.to_string()),
            claim: finding.claim.clone(),
            artifact_digests: vec![artifact.digest_blake3.clone()],
            level: EvidenceLevel::E3InvariantViolation,
        };
        let mut verifier_input = crate::verifier::reduced_input(
            &finding,
            &bundle,
            VerifierMode::ReproduceCandidate,
            oracle_contract(kind),
            &hypothesis.security_invariant,
        );
        verifier_input.replay = Some(verifier_replay(
            fixture_root,
            &original.source_tree_digest,
            kind,
        ));
        let independent = match crate::verifier::verify_in_subprocess(&verifier_input) {
            Ok(result) => result,
            Err(error) => {
                campaign.state = CampaignState::InsufficientEvidence;
                finding.evidence_level = EvidenceLevel::E3InvariantViolation;
                store.put_campaign(&campaign)?;
                store.persist_ledger_for(campaign.id, broker.ledger)?;
                return Err(EngineError::FailClosed(format!(
                    "independent verification unavailable; evidence capped at E3: {error}"
                )));
            }
        };
        if !independent.accepted || !independent.oracle_observed {
            campaign.state = CampaignState::NonReproducible;
            store.put_campaign(&campaign)?;
            store.persist_ledger_for(campaign.id, broker.ledger)?;
            return Err(EngineError::FailClosed(format!(
                "independent verifier rejected: {}",
                independent.reason
            )));
        }
        if independent.target_digest_observed.as_deref()
            != Some(original.source_tree_digest.as_str())
        {
            campaign.state = CampaignState::InsufficientEvidence;
            return Err(EngineError::FailClosed(
                "independent verifier did not reproduce the exact target digest".into(),
            ));
        }
        bundle.level = EvidenceLevel::E4IndependentReproduction;
        let verifier = VerifierRun {
            id: VerifierRunId::new(),
            finding_id,
            campaign_id: campaign.id,
            manifest_hash: campaign.manifest_hash.clone(),
            mode: VerifierMode::ReproduceCandidate,
            result: AuthorityResult::Verified,
            notes: format!(
                "actual-target independent verifier; digest={}",
                independent
                    .target_digest_observed
                    .as_deref()
                    .unwrap_or("missing")
            ),
        };
        let external_authority = TheustadAdapter::from_env();
        if external_authority.is_available()
            && external_authority.adjudicate(&bundle, &verifier) != AuthorityResult::Verified
        {
            campaign.state = CampaignState::NonReproducible;
            return Err(EngineError::FailClosed(
                "configured evidence authority did not confirm".into(),
            ));
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

        ledger_state(&mut broker, &mut campaign, CampaignState::Minimizing)?;
        let research_card = ResearchCard {
            id: format!("card-{}", finding.id),
            campaign_id: campaign.id,
            finding_id: Some(finding.id),
            symptom: observation.body.chars().take(200).collect::<String>(),
            root_cause: hypothesis.claim.clone(),
            exploit_primitive: match kind {
                FixtureKind::Authz => "insecure-direct-object-reference".into(),
                FixtureKind::Path => "path-traversal".into(),
                FixtureKind::Deceptive => "none".into(),
            },
            violated_invariant: hypothesis.security_invariant.clone(),
        };
        store.put_record(
            "research_card",
            &research_card.id,
            &serde_json::to_string(&research_card)?,
        )?;
        broker.ledger.append(
            ResearchEvent::ClaimCreated {
                campaign_id: campaign.id,
                claim: research_card.root_cause.clone(),
            },
            vec![],
        )?;

        ledger_state(&mut broker, &mut campaign, CampaignState::Remediating)?;
        let twin = work_root.join("twin");
        if twin.exists() {
            fs::remove_dir_all(&twin)?;
        }
        copy_dir(fixture_root, &twin)?;
        apply_fixture_patch(&twin, kind)?;
        if !twin_is_patched(&twin, kind) {
            return Err(EngineError::FailClosed(
                "patch transformation did not modify the expected fixture seam".into(),
            ));
        }
        let patch = PatchCandidate {
            id: PatchId::new(),
            finding_id,
            worktree_path: twin.display().to_string(),
            diff_digest: snapshot_tree(manifest.target_id, &twin)?.source_tree_digest,
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

        ledger_state(&mut broker, &mut campaign, CampaignState::Reattacking)?;
        broker.ledger.append(
            ResearchEvent::ReattackStarted {
                campaign_id: campaign.id,
                finding_id,
            },
            vec![],
        )?;
        let mut twin_process = RunningFixture::start(&twin)?;
        let original_effect_absent = patched_original_effect_absent(twin_process.port, kind)?;
        let variant_failed_to_reexploit = patched_variant_effect_absent(twin_process.port, kind)?;
        let functional_tests_passed = patched_functionality_holds(twin_process.port, kind)?;
        if !(original_effect_absent && variant_failed_to_reexploit && functional_tests_passed) {
            twin_process.stop();
            return Err(EngineError::FailClosed(
                "patched twin failed original re-attack, variant re-attack, or functional invariant"
                    .into(),
            ));
        }
        finding.evidence_level = EvidenceLevel::E6CounterfactualDifferential;

        let regression_path = twin.join("regression_test.py");
        fs::write(&regression_path, regression_source(kind))?;
        let regression_passed = run_regression(&twin, twin_process.port)?;
        twin_process.stop();
        if !regression_passed {
            return Err(EngineError::FailClosed(
                "generated security regression did not pass on patched twin".into(),
            ));
        }

        let reattack = ReattackRun {
            id: aros_types::ReattackId::new(),
            finding_id,
            patch_id: patch.id,
            original_path_failed: original_effect_absent,
            functional_tests_passed,
            variant_failed_to_reexploit,
        };
        debug_assert!(reattack.original_path_failed);
        broker.ledger.append(
            ResearchEvent::ReattackCompleted {
                campaign_id: campaign.id,
                finding_id,
                original_effect_absent,
            },
            vec![],
        )?;
        let _regression = Regression {
            id: RegressionId::new(),
            finding_id,
            test_path: regression_path.display().to_string(),
            passed_on_patched: regression_passed,
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
        campaign.state = CampaignState::RegressionProtected;
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
                "original_reattack": original_effect_absent,
                "variant_reattack": variant_failed_to_reexploit,
                "functional_tests": functional_tests_passed,
                "regression_executed": regression_passed
            }),
            provenance: "actual-target-verifier+actual-patched-twin".into(),
            artifact_refs: Vec::new(),
            created_unix_ms: unix_now_ms(),
        });

        store.put_campaign(&campaign)?;
        store.persist_ledger_for(campaign.id, broker.ledger)?;
        store.persist_graph(campaign.id, &graph.nodes(), &graph.edges())?;
        let final_original = snapshot_tree(manifest.target_id, fixture_root)?;
        Ok(CampaignOutcome {
            campaign,
            finding: Some(finding),
            evidence_level: Some(EvidenceLevel::E7VariantReattackAndRegression),
            original_digest: original.source_tree_digest,
            original_digest_after: final_original.source_tree_digest,
            deceptive_rejected: false,
            patch: Some(patch),
            live_reattack_confirmed: true,
            research_card_id: Some(research_card.id),
            verifier_isolated: true,
        })
    }
}

fn graph_edge(
    campaign_id: aros_types::CampaignId,
    from: NodeId,
    to: NodeId,
    kind: &str,
    epistemic: EpistemicState,
) -> GraphEdge {
    GraphEdge {
        id: aros_types::EdgeId::new(),
        campaign_id,
        graph: GraphKind::Research,
        from,
        to,
        kind: kind.into(),
        epistemic,
        confidence: None,
        provenance: "campaign-engine".into(),
        artifact_refs: Vec::new(),
        created_unix_ms: unix_now_ms(),
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

fn fixture_endpoint(kind: FixtureKind) -> &'static str {
    match kind {
        FixtureKind::Authz => "/users/{id}",
        FixtureKind::Path => "/files?path=...",
        FixtureKind::Deceptive => "/pwned",
    }
}

fn hypothesis_claim(kind: FixtureKind) -> &'static str {
    match kind {
        FixtureKind::Authz => "user 1 can read user 2's protected record",
        FixtureKind::Path => "path input can read a file outside the authorized data root",
        FixtureKind::Deceptive => "success-looking response text proves a security impact",
    }
}

fn hypothesis_invariant(kind: FixtureKind) -> &'static str {
    match kind {
        FixtureKind::Authz => "user A cannot read user B secret",
        FixtureKind::Path => "handler cannot read files outside data/",
        FixtureKind::Deceptive => "success-looking text alone is not an invariant violation",
    }
}

fn oracle_contract(kind: FixtureKind) -> &'static str {
    match kind {
        FixtureKind::Authz => "status 200 and response body contains bob-secret",
        FixtureKind::Path => "status 200 and response body contains fixture-path-secret",
        FixtureKind::Deceptive => "negative control",
    }
}

fn perform_attack_request(
    host: &str,
    port: u16,
    kind: FixtureKind,
) -> Result<crate::http_lab::HttpResponse, EngineError> {
    Ok(match kind {
        FixtureKind::Authz => http_get(host, port, "/users/2", Some("user=1"))?,
        FixtureKind::Path => http_get(host, port, "/files?path=../secret.txt", None)?,
        FixtureKind::Deceptive => http_get(host, port, "/pwned", Some("user=1"))?,
    })
}

fn invariant_violated(kind: FixtureKind, status: u16, body: &str) -> bool {
    match kind {
        FixtureKind::Authz => status == 200 && body.contains("bob-secret"),
        FixtureKind::Path => status == 200 && body.contains("fixture-path-secret"),
        // The negative-control invariant deliberately has no body string that
        // constitutes impact. A label can no longer force rejection/success.
        FixtureKind::Deceptive => false,
    }
}

fn verifier_replay(root: &Path, digest: &str, kind: FixtureKind) -> VerifierReplay {
    match kind {
        FixtureKind::Authz => VerifierReplay {
            target_root: root.to_string_lossy().into_owned(),
            expected_tree_digest: digest.into(),
            kind: FixtureReplayKind::Authz,
            request_path: "/users/2".into(),
            cookie: Some("user=1".into()),
            oracle: VerifierOracle {
                expected_status: Some(200),
                body_contains: Some("bob-secret".into()),
                body_not_contains: None,
            },
        },
        FixtureKind::Path => VerifierReplay {
            target_root: root.to_string_lossy().into_owned(),
            expected_tree_digest: digest.into(),
            kind: FixtureReplayKind::Path,
            request_path: "/files?path=../secret.txt".into(),
            cookie: None,
            oracle: VerifierOracle {
                expected_status: Some(200),
                body_contains: Some("fixture-path-secret".into()),
                body_not_contains: None,
            },
        },
        FixtureKind::Deceptive => unreachable!("negative control never reaches E4"),
    }
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), EngineError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(EngineError::FailClosed(format!(
                "refusing remediation copy through symlink {}",
                entry.path().display()
            )));
        }
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            if entry.file_name() == "__pycache__" {
                continue;
            }
            copy_dir(&entry.path(), &to)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

fn apply_fixture_patch(twin: &Path, kind: FixtureKind) -> Result<(), EngineError> {
    let path = twin.join("server.py");
    let text = fs::read_to_string(&path)?;
    let patched = match kind {
        FixtureKind::Authz => text.replace("VULN_IDOR = True", "VULN_IDOR = False"),
        FixtureKind::Path => text.replace("VULN_PATH = True", "VULN_PATH = False"),
        FixtureKind::Deceptive => text,
    };
    fs::write(path, patched)?;
    Ok(())
}

fn twin_is_patched(twin: &Path, kind: FixtureKind) -> bool {
    let Ok(text) = fs::read_to_string(twin.join("server.py")) else {
        return false;
    };
    match kind {
        FixtureKind::Authz => {
            text.contains("VULN_IDOR = False") && !text.contains("VULN_IDOR = True")
        }
        FixtureKind::Path => {
            text.contains("VULN_PATH = False") && !text.contains("VULN_PATH = True")
        }
        FixtureKind::Deceptive => false,
    }
}

struct RunningFixture {
    child: Child,
    port: u16,
}

impl RunningFixture {
    fn start(root: &Path) -> Result<Self, EngineError> {
        let python = resolve_python().ok_or_else(|| {
            EngineError::FailClosed("python unavailable for real patched-twin execution".into())
        })?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let child = Command::new(python)
            .arg("server.py")
            .current_dir(root)
            .env("SECURITY_FIXTURE_PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut running = Self { child, port };
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            if running.child.try_wait()?.is_some() {
                running.stop();
                return Err(EngineError::FailClosed(
                    "patched twin exited before readiness".into(),
                ));
            }
            if http_get("127.0.0.1", port, "/health", None).is_ok() {
                return Ok(running);
            }
            thread::sleep(Duration::from_millis(50));
        }
        running.stop();
        Err(EngineError::FailClosed(
            "patched twin readiness deadline exceeded".into(),
        ))
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RunningFixture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn resolve_python() -> Option<String> {
    if let Ok(explicit) = std::env::var(env_name("PYTHON")) {
        if !explicit.trim().is_empty() {
            return Some(explicit);
        }
    }
    ["python3", "python"].into_iter().find_map(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()
            .filter(|status| status.success())
            .map(|_| candidate.to_string())
    })
}

fn patched_original_effect_absent(port: u16, kind: FixtureKind) -> Result<bool, EngineError> {
    let response = perform_attack_request("127.0.0.1", port, kind)?;
    Ok(!invariant_violated(kind, response.status, &response.body))
}

fn patched_variant_effect_absent(port: u16, kind: FixtureKind) -> Result<bool, EngineError> {
    let response = match kind {
        FixtureKind::Authz => http_get("127.0.0.1", port, "/users/2", None)?,
        FixtureKind::Path => http_get("127.0.0.1", port, "/files?path=..%2Fsecret.txt", None)?,
        FixtureKind::Deceptive => return Ok(false),
    };
    Ok(!invariant_violated(kind, response.status, &response.body))
}

fn patched_functionality_holds(port: u16, kind: FixtureKind) -> Result<bool, EngineError> {
    let response = match kind {
        FixtureKind::Authz => http_get("127.0.0.1", port, "/users/2", Some("user=2"))?,
        FixtureKind::Path => http_get("127.0.0.1", port, "/files?path=public.txt", None)?,
        FixtureKind::Deceptive => return Ok(false),
    };
    Ok(match kind {
        FixtureKind::Authz => response.status == 200 && response.body.contains("bob-secret"),
        FixtureKind::Path => response.status == 200 && response.body.contains("fixture-public-ok"),
        FixtureKind::Deceptive => false,
    })
}

fn regression_source(kind: FixtureKind) -> &'static str {
    match kind {
        FixtureKind::Authz => {
            r#"import os, urllib.request, urllib.error
base=f'http://127.0.0.1:{os.environ["SECURITY_PATCHED_PORT"]}'
def get(path,cookie=None):
    r=urllib.request.Request(base+path)
    if cookie: r.add_header('Cookie',cookie)
    try:
        with urllib.request.urlopen(r,timeout=2) as x: return x.status,x.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
status,body=get('/users/2','user=1'); assert 'bob-secret' not in body
status,body=get('/users/2'); assert 'bob-secret' not in body
status,body=get('/users/2','user=2'); assert status==200 and 'bob-secret' in body
"#
        }
        FixtureKind::Path => {
            r#"import os, urllib.request, urllib.error
base=f'http://127.0.0.1:{os.environ["SECURITY_PATCHED_PORT"]}'
def get(path):
    try:
        with urllib.request.urlopen(base+path,timeout=2) as x: return x.status,x.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
for p in ['/files?path=../secret.txt','/files?path=..%2Fsecret.txt']:
    status,body=get(p); assert 'fixture-path-secret' not in body
status,body=get('/files?path=public.txt'); assert status==200 and 'fixture-public-ok' in body
"#
        }
        FixtureKind::Deceptive => "raise SystemExit(2)\n",
    }
}

fn run_regression(twin: &Path, port: u16) -> Result<bool, EngineError> {
    let python = resolve_python().ok_or_else(|| {
        EngineError::FailClosed("python unavailable for generated regression".into())
    })?;
    let status = Command::new(python)
        .arg("regression_test.py")
        .current_dir(twin)
        .env("SECURITY_PATCHED_PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}
