use serde::{Deserialize, Serialize};

use crate::enums::{
    AuthorityResult, CampaignState, EpistemicState, EvidenceLevel, FailureCategory, GraphKind,
    VisibilityMode,
};
use crate::ids::{
    ArtifactId, CampaignId, ExperimentId, FindingId, HypothesisId, NodeId, PatchId, ReattackId,
    RegressionId, RunId, SnapshotId, TargetId, VerifierRunId,
};
use crate::time::unix_now_ms;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: TargetId,
    pub name: String,
    pub kind: TargetKind,
    pub source_path: String,
    pub visibility: VisibilityMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetKind {
    SourceRepository,
    LocalWebApi,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub id: SnapshotId,
    pub target_id: TargetId,
    pub git_commit: Option<String>,
    pub dirty_tree_hash: Option<String>,
    pub source_tree_digest: String,
    pub lockfile_hashes: Vec<String>,
    pub container_image_digest: Option<String>,
    pub runtime_description: String,
    pub captured_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    pub id: CampaignId,
    pub target_id: TargetId,
    pub snapshot_id: SnapshotId,
    pub manifest_hash: String,
    pub state: CampaignState,
    pub created_unix_ms: u64,
    pub updated_unix_ms: u64,
}

impl Campaign {
    pub fn new(
        id: CampaignId,
        target_id: TargetId,
        snapshot_id: SnapshotId,
        manifest_hash: String,
    ) -> Self {
        let now = unix_now_ms();
        Self {
            id,
            target_id,
            snapshot_id,
            manifest_hash,
            state: CampaignState::Discovering,
            created_unix_ms: now,
            updated_unix_ms: now,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: NodeId,
    pub campaign_id: CampaignId,
    pub graph: GraphKind,
    pub kind: String,
    pub label: String,
    pub epistemic: EpistemicState,
    pub payload: serde_json::Value,
    pub provenance: String,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: crate::ids::EdgeId,
    pub campaign_id: CampaignId,
    pub graph: GraphKind,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: String,
    pub epistemic: EpistemicState,
    pub confidence: Option<f32>,
    pub provenance: String,
    pub artifact_refs: Vec<String>,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assumption {
    pub id: NodeId,
    pub campaign_id: CampaignId,
    pub statement: String,
    pub epistemic: EpistemicState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    pub campaign_id: CampaignId,
    pub claim: String,
    pub supporting_facts: Vec<String>,
    pub historical_analogues: Vec<String>,
    pub affected_components: Vec<String>,
    pub security_invariant: String,
    pub possible_impact: String,
    pub cheapest_experiment: String,
    pub estimated_cost: u32,
    pub epistemic: EpistemicState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Experiment {
    pub id: ExperimentId,
    pub campaign_id: CampaignId,
    pub hypothesis_id: HypothesisId,
    pub manifest_hash: String,
    pub description: String,
    pub started_unix_ms: u64,
    pub finished_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub id: NodeId,
    pub experiment_id: ExperimentId,
    pub campaign_id: CampaignId,
    pub manifest_hash: String,
    pub raw_artifact_digest: String,
    pub summary: String,
    pub created_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anomaly {
    pub id: NodeId,
    pub campaign_id: CampaignId,
    pub observation: String,
    pub baseline: String,
    pub components: Vec<String>,
    pub possible_explanations: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub campaign_id: CampaignId,
    pub hypothesis_id: HypothesisId,
    pub claim: String,
    pub evidence_level: EvidenceLevel,
    pub manifest_hash: String,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub id: ArtifactId,
    pub digest_blake3: String,
    pub digest_sha256: String,
    pub media_type: String,
    pub byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub finding_id: FindingId,
    pub campaign_id: CampaignId,
    pub manifest_hash: String,
    pub snapshot_id: SnapshotId,
    pub sandbox_id: Option<String>,
    pub claim: String,
    pub artifact_digests: Vec<String>,
    pub level: EvidenceLevel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierRun {
    pub id: VerifierRunId,
    pub finding_id: FindingId,
    pub campaign_id: CampaignId,
    pub manifest_hash: String,
    pub mode: VerifierMode,
    pub result: AuthorityResult,
    pub notes: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifierMode {
    ReproduceCandidate,
    Blindish,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchCandidate {
    pub id: PatchId,
    pub finding_id: FindingId,
    pub worktree_path: String,
    pub diff_digest: String,
    pub original_target_unmodified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReattackRun {
    pub id: ReattackId,
    pub finding_id: FindingId,
    pub patch_id: PatchId,
    pub original_path_failed: bool,
    pub functional_tests_passed: bool,
    pub variant_failed_to_reexploit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Regression {
    pub id: RegressionId,
    pub finding_id: FindingId,
    pub test_path: String,
    pub passed_on_patched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchFailureCard {
    pub campaign_id: CampaignId,
    pub run_id: RunId,
    pub category: FailureCategory,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchSkill {
    pub id: String,
    pub description: String,
    pub applicability: Vec<String>,
    pub required_facts: Vec<String>,
    pub hypothesis_templates: Vec<String>,
    pub experiment_strategy: String,
    pub negative_controls: Vec<String>,
    pub evidence_contract: String,
    pub known_failure_modes: Vec<String>,
    pub relevant_pattern_families: Vec<String>,
    pub recommended_tool_categories: Vec<String>,
    pub estimated_cost_class: String,
    pub safety_requirements: Vec<String>,
    pub provenance: Vec<String>,
}
