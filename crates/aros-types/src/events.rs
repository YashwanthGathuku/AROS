use serde::{Deserialize, Serialize};

use crate::enums::{CampaignState, EvidenceLevel, PolicyDecision};
use crate::ids::{
    CampaignId, ExperimentId, FindingId, HypothesisId, PatchId, RequestId, SnapshotId, TargetId,
};
use crate::time::unix_now_ms;
use crate::tool::ToolCapability;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "PascalCase")]
pub enum ResearchEvent {
    TargetRegistered {
        target_id: TargetId,
        name: String,
    },
    TargetSnapshotted {
        target_id: TargetId,
        snapshot_id: SnapshotId,
        tree_digest: String,
    },
    CampaignStarted {
        campaign_id: CampaignId,
        manifest_hash: String,
    },
    CampaignStateChanged {
        campaign_id: CampaignId,
        state: CampaignState,
    },
    SurfaceMapped {
        campaign_id: CampaignId,
        component_count: u32,
    },
    AssumptionCreated {
        campaign_id: CampaignId,
        statement: String,
    },
    HypothesisCreated {
        campaign_id: CampaignId,
        hypothesis_id: HypothesisId,
        claim: String,
    },
    HypothesisPrioritized {
        campaign_id: CampaignId,
        hypothesis_id: HypothesisId,
        score: u32,
    },
    HypothesisRefuted {
        campaign_id: CampaignId,
        hypothesis_id: HypothesisId,
        reason: String,
    },
    ExperimentStarted {
        campaign_id: CampaignId,
        experiment_id: ExperimentId,
        manifest_hash: String,
    },
    ExperimentFinished {
        campaign_id: CampaignId,
        experiment_id: ExperimentId,
    },
    ObservationRecorded {
        campaign_id: CampaignId,
        artifact_digest: String,
        manifest_hash: String,
    },
    AnomalyRecorded {
        campaign_id: CampaignId,
        summary: String,
    },
    PrimitiveSupported {
        campaign_id: CampaignId,
        primitive: String,
    },
    PrimitiveVerified {
        campaign_id: CampaignId,
        primitive: String,
    },
    AttackChainCreated {
        campaign_id: CampaignId,
        summary: String,
    },
    FindingCandidateCreated {
        campaign_id: CampaignId,
        finding_id: FindingId,
        claim: String,
    },
    FindingVerified {
        campaign_id: CampaignId,
        finding_id: FindingId,
        level: EvidenceLevel,
    },
    FindingFalsified {
        campaign_id: CampaignId,
        finding_id: FindingId,
        reason: String,
    },
    PatchCandidateCreated {
        campaign_id: CampaignId,
        patch_id: PatchId,
        finding_id: FindingId,
    },
    ReattackStarted {
        campaign_id: CampaignId,
        finding_id: FindingId,
    },
    ReattackCompleted {
        campaign_id: CampaignId,
        finding_id: FindingId,
        original_effect_absent: bool,
    },
    RegressionCreated {
        campaign_id: CampaignId,
        finding_id: FindingId,
        test_path: String,
    },
    AgentStarted {
        campaign_id: CampaignId,
        agent: String,
    },
    AgentStopped {
        campaign_id: CampaignId,
        agent: String,
    },
    ToolRequested {
        campaign_id: CampaignId,
        request_id: RequestId,
        capability: ToolCapability,
    },
    ToolAllowed {
        campaign_id: CampaignId,
        request_id: RequestId,
    },
    ToolDenied {
        campaign_id: CampaignId,
        request_id: RequestId,
        reason: String,
    },
    ProcessStarted {
        campaign_id: CampaignId,
        executable: String,
    },
    ProcessFinished {
        campaign_id: CampaignId,
        executable: String,
        exit_status: i32,
    },
    NetworkAttempted {
        campaign_id: CampaignId,
        host: String,
        port: u16,
        decision: PolicyDecision,
    },
    PolicyViolationAttempt {
        campaign_id: CampaignId,
        detail: String,
    },
    SandboxKilled {
        campaign_id: CampaignId,
        reason: String,
    },
    EvidenceCreated {
        campaign_id: CampaignId,
        digest: String,
    },
    ClaimCreated {
        campaign_id: CampaignId,
        claim: String,
    },
    VerificationStarted {
        campaign_id: CampaignId,
        finding_id: FindingId,
    },
    VerificationSucceeded {
        campaign_id: CampaignId,
        finding_id: FindingId,
    },
    VerificationFailed {
        campaign_id: CampaignId,
        finding_id: FindingId,
        reason: String,
    },
    CampaignCompleted {
        campaign_id: CampaignId,
        state: CampaignState,
    },
    CampaignFailed {
        campaign_id: CampaignId,
        reason: String,
    },
}

impl ResearchEvent {
    pub fn campaign_id(&self) -> Option<CampaignId> {
        match self {
            Self::TargetRegistered { .. } | Self::TargetSnapshotted { .. } => None,
            Self::CampaignStarted { campaign_id, .. }
            | Self::CampaignStateChanged { campaign_id, .. }
            | Self::SurfaceMapped { campaign_id, .. }
            | Self::AssumptionCreated { campaign_id, .. }
            | Self::HypothesisCreated { campaign_id, .. }
            | Self::HypothesisPrioritized { campaign_id, .. }
            | Self::HypothesisRefuted { campaign_id, .. }
            | Self::ExperimentStarted { campaign_id, .. }
            | Self::ExperimentFinished { campaign_id, .. }
            | Self::ObservationRecorded { campaign_id, .. }
            | Self::AnomalyRecorded { campaign_id, .. }
            | Self::PrimitiveSupported { campaign_id, .. }
            | Self::PrimitiveVerified { campaign_id, .. }
            | Self::AttackChainCreated { campaign_id, .. }
            | Self::FindingCandidateCreated { campaign_id, .. }
            | Self::FindingVerified { campaign_id, .. }
            | Self::FindingFalsified { campaign_id, .. }
            | Self::PatchCandidateCreated { campaign_id, .. }
            | Self::ReattackStarted { campaign_id, .. }
            | Self::ReattackCompleted { campaign_id, .. }
            | Self::RegressionCreated { campaign_id, .. }
            | Self::AgentStarted { campaign_id, .. }
            | Self::AgentStopped { campaign_id, .. }
            | Self::ToolRequested { campaign_id, .. }
            | Self::ToolAllowed { campaign_id, .. }
            | Self::ToolDenied { campaign_id, .. }
            | Self::ProcessStarted { campaign_id, .. }
            | Self::ProcessFinished { campaign_id, .. }
            | Self::NetworkAttempted { campaign_id, .. }
            | Self::PolicyViolationAttempt { campaign_id, .. }
            | Self::SandboxKilled { campaign_id, .. }
            | Self::EvidenceCreated { campaign_id, .. }
            | Self::ClaimCreated { campaign_id, .. }
            | Self::VerificationStarted { campaign_id, .. }
            | Self::VerificationSucceeded { campaign_id, .. }
            | Self::VerificationFailed { campaign_id, .. }
            | Self::CampaignCompleted { campaign_id, .. }
            | Self::CampaignFailed { campaign_id, .. } => Some(*campaign_id),
        }
    }

    pub fn stamped_payload(&self) -> EventRecord {
        EventRecord {
            occurred_unix_ms: unix_now_ms(),
            event: self.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub occurred_unix_ms: u64,
    pub event: ResearchEvent,
}
