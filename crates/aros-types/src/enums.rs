use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VisibilityMode {
    BlackBox,
    GrayBox,
    WhiteBox,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicState {
    Observed,
    Derived,
    Inferred,
    Hypothesized,
    Supported,
    Claimed,
    Verified,
    Refuted,
    Stale,
}

impl EpistemicState {
    pub fn is_established_fact(self) -> bool {
        matches!(self, Self::Observed | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequiresHuman,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignState {
    Discovering,
    Mapping,
    Hypothesizing,
    Experimenting,
    Candidate,
    Verifying,
    Verified,
    Minimizing,
    Remediating,
    Reattacking,
    RegressionProtected,
    Refuted,
    NonReproducible,
    InsufficientEvidence,
    OutOfScope,
    PolicyBlocked,
    Tampered,
    Failed,
}

impl CampaignState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::RegressionProtected
                | Self::Refuted
                | Self::NonReproducible
                | Self::InsufficientEvidence
                | Self::OutOfScope
                | Self::PolicyBlocked
                | Self::Tampered
                | Self::Failed
        )
    }
}

/// Evidence levels E0–E7 from the MVP spec. LLM confidence is not a level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLevel {
    E0HypothesisOnly,
    E1StaticSupport,
    E2DynamicAnomaly,
    E3InvariantViolation,
    E4IndependentReproduction,
    E5MinimizedReproduction,
    E6CounterfactualDifferential,
    E7VariantReattackAndRegression,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphKind {
    TargetReality,
    Research,
    Historical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DestructivePolicy {
    Forbid,
    RequireHuman,
    AllowInSandbox,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolKind {
    Tcp,
    Udp,
    Http,
    Https,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityResult {
    Verified,
    Falsified,
    InsufficientEvidence,
    NonReproducible,
    Tampered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureCategory {
    SurfaceNotDiscovered,
    ArchitectureMisunderstood,
    AssumptionNotGenerated,
    HypothesisNotGenerated,
    HypothesisDeprioritized,
    ExperimentInadequate,
    ObservationMisinterpreted,
    ToolGap,
    VerificationFailure,
    BudgetExhaustion,
    PolicyBlocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DoctorStatus {
    Required,
    Optional,
    UnsafeMisconfigured,
}
