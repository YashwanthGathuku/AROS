//! Independent verifier. Must not receive attacker hidden reasoning.

use aros_evidence::{BuiltinEvidenceAuthority, EvidenceAuthority};
use aros_types::{
    AuthorityResult, EvidenceBundle, EvidenceLevel, Finding, VerifierMode, VerifierRun,
};

/// The payload actually given to the independent verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierInput {
    pub claim: String,
    pub snapshot_id: String,
    pub candidate_reproduction: Option<String>,
    pub oracle_contract: String,
    pub invariant: String,
    pub attacker_hidden_reasoning: bool,
}

pub fn reduced_input(
    finding: &Finding,
    bundle: &EvidenceBundle,
    mode: VerifierMode,
    oracle: &str,
    invariant: &str,
) -> VerifierInput {
    VerifierInput {
        claim: finding.claim.clone(),
        snapshot_id: bundle.snapshot_id.to_string(),
        candidate_reproduction: match mode {
            VerifierMode::ReproduceCandidate => bundle.artifact_digests.first().cloned(),
            VerifierMode::Blindish => None,
        },
        oracle_contract: oracle.to_string(),
        invariant: invariant.to_string(),
        attacker_hidden_reasoning: false,
    }
}

pub fn adjudicate(bundle: &EvidenceBundle, run: &VerifierRun) -> AuthorityResult {
    BuiltinEvidenceAuthority.adjudicate(bundle, run)
}

pub fn accepts_true_finding(level: EvidenceLevel, result: AuthorityResult) -> bool {
    result == AuthorityResult::Verified && level >= EvidenceLevel::E4IndependentReproduction
}

#[cfg(test)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, FindingId, HypothesisId, SnapshotId};

    #[test]
    fn verifier_does_not_include_attacker_notes() {
        let finding = Finding {
            id: FindingId::new(),
            campaign_id: CampaignId::new(),
            hypothesis_id: HypothesisId::new(),
            claim: "idor".into(),
            evidence_level: EvidenceLevel::E4IndependentReproduction,
            manifest_hash: "h".into(),
            verified: false,
        };
        let bundle = EvidenceBundle {
            finding_id: finding.id,
            campaign_id: finding.campaign_id,
            manifest_hash: "h".into(),
            snapshot_id: SnapshotId::new(),
            sandbox_id: None,
            claim: finding.claim.clone(),
            artifact_digests: vec!["abc".into()],
            level: EvidenceLevel::E4IndependentReproduction,
        };
        let input = reduced_input(
            &finding,
            &bundle,
            VerifierMode::Blindish,
            "secret-not-returned",
            "tenant isolation",
        );
        assert!(!input.attacker_hidden_reasoning);
        assert!(input.candidate_reproduction.is_none());
    }
}
