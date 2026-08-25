//! Heuristic experiment/hypothesis scheduler. Scores are not truth.

use aros_types::Hypothesis;

#[derive(Clone, Debug, PartialEq)]
pub struct PriorityScore {
    pub total: u32,
    pub plausibility: u32,
    pub impact: u32,
    pub novelty: u32,
    pub information_gain: u32,
    pub cascade_potential: u32,
    pub execution_cost: u32,
    pub risk: u32,
}

/// Cheap discriminating experiments first: high information gain and impact,
/// low cost and risk. Never treat the integer as a verified fact.
pub fn score_hypothesis(h: &Hypothesis) -> PriorityScore {
    let plausibility = 50;
    let impact = if h.possible_impact.contains("confidential") || h.possible_impact.contains("auth")
    {
        80
    } else {
        40
    };
    let novelty = if h.historical_analogues.is_empty() {
        60
    } else {
        40
    };
    let information_gain = 70;
    let cascade_potential = 30;
    let execution_cost = h.estimated_cost.min(100);
    let risk = 20;
    let total = plausibility
        + impact
        + novelty
        + information_gain
        + cascade_potential
        + 100u32.saturating_sub(execution_cost)
        + 100u32.saturating_sub(risk);
    PriorityScore {
        total,
        plausibility,
        impact,
        novelty,
        information_gain,
        cascade_potential,
        execution_cost,
        risk,
    }
}

pub fn pick_cheapest(hypotheses: &[Hypothesis]) -> Option<&Hypothesis> {
    hypotheses.iter().min_by_key(|h| h.estimated_cost)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use aros_types::{CampaignId, EpistemicState, Hypothesis, HypothesisId};

    #[test]
    fn cheaper_experiment_preferred() {
        let c = CampaignId::new();
        let a = Hypothesis {
            id: HypothesisId::new(),
            campaign_id: c,
            claim: "a".into(),
            supporting_facts: vec![],
            historical_analogues: vec![],
            affected_components: vec![],
            security_invariant: "i".into(),
            possible_impact: "confidentiality".into(),
            cheapest_experiment: "GET".into(),
            estimated_cost: 1,
            epistemic: EpistemicState::Hypothesized,
        };
        let mut b = a.clone();
        b.id = HypothesisId::new();
        b.estimated_cost = 90;
        let set = [a.clone(), b];
        let picked = pick_cheapest(&set).unwrap();
        assert_eq!(picked.estimated_cost, 1);
        assert!(score_hypothesis(&a).total > 0);
    }
}
