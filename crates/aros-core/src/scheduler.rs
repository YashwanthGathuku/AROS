//! Heuristic experiment/hypothesis scheduler. Scores are not truth.

use aros_types::{Anomaly, Hypothesis, HypothesisId};

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

/// Later facts that can make an open anomaly worth reading again.
/// Matching is exact on a trimmed token. A substring is not a match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelevanceCue {
    pub components: Vec<String>,
    pub hypothesis_ids: Vec<HypothesisId>,
    pub patterns: Vec<String>,
}

/// Open anomalies whose component, hypothesis, or historical pattern equals a cue token.
/// Dismissed and revisited notes stay out. An empty cue selects nothing.
pub fn revisit_anomalies<'a>(notes: &'a [Anomaly], cue: &RelevanceCue) -> Vec<&'a Anomaly> {
    if cue.components.is_empty() && cue.hypothesis_ids.is_empty() && cue.patterns.is_empty() {
        return Vec::new();
    }
    notes
        .iter()
        .filter(|note| note.status.trim() == "open" && note_matches(note, cue))
        .collect()
}

fn note_matches(note: &Anomaly, cue: &RelevanceCue) -> bool {
    tokens_overlap(&note.components, &cue.components)
        || note
            .related_hypotheses
            .iter()
            .any(|id| cue.hypothesis_ids.iter().any(|cue_id| cue_id == id))
        || tokens_overlap(&note.related_historical_patterns, &cue.patterns)
}

fn tokens_overlap(stored: &[String], cue: &[String]) -> bool {
    stored.iter().any(|item| {
        let item = item.trim();
        !item.is_empty() && cue.iter().any(|token| token.trim() == item)
    })
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

    #[test]
    fn open_anomaly_is_revisited_only_on_an_exact_cue() {
        use aros_types::{Anomaly, CampaignId, NodeId};
        let hypothesis = HypothesisId::new();
        let note = Anomaly {
            id: NodeId::new(),
            campaign_id: CampaignId::new(),
            observation: "COVERAGE_ENGINE absent".into(),
            baseline: "no coverage engine".into(),
            components: vec!["coverage-engine".into()],
            possible_explanations: vec!["binary missing".into()],
            related_hypotheses: vec![hypothesis],
            related_historical_patterns: vec!["COVERAGE_ENGINE absent".into()],
            status: "open".into(),
        };
        let mut dismissed = note.clone();
        dismissed.status = "dismissed".into();
        let notes = [note.clone(), dismissed];
        assert!(revisit_anomalies(&notes, &RelevanceCue::default()).is_empty());
        let by_component = revisit_anomalies(
            &notes,
            &RelevanceCue {
                components: vec!["coverage-engine".into()],
                ..RelevanceCue::default()
            },
        );
        assert_eq!(by_component.len(), 1);
        assert_eq!(by_component[0].status, "open");
        let by_substring = revisit_anomalies(
            &notes,
            &RelevanceCue {
                components: vec!["coverage".into()],
                ..RelevanceCue::default()
            },
        );
        assert!(by_substring.is_empty());
        let by_hypothesis = revisit_anomalies(
            &notes,
            &RelevanceCue {
                hypothesis_ids: vec![hypothesis],
                ..RelevanceCue::default()
            },
        );
        assert_eq!(by_hypothesis.len(), 1);
        let mut revisited = note;
        revisited.status = "revisited".into();
        assert!(revisit_anomalies(
            &[revisited],
            &RelevanceCue {
                patterns: vec!["COVERAGE_ENGINE absent".into()],
                ..RelevanceCue::default()
            },
        )
        .is_empty());
    }
}
