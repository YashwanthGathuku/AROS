# Failure memory

`ResearchFailureCard` records why a known fixture bug was missed:

surface_not_discovered, architecture_misunderstood, assumption_not_generated,
hypothesis_not_generated, hypothesis_deprioritized, experiment_inadequate,
observation_misinterpreted, tool_gap, verification_failure, budget_exhaustion,
policy_blocked, unknown.

Evaluation data lives under `evaluation/quarantined/` and must not leak into
`knowledge/historical/` retrieval.
