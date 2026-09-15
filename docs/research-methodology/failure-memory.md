# Failure memory

`ResearchFailureCard` records why a known fixture bug was missed:

surface_not_discovered, architecture_misunderstood, assumption_not_generated,
hypothesis_not_generated, hypothesis_deprioritized, experiment_inadequate,
observation_misinterpreted, tool_gap, verification_failure, budget_exhaustion,
policy_blocked, unknown.

Wired in v0.1:

- missing/unknown catalog harness → `TOOL_GAP` in `aros.db` records (`failure_card`)
- PoC-or-nothing case with `expect=verified` that did not verify → `EXPERIMENT_INADEQUATE` in `failure-cards.jsonl`
- an invariant that **held** is not a miss

Evaluation data lives under `evaluation/quarantined/` and `evaluation/poc-or-nothing/` and must not leak into `knowledge/historical/` retrieval.
