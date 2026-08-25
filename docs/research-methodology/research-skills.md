# Research skills

Generated from `python/aros_research/skills/catalog.py`.
These are structured methodologies, not prompts with authority.

## `breadth_depth_context`

Alternate breadth-first mapping with depth-first investigation of promising components.

- Applicability: white_box, gray_box
- Experiment: Enumerate entry points, then dive on trust-boundary crossings.
- Evidence: Persist the component map as raw graph nodes.
- Cost class: medium

## `reachability_boundary_mapping`

Map which principals can reach which operations.

- Applicability: white_box, gray_box, black_box
- Experiment: Probe each endpoint as unauthenticated and as a low-privilege user.
- Evidence: Raw HTTP status and body for each principal.
- Cost class: low

## `trust_boundary_mapping`

Identify where trust is assumed across components.

- Applicability: white_box, gray_box
- Experiment: List parser/validator/consumer pairs and disagree them.
- Evidence: Graph edges labeled trust-boundary with provenance.
- Cost class: medium

## `source_to_sink`

Forward taint: attacker-controlled source through transforms to a sensitive sink.

- Applicability: white_box
- Experiment: Trace one source along the cheapest path to a sink.
- Evidence: Request that demonstrates sink effect plus source mapping.
- Cost class: medium

## `sink_to_source`

Reverse: start from a sensitive operation and walk callers to attacker influence.

- Applicability: white_box
- Experiment: Find authorization, file, and parser sinks first.
- Evidence: Call-chain evidence plus dynamic confirmation.
- Cost class: medium

## `assumption_attack`

Turn implicit trust assumptions into falsifiable hypotheses.

- Applicability: white_box, gray_box
- Experiment: Cheapest request that would succeed if the assumption is false.
- Evidence: Raw request/response showing invariant violation, not an LLM summary.
- Cost class: low

## `parser_interpretation_disagreement`

Find Interpret_A(x) != Interpret_B(x) where A decides and B acts.

- Applicability: white_box, gray_box
- Experiment: Send dual-interpretation payloads (path, JSON, headers).
- Evidence: Two raw interpretations plus the security decision/action split.
- Cost class: medium

## `representation_transformation_analysis`

Study decode/normalize/encode steps for security-relevant loss or gain.

- Applicability: white_box, gray_box
- Experiment: Alternate encodings of the same semantic value.
- Evidence: Before/after bytes of the transformation.
- Cost class: medium

## `hidden_component_inference`

Infer components not advertised by READMEs or OpenAPI.

- Applicability: gray_box, black_box
- Experiment: Compare binaries, compose files, and runtime routes.
- Evidence: How the hidden component was observed, not guessed.
- Cost class: medium

## `fast_falsification`

Prefer the cheapest experiment that distinguishes competing explanations.

- Applicability: all visibility modes
- Experiment: Single discriminating probe with a negative control.
- Evidence: Persist raw observation regardless of outcome.
- Cost class: low

## `differential_experiment`

Compare two targets or two inputs that should be equivalent.

- Applicability: white_box, gray_box
- Experiment: Same probe on T_vulnerable and T_patch_candidate.
- Evidence: Paired raw observations.
- Cost class: medium

## `negative_control_design`

Every experiment needs a control that should not fire the oracle.

- Applicability: all visibility modes
- Experiment: Run a should-fail-to-violate control beside the probe.
- Evidence: Control observation stored with the probe.
- Cost class: low

## `anomaly_investigation`

Treat anomalies as notebooks, not findings.

- Applicability: all visibility modes
- Experiment: Revisit when later graph facts arrive.
- Evidence: Anomaly record with status, not a finding id.
- Cost class: low

## `primitive_composition`

Compose exploit primitives when preconditions match.

- Applicability: white_box, gray_box
- Experiment: Graph search over primitive preconditions.
- Evidence: Explicit primitive nodes, not chat summaries.
- Cost class: high

## `attack_chain_reasoning`

Search composed impact that a single primitive cannot achieve.

- Applicability: white_box, gray_box
- Experiment: Only chain after each primitive is evidenced.
- Evidence: Per-hop observations plus the chain node.
- Cost class: high

## `patch_archaeology`

Study how similar bugs were fixed historically, without contaminating evaluation.

- Applicability: white_box
- Experiment: Diff patched vs vulnerable twins.
- Evidence: Patch diff digest on the twin only.
- Cost class: medium

## `variant_analysis`

After a finding, search sibling encodings and analogous paths.

- Applicability: white_box, gray_box
- Experiment: Mutate representation, path, and auth context.
- Evidence: Variant results stored separately from the original PoC.
- Cost class: medium

## `incomplete_fix_search`

Assume the patch is incomplete until variant re-attack fails.

- Applicability: remediation
- Experiment: Re-attack original, sibling, and analogue paths on the twin.
- Evidence: ReattackRun with all three outcomes.
- Cost class: medium

## `discovery_cascade`

Generalize a confirmed finding into new hypotheses.

- Applicability: after verified finding
- Experiment: Turn symptom/root-cause/primitive/invariant into new hypotheses.
- Evidence: ResearchCard persisted; new hypotheses stay HYPOTHESIZED.
- Cost class: medium

## `missed_bug_analysis`

When a known fixture bug is missed, record a ResearchFailureCard.

- Applicability: evaluation, benchmarks
- Experiment: Classify the miss; do not hide it.
- Evidence: ResearchFailureCard with category.
- Cost class: low
