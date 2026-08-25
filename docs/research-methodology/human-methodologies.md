# Human methodologies

AROS seeds structured Research Skills rather than pasting long prompts.
See `docs/research-methodology/research-skills.md` (generated from
`skills/builtin/*.json`).

Skills encode: applicability, required facts, hypothesis templates,
experiment strategy, negative controls, evidence contract, failure modes,
pattern families, tools, cost, safety, provenance.

The LLM may use a skill to propose a `ToolIntent`. Rust still authorizes.
