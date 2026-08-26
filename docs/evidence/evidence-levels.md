# Evidence levels

LLM confidence is not evidence.

For v0.1, the critical boundary is:

- E3: the research path observed a security-invariant violation.
- E4: a dedicated verifier independently reproduced the finding against the exact target state.

E4 requires the verifier process to confirm the expected target digest, launch its own fresh verifier target instance, execute the replay itself, and evaluate the oracle from its own observation. The campaign must not supply an oracle-hit answer.

If the verifier executable or replay recipe is unavailable, the exact target digest differs, or independent observation cannot be obtained, evidence remains capped at E3 and the campaign reports insufficient evidence instead of claiming E4.

Higher levels continue through minimization, remediation, re-attack, and regression protection as defined by `docs/AROS_MVP_SPEC.md`.
