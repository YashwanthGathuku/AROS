# Evidence levels

LLM confidence is not evidence.

AROS must never infer a stronger evidence level from the existence of code, a source marker, a generated file, or an asserted boolean. The level is earned only by the corresponding executed measurement.

- **E0 — hypothesis only.** A falsifiable claim exists.
- **E1 — static/architectural support.** Target/source structure supports the claim.
- **E2 — dynamic supporting observation.** A real target produced behavior relevant to the claim, without yet proving the security invariant was violated.
- **E3 — invariant violation.** The research path observed a real response/effect that satisfies the explicit invariant-violation oracle.
- **E4 — independent reproduction.** A second execution against a copied byte-identical target tree, with the oracle evaluated from that replica's own stdout. The original tree digest must be unchanged. E5 shrink does not count as E4. HTTP fixture campaigns that previously stopped at E3 earn E4 when this replica re-run matches.
- **E5 — minimized reproduction.** A separate minimization procedure demonstrates that unnecessary steps/inputs can be removed while the invariant violation remains. Earned only when a generator emits `SHRINK_BEFORE` / `SHRINK_LEN` / `SHRINK_HEX`, the bytes re-trigger the oracle, and the minimized payload is CAS-addressed. HTTP class campaigns without shrink stay at E3. E5 does not satisfy an E4 independent-reproduction requirement.
- **E6 — counterfactual differential.** The original exploit effect is present on the original target and absent on an actual patched twin while declared legitimate functionality still works.
- **E7 — variant re-attack + executable regression.** At least one meaningful variant fails to re-exploit the patched twin and an actual generated regression test is executed successfully.

For the current hardening branch, E4/E6/E7 code paths have been rewritten around actual target processes and are `IN PROGRESS` until the branch's Rust CI passes. E5 is implemented for shrink-capable generators (`mutate-fuzz`). See `docs/BUILD_STATUS.md`.

If the verifier executable, Python target runtime, replay recipe, or exact target state is unavailable, evidence is capped at E3 and the campaign reports insufficient evidence rather than substituting a behavioral mock.

Containment is orthogonal to evidence level: a finding may have strong reproduction evidence and still be unacceptable for release if the execution boundary itself was not demonstrated. A `ContainmentReport` proves host isolation capability; it does not prove a campaign used that isolation unless the measured container/network identity is the one that executed the campaign.
