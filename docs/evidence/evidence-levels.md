# Evidence levels

LLM confidence is not evidence.

AROS must never infer a stronger evidence level from the existence of code, a source marker, a generated file, or an asserted boolean. The level is earned only by the corresponding executed measurement.

- **E0 — hypothesis only.** A falsifiable claim exists.
- **E1 — static/architectural support.** Target/source structure supports the claim.
- **E2 — dynamic supporting observation.** A real target produced behavior relevant to the claim, without yet proving the security invariant was violated.
- **E3 — invariant violation.** The research path observed a real response/effect that satisfies the explicit invariant-violation oracle.
- **E4 — independent reproduction.** A second execution against a copied byte-identical target tree, with the oracle evaluated from that replica's own stdout. The original tree digest must be unchanged. E5 shrink does not count as E4. HTTP fixture campaigns that previously stopped at E3 earn E4 when this replica re-run matches.
- **E5 — minimized reproduction.** A separate minimization procedure demonstrates that unnecessary steps/inputs can be removed while the invariant violation remains. Earned only when a generator emits `SHRINK_BEFORE` / `SHRINK_LEN` / `SHRINK_HEX`, the bytes re-trigger the oracle, and the minimized payload is CAS-addressed. HTTP class campaigns without shrink stay at E4 when the replica matches; they do not earn E5. E5 does not satisfy an E4 independent-reproduction requirement.
- **E6 — counterfactual differential.** Declared catalog path: original attack succeeded, E4 replica matched, the same campaign **holds** on a copy of an operator-supplied patched twin (`--twin`), and the original and operator twin digests are unchanged. Health/`OPEN_OK` is the functional check. A missing or still-vulnerable twin does not earn E6. A twin without a derivable related variant stays at E6. Fixture HTTP lab still uses its dedicated twin launcher.
- **E7 — variant re-attack + executable regression.** Declared catalog path: E6 holds, a related variant (drop cookie, or encoded/decoded `../`) **succeeds on the original replica** and **holds on the twin copy**, and `work_root/e7-regression/regression_test.py` is generated, CAS-addressed, and executed against the twin copy. The script is not written into the original or operator twin. No derivable variant, or a variant that does not discriminate original vs twin, does not earn E7. Fixture HTTP lab still uses its dedicated regression writer.

Declared catalog E4/E6/E7 and shrink E5 are implemented and tested. Live contained execution remains `IN PROGRESS`. See `docs/BUILD_STATUS.md`.

If the verifier executable, Python target runtime, replay recipe, or exact target state is unavailable, evidence is capped at E3 and the campaign reports insufficient evidence rather than substituting a behavioral mock.

Containment is orthogonal to evidence level: a finding may have strong reproduction evidence and still be unacceptable for release if the execution boundary itself was not demonstrated. A `ContainmentReport` proves host isolation capability; it does not prove a campaign used that isolation unless the measured container/network identity is the one that executed the campaign.
