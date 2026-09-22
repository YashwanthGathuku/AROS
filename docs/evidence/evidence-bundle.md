# Evidence bundle

A bundle is content-addressed (BLAKE3, SHA-256 metadata) and must include:

- claim
- exact target snapshot identity
- authorization manifest hash
- sandbox identity / policy hash when present
- experiment preconditions, actions, raw artifacts
- security oracle and negative control
- independent verifier reproduction
- remediation / re-attack / regression when those stages ran

Declared RedLab campaigns also write `evidence-report.html` under the work
root. That report is the human-readable surface of the same bundle: claim /
invariant, target digest + revision pin, harness digest, generator and oracle,
run kind (`security` or `environment_mismatch`), level achieved vs required,
ledger verification, token negative-control, structural good/mutant arms, and
per-surface results. It is not a substitute for the CAS objects or the ledger.

Filenames are not identity. `aros evidence verify --work DIR` checks the hash chain. When `certificate.json` is present it also checks that file.

## Certificate

A declared campaign writes `certificate.json` in the work directory. The BLAKE3 digest covers the claims with the digest field removed. The ledger event `CertificateIssued` records `contained` and `original_unmodified`. Verification fails if those flags, the ledger head, the harness digest, the regression file, or the minimized payload disagree.

`release_eligible` is true only when containment was demonstrated, the original digest is unchanged, required evidence was met, and the evidence level matches the measurements. A waived host run can still have `statement_ok` and must have `release_eligible: false` with the limit `containment not demonstrated`.

This is a consistency check of a copied work directory. It is not a signature from a key the holder does not have. Rewriting the ledger and the certificate together creates a different bundle; editing only one of them fails.
