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

Filenames are not identity. `aros evidence verify-ledger` checks the hash chain.
