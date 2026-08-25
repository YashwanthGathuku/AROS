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

Filenames are not identity. `aros evidence verify-ledger` checks the hash chain.
