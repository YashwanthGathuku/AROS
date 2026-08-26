# THEUSTAD

THEUSTAD is an optional external falsification authority.

`BuiltinEvidenceAuthority` is required for standalone MVP.
`TheustadAdapter` is present and unused unless an endpoint is configured.

Set `AROS_THEUSTAD_URL=http://127.0.0.1:<port>/adjudicate` to enable a
loopback HTTP POST of the evidence bundle. Non-loopback URLs and transport
errors fail closed (`INSUFFICIENT_EVIDENCE`). They do not silently fall
back to builtin verification.

Without the env var, `BuiltinEvidenceAuthority` is used.

Results: VERIFIED, FALSIFIED, INSUFFICIENT_EVIDENCE, NON_REPRODUCIBLE,
TAMPERED.

AROS internals are not coupled to THEUSTAD.
