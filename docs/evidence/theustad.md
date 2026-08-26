# THEUSTAD

THEUSTAD is an optional external falsification authority.

`BuiltinEvidenceAuthority` remains available for standalone MVP operation when THEUSTAD is not configured.

Set `AROS_THEUSTAD_URL=http://127.0.0.1:<port>/adjudicate` to enable a loopback HTTP POST of the evidence bundle and verifier result.

When THEUSTAD is configured, the adapter is fail-closed:

- non-loopback endpoints are refused
- connection/read/write failures become `INSUFFICIENT_EVIDENCE`
- malformed authority responses become `INSUFFICIENT_EVIDENCE`
- **non-2xx HTTP responses become `INSUFFICIENT_EVIDENCE`, even when their body says `VERIFIED`**
- there is no silent fallback to builtin verification after an explicitly configured THEUSTAD endpoint fails

Without the environment variable, `BuiltinEvidenceAuthority` is used.

Authority results include VERIFIED, FALSIFIED, INSUFFICIENT_EVIDENCE, NON_REPRODUCIBLE, and TAMPERED.

The product identity is not coupled to THEUSTAD; the current `AROS_` environment prefix is a compatibility alias managed through the centralized product-identity layer.
