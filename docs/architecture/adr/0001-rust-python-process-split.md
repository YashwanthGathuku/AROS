# ADR-0001: Rust trusted plane, isolated Python workers

- Status: Accepted
- Date: 2026-08-25
- Specs: `docs/AROS_MVP_SPEC.md` [TECHNOLOGY ARCHITECTURE]; `docs/TECH_STACK.md` §§1, 10–14, 33

## Decision

Rust owns the trusted control plane. Python research intelligence runs in
separate, restartable processes and talks to Rust over typed IPC.

Python is not embedded in `arosd`.

## Alternatives

1. Python application with Rust extensions — rejected; puts authority next to
   untrusted model output.
2. Embedded CPython in the daemon — rejected by TECH_STACK §12 unless an ADR
   later proves isolation is impossible.
3. Go control plane — rejected by TECH_STACK §20.

## Security consequences

A worker crash, hang, or malicious native extension cannot take down the
policy engine. Privileged operations remain behind deterministic policy.
