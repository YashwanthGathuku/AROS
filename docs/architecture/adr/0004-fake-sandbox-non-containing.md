# ADR-0004: FakeSandboxProvider cannot demonstrate containment

- Status: Accepted
- Date: 2026-08-25
- Specs: MVP fail-closed; `docs/TECH_STACK.md` §31

## Decision

`FakeSandboxProvider` exists for unit tests. It always reports
`containment_demonstrated = false`.

A campaign whose policy requires isolation must fail closed on Fake (and on
any host where rootless OCI cannot prove the network invariants).

## Alternatives

1. Treat tempdir as a sandbox for acceptance C — rejected; that would fake
   containment.
2. Skip containment tests when Podman is missing — rejected; skip is not
   fail-closed.

## Security consequences

Acceptance check C may remain unproven on this Windows host until Podman
rootless is installed in WSL. That limitation must be labeled; it must not
be marked DONE.
