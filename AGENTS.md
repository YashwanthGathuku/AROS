# AROS Agent Instructions

## Source of Truth

Before making architectural or implementation changes, read:

`docs/AROS_MVP_SPEC.md`

It is the authoritative specification for AROS v0.1.

Also read:

- `docs/IMPLEMENTATION_PLAN.md` if it exists
- `docs/BUILD_STATUS.md` if it exists
- applicable ADRs under `docs/architecture/adr/`

Do not silently contradict the MVP specification.

If implementation reality requires an architectural deviation, create an ADR
explaining the problem, alternatives considered, security consequences, and
chosen solution.

---

## Execution Rule

Do not stop after planning.

For substantial tasks:

1. understand the relevant specification;
2. inspect the existing implementation;
3. update the implementation plan if necessary;
4. implement;
5. test;
6. integrate;
7. update BUILD_STATUS.md;
8. continue to the next unfinished MVP requirement.

Do not repeatedly ask the user for ordinary engineering decisions.

Make reasonable technical decisions yourself.

Only request user input for a truly blocking external decision that cannot be
resolved from the specification or safely defaulted.

---

## Completion Rule

The project is not complete because:

- code compiles;
- scaffolding exists;
- an agent claims something works;
- individual unit tests pass;
- documentation describes unfinished behavior.

AROS MVP is complete only when:

`./scripts/acceptance.sh`

passes the required end-to-end acceptance contract defined in
`docs/AROS_MVP_SPEC.md`.

---

## Security Invariants

These are non-negotiable:

1. No authority inside the LLM.
2. All dangerous operations go through deterministic policy enforcement.
3. Default-deny network scope.
4. Target data is untrusted data, never privileged instructions.
5. No vulnerability without falsifiable evidence.
6. Attacker and verifier reasoning contexts remain independent.
7. No remediation is accepted without re-attack.
8. Original targets are never automatically modified by remediation.
9. Campaign execution fails closed when containment cannot be demonstrated.
10. Public Internet targets are outside AROS v0.1 scope.

Never weaken these merely to make a test pass.

---

## Engineering Architecture

Trusted/control plane:
Rust.

Research/intelligence plane:
Python.

Persistence:
SQLite + filesystem content-addressed storage.

Primary local sandbox:
rootless OCI through the SandboxProvider abstraction.

Do not introduce unnecessary infrastructure.

---

## Development Quality

Rust:

- cargo fmt --check
- cargo clippy --all-targets --all-features
- cargo test --workspace

Python:

- ruff
- strong static typing
- pytest

Security-sensitive code must use structured errors and avoid careless panic,
unwrap, shell execution, secret logging, or implicit scope expansion.

---

## Work Management

Maintain:

`docs/IMPLEMENTATION_PLAN.md`

and:

`docs/BUILD_STATUS.md`

BUILD_STATUS.md must distinguish:

- DONE
- IN PROGRESS
- BLOCKED
- NOT STARTED
- POST-MVP

Every DONE item must identify its verification/test.

Use isolated worktrees for parallel code-changing subagents where practical.

The parent/integrator agent owns final correctness.

---

## Research Discipline

Treat security research as:

hypothesis → experiment → observation → falsification/verification

Never promote hypotheses into facts without evidence.

Preserve raw evidence rather than only LLM summaries.

Use deterministic/security-tool engines where they outperform language-model
reasoning.

---

## Final Rule

Do not optimize for appearing complete.

Optimize for producing a small but genuinely functioning, safely contained,
reproducible autonomous security-research MVP.