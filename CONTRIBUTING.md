# Contributing

Read `docs/AROS_MVP_SPEC.md` and `docs/TECH_STACK.md` before changing
architecture.

## Rules

- Do not put authorization inside the LLM.
- Do not embed Python in the trusted Rust daemon.
- Do not add Postgres, Kafka, Redis, Neo4j, or Go without an ADR.
- Do not weaken fail-closed containment to make a test pass.
- Original targets must never be modified by automatic remediation.

## Quality gates

Rust:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
```

Python:

```bash
ruff check python
mypy python
pytest
```

Completion gate:

```bash
./scripts/acceptance.sh
```

## ADRs

If implementation must deviate from the specs, add
`docs/architecture/adr/NNNN-title.md` covering the problem, alternatives,
security consequences, and the chosen solution.
