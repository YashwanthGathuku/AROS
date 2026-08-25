# AROS v0.1 Build Status

Persistent execution ledger. Status values: `DONE` | `IN PROGRESS` | `BLOCKED` | `NOT STARTED` | `POST-MVP`.

A `DONE` item must cite verification evidence. File existence is not enough except for specification documents.

Last updated: 2026-08-25

---

## Specifications

| Item | Status | Evidence |
|---|---|---|
| `docs/AROS_MVP_SPEC.md` | DONE | File present; read in full |
| `docs/TECH_STACK.md` | DONE | File present; read in full |
| `AGENTS.md` | DONE | File present; read in full |
| `docs/IMPLEMENTATION_PLAN.md` | DONE | Replaced placeholder with approved plan |
| `docs/RESEARCH_BACKLOG.md` | DONE | RB-001..008 recorded |
| ADR-0001 Rust/Python split | DONE | `docs/architecture/adr/0001-rust-python-process-split.md` |
| ADR-0002 Protobuf UDS IPC | DONE | `docs/architecture/adr/0002-protobuf-uds-ipc.md` |
| ADR-0003 Python version floor | DONE | `docs/architecture/adr/0003-python-version-floor.md` |
| ADR-0004 FakeSandbox non-containing | DONE | `docs/architecture/adr/0004-fake-sandbox-non-containing.md` |
| ADR-0005 petgraph + SQLite | DONE | `docs/architecture/adr/0005-sqlite-petgraph.md` |
| ADR-0006 Apache-2.0 | DONE | `docs/architecture/adr/0006-apache-2.md` |
| ADR-0007 rusqlite bundled | DONE | `docs/architecture/adr/0007-rusqlite-bundled.md` |

---

## Phase 0 — Bootstrap

| Item | Status | Evidence |
|---|---|---|
| Cargo workspace | DONE | `cargo test --workspace` exit 0 (2026-08-25) |
| Python package | DONE | `python -m pytest python` 2 passed; ruff/mypy clean |
| LICENSE Apache-2.0 | DONE | `LICENSE` |
| SECURITY.md / CONTRIBUTING.md / CODE_OF_CONDUCT.md | DONE | files present |
| `scripts/acceptance.sh` | IN PROGRESS | Skeleton runs quality gates; live OCI C not claimed |
| CLI `aros doctor` | DONE | `cargo run -p aros-cli -- doctor` (binary builds) |

---

## Trusted Rust core

| Item | Status | Evidence |
|---|---|---|
| `aros-types` domain model | DONE | 3 unit tests; `cargo test -p aros-types` |
| `aros-policy` AuthorizationManifest + engine | DONE | 13 tests including public Internet deny, fail-closed containment, REQUIRES_HUMAN not auto-promoted |
| `aros-evidence` CAS + ledger | DONE | 4 tests including tamper detection |
| `aros-store` SQLite | DONE | 2 tests roundtrip + ledger reload |
| `aros-core` campaign/graph/budget/broker | IN PROGRESS | mock authz lifecycle + budget semaphore + fail-closed tests; Python worker not yet driving engine |
| `aros-sandbox` Fake + Rootless OCI | IN PROGRESS | Fake never claims containment (3 tests). OCI provider fail-closes; live isolation unproven |
| `aros-ipc` framed protobuf | IN PROGRESS | 2 tests (roundtrip + oversized reject). Unix socket server/worker loop not fully wired |
| `aros-api` arosd | IN PROGRESS | `/health` daemon only |
| `aros-cli` aros | IN PROGRESS | doctor, campaign run, evidence verify-ledger, demo |

---

## Python research plane

| Item | Status | Evidence |
|---|---|---|
| `aros_research` package | IN PROGRESS | import + framing tests; worker `--hello-only` |
| Typed IPC client | IN PROGRESS | framing encode/decode; no live UDS session |
| Deterministic mock provider | IN PROGRESS | Pydantic models exist; Rust mock loop is the exercised path |
| Five research agents | IN PROGRESS | names listed; not independently scheduled |
| ResearchSkill builtin set | IN PROGRESS | `assumption_attack`, `fast_falsification` + schema; remaining skills not authored |
| NativeHarness / GrokBuildHarness | IN PROGRESS | stubs; Grok `available() == False` |

---

## Research lifecycle

| Item | Status | Evidence |
|---|---|---|
| Snapshot | DONE | `snapshot_tree` hashed in engine test |
| Surface / assumptions / hypotheses | IN PROGRESS | exercised in mock engine, not LLM-generated |
| Experiment / observation / falsify | IN PROGRESS | HTTP GET against in-test server |
| Independent verifier | IN PROGRESS | reduced-note verifier run in-process; not a separate worker process |
| THEUSTAD adapter (optional) | IN PROGRESS | trait + unavailable adapter; not invoked against a live THEUSTAD |
| Patch twin / re-attack / regression | IN PROGRESS | twin copy + VULN_IDOR flip + regression file; no live re-HTTP against patched server |
| Original-target immutability | DONE | engine test asserts original digest unchanged |

---

## Fixtures and acceptance

| Item | Status | Evidence |
|---|---|---|
| Fixture 1 authorization/state | DONE | `fixtures/vulnerable/authz` + patched twin; engine test |
| Fixture 2 representation/path | IN PROGRESS | servers exist; engine path kind not yet e2e-tested |
| Fixture 3 deceptive | IN PROGRESS | server exists; engine has deceptive branch; no dedicated cargo test yet |
| Acceptance A–L | IN PROGRESS | A,B,H,L-style unit tests pass; C live isolation NOT proven |
| Security tests against AROS | IN PROGRESS | policy/sandbox/evidence tests; host FS/socket/IPv6 live tests missing |

---

## Host environment (measured 2026-08-25)

| Capability | Status | Notes |
|---|---|---|
| Windows Rust 1.96.0 gnu | DONE | `.cargo/config.toml` uses rust-lld self-contained |
| WSL2 Ubuntu-24.04 | DONE | Present; no rustc/podman inside |
| Python 3.14 | BLOCKED | Windows 3.13.5; WSL 3.12.3; ADR-0003 |
| Rootless Podman/Docker | BLOCKED | Not installed; campaigns fail closed unless `--operator-waive-containment` |
| Git | IN PROGRESS | initializing |

---

## Quality gates last run (2026-08-25)

```text
cargo fmt --all -- --check          PASS (after cargo fmt --all)
cargo clippy --workspace --all-targets --all-features -- -D warnings
                                    PASS
cargo test --workspace              PASS (30 tests)
python -m pytest python             PASS (2 tests)
python -m ruff check python         PASS
python -m mypy python/aros_research PASS
```

---

## Post-MVP (do not implement until acceptance A–L pass)

| Item | Status |
|---|---|
| gVisor / Firecracker providers | POST-MVP |
| Go services | POST-MVP |
| Web UI | POST-MVP |
| Public Internet targets | POST-MVP |
| Large historical corpora | POST-MVP |
| Paid cloud inference as a requirement | POST-MVP |
