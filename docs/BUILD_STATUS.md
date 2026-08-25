# AROS v0.1 Build Status

Persistent execution ledger. Status values: `DONE` | `IN PROGRESS` | `BLOCKED` | `NOT STARTED` | `POST-MVP`.

A `DONE` item must cite verification evidence. File existence is not enough except for specification documents.

Last updated: 2026-08-25 (ToolBroker executes ALLOW in arosd; CAS digests returned)

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
| Python package | DONE | `python -m pytest python` |
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
| `aros-core` campaign/graph/budget/broker | IN PROGRESS | ToolBroker executes list_tree/read/search/git/http; unit tests `list_tree_executes_and_stores_cas_digest`, `denied_capability_does_not_execute`. Campaign orchestration still partial |
| `aros-sandbox` Fake + Rootless OCI | IN PROGRESS | Fake never claims containment. Podman detect + `--internal` network probe. Full 5-way live egress/IPv6 tests not yet run |
| `aros-ipc` framed protobuf | DONE | Hello+token, ToolIntent closed-loop with IntentResult, crash isolation |
| `aros-api` arosd | IN PROGRESS | Worker ToolIntent → policy → **ToolBroker execute on ALLOW** → IntentResult with exit_status + stdout_digest (CAS). Health reports intents_executed + cas_root. Full campaign API still pending |
| `aros-cli` aros | IN PROGRESS | doctor reports Python 3.14.7 and Podman WSL machine |

---

## Python research plane

| Item | Status | Evidence |
|---|---|---|
| `aros_research` package | IN PROGRESS | worker drives real ToolIntent via `--research-once` / `--probe-intent`; awaits IntentResult with digests; still not full multi-turn campaign |
| Typed IPC client | DONE | Hello token + ToolIntent + IntentResult decode; closed loop |
| Deterministic mock provider | WORKING AND VERIFIED | plus OpenAI-compat config with secret redaction |
| Five research agents | IN PROGRESS | Researcher builds real list_tree/read_file/search_text/http_probe intents; not yet independently scheduled as long-running actors against arosd |
| ResearchSkill builtin set | DONE | 20 skills in `skills/builtin/` + generated markdown |
| NativeHarness / GrokBuildHarness | DONE | plan_argv never uses `--always-approve`; pytest |

---

## Research lifecycle

| Item | Status | Evidence |
|---|---|---|
| Snapshot | DONE | `snapshot_tree` hashed in engine test |
| Surface / assumptions / hypotheses | IN PROGRESS | exercised in mock engine, not LLM-generated |
| Experiment / observation / falsify | IN PROGRESS | HTTP GET against in-test server; broker can now run authorized http_request |
| Independent verifier | IN PROGRESS | reduced-note verifier run in-process; not a separate worker process |
| THEUSTAD adapter (optional) | IN PROGRESS | trait + unavailable adapter |
| Patch twin / re-attack / regression | IN PROGRESS | twin copy + VULN_IDOR flip + regression file; no live re-HTTP against patched server |
| Original-target immutability | DONE | engine test asserts original digest unchanged |

---

## Fixtures and acceptance

| Item | Status | Evidence |
|---|---|---|
| Fixture 1 authorization/state | DONE | `mock_authz_lifecycle_with_waiver` |
| Fixture 2 representation/path | DONE | `mock_path_lifecycle_with_waiver` |
| Fixture 3 deceptive | DONE | `mock_deceptive_is_rejected` |
| Acceptance A–L | IN PROGRESS | mapped in `scripts/acceptance.sh` to cargo tests; live OCI C not claimed |
| Security tests against AROS | IN PROGRESS | Internet deny, IPv6 non-inherit, docker.sock/ssh deny, README cannot expand tools, CAS isolation, ledger tamper, original integrity. Live host-socket/OCI tests still fail-closed |

---

## Host environment (measured 2026-08-25)

| Capability | Status | Notes |
|---|---|---|
| Windows Rust 1.96.0 gnu | DONE | `.cargo/config.toml` uses rust-lld self-contained |
| WSL2 Ubuntu-24.04 | DONE | Present |
| Python 3.14.7 | DONE | |
| Rootless Podman 6.1.0 WSL2 | IN PROGRESS | internal-network probe passed; five live egress tests not claimed |
| Git | DONE | `main` at origin |

---

## Quality gates to re-run after pull

```text
cargo test -p aros-core
cargo test -p aros-ipc
cargo check -p aros-api
python -m pytest python
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
