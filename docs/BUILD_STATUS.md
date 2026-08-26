# AROS v0.1 Build Status

Persistent execution ledger. Status values: `DONE` | `IN PROGRESS` | `BLOCKED` | `NOT STARTED` | `POST-MVP`.

A `DONE` item must cite verification evidence. File existence is not enough except for specification documents.

Last updated: 2026-08-25 (5-way packet probes, subprocess verifier, THEUSTAD HTTP, multi-turn worker, CLI remote)

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
| Cargo workspace | DONE | `cargo test --workspace` |
| Python package | DONE | `python -m pytest python` |
| LICENSE Apache-2.0 | DONE | `LICENSE` |
| SECURITY.md / CONTRIBUTING.md / CODE_OF_CONDUCT.md | DONE | files present |
| `scripts/acceptance.sh` | DONE | Maps A–L to cargo/pytest; live OCI C not claimed unless `ContainmentReport.live_oci_claimable()` |
| CLI `aros doctor` | DONE | Prints packet probes + ContainmentReport JSON |

---

## Trusted Rust core

| Item | Status | Evidence |
|---|---|---|
| `aros-types` domain model | DONE | `cargo test -p aros-types` |
| `aros-policy` AuthorizationManifest + engine | DONE | Public Internet deny, fail-closed containment, REQUIRES_HUMAN not auto-promoted |
| `aros-evidence` CAS + ledger + THEUSTAD | DONE | Tamper detection; `TheustadAdapter` loopback HTTP fail-closed tests |
| `aros-store` SQLite | DONE | Roundtrip + ledger reload; `research_card` records |
| `aros-core` campaign/graph/budget/broker | DONE | Live re-attack; ResearchCard persist; `verify_in_subprocess`; `mock_authz_lifecycle_with_live_reattack` |
| `aros-sandbox` Fake + Rootless OCI | DONE | Fake never claims. 5-way packet fields on `ContainmentReport`. `live_oci_claimable` requires probes actually ran |
| `aros-ipc` framed protobuf | DONE | Hello+token, ToolIntent closed-loop, crash isolation |
| `aros-api` arosd | DONE | `/health`, `/v1/tool-intent`, `/v1/campaigns/fixture`, registry |
| `aros-cli` aros | DONE | doctor packet report; in-process campaign; `--remote` / `AROS_DAEMON_URL` to arosd |

---

## Python research plane

| Item | Status | Evidence |
|---|---|---|
| `aros_research` package | DONE | `--research-once` and `--research-campaign` multi-turn ToolIntent loop |
| Typed IPC client | DONE | Hello token + ToolIntent + IntentResult decode |
| Deterministic mock provider | DONE | plus OpenAI-compat config with secret redaction |
| Five research agents | DONE | Director `plan_campaign_intents`; pytest `test_campaign.py` |
| ResearchSkill builtin set | DONE | 20 skills in `skills/builtin/` + generated markdown |
| NativeHarness / GrokBuildHarness | DONE | plan_argv never uses `--always-approve`; pytest |

---

## Research lifecycle

| Item | Status | Evidence |
|---|---|---|
| Snapshot | DONE | `snapshot_tree` hashed in engine test |
| Surface / assumptions / hypotheses | DONE | mock engine + worker campaign intents |
| Experiment / observation / falsify | DONE | HTTP GET against in-test server; deceptive fixture rejected |
| Independent verifier | DONE | `aros-verifier` subprocess; `crates/aros-core/tests/verifier_subprocess.rs` |
| THEUSTAD adapter (optional) | DONE | `AROS_THEUSTAD_URL` loopback HTTP; fail-closed if down |
| Patch twin / re-attack / regression | DONE | twin copy + live HTTP re-attack on patched port |
| Original-target immutability | DONE | engine test asserts original digest unchanged |
| ResearchCard persist | DONE | `store.get_record("research_card", ...)` in authz lifecycle test |

---

## Fixtures and acceptance

| Item | Status | Evidence |
|---|---|---|
| Fixture 1 authorization/state | DONE | `mock_authz_lifecycle_with_live_reattack` |
| Fixture 2 representation/path | DONE | `mock_path_lifecycle_with_live_reattack` |
| Fixture 3 deceptive | DONE | `mock_deceptive_is_rejected` |
| Acceptance A–L | DONE | mapped in `scripts/acceptance.sh`; live OCI C claimed only when packet probes pass |
| Security tests against AROS | DONE | Internet deny, IPv6 non-inherit, docker.sock/ssh deny, README cannot expand tools, CAS isolation, ledger tamper, original integrity. Live packet isolation is measured, never assumed |

---

## Host environment (measured 2026-08-25)

| Capability | Status | Notes |
|---|---|---|
| Windows Rust 1.96.0 gnu | DONE | `.cargo/config.toml` uses rust-lld self-contained |
| WSL2 Ubuntu-24.04 | DONE | Present |
| Python 3.14.7 | DONE | `py -3.14` |
| Rootless Podman 6.1.0 WSL2 | IN PROGRESS | Machine can start; live_oci_claimable requires alpine image + 5-way probes |
| Git | DONE | `main` at origin |

---

## Quality gates

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
PYTHONPATH=python python -m pytest python
```

Live OCI acceptance C is **not** claimed unless `ContainmentReport.live_oci_claimable()` is true on the host.

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
