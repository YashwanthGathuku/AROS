# AROS v0.1 Build Status

Persistent execution ledger. Status values: `DONE` | `IN PROGRESS` | `BLOCKED` | `NOT STARTED` | `POST-MVP`.

A `DONE` item must cite behavior that the code actually executes. A simulated stand-in, an unexecuted generated file, a declared type, or a capability probe is not accepted as evidence for a stronger runtime claim.

Last updated: 2026-09-01 — `campaign-loader/` added as declarative RedLab campaign data (schema + two dycrpt campaigns + 10 roles). This is **not** executed behaviour: AROS still runs `FixtureKind` fixtures; dycrpt RedLab harnesses do not exist; no evidence bundle. Campaign-bound OCI remains deferred.

## Release posture

**`v0.1.0-mvp` is BLOCKED.** The source branch now refuses to equate “this host can create an isolated Podman network” with “this campaign executed inside that network.” Campaign-bound OCI target execution remains unfinished and therefore containment-required host campaigns fail closed. Do not tag until the acceptance gate and the host-specific campaign-bound isolation proof both pass.

## Specifications and decisions

| Item | Status | Evidence / limitation |
|---|---|---|
| `docs/AROS_MVP_SPEC.md` | DONE | Source-of-truth specification exists. Implementation drift is tracked below. |
| Rust/Python trust split | IN PROGRESS | UDS + isolated rootless worker launcher implemented; a host worker exists only behind an explicit development waiver. Target/broker campaign execution is not yet bound to OCI. |
| Protobuf UDS IPC | IN PROGRESS | Unix/WSL UDS is implemented; TCP remains explicit test/development transport. Containerized-worker CI/host proof is still required. |
| SQLite + petgraph choice | DONE | Implemented libraries exist. Graph persistence/use is still `IN PROGRESS`. |
| Apache-2.0 / rusqlite bundled | DONE | Repository configuration. |

## Trusted Rust core

| Item | Status | Evidence / limitation |
|---|---|---|
| `aros-types` domain types | DONE | Core types compile as the shared model. Construction/use of every research type is not implied. |
| Authorization/policy engine | IN PROGRESS | Default deny, explicit roots/ports, path property tests, canonical/symlink checks in broker. More trusted-core property tests are being added. |
| CAS | DONE | Content-addressed evidence storage. |
| Event ledger in memory | DONE | Canonical chain hashing and verification. |
| Event ledger across SQLite persistence | IN PROGRESS | Stored hashes/digests are preserved and verified; direct SQLite tamper and cross-campaign tests added. Awaiting green Rust CI for this branch. External/keyed anchoring is not yet implemented. |
| Campaign-scoped evidence persistence | IN PROGRESS | New `ledger_events(campaign_id, idx, ...)` storage prevents global event deletion. Awaiting green Rust CI. |
| Exact-target snapshot | IN PROGRESS | Tree hashing rejects symlinks; verifier brackets target before/after replay. Awaiting green Rust CI. |
| Independent verifier E4 | IN PROGRESS | Rust behavioral mock removed. Dedicated verifier copies the byte-identical tree and launches its actual `server.py`, with readiness and hard subprocess deadlines. Awaiting green integration tests; E4 must remain unavailable when runtime prerequisites are absent. |
| Rootless OCI isolation measurement | IN PROGRESS | Five tri-state dimensions, fresh measurement, tool preflight, transport-level reachability probes. This proves isolation capability only. |
| Campaign-bound OCI execution | BLOCKED | Not yet implemented. `RootlessOciSandboxProvider` now refuses fake build/spawn/snapshot and raw caller-supplied Podman argv. Host fixture campaigns requiring containment fail closed. |
| Broker filesystem isolation | IN PROGRESS | Canonical target/root checking; final symlink refusal; recursive traversal skips symlinks; exact snapshots reject symlinks. Awaiting CI. |
| `arosd` daemon default policy | IN PROGRESS | Explicit `AROS_LAB_ROOT`, containment defaults true, network ports explicit, bearer token required for `/v1/*`. CLI authenticated remote compatibility still being updated. |
| THEUSTAD transport | DONE | Loopback-only; configured transport/parse/non-2xx failure is insufficient evidence. It is optional and is not presented as a second independent opinion when absent. |

## Python research plane

| Item | Status | Evidence / limitation |
|---|---|---|
| Typed worker IPC | IN PROGRESS | UDS production seam and token-in-environment implemented. |
| Host worker containment | BLOCKED by design | Host worker is not a security boundary and is disabled unless `AROS_ALLOW_UNCONTAINED_WORKER=1`. |
| Rootless containerized worker | IN PROGRESS | `--network=none`, read-only rootfs, dropped caps, no-new-privileges, resource limits and narrow mounts implemented; host/CI runtime proof pending. |
| ResearchSkill catalog | IN PROGRESS | 20 JSON skills are runtime-loaded/validated and `ResearchDirector.next_hypothesis()` derives hypothesis/controls/tool metadata from a selected skill. Python CI must stay green. |
| Multi-turn research worker | IN PROGRESS | Typed intents work, but the general autonomous research graph/scheduler loop is not yet equivalent to the full MVP spec. |
| Model provider abstraction | DONE | Deterministic mock and local OpenAI-compatible configuration with secret redaction. |

## Evidence ladder / lifecycle

| Level / operation | Status | Meaning currently earned |
|---|---|---|
| E0 hypothesis | DONE | Hypothesis exists; skill-driven Python hypothesis generation is being wired to the campaign system. |
| E1/E2 static/dynamic support | IN PROGRESS | Target mapping and observations exist, but explicit typed persistence/graph relations are being expanded. |
| E3 invariant violation | DONE for fixture development path | Based on actual fixture HTTP behavior, not a source flag. |
| E4 independent reproduction | IN PROGRESS | Actual target program launched by verifier; no behavioral stand-in. Awaiting green CI. |
| E5 minimized reproduction | NOT STARTED as a distinct proof | A low-cost replay recipe exists, but a separate minimization step is not yet demonstrated and must not be claimed implicitly. |
| E6 counterfactual differential | IN PROGRESS | Actual patched twin is launched and original exploit + legitimate-function checks run. Awaiting CI. |
| E7 variant + regression | IN PROGRESS | At least one variant is replayed and an executable generated regression is run before E7. Awaiting CI. |
| Deceptive/negative control | IN PROGRESS | Generic invariant outcome rejects the deceptive fixture; no `kind == Deceptive` success/failure shortcut. Awaiting CI. |
| ResearchCard | DONE in development lifecycle | Persisted learning record. |
| ResearchFailureCard / failure memory | NOT STARTED | Domain type exists; durable failure-memory behavior still needs wiring. |

## Graph and research memory

| Item | Status | Evidence / limitation |
|---|---|---|
| In-memory typed graph | DONE | `ActiveGraph` supports nodes and edges. |
| Persisted graph nodes/edges | IN PROGRESS | Store schema exists; runtime persistence/reload wiring is being completed. |
| Causal/epistemic edges through lifecycle | IN PROGRESS | Required before claiming the graph is a durable epistemic research graph. |
| Anomaly notebook | NOT STARTED | Type exists; behavior not yet implemented. |
| Telemetry stream | NOT STARTED | Type exists; behavior not yet implemented. |
| Methodology/failure memory | IN PROGRESS | JSON ResearchSkill runtime is wired; durable MethodologyCard/ResearchFailureCard behavior remains. |

## Fixtures

| Fixture | Status | Evidence / limitation |
|---|---|---|
| Authorization/state | IN PROGRESS | API campaign launches real Python target; verifier and patched twin launch actual target programs. Awaiting Rust CI. |
| Representation/path | IN PROGRESS | Same; legitimate `public.txt` behavior added for functional post-patch check. Awaiting CI. |
| Deceptive negative control | IN PROGRESS | Real Python negative-control fixture; generic invariant rejects it. Awaiting CI. |
| Mislabelled vulnerable-authz | DONE as a refusal test | Directory labelled Authz, patched server; campaign stays E0. |

## RedLab campaign files (declarative only)

| Item | Status | Evidence / limitation |
|---|---|---|
| `campaign-loader/campaign.schema.json` | DONE as data | 13 required fields; both campaign files have all of them and no extras. |
| dycrpt replay / MAX_SKIP campaigns | DONE as data | Pinned to dycrpt `e4e200ad71bda9ef81ea0bfa4c6e427dc9d7d82c`. Generator commands name harnesses that do not exist yet. |
| 10 roles in `roles.json` | DONE as data | Attackers separated from independent-reproducer and remediation-agent. |
| AROS engine loads campaign schema | IN PROGRESS | `CampaignSpec` parses shipped files; `run_declared_campaign` fails closed when the harness is absent (tested). HTTP fixtures still use `FixtureKind`. No dycrpt evidence yet. |
| dycrpt `redlab_replay` / `redlab_maxskip` harnesses | NOT STARTED | Outside this repo until written in dycrpt. |

## Current quality gates

Required before merge:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
python -m ruff check python
python -m mypy python/aros_research
PYTHONPATH=python python -m pytest python -q
```

Current PR: `#2 Repair epistemic evidence and runtime trust boundaries`.

Python CI has reached green during this remediation. Rust CI is still being iterated and **must not be reported as green until the current branch head passes format, Clippy and workspace tests.**

## Host-specific acceptance left to the operator

A Podman/WSL host must run fresh containment probes. Even a fully `Proven` five-way `ContainmentReport` does **not** by itself close campaign-bound containment; the actual target/worker execution identities must correspond to the containers being measured.

## Post-MVP / intentionally deferred

| Item | Status |
|---|---|
| gVisor / Firecracker providers | POST-MVP |
| Public Internet targets | POST-MVP |
| Large historical corpora | POST-MVP |
| Web UI | POST-MVP |
| Paid cloud inference as a requirement | POST-MVP |
