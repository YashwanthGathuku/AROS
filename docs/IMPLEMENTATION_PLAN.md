# AROS v0.1 Implementation Plan

> **For agentic workers:** After this plan is approved, write it to `docs/IMPLEMENTATION_PLAN.md`, initialize `docs/BUILD_STATUS.md` and `docs/RESEARCH_BACKLOG.md`, then implement immediately. Do not stop after documentation. Use isolated Git worktrees for independent code-changing subagents. The parent agent is the integrator.

**Goal:** A locally runnable AROS v0.1 whose scientific research lifecycle works end-to-end against repository-owned fixtures and is proven by `./scripts/acceptance.sh`.

**Architecture:** Rust-first trusted daemon (`arosd`) owns authorization, policy, sandbox, broker, evidence, graph, and orchestration. Isolated Python workers perform research intelligence over typed, versioned, bounded Protobuf IPC. SQLite is canonical persistence; a Rust in-memory graph is the active campaign projection. Rootless OCI is the MVP sandbox.

**Tech Stack:** Rust + Tokio + Rayon; Python 3.14+ research workers (see ADR for host version gap); Protobuf over Unix domain sockets; SQLite + filesystem CAS (BLAKE3); rootless OCI via `SandboxProvider`; no Go, no Kafka/Redis/Postgres/Neo4j.

**Specs:**
- `docs/AROS_MVP_SPEC.md` — what the system must do
- `docs/TECH_STACK.md` — how runtime, concurrency, process boundaries, and language ownership must be implemented
- `AGENTS.md` — execution, security invariants, quality gates

## ANCHOR

```text
goal:          Build AROS v0.1 so the authorized local research lifecycle actually runs and acceptance.sh proves it.
acceptance:    ./scripts/acceptance.sh passes spec checks A–L (build, policy, sandbox, snapshot, research, verification, falsification, evidence tamper, remediation, reattack, regression, original integrity).
out of scope:  public Internet targets; Go; web UI; gVisor/Firecracker; large historical corpora; paid cloud inference; Postgres/Kafka/Redis/Neo4j/Elasticsearch; embedding Python in arosd; Android/CI/MCP-as-product-targets.
```

Completing every phase below must satisfy that acceptance line (checkpoint 1). If a phase cannot, the plan is wrong.

---

## 0. Repository inspection (verified)

Existing and **valid — preserve**:

| Path | Status |
|---|---|
| `AGENTS.md` | Complete agent contract |
| `docs/AROS_MVP_SPEC.md` | Full v0.1 specification |
| `docs/TECH_STACK.md` | Full runtime/tech specification (now present) |
| `docs/IMPLEMENTATION_PLAN.md` | Placeholder stub — replace contents, keep file |
| `docs/BUILD_STATUS.md` | Placeholder stub — replace contents, keep file |
| `docs/RESEARCH_BACKLOG.md` | Placeholder stub — replace contents, keep file |
| empty dirs (`crates/`, `python/`, `fixtures/`, `scripts/`, `docs/architecture/`, `.grok/*`) | Intended layout — fill, do not delete |

Missing vs both specs:

- No git repository
- Empty `README.md`
- No Cargo/Python workspace, crates, schemas, CLI, daemon, IPC, fixtures, or scripts
- No ADRs, threat model, or architecture docs
- No `LICENSE` / `SECURITY.md` / `CONTRIBUTING.md`

Host environment (measured, 2026-08-25):

| Fact | Value | Spec impact |
|---|---|---|
| OS | Windows + WSL2 Ubuntu-24.04 (stopped) | Sandbox/OCI is Linux; doctor and acceptance must run containment on WSL |
| Rust | 1.96.0 on Windows; **absent in WSL** | Trusted core can build on Windows; WSL needs Rust for Linux sandbox integration tests |
| Python | Windows 3.13.5; WSL 3.12.3 | **Conflicts with TECH_STACK “Python 3.14+”** — ADR required; do not silently drop the floor |
| Containers | No Podman/Docker on Windows or WSL | Containment tests fail closed until rootless OCI is installed; FakeSandbox is unit-test only |
| Git | Not initialized | First bootstrap step |
| ruff/mypy | Not installed as CLIs | Install via pyproject/dev extras |

**Discrepancies to document before correcting:**

1. `TECH_STACK.md` was initially absent; it now exists and is authoritative HOW. No code currently contradicts it (there is no implementation yet).
2. Python 3.14+ is frozen in TECH_STACK §10/§33; this machine has 3.13.5 / 3.12.3. Create `docs/architecture/adr/0003-python-version-floor.md`. Implementation uses 3.13-compatible syntax until 3.14 is available. `aros doctor` reports SPEC_TARGET 3.14, REQUIRED ≥3.13 for local unit tests, and does not claim 3.14 compliance until present.
3. Rootless OCI is required for campaign execution (MVP spec sandbox + TECH_STACK §33). Runtime missing. Campaigns that cannot demonstrate containment **fail closed**. Unit tests use `FakeSandboxProvider` which must never satisfy `containment_demonstrated`.
4. Preferred IPC is Protobuf over UDS (TECH_STACK §12/§33). Windows AF_UNIX exists but is not the production sandbox host. Production IPC is Linux/WSL UDS. ADR if a Windows test transport is needed.

Do not destroy the spec documents or placeholder ledger files. Replace placeholder *contents*.

---

## 1. Architecture mapping

Maps to: MVP spec [TECHNOLOGY ARCHITECTURE], [REPOSITORY SHAPE], [NON-NEGOTIABLE PRINCIPLES]; TECH_STACK §§1–2, 22, 31, 33.

```text
aros (CLI)
    │ typed local API / Unix socket to daemon
    ▼
arosd (trusted Rust daemon)
    ├── Tokio: I/O, IPC, HTTP, DB, process stdio, timeouts, cancellation
    ├── Rayon + bounded spawn_blocking pools: hashing, graph, diffs
    ├── BudgetGovernor: cells, experiments, sandboxes, CPU, memory, tokens, wall time
    ├── Policy engine (deterministic) ← AuthorizationManifest
    ├── Tool broker (argv[], never unrestricted host shell)
    ├── SandboxProvider → Rootless OCI (fail closed) | Fake (tests only)
    ├── ActiveGraph (petgraph) ←→ SQLite (canonical)
    ├── CAS (filesystem, BLAKE3) + tamper-evident event ledger
    ├── Verifier coordinator (independent context, clean target instance)
    └── Worker supervisor (restartable)
            │ framed Protobuf IPC (versioned, bounded, validated)
            ▼
aros-research-worker (Python, untrusted intelligence)
            ToolIntent / ExecuteExperiment / ReadAuthorizedArtifact
            NO docker socket, host shell, credentials, network policy, FS authority
            ▼
sandbox workloads (separate containers/processes)
    builder | researcher | target | verifier | optional engines
```

Trust hierarchy (TECH_STACK §31): async Rust task → dedicated pool → worker process → rootless container → (post-MVP gVisor/microVM). Isolation increases as trust decreases. `SandboxProvider` is the seam.

Security invariants encoded in types and process boundaries, not prompts:

- LLM never authorizes (MVP principle 1; TECH_STACK §13)
- Default-deny network `0.0.0.0/0` and `::/0`
- Target data is untrusted data
- Fail closed when containment cannot be proven
- Original targets never modified by remediation
- Independent verifier does not receive attacker hidden reasoning

---

## 2. Crate / package boundaries

Maps to: MVP spec [REPOSITORY SHAPE]; TECH_STACK §§2, 29, 33.

Keep close to the spec’s seven crates. Add only crates that are **security or process boundaries**.

### Rust workspace (`Cargo.toml`)

| Crate | Owns | Forbids |
|---|---|---|
| `aros-types` | Domain types, visibility modes, epistemic states, evidence levels, canonical JSON, JSON Schema export | I/O, policy decisions, sandbox |
| `aros-policy` | `AuthorizationManifest` parse/hash, `ToolIntent` validation, deterministic `PolicyDecision` {ALLOW, DENY, REQUIRES_HUMAN} | Execution, Python |
| `aros-sandbox` | `SandboxProvider` trait, typed sandbox states, `RootlessOciSandboxProvider`, `FakeSandboxProvider`, network policy application | Policy *decisions* (consumes them) |
| `aros-evidence` | CAS, evidence bundles, hash-chain ledger, `BuiltinEvidenceAuthority`, `TheustadAdapter` trait | Campaign scheduling |
| `aros-store` | SQLite schema/migrations (sqlx), durable campaign/graph/event rows | In-memory algorithms beyond load/save |
| `aros-core` | Campaign state machine, `ActiveGraph` (petgraph), `BudgetGovernor`, event bus, tool broker, research-twin coordination, verifier control | Python embedding, host shell |
| `aros-ipc` | Protobuf codec, length-prefixed framing, max-size reject, Unix socket server/client | Privilege |
| `aros-api` | `arosd` binary: axum local API, worker supervision, campaign owner actor | Research reasoning |
| `aros-cli` | `aros` binary (clap) | Daemon internals |

Crate-level `#![forbid(unsafe_code)]` on all of the above except a future tiny FFI crate if an engine requires it (none in MVP).

**Not created in v0.1:** Go services, `aros-python-embedded`, graph DB crates, Kafka clients.

### Python package (`pyproject.toml`)

`python/aros_research/`:

```text
agents/        Research Director, Surface Scientist, Researcher, Independent Verifier, Remediation Researcher
harnesses/     NativeHarness, GrokBuildHarness (detect + mock)
models/        OpenAI-compatible local, DeterministicMockProvider, optional remote stubs
skills/        ResearchSkill runtime; schemas live in skills/schema + skills/builtin
tools/         IPC client only (submit ToolIntent)
experiments/   experiment planning DTOs
remediation/   patch reasoning (apply goes through Rust)
ipc/           protobuf client, reconnect, bounded reads
```

Python **does not** exec host tools, open container sockets, or write the original target.

### Shared schemas

```text
proto/aros/v1/*.proto     IPC (source of truth for process messages)
schema/json/*.json        domain JSON Schema generated from aros-types
skills/schema/*.json      ResearchSkill machine-readable schema
```

Cross-language tests: Rust types ↔ JSON Schema ↔ Pydantic; protobuf round-trip.

---

## 3. Rust / Python process boundaries

Maps to: TECH_STACK §§10–14, 22; MVP spec research/intelligence plane.

MVP process topology:

```text
aros                  CLI (user)
arosd                 trusted daemon (Rust)
aros-research-worker  Python  (N bounded workers, restartable)
sandbox containers    target / researcher / builder / verifier
```

`aros-harness-worker` is optional and **not** a separate binary in MVP unless Grok Build invocation requires it. Native harness runs inside the research worker; Grok Build, if present, is an adapter with capability detection.

Fault isolation (TECH_STACK §14): Python hang/crash/leak → daemon terminates worker, records `ResearchFailureCard` / campaign event, restarts or fail-closes per policy. Daemon must not die.

Python requests only:

```text
ExecuteExperiment
RunTool            → ToolIntent
ReadAuthorizedArtifact
RequestSandboxAction
PerformHttpExperiment
```

Rust evaluates `AuthorizationManifest + TargetSnapshot + SandboxIdentity + RequestedCapability` and returns ALLOW / DENY / REQUIRES_HUMAN. REQUIRES_HUMAN is blocked in v0.1 unless invoked via CLI.

---

## 4. IPC architecture

Maps to: TECH_STACK §§12, 30, 33; MVP spec “typed capabilities from the Rust control plane”.

**Choice (no user decision required):** framed Protobuf over Unix domain sockets. Not gRPC (complexity not justified). Not shell/text. Not JSON as the privileged protocol.

Frame:

```text
u32 BE length (payload only, max 4 MiB default)
protobuf Envelope {
  protocol_version: u32   // v1
  request_id: bytes
  kind: oneof { Hello, ToolIntent, IntentResult, Event, Heartbeat, Error, Shutdown }
}
```

Reject:

- length > max
- truncated frames
- unknown required fields that fail protobuf decode
- protocol_version ≠ supported
- oversized strings/repeated fields (prost decode + explicit caps)
- artifact refs that fail CAS path validation

Handshake: worker sends `Hello { worker_kind, protocol_version, python_version }`. Daemon sends `HelloAck { daemon_version, max_frame_bytes, campaign_id, manifest_hash }`.

Windows developer note: prefer running IPC tests in WSL. If Windows AF_UNIX works under Tokio, use it for unit tests; if not, ADR a localhost TCP transport **with a daemon-issued HMAC token and loopback bind only**, never as a production sandbox path.

Security-sensitive IPC is typed, versioned, bounded, validated. Malformed messages → `Error { code: PROTOCOL }` and no execution.

---

## 5. Async / concurrency architecture

Maps to: TECH_STACK §§4–8, 23–24, 27.

Three execution classes:

| Class | Mechanism | Examples |
|---|---|---|
| A Async I/O | Tokio | IPC, axum, sqlx, container API, model streams, sandbox stdio, timeouts |
| B CPU | Rayon pool + `spawn_blocking` (bounded) | BLAKE3 of large blobs, petgraph algorithms, canonicalization of large graphs, diffs |
| C Hostile | sandboxed processes/containers | fuzzers, compilers, target apps, static analyzers, browsers |

**Never:** CPU-heavy work on Tokio worker threads; unbounded agent tasks; unbounded experiments; unbounded queues; hostile tools inside `arosd`; Python privileged host ops.

`BudgetGovernor` (aros-core) enforces:

```text
min(policy_limit, CPU_limit, memory_limit, sandbox_limit, campaign_budget)
```

Implementation: Tokio `Semaphore`s + bounded `mpsc` (explicit capacities) + `CancellationToken` + per-operation timeouts. Campaign owner is an actor (owned state, typed messages) per TECH_STACK §8.

Backpressure: evidence queue is bounded; **never drop** evidence required for verification; telemetry may sample/drop.

Typed intent states (TECH_STACK §9):

```text
UnvalidatedIntent → ValidatedIntent → AuthorizedIntent → ExecutionReceipt
Sandbox<Prepared> → PolicyVerified → Running → Frozen → Destroyed
```

---

## 6. Event architecture

Maps to: TECH_STACK §16; MVP spec [TELEMETRY], [TAMPER-EVIDENT EVENT LEDGER].

In-process: typed `ResearchEvent` enum over bounded Tokio channels. Persistence: append-only SQLite `events` with hash chain (aros-evidence). No Kafka.

Required event types (union of both docs):

```text
TargetRegistered, TargetSnapshotted
CampaignStarted, CampaignCompleted, CampaignFailed
SurfaceMapped, AssumptionCreated
HypothesisCreated, HypothesisPrioritized, HypothesisRefuted
ExperimentStarted, ExperimentFinished
ObservationRecorded, AnomalyRecorded
PrimitiveSupported, PrimitiveVerified, AttackChainCreated
FindingCandidateCreated, FindingVerified, FindingFalsified
PatchCandidateCreated
ReattackStarted, ReattackCompleted
RegressionCreated
AgentStarted, AgentStopped
ToolRequested, ToolAllowed, ToolDenied
ProcessStarted, ProcessFinished
NetworkAttempted, PolicyViolationAttempt, SandboxKilled
EvidenceCreated, ClaimCreated
VerificationStarted, VerificationSucceeded, VerificationFailed
```

Each persisted event:

```text
event_hash = BLAKE3(previous_event_hash || canonical_event || artifact_refs)
```

Includes `manifest_hash`, campaign/run id, timestamp. CLI: `aros evidence verify-ledger`.

---

## 7. Graph / storage architecture

Maps to: MVP spec [THREE LOGICAL GRAPHS], [EPISTEMIC STATES], persistence; TECH_STACK §§15, 17, 33.

**SQLite** = durable canonical store. **Rust `ActiveGraph`** (petgraph) = active campaign operations. Do not recurse SQL for path/chain search.

Logical graphs (same store, `graph` discriminator):

1. Target Reality Graph (Repository, Function, Route, TrustBoundary, …)
2. Research Graph (Assumption, Hypothesis, Experiment, Finding, …)
3. Historical Research Graph (schema now; seed a tiny curated sample only)

Every important edge:

```text
provenance, epistemic_state, confidence?, campaign_id, timestamp, source_artifact_refs
```

Epistemic states: OBSERVED, DERIVED, INFERRED, HYPOTHESIZED, SUPPORTED, CLAIMED, VERIFIED, REFUTED, STALE.

LLM output may create HYPOTHESIZED/CLAIMED nodes only. Promotion to VERIFIED is verifier + evidence authority, never the researcher worker.

CAS: `data/cas/blake3/<aa>/<digest>`; SHA-256 sidecar metadata when interoperability needs it. Filenames are not identity.

SQLite (indicative): `campaigns`, `manifests`, `targets`, `snapshots`, `nodes`, `edges`, `events`, `artifacts`, `findings`, `verifier_runs`, `patches`, `reattacks`, `regressions`, `research_cards`, `failure_cards`, `anomalies`, `telemetry`.

---

## 8. Sandbox architecture

Maps to: MVP spec [SANDBOX PROVIDER], [OCI HARDENING], [NETWORK MODEL], [BUILDER VS ATTACK]; TECH_STACK §§18, 31, 33.

```text
trait SandboxProvider {
  prepare, build_target, spawn, execute, snapshot, reset, freeze, collect, destroy
}
```

MVP provider: `RootlessOciSandboxProvider` (Podman rootless preferred; Docker rootless only if controls hold). No silent safety downgrade.

OCI defaults: non-root, drop caps, no-new-privileges, read-only rootfs, tmpfs scratch, PID/memory/CPU/disk limits, no host socket/home, no privileged, source RO, mutable scratch volume.

Network:

```text
Researcher container → AROS internal network → Target container
```

No public gateway. Authorized names/addresses/ports only. IPv4 and IPv6. Controlled DNS. Tests: target reachable; unauthorized external not; public DNS not an egress bypass; host gateway denied; IPv6 does not bypass. If unprovable → campaign fail closed.

Builder sandbox (dependency fetch) is separate from research sandbox (no arbitrary Internet).

`FakeSandboxProvider`: in-process/tempdir for unit tests. Sets `containment_demonstrated = false`. Policy layer must refuse real campaigns on it.

Host: install Podman rootless in WSL as bootstrap optional; `aros doctor` classifies REQUIRED / OPTIONAL / UNSAFE.

---

## 9. Dependency graph (build order)

```text
aros-types
    ├── aros-policy
    ├── aros-evidence
    ├── aros-store
    ├── aros-ipc
    └── aros-sandbox ──► aros-policy (decisions in, execution out)
            │
            ▼
        aros-core  (policy, sandbox, evidence, store, ipc, types)
            │
            ├── aros-api (arosd)
            └── aros-cli (talks to api)

python/aros_research  ──► proto generated stubs + pydantic domain (no rust link)
fixtures              ── independent after Phase 0
skills/builtin        ── after schema in Phase 1
```

Libraries (evaluate before adding; prefer spec list):

Rust: tokio, axum, serde, serde_json, clap, tracing, sqlx (sqlite), blake3, sha2, rayon, petgraph, thiserror, prost, tokio-util, uuid, tempfile (dev), proptest (dev).

Python: pydantic, httpx, asyncio stdlib, pytest, ruff, mypy, protobuf.

License: Apache-2.0. Audit in `docs/dependency-license-audit.md`. No GPL/AGPL vendoring.

---

## 10. Implementation phases

Each phase has a checkable acceptance sentence.

### Phase 0 — Bootstrap and ledgers

**Acceptance:** `cargo metadata` works; `python -m compileall` on empty package works; `docs/IMPLEMENTATION_PLAN.md` / `BUILD_STATUS.md` / `RESEARCH_BACKLOG.md` are real ledgers; git repo exists with Apache-2.0 license files; `scripts/acceptance.sh` exists and fails on missing gates rather than exiting 0.

Work: git init; workspace files; LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, NOTICE; README; ADRs 0001–0003; script skeletons; `.gitignore`; rustfmt/clippy config; pyproject.

### Phase 1 — Domain types and schemas

**Acceptance:** All MVP domain types exist in `aros-types` and Pydantic; JSON Schema round-trip tests pass; canonical serialization is deterministic (property test).

### Phase 2 — Policy and AuthorizationManifest

**Acceptance:** Manifest hashes stably; unauthorized path/network/tool is DENY; REQUIRES_HUMAN is not auto-promoted; fuzz/property tests cover parse, path-scope, network-scope.

### Phase 3 — SQLite, CAS, ledger

**Acceptance:** store round-trips a campaign; CAS retrieves by digest only; mutating a stored event fails `verify-ledger`.

### Phase 4 — Tokio runtime, events, BudgetGovernor

**Acceptance:** bounded experiment semaphore rejects overflow; cancellation stops a fake long task; CPU hash of a blob runs on spawn_blocking/rayon not documented as on worker threads; events persist.

### Phase 5 — Tool broker

**Acceptance:** `read_file` / `list_tree` / `search_text` work inside allowlist; shell metacharacter argv smuggling rejected; every execution writes a receipt with manifest hash.

### Phase 6 — Sandbox provider

**Acceptance:** Fake provider cannot start a campaign that requires containment; on WSL+Podman, isolation tests A–E in spec network model pass; without Podman, doctor=UNSAFE and campaign fail-closed test passes.

### Phase 7 — Typed IPC + Python worker

**Acceptance:** worker crash does not kill a test daemon; oversized/malformed frames rejected; Python `ToolIntent` is policy-evaluated before a fake tool runs; worker restart succeeds.

### Phase 8 — Campaign state machine + mock research loop

**Acceptance:** mock provider drives DISCOVERING→…→REGRESSION_PROTECTED against in-memory/fake sandbox using fixture 1 scripted path; state is not stored as chat history.

### Phase 9 — Python agents and ResearchSkills

**Acceptance:** five agents exist; builtin skills have machine-readable schema + generated markdown; mock cell uses at least `assumption_attack` and `fast_falsification`.

### Phase 10 — Independent verifier + evidence authority

**Acceptance:** true fixture reaches E4+ via verifier with reduced context; deceptive fixture is FALSIFIED/INSUFFICIENT; TheustadAdapter is present but optional.

### Phase 11 — Local fixtures (parallel from Phase 0)

**Acceptance:** three fixtures exist (authz/state, representation/path, deceptive) each with vulnerable/patched, functional tests, security oracle; no Internet.

### Phase 12 — CLI, doctor, demo

**Acceptance:** documented CLI commands work against the mock lifecycle; `aros doctor` prints REQUIRED/OPTIONAL/UNSAFE; `scripts/demo.sh` runs the spec pipeline on fixture 1.

### Phase 13 — Patch isolation, re-attack, regression, original integrity

**Acceptance:** patch applied only to twin/worktree; original fixture tree hash unchanged; original effect gone on patched twin; functional tests still pass; regression test generated and passes.

### Phase 14 — Acceptance gate, docs, security tests

**Acceptance:** `./scripts/acceptance.sh` green on a machine with required tools, or explicitly fails closed with a machine-readable missing-capability report **without claiming MVP complete**. All required docs from MVP spec [DOCUMENTATION] exist. Clippy/fmt/ruff/mypy/pytest/cargo test pass.

---

## 11. Critical path

```text
0 Bootstrap
  → 1 Types
    → 2 Policy
    → 3 Store/CAS/ledger
    → 4 Runtime/events/budget
      → 5 Broker
      → 7 IPC+Python worker
      → 6 Sandbox (can start after 2; join before 8)
        → 8 Campaign SM + mock loop
          → 10 Verifier
          → 12 CLI/demo
          → 13 Patch/reattack/regression
            → 14 Acceptance
```

Phase 11 (fixtures) and documentation can start at Phase 0 and must join before Phase 8 e2e.

Phase 9 (skills/agents) starts after 7, joins 8.

---

## 12. Parallelizable workstreams

Parallelize only when interfaces are already specified (this plan + `aros-types`).

| Workstream | Needs | Must not race |
|---|---|---|
| A Trusted Rust types/policy | nothing after 0 | store APIs |
| B Store/CAS/ledger | types | campaign SM internals |
| C Sandbox | types + policy decision types | broker implementation |
| D IPC proto + Python worker skeleton | types | campaign SM |
| E Fixtures | nothing | none |
| F Skills schema + markdown | skill schema from spec | Python runtime internals |
| G Docs/ADRs/threat model | specs | code |
| H CLI surface (clap stubs) | types | daemon until Phase 8 |

Do **not** parallelize campaign state machine vs broker vs IPC server — those share the campaign owner actor.

---

## 13. Subagent ownership

Parent = integrator, worktree merges, BUILD_STATUS, acceptance.

| Stream | Subagent | Isolation |
|---|---|---|
| A types+policy | rust-policy | worktree |
| B store/evidence | rust-store | worktree |
| C sandbox | rust-sandbox | worktree |
| D ipc+python | ipc-python | worktree |
| E fixtures | fixtures | worktree |
| F skills+docs | docs-skills | worktree (docs) or none for docs-only |
| G runtime/core/broker | rust-core | **serial after A+B**, worktree |
| H cli | rust-cli | after types, finish after G |

Integrator writes Phase 0, merges, runs workspace tests, updates BUILD_STATUS after each stream.

---

## 14. Integration order

1. Merge Phase 0 on main.
2. Merge types (A) first — everyone rebases.
3. Merge policy (A continued) and store (B) — independent.
4. Merge IPC proto (D) so Python and daemon share messages.
5. Merge sandbox trait + fake (C); OCI provider can land gated.
6. Merge core/runtime/broker (G) on main.
7. Wire arosd + worker (D+G).
8. Fixtures (E) + mock loop (Phase 8).
9. Verifier, CLI, demo, patch/reattack.
10. Acceptance.

Each merge requires: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features`, `cargo test --workspace`, and Python ruff/mypy/pytest when Python files change.

---

## 15. Test strategy

Maps to: MVP spec [UNIT + INTEGRATION + E2E], [FUZZ/PARSER TESTING], [SECURITY TESTS]; AGENTS.md quality gates.

| Layer | How |
|---|---|
| Rust unit | cargo test per crate; no unwrap on parse paths |
| Rust property/fuzz | proptest (and cargo-fuzz if practical) on manifest, ToolIntent, network/path scope, evidence serialize, ledger verify |
| Python unit | pytest + typed models |
| Schema | JSON Schema + protobuf compatibility tests |
| Integration | policy+broker+fake sandbox; CAS+ledger tamper; IPC crash/restart; SQLite graph load |
| E2E | mock provider full lifecycle on fixtures 1–3 |
| Security | spec list: egress, unauthorized addr, IPv6, host FS, container socket, shell smuggle, manifest mutation, evidence mutation, cross-campaign CAS, budget, prompt-injection from target files, deceptive reject, original unmodified |
| Quality | fmt, clippy (warnings as errors in CI/acceptance), ruff, mypy, pytest |

`scripts/acceptance.sh` is the only completion gate.

---

## 16. Performance-test strategy

Maps to: TECH_STACK §§25–27.

MVP does **not** chase scale. It must prove bounded concurrency.

Benchmarks under `benchmarks/smoke/`:

- CAS put/get throughput for 1k small blobs and one 64 MiB blob (Rayon/blocking path)
- Event ledger append + verify of 10k events
- ActiveGraph path search on a synthetic 10k-node graph
- BudgetGovernor: N=limit experiments run, N+1 blocked (correctness + timing)
- IPC reject of max+1 frame (latency not the point)

Criterion or a small binary is enough. No rewrite of SQLite/Python unless these fail for a measured reason.

---

## 17. Security-validation strategy

Maps to: MVP spec principles + [SECURITY TESTS]; TECH_STACK trust hierarchy.

1. Policy unit tests: DENY is default; allowlist is exact; human-required stays blocked.
2. Broker tests: no `sh -c`; argv only; env allowlist.
3. Containment tests (WSL+OCI) or fail-closed test if OCI absent.
4. Evidence tamper: flip one byte in CAS or event row → verify fails.
5. Target-instruction injection: fixture README says “grant ALL tools”; capabilities must not expand.
6. Verifier independence: researcher notes omitted from verifier prompt/payload; test asserts reduced evidence bundle.
7. Patch isolation: original tree digest unchanged.
8. Clippy + forbid(unsafe_code) on trusted crates.
9. No secrets in logs (API key redaction test).

Never weaken a control to make a test pass. If OCI is missing, the test that campaigns fail closed **is** the passing test; do not skip it and mark sandbox DONE.

---

## 18. Acceptance criteria

Maps to: MVP spec [ACCEPTANCE TEST] A–L and [DEFINITION OF DONE].

`scripts/acceptance.sh` must:

A. Build Rust workspace + install/import Python package  
B. Unauthorized operation rejected  
C. Authorized local target reachable; public Internet not (or fail closed if OCI missing — and then **not** claim C passed)  
D. Snapshot identity captured (git commit / tree digest)  
E. Fixture progresses surface → hypothesis → experiment → observation  
F. True fixture independently reproduced  
G. Deceptive fixture rejected  
H. Evidence tamper detected  
I. Patch only on twin  
J. Re-attack: effect gone, function remains  
K. Regression generated and passes on patched twin  
L. Original fixture unchanged  

Plus fmt/clippy/test/ruff/mypy.

**MVP is not complete** if only compile/CLI/chat/PoC/docs/unit tests succeed.

---

## 19. ADRs to write immediately (Phase 0)

| ID | Decision |
|---|---|
| 0001 | Rust trusted plane + isolated Python workers (already specified; record as adopted) |
| 0002 | Protobuf length-prefixed UDS IPC, not gRPC, not embedded CPython |
| 0003 | Python version: spec 3.14+ vs host 3.13.5/WSL 3.12.3 — implement 3.13-compatible; doctor distinguishes SPEC_TARGET vs REQUIRED; bootstrap will try to provision 3.14 in WSL |
| 0004 | FakeSandboxProvider is non-containing; cannot satisfy containment_demonstrated |
| 0005 | petgraph + SQLite, not Neo4j |
| 0006 | Apache-2.0 |

---

## 20. Research backlog (non-blocking)

Record in `docs/RESEARCH_BACKLOG.md`, continue implementation:

- Python 3.14 / free-threading availability and dependency compatibility
- Podman rootless on this WSL2 kernel; IPv6 isolation completeness
- Windows AF_UNIX reliability for IPC unit tests
- Grok Build CLI/API actual invocation surface (inspect at harness implementation time)
- THEUSTAD local transport availability
- Optional engines (CodeQL, AFL++, ASan) as adapters only
- gVisor / Firecracker providers (post-MVP)
- Time-travel evaluation methodology (post-MVP)

None of these block Phases 0–5, 7 (fake), 11, or mock-loop 8.

---

## 21. Execution after plan approval (do not wait for extra user prompts)

The user forbade stopping after planning and forbade asking for ordinary engineering decisions.

Immediately:

1. Write `docs/IMPLEMENTATION_PLAN.md` from this plan.
2. Write `docs/BUILD_STATUS.md` as the execution ledger (all workstreams NOT STARTED except specs/docs that exist).
3. Expand `docs/RESEARCH_BACKLOG.md`.
4. Execute Phase 0 on the main workspace.
5. Launch worktree subagents for independent streams A/B/C/D/E as soon as types interfaces are in place (types first on main if needed to avoid merge pain).
6. After each stream: unit + integration + lint, integrate, update BUILD_STATUS, continue critical path.
7. Keep going until acceptance.sh is honest: pass, or fail closed with labeled limitations — never a fake DONE.

### BUILD_STATUS initial classifications

- DONE: `docs/AROS_MVP_SPEC.md` present; `docs/TECH_STACK.md` present; `AGENTS.md` present (verification: files exist and were read).
- IN PROGRESS: Phase 0 bootstrap (starts immediately).
- NOT STARTED: all implementation crates, Python worker, IPC, sandbox, fixtures, CLI, acceptance body.
- BLOCKED: live OCI containment (missing Podman); Python 3.14 floor (missing interpreter) — not blocking mock lifecycle.
- POST-MVP: gVisor, Firecracker, Go, web UI, large corpora, public Internet, paid APIs.

A DONE item must cite a command/evidence. File existence is enough only for specification documents.

---

## 22. Checkpoint 1 (goal-anchor)

If every phase’s acceptance sentence holds, the original goal holds: a real lifecycle plus `./scripts/acceptance.sh`. The plan does not substitute scaffolding, a chatbot, or a scanner for that goal. Out-of-scope items stay out.
