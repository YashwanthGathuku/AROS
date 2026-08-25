# AROS Technology Stack and Runtime Architecture

## Status

This document defines the authoritative technology, runtime, concurrency, process-boundary, and performance architecture for **AROS v0.1**.

All implementation work must follow this document together with:

- `docs/AROS_MVP_SPEC.md`
- `AGENTS.md`

If an implementation decision conflicts with this document, do not silently choose another technology. Create an Architecture Decision Record under `docs/architecture/adr/` explaining the reason, alternatives, performance/security consequences, and final decision.

---

# 1. Core Technology Decision

AROS is a **Rust-first asynchronous systems platform**.

The architecture is:

```text
Rust
    owns trusted execution and high-performance orchestration

Python
    owns replaceable research intelligence and model integrations

External native tools
    perform specialized security analysis inside sandboxes
```

The MVP must **not** become a Python application with a few Rust extensions.

The trusted and performance-sensitive parts of AROS belong in Rust.

The primary architecture is:

```text
Rust + Tokio + Rayon + isolated Python research workers
```

---

# 2. Language Responsibilities

## Rust — Primary Language

Rust owns:

```text
campaign orchestration
research scheduling
async runtime
authorization
policy enforcement
sandbox lifecycle
network policy enforcement
filesystem capabilities
tool brokering
process supervision
resource governance
target snapshots
event system
evidence recording
content-addressed storage
tamper-evident ledger
active attack/research graph
persistent state
verifier coordination
research-twin coordination
telemetry
CLI
local control API
IPC
```

Rust is the trusted control plane.

No Python component may bypass Rust to perform privileged or security-sensitive operations.

Target roughly:

```text
75–85% Rust
15–25% Python
```

Do not enforce this as an artificial line-count requirement. It expresses architectural ownership.

---

# 3. Rust Runtime

Use stable Rust.

Prefer mature, actively maintained and permissively licensed libraries.

Expected core libraries include approximately:

```text
tokio
axum
serde
serde_json
clap
tracing
sqlx
blake3
sha2
rayon
petgraph or an equivalent graph implementation
thiserror
anyhow only where appropriate outside strongly typed domain boundaries
```

Do not automatically add every library above.

Evaluate whether each dependency is actually necessary.

Avoid excessive dependency growth in the trusted core.

---

# 4. Tokio — Asynchronous I/O Runtime

Use **Tokio** as the primary asynchronous runtime.

Tokio is responsible for I/O-oriented concurrency such as:

```text
campaign coordination
IPC
HTTP
local service communication
model streaming
sandbox monitoring
process output streams
database access
filesystem operations
telemetry
event propagation
timeouts
cancellation
```

Do not create one OS thread per research action.

Use asynchronous tasks where workloads spend significant time waiting for I/O.

Conceptually:

```text
AROS
├── campaign tasks
├── research tasks
├── verifier tasks
├── model streams
├── sandbox monitors
├── evidence writers
├── telemetry tasks
└── tool-execution monitors
```

---

# 5. Async Is Not CPU Parallelism

Do not perform heavy CPU computation directly on Tokio worker threads.

Separate workloads into three execution classes.

## Class A — Async I/O

Use Tokio.

Examples:

```text
HTTP experimentation
model-provider calls
container control
IPC
database operations
event streaming
logs
telemetry
```

## Class B — CPU Parallel Work

Use:

```text
Rayon
dedicated bounded worker pools
tokio::task::spawn_blocking only where appropriate
```

Examples:

```text
graph algorithms
AST processing
large artifact hashing
trace analysis
similarity calculations
coverage processing
delta debugging
research-graph projection
large diff operations
```

## Class C — Hostile or Heavy External Workloads

Run as separate sandboxed processes or containers.

Examples:

```text
fuzzers
compilers
static analyzers
symbolic executors
target applications
sanitizer workloads
browser instances
MCP servers
malicious repositories
native binaries
```

Never run these directly inside the trusted AROS process.

---

# 6. Concurrency Architecture

Use **bounded concurrency** everywhere.

Never create unbounded work from agent-generated hypotheses.

A `BudgetGovernor` must constrain at minimum:

```text
maximum active research cells
maximum concurrent experiments
maximum sandbox instances
maximum subprocesses
maximum CPU consumption
maximum memory consumption
maximum model requests
maximum model tokens
maximum wall time
maximum artifact throughput
```

The effective concurrency should conceptually behave like:

```text
min(
    policy_limit,
    CPU_limit,
    memory_limit,
    sandbox_limit,
    campaign_budget
)
```

Use Tokio semaphores, bounded channels, queues, cancellation tokens, or equivalent mechanisms.

---

# 7. Backpressure

AROS will eventually consume extremely high-volume output from:

```text
fuzzers
sanitizers
logs
traces
network experiments
telemetry
```

All producer/consumer pipelines must support bounded queues.

Do not allow unlimited memory growth.

When consumers fall behind, support appropriate mechanisms such as:

```text
backpressure
aggregation
deduplication
sampling
priority handling
controlled dropping of noncritical telemetry
```

Never discard evidence required for verification.

---

# 8. Actor-Like Ownership for Critical State

Avoid unrestricted shared mutable state.

Security-critical state should have clear owners.

Examples:

```text
CampaignState
AuthorizationState
EvidenceLedger
TargetSnapshotState
SandboxLifecycle
```

Prefer architectures resembling:

```text
              Campaign Owner
                    ▲
                    │ typed messages
        ┌───────────┼───────────┐
        │           │           │
   Researcher   Experiment   Verifier
```

Use channels/message passing where this improves correctness.

Combine the concurrency philosophy of communicating through controlled messages with Rust's ownership and type guarantees.

---

# 9. Encode Security States in Rust Types

Use the Rust type system where practical to prevent invalid security-state transitions.

Prefer conceptual states such as:

```text
UnvalidatedIntent
        ↓
ValidatedIntent
        ↓
AuthorizedIntent
        ↓
ExecutionReceipt
```

and:

```text
Sandbox<Prepared>
        ↓
Sandbox<PolicyVerified>
        ↓
Sandbox<Running>
        ↓
Sandbox<Frozen>
        ↓
Sandbox<Destroyed>
```

Do not implement this pattern merely for aesthetic type complexity.

Use it where it materially prevents security-sensitive misuse.

---

# 10. Python — Research Intelligence Plane

Use **Python 3.14+** for research-intelligence components.

Python owns:

```text
model provider integrations
research-agent reasoning
methodology experimentation
ResearchSkill execution logic where generative reasoning is required
ResearchCard processing
MethodologyCard processing
historical research retrieval
hypothesis-generation strategies
research summarization
remediation reasoning
experimental model/harness integrations
scientific/research prototypes
```

Use:

```text
asyncio
Pydantic
httpx
pytest
ruff
mypy or pyright
```

where appropriate.

The Python layer is:

```text
replaceable
restartable
untrusted or semi-trusted
non-authoritative
```

It must not become part of the core authorization boundary.

---

# 11. Python Free-Threading

Python 3.14 free-threaded builds may be supported where dependencies are compatible.

Do **not** require free-threaded Python for MVP correctness.

Python performance-critical algorithms should first be profiled.

If a Python component becomes:

```text
stable
high-volume
CPU-intensive
latency-sensitive
```

consider migrating it to Rust.

Do not prematurely rewrite research logic before it stabilizes.

---

# 12. Rust ↔ Python Boundary

Do **not** embed Python directly into the trusted Rust daemon for MVP.

Use separate processes.

Recommended architecture:

```text
┌───────────────────────────────────────────┐
│                 arosd                     │
│                                           │
│              Trusted Rust                 │
└───────────────────┬───────────────────────┘
                    │
               typed IPC
                    │
                    ▼
┌───────────────────────────────────────────┐
│          aros-research-worker             │
│                                           │
│                Python                     │
└───────────────────────────────────────────┘
```

Use a typed protocol.

Preferred options:

```text
Protobuf over Unix Domain Sockets

or

another compact framed typed protocol
```

gRPC may be used if its complexity is justified.

Do not use an unstructured shell/text protocol for privileged operations.

---

# 13. Python Has No Direct Authority

Python may send requests such as:

```text
ExecuteExperiment
RunTool
ReadAuthorizedArtifact
RequestSandboxAction
PerformHttpExperiment
```

Rust decides whether they are allowed.

Conceptual flow:

```text
Python researcher
      ↓
ToolIntent
      ↓
Rust Policy Engine
      ↓
ALLOW / DENY / REQUIRES_HUMAN
      ↓
Rust Tool Broker
      ↓
sandbox
```

Python must never directly obtain:

```text
Docker socket
Podman privileged socket
host filesystem authority
host shell authority
network policy authority
credential store
sandbox supervisor authority
```

---

# 14. Process Fault Isolation

A crash in the research worker must not crash the trusted daemon.

If Python:

```text
hangs
leaks memory
loads a faulty native extension
crashes
deadlocks
```

AROS must be able to:

```text
terminate worker
record failure
restart worker
continue or safely stop campaign
```

depending on policy.

The same principle applies to model adapters and future harness adapters.

---

# 15. Graph Architecture

Use:

```text
SQLite
    +
Rust in-memory active graph
```

SQLite remains the durable canonical store for MVP.

Do not perform every active graph traversal through recursive SQL.

Maintain an in-memory graph projection for active campaigns.

Conceptually:

```text
                 SQLite
              durable state
                   ▲
                   │ events/state
                   ▼
          ┌──────────────────┐
          │ Active Rust Graph│
          └──────────────────┘
             │      │      │
             ▼      ▼      ▼
           paths  chains similarity
```

Evaluate `petgraph` or an equivalent implementation.

Do not build a custom graph engine unless profiling demonstrates a real reason.

Do not introduce Neo4j for MVP.

---

# 16. Event-Driven Internal Architecture

Use typed internal research events.

Examples:

```text
TargetRegistered
TargetSnapshotted

CampaignStarted

SurfaceMapped
AssumptionCreated

HypothesisCreated
HypothesisPrioritized
HypothesisRefuted

ExperimentStarted
ExperimentFinished

ObservationRecorded
AnomalyRecorded

PrimitiveSupported
PrimitiveVerified

AttackChainCreated

FindingCandidateCreated
FindingVerified
FindingFalsified

PatchCandidateCreated

ReattackStarted
ReattackCompleted

RegressionCreated

CampaignCompleted
CampaignFailed
```

Events should support:

```text
auditability
replay
telemetry
independent consumers
future distribution
```

Do not introduce Kafka for MVP.

Use Rust channels plus durable event persistence.

---

# 17. Evidence Pipeline

Evidence collection must remain non-blocking wherever practical while preserving ordering and integrity.

Use dedicated evidence-writing tasks.

Required properties:

```text
bounded queues
backpressure
content addressing
canonical serialization
hash-chain integrity
crash-safe persistence where practical
```

Evidence required to validate a finding must never be silently dropped because of telemetry pressure.

---

# 18. External Security Engines

AROS coordinates specialized tools rather than rewriting them.

Potential external engines include:

```text
CodeQL
Semgrep
Joern

AFL++
libFuzzer
Honggfuzz

ASan
UBSan
MSan
TSan

Miri

property-testing frameworks

browser automation
HTTP/API tooling

angr-class tooling
KLEE-class tooling
CBMC-class tooling
```

These are adapters.

They are not part of the trusted core.

Invoke them inside appropriate sandboxes.

---

# 19. C and C++

C and C++ are **not AROS core implementation languages**.

Use them where naturally required by:

```text
LLVM tooling
fuzz targets
sanitizer runtimes
external analysis engines
native target harnesses
third-party libraries
```

Any Rust FFI boundary must be:

```text
small
explicit
reviewable
well-tested
```

Keep `unsafe` code minimal.

Document why every security-sensitive `unsafe` block exists.

---

# 20. Go

Go is **not part of AROS v0.1**.

This is not because Go lacks performance or concurrency capabilities.

It is excluded to avoid an unnecessary third backend runtime and language.

Potential future Go use may include:

```text
Kubernetes operator
remote fleet worker
cloud collector
independent distributed service
```

Only add Go when a concrete requirement demonstrates meaningful benefit over Rust.

Create an ADR before introducing Go.

---

# 21. UI

The MVP is CLI/API first.

Do not prioritize a web interface until the autonomous research lifecycle works.

Future UI technology:

```text
TypeScript
React
```

or another suitable frontend stack.

The UI must communicate with the Rust control API.

It must not communicate directly with privileged sandboxes.

---

# 22. Recommended Process Architecture

Target eventual local process topology:

```text
aros
    CLI

arosd
    Rust trusted daemon

aros-research-worker
    Python research intelligence

aros-harness-worker
    optional isolated harness process

sandbox workloads
    target
    fuzzer
    analyzer
    browser
    verifier
```

For MVP, some executable boundaries may be combined where safe, but preserve the architectural separation.

---

# 23. Cancellation and Timeouts

Every asynchronous external operation must support:

```text
timeout
cancellation
campaign shutdown
sandbox termination
resource-budget termination
```

No research job should be able to hang forever.

Use structured cancellation rather than arbitrary task killing wherever possible.

---

# 24. Resource Accounting

Track resources at least per:

```text
campaign
research cell
experiment
sandbox
model provider
```

Measure where practical:

```text
wall time
CPU
memory
disk
tool invocations
model requests
input tokens
output tokens
artifact bytes
```

These metrics later support research-efficiency benchmarking.

---

# 25. Performance Philosophy

Optimize architecture before micro-optimizing code.

Priority order:

```text
correctness
security
containment
reproducibility
bounded concurrency
algorithmic efficiency
observability
then micro-optimization
```

Never weaken authorization, isolation, evidence integrity, or verifier independence for benchmark speed.

---

# 26. Benchmark Before Rewriting

If a component is considered too slow:

1. measure;
2. profile;
3. identify the real bottleneck;
4. establish a reproducible benchmark;
5. optimize;
6. compare before/after.

Do not rewrite Python into Rust merely because Rust is faster in theory.

Do not replace SQLite without benchmark evidence.

Do not write custom lock-free structures without demonstrated necessity.

---

# 27. Target Performance Characteristics

AROS should be designed to support eventually:

```text
multiple simultaneous campaigns
dozens of concurrent research experiments
multiple model streams
multiple sandbox instances
high-volume tool output
continuous evidence ingestion
parallel verifier runs
```

MVP does not have to demonstrate massive scale.

It must demonstrate that the architecture supports bounded concurrency without redesign.

---

# 28. Dependency Philosophy

Prefer:

```text
mature
widely used
maintained
permissively licensed
small dependency surfaces
```

Avoid adding frameworks merely because they accelerate early scaffolding.

Security-sensitive dependencies must receive additional scrutiny.

Record major dependency decisions.

---

# 29. Compile-Time and Runtime Safety

Rust trusted-core rules:

```text
#![forbid(unsafe_code)]
```

should be considered for crates that do not require unsafe functionality.

Where unsafe is required, isolate it into minimal audited modules/crates.

Avoid:

```text
unwrap()
expect()
panic!()
```

on externally controlled input or normal failure paths.

Use typed structured errors.

---

# 30. Serialization

Cross-process and security-sensitive serialization must be:

```text
typed
versioned
bounded
validated
```

Do not deserialize arbitrary unbounded structures from research workers.

Validate:

```text
message size
string length
collection size
artifact references
enum values
protocol versions
```

at trust boundaries.

---

# 31. Security Trust Hierarchy

Treat execution classes roughly as:

```text
async Rust task
        ↓
dedicated Rust thread/pool
        ↓
separate worker process
        ↓
rootless container
        ↓
gVisor-class sandbox
        ↓
microVM
```

Isolation should increase as workload trust decreases.

The SandboxProvider abstraction must allow movement down this hierarchy without redesigning the research architecture.

---

# 32. Future Migration Principle

AROS should progressively move stable, frequently repeated research operations from:

```text
generative reasoning
        ↓
Python ResearchSkill
        ↓
deterministic algorithm
        ↓
optimized Rust engine
```

when evidence demonstrates that the operation is understood sufficiently well.

This is an intentional architectural property.

The system should become more deterministic as its successful research methodology matures.

---

# 33. Final Technology Decision

For AROS v0.1, freeze:

```text
Primary systems language:
Rust

Async runtime:
Tokio

CPU parallelism:
Rayon + bounded dedicated worker pools

Research intelligence:
Python 3.14+

Research-worker concurrency:
asyncio

Cross-process communication:
typed IPC, preferably Protobuf over Unix Domain Socket

Persistent database:
SQLite

Active research graph:
in-memory Rust graph backed by SQLite

Artifact storage:
filesystem CAS

Hashing:
BLAKE3 internally + SHA-256 metadata where interoperability requires

Sandbox:
rootless OCI through SandboxProvider

External analyzers:
sandboxed tool adapters

Go:
not part of v0.1

C/C++:
external tools, targets and carefully isolated FFI only

Frontend:
post-MVP TypeScript/React or equivalent
```

This technology architecture is part of the AROS v0.1 source of truth.