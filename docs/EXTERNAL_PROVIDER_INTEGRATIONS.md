# External Provider Integration — Grok Build, Bumblebee, Numbat

Status: source-integrated provider contracts; runtime execution remains gated by AROS policy/sandbox and host availability.

## Why three providers have three different roles

AROS deliberately does not treat these projects as interchangeable plugins.

| Provider | AROS role | What AROS accepts | What AROS never delegates |
|---|---|---|---|
| Grok Build | Research harness | hypotheses, proposed experiments, research observations | authorization, policy, evidence promotion, verification |
| Bumblebee | Passive inventory | read-only package/tool/MCP inventory NDJSON and exposure leads | vulnerability verdicts, execution authority |
| Numbat | Observability | normalized agent activity/detection telemetry | AROS policy enforcement or evidence verification |

All provider output is untrusted input.

## Implemented Rust contract

`crates/aros-core/src/integrations.rs` owns the provider-neutral boundary:

- `IntegrationRole`
- `IntegrationInvocation`
- `ForeignProjectIntegrations`
- `foreign_project_integrations(root)`

Every invocation carries explicit truth fields:

- `read_only`
- `may_authorize_actions`
- `may_verify_findings`
- `output_semantics`

Tests assert that all three providers have `may_authorize_actions=false` and
`may_verify_findings=false`.

The foreign-project onboarding result now contains an `integrations` object
scoped to the immutable snapshot root. Provider plans are therefore generated
*after* GitHub acquisition authority has been removed.

## Grok Build

AROS plans Grok Build as a replaceable research harness using its documented
headless CLI shape:

```text
grok
  --cwd <immutable-target>
  --output-format json
  --no-auto-update
  --max-turns 8
  --prompt-file <AROS-generated prompt>
```

The placeholder prompt path is intentional at this stage: AROS must generate
the research prompt from the admitted ResearchPlan and must not let target
README/source text become privileged instructions.

Before execution, the runner must:

1. materialize a bounded AROS research prompt outside the target;
2. derive tool permissions from the AuthorizationManifest;
3. run Grok inside the research-worker containment tier;
4. route requested actions back through AROS policy/broker;
5. persist returned research output as untrusted research provenance;
6. never convert Grok confidence into E0–E7 evidence.

## Bumblebee

AROS plans Bumblebee against the immutable project snapshot:

```text
bumblebee scan --profile project --root <immutable-target>
```

Bumblebee is used because its project scan is read-only and produces structured
inventory records. AROS should parse the NDJSON into inventory facts with
provider/version provenance.

An exposure match is a research lead. It is not a verified AROS vulnerability.

Future execution requirements:

- run in a no-egress inventory sandbox;
- capture stdout/stderr and binary version;
- content-address the raw NDJSON;
- validate each line before graph ingestion;
- add inventory facts to TargetReality with `Observed` provenance only when
  the record is tied to bytes in the immutable target;
- treat catalog exposure findings as leads requiring normal AROS falsification.

## Numbat

AROS plans Numbat as monitor-only observability:

```text
numbat collect --addr 127.0.0.1:4318
```

The collector stays loopback-only. AROS may feed supported OTLP/HTTP activity
from research harnesses into Numbat and ingest its NDJSON records into the
telemetry stream.

Even though Numbat itself supports optional blocking on some agent hooks, AROS
v0.1 does not delegate enforcement to it. AROS policy remains deterministic and
authoritative. A Numbat finding is telemetry/detection evidence, not proof that
the target is vulnerable.

## Optional binary discovery

`detect_optional_engines()` now recognizes:

```text
grok       → research_harness
bumblebee  → passive_inventory
numbat     → observability
```

Absence is not an error and is never represented as presence. Native AROS
profiling/planning continues without any of these tools.

## Foreign-project lifecycle

```text
GitHub acquisition
       ↓
immutable TargetSnapshot
       ↓
TargetProfile ──────────────┐
       ↓                    │
SurfaceMap                  ├─ Bumblebee passive inventory
       ↓                    │
ResearchPlan                └─ inventory facts / leads
       ↓
Grok Build or native research harness
       │
       ├── proposed action ──→ AROS Policy/Broker ──→ sandbox
       │
       └── activity ─────────→ Numbat observability
                                      │
                                      ↓
                                telemetry only
       ↓
AROS observations/evidence
       ↓
independent verifier / THEUSTAD
       ↓
E0–E7
```

## Runtime work still required

The current batch intentionally stops before pretending external binaries ran.

Remaining runtime integration:

1. AROS-generated Grok prompt contract and response parser.
2. Sandboxed provider runner with process/time/output budgets.
3. Bumblebee NDJSON schema adapter and TargetReality ingestion.
4. Numbat local collector lifecycle + NDJSON telemetry adapter.
5. AROS event correlation IDs propagated into provider activity.
6. CAS storage for provider raw outputs and version/provenance.
7. UI live provider status and telemetry timeline.
8. Host tests with real pinned provider versions.

These are runtime tasks, not reasons to weaken the trusted boundary.
