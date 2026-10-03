# AROS Local Installation & Foreign Project Guide

> **v0.1 release-candidate guide.** AROS is for explicitly authorized local/sandbox security research. v0.1 does not autonomously attack arbitrary Internet systems.

This is the operator path from a clean machine to an AROS research campaign.

## 1. Recommended local environment

For Windows, use **WSL2** for AROS and keep research targets inside the Linux filesystem rather than under `/mnt/c`. Native Linux is also supported. AROS's trusted/control plane is Rust; the replaceable research plane is Python; rootless OCI (preferably Podman) provides the containment boundary.

Required:

- Git
- Rust **1.85+** and Cargo
- Python 3.11+ (project currently also works toward newer Python versions)
- a Python virtual environment
- rootless Podman for unwaived contained campaigns

Useful:

- `curl`, `jq`, compiler/build tools required by the target
- Docker rootless only when it can satisfy the same controls; never silently downgrade containment

### Ubuntu / WSL2 prerequisites

```bash
sudo apt update
sudo apt install -y git curl build-essential python3 python3-venv python3-pip podman

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install 1.85
rustup default 1.85
```

Confirm:

```bash
git --version
rustc --version
cargo --version
python3 --version
podman --version
podman info
```

## 2. Install AROS from source

Until v0.1 is tagged, use the release branch:

```bash
git clone https://github.com/YashwanthGathuku/AROS.git
cd AROS
git switch release/v0.1.0

./scripts/bootstrap.sh
./scripts/doctor.sh
cargo test --workspace
./scripts/acceptance.sh
```

For development, install the CLI locally:

```bash
cargo install --path crates/aros-cli --locked
aros --help
```

If you do not want to install the binary, replace `aros` below with:

```bash
cargo run -p aros-cli --
```

Example:

```bash
cargo run -p aros-cli -- target profile /path/to/project
```

## 3. Mental model

A foreign project enters AROS through a staged pipeline:

```text
authorized checkout
    ↓
TargetProfile
    ↓
surface / interface discovery
    ↓
capability + applicability model
    ↓
research plan
    ↓
deterministic authorization/policy
    ↓
campaign-bound isolated execution
    ↓
observations
    ↓
falsification + independent reproduction
    ↓
E0 → E7 evidence
    ↓
report + regression + learning
```

Profiling, README text, source comments, OpenAPI descriptions and model output are **not vulnerability evidence**. They may motivate experiments only.

## 4. Use AROS with an existing local project

Keep the target outside the AROS checkout:

```text
~/research/
├── AROS/
└── targets/
    └── my-project/
```

Profile it:

```bash
cd ~/research/AROS
aros target profile ~/research/targets/my-project
```

The JSON profile inventories facts such as:

- Rust/Python/Node/Go/Java ecosystem markers;
- manifests;
- source extensions;
- likely entry points;
- tests;
- Docker/Compose;
- CI;
- OpenAPI/Swagger specifications;
- planning capability hints.

Map an HTTP/API target:

```bash
aros campaign map \
  --target ~/research/targets/my-project \
  --out data/work/my-project-surface.json
```

Create a deterministic plan:

```bash
aros campaign plan \
  --target ~/research/targets/my-project \
  --work data/work/my-project-plan \
  --pack all
```

Inspect before execution:

```bash
cat data/work/my-project-surface.json
cat data/work/my-project-plan/plan.json
```

For declared RedLab campaigns:

```bash
aros campaign run \
  --spec campaign-loader/<campaign>.campaign.json \
  --target ~/research/targets/my-project \
  --work data/work/my-project-run
```

Do not use `--operator-waive-containment` for release evidence. A waived run is a development aid, not contained E4 evidence.

## 5. Use a GitHub repository

### Public repository — recommended v0.1 path

The safest and simplest v0.1 design is:

```text
GitHub URL
   ↓
trusted acquisition step
   ↓
pinned local checkout
   ↓
record commit + tree identity
   ↓
network disabled
   ↓
AROS research
```

Today the reproducible manual form is:

```bash
mkdir -p ~/research/targets
cd ~/research/targets

git clone https://github.com/OWNER/REPO.git
cd REPO
git rev-parse HEAD
git status --porcelain
```

Then profile the local checkout:

```bash
cd ~/research/AROS
aros target profile ~/research/targets/REPO
```

AROS research execution should not need GitHub credentials or public Internet access after acquisition.

### Why not give the research agent GitHub access?

A GitHub connector/MCP is useful for **acquisition and metadata**, but it should not become the research sandbox's authority boundary. The research worker must not receive a broad GitHub token.

For private repositories, use a trusted host-side acquisition component or GitHub App with least privilege:

```text
UI / CLI
   │
   │ GitHub URL
   ▼
Repository Acquisition Service     ← trusted plane
   │
   ├─ validate github.com URL
   ├─ verify authorization
   ├─ resolve owner/repo/ref
   ├─ acquire with read-only credentials
   ├─ record commit SHA
   ├─ snapshot source
   └─ discard/restrict credentials
   │
   ▼
immutable local target snapshot
   │
   └──────────► AROS campaign
                 (no GitHub token)
```

This keeps credentials out of the Python research plane and attack containers.

## 6. GitHub URL UX proposed for AROS

A high-value v0.1.x/v0.2 onboarding command is:

```bash
aros project add https://github.com/OWNER/REPO
```

Optional:

```bash
aros project add https://github.com/OWNER/REPO \
  --ref <branch-tag-or-sha> \
  --visibility white
```

Expected trusted workflow:

1. Parse and validate URL.
2. Ask for/verify explicit authorization.
3. Resolve repository and requested ref.
4. Clone/download in a **builder/acquisition environment**, not the attack environment.
5. Resolve immutable commit SHA.
6. Compute source-tree/lockfile digests.
7. Store `TargetSnapshot`.
8. Run `TargetProfile`.
9. Detect build/test/container/API surfaces.
10. Present the proposed research plan.
11. Require policy admission.
12. Build immutable target image where applicable.
13. Remove external network access.
14. Start campaign.

For a private repository, authentication should be supplied to the trusted acquisition service by a GitHub App/device/user credential flow. Never put a PAT in:

- command-line history;
- campaign JSON;
- Python prompts;
- target environment;
- target container;
- worker container;
- evidence bundles.

## 7. VAmPI foreign-project validation

AROS includes:

```bash
bash scripts/foreign_vampi_smoke.sh
```

This uses the independent `erev0s/VAmPI` project as an onboarding test.

It records:

```text
data/foreign-smoke/aros/
├── vampi.commit
├── profile.json
├── surface.json
├── plan.json
└── plan/
```

The smoke test proves only deterministic onboarding/planning. It does **not** by itself prove a vulnerability, independent reproduction, or OCI containment.

See `docs/V0_1_FOREIGN_PROJECT_VALIDATION.md` for the full evidence/pending-work record.

## 8. What a good UI should expose

The UI should hide orchestration complexity without hiding evidence quality.

### Project screen

```text
┌──────────────────────────────────────────────────────────────┐
│ AROS                                              ● Local    │
├──────────────┬───────────────────────────────────────────────┤
│ Projects     │  New Research Project                         │
│ Campaigns    │                                               │
│ Findings     │  [ GitHub URL                              ] │
│ Evidence     │  or [ Select local folder ]                  │
│ Activity     │                                               │
│ Settings     │  Visibility   ○ White  ○ Gray  ○ Black       │
│              │                                               │
│              │  [ Analyze Project ]                          │
└──────────────┴───────────────────────────────────────────────┘
```

### Analysis screen

```text
VAmPI / <commit>
──────────────────────────────────────────────────────────────
Profile       Surface       Plan       Execute       Evidence
   ✓             ✓            ●            ○             ○

Detected
 Python    Web/API    Docker    Compose    OpenAPI

Target model
  12 routes       1 API specification
  1 entry point   containerizable
  tests detected

Applicable research
  ✓ authorization-boundary research
  ✓ authentication experiments
  ✓ representation/HTTP differential tests
  ? filesystem/path class — insufficient evidence

Blocked
  ✕ public Internet egress
  ✕ host filesystem
  ✕ host gateway

                    [ Review Plan ] [ Start Contained Research ]
```

### Campaign screen

Show a lifecycle, not a chatbot:

```text
UNDERSTAND ✓
MODEL      ✓
HYPOTHESIZE ✓
EXPERIMENT ███████░░
VERIFY     ○
MINIMIZE   ○
REMEDIATE  ○
REATTACK   ○
REGRESSION ○
```

Every action should answer:

- Why is AROS doing this?
- Which target fact justified it?
- Which authorization permits it?
- Where is it executing?
- What evidence resulted?
- What would falsify the hypothesis?

### Findings screen

Never lead with an LLM confidence percentage.

Prefer:

```text
Authorization boundary violation                 VERIFIED E4
/users/v1/{username}

Observed        ✓
Reproduced      ✓ independent target
Minimized       ○
Patched twin    ○
Regression      ○

[ Evidence ] [ Reproduction ] [ Timeline ] [ Provenance ]
```

Use explicit states such as `HYPOTHESIZED`, `SUPPORTED`, `VERIFIED`,
`REFUTED`, `INSUFFICIENT_EVIDENCE`, and `POLICY_BLOCKED`.

## 9. Proposed local UI architecture

Do not put policy enforcement in the frontend.

```text
Browser UI
 localhost only
      │
      ▼
aros-api / arosd (Rust)
      │
      ├── Project/Target API
      ├── Campaign API
      ├── Evidence API
      ├── SSE event stream
      └── GitHub acquisition endpoint (trusted)
      │
      ├────────► Policy / Broker / Evidence / Store
      │
      ├────────► Python research worker over authenticated UDS
      │
      └────────► Rootless OCI sandbox
```

Recommended UI implementation when started:

- React + TypeScript + Vite for the local web interface.
- Serve/bind to loopback by default.
- Rust API remains authoritative.
- SSE for campaign progress/events.
- No direct browser → research-worker connection.
- No GitHub token in browser persistence/localStorage.
- No raw host shell in the UI.
- Evidence views render persisted artifacts from the Rust evidence layer.

The UI is an operator/control surface, **not a security boundary**.

## 10. v0.1 truth boundary

Do not call AROS v0.1 complete until:

- release branch compiles and all required CI passes;
- foreign-target profiling is exercised by the Rust binary;
- capability-driven planning no longer requires AROS fixture filenames for normal onboarding;
- at least one independent foreign project completes the intended lifecycle;
- real campaign-bound OCI containment passes the five network invariants;
- independent reproduction is demonstrated;
- evidence/provenance is persisted;
- the original target remains unchanged;
- README/BUILD_STATUS match observed evidence.

Anything not demonstrated must remain `IN PROGRESS`, `BLOCKED`, or `DEFERRED`.


## 11. Implemented local operator UI (release branch)

The release branch now contains an initial evidence-first UI at `ui/index.html`, served directly by the trusted Rust daemon at:

```text
http://127.0.0.1:7432/
```

Start it with a strong local bearer token:

```bash
export AROS_DAEMON_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
cargo run -p aros-api
```

Then open `http://127.0.0.1:7432/`.

The first UI slice implements:

- GitHub repository URL intake;
- optional ref input;
- visibility selection;
- authenticated call to `POST /v1/projects/github/plan`;
- display of the exact trusted acquisition plan;
- explicit trust-boundary presentation;
- research/evidence lifecycle presentation.

The token is requested by the UI and stored in `sessionStorage` for the current tab only. It is not persisted in localStorage and is not sent to a target or research worker.

The daemon also exposes:

```text
POST /v1/projects/github/plan
POST /v1/projects/profile
```

Both require the existing daemon bearer token.

### Current GitHub acquisition status

Implemented now:

```text
GitHub URL
   ↓
strict github.com parser
   ↓
credential/query/fragment rejection
   ↓
owner/repository validation
   ↓
optional ref validation
   ↓
shell-free git argv AcquisitionPlan
```

Not yet implemented:

```text
AcquisitionPlan
   ↓
policy/broker-authorized git execution
   ↓
resolved immutable commit SHA
   ↓
tree/lockfile digests
   ↓
persisted TargetSnapshot
   ↓
automatic TargetProfile
```

This separation is intentional. Network/process execution must go through deterministic authorization rather than allowing an HTTP request from the UI to spawn Git directly.

### CLI acquisition-plan preview

```bash
aros project plan-github https://github.com/erev0s/VAmPI --ref master
```

This prints the canonical repository identity, destination, requested ref and exact `git argv[]` that the future brokered acquisition step will execute. It does not execute Git.


## 12. Implemented trusted acquisition → research-plan transaction

The release branch now implements the following executable separation:

```text
AcquisitionPlan
   ↓
explicit AcquisitionAuthorization
   ↓
bounded Git executor (no shell, github.com HTTPS only)
   ↓
checkout + acquisition receipt
   ↓  network_authority_revoked=true
immutable .git-free copy
   ↓
TargetSnapshot
   ├─ resolved acquisition commit SHA
   ├─ source-tree BLAKE3 digest
   └─ dependency lockfile hashes
   ↓
TargetProfile
   ↓
SurfaceMap
   ↓
capability-aware HTN facts
   ↓
ResearchPlan
```

### CLI

Preview acquisition:

```bash
aros project plan-github https://github.com/erev0s/VAmPI --ref master
```

Execute the narrowly authorized acquisition:

```bash
aros project acquire-github https://github.com/erev0s/VAmPI \
  --ref master \
  --destination-root data/targets \
  --authorize-github-read
```

The explicit `--authorize-github-read` flag is required. Without it acquisition fails closed.

Then convert the checkout into the research target:

```bash
aros project onboard data/targets/erev0s--VAmPI \
  --snapshots-root data/snapshots \
  --work data/onboarding \
  --pack all
```

The onboarding result includes the immutable target path, exact snapshot, profile, surface and research plan. Research uses the immutable path rather than the Git checkout.

### API / UI

The local authenticated API now has:

```text
POST /v1/projects/github/plan
POST /v1/projects/github/acquire
POST /v1/projects/onboard
POST /v1/projects/profile
```

The UI connects these as three explicit operator steps:

1. **Inspect** — validates URL/ref and shows acquisition plan.
2. **Authorize read & acquire** — grants the narrow temporary GitHub-read action and executes bounded Git acquisition.
3. **Build research snapshot** — removes Git/network authority, creates immutable source, snapshots, profiles, maps and plans.

### Security properties

- no shell is used for Git execution;
- only validated `https://github.com/OWNER/REPO` repository URLs are accepted;
- credentials in repository URLs are rejected;
- Git prompts are disabled;
- acquisition has a hard wall-clock timeout;
- destination must remain beneath the authorized acquisition root;
- existing destination is not overwritten;
- symlinks are rejected when producing the exact research snapshot;
- `.git`, build output, `node_modules`, and Python cache directories are excluded from the immutable research copy;
- the research snapshot receives the resolved source commit but contains no `.git` directory;
- dependency lockfiles are content-hashed;
- the onboarding result explicitly states that network authority is not retained.

### Remaining host verification

These source paths still require the normal Rust test/Clippy run on a host with Rust installed. The assistant environment used to author this batch did not contain Cargo/Rust and therefore this document must not be interpreted as a runtime-pass claim.
