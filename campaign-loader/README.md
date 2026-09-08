# RedLab

RedLab is a **portable adversarial-testing standard**: security campaigns written as
data, dropped into any project, executed under policy in a sandbox, and answered with
an evidence bundle you can defend.

RedLab is the **content layer**. It does not run anything itself. The runtime that
reads a RedLab campaign, executes its generator against the pinned target inside a
contained sandbox, applies the oracle, and produces the E0-E7 evidence bundle is
**AROS** (this repository's engine). RedLab standardizes *what to test and how to
believe the result*; AROS is *how it runs*.

## Why this is a spec, not a second engine

The execution machinery a campaign needs already exists in AROS and is tested:

| Concern | Lives in |
|---|---|
| running a campaign under policy | `crates/aros-core` (engine) |
| sandbox / containment | `crates/aros-sandbox` |
| allowlists, path scope, argv guards | `crates/aros-policy` |
| oracle evaluation | engine oracle path |
| evidence ladder E0-E7, CAS, tamper-evident ledger | `crates/aros-evidence` |
| independent reproduction, patched-twin re-attack | verifier + engine |

Re-implementing those under `redlab/runner`, `redlab/evidence`, `redlab/policies`
would duplicate a working, tested system. RedLab deliberately contains **none** of
them. It contains the two things AROS does **not** yet have as data:

- **`campaign.schema.json`** - the declarative campaign contract.
- **`campaigns/` and `agents/roles.json`** - campaigns and attacker roles as data,
  portable across every project, replacing AROS's hardcoded `FixtureKind` enum.

That enum is the "the loop is not a loop" weakness flagged in the AROS audits: adding
a target class today means editing Rust and recompiling. RedLab campaigns retire it -
a new campaign is a new file, not a new enum variant.

## Layout

Shipped in this repository as `campaign-loader/` (not a second engine tree):

```
campaign-loader/
  campaign.schema.json                       # JSON Schema 2020-12, 13 required fields
  dycrpt-replay-resistance.campaign.json     # ReplayCache / second-open must fail
  dycrpt-skipped-key-dos.campaign.json       # DEFAULT_MAX_SKIP bound
  roles.json                                 # 10 attacker/verifier/remediation roles
  README.md
```

There is no `runner/`, `evidence/`, `policies/`, or `oracles/` directory: those
are AROS. The `oracle` and `resource_limits` a campaign needs are fields *inside* each
campaign file, to be enforced by the AROS runtime once a loader exists.

Do not create a parallel `redlab/runner` (or similar) in this repo. That would
duplicate a tested control plane.

## A campaign in one sentence

A campaign is a **falsifiable security claim** (`invariant`) plus everything needed to
attack it (`surface`, `attacker_capabilities`, `generator`), everything needed to judge
the result (`oracle` with a `negative_control`), and everything needed to believe it
(`required_evidence`). `expected_outcome` records what we predict today; divergence from
it is the finding.

## Status - read this before trusting anything here

This layer is **declarative intent plus a loader, not dycrpt evidence.** As of this
commit:

- The schema validates and both campaigns validate against it (`CampaignSpec`).
- AROS can load a campaign file and run `aros campaign run --spec FILE --target DIR`.
- If the generator corpus is missing, the engine **fails closed** and does not mint a
  verified finding. That is the current result for both dycrpt campaigns.
- Unwaived declared runs require `CampaignOciTarget::exec_generator`. Without a
  reachable rootless OCI runtime they fail closed. `--operator-waive-containment`
  is host execution and is not contained evidence.
- `required_evidence` is enforced against the achieved level. Optional
  `surfaces` and `structural_control` are in the schema. Harness bytes are
  CAS-addressed. Unreproducible toolchain pins are `environment_mismatch`.
  `evidence-report.html` is written under the work root.
- **Not yet done:** dycrpt still has no AROS-side adapter that actually calls
  `VoiceChatCryptoEngine::open`. Catalog runners (`stdout-tokens`, `cargo-test`,
  `http-probe`) exist so a target repo is not the place to copy experiment
  code. Until a dycrpt adapter in `campaign-loader/adapters/` calls the real
  API, those two campaigns produce zero evidence. Do not treat a waived local
  Python fixture as a dycrpt result.

Do not mark any campaign "passing" in any status document until
`cargo build --workspace --all-targets` is green in the commit that claims it and the
run has produced an actual evidence bundle. This is the same discipline the AROS audits
exist to enforce.

## Build order to first real result

1. ~~AROS engine campaign loader~~ — present: `load_campaign_file` /
   `run_declared_campaign`. HTTP lab fixtures still use `FixtureKind`.
2. ~~HTML evidence report~~ — written for declared runs; not a dycrpt result.
3. AROS-side dycrpt adapter under `campaign-loader/adapters/` (not a file in
   dycrpt): establish a session, deliver+open, replay, print `OPEN_OK` then
   `REPLAY_ACCEPTED` or `REPLAY_REJECTED`. Bind it from the campaign JSON.
4. Run `dycrpt-replay-resistance` through AROS against pinned dycrpt **inside**
   a live contained generator.
