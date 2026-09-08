# AROS

Autonomous Adversarial Research OS (temporary codename).

AROS is a locally runnable, model- and harness-independent platform for
**explicitly authorized** local and sandbox security research. It is not a
scanner, not a Kali wrapper, and not a chatbot that shells out to tools.

Authoritative specifications:

- [`docs/AROS_MVP_SPEC.md`](docs/AROS_MVP_SPEC.md) — what v0.1 must do
- [`docs/TECH_STACK.md`](docs/TECH_STACK.md) — runtime, process, and language ownership
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
- [`docs/BUILD_STATUS.md`](docs/BUILD_STATUS.md)

## Architecture

```text
aros (CLI) → arosd (trusted Rust) → typed Protobuf IPC → Python research worker
                                      ↓
                               rootless OCI sandbox
                                      ↓
                          local fixtures / authorized targets
```

Rust owns authorization, policy, sandboxing, brokering, evidence, and state.
Python owns replaceable research intelligence only. The LLM never authorizes.

## Quick start

```bash
# Linux / WSL recommended for sandbox containment
./scripts/bootstrap.sh
./scripts/doctor.sh
cargo test --workspace
./scripts/acceptance.sh
```

Windows host (unit tests of the trusted core; containment fail-closed without OCI):

```powershell
cargo test --workspace
python -m pytest python
```

Run a local demo against repository fixtures (mock provider, no paid API):

```bash
./scripts/demo.sh
```

## Campaign files (RedLab content layer)

[`campaign-loader/`](campaign-loader/) is **declarative campaign data**, not a
second runtime. RedLab names the portable campaign contract. **AROS is the
engine that reads it.** The shipped dycrpt campaigns still produce **zero
evidence** because their harnesses do not exist.

| File | What it is |
|---|---|
| [`campaign-loader/campaign.schema.json`](campaign-loader/campaign.schema.json) | JSON Schema 2020-12. Thirteen required fields: id, security class, historical pattern, surface, invariant, attacker capabilities, prerequisites, resource limits, generator, oracle, expected outcome, required evidence, severity rationale. |
| [`campaign-loader/dycrpt-replay-resistance.campaign.json`](campaign-loader/dycrpt-replay-resistance.campaign.json) | Integrity campaign against dycrpt `ReplayCache` / second `open()`. Pinned to [dycrpt@e4e200a](https://github.com/YashwanthGathuku/dycrpt). Expected: invariant holds. Oracle: `REPLAY_ACCEPTED` means the attack succeeded. |
| [`campaign-loader/dycrpt-skipped-key-dos.campaign.json`](campaign-loader/dycrpt-skipped-key-dos.campaign.json) | Availability campaign against `DEFAULT_MAX_SKIP`. Same pin. Oracle: `UNBOUNDED_DERIVATION` means the attack succeeded. |
| [`campaign-loader/roles.json`](campaign-loader/roles.json) | Ten roles as data. Attackers are separate from `independent-reproducer` and `remediation-agent`. |

What this directory **does not** contain, and must not grow: `runner/`,
`evidence/`, `policies/`, `oracles/`. Those already live in
`crates/aros-core`, `aros-sandbox`, `aros-policy`, `aros-evidence`, and the
verifier. Duplicating them would be a second engine.

The engine can **load** these files (`CampaignSpec`) and run
`aros campaign run --spec <file> --target <checkout>`. If the generator
corpus is missing, the run **fails closed** and records no verified finding.
HTTP lab fixtures still use `FixtureKind` (`Authz` / `Path` / `Deceptive`).
New targets should not add enum variants; they should add a campaign file.

Declared-campaign behaviour that is wired (still not dycrpt evidence):

- Unwaived runs execute the generator through `CampaignOciTarget::exec_generator`
  and fail closed without a reachable rootless OCI runtime. Waived host runs
  are not contained evidence.
- Achieved evidence is checked against `required_evidence`; a short ladder
  becomes `InsufficientEvidence`, not `Verified`.
- Harness bytes are snapshotted into CAS; the digest is in the bundle, ledger,
  and HTML report.
- Optional `structural_control` runs a known-good arm (must hold) and a mutant
  arm (must break). Optional `surfaces` run per-surface generators; any break
  breaks the campaign.
- Unreproducible `rust-toolchain.toml` pins are `environment_mismatch`, not a
  security result.
- A readable `evidence-report.html` is written under the work root.

Do not copy experiment code into each target repo. Campaigns plug an AROS
catalog harness (`generator.harness` + `bind`) from
`campaign-loader/harnesses/`. HTTP/API and CLI **class** campaigns live in
`campaign-loader/classes/`. Map and gate:

```text
aros campaign map --target path/to/app --out data/work/surface.json
aros campaign gate --target path/to/app --pack http
```

Gate fails if a class is Verified or if containment cannot be shown. The
target tree stays unmodified.

The shipped dycrpt campaigns still produce zero evidence: there is not yet
an AROS-side adapter that calls dycrpt's real `open()` path. Loading them
today fails closed. That is correct. Do not claim live contained dycrpt
evidence from this host.

**Decisions recorded here (do not silently reverse):**

1. No Go and no rewrite of AROS into a Python monolith. Trusted core stays
   Rust; research intelligence stays Python. See ADR-0001 and
   `docs/TECH_STACK.md`.
2. RedLab is the spec/content layer **over** AROS, not a clean-room
   standalone runtime.

**Next work, in order, to first real evidence:**

1. ~~AROS campaign loader~~ — `load_campaign_file` + `run_declared_campaign`
   are in `aros-core`. `aros campaign run --spec … --target …` is the CLI.
2. ~~Readable evidence report~~ — `evidence-report.html` is written for
   declared runs. It is not a dycrpt result.
3. AROS-side dycrpt adapter in `campaign-loader/adapters/` — not a file in
   dycrpt. Same experiment: session, deliver+open, replay, print tokens.
4. Run `dycrpt-replay-resistance` through AROS against the pinned revision
   **inside** a live contained generator (not `--operator-waive-containment`).

Do not mark either dycrpt campaign passing in `docs/BUILD_STATUS.md` until
a run of this engine against that pin has produced an evidence bundle.

Details: [`campaign-loader/README.md`](campaign-loader/README.md).

## License

Apache-2.0. See `LICENSE`.
