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
- [`docs/LOCAL_INSTALL_AND_FOREIGN_PROJECTS.md`](docs/LOCAL_INSTALL_AND_FOREIGN_PROJECTS.md) — local setup, foreign repositories, GitHub acquisition, and proposed operator UI
- [`docs/V0_1_FOREIGN_PROJECT_VALIDATION.md`](docs/V0_1_FOREIGN_PROJECT_VALIDATION.md) — executed/source-inspected validation record and operator handoff

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

A measured run of this host on 2026-11-10 is in the table below. `scripts/acceptance.sh` was not executed here: `python3` is the Microsoft Store alias and exits 9009, while `python` is 3.14.8.

Run a local demo against repository fixtures (mock provider, no paid API):

```bash
./scripts/demo.sh
```

## Campaign files (RedLab content layer)

[`campaign-loader/`](campaign-loader/) is **declarative campaign data**, not a
second runtime. RedLab names the portable campaign contract. **AROS is the
engine that reads it.** The dycrpt adapter lives in AROS
(`campaign-loader/adapters/dycrpt-lib`) and calls `decrypt`. Without a
`voicechat_crypto` checkout those campaigns still fail closed. A waived host
run is not E4 and not contained evidence.

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

The dycrpt adapter calls `VoiceChatCryptoEngine::decrypt` (receive/`open`)
from AROS, not from a file copied into dycrpt. An empty target still fails
closed. Required E4 is unmet on waived runs. Do not claim live contained
dycrpt evidence from this host.

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
3. ~~AROS-side dycrpt adapter~~ — `adapters/dycrpt-lib` calls `decrypt`.
4. Run `dycrpt-replay-resistance` and `dycrpt-skipped-key-dos` through AROS
   against the pinned revision **inside** a live contained generator
   (not `--operator-waive-containment`). A waived skipped-key run on pin
   `e4e200a` held: `BOUNDED_OK`, no `UNBOUNDED_DERIVATION`, level E2,
   replica agreed, `contained` false. That is not a vulnerability and not
   release evidence.

Do not mark either dycrpt campaign passing in `docs/BUILD_STATUS.md` until
a run of this engine against that pin has produced an evidence bundle.
The 2026-11-10 suite fetched the pinned dycrpt checkout during
`dycrpt_replay_adapter_calls_open_path_when_target_present` and that test
passed. That fetch is not a contained campaign result.

Details: [`campaign-loader/README.md`](campaign-loader/README.md).

## Measured on this Windows host (2026-11-10)

Branch `bounty-hunter` at `8ce56ee`. rustc 1.96.0. Python 3.14.8. These
commands ran after `cargo fmt --all` and after `#[allow(clippy::expect_used, clippy::unwrap_used)]`
on the test modules in `acquisition.rs`, `acquisition_exec.rs`,
`provider_output.rs`, and `target_profile.rs`. The crate lints were not
weakened. This table does not make v0.1 release-eligible.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 in 3.15s |
| `cargo test --workspace` | 230 passed, 0 failed, wall 200.31s |
| `aros-core` lib inside that run | 143 passed, 0 failed, 138.84s |
| `aros-api` lib | 14 passed, 7.51s |
| `verifier_subprocess` | 3 passed, 3.33s |
| `aros-evidence` | 15 passed, 3.24s |
| `aros-ipc` | 5 passed, 1.89s |
| `aros-policy` | 22 passed, 0.13s |
| `aros-sandbox` | 8 passed, 0.43s |
| `aros-store` | 5 passed, 0.05s |
| `aros-types` | 15 passed, 0.29s |
| `aros` CLI, `arosd`, `aros-verifier` unit tests | 0 tests |
| doc-tests (`aros-api`, `aros-core`, `aros-evidence`, `aros-ipc`, `aros-policy`, `aros-sandbox`, `aros-store`, `aros-types`) | 0 tests |
| smoke: `mutate_fuzz_finds_nul_crash_and_shrinks -- --exact` | 1 passed, harness 1.15s, wall 8.48s |
| stress: `crash_crusher_finds_nul_crash_and_shrinks -- --exact` | 1 passed, harness 1.50s, wall 1.87s |
| `python -m ruff check python` | all checks passed |
| `python -m mypy python/aros_research` | no issues in 27 files |
| `PYTHONPATH=python python -m pytest python -q` | 31 passed in 25.12s |
| `cargo run -q -p aros-cli -- doctor` | exit 0, `live_oci_claimable` false |

The smoke class budget is 30 seconds. The stress class budget is 120
seconds inside a 180-second wall. Both exact runs found the nul crash
immediately. They are not an hour-scale coverage run. `aros benchmark smoke`
prints `benchmark smoke: use fixtures + acceptance gate` and does not run
the fuzzer.

`aros doctor` on this host: Podman is installed, `machine_reachable` is
false, `podman info` failed, and all five packet probes are `indeterminate`
with `packet_probes_ran` false. `podman machine start` had already returned
success earlier the same day and the API socket was still refused.
Unwaived campaigns fail closed. `AROS_REQUIRE_LIVE_OCI` was not set.
`scripts/demo.sh` and `scripts/foreign_vampi_smoke.sh` were not run.
Grok, Bumblebee, and Numbat were not started. No bounty program host was
contacted. The dycrpt unit test did fetch `https://github.com/YashwanthGathuku/dycrpt`.

Still open after this measurement:

- `v0.1.0-mvp` stays blocked. Campaign-bound OCI execution and a Proven five-way Podman run are unfinished.
- Rows marked awaiting green Rust CI stay in progress. This local suite is not that CI run.
- Numbat collector, live provider argv correlation, and the provider screen.
- Hour-scale coverage, the other crush oracles, and 64 MST-wi relations that still lack a discriminating fixture and a patched twin.
- A thicker methodology card, a cross-campaign graph, free-form assumption mining, and the Python research loop as the full MVP scheduler.
- gVisor, Firecracker, paid cloud inference as a requirement, a large historical corpus, and a live web console stay later. Public internet targets stay outside v0.1.

## License

Apache-2.0. See `LICENSE`.
