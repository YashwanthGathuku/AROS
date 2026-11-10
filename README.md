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
- [`docs/research/session-2026-11-10.md`](docs/research/session-2026-11-10.md) — 2026-11-10 record: acceptance script, doctor probe, unwaived dycrpt stops, Numbat plan, provider page, and what is next

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

A measured run of this host on 2026-11-10 is in the table below. `scripts/acceptance.sh` exited 0 in 224.36s. `python3` is still the Microsoft Store alias and exits 9009. The script used `python` 3.14.8.

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

**Next work, in order.** The full record is
[`docs/research/session-2026-11-10.md`](docs/research/session-2026-11-10.md).

1. ~~AROS campaign loader~~ — `load_campaign_file` + `run_declared_campaign`
   are in `aros-core`. `aros campaign run --spec … --target …` is the CLI.
2. ~~Readable evidence report~~ — `evidence-report.html` is written for
   declared runs. It is not a dycrpt result.
3. ~~AROS-side dycrpt adapter~~ — `adapters/dycrpt-lib` calls `decrypt`.
4. ~~Acceptance script on this PC~~ — `scripts/acceptance.sh` exited 0 in
   224.36s. `python3` exits 9009. The script used `python` 3.14.8. Live OCI
   was not claimed because `AROS_REQUIRE_LIVE_OCI` was unset.
5. Live OCI acceptance was run with the machine reachable. Git bash
   `AROS_REQUIRE_LIVE_OCI=1 ./scripts/acceptance.sh` printed
   `LIVE OCI GATE FAILED: host_gateway_probe='failed'` and
   `ACCEPTANCE FAILED` (exit 1, captured log span 192.56s). A second
   doctor printed the same failure. The bridge gateway `10.89.1.1`
   answered ping. The probe was not changed. One earlier doctor had
   reported all five probes `proven` after two connection refusals. That
   report is a separate measurement.
6. Run a campaign whose toolchain the container can reproduce, inside
   `CampaignOciTarget::exec_generator`. Both unwaived dycrpt campaigns on
   pin `e4e200a` stopped before that call: `stable-x86_64-pc-windows-gnu`
   is not a Linux triple. `contained` is false. The original digest was
   unchanged. A waived skipped-key hold (`BOUNDED_OK`, level E2) is not
   that run and is not a vulnerability.

Do not mark either dycrpt campaign passing in `docs/BUILD_STATUS.md` until
a run of this engine against that pin has produced an evidence bundle.
The 2026-11-10 suite fetched the pinned dycrpt checkout during
`dycrpt_replay_adapter_calls_open_path_when_target_present` and that test
passed. That fetch is not a contained campaign result.

Details: [`campaign-loader/README.md`](campaign-loader/README.md).

## Measured on this Windows host (2026-11-10)

Branch `bounty-hunter` at `49b436d`, recorded in
[`docs/research/session-2026-11-10.md`](docs/research/session-2026-11-10.md).
rustc 1.96.0. Python 3.14.8.
`scripts/acceptance.sh` was run by Git bash with `AROS_REQUIRE_LIVE_OCI`
unset. The script exited 0 in 224.36s. `python3` exits 9009, so the script
used `python`. This table does not make v0.1 release-eligible. The earlier
workspace count of 230 was commit `8ce56ee`, before these tests existed.
Smoke and stress were not re-timed as exact one-test runs in this slice.
Both still passed inside the 149 `aros-core` tests. Their class budgets
remain 30s and 120s. That is not hour-scale coverage.

| Check | Result |
|---|---|
| `scripts/acceptance.sh` | exit 0, wall 224.36s. Live OCI not claimed |
| `cargo fmt --all -- --check` | passed inside that script |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | finished in 8.33s inside that script |
| `cargo test --workspace` | 237 passed, 0 failed, inside that script |
| `aros-core` lib inside that run | 149 passed, 0 failed, 76.93s |
| `aros-api` lib | 14 passed, 8.79s |
| `verifier_subprocess` | 3 passed, 0.96s |
| `aros-evidence` | 15 passed, 2.13s |
| `aros-ipc` | 5 passed, 1.97s |
| `aros-policy` | 22 passed, 0.11s |
| `aros-sandbox` | 8 passed, 0.42s |
| `aros-store` | 6 passed, 0.05s |
| `aros-types` | 15 passed, 0.15s |
| `aros` CLI, `arosd`, `aros-verifier` unit tests | 0 tests |
| doc-tests (eight crates) | 0 tests |
| `PYTHONPATH=python python -m pytest python -q` | 32 passed in 3.07s |
| `python -m ruff check python` | all checks passed |
| `python -m mypy python/aros_research` | no issues in 27 files |
| `aros campaign providers` | wrote `provider.html`; payload escaped; not a finding |
| unwaived dycrpt replay and skipped-key | `environment_mismatch`, `contained` false, digest unchanged |

One `aros doctor` while `podman-machine-default` was running reported
`live_oci_claimable` true, image `alpine`, and all five probes `proven`.
The same process also printed two connection refusals to `127.0.0.1:53209`.
A later inspect showed the machine stopped. The probe does not mean either
dycrpt campaign ran inside a container. Both unwaived runs stopped because
the pin's toolchain is `stable-x86_64-pc-windows-gnu`. `scripts/demo.sh` and
`scripts/foreign_vampi_smoke.sh` were not run. Grok, Bumblebee, and Numbat
were not started. No bounty program host was contacted.

Later the same day, on tree `0fcfad2`, Git bash ran `scripts/acceptance.sh`
with `AROS_REQUIRE_LIVE_OCI=1`. The captured log spans 192.56s. The script
printed `LIVE OCI GATE FAILED: host_gateway_probe='failed'` and
`ACCEPTANCE FAILED`, and exited 1. `machine_reachable` was true. The other
four packet probes were `proven`. A second `aros doctor` printed the same
host-gateway failure. On an `--internal` network the gateway was
`10.89.1.1`: ping exited 0, TCP 22 and TCP 80 exited 1, and there was no
default route. `ping 1.1.1.1` reported `Network unreachable`. The probe
requires the ping to be denied, so the dimension stays `failed`. Detail is
in [`docs/research/session-2026-11-10.md`](docs/research/session-2026-11-10.md).

What is next, in the order that still blocks a release. Detail and the
command output are in
[`docs/research/session-2026-11-10.md`](docs/research/session-2026-11-10.md).

1. `v0.1.0-mvp` stays blocked. Automatable acceptance passed. The script did not claim live OCI. The pinned dycrpt campaigns did not enter a container.
2. `AROS_REQUIRE_LIVE_OCI=1 ./scripts/acceptance.sh` was run and failed: `host_gateway_probe` is `failed` because gateway `10.89.1.1` answers ping. A repeat doctor matched that result. The probe stays as written. The contained generator stays blocked while `live_oci_claimable` is false.
3. A contained generator run for a toolchain the image can reproduce. The current dycrpt pin stops on `stable-x86_64-pc-windows-gnu`. The harness also needs cargo, which the default Python image and an internal network do not provide. Do not waive that check.
4. Hour-scale coverage and the other crush oracles, after a contained run of untrusted bytes. The 120-second class budget is not that run.
5. Each of the remaining 64 MST-wi relations only with a vulnerable fixture and a patched twin.
6. A host `numbat` binary can be tested against the loopback plan. The correlation id stays off argv. `aros campaign providers` already writes a static page. That page is not a live console.
7. `apply_failure_memory` may reorder a plan. Rust still authorizes. Rows that await green Rust CI stay in progress until that CI is observed.

Stay later, outside v0.1: gVisor, Firecracker, paid cloud inference as a requirement, a large historical corpus, a live web console, and public internet targets.

## License

Apache-2.0. See `LICENSE`.
