# AROS v0.1 Build Status

Persistent execution ledger. Status values: `DONE` | `IN PROGRESS` | `BLOCKED` | `NOT STARTED` | `POST-MVP`.

A `DONE` item must cite behavior that the code actually executes. A simulated stand-in, an unexecuted generated file, a declared type, or a capability probe is not accepted as evidence for a stronger runtime claim.

Last updated: 2026-11-03 — on branch `bounty-hunter`, a program scope file accepts a local tree or a loopback asset, and `write_bounty_report` emits an unsent draft. The draft is eligible only for a verified independent reproduction at E4 or higher. `submitted` stays false. `release/v0.1.0` stays at `da29633` (provider raw bytes and Numbat NDJSON). Unwaived contained execution is still fail-closed without a Proven five-way OCI runtime. `v0.1.0-mvp` stays blocked. Live company hosts, the remaining hunter classes, and platform submission are not done.

## Release posture

**`v0.1.0-mvp` is BLOCKED.** The source branch now refuses to equate “this host can create an isolated Podman network” with “this campaign executed inside that network.” Campaign-bound OCI target execution remains unfinished and therefore containment-required host campaigns fail closed. Do not tag until the acceptance gate and the host-specific campaign-bound isolation proof both pass.

## Specifications and decisions

| Item | Status | Evidence / limitation |
|---|---|---|
| `docs/AROS_MVP_SPEC.md` | DONE | Source-of-truth specification exists. Implementation drift is tracked below. |
| Rust/Python trust split | IN PROGRESS | UDS + isolated rootless worker launcher implemented; a host worker exists only behind an explicit development waiver. Target/broker campaign execution is not yet bound to OCI. |
| Protobuf UDS IPC | IN PROGRESS | Unix/WSL UDS is implemented; TCP remains explicit test/development transport. Containerized-worker CI/host proof is still required. |
| SQLite + petgraph choice | DONE | Libraries are in use. One declared campaign's nodes and edges persist and reload (`9456fb3`). A graph that spans campaigns is still open. Telemetry events persist as their own record kind and can be dropped at the cap. A Numbat collector is still open. The anomaly notebook is a separate record. See the graph table below. |
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
| Independent verifier E4 | IN PROGRESS | Fixture HTTP path still uses the dedicated verifier process. Declared campaigns copy the tree and re-run the catalog generator; matching oracle + unchanged digest earns `independent_reproduced`. Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture` (E4), `independent_hold_satisfies_required_e4_without_a_finding`. |
| Rootless OCI isolation measurement | IN PROGRESS | Five tri-state dimensions, fresh measurement, tool preflight, transport-level reachability probes. This proves isolation capability only. |
| Campaign-bound OCI execution | IN PROGRESS | HTTP fixtures still require `server.py` via `CampaignOciTarget::start`. Declared campaigns run `CampaignOciTarget::exec_generator` (no `server.py`) and fail closed without reachable Podman. Live contained-generator evidence is **not** claimed on this host. |
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
| E4 independent reproduction | DONE for declared catalog runs | Replica tree + second generator/oracle. Fixture HTTP verifier process remains the HTTP-lab path. |
| E5 minimized reproduction | DONE for shrink-capable generators | `mutate-fuzz` emits `SHRINK_*` + hex; engine CAS-addresses `minimized.bin` and sets E5. E4 is a replica re-run, not implied by E5. Tests: `mutate_fuzz_finds_nul_crash_and_shrinks`, `mutate_fuzz_independent_rerun_satisfies_required_e4`. |
| E6 counterfactual differential | DONE for declared catalog + twin | `CampaignEngine::with_twin` / `aros campaign run --twin`. Original must break, replica E4 match, twin copy must hold, original and operator twin digests unchanged. No twin or a still-vulnerable twin stays at E4. A twin without a derivable related variant stays at E6 (does not invent E7). Fixture HTTP lab still has its own twin path. Tests: `http_unauth_patched_twin_stays_at_e6_without_a_variant`, `required_e6_without_twin_is_insufficient`, `vulnerable_twin_does_not_earn_e6`. |
| E7 variant + regression | DONE for declared catalog + twin | Related variant must **break the original replica** and **hold on the twin copy**. A generated `e7-regression/regression_test.py` is executed against the twin copy (not written into original or operator twin) and CAS-addressed. State `RegressionProtected`. HTTP variants: drop cookie, or `../` ↔ `..%2F`. No derivable variant stays at E6. Fixture HTTP lab still has its own E7 path. Tests: `http_idor_patched_twin_earns_e7`, `http_path_patched_twin_earns_e7`, `required_e7_without_twin_is_insufficient`. |
| Deceptive/negative control | IN PROGRESS | Generic invariant outcome rejects the deceptive fixture; no `kind == Deceptive` success/failure shortcut. Awaiting CI. |
| ResearchCard | DONE in development lifecycle | Persisted learning record. |
| ResearchFailureCard / failure memory | DONE as durable records | Unknown harness → `TOOL_GAP` in SQLite `failure_card`. Eval miss of a known PoC → `failure-cards.jsonl`. Test: `unknown_harness_records_a_failure_card`. |

## Graph and research memory

| Item | Status | Evidence / limitation |
|---|---|---|
| In-memory typed graph | DONE | `ActiveGraph` supports nodes and edges. |
| Persisted graph nodes/edges | DONE for declared catalog runs and the fixture HTTP path | Declared runs write hypothesis, experiment, observation, and a conclusion node. A second `Store::open` reloads them. Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture`, `http_idor_class_holds_on_patched_authz_fixture`. |
| Causal/epistemic edges through the declared lifecycle | DONE for that chain | Edges are `tested-by`, `observed`, then `supports` (verified break), `falsifies` (hold), or `inconclusive`. Replica adds `reproduced`. A holding twin adds `absent-on`. An accepted `http-idor` oracle line adds `assumption` → `motivates` → hypothesis. The assumption stays `Hypothesized`. A verified finding does not promote the file's text. Not a cross-campaign graph. Tests: `http_idor_patched_twin_earns_e7` reloads `absent-on`; `http_idor_class_verifies_break_on_vulnerable_authz_fixture` reloads `motivates`. |
| Anomaly notebook | DONE as a non-finding record | `Anomaly` rows persist in SQLite (`kind=anomaly`) and `work_root/anomalies.jsonl`. The ledger event is `AnomalyRecorded`. Status is `open`, `revisited`, or `dismissed`. `verified` and evidence levels are rejected. `revisit_anomalies` returns open notes whose component, hypothesis id, or historical pattern equals a later cue. A substring does not match, and an empty cue selects nothing. A `crash-crusher` run that prints `COVERAGE_ENGINE absent` stores that observation without changing the crash finding. Tests: `notebook_reloads_and_is_not_a_finding`, `verdict_status_and_empty_observation_are_rejected`, `open_anomaly_is_revisited_only_on_an_exact_cue`, `crash_crusher_finds_nul_crash_and_shrinks`. |
| Telemetry stream | DONE as an allowlisted record | `TelemetryEvent` rows persist in SQLite (`kind=telemetry`) and, when a work root is passed, `work_root/telemetry.jsonl`. Names are the 23 spec names. Any other name is rejected. Payload is at most 1024 characters. After 4096 retained events, further events increment a drop counter and are not stored. Dropping telemetry does not delete an `evidence` record. Stored JSON has no `evidence_level`, `verified`, or `finding_id`. `to_numbat_record` emits `record_type=event`, `schema=aros-telemetry/1`, and `enforcement=false`. It does not start Numbat and it is not policy enforcement. Campaign runs do not yet emit these names for events that already happened. Tests: `allowlisted_event_reloads_without_evidence_keys`, `unknown_name_long_payload_and_cap_do_not_drop_evidence`. |
| Bumblebee inventory ingest | DONE as an NDJSON adapter | `ingest_bumblebee_ndjson` parses caller-supplied bytes with `parse_ndjson`. It does not execute Bumblebee or walk the target. The raw bytes are stored in the caller-supplied content-addressed store, and each accepted node’s `artifact_refs` holds that BLAKE3 digest. A caller correlation id of 1 to 64 ascii characters is required. A line whose `correlation_id`, `run_id`, or `correlation` differs is skipped. `component`, `package`, and `dependency` records become Target Reality nodes with epistemic `Observed` and provenance `provider:bumblebee` only when the path normalizes to a safe relative path in the caller-supplied snapshot set. Absolute paths, drive letters, and `..` are skipped. Untied paths are skipped. `finding`, `exposure`, and `lead` records become Research nodes of kind `lead` with epistemic `Hypothesized`, including when the JSON says `verified` or `evidence_level`. Those keys are not copied. `has_verified_finding` stays false. Invalid UTF-8 writes no nodes and no raw record. A CAS limit smaller than the bytes writes no nodes. Tests: `tied_inventory_is_observed_and_exposure_stays_a_lead`, `invalid_ndjson_writes_nothing`. `parses_bumblebee_style_ndjson_without_promoting_meaning` still only parses. |
| Bounty scope and report | DONE as a local draft on `bounty-hunter` | `parse_program_scope` accepts a program file whose assets are local trees or loopback endpoints. A public name, a public address, a URL, an unknown field, or a minimum below E4 is rejected. Out of scope wins over in scope. Denial of service, social engineering, physical access, production modification, and excessive data access stay forbidden. `write_bounty_report` emits schema `aros-bounty-report/1`. The draft is eligible only when the target is in scope, the finding is verified, reproduction was independent, and the level is at least E4 and at least the program minimum. `submitted` is false. AROS does not grant safe harbor and does not send the draft. A waived run can be eligible and still has `release_eligible` false. Tests: `eligible_draft_keeps_the_invariant_and_is_not_submitted`, `public_assets_unknown_fields_and_weak_evidence_are_refused`. Research: `docs/research/bug-bounty-hunter.md`. ADR-0009. Live company hosts and the remaining hunter classes are not this row. |
| Numbat NDJSON adapter | DONE for caller-supplied bytes | `ingest_numbat_ndjson` does not start `numbat collect`. Observational names (`ToolDenied`, `ProcessStarted`, `NetworkAttempted`, and the other names listed in code) are stored as telemetry for the caller’s campaign id. `VerificationSucceeded` and the other AROS verdict names are refused. `enforcement: true` is refused. A finding, detection, or exposure line is stored as `ObservationCreated` with a clipped id and title. `verified` and `evidence_level` are not copied. A mismatched `run_id` or `campaign_id` is refused. Unknown names are skipped. The raw bytes are content-addressed under SQLite kind `provider_raw`. Invalid UTF-8 and a bad correlation id write nothing. Tests: `numbat_ndjson_stays_telemetry_and_refuses_verdicts`, `bad_numbat_input_writes_nothing`. The collector lifecycle, live provider argv, and the provider UI remain open. |
| Methodology/failure memory | IN PROGRESS | `ResearchFailureCard` still persists. `TOOL_GAP` drops that catalog id from the next plan; `EXPERIMENT_INADEQUATE` moves it first. No substitute campaign is invented. `replan.json` records the change. MethodologyCard is still thin. Tests: `tool_gap_drops_a_campaign_without_inventing_a_replacement`, `missed_campaign_in_the_work_dir_is_planned_first`. |
| Project oracle line | DONE for one `http-idor` line, stored as an assumption | `INVARIANT.md` may contain one line beginning `Oracle: authenticated as`, with a backtick cookie, a backtick `GET` path, and a backtick needle. That line overlays `attack_cookie`, `attack_path`, and `attack_contains` for `http-idor` only. Instructions in the same file are ignored. Two oracle lines, or a cookie, path, or needle outside the safe token set, leave the class bind unchanged. Other campaign ids are not rewritten. When the line is accepted, the graph gains an `assumption` node (`provenance: project-claim`, epistemic `Hypothesized`) and a `motivates` edge to the hypothesis, and the ledger records `AssumptionCreated`. A missing or rejected line adds neither. Free-form assumption mining is still open. Rust still measures the run. Tests: `parses_the_fixture_oracle_line`, `rejects_instructions_without_the_oracle_line`, `rejects_two_oracle_lines_and_unsafe_tokens`, `http_idor_project_claim_overrides_a_harmless_bind`, `http_idor_ignores_invariant_text_that_is_not_the_oracle_line`, `project_claim_leaves_other_classes_and_a_rejected_line_alone`, `http_idor_class_holds_on_patched_authz_fixture`. CLI: `aros campaign claim --target DIR`. |

## Fixtures

| Fixture | Status | Evidence / limitation |
|---|---|---|
| Authorization/state | IN PROGRESS | API campaign launches real Python target; verifier and patched twin launch actual target programs. Awaiting Rust CI. |
| Representation/path | IN PROGRESS | Same; legitimate `public.txt` behavior added for functional post-patch check. Awaiting CI. |
| Deceptive negative control | IN PROGRESS | Real Python negative-control fixture; generic invariant rejects it. Awaiting CI. |
| Mislabelled vulnerable-authz | DONE as a refusal test | Directory labelled Authz, patched server; campaign stays E0. |

## RedLab campaign files (declarative + declared runner)

| Item | Status | Evidence / limitation |
|---|---|---|
| `campaign-loader/campaign.schema.json` | DONE as data | 13 required fields; optional `surfaces` and `structural_control`. Both shipped campaign files still have the 13 required fields and no extras. |
| dycrpt replay / MAX_SKIP campaigns | DONE as data + adapter | Pinned to dycrpt `e4e200ad71bda9ef81ea0bfa4c6e427dc9d7d82c`. Generator is catalog `dycrpt-lib`. |
| 10 roles in `roles.json` | DONE as data | Attackers separated from independent-reproducer and remediation-agent. |
| AROS engine loads campaign schema | DONE | `CampaignSpec` parses shipped files; `run_declared_campaign` fails closed when the harness is absent (tested). HTTP fixtures still use `FixtureKind`. |
| G-1 contained generator exec | IN PROGRESS | `CampaignOciTarget::exec_generator` exists; unwaived declared runs use it; fail-closed without Podman is tested. Live OCI generator evidence is not claimed. |
| G-2 `required_evidence` enforced | DONE | Achieved < required → `InsufficientEvidence`, not `Verified`. Test: `g2_required_e4_is_not_claimed_at_e2`. |
| G-3 harness provenance | DONE | Harness bytes CAS-addressed; digest in ledger + HTML. Test: `g3_harness_bytes_are_cas_addressed`. |
| G-4 structural negative controls | DONE | Optional `structural_control`; good must hold, mutant must break. Tests: `g4_structural_controls_must_discriminate`, `g4_non_discriminating_mutant_fails_closed`. |
| G-5 multi-surface campaigns | DONE | Optional `surfaces`; any `AttackSucceeded` elevates the campaign. Test: `g5_second_surface_can_break_the_campaign`. |
| G-6 environment mismatch | DONE | Unreproducible `rust-toolchain.toml` is `run_kind=environment_mismatch`, no finding. Tests: `g6_unreproducible_toolchain_is_environment_mismatch`, `g6_windows_gnu_toolchain_pin_is_not_a_security_result`. |
| G-7 readable evidence report | DONE | `evidence-report.html` under the work root. Test: `g7_report_contains_claim_levels_and_harness_digest`. |
| AROS harness catalog (plug-and-play) | IN PROGRESS | `generator.harness` + `bind` run catalog runners from `campaign-loader/harnesses/` without writing into the target. Tests: `catalog_harness_runs_without_files_in_the_target`, `unknown_catalog_harness_fails_closed`. |
| HTTP/API class pack | DONE | IDOR, unauth, cookie-confusion, path traversal, surface map. Tests: `http_idor_*`, `http_unauth_*`, `http_cookie_confusion_*`, `http_path_*`, `http_surface_map_*`. |
| Surface mapper | DONE | `map_http_surface` + `aros campaign map` write bindable `surface.json`. `overlay_surface_bind` feeds class campaigns. |
| Research worker uses surface map | DONE | `ResearchDirector.propose_from_surface` + worker `--surface`. Test: `test_director_proposes_http_intents_from_surface_map`. Intents still go through Rust policy. |
| Library/CLI class pack | DONE | `cli-crash` (NUL) and `lib-call-twice` against lab fixtures. Tests: `cli_crash_class_verifies_break_on_nul_parser`, `lib_call_twice_class_verifies_replay_of_one_shot`. |
| Release gate | DONE | `aros campaign gate` / `scripts/gate.sh`. Fails if a class is Verified or containment cannot be shown. Tests: `gate_without_containment_fails_closed`, `waived_gate_blocks_vulnerable_authz`, `waived_gate_allows_patched_authz_http_pack`. |
| Live contained runtime | IN PROGRESS | Unwaived gate fail-closes without `live_oci_claimable`. Doctor prints that unwaived campaigns fail closed. This host/CI does not claim a Proven five-way Podman run. |
| Related systems / papers / LLM-free agents | DONE as research note | `docs/research/related-systems-papers.md`. |
| HTN planner + deterministic crew | DONE | `htn_plan` / `run_deterministic_crew`; Python `--no-model`. Tests: `users_surface_plans_idor_not_path`, `crew_plans_http_classes_for_authz_fixture`. |
| PDDL / STRIPS planner | DONE builtin | `plan_campaigns` emits domain.pddl/problem.pddl; Fast Downward if present and complete; else STRIPS. Tests: `strips_matches_htn_on_users_surface`, `missing_work_dir_does_not_invent_fast_downward`. This host does not claim a live Fast Downward run. |
| MST-wi metamorphic HTTP | IN PROGRESS | 12 relations (not 76): plus auth-header, nested-dotdot, double-slash. Harness relations unchanged (`b_must_not_contain`, `a_must_not_contain`, `b_must_not_gain`, `bodies_must_differ`). Tests: `http_mr_auth_header_verifies_on_vulnerable_authz`, `http_mr_auth_header_holds_on_patched_authz`, `http_mr_nested_dotdot_verifies_on_vulnerable_path`, `http_mr_nested_dotdot_holds_on_patched_path`, `http_mr_double_slash_verifies_on_vulnerable_path`. |
| Mutational fuzz + shrink | DONE | `mutate-fuzz` + `shrink_bytes`. AFL++/libFuzzer invoked when present + `bind.binary`; else mutate. Tests: `mutate_fuzz_finds_nul_crash_and_shrinks`, `test_mutate_fuzz_invokes_afl_when_present`. |
| Crash crusher | DONE for one parser entry on a waived host | `crash-crusher` keeps `mutate-fuzz` as the 30-second smoke campaign. Search budget is 120 seconds inside a 180-second wall. `bind.entry` or `parse.py` is the mutational entry when it stays inside the target. AFL++ or libFuzzer runs when that binary exists (`FUZZ_ENGINE afl` or `FUZZ_ENGINE libfuzzer`, `COVERAGE_ENGINE afl` or `libfuzzer`). With no coverage binary the engine line is `FUZZ_ENGINE mutational` and `COVERAGE_ENGINE absent`. That absence is an observation on the run, so failure memory does not drop the campaign. A missing executable entry, an entry path outside the target, or a discovered `LLVMFuzzerTestOneInput` / `fuzz_targets` source with no binary is `CRUSH_GAP` and a `TOOL_GAP` card. A replayed crash emits `SHRINK_*` and reaches E5; required E4 still uses the replica re-run. `SANITIZER asan` is recorded only when the crash text contains AddressSanitizer. This host did not build with a sanitizer and did not run AFL++ or libFuzzer. No coverage retention and no cross-run stack-hash store. Unwaived execution still fail-closes. Tests: `crash_crusher_finds_nul_crash_and_shrinks`, `crash_crusher_independent_rerun_satisfies_required_e4`, `crash_crusher_missing_entry_is_a_tool_gap`, `crash_crusher_fuzzer_source_without_binary_is_a_tool_gap`, `test_crash_crusher_labels_mutational_engine`, `test_crash_crusher_missing_entry_does_not_accept`, `test_crash_crusher_fuzzer_source_without_binary_is_a_gap`, `test_crash_crusher_refuses_entry_outside_the_target`, `test_crash_crusher_invokes_afl_when_present`. |
| QuickCheck property harness | DONE | `property-check` + `prop-ascii`. Test: `prop_ascii_holds_on_nul_parser`. |
| KLEE adapter | DONE fail-closed | `klee-run` campaign; invokes only with `bind.bitcode`. Test: `klee_run_holds_without_inventing_a_bitcode_result`. |
| HTN skill coverage | DONE | All 20 builtin JSON skills mapped in `SKILL_TASKS`. Tests: `every_builtin_skill_has_an_htn_task`, `test_every_builtin_skill_has_an_htn_task`. |
| PoC-or-nothing eval pack | DONE as local pack | `evaluation/poc-or-nothing/cases.json`, `aros benchmark poc`. Test: `poc_or_nothing_local_eval_pack`. Not CyberGym's 1,507-vuln corpus. |
| dycrpt AROS-side adapter | DONE fail-closed without target | `adapters/dycrpt-lib` calls `decrypt`. Empty trees fail closed. Required evidence is E2+E4 (replica re-run). Pin `e4e200a` printed OPEN_OK/REPLAY_REJECTED. Not contained. Tests: `dycrpt_adapter_source_calls_decrypt`, `dycrpt_replay_adapter_calls_open_path_when_target_present` (skips if checkout fails). |
| Evidence certificate | DONE as a consistency bundle | Declared runs write `certificate.json`. Digest covers claims. Ledger `CertificateIssued` binds `contained` and `original_unmodified`. `aros evidence verify --work` checks ledger head, harness digest, regression file, minimized payload. `release_eligible` requires containment. Not a detached signature. Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture`, `http_idor_patched_twin_earns_e7`, `digest_changes_when_a_claim_changes`. How to point this at another repo: `docs/research/testing-other-projects.md`. |

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

Local quality gates on 2026-09-29 (slice 14): `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p aros-core --lib` (92 passed, 0 failed, including the assumption reload on `http_idor_class_verifies_break_on_vulnerable_authz_fixture` and the absence of that node on `http_idor_ignores_invariant_text_that_is_not_the_oracle_line` and `http_idor_class_holds_on_patched_authz_fixture`). The dycrpt host test fetched pin `e4e200a` and passed. Python files were not changed, so ruff, mypy, and pytest were not re-run. A full `cargo test --workspace` was not re-run for this slice; the other crates were unchanged. Unwaived containment is still fail-closed. The assumption is one strict `http-idor` line. Free-form assumption mining remains open.

Local quality gates on 2026-10-20 (`crash-crusher`, `release/v0.1.0`): `cargo test -p aros-core --lib` (118 passed, 0 failed), `cargo clippy -p aros-core --lib --all-features -- -D warnings`, `python -m ruff check python`, `python -m mypy python/aros_research` (27 files), `python -m pytest python -q` (30 passed). `cargo test -p aros-types --lib http_class_campaigns_parse` passed. Workspace `cargo fmt --all -- --check`, workspace clippy, and `cargo test --workspace` were not re-run. Unwaived five-way OCI containment was not shown. The crusher tests use `CampaignEngine::new(true)`, which is a waived host run.

Local quality gates on 2026-10-20 (anomaly notebook, same branch): `cargo test -p aros-core --lib` (121 passed, 0 failed) and `cargo clippy -p aros-core --lib --all-features -- -D warnings`. Python files were not changed, so ruff, mypy, and pytest were not re-run. Workspace fmt, workspace clippy, and `cargo test --workspace` were not re-run. Unwaived containment was not shown.

Local quality gates on 2026-11-03 (telemetry stream and Bumblebee ingestion, same branch): `cargo test -p aros-core --lib` (125 passed, 0 failed, 45.50s) and `cargo clippy -p aros-core --lib --all-features -- -D warnings` (exit 0). Python files were not changed, so ruff, mypy, and pytest were not re-run. Workspace fmt, workspace clippy, and `cargo test --workspace` were not re-run. Unwaived containment was not shown. Bumblebee and Numbat were not executed.

Local quality gates on 2026-11-03 (provider raw CAS, correlation id, Numbat NDJSON adapter, same branch): `cargo test -p aros-core --lib` (127 passed, 0 failed, 56.05s) and `cargo clippy -p aros-core --lib --all-features -- -D warnings` (exit 0). Python files were not changed, so ruff, mypy, and pytest were not re-run. Workspace fmt, workspace clippy, and `cargo test --workspace` were not re-run. Unwaived containment was not shown. Bumblebee and Numbat were not executed. `run_provider` still does not write the content-addressed store.

Local quality gates on 2026-11-03 (bounty scope and report, branch `bounty-hunter`): `cargo test -p aros-core --lib` (129 passed, 0 failed, 45.35s) and `cargo clippy -p aros-core --lib --all-features -- -D warnings` (exit 0). Python files were not changed, so ruff, mypy, and pytest were not re-run. Workspace fmt, workspace clippy, and `cargo test --workspace` were not re-run. Unwaived containment was not shown. The draft was not submitted. Public hosts were not contacted.

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
