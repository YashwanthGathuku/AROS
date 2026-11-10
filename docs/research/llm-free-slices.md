# LLM-free implementation slices

This is the ledger of paper-backed work that does **not** put authority in an
LLM. Each slice names what shipped, how it was verified, and what it still is
not. `docs/BUILD_STATUS.md` remains the status table; this file is the
narrative of *what we did, in order*.

No slice is “AROS MVP complete.” Complete only when `./scripts/acceptance.sh`
passes the spec contract.

## Slice 1 — HTN crew, first MST-wi, fuzz+shrink, KLEE (`ddc7094` / `729fc8b`)

HTN over class campaigns; deterministic crew; `http-mr-cookie-drop` /
`http-mr-method`; `mutate-fuzz` + Zeller shrink; `klee-run` fail-closed.

## Slice 2 — More MST-wi, AFL invoke-when-present, eval pack (`52decd0`)

Six then more HTTP relations; AFL++/libFuzzer called only when present;
local PoC-or-nothing pack. Not 76 MST-wi relations. Not CyberGym’s 1,507
vulns. AFL invoke proven with a fake script on this host.

## Slice 3 — STRIPS/PDDL, more MST-wi, QuickCheck (`e4f3930`)

Builtin forward search + optional Fast Downward; 9 MST-wi relations;
`prop-ascii`. Fast Downward was not present here.

## Slice 4 — E5 + ResearchFailureCard (`1511e76`)

Minimized payload CAS-addressed only with `SHRINK_*` hex. HTTP classes do
not get E5. Unknown harness → `TOOL_GAP`. Eval miss → `failure-cards.jsonl`.

## Slice 5 — dycrpt adapter (`306d9a2`)

`campaign-loader/adapters/dycrpt-lib` path-depends on `voicechat_crypto` and
calls `decrypt` (the receive/`open` path). Writes nothing into dycrpt. Against
pin `e4e200a`: `OPEN_OK` then `REPLAY_REJECTED`. Not contained.

## Slice 6 — Declared E4 replica re-run (`94c7d91`)

Copy tree, re-run generator, matching oracle + unchanged digest →
`independent_reproduced`. E5 does not imply E4. HTTP IDOR/path findings at
E4. Not an OCI verifier process.

## Slice 7 — Declared E6 patched twin (`with_twin` / `--twin`)

If the engine is given a patched twin root, the twin is **copied** to
`work_root/e6-twin` and the same catalog campaign is run on that copy.
E6 requires: original attack succeeded, E4 replica matched, twin oracle
**holds** (exploit gone, health still `OPEN_OK`), original and operator
twin digests unchanged. Original and operator twin trees are not modified.

Tests: `http_idor_patched_twin_earns_e6` was superseded by slice 8 for
IDOR (cookie-drop is a real variant). E6 without a variant:
`http_unauth_patched_twin_stays_at_e6_without_a_variant`. Also
`required_e6_without_twin_is_insufficient`,
`vulnerable_twin_does_not_earn_e6`.

## Slice 8 — Declared E7 variant + generated regression

A related variant must break the original replica and hold on the twin
copy. Variants derived from bind (not LLM): drop `attack_cookie`, or
swap `../` with `..%2F`. Then `e7-regression/regression_test.py` is
written under the work root, CAS-addressed, and executed against the
twin copy. Original and operator twin are not modified. Campaign state
`RegressionProtected`.

Tests: `http_idor_patched_twin_earns_e7`, `http_path_patched_twin_earns_e7`,
`required_e7_without_twin_is_insufficient`,
`http_unauth_patched_twin_stays_at_e6_without_a_variant`.

Still not at the end of slice 8: live five-way Podman containment; all 76
MST-wi relations; CyberGym corpus.

## Slice 9 — Three more MST-wi relations (12 of 76)

Same `http-metamorphic` harness. No new relation operators.

- `http-mr-auth-header`: Cookie `user=2` vs `Authorization: Bearer 2`. Breaks on vulnerable authz, holds on patched authz.
- `http-mr-nested-dotdot`: `public.txt/../../secret.txt`. Breaks on vulnerable path, holds on patched path.
- `http-mr-double-slash`: `..//secret.txt`. Breaks on vulnerable path.

Planner lists (`HTTP_USER_CAMPAIGNS` / `HTTP_FILE_CAMPAIGNS`) include them in Rust and Python. PoC-or-nothing cases added. Not the other 64 MST-wi relations.

Tests: `http_mr_auth_header_verifies_on_vulnerable_authz`, `http_mr_auth_header_holds_on_patched_authz`, `http_mr_nested_dotdot_verifies_on_vulnerable_path`, `http_mr_nested_dotdot_holds_on_patched_path`, `http_mr_double_slash_verifies_on_vulnerable_path`.

Still not at the end of slice 9: live five-way Podman containment; all 76
MST-wi relations; CyberGym corpus.

## Slice 10 — Evidence certificate

A declared campaign writes `work_root/certificate.json`. The digest covers
the claims. `CertificateIssued` in the ledger stores `contained` and
`original_unmodified`. `aros evidence verify --work DIR` re-checks the
ledger head, harness digest, regression file, and minimized payload.

`statement_ok` means the bundle is internally consistent. `release_eligible`
is false unless containment was demonstrated. A waived lab run verifies
and is not a release. Editing `contained` without the ledger fails.
This is not a signature from a key you do not hold.

How to aim the same run at another checkout, a twin, or a pinned
dependency: `docs/research/testing-other-projects.md`.

Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture`
(statement ok, release not eligible, tampered `contained` rejected),
`http_idor_patched_twin_earns_e7` (E7 bundle still not a release when waived).

Still not at the end of slice 10: live five-way Podman containment; all 76
MST-wi relations; CyberGym corpus. A certificate does not create them.

## Slice 11 — Failure memory changes the next plan

`TOOL_GAP` removes that catalog id from the next plan and does not invent
a substitute. `EXPERIMENT_INADEQUATE` moves that id to the front if the
facts already included it. Other categories are recorded and do not
reorder the plan. An id that was not in the fact plan is not added.

Cards live in `failure_card` rows (`spec_id`) and in
`failure-cards.jsonl` (`campaign`). `plan_campaigns` writes `replan.json`.
The same rule is in the Python planner helper.

Tests: `tool_gap_drops_a_campaign_without_inventing_a_replacement`,
`missed_poc_is_planned_first_and_unknown_ids_are_not_added`,
`missed_campaign_in_the_work_dir_is_planned_first`,
`test_failure_memory_drops_tool_gap_and_promotes_a_miss`.

Still not at the end of slice 11: live five-way Podman containment; all 76
MST-wi relations; CyberGym corpus.

## Slice 12 — Declared research graph survives reload

A declared run writes a research graph into SQLite: hypothesis, experiment,
observation, and a conclusion. Edges are `tested-by`, `observed`, then
`supports`, `falsifies`, or `inconclusive` with the epistemic state of that
result. An E4 replica adds `reproduced`. A twin that holds adds `absent-on`.
Opening the database again returns the same nodes and edges.

Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture`,
`http_idor_class_holds_on_patched_authz_fixture`,
`http_idor_patched_twin_earns_e7`.

Still not: live five-way Podman containment; all 76 MST-wi relations;
CyberGym corpus; anomaly notebook; telemetry; a graph that spans campaigns.

## Slice 13 — One oracle line from the target (`0fb3353`)

`INVARIANT.md` is untrusted data. The runner accepts at most one line of this
shape:

```text
Oracle: authenticated as `Cookie: user=1`, `GET /users/2` must not contain `bob-secret`.
```

When that line parses, `http-idor` uses its cookie, path, and needle. Every
other line in the file is ignored, including instructions to the runner. Two
oracle lines, a semicolon in the cookie, or a space in the path make the file
unusable and the class bind stays. `http-path-traversal` and `http-unauth`
are not rewritten by an IDOR line. The fixture at
`fixtures/vulnerable/authz/INVARIANT.md` already states the class bind, so
the existing IDOR fixture runs are unchanged. A harmless bind (`/users/9`,
`user=9`, needle `nope`) verifies only when the real oracle line is present,
and stays `Refuted` when the file is only an instruction.

`aros campaign claim --target DIR` prints the accepted triple as JSON, or
`none`. A missing line is not an error.

This is not step 2 of the MVP spec. Free-form assumptions are not mined, and
the line is not its own research-graph node. The measured bind is whatever
the run used after the overlay. Rust still decides `AttackSucceeded` or
`InvariantHolds` by executing the target.

Tests: `parses_the_fixture_oracle_line`,
`rejects_instructions_without_the_oracle_line`,
`rejects_two_oracle_lines_and_unsafe_tokens`,
`http_idor_project_claim_overrides_a_harmless_bind`,
`http_idor_ignores_invariant_text_that_is_not_the_oracle_line`,
`project_claim_leaves_other_classes_and_a_rejected_line_alone`.

Still not: live five-way Podman containment; all 76 MST-wi relations;
CyberGym corpus; general assumption mining; a claim node in the graph.

## Slice 14 — The accepted oracle line is an assumption (`7306e42`)

When slice 13 accepts the line, the declared graph stores it. The node kind
is `assumption`, provenance `project-claim`, epistemic `Hypothesized`. The
payload is the parsed cookie, path, and needle. An edge `motivates` links
that node to the hypothesis. The ledger event is `AssumptionCreated`. The
statement is built from the parsed tokens.

The assumption stays `Hypothesized` when the finding is `Verified`. The file
stated a check. The run measured the server. Those are different facts.
A file with no accepted line, including the patched authz fixture and a file
that is only an instruction, adds no assumption node and no ledger event.
`http-path-traversal` and `http-unauth` do not accept the line, so an IDOR
sentence in their tree is not stored on their graph.

Tests: `http_idor_class_verifies_break_on_vulnerable_authz_fixture`,
`http_idor_project_claim_overrides_a_harmless_bind`,
`http_idor_ignores_invariant_text_that_is_not_the_oracle_line`,
`http_idor_class_holds_on_patched_authz_fixture`,
`project_claim_leaves_other_classes_and_a_rejected_line_alone`.

Still open: free-form assumption mining, a graph that spans campaigns, the
anomaly notebook, telemetry, live five-way Podman containment, the remaining
MST-wi relations, and the CyberGym corpus.

## Crash crusher (`release/v0.1.0`)

`crash-crusher` is the first slice from `docs/research/crush-testing.md`.
`mutate-fuzz` stays the 30-second smoke campaign. The crusher's manifest
budget is 120 seconds of search inside a 180-second wall. It takes one
entry: `bind.entry` or `parse.py` when that file resolves inside the
target, or AFL++ / libFuzzer when `bind.binary` and the engine binary
exist. The mutational path prints `FUZZ_ENGINE mutational` and
`COVERAGE_ENGINE absent`. A missing coverage engine stays on that path so
failure memory does not drop the only crash search. `CRUSH_GAP` fails
closed with a `TOOL_GAP` card when the entry is missing, escapes the
target, or is a `LLVMFuzzerTestOneInput` / `fuzz_targets` source with no
binary. A crash that replays is shrunk (`SHRINK_*`, E5). Required E4 is
the existing replica re-run. `SANITIZER asan` is printed only when the
crash text contains AddressSanitizer.

The planner adds `crash-crusher` for a tree that has `parse.py`, next to
the other CLI parse campaigns. The harness is staged from
`campaign-loader/harnesses/crash-crusher/` and is not copied into the
target.

Tests: `crash_crusher_finds_nul_crash_and_shrinks`,
`crash_crusher_independent_rerun_satisfies_required_e4`,
`crash_crusher_missing_entry_is_a_tool_gap`,
`crash_crusher_fuzzer_source_without_binary_is_a_tool_gap`,
`test_crash_crusher_labels_mutational_engine`,
`test_crash_crusher_invokes_afl_when_present`,
`test_parser_plan_includes_crash_crusher`.

Still not this slice: an hour-scale run, coverage retention, a cross-run
stack-hash store, a sanitizer build, a real AFL++ or libFuzzer run on
this host, unwaived rootless Podman, the HTTP pack, the other MST-wi
relations, and state exploration.

## Anomaly notebook (`release/v0.1.0`)

An anomaly is stored as the existing `Anomaly` record: observation,
baseline, components, explanations, related hypotheses, historical
patterns, and status. Status is `open`, `revisited`, or `dismissed`.
A status of `verified` is rejected. The JSON has no evidence level and
no finding id. SQLite kind `anomaly` reloads on a second `Store::open`.
The work directory also gets `anomalies.jsonl`. The ledger event is
`AnomalyRecorded`.

`revisit_anomalies` returns open notes when a later cue exactly matches
one stored component, hypothesis id, or pattern. An empty cue and a
substring do not select a note. Dismissed and revisited notes stay out.

`crash-crusher` writes one open note when it prints `COVERAGE_ENGINE
absent`. That note does not replace the crash finding.

Tests: `notebook_reloads_and_is_not_a_finding`,
`verdict_status_and_empty_observation_are_rejected`,
`open_anomaly_is_revisited_only_on_an_exact_cue`,
`crash_crusher_finds_nul_crash_and_shrinks`.

A cross-campaign graph and hour-scale coverage retention remain unbuilt.
Telemetry and Bumblebee ingestion are the next sections on this branch.

## Telemetry stream (`release/v0.1.0`)

The spec names are an allowlist of 23 event names. `emit_telemetry` stores
a `TelemetryEvent` under SQLite kind `telemetry`. When a work root is
passed it also appends `telemetry.jsonl`. A name outside the list is
rejected. A payload longer than 1024 characters is rejected. After 4096
retained events, the next event increments a drop counter and is not
stored. That drop does not delete an evidence record. The stored object
has no evidence level and no verified flag.

`to_numbat_record` writes `record_type` `event`, schema `aros-telemetry/1`,
and `enforcement` false. It does not start Numbat and it does not enforce
policy. Declared campaigns did not emit these names in that slice. The
later section on `bounty-hunter` does.

Tests: `allowlisted_event_reloads_without_evidence_keys`,
`unknown_name_long_payload_and_cap_do_not_drop_evidence`.

## Bumblebee inventory (`release/v0.1.0`)

`ingest_bumblebee_ndjson` reads NDJSON the caller already has. It does not
run `bumblebee`. `parse_ndjson` is unchanged and still does not assign
meaning by itself.

A component, package, or dependency becomes a Target Reality node with
epistemic `Observed` and provenance `provider:bumblebee` only when the
path normalizes to a safe relative path that the caller listed from the
immutable snapshot. Slash and backslash forms match. A path that is
absolute, has a drive letter, or contains `..` is skipped even if that
string was supplied in the set. A path that is not in the set is skipped.

A finding, exposure, or lead becomes a Research node of kind `lead` with
epistemic `Hypothesized`. A `verified` or `evidence_level` field on the
line is not copied and does not make the node verified. Invalid UTF-8
writes no nodes. Content-addressing of the raw bytes is the next section.

Tests: `tied_inventory_is_observed_and_exposure_stays_a_lead`,
`invalid_ndjson_writes_nothing`.

## Provider raw bytes and Numbat NDJSON (`release/v0.1.0`)

`ingest_bumblebee_ndjson` and `ingest_numbat_ndjson` take a
content-addressed store and a caller correlation id. The raw bytes are
stored before any node or telemetry event is written. The SQLite record
kind is `provider_raw`. It holds the provider name, campaign id,
correlation id, BLAKE3 digest, SHA-256 digest, byte length, and media
type. It has no evidence level. Reloading the digest returns the same
bytes. A digest mismatch is not a vulnerability.

The correlation id is 1 to 64 characters from ascii letters, digits, `.`,
`_`, and `-`. A line that names a different `correlation_id`, `run_id`, or
`correlation` is left unused. An empty or path-like id rejects the call
and writes nothing.

Numbat lines with observational names, such as `ToolDenied`, are telemetry
for the caller’s campaign. `VerificationSucceeded` and the other verdict
names are refused. `enforcement: true` is refused. A finding line is stored
as `ObservationCreated` with the clipped title. The words `verified` and
`E7` from that line are not copied. This does not start `numbat collect`.
`run_provider` did not write the content-addressed store in that slice. The
later section on `bounty-hunter` stores the bytes a successful run returned.

Tests: `tied_inventory_is_observed_and_exposure_stays_a_lead`,
`invalid_ndjson_writes_nothing`,
`numbat_ndjson_stays_telemetry_and_refuses_verdicts`,
`bad_numbat_input_writes_nothing`.

Still later: a live Bumblebee or Numbat process, correlation ids on live
provider argv, the provider UI, and pinned-provider host tests.

## Bounty scope and report (`bounty-hunter`)

The research note is `docs/research/bug-bounty-hunter.md`. A program file
names local trees or loopback assets. A public name, a public address, or a
URL is rejected. Out of scope wins. The hazardous activities from the
HackerOne Code of Conduct stay forbidden. A draft is eligible only for a
verified independent reproduction at E4 or higher. `submitted` stays false.
AROS does not grant safe harbor and does not send the draft.

Tests: `eligible_draft_keeps_the_invariant_and_is_not_submitted`,
`public_assets_unknown_fields_and_weak_evidence_are_refused`.

`plan_bounty_hunt` is the working order from the same research note. It
stops before mapping when the asset is outside the program. On an in-scope
asset the map is local facts, and the class list is the existing planner.
An empty map stays an empty list. Schema `aros-bounty-hunt/1` is not a
finding.

Tests: `in_scope_user_surface_maps_before_classes`,
`out_of_scope_and_unmapped_assets_do_not_grow_a_class_list`.

`conduct_bounty_hunt` (`aros campaign hunt --scope FILE --target DIR`)
puts that plan in front of the engine. The target directory is opened
only when the program asset matches it. Reports from the run stay unsent.

Tests: `out_of_scope_hunt_does_not_open_the_target`,
`unwaived_hunt_does_not_run_without_live_oci`,
`in_scope_authz_hunt_runs_the_planned_classes`.

After the asset matches, one accepted oracle line names the cookie
identifier and, when the subjects differ, two principals. The needle is
not copied and the line adds no class. A prior `TOOL_GAP` is not run. A
prior `EXPERIMENT_INADEQUATE` moves to the front of the execution list.
The hypothesis list stays unchanged. The mapper's default `/health`
suggestion is not an observed path.

Tests: `oracle_line_names_two_principals_and_adds_no_class`,
`oracle_line_with_one_subject_records_no_distinct_level`,
`prior_tool_gap_is_not_a_class_the_hunt_will_run`.

The work directory keeps `hunt-run.json` and `hunt-journal.jsonl`.
`aros campaign board --work DIR` writes `board.html` from that record and
does not start a hunt. A refusal is a journal line, not a finding.

Tests: `hunt_board_escapes_a_refusal_and_shows_an_empty_directory`.

Still later: live company hosts, directory brute force, the remaining
hunter bug classes, role names, a unique threat model, unwaived
containment, and filing the draft.

## Campaign telemetry (`bounty-hunter`)

A campaign that persists its ledger then calls `publish_ledger_telemetry`.
The fixture HTTP path and the declared catalog path both do this, including
a fail-closed return after events were already appended. Each mapped event
becomes one `TelemetryEvent`. The name is one of the 23 allowlisted names.
`ObservationRecorded` is stored as `ObservationCreated` with payload
`observation recorded`. `AnomalyRecorded` becomes `AnomalyCreated` with
`anomaly recorded`, and the summary is not copied. `PatchCandidateCreated`
becomes `PatchCreated` with `patch candidate recorded` and the two
identifiers.

`AssumptionCreated` is not stored. Its statement is untrusted file text and
can contain the oracle needle. `FindingVerified` is not stored, so the
evidence level is not copied into telemetry. `CertificateIssued` is not
stored, so `contained` is not copied. `ExperimentStarted` and
`ExperimentFinished` are not renamed into process events.
`CampaignCompleted` is not renamed into `AgentStopped`.

A payload may include a hypothesis, finding, patch, or request identifier.
It does not include a claim, a reason, a host, an executable path, a digest,
or an evidence level. `verification succeeded` does not contain the word
`verified`. Dropping or failing a telemetry write does not delete the ledger
or an evidence row.

On the vulnerable authz campaign, telemetry contains `ObservationCreated`
and `EvidenceCreated`, and the file `telemetry.jsonl` does not contain
`bob-secret`. The E7 twin run also stores `RegressionCreated` without the
regression path.

Tests: `research_ledger_emits_allowlisted_names_without_target_text`,
`http_idor_class_verifies_break_on_vulnerable_authz_fixture`,
`http_idor_patched_twin_earns_e7`.

Still later: the Numbat collector, correlation ids on live provider argv,
hour-scale coverage,
the other crush oracles, the remaining 64 MST-wi relations, a methodology
card thicker than the fields a run already has, a graph that spans
campaigns, free-form assumption mining, and the full Python scheduler.
gVisor, Firecracker, a required paid cloud model, a large historical
corpus, and a live web console stay later. Public internet targets stay
outside v0.1.

## Provider run bytes (`bounty-hunter`)

`run_provider` requires a caller correlation id and a provider name of 1 to
64 ascii letters, digits, `.`, `_`, or `-`. A bad id returns before the
process starts and writes nothing. A successful run stores the stdout it
returned. When stdout and stderr are separate, it stores stderr too,
including an empty stderr. The OCI path combines the streams, so only
stdout is stored. The media type is `application/octet-stream`. The SQLite
kind is `provider_raw`. The record holds the provider, campaign id,
correlation id, stream name, and the two digests. It has no evidence level
and it does not copy the bytes into the row.

The correlation id is not appended to argv. Grok stays
`grok --cwd ... --prompt-file`. Numbat stays
`numbat collect --addr 127.0.0.1:4318`. Neither binary is started. A store
smaller than the returned bytes fails closed and leaves no `run-tiny`
record. A timed-out process stores nothing. An unwaived run on this host
stores nothing because containment is not demonstrated.

Tests: `authority_shell_placeholder_and_budgets_fail_closed_before_spawn`,
`waived_host_run_caps_output_time_and_env_and_unwaived_fails_closed`.

Still later: the Numbat collector, putting the correlation id on a live
provider command line, a provider screen, pinned-binary host tests,
hour-scale coverage, the other crush oracles, the remaining MST-wi
relations, a thicker methodology card, a graph that spans campaigns,
free-form assumption mining, and the full Python scheduler.

## Where each fact is recorded

| Kind of fact | File |
|---|---|
| Can we claim DONE? | `docs/BUILD_STATUS.md` |
| What the MVP must be | `docs/AROS_MVP_SPEC.md` |
| Paper sources / LLM-free stack | `docs/research/related-systems-papers.md` |
| Evidence level meanings | `docs/evidence/evidence-levels.md` |
| This slice history | this file |
| Campaign/adapter how-to | `campaign-loader/README.md`, `adapters/README.md` |
| Testing another checkout | `docs/research/testing-other-projects.md` |
| This session and the next steps | `docs/research/session-2026-09-22.md` |
