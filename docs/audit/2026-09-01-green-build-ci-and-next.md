# Green-build patch, CI signal, and ordered next work

Date: 2026-09-01
Branch: `hardening/epistemic-honesty-runtime-boundary`
Base: `00dd6b6`
Do not merge: `hardening/mvp-evidence-containment-rename-seam`

## Goal of this pass

Apply `aros-ehrb-green-build.patch`, get an independent GitHub Actions signal,
and stop treating an unexecuted branch as verified. Campaign-bound OCI
execution is **out of scope** until items 1–4 below have landed and CI has
been green for more than one commit.

## Patch applied

Source: `aros-ehrb-green-build.patch` (companion to
`docs/AROS-epistemic-honesty-branch-verification.md`).

| Change | Why |
|---|---|
| CI `on.push.branches: ['**']` | Hardening-branch pushes never ran `ci.yml` |
| Constant-time bearer compare | Token recovery via latency |
| HTTP-target / cookie validators | Shell metacharacter guard denied query-string exploits (`?`) |
| `default_deny_local` drops `HttpRequest`/`RunTests` | Constructor name was not deny-by-default |
| Worker token via `-e NAME` + `Command.env` | Secret was on podman argv |
| Deceptive fixture uses a real confidentiality oracle | Label shortcut moved one layer down |
| Graph load `ORDER BY rowid` | UUID order made persistence tests a coin flip |
| Compile repairs | Stale `seed_fixture` re-export, `uuid`/`tempfile` deps, `prop_assert!` braces |

## Extra closures required for an actually green run

The patch alone is not sufficient on this HEAD:

1. `VerifierReplay.containment_required` — subprocess tests must set `false`
   for host Python fixtures or they do not compile.
2. THEUSTAD `serve_once` must drain the request before close — Windows RST
   (`WSAECONNRESET`) otherwise fails `http_2xx_adjudicates`.
3. Unix-only snapshot tests must be `#[cfg(all(test, unix))]` — empty module
   trips clippy `-D warnings` on Windows.
4. IPC tests must probe `import aros_research.worker`, not `import aros_research`.
   The package import succeeds without pydantic; the worker does not. Linux CI
   then spawned a dead worker and timed out on hello.
5. The rust CI job installs Python 3.14 + pydantic/httpx/protobuf so worker
   tests actually execute.
6. One-shot `apply-*` workflows are `workflow_dispatch` only. They rewrite
   source with `contents: write` and must not fire on every hardening push.

Local evidence before push (this session, after the last edit):

- `cargo fmt --all -- --check` — exit 0
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0
- `cargo test --workspace` — exit 0
- `PYTHONPATH=python python -m pytest python -q` — 14 passed

GitHub Actions on the pull request is the independent confirmation. Do not
treat local Windows results as Linux CI.

## Kill the older branch — do not merge it

`hardening/mvp-evidence-containment-rename-seam` and this branch share base
`c60c001`. Every file the older branch touches, this branch also touches.
There is nothing unique on the older branch: tri-state probes,
`packet_probes_ran`, `live_oci_claimable`, strict THEUSTAD,
`BuiltinEvidenceAuthority` are all present here. `env_name` coverage is
wider on this branch. `acceptance.sh` is byte-identical at the common
analysis. Merging it buys conflicted files and zero content.

Action: close any remaining PR from that branch; delete the remote branch.

## Ordered work after CI is green

Do these in order. Do not start campaign-bound OCI until they have landed
and CI has stayed green for a few commits.

1. **Wrong-label fixture.** A directory labelled `vulnerable` whose
   `server.py` is the patched implementation. Assert the pipeline refuses
   it. This is the only test that catches “the system agrees with its own
   labels.”
2. **`verify-ledger` scoping (R-3).** `aros-cli` still calls
   `Store::load_ledger()`, which errors unless the database holds exactly
   one campaign. Add `--campaign-id` routed to `load_ledger_for`.
3. **Worker token off podman argv (R-1).** Present in this patch
   (`-e AROS_WORKER_TOKEN` with value in the process environment). Must be
   verified on a host with Podman; this Windows workspace cannot run that
   container.
4. **Typed `http_target` / `http_cookie` on `ToolIntent`.** The patch
   scopes the validator correctly, but `argv` still carries three meanings.
   Fix the shape, not just the check.

Then: **campaign-bound OCI execution** — bind actual target/worker identity
to the containers being measured so `assert_containment_or_fail` is no
longer a permanent hard stop.
