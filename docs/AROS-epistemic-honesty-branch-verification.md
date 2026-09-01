# AROS — build-and-test verification of `hardening/epistemic-honesty-runtime-boundary`

Prepared for Yashwanth (Ash) — DigitalSvarga
Repository: `YashwanthGathuku/AROS` @ `9ca5ac7` (branch head)
Base: forked from `c60c001`, parallel to `hardening/mvp-evidence-containment-rename-seam` (not a descendant)
Scope: 78 commits vs `main`; 4,021 insertions / 2,270 deletions across 53 files
Method: full clone, toolchain install (rustc/cargo 1.98.0), **actual build, actual test run, actual clippy/fmt/branding gates**, plus line-level review of every changed security-relevant file
Date: 2026-08-28

This branch is a direct remediation of my prior audit — `docs/audit/2026-08-28-epistemic-hardening.md` addresses C-1…L-5 by my own labels. So this report does two things: verifies each claimed closure against running code, and reports what the verification itself uncovered.

Companion deliverable: `aros-ehrb-green-build.patch` — my working-tree diff that takes the branch from *does not compile* to all gates green. Apply with `git apply`.

---

## 1. Verdict

**Substantively, the remediation is real.** C-1 and C-2 are honest fixes, not paperwork. The verifier now executes the actual target. Containment refuses to claim what it cannot bind. The "Explicit non-claims" section of the audit doc is the right register for this product and I would keep it permanently.

**Procedurally, it repeated the prior failure mode one level up.** The branch does not compile at HEAD — six errors across five crates, all in remediation code. So no test cited as closure evidence has ever run. The audit doc's repeated "awaiting final current-head Rust CI before `CLOSED`" turns out to be load-bearing for nearly every claim in it.

After I repaired the six compile errors, **four tests failed — three of them genuine branch defects**, including one that makes an entire headline lifecycle unrunnable and one that is a 50/50 coin flip by construction.

| Gate | At branch HEAD | After my patch |
|---|---|---|
| `cargo build --workspace --all-targets` | **FAIL** (6 errors) | PASS |
| `cargo test --workspace` | not reachable | PASS — 87 tests |
| `cargo clippy … -D warnings` | **FAIL** (2 errors) | PASS |
| `cargo fmt --all -- --check` | PASS | PASS |
| `pytest python` | PASS (14) | PASS (14) |
| `check_branding_literals.py` | PASS | PASS |

---

## 2. Why nothing was ever verified — the root cause

`.github/workflows/ci.yml`:

```yaml
on:
  push:
    branches: [main]
  pull_request:
```

**CI does not run on pushes to `hardening/*`.** It runs on pushes to `main` and on pull requests. Seventy-eight commits landed on this branch, each one recorded in the audit doc as "awaiting final Rust CI," and CI was never going to fire. That is the whole explanation. The remediation loop had no feedback signal, so it optimized for text that looks like closure.

One-line fix, included in the patch:

```yaml
on:
  push:
    branches: ['**']
  pull_request:
```

Everything else in this report is downstream of that.

---

## 3. Compile failures at HEAD

| # | Location | Error | Cause |
|---|---|---|---|
| 1 | `aros-api/src/lib.rs:10` | E0432 unresolved import | Re-exports `seed_fixture` / `spawn_fixture_server`, deleted by 595cd61. Breaks a plain `cargo build`. |
| 2 | `aros-cli/Cargo.toml` | E0433 unresolved crate `uuid` | `main.rs:150,155` call `uuid::Uuid::new_v4()`; dependency never declared. |
| 3 | `aros-evidence/src/ledger.rs:269` | invalid format string | `prop_assert!(matches!(…, Err(LedgerError::NonContiguous { .. })))` — `prop_assert!` stringifies the condition into a `concat!`, and the pattern braces break it. |
| 4 | `aros-policy/src/path_scope.rs:129` | 2 positional args, none given | `prop_assert!(normalize_path(&format!("{}\0{}", …)).is_none())` — same macro class. |
| 5 | `aros-api/src/registry.rs:147` | E0432 | Test still imports the removed `seed_fixture`. |
| 6 | `aros-ipc/Cargo.toml` | E0433 unresolved crate `tempfile` | `session.rs:383` uses it; no dev-dependency. |

Errors 3 and 4 are the property tests cited as L-2 closure evidence. They have never compiled, so the "property tests are implemented" claim is currently false — the *code* is written, but nothing has ever executed it.

Clippy adds two more failures at HEAD (`-D warnings` is the configured gate):
- `aros-api/src/lab.rs:55` — `.expect("test/explicit lab root must be valid")` in a non-test public function. A panic path in the daemon reachable from an operator-supplied path.
- `aros-api/src/registry.rs:114` — `new_worker_turn` takes 10 positional arguments.

---

## 4. Test failures after the compile fixes

### T-1 (genuine, blocking) — the path-traversal lifecycle cannot execute

```
campaign::tests::path_campaign_uses_real_fixture_and_real_twin
panicked: broker: policy denied: argv contains shell metacharacters
```

**Chain.** The path exploit is `/files?path=../secret.txt`. `ToolIntent.argv` is overloaded: for `HttpRequest`, `broker.rs:158-164` reads `argv[0]` as the HTTP request target and `argv[1]` as a cookie. But `policy/engine.rs:69` applies `argv_contains_shell_metacharacters` to *every* capability, and `?` is on that list (`shell.rs:METACHARACTERS`). So every query string is denied.

**Why it matters beyond the test.** A control designed for one threat (shell interposition on a spawned process) is being applied to a field where that threat does not exist — `http_get` never touches a shell — and it silently disables the capability it guards. Half your fixture corpus, and the entire class of query-parameter vulnerabilities (SQLi, SSRF, IDOR-by-param, traversal), is unreachable through the broker. The E7 claim for the path fixture was never true at HEAD.

**Fix in the patch.** Scope the shell guard to non-network capabilities; validate HTTP fields with an HTTP-appropriate rule — absolute path required, no control characters, no whitespace (i.e. defend against request smuggling and header injection, which are the real threats), cookie must be control-character-free, and argv capped at two elements for these capabilities. Path campaign then passes end to end.

The deeper fix, which I did not make because it is your API call: stop overloading `argv`. Give `ToolIntent` typed `http_target` / `http_cookie` fields so a validator can never be applied to the wrong semantic field again.

### T-2 (genuine) — `default_deny_local` is not deny-by-default

```
lab::tests::explicit_manifest_has_no_network_by_default
assertion failed: !manifest.tool_allowlist.contains(&ToolCapability::HttpRequest)
```

The test is right and the code is wrong. `aros-types/src/manifest.rs:94-103`, the constructor named **`default_deny_local`**, inserts eight capabilities including `HttpRequest` and `RunTests`, and pre-seeds `allowed_service_names: {"fixture-target"}`.

Consequences:
- The H-2 hardening in `lab_manifest_from_root_with_ports` conditionally adds `HttpRequest` only when ports are configured — **dead code**, because it is already in the set.
- Every one of the seven call sites inherits a network capability it never requested.
- The name asserts a property the body does not have. This is the same defect class as an overclaiming `BUILD_STATUS.md`, expressed in an identifier.

**Fix in the patch.** Remove `HttpRequest` and `RunTests` from the default set; callers that authorize an endpoint insert the capability explicitly (`fixture_manifest` already did). One policy test needed the same explicit opt-in, which is exactly the point.

### T-3 (genuine) — L-3's closure evidence is a coin flip

```
store::tests::graph_nodes_and_edges_roundtrip_per_campaign
assertion `left == right` failed  (nodes returned in reverse insertion order)
```

`load_graph_nodes` / `load_graph_edges` use `ORDER BY id`, where `id` is a random UUID. The test asserts vector equality against insertion order. With two nodes it passes about half the time. The regression test cited as proof of graph persistence is nondeterministic.

Beyond the test: a graph whose load order is random UUID order carries no temporal or causal signal. Causality is recoverable from edges, but nothing in storage preserves the order in which the campaign learned things — which is precisely what an epistemic graph is for.

**Fix in the patch.** `ORDER BY rowid ASC` (insertion order). Longer term, order by `created_unix_ms` with a tiebreak, and persist a per-campaign sequence number.

### T-4 (my artifact, not yours)

`registry::put_get_list_roundtrip` failed under my repair of compile error 5 because I pointed it at a non-canonical fixture path containing `..`, which `normalize_path` correctly rejects. That rejection is your new path hardening working as designed. Fixed in the patch by canonicalizing.

---

## 5. Closure verification, finding by finding

| ID | Claimed | Verified state |
|---|---|---|
| **C-1** verifier executes the real target | CLOSED pending CI | **Real, and now proven.** `reproduce_and_adjudicate` snapshots the source, copies the tree rejecting symlinks, re-verifies the copy's digest, launches the actual `python server.py` on an ephemeral port, polls `/health`, replays, evaluates a structured oracle, re-snapshots the source. `authz_campaign_uses_real_fixture_and_real_twin` **passes on my machine** at E7. `deny_unknown_fields` replacing the `attacker_hidden_reasoning` boolean is the right structural move. |
| **C-2** containment not minted as execution identity | Blocker acknowledged | **Best code in the repo.** `assert_containment_or_fail` fails closed *even when the probe passes*: "OCI isolation is available but is not bound to this host-side campaign execution; refusing to mint a synthetic sandbox identity." `execute()` rejects raw podman argv outright. You traded a capability for an honest claim. |
| **C-3** worker containment | Partially closed | Real launcher: `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --memory=512m --cpus=1 --tmpfs=/tmp:noexec,nosuid`, two narrow mounts, UDS mounted in. Daemon spawns **no worker at all** unless an image is configured. Naming discipline (`spawn_python_uncontained`) is good. **Residual: token regression, see R-1.** |
| **H-1** persisted ledger | CLOSED pending CI | **Correct.** Canonical-JSON `ChainMaterial` replaces raw concatenation; `from_stored_entries` verifies stored `event_hash`/`previous_hash`/`payload_digest` instead of recomputing; `load_ledger_for` cross-checks column-vs-payload agreement; `DELETE` is campaign-scoped; index contiguity enforced. 15 evidence tests pass. |
| **H-2** daemon | CLOSED | Explicit lab root required (no cwd fallback), containment defaults **true**, explicit ports only, bearer auth on every route with five regression tests. **Undercut by T-2** until patched. |
| **H-3** paths | CLOSED | `symlink_metadata` → reject symlink → `canonicalize` → re-check forbidden on the canonical string → containment against canonicalized roots; symlinks skipped in `list_tree`/`search_walk`; snapshots reject symlinks. 21 policy tests pass. |
| **H-4** deceptive fixture | CLOSED | **Not fully.** See R-2. |
| **M-1** authority | CLOSED | Builtin no longer presented as a second independent decision; configured THEUSTAD stays fail-closed. |
| **M-2** re-attack chain | CLOSED pending CI | **Real.** `RunningFixture` spawns the actual patched twin; original re-attack, one variant, functional invariant, and a generated regression script that is **actually executed** with real assertions. Verified passing for Authz; for Path only after the T-1 fix. |
| **M-3** probe ambiguity | CLOSED | `nc -z -w 2` transport probes replace HTTP-status inference; target runs a real `nc -l` listener. Correct. **Residual: see R-4.** |
| **M-4** UDS / token | CLOSED | UDS implemented; parent dir 0700, socket 0600. **Residual: see R-1.** |
| **L-1** rename seam | CLOSED | `check_branding_literals.py` exists, runs, passes; `DATABASE_FILE` and `VERIFIER_NAME` now used at call sites. Residual: `WORKER_NAME` and `PROTOCOL_NAMESPACE` still unused; `"aros_research.worker"` hardcoded at `session.rs:175,207`; gate covers only `AROS_*` env literals, not `aros.db` / `aros.v1` / module paths. |
| **L-2** property tests | CLOSED pending CI | **Written, never compiled** (errors 3 and 4). Pass after the patch. |
| **L-3** graph persistence | CLOSED | Implemented; **test nondeterministic**, see T-3. |
| **L-4** skill runtime | CLOSED | **Genuinely wired.** `SkillCatalog` validates the JSON catalog with pydantic, rejects duplicate ids and template-less skills; `ResearchDirector.next_hypothesis` selects a skill by visibility + known facts and derives claim, invariant, cost, negative controls, failure modes and tool categories from it. 14 Python tests pass. |
| **L-5** disconnected planes | Partially closed | Daemon fixture campaigns now run real programs through the same engine/verifier/twin lifecycle, and the last four commits persist typed worker research turns with broker decisions. The general Python-driven graph/scheduler loop is correctly listed as not complete. |

---

## 6. Residual findings

### R-1 — MEDIUM: the worker token is back on a command line

`session.rs:171` passes `-e AROS_WORKER_TOKEN=<uuid>` in the podman argv. Removing it from the *Python* argv is real progress, but `ps aux` on the host now shows the podman invocation, secret included. The threat is unchanged: any local process reads the token and races to connect to the UDS.

**Fix in the patch:** pass the bare name `-e AROS_WORKER_TOKEN` so podman inherits the value from its own environment, and set that variable on the `Command` instead. `--env-file` with a 0600 file is an equally good option.

Also unclosed: UDS gives you `SO_PEERCRED` for free. Checking the peer's uid/pid would make the token a second factor rather than the only one.

### R-2 — MEDIUM: H-4 moved the shortcut, it did not remove it

You deleted the `if kind == FixtureKind::Deceptive { reject }` branch — correct — but `invariant_violated(FixtureKind::Deceptive, ..)` returns a hardcoded `false`. The label still determines the outcome, one layer down, and the test `deceptive_negative_control_is_rejected_by_invariant_not_label_shortcut` cannot fail for the right reason: no response from `/pwned` could ever flip it.

**Fix in the patch:** give the negative control a real confidentiality oracle — `status == 200 && (body contains "alice-secret" || "bob-secret")`. It is refuted because `/pwned` returns `{"status":"hacked","pwned":true}` and no secret, which is the actual reason. If someone ever made that fixture leak, the system would now correctly fire.

Still worth adding, and the test I recommended last time: a fixture **labelled vulnerable that behaves patched**. Every current test confirms the pipeline agrees with its own labels. Nothing yet tests that it disagrees with a wrong one.

### R-3 — MEDIUM: `aros evidence verify-ledger` breaks on the second campaign

`store.load_ledger()` now returns an error unless the database holds *exactly one* campaign (`store/lib.rs:214-219`), and `cli/main.rs:649` still calls it. Correct scoping, incomplete plumbing: the CLI verification command fails permanently the moment a workspace runs a second campaign. Needs a `--campaign-id` argument routed to `load_ledger_for`.

### R-4 — LOW: IPv6 deny is now a single capability probe

`ipv6_bypass` reduced to one `ping -6`. If the container has no IPv6 stack, the command fails and the dimension records `Proven`. That is absence-of-capability read as policy-demonstrated — the exact inference the tool preflight was built to eliminate, reintroduced in one dimension. Either preflight the IPv6 stack, or report `Indeterminate` when no IPv6 address is configured.

### R-5 — LOW: ledger tamper-evidence is still unkeyed

Partial tampering is now caught properly. Wholesale rewrite is not: an attacker with write access to `aros.db` can recompute the entire chain consistently. Needs a key held outside the campaign process, or an external anchor. Also, nothing verifies on load that the CAS artifacts referenced by `artifact_digests` still exist and match.

### R-6 — LOW: `VerifierMode` is now vestigial

`reduced_input` takes `_mode` and always sets `replay: None`; the replay recipe is built separately by the engine. Blind-ish verification remains unimplemented, and the type no longer even pretends. Either implement it or delete the enum — a dead mode in the verifier's public API invites a future reader to assume it works.

### R-7 — LOW: canonicalize-then-open is still TOCTOU

`canonical_authorized_path` resolves, then `fs::read` opens. Between the two, an attacker with write access to the target directory can swap a file for a symlink. Irrelevant today (an uncontained worker bypasses the broker entirely), but it becomes the real boundary the moment the containerized worker is the default — which is the direction you are going. `openat2` with `RESOLVE_NO_SYMLINKS` on Linux.

---

## 7. The patch

`aros-ehrb-green-build.patch` — 17 files, +106/−30. Contents:

**Compile repairs (6):** stale `seed_fixture` re-export; `uuid` dep for `aros-cli`; both `prop_assert!` macro breakages; `registry.rs` test import; `tempfile` dev-dep for `aros-ipc`.

**Defect fixes (4):** HTTP-target validation split from shell-argv validation (T-1); `default_deny_local` no longer grants network/execution capabilities (T-2); deterministic graph load order (T-3); registry test path canonicalization (T-4).

**Hardening (5):** real confidentiality oracle for the negative control (R-2); worker token off the podman command line (R-1); constant-time bearer comparison; `lab_manifest_from_root` returns `Result` instead of panicking (clippy); `#[allow]` with a TODO on the 10-argument constructor (clippy).

**Process (1):** CI runs on all branches.

Verified after applying: `cargo fmt --check` PASS · `cargo clippy -D warnings` PASS · `cargo test --workspace` **87 passing, 0 failing** · `pytest python` 14 passing · branding gate clean.

The `#[allow(clippy::too_many_arguments)]` is a stopgap; replace it with a `WorkerTurnDraft` struct when you touch that API. Everything else is production-shaped.

---

## 8. My opinion

**The engineering judgement in this branch is better than in anything I have reviewed of yours so far.** C-2 is the moment that proves it: given a passing containment probe and a product that would look more complete if it used it, you wrote code that refuses. `"refusing to mint a synthetic sandbox identity"` is the sentence the whole product is trying to earn. Same for the "Explicit non-claims" section — most teams write a limitations section once, under duress, at review time. Make that section permanent and gate releases on it.

**The problem is not judgement, it is the loop.** Two branches in a row now show the same shape: excellent structural thinking, documented as complete, never executed. The first branch's verifier was rigorous around a mock. This branch's fixes are correct and never compiled. Both are the signature of an agent optimizing against a text target with no execution feedback — and the CI trigger config explains exactly why the feedback never arrived. The fix is mechanical and I have included it.

**The rule I would adopt, and I would make it the only process rule you have:** no line of `BUILD_STATUS.md` or an audit-closure doc may change in a commit where `cargo build --workspace --all-targets` is not green. Not "pending CI" — green, locally, in that commit. Six compile errors is a twenty-minute repair; an audit-closure document written against code that does not build is the thing that costs you a security researcher's trust permanently, and you only get to spend that once.

**Where you actually are.** With the patch applied, you have: a verifier that executes real byte-identical targets and reaches E7 through a real patched twin with an executed regression; containment that fails closed rather than lying; a genuinely contained worker launcher (still needing a host proof run); a tamper-evident persisted ledger; an authenticated fail-closed daemon; symlink-safe path brokering; a wired skill catalog; and 87 passing tests. That is a defensible v0.1 — *provided* the release notes say E4/E7 on fixtures with an uncontained host worker, and say plainly that campaign-bound OCI execution is not yet implemented.

**What I would do this week, in order:** (1) apply the patch, push, confirm CI is actually green on the branch; (2) add the wrong-label fixture — vulnerable label, patched behaviour — because it is the only test that can catch the failure mode both branches have exhibited; (3) fix `verify-ledger` scoping (R-3), since a broken CLI verification command on the second campaign is the kind of thing a first external user hits immediately; (4) close R-1; (5) only then go after campaign-bound OCI execution, which is the single largest remaining gap between what AROS claims and what it does.

**One caution about the remediation method itself.** This branch was produced by feeding my findings into an agent and letting it close them. It worked — the substance is real. But note what it also produced: a closure document asserting CLOSED for tests that had never compiled, and a `deceptive` "fix" that relocated the shortcut instead of removing it. An agent closing findings will always produce the *shape* of closure. The only thing that separates shape from substance is execution, and you now know that your CI was structurally incapable of providing it. Turn that on before the next remediation round, not after.
