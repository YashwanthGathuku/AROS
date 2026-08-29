# Epistemic hardening audit closure — 2026-08-28

This branch repairs the findings from the 2026-08-28 deep audit. It deliberately downgrades claims when execution is not actually bound to the claimed boundary.

## Closure policy

A finding is only marked `CLOSED` when code plus a regression test exists and the current branch CI passes. Host-specific OCI measurements remain local acceptance evidence and are not inferred from source review.

## Current workstreams

- C-1 verifier executes the actual byte-identical target: implementation and integration regressions added; awaiting final current-head Rust CI before `CLOSED`.
- C-2 containment capability is no longer minted as campaign execution identity: raw Podman argv execution disabled. Campaign-bound target sandbox remains a release blocker when containment is required; the engine fails closed instead of converting a capability probe into containment evidence.
- C-3 Python worker: UDS production transport, token removed from argv, isolated rootless-container launcher implemented; host worker requires explicit waiver. Host container proof remains local acceptance work.
- H-1 persisted ledger: stored hashes verified; campaign-scoped persistence; canonical structured chain material; SQLite tamper and cross-campaign tests added; awaiting final current-head Rust CI.
- H-2 daemon: explicit lab root, containment default true, explicit ports only, bearer authentication required. CLI remote POST/GET now require the same bearer token, and the auth predicate has missing/wrong/scheme/exact-token regression tests.
- H-3 paths: broker canonicalizes real paths and rejects/does not traverse symlinks; exact target snapshots reject symlinks; property tests added.
- H-4 deceptive fixture: outcome now depends on the invariant oracle, not the fixture enum shortcut.
- M-1 builtin authority is no longer presented as a second independent decision after local E4; optional THEUSTAD remains fail-closed when configured.
- M-2 patched twin is an actual process; original reattack, variant, functional invariant, and generated regression are executed before E7.
- M-3 containment HTTP-status ambiguity: egress reachability probes use transport (`nc`) rather than HTTP status.
- M-4 UDS implemented for Unix/WSL; loopback TCP is development/test transport; worker token is delivered by environment rather than argv.
- L-1 rename seam: Rust and Python environment-name compatibility helpers are centralized; internal fixture port names are product-neutral; CI fails on new raw `AROS_*` runtime literals outside the compatibility definition files.
- L-2 property tests: path scope, network scope, canonical serialization, and evidence-chain mutation/determinism properties are implemented; awaiting final Rust CI.
- L-3 graph persistence: campaign-scoped SQLite node/edge roundtrip implemented. Fixture lifecycle records causal surface → assumption → hypothesis → experiment → observation relations and persists the graph; broader anomaly/failure/telemetry graph behavior remains in progress.
- L-4 ResearchSkill runtime wiring: the director loads/validates the JSON methodology catalog and derives hypothesis/negative-control/tool metadata from selected skills. Python regression tests are green on the branch.
- L-5 daemon fixture campaigns execute real fixture programs and feed the same engine/verifier/twin lifecycle. A general Python-driven autonomous graph/scheduler loop remains in progress and is not claimed complete.

## Explicit non-claims

- A five-way `ContainmentReport` does not mean a campaign used that network.
- Campaign-bound OCI target execution is not yet implemented; containment-required campaigns fail closed rather than claim it.
- E5 minimized reproduction is not yet a distinct executed proof.
- The host research worker is not contained and is disabled by default.
- Graph persistence does not mean anomaly notebook, failure memory, or telemetry are complete.
- The skill-driven Python research planner is not yet the general campaign state machine.
- No MVP tag is justified until final Rust/Python CI and the host-specific containment/runtime acceptance gate pass.
