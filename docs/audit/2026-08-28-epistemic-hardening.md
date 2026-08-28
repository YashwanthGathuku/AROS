# Epistemic hardening audit closure — 2026-08-28

This branch repairs the findings from the 2026-08-28 deep audit. It deliberately downgrades claims when execution is not actually bound to the claimed boundary.

## Closure policy

A finding is only marked `CLOSED` when code plus a regression test exists. Host-specific OCI measurements remain local acceptance evidence and are not inferred from source review.

## Current workstreams

- C-1 verifier executes the actual byte-identical target: implemented; integration tests updated.
- C-2 containment capability is no longer minted as campaign execution identity: implemented; raw Podman argv execution disabled. Campaign-bound target sandbox remains a release blocker when containment is required.
- C-3 Python worker: UDS production transport, token removed from argv, isolated rootless-container launcher implemented; host worker requires explicit waiver.
- H-1 persisted ledger: stored hashes verified; campaign-scoped persistence; SQLite tamper and cross-campaign tests added.
- H-2 daemon: explicit lab root, containment default true, explicit ports only, bearer authentication required.
- H-3 paths: broker canonicalizes real paths and rejects/does not traverse symlinks; exact target snapshots reject symlinks.
- H-4 deceptive fixture: outcome now depends on the invariant oracle, not the fixture enum shortcut.
- M-1 builtin authority is no longer presented as a second independent decision after local E4; optional THEUSTAD remains fail-closed when configured.
- M-2 patched twin is an actual process; original reattack, variant, functional invariant, and generated regression are executed before E7.
- M-3 containment HTTP-status ambiguity: egress reachability probes use transport (`nc`) rather than HTTP status.
- M-4 UDS implemented for Unix/WSL; loopback TCP is development/test transport.
- L-1 rename seam coverage and CI literal gate: in progress.
- L-2 property tests: path invariants added; trusted-core suite expansion in progress.
- L-3 graph persistence and research-model wiring: in progress.
- L-4 ResearchSkill runtime wiring: in progress.
- L-5 daemon fixture campaigns now execute real fixture programs; Python research-loop integration remains in progress.
