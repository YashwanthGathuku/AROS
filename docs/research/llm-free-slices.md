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

Tests: `http_idor_patched_twin_earns_e6` (vulnerable authz vs patched
authz), `required_e6_without_twin_is_insufficient`,
`vulnerable_twin_does_not_earn_e6`.

Still not: live five-way Podman containment; E7 regression file on declared
path; all 76 MST-wi relations; CyberGym corpus.

## Where each fact is recorded

| Kind of fact | File |
|---|---|
| Can we claim DONE? | `docs/BUILD_STATUS.md` |
| What the MVP must be | `docs/AROS_MVP_SPEC.md` |
| Paper sources / LLM-free stack | `docs/research/related-systems-papers.md` |
| Evidence level meanings | `docs/evidence/evidence-levels.md` |
| This slice history | this file |
| Campaign/adapter how-to | `campaign-loader/README.md`, `adapters/README.md` |
