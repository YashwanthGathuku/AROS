# Using AROS on another project

AROS does not scan the public internet. v0.1 tests a tree you already have, on loopback, under policy. The certificate from that run is what you keep.

Nothing in this note writes a harness into the other project. Catalog runners stay in `campaign-loader/harnesses/` and `campaign-loader/adapters/`.

## What you can test today

### 1. A source checkout

Point a class campaign at the checkout. The original tree is snapshotted and must stay unchanged.

```text
aros campaign map --target PATH/TO/CHECKOUT --out data/work/surface.json
aros campaign plan --target PATH/TO/CHECKOUT --work data/plan-work --pack http
aros campaign run --spec campaign-loader/classes/http-idor.campaign.json ^
  --target PATH/TO/CHECKOUT --work data/work --operator-waive-containment
aros evidence verify --work data/work
```

`--operator-waive-containment` is host execution. The certificate will verify the statement and will not be `release_eligible`. Drop the waiver only where a proven rootless container actually runs the generator. Without that, the run fails closed. That is the intended result.

HTTP classes start `server.py` from the target, or use `bind.port` if something is already listening on loopback. CLI classes look for `parse.py`. Replay classes look for `once.py`. If the tree has neither, the campaign does not invent a result.

Override `generator.bind` in a copy of the campaign when the routes are not `/users/2` and `/files`. `overlay_surface_bind` fills IDOR paths from `surface.json` when you wire that overlay; the map file itself is the discovery step.

### 2. A patched twin

A second checkout or a fix branch is the twin. It is copied under the work directory and not modified.

```text
aros campaign run --spec campaign-loader/classes/http-idor.campaign.json ^
  --target PATH/VULN --twin PATH/PATCHED --work data/work ^
  --operator-waive-containment
```

E6 means the same campaign holds on the twin. E7 means a related variant also holds and `e7-regression/regression_test.py` executed. No variant means the result stays at E6.

### 3. A pinned external repo, via an adapter

The dycrpt campaigns are the pattern: pin a revision, put the glue in `campaign-loader/adapters/`, call the real function (`decrypt`), write nothing into that repo. Empty trees fail closed. Required evidence is E2+E4. The run is not contained unless the container proof exists.

Use this for a library you depend on. Do not clone the campaign into the library.

### 4. The release gate

```text
aros campaign gate --target PATH/TO/CHECKOUT --work data/gate-work --pack http
```

Unwaived, this fails closed when containment cannot be shown. Waived, it fails the release if any planned class verifies a break. A pass is "this pack did not verify a break under the waiver," not "the project is safe."

## How to find projects worth a run

| Source | Use it when |
|---|---|
| Repos you ship | This is the point of AROS. Map, run the class pack, keep the certificate with the commit. |
| A fix branch of the same repo | Pass it as `--twin`. |
| A dependency at a pinned commit | Write an adapter beside AROS, not inside the dependency. |
| A local lab tree you control | Same commands as the fixtures under `fixtures/`. |

Do not use AROS to discover random internet hosts, CTF scoreboards, or any target you cannot authorize and snapshot.

## What a foreign tree must have before a class can say anything

| Tree contains | Campaigns that can run |
|---|---|
| `server.py` or a loopback port in `bind.port` | HTTP classes and MST-wi relations |
| Quoted routes or a `surface.json` | `http-surface-map`, then the planner |
| `parse.py` | `cli-crash`, `mutate-fuzz`, `prop-ascii`, `klee-run` (KLEE only with bitcode) |
| `once.py` | `lib-call-twice` |
| A Rust crate the adapter path-depends on | the dycrpt-style adapter |

If none of those are present, AROS should record a failure or hold, not a vulnerability.

## What is still not a way to test other projects

- Public internet targets.
- An LLM reading the source and declaring a bug.
- Copying harness files into the other repo.
- Treating `release_eligible: false` as a ship decision, or treating a waived pass as containment.
- The Berkeley CyberGym corpus. The local PoC pack is only the fixtures in this repo.
