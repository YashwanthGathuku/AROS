# AROS harness catalog

These runners live **in AROS**, not in the target project.

A new target should not receive a copied `redlab_*.rs`. The campaign JSON
plugs a catalog id plus `bind` parameters. AROS stages the runner next to
the pinned checkout, runs it, and snapshots the runner into CAS.

| Id | Use when |
|---|---|
| `stdout-tokens` | Engine/oracle wiring. Bind `open_token` / `result_token`. |
| `cargo-test` | The target already has tests. Bind `test` (integration test name) or `filter`. |
| `http-probe` | An HTTP server is already listening. Bind host/port/paths/cookies/needles. |

Per-project API glue that is not a generic runner (session setup for a
crypto crate, for example) belongs in `campaign-loader/adapters/<project>/`
in **this** repository — still not in the target tree.

Do not treat a catalog run as evidence that a named library invariant held
until the adapter actually calls that library.
