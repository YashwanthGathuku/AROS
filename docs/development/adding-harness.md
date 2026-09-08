# Adding a harness

Do **not** copy experiment code into every target repository.

AROS owns reusable runners in `campaign-loader/harnesses/`. A campaign
plugs one in with `generator.harness` and optional `bind` parameters.
The pinned target tree stays unmodified. AROS stages the runner, runs it,
and snapshots its bytes into CAS.

| Catalog id | When to use it |
|---|---|
| `stdout-tokens` | Oracle/engine wiring. Bind `open_token` / `result_token`. |
| `cargo-test` | Target already has tests. Bind `test` or `filter`. |
| `http-probe` | HTTP server already listening. Bind host, port, paths, cookies, needles. |

Per-project API glue that is not generic (session setup for a crypto crate)
belongs in `campaign-loader/adapters/<project>/` **in AROS**, still not in
the target.

Command form:

```json
"generator": {
  "kind": "harness",
  "harness": "cargo-test",
  "command": "python {harness}/run.py",
  "bind": { "test": "replay" }
}
```

`{harness}` is replaced with the staged catalog directory. `corpus` remains
valid for a file that already exists in the target; prefer `harness` so the
experiment is not duplicated across projects.

`NativeHarness` is the default research-worker adapter.

`GrokBuildHarness` is capability-detected (`grok` on PATH). If Grok cannot
be invoked in CI, keep the adapter, detection, a mock test, and these
enablement notes. The rest of AROS must not depend on Grok internals.
The language model may propose a campaign/bind; it does not author the
oracle and it does not write files into the target.
