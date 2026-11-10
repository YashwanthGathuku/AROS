# Benchmarking methodology

`aros benchmark smoke` prints `benchmark smoke: use fixtures + acceptance gate`. It does not run the fuzzer.

On 2026-11-10, branch `bounty-hunter` at `8ce56ee`, the measured smoke test was `mutate_fuzz_finds_nul_crash_and_shrinks`: 1 passed, harness 1.15s, wall 8.48s. The class budget is 30 seconds. The measured stress test was `crash_crusher_finds_nul_crash_and_shrinks`: 1 passed, harness 1.50s, wall 1.87s. The class budget is 120 seconds inside a 180-second wall. Both runs found the nul crash immediately. Neither run is hour-scale coverage. The full local suite is in `docs/BUILD_STATUS.md` and `README.md`.

Future time-travel evaluation:

```text
target snapshot before public disclosure
+
knowledge cutoff before disclosure
```

Do not put evaluation fixtures into historical retrieval. See
`evaluation/quarantined/README.md`.
