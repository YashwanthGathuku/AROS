# Smoke benchmarks

MVP proves bounded concurrency, not scale.

Run:

```bash
cargo test -p aros-core rejects_unbounded_experiments
cargo test -p aros-evidence
```

Do not rewrite SQLite or Python because these feel slow. Measure first.
