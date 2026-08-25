# Stop hook (quality gate)

Do not declare AROS MVP complete unless:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
python -m ruff check python
python -m mypy python/aros_research
python -m pytest python
./scripts/acceptance.sh
```

Live OCI containment (acceptance C) must not be claimed when doctor reports
UNSAFE/MISCONFIGURED for the container runtime.
