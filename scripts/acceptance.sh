#!/usr/bin/env bash
# AROS v0.1 acceptance gate. Never exits 0 unless required checks pass.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
note() { printf '\n== %s ==\n' "$1"; }

note "A. Build"
cargo build --workspace || FAIL=1
python -c "import sys; sys.path.insert(0,'python'); import aros_research; print(aros_research.__version__)" || FAIL=1

note "fmt"
cargo fmt --all -- --check || FAIL=1

note "clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings || FAIL=1

note "unit tests"
cargo test --workspace || FAIL=1
python -m pytest python -q || FAIL=1

if command -v ruff >/dev/null 2>&1; then
  ruff check python || FAIL=1
else
  python -m ruff check python || FAIL=1
fi

if command -v mypy >/dev/null 2>&1; then
  mypy python/aros_research || true
fi

note "B. Policy deny"
cargo test -p aros-policy -- --nocapture || FAIL=1

note "C. Sandbox containment"
if cargo test -p aros-sandbox oci_without_runtime_fails_closed -- --nocapture; then
  echo "C: fail-closed without OCI is proven."
  echo "C: live network isolation NOT claimed (see doctor / BUILD_STATUS)."
else
  FAIL=1
fi

note "H. Evidence tamper"
cargo test -p aros-evidence verify_detects_payload_tamper -- --nocapture || FAIL=1

note "L. Original integrity (engine test)"
cargo test -p aros-core mock_authz_lifecycle_with_waiver -- --nocapture || FAIL=1

note "Fail-closed without waiver"
cargo test -p aros-core fail_closed_without_containment_waiver -- --nocapture || FAIL=1

if [[ "$FAIL" -ne 0 ]]; then
  echo "ACCEPTANCE FAILED"
  exit 1
fi
echo "ACCEPTANCE CHECKS THAT ARE AUTOMATABLE ON THIS HOST PASSED"
echo "Live OCI isolation (acceptance C full) is NOT claimed without demonstrated containment."
exit 0
