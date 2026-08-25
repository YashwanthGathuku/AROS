#!/usr/bin/env bash
# AROS v0.1 acceptance gate. Never exits 0 while claiming live OCI if missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
note() { printf '\n== %s ==\n' "$1"; }

note "A. Build"
cargo build --workspace || FAIL=1
PYTHONPATH=python python -c "import aros_research; print(aros_research.__version__)" || FAIL=1

note "fmt/clippy/unit"
cargo fmt --all -- --check || FAIL=1
cargo clippy --workspace --all-targets --all-features -- -D warnings || FAIL=1
cargo test --workspace || FAIL=1
PYTHONPATH=python python -m pytest python -q || FAIL=1
python -m ruff check python || FAIL=1
python -m mypy python/aros_research || FAIL=1

note "B. Policy"
cargo test -p aros-policy public_internet_denied docker_socket_and_ssh_key_denied -- --nocapture || FAIL=1

note "C. Sandbox (fail-closed if OCI missing; live isolation not claimed)"
cargo test -p aros-sandbox oci_without_runtime_fails_closed fake_never_claims_containment -- --nocapture || FAIL=1
cargo test -p aros-core fail_closed_without_containment_waiver -- --nocapture || FAIL=1

note "D. Snapshot + L original integrity"
cargo test -p aros-core mock_authz_lifecycle_with_waiver -- --nocapture || FAIL=1

note "E/F. Research + verification (authz fixture)"
cargo test -p aros-core mock_authz_lifecycle_with_waiver -- --nocapture || FAIL=1

note "G. Falsification (deceptive fixture)"
cargo test -p aros-core mock_deceptive_is_rejected -- --nocapture || FAIL=1

note "H. Evidence tamper"
cargo test -p aros-evidence verify_detects_payload_tamper -- --nocapture || FAIL=1

note "I/J/K. Remediation / reattack / regression (twin in mock lifecycle)"
cargo test -p aros-core mock_authz_lifecycle_with_waiver mock_path_lifecycle_with_waiver -- --nocapture || FAIL=1

note "README cannot expand capabilities"
cargo test -p aros-core target_readme_cannot_expand_capabilities -- --nocapture || FAIL=1

if [[ "$FAIL" -ne 0 ]]; then
  echo "ACCEPTANCE FAILED"
  exit 1
fi
echo "ACCEPTANCE: automatable checks passed on this host."
echo "ACCEPTANCE C live OCI isolation is NOT claimed unless doctor shows a demonstrated runtime."
exit 0
