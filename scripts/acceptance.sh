#!/usr/bin/env bash
# AROS v0.1 acceptance gate. Never exits 0 while claiming live OCI if missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
note() { printf '\n== %s ==\n' "$1"; }

note "A. Build"
cargo build --workspace || FAIL=1
cargo build -p aros-core --bin aros-verifier || FAIL=1
PYTHONPATH=python python3 -c "import aros_research; print(aros_research.__version__)" || FAIL=1

note "fmt/clippy/unit"
cargo fmt --all -- --check || FAIL=1
cargo clippy --workspace --all-targets --all-features -- -D warnings || FAIL=1
cargo test --workspace || FAIL=1
PYTHONPATH=python python3 -m pytest python -q || FAIL=1
python3 -m ruff check python || true
python3 -m mypy python/aros_research || true

note "B. Policy"
cargo test -p aros-policy -- --nocapture || FAIL=1

note "C. Sandbox (fail-closed if OCI missing; live isolation not claimed)"
cargo test -p aros-sandbox -- --nocapture || FAIL=1
cargo test -p aros-core fail_closed_without_containment_waiver -- --nocapture || FAIL=1
cargo test -p aros-sandbox containment_report_never_claims_live_without_runtime -- --nocapture || FAIL=1
cargo test -p aros-sandbox live_oci_claimable_requires_packet_probes -- --nocapture || FAIL=1

note "D. Snapshot + L original integrity (live re-attack)"
cargo test -p aros-core mock_authz_lifecycle_with_live_reattack -- --nocapture || FAIL=1

note "E/F. Research + independent verification"
cargo test -p aros-core mock_authz_lifecycle_with_live_reattack -- --nocapture || FAIL=1
cargo test -p aros-core verifier -- --nocapture || FAIL=1
cargo test -p aros-core --test verifier_subprocess -- --nocapture || FAIL=1
cargo test -p aros-evidence --lib -- --nocapture || FAIL=1

note "G. Falsification (deceptive fixture)"
cargo test -p aros-core mock_deceptive_is_rejected -- --nocapture || FAIL=1

note "H. Evidence tamper"
cargo test -p aros-evidence -- --nocapture || FAIL=1

note "I/J/K. Remediation / reattack / regression"
cargo test -p aros-core mock_authz_lifecycle_with_live_reattack mock_path_lifecycle_with_live_reattack -- --nocapture || FAIL=1

note "Campaign registry + LabRuntime"
cargo test -p aros-api --lib -- --nocapture || FAIL=1

note "README cannot expand capabilities"
cargo test -p aros-core target_readme_cannot_expand_capabilities -- --nocapture || FAIL=1

note "Containment report (honest; does not claim live OCI)"
if cargo test -p aros-sandbox containment_report_is_honest_on_this_host -- --nocapture; then
  :
else
  FAIL=1
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "ACCEPTANCE FAILED"
  exit 1
fi
echo "ACCEPTANCE: automatable checks passed on this host."
echo "ACCEPTANCE C live OCI isolation is NOT claimed unless ContainmentReport.live_oci_claimable() is true."
exit 0
