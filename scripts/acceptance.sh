#!/usr/bin/env bash
# v0.1 acceptance gate. Set AROS_REQUIRE_LIVE_OCI=1 for the release/tag gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
note() { printf '\n== %s ==\n' "$1"; }

note "A. Build"
cargo build --workspace || FAIL=1
cargo build -p aros-core --bin aros-verifier || FAIL=1
PYTHONPATH=python python3 -c "import aros_research; print(aros_research.__version__)" || FAIL=1

note "Quality gates"
cargo fmt --all -- --check || FAIL=1
cargo clippy --workspace --all-targets --all-features -- -D warnings || FAIL=1
cargo test --workspace || FAIL=1
PYTHONPATH=python python3 -m pytest python -q || FAIL=1
python3 -m ruff check python || FAIL=1
python3 -m mypy python/aros_research || FAIL=1

note "B. Policy"
cargo test -p aros-policy -- --nocapture || FAIL=1

note "C. Sandbox / five-way containment semantics"
cargo test -p aros-sandbox -- --nocapture || FAIL=1
cargo test -p aros-core fail_closed_without_containment_waiver -- --nocapture || FAIL=1
cargo test -p aros-sandbox missing_runtime_never_claims -- --nocapture || FAIL=1
cargo test -p aros-sandbox live_claim_requires_all_five_proven -- --nocapture || FAIL=1
cargo test -p aros-sandbox legacy_boolean_cannot_override_indeterminate_probe -- --nocapture || FAIL=1
cargo test -p aros-sandbox combine_denials_propagates_indeterminate -- --nocapture || FAIL=1

note "D/L. Snapshot and original-target integrity"
cargo test -p aros-core mock_authz_lifecycle_with_live_reattack -- --nocapture || FAIL=1

note "E/F. Research and true independent verification"
cargo test -p aros-core verifier -- --nocapture || FAIL=1
cargo test -p aros-core --test verifier_subprocess -- --nocapture || FAIL=1
cargo test -p aros-evidence --lib -- --nocapture || FAIL=1

note "G. Falsification"
cargo test -p aros-core mock_deceptive_is_rejected -- --nocapture || FAIL=1

note "H. Evidence tamper"
cargo test -p aros-evidence -- --nocapture || FAIL=1

note "I/J/K. Remediation, reattack, regression"
cargo test -p aros-core mock_authz_lifecycle_with_live_reattack -- --nocapture || FAIL=1
cargo test -p aros-core mock_path_lifecycle_with_live_reattack -- --nocapture || FAIL=1

note "Campaign registry and LabRuntime"
cargo test -p aros-api --lib -- --nocapture || FAIL=1

note "Target content cannot expand capabilities"
cargo test -p aros-core target_readme_cannot_expand_capabilities -- --nocapture || FAIL=1

note "Fresh containment report"
cargo test -p aros-sandbox containment_report_is_honest_on_this_host -- --nocapture || FAIL=1

# Release mode additionally requires the real packet environment to be live and
# all five tri-state probes to be Proven. Doctor emits a single JSON line so the
# gate does not infer success from prose.
if [[ "${AROS_REQUIRE_LIVE_OCI:-0}" == "1" ]]; then
  note "Release-only live OCI gate"
  DOCTOR="$(cargo run -q -p aros-cli -- doctor)" || FAIL=1
  printf '%s\n' "$DOCTOR"
  REPORT="$(printf '%s\n' "$DOCTOR" | sed -n 's/^  containment_report_json: //p' | tail -n 1)"
  if [[ -z "$REPORT" ]]; then
    echo "missing containment report JSON"
    FAIL=1
  else
    REPORT_JSON="$REPORT" python3 - <<'PY' || FAIL=1
import json, os, sys
r = json.loads(os.environ["REPORT_JSON"])
required = [
    "target_reachability_probe",
    "external_egress_probe",
    "dns_bypass_probe",
    "host_gateway_probe",
    "ipv6_bypass_probe",
]
problems = []
if not r.get("runtime_present"):
    problems.append("runtime absent")
if not r.get("machine_reachable"):
    problems.append("Podman machine unreachable")
if not r.get("internal_network"):
    problems.append("internal network not demonstrated")
if not r.get("packet_probes_ran"):
    problems.append("packet probes did not run")
for key in required:
    if r.get(key) != "proven":
        problems.append(f"{key}={r.get(key)!r}")
if problems:
    print("LIVE OCI GATE FAILED: " + "; ".join(problems))
    sys.exit(1)
print("LIVE OCI GATE: all five packet dimensions Proven")
PY
  fi
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "ACCEPTANCE FAILED"
  exit 1
fi

echo "ACCEPTANCE: automatable checks passed on this host."
if [[ "${AROS_REQUIRE_LIVE_OCI:-0}" == "1" ]]; then
  echo "ACCEPTANCE C: live OCI isolation demonstrated with all five probes Proven."
else
  echo "ACCEPTANCE C live OCI is not claimed; rerun with AROS_REQUIRE_LIVE_OCI=1 for release/tagging."
fi
