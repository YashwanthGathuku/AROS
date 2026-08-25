#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Demo against the in-process test server is covered by cargo tests.
# This script starts the local authz fixture and runs a waived lab campaign
# only when --operator-waive-containment is passed through.
WAIVE="${1:-}"
python fixtures/vulnerable/authz/server.py &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 0.5
if [[ "$WAIVE" == "--operator-waive-containment" ]]; then
  cargo run -p aros-cli -- demo --fixture authz --port 18080 --operator-waive-containment
else
  echo "Refusing demo without demonstrated containment."
  echo "Re-run: ./scripts/demo.sh --operator-waive-containment"
  exit 2
fi
