#!/usr/bin/env bash
# Release gate: fail if a class is Verified or containment cannot be shown.
# Usage: ./scripts/gate.sh <target> [work] [pack]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGET="${1:?target tree required}"
WORK="${2:-data/gate-work}"
PACK="${3:-http}"
WAIVE="${AROS_GATE_WAIVE_CONTAINMENT:-0}"
ARGS=(campaign gate --target "$TARGET" --work "$WORK" --pack "$PACK")
if [[ "$WAIVE" == "1" ]]; then
  ARGS+=(--operator-waive-containment)
fi
exec cargo run -q -p aros-cli -- "${ARGS[@]}"
