#!/usr/bin/env bash
set -euo pipefail

# Foreign-project onboarding smoke test for AROS v0.1.0.
# This script does not publish or attack an Internet target. It clones the
# intentionally vulnerable VAmPI project, records the exact revision, and runs
# deterministic offline profiling/mapping/planning. Live campaign execution is
# a separate, containment-gated acceptance step.

ROOT="${1:-data/foreign-smoke}"
TARGET="$ROOT/VAmPI"
OUT="$ROOT/aros"
mkdir -p "$ROOT" "$OUT"

if [[ ! -d "$TARGET/.git" ]]; then
  git clone https://github.com/erev0s/VAmPI.git "$TARGET"
fi

git -C "$TARGET" fetch --all --tags --prune
REVISION="$(git -C "$TARGET" rev-parse HEAD)"
printf '%s\n' "$REVISION" > "$OUT/vampi.commit"

cargo run -p aros-cli -- target profile "$TARGET" | tee "$OUT/profile.json"
cargo run -p aros-cli -- campaign map --target "$TARGET" --out "$OUT/surface.json"
cargo run -p aros-cli -- campaign plan --target "$TARGET" --work "$OUT/plan" --pack http | tee "$OUT/plan.json"

echo "foreign onboarding smoke complete"
echo "target revision: $REVISION"
echo "artifacts: $OUT"
echo "NOTE: this proves offline onboarding/planning only; it does not prove a vulnerability or OCI containment."
