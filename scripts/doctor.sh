#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -x "$ROOT/target/debug/aros" ]]; then
  "$ROOT/target/debug/aros" doctor
else
  cargo run -p aros-cli --quiet -- doctor
fi
