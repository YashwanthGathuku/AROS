#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "AROS bootstrap"
rustc --version
cargo --version
python --version || python3 --version
echo "Install Python 3.14 in WSL when available (ADR-0003)."
echo "Install Podman rootless in WSL for live containment."
cargo fetch
echo "bootstrap complete"
