#!/usr/bin/env bash
# Publish the MVP tag only after the real local containment gate passes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TAG="v0.1.0-mvp"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "refusing to tag: working tree has uncommitted changes" >&2
  exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "refusing to overwrite existing tag $TAG" >&2
  exit 1
fi

export AROS_REQUIRE_LIVE_OCI=1
./scripts/acceptance.sh

git tag -a "$TAG" -m "AROS v0.1.0 MVP: independent verifier and demonstrated local containment"
printf 'Created local tag %s at %s\n' "$TAG" "$(git rev-parse HEAD)"
printf 'Review the acceptance output, then publish with: git push origin %s\n' "$TAG"
