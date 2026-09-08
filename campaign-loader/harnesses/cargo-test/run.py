"""Run an existing cargo test in the target tree. Writes nothing into the target."""

from __future__ import annotations

import json
import os
import subprocess
import sys


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def main() -> int:
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    manifest = os.path.join(target, "Cargo.toml")
    if not os.path.isfile(manifest):
        sys.stderr.write("AROS_ENV_MISMATCH missing Cargo.toml\n")
        return 2
    bind = load_bind()
    cmd = ["cargo", "test", "--manifest-path", manifest]
    test_name = bind.get("test", "").strip()
    filt = bind.get("filter", "").strip()
    if test_name:
        cmd.extend(["--test", test_name])
    elif filt:
        cmd.append(filt)
    cmd.extend(["--", "--nocapture"])
    completed = subprocess.run(cmd, cwd=target, check=False)
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
