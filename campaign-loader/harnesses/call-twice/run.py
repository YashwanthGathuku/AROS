"""Invoke a public entrypoint twice. Writes nothing into the target."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def run_once(entry: str, cwd: str, stamp: str) -> tuple[int, str]:
    env = os.environ.copy()
    env["AROS_ONCE_STAMP"] = stamp
    completed = subprocess.run(
        [sys.executable, entry],
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
    )
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    return int(completed.returncode), text


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    entry = os.path.join(target, bind.get("entry", "once.py"))
    if not os.path.isfile(entry):
        sys.stderr.write("call-twice: entry is missing\n")
        return 2
    stamp_dir = tempfile.mkdtemp(prefix="aros-once-")
    stamp = os.path.join(stamp_dir, "used")
    print(bind.get("open_token", "OPEN_OK"))
    code1, _out1 = run_once(entry, target, stamp)
    code2, out2 = run_once(entry, target, stamp)
    second_ok = code2 == 0 and "FAIL" not in out2
    if code1 == 0 and second_ok:
        print(bind.get("success_token", "REPLAY_ACCEPTED"))
    else:
        print(bind.get("hold_token", "REPLAY_REJECTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
