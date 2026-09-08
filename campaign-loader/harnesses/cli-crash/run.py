"""Feed hostile stdin to a target CLI/parser. Writes nothing into the target."""

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
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    entry = os.path.join(target, bind.get("entry", "parse.py"))
    if not os.path.isfile(entry):
        sys.stderr.write("cli-crash: entry is missing\n")
        return 2
    payload = b"A" * 64 + b"\x00../" + b"B" * 64
    print(bind.get("open_token", "OPEN_OK"))
    completed = subprocess.run(
        [sys.executable, entry],
        cwd=target,
        input=payload,
        capture_output=True,
        check=False,
    )
    crashed = completed.returncode != 0
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if crashed or "Error" in text or "Traceback" in text:
        print(bind.get("success_token", "REPLAY_ACCEPTED"))
    else:
        print(bind.get("hold_token", "REPLAY_REJECTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
