"""Optional KLEE adapter. Fail closed when the binary or bitcode is absent. No LLM."""

from __future__ import annotations

import json
import os
import shutil
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


def main() -> int:
    bind = load_bind()
    print(bind.get("open_token", "OPEN_OK"))
    klee = os.environ.get("AROS_KLEE", "").strip() or shutil.which("klee")
    if klee is None:
        sys.stderr.write("KLEE unavailable; symbolic class skipped (not a security result)\n")
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    bitcode = bind.get("bitcode", "").strip()
    if not bitcode:
        sys.stderr.write("klee present but no bitcode bind; refusing to invent a run\n")
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    bitcode_path = bitcode if os.path.isabs(bitcode) else os.path.join(target, bitcode)
    if not os.path.isfile(bitcode_path):
        sys.stderr.write("klee bitcode missing; refusing to invent a run\n")
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    argv = [klee]
    if klee.endswith(".py"):
        argv = [sys.executable, klee]
    with tempfile.TemporaryDirectory(prefix="aros-klee-") as work:
        try:
            completed = subprocess.run(
                [*argv, "--output-dir", work, bitcode_path],
                capture_output=True,
                timeout=int(bind.get("klee_seconds", "8")),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            sys.stderr.write("klee invocation failed; not a security result\n")
            print(bind.get("hold_token", "REPLAY_REJECTED"))
            return 0
        for root, _dirs, files in os.walk(work):
            for name in files:
                if name.endswith(".ktest") or name.endswith(".err"):
                    sys.stderr.write(f"KLEE_CASE {os.path.join(root, name)}\n")
                    print(bind.get("success_token", "REPLAY_ACCEPTED"))
                    return 0
        text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        if "KLEE: ERROR" in text or "ASSERTION FAIL" in text:
            print(bind.get("success_token", "REPLAY_ACCEPTED"))
            return 0
    sys.stderr.write("klee ran without a crashing test case\n")
    print(bind.get("hold_token", "REPLAY_REJECTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
