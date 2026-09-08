"""Coverage-free mutational fuzzer + delta-debug shrink. No LLM, AFL optional."""

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


def crashes(entry: str, cwd: str, payload: bytes) -> bool:
    completed = subprocess.run(
        [sys.executable, entry],
        cwd=cwd,
        input=payload,
        capture_output=True,
        check=False,
    )
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    return completed.returncode != 0 or "Error" in text or "Traceback" in text


def shrink(payload: bytes, pred) -> bytes:  # noqa: ANN001
    current = payload
    chunk = max(len(current), 1)
    while chunk > 0:
        progressed = False
        offset = 0
        while offset < len(current):
            end = min(offset + chunk, len(current))
            candidate = current[:offset] + current[end:]
            if candidate and pred(candidate):
                current = candidate
                progressed = True
            else:
                offset = end
        if not progressed:
            chunk //= 2
    return current


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    entry = os.path.join(target, bind.get("entry", "parse.py"))
    if not os.path.isfile(entry):
        sys.stderr.write("mutate-fuzz: entry missing\n")
        return 2
    print(bind.get("open_token", "OPEN_OK"))
    corpus = [b"AAAA", b"\x00", b"../" * 8, os.urandom(32), b"A" * 4096]
    crashing: bytes | None = None
    for seed in corpus:
        if crashes(entry, target, seed):
            crashing = seed
            break
        mutated = bytearray(seed)
        if mutated:
            mutated[0] = 0
        if crashes(entry, target, bytes(mutated)):
            crashing = bytes(mutated)
            break
    if crashing is None:
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    minimized = shrink(crashing, lambda payload: crashes(entry, target, payload))
    sys.stderr.write(f"SHRINK_LEN {len(minimized)}\n")
    print(bind.get("success_token", "REPLAY_ACCEPTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
