"""QuickCheck-style property trials. Deterministic seed. No LLM. Target is not modified."""

from __future__ import annotations

import json
import os
import random
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


def trial_payload(rng: random.Random, alphabet: str, size: int) -> bytes:
    if alphabet == "ascii":
        return bytes(rng.randrange(32, 127) for _ in range(size))
    if alphabet == "letters":
        return bytes(rng.choice(list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")) for _ in range(size))
    return bytes(rng.randrange(1, 256) for _ in range(size))


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    entry = os.path.join(target, bind.get("entry", "parse.py"))
    if not os.path.isfile(entry):
        sys.stderr.write("property-check: entry missing\n")
        return 2
    print(bind.get("open_token", "OPEN_OK"))
    trials = int(bind.get("trials", "24"))
    size = int(bind.get("size", "32"))
    rng = random.Random(int(bind.get("seed", "1")))
    alphabet = bind.get("alphabet", "ascii")
    property_name = bind.get("property", "no_crash")
    if property_name != "no_crash":
        sys.stderr.write(f"property-check: unknown property {property_name}\n")
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    for index in range(trials):
        payload = trial_payload(rng, alphabet, size)
        if crashes(entry, target, payload):
            sys.stderr.write(f"PROPERTY_FAIL trial={index} len={len(payload)}\n")
            print(bind.get("success_token", "REPLAY_ACCEPTED"))
            return 0
    sys.stderr.write(f"PROPERTY_HOLD trials={trials} alphabet={alphabet}\n")
    print(bind.get("hold_token", "REPLAY_REJECTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
