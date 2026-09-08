"""Optional KLEE adapter. Fail closed when the binary is absent. No LLM."""

from __future__ import annotations

import os
import shutil
import sys


def main() -> int:
    print("OPEN_OK")
    if shutil.which("klee") is None:
        sys.stderr.write("KLEE unavailable; symbolic class skipped (not a security result)\n")
        print("REPLAY_REJECTED")
        return 0
    sys.stderr.write("klee present but no bitcode bind; refusing to invent a run\n")
    print("REPLAY_REJECTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
