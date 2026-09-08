"""Lab one-shot entry that still succeeds on the second call."""

from __future__ import annotations

import os
from pathlib import Path


def main() -> None:
    stamp = Path(os.environ.get("AROS_ONCE_STAMP", ".aros-once"))
    if stamp.exists():
        print("REPLAY_ACCEPTED")
        return
    stamp.write_text("1", encoding="utf-8")
    print("OPEN_OK")


if __name__ == "__main__":
    main()
