"""AROS catalog harness: emit oracle tokens from bind. Does not live in the target."""

from __future__ import annotations

import json
import os


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def main() -> None:
    bind = load_bind()
    print(bind.get("open_token", "OPEN_OK"))
    print(bind.get("result_token", "REPLAY_REJECTED"))


if __name__ == "__main__":
    main()
