"""Lab parser that crashes on NUL. Not a production program."""

from __future__ import annotations

import sys


def main() -> None:
    data = sys.stdin.buffer.read()
    if b"\x00" in data:
        raise MemoryError("nul")
    sys.stdout.write("OPEN_OK\nPARSED\n")


if __name__ == "__main__":
    main()
