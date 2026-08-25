"""Restartable research worker. Submits ToolIntent; never executes privileged ops."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aros-research-worker")
    parser.add_argument("--socket", help="Unix domain socket path for typed IPC")
    parser.add_argument("--hello-only", action="store_true")
    args = parser.parse_args(argv)
    if args.hello_only:
        print("aros-research-worker protocol=1 python", sys.version.split()[0])
        return 0
    if not args.socket:
        print("aros-research-worker: --socket required (no host shell fallback)", file=sys.stderr)
        return 2
    print(
        "worker would connect to",
        args.socket,
        "and submit ToolIntent over framed protobuf",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
