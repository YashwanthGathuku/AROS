"""Restartable research worker. Submits ToolIntent; never executes privileged ops."""

from __future__ import annotations

import argparse
import socket
import sys

from aros_research.ipc.framing import MAX_FRAME, decode_header
from aros_research.ipc.wire import Hello, encode_hello


def _connect(args: argparse.Namespace) -> socket.socket:
    if args.tcp:
        host, _, port_s = args.tcp.rpartition(":")
        sock = socket.create_connection((host, int(port_s)), timeout=10)
        return sock
    if args.socket:
        af_unix = getattr(socket, "AF_UNIX", None)
        if af_unix is None:
            raise SystemExit("Unix sockets unavailable on this Python; pass --tcp host:port")
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(args.socket)
        return sock
    raise SystemExit("aros-research-worker: --socket or --tcp required (no host shell fallback)")


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def serve(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aros-research-worker")
    parser.add_argument("--socket", help="Unix domain socket path for typed IPC")
    parser.add_argument("--tcp", help="host:port for loopback framed IPC (Windows lab)")
    parser.add_argument("--token", help="daemon-issued token (loopback transport)")
    parser.add_argument("--hello-only", action="store_true")
    parser.add_argument("--crash-after-hello", action="store_true")
    args = parser.parse_args(argv)
    if args.hello_only:
        print("aros-research-worker protocol=1 python", sys.version.split()[0])
        return 0

    sock = _connect(args)
    hello = encode_hello(Hello(worker_kind="research", python_version=sys.version.split()[0]))
    sock.sendall(hello)
    header = _read_exact(sock, 4)
    length = decode_header(header, MAX_FRAME)
    _ = _read_exact(sock, length)
    if args.crash_after_hello:
        raise SystemExit(99)
    try:
        while True:
            header = _read_exact(sock, 4)
            length = decode_header(header, MAX_FRAME)
            _ = _read_exact(sock, length)
    except ConnectionError:
        return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return serve(argv)
    except ConnectionError:
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
