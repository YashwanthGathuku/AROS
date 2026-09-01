"""Restartable research worker. Submits ToolIntent; never executes privileged ops."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import uuid
from pathlib import Path

from aros_research.agents.director import ResearchDirector
from aros_research.agents.researcher import Researcher
from aros_research.compat import env_name
from aros_research.domain import ToolIntent
from aros_research.ipc.framing import MAX_FRAME, decode_header
from aros_research.ipc.wire import Hello, decode_intent_result, encode_hello, encode_tool_intent


def _connect(args: argparse.Namespace) -> socket.socket:
    if args.tcp:
        host, _, port_s = args.tcp.rpartition(":")
        return socket.create_connection((host, int(port_s)), timeout=10)
    if args.socket:
        af_unix = getattr(socket, "AF_UNIX", None)
        if af_unix is None:
            raise SystemExit("Unix sockets unavailable on this Python; pass --tcp host:port")
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(args.socket)
        return sock
    raise SystemExit("research worker: --socket or --tcp required (no host shell fallback)")


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(sock: socket.socket) -> bytes:
    header = _read_exact(sock, 4)
    length = decode_header(header, MAX_FRAME)
    return _read_exact(sock, length)


def _send_intent(sock: socket.socket, intent: ToolIntent, request_id: str | None = None) -> None:
    rid = request_id or str(uuid.uuid4())
    frame = encode_tool_intent(
        intent.capability.value,
        argv=list(intent.argv),
        path=intent.path,
        host=intent.host,
        port=intent.port,
        timeout_ms=intent.timeout_ms,
        http_target=intent.http_target,
        http_cookie=intent.http_cookie,
        request_id=rid,
    )
    sock.sendall(frame)


def _absolute_path(path: str) -> str:
    if path.startswith("/") or path.startswith("\\\\"):
        return path
    p = Path(path).expanduser()
    if p.is_absolute():
        return str(p)
    return str(p.resolve())


def serve(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aros-research-worker")
    parser.add_argument("--socket", help="Unix domain socket path for typed IPC")
    parser.add_argument("--tcp", help="host:port loopback test/development transport")
    # Legacy CLI token is retained only for compatibility with older launchers.
    # New launchers pass the compatibility WORKER_TOKEN environment variable so
    # secrets are not exposed in process listings.
    parser.add_argument("--token", help=argparse.SUPPRESS)
    parser.add_argument("--hello-only", action="store_true")
    parser.add_argument("--crash-after-hello", action="store_true")
    parser.add_argument("--probe-intent", help="send one ToolIntent after hello then exit")
    parser.add_argument("--probe-path", help="path for --probe-intent")
    parser.add_argument(
        "--research-once",
        action="store_true",
        help="after hello, propose one real ToolIntent via Researcher, await IntentResult, exit",
    )
    parser.add_argument(
        "--research-campaign",
        action="store_true",
        help="after hello, run a multi-turn ToolIntent campaign (list/search/read/optional http)",
    )
    parser.add_argument("--read-path", default=None, help="optional read_file path for --research-campaign")
    parser.add_argument(
        "--list-root",
        default=".",
        help="filesystem root for list_tree research-once probe (must be allowlisted by daemon)",
    )
    parser.add_argument("--http-host", default=None, help="optional host for http_request probe")
    parser.add_argument("--http-port", type=int, default=None, help="optional port for http_request")
    args = parser.parse_args(argv)
    if args.hello_only:
        print("research-worker protocol=1 python", sys.version.split()[0])
        return 0

    worker_token_name = env_name("WORKER_TOKEN")
    token = os.environ.get(worker_token_name) or args.token or ""
    if not token:
        raise SystemExit(f"{worker_token_name} is required")

    sock = _connect(args)
    hello = encode_hello(
        Hello(
            worker_kind="research",
            python_version=sys.version.split()[0],
            token=token,
        )
    )
    sock.sendall(hello)
    _ = _read_frame(sock)

    if args.crash_after_hello:
        raise SystemExit(99)

    if args.probe_intent:
        path = _absolute_path(args.probe_path) if args.probe_path else args.probe_path
        sock.sendall(encode_tool_intent(args.probe_intent, path=path))
        payload = _read_frame(sock)
        try:
            result = decode_intent_result(payload)
            print(
                json.dumps(
                    {
                        "decision": result.decision,
                        "reason": result.reason,
                        "request_id": result.request_id,
                        "exit_status": result.exit_status,
                        "stdout_digest": result.stdout_digest,
                    }
                )
            )
        except ValueError:
            print(json.dumps({"decision": "UNKNOWN", "reason": "no IntentResult decoded"}))
        return 0

    if args.research_once:
        researcher = Researcher()
        if args.http_host is not None and args.http_port is not None:
            intent = researcher.http_probe(args.http_host, args.http_port)
        else:
            intent = researcher.list_tree(_absolute_path(args.list_root))
        _send_intent(sock, intent)
        result = decode_intent_result(_read_frame(sock))
        print(
            json.dumps(
                {
                    "capability": intent.capability.value,
                    "path": intent.path,
                    "decision": result.decision,
                    "reason": result.reason,
                    "request_id": result.request_id,
                    "exit_status": result.exit_status,
                    "stdout_digest": result.stdout_digest,
                }
            )
        )
        return 0 if result.decision == "ALLOW" else 2

    if args.research_campaign:
        director = ResearchDirector()
        intents = director.plan_campaign_intents(
            _absolute_path(args.list_root),
            read_path=_absolute_path(args.read_path) if args.read_path else None,
            http_host=args.http_host,
            http_port=args.http_port,
        )
        turns: list[dict[str, object]] = []
        allowed = 0
        for intent in intents:
            _send_intent(sock, intent)
            result = decode_intent_result(_read_frame(sock))
            turns.append(
                {
                    "capability": intent.capability.value,
                    "path": intent.path,
                    "host": intent.host,
                    "port": intent.port,
                    "decision": result.decision,
                    "reason": result.reason,
                    "exit_status": result.exit_status,
                    "stdout_digest": result.stdout_digest,
                }
            )
            if result.decision == "ALLOW":
                allowed += 1
        print(json.dumps({"turns": turns, "allowed": allowed}))
        return 0 if allowed > 0 else 2

    try:
        while True:
            _ = _read_frame(sock)
    except ConnectionError:
        return 0


def main() -> None:
    raise SystemExit(serve())


if __name__ == "__main__":
    main()
