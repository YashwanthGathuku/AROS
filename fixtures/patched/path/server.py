#!/usr/bin/env python3
from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent / "data"
VULN_PATH = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send(200, b"ok")
        if parsed.path != "/files":
            return self._send(404, b"no")
        rel = parse_qs(parsed.query).get("path", [""])[0]
        target = (ROOT / Path(rel).name).resolve()
        try:
            target.relative_to(ROOT.resolve())
        except ValueError:
            return self._send(403, b"forbidden")
        if not target.is_file():
            return self._send(404, b"missing")
        return self._send(200, target.read_bytes())

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("SECURITY_FIXTURE_PORT", "18083"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
