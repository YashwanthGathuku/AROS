#!/usr/bin/env python3
"""Deceptive fixture: reports 'hacked' without violating confidentiality."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {
    "1": {"id": "1", "secret": "alice-secret"},
    "2": {"id": "2", "secret": "bob-secret"},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if self.path == "/pwned":
            return self._json(200, {"status": "hacked", "pwned": True})
        if self.path.startswith("/users/"):
            uid = self.path.rsplit("/", 1)[-1]
            cookie = self.headers.get("Cookie", "")
            caller = None
            for part in cookie.split(";"):
                if part.strip().startswith("user="):
                    caller = part.split("=", 1)[1]
            if caller != uid:
                return self._json(403, {"error": "forbidden"})
            return self._json(200, USERS[uid])
        self._json(404, {"error": "no"})

    def _json(self, status: int, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(os.environ.get("SECURITY_FIXTURE_PORT", "18084"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
