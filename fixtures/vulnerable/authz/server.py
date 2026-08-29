#!/usr/bin/env python3
"""Local authorization-flaw fixture. Do not expose on a public interface."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {
    "1": {"id": "1", "name": "alice", "secret": "alice-secret"},
    "2": {"id": "2", "name": "bob", "secret": "bob-secret"},
}

VULN_IDOR = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _session_user(self) -> str | None:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("user="):
                return part.split("=", 1)[1]
        return None

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            return self._json(200, {"ok": True, "vuln": VULN_IDOR})
        if self.path.startswith("/users/"):
            uid = self.path.rsplit("/", 1)[-1]
            caller = self._session_user()
            if uid not in USERS:
                return self._json(404, {"error": "missing"})
            if not VULN_IDOR and caller != uid:
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


def main() -> None:
    host = os.environ.get("SECURITY_FIXTURE_BIND", "127.0.0.1")
    port = int(os.environ.get("SECURITY_FIXTURE_PORT", "18080"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
