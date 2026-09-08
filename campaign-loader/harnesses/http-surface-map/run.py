"""Map HTTP surface from source plus a live local server. Does not modify the target."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

WORDLIST = [
    "/health",
    "/",
    "/api",
    "/api/health",
    "/users",
    "/users/1",
    "/users/2",
    "/files",
    "/files?path=public.txt",
    "/admin",
    "/login",
    "/openapi.json",
    "/docs",
    "/status",
    "/ready",
]

SKIP_DIRS = {
    ".git",
    "node_modules",
    "target",
    "dist",
    ".aros",
    "__pycache__",
    ".venv",
}

PATH_RE = re.compile(r"""['\"](/[A-Za-z0-9_./{}?-]{1,120})['\"]""")


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def fetch(url: str, headers: dict[str, str]) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read(4096).decode("utf-8", "replace")
            return int(response.status), body
    except urllib.error.HTTPError as error:
        return int(error.code), error.read(4096).decode("utf-8", "replace")
    except OSError as error:
        return 0, str(error)


def extract_from_source(root: str) -> list[str]:
    found: set[str] = set()
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith((".py", ".js", ".ts", ".tsx", ".go", ".rs", ".java")):
                continue
            path = os.path.join(dirpath, name)
            scanned += 1
            if scanned > 400:
                return sorted(found)
            try:
                if os.path.getsize(path) > 256_000:
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            for match in PATH_RE.finditer(text):
                value = match.group(1).split("?")[0]
                if value.startswith("//"):
                    continue
                found.add(value)
    return sorted(found)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    source_paths = extract_from_source(target)
    host = bind.get("host", "127.0.0.1")
    child: subprocess.Popen[bytes] | None = None
    port_raw = bind.get("port", "").strip()
    if port_raw:
        port = int(port_raw)
    else:
        server = os.path.join(target, "server.py")
        if os.path.isfile(server):
            port = free_port()
            env = os.environ.copy()
            env["SECURITY_FIXTURE_PORT"] = str(port)
            env["SECURITY_FIXTURE_BIND"] = "127.0.0.1"
            child = subprocess.Popen(
                [sys.executable, "server.py"],
                cwd=target,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            port = 0
    live: list[dict[str, object]] = []
    if port:
        health = bind.get("health_path", "/health")
        deadline = time.time() + 4.0
        ready = False
        while time.time() < deadline:
            status, _body = fetch(f"http://{host}:{port}{health}", {})
            if status == 200:
                ready = True
                break
            time.sleep(0.05)
        if ready:
            print(bind.get("open_token", "OPEN_OK"))
            seen: set[str] = set()
            for path in WORDLIST + source_paths:
                if path in seen:
                    continue
                seen.add(path)
                status, body = fetch(f"http://{host}:{port}{path}", {})
                if status == 0:
                    continue
                live.append({"path": path, "status": status, "bytes": len(body)})
        else:
            sys.stderr.write("http-surface-map: live server not ready\n")
    else:
        print(bind.get("open_token", "OPEN_OK"))
    print("SURFACE_MAP")
    print(json.dumps({"source_paths": source_paths, "live": live}, sort_keys=True))
    print(bind.get("hold_token", "REPLAY_REJECTED"))
    if child is not None:
        child.kill()
        child.wait(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
