"""Start a local HTTP target if needed, then probe one attack. Target tree is not modified."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


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
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(response.status), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return int(error.code), error.read().decode("utf-8", "replace")
    except OSError as error:
        return 0, str(error)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_health(url: str, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status, _body = fetch(url, {})
        if status == 200:
            return True
        time.sleep(0.05)
    return False


def start_server(target: str, port: int) -> subprocess.Popen[bytes] | None:
    server = os.path.join(target, "server.py")
    if not os.path.isfile(server):
        return None
    env = os.environ.copy()
    env["SECURITY_FIXTURE_PORT"] = str(port)
    env["SECURITY_FIXTURE_BIND"] = "127.0.0.1"
    return subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=target,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    host = bind.get("host", "127.0.0.1")
    health_path = bind.get("health_path", "/health")
    child: subprocess.Popen[bytes] | None = None
    port_raw = bind.get("port", "").strip()
    if port_raw:
        port = int(port_raw)
    else:
        port = free_port()
        child = start_server(target, port)
        if child is None:
            sys.stderr.write("http-local: no server.py and no bind.port\n")
            return 2
    health_url = f"http://{host}:{port}{health_path}"
    if not wait_health(health_url, 4.0):
        if child is not None:
            child.kill()
            child.wait(timeout=2)
        sys.stderr.write("http-local: health check failed\n")
        return 2
    print(bind.get("open_token", "OPEN_OK"))
    headers: dict[str, str] = {}
    cookie = bind.get("attack_cookie", "") or bind.get("cookie", "")
    if cookie:
        headers["Cookie"] = cookie
    attack_path = bind.get("attack_path", "/")
    _status, body = fetch(f"http://{host}:{port}{attack_path}", headers)
    needle = bind.get("attack_contains", "")
    if needle and needle in body:
        print(bind.get("success_token", "REPLAY_ACCEPTED"))
    else:
        print(bind.get("hold_token", "REPLAY_REJECTED"))
    if child is not None:
        child.kill()
        child.wait(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
