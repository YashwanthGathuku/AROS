"""AROS-generated HTTP security regression. Does not modify the original target."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


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


def main() -> int:
    target = os.environ["AROS_REGRESSION_TARGET"]
    recipe_path = os.environ["AROS_REGRESSION_FILE"]
    with open(recipe_path, encoding="utf-8") as handle:
        recipe = json.load(handle)
    server = os.path.join(target, "server.py")
    if not os.path.isfile(server):
        sys.stderr.write("regression: twin copy has no server.py\n")
        return 2
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
    try:
        health = recipe.get("health_path", "/health")
        health_url = f"http://127.0.0.1:{port}{health}"
        deadline = time.time() + 4.0
        healthy = False
        while time.time() < deadline:
            status, _body = fetch(health_url, {})
            if status == 200:
                healthy = True
                break
            time.sleep(0.05)
        if not healthy:
            sys.stderr.write("regression: health check failed\n")
            return 2
        attacks = recipe.get("attacks", [])
        if not attacks:
            sys.stderr.write("regression: no attacks in recipe\n")
            return 2
        for attack in attacks:
            path = str(attack.get("path", "/"))
            cookie = str(attack.get("cookie", ""))
            needle = str(attack.get("must_not_contain", ""))
            headers: dict[str, str] = {}
            if cookie:
                headers["Cookie"] = cookie
            _status, body = fetch(f"http://127.0.0.1:{port}{path}", headers)
            if needle and needle in body:
                sys.stderr.write(f"regression: {path} still leaked {needle}\n")
                return 1
        return 0
    finally:
        child.kill()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()


if __name__ == "__main__":
    raise SystemExit(main())
