"""MST-wi style two-arm HTTP relation. No LLM. Target is not modified."""

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


def parse_header(raw: str) -> tuple[str, str] | None:
    if ":" not in raw:
        return None
    name, value = raw.split(":", 1)
    name, value = name.strip(), value.strip()
    if not name:
        return None
    return name, value


def headers_from(bind: dict[str, str], cookie_key: str, header_key: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    cookie = bind.get(cookie_key, "")
    if cookie:
        headers["Cookie"] = cookie
    extra = parse_header(bind.get(header_key, ""))
    if extra is not None:
        headers[extra[0]] = extra[1]
    return headers


def fetch(url: str, headers: dict[str, str], method: str) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers, method=method)
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


def relation_broken(relation: str, needle: str, body_a: str, body_b: str) -> bool:
    in_a = bool(needle) and needle in body_a
    in_b = bool(needle) and needle in body_b
    if relation == "b_must_not_contain":
        return in_b
    if relation == "a_must_not_contain":
        return in_a
    if relation == "bodies_must_differ":
        return body_a == body_b and in_a
    if relation == "b_must_not_gain":
        return in_b and not in_a
    return False


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    host = bind.get("host", "127.0.0.1")
    child: subprocess.Popen[bytes] | None = None
    port_raw = bind.get("port", "").strip()
    if port_raw:
        port = int(port_raw)
    else:
        port = free_port()
        server = os.path.join(target, "server.py")
        if not os.path.isfile(server):
            sys.stderr.write("http-metamorphic: no server.py and no bind.port\n")
            return 2
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
    health = bind.get("health_path", "/health")
    deadline = time.time() + 4.0
    ready = False
    while time.time() < deadline:
        status, _body = fetch(f"http://{host}:{port}{health}", {}, "GET")
        if status == 200:
            ready = True
            break
        time.sleep(0.05)
    if not ready:
        if child is not None:
            child.kill()
            child.wait(timeout=2)
        sys.stderr.write("http-metamorphic: health failed\n")
        return 2
    print(bind.get("open_token", "OPEN_OK"))
    path_a = bind.get("path_a", bind.get("attack_path", "/"))
    path_b = bind.get("path_b", path_a)
    method_a = bind.get("method_a", "GET")
    method_b = bind.get("method_b", "GET")
    headers_a = headers_from(bind, "cookie_a", "header_a")
    headers_b = headers_from(bind, "cookie_b", "header_b")
    _sa, body_a = fetch(f"http://{host}:{port}{path_a}", headers_a, method_a)
    _sb, body_b = fetch(f"http://{host}:{port}{path_b}", headers_b, method_b)
    needle = bind.get("needle", bind.get("attack_contains", ""))
    relation = bind.get("relation", "b_must_not_contain")
    broken = relation_broken(relation, needle, body_a, body_b)
    print(
        bind.get(
            "success_token" if broken else "hold_token",
            "REPLAY_ACCEPTED" if broken else "REPLAY_REJECTED",
        )
    )
    if child is not None:
        child.kill()
        child.wait(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
