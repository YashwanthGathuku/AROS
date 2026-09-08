"""Probe an already-listening HTTP target. Writes nothing into the target."""

from __future__ import annotations

import json
import os
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
            body = response.read().decode("utf-8", "replace")
            return int(response.status), body
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        return int(error.code), body
    except OSError as error:
        return 0, str(error)


def main() -> None:
    bind = load_bind()
    host = bind.get("host", "127.0.0.1")
    port = bind.get("port", "18080")
    headers: dict[str, str] = {}
    cookie = bind.get("cookie", "")
    if cookie:
        headers["Cookie"] = cookie
    health = bind.get("health_path", "/health")
    status, _body = fetch(f"http://{host}:{port}{health}", headers)
    if status == 200:
        print(bind.get("open_token", "OPEN_OK"))
    attack_headers = dict(headers)
    attack_cookie = bind.get("attack_cookie", "")
    if attack_cookie:
        attack_headers["Cookie"] = attack_cookie
    attack_path = bind.get("attack_path", "/")
    _status, attack_body = fetch(f"http://{host}:{port}{attack_path}", attack_headers)
    needle = bind.get("attack_contains", "")
    if needle and needle in attack_body:
        print(bind.get("success_token", "REPLAY_ACCEPTED"))
    else:
        print(bind.get("hold_token", "REPLAY_REJECTED"))


if __name__ == "__main__":
    main()
