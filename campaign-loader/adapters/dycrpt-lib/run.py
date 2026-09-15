"""Path-depend on voicechat_crypto and run an AROS-owned experiment. Target is not modified."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def is_voicechat_crypto(target: str) -> bool:
    manifest = os.path.join(target, "Cargo.toml")
    if not os.path.isfile(manifest):
        return False
    with open(manifest, encoding="utf-8") as handle:
        text = handle.read()
    return 'name = "voicechat_crypto"' in text


def cargo_path(path: str) -> str:
    return os.path.abspath(path).replace("\\", "/")


def main() -> int:
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    if not is_voicechat_crypto(target):
        sys.stderr.write(
            "dycrpt-lib: target is not voicechat_crypto (dycrpt); zero evidence\n"
        )
        return 2
    bind = load_bind()
    experiment = bind.get("experiment", "replay").strip()
    here = os.path.dirname(os.path.abspath(__file__))
    source = os.path.join(here, f"{experiment}.rs")
    if not os.path.isfile(source):
        sys.stderr.write(f"dycrpt-lib: unknown experiment {experiment}\n")
        return 2
    crate = tempfile.mkdtemp(prefix="aros-dycrpt-")
    src_dir = os.path.join(crate, "src")
    os.makedirs(src_dir, exist_ok=True)
    with open(os.path.join(crate, "Cargo.toml"), "w", encoding="utf-8") as handle:
        handle.write(
            "[package]\n"
            f'name = "aros-dycrpt-{experiment}"\n'
            'version = "0.0.0"\n'
            'edition = "2021"\n'
            "publish = false\n\n"
            "[dependencies]\n"
            f'voicechat_crypto = {{ path = "{cargo_path(target)}" }}\n'
        )
    with open(source, encoding="utf-8") as handle:
        body = handle.read()
    with open(os.path.join(src_dir, "main.rs"), "w", encoding="utf-8") as handle:
        handle.write(body)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = os.path.join(tempfile.gettempdir(), "aros-dycrpt-target")
    env.pop("RUSTUP_TOOLCHAIN", None)
    completed = subprocess.run(
        ["cargo", "run", "--quiet", "--manifest-path", os.path.join(crate, "Cargo.toml")],
        cwd=crate,
        capture_output=True,
        check=False,
        env=env,
    )
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    if completed.returncode != 0:
        sys.stderr.write(f"dycrpt-lib: cargo run exit {completed.returncode}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
