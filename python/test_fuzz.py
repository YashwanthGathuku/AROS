from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "campaign-loader/harnesses/mutate-fuzz/run.py"
PARSER = ROOT / "fixtures/vulnerable/parser"

FAKE_AFL = """
import os
import sys

out = None
args = sys.argv[1:]
for i, arg in enumerate(args):
    if arg == "-o" and i + 1 < len(args):
        out = args[i + 1]
if not out:
    raise SystemExit(2)
crashes = os.path.join(out, "default", "crashes")
os.makedirs(crashes, exist_ok=True)
with open(os.path.join(crashes, "id_000000"), "wb") as handle:
    handle.write(b"\\x00")
"""


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env)
    return subprocess.run(
        [sys.executable, str(HARNESS)],
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def test_mutate_fuzz_falls_back_without_afl(tmp_path: Path) -> None:
    bind = tmp_path / "bind.json"
    bind.write_text(json.dumps({"entry": "parse.py", "engine": "auto"}), encoding="utf-8")
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(PARSER),
            "AROS_BIND_FILE": str(bind),
        }
    )
    assert completed.returncode == 0, completed.stderr
    assert "OPEN_OK" in completed.stdout
    assert "REPLAY_ACCEPTED" in completed.stdout
    assert "FUZZ_ENGINE mutate" in completed.stderr


def test_mutate_fuzz_invokes_afl_when_present(tmp_path: Path) -> None:
    fake = tmp_path / "fake_afl.py"
    fake.write_text(FAKE_AFL, encoding="utf-8")
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"not-instrumented")
    bind = tmp_path / "bind.json"
    bind.write_text(
        json.dumps({"entry": "parse.py", "binary": str(binary), "engine": "auto"}),
        encoding="utf-8",
    )
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(PARSER),
            "AROS_BIND_FILE": str(bind),
            "AROS_AFL_FUZZ": str(fake),
        }
    )
    assert completed.returncode == 0, completed.stderr
    assert "OPEN_OK" in completed.stdout
    assert "REPLAY_ACCEPTED" in completed.stdout
    assert "FUZZ_ENGINE afl" in completed.stderr
    assert "FUZZ_ENGINE mutate" not in completed.stderr
