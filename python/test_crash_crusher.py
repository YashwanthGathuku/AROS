from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "campaign-loader/harnesses/crash-crusher/run.py"
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
    handle.write(b"\\x00AAAA")
"""

ORACLE = """
import sys

data = sys.stdin.buffer.read()
if b"\\x00" in data:
    raise SystemExit("AddressSanitizer: heap-buffer-overflow")
"""


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["AROS_CRUSH_BUDGET_SECONDS"] = "2"
    merged.update(env)
    return subprocess.run(
        [sys.executable, str(HARNESS)],
        capture_output=True,
        text=True,
        check=False,
        env=merged,
    )


def test_crash_crusher_labels_mutational_engine(tmp_path: Path) -> None:
    bind = tmp_path / "bind.json"
    bind.write_text(
        json.dumps({"entry": "parse.py", "engine": "auto", "budget_seconds": "120"}),
        encoding="utf-8",
    )
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(PARSER),
            "AROS_BIND_FILE": str(bind),
        }
    )
    assert completed.returncode == 0, completed.stderr
    assert "OPEN_OK" in completed.stdout
    assert "REPLAY_ACCEPTED" in completed.stdout
    assert "FUZZ_ENGINE mutational" in completed.stderr
    assert "FUZZ_ENGINE afl" not in completed.stderr
    assert "COVERAGE_ENGINE absent" in completed.stderr
    assert "coverage-guided" not in completed.stderr
    assert "SANITIZER absent" in completed.stderr
    assert "STACK_HASH " in completed.stderr
    assert "SHRINK_LEN 1" in completed.stderr
    assert "SHRINK_HEX 00" in completed.stderr
    assert "CRUSH_GAP" not in completed.stderr


def test_crash_crusher_missing_entry_does_not_accept(tmp_path: Path) -> None:
    bind = tmp_path / "bind.json"
    bind.write_text(json.dumps({"entry": "parse.py", "engine": "auto"}), encoding="utf-8")
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(tmp_path),
            "AROS_BIND_FILE": str(bind),
        }
    )
    assert completed.returncode == 0, completed.stderr
    assert "CRUSH_GAP no executable parser entry" in completed.stderr
    assert "REPLAY_ACCEPTED" not in completed.stdout
    assert "FUZZ_ENGINE" not in completed.stderr


def test_crash_crusher_fuzzer_source_without_binary_is_a_gap(tmp_path: Path) -> None:
    source = tmp_path / "fuzz" / "fuzz_targets" / "parser.rs"
    source.parent.mkdir(parents=True)
    source.write_text("int LLVMFuzzerTestOneInput(const char* data, unsigned long size);\n", encoding="utf-8")
    bind = tmp_path / "bind.json"
    bind.write_text(json.dumps({"entry": "parse.py", "engine": "auto"}), encoding="utf-8")
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(tmp_path),
            "AROS_BIND_FILE": str(bind),
        }
    )
    assert "CRUSH_GAP discovered fuzzer source is not executable: fuzz/fuzz_targets/parser.rs" in completed.stderr
    assert "REPLAY_ACCEPTED" not in completed.stdout


def test_crash_crusher_refuses_entry_outside_the_target(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text(
        "import pathlib\n"
        "pathlib.Path('RAN').write_text('x')\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    bind = tmp_path / "bind.json"
    bind.write_text(json.dumps({"entry": str(outside), "engine": "auto"}), encoding="utf-8")
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(target),
            "AROS_BIND_FILE": str(bind),
        }
    )
    assert "CRUSH_GAP entry path escapes the target" in completed.stderr
    assert "REPLAY_ACCEPTED" not in completed.stdout
    assert not (target / "RAN").exists()
    assert not (tmp_path / "RAN").exists()


def test_crash_crusher_invokes_afl_when_present(tmp_path: Path) -> None:
    fake = tmp_path / "fake_afl.py"
    fake.write_text(FAKE_AFL, encoding="utf-8")
    binary = tmp_path / "oracle.py"
    binary.write_text(ORACLE, encoding="utf-8")
    target = tmp_path / "tree"
    target.mkdir()
    bind = tmp_path / "bind.json"
    bind.write_text(
        json.dumps({"entry": "parse.py", "binary": str(binary), "engine": "auto"}),
        encoding="utf-8",
    )
    completed = _run(
        {
            "AROS_TARGET_ROOT": str(target),
            "AROS_BIND_FILE": str(bind),
            "AROS_AFL_FUZZ": str(fake),
        }
    )
    assert completed.returncode == 0, completed.stderr
    assert "FUZZ_ENGINE afl" in completed.stderr
    assert "FUZZ_ENGINE mutational" not in completed.stderr
    assert "COVERAGE_ENGINE afl" in completed.stderr
    assert "SANITIZER asan" in completed.stderr
    assert "REPLAY_ACCEPTED" in completed.stdout
    assert "SHRINK_LEN 1" in completed.stderr
    assert "CRUSH_GAP" not in completed.stderr


def test_parser_plan_includes_crash_crusher() -> None:
    from aros_research.agents.htn import facts_from, htn_plan

    facts = facts_from(PARSER, {})
    assert htn_plan(facts, "cli") == [
        "cli-crash",
        "mutate-fuzz",
        "crash-crusher",
        "prop-ascii",
        "klee-run",
    ]
