"""Coverage-free mutational fuzzer + delta-debug shrink. AFL++/libFuzzer when present. No LLM."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return {str(key): str(value) for key, value in raw.items()}


def crashes(entry: str, cwd: str, payload: bytes) -> bool:
    completed = subprocess.run(
        [sys.executable, entry],
        cwd=cwd,
        input=payload,
        capture_output=True,
        check=False,
    )
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    return completed.returncode != 0 or "Error" in text or "Traceback" in text


def shrink(payload: bytes, pred: Callable[[bytes], bool]) -> bytes:
    current = payload
    chunk = max(len(current), 1)
    while chunk > 0:
        progressed = False
        offset = 0
        while offset < len(current):
            end = min(offset + chunk, len(current))
            candidate = current[:offset] + current[end:]
            if candidate and pred(candidate):
                current = candidate
                progressed = True
            else:
                offset = end
        if not progressed:
            chunk //= 2
    return current


def crash_dir_has_case(out_dir: str) -> bool:
    for root, _dirs, files in os.walk(out_dir):
        if os.path.basename(root) != "crashes":
            continue
        for name in files:
            if name in {"README.txt", "README"}:
                continue
            return True
    return False


def afl_argv(afl: str) -> list[str]:
    if afl.endswith(".py"):
        return [sys.executable, afl]
    return [afl]


def run_afl(afl: str, binary: str, timeout_s: int) -> bool:
    with tempfile.TemporaryDirectory(prefix="aros-afl-") as work:
        seeds = os.path.join(work, "in")
        out = os.path.join(work, "out")
        os.makedirs(seeds)
        os.makedirs(out)
        with open(os.path.join(seeds, "seed"), "wb") as handle:
            handle.write(b"AAAA")
        argv = [*afl_argv(afl), "-i", seeds, "-o", out, "-V", str(timeout_s), "--", binary]
        env = os.environ.copy()
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_BIN_CHECK"] = "1"
        try:
            subprocess.run(
                argv,
                env=env,
                capture_output=True,
                timeout=timeout_s + 8,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return crash_dir_has_case(out)


def run_libfuzzer(binary: str, timeout_s: int) -> bool:
    with tempfile.TemporaryDirectory(prefix="aros-lf-") as corpus:
        argv = [binary, f"-max_total_time={timeout_s}", "-timeout=1", corpus]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout_s + 8,
                check=False,
                cwd=corpus,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        if "ERROR: libFuzzer" in text or "Test unit written" in text:
            return True
        for _root, _dirs, files in os.walk(corpus):
            for name in files:
                if name.startswith("crash-"):
                    return True
        return False


def detect_afl() -> str | None:
    override = os.environ.get("AROS_AFL_FUZZ", "").strip()
    if override:
        return override
    return shutil.which("afl-fuzz") or shutil.which("afl-fuzz++")


def detect_libfuzzer(bind: dict[str, str], target: str) -> str | None:
    override = os.environ.get("AROS_LIBFUZZER", "").strip()
    if override and os.path.isfile(override):
        return override
    binary = bind.get("binary", "").strip()
    if bind.get("engine") == "libfuzzer" and binary:
        path = binary if os.path.isabs(binary) else os.path.join(target, binary)
        if os.path.isfile(path):
            return path
    return None


def mutate_crash(entry: str, target: str) -> bytes | None:
    corpus = [b"AAAA", b"\x00", b"../" * 8, os.urandom(32), b"A" * 4096]
    for seed in corpus:
        if crashes(entry, target, seed):
            return seed
        mutated = bytearray(seed)
        if mutated:
            mutated[0] = 0
        if crashes(entry, target, bytes(mutated)):
            return bytes(mutated)
    return None


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    print(bind.get("open_token", "OPEN_OK"))
    engine = bind.get("engine", "auto")
    binary = bind.get("binary", "").strip()
    binary_path = ""
    if binary:
        binary_path = binary if os.path.isabs(binary) else os.path.join(target, binary)
    afl = detect_afl()
    if engine in {"auto", "afl"} and afl and binary_path and os.path.isfile(binary_path):
        sys.stderr.write(f"FUZZ_ENGINE afl {afl}\n")
        crashed = run_afl(afl, binary_path, int(bind.get("afl_seconds", "3")))
        token = "success_token" if crashed else "hold_token"
        default = "REPLAY_ACCEPTED" if crashed else "REPLAY_REJECTED"
        print(bind.get(token, default))
        return 0
    libfuzzer = detect_libfuzzer(bind, target)
    if engine in {"auto", "libfuzzer"} and libfuzzer:
        sys.stderr.write(f"FUZZ_ENGINE libfuzzer {libfuzzer}\n")
        crashed = run_libfuzzer(libfuzzer, int(bind.get("afl_seconds", "3")))
        token = "success_token" if crashed else "hold_token"
        default = "REPLAY_ACCEPTED" if crashed else "REPLAY_REJECTED"
        print(bind.get(token, default))
        return 0
    entry = os.path.join(target, bind.get("entry", "parse.py"))
    if not os.path.isfile(entry):
        sys.stderr.write("mutate-fuzz: entry missing and no AFL/libFuzzer binary\n")
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    sys.stderr.write("FUZZ_ENGINE mutate\n")
    crashing = mutate_crash(entry, target)
    if crashing is None:
        print(bind.get("hold_token", "REPLAY_REJECTED"))
        return 0
    minimized = shrink(crashing, lambda payload: crashes(entry, target, payload))
    sys.stderr.write(f"SHRINK_LEN {len(minimized)}\n")
    print(bind.get("success_token", "REPLAY_ACCEPTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
