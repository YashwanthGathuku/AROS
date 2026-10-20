"""One-entry crash search. Coverage engine when a binary exists; otherwise mutational.

The harness stays beside AROS. It does not write into the target, invent a
crash, or describe the mutational search as coverage-guided.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable


def load_bind() -> dict[str, str]:
    path = os.environ.get("AROS_BIND_FILE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def budget_seconds(bind: dict[str, str]) -> int:
    raw = os.environ.get("AROS_CRUSH_BUDGET_SECONDS", "").strip()
    if not raw:
        raw = bind.get("budget_seconds", "").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 30
    return max(1, min(value, 3600))


def is_inside(root: str, path: str) -> bool:
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def path_escapes(root: str, raw: str) -> bool:
    if not raw.strip():
        return False
    joined = raw if os.path.isabs(raw) else os.path.join(root, raw)
    return not is_inside(root, joined)


def resolve_inside(root: str, raw: str) -> str | None:
    if not raw.strip() or path_escapes(root, raw):
        return None
    joined = raw if os.path.isabs(raw) else os.path.join(root, raw)
    candidate = os.path.realpath(joined)
    if os.path.isfile(candidate) and is_inside(root, candidate):
        return candidate
    return None


def program_argv(path: str) -> list[str]:
    if path.endswith(".py"):
        return [sys.executable, path]
    return [path]


def probe(argv: list[str], cwd: str, payload: bytes) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            input=payload,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        return True, "TIMEOUT"
    except OSError:
        return False, ""
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    crashed = completed.returncode != 0 or "Error" in text or "Traceback" in text
    return crashed, text


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


def sanitizer_label(text: str) -> str:
    if "AddressSanitizer" in text:
        return "asan"
    if "MemorySanitizer" in text:
        return "msan"
    if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        return "ubsan"
    return "absent"


def stack_hash(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    tail = "\n".join(lines[-8:]) or "exit"
    return hashlib.sha256(tail.encode("utf-8", "replace")).hexdigest()[:16]


def emit_gap(detail: str) -> int:
    sys.stderr.write(f"CRUSH_GAP {detail}\n")
    return 0


def finish_crash(
    argv: list[str],
    cwd: str,
    payload: bytes,
    text: str,
    bind: dict[str, str],
) -> int:
    replayed, replay_text = probe(argv, cwd, payload)
    observed = f"{text}\n{replay_text}"
    sys.stderr.write(f"SANITIZER {sanitizer_label(observed)}\n")
    sys.stderr.write(f"STACK_HASH {stack_hash(observed)}\n")
    if replayed:
        minimized = shrink(payload, lambda item: probe(argv, cwd, item)[0])
        sys.stderr.write(f"SHRINK_BEFORE {len(payload)}\n")
        sys.stderr.write(f"SHRINK_LEN {len(minimized)}\n")
        sys.stderr.write(f"SHRINK_HEX {minimized.hex()}\n")
    print(bind.get("success_token", "REPLAY_ACCEPTED"))
    return 0


def finish_hold(bind: dict[str, str]) -> int:
    print(bind.get("hold_token", "REPLAY_REJECTED"))
    return 0


def resolve_binary(bind: dict[str, str], target: str) -> str | None:
    binary = bind.get("binary", "").strip()
    if not binary:
        return None
    if os.path.isabs(binary):
        return binary if os.path.isfile(binary) else None
    path = os.path.join(target, binary)
    return path if os.path.isfile(path) else None


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


def crash_bytes(out_dir: str) -> bytes | None:
    found: list[str] = []
    for root, _dirs, files in os.walk(out_dir):
        if os.path.basename(root) != "crashes":
            continue
        for name in files:
            if name in {"README.txt", "README"}:
                continue
            found.append(os.path.join(root, name))
    for path in sorted(found):
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if data:
            return data
    return None


def run_afl(afl: str, binary: str, timeout_s: int) -> tuple[bytes | None, str]:
    with tempfile.TemporaryDirectory(prefix="aros-crush-afl-") as work:
        seeds = os.path.join(work, "in")
        out = os.path.join(work, "out")
        os.makedirs(seeds)
        os.makedirs(out)
        with open(os.path.join(seeds, "seed"), "wb") as handle:
            handle.write(b"AAAA")
        argv = [*program_argv(afl), "-i", seeds, "-o", out, "-V", str(timeout_s), "--", binary]
        env = os.environ.copy()
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_BIN_CHECK"] = "1"
        try:
            completed = subprocess.run(
                argv,
                env=env,
                capture_output=True,
                timeout=timeout_s + 8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return crash_bytes(out), "TIMEOUT"
        except OSError:
            return None, ""
        text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        return crash_bytes(out), text


def run_libfuzzer(binary: str, timeout_s: int) -> tuple[bytes | None, str]:
    with tempfile.TemporaryDirectory(prefix="aros-crush-lf-") as corpus:
        argv = [*program_argv(binary), f"-max_total_time={timeout_s}", "-timeout=1", corpus]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout_s + 8,
                check=False,
                cwd=corpus,
            )
        except subprocess.TimeoutExpired:
            return _libfuzzer_crash(corpus), "TIMEOUT"
        except OSError:
            return None, ""
        text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        return _libfuzzer_crash(corpus), text


def _libfuzzer_crash(corpus: str) -> bytes | None:
    found: list[str] = []
    for root, _dirs, files in os.walk(corpus):
        for name in files:
            if name.startswith("crash-"):
                found.append(os.path.join(root, name))
    for path in sorted(found):
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if data:
            return data
    return None


def discover_python_entry(target: str, bind: dict[str, str]) -> tuple[str | None, str | None]:
    requested = bind.get("entry", "").strip()
    if requested:
        if path_escapes(target, requested):
            return None, "entry path escapes the target"
        resolved = resolve_inside(target, requested)
        if resolved is not None:
            if resolved.endswith(".py"):
                return resolved, None
            return None, "entry is not a python parser and no coverage engine is available"
    fallback = resolve_inside(target, "parse.py")
    if fallback is not None:
        return fallback, None
    return None, None


_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".py", ".rs")


def discover_fuzzer_source(target: str) -> str | None:
    seen = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")]
        parts = set(os.path.normpath(os.path.relpath(dirpath, target)).split(os.sep))
        in_fuzz_targets = "fuzz_targets" in parts
        for name in filenames:
            seen += 1
            if seen > 2000:
                return None
            if not name.endswith(_SOURCE_SUFFIXES):
                continue
            path = os.path.join(dirpath, name)
            if in_fuzz_targets:
                return path
            try:
                with open(path, "rb") as handle:
                    blob = handle.read(65536)
            except OSError:
                continue
            if b"LLVMFuzzerTestOneInput" in blob:
                return path
    return None


def relative_source(target: str, source: str) -> str:
    rel = os.path.relpath(source, target).replace("\\", "/")
    if rel.startswith(".."):
        return "fuzzer-source"
    return rel


def search(entry: str, target: str, seconds: int) -> tuple[bytes | None, str]:
    argv = [sys.executable, entry]
    deadline = time.monotonic() + seconds
    seeds = [b"AAAA", b"\x00", b"../" * 8, b"A" * 4096, b"%n" * 16, b"\xff" * 16]
    for seed in seeds:
        if time.monotonic() >= deadline:
            return None, ""
        found = _try(argv, target, seed)
        if found is not None:
            return found
        mutated = bytearray(seed)
        if not mutated:
            continue
        mutated[0] = 0
        if bytes(mutated) == seed:
            continue
        found = _try(argv, target, bytes(mutated))
        if found is not None:
            return found
    rng = random.Random(0)
    while time.monotonic() < deadline:
        payload = bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
        found = _try(argv, target, payload)
        if found is not None:
            return found
    return None, ""


def _try(argv: list[str], cwd: str, payload: bytes) -> tuple[bytes, str] | None:
    crashed, text = probe(argv, cwd, payload)
    if crashed:
        return payload, text
    return None


def main() -> int:
    bind = load_bind()
    target = os.environ.get("AROS_TARGET_ROOT", os.getcwd())
    print(bind.get("open_token", "OPEN_OK"))
    engine = bind.get("engine", "auto")
    seconds = budget_seconds(bind)
    binary = resolve_binary(bind, target)
    if engine in {"auto", "afl"} and binary:
        afl = detect_afl()
        if afl:
            sys.stderr.write(f"FUZZ_ENGINE afl {afl}\n")
            sys.stderr.write("COVERAGE_ENGINE afl\n")
            payload, text = run_afl(afl, binary, seconds)
            if payload is None:
                sys.stderr.write("SANITIZER absent\n")
                return finish_hold(bind)
            return finish_crash(program_argv(binary), target, payload, text, bind)
    if engine in {"auto", "libfuzzer"}:
        libfuzzer = detect_libfuzzer(bind, target)
        if libfuzzer:
            sys.stderr.write(f"FUZZ_ENGINE libfuzzer {libfuzzer}\n")
            sys.stderr.write("COVERAGE_ENGINE libfuzzer\n")
            payload, text = run_libfuzzer(libfuzzer, seconds)
            if payload is None:
                sys.stderr.write("SANITIZER absent\n")
                return finish_hold(bind)
            return finish_crash(program_argv(libfuzzer), target, payload, text, bind)
    entry, gap = discover_python_entry(target, bind)
    if gap:
        return emit_gap(gap)
    if entry is None:
        source = discover_fuzzer_source(target)
        if source:
            return emit_gap(
                f"discovered fuzzer source is not executable: {relative_source(target, source)}"
            )
        return emit_gap("no executable parser entry")
    sys.stderr.write("FUZZ_ENGINE mutational\n")
    sys.stderr.write("COVERAGE_ENGINE absent\n")
    payload, text = search(entry, target, seconds)
    if payload is None:
        sys.stderr.write("SANITIZER absent\n")
        return finish_hold(bind)
    return finish_crash([sys.executable, entry], target, payload, text, bind)


if __name__ == "__main__":
    raise SystemExit(main())
