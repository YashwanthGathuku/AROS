#!/usr/bin/env python3
"""Fail when product-prefixed runtime environment names bypass compatibility seams.

Public/legacy environment aliases are compatibility API, but runtime code must
construct them through the centralized Rust/Python helpers. This prevents a
future public product rename from accumulating new scattered `AROS_*` literals.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = (ROOT / "crates", ROOT / "python" / "aros_research")
ALLOWED = {
    (ROOT / "crates" / "aros-types" / "src" / "branding.rs").resolve(),
    (ROOT / "python" / "aros_research" / "compat.py").resolve(),
}
SUFFIXES = {".rs", ".py"}
NEEDLES = ('"AROS_', "'AROS_")


def violations() -> list[str]:
    found: list[str] = []
    for scan_root in SCAN_ROOTS:
        for path in sorted(scan_root.rglob("*")):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            resolved = path.resolve()
            if resolved in ALLOWED:
                continue
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if any(needle in line for needle in NEEDLES):
                    found.append(f"{path.relative_to(ROOT)}:{line_no}: {line.strip()}")
    return found


def main() -> int:
    found = violations()
    if found:
        print("Raw AROS_* runtime compatibility literals found outside centralized seams:")
        for item in found:
            print(f"  {item}")
        print("Use aros_types::env_name(...) or aros_research.compat.env_name(...).")
        return 1
    print("branding runtime-literal gate: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
