"""Validate the PoC-or-nothing pack. Execution is `aros benchmark poc`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = Path(__file__).resolve().parent / "cases.json"
CLASSES = ROOT / "campaign-loader" / "classes"


def main() -> int:
    payload = json.loads(CASES.read_text(encoding="utf-8"))
    if payload.get("scoring") != "poc-or-nothing":
        sys.stderr.write("scoring must be poc-or-nothing\n")
        return 2
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        sys.stderr.write("cases missing\n")
        return 2
    errors = 0
    for case in cases:
        if not isinstance(case, dict):
            errors += 1
            continue
        case_id = case.get("id")
        target = ROOT / str(case.get("target", ""))
        campaign = str(case.get("campaign", ""))
        expect = case.get("expect")
        spec = CLASSES / f"{campaign}.campaign.json"
        if expect not in {"verified", "held"}:
            sys.stderr.write(f"{case_id}: expect must be verified|held\n")
            errors += 1
        if not target.exists():
            sys.stderr.write(f"{case_id}: missing target {target}\n")
            errors += 1
        if not spec.is_file():
            sys.stderr.write(f"{case_id}: missing campaign {spec}\n")
            errors += 1
    print(f"poc-or-nothing cases={len(cases)} schema_ok={errors == 0}")
    print("execute: aros benchmark poc --operator-waive-containment")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
