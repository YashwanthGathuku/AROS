#!/usr/bin/env python3
"""Write skills/builtin/*.json and docs/research-methodology/research-skills.md."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from aros_research.skills.catalog import SKILLS  # noqa: E402


def main() -> None:
    builtin = ROOT / "skills" / "builtin"
    builtin.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Research skills",
        "",
        "Generated from `python/aros_research/skills/catalog.py`.",
        "These are structured methodologies, not prompts with authority.",
        "",
    ]
    for skill in SKILLS:
        path = builtin / f"{skill['id']}.json"
        path.write_text(json.dumps(skill, indent=2) + "\n", encoding="utf-8")
        lines.append(f"## `{skill['id']}`")
        lines.append("")
        lines.append(skill["description"])
        lines.append("")
        lines.append(f"- Applicability: {', '.join(skill['applicability'])}")
        lines.append(f"- Experiment: {skill['experiment_strategy']}")
        lines.append(f"- Evidence: {skill['evidence_contract']}")
        lines.append(f"- Cost class: {skill['estimated_cost_class']}")
        lines.append("")
    docs = ROOT / "docs" / "research-methodology"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "research-skills.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {len(SKILLS)} skills")


if __name__ == "__main__":
    main()
