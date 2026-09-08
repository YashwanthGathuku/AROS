from __future__ import annotations

import json
from pathlib import Path

from aros_research.agents.htn import SKILL_TASKS
from aros_research.skills.catalog import skill_ids

ROOT = Path(__file__).resolve().parents[1]


def test_poc_or_nothing_cases_exist() -> None:
    payload = json.loads((ROOT / "evaluation/poc-or-nothing/cases.json").read_text(encoding="utf-8"))
    assert payload["scoring"] == "poc-or-nothing"
    assert len(payload["cases"]) >= 8
    for case in payload["cases"]:
        assert case["expect"] in {"verified", "held"}
        assert (ROOT / case["target"]).exists()
        assert (ROOT / "campaign-loader/classes" / f"{case['campaign']}.campaign.json").is_file()


def test_every_builtin_skill_has_an_htn_task() -> None:
    mapped = set(SKILL_TASKS)
    missing = set(skill_ids()) - mapped
    assert not missing, f"unmapped skills: {sorted(missing)}"
