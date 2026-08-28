"""Runtime loader for AROS ResearchSkill methodology cards."""

from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field


class ResearchSkill(BaseModel):
    id: str
    description: str
    applicability: list[str] = Field(default_factory=list)
    required_facts: list[str] = Field(default_factory=list)
    hypothesis_templates: list[str] = Field(default_factory=list)
    experiment_strategy: str
    negative_controls: list[str] = Field(default_factory=list)
    evidence_contract: str
    known_failure_modes: list[str] = Field(default_factory=list)
    relevant_pattern_families: list[str] = Field(default_factory=list)
    recommended_tool_categories: list[str] = Field(default_factory=list)
    estimated_cost_class: str
    safety_requirements: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)


def default_skills_dir() -> Path:
    explicit = os.environ.get("AROS_SKILLS_DIR")
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "skills" / "builtin"


class SkillCatalog:
    """Validated, deterministic skill catalog used by the research director."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or default_skills_dir()).resolve()
        self._skills = self._load()

    def _load(self) -> dict[str, ResearchSkill]:
        if not self.root.is_dir():
            raise ValueError(f"research skill directory does not exist: {self.root}")
        loaded: dict[str, ResearchSkill] = {}
        for path in sorted(self.root.glob("*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            skill = ResearchSkill.model_validate(raw)
            if skill.id in loaded:
                raise ValueError(f"duplicate research skill id: {skill.id}")
            if not skill.hypothesis_templates:
                raise ValueError(f"research skill has no hypothesis template: {skill.id}")
            loaded[skill.id] = skill
        if not loaded:
            raise ValueError(f"no research skills found in {self.root}")
        return loaded

    def all(self) -> tuple[ResearchSkill, ...]:
        return tuple(self._skills[key] for key in sorted(self._skills))

    def get(self, skill_id: str) -> ResearchSkill:
        try:
            return self._skills[skill_id]
        except KeyError as exc:
            raise KeyError(f"unknown research skill: {skill_id}") from exc

    def applicable(self, visibility: str, facts: set[str]) -> tuple[ResearchSkill, ...]:
        visibility = visibility.lower()
        return tuple(
            skill
            for skill in self.all()
            if (not skill.applicability or visibility in {v.lower() for v in skill.applicability})
            and set(skill.required_facts).issubset(facts)
        )

    def select(self, visibility: str, facts: set[str]) -> ResearchSkill:
        candidates = self.applicable(visibility, facts)
        if not candidates:
            raise ValueError(
                f"no research skill applies to visibility={visibility!r}, facts={sorted(facts)!r}"
            )
        # Deterministic cost-aware selection. Specific skills (more required facts)
        # win before the lexical id tie-breaker.
        return sorted(candidates, key=lambda s: (-len(s.required_facts), s.id))[0]
