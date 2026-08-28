"""Research Director owns campaign strategy. It never authorizes."""

from __future__ import annotations

from aros_research.agents.researcher import Researcher
from aros_research.domain import Hypothesis, ToolIntent
from aros_research.skills.runtime import SkillCatalog


class ResearchDirector:
    name = "research_director"

    def __init__(self, skills: SkillCatalog | None = None) -> None:
        self.skills = skills or SkillCatalog()

    def next_hypothesis(
        self,
        *,
        visibility: str = "white_box",
        facts: set[str] | None = None,
        skill_id: str | None = None,
    ) -> Hypothesis:
        known = facts or {"component", "trust_boundary"}
        skill = self.skills.get(skill_id) if skill_id else self.skills.select(visibility, known)
        claim = skill.hypothesis_templates[0]
        return Hypothesis(
            claim=claim,
            security_invariant=skill.evidence_contract,
            cheapest_experiment=skill.experiment_strategy,
            estimated_cost={"low": 1, "medium": 3, "high": 8}.get(
                skill.estimated_cost_class, 5
            ),
            extras={
                "research_skill_id": skill.id,
                "negative_controls": skill.negative_controls,
                "known_failure_modes": skill.known_failure_modes,
                "pattern_families": skill.relevant_pattern_families,
                "recommended_tools": skill.recommended_tool_categories,
                "provenance": skill.provenance,
            },
        )

    def plan_campaign_intents(
        self,
        list_root: str,
        *,
        search_needle: str = "VULN_",
        read_path: str | None = None,
        http_host: str | None = None,
        http_port: int | None = None,
    ) -> list[ToolIntent]:
        """Propose a bounded experiment sequence. Rust still authorizes every intent."""
        researcher = Researcher()
        intents = [
            researcher.list_tree(list_root),
            researcher.search_text(list_root, search_needle),
        ]
        if read_path:
            intents.append(researcher.read_file(read_path))
        if http_host is not None and http_port is not None:
            intents.append(researcher.http_probe(http_host, http_port))
        return intents
