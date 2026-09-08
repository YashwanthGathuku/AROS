"""Deterministic multi-agent crew. Roles never call an LLM and never authorize."""

from __future__ import annotations

from dataclasses import dataclass

from aros_research.agents.htn import facts_from, htn_plan
from aros_research.agents.researcher import Researcher
from aros_research.agents.surface import SurfaceScientist
from aros_research.agents.verifier import IndependentVerifier
from aros_research.domain import ToolIntent

ROLES = ("mapper", "planner", "runner", "shrinker", "scribe")


@dataclass(frozen=True)
class CrewPlan:
    roles: tuple[str, ...]
    campaign_ids: list[str]
    intents: list[ToolIntent]


class DeterministicCrew:
    """Mapper + planner + runner intents. Rust still executes and adjudicates."""

    name = "deterministic_crew"

    def plan(
        self,
        list_root: str,
        surface: dict[str, object],
        *,
        pack: str = "http",
        http_host: str = "127.0.0.1",
        http_port: int = 18080,
    ) -> CrewPlan:
        _mapper = SurfaceScientist()
        facts = facts_from(list_root, surface)
        campaign_ids = htn_plan(facts, pack)
        researcher = Researcher()
        intents: list[ToolIntent] = [_mapper.map_intent(list_root)]
        for campaign_id in campaign_ids:
            if campaign_id.startswith("http-"):
                probe = researcher.http_probe(http_host, http_port)
                probe.argv = ["class", campaign_id]
                intents.append(probe)
        _verifier = IndependentVerifier()
        return CrewPlan(roles=ROLES, campaign_ids=campaign_ids, intents=intents)
