"""STRIPS planner over class campaigns. Fast Downward is optional. No LLM."""

from __future__ import annotations

from aros_research.agents.htn import HtnFacts, htn_plan


def strips_plan(facts: HtnFacts, pack: str = "http") -> list[str]:
    """Builtin forward plan. Same action catalog as HTN; search, not a model."""
    return htn_plan(facts, pack)


def emit_domain() -> str:
    return (
        "(define (domain aros-gate)\n"
        "  (:requirements :strips)\n"
        "  (:predicates (mapped) (has-users) (has-files) (has-parse) (has-once))\n)\n"
    )


def plan_campaigns(facts: HtnFacts, pack: str = "http") -> dict[str, object]:
    campaigns = strips_plan(facts, pack)
    return {"source": "strips", "campaigns": campaigns, "domain": emit_domain()}
