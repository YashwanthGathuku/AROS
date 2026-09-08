"""Five MVP research agents. They propose; they never authorize."""

from __future__ import annotations

from .crew import DeterministicCrew
from .director import ResearchDirector
from .htn import htn_plan
from .remediation import RemediationResearcher
from .researcher import Researcher
from .surface import SurfaceScientist
from .verifier import IndependentVerifier

AGENTS = (
    "research_director",
    "surface_scientist",
    "researcher",
    "independent_verifier",
    "remediation_researcher",
    "deterministic_crew",
)

__all__ = [
    "AGENTS",
    "DeterministicCrew",
    "IndependentVerifier",
    "RemediationResearcher",
    "ResearchDirector",
    "Researcher",
    "SurfaceScientist",
    "htn_plan",
]
