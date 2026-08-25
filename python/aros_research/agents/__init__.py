"""Five MVP research agents. They propose; they never authorize."""

from __future__ import annotations

from .director import ResearchDirector
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
)

__all__ = [
    "AGENTS",
    "IndependentVerifier",
    "RemediationResearcher",
    "ResearchDirector",
    "Researcher",
    "SurfaceScientist",
]
