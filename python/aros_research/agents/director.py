"""Research Director owns campaign strategy. It never authorizes."""

from __future__ import annotations

from aros_research.domain import Hypothesis
from aros_research.models.mock import DeterministicMockProvider


class ResearchDirector:
    name = "research_director"

    def __init__(self, provider: DeterministicMockProvider | None = None) -> None:
        self.provider = provider or DeterministicMockProvider()

    def next_hypothesis(self) -> Hypothesis:
        return self.provider.hypothesize_idor()
