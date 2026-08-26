"""Research Director owns campaign strategy. It never authorizes."""

from __future__ import annotations

from aros_research.agents.researcher import Researcher
from aros_research.domain import Hypothesis, ToolIntent
from aros_research.models.mock import DeterministicMockProvider


class ResearchDirector:
    name = "research_director"

    def __init__(self, provider: DeterministicMockProvider | None = None) -> None:
        self.provider = provider or DeterministicMockProvider()

    def next_hypothesis(self) -> Hypothesis:
        return self.provider.hypothesize_idor()

    def plan_campaign_intents(
        self,
        list_root: str,
        *,
        search_needle: str = "VULN_",
        read_path: str | None = None,
        http_host: str | None = None,
        http_port: int | None = None,
    ) -> list[ToolIntent]:
        """Propose a bounded multi-turn experiment sequence. Rust still authorizes."""
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
