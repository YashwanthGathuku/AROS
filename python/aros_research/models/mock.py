"""Deterministic mock provider for tests and demo (no paid API)."""

from __future__ import annotations

from aros_research.domain import Hypothesis, ToolCapability, ToolIntent


class DeterministicMockProvider:
    def hypothesize_idor(self) -> Hypothesis:
        return Hypothesis(
            claim="GET /users/{id} returns another user's secret",
            security_invariant="user A cannot read user B secret",
            cheapest_experiment="GET /users/2 as user=1",
        )

    def experiment_intent(self, host: str, port: int) -> ToolIntent:
        return ToolIntent(capability=ToolCapability.http_request, host=host, port=port)
