"""Researcher proposes experiments. Rust executes them if policy allows."""

from __future__ import annotations

from aros_research.domain import ToolCapability, ToolIntent


class Researcher:
    name = "researcher"

    def http_probe(self, host: str, port: int) -> ToolIntent:
        return ToolIntent(capability=ToolCapability.http_request, host=host, port=port)
