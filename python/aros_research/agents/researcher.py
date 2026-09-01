"""Researcher proposes experiments. Rust executes them if policy allows."""

from __future__ import annotations

from aros_research.domain import ToolCapability, ToolIntent


class Researcher:
    """Proposes typed ToolIntents. Never authorizes and never executes."""

    name = "researcher"

    def list_tree(self, root: str) -> ToolIntent:
        """Propose a filesystem surface scan under an authorized root."""
        return ToolIntent(
            capability=ToolCapability.list_tree,
            path=root,
            argv=[],
            timeout_ms=30_000,
        )

    def read_file(self, path: str) -> ToolIntent:
        return ToolIntent(
            capability=ToolCapability.read_file,
            path=path,
            argv=[],
            timeout_ms=30_000,
        )

    def search_text(self, root: str, needle: str) -> ToolIntent:
        return ToolIntent(
            capability=ToolCapability.search_text,
            path=root,
            argv=["search", needle],
            timeout_ms=60_000,
        )

    def http_probe(self, host: str, port: int) -> ToolIntent:
        """Propose a single HTTP GET against an authorized local endpoint."""
        return ToolIntent(
            capability=ToolCapability.http_request,
            host=host,
            port=port,
            argv=[],
            http_target="/",
            timeout_ms=15_000,
        )
