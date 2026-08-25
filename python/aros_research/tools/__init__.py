"""IPC-only tool client. No host shell, docker socket, or credentials."""

from __future__ import annotations

from aros_research.domain import ToolIntent


class ToolClient:
    def submit(self, intent: ToolIntent) -> None:
        raise RuntimeError("privileged execution is owned by the Rust broker")
