from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VisibilityMode(StrEnum):
    BLACK_BOX = "BLACK_BOX"
    GRAY_BOX = "GRAY_BOX"
    WHITE_BOX = "WHITE_BOX"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_HUMAN = "REQUIRES_HUMAN"


class ToolCapability(StrEnum):
    read_file = "read_file"
    list_tree = "list_tree"
    search_text = "search_text"
    http_request = "http_request"


class ToolIntent(BaseModel):
    capability: ToolCapability
    argv: list[str] = Field(default_factory=list)
    cwd: str | None = None
    path: str | None = None
    host: str | None = None
    port: int | None = None
    timeout_ms: int = 30_000


class Hypothesis(BaseModel):
    claim: str
    security_invariant: str
    cheapest_experiment: str
    estimated_cost: int = 1
    extras: dict[str, Any] = Field(default_factory=dict)
