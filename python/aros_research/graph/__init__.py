"""Read-only views of graph kinds. Rust owns the active graph."""

from __future__ import annotations

GRAPH_KINDS = ("TARGET_REALITY", "RESEARCH", "HISTORICAL")
EPISTEMIC = (
    "OBSERVED",
    "DERIVED",
    "INFERRED",
    "HYPOTHESIZED",
    "SUPPORTED",
    "CLAIMED",
    "VERIFIED",
    "REFUTED",
    "STALE",
)
