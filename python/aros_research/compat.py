"""Stable compatibility identifiers separated from public product branding.

The current public product name may change. Persisted/imported Python package
names and environment-variable aliases are compatibility API for v0.1 and are
centralized here so a rename does not require scattered runtime edits.
"""

from __future__ import annotations

ENV_PREFIX = "AROS"


def env_name(suffix: str) -> str:
    """Return the current/legacy environment-variable compatibility name."""
    if not suffix or suffix.startswith("_"):
        raise ValueError("environment suffix must be a non-empty bare identifier")
    return f"{ENV_PREFIX}_{suffix}"
