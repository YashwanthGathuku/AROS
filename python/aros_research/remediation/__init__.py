"""Remediation reasoning. Apply only through Rust on a twin."""

from __future__ import annotations

from pydantic import BaseModel


class TwinPatchPlan(BaseModel):
    finding_id: str
    worktree: str
    never_modify_original: bool = True
