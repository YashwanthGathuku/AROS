"""Remediation researcher. May only propose patches for a twin/worktree."""

from __future__ import annotations


class RemediationResearcher:
    name = "remediation_researcher"

    def patch_plan(self, finding_id: str) -> dict[str, str]:
        return {"finding_id": finding_id, "target": "twin_only", "never": "original"}
