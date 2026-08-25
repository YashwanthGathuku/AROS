"""Experiment planning DTOs. Execution is a ToolIntent to Rust."""

from __future__ import annotations

from pydantic import BaseModel


class ExperimentPlan(BaseModel):
    hypothesis_claim: str
    cheapest_probe: str
    negative_control: str
    estimated_cost: int = 1
