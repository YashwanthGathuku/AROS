"""Surface Scientist builds attack-surface models from authorized reads."""

from __future__ import annotations

from aros_research.domain import ToolCapability, ToolIntent


class SurfaceScientist:
    name = "surface_scientist"

    def map_intent(self, root: str) -> ToolIntent:
        return ToolIntent(capability=ToolCapability.list_tree, path=root)
