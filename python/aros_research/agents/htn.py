"""HTN compiler: surface facts → class campaign ids. No LLM."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_CRUSHER_SKIP = {
    ".git",
    ".aros",
    "node_modules",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
}
_CRUSHER_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".py", ".rs"}
_CRUSHER_SYMBOL = b"LLVMFuzzerTestOneInput"
_CRUSHER_PEEK = 65_536
_CRUSHER_READ_CAP = 2_000
_CRUSHER_ENTRY_CAP = 32


def crusher_entries(root: Path) -> list[str]:
    """Paths the crash-crusher harness can notice. Nothing is executed."""
    entries: list[str] = []
    reads = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _CRUSHER_SKIP and not (Path(dirpath) / name).is_symlink()
        ]
        for name in filenames:
            if len(entries) >= _CRUSHER_ENTRY_CAP or reads >= _CRUSHER_READ_CAP:
                entries.sort()
                return entries
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            suffix = path.suffix
            if rel == "parse.py" or (
                "fuzz_targets" in rel.split("/") and suffix in _CRUSHER_SUFFIXES
            ):
                entries.append(rel)
                continue
            if suffix not in _CRUSHER_SUFFIXES:
                continue
            reads += 1
            try:
                blob = path.read_bytes()[:_CRUSHER_PEEK]
            except OSError:
                continue
            if _CRUSHER_SYMBOL in blob:
                entries.append(rel)
    entries.sort()
    return entries

SKILL_TASKS: dict[str, list[str]] = {
    "reachability_boundary_mapping": ["http-surface-map"],
    "breadth_depth_context": ["http-surface-map"],
    "negative_control_design": ["http-mr-cookie-drop"],
    "trust_boundary_mapping": ["http-unauth", "http-mr-auth-header"],
    "assumption_attack": ["http-idor"],
    "hidden_component_inference": ["http-cookie-confusion"],
    "differential_experiment": ["http-mr-method"],
    "attack_chain_reasoning": ["http-mr-cross-user"],
    "anomaly_investigation": ["http-mr-header-noise", "http-mr-xff"],
    "discovery_cascade": ["http-mr-query-noise"],
    "variant_analysis": [
        "http-mr-query-noise",
        "http-mr-encoded-dotdot",
        "http-mr-dot-segment",
        "http-mr-encoded-dot",
        "http-mr-nested-dotdot",
        "http-mr-double-slash",
    ],
    "incomplete_fix_search": ["http-mr-method", "http-mr-encoded-dotdot"],
    "parser_interpretation_disagreement": ["http-path-traversal", "cli-crash"],
    "representation_transformation_analysis": [
        "http-mr-encoded-dotdot",
        "http-mr-dot-segment",
        "http-mr-encoded-dot",
        "http-mr-nested-dotdot",
        "http-mr-double-slash",
    ],
    "source_to_sink": ["http-path-traversal"],
    "sink_to_source": ["http-path-traversal"],
    "fast_falsification": ["mutate-fuzz", "prop-ascii"],
    "missed_bug_analysis": ["mutate-fuzz"],
    "patch_archaeology": ["klee-run"],
    "primitive_composition": ["lib-call-twice"],
}


@dataclass(frozen=True)
class HtnFacts:
    has_http_paths: bool
    has_users: bool
    has_files: bool
    has_server: bool
    has_parse: bool
    has_once: bool
    has_crusher_entry: bool = False


def facts_from(target: str | Path, surface: dict[str, object]) -> HtnFacts:
    root = Path(target)
    paths: list[str] = []
    source = surface.get("source_paths")
    if isinstance(source, list):
        paths.extend(item for item in source if isinstance(item, str))
    live = surface.get("live")
    if isinstance(live, list):
        for item in live:
            if isinstance(item, dict):
                path = item.get("path")
                if isinstance(path, str):
                    paths.append(path)
    suggested = surface.get("suggested_bind")
    if isinstance(suggested, dict):
        paths.extend(str(value) for value in suggested.values())
    joined = " ".join(paths)
    return HtnFacts(
        has_http_paths=bool(paths),
        has_users="/users" in joined,
        has_files="/files" in joined,
        has_server=(root / "server.py").is_file(),
        has_parse=(root / "parse.py").is_file(),
        has_once=(root / "once.py").is_file(),
        has_crusher_entry=bool(crusher_entries(root)),
    )


def apply_failure_memory(plan: list[str], memory: list[tuple[str, str]]) -> dict[str, list[str]]:
    """TOOL_GAP drops that id. EXPERIMENT_INADEQUATE moves it first. No new ids."""
    skipped: list[str] = []
    for spec_id, category in memory:
        if category == "TOOL_GAP" and spec_id in plan and spec_id not in skipped:
            skipped.append(spec_id)
    campaigns = [item for item in plan if item not in skipped]
    promoted: list[str] = []
    for spec_id, category in memory:
        if category != "EXPERIMENT_INADEQUATE" or spec_id in skipped:
            continue
        if spec_id in campaigns and spec_id not in promoted:
            campaigns.remove(spec_id)
            promoted.append(spec_id)
    return {
        "campaigns": promoted + campaigns,
        "skipped": skipped,
        "promoted": promoted,
    }


def htn_plan(facts: HtnFacts, pack: str = "http") -> list[str]:
    http = pack in {"http", "all"}
    cli = pack in {"cli", "all"}
    plan: list[str] = []
    if http and (facts.has_http_paths or facts.has_server):
        plan.append("http-surface-map")
    if http and facts.has_users:
        plan.extend(
            [
                "http-mr-cookie-drop",
                "http-unauth",
                "http-idor",
                "http-cookie-confusion",
                "http-mr-method",
                "http-mr-cross-user",
                "http-mr-header-noise",
                "http-mr-query-noise",
                "http-mr-xff",
                "http-mr-auth-header",
            ]
        )
    if http and facts.has_files:
        plan.extend(
            [
                "http-path-traversal",
                "http-mr-encoded-dotdot",
                "http-mr-dot-segment",
                "http-mr-encoded-dot",
                "http-mr-nested-dotdot",
                "http-mr-double-slash",
            ]
        )
    if cli and facts.has_parse:
        plan.extend(["cli-crash", "mutate-fuzz", "crash-crusher", "prop-ascii", "klee-run"])
    if cli and facts.has_crusher_entry and "crash-crusher" not in plan:
        plan.append("crash-crusher")
    if cli and facts.has_once:
        plan.append("lib-call-twice")
    return plan
