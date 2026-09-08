"""HTN compiler: surface facts → class campaign ids. No LLM."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKILL_TASKS: dict[str, list[str]] = {
    "reachability_boundary_mapping": ["http-surface-map"],
    "breadth_depth_context": ["http-surface-map"],
    "negative_control_design": ["http-mr-cookie-drop"],
    "trust_boundary_mapping": ["http-unauth"],
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
    ],
    "incomplete_fix_search": ["http-mr-method", "http-mr-encoded-dotdot"],
    "parser_interpretation_disagreement": ["http-path-traversal", "cli-crash"],
    "representation_transformation_analysis": [
        "http-mr-encoded-dotdot",
        "http-mr-dot-segment",
        "http-mr-encoded-dot",
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
    )


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
            ]
        )
    if http and facts.has_files:
        plan.extend(
            [
                "http-path-traversal",
                "http-mr-encoded-dotdot",
                "http-mr-dot-segment",
                "http-mr-encoded-dot",
            ]
        )
    if cli and facts.has_parse:
        plan.extend(["cli-crash", "mutate-fuzz", "prop-ascii", "klee-run"])
    if cli and facts.has_once:
        plan.append("lib-call-twice")
    return plan
