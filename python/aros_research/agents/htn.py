"""HTN compiler: surface facts → class campaign ids. No LLM."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
            ]
        )
    if http and facts.has_files:
        plan.append("http-path-traversal")
    if cli and facts.has_parse:
        plan.extend(["cli-crash", "mutate-fuzz"])
    if cli and facts.has_once:
        plan.append("lib-call-twice")
    return plan
