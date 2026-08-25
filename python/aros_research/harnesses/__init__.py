"""Harness adapters. NativeHarness is the default; Grok is capability-detected."""

from __future__ import annotations

import shutil


class NativeHarness:
    name = "native"


class GrokBuildHarness:
    """Inspected 2026-08-25: `grok [PROMPT]` with --cwd --agent --deny --allow.

    Never pass --always-approve. AROS policy remains in Rust.
    """

    name = "grok-build"
    flags = (
        "--cwd",
        "--agent",
        "--deny",
        "--allow",
        "--disable-web-search",
        "--debug",
    )

    def available(self) -> bool:
        return shutil.which("grok") is not None

    def plan_argv(self, prompt: str, cwd: str) -> list[str]:
        return ["grok", "--disable-web-search", "--cwd", cwd, prompt]
