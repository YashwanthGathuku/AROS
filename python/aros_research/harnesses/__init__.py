"""Harness adapters. NativeHarness is the default; Grok is capability-detected."""

from __future__ import annotations

import shutil


class NativeHarness:
    name = "native"


class GrokBuildHarness:
    name = "grok-build"

    def available(self) -> bool:
        return shutil.which("grok") is not None
