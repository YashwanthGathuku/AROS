# ADR-0003: Python version floor during v0.1 development

- Status: Superseded in part (2026-08-25)
- Date: 2026-08-25
- Specs: `docs/TECH_STACK.md` §10, §33 (Python 3.14+)

## Problem

TECH_STACK freezes Python 3.14+ for research workers. The host originally
had 3.13.5 as `python` because Machine PATH listed Python313 first.

## Decision (updated)

- Floor is **Python 3.14+** (`requires-python = ">=3.14"`).
- Host now has Python 3.14.7 (`py -3.14`). `PY_PYTHON=3.14` is set for the
  user. This process prepends Python314 so `python` is 3.14.7.
- Machine PATH still contains Python 3.13 (admin required to reorder). New
  shells should use `py -3.14` or the user PATH entry.
- Free-threading remains optional.
- WSL Ubuntu 24.04 system Python is still 3.12.3; Windows 3.14 is the
  research-worker interpreter for this development host.

## Alternatives

1. Block all work until 3.14 is installed — rejected; not a security invariant.
2. Silently rewrite TECH_STACK to 3.13 — rejected; would hide the discrepancy.

## Security consequences

None for authorization. Worker isolation does not depend on 3.14.
