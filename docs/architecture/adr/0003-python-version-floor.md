# ADR-0003: Python version floor during v0.1 development

- Status: Accepted
- Date: 2026-08-25
- Specs: `docs/TECH_STACK.md` §10, §33 (Python 3.14+)

## Problem

TECH_STACK freezes Python 3.14+ for research workers. This development host
has Python 3.13.5 (Windows) and 3.12.3 (WSL Ubuntu 24.04). Free-threaded
3.14 is not required for MVP correctness (§11).

## Decision

- Spec target remains **Python 3.14+**.
- Worker source stays **3.13-compatible** (no 3.14-only syntax).
- `requires-python = ">=3.13"` in `pyproject.toml` so this host can run tests.
- `aros doctor` reports:
  - `SPEC_TARGET`: 3.14
  - `REQUIRED` for local unit tests: 3.13
  - WSL 3.12: `UNSAFE/MISCONFIGURED` relative to SPEC_TARGET
- Bootstrap attempts to provision 3.14 in WSL when practical.
- Free-threading is optional and not required.

## Alternatives

1. Block all work until 3.14 is installed — rejected; not a security invariant.
2. Silently rewrite TECH_STACK to 3.13 — rejected; would hide the discrepancy.

## Security consequences

None for authorization. Worker isolation does not depend on 3.14.
