# ADR-0006: Apache-2.0 license

- Status: Accepted
- Date: 2026-08-25
- Specs: MVP [OPEN-SOURCE HYGIENE]

## Decision

The project uses Apache License 2.0.

Do not vendor GPL/AGPL code. Optional engines are invoked through adapters.

## Alternatives

1. MIT-only — Apache-2.0 adds explicit patent grant, preferred by the spec.
2. Copyleft — would constrain adapter strategy; rejected unless a later ADR
   is forced by a required dependency.
