# ADR-0005: SQLite canonical store + in-memory petgraph

- Status: Accepted
- Date: 2026-08-25
- Specs: MVP persistence; `docs/TECH_STACK.md` §15, §33

## Decision

SQLite is the durable canonical store. Active campaign graph operations use
an in-memory `petgraph` projection loaded from SQLite.

Neo4j, Postgres, Kafka, Redis, and Elasticsearch are out of v0.1.

## Alternatives

1. Recursive SQL for path/chain search — rejected by TECH_STACK §15.
2. Neo4j — unnecessary infrastructure.
3. Custom graph engine — not until profiling shows a need.

## Security consequences

Canonical state is local and inspectable. Graph mutations still go through
typed events and the ledger.
