# ADR-0007: rusqlite bundled for MVP SQLite

- Status: Accepted
- Date: 2026-08-25
- Specs: MVP persistence prefers sqlx; TECH_STACK §3 lists sqlx as expected, not mandatory

## Decision

v0.1 uses `rusqlite` with the `bundled` feature for the canonical SQLite
store. Database work runs on a dedicated blocking pool
(`spawn_blocking` / bounded), not on Tokio worker threads.

`sqlx` remains in the workspace dependency set for a possible later
migration. It is not required to compile the MVP.

## Why

sqlx is the spec's recommended async database crate. On this Windows
development host, a bundled SQLite via rusqlite is the smallest path
that does not introduce extra infrastructure and still stores
canonical state in SQLite.

## Alternatives

1. sqlx + libsqlite3-sys bundled — still valid; revisit if compile-time
   query checking is needed.
2. Postgres — rejected by both specs.

## Security consequences

Same local-file SQLite model. No network database. No change to
authorization.
