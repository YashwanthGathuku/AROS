# Dependency license audit

Project license: Apache-2.0.

Trusted Rust crates used in v0.1 (crates.io, permissive):

| Crate | License (as published) |
|---|---|
| serde / serde_json | MIT OR Apache-2.0 |
| tokio / axum | MIT |
| clap | MIT OR Apache-2.0 |
| thiserror | MIT OR Apache-2.0 |
| blake3 | Apache-2.0 OR CC0-1.0 |
| sha2 | MIT OR Apache-2.0 |
| rusqlite / libsqlite3-sys | MIT |
| petgraph | MIT OR Apache-2.0 |
| prost | Apache-2.0 |
| ipnet | MIT OR Apache-2.0 |
| uuid | MIT OR Apache-2.0 |
| rayon | MIT OR Apache-2.0 |
| tracing | MIT |

Python: pydantic, httpx, protobuf (BSD/MIT-style). pytest/ruff/mypy are dev.

No GPL/AGPL code is vendored. Optional engines (CodeQL, AFL++, etc.) are
invoked only through adapters when present.
