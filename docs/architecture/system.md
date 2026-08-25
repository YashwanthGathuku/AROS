# System architecture

See `docs/IMPLEMENTATION_PLAN.md` and `docs/TECH_STACK.md`.

Trusted control plane: Rust (`arosd`, policy, sandbox, broker, evidence, graph).
Research intelligence: isolated Python worker over framed Protobuf IPC.
Persistence: SQLite + filesystem CAS.
Sandbox: rootless OCI through `SandboxProvider`; Fake provider never claims containment.
