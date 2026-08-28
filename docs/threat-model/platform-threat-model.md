# Platform threat model (v0.1)

## Assets

- `AuthorizationManifest` and deterministic policy decisions
- Host credentials, sockets and files outside explicitly authorized roots
- Original target trees and exact-target snapshots
- Evidence artifacts, persisted event hashes and campaign graph provenance
- Daemon authorization token and worker handshake token

## In-scope adversaries

- Compromised or deceptive target content: source files, README/comments, generated text, MCP/tool descriptions and fixture responses.
- Malicious or compromised Python research worker / model output.
- Another untrusted local process attempting to call `arosd` or impersonate a research worker.
- Tampering with the local SQLite evidence database after a campaign.
- Filesystem alias attacks such as symlinks from an authorized tree to an unauthorized host resource.

Public Internet scanning is not a v0.1 target class.

## Trust boundaries

### Rust trusted plane

Rust policy, broker, evidence and persistence code is trusted to enforce authorization. This does **not** imply that every Rust process is sandboxed. A host-side broker execution is reported as host-side; it does not receive a synthetic positive sandbox identity.

### Python research plane

Python/model code is treated as untrusted proposal-generation code.

- Production Linux/WSL IPC uses a private Unix domain socket.
- The worker handshake token is passed through an environment boundary, not process argv.
- The daemon does not start an uncontained host worker by default.
- `AROS_WORKER_CONTAINER_IMAGE` selects the rootless-container worker path (`--network=none`, read-only rootfs, dropped capabilities, `no-new-privileges`, resource limits and narrow mounts).
- `AROS_ALLOW_UNCONTAINED_WORKER=1` is an explicit development waiver. When set, the worker can directly access resources available to the host user; the broker allowlist is **not** a containment boundary for that process.

A host worker must therefore never be described as contained merely because its ToolIntent requests pass through the Rust broker.

### Campaign target containment

`ContainmentReport` answers: **can this host demonstrate the required isolation properties on a measured Podman network?** It does not answer: **did this campaign run in that network/container?**

The current host-side fixture engine intentionally fails closed when `require_containment=true`, because campaign-bound OCI target construction/spawn/snapshot is not yet complete. A development waiver may run fixtures on the host, but the resulting evidence has no positive `sandbox_id` claim.

## Controls currently implemented

- No authorization authority in the LLM/research worker.
- Default-deny manifest and explicit tool/root/endpoint allowlists.
- Canonical filesystem enforcement in the broker plus symlink refusal for exact-target evidence.
- Authenticated local daemon API for `/v1/*`.
- Private UDS production worker transport on Unix/WSL; loopback TCP is test/development transport.
- Fresh tri-state OCI capability probes; indeterminate results cannot become success.
- Dedicated verifier process that launches the actual byte-identical target and evaluates its own response oracle.
- Persisted ledger verification that checks stored hashes instead of rebuilding a new chain from possibly tampered payloads.
- Campaign-scoped ledger and graph persistence.

## Explicit non-controls / residual risks

- Campaign-bound OCI target execution is not complete; release remains blocked for claims requiring it.
- Local SQLite hash chains are tamper-detecting against payload edits that do not possess/rewrite all evidence correctly, but they are not yet externally/keyed anchored. An attacker with full database write access who recomputes every unkeyed chain value remains a residual threat.
- Rootless-container worker isolation still requires host-specific Podman acceptance evidence.
- E5 minimized reproduction, durable failure-memory and telemetry behavior are not yet complete.

Security documentation must distinguish these residual risks from implemented controls rather than marking the whole architecture `DONE`.
