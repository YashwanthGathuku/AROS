# Platform threat model (v0.1)

## Assets

- AuthorizationManifest and policy engine
- Sandbox supervisor and host credentials
- Evidence ledger integrity
- Original target trees

## Adversaries

- Compromised or deceptive target content (README, comments, MCP text)
- Malicious Python worker / model output
- Attacker on the local network (out of scope for Internet scanning)

## Controls

- No authority in the LLM
- Typed IPC, default-deny network, argv broker
- Fail closed when containment is not demonstrated
- Independent verifier with reduced context
- Tamper-evident ledger
