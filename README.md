# AROS

Autonomous Adversarial Research OS (temporary codename).

AROS is a locally runnable, model- and harness-independent platform for
**explicitly authorized** local and sandbox security research. It is not a
scanner, not a Kali wrapper, and not a chatbot that shells out to tools.

Authoritative specifications:

- [`docs/AROS_MVP_SPEC.md`](docs/AROS_MVP_SPEC.md) — what v0.1 must do
- [`docs/TECH_STACK.md`](docs/TECH_STACK.md) — runtime, process, and language ownership
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
- [`docs/BUILD_STATUS.md`](docs/BUILD_STATUS.md)

## Architecture

```text
aros (CLI) → arosd (trusted Rust) → typed Protobuf IPC → Python research worker
                                      ↓
                               rootless OCI sandbox
                                      ↓
                          local fixtures / authorized targets
```

Rust owns authorization, policy, sandboxing, brokering, evidence, and state.
Python owns replaceable research intelligence only. The LLM never authorizes.

## Quick start

```bash
# Linux / WSL recommended for sandbox containment
./scripts/bootstrap.sh
./scripts/doctor.sh
cargo test --workspace
./scripts/acceptance.sh
```

Windows host (unit tests of the trusted core; containment fail-closed without OCI):

```powershell
cargo test --workspace
python -m pytest python
```

Run a local demo against repository fixtures (mock provider, no paid API):

```bash
./scripts/demo.sh
```

## License

Apache-2.0. See `LICENSE`.
