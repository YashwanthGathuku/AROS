# AROS Research Backlog

Scientific and platform questions that need investigation. None of these block
Phases 0–5, fake-sandbox unit tests, IPC protocol design, fixtures, or the
mock research loop.

Status: `OPEN` | `INVESTIGATING` | `RESOLVED` | `POST-MVP`

---

## RB-001 Python 3.14 floor vs available interpreters

- **Question:** Can this development host and WSL provide Python 3.14, and do
  pydantic/httpx/protobuf support 3.14 free-threading?
- **Affects:** research worker runtime; `aros doctor`
- **Blocks development?** No. ADR-0003: implement 3.13-compatible worker code;
  doctor reports SPEC_TARGET vs REQUIRED.
- **Status:** RESOLVED — Python 3.14.7 on Windows (`py -3.14`, `PY_PYTHON=3.14`).
  pydantic/httpx/protobuf import on 3.14. Free-threading still not required.

## RB-002 Rootless OCI on WSL2

- **Question:** Can Podman rootless on this WSL2 kernel (6.6.87.2-microsoft-standard-WSL2)
  demonstrate the five network-containment tests (target reachability, deny
  external, DNS bypass, host gateway, IPv6)?
- **Affects:** `RootlessOciSandboxProvider`; acceptance check C
- **Blocks development?** No for unit tests. Live campaigns fail closed until
  containment is demonstrated.
- **Status:** INVESTIGATING — `podman-machine-default` WSL2 rootless starts;
  `--internal` network inspect probe passed via `aros doctor`. Packet-level
  egress/DNS/IPv6 tests still open.

## RB-003 Windows AF_UNIX for IPC unit tests

- **Question:** Does Tokio `UnixListener` work reliably on this Windows host
  for framed Protobuf tests, or is a loopback-TCP+HMAC test transport needed?
- **Affects:** `aros-ipc` developer tests
- **Blocks development?** No. Production IPC remains Linux/WSL UDS.
- **Status:** RESOLVED — loopback TCP + daemon-issued token (Hello.token)
  used on Windows. Unix domain sockets remain the Linux production path.

## RB-004 Grok Build harness surface

- **Question:** What CLI/API does Grok Build actually expose in this
  environment for `GrokBuildHarness`?
- **Affects:** harness adapter
- **Blocks development?** No. NativeHarness + mock is the MVP default;
  Grok adapter is capability-detected.
- **Status:** RESOLVED — inspected `grok --help` (2026-08-25): positional
  prompt, `--cwd`, `--agent`, `--allow`/`--deny`, `--disable-web-search`.
  Adapter never passes `--always-approve`.

## RB-005 THEUSTAD availability

- **Question:** Is THEUSTAD installed locally, and which transport (process,
  HTTP, Unix socket) should `TheustadAdapter` use?
- **Affects:** evidence authority
- **Blocks development?** No. `BuiltinEvidenceAuthority` is required; THEUSTAD
  is optional.
- **Status:** OPEN — not installed on this host.

## RB-006 Optional analysis engines

- **Question:** Which of CodeQL, Semgrep, AFL++, ASan, property-test frameworks
  are present and worth wiring as optional adapters in v0.1?
- **Affects:** specialist tool adapters
- **Blocks development?** No. Core remains functional without them.
- **Status:** INVESTIGATING — git and clang present; semgrep, CodeQL, AFL++
  absent. Optional detector: `aros-core::adapters`.

## RB-007 Stronger isolation providers

- **Question:** When should gVisor or Firecracker replace rootless OCI?
- **Affects:** SandboxProvider hierarchy
- **Blocks development?** No.
- **Status:** POST-MVP

## RB-008 Time-travel evaluation

- **Question:** How should knowledge cutoff and pre-disclosure snapshots be
  enforced for future CVE rediscovery benchmarks?
- **Affects:** historical graph; evaluation quarantine
- **Blocks development?** No. Schema support only in v0.1.
- **Status:** POST-MVP
