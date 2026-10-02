# v0.1.0 foreign-project validation log

Status: **code-side validation in progress; host containment acceptance pending**

This document records what was actually attempted while closing v0.1.0. It deliberately separates executed evidence from source inspection and from operator-only work.

## Environment used by the assistant

The available execution container on 2026-10-02 had:

- Python 3.13.5.
- No Rust toolchain (`rustc` and `cargo` absent).
- No Podman.
- No Docker.
- No outbound DNS/network from the shell; direct `git clone` of GitHub repositories failed with `Could not resolve host: github.com`.
- GitHub repository contents remained available through the connected GitHub integration.

Consequences:

1. Rust compilation, Clippy, Rust unit/integration tests, and the real `aros target profile` binary could **not** be executed in this container.
2. Live OCI isolation and campaign-bound five-way packet probes could **not** be executed here.
3. Source changes were inspected through GitHub and foreign-project metadata/source was retrieved through GitHub.
4. A local surrogate of the deterministic profiler rules was executed in Python only to validate the expected classification logic. This is **not** counted as a Rust AROS test.

## Foreign project selected: VAmPI

Repository: `erev0s/VAmPI`

Why this target:

- It is independent of AROS and was not designed around AROS fixture names.
- It is a Flask/OpenAPI API.
- It has a Dockerfile and Compose topology.
- Compose provides vulnerable and secure configurations of the same application, which is useful for false-positive and counterfactual testing.
- Its documented API includes authorization/authentication/data-exposure weaknesses, making it a useful future test for AROS's HTTP/API research pack.

Files inspected from the upstream `master` branch:

- `requirements.txt`
- `Dockerfile`
- `docker-compose.yaml`
- `app.py`
- `openapi_specs/openapi3.yml`
- `README.md`

Observed target facts:

- Python/Flask/Connexion application.
- `app.py` starts the service on port 5000.
- Docker image exists.
- Compose declares:
  - `vampi-secure` with `vulnerable=0` on host port 5001.
  - `vampi-vulnerable` with `vulnerable=1` on host port 5002.
- OpenAPI 3 specification declares the HTTP surface and bearer authentication.

## Profiler work performed

Release branch: `release/v0.1.0`

Implemented:

- `crates/aros-core/src/target_profile.rs`
- exported profiler from `aros-core`
- CLI entry point: `aros target profile <path>`

The profiler is deterministic and does not infer vulnerability. It inventories project facts such as:

- ecosystem/manifests;
- source extensions;
- likely entry points;
- test markers;
- Docker/Compose markers;
- CI markers;
- planning capability hints.

The first local surrogate classification, built only from upstream VAmPI facts, produced:

```json
{
  "ecosystems": ["python"],
  "manifests": ["requirements.txt"],
  "entrypoints": ["app.py"],
  "container_markers": ["Dockerfile"],
  "capabilities": [
    "buildable",
    "cli_candidate",
    "container_build",
    "http_candidate",
    "library_candidate",
    "python",
    "source_inspection"
  ]
}
```

The full upstream tree also contains `docker-compose.yaml`, so the real Rust profiler should additionally identify `compose_topology` when executed against a full clone.

### Important limitation

The result above was produced by a small Python reproduction of the profiler's deterministic classification rules because this environment has no Rust compiler and cannot clone repositories from the shell. It proves the expected classification of the observed files; it does **not** prove the Rust implementation compiles or behaves identically.

## What must be executed on the operator host

### A. Validate the release branch

From PowerShell/WSL:

```bash
git fetch origin
git switch release/v0.1.0
git pull --ff-only

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace

python -m ruff check python scripts
python -m mypy python/aros_research
PYTHONPATH=python python -m pytest python -q
```

Do not continue to foreign-target execution if any command fails. Preserve the first failing command/output in this document or an issue.

### B. Clone the foreign target

Only use the intentionally vulnerable project locally.

```bash
mkdir -p external-targets
cd external-targets
git clone https://github.com/erev0s/VAmPI.git
cd VAmPI
git rev-parse HEAD
```

Record the commit SHA. Do not expose the application to a public interface.

### C. Run AROS profiling

From the AROS checkout:

```bash
cargo run -p aros-cli -- target profile ../external-targets/VAmPI
```

Expected minimum facts:

- ecosystem contains `python`;
- manifest includes `requirements.txt`;
- entry point includes `app.py`;
- container marker includes `Dockerfile`;
- Compose marker includes `docker-compose.yaml`;
- capabilities include `source_inspection`, `python`, `buildable`, `http_candidate`, `container_build`, and `compose_topology`.

A mismatch is a profiler defect; do not manually override the result and call the test passed.

### D. Run VAmPI only in the local contained test environment

VAmPI is intentionally vulnerable. Do not publish its ports beyond loopback.

First start/verify Podman:

```bash
podman machine start
cargo run -p aros-cli -- doctor
```

The AROS release gate must demonstrate all five packet properties before an unwaived contained result is claimable.

For a direct upstream sanity check, VAmPI's Compose file exposes secure/vulnerable twins on 5001/5002. If you run upstream Compose outside AROS for comparison, bind/limit it to your local machine and stop it after the test.

### E. Foreign-project AROS acceptance goal

The final v0.1 foreign-project proof is **not** "AROS recognizes VAmPI." It is:

1. profile the unfamiliar checkout;
2. derive its API/container capabilities without AROS-specific filenames;
3. map its declared/live HTTP surface;
4. select only applicable research classes;
5. execute against the authorized vulnerable twin in campaign-bound containment;
6. independently reproduce a candidate finding against a pristine target;
7. test the secure twin as a negative/counterfactual control where applicable;
8. persist evidence/provenance;
9. leave the upstream checkout byte-identical;
10. report unsupported research classes as unsupported/held rather than inventing findings.

Until those steps execute, VAmPI is a **foreign-target profiling candidate**, not a completed AROS vulnerability scan.

## Pending v0.1 work after profiling

Release-blocking:

- compile/test the new target profiler;
- persist/consume TargetProfile in planning;
- remove special-filename assumptions from generic project onboarding;
- parse common API descriptions (OpenAPI is the first high-value case);
- derive applicable campaign classes from capabilities/surface rather than fixture labels;
- execute at least one genuinely foreign project end to end;
- demonstrate campaign-bound OCI on the operator host;
- run the complete release acceptance suite on one clean commit;
- update BUILD_STATUS/README with only demonstrated claims;
- tag v0.1.0 only after the host evidence exists.

Explicitly deferred to v0.2:

- public-Internet targets;
- gVisor/Firecracker/Kata;
- mobile targets;
- large historical corpora;
- broad MCP/agent target classes;
- distributed workers;
- web UI.

## Evidence policy for this validation

A source-inspected fact is labelled **observed from source**.
A surrogate classifier result is labelled **surrogate**.
A Rust test is only labelled **passed** when Cargo actually executes it.
OCI containment is only labelled **demonstrated** when the real campaign network and target pass the live probes.
