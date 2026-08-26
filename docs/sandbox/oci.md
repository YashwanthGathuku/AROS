# Rootless OCI

MVP provider: `RootlessOciSandboxProvider` with Podman. Do not silently downgrade containment.

Security admission uses **fresh measurements**. A previous successful probe is not cached across later campaigns because the Podman machine, routes, network configuration, or host policy may have changed.

`ContainmentReport` records runtime/machine/internal-network state plus five packet dimensions:

1. authorized target reachable on the isolated network
2. unauthorized public IPv4 denied
3. public DNS cannot bypass isolation
4. host/gateway path denied or absent
5. IPv6 cannot bypass isolation

Each packet dimension is tri-state:

- `proven` — the required containment property was positively demonstrated
- `failed` — the probe ran and demonstrated the unsafe/opposite property
- `indeterminate` — the property could not be measured reliably

Before interpreting a network command failure as a deny, the probe image must pass a tool-execution preflight. Missing tools, container execution failure, and timeouts therefore become `indeterminate`, not successful denial evidence.

`live_oci_claimable()` is true only when the runtime is present, the machine is reachable, the network is demonstrably internal, packet probes actually ran, and **all five tri-state outcomes are `proven`**. Compatibility boolean fields are never authoritative for security admission.

Tests do not pull probe images unless `AROS_OCI_PULL=1`. For the final release gate, run `AROS_REQUIRE_LIVE_OCI=1 ./scripts/acceptance.sh` after starting the Podman machine.
