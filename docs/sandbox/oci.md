# Rootless OCI

MVP provider: `RootlessOciSandboxProvider` (Podman preferred, Docker rootless
only if the same controls hold). Do not silently downgrade.

Hardening intent: non-root, drop caps, no-new-privileges, read-only rootfs,
tmpfs scratch, PID/memory/CPU limits, no host sockets or home, no privileged
mode. Source is read-only; mutable work is a scratch volume.

Builder sandboxes may fetch dependencies. Research sandboxes must not use
package install as an egress hatch.

Until isolation tests pass, `containment_demonstrated` stays false and
campaigns fail closed.

`ContainmentReport` records:

1. runtime present
2. machine reachable
3. `--internal` network
4. target reachable on that network
5. unauthorized external (1.1.1.1) denied
6. public DNS not an egress bypass
7. host gateway denied (or absent)
8. IPv6 does not bypass

`live_oci_claimable()` is true only when packet probes actually ran and all
five network tests passed. Missing alpine/busybox image, a down Podman
machine, or a failed probe is recorded as not demonstrated — never as
success. Tests do not pull images unless `AROS_OCI_PULL=1`.
