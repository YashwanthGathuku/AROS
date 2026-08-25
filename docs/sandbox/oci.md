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
