# Adding a sandbox provider

Implement `SandboxProvider`:

prepare, build_target (via spawn/prepare split), spawn, execute, snapshot,
reset, freeze, collect, destroy.

Never report `containment_demonstrated` unless the five network tests pass.
gVisor and Firecracker are post-MVP.
