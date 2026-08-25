# Adding a target adapter

MVP targets: source repository / CLI, and locally hosted web/API.

1. Represent the target as `Target` + `TargetKind`.
2. Snapshot via `snapshot_tree` (digest, git HEAD when present).
3. Put filesystem roots and loopback endpoints in `AuthorizationManifest`.
4. Do not add Internet scanning.
