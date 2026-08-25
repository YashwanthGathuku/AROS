# Sandbox security model

Default deny network (`0.0.0.0/0`, `::/0`).
Researcher and target are intended to sit on an AROS-managed internal network.
If containment cannot be proven, campaigns fail closed (ADR-0004).
`--operator-waive-containment` is an explicit lab waiver, recorded as unsafe.
