# Security Policy

AROS is an authorized, local/sandbox-only adversarial research platform.

## v0.1 scope

Do not use AROS against systems you do not own or do not have explicit
written authorization to test.

v0.1 does not autonomously attack public Internet targets.

Default network policy is deny (`0.0.0.0/0` and `::/0`).

## Reporting a vulnerability in AROS itself

Please do **not** open a public issue for security flaws in AROS.

Email or otherwise privately notify the maintainers with:

- affected version / commit
- reproduction against a local fixture or the AROS control plane
- impact (authorization bypass, sandbox escape, evidence tampering, etc.)

Do not include secrets, live target data, or exploit code against third parties.

## Non-goals for reporters

- Findings that require weakening containment to demonstrate
- Public-Internet scanning reports
- Model-provider jailbreaks that do not bypass deterministic policy
