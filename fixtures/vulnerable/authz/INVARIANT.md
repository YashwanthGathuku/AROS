# Security invariant

User 1 must not read user 2's `secret`.

Oracle: authenticated as `Cookie: user=1`, `GET /users/2` must not contain `bob-secret`.

Functional test: `GET /users/1` as user 1 returns alice.

Non-destructive.
