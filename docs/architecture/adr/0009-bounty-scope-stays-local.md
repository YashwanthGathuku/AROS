# ADR-0009: A bounty scope file does not open the public internet

- Status: Accepted
- Date: 2026-11-03

## Problem

Company bug-bounty work starts from a written program scope and ends in a
report someone else can replay. AROS v0.1 had neither artifact. Adding them
by accepting the hostnames from a HackerOne brief would contradict the spec
rule that public-internet targets are outside v0.1, and it would treat a
file as authorization.

## Alternatives

1. Parse platform briefs and hunt every in-scope hostname.
2. Keep bounty behavior out of the tree until containment exists.
3. Accept a local program file and emit a report draft only for a local tree
   or a loopback asset, and only after independent reproduction.

## Decision

Alternative 3. The scope file records the program id, the disclosure mode,
and the program's own safe-harbor claim. In-scope and out-of-scope assets
are local trees or loopback endpoints. A public name, a public address, a
URL, or an unknown field is rejected. Out of scope wins over in scope. The
hazardous activities named by the HackerOne Code of Conduct stay forbidden
and the file cannot permit them. The report draft follows the Bugcrowd /
Vickie Li sections and stays `submitted: false`. Evidence below E4, a missing
independent reproduction, or an unverified finding produces an ineligible
draft. AROS does not grant safe harbor and does not send the draft.

## Consequences

Hunters and companies can rehearse the scope-and-report contract on a
checkout they already have. A waived host run may be eligible as a draft and
is still not `release_eligible`. Live program assets, the remaining bug
classes, and submission stay later. The security invariants are unchanged:
no authority in the model, no vulnerability without the existing evidence
ladder, and no public-internet target in v0.1.
