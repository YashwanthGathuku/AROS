# How a bug bounty actually works

Research note for the `bounty-hunter` branch. Read before treating AROS as a
company hunting agent. Sources were read on 2026-11-03. This note does not
authorize public-internet testing.

## What the programs require

A bounty is a contract, not a scan.

HackerOne's Code of Conduct forbids testing that the program did not
authorize. That includes exploiting past the proof, using production
credentials the policy did not approve, changing production data, denial of
service, social engineering, noisy spam, and physical attacks. Hazardous
tests stay forbidden unless the program explicitly allows them. Finders are
responsible for their own tools. Source:
<https://www.hackerone.com/policies/code-of-conduct>.

HackerOne's scope guidance tells the company to name each asset, to list
out-of-scope assets on purpose, and to say which assets pay a bounty.
Source: <https://docs.hackerone.com/en/articles/8495670-scope-best-practices>.

Safe harbor is the company's written permission for good-faith research, not
a tool's opinion. disclose.io's full safe harbor is an authorization against
anti-hacking laws, an anti-circumvention carve-out, a terms-of-service
carve-out, and a good-faith statement, plus a clear scope and a disclosure
channel. Source: <https://disclose.io/framework/terms/safe-harbor/> and
<https://disclose.io/framework/>. AROS records what a program file claims. It
does not grant safe harbor.

Bugcrowd's report form asks for a title, the target, a VRT classification,
the location, a description, a walkthrough, evidence, and demonstrated
impact. A report against an out-of-scope target is penalized. Reports that
are only scanner output, or only a theory with no proof, are not applicable.
Source: <https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/>
and the Bugcrowd program text that classifies unproven scanner output as
Not Applicable. The VRT is a P1–P5 baseline. P5 is informational. Impact
still depends on the function. Source:
<https://bugcrowd.com/vulnerability-rating-taxonomy>.

## What experienced hunters repeat

Jason Haddix's Bug Hunter's Methodology separates reconnaissance from
application analysis. The public notes start from the program's seed assets,
then map, then study authorization and session, and only then look at bug
classes. Crowdsourced work pays for unique impact, not for a count of easy
findings. A report template that names the wrong host is invalidated.
Source: <https://github.com/jhaddix/tbhm> (`01_Philosophy.md`, and the
mapping / authorization sections). The 2020 recon edition, as summarized by
Trickster Dev, starts the tree at the program's root domains and treats
wildcards as a research problem, not as permission to touch every host.

Vickie Li, *Bug Bounty Bootcamp* (No Starch Press, 2021, ISBN
9781718501546), puts the report before the exploit catalog. The report steps
in chapter 2 are: a descriptive title, a summary, a severity, numbered
reproduction steps, a proof of concept, the impact, a possible mitigation,
and a check that the report is valid. The book also separates program scope,
asset type, and response time from the hunt itself. AROS uses those report
parts. It does not copy the book's exploit procedures into this slice.

Peter Yaworski's *Web Hacking 101* is the earlier field guide of real
disclosed reports. The lesson that matches this codebase is the same one Li
and Bugcrowd state: a report other people can replay. This note does not
quote the book.

## What AROS will copy, and what stays later

Copied into this branch as code:

- A program file with an id, an organization, a disclosure mode, the
  program's own safe-harbor claim, a minimum evidence level of E4 or higher,
  explicit in-scope assets, and explicit out-of-scope assets.
- Assets in v0.1 are a local tree or a loopback address. A public name, a
  public address, or a URL is rejected even if the file lists it.
- The hazardous set is always on: denial of service, social engineering,
  physical access, production modification, and excessive data access. The
  file cannot permit them.
- A report draft in the Li / Bugcrowd shape. It is eligible only when the
  target is in scope, not out of scope, the finding is verified, reproduction
  was independent, and the evidence level is at least E4 and at least the
  program minimum. `submitted` stays false. AROS does not send the report.

Still not this branch, and not honest to mark done:

- Live company hostnames, wildcards, ASN sweeps, and port scans.
- The rest of Haddix's application classes (XSS, SQLi, CSRF, file upload,
  mobile) and Li's later chapters. AROS already has a small HTTP and parser
  pack. Those classes are not a full hunter.
- Unwaived rootless containment. Without it, a waived run can still produce
  an eligible draft, and the draft says the run was not a contained release.
- Filing the draft to HackerOne, Bugcrowd, or the company.

`v0.1.0-mvp` stays blocked. Public-internet targets stay outside v0.1.
See `docs/architecture/adr/0009-bounty-scope-stays-local.md`.
