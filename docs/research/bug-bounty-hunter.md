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

## How a person learns the job

The path from beginner to a working hunter is a sequence, and the later
chapters do not replace the earlier ones.

Vickie Li, *Bug Bounty Bootcamp* (No Starch Press, 2021, ISBN
9781718501546), is the beginner-to-professional book Jason Haddix's
application-analysis talk tells people to read. Part I is the industry:
pick a program whose asset type and rules you can follow (chapter 1), then
learn the report before the exploit catalog (chapter 2). Part II is HTTP,
a lab, and reconnaissance. Part III is the class catalog, from XSS through
access control, SSO, and information disclosure. Part IV is the expert
work: code review, Android, APIs, and fuzzing. AROS copies the order. It
does not copy the exploit procedures.

Peter Yaworski, *Real-World Bug Hunting* (No Starch Press, 2019), is the
field guide of disclosed reports that the same talk lists beside Li. The
lesson that matches this codebase is a report other people can replay.
This note does not quote the book. His earlier *Web Hacking 101* is the
same kind of field guide.

Dafydd Stuttard and Marcus Pinto, *The Web Application Hacker's Handbook*
(Wiley, 2nd ed., 2011), is the book that talk says to read twice. AROS
does not copy its attack catalog. The map-then-test order in this branch
comes from that talk's own sequence and from zseano's three steps.
The same talk also names the OWASP Web Security Testing Guide as the
checklist a hunter studies. AROS does not import that checklist as new
campaigns.

Sean "zseano" Roesner publishes the working flow at
<https://www.bugbountyhunter.com/zseano/>. Stay on one program and learn
its scope and features. Use the application as it was meant to be used,
and decide what a feature should be checked for, instead of spraying
payloads. The guide's own contents name three steps: get a feel for the
application, expand the attack surface, then automate and repeat, while
writing notes the whole time. He points beginners who still need ports
and the basics of the internet to Andy Gill, *Breaking into Information
Security*. This note uses the three step names and the "do not spray"
rule. It does not copy his finding write-ups.

## The working order

Jason Haddix split TBHM into reconnaissance and application analysis when
one talk could no longer hold both. The application-analysis talk at
NahamCon 2022 (<https://www.youtube.com/watch?v=HmDY7w8AbR4>, notes by
Trickster Dev at
<https://www.trickster.dev/post/notes-from-the-bug-hunters-methodology-application-analysis-v1/>)
and the TBHM tree at <https://github.com/jhaddix/tbhm> put technology
profiling and content discovery before class testing, and they keep that
discovery tied to the program's seed assets. The 2020 recon edition still
starts at those seeds. A wildcard is a research problem, not permission
to touch every host.

Before choosing classes, that talk asks six questions. AROS can answer
only the ones a local tree exposes:

1. How does the application pass data? HTTP paths, an API specification,
   a parser entry, or a one-shot entry, and only when that file or path
   was observed.
2. Where does it refer to users? A path containing `/users` is an
   observation. The identifier type is not invented.
3. Are there multiple principals or permission levels? A user surface can
   be observed. Distinct roles are not counted unless the tree showed them.
4. Does the asset have a unique threat model? Unanswered unless the tree
   showed one. The question adds no class.
5. What has already been published about this system? Not collected.
   Public web search is outside this hunt, so the question adds no class.
6. How does the application handle injection? Not observed from the
   profile. The question adds no class.

The talk names STÖK, Katie Paxton-Fear (InsiderPhD), zseano, NahamSec,
TomNomNom, and James Kettle as people whose public work hunters watch.
Those videos are about judgment on an application the hunter is allowed
to use. They are not a reason to scan a company from this host.

HackerOne's rule that a finder stops at proof still binds the end of the
hunt. A class list is a set of hypotheses. Bugcrowd still treats a
scanner-only or theoretical report as not applicable.

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
- `plan_bounty_hunt` follows the working order. It reads the program, stops
  if the asset is out of scope or not in scope, and does not map an asset
  it stopped on. Out of scope wins when the same path is on both lists.
  On an in-scope asset it records the six questions from local facts, then
  asks the existing campaign planner for classes. The surface map stays
  first when HTTP paths were observed. User classes require a `/users`
  path. File classes require a file path. Parser classes require `parse.py`.
  An empty map produces an empty class list. Questions that were not
  observed add no class. The notes say the list is hypotheses, that content
  discovery stays inside files already observed, and that the hunter stops
  at an independent reproduction. The hunt record has no `verified` field
  and no evidence level.

Still not this branch, and not honest to mark done:

- Live company hostnames, wildcards, ASN sweeps, and port scans.
- Directory brute force, historical URL collection, Nuclei-style template
  scans, and mobile-package harvesting. Those are how a public-internet
  hunter expands a hostname. v0.1 does not run them.
- The rest of Haddix's application classes (XSS, SQLi, CSRF, file upload,
  mobile) and Li's later chapters. AROS already has a small HTTP and parser
  pack. Those classes are not a full hunter.
- Distinct role counts, identifier types, and a unique threat model, until
  a local tree actually exposes them.
- Unwaived rootless containment. Without it, a waived run can still produce
  an eligible draft, and the draft says the run was not a contained release.
- Filing the draft to HackerOne, Bugcrowd, or the company.

`v0.1.0-mvp` stays blocked. Public-internet targets stay outside v0.1.
See `docs/architecture/adr/0009-bounty-scope-stays-local.md`.
