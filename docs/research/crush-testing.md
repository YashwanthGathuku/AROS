# Crush-testing research — what “break any project” can mean for AROS

Recorded: 2026-10-20, on `release/v0.1.0` after `768efe0`.

This note writes down the research requested that day: turn AROS into a
product that can take a project, stress it hard, and identify bugs and
loopholes. It is a research record. It does not add a campaign, a fuzzer,
or a containment proof. Nothing here moves a `BUILD_STATUS.md` item to
DONE.

AROS stays a local cyber-reasoning and evidence system. The targets are
snapshots the operator is allowed to run. Public-internet scanning stays
outside v0.1.

## The claim, and the limit

The useful product sentence is:

> For every entry point AROS can build, run until the budget ends, and
> emit either a minimized input that replays on a fresh copy, or a card
> that names the missing oracle, the missing entry point, or the missing
> engine.

“Every loophole in any project” is not a claim a fuzzer, a model, or this
repository can make. The evidence below is why the product is still worth
building, and why completeness is the wrong success metric.

A pass of the current release gate means the pack that ran did not verify
a break. `docs/research/testing-other-projects.md` already says that pass
is not a claim the project is safe.

## What the external evidence actually supports

Sources opened on 2026-10-20. Figures below are from those pages, not from
memory of a dashboard.

### Continuous fuzzing finds bugs when something keeps running

Shirai, Nourry, Kashiwa, Fujiwara, Kamei, and Iida, “Large-Scale Empirical
Analysis of Continuous Fuzzing,” arXiv:2510.16433 (submitted 2025-10-18),
HTML at <https://arxiv.org/html/2510.16433v1>.

They studied OSS-Fuzz logs: about 1.12 million fuzzing sessions from 878
projects, plus more than 3.95 million build logs, about 1 million coverage
reports, and over 70,000 issue reports. Findings they state:

- Many bugs are already in the tree before continuous fuzzing starts. In
  their sample, 36% of projects that found a fuzzing bug did so in the
  first session, and 20% in the second. After the 26th session the
  detection rate settles near 5%, and bugs still appear after thousands
  of sessions.
- Coverage in this continuous setting kept rising with the number of
  sessions. They report a correlation of 0.962 between cumulative sessions
  and coverage percentage. They contrast that with older long-session
  studies, which they say saw logarithmic growth.
- When a bug was found, coverage had increased in 51.6% of sessions,
  decreased in 27.9%, and stayed flat in 20.5%. When no bug was found,
  coverage was flat in 61.0% of sessions. They treat both a rise and a
  drop as a signal, and they tell researchers to aim fuzzing at the diff.

They also record the surrounding literature they rely on, which this note
did not re-open: Böhme et al. on coverage correlating with bugs, Liyanage
et al. on seven-day logarithmic coverage, recommendations of at least 24
hours and of campaigns on the order of a week to 30 days, Klooster et al.
on 15-minute CI sessions still catching critical bugs, and Zhu et al.
(2021) on 77% of fuzzing bugs coming from recent changes.

In the same paper, OSS-Fuzz as of their 2025 citation is described as
having integrated over 1,000 projects and as having led to more than
10,000 vulnerabilities and 36,000 bugs. That tally disagrees with
`related-systems-papers.md`, which says 13,000+ vulnerabilities and
50,000+ bugs, and with the Google blog below, which says over 11,000
vulnerabilities in eight years. This note does not pick a winner. The
live OSS-Fuzz statistics page was not opened.

### The harness is the bottleneck, then the sanitizer crash is the proof

Google’s OSS-Fuzz page “Fuzz target generation using LLMs,”
<https://google.github.io/oss-fuzz/research/llms/target_generation/>,
states that most integrated projects sit near 30% runtime coverage after
millions of CPU-hours, so about 70% of each project is never exercised.
It says many fuzz blockers are weak targets, not weak engines. The best
result they report there is TinyXML2, from 38% line coverage to 69%, and
a generated target that rediscovered CVE-2022-3602 in OpenSSL.

Google Online Security Blog, “Leveling Up Fuzzing: Finding more
vulnerabilities with AI,” 2024-11-20,
<https://security.googleblog.com/2024/11/leveling-up-fuzzing-finding-more.html>:

- AI-generated or AI-improved fuzz targets produced 26 new vulnerability
  reports in projects that had already had hundreds of thousands of
  fuzzing hours, including CVE-2024-9143 in OpenSSL. They say that bug
  had likely been present for about two decades and was not reachable
  from the human-written targets.
- Coverage improved in 272 C/C++ projects (previously 160), adding more
  than 370,000 lines. One project moved from 77 lines covered to 5,434.
- The workflow they describe is still execute-and-triage: draft a target,
  compile, run briefly, run longer on ClusterFuzz, then decide whether
  the crash is in the target or in the harness. A model that emits a
  crash story is not the report. They also say line coverage does not
  mean a function is free of bugs.

### AIxCC scored an input that misbehaves, plus a patch that stops it

Ze Sheng et al., “All You Need Is A Fuzzing Brain,” arXiv:2509.07225
(2025-09-08), abstract and HTML <https://arxiv.org/html/2509.07225v1>.
Fourth of seven AIxCC finalists. Their CRS reported 28 vulnerabilities,
six of them previously unknown, and patched 14. The paper’s definition of
a proof-of-vulnerability is an input that triggers a sanitizer error
through a fuzzer harness (libFuzzer or AFL for C, Jazzer for Java;
AddressSanitizer, MemorySanitizer, or UndefinedBehaviorSanitizer on C).
The patch has to stop the known proofs and still pass functionality
tests. Code: <https://github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain>.

Cen Zhang et al., “SoK: DARPA’s AI Cyber Challenge,” arXiv:2602.07666v5,
USENIX Security 2026, HTML <https://arxiv.org/html/2602.07666v5>. The
August 2025 final ran about 143 hours. Seven finalist systems analyzed 53
challenge projects in C and Java, with $85,000 of Azure compute and
$50,000 of model credit per team. Scoring used 48 challenge projects from
24 OSS-Fuzz repositories, containing 63 vulnerabilities. Five further
projects had no fuzzing harness and were excluded from scoring. A
proof-of-vulnerability in their scoring section is an input that triggers
abnormal execution, for example a crash. A patch scores higher because it
saves the developer the fix. A SARIF judgment scores lower.

Those two papers use different challenge counts (the SoK’s 53 analyzed /
48 scored, versus figures that appear in other write-ups). This note uses
the SoK HTML for the competition shape and the Fuzzing Brain abstract for
that one team’s 28 / 14 result. It does not merge them into one scoreboard.

## What AROS already has that matches this evidence

From `docs/AROS_MVP_SPEC.md` and the current tree:

| Spec or code | Why it matches the evidence |
|---|---|
| Evidence ladder E0–E7 | Same split as a proof-of-vulnerability, then an independent replay (E4), a shrunk input (E5), a patched twin (E6), and a variant plus regression (E7). |
| “No vulnerability without falsifiable evidence” | The Google triage example and the AIxCC proof rule say the same thing. |
| Independent verifier, re-attack after a fix | A patch is accepted only when the original proof stops firing and a variant is tried. |
| Target text is data | README, comments, issues, and MCP text cannot authorize a run or declare a bug. |
| Fail closed without demonstrated containment | A long fuzz run executes attacker-controlled bytes. The spec forbids that on the host when containment is unproven. |
| Disagreement research in the spec | Two interpreters of the same bytes, where one decides and the other acts. That is the differential oracle. |
| Anomaly notebook in the spec | A long run has to keep observations that are not yet vulnerabilities. |
| `campaign-loader/` harnesses stay outside the target | OSS-Fuzz’s own lesson: the harness is separate from the project. AROS already refuses to copy one into the tree. |

The catalog on disk, `campaign-loader/classes/`, is 22 campaign files
(the README in that directory is not a campaign):

- 17 HTTP campaigns. Twelve of them are `http-mr-*` metamorphic relations.
  `docs/BUILD_STATUS.md` and `docs/research/llm-free-slices.md` record
  that as 12 of the 76 MST-wi relations. The other five HTTP campaigns are
  `http-idor`, `http-unauth`, `http-cookie-confusion`,
  `http-path-traversal`, and `http-surface-map`.
- Five non-HTTP campaigns: `cli-crash`, `mutate-fuzz`, `prop-ascii`,
  `lib-call-twice`, `klee-run`.

`mutate-fuzz.campaign.json` allows 30 seconds and 64 MB. Its historical
note calls the built-in engine coverage-free mutation, with AFL++ or
libFuzzer only when those binaries and `bind.binary` exist.
`docs/RESEARCH_BACKLOG.md` RB-006 says this host does not have AFL++ or
KLEE, and that absence is not a security result.

`docs/research/testing-other-projects.md` states the entry-point rule in
force today:

| The tree contains | Campaigns that can say something |
|---|---|
| `server.py` or a loopback `bind.port` | HTTP classes |
| `parse.py` | `cli-crash`, `mutate-fuzz`, `prop-ascii`; `klee-run` only with bitcode |
| `once.py` | `lib-call-twice` |
| A pinned library plus an adapter beside AROS | the dycrpt pattern |

A tree with none of those holds or fails closed. It does not receive an
invented vulnerability.

Also still open in the status ledger, and relevant here: the anomaly
notebook is NOT STARTED; free-form assumption mining past one `http-idor`
oracle line is open; unwaived five-way rootless Podman has not been shown
on this Windows host; a waived run can verify its statement and must not
be `release_eligible`.

## Five oracles, and which bugs each one can carry

A brutal product is this stack. A larger model does not add an oracle.

1. **Crash, hang, and sanitizer.** The process dies, times out, or runs
   out of memory. AddressSanitizer and UndefinedBehaviorSanitizer, when
   the toolchain can emit them, turn silent memory corruption into a
   replayable report. This is the oracle that applies to a repo that
   states no invariant. It covers memory safety, panics, and many parser
   bugs. A permission check that returns success is invisible to it.

2. **Metamorphic relations.** A transform that must not change a security
   decision: drop the cookie, add an admin header, encode `../`, change
   the method. AROS has 12 of these for HTTP. The other 64 MST-wi
   relations stay out until a real tree discriminates a break from a
   relation that always holds. A relation with no negative control is how
   a crusher invents bugs. The catalog already fails closed on a
   non-discriminating mutant (`g4` in the campaign tests).

3. **Differential disagreement.** Two parsers, two decoders, or a
   normalizer and the component that enforces the decision, on the same
   bytes. The spec lists proxy/backend, validator/consumer,
   serializer/deserializer, and agent-policy/tool-executor. The dycrpt
   adapter is the implementation pattern: pin a revision, call the real
   function from `campaign-loader/adapters/`, write nothing into that
   repo. High-yield families for later adapters are path normalization,
   URL parsing, JSON, integer parsing, and crypto round-trips. A
   dependency advisory from a passive inventory is a lead. It is not this
   oracle.

4. **The project’s own guarantees.** Tests, assertions, and a precise
   oracle line are hypotheses until AROS executes them. Today one
   `INVARIANT.md` line can overlay `http-idor` only, and the stored
   assumption stays `Hypothesized` after a verified finding
   (`7306e42` on `main`, described in `docs/research/session-2026-09-22.md`).
   The product form is to mine candidate oracles from the project’s
   tests, store them as assumptions, and let Rust decide by running them.

5. **State and concurrency.** Sequences, not single requests: a session,
   an identity change, a nonce reused, a one-shot function called twice,
   two clients interleaved. `lib-call-twice` is one instance. A local HTTP
   state explorer and a ThreadSanitizer stress run are the general form.
   Single-request HTTP classes do not reach these bugs.

Oracles 2 through 5 are how logic bugs become evidence. Oracle 1 is how
an arbitrary repo gets an honest report when it states nothing: these
inputs crash, these inputs hang, and no logic invariant was available.

## What to build, in order

This order is the research conclusion. It is not scheduled work until a
later change says so.

1. **Containment, before a long run.** A multi-hour fuzzer feeds
   attacker-controlled bytes to a live process. Unwaived execution
   already fail-closes without a demonstrated rootless container. That
   behavior stays. Linux or WSL with rootless Podman is the host that can
   close it. This Windows machine cannot.

2. **Discover entry points the repo already has, and keep the harness
   beside AROS.** Existing `LLVMFuzzerTestOneInput` / `cargo fuzz` /
   Atheris targets, a public parse or decode function reached the way
   `decrypt` is reached, an OpenAPI or route map, a CLI that reads stdin.
   `TargetProfile` already records the ecosystem. It does not yet choose
   a crusher campaign from that record.

3. **Replace the 30-second smoke budget with a manifest budget of minutes
   or hours**, keep inputs that add edges, deduplicate by stack hash, and
   use the shrink and independent-replay path E5 and E4 already describe.
   Call AFL++ or libFuzzer when the binary is present. When it is absent,
   write a tool-gap card. The coverage-free mutator must not be described
   as coverage-guided.

4. **Sanitizer output is an observation.** It becomes E3 when the oracle
   matches, and E4 when a second process replays the same bytes. A
   generated patch is applied to a twin copy. It counts when the original
   proof still fires on the unpatched tree and stops on the twin.

5. **Widen logic testing only where an oracle exists.** More metamorphic
   relations that a real tree discriminates. Differential adapters for
   pinned dependencies. Assumption nodes mined from the project’s tests.
   The anomaly notebook is what makes hour six able to use hour one.
   Without it, each campaign forgets the last.

Left out of this product on purpose, because the spec already left them
out or marked them post-MVP: public-internet targets, automatic edits to
the original tree, a model assigning a severity or an evidence level, and
treating a waived host pass as containment.

## First implementation slice, when implementation starts

A contained, long-budget crash crusher for one discovered parser entry
point: sanitizer when the toolchain has one, coverage engine when that
binary exists, shrink, independent replay, and a failure card when the
entry point or the engine is missing.

That slice can be aimed at repos that are not shaped like `server.py`.
It does not invent a logic bug the tree never stated. The HTTP pack, the
remaining MST-wi relations, and state exploration stay later slices with
their own oracles.

## What this note did not do

- It did not open the live OSS-Fuzz statistics dashboard, so the 10,000 /
  11,000 / 13,000 vulnerability tallies stay unresolved.
- It did not re-read Böhme, Liyanage, Klooster, or Zhu. Those numbers
  appear only as citations inside Shirai et al.
- It did not run a fuzzer, a sanitizer, or Podman. The local facts are
  from the campaign files and the status docs cited above.
- It did not change `docs/BUILD_STATUS.md`. Implementation status is
  unchanged.
