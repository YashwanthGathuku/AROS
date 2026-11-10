# Related systems, papers, and LLM-free agents

Last updated: 2026-11-10. Sections 1–7 are the 2026-09-15 survey. Section 8
is a check of those neighbors against public pages opened on 2026-11-10.
The 2026-10-20 product research that uses this survey is `crush-testing.md`.
That note also records the OSS-Fuzz vulnerability-tally conflict with the
figures in section 2.1. Section 8 does not resolve that tally: the live
OSS-Fuzz statistics dashboard was not opened.

This note is a working bibliography for AROS: what already exists that is
*like* a local autonomous red team, which **proven** papers make AROS faster
and more honest, and how to run the research loop **without an LLM**.

AROS is not PentestGPT. The useful overlap is: **map a target, run
experiments, demand a proof, re-attack a fix, stay inside a sandbox.**
The useful non-overlap is: AROS keeps policy and verdicts in deterministic
Rust. Language models, if used at all, only propose.

---

## 1. What AROS is, in this landscape

| AROS already does | Closest external name |
|---|---|
| Local/sandbox, fail-closed, authorized targets only | Cyber reasoning system (CRS), not a SaaS pentest |
| Class campaigns + catalog harnesses + oracle | Metamorphic / property tests for security |
| Evidence ladder E0–E7, independent verifier | “Creative AI discovers; deterministic logic decides” (XBOW) |
| Skills as data, not enum variants | Hierarchical task network / skill catalog |
| No authority in the LLM | Symbolic / policy guardrails for agents |

The 2026 market and literature agree on one thing AROS already encoded:
**volume of AI findings is worthless; a working exploit or sanitizer crash
is the unit of evidence.** Cobalt’s 2026 pentest survey reported that
practitioners soured on autonomous pentest tools that miss critical bugs
and flood dashboards. AROS must stay on the proof side.

---

## 2. Closest applications and frameworks

### 2.1 Autonomous cyber reasoning (copy architecture, not branding)

| System | What it is | Why it matters to AROS | License / access |
|---|---|---|---|
| **DARPA CGC 2016 — Mayhem (ForAllSecure / CMU)** | First all-machine CTF winner. Symbolic execution + fuzzing, no LLM. Found bugs, generated PoCs, patched, **and QA’d patches** so they did not wreck performance. | Proof that a **non-LLM CRS** can find, prove, and fix. AROS’s library/CLI pack should grow toward Mayhem’s “behavior testing” (concolic + fuzz), not toward chat. | Commercial Mayhem; CGC corpora at MIT Lincoln Lab |
| **DARPA AIxCC 2023–2025 — ATLANTIS (Team Atlanta)** | 1st place CRS. LLM **plus** symbolic execution, directed fuzzing, static analysis. PoV (proof of vulnerability) + patch required to score. [arXiv:2509.14589](https://arxiv.org/abs/2509.14589) | **Do this split:** program analysis finds crashes; LLM (optional) localizes. Scoring on PoV is AROS’s evidence ladder. | Artifacts promised; SoK [arXiv:2602.07666](https://arxiv.org/abs/2602.07666) |
| **AIxCC — Trail of Bits (2nd), Theori RoboDuck (3rd)** | Same contest. Theori: LLMs for PoV, patch, crash RCA; they warn naive LLM integration is risky. | Use LLMs only behind oracles. Their blog “Building Effective LLM Agents” is a playbook for *when* to call a model. | Open-source CRS releases expected |
| **Microsoft MDASH / ACS** | Multi-model agentic scanning; 16 Windows vulns including RCEs; 88.45% on CyberGym. Built by people from Team Atlanta. | Ensemble of **specialists** (not one chat). AROS skills catalog is the cheap version of that. | Private preview |
| **Google OSS-Fuzz + ClusterFuzz + libFuzzer/AFL++/Honggfuzz** | Continuous fuzzing. As of 2025: 13,000+ vulns, 50,000+ bugs, 1,000 projects. ClusterFuzz: minimize, bisect, dedup. | **Highest-ROI LLM-free engine AROS can adopt as a generator kind.** `generator.kind: fuzzer` is already in the campaign schema. | Apache-2.0 (ClusterFuzz, OSS-Fuzz configs) |
| **Google Big Sleep** (DeepMind + Project Zero) | AI agent that searches for unknown vulns in software. | Optional research-plane specialist, never the oracle. | Lab system |
| **KLEE** (Cadar et al., Imperial / Stanford lineage of EXE) | Symbolic execution on LLVM. High coverage on COREUTILS; found 15-year-old bugs. | Parser/CLI class pack: KLEE as a catalog generator. SHA-3 buffer overflow found with KLEE (Mouha). | Open source |
| **Microsoft SAGE** | Whitebox fuzzing; ~1/3 of Windows 7 file-fuzzing bugs. Binary-level DSE + Z3. | Same idea as KLEE for closed binaries. AROS v0.1 stays source/local; SAGE is the post-MVP binary path. | Internal MS |

### 2.2 Autonomous pentest products (do not clone)

| System | Fit | What not to copy |
|---|---|---|
| **XBOW** | Web/API exploit proof; separate validation layer; “Creative AI discovers. Deterministic logic decides.” | Public-internet targeting; SaaS; claiming zero false positives without an AROS-style ledger |
| **NodeZero / Pentera** | Internal network / cloud attack paths | Out of AROS v0.1 scope (network enterprise, not local project) |
| **Astra, Bright AI PT** | Web/API continuous pentest | Scanner UX; no evidence ladder |
| **Stingrai Snipe** | IDOR / BOLA / business logic | Hybrid human validation as a *product*, not as AROS’s oracle |
| **CAI** (alias1 / Mayoral-Vilches et al.) | Open-source agent framework; CTF wins 2025 | Autonomy-without-sandbox; CTF ≠ release gate |
| **PentestGPT** (USENIX Security 2024) | Modular LLM sessions + pentest task tree | Human-in-the-loop chat; no containment; no CAS |
| **AutoPentest / AutoPentester** | LangChain + tools on HTB | Costly LLM loops; weak proofs |
| **strix, Darkmoon, DeepAudit** | Open-source AI pentest / Docker exploit validation | Useful as *ideas*; DeepAudit’s sandbox+validation is closest in spirit |

**Positioning:** AROS is a **local CRS + evidence OS** for *your* repos before release. It is not a network pentest platform and not a CTF agent.

### 2.3 Benchmarks AROS should run against (quality, not marketing)

| Benchmark | Who | What to steal |
|---|---|---|
| **CyberGym** [arXiv:2506.02548](https://arxiv.org/abs/2506.02548) | UC Berkeley (Dawn Song et al.) | 1,507 real vulns / 188 projects from OSS-Fuzz. Task = **PoC that reproduces**. Top agents ~20% in early evals. **AROS gate should be scored like this: PoC or nothing.** |
| **CyberGym-E2E** [arXiv:2606.04460](https://arxiv.org/abs/2606.04460) | Berkeley | Discovery + PoC + patch + functional tests. Finding is easier than proving; patching given a PoC is easier than discovery. Matches AROS E3 vs E4 vs E6. |
| **Cybench** | Public CTF-style LLM eval | Anthropic used it; models jumped from ~5% to ~33% in a year. Saturated for chat; still useful as a *negative* control (AROS must not only solve CTFs). |
| **FuzzBench** | Google | Compare fuzzers fairly. When AROS adds `kind: fuzzer`, score it here. |
| **AIxCC scoring** | DARPA | Points only for **executable PoV + correct patch that preserves function**. Directly maps to AROS re-attack + twin. |

---

## 3. Proven papers that make AROS faster, cheaper, better

Priority is **adopt into generators/oracles**, not “cite in a pitch.”

### 3.1 Program analysis (LLM-free, high yield)

| Paper / system | Result | AROS use |
|---|---|---|
| Cadar et al., **KLEE**, USENIX OSDI 2008 | 84.5% COREUTILS line coverage; 56 serious bugs | Catalog generator `klee` for C/C++/LLVM parsers |
| Godefroid, Levin, Molnar, **SAGE**, CACM/Queue 2012 | ~1/3 of Win7 file-fuzz bugs; 24/7 on 100+ cores | Binary/whitebox path after v0.1 |
| Zalewski **AFL**; Fioraldi et al. **AFL++** | Coverage-guided mutation; OSS-Fuzz default | `generator.kind: fuzzer` + sanitizers (ASan/UBSan) |
| Serebryany **libFuzzer** / **AddressSanitizer** | In-process, cheap | Same |
| **OSS-Fuzz** (Google) | 13k+ vulns at scale | Continuous class: every commit fuzzes the same harness |
| Mouha, **SHA-3 overflow via KLEE** (KLEE Workshop 2024) | Differential symbolic check of “update once vs twice” | Template for `lib-call-twice` on crypto/parsers |

### 3.2 Oracles without a human (the AROS bottleneck)

| Paper | Result | AROS use |
|---|---|---|
| Chen, Kuo, et al. **Metamorphic testing** survey | When there is no true/false oracle, check **relations** between outputs | Class oracles: “same cookie, different id → not the other user’s secret”; “encode∘decode = id” |
| **MST-wi**, IEEE TSE 2023 | 76 system-agnostic metamorphic relations for **web security**; 85% of Jenkins/Joomla vulns; 99.81% specificity; new Jenkins vuln | **Import this catalog as HTTP class campaigns.** Highest-leverage paper for AROS web pack. Covers ~45% of CWE design-principle vulns. |
| Claessen & Hughes, **QuickCheck**, ICFP 2000 | Property-based testing + shrinking | Library pack: properties, not example tests. Shrinking = AROS E5. |
| IACR ePrint 2024/1122 (crypto metamorphic + AFL++) | Bit-contribution / bit-exclusion crashes if crypto properties fail | Crypto class pack without writing dycrpt-specific oracles by hand |

### 3.3 Autonomous pentest / CRS (architecture)

| Paper | Result | AROS use |
|---|---|---|
| Deng et al., **PentestGPT**, USENIX Security 2024 | Split reasoning / generation / parsing; pentest task tree; +228% vs GPT-3.5 | **Task tree = AROS graph.** Do **not** copy the chat UX. |
| Team Atlanta, **ATLANTIS**, arXiv:2509.14589 | Winner AIxCC: LLM + directed fuzz + symbolic | Hybrid generators; LLM never scores |
| SoK AIxCC, arXiv:2602.07666 | What actually won: PoV+patch scoring, not chat quality | Keep AROS scoring as evidence levels |
| Wang, Shi, He, Song et al., **CyberGym**, arXiv:2506.02548 | Hard real-world PoC benchmark | Future AROS eval target |
| AutoPT / state-machine pentest agents | FSM constrains LLM | AROS already has campaign state machine — keep it |
| Expert Systems w/ Applications 2026, **RL pentest review** | RL for attack-path planning vs full pentest | Later: planner over class campaigns, not packet RL |

### 3.4 Lab / university sources (requested)

| Org | Artifact | Takeaway for AROS |
|---|---|---|
| **Google / OSS-Fuzz / FuzzBench / ClusterFuzz** | Continuous fuzzing infra | First LLM-free generator to wire after HTTP classes |
| **Google DeepMind** | Cyber-attack-chain eval; Big Sleep with Project Zero | Optional research agent; keep sealed evals (see Anthropic incidents) |
| **Anthropic** Frontier Red Team (2025); eval incident post (2026) | Cybench progress; **models escaped eval networks** and hit real orgs | **Mandatory:** AROS evals never get a route to the public internet. Their incident is the threat model for `require_containment`. |
| **OpenAI** | Agent red-teaming challenge (ART, with UK AISI); model-card jailbreak evals | Multi-turn attacks beat single-turn 2–10× (Cisco too). AROS class campaigns must be **multi-step** (map → bind → attack → negative control). |
| **UC Berkeley (Dawn Song / RDI)** | CyberGym, CyberGym-E2E | PoC-or-nothing scoring |
| **Georgia Tech + KAIST + POSTECH + Samsung** | ATLANTIS | Hybrid CRS |
| **CMU / ForAllSecure** | Mayhem, CGC | LLM-free CRS; patch QA |
| **MIT Lincoln Lab** | CGC corpora | Historical CRS test corpus |
| **Imperial / KLEE community** | KLEE, SHA-3 case | Parser classes |
| **Stanford-adjacent / USENIX** | PentestGPT (NTU/Aalto/etc., USENIX) | Task tree, not Stanford-owned but venue-grade |
| **Harvard** | No flagship CRS paper in this sweep comparable to Berkeley/CMU/GT; treat as gap, not a blocker | — |

If a Harvard or Stanford CRS paper appears later, add it here. Do not invent one.

---

## 4. How to run AROS agents **without an LLM**

This is not a compromise. For AROS it is the **preferred default**.
The spec already says the model never authorizes and never adjudicates.
The class pack and gate already run with zero tokens.

### 4.1 What “agent” means here

An AROS agent is anything that:

1. picks the next experiment from a **finite, declared** set;
2. runs it through policy in a sandbox;
3. records an observation;
4. updates a graph / campaign state;
5. stops when budget, evidence, or fail-closed fires.

No language model is required for that loop.

### 4.2 Stack (cheapest → richest)

```text
Level 0  Class pack + gate          (SHIPPED)
         HTTP/CLI campaigns, oracles, surface.json
         Cost: $0 tokens. Deterministic.

Level 1  Hierarchical task network over skills
         skills/*.json already exist (20 skills).
         Compile each skill to: required_facts → experiment_strategy
         → catalog harness + bind.
         Planner: if surface has /users/2, run http-idor.
                 if parse.py exists, run cli-crash.
         No LLM. Same as classical HTN / GOAP / behavior trees.

Level 2  Classical planner (PDDL / Fast Downward)  (SHIPPED builtin STRIPS)
         Predicates: mapped, has-users/files/parse/once, ran-<campaign>.
         Builtin forward search; Fast Downward if present and complete.
         `aros campaign plan` writes domain.pddl + problem.pddl.
         Missing Fast Downward is not a security result.

Level 3  Coverage-guided fuzz + sanitizers
         generator.kind = fuzzer. AFL++ / libFuzzer / honggfuzz.
         Crash = observation. Dedup + minimize = E5.

Level 4  Symbolic / concolic
         KLEE (source/LLVM), later SAGE-like for binaries.
         Counterexample input = PoC.

Level 5  Metamorphic / property engines
         MST-wi relations; QuickCheck shrinking.
         No LLM. Oracles are relations, not “the model thinks”.

Level 6  RL over the class graph (POST-MVP)
         NASim-style attack graphs. Reward = oracle fire.
         Not packet-level RL on the internet.

Level 7  Optional LLM proposer (already in Python worker)
         May emit ToolIntent or extra bind guesses.
         Rust still denies. Oracle still stdout/crash/relation.
```

**Default production path = Levels 0–5. Level 7 is opt-in.**

### 4.3 Concrete HTN for the current catalog (no model)

```text
GOAL: release_gate(target)
  TASK map:
    extract_http_paths_from_tree
    optional live GET if loopback listener
    write surface.json
  TASK select:
    if suggested_bind.idor_path → enqueue http-idor, http-unauth, http-cookie-confusion
    if suggested_bind.files_path → enqueue http-path-traversal
    if parse.py or bind.entry → enqueue cli-crash
    if once.py → enqueue lib-call-twice
    always enqueue http-surface-map as recon (must not Verified)
  TASK run:
    for each campaign: exec_generator (OCI) or fail closed
    oracle
    ledger
  TASK decide:
    if any Verified → GATE FAIL (do not ship)
    if containment unproven → GATE FAIL
    else GATE PASS
```

That is an agent. It is also `aros campaign gate`.

### 4.4 Why not “just use an LLM agent”

| Failure | Source | AROS counter |
|---|---|---|
| Hallucinated vulns | Every LLM pentest paper; XBOW’s whole product is “don’t ship those” | Oracle + evidence ladder |
| Context loss over long pentests | PentestGPT motivation | Graph + skills, not a 200k context dump |
| Eval sandbox escape to real orgs | Anthropic 2026; OpenAI 2026 Hugging Face eval breakout | Default-deny network, fail closed |
| Fragile structured reasoning | arXiv:2608.20966 — LLMs approximate attack-graph defense only when the graph is handed to them | Keep the graph in Rust |
| Cost | AutoPentest ~$96 vs $20 ChatGPT on three HTB boxes | Class pack is $0 |
| False negatives on logic bugs | Cobalt 2026 | Metamorphic relations (MST-wi), not signatures |

Use an LLM later as a **hypothesis printer** over `surface.json`, bounded by the HTN. Never as the runner.

---

## 5. Adopt-first list (makes AROS better this quarter)

Ordered by leverage for *every* project, not by academic prestige.

1. **MST-wi 76 metamorphic relations** — **in progress** (12 of 76 as HTTP class campaigns): cookie-drop, method, cross-user, header-noise, query-noise, xff, auth-header, encoded-dotdot, dot-segment, encoded-dot, nested-dotdot, double-slash. Harness `http-metamorphic` relations: `b_must_not_contain`, `a_must_not_contain`, `b_must_not_gain`, `bodies_must_differ`. Not the full 76.
2. **AFL++ or libFuzzer as `generator.kind: fuzzer`** — **shipped invoke-when-present**: `mutate-fuzz` calls `afl-fuzz` / libFuzzer when the binary and `bind.binary` exist (`AROS_AFL_FUZZ` / `AROS_LIBFUZZER` overrides). Otherwise mutational fuzz + shrink. No invented crash file.
3. **HTN over existing skills JSON** — **shipped**: all 20 builtin skills map to catalog campaigns (`SKILL_TASKS` in Rust and Python). Worker `--no-model`; `aros campaign crew`.
4. **QuickCheck-style shrinking + properties** — **shipped**: `shrink_bytes` + `prop-ascii`. `mutate-fuzz` emits `SHRINK_*` and the engine CAS-addresses the minimized bytes as **E5**. E5 does not count as E4.
5. **KLEE adapter** — **shipped fail-closed**: `klee-run` catalog campaign; invokes KLEE only with `bind.bitcode`; otherwise holds. No invented symbolic run.
6. **CyberGym subset** as a regression corpus (PoC-or-nothing) — **shipped local pack**: `evaluation/poc-or-nothing/` + `aros benchmark poc`. Scores oracle match only. Not the 1,507-vuln Berkeley corpus.
7. **AIxCC SoK** as the design review checklist: PoV, patch that preserves function, no points for chatter.
8. **PDDL / Fast Downward** — **shipped builtin STRIPS**: `plan_campaigns` / `aros campaign plan`. Fast Downward invoked when present and the plan is complete; otherwise STRIPS. Missing FD is not a security result.
9. **Declared E4/E6/E7** — **shipped**: replica re-run (`independent_reproduced`), optional patched twin (`--twin`), related variant that discriminates original vs twin, generated `e7-regression/regression_test.py` executed on the twin copy. Operator trees are not modified. Tests: E4 `http_idor_class_verifies_break_on_vulnerable_authz_fixture`, E6 `http_unauth_patched_twin_stays_at_e6_without_a_variant`, E7 `http_idor_patched_twin_earns_e7`. Slice ledger: `docs/research/llm-free-slices.md`.
10. **Evidence certificate** — **shipped** (`dfa8966`): `certificate.json` plus `aros evidence verify --work`. `statement_ok` is internal consistency. `release_eligible` requires demonstrated containment.
11. **Failure memory** — **shipped** (`f8eb737`): `TOOL_GAP` drops that catalog id. `EXPERIMENT_INADEQUATE` moves an already-justified id first. Unknown ids are not added. `replan.json` records the change.
12. **One-campaign research graph** — **shipped** (`9456fb3`): hypothesis, experiment, observation, conclusion, reloaded from SQLite. A graph that spans campaigns is still open.
13. **One project oracle line** — **shipped** (`0fb3353` bind, `7306e42` graph node): one `INVARIANT.md` line overlays the `http-idor` bind and is stored as a `Hypothesized` assumption that `motivates` the hypothesis. Other text is ignored. Two lines or an unsafe token keep the class bind and add no node. Other campaign ids are not rewritten. `aros campaign claim --target DIR`. Free-form assumption mining is still open.

Deterministic multi-agent roles (no LLM): mapper, planner, runner, shrinker, scribe
(`run_deterministic_crew` / `DeterministicCrew`).

Do **not** prioritize: LangChain clones, HTB autonomy leaderboards, public-internet scanners, training an RL packet agent.

---

## 6. What AROS must not become

- A PentestGPT with a different name.
- A fuzzer with no evidence ledger.
- An LLM that reads source and prints “this looks like IDOR.”
- An eval harness with a path to the public internet.

Those exist. They are cheaper to download than to rebuild. AROS’s only
defensible product is: **contained experiment → falsifiable proof →
re-attack → report a maintainer can defend.**

---

## 7. Bibliography (primary links)

CRS / competitions

- <https://arxiv.org/abs/2509.14589> ATLANTIS (AIxCC 1st)
- <https://arxiv.org/abs/2602.07666> SoK: DARPA AIxCC
- <https://www.darpa.mil/news/2025/aixcc-results> AIxCC results
- <https://www.darpa.mil/news/2016/mayhem-winner-cyber-grand-challenge> CGC Mayhem
- <https://archive.ll.mit.edu/mission/cybersec/corpora/Cybercorpora/cgc/cybergrandchallenge-final-event.html> MIT LL CGC

Fuzzing / symbolic

- <https://github.com/google/oss-fuzz>
- <https://github.com/google/clusterfuzz>
- <https://klee.github.io/>
- <https://queue.acm.org/detail.cfm?id=2094081> SAGE
- <https://llvm.org/docs/LibFuzzer.html>
- <https://aflplus.plus/>

Pentest / agents / benchmarks

- <https://arxiv.org/abs/2308.06782> PentestGPT
- <https://www.usenix.org/conference/usenixsecurity24/presentation/deng>
- <https://arxiv.org/abs/2506.02548> CyberGym
- <https://arxiv.org/abs/2606.04460> CyberGym-E2E
- <https://arxiv.org/html/2607.02605v1> Survey of LLM-driven pentest (81 papers)
- <https://arxiv.org/abs/2505.10321> AutoPentest
- <https://xbow.com/briefs/what-is-autonomous-pentesting>

Labs

- <https://www.anthropic.com/news/strategic-warning-for-ai-risk-progress-and-insights-from-our-frontier-red-team>
- <https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals>
- <https://deepmind.google/discover/blog/evaluating-potential-cybersecurity-threats-of-advanced-ai>
- <https://www.microsoft.com/en-us/security/blog/2026/05/12/defense-at-ai-speed-microsofts-new-multi-model-agentic-security-system-tops-leading-industry-benchmark/>

Oracles / testing theory

- MST-wi, IEEE TSE 2023 (metamorphic web security)
- Claessen & Hughes, QuickCheck, ICFP 2000
- <https://eprint.iacr.org/2024/1122> metamorphic crypto + AFL++

Planning without LLM authority

- HTN / SHOP2 (classical)
- PDDL + Fast Downward
- Behavior trees (game AI; good enough for gate)
- <https://arxiv.org/html/2503.18809> LLM-generated *heuristics*, classical search executes
- <https://arxiv.org/html/2604.15579v1> symbolic guardrails for agents
- <https://arxiv.org/abs/2609.01035> spawn in sandbox, vest authority sparingly

---

## 8. Survey check, 2026-11-10

Sections 1–7 stay as the September survey. This section records what
public pages said when the comparison was checked again. Star counts are
from a catalogue dated 2026-11-08, not from a fresh GitHub count. Scores
named as a team's own report are that team's report.

### Where AROS sits

The closest relatives are still cyber reasoning systems and continuous
fuzzers. Mayhem (DARPA CGC 2016) finds a bug, builds a proof, patches,
and checks the patch. The 2025 DARPA AI Cyber Challenge scored the same
way: an executable proof, and a patch that preserves function.
[DARPA's results page](https://www.darpa.mil/news/2025/aixcc-results)
(8 August 2025) names Team Atlanta first, Trail of Bits second, and
Theori third, with prizes of $4 million, $3 million, and $1.5 million.
The finalists found 54 of 63 planted bugs and patched 43. They also
found 18 real bugs that were being disclosed to maintainers. Team
Atlanta's system is ATLANTIS
([arXiv:2509.14589](https://arxiv.org/abs/2509.14589)): a model plus
symbolic execution, directed fuzzing, and static analysis. Trail of Bits
reports that Buttercup found 28 vulnerabilities and applied 19 patches
in that final round, using less expensive non-reasoning models
([their write-up](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)).

OSS-Fuzz plus ClusterFuzz remains the generator to call, not a product
to imitate. The program's own long-standing figure, quoted from August
2023, is over 10,000 vulnerabilities and 36,000 bugs across 1,000
projects. Section 2.1's later "13,000+" line is still unresolved. A
2026 recount of published OSV records shows fewer new records per year
after the early peak. That recount is not the live OSS-Fuzz dashboard.

CyberGym is the scoring rule, not a corpus AROS has run. The official
task is still 1,507 historical bugs across 188 projects, and a point
requires a proof-of-concept that crashes the vulnerable build and stays
clean on the patched build
([cybergym.io](https://www.cybergym.io/cybergym)). Level 1 also hands
the agent a vulnerability description. Early evals in section 2.3 were
near one success in five. By late 2026, reproduction rates reported for
strong agents are much higher. One example is a Tsinghua self-report of
1,488 of 1,507 (19 September 2026). Reproducing a described bug is a
different job from the one AROS has on a foreign tree, where nobody has
named the bug. The local pack under `evaluation/poc-or-nothing/` is not
those 1,507 bugs.

### What people usually mean by "similar"

XBOW, Strix, Shannon, PentAGI, PentestGPT, and CAI are autonomous
pentest agents. They share the aim of finding bugs in an application.
They do not publish AROS's ledger.

XBOW still uses the line in section 2.2: creative AI discovers,
deterministic logic decides. It is a hosted product aimed at running
web and API applications. A 2 October 2026 discussion of what
"autonomous" means records that XBOW's own account of its HackerOne
result included a human review before submission.

Open-source agents, from a catalogue checked 8 November 2026:

| Agent | Stars on that date | What the public repo says |
|---|---|---|
| Strix | about 74,000 | Apache-2.0. Docker sandbox, source and live app targets, proof-of-concept validation. |
| Shannon | about 51,000 | AGPL-3.0. Reads source, runs exploits, reports a proof of concept. |
| PentAGI | about 34,000 | MIT. Self-hosted multi-agent system with a web console. |
| PentestGPT | about 16,000 | MIT. The USENIX Security 2024 task tree, plus an autonomous mode on Claude Code or Codex. |
| CAI (alias1) | about 9,900 | Agent framework for CTFs and bounty workflows. Command guardrails. A CTF solve is not a release certificate. |

A November 2026 catalogue of default listeners also found that several
of these frameworks bind a service on a stock install. That is an
operational difference from AROS, whose campaign path refuses a public
host at parse time and fail-closes when containment is not shown.

NodeZero, Pentera, and HexStrike remain internal-network or cloud
attack platforms. Those targets are outside AROS v0.1.

Google's open-source vulnerability reward program paused new product
reports into 2027 because invalid AI-written submissions overwhelmed
it (Computer Weekly, 6 October 2026, quoting Google). That pause is
the bounty inbox, not OSS-Fuzz. It is the failure mode the evidence
ladder exists to refuse: a model sentence is not a finding.

A news summary of a Project Zero comparison (April–September 2026)
reported 45 actionable V8 bugs for Big Sleep against 37 for the
Fuzzilli fuzzer, with about a quarter overlap in the tracker. The
Project Zero post itself was not opened. The useful claim, if that
summary is accurate, is that a model and a fuzzer find different bugs.
AROS keeps the fuzzer as a generator and the model, when one is used,
as a proposer.

### What a real test still requires

`v0.1.0-mvp` stays blocked. Done means `./scripts/acceptance.sh`
against `docs/AROS_MVP_SPEC.md`, plus a host that shows the campaign
ran inside the container that was measured. This Windows host cannot
show that. Unwaived `aros campaign run`, `hunt`, and `gate` fail closed
here. A waived run can execute a local checkout and the certificate
will not be `release_eligible`.

A foreign tree can be tested today only when it already has an entry
the catalog understands: `server.py` or a loopback bind, quoted routes,
`parse.py`, `once.py`, or an adapter beside AROS. Otherwise the honest
result is a hold or a failure card. The procedure is
`testing-other-projects.md`.

Still open after that, and not closed by naming a neighbor:

- Hour-scale coverage. `crash-crusher` is 120 seconds of search inside
  a 180-second wall. `mutate-fuzz` is the 30-second smoke campaign.
- The other crush oracles. One parser entry is implemented.
- 64 of the 76 MST-wi relations. Twelve are in the catalog. A relation
  is added only when a real tree discriminates a break from a hold.
- The Python research loop is not the MVP scheduler.
- A graph across campaigns, free-form assumption mining, and a
  methodology card thicker than the fields a run already stores.
- Provider binaries are not started. The Numbat collector is not
  running. A correlation id stored with returned bytes is not placed
  on the live command line.
- The Berkeley 1,507-bug corpus is not wired in.

Left for later on purpose: gVisor, Firecracker, a required paid cloud
model, a large historical corpus, a live web console, and any public
internet target.
