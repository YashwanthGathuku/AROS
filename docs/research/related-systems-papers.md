# Related systems, papers, and LLM-free agents

Last updated: 2026-09-08.

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

Level 2  Classical planner (PDDL / Fast Downward)
         Predicates: mapped(surface), listening(port),
                     class_ran(idor), verified(idor).
         Actions: map_surface, start_local, run_class, verify_ledger.
         Goal: all_required_classes_held OR finding_with_E3.
         LLMs are bad at this (2025–2026 planning papers: generate
         heuristics in code, then search — do not let the model plan).

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

1. **MST-wi 76 metamorphic relations** — **in progress** (6 of 76 as HTTP class campaigns): cookie-drop, method, cross-user, header-noise, query-noise, encoded-dotdot. Harness `http-metamorphic` relations: `b_must_not_contain`, `a_must_not_contain`, `b_must_not_gain`, `bodies_must_differ`. Not the full 76.
2. **AFL++ or libFuzzer as `generator.kind: fuzzer`** — **shipped invoke-when-present**: `mutate-fuzz` calls `afl-fuzz` / libFuzzer when the binary and `bind.binary` exist (`AROS_AFL_FUZZ` / `AROS_LIBFUZZER` overrides). Otherwise mutational fuzz + shrink. No invented crash file.
3. **HTN over existing skills JSON** — **shipped**: all 20 builtin skills map to catalog campaigns (`SKILL_TASKS` in Rust and Python). Worker `--no-model`; `aros campaign crew`.
4. **QuickCheck-style shrinking** — **shipped**: `shrink_bytes` (Zeller delta debug) + mutate-fuzz shrink.
5. **KLEE adapter** — **shipped fail-closed**: `klee-run` catalog campaign; invokes KLEE only with `bind.bitcode`; otherwise holds. No invented symbolic run.
6. **CyberGym subset** as a regression corpus (PoC-or-nothing) — **shipped local pack**: `evaluation/poc-or-nothing/` + `aros benchmark poc`. Scores oracle match only. Not the 1,507-vuln Berkeley corpus.
7. **AIxCC SoK** as the design review checklist: PoV, patch that preserves function, no points for chatter.

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
