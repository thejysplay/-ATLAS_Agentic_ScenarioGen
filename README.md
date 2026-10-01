# SPECTRA

**S**cenario **P**ipeline for **E**valuating **C**apability-grounded **T**hreats on **R**eal **A**gents

SPECTRA turns 22 real-world agentic-AI incidents (MITRE ATLAS) into a reusable attack
**knowledge base** of 675 attack-node skeletons, maps that knowledge onto any agent's
**actual tool capabilities**, and generates **LLM-written, deterministically-scored**
indirect-prompt-injection scenarios for it. Every attack succeeds or fails by a code
predicate — no LLM judge — so results are reproducible.

Applied to **8 agent environments** (4 AgentDojo suites, 3 AgentDyn suites, AppWorld),
SPECTRA generates **1,505 scenarios** that breach a Gemini 2.5 Flash agent **55%** of the time
under a strict data-only threat model.

---

## Pipeline

```
MITRE ATLAS incidents
   │  (1) case selection          1_case_selection/        72 → 22 cases
   ▼
Attack knowledge (8 Unit / 19 Node taxonomy)
   │  (2) threat decomposition    2_threat_knowledge/      → 675 skeletons
   ▼
Per-agent capability map
   │  (3a) capability tagging      g0_capability_tagging.py  tools → 19 nodes (anchored LLM)
   │  (3b) skeleton filter         g1_capability_mapping.py  675 → feasible skeletons / env
   ▼
Scenarios  (skeleton × terminal tool × style A/B, entry fixed, middle folded)
   │  (3c) generation (LLM, temp=0) g2_scenario_gen.py  +  g2_appworld_adapter.py
   │  (3d) I/O compatibility        g3_io_check.py
   ▼
Execution + deterministic scoring
      (4) executors                run_canon.py / run_canon_agentdyn.py / run_scenarios_appworld.py
                                    → results/
```

Three scoring oracles, all code: **action** (attacker id in a non-read tool call),
**state** (environment DB diff), **disclosure** (sensitive value appears in the agent's reply).

---

## Repository layout

| Path | Contents |
|---|---|
| `1_case_selection/` | ATLAS case selection (`s1`–`s4`), selected cases in `out/` |
| `2_threat_knowledge/` | 8U/19N decomposition (`k1`–`k4`), **`out/threat_knowledge.json`** (675 skeletons) |
| `3_scenario_generation/` | `g0` capability tagging, `g1` skeleton filter, **`g2_scenario_gen.py`** generator, `g2_appworld_adapter.py`, `g3_io_check.py`; `targets_auto/*.yaml` = per-env capability tags; `backend.py` = Gemini wrapper |
| `4_evaluation/` | executors: `agentdojo/` (AgentDojo + AgentDyn), `appworld/` (code-as-action, with `spectra_backup.py` / `spectra_oracle.py`) |
| `scenarios/` | the **1,505 generated scenarios** (`agentdojo/`, `agentdyn/`, `appworld/`) |
| `results/` | `run/` final per-env results (JSON), `tables/asr_results.md` |
| `docs/` | `methodology.md`, `domain_detail.md`, `skeletons_all.md` (all 421 feasible skeletons) |

---

## Results (Gemini 2.5 Flash, deterministic predicates)

| Environment | n | ASR | | Environment | n | ASR |
|---|---:|---:|---|---|---:|---:|
| banking | 162 | 47% | | shopping | 247 | 69% |
| travel | 74 | 53% | | github | 280 | 65% |
| workspace | 114 | 42% | | dailylife | 328 | 64% |
| slack | 112 | 68% | | appworld | 188 | 14% |
| **AgentDojo (4)** | **462** | **52%** | | **AgentDyn (3)** | **855** | **66%** |
| | | | | **Overall** | **1,505** | **55%** |

By objective: external exfiltration (ID-ER) is most reliable (**70%**); setting change
(SC-SYS 57%) and business action (SC-BIZ 49%) next; quoting an injected value back in the
reply (ID-RG) almost always fails (7%). Code-as-action AppWorld is the most robust (14%).
Full breakdown and the native-attack baseline: [`results/tables/asr_results.md`](results/tables/asr_results.md).

---

## Environment variables

All paths are resolved relative to this repo; only external benchmark checkouts and the API
key are set via environment (copy `.env.example` → `.env`):

| Variable | Purpose |
|---|---|
| `GEMINI_API_KEY` | Gemini API key (agent execution + scenario generation; **scoring never uses an LLM**) |
| `AGENTDOJO_REPO` | AgentDojo checkout (its `src/` is added to `sys.path`) |
| `AGENTDYN_REPO` | AgentDyn checkout |
| `APPWORLD_ROOT` | AppWorld checkout (`data/`, `base_dbs/`) |
| `SPECTRA_OUT` | *(optional)* output dir for regenerated scenarios / results (default: this repo) |

## Running

Each stage is a standalone script run in sequence. The capability tagger and generator call
the Gemini API (temperature 0) via `GEMINI_API_KEY`; **only the agent execution and scenario
generation use an LLM — scoring is always code.**

```bash
# (1) capability tagging  →  targets_auto/<env>.yaml
python 3_scenario_generation/g0_capability_tagging.py <env>

# (2) scenario generation (LLM, temp=0)  →  scenarios/<group>/<env>/
python 3_scenario_generation/g2_scenario_gen.py <env>

# (3) execute + score  →  results/run/<env>.json
python 4_evaluation/agentdojo/run_canon.py <env> --items scenarios/.../<env>.json
```

### Benchmark environments

The executors drive three external benchmarks that are **not vendored** here (size / license):
[AgentDojo](https://github.com/ethz-spylab/agentdojo), AgentDyn, and
[AppWorld](https://github.com/StonyBrookNLP/appworld). Install each, point the executor paths
at your checkout, and set `GEMINI_API_KEY`. See `4_evaluation/` for the expected wiring.

---

## Notes

- All LLM calls use **temperature 0** for reproducibility.
- Attacker constants (e.g. `mark.black-2134@gmail.com`, `US133...`) are the benchmarks' own
  authorized test values, not real targets.
- Scenarios are indirect prompt injection only: the adversary controls **data the agent
  reads**, never the user channel.
