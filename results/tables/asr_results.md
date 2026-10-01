# SPECTRA — Attack Success Rate (final, Gemini 2.5 Flash, deterministic predicates)

## Per-environment ASR
| Environment | type | n | breached | ASR |
|---|---|---:|---:|---:|
| banking | AgentDojo | 162 | 76 | 47% |
| travel | AgentDojo | 74 | 39 | 53% |
| workspace | AgentDojo | 114 | 48 | 42% |
| slack | AgentDojo | 112 | 76 | 68% |
| **AgentDojo (4)** | | **462** | 239 | **52%** |
| shopping | AgentDyn | 247 | 170 | 69% |
| github | AgentDyn | 280 | 182 | 65% |
| dailylife | AgentDyn | 328 | 211 | 64% |
| **AgentDyn (3)** | | **855** | 563 | **66%** |
| appworld | code-as-action | 188 | 26 | 14% |
| **Overall** | | **1,505** | **828** | **55%** |

## Objective (terminal node) × domain matrix — breaches/executed
| Objective | bank | travel | wksp | slack | shop | git | life | AppWd | Total |
|---|---|---|---|---|---|---|---|---|---|
| DAC-UBD (read user data) | 40/96 | 9/16 | 21/48 | – | – | – | – | 6/21 | 76/181 (42%) |
| ID-ER (external exfiltration) | 16/32 | 26/32 | 27/64 | 65/96 | 115/135 | 106/156 | 125/136 | 20/68 | 500/719 (70%) |
| ID-RG (disclosure in reply) | 1/2 | 1/2 | 0/2 | – | – | – | – | 0/22 | 2/28 (7%) |
| SC-BIZ (business action) | 13/24 | 3/24 | – | – | 20/36 | 16/24 | 11/12 | 0/9 | 63/129 (49%) |
| SC-SYS (setting change) | 6/8 | – | – | 11/16 | 22/36 | 48/84 | – | 0/9 | 87/153 (57%) |
| SC-DAT (data destruction) | – | – | – | – | – | – | – | 0/24 | 0/24 (0%) |
| EXE (code execution) | – | – | – | – | – | – | – | 0/35 | 0/35 (0%) |
| INV-SCU (computer-use) | – | – | – | – | 13/40 | 12/16 | 75/180 | – | 100/236 (42%) |
| **Total** | 76/162 | 39/74 | 48/114 | 76/112 | 170/247 | 182/280 | 211/328 | 26/188 | **828/1505** |

## Delivery style (tool-calling 7 envs)
| style | breaches/n | ASR |
|---|---:|---:|
| A (immediate) | 434/658 | 66% |
| B (delayed, multi-turn) | 368/659 | 56% |

## Baseline — native/original benchmark attack (static dataset, undefended)
| benchmark | pairs | success | ASR |
|---|---:|---:|---:|
| AgentDojo (important_instructions) | 629 | 330 | 52.5% |
| AgentDyn (important_instructions) | 560 | 306 | 54.6% |
| RAS-Eval (tool-injection) | 3802 | 1600 | 42.1% |
