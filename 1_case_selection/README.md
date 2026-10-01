# 1_Case_Selection — 케이스 선정 파이프라인 (S1~S4)

> **역할**: ATLAS 원본(YAML) → *우리 기준*으로 **에이전트 런타임 자기취약성 case study**만 자동 추출.
> **출력**: `seed 22` (시나리오 생성 대상) + `knowledge 30` (지식 보존용).
> **성질**: 결정론·100% 재현 (LLM 미사용). 단 애매한 신규 case는 **사람 검토 게이트**를 거침(§ 자동화 수준).
> 이론적 정당화(IPI 위협모델·제외 근거)는 상위 `../METHODOLOGY.md § 1` 참조.

---

## 0. 폴더 구성

```
1_Case_Selection/
├── atlas/
│   └── ATLAS-2026.08.yaml        # 입력: ATLAS 원본 (72 case studies)
├── s1_load_atlas.py              # STAGE 1  로드·정규화
├── s2_select_platform.py         # STAGE 2  Gate1 — Agentic Platform
├── s3_select_agentic.py          # STAGE 3  Gate2 — Agentic Involvement
├── s4_select_target.py           # STAGE 4  Gate3 — Runtime Self-Vulnerability
├── out/                          # 각 단계 출력 JSON
│   ├── s1_cases.json
│   ├── s2_candidates.json
│   ├── s3_selected.json
│   └── s4_seed.json              # ★ 최종 산출물 (seed 22 / knowledge 30)
└── README.md                     # (이 파일)
```

## 1. 실행 방법

각 단계는 앞 단계의 `out/*.json`을 입력으로 받는다. 순서대로 실행:

```bash
cd 1_Case_Selection
python3 s1_load_atlas.py       # atlas/ATLAS-2026.08.yaml → out/s1_cases.json
python3 s2_select_platform.py  # out/s1_cases.json         → out/s2_candidates.json
python3 s3_select_agentic.py   # out/s2_candidates.json    → out/s3_selected.json
python3 s4_select_target.py    # out/s3_selected.json      → out/s4_seed.json
```

최종 `out/s4_seed.json`은 상위 폴더의 HTML 생성기(`../gen_full_html.py`)·케이스 폴더 생성기
(`../make_case_folders.py`)가 소비한다.

---

## 2. 선정 퍼널 (ATLAS 2026.08 기준)

```
72  ATLAS 전체 case study
│   ▼ Gate1  Agentic Platform          (S2)
39  Agentic-AI 고유 기법을 쓰는 후보
│   ▼ Gate2  Agentic Involvement       (S3)   [제외 5]
34  에이전트가 공격에 개입한 case          (게이트마다 완전 boolean)
│   ▼ Gate3  Runtime Self-Vulnerability (S4)   [제외 12]
22  SEED  ← 시나리오 생성 대상 (런타임 주입 → 자율 전복)
```

- **SEED 22** = 처리 데이터(웹·이메일·문서·도구출력·메시지)를 통해 **런타임에 자율 전복**되는 사건.
- **Knowledge 30** = 에이전트 *자체* 취약성 전체 = seed + 공급망(5) + 비런타임(3). (수단 4건만 완전 제외)
  - 위협 지식(Unit·Attack Node·Resource) 구축에는 30을 쓰고, 시나리오 자동 생성에는 22를 쓴다.

---

## 3. 단계별 상세

### STAGE 1 — `s1_load_atlas.py` · 로드·정규화
| 항목 | 내용 |
|---|---|
| **입력** | `atlas/ATLAS-2026.08.yaml` |
| **하는 일** | ATLAS의 `case-studies`·`techniques`·`relationships`를 파이프라인이 쓰기 쉬운 형태로 정규화. CS별로 `{id, name, description, steps[]}`. |
| **핵심** | `relationships[cs].employs`를 **`step-id` 순으로 정렬**(원문 리스트 순서 ≠ 공격 순서). 각 스텝에 `technique`·`technique_name`·`platforms`·`leads_to` 부착. |
| **출력** | `out/s1_cases.json` (72 CS · 659 step) |
| **자동화** | ✅ 완전 자동 (파싱만) |

> 왜 step-id 정렬? — 초기에 `employs` 리스트 순서를 그대로 썼다가 CS0016 시퀀스가
> `상태변경`부터 시작하는 오류가 났음. ATLAS의 실제 공격 흐름은 `leads-to`로 이어지는 step-id 순서다.

---

### STAGE 2 — `s2_select_platform.py` · **Gate1: Agentic Platform**
| 항목 | 내용 |
|---|---|
| **입력** | `out/s1_cases.json` |
| **판정 규칙** | 한 스텝이라도 아래 조건을 만족하는 technique를 employs → 후보:<br>`"Agentic AI" ∈ platforms  ∧  "Predictive AI" ∉ platforms` |
| **의미** | Agentic이 포함되고 전통 예측 ML(Predictive)은 배제된 기법 = **에이전트 고유 기법**. |
| **출력** | `out/s2_candidates.json` (39 CS, 근거 스텝 포함) |
| **자동화** | ✅ 완전 자동 (순수 조건식, 재현 100%) |

> **semantic 규칙 채택 이유**: 초기 exact-match(`{Agentic AI}` / `{GenAI, Agentic AI}`만 허용)는
> `{Agentic AI, Enterprise}` 같은 조합(예: T0118 Autonomous AI Agent Communication)을 실수로 누락시켰음.
> 규칙의 *취지*(Agentic∈ ∧ Predictive∉)를 그대로 코드화해 해소.
> 이 게이트는 "에이전트 관여"만 본다. "에이전트가 피해자인가"는 Gate3에서 별도 판정.

---

### STAGE 3 — `s3_select_agentic.py` · **Gate2: Agentic Involvement**
Gate1 후보 중 **에이전트 기능이 실제 공격 경로에 개입**했는지 3규칙으로 판정.

| 규칙 | 판정 | 자동화 |
|---|---|---|
| **Rule 1** Technique Anchor | `AGENTIC_ANCHORS`(behavior/component/ecosystem 앵커 technique 집합) 1개+ employs → **자동 포함** | ✅ 자동 (technique ID 기반) |
| **Rule 2** Procedure Review | 앵커 없으면 `PROCEDURE_REVIEW_DECISIONS`(CS별 사전 확정 판정)만 사용 | ⚠️ 하드코딩 (사람 판정) |
| **Rule 3** Unresolved | 앵커도 없고 검토표에도 없으면 `include=None` → **선정 확정 안 하고 사람 검토 요구** | 🛑 멈춤 (추측 포함 금지) |

- **출력**: `out/s3_selected.json` = `{results, included[], unresolved[]}`
- ATLAS 2026.08 결과: Rule1 앵커 **29** + 원문판독 포함 **5**(CS0020·29·68·69·71) = **34 선정** / 원문판독 제외 5(CS0022·43·56·57·60).
  - CS0068·69·71(공격자가 운영한 에이전트=행위 주체)은 Gate2 **포함** → Gate3에서 '수단'으로 제외 (보류 없음, 게이트마다 완전 boolean).
  - Rule3(앵커도 검토표도 없음 → 수동검토)는 안전망이며 현재 데이터에선 0건.

> `PROCEDURE_REVIEW_DECISIONS`에는 각 CS의 `include`·근거스텝·사유가 명시돼 있어 재현·감사 가능.
> (예: CS0020 포함 — "에이전트가 사용자가 열어둔 외부 웹페이지를 직접 읽는 능력이 공격 경로에 사용됨")

---

### STAGE 4 — `s4_select_target.py` · **Gate3: Runtime Self-Vulnerability**
Gate2 통과분(+미해결) 중, **런타임 자기취약성**이 아닌 3범주를 제외.

| 제외 범주 | 테이블 | 뜻 | 건수 |
|---|---|---|---|
| ① **수단(Means)** | `AGENT_AS_MEANS` | 공격자가 *자기* 에이전트를 운영해 제3자를 침해 (피해 에이전트 없음, C2 릴레이 포함) | 4 |
| ② **공급망** | `SUPPLY_CHAIN` | 컴포넌트 사전 오염 — 사람이 직접 배치 + 사용자 승인 시 정상 도구 | 5 |
| ③ **비런타임** | `NON_RUNTIME` | 메모리 포렌식·노출 인터페이스·전통 RCE — 런타임 데이터 주입으로 재현 불가 | 3 |

- **포함(seed)** = 위 3범주에 없는 나머지 = 런타임 자율 전복 사건.
- **출력**: `out/s4_seed.json` = `{seed[22], excluded{means, supply_chain, non_runtime}, knowledge[30]}`
- **자동화**: ⚠️ 하드코딩 (12건 CS별 사람 판정을 사유와 함께 코드에 기록).

> 경계선 정리: CS0052(프레임워크 RCE via 프롬프트 주입)는 CS0016/CS0062와 동일 유형이라 **seed 포함**,
> CS0061(C2 릴레이)은 '수단'이라 `AGENT_AS_MEANS`로 이동 → **경계선 0건**.

---

## 4. 자동화 수준 요약 — "yaml만 넣으면 자동인가?"

| 단계 | 자동화 | 새 case가 들어오면 |
|---|---|---|
| S1 로드 | ✅ 완전 자동 | 그대로 파싱 |
| S2 Gate1 platform | ✅ 완전 자동 | platform 필드로 자동 판정 |
| S3 Gate2 Rule1 (앵커) | ✅ 자동 | 앵커 기법 쓰면 자동 포함 |
| S3 Gate2 Rule2 (검토표) | ⚠️ 하드코딩 | 표에 없으면 판정 불가 |
| S3 Gate2 Rule3 | 🛑 멈춤 | **자동 처리 안 됨 → 사람 검토** |
| S4 Gate3 self-vuln | ⚠️ 하드코딩 | 표에 없으면 무조건 seed로 감 |

- **현재 ATLAS 2026.08**: `s1→s4` 실행 시 **72→39→34→22가 항상 동일하게 재현**된다.
- **완전 자동 규칙 엔진은 아님**: Gate1 + Gate2-Rule1(앵커)까지가 순수 규칙, Gate2-Rule2·Gate3는
  *특정 CS-ID에 대한 사람 판정을 사유와 함께 코드에 박아둔 것*.
- 이는 **의도된 설계** — 애매한 사건을 몰래 자동 통과시키지 않고 멈춰서 사람에게 넘긴다(grounding 원칙).

### 신규 ATLAS 버전 반영 절차
1. 새 YAML을 `atlas/`에 두고 `s1_load_atlas.py`의 `ATLAS_FILE` 경로를 맞춘다.
2. `s2`→`s3` 실행. `s3` 출력의 `⚠ Rule3 수동검토 필요` 목록을 확인.
3. 목록의 각 CS를 검토해 `s3`의 `PROCEDURE_REVIEW_DECISIONS`(관여 여부)와
   `s4`의 제외 테이블(수단/공급망/비런타임)에 **사유와 함께** 판정을 추가.
4. `s3`→`s4` 재실행 → 확정.

---

## 5. 하류 소비자 (참고)

`out/s4_seed.json`(및 `s1_cases.json`)은 상위 폴더에서 다음이 읽는다:

| 소비자 | 용도 |
|---|---|
| `../gen_full_html.py` | seed 22 기준 Case Mapping HTML(매트릭스·시퀀스) 생성 |
| `../make_case_folders.py` | `cases/CSxxxx/case.json` (메타+ATLAS스텝+시퀀스) 생성 |
| `../build_observation.py` | (실험) Technique→Attack Node 크로스워크 재관측 |
