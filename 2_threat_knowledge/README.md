# 2_Threat_Knowledge — Phase 1: Build Threat Knowledge

> **역할**: 선정된 실제 공격 사건(seed) → **재사용 가능한 Threat Knowledge Base** 구축 (대상 무관, 1회).
> **위치**: SPECTRA Architecture(PPT)의 **Phase 1**. 입력은 `../1_Case_Selection/`의 seed 22.
> **성질**: 결정론(규칙 기반). Attack Decomposition 시퀀스 정본 = 사람 검증본(v7 HTML) 재사용.

```
Phase 1 · Build Threat Knowledge (대상 무관, 1회)
  k1  Attack Decomposition       각 사건 → 순서화된 Attack Sequence (분기 인식)   ✅
  k2  2-gram / Transition Graph  인접 노드 전이 추출 → 전이 그래프                ✅
  k3  Candidate Sequence Gen     그래프에서 후보 시퀀스 열거 (2-track 태그)        ✅
  k4  Validity Filtering         인과 유효한 것만 (SR1~3)                         ✅
  → Threat Knowledge Base = 675 시퀀스 (커버리지 27 / 다양성 648[신규626+부분흐름22])

Phase 2 · Generate Inspection Scenarios (대상별)  → 별도 폴더 예정
```

**Phase 1 완료.** 최종 산출물 `out/threat_knowledge.json` = 재사용 Threat Knowledge Base.

## 2-track (커버리지 vs 다양성)
하나의 생성 과정에서 두 트랙이 자동으로 갈린다:
- **Track 1 · 커버리지**: 원본 케이스 경로에 '포함'되는 후보 → "이 경로는 CS####에서 실제 관측됨" = ATLAS 근거.
- **Track 2 · 다양성**: 원본에 없던 신규 조합 경로.

---

## 실행
```bash
cd 2_Threat_Knowledge
python3 k1_attack_decomposition.py   # → out/attack_sequences.json
python3 k2_transition_graph.py       # → out/transition_graph.json
python3 k3_candidate_generation.py   # → out/candidate_sequences.json
python3 k4_validity_filter.py        # → out/threat_knowledge.json (최종)
```

---

## STEP 1 — Attack Decomposition (branch-aware) ✅
각 seed case의 Attack Flow를 Unit/Attack Node/Resource 순서 체인으로 분해.

- **입력**: v7 HTML(사람 검증 정본) + seed 22 + ATLAS 메타
- **출력**: `out/attack_sequences.json` — 케이스별 **paths[]** (분기 케이스는 경로 여러 개)
- **결과**: **22 케이스 → 29 경로**, 경로 길이 2~**7**(평균 4.5)

### ★ 분기(branch) 처리 — 반드시
일부 케이스는 '공통 진입 후 여러 목표로 분기'한다. 하나의 긴 시퀀스로 이어붙이면 안 됨.
- **CS0063**: 공통 `ENT-II→PST-MEM→ENT-II` + **6개 목표**(무결성/파괴/물리/위치/프라이버시/유출) → 6경로
- **CS0066**: 공통 `ENT-II` + **3개 목표**(유출/지속/재배포) → 3경로
- **CS0021**: 2번째 경로는 `◇가능성(관측된 공격 아님)` → **제외**, 관측 1경로만
- 나머지 19케이스 = 1경로.  (예전 오류: CS0063을 16노드 한 줄로 뭉쳤음 → 수정됨)

### 분해 규칙 (결정론)
```
① 분기 전개 : 분기 케이스 → (공통 + 각 branch) 별도 경로. pbar(가능성) 제외.
② 19-Node remap : INT-EC→ENT-II · EXE-SE/SSE→EXE · INV-SCU+코드Resource→EXE
③ 연속 동일 노드 collapse (INV-AT·INV-SCU(비코드)·EXE 는 서로 다른 노드 → 보존)
```

---

## STEP 2 — Transition Graph (2-gram) ✅
29경로에서 인접 노드 쌍(2-gram)을 모아 방향 전이 그래프 구성. 관측 전이만 edge.

- **입력**: `out/attack_sequences.json`
- **출력**: `out/transition_graph.json` (edges·adjacency·start_nodes·terminal_nodes)
- **결과**: 관측 노드 **18/19**(HD-UAD 미관측) · **관측 전이 39 edge** (상한 361) · 총 전이 102
- **모든 경로가 진입(ENT-DI·ENT-II)에서 시작** → 유효 시작 규칙(SR1)의 관측 근거.
- self-loop(A→A) 없음(k1 collapse). 상위 전이: `ENT-II→INV-AT`(×10), `ENT-II→PST-MEM`(×8)…

---

## STEP 3 — Candidate Sequence Generation (2-track) ✅
전이 그래프를 따라 진입에서 시작하는 모든 경로를 열거하고, 원본 대응으로 2-track 태그.

- **입력**: `out/transition_graph.json` + `out/attack_sequences.json`
- **출력**: `out/candidate_sequences.json`
- **생성 조건**: 시작=관측 진입노드 · 관측 edge만 따라감 · 길이 2~**MAX_LEN(=7, 실제 최대 경로 길이)** · 노드 재방문 허용
- **결과 (L=7)**: 총 **1,665** 후보 (k4 필터 전)
  - **Track1 커버리지**: 27 (원본 완전일치 = **케이스 22/22 커버**)
  - **Track2 다양성**: 1,638 (신규 조합 1,589 + 원본 부분흐름 49)
  - ※ 커버리지=완전일치만(사용자 확정), 부분흐름은 다양성에 포함.

### 왜 길이 제한이 필요한가 (조합 폭발)
전이 그래프에 순환(예 `PST-KB↔ENT-II`)이 있어 **길이 무제한이면 무한대**. 조건별 상한:

| 조건 | 후보 수 |
|---|---|
| 조건 없음(아무 노드→아무 노드, 길이 2~7) | ≈ 9.4억 |
| 관측 edge만 + 진입시작 + 재방문허용, L=7 | **1,665** |
| 관측 edge만 + 재방문금지(simple) | 최대 ~수백 (단 재유입 패턴 손실 → 부적합) |

→ "관측 edge만"이 폭발을 크게 줄이고, **L=실제 최대 길이(7)**로 유한화. 순환/무의미 반복은 다음 k4가 인과로 제거.

---

## STEP 4 — Validity Filtering (SR1~SR3) ✅
후보 1,665개는 관측 2-gram을 재조합한 것이라, 그중엔 실제로 성립 못 하는 것도 섞여 있다.
**"이 조합이 진짜 공격인가?"를 3가지로 확인**해 통과한 것만 최종 Threat Knowledge Base로 둔다.

- **입력**: candidate_sequences.json + transition_graph.json + attack_sequences.json
- **출력**: `out/threat_knowledge.json`

| 규칙 | 확인하는 것 | 왜 |
|---|---|---|
| **SR1 시작이 맞나** | 첫 노드가 진입(ENT-DI·ENT-II)인가 | 공격자는 에이전트가 받는 '입력'만 조작 가능 → 반드시 진입에서 시작 |
| **SR2 목표에 도달했나** ★ | 끝 노드가 공격 목표(관측 종점 9종)인가 | 목표 없이 끊기면 공격이 아니라 '조각' → 제거 |
| **SR3 말이 되나** | ① 관측된 순서만 ② 같은 노드를 관측 횟수 이내로만 반복 | 끝없는 순환·무의미 반복 제거 |

- **공격 목표 9종** (실제 사건이 도달한 마지막 노드): ID-ER 유출 · ID-RG 노출/생성 · EXE 실행 · SC-SYS/SC-DAT/SC-BIZ 상태변경 · PST-MEM 지속 · DAC-UBD 데이터확보 · INV-SCU 기기조작.
- ※ 옛 규칙 '실행·권한·상태변경 ← 호출(E5)'은 본 taxonomy가 호출+실행을 통합 + 관측 edge만 사용 → 자동 충족. SR3는 '반복 제한'만 담당.
- ※ 능력 규칙(R13~15: 기능·메모리·플랫폼 가용성)은 여기가 아니라 **Phase 2(대상 에이전트)** 에서 적용.

**결과 (퍼널)**: 후보 1,665 → SR1 1,665 → SR2 952 → SR3 **675**
- **Track1 커버리지 27** (케이스 22/22, 필터 전량 통과) · **Track2 다양성 648** (신규 626 + 원본 부분흐름 22)
- 참고: PPT는 5,068→1,279. 우리는 22케이스·19노드·더 엄격이라 675로 자연히 작음.
