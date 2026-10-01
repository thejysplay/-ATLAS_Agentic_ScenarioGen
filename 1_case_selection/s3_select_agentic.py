# -*- coding: utf-8 -*-
"""STAGE 3 — select_agentic_involvement

STAGE2 후보에서 'Agentic 개입'이 확인되는 CS만 최종 선정한다. (결정론·재현 100%, LLM 미사용)
Official_ATLAS_Generation.py stage2 의 3규칙 그대로:

  Rule 1 Technique Anchor : Agentic Anchor Technique(behavior/component/ecosystem)를
                            1개+ employs → 자동 포함
  Rule 2 Procedure Review : anchor 없으면 PROCEDURE_REVIEW_DECISIONS(사전 확정)만 사용
  Rule 3 Unresolved       : anchor도 없고 검토결과도 없으면 include=None → 실행 중단
                            (몰래 추측 포함 금지 · 새 CS는 반드시 사람 검토)
"""
from pathlib import Path
import json

HERE = Path(__file__).parent
CASES_FILE = HERE / "out" / "s1_cases.json"        # employs technique 조회용
CAND_FILE = HERE / "out" / "s2_candidates.json"    # STAGE2 후보
OUT_FILE = HERE / "out" / "s3_selected.json"       # STAGE3 출력

# ── Rule 1: Agentic Anchor Technique (behavior/component/ecosystem) ──
AGENTIC_ANCHORS = {
    "behavior": {
        "AML.T0053", "AML.T0086", "AML.T0098", "AML.T0100", "AML.T0101",
    },
    "component": {
        "AML.T0064", "AML.T0066", "AML.T0070", "AML.T0071", "AML.T0082", "AML.T0085.000",
        "AML.T0080.000", "AML.T0080.001", "AML.T0092",
        "AML.T0081", "AML.T0083", "AML.T0084.000", "AML.T0084.001", "AML.T0084.002",
        "AML.T0084.003", "AML.T0085.001", "AML.T0002.002",
    },
    "ecosystem": {
        "AML.T0010.005", "AML.T0011.002", "AML.T0110", "AML.T0110.000", "AML.T0110.001",
        "AML.T0115.002", "AML.T0018.003",
    },
}

# ── Rule 2: anchor 없는 Case의 사전 검토 결과(고정, LLM 미사용, 100% 재현) ──
PROCEDURE_REVIEW_DECISIONS = {
    "AML.CS0020": {"include": True,  "agent_behavior": False, "agent_component": False, "agent_ecosystem": True,
                   "evidence_steps": ["S02"],
                   "reason": "에이전트가 사용자가 열어둔 외부 웹페이지를 직접 읽는 능력이 공격 경로에 사용됨"},
    "AML.CS0029": {"include": True,  "agent_behavior": False, "agent_component": True,  "agent_ecosystem": True,
                   "evidence_steps": ["S00", "S03", "S04", "S05"],
                   "reason": "에이전트가 공유 외부 문서를 처리하고, 응답 렌더링을 통해 대화가 외부로 유출됨"},
    "AML.CS0022": {"include": False, "agent_behavior": False, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "LLM이 패키지명을 환각하고 다운로드·실행은 사람이 수행. 에이전트 기능 관여 없음"},
    "AML.CS0043": {"include": False, "agent_behavior": False, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "공격 대상이 LLM 악성코드 탐지기/분석기. 에이전트 도구·구성요소·생태계 미사용"},
    "AML.CS0056": {"include": False, "agent_behavior": False, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "반복 질의로 모델 추출/증류. 에이전트의 실제 기능 사용 아님"},
    "AML.CS0057": {"include": False, "agent_behavior": False, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "LLM 서비스 가드레일 우회·유해콘텐츠 생성. 에이전트 도구/RAG/메모리/외부접근 미사용"},
    "AML.CS0060": {"include": False, "agent_behavior": False, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "LLM이 악성 HTML 생성, 실행은 인간 상담원 브라우저에서 발생. 에이전트 capability 아님"},
    # 공격자가 에이전트를 '운영'해 공격 수행 → 에이전트가 행위 주체(개입 확실). 포함.
    #   앵커 미태깅은 ATLAS가 공격자 측 기법으로 기술했기 때문이지 개입이 없어서가 아님.
    #   '피해 에이전트 없음(수단)'은 Gate3에서 별도 판정 → 여기서 보류하지 않고 Gate2를 완전 boolean으로.
    "AML.CS0068": {"include": True, "agent_behavior": True, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "공격자가 자율 에이전트를 운영해 외부 인프라 침해 → 에이전트가 행위 주체(개입). 피해 에이전트 여부는 Gate3(수단)에서 판정"},
    "AML.CS0069": {"include": True, "agent_behavior": True, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "탈옥된 코딩 에이전트를 사이버 간첩 도구로 운영 → 에이전트가 행위 주체(개입). 피해 에이전트 여부는 Gate3(수단)에서 판정"},
    "AML.CS0071": {"include": True, "agent_behavior": True, "agent_component": False, "agent_ecosystem": False,
                   "evidence_steps": [],
                   "reason": "다중 에이전트 프레임워크를 운영해 시스템 침해 → 에이전트가 행위 주체(개입). 피해 에이전트 여부는 Gate3(수단)에서 판정"},
}


def select_agentic_involvement(cases: dict, candidates: list[str]) -> dict:
    """cases + 후보 → {"results": {...}, "included": [...], "unresolved": [...]}.

    unresolved 가 있으면(Rule 3) 최종 선정을 확정하지 않고 그대로 반환 —
    호출부가 '수동 검토 필요' 목록을 보고 처리하도록 한다.
    """
    results: dict[str, dict] = {}
    for cid in candidates:
        emp = {s["technique"] for s in cases[cid]["steps"]}
        matched = {cat: sorted(emp & anch) for cat, anch in AGENTIC_ANCHORS.items()}
        if any(matched.values()):                                   # Rule 1
            results[cid] = {"include": True, "basis": "technique_anchor", **matched}
        elif cid in PROCEDURE_REVIEW_DECISIONS:                      # Rule 2
            dec = PROCEDURE_REVIEW_DECISIONS[cid]
            results[cid] = {"include": bool(dec["include"]),
                            "basis": "procedure_evidence_reviewed", "review": dec}
        else:                                                        # Rule 3
            results[cid] = {"include": None, "basis": "manual_review_required",
                            "reason": "No agentic anchor and no reviewed procedure decision"}

    included = sorted(cid for cid, r in results.items() if r["include"] is True)
    unresolved = sorted(cid for cid, r in results.items() if r["include"] is None)
    return {"results": results, "included": included, "unresolved": unresolved}


if __name__ == "__main__":
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    candidates = json.loads(CAND_FILE.read_text(encoding="utf-8"))["candidates"]
    result = select_agentic_involvement(cases, candidates)
    OUT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")

    res = result["results"]
    n_anchor = sum(1 for r in res.values() if r["basis"] == "technique_anchor")
    n_proc_in = sum(1 for r in res.values() if r["basis"] == "procedure_evidence_reviewed" and r["include"])
    n_proc_ex = sum(1 for r in res.values() if r["basis"] == "procedure_evidence_reviewed" and not r["include"])
    print("[STAGE3 select_agentic_involvement]")
    print(f"  입력: 후보 {len(candidates)} CS")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  Rule1 anchor 포함        : {n_anchor}")
    print(f"  Rule2 procedure 포함/제외 : +{n_proc_in} / -{n_proc_ex}")
    print(f"  → 최종 선정: {len(result['included'])} CS")
    if result["unresolved"]:
        print(f"  ⚠ Rule3 수동검토 필요 {len(result['unresolved'])}건 (08 신규·앵커없음): {result['unresolved']}")
