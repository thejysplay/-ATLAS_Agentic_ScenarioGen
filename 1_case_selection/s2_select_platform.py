# -*- coding: utf-8 -*-
"""STAGE 2 — select_platform_candidates  [Gate 1: Agentic Platform]

STAGE1 출력(cases)에서 'Agentic-AI 고유' technique를 1개 이상 employs 하는 CS만
후보로 남긴다. (결정론·재현 100%, LLM 미사용)

판정 규칙 = semantic(조건식):
    "Agentic AI" in platforms  AND  "Predictive AI" not in platforms
  즉 Agentic이 포함되고 전통 예측 ML(Predictive)은 배제된 기법 = Agent 고유.

  ※ 기존 exact-match({"Agentic AI"} / {"GenAI","Agentic AI"}만 허용)에서 semantic으로 교체.
    exact-match는 `{Agentic AI, Enterprise}`(예: T0118 Autonomous AI Agent Communication)를
    실수로 누락시켰음 → 규칙의 취지(Agentic∈ ∧ Predictive∉)를 그대로 코드화해 해소.
    (이 게이트는 '에이전트 관여'만 판정. '에이전트가 피해자인가'는 Gate3에서 별도 판정.)
"""
from pathlib import Path
import json

HERE = Path(__file__).parent
IN_FILE = HERE / "out" / "s1_cases.json"          # STAGE1 출력
OUT_FILE = HERE / "out" / "s2_candidates.json"    # STAGE2 출력


def is_agentic_platform(platforms: list[str]) -> bool:
    """Agentic AI 고유 platform? (Agentic 포함 ∧ Predictive 미포함)"""
    return "Agentic AI" in platforms and "Predictive AI" not in platforms


def select_platform_candidates(cases: dict) -> dict:
    """cases → {"candidates": [cs_id, ...], "evidence": {cs_id: [step, ...]}}.

    evidence = 후보 판정 근거가 된 스텝(들): step_id·technique·platforms.
    """
    candidates: list[str] = []
    evidence: dict[str, list] = {}
    for cs_id, case in cases.items():
        hits = [s for s in case["steps"] if is_agentic_platform(s["platforms"])]
        if hits:
            candidates.append(cs_id)
            evidence[cs_id] = [{"step_id": h["step_id"],
                                "technique": h["technique"],
                                "technique_name": h["technique_name"],
                                "platforms": h["platforms"]} for h in hits]
    return {"candidates": sorted(candidates), "evidence": evidence}


if __name__ == "__main__":
    cases = json.loads(IN_FILE.read_text(encoding="utf-8"))
    result = select_platform_candidates(cases)
    OUT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")

    cands = result["candidates"]
    print("[STAGE2 select_platform_candidates]")
    print(f"  입력: out/{IN_FILE.name}  (전체 {len(cases)} CS)")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  후보: {len(cands)} CS  (제외 {len(cases) - len(cands)})")
    ex = "AML.CS0016"
    if ex in result["evidence"]:
        print(f"  예시 {ex} 후보 근거:")
        for h in result["evidence"][ex]:
            print(f"    {h['step_id']} {h['technique']}({h['technique_name']}) platforms={h['platforms']}")
