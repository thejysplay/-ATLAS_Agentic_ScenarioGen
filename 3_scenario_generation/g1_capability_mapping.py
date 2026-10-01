# -*- coding: utf-8 -*-
"""PHASE 2 · STEP 1 — Capability Mapping + Feasibility Filter
================================================================
ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
(SPECTRA Architecture · Phase 2 "Generate Inspection Scenarios" 의 1단계)

  "Map the target agent's capabilities to Attack Nodes and verify whether the
   required node transitions are executable."
   대상 에이전트의 능력(도구·데이터·주입면)을 Attack Node로 매핑하고,
   Phase 1의 Threat Knowledge 675개 중 그 능력만으로 실행 가능한 시퀀스만 남긴다.

★ 원칙: "이 에이전트가 뭘 할 수 있나"로 필터. 벤치마크가 이미 정의한 공격에 갇히지 않는다.
        판정 기준 = "그 노드의 효과가 이 환경에서 실제로 성립하는가"(도구 유무가 아니라 효과 성립).
        예) HD-UI(사용자 유도)는 사용자가 클릭·입력해야 성립 → 사용자 행동 루프 없는 banking엔 불가.

── 입력 ──────────────────────────────────────────────────────
  ../2_Threat_Knowledge/out/threat_knowledge.json   Phase1 결과(675, 대상무관)
  targets/<agent>.yaml                              대상 능력맵 (node_tools)

── 필터 ──────────────────────────────────────────────────────
  시퀀스의 모든 노드 ∈ feasible(능력 있는 노드) → 실행 가능.
  (Phase1 SR2로 이미 목표 종점에서 끝나므로, 종점의 실행가능성도 함께 보장됨)

── 출력 ──────────────────────────────────────────────────────
  out/scenarios_<agent>.json  (실행가능 시퀀스, 2-track 유지 · 능력맵 동봉)
"""
from pathlib import Path
import json, sys, yaml

HERE = Path(__file__).parent
ROOT = HERE.parent
TK_FILE = ROOT / "2_threat_knowledge" / "out" / "threat_knowledge.json"


def load_target(agent: str) -> dict:
    return yaml.safe_load((HERE / "targets_auto" / f"{agent}.yaml").read_text(encoding="utf-8"))


def feasible_nodes(cap: dict) -> set:
    return {n for n, tools in cap["node_tools"].items() if tools}


def run(agent: str):
    tk = json.loads(TK_FILE.read_text(encoding="utf-8"))
    seqs = tk["threat_knowledge"]
    cap = load_target(agent)
    feas = feasible_nodes(cap)
    pre_sat = set(cap.get("pre_satisfied", []))     # 이미 충족(제거) — 예: banking의 PA-GA(권한)

    kept, dropped = [], []
    for s in seqs:
        infeasible = set(s["path"]) - feas
        blocking = sorted(infeasible - pre_sat)      # 진짜 못하는 노드
        auto = sorted(infeasible & pre_sat)          # 이미 충족 → 자동 제거
        norm = [n for n in s["path"] if n not in pre_sat]           # PA-GA 등 제거
        norm = [n for i, n in enumerate(norm) if i == 0 or n != norm[i-1]]  # 연속중복 정리
        rec = {**s, "exec_path": norm, "auto_satisfied": auto, "missing_nodes": blocking}
        (kept if not blocking else dropped).append(rec)

    exact = [s for s in kept if s["align"] == "exact"]
    novel = [s for s in kept if s["align"] == "novel"]
    subp = [s for s in kept if s["align"] == "subpath"]
    covered = sorted({c for s in exact for c in s["source_cases"]})

    from collections import Counter
    drop_reason = Counter()
    for s in dropped:
        for n in s["missing_nodes"]:
            drop_reason[n] += 1
    goals = Counter(s["exec_path"][-1] for s in kept)          # 실행경로 종점(목표)별
    n_presat = sum(1 for s in kept if s["auto_satisfied"])      # 전제 자동제거된 시퀀스 수

    out = {
        "agent": agent,
        "feasible_nodes": sorted(feas),
        "infeasible_nodes": sorted(set(cap["node_tools"]) - feas),
        "stats": {
            "threat_knowledge_in": len(seqs),
            "executable": len(kept),
            "dropped": len(dropped),
            "track1_coverage_exact": len(exact),
            "cases_covered_by_exact": covered,
            "track2_diversity": len(novel) + len(subp),
            "goals_reached": dict(goals.most_common()),
            "pre_satisfied_removed_in": n_presat,
            "drop_by_missing_node": dict(drop_reason.most_common()),
        },
        "pre_satisfied": sorted(pre_sat),
        "scenarios": kept,
    }
    OUT = HERE / "out" / "_pipeline" / f"scenarios_{agent}.json"
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    st = out["stats"]
    print(f"[PHASE2 · STEP1 Capability Mapping — {agent}]")
    print(f"  입력: Threat Knowledge {st['threat_knowledge_in']}")
    print(f"  실현가능 노드({len(feas)}): {', '.join(sorted(feas))}")
    print(f"  불가 노드({len(out['infeasible_nodes'])}): {', '.join(out['infeasible_nodes'])}")
    print(f"  출력: out/scenarios_{agent}.json")
    print(f"  전제 자동충족(제거): {out['pre_satisfied']} → {st['pre_satisfied_removed_in']}개 시퀀스에 적용")
    print(f"  ── 실행 가능 시퀀스: {st['executable']} / {st['threat_knowledge_in']} (제외 {st['dropped']}) ──")
    print(f"   ├─ Track1 커버리지(완전일치): {st['track1_coverage_exact']}  → 케이스 {len(st['cases_covered_by_exact'])}건 {st['cases_covered_by_exact']}")
    print(f"   └─ Track2 다양성            : {st['track2_diversity']}")
    print(f"  목표별(실행경로 종점): {st['goals_reached']}")
    print(f"  제외 사유(없는 노드별 건수): {st['drop_by_missing_node']}")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "banking")
