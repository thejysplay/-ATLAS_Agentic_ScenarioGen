# -*- coding: utf-8 -*-
"""PHASE 1 · STEP 4 — Validity Filtering (SR1~SR3)
================================================================
ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
(SPECTRA Architecture · Phase 1 "Build Threat Knowledge" 의 4단계 · 마지막)

  "Keep only causally valid sequences (drop impossible orders)."
   k3 후보에서 실제 공격 흐름으로 성립 가능한 경로만 SR1~SR3으로 선별
   → 최종 Threat Knowledge Base.

── SR 규칙 = "이 조합이 진짜 공격인가?"를 3가지로 확인 ───────
  후보(k3)는 관측 2-gram을 재조합한 것이라 그중엔 실제로 성립하지 못하는 것도 섞여 있다.
  아래 3가지를 모두 통과해야 '시작→목표까지 완결된 실제 공격'으로 인정한다.

  SR1  시작이 맞나   : 첫 노드가 진입(ENT-DI·ENT-II)인가.
                       공격자는 에이전트가 받는 '입력'만 조작 가능하므로 반드시 진입에서 시작.
                       (k3가 진입에서만 생성 → 이미 보장, 여기서 재확인)
  SR2  목표에 도달했나 : 끝 노드가 공격 목표인가.  ★핵심 필터
                       목표 없이 중간에 끊기면 공격이 아니라 '조각'이라 제거.
                       공격 목표 = 실제 사건들이 실제로 도달한 마지막 노드 9종
                       (k2 terminal_nodes: ID-ER·ID-RG·EXE·SC-3종·PST-MEM·DAC-UBD·INV-SCU).
  SR3  말이 되나     : (a) 관측된 순서만 따름(k3에서 관측 edge만 써서 이미 보장)
                       (b) 같은 노드를 '관측된 횟수'보다 많이 반복하지 않음.
                       → 끝없는 순환·무의미 반복 제거 (R2·R17·R18).

  ※ 옛 규칙 '실행·권한·상태변경은 호출(E5) 뒤에만'은 본 taxonomy가 호출+실행을 한 Unit으로
     통합했고 관측 edge만 사용하므로 자동 충족 → SR3는 '반복 제한'만 담당.

── 입력/출력 ─────────────────────────────────────────────────
  in : out/candidate_sequences.json · out/transition_graph.json · out/attack_sequences.json
  out: out/threat_knowledge.json  (SR 통과 = 최종 Threat Knowledge Base, 2-track 유지)
"""
from pathlib import Path
import json
from collections import Counter

HERE = Path(__file__).parent
CAND_FILE = HERE / "out" / "candidate_sequences.json"
GRAPH_FILE = HERE / "out" / "transition_graph.json"
DECOMP_FILE = HERE / "out" / "attack_sequences.json"
OUT_FILE = HERE / "out" / "threat_knowledge.json"

ENTRY = {"ENT-DI", "ENT-II"}          # SR1 유효 시작 (진입)


def observed_repeat_caps(decomp: dict) -> dict:
    """각 노드의 '관측 최대 반복수' = 관측 경로 중 한 경로에서 그 노드가 등장한 최대 횟수."""
    cap = {}
    for info in decomp["cases"].values():
        for path in info["paths"]:
            ctr = Counter(s["node"] for s in path["sequence"])
            for n, c in ctr.items():
                cap[n] = max(cap.get(n, 0), c)
    return cap


def filter_valid(cands, terminals, rep_cap):
    kept, funnel = [], {"input": len(cands), "sr1_start": 0, "sr2_terminal": 0, "sr3_repeat": 0}
    for c in cands:
        p = c["path"]
        if p[0] not in ENTRY:                                   # SR1
            continue
        funnel["sr1_start"] += 1
        if p[-1] not in terminals:                              # SR2
            continue
        funnel["sr2_terminal"] += 1
        ctr = Counter(p)                                        # SR3
        if any(ctr[n] > rep_cap.get(n, 1) for n in ctr):
            continue
        funnel["sr3_repeat"] += 1
        kept.append(c)
    return kept, funnel


def run(cands, graph, decomp):
    terminals = set(graph["terminal_nodes"].keys())            # 관측 종점(목표)
    rep_cap = observed_repeat_caps(decomp)
    kept, funnel = filter_valid(cands, terminals, rep_cap)

    exact = [c for c in kept if c["align"] == "exact"]
    novel = [c for c in kept if c["align"] == "novel"]
    subpath = [c for c in kept if c["align"] == "subpath"]
    covered = sorted({cc for c in exact for cc in c["source_cases"]})
    n_cases = len(decomp["cases"])

    stats = {
        "terminals_SR2": sorted(terminals),
        "repeat_caps_SR3": {k: v for k, v in sorted(rep_cap.items()) if v > 1},
        "funnel": funnel,
        "final_total": len(kept),
        "track1_coverage_exact": len(exact),
        "cases_covered": f"{len(covered)}/{n_cases}",
        "track2_diversity": len(novel) + len(subpath),          # 다양성 = 신규 + 원본부분흐름
        "track2_detail": {"novel": len(novel), "subpath_variant": len(subpath)},
    }
    return {"meta": {"note": "SR1(진입 시작)·SR2(관측 종점)·SR3(관측 반복수 이내) 통과 = Threat Knowledge Base. 2-track 유지."},
            "stats": stats, "threat_knowledge": kept, "covered_cases": covered}


if __name__ == "__main__":
    cands = json.loads(CAND_FILE.read_text(encoding="utf-8"))["candidates"]
    graph = json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    decomp = json.loads(DECOMP_FILE.read_text(encoding="utf-8"))

    out = run(cands, graph, decomp)
    OUT_FILE.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    s = out["stats"]; f = s["funnel"]
    print("[PHASE1 · STEP4 Validity Filtering — SR1~SR3]")
    print(f"  출력: out/{OUT_FILE.name}  (= Threat Knowledge Base)")
    print(f"  SR2 관측 종점({len(s['terminals_SR2'])}): {', '.join(s['terminals_SR2'])}")
    print(f"  퍼널: 후보 {f['input']} → SR1 {f['sr1_start']} → SR2 {f['sr2_terminal']} → SR3 {f['sr3_repeat']}")
    print(f"  ── 최종 Threat Knowledge Base: {s['final_total']} ──")
    print(f"   ├─ Track1 커버리지(완전일치): {s['track1_coverage_exact']}  → 케이스 {s['cases_covered']}")
    print(f"   └─ Track2 다양성            : {s['track2_diversity']}  "
          f"(신규 {s['track2_detail']['novel']} + 원본부분흐름 {s['track2_detail']['subpath_variant']})")
