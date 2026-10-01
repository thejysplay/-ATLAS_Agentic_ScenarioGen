# -*- coding: utf-8 -*-
"""PHASE 1 · STEP 3 — Candidate Sequence Generation (2-track)
================================================================
ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
(SPECTRA Architecture · Phase 1 "Build Threat Knowledge" 의 3단계)

  "Enumerate all candidate attack-unit sequences from the graph."
   k2 전이그래프(관측 46 edge)를 따라 진입 노드에서 시작하는 모든 경로를 열거한다.
   생성된 각 후보는 원본 케이스와의 대응 여부로 자동 2-track 분류:

     ┌ Track 1 · 커버리지 : 원본 케이스 시퀀스에 '포함'되는 경로(관측 재현)
     │                       → "이 경로는 CS#### 에서 실제 관측됨" = ATLAS 근거
     └ Track 2 · 다양성   : 원본에 없던 신규 조합 경로

── 입력 ──────────────────────────────────────────────────────
  out/transition_graph.json   k2 결과(adjacency · start_nodes)
  out/attack_sequences.json   k1 결과(원본 22 시퀀스 = 대응 판정 기준)

── 생성 규칙 ─────────────────────────────────────────────────
  - 시작: 관측된 진입 노드(ENT-DI·ENT-II)  (= 유효 시작 SR1의 선반영)
  - 확장: 관측 edge(adjacency)만 따라감      (관측 근거 없는 전이 생성 금지)
  - 노드 재방문 허용(실제 케이스가 반복함: 예 ENT-II→PST-KB→ENT-II),
    단 순환 폭발 방지를 위해 경로 길이 ≤ MAX_LEN 으로 제한.
  ※ 인과 유효성(정보공개 후 재입력 금지 등)은 다음 단계 k4에서 필터.

── 출력 ──────────────────────────────────────────────────────
  out/candidate_sequences.json
    stats / candidates[]  (각 후보: path·length·track·align·source_cases)
"""
from pathlib import Path
import json

from k1_attack_decomposition import NODE

HERE = Path(__file__).parent
GRAPH_FILE = HERE / "out" / "transition_graph.json"
DECOMP_FILE = HERE / "out" / "attack_sequences.json"
OUT_FILE = HERE / "out" / "candidate_sequences.json"

MAX_LEN = 7    # 경로 최대 노드 수(순환 폭발 방지·조절 손잡이)
MIN_LEN = 2    # 최소 2노드(전이 1개 이상)


def enumerate_paths(adjacency: dict, starts: list[str], max_len: int) -> list[tuple]:
    """진입 노드에서 관측 edge를 따라 길이 ≤ max_len 인 모든 경로(길이 ≥ MIN_LEN) 열거."""
    paths = []
    def dfs(path):
        if len(path) >= MIN_LEN:
            paths.append(tuple(path))
        if len(path) >= max_len:
            return
        for nxt in adjacency.get(path[-1], []):
            dfs(path + [nxt])
    for s in sorted(set(starts)):
        dfs([s])
    return paths


def build_alignment_index(originals: dict):
    """원본 29 경로 → (전체 경로 집합, 모든 연속 부분경로→해당 case 목록).
       분기 케이스는 경로(paths)마다 개별 원본으로 취급."""
    full = {}                       # tuple(full path) → [cases]
    sub = {}                        # tuple(연속 부분경로, len≥MIN_LEN) → set(cases)
    for cid, info in originals.items():
        for path in info["paths"]:
            nodes = [s["node"] for s in path["sequence"]]
            full.setdefault(tuple(nodes), []).append(cid)
            n = len(nodes)
            for i in range(n):
                for j in range(i + MIN_LEN, n + 1):
                    sub.setdefault(tuple(nodes[i:j]), set()).add(cid)
    # full 값 중복 케이스 정리
    full = {k: sorted(set(v)) for k, v in full.items()}
    return full, sub


def classify(path: tuple, full: dict, sub: dict) -> dict:
    """후보 경로 → track/align/source_cases.
       Track1 커버리지 = 원본 '완전일치'(exact)만 (사용자 확정: 케이스 22/22).
       subpath = 원본의 부분조각(불완전) → 커버리지 아님, k4에서 대부분 탈락 예상.
       novel = 신규 조합(다양성)."""
    if path in full:
        return {"track": 1, "align": "exact", "source_cases": sorted(full[path])}
    if path in sub:
        return {"track": 2, "align": "subpath", "source_cases": sorted(sub[path])}
    return {"track": 2, "align": "novel", "source_cases": []}


def generate(graph: dict, originals: dict, max_len: int = MAX_LEN) -> dict:
    starts = list(graph["start_nodes"].keys())          # 관측 진입 노드
    paths = enumerate_paths(graph["adjacency"], starts, max_len)
    full, sub = build_alignment_index(originals)

    cands = []
    for p in paths:
        c = classify(p, full, sub)
        cands.append({"path": list(p), "length": len(p), **c})
    # 정렬: track → length → path
    cands.sort(key=lambda c: (c["track"], c["length"], c["path"]))

    exact = [c for c in cands if c["align"] == "exact"]       # Track1 커버리지
    subpath = [c for c in cands if c["align"] == "subpath"]   # 부분조각(불완전)
    novel = [c for c in cands if c["align"] == "novel"]       # Track2 다양성
    covered_cases = sorted({cc for c in exact for cc in c["source_cases"]})
    by_len = {}
    for c in cands:
        by_len.setdefault(c["length"], {"exact": 0, "subpath": 0, "novel": 0})
        by_len[c["length"]][c["align"]] += 1

    stats = {
        "max_len": max_len, "min_len": MIN_LEN,
        "start_nodes": starts,
        "total": len(cands),
        "track1_coverage_exact": len(exact),
        "cases_covered": f"{len(covered_cases)}/{len(originals)}",
        "track2_diversity": len(novel) + len(subpath),          # 다양성 = 신규 + 부분흐름
        "track2_detail": {"novel": len(novel), "subpath_variant": len(subpath)},
        "by_length": {str(k): by_len[k] for k in sorted(by_len)},
    }
    return {"meta": {"source": "k2 graph + k1 originals",
                     "note": "Track1 커버리지=원본 완전일치(exact)만. Track2 다양성=신규(novel)+원본부분흐름(subpath)."},
            "stats": stats, "candidates": cands,
            "covered_cases": covered_cases}


if __name__ == "__main__":
    graph = json.loads(GRAPH_FILE.read_text(encoding="utf-8"))
    originals = json.loads(DECOMP_FILE.read_text(encoding="utf-8"))["cases"]
    out = generate(graph, originals, MAX_LEN)
    OUT_FILE.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    s = out["stats"]
    print("[PHASE1 · STEP3 Candidate Sequence Generation — 2 track]")
    print(f"  입력: k2 그래프 + k1 원본 · MAX_LEN={s['max_len']} · 시작={s['start_nodes']}")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  총 후보: {s['total']}")
    print(f"   ├─ Track1 커버리지(원본 완전일치): {s['track1_coverage_exact']}  → 케이스 커버 {s['cases_covered']}")
    print(f"   └─ Track2 다양성                 : {s['track2_diversity']}  "
          f"(신규 {s['track2_detail']['novel']} + 원본부분흐름 {s['track2_detail']['subpath_variant']})")
    print("  길이별 (exact/novel/subpath):")
    for L, d in s["by_length"].items():
        print(f"    len {L}: 완전일치 {d['exact']:3} · 신규 {d['novel']:5} · 부분 {d['subpath']:3}")
