# -*- coding: utf-8 -*-
"""PHASE 1 · STEP 2 — 2-gram Analysis & Transition Graph
================================================================
ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
(SPECTRA Architecture · Phase 1 "Build Threat Knowledge" 의 2단계)

  "Extract adjacent unit transitions (2-gram) and construct the attack transition graph."
   k1의 Attack Sequence 22개에서 인접한 Attack Node 쌍(2-gram)을 모두 추출하여
   **방향 전이 그래프**를 만든다. 실제 관측된 전이만 edge로 채택(관측 근거 기반).

── 입력 ──────────────────────────────────────────────────────
  out/attack_sequences.json      k1 결과(seed 22의 19-Node 시퀀스)

── 하는 일 ───────────────────────────────────────────────────
  각 시퀀스에서 연속 쌍 (node_i → node_{i+1}) 을 뽑아 집계.
  같은 방향 edge는 등장 횟수(count)와 근거 case 목록을 누적.
  (k1에서 연속 동일 노드를 collapse했으므로 self-loop(A→A)은 발생하지 않음.)

── 출력 ──────────────────────────────────────────────────────
  out/transition_graph.json
    meta / stats / nodes / edges / adjacency / start_nodes / terminal_nodes
  - edges       : [{from,to,count,cases[]}]  ← 관측 전이 = 그래프 Edge
  - adjacency   : {node: [후행노드...]}       ← k3 후보경로 생성용
  - start_nodes : 시퀀스 맨 앞에 관측된 노드  ← k4 유효 시작(SR1)용
  - terminal_nodes : 시퀀스 맨 끝에 관측된 노드
"""
from pathlib import Path
import json
from collections import defaultdict

from k1_attack_decomposition import NODE, TAXONOMY   # 정본 taxonomy 재사용

HERE = Path(__file__).parent
IN_FILE = HERE / "out" / "attack_sequences.json"
OUT_FILE = HERE / "out" / "transition_graph.json"

ALL_NODES = [code for _u, _e, _c, nodes in TAXONOMY for code, _ko, _en in nodes]   # 19개(정의순)


def build_graph(decomp: dict) -> dict:
    edge_count = defaultdict(int)             # (from,to) → count
    edge_cases = defaultdict(set)             # (from,to) → {case}
    observed = set()                          # 등장한 노드
    start_ct = defaultdict(int)               # 시작 노드 빈도
    term_ct = defaultdict(int)                # 종료 노드 빈도

    n_paths = 0
    for cid, info in decomp["cases"].items():
        for path in info["paths"]:                         # 분기 케이스는 경로 여러 개
            n_paths += 1
            nodes = [s["node"] for s in path["sequence"]]
            observed.update(nodes)
            if nodes:
                start_ct[nodes[0]] += 1
                term_ct[nodes[-1]] += 1
            for a, b in zip(nodes, nodes[1:]):
                edge_count[(a, b)] += 1
                edge_cases[(a, b)].add(cid)

    # edges (count 내림차순 → from,to 순)
    edges = []
    adjacency = defaultdict(list)
    for (a, b), c in sorted(edge_count.items(), key=lambda kv: (-kv[1], kv[0])):
        edges.append({
            "from": a, "to": b,
            "from_unit": NODE[a]["unit"], "to_unit": NODE[b]["unit"],
            "count": c, "cases": sorted(edge_cases[(a, b)]),
        })
        adjacency[a].append(b)
    for a in adjacency:
        adjacency[a] = sorted(adjacency[a])

    # 노드 메타(차수 포함)
    out_deg = defaultdict(int); in_deg = defaultdict(int)
    for e in edges:
        out_deg[e["from"]] += 1; in_deg[e["to"]] += 1
    nodes_meta = {}
    for code in ALL_NODES:
        nodes_meta[code] = {
            "unit": NODE[code]["unit"], "node_ko": NODE[code]["node_ko"],
            "observed": code in observed,
            "out_degree": out_deg[code], "in_degree": in_deg[code],
        }

    n_nodes = len(ALL_NODES)
    stats = {
        "cases": len(decomp["cases"]),
        "paths": n_paths,
        "nodes_total": n_nodes,
        "nodes_observed": len(observed),
        "possible_edges": n_nodes * n_nodes,           # 19×19=361 (self-loop 포함 상한)
        "observed_edges": len(edges),
        "total_transitions": sum(edge_count.values()),
    }
    return {
        "meta": {"source": "k1 attack_sequences.json",
                 "taxonomy": "8 Unit / 19 Attack Node",
                 "note": "관측 전이만 edge. self-loop 없음(k1 collapse). count=관측 사건수 누적, cases=근거."},
        "stats": stats,
        "nodes": nodes_meta,
        "edges": edges,
        "adjacency": dict(adjacency),
        "start_nodes": dict(sorted(start_ct.items(), key=lambda kv: (-kv[1], kv[0]))),
        "terminal_nodes": dict(sorted(term_ct.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


if __name__ == "__main__":
    decomp = json.loads(IN_FILE.read_text(encoding="utf-8"))
    g = build_graph(decomp)
    OUT_FILE.write_text(json.dumps(g, ensure_ascii=False, indent=1), encoding="utf-8")

    s = g["stats"]
    print("[PHASE1 · STEP2 Transition Graph]")
    print(f"  입력: out/{IN_FILE.name} (case {s['cases']} · path {s['paths']})")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  노드: {s['nodes_observed']}/{s['nodes_total']} 관측 · "
          f"전이: 관측 {s['observed_edges']} edge / 상한 {s['possible_edges']} · "
          f"총 전이횟수 {s['total_transitions']}")
    print(f"  시작 노드(SR1 후보): {list(g['start_nodes'])}")
    print(f"  종료 노드: {list(g['terminal_nodes'])}")
    print("  ── 관측 전이 상위 (count · 근거수) ──")
    for e in g["edges"][:12]:
        print(f"    {e['from']:8} → {e['to']:8}  ×{e['count']}  ({len(e['cases'])}건: {','.join(e['cases'][:4])}{'…' if len(e['cases'])>4 else ''})")
