# -*- coding: utf-8 -*-
"""PHASE 1 · STEP 1 — Attack Decomposition (branch-aware)
================================================================
ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
(SPECTRA Architecture · Phase 1 "Build Threat Knowledge" 의 1단계)

  "Break each real attack case into an ordered chain of attack units."
   각 실제 공격 사건(선정 seed)의 ATLAS Attack Flow를
   Unit / Attack Node / Resource 수준의 **순서화된 Attack Sequence** 로 분해한다.

★ 분기(branch) 처리 — 중요
   일부 케이스는 '공통 진입 이후 여러 목표로 분기'한다(CS0063=6목표, CS0066=3목표).
   이를 하나의 긴 시퀀스로 이어붙이면 안 되고(예전 오류: CS0063이 16노드),
   **각 분기를 별도 경로로 분해**한다: path = 공통 prefix + 각 branch.
   또 '◇ 가능성(관측된 공격 아님)' 표시된 pbar 경로는 관측이 아니므로 **제외**.

── 입력 ──────────────────────────────────────────────────────
  ../PPT/[v7·26] ... .html        사람이 검증한 per-case 시퀀스(정본, 분기구조 포함)
  ../1_Case_Selection/out/s4_seed.json   선정 seed 22
  ../1_Case_Selection/out/s1_cases.json  ATLAS 메타(이름)

── 분해 규칙(결정론) ─────────────────────────────────────────
  ① 분기 전개: 분기 케이스 → (공통 + 각 branch) 별도 경로. pbar(가능성) 제외.
  ② 19-Node remap: INT-EC→ENT-II · EXE-SE/SSE→EXE · INV-SCU+코드Resource→EXE
  ③ 연속 동일 노드 collapse (INV-AT·INV-SCU(비코드)·EXE 는 서로 다른 노드 → 보존)

── 출력 ──────────────────────────────────────────────────────
  out/attack_sequences.json
    { "cases": { "CS0063": {name, scope, n_paths, paths:[{label,sequence,chain}]}, ... },
      "stats": {...} }
  한 케이스가 여러 경로(paths)를 가질 수 있다. 이 '경로' 하나하나가 다음 단계의 단위.
"""
from pathlib import Path
import re, json

HERE = Path(__file__).parent
ROOT = HERE.parent
V7 = ROOT / "PPT" / "[v7·26] SPECTRA Case Mapping v7 (26건 선정 · 8건 3차 제외 · ATLAS 2026.08).html"
SEED_FILE = ROOT / "1_Case_Selection" / "out" / "s4_seed.json"
CASES_FILE = ROOT / "1_Case_Selection" / "out" / "s1_cases.json"
OUT_FILE = HERE / "out" / "attack_sequences.json"

# ── 정본 Taxonomy: 8 Unit / 19 Attack Node ─────────────────────
TAXONOMY = [
 ("진입","Entry","ENT",[("ENT-DI","직접입력","Direct Input"),("ENT-II","간접입력","Indirect Input")]),
 ("권한·권위","Privilege/Authority","PA",[("PA-GA","부여 권한","Granted Authority")]),
 ("데이터 접근","Data Access","DAC",[("DAC-UBD","사용자·업무","User/Business Data"),
    ("DAC-CS","자격증명·비밀","Credential/Secret"),("DAC-SRD","시스템·런타임","System/Runtime Data")]),
 ("실행","Execution","EXE",[("INV-AT","응용 도구","Application Tool"),
    ("INV-SCU","컴퓨터·시스템 조작","System/Computer-Use"),("EXE","코드·명령 실행","Code/Command Execution")]),
 ("상태 변경","State Change","SC",[("SC-SYS","시스템·설정 상태","System/Config State"),
    ("SC-DAT","데이터·파일 상태","Data/File State"),("SC-BIZ","업무·거래 상태","Business/Transaction State")]),
 ("지속화","Persistence","PST",[("PST-MEM","세션·메모리 잔류","Session/Memory Residue"),
    ("PST-KB","지식베이스 잔류","Knowledge-base Residue"),("PST-CFG","지속 설정·규칙 잔류","Persistent Config/Rule Residue")]),
 ("정보 공개","Info Disclosure","ID",[("ID-RG","결과 생성","Result Generation"),("ID-ER","외부 공개","External Release")]),
 ("인간 의존","Human Dependency","HD",[("HD-UI","사용자 유도","User Inducement"),("HD-UAD","사용자 승인·판단","User Approval/Judgment")]),
]
NODE = {}
for u_ko, u_en, u_code, nodes in TAXONOMY:
    for code, ko, en in nodes:
        NODE[code] = {"unit": u_ko, "unit_code": u_code, "node_ko": ko, "node_en": en}

CODE_RES = {"Terminal / CLI", "Code / IDE Tool", "SSH / Remote Shell"}


# ── v7 HTML 파싱 (분기 인식) ───────────────────────────────────
def _nodes_in(seqbar_html: str):
    """seqbar HTML 조각 → [(node_code, resource)] (순서대로)."""
    out = []
    for chunk in re.split(r'<div class="sqnode', seqbar_html)[1:]:
        chunk = chunk.split('<div class="sqarrow')[0]      # 다음 화살표 전까지
        code = re.search(r'\[([A-Z]{2,4}-[A-Z]{2,4})\]', chunk)
        res = re.search(r'sqinst"[^>]*>([^<]+)', chunk)
        if code:
            out.append((code.group(1), res.group(1).strip() if res else ""))
    return out


def _main_bar(top: str) -> str:
    """맨 앞 공통/메인 seqbar('<div class="seqbar">' 정확히) HTML만 잘라 반환."""
    m = re.search(r'<div class="seqbar">', top)
    if not m:
        return ""
    rest = top[m.end():]
    cuts = [rest.find(t) for t in ('<div class="seqbar', '<div class="branchwrap"') if rest.find(t) >= 0]
    return rest[:min(cuts)] if cuts else rest


def extract_paths(sec: str):
    """케이스 섹션 → [(label, [(node,res)...])]  (관측 경로만; 가능성 pbar 제외)."""
    top = sec.split('<table class="steptbl"')[0]
    main = _nodes_in(_main_bar(top))                       # 공통/메인
    if '<div class="branchwrap"' in top:                   # 분기 케이스
        paths = []
        for b in top.split('<div class="branch">')[1:]:
            goal = re.search(r'class="bgoal">([^<]+)', b)
            bnodes = _nodes_in(b.split('<div class="bnote"')[0])
            paths.append((goal.group(1).strip() if goal else None, main + bnodes))
        return paths
    return [(None, main)]                                  # 단일 경로 (pbar는 애초에 제외됨)


# ── 19-Node 정합 (remap + collapse) ────────────────────────────
def remap_node(node: str, resource: str) -> str:
    if node == "INT-EC":
        return "ENT-II"
    if node in ("EXE-SE", "EXE-SSE"):
        return "EXE"
    if node == "INV-SCU" and resource in CODE_RES:
        return "EXE"
    return node


def decompose(raw: list) -> list:
    """[(node,res)] → 19-Node 시퀀스(연속 동일 collapse)."""
    remapped = [(remap_node(n, r), r) for n, r in raw]
    seq = []
    for code, res in remapped:
        if seq and seq[-1]["node"] == code:               # 연속 동일 collapse
            continue
        meta = NODE.get(code)
        if meta is None:
            raise ValueError(f"미정의 노드 {code}")
        seq.append({"idx": 0, "node": code, "resource": res,
                    "unit": meta["unit"], "unit_code": meta["unit_code"],
                    "node_ko": meta["node_ko"], "node_en": meta["node_en"]})
    for i, s in enumerate(seq, 1):
        s["idx"] = i
    return seq


def build(seed, cases, html):
    result, total_paths = {}, 0
    for cid in seed:
        short = cid.replace("AML.", "")
        m = re.search(r'id="' + short + r'".*?</section>', html, re.S)
        if not m:
            continue
        paths = []
        for label, raw in extract_paths(m.group(0)):
            seq = decompose(raw)
            if not seq:
                continue
            paths.append({"label": label, "sequence": seq,
                          "chain": " → ".join(s["node"] for s in seq)})
        total_paths += len(paths)
        result[short] = {"name": cases.get(cid, {}).get("name", ""),
                         "scope": "seed", "n_paths": len(paths), "paths": paths}
    return {"cases": result,
            "stats": {"cases": len(result), "total_paths": total_paths}}


if __name__ == "__main__":
    seed = json.loads(SEED_FILE.read_text(encoding="utf-8"))["seed"]
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    html = V7.read_text(encoding="utf-8")

    out = build(seed, cases, html)
    OUT_FILE.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    s = out["stats"]
    print("[PHASE1 · STEP1 Attack Decomposition — branch-aware]")
    print(f"  입력: v7 HTML · seed {len(seed)}")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  케이스 {s['cases']} · 총 경로(paths) {s['total_paths']}  (분기 케이스는 여러 경로)")
    lens = [len(p["sequence"]) for c in out["cases"].values() for p in c["paths"]]
    print(f"  경로 길이: 최소 {min(lens)} · 최대 {max(lens)} · 평균 {sum(lens)/len(lens):.1f}")
    print("  ── 분기 케이스 확인 ──")
    for cid, c in out["cases"].items():
        if c["n_paths"] > 1:
            print(f"    {cid} ({c['n_paths']}경로):")
            for p in c["paths"]:
                print(f"       [{p['label'] or '경로'}] {p['chain']}")
