# -*- coding: utf-8 -*-
"""STAGE 4 — select_runtime_seed  [Gate 3: Runtime Self-Vulnerability]

우리 프레임워크는 '에이전트가 런타임에 자율 동작하는 중 자기 취약성으로 전복되는' 사건을
seed로 삼는다(§ METHODOLOGY.md 1.3). Gate2까지 통과한 것 중, 아래 3범주는 제외한다.

  제외 ① Agent-as-Means   : 공격자가 자기 에이전트를 운영해 제3자 공격 (피해 에이전트 없음)
  제외 ② Supply-Chain     : 컴포넌트 사전 오염 — 사람이 직접 배치 + 사용자 승인 시 정상 도구
  제외 ③ Non-runtime      : 메모리·인터페이스·전통 RCE·C2 — 런타임 주입 seed로 재현 불가

포함(seed) = 처리 데이터(웹·이메일·문서·도구출력·메시지)를 통해 런타임에 자율 전복되는 사건.
각 제외는 사유를 코드에 기록(재현 가능). 근거의 이론적 정당화는 METHODOLOGY.md § 1.3 참조.
"""
from pathlib import Path
import json

HERE = Path(__file__).parent
IN_FILE = HERE / "out" / "s3_selected.json"        # Gate2 결과(included + unresolved)
OUT_FILE = HERE / "out" / "s4_seed.json"           # 최종 seed

# ── 제외 ① 에이전트가 '수단'(means) — 공격자가 에이전트를 도구/인프라로 부림, 피해자는 제3자 ──
AGENT_AS_MEANS = {
    "AML.CS0068": "자율 에이전트를 부려 외부 인프라(HuggingFace) 침해 — 피해자=인프라, 에이전트는 수단",
    "AML.CS0069": "탈옥 Claude Code를 사이버 간첩 도구로 악용(30개 조직) — 피해자=조직, 에이전트는 수단",
    "AML.CS0071": "다중 에이전트 프레임워크로 정부 시스템 침해 — 피해자=정부, 에이전트는 수단",
    "AML.CS0061": "AI를 C2 릴레이(통신 인프라)로 악용 — 피해자=malware 표적, 에이전트는 도관(수단)",
}
# ── 제외 ② 공급망 (사전 컴포넌트 오염) ──
SUPPLY_CHAIN = {
    "AML.CS0041": "AI 코딩 어시스턴트 rules 파일 오염 — 설정 컴포넌트 사전 배치",
    "AML.CS0047": "Amazon Q 확장 저장소에 악성코드 커밋 — 배포 공급망",
    "AML.CS0049": "레지스트리 배포 오염 스킬 — 스킬 패키지 공급망",
    "AML.CS0053": "postmark-mcp npm 패키지 impersonation — 패키지 공급망",
    "AML.CS0064": "오염 GGUF 채팅 템플릿 — 추론-시점 공급망",
}
# ── 제외 ③ 비런타임 (런타임 데이터 채널이 공격 벡터가 아님 → 전통 AppSec/인프라) ──
# ※ CS0052(프레임워크 RCE via 프롬프트 주입)는 CS0016/CS0062와 동일 유형이라 SEED로 포함(경계선 아님).
# ※ CS0061(C2 릴레이)은 '수단'이라 AGENT_AS_MEANS로 이동. → 경계선 0.
NON_RUNTIME = {
    "AML.CS0036": "LLM 데스크톱 앱 메모리에서 토큰 추출 — 메모리 포렌식(주입 아님)",
    "AML.CS0048": "노출된 제어 인터페이스 접근 — 네트워크 노출/설정(주입 아님)",
    "AML.CS0050": "악성 링크 1-click RCE — 전통 소프트웨어 취약점",
}
EXCLUSIONS = {"means": AGENT_AS_MEANS, "supply_chain": SUPPLY_CHAIN, "non_runtime": NON_RUNTIME}


def _reason(cid):
    for cat, tbl in EXCLUSIONS.items():
        if cid in tbl:
            return cat, tbl[cid]
    return None, None


def select_runtime_seed(gate2: dict) -> dict:
    """Gate2 결과 → {seed, excluded{cat:{cid:reason}}, knowledge, needs_review}."""
    pool = sorted(set(gate2["included"]) | set(gate2.get("unresolved", [])))
    seed, excluded = [], {"means": {}, "supply_chain": {}, "non_runtime": {}}
    for cid in pool:
        cat, reason = _reason(cid)
        if cat:
            excluded[cat][cid] = reason
        else:
            seed.append(cid)
    # knowledge = 에이전트 자체 취약성 전체(수단 제외) = seed + supply_chain + non_runtime
    knowledge = sorted(set(seed) | set(excluded["supply_chain"]) | set(excluded["non_runtime"]))
    return {"seed": sorted(seed), "excluded": excluded, "knowledge": knowledge}


if __name__ == "__main__":
    gate2 = json.loads(IN_FILE.read_text(encoding="utf-8"))
    r = select_runtime_seed(gate2)
    OUT_FILE.write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")

    ex = r["excluded"]
    print("[STAGE4 select_runtime_seed — Gate3: Runtime Self-Vulnerability]")
    print(f"  입력: Gate2 {len(gate2['included'])} + 미해결 {len(gate2.get('unresolved', []))}")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  ▸ SEED(런타임): {len(r['seed'])}")
    print(f"  ▸ 제외: 수단 {len(ex['means'])} · 공급망 {len(ex['supply_chain'])} · 비런타임 {len(ex['non_runtime'])}")
    print(f"  ▸ Knowledge(에이전트 자체 취약성 전체, 수단 제외): {len(r['knowledge'])}")
    print(f"  SEED = {', '.join(c.replace('AML.','') for c in r['seed'])}")
