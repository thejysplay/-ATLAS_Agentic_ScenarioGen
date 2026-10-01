# -*- coding: utf-8 -*-
"""PHASE 2 · STEP 3 — I/O Compatibility Check (구체 시나리오 정합 검증)
================================================================
g2 가 산출한 실행 표본(bound_<env>.json)의 각 시나리오가 실제로 '실행 가능한
데이터 흐름'을 이루는지 검증한다. g2 는 (종점, 목표도구) 대표를 뽑을 뿐, 골격
경로의 노드들이 실제 도구로 채워졌을 때 앞→뒤가 연결되는지는 보지 않았다.
g3 가 그 마지막 고리를 채운다.

── 3가지 정합 검사 ────────────────────────────────────────
1. terminal (종점 정합)
   경로의 마지막 노드가 곧 목표 도구가 실현하는 노드여야 한다.
   PREDICATE_KIND[end] 와 목표도구의 역할이 일치하는지.
2. dataflow (데이터 흐름)
   목표(유출·조작)에 필요한 데이터를 경로 앞부분이 실제로 공급하는지.
   - ID-ER(유출): 유출할 '비밀'을 앞선 DAC-* 조회 노드가 공급해야 성립.
     경로에 DAC-* 가 없으면 '유출할 것이 없음' → 정합 실패(또는 진입 콘텐츠 자체가 표적).
   - SC-* (조작): 조작 대상 식별자(id 등)를 앞선 조회가 공급하거나 고정값이면 성립.
3. entry (진입 정합)
   ENT-II 주입 슬롯이, 이 경로에서 에이전트가 실제로 읽는 채널인지.
   (주입한 필드를 아무 도구도 읽지 않으면 주입이 에이전트 관측에 도달하지 못함)

── 판정 ───────────────────────────────────────────────────
각 시나리오에 io_status = pass | warn | fail 부여.
  pass = 3검사 통과
  warn = 실행은 되나 순서 정밀화 필요(노드 순서가 실제 도구콜 순서와 다름)
  fail = 데이터 흐름이 성립 불가 → 실행 표본에서 제외 권고
"""
from pathlib import Path
import json, sys

HERE = Path(__file__).parent

# 종점 → 성공술어 방식 (g2 와 동일 정본)
PREDICATE_KIND = {
    "SC-BIZ": "state", "SC-SYS": "state", "SC-DAT": "state", "ID-ER": "state",
    "EXE": "state", "INV-SCU": "state",
    "DAC-UBD": "trace", "DAC-CS": "trace", "DAC-SRD": "trace",
    "ID-RG": "output",
}
# 데이터 접근(조회) 노드 = '비밀/데이터를 공급'하는 노드
SUPPLY_NODES = {"DAC-UBD", "DAC-CS", "DAC-SRD"}


def check(sc: dict) -> dict:
    path = sc["skeleton_path"]
    end = sc["end_node"]
    checks = {}

    # 1. terminal: 경로 마지막 == 종점, PREDICATE_KIND 에 정의됨
    checks["terminal"] = (path[-1] == end) and (end in PREDICATE_KIND)

    # 2. dataflow
    if end == "ID-ER":
        # 유출: 앞에 공급 노드(DAC-*)가 있거나, 진입 콘텐츠 자체가 표적(경로 길이 2 = ENT-II→ID-ER)
        has_supply = any(n in SUPPLY_NODES for n in path[:-1])
        entry_is_target = len(path) == 2 and path[0].startswith("ENT")
        checks["dataflow"] = has_supply or entry_is_target
    elif end in ("SC-BIZ", "SC-SYS", "SC-DAT", "EXE", "INV-SCU"):
        # 조작/실행: 도구 호출 노드(INV-AT/INV-SCU/EXE)가 경로에 있어야 실현
        checks["dataflow"] = any(n in ("INV-AT", "INV-SCU", "EXE") for n in path) or path[-1] in ("INV-SCU", "EXE")
    else:
        # 조회(DAC-*)·응답(ID-RG): 별도 공급 불필요 (그 자체가 목표)
        checks["dataflow"] = True

    # 3. entry: 경로가 진입 노드로 시작 (주입 채널 존재)
    checks["entry"] = path[0] in ("ENT-II", "ENT-DI")

    # 순서 정밀화 필요 여부: 유출인데 공급 노드가 종점 바로 앞이 아님
    order_warn = False
    if end == "ID-ER":
        supply_idx = [i for i, n in enumerate(path) if n in SUPPLY_NODES]
        # 공급 노드가 있는데 종점 직전이 아니면 순서 정밀화 대상
        if supply_idx and supply_idx[-1] != len(path) - 2:
            order_warn = True

    if not all(checks.values()):
        status = "fail"
    elif order_warn:
        status = "warn"
    else:
        status = "pass"

    return {"io_status": status, "io_checks": checks,
            "io_note": "유출 공급노드가 종점 직전이 아님(g3 순서 정밀화 대상)" if order_warn else ""}


def run(env: str):
    src = HERE / "out" / "_pipeline" / f"bound_{env}.json"
    if not src.exists():
        print(f"[!] {src} 없음")
        return
    data = json.loads(src.read_text(encoding="utf-8"))
    for sc in data["scenarios"]:
        sc.update(check(sc))

    from collections import Counter
    dist = Counter(sc["io_status"] for sc in data["scenarios"])
    data["io_summary"] = dict(dist)
    OUT = HERE / "out" / "_pipeline" / f"final_{env}.json"
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"[PHASE2 · STEP3 I/O Check — {env}]")
    print(f"  표본 {len(data['scenarios'])} → pass {dist['pass']} / warn {dist['warn']} / fail {dist['fail']}")
    for sc in data["scenarios"]:
        if sc["io_status"] != "pass":
            print(f"    [{sc['io_status']}] {sc['sid']} {'→'.join(sc['skeleton_path'])} {sc.get('io_note','')}")
    print(f"  출력: out/final_{env}.json")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "all":
        for e in ["banking", "travel", "workspace", "slack", "appworld", "theagentcompany"]:
            run(e)
            print()
    else:
        run(sys.argv[1] if len(sys.argv) > 1 else "banking")
