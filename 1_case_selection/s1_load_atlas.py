# -*- coding: utf-8 -*-
"""STAGE 1 — load_atlas

ATLAS 기반 에이전틱 AI 맞춤형 공격시나리오 자동 생성 프레임워크
--------------------------------------------------------------------
ATLAS YAML 원문을 파이프라인이 쓰기 쉬운 형태로 정규화한다.
  - case-studies(dict)         → CS별 {id, name, description}
  - relationships[cs].employs  → 공격 스텝(S01, S02, ...) [원문 순서 유지]
  - techniques[tid].platforms  → 각 스텝에 technique 이름·platform 부착
이후 단계(선별·스펙생성)가 ATLAS를 다시 파싱하지 않도록 필요한 것을 한 번에 붙여 반환.
"""
from pathlib import Path
import json
import yaml

HERE = Path(__file__).parent
ATLAS_FILE = HERE / "atlas" / "ATLAS-2026.08.yaml"   # 파이프라인 전용 ATLAS 원본
OUT_FILE = HERE / "out" / "s1_cases.json"            # STAGE1 출력


def load_atlas(atlas_path: str | Path) -> dict[str, dict]:
    """ATLAS YAML → {cs_id: case}.

    반환 case 구조:
        {"id", "name", "description",
         "steps": [{"step_id","technique","technique_name","platforms","description"}, ...]}
    """
    atlas = yaml.safe_load(Path(atlas_path).read_text(encoding="utf-8"))
    case_studies = atlas.get("case-studies", {})
    techniques = atlas.get("techniques", {})
    relationships = atlas.get("relationships", {})

    def _stepnum(sid):                                      # "S07" → 7 (정렬 키)
        try: return int("".join(ch for ch in str(sid) if ch.isdigit()))
        except Exception: return 10 ** 9

    cases: dict[str, dict] = {}
    for cs_id, cs in case_studies.items():
        employs = (relationships.get(cs_id, {}) or {}).get("employs", []) or []
        # ATLAS employs 리스트 순서 ≠ 공격 순서 → step-id 순으로 정렬(실제 leads-to 순)
        employs = sorted(employs, key=lambda r: _stepnum(r.get("step-id", "")))
        steps = []
        for rel in employs:
            tid = rel.get("target", "")
            tech = techniques.get(tid, {}) or {}
            steps.append({
                "step_id": rel.get("step-id", ""),
                "leads_to": rel.get("leads-to", []) or [],
                "tactic": rel.get("tactic", ""),
                "technique": tid,
                "technique_name": tech.get("name", ""),
                "platforms": tech.get("platforms", []) or [],
                "description": rel.get("description", ""),
            })
        cases[cs_id] = {
            "id": cs.get("id", cs_id),
            "name": cs.get("name", ""),
            "description": cs.get("description", ""),
            "steps": steps,
        }
    return cases


if __name__ == "__main__":
    cases = load_atlas(ATLAS_FILE)
    OUT_FILE.write_text(json.dumps(cases, ensure_ascii=False, indent=1), encoding="utf-8")

    n_steps = sum(len(c["steps"]) for c in cases.values())
    print("[STAGE1 load_atlas]")
    print(f"  입력: atlas/{ATLAS_FILE.name}")
    print(f"  출력: out/{OUT_FILE.name}")
    print(f"  case studies: {len(cases)} · 총 스텝: {n_steps}")
    ex = cases.get("AML.CS0016")
    if ex:
        print(f"  예시 {ex['id']} — {ex['name']} (스텝 {len(ex['steps'])})")
        for s in ex["steps"]:
            print(f"    {s['step_id']} {s['technique']}({s['technique_name']}) platforms={s['platforms']}")
