# -*- coding: utf-8 -*-
"""appworld 전용 보정: EXE(code-as-action) + PST(지속 잔류물) 노드 추가.
 - EXE  : appworld는 world.execute 로 Python 실행 = 코드실행 기전 → 규칙으로 "(world.execute)" 추가.
 - PST-*: create/update로 남는 지속 잔류물(노트·파일·태스크·알람·설정)을 temp=0 LLM으로 식별해 병합.
검증된 기존 태그(ENT-II·DAC·SC·ID·INV-AT)는 그대로 두고 EXE/PST만 추가한다.
"""
import sys
from pathlib import Path
import yaml
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))  # backend.py co-located
import backend

spec = yaml.safe_load((HERE / "agent_specs" / "appworld.yaml").read_text(encoding="utf-8"))
tools = spec.get("tools", [])
names = [t.get("name") for t in tools]
tool_lines = "\n".join(
    f"- {t.get('name')}: {(t.get('description') or '').strip()[:110]}" for t in tools)

PROMPT = """AppWorld agent. For EACH tool below decide if it realizes a PERSISTENCE effect
(leaving residue that survives and can influence LATER turns/sessions, e.g. an injected note/file/
task/comment/alarm/setting that fires or is re-read later). Classify into:
  PST-KB  = persistent readable content the agent/user reads later: notes, files, task comments,
            documents, reviews (knowledge-base residue).
  PST-MEM = session/agent memory residue (rare; only if a tool writes agent memory/state).
  PST-CFG = persistent configuration/rules/schedules: alarms, account settings, recurring rules.
Only include a tool if creating/updating it leaves a PERSISTENT artifact. Pure reads or one-shot
sends (money transfer, send email/text) are NOT persistence. A tool may be in at most one PST-*.
Return ONLY JSON: {{"PST-KB":[...],"PST-MEM":[...],"PST-CFG":[...]}}
TOOLS:
{tools}"""

res = backend.gen_json(PROMPT.format(tools=tool_lines), model="gemini", temp=0)

path = HERE / "targets_auto" / "appworld.yaml"
cap = yaml.safe_load(path.read_text(encoding="utf-8"))
nt = cap["node_tools"]

# ── EXE (규칙): code-as-action 기전 ──
nt.setdefault("EXE", [])
if "(world.execute)" not in nt["EXE"]:
    nt["EXE"].append("(world.execute)")

# ── PST (LLM): 실재 도구만, 중복 제거 ──
valid = set(names)
for node in ("PST-KB", "PST-MEM", "PST-CFG"):
    add = [t for t in (res.get(node) or []) if t in valid]
    nt.setdefault(node, [])
    for t in add:
        if t not in nt[node]:
            nt[node].append(t)

cap["_appworld_boost"] = "EXE(world.execute rule) + PST(LLM) 추가"
path.write_text(yaml.safe_dump(cap, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")

print("[appworld EXE+PST 보정]")
for n in ("EXE", "PST-KB", "PST-MEM", "PST-CFG"):
    print(f"  {n:8}: {nt.get(n)}")
