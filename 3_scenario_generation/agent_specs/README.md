# Agent Specifications (Phase 2 입력)

점검자(inspector)가 받는 각 에이전트의 **화이트박스 명세**. 여기서 능력 태깅 → `../targets/<env>.yaml`(능력맵) → g1 파이프라인.

## 흐름
```
agent_specs/<env>.yaml  (도구·데이터·주입면·권한)
      │ 능력 태깅 (효과 기준·공격자 능력 기준)
      ▼
targets/<env>.yaml       (node_tools[19노드]=실제도구, feasible/pre-satisfied/absent)
      ▼
g1 → g2 → g3 → build     (실행가능 시나리오)
```

## 파일
| 파일 | 에이전트 | 추출원 |
|---|---|---|
| agentdojo_{banking,travel,workspace,slack}.yaml | AgentDojo 4 suite | suite에서 도구 실측 추출 |
| appworld.yaml | AppWorld supervisor | 능력맵 실측(앱·API) |
| theagentcompany.yaml | OpenHands CodeActAgent | 능력맵 실측(generic 도구·서비스) |
| agentdyn.yaml | AgentDyn (예정) | 통합 서브에이전트가 생성 |

각 spec: agent·benchmark·domain·execution·injection_surface·permissions·tools/apps.
