# AgentSpec 고정 스키마 (contract)

**정의**: 점검자(화이트박스)가 대상 에이전트의 **실제 코드에서 추출**한 에이전트 전체 정보.
파이프라인 입력 = 이 스펙. 아무 에이전트든 이 형식이면 capability mapping→위협지식 결합→시나리오 생성 가능.

## 필수 코어 (모든 스펙에 항상, 이 모양 고정)
```yaml
agent:
  id: <str>                 # 고유 id (예: agentdojo_banking)
  display_name: <str>
  summary: <str>
system_prompt: <str>        # 코드에서 추출한 실제 시스템 프롬프트(화이트박스)
_injection_surface:         # 비신뢰 입력이 들어오는 채널(환경별 상이·필수)
  untrusted_input: [<str>]  # 예: [tool_output]
  note: <str>
tools:                      # 코드에서 추출한 실제 도구 전체(비어있으면 위반)
- name: <str>
  title: <str>
  description: <str>
  meta:
    category: <str>
    trust_level: trusted_internal | untrusted_external   # ★비신뢰 데이터 반환 도구=untrusted_external=주입 진입점
  input_schema:
    properties: {<argname>: {type: <str>, ...}}
```

## 선택 (점검자가 아는 부가 에이전트 정보 — 있어도 됨)
suite / suites / apps / execution / n_tools / services / realized_capabilities 등.

## 판정 기준
- trust_level 로 주입 진입점(ENT-II) 자동 식별.
- 목표(G1~G9)·성공기준은 이 스펙(도구·효과)에서 도출.
