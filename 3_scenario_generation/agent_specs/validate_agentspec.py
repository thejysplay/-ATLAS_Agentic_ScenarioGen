import yaml, glob, sys
REQ_AGENT={'id','display_name','summary'}
def validate(f):
    d=yaml.safe_load(open(f,encoding='utf-8')); errs=[]
    a=d.get('agent',{})
    if not REQ_AGENT<=set(a): errs.append(f"agent 누락:{REQ_AGENT-set(a)}")
    if not isinstance(d.get('system_prompt'),str) or not d.get('system_prompt'): errs.append("system_prompt 없음")
    inj=d.get('_injection_surface') or d.get('injection_surface')
    if not inj or 'untrusted_input' not in inj: errs.append("_injection_surface 없음")
    tools=d.get('tools') or []
    if not tools: errs.append("tools 비어있음")
    bad=0
    for t in tools:
        if not t.get('name') or 'meta' not in t or t.get('meta',{}).get('trust_level') not in ('trusted_internal','untrusted_external') or 'input_schema' not in t:
            bad+=1
    if bad: errs.append(f"tool {bad}개 필드/trust_level 위반")
    return errs
if __name__=="__main__":
    allok=True
    for f in sorted(glob.glob('*.yaml')):
        e=validate(f)
        print(f"  {'PASS' if not e else 'FAIL'}  {f}"+("" if not e else "  → "+"; ".join(e)))
        allok&=not e
    print("\n전체:", "모두 통과" if allok else "위반 있음")
