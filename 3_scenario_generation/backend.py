# -*- coding: utf-8 -*-
"""
LLM 백엔드 (gemini / ollama) — JSON 출력 전용
====================================================================================================
프로젝트 규칙: 모든 LLM 호출은 temperature=0 (매핑·생성 재현성). temp 인자 기본값 0, 강제.
gemini 키는 damn-vulnerable-llm-agent/.env 에서 로드.
"""
import os
import json
import re
import time
from pathlib import Path

MODELS = {
    "gemini":  {"backend": "gemini", "model": "gemini-2.5-flash"},
    "qwen7b":  {"backend": "ollama", "model": "qwen2.5:latest"},
    "qwen14b": {"backend": "ollama", "model": "qwen2.5:14b"},
    "llama8b": {"backend": "ollama", "model": "llama3.1:latest"},
}
OLLAMA_URL = "http://localhost:11434/api/generate"
_ENV = Path(os.getenv("SPECTRA_ENV_FILE", str(Path(__file__).parent / ".env")))
_client = None


def _load_key():
    if os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
        return
    if _ENV.exists():
        for ln in _ENV.read_text().splitlines():
            if ln.startswith("GEMINI_API_KEY="):
                os.environ["GEMINI_API_KEY"] = ln.split("=", 1)[1].strip().strip('"')
                break


def _parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            return json.loads(m.group(0))
    raise ValueError("JSON 파싱 실패")


def _gen_gemini(prompt, model, temp):
    global _client
    from google import genai
    _load_key()
    if _client is None:
        _client = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
    last = ""
    for _ in range(4):
        try:
            r = _client.models.generate_content(
                model=model, contents=prompt,
                config={"temperature": temp, "max_output_tokens": 16384, "response_mime_type": "application/json"})
            last = (getattr(r, "text", "") or "").strip()
            if last:
                return _parse_json(last)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"; time.sleep(3)
    raise RuntimeError(f"gemini 실패: {last[:200]}")


def _gen_ollama(prompt, model, temp):
    import urllib.request
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json",
                       "options": {"temperature": temp, "num_ctx": 16384, "num_predict": 8192}}).encode()
    last = ""
    for _ in range(3):
        try:
            req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=1200) as resp:
                r = json.loads(resp.read().decode())
            last = (r.get("response") or "").strip()
            if last:
                return _parse_json(last)
        except Exception as e:
            last = f"{type(e).__name__}: {e}"; time.sleep(3)
    raise RuntimeError(f"ollama 실패: {last[:200]}")


def gen_json(prompt, model="gemini", temp=0):
    """JSON 생성. temp 는 항상 0 권장(기본 0). model = MODELS 키."""
    m = MODELS[model]
    if m["backend"] == "gemini":
        return _gen_gemini(prompt, m["model"], temp)
    return _gen_ollama(prompt, m["model"], temp)
