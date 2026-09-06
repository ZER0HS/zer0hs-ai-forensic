import os
import json
import httpx
import re

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "claude")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://localhost:11434")

claude_client = None
if os.getenv("ANTHROPIC_API_KEY"):
    import anthropic
    claude_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

async def ask_llm(prompt: str, system: str = "", max_tokens: int = 2000) -> str:
    if LLM_PROVIDER == "ollama":
        return await ask_ollama(prompt, system, max_tokens)
    else:
        return ask_claude(prompt, system, max_tokens)

def ask_claude(prompt: str, system: str, max_tokens: int) -> str:
    if not claude_client:
        raise ValueError("ANTHROPIC_API_KEY not set")
    kwargs = {
        "model":      "claude-sonnet-4-5",
        "max_tokens": max_tokens,
        "messages":   [{"role": "user", "content": prompt}]
    }
    if system:
        kwargs["system"] = system
    msg = claude_client.messages.create(**kwargs)
    return msg.content[0].text

async def ask_ollama(prompt: str, system: str, max_tokens: int) -> str:
    full_prompt = f"{system}\n\n{prompt}" if system else prompt
    async with httpx.AsyncClient(timeout=180) as client:
        r = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":  OLLAMA_MODEL,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature":   0.05,
                    "num_predict":   max_tokens,
                    "top_p":         0.9,
                    "repeat_penalty": 1.1
                }
            }
        )
        if r.status_code != 200:
            raise ValueError(f"Ollama error: {r.status_code} {r.text}")
        return r.json().get("response", "")

def clean_json(raw: str) -> dict:
    raw = raw.strip()
    # Remove markdown
    raw = re.sub(r'```json\s*', '', raw)
    raw = re.sub(r'```\s*', '', raw)
    raw = raw.strip()
    # Extract JSON object
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start != -1 and end > start:
        raw = raw[start:end]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raw = raw.replace("'", '"')
        raw = raw.replace("True", "true").replace("False", "false")
        raw = raw.replace("None", "null")
        try:
            return json.loads(raw)
        except Exception:
            return {}