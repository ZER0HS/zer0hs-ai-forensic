import os
import json
import logging
import re
from typing import Optional, Tuple, Type, TypeVar

import anthropic
import httpx
from pydantic import BaseModel, ValidationError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from retry_utils import llm_retry

logger = logging.getLogger(__name__)

LLM_PROVIDER  = os.getenv("LLM_PROVIDER", "claude")
OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://localhost:11434")

claude_client = None
if os.getenv("ANTHROPIC_API_KEY"):
    claude_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Only retry Claude calls on connection/rate-limit errors — never on a
# timeout, for the same "might just be slow, not broken" reasoning as Ollama.
_claude_retry = retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=3),
    retry=retry_if_exception_type((anthropic.APIConnectionError, anthropic.RateLimitError)),
    reraise=True,
)


async def ask_llm(prompt: str, system: str = "", max_tokens: int = 2000) -> str:
    if LLM_PROVIDER == "ollama":
        return await ask_ollama(prompt, system, max_tokens)
    else:
        return ask_claude(prompt, system, max_tokens)


@_claude_retry
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


@llm_retry
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
    """Best-effort extraction of a JSON object from raw LLM text (strips
    markdown fences, tolerates single quotes / Python literals). This is
    intentionally forgiving about *formatting* — schema correctness is
    then enforced separately by ask_llm_json()."""
    raw = raw.strip()
    raw = re.sub(r'```json\s*', '', raw)
    raw = re.sub(r'```\s*', '', raw)
    raw = raw.strip()
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


T = TypeVar("T", bound=BaseModel)


def _validate(raw: str, schema: Type[T]) -> Tuple[Optional[T], Optional[str]]:
    data = clean_json(raw)
    if not data:
        return None, "Response was not valid JSON."
    try:
        return schema.model_validate(data), None
    except ValidationError as e:
        return None, str(e)[:800]


async def ask_llm_json(
    prompt: str,
    system: str,
    schema: Type[T],
    max_tokens: int = 2000,
) -> T:
    """Ask the LLM for JSON and validate it against `schema`.

    Replaces the old pattern of `clean_json()` + a pile of `.setdefault()`
    calls, which silently turned a broken model response into an empty dict
    that *looked* like a confident default verdict. Here, a schema failure
    triggers exactly one re-prompt with the validation error attached; if
    that also fails, we return `schema()` — the model's own explicit,
    conservative defaults — so a broken response is always distinguishable
    from a real one in the data (e.g. verdict defaults to "FP", never "TP").
    """
    raw = await ask_llm(prompt, system, max_tokens)
    parsed, err = _validate(raw, schema)
    if parsed is not None:
        return parsed

    logger.warning("LLM response failed schema validation for %s, re-prompting once: %s",
                    schema.__name__, err)

    retry_prompt = (
        f"{prompt}\n\n---\n"
        f"Your previous response failed schema validation: {err}\n"
        f"Return ONLY a single valid JSON object matching the exact schema "
        f"requested above. No text before or after it, no markdown fences."
    )
    raw2 = await ask_llm(retry_prompt, system, max_tokens)
    parsed2, err2 = _validate(raw2, schema)
    if parsed2 is not None:
        return parsed2

    logger.error("LLM response failed schema validation twice for %s, falling back to "
                 "safe defaults: %s", schema.__name__, err2)
    return schema()
