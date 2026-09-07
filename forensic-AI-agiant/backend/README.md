# Backend — Forensic AI Agent

FastAPI service that parses a suspicious email/log, extracts indicators,
checks them against threat intel, runs a deterministic rule engine, and
asks an LLM (local Ollama by default, or Claude) to produce a forensic
write-up and a TP/FP verdict. The rule engine is ground truth: when it
reaches a maximally-confident verdict, the LLM is skipped entirely; when it
isn't confident, the LLM's output is still validated against the rule
engine's hard findings before being trusted.

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux
pip install -r requirements-dev.txt   # runtime + test deps
# pip install -r requirements.txt     # runtime only (e.g. for a Docker image)
cp .env.example .env           # then fill in real values
```

By default `LLM_PROVIDER=ollama` — install [Ollama](https://ollama.com),
run `ollama pull qwen2.5:14b` (or whatever `OLLAMA_MODEL` you set), and
make sure it's running before starting the server. Set `LLM_PROVIDER=claude`
and `ANTHROPIC_API_KEY` to use Claude instead — email content then leaves
the machine, so this is opt-in, not the default.

Threat-intel API keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
`URLSCAN_API_KEY`) are optional — each check degrades gracefully to "not
configured" rather than failing when its key is missing.

Set `API_KEY` before exposing this past `localhost` — every write endpoint
(`/analyze`, `/threat-check`, `/sandbox`) then requires a matching
`X-API-Key` header. Left unset, auth is a no-op for local development.

## Run

```bash
uvicorn main:app --reload --port 8000
```

## Test

```bash
pytest
```

The suite (`tests/`) covers the deterministic modules (extractor, rule
engine, header parser) as pure unit tests, the full `/analyze` pipeline as
integration tests against a mocked LLM and mocked threat-intel HTTP calls
(no live network calls, ever — `tests/conftest.py` force-blanks every API
key so a forgotten mock fails loudly instead of hitting a real service),
and a fixture set of adversarial `.eml` files under `tests/fixtures/`
(typosquatting + malicious IP, a legitimate urgent business email as the
false-positive stress test, malformed/broken MIME, and a prompt-injection
payload in the body). Several tests intentionally document known
limitations rather than silently assuming they're handled — e.g. the
English-only keyword lists missing Arabic-language social engineering, or
a punycode homoglyph domain evading the plain-text typosquat check — see
their docstrings for the reasoning and the recommended fix.

## Architecture notes

- `rule_engine.py` is the only thing allowed to force a verdict. `main.py`
  skips both LLM calls entirely when the rule engine already reached a
  `verdict_override` (`shortcircuit_forensic`/`shortcircuit_verdict`); when
  it hasn't, the LLM path runs and its output is validated against
  `schemas.py` before use.
- Every LLM prompt loads `skills/forensic_analysis_skill.md` as its system
  prompt (via `skill_loader.py`) and wraps untrusted evidence text in
  `<<<EVIDENCE_START>>>`/`<<<EVIDENCE_END>>>` markers with an explicit
  instruction not to follow anything instruction-like found inside them.
- `llm_client.ask_llm_json()` validates every LLM response against a
  Pydantic schema, re-prompts once on failure, and only falls back to the
  schema's own explicit defaults after a second failure.
