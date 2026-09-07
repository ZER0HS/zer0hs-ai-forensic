# Backend — Forensic AI Agent

FastAPI service that parses a suspicious email/log, extracts indicators,
checks them against threat intel, runs a deterministic rule engine, and
asks an LLM (local Ollama by default, or Claude) to produce a forensic
write-up and a verdict — TP, FP, or needs review — in a single call. The
rule engine is ground truth: when it reaches a maximally-confident
verdict (including a match against something a human has confirmed
before, see "Persistent memory" below), the LLM is skipped entirely; when
it isn't confident, the LLM's output is still validated against the rule
engine's hard findings before being trusted, and a genuinely uncertain
call is flagged for human review instead of forced into a confident TP
or FP it hasn't earned.

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
engine, header parser, schemas) as pure unit tests, the full `/analyze`
pipeline as integration tests against a mocked LLM and mocked threat-intel
HTTP calls (no live network calls, ever — `tests/conftest.py` force-blanks
every API key so a forgotten mock fails loudly instead of hitting a real
service), and a fixture set of adversarial `.eml` files under
`tests/fixtures/`: typosquatting plus a malicious IP, a legitimate urgent
business email as the false-positive stress test, malformed and broken
MIME, a prompt-injection payload in the body, and an Arabic-language
phishing email. A few tests document real, currently-open limitations
rather than silently assuming they're handled, e.g. zero-width-character
injection defeating plain substring keyword matching, or a typosquat
brand name outside the hardcoded `TYPOSQUAT_BRANDS` list going
unrecognized. See their docstrings for the reasoning.

## Accuracy benchmark

```bash
python scripts/run_benchmark.py --markdown out.md
```

Runs the labeled set in `tests/benchmark/` (41 synthetic cases, roughly
half phishing and half clean) through the real pipeline, offline from the
HTTP layer, and reports accuracy/precision/recall plus a confusion
matrix. This is separate from the pytest fixtures on purpose: it's a
fixed benchmark for tracking regressions and getting a real number for
the README, not a correctness test suite. See the root `README.md`'s
performance section for the current result and what it does and doesn't
claim.

## Architecture notes

- `rule_engine.py` is the only thing allowed to force a verdict. `main.py`
  skips the LLM call entirely when the rule engine already reached a
  `verdict_override` (`shortcircuit_forensic`/`shortcircuit_verdict`); when
  it hasn't, `combined_analysis.run_combined_analysis()` runs and its
  output is validated against `schemas.py` before use.
- `combined_analysis.py` asks for the forensic write-up and the TP/FP/
  needs-review verdict in one LLM call and one schema
  (`schemas.CombinedAnalysis`), not two sequential calls — see that
  file's docstring for why, and `agent.run_analysis()` /
  `fp_tp_scorer.score_case()` for the two-call version this replaced on
  the `/analyze` path (still used directly by tests, and by
  `fp_tp_scorer.score_single()` for the single-indicator `/threat-check`
  and Sandbox Check paths, which are a different, smaller problem).
- `fp_tp_scorer.finalize_case_verdict()` is the one place the zero-
  evidence auto-correct, the confidence floor, and the needs-review
  triggers live — both `score_case()` and `combined_analysis.py` call it,
  so the two call paths can't quietly drift apart in how they finalize a
  verdict.
- Every LLM prompt loads `skills/forensic_analysis_skill.md` as its system
  prompt (via `skill_loader.py`) and wraps untrusted evidence text in
  `<<<EVIDENCE_START>>>`/`<<<EVIDENCE_END>>>` markers with an explicit
  instruction not to follow anything instruction-like found inside them.
- `llm_client.ask_llm_json()` validates every LLM response against a
  Pydantic schema, re-prompts once on failure, and only falls back to the
  schema's own explicit defaults after a second failure.
- `confirmed_indicators.py` is a permanent memory of indicators a human
  has confirmed via the feedback loop, checked before threat intel or the
  LLM are called at all — distinct from `threat_intel.py`'s 10-minute API
  cache, which is a speed optimization, not memory. `scripts/
  suggest_rules.py` scans confirmed feedback for patterns worth adding to
  `TYPOSQUAT_BRANDS`/`PHISHING_KEYWORDS` and prints them for a human to
  review; nothing ever edits `rule_engine.py`'s lists automatically.
- Sandbox has two speeds: `/sandbox/check` (threat intel plus the
  typosquat check on a URL's domain, seconds) and `/sandbox/scan` (the
  URLScan.io submission, 15-45s) — Scan always includes the same verdict
  Check would produce, computed concurrently with the URLScan wait so
  combining them costs nothing extra.
