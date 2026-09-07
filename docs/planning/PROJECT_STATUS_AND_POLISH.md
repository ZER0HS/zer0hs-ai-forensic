# Where This Project Actually Stands Now

I went back into the live code rather than trusting the last review — a lot has changed. Short version: this is no longer "some code you're unsure about." Claude Code has genuinely implemented almost the entire brief, well, with good judgment calls along the way. Below is what I verified, what the tool does today, the design, and what's left to call this a finished, portfolio-ready project rather than a very good work-in-progress.

## What I found on recheck

The repo now has real history — 6 commits, not zero:

```
6131682 Stage: Docker + CI, plus a real OLLAMA_URL bug Docker testing found
335fd2c Stage 4: frontend redesign, Case History + Accuracy pages
13385fa Stage 5: pytest suite + three real bugs it found in the rule engine
e3e0704 Stage 2+3: security hardening, prompt-injection defense, and performance
378fef9 Stage 1: foundation cleanup
4339017 Baseline: initial import before hardening pass
```

I read the actual code behind each of these, not just the commit messages, and it holds up:

- `backend/main.py` now has real API-key auth (`require_api_key`), per-route rate limits (`@limiter.limit("10/minute")` on `/analyze`, tighter on `/sandbox`), and CORS pulled from `CORS_ORIGINS` — no more `"*"`.
- `backend/schemas.py` replaces the old regex-based JSON scraping with real Pydantic validation for every LLM response shape, with a comment explaining exactly why (a malformed response used to silently become a confident-looking default verdict — now it's loud instead of silent).
- `backend/skills/forensic_analysis_skill.md` exists and `skill_loader.py` loads it into both `agent.py` and `fp_tp_scorer.py` — the evidence-grounding/anti-injection methodology is now one file, not two duplicated prompts.
- The `Highlight` schema explicitly documents "plain text only — never HTML" and requires the frontend to render it via character offsets instead of `dangerouslySetInnerHTML`. The XSS is fixed at the schema level, not just patched in one component.
- `check_all_hashes()` in `sandbox.py` finally calls the `check_hash_vt()` function that used to just sit there unused — attachment hashes are now actually checked against VirusTotal, with a code comment explicitly calling out that this was "the missing link that was flagged in the review."
- The rule engine now has `shortcircuit_forensic`/`shortcircuit_verdict` — when it's already maximally confident, both LLM calls are skipped entirely. I found the actual test proving it: `test_obvious_phishing_short_circuits_and_never_calls_the_llm` asserts the Ollama route was never called.
- There's a real test suite now (`backend/tests/`), including a fixture called `prompt_injection.eml` containing a literal "SYSTEM NOTICE TO AI ANALYST: ignore all previous instructions" payload, and a test that feeds a *hijacked* mocked LLM response back through the pipeline and asserts the rule engine still wins. That's a genuinely good adversarial test, not a token one.
- There's a zip-bomb test, a malformed-`.eml` test, an API-key-required test, and a regression test for a real bug the team found while dockerizing (`/status` was hardcoding `localhost:11434`, which broke silently inside Docker where Ollama runs on the host — now covered by `test_status_checks_ollama_at_the_configured_url`).
- CI (`.github/workflows/ci.yml`) runs `pytest`, `pip-audit`, a frontend build, and `npm audit` on every push.
- The frontend has a real `Sidebar.jsx` with `lucide-react` icons (no more emoji), a proper `CaseHistory.jsx` and `AccuracyDashboard.jsx` — the two features I flagged as "built on the backend, invisible in the UI" now exist — and `frontend/src/index.css` now defines a real design-token system: a named type scale, a spacing scale, radii, `--sidebar-width`/`--topbar-height`. This is close to pixel-for-pixel what I described in the last plan.

Two things worth flagging plainly, not to nitpick but because they're easy to lose:

- **A meaningful amount of work is sitting uncommitted right now** — `rule_engine.py`, `header_parser.py`, `knowledge_base.py`, `extractor.py`, and several frontend components show as modified with a full-file rewrite's worth of changes. This is almost certainly the Stage 5 bug-fixing pass (the commit message says pytest found three real bugs in the rule engine) that hasn't been committed yet. Commit it before anything else — uncommitted work in a folder that isn't backed up anywhere is the one way all of this could still be lost.
- **There's no git remote configured.** `git remote -v` returns nothing — this repo exists only on this machine. Push it to a private (or public, once you're comfortable) GitHub repo. Beyond backup, this is also what makes the CI badge and the repo link real things you can put in front of an interviewer instead of something you'd have to explain isn't live anywhere.

## What this tool actually does, as it stands today

It's a self-hosted phishing/forensic-email analysis platform: you give it an email (`.eml`, `.txt`, `.log`, a `.zip` of several, or pasted text) and it returns a cited, confidence-scored verdict on whether it's a real threat, with the evidence to back that verdict up.

The pipeline, in order: it parses the email (headers, SPF/DKIM/DMARC, attachment hashes, routing IPs) and extracts indicators (IPs, domains, URLs, emails) from the body; it checks every IP and domain against AbuseIPDB and VirusTotal, and every attachment hash against VirusTotal, all in parallel; it runs those results plus keyword/typosquat/urgency-pattern analysis through a deterministic rule engine that produces its own score and, for the clear-cut cases, a hard TP/FP verdict; if the rule engine is already confident, the pipeline stops there and returns immediately — no LLM call, which is both faster and removes any chance of a manipulated model response overriding a case that was never ambiguous. For the genuinely ambiguous middle, it calls an LLM (Claude or a fully local Ollama model — your choice, one env var) twice: once for a structured forensic breakdown (entities, timeline, anomalies, cited findings) and once for the final TP/FP verdict with a MITRE ATT&CK mapping and recommended actions, both governed by the same shared analysis methodology and both schema-validated on the way back. Every analysis is saved, an analyst can correct the verdict, and that feedback rolls up into a real accuracy/precision/recall dashboard.

On top of that pipeline there's also a standalone single-indicator threat checker (paste an IP or domain, get the same AI-scored verdict without a full email), and a URL sandbox that submits a link to URLScan.io and returns a screenshot, verdict, and behavioral report. All of it runs local-first by default — Ollama, nothing leaves the machine — with cloud (Claude) as an explicit opt-in, and the whole thing is now behind an API key and rate limits so it's safe to point at more than just localhost.

## The design

I built a visual mockup as an artifact before reading the current frontend code in depth, so treat it as a second opinion arriving after the fact rather than the blueprint — the direction I sketched (persistent sidebar, one shared severity-badge language, a Case History page, an Accuracy dashboard with real charts) turned out to already match what's actually been built, which is a good sign the instinct was right, not a reason to redo anything. Worth comparing side by side for a few specific ideas that may still be worth adding to the real app: a small "recent cases" strip on the Analyze screen itself so a first-time visitor immediately sees the tool has history; a confusion-matrix tile and an accuracy-over-time trend line on the Accuracy dashboard specifically (beyond whatever chart is there now); and cited evidence rendered inline with a `<mark>`-style highlight in the Overview tab, which is the visual expression of the evidence-grounding rule the skill file already enforces on the backend.

## What's left to make this a *perfect* project, not just very good code

Everything below assumes the code-level work above stays as good as it already is — this list is specifically the things that sit outside the codebase and determine whether this reads as a finished, presentable project versus a strong repo with no frame around it.

1. **Commit and push.** Commit the pending rewrite, push to a real GitHub remote (private is fine to start). This is the single highest-priority item — everything else assumes the work is safe and shareable.
2. **A real root README.** Right now the story of this project is spread across `PROJECT_REVIEW.md`, `IMPLEMENTATION_PLAN.md`, `DEPLOYMENT.md`, and two per-package READMEs — there's no single front door. Write one root `README.md` with: a one-paragraph pitch, a screenshot or two (the published design mockup or real screenshots once you're happy with the live UI), the CI badge once it's pushed, a "quick start" (`docker compose up`), and a short "why this is architected the way it is" section — the rule-engine-overrides-LLM decision and the prompt-injection test are exactly the kind of design reasoning worth stating explicitly, since it's the most defensible security decision in the whole project.
3. **A LICENSE file.** There isn't one. Pick MIT or Apache-2.0 (either is a reasonable default for a portfolio project) — an unlicensed public repo technically reserves all rights, which undercuts a repo you want people (or an interviewer) to actually clone and run.
4. **Verify the test suite actually passes end to end, and get it green in CI**, not just locally reasoned-about — run `pytest -v` in a clean environment (`pip install -r requirements-dev.txt` first) and confirm all of it passes, since the uncommitted rewrite hasn't been proven green yet.
5. **Fill the one adversarial gap that's still open**: the hard-case list called for Arabic-language phishing content and homoglyph/obfuscated-URL detection specifically because `rule_engine.py`'s keyword and pattern lists are still English-only — I didn't find either addressed in the current code. Given where you're applying for roles, this is also a genuinely good interview talking point once it exists ("I specifically tested non-Latin-script social engineering because English-only keyword matching is a common real-world gap").
6. **A demo path a stranger can actually run in one command.** The Docker Compose setup already exists — the remaining piece is 2-3 safe, synthetic sample emails (the test fixtures already qualify) exposed as an obvious "try it" path in the README or a `samples/` folder, so someone evaluating this doesn't have to write their own test email first.
7. **A short write-up of the security decisions, separate from the README's overview** — a one-page "threat model" doc: what this defends against (prompt injection, a hijacked local model, zip bombs, malicious attachments by hash not just extension), what it explicitly doesn't try to defend against yet (multi-tenant auth, e.g.), and why the rule engine sits above the LLM in the trust hierarchy. This is the artifact that actually gets read in an AppSec interview — more than the code itself, it demonstrates you can reason about a system's trust boundaries, which is the skill the interview is testing for.

Once those seven are done, this stops being "a project I'm not sure about" and becomes a finished, defensible piece of work with a clear story from README to threat model to test suite. The code is already most of the way there — what's left is almost entirely the frame around it.
