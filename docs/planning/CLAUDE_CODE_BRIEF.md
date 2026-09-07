# Brief for Claude Code: fix list, README, and a real accuracy number

Read this whole file before starting. It replaces the "what to send Claude Code" sections in the earlier docs (`PROJECT_REVIEW.md`, `IMPLEMENTATION_PLAN.md`, `PROJECT_STATUS_AND_POLISH.md`) with one current, actionable list. Those older docs are still useful for background on *why* each item matters, but this file is the one to work from.

## Part 1: Fix and improve checklist

Work through these in order. Commit after each numbered group so the changes are reviewable in small pieces.

**Ship what's already sitting uncommitted**

- [ ] Commit the current working-tree changes in `rule_engine.py`, `header_parser.py`, `knowledge_base.py`, `extractor.py`, and the modified frontend components. This looks like the bug-fix pass pytest turned up; get it into git before anything else so it can't be lost.
- [ ] Run `pytest -v` in a clean virtualenv (`pip install -r requirements-dev.txt` first) and confirm everything passes after that commit. The rewrite hasn't been proven green yet.
- [ ] Add a GitHub remote and push. There is no remote configured right now, so none of this is backed up anywhere but one machine.

**Close the one adversarial gap still open**

- [ ] `rule_engine.py`'s keyword lists (`PHISHING_KEYWORDS`, `URGENCY_PATTERNS`, `SOCIAL_ENGINEERING`) and the typosquat check are English-only. Add at minimum: a homoglyph/lookalike-character check on domains (Cyrillic/Latin confusables like `а` vs `a`, `е` vs `e`), and a second, Arabic-language keyword set for the same phishing/urgency/social-engineering categories, applied the same way as the English one. Add a matching test fixture (an Arabic-language phishing `.eml`) alongside the existing four in `backend/tests/fixtures/`.

**Turn this into a project someone else can pick up**

- [ ] Add a `LICENSE` file at the repo root. MIT or Apache-2.0 are both reasonable defaults for a portfolio project; pick one.
- [ ] Add a `samples/` folder (or reuse `backend/tests/fixtures/` and point to it) with 2 or 3 safe, synthetic sample emails, so someone trying the project doesn't have to write their own test case first.
- [ ] Write a short, separate `THREAT_MODEL.md`: what the system defends against (prompt injection from evidence text, a hijacked local model, zip bombs, malicious attachments identified by hash rather than just extension), what it deliberately does not yet handle (multi-tenant auth is the obvious one), and why the deterministic rule engine sits above the LLM in the trust hierarchy rather than the other way around. Keep it to one page.
- [ ] Write the root `README.md` per Part 2 below.
- [ ] Generate a real accuracy number per Part 3 below and drop it into the README's performance table.

## Part 2: The README

There is currently no root `README.md` — only `DEPLOYMENT.md`, per-package READMEs in `backend/` and `frontend/`, and the planning docs. Write one root `README.md` that becomes the actual front door to the project. Requirements:

**Structure.** In order: a one-paragraph pitch (what it does, who it's for, local-first by default), a hero screenshot, a short "how it works" section with the architecture diagram below, a features table, a quick-start section (`docker compose up`, or the manual local steps — link to `DEPLOYMENT.md` for the rest rather than duplicating it), a performance/accuracy table (Part 3), and a short "design decisions" paragraph covering the rule-engine-overrides-LLM choice and the prompt-injection defense, since those are the two most interesting engineering decisions in the repo and worth surfacing instead of leaving buried in code comments.

**The picture.** Four mockup screenshots are included alongside this brief in `readme-assets/` (`analyze.png`, `results.png`, `case-history.png`, `accuracy.png`) — copy the one that best represents the tool (`analyze.png` or `results.png` is the natural hero image) into the repo, e.g. `docs/screenshots/`, and reference it near the top of the README. These are UI concept mockups I had drawn up while reviewing the redesign, not screenshots of the live app, and they use made-up sample case data for illustration. Caption the image plainly as a design concept or UI preview, not as a captured result — the honest phrasing matters here since embedding it without that caption would read as a real result that never happened. Swap it for an actual screenshot of the running app the first chance you get; that's always better than a mockup once it exists.

**The table.** Include at least one real content table, not just the performance one. A good candidate: a "what gets checked" table listing each detection signal (SPF/DKIM/DMARC, typosquatting, dangerous attachment extensions and hashes, threat intel via AbuseIPDB/VirusTotal/URLScan, prompt-injection resistance) against a one-line description of what it catches. A tech-stack table (FastAPI, React/Vite, Ollama/Claude, the third-party APIs) is a fine second one if there's room.

**The design/architecture diagram.** Add a Mermaid flowchart of the analysis pipeline (parse → extract indicators → threat intel + attachment hashing in parallel → deterministic rule engine → short-circuit to a verdict when confident, otherwise two LLM calls governed by the shared skill file → save case). GitHub renders Mermaid natively inside a fenced ` ```mermaid ` code block in a README, so no image export is needed for this one. This is the "design for the project" piece — it should make the rule-engine-overrides-LLM structure visually obvious at a glance.

**Writing style — read this section carefully, it's not optional polish.** Write the README the way a person would explain their own project to a colleague, not the way a language model summarizes a project. Concretely:

- Do not use the em dash (—) anywhere in the README. Use a period, a comma, or just start a new sentence instead. This applies to every section, including image captions.
- Do not use these words and phrases, or close variants of them: "leverage," "seamless," "robust" (as a filler adjective), "elevate," "unlock," "game-changer," "dive into," "delve into," "it's worth noting," "it's important to note," "in today's [fast-paced/digital/etc.] world," "moreover," "furthermore," "in conclusion," "at the end of the day," "empower," "cutting-edge," "state-of-the-art" (unless literally citing a benchmark).
- Do not open a section by restating its own heading ("Architecture: this section covers the architecture of the system"). Just say the thing.
- Avoid the rule-of-three list pattern in prose ("fast, reliable, and secure") — if three adjectives feel necessary, that's usually a sign to cut two of them and say something more specific instead.
- Avoid bolding entire phrases for emphasis inside normal paragraphs. Bold is fine for a table header or a genuine warning, not as a way to make ordinary sentences look more important.
- Keep sentences at a normal, slightly varied length. A README written entirely in short punchy sentences, or entirely in long compound ones, both read as artificial. Mix it the way you'd actually talk.
- Write the pitch paragraph like you're telling someone what you built and why, not like ad copy. "This checks whether an email is actually a phishing attempt or a false alarm, using a rule engine for the obvious cases and a local or cloud LLM for the ambiguous ones" beats "ForensicAI is a cutting-edge, AI-powered solution that revolutionizes email security."
- Once the README is drafted, reread it once specifically looking for em dashes and the banned phrases above, and remove any that slipped through.

## Part 3: A real accuracy number, not a made-up one

I checked `backend/feedback/` directly: there is exactly one case with human-reviewed feedback recorded right now. That is nowhere near enough to publish a percentage in a README and have it mean anything, so I'm not handing you a number to paste in. Making one up would be worse than leaving the section out.

Here's how to get a real one quickly, and a script that produces it on demand from then on:

- [ ] Build a small labeled benchmark set: a folder (`backend/tests/benchmark/`, separate from the pytest fixtures so it isn't mixed in with unit-test data) containing 30 to 60 `.eml` files with a `manifest.json` mapping each filename to its ground-truth verdict (`TP` or `FP`). Seed it with the four existing fixtures (`typosquat_phishing.eml` is a TP, `legit_business.eml` is an FP) and add roughly a 50/50 mix of real phishing examples (a public corpus like Nazario's phishing archive is fine for this, or your own spam folder with anything sensitive stripped out) and genuinely clean business email.
- [ ] Write `backend/scripts/run_benchmark.py`: it loads the manifest, runs each email through the real pipeline (call the same functions `main.py`'s `/analyze` route calls, not the HTTP layer, so it can run offline without spinning up the server), compares the returned verdict against ground truth, and prints accuracy, precision, recall, and a confusion matrix. Have it also emit a ready-to-paste Markdown table so the README stays in sync whenever the benchmark is rerun.
- [ ] Run it once with `LLM_PROVIDER=ollama` (the default, local mode) and paste the resulting table into the README's performance section, with a one-line note on how it was generated and a link to the script so anyone can reproduce it.
- [ ] Keep the live `/accuracy` endpoint and the Accuracy dashboard as the "real-world, growing" number, distinct from the benchmark, since it reflects actual analyst-reviewed cases rather than a curated test set, and it will only get more meaningful the more the tool is actually used. It's worth saying that distinction out loud in the README too: one number is a fixed benchmark, the other is a live figure that reflects real feedback over time.

Do not publish any accuracy figure anywhere in the repo that wasn't produced by an actual run of the benchmark script or pulled live from `/accuracy`. If the benchmark script isn't built yet when the README otherwise ships, leave that section as "benchmark in progress" rather than a placeholder number.
