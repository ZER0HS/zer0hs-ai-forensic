# Sandbox workflow, a real "needs human" tier, learning from feedback, and speed

I read the actual current code for every one of these before writing this, not just your description of the problem. Here's what's really happening and what to change.

## 1. The sandbox should not force a full scan just to get an opinion

I checked `SandboxView.jsx` and `main.py` directly. Good news first: a full URLScan sandbox scan is already never triggered automatically during a normal email analysis, it only runs when someone clicks the "Sandbox" button on a specific URL. So your instinct that it shouldn't just barge into a slow scan is already half true in the code today. The real gap is what happens once someone does click it: right now the only button available for a URL is "Sandbox," which immediately submits it to URLScan.io and waits 15 to 45 seconds for a screenshot, and the result you get back is just URLScan's own raw malicious flag and score, not a reasoned FP/TP verdict from the same rule engine and LLM that judges the rest of the email. That's almost certainly part of why you don't fully trust it yet: it looks like the tool ran something heavy and gave you a shallow answer.

What to build instead: two separate actions per URL, not one.

- **Check** (fast, seconds not tens of seconds): runs the URL's domain through the existing threat-intel and rule-engine path, the same machinery `/threat-check` already uses for a single indicator, and returns a proper FP/TP verdict with reasoning right away. No screenshot, no URLScan submission, just "is this worth worrying about" answered quickly.
- **Scan** (slow, opt-in, clearly labeled as such): the existing URLScan submission and screenshot, but the result view should combine the screenshot with the same FP/TP verdict and reasoning from Check, not just URLScan's own malicious flag. If Check already flagged it, Scan is confirmation with visual evidence attached, not a second, disconnected opinion.

This also directly helps trust: right now if URLScan says "clean" but the rule engine would have said "typosquat, high risk," you'd never see that conflict because they're not shown together. Combining them surfaces exactly that kind of disagreement instead of hiding it.

## 2. A real third verdict: needs human review

Right now every case ends as TP or FP, full stop, even when the evidence is genuinely ambiguous, which just pushes an uncertain call to look confident. Add a third state.

Concretely: extend the `Verdict` type in `schemas.py` from `TP`/`FP` to `TP`/`FP`/`NEEDS_REVIEW`. Trigger it in `fp_tp_scorer.py` when any of these are true: the LLM's own confidence lands in a genuinely uncertain band (roughly 40 to 60 percent, the same range the existing confidence-calibration text in the skill file already calls out as "suspicious but under-evidenced"), or the rule engine's hard indicators and the LLM's verdict actively disagree (rule engine leans one way, LLM leans the other, and neither is a hard override), or evidence is simply thin on both sides (one weak signal, nothing corroborating it either direction).

A `NEEDS_REVIEW` case should come with more detail than a normal verdict, not less: which specific signals pointed toward TP, which pointed toward FP, exactly why neither side won convincingly, and what a human would need to check to settle it (a specific header, a specific IP, whether the recipient actually clicked anything). This is the "full report why need human" you asked for. Log these cases distinctly too (a simple `needs_review: true` flag alongside the existing saved case data in `feedback.py` is enough) so they can be pulled up as a queue rather than mixed in with everything else.

On the frontend, this needs its own visual treatment, not a shade of the existing TP/FP colors. A distinct badge (amber, "Needs Review," separate from the existing critical/high/medium/low/clean severity colors) in `SeverityBadge`/`severity.js`, and ideally its own filter in Case History so those cases are easy to find and clear out.

## 3. Making the tool learn from what gets corrected

I want to be straight with you about what's realistic here before describing what to build, because "train itself" can mean very different things. This system is a rule engine plus an LLM call, not a model you're training from scratch, so it can't retrain its own weights and get smarter in the way a neural network does. What it can genuinely do, and what's worth building:

**A persistent memory of confirmed indicators.** Right now `threat_intel.py` caches API results for 10 minutes, purely to avoid hammering AbuseIPDB and VirusTotal on the same request. That's not memory, it's just a speed optimization that expires almost immediately. Add a real, permanent store (a small local database or even a JSON file is fine at this scale) that remembers every indicator a human has explicitly confirmed as TP or FP through the feedback endpoint. Next time that exact domain, IP, or hash shows up in a new email, whether it's a minute later or a month later, the pipeline checks this store first and can return an instant, confident verdict without a fresh LLM call or even a fresh API call. This is the honest version of "gets better and faster over time": it's not the model learning, it's the system remembering what a person already told it, and that compounds naturally since the same phishing infrastructure gets reused across campaigns.

**Human-approved rule suggestions, not silent self-editing.** Periodically (a script you run on demand is enough to start, it doesn't need to be automatic) scan the confirmed feedback for patterns that keep showing up in confirmed TPs but aren't in the hardcoded lists yet, a phrase that appears in five confirmed phishing cases but isn't in `PHISHING_KEYWORDS`, or a brand name being typosquatted that isn't in `TYPOSQUAT_BRANDS`. Surface these as suggestions for you to approve, rather than having the rule engine quietly rewrite its own rules with no oversight. A system that edits its own detection logic unsupervised is a genuinely bad idea for a security tool, since a single bad piece of feedback (a human accidentally marking something wrong) could poison it silently. Keeping a person in the loop for rule changes, while automating the boring "remember this domain is bad" part, is the right split.

## 4. Where the 1 to 2 minutes is actually going, and how to cut it

I checked this directly rather than guessing. For any email that isn't confidently resolved by the rule engine alone (the short-circuit path, which is already fast), the pipeline makes two full sequential LLM calls, `run_analysis` then `score_case`, each requesting up to 2000 tokens of output, one strictly after the other since `score_case` needs the first call's result as input. On a local 14-billion-parameter model like qwen2.5:14b, each of those calls can easily take 30 to 90 seconds depending on your hardware, especially without a capable GPU. Two of them back to back lands exactly in the 1 to 2 minute range you're seeing. There's also a re-prompt built in (`ask_llm_json` retries once if the model's JSON doesn't validate), so an occasional case can take even longer if the first response comes back malformed.

Three real fixes, roughly in order of impact:

- **Merge the two calls into one.** Combine the forensic write-up and the TP/FP verdict into a single prompt and a single schema, so the ambiguous-case path pays for one LLM round-trip instead of two. This is the single biggest lever here, it should roughly halve the time for every case that isn't already short-circuited.
- **Check whether Ollama is actually using your GPU.** Run `ollama ps` while a request is in flight, or check `nvidia-smi` (or the equivalent for your GPU) during a run. If it's falling back to CPU, that alone explains most of the slowness, and qwen2.5:14b is a genuinely large model to run without acceleration.
- **Offer a smaller model as a speed option.** Add a second `OLLAMA_MODEL` example in `.env.example` for something like `qwen2.5:7b` or a quantized variant, documented as a "faster, slightly less thorough" alternative. This is a real accuracy-for-speed tradeoff, so it should be an explicit choice you make, not a silent default swap, but it's worth having available for a machine that's struggling with the 14b model.

Combined with the permanent indicator memory from Part 3, the common case of "we've seen this exact phishing domain before" should end up near-instant, and the genuinely new, ambiguous case should drop from two LLM calls to one.

## What to send Claude Code

Paste this along with the file itself:

> Read this whole file (`TRUST_REVIEW_SPEED_BRIEF.md`) before starting. Four changes, please commit after each one separately:
>
> 1. Split the Sandbox UI and backend into a fast "Check" action (reuses the existing threat-intel plus rule-engine path, returns a real FP/TP verdict in seconds) and a separate, clearly-labeled "Scan" action (the existing URLScan submission), and when Scan completes, show its screenshot alongside the same FP/TP verdict and reasoning from Check rather than URLScan's raw malicious flag alone.
> 2. Add a `NEEDS_REVIEW` verdict alongside `TP`/`FP` in `schemas.py`, trigger it in `fp_tp_scorer.py` on genuinely ambiguous confidence (roughly 40 to 60 percent) or rule-engine/LLM disagreement with no hard override, include a full explanation of what's conflicting and what a human should check, flag these cases distinctly in saved feedback data, and give them their own badge color and Case History filter on the frontend.
> 3. Add a persistent store of human-confirmed indicators (separate from the existing 10-minute threat-intel cache, this one doesn't expire) that the pipeline checks before calling threat intel or the LLM at all, plus a standalone script that scans confirmed feedback for repeated patterns not yet in `PHISHING_KEYWORDS`/`TYPOSQUAT_BRANDS` and prints them as suggestions for a human to review and add manually. Do not have the rule engine edit its own lists automatically.
> 4. Merge `run_analysis` and `score_case` into a single LLM call and schema for the non-short-circuited path, and add a second, smaller `OLLAMA_MODEL` example in `.env.example` documented as a faster but less thorough option.
