# Changelog

A short history of how this project got here. It used to be six
overlapping planning documents sitting in `docs/planning/`, each written
at a different review pass and increasingly redundant with the ones
before it. Anything in them that's still true now lives in `README.md`
and `THREAT_MODEL.md`; this file keeps two or three lines per pass
instead of the full documents, since that's more useful to a reader than
the original working instructions ever were once the work is done.

- **Initial review.** Baseline audit of the original prototype: no git
  history, an empty `requirements.txt`, no tests, wide-open CORS, no
  auth or rate limiting, and an attachment-hash check that was written
  but never called. Set the direction that held for every pass after
  it: keep the rule-engine-overrides-LLM architecture, harden
  everything around it.
- **Full fix and redesign plan.** Found and fixed a real XSS (LLM-
  generated HTML rendered with `dangerouslySetInnerHTML`), replaced ad
  hoc JSON parsing with Pydantic schema validation, added the prompt-
  injection defense, and specified the frontend redesign: a persistent
  sidebar, shared `Card`/`Badge`/`TabBar` components, a Case History
  page, and an Accuracy dashboard.
- **Project status check.** Confirmed the hardening pass had landed,
  flagged that a batch of rule-engine bug fixes was still sitting
  uncommitted, and called for a root README, a LICENSE, Arabic and
  homoglyph coverage, and a one-page threat model.
- **Consolidated brief.** Folded all of the above into one actionable
  list, specified the README's structure and writing style, and called
  for a real, reproducible accuracy benchmark instead of a number
  someone made up.
- **Trust, review, and speed pass.** Split the URL Sandbox into a fast
  Check and a slower Scan, added the `NEEDS_REVIEW` verdict tier, added
  the confirmed-indicators memory and `scripts/suggest_rules.py`, and
  merged the two sequential LLM calls into one.
- **Rename and cleanup pass.** Renamed the project to ZER0HS and its
  folder to `zer0hs_ai_forensic/`, fixed a URL-extraction bug (trailing
  punctuation and prose brackets ending up inside extracted URLs) and a
  bug where a short-circuited true-positive verdict always reported
  empty IOCs and MITRE techniques, replaced the placeholder logo, and
  removed the individual planning documents in favor of this file.

Nothing below this line describes an open task. If you're looking for
what the project defends against and why it's built the way it is, that
lives in `THREAT_MODEL.md`; if you're looking for what it does and how
to run it, that's `README.md`.
