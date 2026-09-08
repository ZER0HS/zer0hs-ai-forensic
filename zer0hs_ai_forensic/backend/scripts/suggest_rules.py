"""
Scans confirmed feedback for patterns that keep showing up in confirmed
phishing cases but aren't reflected in the hardcoded rule lists yet, and
prints them as suggestions for a human to review. This never edits
rule_engine.py itself — a system that quietly rewrites its own detection
logic is a bad idea for a security tool, since a single bad piece of
feedback (an analyst misclicking "correct") could poison it silently.
Approving a suggestion means opening rule_engine.py and adding the line
yourself.

Two things this can and can't do, and why:

1. Typosquat brand suggestions (fully possible): a confirmed-TP case's
   `indicators.domains` are plain domain strings — not sensitive, not
   raw evidence text — so this compares each one against
   TYPOSQUAT_BRANDS and flags any that check_typosquatting() doesn't
   currently recognize, so you can decide whether it represents a brand
   worth adding.

2. New phishing-keyword phrase suggestions (deliberately limited): the
   review that led to this project explicitly established that raw
   evidence text is never saved to disk (see feedback.save_analysis()),
   by design, for privacy. That means there is no stored text to mine
   new phrases out of after the fact — a genuinely new phrase, by
   definition, never matched anything and so was never recorded anywhere.
   What this script does instead is flag confirmed-TP cases where the
   existing keyword list found *nothing at all* despite the case being
   confirmed phishing — a concrete signal that something in that
   specific, still-in-your-inbox email is worth going back and looking
   at manually, without this script ever needing to store or read the
   email content itself.

Usage:
    cd backend
    python scripts/suggest_rules.py
"""
import json
from collections import Counter
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rule_engine import TYPOSQUAT_BRANDS, check_typosquatting

FEEDBACK_DIR = Path(__file__).resolve().parents[1] / "feedback"


def load_confirmed_tp_cases() -> list:
    cases = []
    for path in FEEDBACK_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if data.get("human_verdict") == "TP":
            cases.append(data)
    return cases


def suggest_typosquat_brands(cases: list) -> None:
    print("=" * 70)
    print("Typosquat brand candidates")
    print("=" * 70)

    unrecognized = Counter()
    for case in cases:
        for domain in case.get("indicators", {}).get("domains", []):
            if not check_typosquatting(domain)["detected"]:
                unrecognized[domain] += 1

    if not unrecognized:
        print("Nothing to suggest — every domain seen in a confirmed TP "
              "case is already recognized by check_typosquatting().")
        return

    print("These domains appeared in a confirmed-TP case but aren't "
          "caught by any brand in TYPOSQUAT_BRANDS. A domain showing up "
          "here isn't automatically a typosquat (it could just be the "
          "attacker's own unbranded infrastructure) — review each one "
          "and decide whether it's impersonating a brand worth adding.\n")
    for domain, count in unrecognized.most_common():
        print(f"  {domain}  (seen in {count} confirmed TP case{'s' if count != 1 else ''})")

    print(f"\nCurrently recognized brands: {', '.join(TYPOSQUAT_BRANDS)}")


def suggest_keyword_review(cases: list) -> None:
    print("\n" + "=" * 70)
    print("Confirmed phishing cases the keyword list found nothing in")
    print("=" * 70)

    missed = [c for c in cases if not c.get("phishing_keywords_matched")]

    if not missed:
        print("None — every confirmed-TP case matched at least one "
              "existing phishing keyword.")
        return

    print("Raw evidence text is never stored (by design — see this "
          "script's docstring), so this can't extract a candidate phrase "
          "for you automatically. What it CAN tell you is which specific "
          "confirmed-phishing cases scored zero on the keyword list "
          "entirely — worth pulling up your own copy of these emails and "
          "seeing what phrasing tipped you off that the keyword list "
          "missed.\n")
    for case in missed:
        print(f"  {case['case_id']}  (rule score: {case.get('rule_score', 0)}/100, "
              f"reviewed {case.get('reviewed_at', '?')})")


if __name__ == "__main__":
    confirmed = load_confirmed_tp_cases()
    print(f"Found {len(confirmed)} confirmed-TP case(s) in {FEEDBACK_DIR}\n")
    if not confirmed:
        print("Nothing to suggest yet — mark some verdicts as correct/incorrect "
              "from the Analyze tab first.")
    else:
        suggest_typosquat_brands(confirmed)
        suggest_keyword_review(confirmed)
