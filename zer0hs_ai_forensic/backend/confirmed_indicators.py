"""
A permanent memory of indicators a human has explicitly confirmed as TP
or FP, distinct from threat_intel.py's 10-minute API cache. That cache is
purely a speed optimization that expires almost immediately; this never
expires, because it isn't caching an API response, it's remembering what
a person already told the system. This is the honest version of "gets
better over time" for a system that's a rule engine plus an LLM call
rather than a model being retrained: it's not learning in the neural-net
sense, it's remembering, and that compounds naturally since the same
phishing infrastructure tends to get reused across campaigns.

Populated by feedback.save_feedback() every time an analyst confirms or
corrects a verdict. Checked by main.py's /analyze before threat intel or
the LLM are called at all — a confirmed hit lets the pipeline skip both.

Simplification worth being explicit about: a confirmed verdict is
attributed to every public indicator in the case that produced it, not
verified indicator-by-indicator. If a case had three IPs and was
confirmed TP, all three get remembered as TP even though only one might
actually have been the malicious one. This trades some precision for
being simple enough to actually ship; a future version could ask the
analyst which specific indicator was responsible.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

STORE_FILE = Path("confirmed_indicators.json")


def _load() -> dict:
    if not STORE_FILE.exists():
        return {}
    try:
        return json.loads(STORE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save(data: dict) -> None:
    STORE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def remember(indicator: str, verdict: str, case_id: str, indicator_type: str = "unknown") -> None:
    """Persist a human-confirmed verdict for a specific indicator.
    Overwrites any prior confirmation for the same indicator — the most
    recent human judgment wins, since infrastructure can change hands."""
    if verdict not in ("TP", "FP"):
        return  # NEEDS_REVIEW or anything else isn't a confirmed verdict
    data = _load()
    data[indicator.lower()] = {
        "verdict": verdict,
        "type": indicator_type,
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
    }
    _save(data)


def lookup(indicator: str) -> Optional[dict]:
    return _load().get(indicator.lower())


def all_confirmed() -> dict:
    return _load()


def get_hits(indicators: dict) -> list:
    """Look up every public IP/domain in an extracted-indicators dict at
    once. Returns a list of {indicator, type, verdict, confirmed_at,
    case_id} for anything found — empty if nothing matches, which is the
    common case."""
    hits = []
    for ip in indicators.get("ips", []):
        entry = lookup(ip)
        if entry:
            hits.append({"indicator": ip, **entry})
    for domain in indicators.get("domains", []):
        entry = lookup(domain)
        if entry:
            hits.append({"indicator": domain, **entry})
    return hits
