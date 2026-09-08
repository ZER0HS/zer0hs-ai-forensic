"""
confirmed_indicators.py: the permanent memory of human-confirmed
verdicts, distinct from threat_intel.py's 10-minute API cache. Covers the
store itself, feedback.save_feedback() populating it, and main.py's
/analyze skipping a fresh threat-intel lookup on a confirmed hit.
"""
import json

import httpx
import pytest

import confirmed_indicators
import feedback


def test_remember_and_lookup_round_trip():
    confirmed_indicators.remember("1.2.3.4", "TP", "CASE-1", "ip")
    entry = confirmed_indicators.lookup("1.2.3.4")
    assert entry["verdict"] == "TP"
    assert entry["type"] == "ip"
    assert entry["case_id"] == "CASE-1"


def test_lookup_is_case_insensitive_for_domains():
    confirmed_indicators.remember("Evil-Domain.COM", "TP", "CASE-1", "domain")
    assert confirmed_indicators.lookup("evil-domain.com") is not None


def test_needs_review_is_never_remembered():
    """NEEDS_REVIEW isn't a confirmed verdict — nothing was actually
    settled, so nothing should be written to permanent memory."""
    confirmed_indicators.remember("9.9.9.9", "NEEDS_REVIEW", "CASE-1", "ip")
    assert confirmed_indicators.lookup("9.9.9.9") is None


def test_get_hits_matches_ips_and_domains():
    confirmed_indicators.remember("1.2.3.4", "TP", "CASE-1", "ip")
    confirmed_indicators.remember("evil.com", "FP", "CASE-2", "domain")

    hits = confirmed_indicators.get_hits({"ips": ["1.2.3.4", "8.8.8.8"], "domains": ["evil.com", "clean.com"]})

    values = {h["indicator"] for h in hits}
    assert values == {"1.2.3.4", "evil.com"}


def test_save_feedback_remembers_every_public_indicator_in_the_case():
    case_id = feedback.save_analysis({
        "case_verdict": {"verdict": "TP", "confidence": 90, "risk_level": "high"},
        "indicators": {"ips": ["1.2.3.4"], "domains": ["evil.com"], "private_ips": ["10.0.0.5"]},
    })
    feedback.save_feedback(case_id, human_verdict="TP", is_correct=True)

    assert confirmed_indicators.lookup("1.2.3.4")["verdict"] == "TP"
    assert confirmed_indicators.lookup("evil.com")["verdict"] == "TP"


def test_save_feedback_records_the_human_correction_not_the_original_verdict():
    """If a human overrides the original TP verdict to FP, the
    *correction* is what gets remembered, not the model's original call."""
    case_id = feedback.save_analysis({
        "case_verdict": {"verdict": "TP", "confidence": 60, "risk_level": "medium"},
        "indicators": {"ips": ["5.5.5.5"], "domains": []},
    })
    feedback.save_feedback(case_id, human_verdict="FP", is_correct=False)

    assert confirmed_indicators.lookup("5.5.5.5")["verdict"] == "FP"


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_analyze_skips_live_lookup_for_a_confirmed_indicator(client, respx_mock, monkeypatch):
    """A confirmed-TP domain must short-circuit the analysis without a
    fresh VirusTotal call or an LLM call — that's the whole point."""
    confirmed_indicators.remember("known-bad-vendor.com", "TP", "CASE-OLD", "domain")

    # No VirusTotal or Ollama route is registered — if either gets called,
    # respx's default assert_all_mocked raises and this test fails loudly.
    r = client.post("/analyze", data={"text": "Please review the invoice at http://known-bad-vendor.com/pay"})

    assert r.status_code == 200
    data = r.json()
    assert data["case_verdict"]["verdict"] == "TP"
    confirmed_result = next(t for t in data["threat_results"] if t["value"] == "known-bad-vendor.com")
    assert "confirmed by human feedback" in confirmed_result["source"]
