"""
combined_analysis.py: the merged single-call replacement for
agent.run_analysis() + fp_tp_scorer.score_case(). Covers the highlight
verification (same defense-in-depth as the old agent.py path) and the
eml_data/auth_block wiring — the old score_case() read
forensic_analysis.get("eml_headers"), which was never actually populated
by anything calling it, so the auth block was silently always empty; the
merged function takes eml_data directly instead.
"""
import json

import httpx
import pytest

from combined_analysis import run_combined_analysis


def _ollama_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json={"response": json.dumps(payload)})


VALID_COMBINED = {
    "forensic": {
        "summary": "Test.", "key_findings": [],
        "entities": {"persons": [], "places": [], "times": [], "orgs": []},
        "highlight": {"text": "verify your account now", "start": 0, "end": 6},
        "anomalies": [], "timeline": [],
    },
    "verdict": {
        "verdict": "TP", "confidence": 90, "risk_level": "high",
        "case_summary": "x", "reasoning": "x",
        "fp_tp_factors": {"factors_for_tp": [], "factors_for_fp": [], "deciding_factor": ""},
        "recommended_actions": [], "mitre_techniques": [], "iocs": [],
        "threat_actor_profile": None,
        "severity_breakdown": {"indicator_risk": 0, "behavioral_risk": 0, "contextual_risk": 0},
    },
}


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_single_call_returns_both_forensic_and_verdict(respx_mock):
    route = respx_mock.post("/api/generate").mock(return_value=_ollama_response(VALID_COMBINED))

    # A real hard_tp_indicator so the "zero evidence anywhere" auto-correct
    # (finalize_case_verdict, shared with score_case) doesn't flip this
    # TP claim to FP — that behavior has its own dedicated test below.
    result = await run_combined_analysis(
        text="verify your account now at http://evil.com",
        indicators={"ips": [], "domains": ["evil.com"]},
        threat_results=[],
        rule_findings={"hard_tp_indicators": ["Typosquatting detected: 'evil.com'"], "hard_fp_indicators": []},
        patterns={"matched_attack_patterns": []},
    )

    assert route.call_count == 1
    assert "forensic" in result and "verdict" in result
    assert result["verdict"]["verdict"] == "TP"
    assert result["forensic"]["highlight"]["text"] == "verify your account now"


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_hallucinated_highlight_falls_back_to_a_literal_slice(respx_mock):
    payload = json.loads(json.dumps(VALID_COMBINED))
    payload["forensic"]["highlight"] = {"text": "this text does not appear anywhere in the evidence", "start": 0, "end": 5}
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(payload))

    text = "the real evidence text starts right here and nothing else"
    result = await run_combined_analysis(
        text=text, indicators={"ips": [], "domains": []}, threat_results=[],
        rule_findings={}, patterns={},
    )

    assert result["forensic"]["highlight"]["text"] == text[:300]


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_eml_auth_results_reach_the_prompt(respx_mock):
    """Regression test: the old score_case() read
    forensic_analysis.get("eml_headers"), a key nothing ever actually set
    before calling it, so the EMAIL AUTHENTICATION block was always
    empty. The merged function takes eml_data directly."""
    captured = {}

    def capture(request):
        captured["body"] = request.content.decode("utf-8")
        return _ollama_response(VALID_COMBINED)

    respx_mock.post("/api/generate").mock(side_effect=capture)

    await run_combined_analysis(
        text="some evidence", indicators={"ips": [], "domains": []}, threat_results=[],
        rule_findings={}, patterns={},
        eml_data={"auth_results": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}, "anomalies": []},
    )

    assert "spf" in captured["body"].lower()
    assert "fail" in captured["body"]


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_rule_engine_verdict_override_wins_even_in_merged_call(respx_mock):
    """finalize_case_verdict() is shared with score_case() — this locks
    in that the merged path still enforces "rule engine wins" the same
    way, not a separate, potentially-drifted copy of that logic."""
    payload = json.loads(json.dumps(VALID_COMBINED))
    payload["verdict"]["verdict"] = "TP"
    payload["verdict"]["confidence"] = 40
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(payload))

    result = await run_combined_analysis(
        text="ambiguous", indicators={"ips": [], "domains": []}, threat_results=[],
        rule_findings={"hard_tp_indicators": [], "hard_fp_indicators": []}, patterns={},
    )

    # No corroborating evidence anywhere + confidence 40 -> NEEDS_REVIEW
    # band handling in finalize_case_verdict, same as the two-call path.
    assert result["verdict"]["verdict"] in ("FP", "NEEDS_REVIEW")
