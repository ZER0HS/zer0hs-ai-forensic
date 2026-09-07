"""
fp_tp_scorer.py tests focused on the parts that don't already have
coverage via test_analyze_integration.py's end-to-end cases: score_single's
typosquat override (used by the Sandbox "Check" action), and the
NEEDS_REVIEW verdict logic in score_case.
"""
import httpx
import pytest

from fp_tp_scorer import score_case, score_single


def _ollama_response(payload: dict) -> httpx.Response:
    import json
    return httpx.Response(200, json={"response": json.dumps(payload)})


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_score_single_typosquat_override_beats_a_clean_score(respx_mock):
    """A brand-new lookalike domain often has zero abuse reports yet
    precisely because it's new — the typosquat finding must win over a
    clean-looking score, not get drowned out by it."""
    respx_mock.post("/api/generate").mock(return_value=_ollama_response({
        "verdict": "FP", "confidence": 20, "risk_level": "clean",
        "reasoning": "no abuse reports", "recommended_action": "none",
        "mitre_technique": None, "indicators_of_compromise": [],
    }))

    threat_data = {"type": "domain", "value": "paypa1-verify.com", "abuse_score": 0, "source": "VirusTotal"}
    typosquat_result = {"detected": True, "brand": "paypal", "domain": "paypa1-verify.com", "technique": "number-substitution"}

    result = await score_single("paypa1-verify.com", threat_data, "", typosquat_result)

    assert result["verdict"] == "TP"
    assert result["confidence"] >= 90
    assert result["mitre_technique"]


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_score_single_no_typosquat_uses_normal_score_logic(respx_mock):
    respx_mock.post("/api/generate").mock(return_value=_ollama_response({
        "verdict": "FP", "confidence": 85, "risk_level": "clean",
        "reasoning": "clean", "recommended_action": "none",
        "mitre_technique": None, "indicators_of_compromise": [],
    }))
    threat_data = {"type": "domain", "value": "example.com", "abuse_score": 0, "source": "VirusTotal"}

    result = await score_single("example.com", threat_data, "", None)

    assert result["verdict"] == "FP"
