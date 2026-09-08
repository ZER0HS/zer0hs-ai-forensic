"""
fp_tp_scorer.py tests focused on the parts that don't already have
coverage via test_analyze_integration.py's end-to-end cases: score_single's
typosquat override (used by the Sandbox "Check" action), and the
NEEDS_REVIEW verdict logic in score_case.
"""
import json

import httpx
import pytest

from fp_tp_scorer import score_case, score_single


def _ollama_response(payload: dict) -> httpx.Response:
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


# ── NEEDS_REVIEW ─────────────────────────────────────────────────────────

def _case_verdict_payload(verdict, confidence):
    return {
        "verdict": verdict, "confidence": confidence, "risk_level": "medium",
        "case_summary": "ambiguous", "reasoning": "uncertain",
        "fp_tp_factors": {"factors_for_tp": [], "factors_for_fp": [], "deciding_factor": ""},
        "recommended_actions": [], "mitre_techniques": [], "iocs": [],
        "threat_actor_profile": None,
        "severity_breakdown": {"indicator_risk": 0, "behavioral_risk": 0, "contextual_risk": 0},
    }


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_uncertain_confidence_band_triggers_needs_review(respx_mock):
    """50% confidence, but with at least one real signal so the "zero
    evidence anywhere" auto-correct doesn't fire first and mask it."""
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(_case_verdict_payload("TP", 50)))

    result = await score_case(
        evidence_text="some ambiguous email",
        indicators={"ips": ["9.9.9.9"], "domains": []},
        threat_results=[{"type": "ip", "value": "9.9.9.9", "abuse_score": 30}],
        forensic_analysis={"summary": "x", "key_findings": [], "anomalies": []},
        rule_findings={"hard_tp_indicators": [], "hard_fp_indicators": []},
        patterns={"matched_attack_patterns": []},
    )

    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["review_reason"]
    assert "50" in result["review_reason"]


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_rule_engine_and_llm_disagreement_triggers_needs_review(respx_mock):
    """LLM says FP with high confidence, but the rule engine found a hard
    TP indicator — that conflict must surface, not get silently resolved
    in the LLM's favor."""
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(_case_verdict_payload("FP", 85)))

    result = await score_case(
        evidence_text="looks clean to the model",
        indicators={"ips": [], "domains": ["paypa1.com"]},
        threat_results=[],
        forensic_analysis={"summary": "x", "key_findings": [], "anomalies": []},
        rule_findings={
            "hard_tp_indicators": ["Typosquatting detected: 'paypa1.com' impersonates 'paypal'"],
            "hard_fp_indicators": [],
        },
        patterns={"matched_attack_patterns": []},
    )

    assert result["verdict"] == "NEEDS_REVIEW"
    assert "paypa1" in result["review_reason"] or "rule engine" in result["review_reason"].lower()


@pytest.mark.respx(base_url="http://localhost:11434")
async def test_confident_clear_cut_case_does_not_trigger_needs_review(respx_mock):
    """A confident, well-corroborated verdict must stay TP/FP — this
    isn't a general "sometimes flag things" feature, it should only fire
    on genuine ambiguity."""
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(_case_verdict_payload("TP", 92)))

    result = await score_case(
        evidence_text="obvious phishing",
        indicators={"ips": ["1.2.3.4"], "domains": ["paypa1.com"]},
        threat_results=[{"type": "ip", "value": "1.2.3.4", "abuse_score": 90}],
        forensic_analysis={"summary": "x", "key_findings": [], "anomalies": [{"severity": "high", "title": "x", "description": "y"}]},
        rule_findings={
            "hard_tp_indicators": ["Typosquatting detected: 'paypa1.com' impersonates 'paypal'"],
            "hard_fp_indicators": [],
        },
        patterns={"matched_attack_patterns": []},
    )

    assert result["verdict"] == "TP"
