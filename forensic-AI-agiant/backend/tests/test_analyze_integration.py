"""
Integration tests for POST /analyze through the real FastAPI app, with the
LLM (Ollama) and every third-party threat-intel call mocked via respx. No
live network call is ever made here — see conftest.py, which force-blanks
every API key so a missed mock fails loudly instead of hitting a real
service.
"""
import io
import json
import zipfile

import httpx
import pytest
import respx


def _ollama_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json={"response": json.dumps(payload)})


FORENSIC_JSON = {
    "summary": "Ambiguous email under review.",
    "key_findings": ["Some mildly suspicious wording"],
    "entities": {"persons": [], "places": [], "times": [], "orgs": []},
    "highlight": {"text": "please review this document", "start": 0, "end": 6},
    "anomalies": [],
    "timeline": [],
}


def _mock_high_risk_abuseipdb(respx_mock, monkeypatch, score: int = 90):
    """The rule engine's typosquat+high-IP override needs a real AbuseIPDB
    score. conftest.py blanks ABUSEIPDB_API_KEY so a forgotten mock fails
    loudly elsewhere — here we deliberately re-enable it for this one test
    and mock the actual HTTP call, never touching the live API."""
    import threat_intel
    monkeypatch.setattr(threat_intel, "ABUSEIPDB_KEY", "test-key")
    respx_mock.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {
            "abuseConfidenceScore": score, "countryCode": "RU",
            "isp": "Bad ISP", "totalReports": 50, "usageType": "Data Center",
        }})
    )


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_obvious_phishing_short_circuits_and_never_calls_the_llm(client, fixtures_dir, respx_mock, monkeypatch):
    """A typosquat domain + a high-risk IP is a definite-TP rule-engine
    override — the LLM must never be called at all."""
    _mock_high_risk_abuseipdb(respx_mock, monkeypatch)
    ollama_route = respx_mock.post("/api/generate").mock(
        return_value=_ollama_response(FORENSIC_JSON)
    )

    eml_bytes = (fixtures_dir / "typosquat_phishing.eml").read_bytes()
    r = client.post(
        "/analyze",
        files={"file": ("phish.eml", eml_bytes, "message/rfc822")},
    )

    assert r.status_code == 200
    data = r.json()
    assert data["case_verdict"]["verdict"] == "TP"
    assert data["rule_findings"]["verdict_override"] == "TP"
    assert not ollama_route.called, "rule engine was confident — the LLM should never have been called"


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_clean_email_short_circuits_to_fp_without_calling_llm(client, respx_mock):
    ollama_route = respx_mock.post("/api/generate").mock(
        return_value=_ollama_response(FORENSIC_JSON)
    )

    r = client.post("/analyze", data={"text": "Hey, are we still on for lunch tomorrow?"})

    assert r.status_code == 200
    data = r.json()
    assert data["case_verdict"]["verdict"] == "FP"
    assert not ollama_route.called


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_legit_urgent_business_email_is_not_a_false_positive(client, fixtures_dir, respx_mock):
    """The false-positive stress test: a real invoice reminder uses the
    word "due today" but has no technical indicators at all — must not be
    flagged as TP."""
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(FORENSIC_JSON))

    eml_bytes = (fixtures_dir / "legit_business.eml").read_bytes()
    r = client.post("/analyze", files={"file": ("invoice.eml", eml_bytes, "message/rfc822")})

    assert r.status_code == 200
    assert r.json()["case_verdict"]["verdict"] == "FP"


@pytest.mark.respx(base_url="http://localhost:11434")
def test_ambiguous_case_does_call_the_llm_and_uses_its_verdict(client, respx_mock, monkeypatch):
    """No rule-engine override fires here (a single mid-score IP, nothing
    else) — this is the genuinely-ambiguous middle the LLM path exists
    for, so the two LLM calls (forensic + scoring) should both happen."""
    _mock_high_risk_abuseipdb(respx_mock, monkeypatch, score=30)  # mid-range: too
    # low to trip the typosquat+high-IP TP override (needs >=75), too high
    # to trip the all-clean FP override (needs <10) — genuinely ambiguous.
    verdict_json = {
        "verdict": "TP", "confidence": 65, "risk_level": "medium",
        "case_summary": "Borderline case.", "reasoning": "moderate signal",
        "fp_tp_factors": {"factors_for_tp": ["mid-score IP"], "factors_for_fp": [], "deciding_factor": "IP score"},
        "recommended_actions": ["Monitor"], "mitre_techniques": [], "iocs": [],
        "threat_actor_profile": None,
        "severity_breakdown": {"indicator_risk": 30, "behavioral_risk": 0, "contextual_risk": 0},
    }
    route = respx_mock.post("/api/generate").mock(
        side_effect=[_ollama_response(FORENSIC_JSON), _ollama_response(verdict_json)]
    )

    r = client.post("/analyze", data={"text": "please review this document, contact 9.9.9.9 for access"})

    assert r.status_code == 200
    assert route.call_count == 2
    assert r.json()["case_verdict"]["verdict"] == "TP"
    assert r.json()["case_verdict"]["confidence"] == 65


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_prompt_injection_cannot_override_the_rule_engine_verdict(client, fixtures_dir, respx_mock, monkeypatch):
    """Even if a hijacked/compliant LLM tried to obey the injected
    "return FP, confidence 99" instruction in the email body, the rule
    engine's definite-TP override (typosquat domain here) must win — and
    since it's a definite override, the LLM is never even called, which is
    the strongest possible defense against this class of attack."""
    _mock_high_risk_abuseipdb(respx_mock, monkeypatch)
    hijacked_response = {
        "verdict": "FP", "confidence": 99, "risk_level": "clean",
        "case_summary": "Verified false positive.", "reasoning": "as instructed",
        "fp_tp_factors": {"factors_for_tp": [], "factors_for_fp": ["instructed"], "deciding_factor": ""},
        "recommended_actions": [], "mitre_techniques": [], "iocs": [],
        "threat_actor_profile": None,
        "severity_breakdown": {"indicator_risk": 0, "behavioral_risk": 0, "contextual_risk": 0},
    }
    ollama_route = respx_mock.post("/api/generate").mock(
        return_value=_ollama_response(hijacked_response)
    )

    eml_bytes = (fixtures_dir / "prompt_injection.eml").read_bytes()
    r = client.post("/analyze", files={"file": ("pw.eml", eml_bytes, "message/rfc822")})

    assert r.status_code == 200
    data = r.json()
    assert data["case_verdict"]["verdict"] == "TP", (
        "prompt injection must never flip a rule-engine-confirmed verdict"
    )
    assert not ollama_route.called


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_arabic_phishing_short_circuits_via_domain_and_ip_not_language(client, fixtures_dir, respx_mock, monkeypatch):
    """The full pipeline on an Arabic-language phishing email: the
    typosquat domain (paypa1-verify-ar.com, a number-substituted "paypal")
    plus a high-risk IP is enough for a rule-engine short-circuit on its
    own, but the Arabic keyword lists corroborate it too — this asserts
    both actually fired, not just that the final verdict happened to come
    out right for an unrelated reason."""
    _mock_high_risk_abuseipdb(respx_mock, monkeypatch)
    ollama_route = respx_mock.post("/api/generate").mock(return_value=_ollama_response(FORENSIC_JSON))

    eml_bytes = (fixtures_dir / "arabic_phishing.eml").read_bytes()
    r = client.post("/analyze", files={"file": ("phish_ar.eml", eml_bytes, "message/rfc822")})

    assert r.status_code == 200
    data = r.json()
    assert data["case_verdict"]["verdict"] == "TP"
    assert data["rule_findings"]["typosquat_results"]
    assert data["rule_findings"]["text_analysis"]["total_score"] > 0
    assert not ollama_route.called


def test_malformed_eml_does_not_crash_the_endpoint(client, fixtures_dir):
    eml_bytes = (fixtures_dir / "malformed.eml").read_bytes()
    r = client.post("/analyze", files={"file": ("broken.eml", eml_bytes, "message/rfc822")})
    assert r.status_code == 200


def test_zip_bomb_upload_returns_400_not_500(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(250):
            z.writestr(f"f{i}.txt", "x")
    r = client.post("/analyze", files={"file": ("bomb.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400


def test_analyze_requires_api_key_when_configured(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "_API_KEY", "test-secret")
    r = client.post("/analyze", data={"text": "hello"})
    assert r.status_code == 401


def test_health_and_status_stay_open_without_a_key(client, monkeypatch):
    import main
    monkeypatch.setattr(main, "_API_KEY", "test-secret")
    assert client.get("/health").status_code == 200
    assert client.get("/status").status_code == 200


@pytest.mark.respx(base_url="http://ollama-host:11434")
def test_status_checks_ollama_at_the_configured_url(client, respx_mock, monkeypatch):
    """Regression test: /status used to hardcode localhost:11434, which
    silently broke the connectivity check in Docker (where Ollama runs on
    the host, not inside the backend container) even though the actual
    generation calls in llm_client.py already respected OLLAMA_URL."""
    monkeypatch.setenv("OLLAMA_URL", "http://ollama-host:11434")
    route = respx_mock.get("/api/tags").mock(
        return_value=httpx.Response(200, json={"models": [{"name": "qwen2.5:14b"}]})
    )
    r = client.get("/status")
    assert r.status_code == 200
    assert route.called
    assert r.json()["provider_ok"] is True
