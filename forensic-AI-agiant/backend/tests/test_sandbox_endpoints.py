"""
/sandbox/check and /sandbox/scan: the fast-verdict / slow-screenshot split
described in TRUST_REVIEW_SPEED_BRIEF.md. Check should never touch
URLScan; Scan should always carry the same verdict Check would produce,
computed concurrently rather than as a second round trip.
"""
import json

import httpx
import pytest


def _ollama_response(payload: dict) -> httpx.Response:
    return httpx.Response(200, json={"response": json.dumps(payload)})


CLEAN_VERDICT = {
    "verdict": "FP", "confidence": 20, "risk_level": "clean",
    "reasoning": "no corroborating evidence", "recommended_action": "none",
    "mitre_technique": None, "indicators_of_compromise": [],
}


@pytest.mark.respx(base_url="http://localhost:11434")
def test_sandbox_check_never_calls_urlscan(client, respx_mock, monkeypatch):
    """Check is the fast path — it must not submit anything to URLScan."""
    import threat_intel
    monkeypatch.setattr(threat_intel, "ABUSEIPDB_KEY", None)
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(CLEAN_VERDICT))
    # If Check ever calls URLScan this test fails loudly: no route is
    # registered for it and respx's default assert_all_mocked will raise.

    r = client.post("/sandbox/check", data={"url": "http://example.com/path"})

    assert r.status_code == 200
    data = r.json()
    assert data["indicator"] == "example.com"
    assert "ai_verdict" in data
    assert "typosquat" in data


@pytest.mark.respx(base_url="http://localhost:11434")
def test_sandbox_check_typosquat_forces_tp_over_llm(client, respx_mock, monkeypatch):
    import threat_intel
    monkeypatch.setattr(threat_intel, "ABUSEIPDB_KEY", None)
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(CLEAN_VERDICT))

    r = client.post("/sandbox/check", data={"url": "http://paypa1-verify.com/login"})

    assert r.status_code == 200
    data = r.json()
    assert data["typosquat"]["detected"] is True
    assert data["ai_verdict"]["verdict"] == "TP"


@pytest.mark.respx(base_url="http://localhost:11434", assert_all_called=False)
def test_sandbox_scan_includes_the_same_verdict_as_check(client, respx_mock, monkeypatch):
    """Scan's response must carry a `check` field with a real verdict,
    not just URLScan's own raw malicious flag."""
    import threat_intel
    monkeypatch.setattr(threat_intel, "ABUSEIPDB_KEY", None)
    respx_mock.post("/api/generate").mock(return_value=_ollama_response(CLEAN_VERDICT))

    submit_route = respx_mock.post("https://urlscan.io/api/v1/scan/").mock(
        return_value=httpx.Response(200, json={"uuid": "abc-123"})
    )
    respx_mock.get("https://urlscan.io/api/v1/result/abc-123/").mock(
        return_value=httpx.Response(404)
    )
    monkeypatch.setattr("sandbox.URLSCAN_KEY", "test-key")
    monkeypatch.setattr("asyncio.sleep", _instant_sleep)

    r = client.post("/sandbox/scan", data={"url": "http://paypa1-verify.com/login"})

    assert r.status_code == 200
    data = r.json()
    assert submit_route.called
    assert "check" in data
    assert data["check"]["ai_verdict"]["verdict"] == "TP"  # typosquat override, same as Check alone


async def _instant_sleep(*_args, **_kwargs):
    return None
