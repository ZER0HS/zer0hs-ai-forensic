"""
/cases and /cases/{id} back the frontend's Case History page. They only
ever read back what save_analysis() already wrote to disk, so these tests
work directly against feedback.py's own file store rather than needing a
full /analyze run. (Case files land in a throwaway directory automatically
— see conftest.py's autouse _isolate_feedback_dir fixture.)
"""
import feedback


def test_list_cases_returns_saved_metadata_only():
    case_id = feedback.save_analysis({
        "case_verdict": {"verdict": "TP", "confidence": 80, "risk_level": "high"},
        "rule_findings": {"rule_score": 60},
        "indicators": {"ips": ["1.2.3.4"]},
        "threat_results": [],
        "anomalies": [{"severity": "high", "title": "x", "description": "y"}],
    })

    cases = feedback.list_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == case_id
    assert cases[0]["llm_verdict"] == "TP"
    # The whole point of save_analysis(): raw evidence text never gets
    # written to disk, only metadata.
    assert "evidence" not in cases[0]
    assert "body_text" not in str(cases[0])


def test_get_case_returns_none_for_unknown_id():
    assert feedback.get_case("CASE-does-not-exist") is None


def test_cases_endpoint_returns_list(client):
    feedback.save_analysis({"case_verdict": {"verdict": "FP", "confidence": 90, "risk_level": "clean"}})

    r = client.get("/cases")
    assert r.status_code == 200
    assert len(r.json()["cases"]) == 1


def test_case_detail_endpoint_404s_for_unknown_id(client):
    r = client.get("/cases/CASE-nope")
    assert r.status_code == 404


def test_verdict_distribution_counts_by_verdict():
    feedback.save_analysis({"case_verdict": {"verdict": "TP", "confidence": 80, "risk_level": "high"}})
    feedback.save_analysis({"case_verdict": {"verdict": "FP", "confidence": 90, "risk_level": "clean"}})
    feedback.save_analysis({"case_verdict": {"verdict": "FP", "confidence": 90, "risk_level": "clean"}})

    dist = feedback.get_verdict_distribution()
    assert dist == {"TP": 1, "FP": 2, "unknown": 0}
