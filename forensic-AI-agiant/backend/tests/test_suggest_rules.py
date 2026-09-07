"""
scripts/suggest_rules.py: human-approved rule suggestions, never
self-editing. Tests the two suggestion functions directly against a
throwaway feedback directory rather than shelling out to the script, so
they run fast and don't depend on print-output scraping.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import suggest_rules  # noqa: E402


def _write_case(feedback_dir: Path, case_id: str, **fields) -> None:
    base = {
        "case_id": case_id, "human_verdict": None, "indicators": {"domains": []},
        "phishing_keywords_matched": [], "rule_score": 0, "reviewed_at": None,
    }
    base.update(fields)
    (feedback_dir / f"{case_id}.json").write_text(json.dumps(base), encoding="utf-8")


def test_load_confirmed_tp_cases_only_returns_human_confirmed_tp(tmp_path, monkeypatch):
    monkeypatch.setattr(suggest_rules, "FEEDBACK_DIR", tmp_path)
    _write_case(tmp_path, "CASE-1", human_verdict="TP")
    _write_case(tmp_path, "CASE-2", human_verdict="FP")
    _write_case(tmp_path, "CASE-3", human_verdict=None)

    cases = suggest_rules.load_confirmed_tp_cases()
    assert [c["case_id"] for c in cases] == ["CASE-1"]


def test_suggest_typosquat_brands_flags_unrecognized_domains(capsys):
    cases = [
        {"case_id": "CASE-1", "indicators": {"domains": ["totally-not-a-brand-xyz.com"]}},
        {"case_id": "CASE-2", "indicators": {"domains": ["paypa1.com"]}},  # already recognized
    ]
    suggest_rules.suggest_typosquat_brands(cases)
    out = capsys.readouterr().out
    assert "totally-not-a-brand-xyz.com" in out
    assert "paypa1.com" not in out  # already caught, nothing to suggest


def test_suggest_keyword_review_flags_zero_keyword_matches(capsys):
    cases = [
        {"case_id": "CASE-1", "phishing_keywords_matched": [], "rule_score": 40, "reviewed_at": "x"},
        {"case_id": "CASE-2", "phishing_keywords_matched": ["urgent action"], "rule_score": 60, "reviewed_at": "x"},
    ]
    suggest_rules.suggest_keyword_review(cases)
    out = capsys.readouterr().out
    assert "CASE-1" in out
    assert "CASE-2" not in out


def test_suggest_functions_handle_no_confirmed_cases_gracefully(capsys):
    suggest_rules.suggest_typosquat_brands([])
    suggest_rules.suggest_keyword_review([])
    out = capsys.readouterr().out
    assert "Nothing to suggest" in out
    assert "None" in out
