"""
These lock in the normalization behavior ask_llm_json() relies on: cosmetic
model mistakes (wrong case, out-of-range numbers, a lone string instead of
a list) should be silently corrected, not treated as a schema failure that
burns the one-shot re-prompt.
"""
from schemas import Anomaly, CaseVerdict, Highlight, SingleIndicatorVerdict


def test_verdict_is_normalized_to_uppercase():
    v = CaseVerdict.model_validate({"verdict": "tp"})
    assert v.verdict == "TP"


def test_unknown_verdict_falls_back_to_fp_not_an_exception():
    v = CaseVerdict.model_validate({"verdict": "MAYBE"})
    assert v.verdict == "FP"


def test_confidence_out_of_range_is_clamped_not_rejected():
    assert CaseVerdict.model_validate({"confidence": 150}).confidence == 100
    assert CaseVerdict.model_validate({"confidence": -20}).confidence == 0
    assert CaseVerdict.model_validate({"confidence": "not a number"}).confidence == 50


def test_risk_level_unknown_value_falls_back_to_low():
    v = CaseVerdict.model_validate({"risk_level": "apocalyptic"})
    assert v.risk_level == "low"


def test_single_string_is_coerced_into_a_list():
    v = CaseVerdict.model_validate({"recommended_actions": "just one string, not a list"})
    assert v.recommended_actions == ["just one string, not a list"]


def test_missing_fields_fall_back_to_safe_defaults():
    v = SingleIndicatorVerdict.model_validate({})
    assert v.verdict == "FP"
    assert v.confidence == 50
    assert v.indicators_of_compromise == []


def test_anomaly_severity_normalized():
    a = Anomaly.model_validate({"severity": "SUPER-CRITICAL!!"})
    assert a.severity == "low"
    a2 = Anomaly.model_validate({"severity": "Critical"})
    assert a2.severity == "critical"


def test_highlight_offsets_are_clamped_non_negative():
    h = Highlight.model_validate({"text": "abc", "start": -5, "end": 99999})
    assert h.start == 0
    assert h.end == 10_000  # clamp ceiling, further clamped to len() by agent.py
