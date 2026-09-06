import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

FEEDBACK_DIR = Path("feedback")
FEEDBACK_DIR.mkdir(exist_ok=True)

def save_analysis(case_data: dict) -> str:
    """Save analysis for human review"""
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:6].upper()}"
    
    # Never save raw evidence text — only metadata and results
    safe_data = {
        "case_id":         case_id,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "llm_verdict":     case_data.get("case_verdict", {}).get("verdict"),
        "llm_confidence":  case_data.get("case_verdict", {}).get("confidence"),
        "llm_risk_level":  case_data.get("case_verdict", {}).get("risk_level"),
        "rule_score":      case_data.get("rule_findings", {}).get("rule_score", 0),
        "indicators":      case_data.get("indicators", {}),
        "threat_results":  case_data.get("threat_results", []),
        "anomaly_count":   len(case_data.get("anomalies", [])),
        "human_verdict":   None,
        "human_correct":   None,
        "human_notes":     None,
        "reviewed_at":     None
    }
    
    path = FEEDBACK_DIR / f"{case_id}.json"
    path.write_text(json.dumps(safe_data, indent=2))
    return case_id

def save_feedback(case_id: str, human_verdict: str,
                  is_correct: bool, notes: str = "") -> bool:
    path = FEEDBACK_DIR / f"{case_id}.json"
    if not path.exists():
        return False
    
    data = json.loads(path.read_text())
    data["human_verdict"] = human_verdict
    data["human_correct"] = is_correct
    data["human_notes"]   = notes
    data["reviewed_at"]   = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2))
    return True

def get_accuracy_stats() -> dict:
    """Calculate current system accuracy from human feedback"""
    cases    = list(FEEDBACK_DIR.glob("*.json"))
    reviewed = []
    
    for case_path in cases:
        data = json.loads(case_path.read_text())
        if data.get("human_verdict"):
            reviewed.append(data)
    
    if not reviewed:
        return {
            "total_reviewed": 0,
            "accuracy": None,
            "message": "No reviewed cases yet"
        }
    
    correct    = sum(1 for c in reviewed if c.get("human_correct"))
    tp_correct = sum(1 for c in reviewed
                    if c.get("human_correct") and
                    c.get("llm_verdict") == "TP")
    fp_correct = sum(1 for c in reviewed
                    if c.get("human_correct") and
                    c.get("llm_verdict") == "FP")
    false_pos  = sum(1 for c in reviewed
                    if not c.get("human_correct") and
                    c.get("llm_verdict") == "TP")
    false_neg  = sum(1 for c in reviewed
                    if not c.get("human_correct") and
                    c.get("llm_verdict") == "FP")
    
    return {
        "total_reviewed":   len(reviewed),
        "total_correct":    correct,
        "accuracy":         round(correct / len(reviewed) * 100, 1),
        "tp_correct":       tp_correct,
        "fp_correct":       fp_correct,
        "false_positives":  false_pos,
        "false_negatives":  false_neg,
        "precision":        round(tp_correct / max(tp_correct + false_pos, 1) * 100, 1),
        "recall":           round(tp_correct / max(tp_correct + false_neg, 1) * 100, 1)
    }