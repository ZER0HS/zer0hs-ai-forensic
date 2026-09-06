from llm_client import ask_llm, clean_json
import json

FORENSIC_SYSTEM = """You are a certified digital forensics examiner (GCFE, GCFA).
You think methodically and base verdicts only on concrete evidence.
You MUST return valid JSON only — no text before or after."""

async def run_analysis(text: str,
                       rule_findings: dict = None,
                       patterns: dict = None) -> dict:
    
    rule_context = ""
    if rule_findings:
        rule_context = f"""
PRE-ANALYSIS FROM RULE ENGINE (trust these — they are deterministic):
- Rule-based risk score: {rule_findings.get('rule_score', 0)}/100
- Hard TP indicators found: {rule_findings.get('hard_tp_indicators', [])}
- Hard FP indicators found: {rule_findings.get('hard_fp_indicators', [])}
- Typosquatting detected: {[t['domain'] for t in rule_findings.get('typosquat_results', [])]}
- Dangerous files: {rule_findings.get('dangerous_files', [])}
- Text analysis score: {rule_findings.get('text_analysis', {}).get('total_score', 0)}/100
- Phishing keywords found: {rule_findings.get('text_analysis', {}).get('phishing_keywords', [])}
"""
    
    pattern_context = ""
    if patterns and patterns.get("matched_attack_patterns"):
        pattern_context = f"""
MATCHED FORENSIC PATTERNS:
{json.dumps(patterns['matched_attack_patterns'], indent=2)}
"""

    prompt = f"""Perform systematic forensic analysis of this evidence.

{rule_context}
{pattern_context}

EVIDENCE:
---
{text[:6000]}
---

Return ONLY this JSON:
{{
  "summary": "Factual 2-3 sentence description. State WHO, WHAT, WHEN. Reference the rule engine findings if relevant.",
  
  "key_findings": [
    "Finding 1 — cite specific evidence from text",
    "Finding 2 — cite specific evidence from text",
    "Finding 3 — cite specific evidence from text"
  ],
  
  "entities": {{
    "persons": ["names found in text"],
    "places":  ["locations found in text"],
    "times":   ["timestamps found like 2024-03-15 02:47"],
    "orgs":    ["organizations/domains found"]
  }},
  
  "highlighted_text": "Most forensically significant excerpt under 300 chars with HTML spans",
  
  "anomalies": [
    {{
      "severity":    "critical/high/medium/low",
      "title":       "Specific anomaly name",
      "description": "Quote from evidence + forensic explanation"
    }}
  ],
  
  "timeline": [
    {{
      "time":    "YYYY-MM-DD HH:MM",
      "event":   "Action from evidence",
      "actors":  "Who performed it",
      "anomaly": false
    }}
  ]
}}"""

    raw    = await ask_llm(prompt, FORENSIC_SYSTEM, max_tokens=2000)
    result = clean_json(raw)
    result.setdefault("summary", "Analysis complete")
    result.setdefault("key_findings", [])
    result.setdefault("entities", {"persons":[],"places":[],"times":[],"orgs":[]})
    result.setdefault("anomalies", [])
    result.setdefault("timeline", [])
    result.setdefault("highlighted_text", text[:300])
    return result