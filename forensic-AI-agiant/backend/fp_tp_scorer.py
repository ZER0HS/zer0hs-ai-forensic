import json
from llm_client import ask_llm, clean_json

ANALYST_SYSTEM = """You are a senior SOC analyst and threat intelligence expert 
with 20 years experience at a national CERT. You have investigated thousands of 
incidents and are extremely precise about True Positive vs False Positive verdicts.

YOUR DECISION FRAMEWORK:

TRUE POSITIVE (TP) requires at least ONE of:
- IP with AbuseIPDB score >= 50 AND appears in suspicious context
- Domain flagged malicious by VirusTotal (malicious_votes > 0)
- Clear evidence of phishing, malware, C2, or data exfiltration in text
- Authentication failures (SPF fail + DKIM fail + DMARC fail together)
- Typosquatting domain clearly impersonating a known brand
- Attachment with dangerous extension (.exe, .bat, .ps1, .vbs, .js)
- Multiple corroborating indicators together

FALSE POSITIVE (FP) indicators:
- IP is Google (8.8.8.8), Cloudflare (1.1.1.1), known CDN
- Domain is a major legitimate service (gmail, outlook, github, etc)
- AbuseIPDB score < 20 with no other corroborating evidence
- Normal business communication with no technical indicators
- Single low-confidence indicator with no corroboration
- Internal/private IP addresses (10.x, 192.168.x, 172.16-31.x)

CALIBRATION:
- High confidence TP: 80-100% — multiple strong indicators
- Medium confidence TP: 60-79% — clear indicators but some uncertainty
- Low confidence TP: 50-59% — suspicious but needs more investigation
- FP: below 50% — insufficient evidence for TP verdict

YOU MUST RETURN VALID JSON ONLY — no text before or after the JSON object."""


async def score_case(
    evidence_text:    str,
    indicators:       dict,
    threat_results:   list,
    forensic_analysis: dict,
    rule_findings:    dict = None,
    patterns:         dict = None
) -> dict:

    # ── Pre-process threat results ────────────────────────────────────────
    ip_lines     = []
    domain_lines = []

    for r in threat_results:
        score = r.get("abuse_score", 0)
        val   = r.get("value", "")

        if r.get("type") == "ip":
            risk = ("CRITICAL" if score >= 75
                    else "HIGH"   if score >= 50
                    else "MEDIUM" if score >= 25
                    else "LOW")
            ip_lines.append(
                f"  IP {val}: AbuseIPDB={score}/100 ({risk}), "
                f"Country={r.get('country','?')}, "
                f"ISP={r.get('isp','?')}, "
                f"Reports={r.get('total_reports',0)}, "
                f"Type={r.get('usage_type','?')}"
            )

        elif r.get("type") == "domain":
            mal = r.get("malicious_votes", 0)
            sus = r.get("suspicious_votes", 0)
            domain_lines.append(
                f"  Domain {val}: VirusTotal score={score}/100, "
                f"Malicious={mal}, Suspicious={sus}, "
                f"Scanners={r.get('total_scanners','?')}"
            )

    # ── Pre-process anomalies ─────────────────────────────────────────────
    anomaly_lines = []
    for a in forensic_analysis.get("anomalies", []):
        anomaly_lines.append(
            f"  [{a.get('severity','?').upper()}] "
            f"{a.get('title','?')}: {a.get('description','')}"
        )

    # ── Email auth block ──────────────────────────────────────────────────
    auth_block = ""
    eml = forensic_analysis.get("eml_headers")
    if eml and isinstance(eml, dict):
        auth   = eml.get("auth_results", {})
        h_anom = eml.get("anomalies", [])
        auth_block = f"""
EMAIL AUTHENTICATION:
  SPF:   {auth.get('spf',  'unknown')}
  DKIM:  {auth.get('dkim', 'unknown')}
  DMARC: {auth.get('dmarc','unknown')}
  Header anomalies ({len(h_anom)} found):
{chr(10).join(f"    - {a.get('detail','')}" for a in h_anom)}"""

    # ── Rule engine block ─────────────────────────────────────────────────
    rule_block = ""
    if rule_findings:
        rule_block = f"""
DETERMINISTIC RULE ENGINE RESULTS (highest priority — trust these):
  Rule score:        {rule_findings.get('rule_score', 0)}/100
  Hard TP indicators: {rule_findings.get('hard_tp_indicators', [])}
  Hard FP indicators: {rule_findings.get('hard_fp_indicators', [])}
  Verdict override:  {rule_findings.get('verdict_override', 'None')}
  Override reason:   {rule_findings.get('override_reason', '')}
  Typosquatting:     {[t['domain'] for t in rule_findings.get('typosquat_results', [])]}
  Dangerous files:   {rule_findings.get('dangerous_files', [])}
  Text risk score:   {rule_findings.get('text_analysis', {}).get('total_score', 0)}/100
  Phishing keywords: {rule_findings.get('text_analysis', {}).get('phishing_keywords', [])}
  SE patterns:       {rule_findings.get('text_analysis', {}).get('social_engineering', [])}

IMPORTANT: If verdict_override is set you MUST match it."""

    # ── Pattern block ─────────────────────────────────────────────────────
    pattern_block = ""
    if patterns:
        matched = patterns.get("matched_attack_patterns", [])
        benign  = patterns.get("benign_indicators", [])
        if matched or benign:
            pattern_block = f"""
MATCHED FORENSIC PATTERNS FROM KNOWLEDGE BASE:
{json.dumps(matched, indent=2) if matched else '  None matched'}

BENIGN INDICATORS (evidence this may be FP):
{chr(10).join(f'  - {b}' for b in benign) if benign else '  None found'}"""

    # ── Build final prompt ────────────────────────────────────────────────
    prompt = f"""Analyze ALL the following data holistically and determine
if this is a TRUE POSITIVE (real threat) or FALSE POSITIVE (benign/false alarm).

═══════════════════════════════════════════════════════════
EVIDENCE SUMMARY:
{forensic_analysis.get('summary', 'No summary available')}

KEY FINDINGS:
{chr(10).join(f'  - {f}' for f in forensic_analysis.get('key_findings', []))}

EXTRACTED INDICATORS:
  Public IPs:   {indicators.get('ips', [])}
  Domains:      {indicators.get('domains', [])}
  URLs:         {indicators.get('urls', [])}
  Emails:       {indicators.get('emails', [])}
  Private IPs:  {indicators.get('private_ips', [])} ← IGNORE these, always normal

THREAT INTELLIGENCE:
{chr(10).join(ip_lines)     if ip_lines     else '  No IP results'}
{chr(10).join(domain_lines) if domain_lines else '  No domain results'}

FORENSIC ANOMALIES:
{chr(10).join(anomaly_lines) if anomaly_lines else '  No anomalies detected'}
{auth_block}
{rule_block}
{pattern_block}

EVIDENCE EXCERPT:
{evidence_text[:1500]}
═══════════════════════════════════════════════════════════

Apply the decision framework step by step and return ONLY this JSON:
{{
  "verdict": "TP or FP",

  "confidence": 0,

  "risk_level": "critical or high or medium or low or clean",

  "case_summary": "3-4 sentences. State exactly what happened, who was involved, and what specific evidence determined the verdict. Reference actual data points like IP scores, domain names, keywords found.",

  "reasoning": "Step-by-step: 1) What indicators were found and their scores. 2) What each threat intel result means. 3) How rule engine findings support or contradict. 4) How anomalies corroborate. 5) Final verdict justification based on decision framework.",

  "fp_tp_factors": {{
    "factors_for_tp": [
      "Specific evidence point supporting TP verdict"
    ],
    "factors_for_fp": [
      "Specific evidence point supporting FP verdict"
    ],
    "deciding_factor": "The single most important piece of evidence that determined the final verdict"
  }},

  "recommended_actions": [
    "Specific actionable step 1 for the analyst",
    "Specific actionable step 2",
    "Specific actionable step 3"
  ],

  "mitre_techniques": [
    "T1566.002 - Phishing: Spearphishing Link"
  ],

  "iocs": [
    "Only CONFIRMED malicious indicators — IPs with score 50+, flagged domains, dangerous attachments"
  ],

  "threat_actor_profile": "Description of likely threat actor profile and motivation, or null if FP",

  "severity_breakdown": {{
    "indicator_risk":   0,
    "behavioral_risk":  0,
    "contextual_risk":  0
  }}
}}

MANDATORY RULES:
- Normal email between colleagues with no suspicious links/IPs = FP, confidence 85+
- Internal IPs (10.x, 192.168.x) = always ignore, never evidence of TP
- AbuseIPDB score under 20 alone = not enough for TP
- If rule engine says verdict_override = FP you MUST return FP
- If rule engine says verdict_override = TP you MUST return TP
- Only put confirmed malicious items in iocs array
- Empty iocs array if FP verdict"""

    raw    = await ask_llm(prompt, ANALYST_SYSTEM, max_tokens=2000)
    result = clean_json(raw)

    # ── Defaults ──────────────────────────────────────────────────────────
    result.setdefault("verdict",    "FP")
    result.setdefault("confidence", 50)
    result.setdefault("risk_level", "low")
    result.setdefault("case_summary", "Analysis complete")
    result.setdefault("reasoning",  "")
    result.setdefault("fp_tp_factors", {
        "factors_for_tp":  [],
        "factors_for_fp":  [],
        "deciding_factor": ""
    })
    result.setdefault("recommended_actions", [])
    result.setdefault("mitre_techniques",    [])
    result.setdefault("iocs",                [])
    result.setdefault("threat_actor_profile", None)
    result.setdefault("severity_breakdown", {
        "indicator_risk":  0,
        "behavioral_risk": 0,
        "contextual_risk": 0
    })

    # ── Sanity check — no evidence = cannot be TP ─────────────────────────
    has_threats   = any(
        r.get("abuse_score", 0) >= 25 for r in threat_results
    )
    has_anomalies = len(forensic_analysis.get("anomalies", [])) > 0
    has_rule_hits = len(
        (rule_findings or {}).get("hard_tp_indicators", [])
    ) > 0
    has_patterns  = len(
        (patterns or {}).get("matched_attack_patterns", [])
    ) > 0

    if (not has_threats and
        not has_anomalies and
        not has_rule_hits and
        not has_patterns):
        if result["verdict"] == "TP":
            result["verdict"]    = "FP"
            result["confidence"] = max(result["confidence"], 80)
            result["risk_level"] = "clean"
            result["reasoning"]  = (
                "[AUTO-CORRECTED] No threat intelligence hits, no forensic "
                "anomalies, no rule engine hits, and no pattern matches. "
                "Insufficient evidence for TP verdict. "
                + result.get("reasoning", "")
            )

    # ── Confidence floor based on evidence strength ───────────────────────
    if result["verdict"] == "TP":
        min_confidence = 50
        if has_rule_hits:      min_confidence += 15
        if has_threats:        min_confidence += 15
        if has_patterns:       min_confidence += 10
        result["confidence"]   = max(result["confidence"], min_confidence)
        result["confidence"]   = min(result["confidence"], 99)

    if result["verdict"] == "FP":
        result["iocs"] = []  # never have IOCs in a FP

    return result


async def score_single(
    indicator:   str,
    threat_data: dict,
    context:     str = ""
) -> dict:

    score  = threat_data.get("abuse_score", 0)
    itype  = threat_data.get("type", "unknown")
    source = threat_data.get("source", "unknown")

    if score >= 75:
        pre = "CRITICAL — very high abuse confidence, almost certainly malicious"
    elif score >= 50:
        pre = "HIGH — significant abuse reports, likely malicious"
    elif score >= 25:
        pre = "MEDIUM — some reports, investigate with context"
    elif score >= 10:
        pre = "LOW — minor reports, likely FP unless context is suspicious"
    else:
        pre = "CLEAN — no significant abuse reports found"

    prompt = f"""Analyze this single network indicator.

INDICATOR:
  Value:          {indicator}
  Type:           {itype}
  Source:         {source}
  Abuse score:    {score}/100
  Pre-assessment: {pre}

FULL THREAT DATA:
{json.dumps(threat_data, indent=2)}

ANALYST CONTEXT:
{context if context else "No additional context provided"}

SCORING RULES:
  Score  0-9  → Almost always FP (confidence 80-95%)
  Score 10-24 → Likely FP, needs strong context for TP
  Score 25-49 → Borderline — context is critical
  Score 50-74 → Likely TP, needs good reason to call FP
  Score 75+   → Almost always TP (confidence 80-95%)

Return ONLY this JSON:
{{
  "verdict":    "TP or FP",
  "confidence": 0,
  "risk_level": "critical or high or medium or low or clean",
  "reasoning":  "2-3 sentences referencing the actual score and data",
  "recommended_action":          "Specific next step for an analyst",
  "mitre_technique":             "Most relevant MITRE technique or null",
  "indicators_of_compromise":    []
}}"""

    raw    = await ask_llm(prompt, ANALYST_SYSTEM, max_tokens=600)
    result = clean_json(raw)

    # Defaults
    result.setdefault("verdict",    "FP")
    result.setdefault("confidence", 50)
    result.setdefault("risk_level", "low")
    result.setdefault("reasoning",  "")
    result.setdefault("recommended_action",       "Continue monitoring")
    result.setdefault("mitre_technique",          None)
    result.setdefault("indicators_of_compromise", [])

    # Hard overrides for single indicator
    if score < 10 and not context:
        result["verdict"]    = "FP"
        result["confidence"] = 90
        result["risk_level"] = "clean"
        result["iocs"]       = []

    elif score >= 75:
        result["verdict"]    = "TP"
        result["confidence"] = max(result["confidence"], 80)
        if result["risk_level"] not in ("critical", "high"):
            result["risk_level"] = "high"

    if result["verdict"] == "FP":
        result["indicators_of_compromise"] = []

    return result