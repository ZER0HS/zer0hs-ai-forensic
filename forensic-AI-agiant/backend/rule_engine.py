import re
import ipaddress
from typing import List

# Known malicious patterns
PHISHING_KEYWORDS = [
    "verify your account", "suspended", "urgent action",
    "click here immediately", "your account will be deleted",
    "confirm your identity", "unusual activity detected",
    "limited time", "act now", "verify immediately",
    "your password has expired", "unauthorized access",
    "account compromised", "security alert"
]

URGENCY_PATTERNS = [
    r"within \d+ hours?",
    r"expires? (today|tonight|now|soon)",
    r"immediately|urgent|asap|right away",
    r"last (chance|warning|notice)",
    r"before (monday|tuesday|wednesday|thursday|friday)"
]

SOCIAL_ENGINEERING = [
    "do not reply", "do not tell anyone", "keep this confidential",
    "delete this email", "do not forward", "between us",
    "before the audit", "before they find out"
]

TYPOSQUAT_BRANDS = [
    "paypal", "amazon", "microsoft", "google", "apple",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "dropbox", "docusign", "fedex", "dhl", "usps",
    "irs", "hmrc", "bankofamerica", "wellsfargo", "chase"
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".cmd", ".msi", ".dll", ".hta", ".wsf"
]

PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_IP_RANGES)
    except ValueError:
        return False

def check_typosquatting(domain: str) -> dict:
    domain_lower = domain.lower()
    # Remove TLD
    domain_base  = domain_lower.rsplit(".", 1)[0]
    
    for brand in TYPOSQUAT_BRANDS:
        if brand in domain_base and domain_base != brand:
            # Check for number substitutions (paypa1, g00gle)
            normalized = (domain_base
                .replace("0", "o").replace("1", "l")
                .replace("3", "e").replace("4", "a")
                .replace("5", "s").replace("@", "a"))
            if brand in normalized:
                return {
                    "detected":    True,
                    "brand":       brand,
                    "domain":      domain,
                    "technique":   "typosquatting"
                }
        
        # Levenshtein-like: check if very similar to brand
        if len(brand) > 4 and levenshtein(domain_base, brand) <= 2:
            return {
                "detected":  True,
                "brand":     brand,
                "domain":    domain,
                "technique": "lookalike"
            }
    
    return {"detected": False}

def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1,
                           prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]

def analyze_text_patterns(text: str) -> dict:
    text_lower = text.lower()
    results    = {
        "phishing_keywords":    [],
        "urgency_patterns":     [],
        "social_engineering":   [],
        "phishing_score":       0,
        "urgency_score":        0,
        "se_score":             0,
        "total_score":          0
    }
    
    # Check phishing keywords
    for kw in PHISHING_KEYWORDS:
        if kw in text_lower:
            results["phishing_keywords"].append(kw)
    
    # Check urgency patterns
    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, text_lower)
        if matches:
            results["urgency_patterns"].extend(matches)
    
    # Check social engineering
    for se in SOCIAL_ENGINEERING:
        if se in text_lower:
            results["social_engineering"].append(se)
    
    # Score calculation
    results["phishing_score"] = min(
        len(results["phishing_keywords"]) * 15, 60
    )
    results["urgency_score"]  = min(
        len(results["urgency_patterns"]) * 20, 40
    )
    results["se_score"]       = min(
        len(results["social_engineering"]) * 25, 50
    )
    results["total_score"]    = min(
        results["phishing_score"] +
        results["urgency_score"] +
        results["se_score"], 100
    )
    
    return results

def check_dangerous_attachments(text: str) -> list:
    found = []
    for ext in DANGEROUS_EXTENSIONS:
        pattern = rf'\b\w+{re.escape(ext)}\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        found.extend(matches)
    return found

def run_rules(text: str, indicators: dict,
              threat_results: list) -> dict:
    """
    Run all deterministic rules and return structured findings.
    This is ground truth — LLM cannot override these results.
    """
    findings  = {
        "rule_score":           0,
        "hard_tp_indicators":   [],
        "hard_fp_indicators":   [],
        "text_analysis":        {},
        "typosquat_results":    [],
        "dangerous_files":      [],
        "threat_summary":       {},
        "verdict_override":     None,
        "override_reason":      ""
    }
    
    # 1. Text pattern analysis
    text_analysis = analyze_text_patterns(text)
    findings["text_analysis"] = text_analysis
    
    if text_analysis["total_score"] >= 50:
        findings["hard_tp_indicators"].append(
            f"High social engineering score: "
            f"{text_analysis['total_score']}/100 "
            f"({len(text_analysis['phishing_keywords'])} phishing keywords, "
            f"{len(text_analysis['urgency_patterns'])} urgency patterns)"
        )
    
    # 2. Check typosquatting on all domains
    for domain in indicators.get("domains", []):
        ts = check_typosquatting(domain)
        if ts["detected"]:
            findings["typosquat_results"].append(ts)
            findings["hard_tp_indicators"].append(
                f"Typosquatting detected: '{domain}' "
                f"impersonates '{ts['brand']}' ({ts['technique']})"
            )
    
    # 3. Dangerous file attachments
    dangerous = check_dangerous_attachments(text)
    if dangerous:
        findings["dangerous_files"] = dangerous
        findings["hard_tp_indicators"].append(
            f"Dangerous file references: {', '.join(dangerous)}"
        )
    
    # 4. Threat intel scoring
    max_ip_score     = 0
    max_domain_score = 0
    clean_ips        = []
    
    for r in threat_results:
        score = r.get("abuse_score", 0)
        val   = r.get("value", "")
        
        if r.get("type") == "ip":
            if is_private_ip(val):
                findings["hard_fp_indicators"].append(
                    f"{val} is a private/internal IP — not a threat indicator"
                )
                continue
            
            max_ip_score = max(max_ip_score, score)
            
            if score >= 75:
                findings["hard_tp_indicators"].append(
                    f"IP {val} has critical AbuseIPDB score: "
                    f"{score}/100 "
                    f"({r.get('total_reports',0)} reports, "
                    f"{r.get('isp','unknown')})"
                )
            elif score < 10:
                clean_ips.append(val)
                findings["hard_fp_indicators"].append(
                    f"IP {val} is clean: AbuseIPDB score {score}/100"
                )
        
        elif r.get("type") == "domain":
            max_domain_score = max(max_domain_score, score)
            mal = r.get("malicious_votes", 0)
            
            if mal > 0:
                findings["hard_tp_indicators"].append(
                    f"Domain {val} flagged by "
                    f"{mal} VirusTotal engines as malicious"
                )
            elif score == 0 and mal == 0:
                findings["hard_fp_indicators"].append(
                    f"Domain {val} is clean on VirusTotal"
                )
    
    findings["threat_summary"] = {
        "max_ip_score":     max_ip_score,
        "max_domain_score": max_domain_score,
        "clean_ips":        clean_ips
    }
    
    # 5. Calculate rule-based score
    rule_score = 0
    rule_score += min(text_analysis["total_score"] * 0.3, 30)
    rule_score += min(max_ip_score * 0.4, 40)
    rule_score += min(max_domain_score * 0.3, 30)
    rule_score += len(findings["typosquat_results"]) * 20
    rule_score += len(findings["dangerous_files"]) * 25
    findings["rule_score"] = min(int(rule_score), 100)
    
    # 6. Hard overrides — cases where rules are definitive
    tp_count = len(findings["hard_tp_indicators"])
    fp_count = len(findings["hard_fp_indicators"])
    
    # Definite TP cases
    if len(findings["typosquat_results"]) > 0 and max_ip_score >= 75:
        findings["verdict_override"] = "TP"
        findings["override_reason"]  = (
            "DEFINITE TP: Typosquatting domain + "
            "high-risk IP confirmed"
        )
    elif len(findings["dangerous_files"]) > 0 and max_ip_score >= 50:
        findings["verdict_override"] = "TP"
        findings["override_reason"]  = (
            "DEFINITE TP: Dangerous attachment + "
            "malicious IP confirmed"
        )
    
    # Definite FP cases
    elif (tp_count == 0 and
          text_analysis["total_score"] < 20 and
          max_ip_score < 10 and
          max_domain_score < 5):
        findings["verdict_override"] = "FP"
        findings["override_reason"]  = (
            "DEFINITE FP: No threat indicators found — "
            "clean IPs, clean domains, no suspicious patterns"
        )
    
    return findings