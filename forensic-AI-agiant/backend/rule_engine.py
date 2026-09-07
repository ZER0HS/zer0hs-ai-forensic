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

# Same three categories, in Arabic. The English lists above only ever
# match Latin-script text — a phishing email written in Arabic scored 0 on
# every one of them regardless of how blatant the social engineering was.
# This isn't a translation layer bolted on top; it's applied identically
# to the English lists inside analyze_text_patterns() below.
PHISHING_KEYWORDS_AR = [
    "تحقق من حسابك", "تم تعليق", "إجراء عاجل",
    "اضغط هنا فورا", "سيتم حذف حسابك", "تأكيد هويتك",
    "نشاط غير معتاد", "عرض لفترة محدودة", "بادر الآن",
    "تحقق فورا", "انتهت صلاحية كلمة المرور", "وصول غير مصرح به",
    "تم اختراق الحساب", "تنبيه أمني",
]

URGENCY_PATTERNS_AR = [
    r"خلال \d+ ساعة",
    r"تنتهي (اليوم|الليلة|الآن|قريبا)",
    r"فورا|عاجل|حالا",
    r"تحذير أخير|فرصة أخيرة",
    r"قبل يوم (الاثنين|الثلاثاء|الأربعاء|الخميس|الجمعة)",
]

SOCIAL_ENGINEERING_AR = [
    "لا ترد على هذا", "لا تخبر أحدا", "احتفظ بهذا سريا",
    "احذف هذا البريد", "لا تعد توجيه هذا", "بيننا فقط",
    "قبل التدقيق", "قبل أن يكتشفوا",
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


# Cyrillic/Greek characters visually indistinguishable from a Latin letter
# at a glance — not exhaustive, but covers the ones actually used to spoof
# brand names in real homoglyph domains. Mixed-script lookalike domains are
# a well-documented phishing technique (e.g. "аpple.com" registered with a
# Cyrillic а, U+0430, instead of Latin a).
HOMOGLYPH_MAP = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ԛ": "q",
    "ѡ": "w", "ь": "b", "п": "n", "м": "m", "к": "k", "н": "h",
    "т": "t", "в": "b", "г": "r",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v", "κ": "k",
    "τ": "t", "χ": "x", "ι": "i", "β": "b",
}


def _decode_punycode_label(label: str) -> str:
    """Punycode-decode a single DNS label (xn--...) back to Unicode.

    This is what actually shows up in a URL — URLs must be ASCII, so a
    domain registered with non-Latin characters is transmitted in its
    "xn--" form and only rendered back to Unicode by the browser or mail
    client for the human reader. To catch what a person would actually
    see, we have to do that same decoding before comparing anything.
    """
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, LookupError):
        return label


def normalize_homoglyphs(domain: str) -> str:
    """Decode punycode labels and fold known look-alike characters to
    their Latin equivalent, so a homoglyph domain compares equal to the
    brand name it's impersonating."""
    labels  = domain.lower().split(".")
    decoded = ".".join(_decode_punycode_label(label) for label in labels)
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in decoded)


def check_typosquatting(domain: str) -> dict:
    domain_lower = domain.lower()
    # Remove TLD
    domain_base  = domain_lower.rsplit(".", 1)[0]

    homoglyph_full = normalize_homoglyphs(domain_lower)
    homoglyph_base = homoglyph_full.rsplit(".", 1)[0]

    for brand in TYPOSQUAT_BRANDS:
        # The brand's own domain, or a real subdomain of it (e.g.
        # "mail.google" for brand "google"), is never a typosquat of
        # itself. Without this check every legitimate brand domain 5+
        # characters long (google.com, paypal.com, chase.com, ...) was
        # being flagged as "impersonating" itself, since the Levenshtein
        # check below matches an exact string against itself at distance 0.
        if domain_base == brand or domain_base.endswith("." + brand):
            continue

        # Check for number substitutions (paypa1, g00gle). This normalizes
        # *before* the substring test, not after — the original code only
        # normalized when the raw string already contained the brand
        # verbatim, which meant it could never actually catch a digit
        # substitution (that's precisely the case where the raw string
        # does NOT contain the brand yet). That made this branch dead code
        # for exactly the domains it was written to catch — e.g.
        # "paypa1-account-security.com" was invisible to it and fell
        # through to the Levenshtein check below, which fails once the
        # domain is padded with enough extra words to push the edit
        # distance past the threshold.
        normalized = (domain_base
            .replace("0", "o").replace("1", "l")
            .replace("3", "e").replace("4", "a")
            .replace("5", "s").replace("@", "a"))

        if brand in domain_base or brand in normalized:
            return {
                "detected":  True,
                "brand":     brand,
                "domain":    domain,
                "technique": "typosquatting" if brand in domain_base else "number-substitution",
            }

        # Homoglyph/lookalike-character domain (possibly punycode-encoded)
        # impersonating the brand — checked after the plain-ASCII paths
        # above since those are cheaper and cover the common case.
        if brand in homoglyph_base:
            return {
                "detected":  True,
                "brand":     brand,
                "domain":    domain,
                "technique": "homoglyph",
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
    
    # Check phishing keywords — English and Arabic, applied identically.
    # Arabic has no case distinction, so .lower() is a harmless no-op on
    # it; the English list still needs text_lower for its own matching.
    for kw in PHISHING_KEYWORDS + PHISHING_KEYWORDS_AR:
        if kw in text_lower:
            results["phishing_keywords"].append(kw)

    # Check urgency patterns — English and Arabic
    for pattern in URGENCY_PATTERNS + URGENCY_PATTERNS_AR:
        matches = re.findall(pattern, text_lower)
        if matches:
            results["urgency_patterns"].extend(matches)

    # Check social engineering — English and Arabic
    for se in SOCIAL_ENGINEERING + SOCIAL_ENGINEERING_AR:
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
              threat_results: list, hash_results: list = None,
              attachments: list = None) -> dict:
    """
    Run all deterministic rules and return structured findings.
    This is ground truth — LLM cannot override these results.
    """
    hash_results = hash_results or []
    attachments  = attachments or []
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
    
    # 3. Dangerous file attachments — both a literal mention in the body
    #    text ("see attached invoice.exe") and, more importantly, an
    #    actual MIME attachment with a dangerous extension. These used to
    #    be checked separately: header_parser.py already flagged a real
    #    dangerous attachment as a header-level anomaly, but that never
    #    fed into this function, so a genuinely attached .exe (as opposed
    #    to one merely mentioned in the text) was invisible to the rule
    #    engine's hard-TP/override logic and fell through to the LLM path
    #    even with a confirmed-malicious IP alongside it.
    dangerous = check_dangerous_attachments(text)
    real_attachments = [
        a.get("filename", "") for a in attachments
        if any(a.get("filename", "").lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    ]
    all_dangerous = list(dict.fromkeys(dangerous + real_attachments))
    if all_dangerous:
        findings["dangerous_files"] = all_dangerous
        findings["hard_tp_indicators"].append(
            f"Dangerous file references: {', '.join(all_dangerous)}"
        )
    
    # 4. Attachment hash checks (VirusTotal) — a confirmed-malicious hash is
    #    about as strong a signal as this engine ever gets, so it alone is
    #    enough to force a definite-TP override (see step 6).
    malicious_hashes = [h for h in hash_results if h.get("malicious", 0) > 0]
    if malicious_hashes:
        for h in malicious_hashes:
            findings["hard_tp_indicators"].append(
                f"Attachment '{h.get('filename', 'unknown')}' hash flagged "
                f"malicious by {h['malicious']}/{h.get('total', '?')} "
                f"VirusTotal engines"
            )

    # 5. Threat intel scoring
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
    
    # 6. Calculate rule-based score
    rule_score = 0
    rule_score += min(text_analysis["total_score"] * 0.3, 30)
    rule_score += min(max_ip_score * 0.4, 40)
    rule_score += min(max_domain_score * 0.3, 30)
    rule_score += len(findings["typosquat_results"]) * 20
    rule_score += len(findings["dangerous_files"]) * 25
    rule_score += len(malicious_hashes) * 30
    findings["rule_score"] = min(int(rule_score), 100)

    # 7. Hard overrides — cases where rules are definitive.
    # Ordered most-confident-signal-first; each is an independent `elif` so
    # exactly one reason is ever recorded.
    tp_count = len(findings["hard_tp_indicators"])

    if malicious_hashes:
        findings["verdict_override"] = "TP"
        findings["override_reason"]  = (
            "DEFINITE TP: Attachment hash confirmed malicious on "
            f"VirusTotal ({len(malicious_hashes)} attachment(s) flagged)"
        )
    elif len(findings["typosquat_results"]) > 0 and max_ip_score >= 75:
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


# ── Short-circuit path for maximally-confident deterministic verdicts ───────
#
# When run_rules() above already produced a `verdict_override`, both LLM
# calls (forensic analysis + FP/TP scoring) are skipped entirely — see
# main.py. In a real inbox, most email is either obviously clean or
# obviously malicious; this is where "fast" actually comes from, not from
# making the LLM call itself faster. These two functions build the same
# response shape the LLM path produces, using only the rule engine's own
# (already-trustworthy) findings.

def shortcircuit_forensic(text: str, rule_findings: dict) -> dict:
    is_tp = rule_findings.get("verdict_override") == "TP"
    hard_tp = rule_findings.get("hard_tp_indicators", [])
    hard_fp = rule_findings.get("hard_fp_indicators", [])
    findings = hard_tp + hard_fp

    # Surface the rule engine's own findings as anomalies too — found live
    # while testing this pass: leaving this empty made a confirmed TP show
    # "0 anomalies" in the UI, which reads as "nothing was found" even
    # though the case summary and factors right next to it clearly list
    # what was. Every hard indicator is real evidence; it should show up
    # wherever the UI displays evidence, not just in one place.
    anomalies = [
        {"severity": "critical" if is_tp else "low", "title": "Rule engine finding", "description": i}
        for i in (hard_tp if is_tp else hard_fp)
    ]

    return {
        "summary": rule_findings.get(
            "override_reason",
            "Deterministic rule engine reached a maximally-confident "
            "verdict; no LLM call was needed."
        ),
        "key_findings": findings[:6],
        "entities": {"persons": [], "places": [], "times": [], "orgs": []},
        "highlight": {"text": text[:300], "start": 0, "end": 0},
        "anomalies": anomalies,
        "timeline": [],
    }


def shortcircuit_verdict(rule_findings: dict) -> dict:
    override  = rule_findings["verdict_override"]
    reason    = rule_findings.get("override_reason", "")
    is_tp     = override == "TP"
    return {
        "verdict":       override,
        "confidence":    95,
        "risk_level":    "critical" if is_tp else "clean",
        "case_summary":  reason,
        "reasoning":     f"[RULE ENGINE — no LLM call needed] {reason}",
        "fp_tp_factors": {
            "factors_for_tp": rule_findings.get("hard_tp_indicators", []) if is_tp else [],
            "factors_for_fp": rule_findings.get("hard_fp_indicators", []) if not is_tp else [],
            "deciding_factor": reason,
        },
        "recommended_actions": (
            ["Escalate to incident response", "Block sender domain/IP",
             "Preserve headers and attachments for the case record"]
            if is_tp else
            ["No action required — routine review only"]
        ),
        "mitre_techniques":     [],
        "iocs":                 [],
        "threat_actor_profile": None,
        "severity_breakdown": {
            "indicator_risk": 0, "behavioral_risk": 0, "contextual_risk": 0
        },
    }