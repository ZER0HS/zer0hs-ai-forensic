"""
Forensic knowledge base for RAG-enhanced analysis.
These are real-world forensic patterns that guide the LLM.
"""

FORENSIC_PATTERNS = {
    "phishing": {
        "description": "Email-based social engineering attack",
        "indicators": [
            "Sender domain different from displayed organization",
            "Reply-To address differs from From address",
            "Urgency language pressuring immediate action",
            "Requests for credentials or personal information",
            "Links to domains not matching the claimed organization",
            "Generic greeting (Dear Customer) vs personalized",
            "SPF/DKIM/DMARC authentication failures"
        ],
        "mitre": "T1566",
        "severity": "high"
    },
    "spearphishing": {
        "description": "Targeted phishing using personal information",
        "indicators": [
            "Personalized content referencing target's role",
            "Impersonation of known contacts or executives",
            "Reference to real internal projects or events",
            "Sent outside business hours (late night/early morning)",
            "Urgency combined with authority (CEO, IT, Legal)"
        ],
        "mitre": "T1566.001",
        "severity": "critical"
    },
    "bec": {
        "description": "Business Email Compromise",
        "indicators": [
            "Request to change payment details",
            "CEO/CFO impersonation requesting wire transfer",
            "Unusual request for gift cards",
            "Request to bypass normal approval process",
            "Reply-To set to attacker-controlled address"
        ],
        "mitre": "T1586.002",
        "severity": "critical"
    },
    "c2_communication": {
        "description": "Command and Control communication",
        "indicators": [
            "Regular beacon intervals to external IP",
            "Connections to high-abuse-score IPs",
            "Encoded/encrypted payload in HTTP requests",
            "DNS queries to recently registered domains",
            "Traffic to Tor exit nodes"
        ],
        "mitre": "T1071",
        "severity": "critical"
    },
    "data_exfiltration": {
        "description": "Data being stolen from organization",
        "indicators": [
            "Large file transfers to external destinations",
            "Uploads to file sharing services",
            "Compressed archives sent externally",
            "Database queries followed by external connections"
        ],
        "mitre": "T1041",
        "severity": "critical"
    },
    "insider_threat": {
        "description": "Malicious or negligent insider activity",
        "indicators": [
            "Access to systems outside normal working hours",
            "Mass file downloads before resignation",
            "Requests to delete files before audit",
            "Forwarding company emails to personal account",
            "Accessing files unrelated to job function"
        ],
        "mitre": "T1078",
        "severity": "high"
    }
}

BENIGN_PATTERNS = {
    "normal_business": [
        "Meeting scheduling and confirmations",
        "Project status updates",
        "File sharing via company-approved tools",
        "Internal IT notifications from known systems",
        "Newsletter or marketing emails with unsubscribe links"
    ],
    "known_clean_ips": [
        "8.8.8.8 (Google DNS)",
        "8.8.4.4 (Google DNS)",
        "1.1.1.1 (Cloudflare DNS)",
        "1.0.0.1 (Cloudflare DNS)",
        "208.67.222.222 (OpenDNS)",
    ],
    "known_clean_domains": [
        "google.com", "gmail.com", "outlook.com",
        "microsoft.com", "office.com", "github.com",
        "amazonaws.com", "cloudflare.com", "zoom.us",
        "slack.com", "teams.microsoft.com"
    ]
}

def get_relevant_patterns(text: str, indicators: dict) -> dict:
    """Find which forensic patterns match the evidence"""
    text_lower    = text.lower()
    matched       = []
    benign_hits   = []
    
    # Check for attack patterns
    for pattern_name, pattern_data in FORENSIC_PATTERNS.items():
        score  = 0
        hits   = []
        for indicator in pattern_data["indicators"]:
            # Simple keyword matching
            keywords = indicator.lower().split()
            if sum(1 for kw in keywords if kw in text_lower) >= 2:
                score += 1
                hits.append(indicator)
        
        if score >= 2:
            matched.append({
                "pattern":     pattern_name,
                "description": pattern_data["description"],
                "mitre":       pattern_data["mitre"],
                "severity":    pattern_data["severity"],
                "matched_indicators": hits,
                "confidence":  min(score * 20, 100)
            })
    
    # Check for benign patterns
    for domain in indicators.get("domains", []):
        if domain in BENIGN_PATTERNS["known_clean_domains"]:
            benign_hits.append(
                f"{domain} is a known legitimate service"
            )
    
    for ip in indicators.get("ips", []):
        for clean in BENIGN_PATTERNS["known_clean_ips"]:
            if ip in clean:
                benign_hits.append(
                    f"{ip} is a known clean IP ({clean})"
                )
    
    return {
        "matched_attack_patterns": matched,
        "benign_indicators":       benign_hits,
        "highest_severity": matched[0]["severity"] if matched else "clean",
        "pattern_count":    len(matched)
    }