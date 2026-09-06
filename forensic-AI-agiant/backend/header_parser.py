import re
import email
from email import policy

def parse_eml(content: bytes) -> dict:
    try:
        msg = email.message_from_bytes(content, policy=policy.default)
    except Exception:
        msg = email.message_from_bytes(content)

    # Basic headers
    result = {
        "from":       msg.get("From", ""),
        "to":         msg.get("To", ""),
        "subject":    msg.get("Subject", ""),
        "date":       msg.get("Date", ""),
        "reply_to":   msg.get("Reply-To", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_chain": [],
        "auth_results": {
            "spf":   "unknown",
            "dkim":  "unknown",
            "dmarc": "unknown"
        },
        "x_headers":  {},
        "attachments": [],
        "body_text":  "",
        "anomalies":  [],
        "routing_ips": []
    }

    # Parse Received chain (email routing path)
    received_headers = msg.get_all("Received", [])
    for r in received_headers:
        hop = {"raw": r, "from": "", "by": "", "ip": "", "time": ""}
        from_match = re.search(r'from\s+(\S+)', r)
        by_match   = re.search(r'by\s+(\S+)', r)
        ip_match   = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', r)
        time_match = re.search(r';\s*(.+)$', r.strip())
        if from_match: hop["from"] = from_match.group(1)
        if by_match:   hop["by"]   = by_match.group(1)
        if ip_match:
            hop["ip"] = ip_match.group(1)
            result["routing_ips"].append(ip_match.group(1))
        if time_match: hop["time"] = time_match.group(1).strip()
        result["received_chain"].append(hop)

    # Reverse chain (oldest hop first)
    result["received_chain"].reverse()

    # SPF / DKIM / DMARC
    auth = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")
    if auth:
        if "spf=pass"   in auth: result["auth_results"]["spf"]   = "pass"
        elif "spf=fail" in auth: result["auth_results"]["spf"]   = "fail"
        elif "spf=softfail" in auth: result["auth_results"]["spf"] = "softfail"
        if "dkim=pass"  in auth: result["auth_results"]["dkim"]  = "pass"
        elif "dkim=fail"in auth: result["auth_results"]["dkim"]  = "fail"
        if "dmarc=pass" in auth: result["auth_results"]["dmarc"] = "pass"
        elif "dmarc=fail"in auth:result["auth_results"]["dmarc"] = "fail"

    # X-headers (often reveal mail platform info)
    for key in msg.keys():
        if key.lower().startswith("x-"):
            result["x_headers"][key] = msg.get(key, "")

    # Originating IP
    orig_ip = msg.get("X-Originating-IP", "") or msg.get("X-Sender-IP", "")
    if orig_ip:
        clean = re.sub(r'[\[\]]', '', orig_ip).strip()
        if clean and clean not in result["routing_ips"]:
            result["routing_ips"].append(clean)

    # Attachments
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            fname    = part.get_filename() or "unnamed"
            payload  = part.get_payload(decode=True) or b""
            import hashlib
            result["attachments"].append({
                "filename": fname,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "md5":  hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest()
            })

    # Body text
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    result["body_text"] = part.get_content() or ""
                    break
        else:
            result["body_text"] = msg.get_content() or ""
    except Exception:
        result["body_text"] = str(msg.get_payload(decode=True) or "")

    # Anomaly detection on headers
    frm = result["from"]
    rt  = result["reply_to"]

    if rt and frm and rt != frm:
        result["anomalies"].append({
            "type": "reply_to_mismatch",
            "detail": f"Reply-To ({rt}) differs from From ({frm})",
            "severity": "high"
        })

    # Check sender domain vs received chain domain
    frm_domain = re.search(r'@([\w.\-]+)', frm)
    if frm_domain and result["received_chain"]:
        frm_d = frm_domain.group(1).lower()
        first_hop = result["received_chain"][0].get("from","").lower()
        if frm_d and first_hop and frm_d not in first_hop:
            result["anomalies"].append({
                "type": "domain_mismatch",
                "detail": f"Sender domain '{frm_d}' not in first hop '{first_hop}'",
                "severity": "high"
            })

    # Auth failures
    auth_r = result["auth_results"]
    if auth_r["spf"] in ("fail","softfail"):
        result["anomalies"].append({"type":"spf_fail",
            "detail":f"SPF {auth_r['spf']}", "severity":"high"})
    if auth_r["dkim"] == "fail":
        result["anomalies"].append({"type":"dkim_fail",
            "detail":"DKIM signature failed", "severity":"high"})
    if auth_r["dmarc"] == "fail":
        result["anomalies"].append({"type":"dmarc_fail",
            "detail":"DMARC policy failed", "severity":"critical"})

    # Attachment anomalies
    dangerous_ext = [".exe",".bat",".ps1",".vbs",".js",".jar",".scr",".cmd"]
    for att in result["attachments"]:
        for ext in dangerous_ext:
            if att["filename"].lower().endswith(ext):
                result["anomalies"].append({
                    "type": "dangerous_attachment",
                    "detail": f"Dangerous attachment: {att['filename']}",
                    "severity": "critical"
                })

    return result