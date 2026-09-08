from header_parser import parse_eml


def test_parses_auth_results_and_flags_all_three_failing(fixtures_dir):
    content = (fixtures_dir / "typosquat_phishing.eml").read_bytes()
    result = parse_eml(content)

    assert result["auth_results"]["spf"] == "fail"
    assert result["auth_results"]["dkim"] == "fail"
    assert result["auth_results"]["dmarc"] == "fail"
    assert result["from"] == "PayPal Security <security@paypa1-verification.com>"
    assert "185.220.101.45" in result["routing_ips"]

    severities = {a["type"] for a in result["anomalies"]}
    assert "reply_to_mismatch" in severities
    assert "spf_fail" in severities
    assert "dkim_fail" in severities
    assert "dmarc_fail" in severities


def test_legit_email_passes_auth_with_no_anomalies(fixtures_dir):
    content = (fixtures_dir / "legit_business.eml").read_bytes()
    result = parse_eml(content)

    assert result["auth_results"]["spf"] == "pass"
    assert result["auth_results"]["dkim"] == "pass"
    assert result["auth_results"]["dmarc"] == "pass"
    assert result["anomalies"] == []


def test_malformed_email_does_not_raise(fixtures_dir):
    """A .eml with no From header and a broken multipart boundary must be
    handled gracefully — parse_eml() already wraps message_from_bytes in a
    try/except fallback; this locks that contract in with a test."""
    content = (fixtures_dir / "malformed.eml").read_bytes()
    result = parse_eml(content)  # must not raise

    assert result["from"] == ""
    assert isinstance(result["body_text"], str)


def test_dangerous_attachment_flagged_as_critical_anomaly():
    raw = (
        b"From: a@example.com\r\n"
        b"To: b@example.com\r\n"
        b"Subject: invoice\r\n"
        b"Content-Type: multipart/mixed; boundary=\"X\"\r\n\r\n"
        b"--X\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"see attached\r\n"
        b"--X\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.exe\"\r\n\r\n"
        b"fake binary content\r\n"
        b"--X--\r\n"
    )
    result = parse_eml(raw)
    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "invoice.exe"
    assert att["sha256"]  # a hash was actually computed

    assert any(a["type"] == "dangerous_attachment" for a in result["anomalies"])


def test_arabic_phishing_email_preserves_utf8_body_and_flags_auth_failures(fixtures_dir):
    """UTF-8 Arabic body text must survive parsing intact — no mangling,
    no silent fallback to an empty body — and the header-level anomaly
    detection (which is script-agnostic) still fires the same as it would
    for an equivalent English-language spoofed sender."""
    content = (fixtures_dir / "arabic_phishing.eml").read_bytes()
    result = parse_eml(content)

    assert result["auth_results"]["spf"] == "fail"
    assert result["auth_results"]["dkim"] == "fail"
    assert result["auth_results"]["dmarc"] == "fail"
    assert "خلال 24" in result["body_text"]
    assert "185.220.101.45" in result["routing_ips"]


def test_prompt_injection_email_still_parses_normally(fixtures_dir):
    """The injection payload lives in the body text, not the headers — it
    should have zero effect on header parsing, and the auth/anomaly
    signals should come through exactly as any other spoofed-sender
    phishing email would."""
    content = (fixtures_dir / "prompt_injection.eml").read_bytes()
    result = parse_eml(content)

    assert result["auth_results"]["spf"] == "fail"
    assert "SYSTEM NOTICE TO AI ANALYST" in result["body_text"]
